// SPDX-License-Identifier: AGPL-3.0-or-later
//! M25a — Crypto recovery pyramid integration tests.
//!
//! Each test exercises a full round-trip: write an encrypted record, then
//! recover the encryption key via one of the supported recovery paths, and
//! assert the record is readable from the on-disk SQLCipher database.
//!
//! ## Recovery paths covered
//!
//! | Test                                    | Path                                   |
//! | --------------------------------------- | -------------------------------------- |
//! | `encrypted_db_survives_restart`         | keychain entry present after restart   |
//! | `recover_from_mnemonic_cold_device`     | BIP-39 mnemonic re-login               |
//! | `recover_with_pin_when_keychain_lost`   | PIN unlock from `wrapped_seed.json`    |
//! | `wrong_pin_leaves_db_inaccessible`      | wrong PIN must not unlock              |
//!
//! ## Keychain isolation
//!
//! These tests never touch the real OS keychain. Each test owns a private
//! in-memory [`MemorySecrets`] store that is shared across runtime instances
//! within the test (standing in for the keychain's cross-restart persistence)
//! and discarded when the test ends. This keeps tests hermetic and free of
//! cross-test pollution or parallel flakiness.

use kotton_device::users::DeviceUsers as _;
use kotton_sys::secret::SecretsStore;
use kotton_crypto::{
    derive_db_key, mnemonic_to_seed32, unwrap_master_secret_recovery, RecoveryCopy,
};
use kotton_record::{
    record_store::{RecordFilter, RecordStore},
    SqliteRecordStore,
};
use kotton_secret::MemorySecrets;
use kotton_device::config::RuntimeConfig;
use kotton_device::DeviceRuntime;
use kotton_schemas::{CoreSchema, Nsid};
use kotton_common::crypto::kdf_labels;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

// ─── Helpers ─────────────────────────────────────────────────────────────────

const NOTES_NSID: &str = "sh.kotton.notes";
const PIN: &str = "123456";

/// Return a unique user id per test to avoid collisions in shared maps.
fn uid(tag: &str) -> String {
    format!("crypto-test-{tag}")
}

/// A fresh in-memory secrets store standing in for the OS keychain.
fn mock_keychain() -> Arc<dyn SecretsStore + Send + Sync> {
    Arc::new(MemorySecrets::new())
}

/// Delete the operational roots from the keychain to simulate keychain loss
/// (RFC-0039: the DB key comes from the stored `master_secret`, not `seed32`).
fn wipe_operational_roots(secrets: &Arc<dyn SecretsStore + Send + Sync>, user: &str) {
    let _ = secrets.delete_secret(&kdf_labels::master_secret_keychain_key(user));
    let _ = secrets.delete_secret(&kdf_labels::identity_signing_key(user));
    let _ = secrets.delete_secret(&kdf_labels::operational_cek(user));
}

/// Spin up an isolated `DeviceRuntime` backed by `dir`, using a mocked
/// (in-memory) keychain so no test ever touches the real OS keychain.
async fn make_runtime(
    dir: &TempDir,
    secrets: Arc<dyn SecretsStore + Send + Sync>,
) -> DeviceRuntime {
    DeviceRuntime::new_with_secrets(dir.path().to_owned(), RuntimeConfig::default(), secrets)
        .await
        .expect("DeviceRuntime::new_with_secrets")
}

/// Ensure the notes table exists and insert one record.
async fn insert_note(store: &SqliteRecordStore, content: &str) -> String {
    store
        .create_table(&CoreSchema::Notes.definition())
        .await
        .expect("create_table");
    let nsid = Nsid::new(NOTES_NSID).unwrap();
    store
        .insert(
            &nsid,
            json!({
                "title": "test",
                "body": content,
                "tags": [],
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }),
        )
        .await
        .expect("insert")
}

/// Assert at least one note with the given `body` content exists in `store`.
async fn assert_note_readable(store: &SqliteRecordStore, content: &str) {
    store
        .create_table(&CoreSchema::Notes.definition())
        .await
        .expect("create_table (idempotent)");
    let nsid = Nsid::new(NOTES_NSID).unwrap();
    let records = store
        .query(&nsid, RecordFilter::new())
        .await
        .expect("query");
    assert!(
        records
            .iter()
            .any(|r| r.body.get("body").and_then(|v| v.as_str()) == Some(content)),
        "expected record with body={content:?} but got: {records:?}"
    );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Baseline: the encrypted DB is readable after a process restart, once the
/// account is unlocked.
///
/// This is the anchor test — if it fails, the M24 encryption wiring is broken.
///
/// **The refusal before the unlock is half the assertion.** An account is locked
/// from creation (RFC-0053 step 4), so a restart finds no resolvable roots and
/// the store refuses rather than opening plaintext. If that first assertion ever
/// succeeds, either the purge stopped happening or the unencrypted fallback came
/// back — the same regression wearing different clothes. `DEC-0049`.
#[tokio::test]
async fn encrypted_db_survives_restart() {
    let user = uid("restart");
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = mock_keychain();

    // ── Pass 1: create user and write a record ────────────────────────────
    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
        rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets()).expect("get store");
        insert_note(&store, "hello from pass 1").await;
    }
    // Runtime dropped here — in-memory cache cleared, connection closed.

    // ── Pass 2: new runtime instance at the same path ────────────────────
    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;

        let err = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets())
            .err()
            .expect(
                "a restarted account opened without its credential — either the \
                 roots were left in platform storage, or the unencrypted fallback \
                 is back",
            );
        assert!(
            err.to_string().contains(kotton_record::open::LOCKED),
            "expected a locked refusal, got: {err}"
        );

        kotton_identity::provisioning::unlock_with_pin(
            &rt,
            &user,
            crate::common::TEST_PASSPHRASE,
        )
        .await
        .expect("unlock (pass 2)");

        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets())
            .expect("get store (pass 2)");
        assert_note_readable(&store, "hello from pass 1").await;
    }
}

/// Recovery test: the BIP-39 mnemonic recovers the (random) DB-encryption key via
/// the sealed recovery bundle.
///
/// RFC-0039: `master_secret` is **random** — not derived from the mnemonic — so the
/// mnemonic recovers the DB key by unsealing the mnemonic-wrapped copy in
/// `recovery.json`, not by re-deriving it. Procedure:
/// 1. Create a user and write a record (DB encrypted under the random `master_secret`).
/// 2. Wipe the keychain so the recovery below cannot "cheat" by reading it.
/// 3. Read `recovery.json` and unseal `master_secret` using only the mnemonic.
/// 4. Open the on-disk SQLCipher file directly with the recovered key.
/// 5. Assert the record is readable.
#[tokio::test]
async fn mnemonic_recovers_db_key_via_recovery_bundle() {
    let user = uid("mnemonic");
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = mock_keychain();

    let recovery_key: String;
    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
        // `_` is the runtime: this test reaches the record store directly
        // (machine state), so it never needs the user resident.
        let (_result, _) = rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
        // Creation mints no phrase; this test needs one, so it sets recovery up
        // the way a person would.
        recovery_key = kotton_device::users::commands::add_recovery_phrase(
            rt.base_dir(),
            rt.secrets(),
            &user,
        )
        .await
        .expect("add_recovery_phrase");
        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets()).expect("get store");
        insert_note(&store, "determinism canary").await;
    }
    // Runtime dropped — connection closed.

    // Wipe the keychain so recovery must go through the mnemonic-sealed bundle.
    wipe_operational_roots(&secrets, &user);

    // Unseal the random master_secret from recovery.json using only the mnemonic.
    let bundle_json =
        std::fs::read_to_string(dir.path().join("users").join(&user).join("recovery.json"))
            .expect("read recovery.json");
    let bundle: serde_json::Value =
        serde_json::from_str(&bundle_json).expect("parse recovery bundle");
    // The file is a per-authority keyed set (one sealed copy per recovery phrase,
    // keyed by the reserve pubkey that opens it) since
    // TASK-a-second-recovery-phrase-silently-disinherits-the-first. This account
    // has one phrase, so `copies` has one entry; take its master_secret copy.
    let copy = bundle["copies"]
        .as_object()
        .expect("recovery.json holds a keyed `copies` set")
        .values()
        .next()
        .expect("one sealed copy for the one phrase");
    let master_copy: RecoveryCopy =
        serde_json::from_value(copy["master_secret"].clone()).expect("master_secret recovery copy");
    let seed32 = mnemonic_to_seed32(&recovery_key);
    let master = unwrap_master_secret_recovery(&master_copy, &seed32)
        .expect("unseal master_secret with the mnemonic");
    let db_key = derive_db_key(&master, &kdf_labels::user_records_db(&user));

    // Open the on-disk file directly with the recovered key.
    let db_path = dir.path().join("users").join(&user).join("records.db");
    let store =
        SqliteRecordStore::open(&db_path, Some(&db_key)).expect("open with recovered key");

    assert_note_readable(&store, "determinism canary").await;
}

/// PIN recovery path — `vault.json` restores the keychain after loss.
///
/// Simulates "keychain wiped; user re-enters their PIN." `unlock_with_pin` opens
/// the at-rest vault (the three operational roots under `U = Argon2id(PIN)`) and
/// restores them to the keychain, so the subsequent `get_or_create_record_store`
/// finds the correct `master_secret` and DB key.
#[tokio::test]
async fn recover_with_pin_when_keychain_lost() {
    let user = uid("pin-ok");
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = mock_keychain();

    // ── Pass 1: create user, set PIN, write record ────────────────────────
    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
        rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
        rt.set_user_pin(&user, PIN).await.expect("set_user_pin");
        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets()).expect("get store");
        insert_note(&store, "pin recovery note").await;
    }

    // ── Simulate keychain loss (wipe the operational roots) ───────────────
    wipe_operational_roots(&secrets, &user);

    // ── Pass 2: recover via PIN, then read record ─────────────────────────
    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
        rt.unlock_with_pin(&user, PIN)
            .await
            .expect("unlock_with_pin");
        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets())
            .expect("get store after PIN recovery");
        assert_note_readable(&store, "pin recovery note").await;
    }
}

/// Negative path — a wrong PIN must not unlock the keychain.
///
/// `unlock_with_pin` with an incorrect PIN returns an error and does NOT
/// write a keychain entry. The encrypted DB therefore remains inaccessible:
/// `get_or_create_record_store` fails because it cannot open an encrypted
/// file without a key.
#[tokio::test]
async fn wrong_pin_leaves_db_inaccessible() {
    let user = uid("pin-bad");
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = mock_keychain();

    // ── Pass 1: create user, set PIN, write record ────────────────────────
    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
        rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
        rt.set_user_pin(&user, PIN).await.expect("set_user_pin");
        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets()).expect("get store");
        insert_note(&store, "secret note").await;
    }

    // ── Simulate keychain loss (wipe the operational roots) ───────────────
    wipe_operational_roots(&secrets, &user);

    // ── Pass 2: attempt unlock with wrong PIN ─────────────────────────────
    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;

        let result = rt.unlock_with_pin(&user, "000000").await;
        assert!(result.is_err(), "wrong PIN must return an error");

        // The master_secret must still be absent — a bad PIN must not restore it.
        let entry = secrets
            .get_secret(&kdf_labels::master_secret_keychain_key(&user))
            .unwrap_or(None);
        assert!(
            entry.is_none(),
            "master_secret must remain absent after a wrong PIN"
        );

        // Opening the record store without the key must fail (DB is encrypted).
        let store_result = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets());
        assert!(
            store_result.is_err(),
            "encrypted DB must not open without the correct key"
        );
    }
}

// ─── RFC-0053 step 4: what the platform is left holding ──────────────────────

/// The security property of RFC-0053 step 4, asserted against the platform
/// store directly: once a daily credential exists, **the keychain holds no
/// material that opens the user's data.**
///
/// Before this, `create_user` wrote `master_secret`, the identity key and the
/// CEK to the OS keychain as lowercase hex and left them there. A keychain is
/// keyed by the OS account, so on a shared login that handed every Kotton
/// identity's data to whoever was sitting at the machine — the case RFC-0053's
/// governing constraint exists to close, and one no Kotton-side check can fix,
/// because the material is simply present.
#[tokio::test]
async fn setting_a_credential_takes_the_roots_out_of_platform_storage() {
    let user = uid("custody");
    let dir = tempfile::tempdir().expect("tempdir");
    let platform = mock_keychain();

    let rt = make_runtime(&dir, Arc::clone(&platform)).await;
    rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");

    // The property holds from the instant the account exists, not from the first
    // `set_user_pin`: creation takes a credential and purges in the same act
    // (`DEC-0049`). The precondition this replaced — "before a credential exists
    // the keychain is the only durable copy" — described a window that no longer
    // opens, and keeping it would have been asserting the gap.
    for label in [
        kdf_labels::master_secret_keychain_key(&user),
        kdf_labels::identity_signing_key(&user),
        kdf_labels::operational_cek(&user),
        kdf_labels::seed32_keychain_key(&user),
    ] {
        assert_eq!(
            platform.get_secret(&label).unwrap(),
            None,
            "{label} was left in platform storage by create_user itself"
        );
    }

    // Setting a credential again is legal and must not put anything back.
    rt.set_user_pin(&user, PIN).await.expect("set_user_pin");

    for label in [
        kdf_labels::master_secret_keychain_key(&user),
        kdf_labels::identity_signing_key(&user),
        kdf_labels::operational_cek(&user),
        kdf_labels::seed32_keychain_key(&user),
    ] {
        assert_eq!(
            platform.get_secret(&label).unwrap(),
            None,
            "{label} is still readable from platform storage in the clear"
        );
    }

    // And the daemon is still fully working — the roots moved, they did not go
    // away. A purge that broke the running session would be a regression, not a
    // hardening.
    let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets()).expect("get store");
    insert_note(&store, "custody note").await;
    assert_note_readable(&store, "custody note").await;
}

/// The other half, and the one that would silently undo the first: unlocking
/// must not re-deposit the plaintext.
///
/// `unlock_with_pin` restores the roots from the vault, and it used to restore
/// them *to the keychain*. Left alone, every unlock would put back exactly what
/// the purge removed, and the property above would hold only until the user next
/// logged in.
#[tokio::test]
async fn unlocking_does_not_put_the_roots_back_in_platform_storage() {
    let user = uid("custody-unlock");
    let dir = tempfile::tempdir().expect("tempdir");
    let platform = mock_keychain();

    {
        let rt = make_runtime(&dir, Arc::clone(&platform)).await;
        rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
        rt.set_user_pin(&user, PIN).await.expect("set_user_pin");
        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets()).expect("get store");
        insert_note(&store, "survives unlock").await;
    }

    // A fresh runtime is a restarted daemon: in-memory custody is empty, and the
    // platform holds nothing, so this device genuinely cannot read its own data
    // until someone supplies the credential. That re-lock is the point.
    let rt = make_runtime(&dir, Arc::clone(&platform)).await;
    rt.unlock_with_pin(&user, PIN)
        .await
        .expect("unlock_with_pin");

    for label in [
        kdf_labels::master_secret_keychain_key(&user),
        kdf_labels::identity_signing_key(&user),
        kdf_labels::operational_cek(&user),
    ] {
        assert_eq!(
            platform.get_secret(&label).unwrap(),
            None,
            "unlock re-deposited {label} into platform storage"
        );
    }

    let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets())
        .expect("get store after unlock");
    assert_note_readable(&store, "survives unlock").await;
}

// ─── RFC-0053 step 8: device binding ─────────────────────────────────────────

/// Binding is **opt-in**: having a TPM changes nothing until the user asks.
///
/// The alternative — binding whenever hardware exists — would silently change
/// the recovery story for everyone who happens to own a machine with a chip in
/// it, and RFC-0053 says hardware sealing is never required.
#[tokio::test]
async fn hardware_is_not_used_until_the_user_opts_in() {
    let user = uid("bind-optin");
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = mock_keychain();

    let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
    rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    rt.set_user_pin(&user, PIN).await.expect("set_user_pin");

    let vault: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("users").join(&user).join("vault.json"))
            .expect("read vault"),
    )
    .expect("parse vault");
    assert_eq!(
        vault["version"], 1,
        "an un-bound vault must stay version 1 even on a machine with a TPM"
    );
    assert!(
        !dir.path().join("users").join(&user).join("device_binding.bin").exists(),
        "no binding file should exist without an explicit opt-in"
    );
}

/// The opt-in round trip, against this machine's real TPM: bind, then unlock
/// across a restart. Skips loudly where no usable TPM exists.
#[tokio::test]
async fn a_bound_identity_still_unlocks_on_this_device() {
    let user = uid("bind-roundtrip");
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = mock_keychain();

    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
        if !rt.hardware_binding_available() {
            eprintln!("SKIPPED: no usable hardware-backed key store on this machine");
            return;
        }
        rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
        rt.set_user_pin(&user, PIN).await.expect("set_user_pin");
        rt.bind_device(&user, PIN).await.expect("bind_device");

        let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets()).expect("get store");
        insert_note(&store, "bound note").await;
    }

    let vault: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("users").join(&user).join("vault.json"))
            .expect("read vault"),
    )
    .expect("parse vault");
    assert_eq!(vault["version"], 2, "binding must produce a v2 vault");

    // A fresh runtime is a restarted daemon: nothing in memory, and the vault
    // now needs the TPM as well as the credential.
    let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
    rt.unlock_with_pin(&user, PIN)
        .await
        .expect("a bound vault must still unlock on its own device");
    let store = kotton_record::open::user_record_store(rt.base_dir(), &user, rt.secrets())
        .expect("get store after unlock");
    assert_note_readable(&store, "bound note").await;
}

/// The property binding exists for: the vault is useless without this device's
/// binding, **even with the correct credential**. Simulated by removing the
/// binding ciphertext, which is what copying `vault.json` alone would produce.
#[tokio::test]
async fn a_bound_vault_does_not_open_without_its_binding() {
    let user = uid("bind-nodevice");
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = mock_keychain();

    {
        let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
        if !rt.hardware_binding_available() {
            eprintln!("SKIPPED: no usable hardware-backed key store on this machine");
            return;
        }
        rt.create_user(&user, crate::common::TEST_PASSPHRASE).await.expect("create_user");
        rt.set_user_pin(&user, PIN).await.expect("set_user_pin");
        rt.bind_device(&user, PIN).await.expect("bind_device");
    }

    std::fs::remove_file(dir.path().join("users").join(&user).join("device_binding.bin"))
        .expect("remove the binding, as copying only vault.json would");

    let rt = make_runtime(&dir, Arc::clone(&secrets)).await;
    assert!(
        rt.unlock_with_pin(&user, PIN).await.is_err(),
        "the correct credential must not open a bound vault without the device"
    );
}
