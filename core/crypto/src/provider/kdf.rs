// SPDX-License-Identifier: AGPL-3.0-or-later
//! HKDF-SHA256 key derivation for the Kotton key hierarchy.
//!
//! The hierarchy has two roots, and neither is derived: `master_secret` and the
//! CEK are 32 random bytes each, which `create_user` fills from `generate_cek`
//! (beside the identity key, a third random value that roots nothing here) and
//! stores rather than re-derives. No key material is ever stored to disk in
//! plaintext. Everything this module derives for data flows from one of them:
//!
//! ```text
//! master_secret [32 random bytes]
//!   ├─► HKDF(info="kotton:db:<name>:v1")        → database keys
//!   │                                              (records.db, agent.db, per-app)
//!   ├─► HKDF(info="kotton:hmac:events:v1")      → the event log's HMAC key
//!   └─► HKDF(info="kotton:history-log:v1")      → history-log segment key
//! CEK [32 random bytes]
//!   ├─► HKDF(info="kotton:pack:v1")             → pack-sealing key
//!   ├─► HKDF(info="kotton:session:<id>:v1")     → session keys
//!   └─► HKDF(info="kotton:cek-domain-id:v1")    → key-domain identifier
//! ```
//!
//! A recovery phrase derives a separate set and no root: `seed32` (the first 32
//! bytes of its PBKDF2 seed) yields the key log's reserve keys `K_rec[i]` and the
//! KEKs that seal recovery copies of the two roots.
//!
//! `derive_master_secret` and `derive_cek` over `seed32` are kept for one reader:
//! a keychain that still holds a seed and no stored root reads that root as
//! derived from it (`resolve_operational_cek` in `core/identity` and its
//! siblings). Nothing writes a seed.
//!
//! # Footguns avoided
//!
//! - We use `mnemonic.to_seed("")[..32]` (first 32 bytes of the PBKDF2 seed,
//!   no passphrase) as HKDF IKM.  We never use the 64-byte PBKDF2 seed or a
//!   64-byte ed25519 "expanded" keypair form as HKDF input.
//! - Salt is omitted (set to `None`) — the BIP-39 seed already has high
//!   entropy and a zero-salt extract is a well-established pattern when the IKM
//!   is uniformly random.
//! - HKDF info strings carry a version suffix (`v1`).  When key rotation is
//!   implemented (M24f), incrementing to `v2` derives a fresh key without
//!   re-deriving master_secret.

use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use kotton_common::crypto::kdf_labels;
use sha2::Sha256;

// ── Core derivation ───────────────────────────────────────────────────────────

/// Derive a 32-byte `master_secret` from a 32-byte BIP-39-derived seed.
///
/// `seed32` must be the **first 32 bytes** of `mnemonic.to_seed("")`. No
/// identity's `master_secret` is made this way — `create_user` makes it random —
/// so outside tests this is the read fallback for a keychain that holds a seed
/// and no stored `master_secret`.
pub fn derive_master_secret(seed32: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(seed32, kdf_labels::MASTER.as_bytes())
}

/// Derive a 32-byte symmetric key for a specific labelled resource.
///
/// `label` must be a stable, version-suffixed ASCII string, e.g.:
/// - `"kotton:db:system:v1"` — events.db
/// - `"kotton:db:app:sh.kotton.contacts:v1"` — per-app record store
///
/// Different labels produce independent, cryptographically separated keys.
/// The same `master_secret` + same `label` always produces the same key.
pub fn derive_db_key(master_secret: &[u8; 32], label: &str) -> [u8; 32] {
    hkdf_expand(master_secret, label.as_bytes())
}

// ── Mnemonic helpers ──────────────────────────────────────────────────────────

/// Extract a 32-byte seed from a BIP-39 mnemonic phrase, returning an error
/// (never panicking) on an invalid phrase.
///
/// **Use this at any trust boundary** where the phrase comes from caller input —
/// recovery login, identity rotation — so a malformed phrase is a clean error,
/// not a daemon panic (audit hygiene). Returns the first 32 bytes of
/// `mnemonic.to_seed("")` (PBKDF2, no passphrase); deterministic for a given
/// mnemonic.
pub fn try_mnemonic_to_seed32(phrase: &str) -> Result<[u8; 32], String> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| format!("invalid recovery phrase: {e}"))?;
    let seed64 = mnemonic.to_seed("");
    let mut out = [0u8; 32];
    out.copy_from_slice(&seed64[..32]);
    Ok(out)
}

/// Extract a 32-byte seed from a BIP-39 mnemonic phrase.
///
/// # Panics
/// Panics if `phrase` is not a valid BIP-39 mnemonic. Use only where the phrase
/// is valid **by construction** (freshly generated during onboarding); for
/// caller-supplied phrases use [`try_mnemonic_to_seed32`].
pub fn mnemonic_to_seed32(phrase: &str) -> [u8; 32] {
    try_mnemonic_to_seed32(phrase).expect("mnemonic_to_seed32 called with invalid mnemonic")
}

/// Convenience: derive `master_secret` directly from a BIP-39 mnemonic phrase.
///
/// Equivalent to `derive_master_secret(&mnemonic_to_seed32(phrase))`.
pub fn master_from_mnemonic(phrase: &str) -> [u8; 32] {
    let seed = mnemonic_to_seed32(phrase);
    derive_master_secret(&seed)
}

/// Derive a 32-byte seed for a specific algorithm migration.
///
/// The label-bump half of algorithm agility: a seed that is deterministic from
/// the root seed and completely independent of the main key hierarchy.
///
/// This is what makes an algorithm change *possible without touching the
/// mnemonic* — RFC-0001 and RFC-0075 ID9 both put the migration point at a
/// versioned dispatch hook, and a versioned label is that hook at the derivation
/// layer. Bump the label, get an unrelated key, keep the same recovery phrase.
///
/// It has no caller today. That is deliberate: the ML-DSA suite that used to be
/// its caller was removed on 2026-08-26 and the seam was kept
/// (`IDEA-the-post-quantum-path-is-built-beside-the-identity`). The test below
/// is what stops "no caller" turning into "no longer works".
///
/// `info` must be a stable, version-suffixed ASCII string, e.g.
/// `"kotton:migrate:<algorithm>:v1"`.
pub fn derive_migration_seed(seed32: &[u8; 32], info: &str) -> [u8; 32] {
    hkdf_expand(seed32, info.as_bytes())
}

/// Derive the 32-byte Ed25519 identity key scalar from `seed32`.
///
/// This is Layer 3 of the identity pipeline:
///
/// ```text
/// mnemonic → seed32 → HKDF-SHA256(info="kotton:identity:ed25519:v1") → Ed25519 scalar
/// ```
///
/// The output is clamped to a valid Ed25519 scalar per RFC 8032 by
/// `Ed25519Keypair::from_seed`.  To derive the `did:key` identifier, pass the
/// resulting `VerifyingKey` bytes to `DidKeyMethod::from_public_key_bytes`.
///
/// **Stability contract:** the info label is fixed forever.  Changing it changes
/// every user's DID.  Any migration must introduce a new dispatch case with a
/// `v2` label — never modify this string.
pub fn derive_identity_key(seed32: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(seed32, kdf_labels::IDENTITY_ED25519.as_bytes())
}

/// Derive the 32-byte Content Encryption Key (CEK) from `seed32`.
///
/// This is Layer C1 of the content encryption pipeline:
///
/// ```text
/// mnemonic → seed32 → HKDF-SHA256(info="kotton:cek:v1") → CEK
/// ```
///
/// The CEK is the root of the per-file key hierarchy, and no identity's CEK is
/// made this way: `create_user` makes it random and the keychain keeps it. This
/// derivation is the read fallback for a keychain that holds a seed and no stored
/// CEK (`resolve_operational_cek`).
///
/// **Stability contract:** the info label is fixed forever.  Changing it changes
/// every user's CEK, invalidating all stored ciphertext.  Any migration must
/// introduce a new dispatch case with a `v2` label and run a full re-encryption
/// pass — never modify this string.
pub fn derive_cek(seed32: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(seed32, kdf_labels::CEK.as_bytes())
}

/// Derive the 32-byte CEK **recovery** key-encryption key (KEK) from `seed32`.
///
/// In the RFC-0033 Hybrid CEK model the CEK is random (not derived); a recovery
/// copy is wrapped under this KEK so the mnemonic alone can always recover the
/// CEK — and therefore the user's data — even after total device loss. This is
/// the continuity invariant in code:
///
/// ```text
/// mnemonic → seed32 → HKDF-SHA256(info="kotton:cek-recovery:v1") → recovery KEK
/// ```
///
/// **Stability contract:** the info label is fixed forever. Changing it makes
/// every user's CEK unrecoverable from their mnemonic — permanent data loss. Any
/// migration must introduce a `v2` label and re-wrap each user's recovery copy.
pub fn derive_cek_recovery_kek(seed32: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(seed32, kdf_labels::CEK_RECOVERY.as_bytes())
}

/// Derive the 32-byte **pack-sealing key** (`K_pack`) from the CEK (RFC-0045).
///
/// A pack is the object-storage envelope — many chunks sealed into one
/// fixed-size container — so its key lives in the object key domain and derives
/// from the CEK, exactly as the path-blinding key does. Deriving it from
/// `master_secret` would leak every pack on a record-database compromise and
/// would leave a FROST-joined device (which receives the CEK but not
/// `master_secret`) unable to open any pack; see [`kdf_labels::PACK`].
///
/// ```text
/// CEK → HKDF-SHA256(info="kotton:pack:v1") → K_pack
/// ```
///
/// **Stability contract:** the info label is fixed forever; a change re-seals
/// every pack. A migration must introduce a `v2` label and rewrite each pack.
pub fn derive_pack_key(cek: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(cek, kdf_labels::PACK.as_bytes())
}

/// Derive the 32-byte **ephemeral session key** from the CEK and a session id
/// (RFC-0075).
///
/// A session key scopes a guest device to a subset of a user's storage for a
/// bounded time. It opens the user's stored bytes, so it lives in the object key
/// domain and derives from the CEK, exactly as [`derive_pack_key`] does — with
/// the session id in the info label so each session gets an independent key.
///
/// ```text
/// CEK → HKDF-SHA256(info="kotton:session:<session_id>:v1") → session key
/// ```
///
/// It is deterministic, so a host recomputes it on restart without storing
/// session keys at rest. Until 2026-09-06 `kotton_grant` computed it with
/// `blake3::derive_key` and an inline label, outside this hierarchy and its
/// registry (`TASK-session-key-derives-outside-the-hierarchy`); this is the same
/// input material through the audited KDF.
///
/// **Not key-wrapping.** As before, anyone holding the CEK and the session id
/// can derive the session key. Wrapping a random per-session key so a CEK
/// compromise does not expose issued sessions is a separate, larger design
/// (random key + stored wrapped copy) and is not attempted here; the change on
/// 2026-09-06 moved the derivation into the hierarchy without altering that
/// property.
pub fn derive_session_key(cek: &[u8; 32], session_id: &str) -> [u8; 32] {
    hkdf_expand(cek, kdf_labels::session(session_id).as_bytes())
}

/// Derive the 32-byte **history-log segment key** (`K_log`) from
/// `master_secret` (RFC-0046, widened to objects by RFC-0047).
///
/// The mirror image of [`derive_pack_key`], and deliberately not derived from
/// the same root. A segment carries record and object *history*, which is
/// db-domain material, so it takes the db-domain root; the pack it is stored in
/// supplies the outer object-domain seal. A segment is therefore double-sealed,
/// and the inner seal is what keeps a CEK compromise from yielding history
/// (RFC-0036). The outer seal is free — it is what packs already do.
///
/// ```text
/// master_secret → HKDF-SHA256(info="kotton:history-log:v1") → K_log
/// ```
///
/// **Stability contract:** the info label is fixed forever; a change orphans
/// every segment ever written. A migration needs a `v2` label and a rewrite.
pub fn derive_history_log_key(master_secret: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(master_secret, kdf_labels::HISTORY_LOG.as_bytes())
}

/// Derive the **key-domain identifier** for a CEK — a non-secret, one-way
/// fingerprint identifying which key domain sealed material belongs to.
///
/// Sealed replication carries this instead of a rotation counter, because the
/// counter cannot answer the question the receiver is actually asking. *Can I
/// open this blob?* is exactly *is this the same CEK?*, and two nodes that were
/// never in the same fleet both start at epoch 0 and compare equal while holding
/// different keys — a check that passes when it must fail. Deriving the
/// identifier from the key itself makes agreement cryptographic rather than
/// clerical, and since a rotation changes the CEK it changes this too.
///
/// Safe to send and to store on an untrusted replica: HKDF is one-way, so the
/// CEK cannot be recovered from it. It *is* a stable fingerprint of the domain,
/// which is inherent — it has to be stable to be comparable — so it is disclosed
/// as replica-visible metadata in RFC-0041 rather than treated as hidden.
///
/// **Stability contract:** the info label is fixed forever; see
/// [`kdf_labels::CEK_DOMAIN_ID`].
pub fn derive_cek_domain_id(cek: &[u8; 32]) -> [u8; 16] {
    let full = hkdf_expand(cek, kdf_labels::CEK_DOMAIN_ID.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// Derive the 32-byte **identity-key recovery** KEK from `seed32`.
///
/// In the RFC-0039 generate-and-seal model the operational identity key is a
/// random Ed25519 scalar (not derived from the mnemonic), so it can be rotated
/// without changing the mnemonic. A recovery copy is wrapped under this KEK so the
/// mnemonic alone can always re-establish a working identity after total device
/// loss — the identity half of the continuity invariant, parallel to
/// [`derive_cek_recovery_kek`].
///
/// ```text
/// mnemonic → seed32 → HKDF-SHA256(info="kotton:identity-recovery:v1") → recovery KEK
/// ```
///
/// **Stability contract:** the info label is fixed forever. Changing it makes
/// every user's identity key unrecoverable from their mnemonic. Any migration
/// must introduce a `v2` label and re-wrap each user's recovery copy.
pub fn derive_identity_recovery_kek(seed32: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(seed32, kdf_labels::IDENTITY_RECOVERY.as_bytes())
}

/// Derive the 32-byte **`master_secret` recovery** KEK from `seed32`.
///
/// In the RFC-0039 generate-and-seal model the operational `master_secret` (the
/// DB-encryption root) is random (not derived from the mnemonic), so it can be
/// rotated without changing the mnemonic. A recovery copy is wrapped under this
/// KEK so the mnemonic alone can always recover every database after total device
/// loss — parallel to [`derive_cek_recovery_kek`] / [`derive_identity_recovery_kek`].
///
/// ```text
/// mnemonic → seed32 → HKDF-SHA256(info="kotton:master-recovery:v1") → recovery KEK
/// ```
///
/// **Stability contract:** the info label is fixed forever. Changing it makes
/// every user's databases unrecoverable from their mnemonic. Any migration must
/// introduce a `v2` label and re-wrap each user's recovery copy.
pub fn derive_master_secret_recovery_kek(seed32: &[u8; 32]) -> [u8; 32] {
    hkdf_expand(seed32, kdf_labels::MASTER_RECOVERY.as_bytes())
}

/// Derive the indexed **KEL pre-rotation recovery key seed** `K_rec[index]` from
/// `seed32` (RFC-0038). Each KEL event pre-commits `hash(pub(K_rec[seq+1]))`, so
/// possession of the current quorum does not let an attacker roll the identity
/// forward — only the mnemonic re-derives the reserve. Returns a 32-byte Ed25519
/// seed; the caller derives the keypair and hashes its public key for the
/// commitment.
///
/// ```text
/// mnemonic → seed32 → HKDF-SHA256(info="kotton:kel:recovery:v1" ‖ index_le) → K_rec[index] seed
/// ```
///
/// **Stability contract:** the label is fixed forever.
pub fn derive_kel_recovery_key(seed32: &[u8; 32], index: u64) -> [u8; 32] {
    let mut info = kdf_labels::KEL_RECOVERY.as_bytes().to_vec();
    info.extend_from_slice(&index.to_le_bytes());
    hkdf_expand(seed32, &info)
}

// ── Private ───────────────────────────────────────────────────────────────────

/// HKDF-SHA256 extract-then-expand with no salt and a single info label.
///
/// Produces exactly 32 bytes of key material.
/// The `expect` is infallible: HKDF-SHA256 with a 32-byte output length
/// always succeeds regardless of input size.
fn hkdf_expand(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand with 32-byte output is infallible");
    okm
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The ephemeral session key derives through this hierarchy — HKDF-SHA256
    /// keyed by the CEK, with a label from the registry — not by a second KDF in
    /// another crate (`TASK-session-key-derives-outside-the-hierarchy`).
    #[test]
    fn session_key_is_hkdf_from_the_cek_with_a_registered_label() {
        let cek = [0x11u8; 32];
        let id = "session-abc";
        // It is exactly HKDF(CEK, kdf_labels::session(id)); if the derivation
        // ever forks to a different primitive or an inline label, this fails.
        let expected = hkdf_expand(&cek, kdf_labels::session(id).as_bytes());
        assert_eq!(derive_session_key(&cek, id), expected);
        // Deterministic for a given (cek, id).
        assert_eq!(derive_session_key(&cek, id), derive_session_key(&cek, id));
        // Independent across session ids — the label carries the id.
        assert_ne!(
            derive_session_key(&cek, "a"),
            derive_session_key(&cek, "b"),
            "different sessions must get independent keys"
        );
        // A session key is not an operational root; misclassifying it would push
        // an ephemeral key toward at-rest handling meant for the seed and CEK.
        assert!(!kotton_common::crypto::kdf_labels::is_operational_root(
            &kotton_common::crypto::kdf_labels::session(id)
        ));
    }

    /// Standard 24-word all-"abandon" test mnemonic (BIP-39 RFC test vector).
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon art";

    #[test]
    fn try_mnemonic_to_seed32_rejects_invalid_without_panicking() {
        // A malformed phrase is a clean error, not a panic (the daemon must not
        // crash on a bad recovery input at a trust boundary).
        assert!(try_mnemonic_to_seed32("not a valid bip39 mnemonic at all").is_err());
        assert!(try_mnemonic_to_seed32("").is_err());
        // A valid phrase yields the same seed as the panicking variant.
        assert_eq!(
            try_mnemonic_to_seed32(TEST_MNEMONIC).unwrap(),
            mnemonic_to_seed32(TEST_MNEMONIC)
        );
    }

    // ── Formal determinism proof test ─────────────────────────────────────────

    /// If this test is green, no code path between the mnemonic and any derived
    /// key introduces non-determinism.  A future change that silently breaks
    /// recovery (changed BIP-39 word list, library update, encoding change)
    /// will fail this test in CI before any user data is at risk.
    #[test]
    fn mnemonic_recovery_is_complete_and_deterministic() {
        // Step 1: derive everything from the mnemonic.
        let master = master_from_mnemonic(TEST_MNEMONIC);
        let system_key = derive_db_key(&master, kdf_labels::SYSTEM_DB);
        let app_ids = [
            "sh.kotton.contacts",
            "sh.kotton.notes",
            "sh.kotton.calendar",
        ];
        let app_keys: Vec<[u8; 32]> = app_ids
            .iter()
            .map(|id| derive_db_key(&master, &kdf_labels::app_db(id)))
            .collect();

        // Step 2: drop all derived material.
        let _ = master;

        // Step 3: re-derive from the same mnemonic.
        let master2 = master_from_mnemonic(TEST_MNEMONIC);
        let system_key2 = derive_db_key(&master2, kdf_labels::SYSTEM_DB);
        let app_keys2: Vec<[u8; 32]> = app_ids
            .iter()
            .map(|id| derive_db_key(&master2, &kdf_labels::app_db(id)))
            .collect();

        // Step 4: assert byte-for-byte equality.
        assert_eq!(
            system_key, system_key2,
            "system DB key is non-deterministic"
        );
        for (i, (k1, k2)) in app_keys.iter().zip(app_keys2.iter()).enumerate() {
            assert_eq!(k1, k2, "app key {} is non-deterministic", app_ids[i]);
        }
    }

    // ── Isolation tests ───────────────────────────────────────────────────────

    #[test]
    fn master_secret_differs_from_seed() {
        let seed = mnemonic_to_seed32(TEST_MNEMONIC);
        let master = derive_master_secret(&seed);
        // master_secret is a transformed version of the seed, not the seed itself.
        assert_ne!(seed, master);
    }

    #[test]
    fn different_apps_get_different_keys() {
        let master = master_from_mnemonic(TEST_MNEMONIC);
        let contacts = derive_db_key(&master, &kdf_labels::app_db("sh.kotton.contacts"));
        let notes = derive_db_key(&master, &kdf_labels::app_db("sh.kotton.notes"));
        let calendar = derive_db_key(&master, &kdf_labels::app_db("sh.kotton.calendar"));
        assert_ne!(contacts, notes, "contacts and notes share a key");
        assert_ne!(contacts, calendar, "contacts and calendar share a key");
        assert_ne!(notes, calendar, "notes and calendar share a key");
    }

    #[test]
    fn system_key_differs_from_app_keys() {
        let master = master_from_mnemonic(TEST_MNEMONIC);
        let system = derive_db_key(&master, kdf_labels::SYSTEM_DB);
        let app = derive_db_key(&master, &kdf_labels::app_db("sh.kotton.contacts"));
        assert_ne!(system, app);
    }

    #[test]
    fn different_seeds_produce_different_master_secrets() {
        let m1 = derive_master_secret(&[0u8; 32]);
        let m2 = derive_master_secret(&[1u8; 32]);
        assert_ne!(m1, m2);
    }

    /// `K_pack` shares the CEK as its input with the path-blinding key and the
    /// domain id; the labels are what keep the three apart. A shared output
    /// would collapse two protection layers into one key.
    #[test]
    fn pack_key_is_domain_separated_from_other_cek_derivations() {
        let cek = [0x42u8; 32];
        let k_pack = derive_pack_key(&cek);
        assert_ne!(k_pack, cek, "K_pack must not be the CEK itself");
        assert_ne!(
            k_pack,
            crate::path_blind::derive_path_blind_key(&cek),
            "K_pack and the path-blinding key must differ"
        );
        assert_eq!(k_pack, derive_pack_key(&cek), "K_pack must be deterministic");
        assert_ne!(derive_pack_key(&[0x43u8; 32]), k_pack);
    }

    // ── Golden test vector ────────────────────────────────────────────────────
    //
    // A known mnemonic → known values at every layer of the identity pipeline
    // and Layer C1 of the content encryption pipeline.
    //
    // **HOW TO READ THIS TEST**
    // If this test fails after any dependency update or code change, something
    // has silently altered a cryptographic derivation.  Before "fixing" the
    // expected values, understand *why* they changed.  A changed value means:
    //   - identity key: every user's DID changes on recovery → catastrophic
    //   - CEK: every user's encrypted data becomes unreadable → catastrophic
    //
    // The expected bytes below were computed by running `cargo test -- --nocapture`
    // with the `eprintln!` lines active and then committed verbatim.
    // DO NOT update them without a corresponding `decisions.md` entry explaining
    // the migration plan.

    #[test]
    fn identity_pipeline_golden_vector() {
        use crate::did::DidKeyMethod;
        use crate::ed25519::Ed25519Keypair;

        // Layer 2: mnemonic → seed32 (BIP-39 PBKDF2-SHA512, first 32 bytes)
        let seed32 = mnemonic_to_seed32(TEST_MNEMONIC);
        eprintln!("seed32       : {}", hex::encode(seed32));

        // Layer 3: seed32 → Ed25519 scalar (HKDF-SHA256)
        let identity_scalar = derive_identity_key(&seed32);
        eprintln!("identity_key : {}", hex::encode(identity_scalar));

        // Layer 3 → 4: scalar → VerifyingKey → did:key
        let (_priv, pub_bytes) = Ed25519Keypair
            .from_seed(&identity_scalar)
            .expect("from_seed is infallible for 32-byte input");
        let pub_array: [u8; 32] = pub_bytes
            .try_into()
            .expect("ed25519 verifying key is 32 bytes");
        let did = DidKeyMethod::from_public_key_bytes(&pub_array)
            .expect("from_public_key_bytes is infallible for 32-byte input");
        eprintln!("did:key      : {}", did);

        // Layer C1: seed32 → CEK (HKDF-SHA256)
        let cek = derive_cek(&seed32);
        eprintln!("cek          : {}", hex::encode(cek));

        // ── Pinned assertions (committed 2025, pipeline v1) ──────────────────
        // These must NEVER be changed without a decisions.md migration entry.
        assert_eq!(
            hex::encode(seed32),
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70",
            "Layer 2 regression: BIP-39 seed derivation changed"
        );
        assert_eq!(
            hex::encode(identity_scalar),
            "7f78d7425446a03a7663e9ca9182cdd8c9788c47b2ce83f0ee1ff745f1b88acd",
            "Layer 3 regression: HKDF identity key derivation changed"
        );
        assert_eq!(
            did.to_string(),
            "did:key:z6MknkVbxWgHLd4ELf2jDDHvNQ525jA386X6EJjUyxkVDtKu",
            "Layer 4 regression: did:key encoding changed"
        );
        assert_eq!(
            hex::encode(cek),
            "54a3b8692791b538a9936129fd1ac5c07eecadbb3bbcdaefe32abdcc0ed95bb9",
            "Layer C1 regression: CEK derivation changed"
        );
    }
}

#[cfg(test)]
mod migration_seed_tests {
    use super::derive_migration_seed;

    /// Same seed and label give the same key; a bumped label gives an unrelated
    /// one. Those two facts together are the whole migration handle.
    #[test]
    fn a_bumped_label_derives_an_unrelated_key() {
        let root = [0x5au8; 32];
        let v1 = derive_migration_seed(&root, "kotton:migrate:example:v1");
        let v2 = derive_migration_seed(&root, "kotton:migrate:example:v2");
        assert_eq!(v1, derive_migration_seed(&root, "kotton:migrate:example:v1"));
        assert_ne!(v1, v2);
        assert_ne!(v1, root);
        assert_ne!(v2, root);
    }

    /// A different root under the same label is a different key — otherwise the
    /// label, not the mnemonic, would be deciding the identity.
    #[test]
    fn the_root_still_decides_the_key() {
        let label = "kotton:migrate:example:v1";
        assert_ne!(
            derive_migration_seed(&[1u8; 32], label),
            derive_migration_seed(&[2u8; 32], label)
        );
    }
}
