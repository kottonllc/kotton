// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's own key, kept and proved
//! (`TASK-a-relay-has-a-key-of-its-own-and-proves-it`, clauses 1, 2 and 5).
//!
//! The key is read off the disk where the relay keeps it, and the proof off a
//! real socket, verified by the same bytes a dialler checks.

use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use kotton_wire::rendezvous::{identity_signing_input, RelayIdentity};

use crate::admission::Admission;
use crate::circuit::Circuits;
use crate::identity::{RelayKey, KEY_FILE};
use crate::rule_tests::{http, state_dir};
use crate::server::{build_router, AppState};
use crate::store::RendezvousStore;

async fn serve(identity: RelayKey, advertise: &str) -> String {
    let state = Arc::new(AppState {
        store: RendezvousStore::new(),
        ttl_secs: 60,
        require_lookup_auth: true,
        admission: Admission::in_memory(&"ab".repeat(32), Default::default()),
        circuits: Circuits::new(),
        identity,
        advertise: advertise.to_owned(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    addr
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2, "{s} is not {N} bytes of hex");
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Clause 1: the first start makes the key beside `rule.json`, readable by the
/// relay's user alone, and a second start finds that key rather than making
/// another — a relay that restarts is the same relay.
#[test]
fn two_starts_keep_one_key_beside_the_rule_and_only_its_user_reads_it() {
    let dir = state_dir();
    // The rule's file is there first, as it is on a relay that already ran.
    Admission::open(&dir).unwrap();

    let first = RelayKey::open(&dir).unwrap().public_hex();
    let path = dir.join(KEY_FILE);
    assert!(path.is_file(), "the key is kept in the state directory");
    assert_eq!(path.parent(), Some(dir.as_path()), "beside the rule, not elsewhere");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the key is the relay user's alone");
    }
    let on_disk = std::fs::read(&path).unwrap();

    let second = RelayKey::open(&dir).unwrap().public_hex();
    assert_eq!(first, second, "a second start keeps the key the first made");
    assert_eq!(std::fs::read(&path).unwrap(), on_disk, "and does not rewrite it");
}

/// A key file that does not read as a key refuses the start: a new key would be
/// the relay silently becoming a stranger to everyone who knows it.
#[test]
fn a_key_that_does_not_read_refuses_the_start_rather_than_making_another() {
    let dir = state_dir();
    std::fs::write(dir.join(KEY_FILE), b"not a key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let err = RelayKey::open(&dir).err().expect("a bad key file refuses the start");
    assert!(err.to_string().contains(KEY_FILE), "the refusal names the file: {err}");
    assert_eq!(std::fs::read(dir.join(KEY_FILE)).unwrap(), b"not a key", "and leaves it for the operator");
}

/// A key file anyone else can read is not the relay's alone, and the relay says
/// so rather than proving a key someone else may hold.
#[cfg(unix)]
#[test]
fn a_key_others_can_read_refuses_the_start() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = state_dir();
    RelayKey::open(&dir).unwrap();
    std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = RelayKey::open(&dir).err().expect("a key others can read refuses the start");
    assert!(err.to_string().contains("0600"), "the refusal says the mode it wants: {err}");
}

/// A key file that is a link, or not a regular file, refuses the start: a link
/// would let whoever can place one in the state directory choose the key the
/// relay proves, or where a first start writes it. Planted by the assessment of
/// 2026-09-29, which found `O_NOFOLLOW` and the regular-file check each
/// removable with every test green.
#[cfg(unix)]
#[test]
fn a_key_file_that_is_a_link_or_not_a_file_refuses_the_start() {
    use std::os::unix::fs::PermissionsExt as _;
    // A link to a good key, kept 0600 elsewhere: followed, it would start.
    let dir = state_dir();
    let elsewhere = state_dir();
    let good = RelayKey::open(&elsewhere).unwrap().public_hex();
    std::os::unix::fs::symlink(elsewhere.join(KEY_FILE), dir.join(KEY_FILE)).unwrap();
    let err = RelayKey::open(&dir).err().expect("a linked key refuses the start");
    assert!(err.to_string().contains(KEY_FILE), "the refusal names the file: {err}");
    assert_eq!(RelayKey::open(&elsewhere).unwrap().public_hex(), good, "and the linked key is untouched");

    // A link to nowhere: followed, the first start would write the key through it.
    let dir = state_dir();
    let target = state_dir().join("planted");
    std::os::unix::fs::symlink(&target, dir.join(KEY_FILE)).unwrap();
    assert!(RelayKey::open(&dir).is_err(), "a dangling link refuses the start");
    assert!(!target.exists(), "and no key is written where it points");

    // A directory where the key should be.
    let dir = state_dir();
    std::fs::create_dir(dir.join(KEY_FILE)).unwrap();
    std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o700)).unwrap();
    let err = RelayKey::open(&dir).err().expect("a directory is not the relay's key");
    assert!(err.to_string().contains("not a regular file"), "the refusal says why: {err}");
}

/// Clause 2: the relay answers its key and a signature over the caller's nonce
/// and the address it announces, and the signature verifies under that key —
/// the same bytes a dialler checks.
#[tokio::test]
async fn a_relay_answers_its_key_and_the_signature_verifies() {
    let dir = state_dir();
    let key = RelayKey::open(&dir).unwrap();
    let expected = key.public_hex();
    for advertise in ["relay.example:7700", ""] {
        let key = RelayKey::open(&dir).unwrap();
        let addr = serve(key, advertise).await;
        let nonce: [u8; 32] = rand::random();
        let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let (status, body) = http(&addr, "GET", &format!("/identity?nonce={nonce_hex}"), None, b"").await;
        assert_eq!(status, 200, "{body}");
        let id: RelayIdentity = serde_json::from_str(&body).unwrap();
        assert_eq!(id.key, expected, "the key it answers is the key it keeps");
        assert_eq!(id.addr, advertise, "the address it announces, empty when none");
        let vk = VerifyingKey::from_bytes(&unhex::<32>(&id.key)).unwrap();
        let sig = Signature::from_bytes(&unhex::<64>(&id.sig));
        vk.verify(&identity_signing_input(&nonce, advertise), &sig)
            .expect("the signature is over the nonce and the announced address");
        // And over those, not others: another nonce, or another address, fails.
        assert!(vk.verify(&identity_signing_input(&[0u8; 32], advertise), &sig).is_err());
        assert!(vk.verify(&identity_signing_input(&nonce, "elsewhere:7700"), &sig).is_err());
    }
}

/// Clause 2's refusal: a nonce that is absent, empty, not hex, an odd number of
/// digits, or longer than the relay signs is refused.
#[tokio::test]
async fn a_nonce_absent_or_not_hex_is_refused() {
    let with_key = serve(RelayKey::from_bytes([7u8; 32]), "").await;
    let too_long = "ab".repeat(kotton_wire::rendezvous::IDENTITY_NONCE_MAX + 1);
    for query in [
        "/identity".to_owned(),
        "/identity?nonce=".to_owned(),
        "/identity?nonce=zz".to_owned(),
        "/identity?nonce=abc".to_owned(),
        "/identity?nonce=0x00".to_owned(),
        "/identity?nonce=%2B1".to_owned(),
        format!("/identity?nonce={too_long}"),
    ] {
        {
            let (status, body) = http(&with_key, "GET", &query, None, b"").await;
            assert_eq!(status, 400, "{query} is refused: {body}");
            assert!(!body.contains("\"sig\""), "nothing is signed for {query}");
        }
    }
    // Upper-case hex is hex.
    let (status, _) = http(&with_key, "GET", "/identity?nonce=ABCD", None, b"").await;
    assert_eq!(status, 200);
}
