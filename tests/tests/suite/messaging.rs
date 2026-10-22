// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — messaging (RFC-0007).
//!
//! The messaging handlers shipped fully wired — eight verbs, DMs and channels
//! with key distribution — and **entirely untested** (see
//! `DEC-0014`). These are the first tests
//! to exercise them, written before a user surface is built on top, so the
//! surface rests on verified behaviour rather than assumption.
//!
//! Everything here runs on **one node**. Messages are `sh.kotton.message.v1`
//! records encrypted per-recipient and delivered by ordinary record sync, so a
//! full send → inbox → decrypt round trip needs no second device: the user
//! addresses their own DID.
//!
//! # Known broken: messaging predates `did:kel`
//!
//! Most tests below are `#[ignore]`d, and the reason is a **real bug they
//! found**, not a limitation of the tests.
//!
//! Messaging was written against `did:key` identities. Since RFC-0038 landed,
//! `create_user` issues a **`did:kel` AID** — and that is the identity a person
//! would actually share as a contact. Messaging never caught up, which produces
//! three symptoms from one root cause:
//!
//! - `message_send` → *"DID not an Ed25519 key: Unsupported DID method: kel"*.
//!   `pubkey_from_did_str` (`handlers/messages.rs`) only understands `did:key`,
//!   where the key is inside the identifier. A `did:kel` AID must be resolved
//!   against a key event log.
//! - `message_channel_send` → *"no channel key grant found"*. The grant is
//!   stored for the member DID passed to `message_channel_create` (a
//!   `did:kel`), but looked up via `user_did()`, which derives a `did:key` from
//!   the keychain. The two never match.
//! - Anything reached through either of the above.
//!
//! **The fix**, when taken up: resolve `did:kel` via
//! `kotton_identity::kel_store::resolve_current_key_for`, the same
//! machinery grant verification already uses, and make the sender's own DID
//! consistent with the AID the rest of the system issues. Note the honest
//! boundary — resolving *another person's* AID needs their KEL chain locally,
//! which is RFC-0038's unbuilt "8e-other" contact KEL sync. Own-device and
//! self-addressed messaging can work before that; messaging a contact cannot.
//!
//! Un-ignore these as the fix lands. They are written to pass once it does.

use crate::common::TestEnv;
use serde_json::Value;

const USER: &str = "owner";

/// Spawn a daemon and return `(env, own_did)`.
///
/// `create_user` yields the user's DID, which is what messages are addressed
/// to — distinct from `get_node_identity`, which returns the *device* DID.
async fn spawn_with_did() -> (TestEnv, String) {
    let mut env = TestEnv::spawn().await;
    let (did, _fingerprint) = env
        .client
        .create_user(USER, crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user (authenticates the connection)");
    (env, did)
}

/// Pull the encrypted fields out of a stored message record.
///
/// The decrypt verbs take the raw crypto fields rather than a message id, so a
/// client must read the record and hand them back. Worth noting as a shape:
/// it makes the API chatty, and any surface built on it will need this helper.
fn crypto_fields(msg: &Value) -> (String, String, String) {
    let get = |k: &str| {
        msg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("message record missing `{k}`: {msg}"))
            .to_string()
    };
    (get("body"), get("nonce"), get("ephemeral_pub"))
}

// ── Direct messages ───────────────────────────────────────────────────────────

/// The core round trip: encrypt to a DID, store as a record, find it in the
/// inbox, decrypt it back to the original text.
#[tokio::test]
async fn a_direct_message_round_trips_through_the_inbox() {
    let (mut env, me) = spawn_with_did().await;

    let message_id = env
        .client
        .message_send(USER, &me, "the milk is in the fridge", None)
        .await
        .expect("message_send");
    assert!(!message_id.is_empty(), "a stored message has an id");

    let inbox = env.client.message_poll_inbox(USER).await.expect("poll_inbox");
    assert!(!inbox.is_empty(), "the sent message should be in the inbox");

    let (body, nonce, eph) = crypto_fields(&inbox[0]);
    let plaintext = env
        .client
        .message_decrypt_dm(USER, &body, &nonce, &eph)
        .await
        .expect("message_decrypt_dm");
    assert_eq!(plaintext, "the milk is in the fridge");
}

/// The ciphertext must not be the plaintext. Cheap to check, and the failure it
/// would catch — a message stored in the clear — is the one that matters most.
#[tokio::test]
async fn a_stored_message_is_not_readable_without_decrypting() {
    let (mut env, me) = spawn_with_did().await;

    let secret = "divorce lawyer appointment thursday";
    env.client
        .message_send(USER, &me, secret, None)
        .await
        .expect("message_send");

    let inbox = env.client.message_poll_inbox(USER).await.expect("poll_inbox");
    let raw = serde_json::to_string(&inbox).expect("serialize inbox");
    assert!(
        !raw.contains(secret),
        "message bodies must be stored encrypted; found plaintext in the record"
    );
    assert!(
        !raw.contains("lawyer"),
        "no fragment of the body should appear in the stored record"
    );
}

/// A caller-supplied thread id is preserved, so a conversation is something a
/// client can group rather than guess at.
#[tokio::test]
async fn a_supplied_thread_id_is_preserved() {
    let (mut env, me) = spawn_with_did().await;

    let thread = "thread-groceries";
    for body in ["milk", "eggs"] {
        env.client
            .message_send(USER, &me, body, Some(thread.to_string()))
            .await
            .expect("message_send");
    }

    let inbox = env.client.message_poll_inbox(USER).await.expect("poll_inbox");
    let in_thread = inbox
        .iter()
        .filter(|m| m.get("thread_id").and_then(|t| t.as_str()) == Some(thread))
        .count();
    assert_eq!(in_thread, 2, "both messages should carry the thread id");
}

/// A malformed recipient is refused rather than producing a record nobody can
/// read.
///
/// Not ignored: it exercises the rejection path, which never reaches the
/// `did:kel` resolution the others are blocked on.
#[tokio::test]
async fn a_bad_recipient_did_is_refused() {
    let (mut env, _me) = spawn_with_did().await;

    let result = env
        .client
        .message_send(USER, "not-a-did", "hello", None)
        .await;
    assert!(
        result.is_err(),
        "an unparseable recipient DID should fail rather than store an unreadable message"
    );
}

// ── Channels ──────────────────────────────────────────────────────────────────

/// A channel is the household case: several people reading one conversation, so
/// the body is encrypted once under a channel key that members are granted.
///
/// API wart worth noting: `message_channel_create` takes the channel id as an
/// **argument** — the caller invents it — and returns the *key-grant record id*,
/// not the channel. Reading the return value as the channel is the obvious
/// mistake and it fails with a confusing "you may not be a member." A surface
/// built on this should either generate the id daemon-side and return it, or
/// return nothing.
#[tokio::test]
async fn a_channel_message_round_trips_for_a_member() {
    let (mut env, _me) = spawn_with_did().await;

    let channel_did = "channel-household";
    env.client
        .message_channel_create(USER, channel_did)
        .await
        .expect("message_channel_create");

    env.client
        .message_channel_send(USER, channel_did, "dinner at seven")
        .await
        .expect("message_channel_send");

    let history = env
        .client
        .message_channel_history(USER, channel_did, None, 50)
        .await
        .expect("message_channel_history");
    assert!(!history.is_empty(), "the channel should carry its message");

    let body = history[0]
        .get("body")
        .and_then(|v| v.as_str())
        .expect("body");
    let nonce = history[0]
        .get("nonce")
        .and_then(|v| v.as_str())
        .expect("nonce");
    let plaintext = env
        .client
        .message_decrypt_channel(USER, channel_did, body, nonce)
        .await
        .expect("message_decrypt_channel");
    assert_eq!(plaintext, "dinner at seven");
}

#[tokio::test]
async fn channel_history_is_scoped_to_its_own_channel() {
    let (mut env, _me) = spawn_with_did().await;

    let (a, b) = ("channel-a", "channel-b");
    env.client
        .message_channel_create(USER, a)
        .await
        .expect("create a");
    env.client
        .message_channel_create(USER, b)
        .await
        .expect("create b");

    env.client
        .message_channel_send(USER, a, "for channel a")
        .await
        .expect("send a");

    let history_b = env
        .client
        .message_channel_history(USER, b, None, 50)
        .await
        .expect("history b");
    assert!(
        history_b.is_empty(),
        "a message sent to one channel must not appear in another"
    );
}
