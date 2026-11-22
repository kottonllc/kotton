// SPDX-License-Identifier: AGPL-3.0-or-later
//! **A contact pairing's digits reach the shell with no name beside them.**
//!
//! The shell draws `RunnerPairingState::Compare` as the daemon maps it from the
//! `PairShowCode` frame. A contact pairing's prompt carries no label on either
//! side: the person compares the digits with the person who read them the code,
//! and the contact is recorded under the name in the other side's signed
//! identity record, read once the pairing completes. So whichever side alice is
//! on, the `Compare` her shell would be pushed holds `peer_label: None`.
//!
//! Through the daemon and loopback relay of [`super`]: alice's stream is opened
//! by the streamed door's `answer`, and bob is the other half of the ceremony
//! itself (`contact_pairing::run_joiner` or `run_issuer`), saying yes at once.

use super::*;
use crate::agent::ceremony::as_state;
use kotton_wire::runner::RunnerPairingState;

/// Alice's `ContactPairJoin` of `code`, opened through the streamed door's
/// `answer`, as `alice_starts` opens her start.
async fn alice_joins(ctx: &AgentContext, conn: &streamed::ConnSession, code: &str) -> mpsc::Receiver<UserResponse> {
    let (changes, _) = broadcast::channel(16);
    let (_watching, watcher) = watch::channel(kotton_sync::engine::FsWatchState::Watching);
    let vfs = streamed::VfsWatchSource { changes: &changes, watcher: &watcher };
    let request = UserRequest::ContactPairJoin { user_id: "alice".into(), code: SecretText::new(code), as_name: None };
    streamed::answer(ctx, &request, conn, vfs)
        .await
        .expect("answered as a stream")
        .expect("the join starts")
}

/// Bob starts a ceremony under `code` at `relay_url`, on a task of his own.
fn bob_starts(relay_url: &str, code: &str) -> tokio::task::JoinHandle<anyhow::Result<contact_pairing::PairedContact>> {
    let (relay_url, code) = (relay_url.to_string(), code.to_string());
    tokio::spawn(async move {
        let (ours, key) = bob();
        contact_pairing::run_issuer(
            &relay_url,
            &code,
            &ours,
            &key,
            &Yes,
            BOUND,
            &kotton_peer::relay_keys::Presenting::handed(None),
        )
        .await
    })
}

/// The `Compare` alice's shell would be pushed: the `PairShowCode` frame on
/// `stream`, mapped as the ceremony maps every frame it pushes.
async fn compared(stream: &mut mpsc::Receiver<UserResponse>) -> RunnerPairingState {
    loop {
        match next(stream, "the six digits").await {
            frame @ UserResponse::PairShowCode { .. } => {
                return as_state(frame).expect("the digits are a frame the shell is pushed");
            }
            UserResponse::PairFailed { reason } => panic!("the ceremony failed before the digits: {reason}"),
            _ => {}
        }
    }
}

fn holds_no_label(state: RunnerPairingState, side: &str) {
    match state {
        RunnerPairingState::Compare { digits, peer_label } => {
            assert_eq!(digits.len(), 6, "the digits are six, zero-padded: {digits:?}");
            assert_eq!(peer_label, None, "a contact pairing's {side} was shown a name beside the digits");
        }
        other => panic!("the digits mapped to {other:?}, not Compare"),
    }
}

/// **Alice joins a contact pairing bob started.** Her side is the channel's
/// joiner, which reads bob's first frame and makes no label of it.
#[tokio::test]
async fn a_contact_join_compares_with_no_label() {
    let relay = relay::spawn().await;
    let temp = tempfile::tempdir().unwrap();
    let (daemon, conn) = alice_at(temp.path(), &relay.url).await;
    let ctx = daemon.agent_context();
    let code = contact_pairing::generate_code();
    let issuer = bob_starts(&relay.url, &code);
    let mut stream = alice_joins(&ctx, &conn, &code).await;

    holds_no_label(compared(&mut stream).await, "joiner");
    issuer.abort();
}

/// **Alice starts a contact pairing bob joins.** Her side is the channel's
/// issuer, whose confirmer is given no label.
#[tokio::test]
async fn a_contact_start_compares_with_no_label() {
    let relay = relay::spawn().await;
    let temp = tempfile::tempdir().unwrap();
    let (daemon, conn) = alice_at(temp.path(), &relay.url).await;
    let ctx = daemon.agent_context();
    let mut stream = alice_starts(&ctx, &conn).await;
    let code = advertised(&mut stream).await;
    let joiner = bob_joins(&relay.url, &code);

    holds_no_label(compared(&mut stream).await, "issuer");
    joiner.abort();
}
