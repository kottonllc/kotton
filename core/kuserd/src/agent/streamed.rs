// SPDX-License-Identifier: AGPL-3.0-or-later
//! **The verbs whose clients read the answer as a stream, answered as one.**
//!
//! Eleven verbs on the agent's door are read with `send_streaming`: the
//! session user's live events (never another identity's, nor the device's:
//! see [`dispatch::handle_subscribe`]), the VFS watch, every pairing ceremony,
//! the web-shell desk and a browser channel's outbound side. `send_streaming` reads frames until the door closes
//! the connection, and `accept_with_session_streaming` closes it after a
//! `HandlerOutput::Stream` and not after a `Single`: after a `Single` it waits
//! for a next request that a streaming client never sends. So a `Single`
//! answering one of these verbs left both sides waiting, and the client could
//! end only by recognising the frame by name (#120, and #112 at the vault's
//! door).
//!
//! **The type is what ends the stream.** [`answer`] returns
//! `mpsc::Receiver<UserResponse>`, so nothing answering these verbs can say a
//! `Single`: a refusal at the gate, and one a verb makes before it starts, is
//! its one frame and then the end ([`one_frame`]); an `Err` is the door's
//! error frame and then the end. There is no reader-side timeout and no list of
//! frames a client must recognise as last, because neither side has to guess.
//!
//! **One gate, before any verb's own work.** Every verb here once carried its
//! own session check, and they were not the same rule — a gateway's
//! `MintPrincipalSession` session satisfied them, so a `Remote` origin could
//! reach `Local`-tier `DeviceAdd`. The rule now lives in
//! [`dispatch::stream_entry`], the same functions `handle_request`
//! reads (both end in one session guard, `dispatch::session_entry`), and it is
//! read here once, before the verb's opening runs. The opening
//! is a future that has not been polled when the gate reads the request, so a
//! refused verb does nothing at all: no desk is registered, no relay is read,
//! no ceremony reserves a code.
//!
//! **The gate reads the session once, and hands the user on.** For a verb that
//! requires a session the gate's answer is the live session user
//! ([`dispatch::Entry::Session`]) or the refusal. The two verbs that act as
//! that user, `SubscribeEvents` and `BrowserOutbound`, take it from the gate
//! as an [`Opening::AsUser`], built from that user once the gate has passed it;
//! neither verb reads the session again, so neither has an answer of its own
//! for a session that ended between two reads. The stream's driver does read it
//! again, by `while_live`, to end the stream when the session ends.
//!
//! **A stream lives as long as the session that opened it (#397).** The gate's
//! read decides whether a stream opens; it cannot decide whether one that
//! opened may go on. So every stream the gate passed with a session is driven
//! through [`while_live`], whatever the verb, and that reads the session again
//! before each frame and on a tick while none is passing. A revoked or expired
//! session ends the stream with the gate's own refusal, `NoActiveSession`.
//! A session-less verb (bootstrap) was passed no session and has none to
//! outlive.

use super::{browser_channel, dispatch, AgentContext, ConnSessionData};
use kotton_ipc::HandlerOutput;
use kotton_wire::ipc::{UserRequest, UserResponse};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc, watch};

/// The connection's session slot, as the acceptor hands it to the handler.
pub(super) type ConnSession = Arc<Mutex<Option<ConnSessionData>>>;

/// Where a `VfsWatch` subscribes: the daemon's change broadcast, and the state
/// of the watcher thread that feeds it.
pub(super) struct VfsWatchSource<'a> {
    pub(super) changes: &'a broadcast::Sender<kotton_sync::engine::VfsChangeFrame>,
    pub(super) watcher: &'a watch::Receiver<kotton_sync::engine::FsWatchState>,
}

/// A streamed verb's work, not yet started.
type Run<'a> = Pin<Box<dyn Future<Output = io::Result<mpsc::Receiver<UserResponse>>> + Send + 'a>>;

/// A streamed verb's opening, not yet started: its work, or, for a verb that
/// acts as the session user, its work once handed that user.
enum Opening<'a> {
    Ready(Run<'a>),
    AsUser(Box<dyn FnOnce(String) -> Run<'a> + Send + 'a>),
}

/// The door's answer to `request` when its client reads it as a stream, and
/// `None` when it does not.
///
/// The gate is read first; a refusal is answered through [`one_frame`], so
/// the client's `recv` gives the refusal and then `None`. What it passes it
/// hands to the opening.
pub(super) async fn answer(
    ctx: &AgentContext,
    request: &UserRequest,
    conn_session: &ConnSession,
    vfs: VfsWatchSource<'_>,
) -> Option<io::Result<mpsc::Receiver<UserResponse>>> {
    use dispatch::Entry;
    let opening = opening(ctx, request, vfs)?;
    let (session, run) = match (dispatch::stream_entry(&ctx.sessions, conn_session, request), opening) {
        // Dropped unpolled: the verb's opening never ran.
        (Entry::Refused(refusal), _) => return Some(Ok(one_frame(*refusal))),
        (Entry::Sessionless, Opening::Ready(run)) => (None, run),
        (Entry::Session(user), Opening::Ready(run)) => (Some(user), run),
        (Entry::Session(user), Opening::AsUser(run)) => (Some(user.clone()), run(user.into_string())),
        // Impossible: both `AsUser` verbs are `requires_session()`, so the gate
        // passes them as `Session` or refuses them (pinned by
        // `the_gate_hands_a_session_verb_the_user_it_read`). An error for the
        // door to frame, not a second answer to a missing session. Not made
        // unrepresentable: whether a verb requires a session is a property of
        // the request's value (`requires_session`, and `AppInstall` turns on a
        // field), not of a type the opening could be written against.
        (Entry::Sessionless, Opening::AsUser(_)) => {
            return Some(Err(io::Error::other(
                "the gate handed no session user to a verb that requires one",
            )))
        }
    };
    let stream = run.await;
    Some(match session {
        // A session-less verb (bootstrap) was passed no session, so it has
        // none to outlive.
        None => stream,
        Some(session) => stream.map(|frames| while_live(Arc::clone(&ctx.sessions), session, frames)),
    })
}

/// How long an idle stream may outlive its session: the period at which
/// [`while_live`] reads the session when no frame is passing.
pub(super) const LIVENESS_TICK: std::time::Duration = std::time::Duration::from_secs(1);

/// `frames`, for as long as the session that opened them is live (#397).
///
/// The one rule for a streamed verb's lifetime, and the one place it is
/// applied: every stream a session opens is driven through here, whatever
/// the verb. Before each frame is passed on, and every [`LIVENESS_TICK`] while
/// none is, the session is read again ([`dispatch::SessionUser::is_still_live`],
/// the gate's own `live_user`). A session that has gone, revoked or past its
/// expiry, ends the stream with the gate's refusal, `NoActiveSession`, as its
/// one last frame: the frame that was waiting is not delivered, and the verb's
/// receiver is dropped, so its sender sees the stream has ended. The verb's own
/// task is not ended from here, only told, and what it does on being told is
/// its own: every ceremony ends on its sender closing, before the yes
/// (`StreamingConfirmer::unless_abandoned`, #436), and a web-shell desk closes.
///
/// The frame is checked as it is taken, not as it was made, and the outgoing
/// channel holds one, so nothing is passed on that was taken after the
/// session ended. The client going away ends it too, and drops the verb's
/// receiver as the door dropping it directly did.
pub(super) fn while_live(
    sessions: kotton_session::service::tokens::SessionMap,
    session: dispatch::SessionUser,
    mut frames: mpsc::Receiver<UserResponse>,
) -> mpsc::Receiver<UserResponse> {
    let (tx, rx) = mpsc::channel::<UserResponse>(1);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(LIVENESS_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let frame = tokio::select! {
                frame = frames.recv() => frame,
                _ = tick.tick() => {
                    if session.is_still_live(&sessions) {
                        continue;
                    }
                    let _ = tx.send(UserResponse::NoActiveSession).await;
                    return;
                }
                () = tx.closed() => return,
            };
            let Some(frame) = frame else { return };
            if !session.is_still_live(&sessions) {
                let _ = tx.send(UserResponse::NoActiveSession).await;
                return;
            }
            if tx.send(frame).await.is_err() {
                return;
            }
        }
    });
    rx
}

/// `frame`, and then the end of the stream.
fn one_frame(frame: UserResponse) -> mpsc::Receiver<UserResponse> {
    HandlerOutput::Single(frame).into_stream()
}

/// What each streamed verb does once the gate has passed it, and `None` for a
/// request that is not one of them.
///
/// Building an arm runs nothing. Each is an `async` block or an `async fn`'s
/// future, which does no work until [`answer`] awaits it; the two `AsUser`
/// arms are closures that return one, built only once the gate has handed
/// them the user.
fn opening<'a>(
    ctx: &'a AgentContext,
    request: &'a UserRequest,
    vfs: VfsWatchSource<'a>,
) -> Option<Opening<'a>> {
    use kotton_device::users::residency::Residency;
    use kotton_device::users::{contacts, pairing};
    let residency = || Arc::new(ctx.users.clone()) as Arc<dyn Residency>;
    Some(Opening::Ready(match request {
        // The session user's events only (#393): built from the user the gate
        // read, never the device's bus and never a second read of the session.
        UserRequest::SubscribeEvents { category, level } => {
            return Some(Opening::AsUser(Box::new(move |user_id| {
                Box::pin(async move {
                    Ok(dispatch::handle_subscribe(&ctx.runtime, user_id, category.clone(), level.clone()).await)
                })
            })))
        }
        UserRequest::VfsWatch { user_id, paths } => Box::pin(async move {
            Ok(dispatch::handle_vfs_watch(
                &ctx.base,
                user_id.clone(),
                paths.clone(),
                vfs.changes.subscribe(),
                vfs.watcher.clone(),
            )
            .await)
        }),
        UserRequest::GatewayEnroll {
            user_id,
            code,
            ttl_seconds,
        } => Box::pin(pairing::handle_gateway_enroll(
            Arc::clone(&ctx.runtime),
            residency(),
            Arc::clone(&ctx.db),
            Arc::clone(&ctx.device_db),
            Arc::clone(&ctx.paired_keys),
            Arc::clone(&ctx.pending_confirms),
            user_id.clone(),
            code.expose().to_owned(),
            *ttl_seconds,
        )),
        UserRequest::DeviceAdd {
            user_id,
            as_name,
            ttl_seconds,
            port,
            posture,
        } => Box::pin(pairing::handle_device_add(
            Arc::clone(&ctx.runtime),
            residency(),
            Arc::clone(&ctx.db),
            Arc::clone(&ctx.device_db),
            Arc::clone(&ctx.paired_keys),
            Arc::clone(&ctx.pending_confirms),
            user_id.clone(),
            as_name.clone(),
            *ttl_seconds,
            *port,
            *posture,
        )),
        // A contact ceremony: two people, a spoken code, this node's relay.
        // Both require a session, and the gate holds the `user_id` they name
        // to that session's user (`target_user_id`), so a contact is admitted
        // only into the store of the person whose session asked.
        UserRequest::ContactPairStart {
            user_id,
            as_name,
            ttl_seconds,
        } => Box::pin(contacts::handle_contact_pair_start(
            Arc::clone(&ctx.runtime),
            residency(),
            Arc::clone(&ctx.pending_confirms),
            user_id.clone(),
            as_name.clone(),
            *ttl_seconds,
        )),
        UserRequest::ContactPairJoin {
            user_id,
            code,
            as_name,
        } => Box::pin(contacts::handle_contact_pair_join(
            Arc::clone(&ctx.runtime),
            residency(),
            Arc::clone(&ctx.pending_confirms),
            user_id.clone(),
            code.expose().to_owned(),
            as_name.clone(),
        )),
        // The transport-reversed pair.
        UserRequest::DeviceAdmit {
            user_id,
            code,
            ttl_seconds,
            posture,
            operator_of,
        } => Box::pin(async move {
            // An admit held to a vault this person operates: the key is the
            // credential's, read here and nowhere else.
            let pinned = match operator_of {
                None => None,
                Some(vault) => match super::operator::pinned_vault(&ctx.users, user_id, vault) {
                    Ok(p) => Some(p),
                    Err(message) => return Ok(one_frame(UserResponse::Error { message })),
                },
            };
            pairing::handle_device_admit(
                Arc::clone(&ctx.runtime),
                residency(),
                Arc::clone(&ctx.db),
                Arc::clone(&ctx.device_db),
                Arc::clone(&ctx.paired_keys),
                Arc::clone(&ctx.pending_confirms),
                user_id.clone(),
                code.expose().to_owned(),
                *ttl_seconds,
                *posture,
                pinned,
            )
            .await
        }),
        UserRequest::DeviceInvite {
            user_id,
            ttl_seconds,
            as_name,
        } => Box::pin(async move {
            // An invite meets at this device's relay, and where a device sets
            // one is its own verb, so this is where its absence is refused;
            // the ceremony is handed the URL checked here and reads none of
            // its own.
            let relay_url = ctx.runtime.reachability().nat().relay_url;
            if relay_url.is_empty() {
                return Ok(one_frame(UserResponse::Error {
                    message: super::NO_RELAY_FOR_AN_INVITE.to_string(),
                }));
            }
            // The relay's invited key, carried only when this person holds it
            // as that relay's operator: another person's keys on this machine
            // are never handed on.
            let offered = kotton_peer::relay_keys::relay_id(
                ctx.runtime.reachability().nat().relay_key.as_deref(),
            )
            .and_then(|r| ctx.runtime.reachability().relay_keys().offer_for(user_id, &r));
            pairing::handle_device_invite(
                Arc::clone(&ctx.runtime),
                relay_url,
                offered,
                residency(),
                Arc::clone(&ctx.db),
                Arc::clone(&ctx.device_db),
                Arc::clone(&ctx.sessions),
                Arc::clone(&ctx.paired_keys),
                Arc::clone(&ctx.pending_confirms),
                user_id.clone(),
                *ttl_seconds,
                as_name.clone(),
                pairing::JoinPolicy::Any,
            )
            .await
        }),
        UserRequest::DeviceJoin {
            user_id,
            code,
            as_name,
        } => Box::pin(pairing::handle_device_join(
            Arc::clone(&ctx.runtime),
            residency(),
            Arc::clone(&ctx.db),
            Arc::clone(&ctx.device_db),
            Arc::clone(&ctx.sessions),
            Arc::clone(&ctx.paired_keys),
            Arc::clone(&ctx.pending_confirms),
            user_id.clone(),
            code.expose().to_owned(),
            as_name.clone(),
            pairing::JoinPolicy::Any,
        )),
        // The operator opens a desk and waits for a browser to pair.
        // `Local`-tier, so the gate is what makes this connection the human at
        // the screen: a browser with an unknown key is admitted only while a
        // desk is open, and only a `Local` origin can open one.
        UserRequest::WebShellPair { user_id, .. } => Box::pin(async move {
            let (tx, rx) = mpsc::channel::<UserResponse>(16);
            let (desk, left) = browser_channel::Desk::open(tx.clone());
            ctx.browser_desks.lock().await.insert(user_id.clone(), desk);
            // Announce the desk is registered before any browser could reach
            // it, so a caller need not race the insertion.
            let _ = tx.send(UserResponse::WebShellPairReady).await;
            // The desk closes with its stream (#436): revoked, expired or gone,
            // nobody is at the screen, so no new browser may be admitted at
            // it. A browser already comparing digits at it is declined by its
            // confirmer, which watches the same sender.
            //
            // The watcher's sender must not outlive the desk's place in the
            // table: a desk replaced by a later `WebShellPair` ends its stream
            // by losing the table's sender, so the watcher ends too, then
            // (`left`), and drops its own.
            let desks = Arc::clone(&ctx.browser_desks);
            let user_id = user_id.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = tx.closed() => {
                        let mut desks = desks.lock().await;
                        // Only this desk: a later `WebShellPair` may have replaced it.
                        if desks.get(&user_id).is_some_and(|open| open.tx.same_channel(&tx)) {
                            desks.remove(&user_id);
                        }
                    }
                    _ = left => {}
                }
            });
            Ok(rx)
        }),
        // The channel's other direction. This connection becomes the side that
        // carries frames no call is waiting on, and holds it for as long as
        // `khttpd` holds the browser's socket. When it ends, so does the
        // channel.
        UserRequest::BrowserOutbound { channel } => return Some(Opening::AsUser(Box::new(move |user_id| Box::pin(async move {
            let key = browser_channel::local_key(&user_id, Some(channel));
            let (tx, rx) = mpsc::channel::<UserResponse>(256);
            // Say so on the stream itself, first, before anything else can be
            // on it. The gateway opens this connection and the one carrying
            // calls independently, so without a mark it cannot know the node
            // has attached this side — and a frame arriving before it attached
            // would be answered inline, to a gateway no longer reading
            // replies. `khttpd` waits for this.
            let _ = tx.send(UserResponse::Ok).await;
            browser_channel::attach_outbound(ctx, key.clone(), tx).await;
            // Watch the stream rather than the socket: the receiver is dropped
            // when the caller goes away, which closes the sender, which is the
            // signal the browser is gone.
            let ctx_for_close = ctx.clone();
            let (out_tx, out_rx) = mpsc::channel::<UserResponse>(256);
            tokio::spawn(async move {
                let mut rx = rx;
                while let Some(frame) = rx.recv().await {
                    if out_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                browser_channel::close_channel(&ctx_for_close, &key).await;
            });
            Ok(out_rx)
        })))),
        _ => return None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::sessions;
    use kotton_ipc::{ChannelAcceptor, IpcClient};
    use kotton_sys::ipc::IpcEndpoint;
    use kotton_wire::ipc::{Principal, SecretText};
    use std::time::Duration;

    /// Every verb this door answers as a stream, as its clients send it.
    fn every_streamed_verb() -> Vec<UserRequest> {
        let alice = || "alice".to_string();
        let code = || SecretText::new("amber-otter-kite");
        vec![
            UserRequest::SubscribeEvents { category: None, level: None },
            UserRequest::VfsWatch { user_id: alice(), paths: vec![] },
            UserRequest::GatewayEnroll { user_id: alice(), code: code(), ttl_seconds: 60 },
            UserRequest::DeviceAdd {
                user_id: alice(),
                as_name: None,
                ttl_seconds: 60,
                port: 0,
                posture: Default::default(),
            },
            UserRequest::ContactPairStart { user_id: alice(), as_name: None, ttl_seconds: 60 },
            UserRequest::ContactPairJoin { user_id: alice(), code: code(), as_name: None },
            UserRequest::DeviceAdmit {
                user_id: alice(),
                code: code(),
                ttl_seconds: 60,
                posture: Default::default(),
                operator_of: None,
            },
            UserRequest::DeviceInvite { user_id: alice(), ttl_seconds: 60, as_name: None },
            UserRequest::DeviceJoin { user_id: alice(), code: code(), as_name: None },
            UserRequest::WebShellPair { user_id: alice(), ttl_seconds: 60 },
            UserRequest::BrowserOutbound { channel: "c".to_string() },
        ]
    }

    /// A gateway acting as itself: its token is mint-only, so the gate refuses
    /// it every verb here but `BrowserOutbound`, which is on the mint-only list
    /// and which the gate's session guard then refuses, for want of a live
    /// session.
    fn a_gateway() -> ConnSessionData {
        let principal = Principal::Gateway;
        ConnSessionData {
            origin: principal.trust_origin(),
            token: "no-such-session".to_string(),
            scope: None,
            cek_available: false,
            principal,
            browser_key: None,
        }
    }

    /// What the door says to [`a_gateway`] for `request`: the gate's refusal.
    /// `BrowserOutbound` is on the mint-only list, so the gate's next guard
    /// answers it, for want of a live session; the arm answers nothing of its own.
    fn refusal_to_a_gateway(request: &UserRequest) -> UserResponse {
        match request {
            UserRequest::BrowserOutbound { .. } => UserResponse::NoActiveSession,
            _ => UserResponse::NotAllowed,
        }
    }

    /// A directory for the daemon's state and, on Unix, its sockets: under
    /// `/tmp` there, so a socket path stays within the platform's length limit.
    /// On Windows the door is a named pipe and nothing joins this directory, which
    /// is the reason this file is on kotton-common's socket allow list
    /// (`paths::tests::a_socket_joined_onto_the_temp_dir_asks_whether_it_fits`).
    fn a_dir() -> tempfile::TempDir {
        #[cfg(unix)]
        let dir = tempfile::tempdir_in("/tmp");
        #[cfg(windows)]
        let dir = tempfile::tempdir();
        dir.expect("a temporary directory")
    }

    /// A door's endpoint as each platform makes one, as kuserd's other socket
    /// tests do: a socket named `name` in `dir` on Unix, a uniquely named pipe
    /// on Windows.
    #[cfg_attr(windows, allow(unused_variables))]
    fn an_endpoint(dir: &std::path::Path, name: &str) -> IpcEndpoint {
        #[cfg(unix)]
        let endpoint = IpcEndpoint::UnixSocket(dir.join(name));
        #[cfg(windows)]
        let endpoint = IpcEndpoint::NamedPipe(format!("kotton-test-{}", uuid::Uuid::new_v4().simple()));
        endpoint
    }

    /// A booted daemon's context, with nobody resident and no relay.
    async fn a_daemon(base: &std::path::Path) -> super::super::DeviceDaemon {
        let keychain: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            Arc::new(kotton_secret::MemorySecrets::new());
        super::super::DeviceDaemon::new_with_base_secrets_and_relay(
            base.to_path_buf(),
            an_endpoint(base, "kuserd.sock"),
            keychain,
            kotton_device::config::db::RelayChoice::None,
        )
        .await
        .expect("the daemon boots")
    }

    /// This module's answer, at a door of its own on a real socket, with every
    /// connection holding what `session` makes, as if it had authenticated.
    async fn a_door(ctx: AgentContext, endpoint: IpcEndpoint, session: fn() -> Option<ConnSessionData>) {
        let server = ChannelAcceptor::<UserRequest, UserResponse>::listen(endpoint).await.expect("bind");
        let (changes, _) = broadcast::channel(16);
        let (_watching, watcher) = watch::channel(kotton_sync::engine::FsWatchState::Watching);
        let _ = server
            .accept_with_session_streaming(move |request, _caller, conn_session: ConnSession| {
                let ctx = ctx.clone();
                let changes = changes.clone();
                let watcher = watcher.clone();
                async move {
                    *conn_session.lock().unwrap() = session();
                    let vfs = VfsWatchSource { changes: &changes, watcher: &watcher };
                    match answer(&ctx, &request, &conn_session, vfs).await {
                        Some(stream) => stream.map(HandlerOutput::Stream),
                        None => Ok(HandlerOutput::Single(UserResponse::Error {
                            message: "not a streamed verb".to_string(),
                        })),
                    }
                }
            })
            .await;
    }

    async fn a_client(endpoint: &IpcEndpoint) -> IpcClient<UserRequest, UserResponse> {
        for _ in 0..100 {
            if let Ok(c) = IpcClient::connect(endpoint.clone()).await {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the door never listened");
    }

    /// Send `request` as its clients do and read the stream to its end: the
    /// frames it carried, or a panic if it had not ended within five seconds.
    async fn read_to_the_end(endpoint: &IpcEndpoint, request: &UserRequest) -> Vec<UserResponse> {
        let mut rx = a_client(endpoint).await.send_streaming(request).await.expect("sent");
        let mut frames = vec![];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => return frames,
                Err(_) => panic!(
                    "{}: the stream had not ended 5 s after {frames:?}",
                    request.variant_name()
                ),
            }
        }
    }

    /// **A refused streaming request is its refusal, and then the end (#120).**
    ///
    /// Each verb a client reads with `send_streaming` is sent over a real
    /// socket by a mint-only gateway, which the gate refuses, and `recv`
    /// returns the refusal and then `None`. Before this, the refusal was a
    /// `Single` and the door waited on the connection for a next request: the
    /// client had the refusal and no end.
    #[tokio::test]
    async fn a_refused_streaming_request_is_its_refusal_and_then_the_end() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let endpoint = an_endpoint(dir.path(), "door.sock");
        let door = tokio::spawn(a_door(daemon.agent_context(), endpoint.clone(), || Some(a_gateway())));

        for request in every_streamed_verb() {
            let said = format!("{:?}", read_to_the_end(&endpoint, &request).await);
            let refusal = refusal_to_a_gateway(&request);
            assert_eq!(said, format!("{:?}", vec![refusal]), "{}", request.variant_name());
        }
        door.abort();
    }

    /// **A refused streamed verb leaves nothing behind (#130).**
    ///
    /// [`opening`] builds every verb's future before the gate reads the
    /// request, and [`answer`] drops it unpolled on a refusal; that is what
    /// makes a refused verb do nothing. The compiler does not hold it: an arm
    /// whose argument expressions did the verb's work would build, and its
    /// stream would still end after the refusal, so the test above would stay
    /// green. This holds it. Each verb is refused for a mint-only gateway, as
    /// above, and the two tables a verb that ran would have written are empty
    /// after it: the open web-shell desks, and the ceremonies waiting on a
    /// confirmation.
    #[tokio::test]
    async fn a_refused_streamed_verb_leaves_no_desk_and_no_pending_ceremony() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        let conn_session: ConnSession = Arc::new(Mutex::new(Some(a_gateway())));
        let (changes, _) = broadcast::channel(16);
        let (_watching, watcher) = watch::channel(kotton_sync::engine::FsWatchState::Watching);

        for request in every_streamed_verb() {
            let verb = request.variant_name();
            let vfs = VfsWatchSource { changes: &changes, watcher: &watcher };
            let mut stream = answer(&ctx, &request, &conn_session, vfs)
                .await
                .unwrap_or_else(|| panic!("{verb}: not answered as a stream"))
                .unwrap_or_else(|e| panic!("{verb}: {e}"));
            let mut frames = vec![];
            loop {
                match tokio::time::timeout(Duration::from_secs(5), stream.recv()).await {
                    Ok(Some(frame)) => frames.push(frame),
                    Ok(None) => break,
                    Err(_) => panic!("{verb}: the stream had not ended 5 s after {frames:?}"),
                }
            }
            let refusal = refusal_to_a_gateway(&request);
            assert_eq!(format!("{frames:?}"), format!("{:?}", vec![refusal]), "{verb}");
            assert!(ctx.browser_desks.lock().await.is_empty(), "{verb}: refused, and a desk is open");
            assert!(
                ctx.pending_confirms.lock().await.is_empty(),
                "{verb}: refused, and a ceremony is waiting on a confirmation"
            );
        }
    }

    /// **A verb's own refusal ends its stream as the gate's does.** An invite
    /// on a device with no relay passes the gate (it is session-less
    /// bootstrap) and is refused by the verb before any ceremony starts.
    #[tokio::test]
    async fn an_invite_refused_for_want_of_a_relay_is_its_refusal_and_then_the_end() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let endpoint = an_endpoint(dir.path(), "door.sock");
        let door = tokio::spawn(a_door(daemon.agent_context(), endpoint.clone(), || None));

        let request = UserRequest::DeviceInvite { user_id: "alice".into(), ttl_seconds: 60, as_name: None };
        let frames = read_to_the_end(&endpoint, &request).await;
        let [UserResponse::Error { message }] = frames.as_slice() else {
            panic!("expected the one refusal, got {frames:?}");
        };
        assert_eq!(message, super::super::NO_RELAY_FOR_AN_INVITE);
        door.abort();
    }

    /// **A session's event stream carries only that session user's events
    /// (#393).** On a device holding two identities, alice subscribes; bob's
    /// event and a device event are published, then one of alice's as a
    /// sentinel. The bus is one channel in order, so whatever the stream would
    /// have delivered before the sentinel it delivers first: the first frame
    /// being the sentinel is the proof the other two were not streamed.
    #[tokio::test]
    async fn a_session_streams_only_its_own_users_events() {
        use kotton_diag::service::{Event, EventCategory, EventLevel};
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        sessions::insert(&ctx.sessions, "alice-session".to_string(), "alice".to_string());
        let principal = Principal::LocalOperator;
        let conn_session: ConnSession = Arc::new(Mutex::new(Some(ConnSessionData {
            origin: principal.trust_origin(),
            token: "alice-session".to_string(),
            scope: None,
            cek_available: true,
            principal,
            browser_key: None,
        })));
        let (changes, _) = broadcast::channel(16);
        let (_watching, watcher) = watch::channel(kotton_sync::engine::FsWatchState::Watching);
        let vfs = VfsWatchSource { changes: &changes, watcher: &watcher };
        let request = UserRequest::SubscribeEvents { category: None, level: None };
        let mut stream = answer(&ctx, &request, &conn_session, vfs)
            .await
            .expect("answered as a stream")
            .expect("subscribed");

        let bus = ctx.runtime.event_bus();
        let (cat, lvl) = (EventCategory::System, EventLevel::Info);
        bus.publish(Event::for_user("bob", cat, lvl, "bob's event")).expect("published");
        bus.publish(Event::new(cat, lvl, "the device's event")).expect("published");
        bus.publish(Event::for_user("alice", cat, lvl, "alice's event")).expect("published");

        let first = tokio::time::timeout(Duration::from_secs(5), stream.recv())
            .await
            .expect("a frame within five seconds");
        let Some(UserResponse::EventStream { event }) = first else {
            panic!("expected an event frame, got {first:?}");
        };
        assert_eq!(
            event.message, "alice's event",
            "alice's stream delivered an event that is not hers before her own"
        );
    }

    /// **The gate hands a verb that requires a session the user it read (#400).**
    ///
    /// `SubscribeEvents` and `BrowserOutbound` require a session, and the gate
    /// answers them with the live session user, the one read their arms take
    /// instead of reading again. A verb that does not require one is passed
    /// with nothing handed, and a session that has gone is the gate's one
    /// refusal.
    #[tokio::test]
    async fn the_gate_hands_a_session_verb_the_user_it_read() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        sessions::insert(&ctx.sessions, "alice-session".to_string(), "alice".to_string());
        let principal = Principal::LocalOperator;
        let session = |token: &str| -> Mutex<Option<ConnSessionData>> {
            Mutex::new(Some(ConnSessionData {
                origin: principal.trust_origin(),
                token: token.to_string(),
                scope: None,
                cek_available: true,
                principal: principal.clone(),
                browser_key: None,
            }))
        };

        for request in [
            UserRequest::SubscribeEvents { category: None, level: None },
            UserRequest::BrowserOutbound { channel: "c".into() },
        ] {
            match dispatch::stream_entry(&ctx.sessions, &session("alice-session"), &request) {
                dispatch::Entry::Session(user) => assert_eq!(user.as_str(), "alice", "{}", request.variant_name()),
                _ => panic!("{}: the gate did not hand on the session user", request.variant_name()),
            }
            let gone = dispatch::stream_entry(&ctx.sessions, &session("no-such-session"), &request);
            assert!(
                matches!(gone, dispatch::Entry::Refused(r) if matches!(*r, UserResponse::NoActiveSession)),
                "{}: a session that has gone is the gate's refusal",
                request.variant_name()
            );
        }

        let invite = UserRequest::DeviceInvite { user_id: "alice".into(), ttl_seconds: 60, as_name: None };
        let passed = dispatch::stream_entry(&ctx.sessions, &Mutex::new(None), &invite);
        assert!(matches!(passed, dispatch::Entry::Sessionless), "a session-less verb hands nothing on");
    }

    /// Alice's connection, holding her live session: the token the gate reads.
    fn alices_connection(ctx: &AgentContext) -> ConnSession {
        sessions::insert(&ctx.sessions, "alice-session".to_string(), "alice".to_string());
        let principal = Principal::LocalOperator;
        Arc::new(Mutex::new(Some(ConnSessionData {
            origin: principal.trust_origin(),
            token: "alice-session".to_string(),
            scope: None,
            cek_available: true,
            principal,
            browser_key: None,
        })))
    }

    /// `request` answered on `conn_session` as a stream, opened.
    async fn opened(ctx: &AgentContext, conn_session: &ConnSession, request: &UserRequest) -> mpsc::Receiver<UserResponse> {
        let (changes, _) = broadcast::channel(16);
        let (_watching, watcher) = watch::channel(kotton_sync::engine::FsWatchState::Watching);
        let vfs = VfsWatchSource { changes: &changes, watcher: &watcher };
        answer(ctx, request, conn_session, vfs)
            .await
            .expect("answered as a stream")
            .expect("opened")
    }

    /// The frames `stream` carries to its end, or a panic if it had not ended
    /// within five seconds.
    async fn to_the_end(mut stream: mpsc::Receiver<UserResponse>) -> Vec<UserResponse> {
        let mut frames = vec![];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.recv()).await {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => return frames,
                Err(_) => panic!("the stream had not ended 5 s after {frames:?}"),
            }
        }
    }

    /// One of alice's own events, which her live stream would carry.
    fn publish_one_of_alices(ctx: &AgentContext) {
        use kotton_diag::service::{Event, EventCategory, EventLevel};
        ctx.runtime
            .event_bus()
            .publish(Event::for_user("alice", EventCategory::System, EventLevel::Info, "alice's event"))
            .expect("published");
    }

    /// **A revoked session ends the streams it opened (#397).**
    ///
    /// Alice subscribes to her events, then logs out (`remove_user`, the path
    /// that drops every token she holds), and one of her own events is
    /// published. The session was checked when the stream opened and is gone
    /// now, so the stream carries the gate's one refusal and ends: the event
    /// is not delivered.
    #[tokio::test]
    async fn a_revoked_session_ends_its_event_stream_without_delivering() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        let conn_session = alices_connection(&ctx);
        let stream = opened(&ctx, &conn_session, &UserRequest::SubscribeEvents { category: None, level: None }).await;

        sessions::remove_user(&ctx.sessions, "alice");
        publish_one_of_alices(&ctx);

        let frames = to_the_end(stream).await;
        assert_eq!(
            format!("{frames:?}"),
            format!("{:?}", vec![UserResponse::NoActiveSession]),
            "a stream whose session was revoked delivered past it"
        );
    }

    /// **An expired session ends the streams it opened, as a revoked one does.**
    ///
    /// The clock passing a session's expiry is what `live_user` reads as
    /// expired, so the session's `expires_at` is moved into the past rather
    /// than waiting twelve hours for it.
    #[tokio::test]
    async fn an_expired_session_ends_its_event_stream_without_delivering() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        let conn_session = alices_connection(&ctx);
        let stream = opened(&ctx, &conn_session, &UserRequest::SubscribeEvents { category: None, level: None }).await;

        ctx.sessions.write().unwrap().get_mut("alice-session").expect("alice's session").expires_at =
            Some(kotton_common::time::now_secs() - 1);
        publish_one_of_alices(&ctx);

        let frames = to_the_end(stream).await;
        assert_eq!(
            format!("{frames:?}"),
            format!("{:?}", vec![UserResponse::NoActiveSession]),
            "a stream whose session expired delivered past it"
        );
    }

    /// **An idle stream ends too, within the liveness tick.** The stream sits
    /// open and live past its first tick, then the session is revoked and
    /// nothing is published, so no frame is pending for a check to ride on;
    /// the stream still ends with the refusal, within a tick and a margin.
    #[tokio::test]
    async fn a_revoked_session_ends_an_idle_stream() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        let conn_session = alices_connection(&ctx);
        let stream = opened(&ctx, &conn_session, &UserRequest::SubscribeEvents { category: None, level: None }).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        sessions::remove_user(&ctx.sessions, "alice");
        let revoked = std::time::Instant::now();

        let frames = to_the_end(stream).await;
        assert_eq!(format!("{frames:?}"), format!("{:?}", vec![UserResponse::NoActiveSession]));
        assert!(
            revoked.elapsed() < LIVENESS_TICK + Duration::from_secs(2),
            "an idle stream outlived its session by {:?}",
            revoked.elapsed()
        );
    }

    /// **A desk closes with its stream (#436).** Alice opens a web-shell desk,
    /// and it is registered; her session is revoked, the stream ends with the
    /// gate's refusal, and the desk is gone with it, so no new browser can be
    /// admitted at a screen nobody is watching. Red before #436: the desk's
    /// sender stayed in the table after its stream had ended.
    #[tokio::test]
    async fn a_revoked_session_closes_its_desk() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        let conn_session = alices_connection(&ctx);
        let mut stream = opened(&ctx, &conn_session, &UserRequest::WebShellPair { user_id: "alice".into(), ttl_seconds: 60 }).await;
        let ready = tokio::time::timeout(Duration::from_secs(5), stream.recv()).await.expect("a first frame");
        assert!(matches!(ready, Some(UserResponse::WebShellPairReady)), "{ready:?}");
        assert!(ctx.browser_desks.lock().await.contains_key("alice"), "the desk is open");

        sessions::remove_user(&ctx.sessions, "alice");
        let frames = to_the_end(stream).await;
        assert_eq!(format!("{frames:?}"), format!("{:?}", vec![UserResponse::NoActiveSession]));
        let closed = std::time::Instant::now();
        while ctx.browser_desks.lock().await.contains_key("alice") {
            assert!(closed.elapsed() < Duration::from_secs(5), "the desk outlived its stream");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// **A replaced desk ends its stream.** Alice opens desk A, then desk B,
    /// which takes A's place in the table. A's stream ends, as it did when
    /// the table held A's only sender, so the screen that opened A is not
    /// left waiting on a desk nobody can reach; B stays open. Red on the
    /// first commit for #436: the watcher that closes a desk with its stream
    /// held a sender of its own, and kept A's stream open for good.
    #[tokio::test]
    async fn a_replaced_desk_ends_its_stream() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        let conn_session = alices_connection(&ctx);
        let request = UserRequest::WebShellPair { user_id: "alice".into(), ttl_seconds: 60 };
        let mut a = opened(&ctx, &conn_session, &request).await;
        let ready = tokio::time::timeout(Duration::from_secs(5), a.recv()).await.expect("a first frame");
        assert!(matches!(ready, Some(UserResponse::WebShellPairReady)), "{ready:?}");
        let mut b = opened(&ctx, &conn_session, &request).await;
        let ready = tokio::time::timeout(Duration::from_secs(5), b.recv()).await.expect("a first frame");
        assert!(matches!(ready, Some(UserResponse::WebShellPairReady)), "{ready:?}");

        let frames = to_the_end(a).await;
        assert!(frames.is_empty(), "the replaced desk said {frames:?}");
        let desk = ctx.browser_desks.lock().await.get("alice").map(|d| d.tx.clone()).expect("B is open");
        assert!(!desk.is_closed(), "the desk that replaced it was closed");
    }

    /// **A session-less streamed verb is not held to a session.** An invite is
    /// session-less bootstrap. Opened on a connection that happens to hold
    /// alice's session, which is then revoked, it still says its own answer
    /// (no relay, here) and not the session's refusal: the rule follows the
    /// session the gate passed, and the gate passed this verb none.
    #[tokio::test]
    async fn a_sessionless_streamed_verb_is_not_ended_by_a_revoked_session() {
        let dir = a_dir();
        let daemon = a_daemon(dir.path()).await;
        let ctx = daemon.agent_context();
        let conn_session = alices_connection(&ctx);
        let request = UserRequest::DeviceInvite { user_id: "alice".into(), ttl_seconds: 60, as_name: None };
        let stream = opened(&ctx, &conn_session, &request).await;

        sessions::remove_user(&ctx.sessions, "alice");

        let frames = to_the_end(stream).await;
        let [UserResponse::Error { message }] = frames.as_slice() else {
            panic!("expected the invite's own one answer, got {frames:?}");
        };
        assert_eq!(message, super::super::NO_RELAY_FOR_AN_INVITE);
    }
}
