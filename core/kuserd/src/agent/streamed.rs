// SPDX-License-Identifier: AGPL-3.0-or-later
//! **The verbs whose clients read the answer as a stream, answered as one.**
//!
//! Eleven verbs on the agent's door are read with `send_streaming`: the event
//! bus, the VFS watch, every pairing ceremony, the web-shell desk and a browser
//! channel's outbound side. `send_streaming` reads frames until the door closes
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
//! [`dispatch::stream_entry_refusal`], the same functions `handle_request`
//! reads, and it is read here once, before the verb's opening runs. The opening
//! is a future that has not been polled when the gate reads the request, so a
//! refused verb does nothing at all: no desk is registered, no relay is read,
//! no ceremony reserves a code.

use super::{browser_channel, dispatch, sessions, AgentContext, ConnSessionData};
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

/// A streamed verb's opening, not yet started.
type Opening<'a> = Pin<Box<dyn Future<Output = io::Result<mpsc::Receiver<UserResponse>>> + Send + 'a>>;

/// The door's answer to `request` when its client reads it as a stream, and
/// `None` when it does not.
///
/// The gate is read first; a refusal is answered through [`one_frame`], so
/// the client's `recv` gives the refusal and then `None`.
pub(super) async fn answer(
    ctx: &AgentContext,
    request: &UserRequest,
    conn_session: &ConnSession,
    vfs: VfsWatchSource<'_>,
) -> Option<io::Result<mpsc::Receiver<UserResponse>>> {
    let opening = opening(ctx, request, conn_session, vfs)?;
    Some(match dispatch::stream_entry_refusal(&ctx.sessions, conn_session, request) {
        // Dropped unpolled: the verb's opening never ran.
        Some(refusal) => Ok(one_frame(refusal)),
        None => opening.await,
    })
}

/// `frame`, and then the end of the stream.
fn one_frame(frame: UserResponse) -> mpsc::Receiver<UserResponse> {
    HandlerOutput::Single(frame).into_stream()
}

/// What each streamed verb does once the gate has passed it, and `None` for a
/// request that is not one of them.
///
/// Building an arm runs nothing: each is an `async` block, which does no work
/// until [`answer`] awaits it.
fn opening<'a>(
    ctx: &'a AgentContext,
    request: &'a UserRequest,
    conn_session: &'a ConnSession,
    vfs: VfsWatchSource<'a>,
) -> Option<Opening<'a>> {
    use kotton_device::users::residency::Residency;
    use kotton_device::users::{contacts, pairing};
    let residency = || Arc::new(ctx.users.clone()) as Arc<dyn Residency>;
    Some(match request {
        UserRequest::SubscribeEvents { category, level } => Box::pin(async move {
            Ok(dispatch::handle_subscribe(&ctx.runtime, category.clone(), level.clone()).await)
        }),
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
        // Both need the session of the user pairing, which the gate reads — a
        // contact is admitted on their word.
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
            ctx.browser_desks.lock().await.insert(user_id.clone(), tx.clone());
            // Announce the desk is registered before any browser could reach
            // it, so a caller need not race the insertion.
            let _ = tx.send(UserResponse::WebShellPairReady).await;
            Ok(rx)
        }),
        // The channel's other direction. This connection becomes the side that
        // carries frames no call is waiting on, and holds it for as long as
        // `khttpd` holds the browser's socket. When it ends, so does the
        // channel.
        UserRequest::BrowserOutbound { channel } => Box::pin(async move {
            let user_id = {
                let g = conn_session.lock().unwrap();
                g.as_ref().and_then(|s| sessions::live_user(&ctx.sessions, &s.token))
            };
            let Some(user_id) = user_id else {
                return Ok(one_frame(UserResponse::NoActiveSession));
            };
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
        }),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
    /// it every verb here but `BrowserOutbound`, which the verb itself refuses
    /// for want of a live session.
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

    /// A booted daemon's context, with nobody resident and no relay.
    async fn a_daemon(base: &std::path::Path) -> super::super::DeviceDaemon {
        let keychain: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            Arc::new(kotton_secret::MemorySecrets::new());
        super::super::DeviceDaemon::new_with_base_secrets_and_relay(
            base.to_path_buf(),
            IpcEndpoint::UnixSocket(base.join("kuserd.sock")),
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
        let dir = tempfile::tempdir_in("/tmp").expect("a directory under /tmp for the socket");
        let daemon = a_daemon(dir.path()).await;
        let endpoint = IpcEndpoint::UnixSocket(dir.path().join("door.sock"));
        let door = tokio::spawn(a_door(daemon.agent_context(), endpoint.clone(), || Some(a_gateway())));

        for request in every_streamed_verb() {
            let said = format!("{:?}", read_to_the_end(&endpoint, &request).await);
            let refusal = match request {
                UserRequest::BrowserOutbound { .. } => UserResponse::NoActiveSession,
                _ => UserResponse::NotAllowed,
            };
            assert_eq!(said, format!("{:?}", vec![refusal]), "{}", request.variant_name());
        }
        door.abort();
    }

    /// **A verb's own refusal ends its stream as the gate's does.** An invite
    /// on a device with no relay passes the gate (it is session-less
    /// bootstrap) and is refused by the verb before any ceremony starts.
    #[tokio::test]
    async fn an_invite_refused_for_want_of_a_relay_is_its_refusal_and_then_the_end() {
        let dir = tempfile::tempdir_in("/tmp").expect("a directory under /tmp for the socket");
        let daemon = a_daemon(dir.path()).await;
        let endpoint = IpcEndpoint::UnixSocket(dir.path().join("door.sock"));
        let door = tokio::spawn(a_door(daemon.agent_context(), endpoint.clone(), || None));

        let request = UserRequest::DeviceInvite { user_id: "alice".into(), ttl_seconds: 60, as_name: None };
        let frames = read_to_the_end(&endpoint, &request).await;
        let [UserResponse::Error { message }] = frames.as_slice() else {
            panic!("expected the one refusal, got {frames:?}");
        };
        assert_eq!(message, super::super::NO_RELAY_FOR_AN_INVITE);
        door.abort();
    }
}
