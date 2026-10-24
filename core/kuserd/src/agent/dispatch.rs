// SPDX-License-Identifier: AGPL-3.0-or-later
//! Request dispatch functions extracted from \gent/mod.rs\.
//!
//! Provides [handle_request] and [handle_subscribe].
use super::app_host::app_host;
use super::custody_window;
use super::file_host::file_host;
use super::handlers;
use super::message_host::msg_host;
use super::occupant_host::occupant_host;
use super::read_mark_host::read_marks;
use super::{ConnSessionData, UserRequest, UserResponse};
use hex;
use kotton_app::daemon::db::app_registry_db;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_ipc::{Caller, HandlerOutput};
use kotton_peer::membership::Membership as _;
use kotton_session::lock_policy;
use kotton_session::service::tokens as sessions;
use sqlx::SqlitePool;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Handle a `SubscribeEvents` request by subscribing to the live event bus
/// and forwarding matching events as `DeviceResponse::EventStream` frames.
///
/// Requires an active authenticated session, applied by
/// [`stream_entry_refusal`] before this is reached — `SubscribeEvents` is
/// `requires_session`, so an unauthenticated connection is answered
/// `NoActiveSession` there and never arrives here.
pub(super) async fn handle_subscribe(
    runtime: &Arc<DeviceRuntime>,
    category: Option<String>,
    level: Option<String>,
) -> io::Result<HandlerOutput<UserResponse>> {
    use kotton_diag::service::{EventCategory, EventLevel};
    use kotton_wire::ipc::EventEntry;
    use std::time::UNIX_EPOCH;
    use tokio::sync::mpsc;

    // Parse optional filters.
    let min_level: Option<EventLevel> = level
        .as_deref()
        .and_then(|s| serde_json::from_str(&format!("\"{s}\"")).ok());
    let filter_cat: Option<EventCategory> = category
        .as_deref()
        .and_then(|s| serde_json::from_str(&format!("\"{s}\"")).ok());

    let mut sub = runtime.event_bus().subscribe();
    let (tx, rx) = mpsc::channel::<UserResponse>(256);

    tokio::spawn(async move {
        let mut counter: u64 = 0;
        loop {
            match sub.recv().await {
                Ok(event) => {
                    // Apply level filter.
                    if let Some(min) = min_level {
                        if event.level < min {
                            continue;
                        }
                    }
                    // Apply category filter.
                    if let Some(cat) = filter_cat {
                        if event.category != cat {
                            continue;
                        }
                    }

                    // Convert Event â†’ EventEntry.
                    let ts = event
                        .timestamp
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let level_str = serde_json::to_value(&event.level)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default();
                    let cat_str = serde_json::to_value(&event.category)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default();

                    counter += 1;
                    let entry = EventEntry {
                        id: format!("live-{counter}"),
                        timestamp: ts,
                        iso_timestamp: None,
                        level: level_str,
                        category: cat_str,
                        message: event.message.clone(),
                        payload: event.payload.as_ref().map(|v| v.to_string()),
                    };

                    if tx
                        .send(UserResponse::EventStream { event: entry })
                        .await
                        .is_err()
                    {
                        break; // client disconnected
                    }
                }
                Err(_) => {
                    // Bus closed (daemon shutting down).
                    let _ = tx.send(UserResponse::EventStreamEnd).await;
                    break;
                }
            }
        }
    });

    Ok(HandlerOutput::Stream(rx))
}

/// Handle a [`UserRequest::VfsWatch`] streaming subscription.
///
/// Requires an authenticated session owning `user_id`, applied by
/// [`stream_entry_refusal`] before this is reached.  Opens with
/// [`UserResponse::VfsWatchReady`], then streams [`UserResponse::VfsChanged`]
/// frames from the daemon's VFS broadcast channel, filtered to `user_id`'s own
/// tree and then by the caller's optional path prefixes.  Ends with
/// [`UserResponse::VfsWatchEnd`] when the channel closes (daemon shutdown).
///
/// **The first frame is a readiness signal, and it is load-bearing.** Two things
/// have to be true before a change reaches a subscriber: this subscription must
/// be attached to the broadcast channel, and `spawn_fs_watcher`'s thread must
/// have registered its watch over `<base>/users/`. Neither is true when
/// `send_streaming` returns — that call writes the request and returns — so a
/// client that subscribes and immediately writes a file can have the write land
/// before there is anything to catch it. No error is reported and no frame
/// arrives, which is indistinguishable from a quiet filesystem.
/// `VfsWatchReady` is sent once both are true, so a caller waits on the watcher
/// rather than on a clock. If the watcher reports it never registered, the
/// opening frame is [`UserResponse::VfsWatchFailed`] carrying the reason —
/// *not* `VfsWatchEnd`, which means the daemon itself is shutting down and
/// tells a client to stop.
///
/// **The first filter is the load-bearing one.** `spawn_fs_watcher` is one
/// watcher over `<base>/users/`, broadcasting absolute paths to one channel for
/// every resident user, so without it a session for one person is handed which
/// of another person's files changed, and when — not the contents, which are
/// sealed, but a record of someone else's activity, which is what Article VII
/// refuses. `user_id` is compared against the session *and* filters the
/// paths; `a_watcher_is_not_shown_another_users_paths` holds the second.
///
/// A prefix over the path is the narrowing available today, and it is a string
/// comparison standing in for an identity: a VFS change frame does not say
/// whose it is, and a frame that named its user would make this a lookup
/// rather than a guess about a layout.
pub(super) async fn handle_vfs_watch(
    base: &Path,
    user_id: String,
    paths: Vec<String>,
    mut broadcast_rx: tokio::sync::broadcast::Receiver<kotton_sync::engine::VfsChangeFrame>,
    mut fs_watch: tokio::sync::watch::Receiver<kotton_sync::engine::FsWatchState>,
) -> io::Result<HandlerOutput<UserResponse>> {
    use kotton_sync::engine::wait_until_watching;
    use tokio::sync::broadcast::error::RecvError;
    use tokio::sync::mpsc;

    let (tx, rx) = mpsc::channel::<UserResponse>(64);
    let user_root = base.join("users").join(&user_id);

    tokio::spawn(async move {
        // The subscription already exists — `broadcast_rx` was taken before this
        // handler was called, so every change from that instant is buffered for
        // it. What is left to wait on is the watcher thread's registration.
        if let Err(reason) = wait_until_watching(&mut fs_watch).await {
            // Nothing will ever arrive. Saying so is the whole point of the
            // frame; a subscriber that waited for `VfsWatchReady` would
            // otherwise wait as long as it used to wait for a change.
            //
            // `VfsWatchFailed`, never `VfsWatchEnd`: the daemon is not going
            // away, only this watch, and the two call for opposite responses
            // from a client. Sending `End` here told `ksyncd` to exit on the
            // exact condition — inotify exhaustion — that its fallback poll
            // exists to survive.
            let _ = tx
                .send(UserResponse::VfsWatchFailed {
                    reason: reason.to_string(),
                })
                .await;
            return;
        }
        if tx.send(UserResponse::VfsWatchReady).await.is_err() {
            return; // client disconnected before the stream began
        }

        loop {
            match broadcast_rx.recv().await {
                Ok((path, kind, ts)) => {
                    let mine = Path::new(&path).starts_with(&user_root);
                    let matches = mine
                        && (paths.is_empty() || paths.iter().any(|p| path.starts_with(p.as_str())));
                    if matches
                        && tx
                            .send(UserResponse::VfsChanged {
                                path,
                                kind,
                                timestamp_secs: ts,
                            })
                            .await
                            .is_err()
                    {
                        break; // client disconnected
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    // Some frames dropped by a slow consumer; continue.
                    continue;
                }
                Err(RecvError::Closed) => {
                    let _ = tx.send(UserResponse::VfsWatchEnd).await;
                    break;
                }
            }
        }
    });

    Ok(HandlerOutput::Stream(rx))
}

/// Resolve the per-user agent database for a verb.
///
/// `None` — and `Some("")`, the wire's long-standing "no user named" spelling
/// that `target_user_id()` reads the same way — is the **principal fallback**,
/// for verbs that predate a user field (`AppList`, `AppLaunch`, the role and
/// handler verbs, …): the daemon's own loaded principal under supervision, an
/// arbitrary loaded user on legacy unsupervised boots — the same rule the
/// sidecar picks use. The fields are deliberately not added to the wire: once
/// the process is the principal, `user_id` comes off every user verb, so
/// widening the format would be churn against the destination.
pub(super) async fn user_db_for(
    runtime: &DeviceRuntime,
    users: &crate::residency::UserRegistry,
    user_dbs: &crate::db::user_db::UserDbMap,
    base: &Path,
    user_id: Option<&str>,
) -> io::Result<Arc<SqlitePool>> {
    let uid = match user_id {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => users
            .any()
            .ok_or_else(|| io::Error::other("no user loaded on this daemon"))?,
    };
    crate::db::user_db::user_agent_db(
        user_dbs,
        base,
        runtime.secrets(),
        &uid,
        &runtime.schema_registry,
    )
    .await
}

/// [`user_db_for`] for a caller that has no session at all.
///
/// The compositor channel is authorised by possession of a handed descriptor,
/// not by a token naming a user, so there is no `session_user` to pass. `None`
/// takes the existing single-resident-user fallback — the same user the old
/// session-derived path resolved to on any one-user node.
///
/// A separate name rather than a `None` at the call site, because the two carry
/// different claims: a dispatch arm passing `None` is saying *this request did
/// not name a user*, and this is saying *this channel cannot*.
/// The per-user database for `user_id`, for a caller outside the dispatch table
/// (the browser channel) that already knows which user it is acting for.
pub(super) async fn user_db_for_user(
    ctx: &super::AgentContext,
    user_id: &str,
) -> io::Result<Arc<SqlitePool>> {
    user_db_for(
        &ctx.runtime,
        &ctx.users,
        &ctx.user_dbs,
        ctx.base.as_path(),
        Some(user_id),
    )
    .await
}

pub(super) async fn user_db_for_compositor(
    runtime: &DeviceRuntime,
    users: &crate::residency::UserRegistry,
    user_dbs: &crate::db::user_db::UserDbMap,
    base: &Path,
) -> io::Result<Arc<SqlitePool>> {
    user_db_for(runtime, users, user_dbs, base, None).await
}

/// The trust-origin floor: `origin(conn) >= required_trust(op)`, over three
/// origins: `Remote`, `Paired` and `Local`.
///
/// `None` for a connection that has not authenticated: there is no origin to
/// compare, and the session guard below is what refuses it. `Authenticate` and
/// `CallerInfo` are exempt because a client must always be able to authenticate
/// and to introspect its own connection.
/// How many messages this person has not read.
///
/// The join is here rather than in the domain because the two halves come from
/// two places: the inbox is a record query through the message host, and the
/// marks are objects in the user's own store. Neither half knows about the
/// other, which is the arrangement that keeps read state out of the message
/// envelope entirely.
async fn unread_count(
    runtime: &DeviceRuntime,
    users: &crate::residency::UserRegistry,
    record_stores: &crate::residency::RecordStores,
    user_id: String,
) -> io::Result<UserResponse> {
    let marks = match read_marks(users, &user_id) {
        Ok(m) => m,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let inbox = match kotton_msg::daemon::messages::message_poll_inbox(
        &msg_host(runtime, users, record_stores),
        user_id,
    )
    .await?
    {
        UserResponse::MessageHistory { messages } => messages,
        // An inbox that could not be read is not an inbox of zero. The caller
        // is drawing a badge and must be able to tell "nothing waiting" from
        // "this could not be answered".
        other => return Ok(other),
    };
    match kotton_msg::read_marks::unread_count(&marks, &inbox).await {
        Ok(count) => Ok(UserResponse::MessageUnread { count }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Record how far this person has read one conversation.
async fn mark_read(
    users: &crate::residency::UserRegistry,
    user_id: String,
    peer_did: String,
    filed_at: u64,
    message_id: String,
) -> io::Result<UserResponse> {
    let marks = match read_marks(users, &user_id) {
        Ok(m) => m,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    use kotton_msg::read_marks::ReadMarks as _;
    match marks.mark_read(&peer_did, filed_at, &message_id).await {
        Ok(moved) => Ok(UserResponse::MessageRead { moved }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

fn origin_refusal(
    origin: Option<kotton_wire::ConnTrustOrigin>,
    request: &UserRequest,
) -> Option<UserResponse> {
    let origin = origin?;
    let variant = request.variant_name();
    if variant == "Authenticate" || variant == "CallerInfo" {
        return None;
    }
    (origin < request.required_trust()).then_some(UserResponse::NotAllowed)
}

/// A gateway's own bootstrap token is **mint-only**.
///
/// It may exchange evidence about a third party for a session minted for that
/// party, and do nothing else. This is what turns an *informed* deputy into a
/// *disarmed* one: binding a principal without it would leave blanket authority
/// sitting there for any handler that forgot to consult it — a convention, not
/// a guarantee.
fn mint_only_refusal(
    principal: Option<&kotton_wire::ipc::Principal>,
    request: &UserRequest,
) -> Option<UserResponse> {
    if !principal?.is_mint_only() {
        return None;
    }
    let variant = request.variant_name();
    // `BrowserOutbound` sits beside `BrowserFrame` and for the same reason: it
    // is the *other direction* of the one channel a gateway carries, and every
    // frame on it is sealed under a key the gateway never had. Mint-only
    // disarms a gateway of authority over the user's data; carrying more
    // ciphertext is not authority. The ceremony test is refused here without
    // it, which is what the list is for.
    let permitted = matches!(
        variant,
        "MintPrincipalSession"
            | "BrowserFrame"
            | "BrowserOutbound"
            | "Authenticate"
            | "CallerInfo"
            | "GetActiveSession"
    );
    if permitted {
        return None;
    }
    tracing::warn!(
        variant,
        "P1: gateway bootstrap token attempted a non-mint operation"
    );
    Some(UserResponse::NotAllowed)
}

/// The session guard: an authenticated session, and — for a request that names
/// a user — one that owns that user.
fn session_refusal(session_user: Option<&str>, request: &UserRequest) -> Option<UserResponse> {
    if !request.requires_session() {
        return None;
    }
    match session_user {
        None => Some(UserResponse::NoActiveSession),
        Some(uid) => match request.target_user_id() {
            Some(target) if target != uid => Some(UserResponse::NoActiveSession),
            _ => None,
        },
    }
}

/// Both guards, for the streaming path — the one caller that is not
/// [`handle_request`].
///
/// Nine verbs return `HandlerOutput::Stream` and are intercepted in the
/// acceptor closure before `handle_request` runs, so they never met its floor.
/// Each carried instead a hand-written approximation, and they were not the
/// same rule: most compared the session's user to the request's, which is a
/// session check with no origin in it. A gateway is handed a session by
/// `MintPrincipalSession` and speaks it on this socket; that session satisfied
/// those checks, so `DeviceAdd` — `Local`-tier, identity-splitting — was
/// reachable from a `Remote` origin with nothing on the path reading the tier.
///
/// The fix is not a tenth check. It is that both paths read the same three
/// functions, in the same order, so there is no second rule left to drift from
/// the first.
///
/// The mint-only rule is here for the same reason: a bootstrap token
/// is `Remote`-origin and a live session, so the floor and the session guard
/// both pass it, and `SubscribeEvents` is `Remote`-tier — a gateway acting as
/// itself could sit on the node's event bus, which is a description of what the
/// person is doing, held by the sidecar the rule exists to disarm. The gate
/// gives the rule one home on this path.
pub(super) fn stream_entry_refusal(
    sessions: &sessions::SessionMap,
    conn_session: &Mutex<Option<ConnSessionData>>,
    request: &UserRequest,
) -> Option<UserResponse> {
    let (origin, token, principal) = {
        let g = conn_session.lock().unwrap();
        match g.as_ref() {
            Some(s) => (
                Some(s.origin),
                Some(s.token.clone()),
                Some(s.principal.clone()),
            ),
            None => (None, None, None),
        }
    };
    if let Some(refusal) = mint_only_refusal(principal.as_ref(), request) {
        return Some(refusal);
    }
    if let Some(refusal) = origin_refusal(origin, request) {
        return Some(refusal);
    }
    let session_user = token
        .as_deref()
        .and_then(|tok| sessions::live_user(sessions, tok));
    session_refusal(session_user.as_deref(), request)
}

pub(super) async fn handle_request(
    ctx: &super::AgentContext,
    request: UserRequest,
    caller: Caller,
    conn_session: Arc<Mutex<Option<ConnSessionData>>>,
) -> io::Result<UserResponse> {
    // Destructured rather than referenced field-by-field through the body: this
    // function is 1,700 lines and every one of them already names these
    // bindings. The struct replaces a 22-argument signature (see
    // `AgentContext`); it is not meant to change how the body reads.
    let super::AgentContext {
        runtime,
        infer_proxy,
        endpoint: _,
        users,
        sync_resources,
        record_stores,
        db,
        device_db,
        user_dbs,
        event_log_tasks,
        base,
        started_at,
        sessions,
        gateway_tokens,
        principal_sessions,
        paired_keys,
        sync_engine,
        live_instances,
        revoked_sessions,
        sidecar_states,
        ipc_sessions,
        connected_peers,
        surface_proxy,
        window_registry,
        file_reassembly,
        runner: _,
        pending_confirms,
        browser_desks: _,
        browser_channels: _,
        ceremonies,
    } = ctx;
    let started_at = *started_at;
    let base = base.as_path();
    let live_instances = Arc::clone(live_instances);
    // â”€â”€ Scope guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // If the connection authenticated with a non-empty scope allow-list,
    // reject any request whose variant is not in that list.
    // `Authenticate` and `CallerInfo` are always permitted (a client must be
    // able to authenticate; gateways may need CallerInfo to introspect).
    {
        // Trust-origin floor + least-privilege scope (no denylist, and no
        // forgeable `explicitly_scoped` carve-out).
        let (origin, scope, principal) = {
            let g = conn_session.lock().unwrap();
            match g.as_ref() {
                Some(s) => (Some(s.origin), s.scope.clone(), Some(s.principal.clone())),
                None => (None, None, None),
            }
        };

        // A gateway's own bootstrap token is **mint-only**. It may
        // exchange evidence about a third party for a session minted for that
        // party, and do nothing else.
        //
        // This is what turns an *informed* deputy into a *disarmed* one. Binding a
        // principal without the mint-only rule would leave the blanket authority sitting there for
        // any handler that forgot to consult it — a convention, not a guarantee.
        // With it there is no ambient authority left to forget about.
        if let Some(refusal) = mint_only_refusal(principal.as_ref(), &request) {
            return Ok(refusal);
        }

        if let Some(origin) = origin {
            let variant = request.variant_name();
            // A client must always be able to authenticate / introspect itself.
            if variant != "Authenticate" && variant != "CallerInfo" {
                // The floor: `origin(conn) >= required_trust(op)`. Origin is bound at
                // Authenticate from the credential, so a Remote (gateway) connection
                // can never reach a Local-tier op even if it names the op in its own
                // scope. This runs on origin, not scope-presence, so a
                // gateway with no declared scope is floored too (the old denylist was
                // gated on scope presence and silently skipped for scope-less gateways).
                //
                // It is an ordering comparison rather than an equality, which is
                // what lets `Paired` sit between the two without touching this
                // line: a browser clears the contact-pairing verbs and is
                // still floored out of everything `Local`.
                // Trust-origin floor: a Remote conn reaching for a
                // Local-tier op. Distinct from a scope miss — no scope re-opens it.
                // Read through `origin_refusal` so the streaming path, which
                // cannot reach this function, applies the identical rule.
                if let Some(refusal) = origin_refusal(Some(origin), &request) {
                    return Ok(refusal);
                }
                // Least-privilege scope allow-list, on top (unchanged semantics).
                if let Some(ref allowed) = scope {
                    if !allowed.is_empty() && !allowed.iter().any(|a| a == variant) {
                        return Ok(UserResponse::NotInScope);
                    }
                }
            }
        }
    }

    // â”€â”€ NoCek guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Blind relay nodes (paired via PairingPayload::BlindRelay) have no CEK.
    // Reject requests that require decryption before the auth guard so the
    // error is clear and does not disclose auth state.
    {
        let cek_available = conn_session
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.cek_available)
            .unwrap_or(true); // if not yet authenticated, let auth guard handle it
        if !cek_available {
            let requires_cek = matches!(
                &request,
                UserRequest::ReadFile { .. }
                    | UserRequest::WriteFile { .. }
                    | UserRequest::RecordInsert { .. }
                    | UserRequest::RecordQuery { .. }
                    | UserRequest::RecordSearch { .. }
                    | UserRequest::RecordOpen { .. }
                    | UserRequest::RecordDelete { .. }
                    // A model is a sealed object and a sealed record. A
                    // blind relay holds neither key and must refuse rather
                    // than half-perform: a keyless node never runs a model
                    // and has no business holding one.
                    | UserRequest::ModelAdd { .. }
                    | UserRequest::ModelWeights { .. }
                    | UserRequest::ModelList { .. }
                    | UserRequest::ModelRemove { .. }
                    | UserRequest::ModelUse { .. }
                    // Import writes sealed records, so it needs the key that
                    // seals them. A blind relay must refuse it rather than
                    // half-perform it.
                    | UserRequest::Import { .. }
            );
            if requires_cek {
                return Ok(UserResponse::Error {
                    message: "NoCek: this node has no content encryption key \u{2014} \
                              it was paired as a blind relay and cannot decrypt user data"
                        .to_string(),
                });
            }
        }
    }
    // ── Session guard (positive, default-deny — audit C2) ────────────────────
    // Every request requires an authenticated session on this connection except
    // the explicit pre-auth set (see `UserRequest::requires_session`). Previously
    // this gate fired only for requests whose `target_user_id()` was `Some`, so
    // the entire control plane (SchemaGrantSet, AppSetRole, RendezvousSet, …) —
    // which carries no `user_id` — dispatched with no session at all, even while
    // locked. For a request that *does* name a user, the session must own it.
    // Resolved once and kept, because two things need it: the guard below, and
    // any handler whose subject is the caller rather than an argument (the window
    // verbs). A handler must never take that from the request — a client naming
    // its own owner could claim `WindowOwner::System`.
    let session_user: Option<String> = {
        let token_opt = conn_session
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.token.clone());
        token_opt
            .as_deref()
            .and_then(|tok| sessions::live_user(sessions, tok))
    };

    // Same rule, one implementation, shared with the streaming path.
    if let Some(refusal) = session_refusal(session_user.as_deref(), &request) {
        return Ok(refusal);
    }

    // -- Request-count increment for authenticated sessions -------------------
    {
        let token_opt = conn_session
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.token.clone());
        if let Some(ref tok) = token_opt {
            if let Some(record) = ipc_sessions.read().unwrap().get(tok) {
                record
                    .request_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    // The connection's authenticated user, for verbs that carry no user field:
    // the per-user database resolution is verb's user_id
    // → this session user → sole loaded user, in that order. "Who is asking"
    // comes from the session, not from a map iteration order.
    let session_user: Option<String> = conn_session
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|s| sessions::live_user(sessions, &s.token));

    let request_name = request.variant_name();
    match request {
        // User lifecycle
        UserRequest::CreateUser {
            user_id,
            passphrase,
        } => {
            // The CLI's door names the id and carries no display name: the
            // shell draws its fallbacks for such an identity until Settings
            // sets one.
            handlers::user::create_user(
                runtime,
                users,
                user_dbs,
                event_log_tasks,
                base,
                handlers::user::NewIdentity {
                    user_id,
                    passphrase: passphrase.expose().to_owned(),
                    display_name: None,
                },
                sessions,
            )
            .await
        }
        UserRequest::AddRecoveryPhrase { user_id } => {
            handlers::user::add_recovery_phrase(runtime, db, user_id).await
        }
        UserRequest::LogoutUser { user_id } => {
            // Ordering matters on Windows, where an open file blocks the
            // directory delete logout ends with. Every holder of a handle to
            // users/{id}/ has to let go, innermost first:
            //
            //   1. the event-log task, which owns a *clone* of the user's pool
            //      and lives in neither the runtime nor the pool cache — the
            //      holder that no eviction path could reach;
            //   2. the runtime, so background services stop enumerating them;
            //   3. the pool cache, which closes the pool itself.
            //
            // Then logout does its disk work against a directory nobody holds.
            crate::event_log::stop_user_log(event_log_tasks, &user_id).await;
            record_stores.remove(&user_id);
            users.remove(&user_id);
            crate::db::user_db::evict(user_dbs, &user_id).await;
            let result = handlers::user::logout_user(runtime, user_id.clone(), sessions).await;
            // The directory is gone (or the attempt failed); either way the
            // name is free to be opened again, so the marker comes off.
            crate::db::user_db::release(user_dbs, &user_id);
            // This user no longer contributes to the allowlist, so their peers
            // stop being admitted (a contribution is present only while its
            // user is). Rebuilt from whoever remains rather than
            // subtracted, so a key two users both paired survives the departure
            // of one of them.
            // Resolve here: `peer` is handed stores, never the registry.
            let resolved: Vec<(
                String,
                std::sync::Arc<dyn kotton_peer::membership::MemberStore>,
            )> = users
                .all()
                .into_iter()
                .map(|(id, rt)| {
                    (
                        id,
                        rt as std::sync::Arc<dyn kotton_peer::membership::MemberStore>,
                    )
                })
                .collect();
            kotton_peer::daemon::nodes::reproject_allowlist(&resolved, db, paired_keys).await;
            result
        }
        UserRequest::LoginWithRecoveryKey {
            recovery_key,
            device_name,
            user_id,
        } => {
            handlers::user::login_with_recovery_key(
                runtime,
                users,
                recovery_key.expose().to_owned(),
                device_name,
                user_id,
                sessions,
            )
            .await
        }
        UserRequest::RotateIdentity {
            user_id,
            recovery_key,
            credential,
        } => {
            handlers::user::rotate_identity(
                runtime,
                user_id,
                recovery_key.expose().to_owned(),
                credential.map(|c| c.expose().to_owned()),
            )
            .await
        }
        UserRequest::Recover {
            user_id,
            recovery_key,
            passphrase,
            vault_line,
        } => {
            let resp =
                handlers::user::recover(
                    runtime,
                    users,
                    db,
                    user_id.clone(),
                    recovery_key.expose().to_owned(),
                    passphrase.expose().to_owned(),
                    vault_line,
                )
                    .await?;
            // The session that ran this was opened on a locked claim (no CEK).
            // Recovery is what put the keys back, so the connection stops being
            // told it has none — the same refresh an unlock does.
            if matches!(resp, UserResponse::Recovered { .. }) {
                if let Some(s) = conn_session.lock().unwrap().as_mut() {
                    s.cek_available =
                        kotton_peer::daemon::nodes::user_has_cek(&user_id, runtime.secrets());
                }
            }
            Ok(resp)
        }
        UserRequest::ListUsers => handlers::user::list_users(users).await,

        // Session auth
        UserRequest::Authenticate { token, scope } => {
            let token = token.expose().to_owned();
            let uid_opt = sessions::live_user(sessions, &token);
            match uid_opt {
                Some(user_id) => {
                    // A process-scoped bootstrap token authenticates only from
                    // the process it was first presented by. The kernel supplied
                    // `caller.pid` at accept (SO_PEERCRED), so a second process
                    // on this machine that read the token out of the environment
                    // is refused here — the one decision on this socket that
                    // rests on kernel evidence rather than the caller's word
                    // for who it is.
                    // Human sessions and platforms with no peer pid are
                    // unaffected; see `claim_process_pid`.
                    if let sessions::PidClaim::Mismatch { bound, seen } =
                        sessions::claim_process_pid(sessions, &token, caller.pid)
                    {
                        tracing::warn!(
                            bound_pid = bound,
                            caller_pid = seen,
                            "refusing a process-scoped token presented from a different process"
                        );
                        return Ok(UserResponse::NoActiveSession);
                    }
                    // A node can decrypt if it holds a CEK: the bootstrap seed32 OR a
                    // delivered operational CEK (a Full-enrolled device). Blind relays
                    // and cosigners have neither. (Keying this on seed32 alone wrongly
                    // blocked a Full-joined device from its own data.)
                    let cek_available =
                        kotton_peer::daemon::nodes::user_has_cek(&user_id, runtime.secrets());
                    // Record (or refresh) the per-connection session entry so
                    // `IpcSessions` introspection can report it.
                    {
                        let authenticated_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        ipc_sessions.write().unwrap().insert(
                            token.clone(),
                            super::IpcSessionRecord {
                                user_id: user_id.clone(),
                                scope: scope.clone(),
                                authenticated_at,
                                request_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                            },
                        );
                    }
                    // The principal comes from the credential, not the
                    // request — a caller-assertable principal would let anything
                    // holding a token name any principal it liked.
                    //
                    // A minted session names the third party it was minted for; a
                    // gateway's own bootstrap token names no one, which is exactly
                    // what the mint-only rule refuses to act on.
                    let is_gateway = gateway_tokens.read().unwrap().contains(&token);
                    let principal = principal_sessions
                        .read()
                        .unwrap()
                        .get(&token)
                        .cloned()
                        .unwrap_or(if is_gateway {
                            // A gateway acting as itself: authority to mint, and
                            // nothing else.
                            kotton_wire::ipc::Principal::Gateway
                        } else {
                            kotton_wire::ipc::Principal::LocalOperator
                        });
                    // Origin derives from the principal — a gateway acting as
                    // itself and an mTLS peer are Remote, a browser the
                    // sealed-channel ceremony admitted is Paired, and only a
                    // direct local client is Local. Keyed on `gateway_tokens`
                    // membership instead, which holds only *bootstrap* tokens, a
                    // gateway-*minted* session would arrive Local and the floor
                    // would be a no-op for exactly the network-facing traffic it
                    // exists to floor.
                    let origin = principal.trust_origin();
                    *conn_session.lock().unwrap() = Some(ConnSessionData {
                        token,
                        scope,
                        cek_available,
                        origin,
                        principal,
                        browser_key: None,
                    });
                    Ok(UserResponse::ActiveSession { user_id })
                }
                None => Ok(UserResponse::NoActiveSession),
            }
        }
        UserRequest::CallerInfo => {
            let (has_session, session_user_id) = {
                let token = conn_session
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|s| s.token.clone());
                match token {
                    Some(token) => {
                        let uid = sessions::live_user(sessions, &token);
                        (uid.is_some(), uid)
                    }
                    None => (false, None),
                }
            };
            Ok(UserResponse::CallerInfoResponse {
                os_user: caller.user.to_string(),
                has_active_session: has_session,
                session_user_id,
                transport: "ipc".to_owned(),
            })
        }
        UserRequest::GetActiveSession => {
            let token = conn_session
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| s.token.clone());
            match token.and_then(|t| sessions::live_user(sessions, &t)) {
                Some(user_id) => Ok(UserResponse::ActiveSession { user_id }),
                None => Ok(UserResponse::NoActiveSession),
            }
        }
        UserRequest::LockSession => {
            let sess_opt = conn_session.lock().unwrap().take();
            if let Some(sess) = sess_opt {
                sessions.write().unwrap().remove(&sess.token);
                ipc_sessions.write().unwrap().remove(&sess.token);
            }
            Ok(UserResponse::SessionLocked)
        }

        UserRequest::ReadFile {
            user_id,
            path,
            offset,
            length,
        } => {
            kotton_device::users::files::read_file(
                &file_host(runtime, &**sync_resources),
                user_id,
                path,
                offset,
                length,
            )
            .await
        }
        UserRequest::WriteFile {
            user_id,
            path,
            data,
            offset,
            total_size,
            content_hash,
        } => {
            kotton_device::users::files::write_file(
                &file_host(runtime, &**sync_resources),
                user_id,
                path,
                data,
                offset,
                total_size,
                content_hash,
                Some(file_reassembly),
            )
            .await
        }
        UserRequest::ListFiles { user_id, prefix } => {
            kotton_device::users::files::list_files(
                &file_host(runtime, &**sync_resources),
                user_id,
                prefix,
            )
            .await
        }
        UserRequest::DeleteFile { user_id, path } => {
            kotton_device::users::files::delete_file(
                &file_host(runtime, &**sync_resources),
                user_id,
                path,
            )
            .await
        }
        UserRequest::ListConflicts { user_id } => {
            kotton_device::users::files::list_conflicts(
                &file_host(runtime, &**sync_resources),
                user_id,
            )
            .await
        }
        UserRequest::ResolveConflict {
            user_id,
            path,
            keep,
        } => {
            kotton_device::users::files::resolve_conflict(
                &file_host(runtime, &**sync_resources),
                user_id,
                path,
                keep,
            )
            .await
        }
        UserRequest::PurgeFile { user_id, path } => {
            kotton_device::users::files::purge_file(
                &file_host(runtime, &**sync_resources),
                user_id,
                path,
            )
            .await
        }

        // -- Per-principal sessions -------------------------------------------
        UserRequest::MintPrincipalSession { user_id, evidence } => {
            // Resolving the store is the residency check: a name nobody here
            // holds mints nothing, and the error says so.
            let _resident = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            handlers::device_config::mint_principal_session(
                sessions,
                principal_sessions,
                paired_keys,
                user_id,
                evidence,
            )
            .await
        }

        // Sealed replication — exhaustiveness arms. The wire contract
        // and trust tier are settled; the handlers land with the sync rewrite, so
        // until then they fail closed rather than falling back to the VFS verbs
        // (which would defeat the point by moving plaintext).
        UserRequest::ReadSealed {
            user_id,
            mount,
            path,
            offset,
            length,
        } => {
            kotton_device::users::files::read_sealed(
                &file_host(runtime, &**sync_resources),
                user_id,
                mount,
                path,
                offset,
                length,
            )
            .await
        }
        UserRequest::ListSealed {
            user_id,
            mount,
            prefix,
        } => {
            kotton_device::users::files::list_sealed(
                &file_host(runtime, &**sync_resources),
                user_id,
                mount,
                prefix,
            )
            .await
        }
        UserRequest::WriteSealed {
            user_id,
            mount,
            path,
            blob,
            domain_id,
            offset,
            total_size,
            content_hash,
        } => {
            // Local path: no shared reassembly (no local chunked-write caller);
            // a complete single chunk only.
            kotton_device::users::files::write_sealed(
                &file_host(runtime, &**sync_resources),
                user_id,
                mount,
                path,
                blob,
                domain_id,
                offset,
                total_size,
                content_hash,
                None,
            )
            .await
        }

        // Remote storage management
        UserRequest::RemoteAdd {
            user_id,
            name,
            backend,
            credentials,
        } => {
            kotton_device::users::files::remote_add(
                db,
                &file_host(runtime, &**sync_resources),
                user_id,
                name,
                backend,
                credentials.map(|c| c.expose().clone()),
            )
            .await
        }
        UserRequest::RemoteRemove { user_id, name } => {
            kotton_device::users::files::remote_remove(
                &file_host(runtime, &**sync_resources),
                user_id,
                name,
            )
            .await
        }
        UserRequest::RemoteList { user_id } => {
            kotton_device::users::files::remote_list(
                &file_host(runtime, &**sync_resources),
                user_id,
            )
            .await
        }
        UserRequest::RemoteCacheClear { user_id, name } => {
            kotton_device::users::files::remote_cache_clear(
                &file_host(runtime, &**sync_resources),
                user_id,
                name,
            )
            .await
        }
        UserRequest::RemoteCredentialsSet {
            user_id,
            name,
            credentials,
        } => {
            kotton_device::users::files::remote_credentials_set(
                &file_host(runtime, &**sync_resources),
                user_id,
                name,
                credentials.expose().clone(),
            )
            .await
        }

        // Sync
        UserRequest::SyncMount {
            user_id,
            mount,
            remote,
            direction,
        } => {
            kotton_device::users::files::sync_mount(
                db,
                &file_host(runtime, &**sync_resources),
                user_id,
                mount,
                remote,
                direction,
            )
            .await
        }

        // -- Peer pairing / network -----------------------------------------------
        UserRequest::PairNodeEphemeral {
            user_id,
            label,
            paths,
            permissions,
            ttl_seconds,
            guest_ephemeral_pubkey,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            let Some(user_rt) = users.get(&user_id) else {
                return Ok(UserResponse::Error {
                    message: format!("user runtime '{user_id}' is not loaded"),
                });
            };
            kotton_peer::daemon::nodes::pair_node_ephemeral(
                &user_db,
                &crate::agent::sealed_read::DaemonSealedRead { store: &user_rt },
                user_id,
                label,
                paths,
                permissions,
                ttl_seconds,
                guest_ephemeral_pubkey,
                runtime.secrets(),
            )
            .await
        }
        UserRequest::NodeList { user_id } => {
            kotton_peer::daemon::nodes::node_list(db, user_id).await
        }
        UserRequest::NodeRelay { .. } => Ok(UserResponse::NodeRelayResult {
            relay_url: Some(runtime.reachability().nat().relay_url).filter(|u| !u.is_empty()),
            relay_key: runtime.reachability().nat().relay_key,
            // Asked on this machine, by a process that presents at no relay.
            admission: None,
        }),
        // A device keeps for itself and meters nothing; the verb is a vault's,
        // asked of the node that is paid by the byte.
        UserRequest::VaultCapacity { .. } => Ok(UserResponse::Error {
            message: "VaultCapacity is a vault's verb; this node is a device".to_string(),
        }),
        // The landlord's verbs at a vault. A device keeps for nobody, so it
        // has no tenants, no quotas and nobody to drop; its person says these
        // to a vault through `AsOperator`, below.
        UserRequest::SetQuota { .. }
        | UserRequest::Tenants
        | UserRequest::DropTenant { .. }
        | UserRequest::StandAt { .. }
        | UserRequest::InviteDigits { .. } => {
            Ok(UserResponse::Error {
                message: format!(
                    "{} is a vault's verb, said to it under its operator credential; this node is a device",
                    request_name
                ),
            })
        }
        // The operator credential, kept and spoken under (`agent::operator`).
        UserRequest::OperatorMint {
            user_id,
            service,
            name,
            rule,
        } => Ok(super::operator::mint(users, &user_id, service, name.as_deref(), rule)),
        UserRequest::OperatorMints { user_id } => Ok(super::operator::mints(users, &user_id)),
        UserRequest::OperatorHeld { user_id, service } => Ok(super::operator::held_of(users, &user_id, service)),
        UserRequest::OperatorForget { user_id, service, name } => {
            Ok(super::operator::forget(runtime, users, &user_id, service, &name).await)
        }
        UserRequest::OperatorEnrol { user_id, credential } => {
            Ok(super::operator::enrol(runtime, users, record_stores, &user_id, credential.expose()).await)
        }
        UserRequest::OperatorEnrolLines { user_id, lines } => {
            Ok(super::operator::enrol_lines(runtime, users, record_stores, &user_id, &lines).await)
        }
        UserRequest::AsOperator { user_id, name, verb } => {
            Ok(super::operator::speak(runtime, users, record_stores, &user_id, &name, verb).await)
        }
        UserRequest::DeviceName { new_name } => {
            handlers::device_config::device_name(device_db, new_name).await
        }
        UserRequest::NodeRevoke { user_id, node_id } => {
            let Some(user_rt) = users.get(&user_id) else {
                return Ok(UserResponse::Error {
                    message: format!("user runtime '{user_id}' is not loaded"),
                });
            };
            // Withdrawn from the person's drives first, then here
            // (`drive_devices::revoke`), on the runtime's own allowlist.
            kotton_device::users::drive_devices::revoke(runtime, user_rt.as_ref(), db, user_id, node_id).await
        }
        UserRequest::ThresholdSign {
            user_id,
            message_hex,
        } => match hex::decode(&message_hex) {
            Ok(message) => {
                let secrets = runtime.secrets_arc();
                // The caller resolves both: which key domain to declare on the
                // link, and how to dial. `threshold_sign` names neither the
                // machine nor the registry.
                let domain_id =
                    runtime.user_cek_domain_id(&user_id, users.get(&user_id).as_deref());
                let Some(user_rt) = users.get(&user_id) else {
                    return Ok(UserResponse::Error {
                        message: format!("user runtime '{user_id}' is not loaded"),
                    });
                };
                kotton_peer::daemon::nodes::threshold_sign(
                    &runtime.dialer(),
                    domain_id,
                    user_rt.as_ref(),
                    db,
                    user_id,
                    message,
                    secrets.as_ref(),
                )
                .await
            }
            Err(e) => Ok(UserResponse::Error {
                message: format!("invalid message_hex: {e}"),
            }),
        },
        UserRequest::PeerAdd {
            user_id,
            label,
            peer_did,
            peer_pubkey_hex,
            peer_addr,
        } => {
            kotton_peer::daemon::nodes::peer_add(
                db,
                paired_keys,
                user_id,
                label,
                peer_did,
                peer_pubkey_hex,
                peer_addr,
            )
            .await
        }
        UserRequest::GetNodeIdentity => {
            // One key, two spellings: the DID is derived from the same public
            // key the `signing_pubkey_hex` beside it carries, so `peer identity`
            // here and `peer list` on the device that paired this node agree.
            let device_did = runtime.operational_did();
            let pubkey_bytes = runtime.device_signing_pubkey_bytes();
            let signing_pubkey_hex = hex::encode(pubkey_bytes);
            Ok(UserResponse::NodeIdentity {
                device_did,
                signing_pubkey_hex,
            })
        }
        // A device's sync rules, each for one of its person's drives
        // (`drive_rules`): the drive record is the machine database's, the
        // rule the person's own.
        UserRequest::SyncConfigure {
            user_id,
            drive,
            direction,
            watch,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::drive_rules::configure(db, &user_db, user_id, drive, direction, watch).await
        }
        UserRequest::SyncRuleList { user_id } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::drive_rules::list(db, &user_db, user_id).await
        }
        UserRequest::SyncRuleRemove { user_id, drive } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::drive_rules::remove(db, &user_db, user_id, drive).await
        }
        UserRequest::SyncDrives { user_id } => {
            let (job_id, targets) = sync_engine.enqueue(&user_id).await;
            Ok(UserResponse::SyncStarted { job_id, targets })
        }
        UserRequest::SyncAwait {
            user_id: _,
            job_id,
            timeout_secs,
        } => {
            use kotton_sync::engine::AwaitResult;
            use std::time::Duration;
            match sync_engine
                .await_job(&job_id, Duration::from_secs(timeout_secs))
                .await
            {
                AwaitResult::Complete(outcome) => {
                    Ok(UserResponse::SyncOutcomeMsg { job_id, outcome })
                }
                AwaitResult::Failed(message) => Ok(UserResponse::SyncJobFailed { job_id, message }),
                AwaitResult::Timeout => Ok(UserResponse::SyncJobTimeout { job_id }),
                AwaitResult::NotFound => Err(io::Error::other(format!(
                    "sync job '{job_id}' not found (expired or never created)"
                ))),
            }
        }
        UserRequest::MountPath {
            user_id,
            node_id,
            remote_path,
            local_path,
            cache_budget_bytes,
            pins,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::nodes::mount_path(
                &user_db,
                user_id,
                node_id,
                remote_path,
                local_path,
                cache_budget_bytes,
                pins,
            )
            .await
        }
        UserRequest::MountList { user_id } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::nodes::mount_list(&user_db, user_id).await
        }
        UserRequest::MountEvict {
            user_id,
            node_id,
            local_path,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::nodes::mount_evict(&user_db, user_id, node_id, local_path).await
        }
        UserRequest::SessionList { user_id } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::nodes::session_list(&user_db, user_id).await
        }
        UserRequest::SessionEnd {
            user_id,
            session_id,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_peer::daemon::nodes::session_end(&user_db, user_id, session_id, revoked_sessions)
                .await
        }

        // -- NAT / coord ------------------------------------------------------
        UserRequest::RendezvousSet { url } => {
            handlers::device_config::coord_set(runtime, device_db, url).await
        }
        UserRequest::RelayStand { user_id, code } => {
            handlers::device_config::relay_stand(runtime, device_db, users, &user_id, code.expose()).await
        }
        UserRequest::RendezvousStatus => handlers::device_config::coord_status(device_db).await,
        UserRequest::TurnSet { url } => handlers::device_config::turn_set(device_db, url).await,
        UserRequest::InferenceSet { enabled } => {
            handlers::device_config::inference_set(device_db, enabled).await
        }
        UserRequest::ConfigStatus => handlers::device_config::config_status(device_db).await,
        UserRequest::LocalDoor { answer } => {
            handlers::device_config::local_door(runtime, device_db, answer).await
        }

        // -- Models: a model is content, a record in the person's store ------
        // The record store and the user's files are resolved here and handed
        // down, so the handler never names the residency map — the same shape `RecordInsert` and `Import` above take.
        UserRequest::ModelAdd { user_id, manifest } => {
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            kotton_device::users::models::model_add(
                &file_host(runtime, &**sync_resources),
                &runtime.schema_registry,
                &store,
                user_id,
                manifest,
                chrono::Utc::now().to_rfc3339(),
            )
            .await
        }
        // The weights' own chunked door: the daemon derives the key from the
        // hash, outside the person's tree, and streams the chunks into it.
        // `WriteFile`'s reassembly map, keyed apart, so the reaping and the
        // ordering rules are the same ones.
        UserRequest::ModelWeights {
            user_id,
            data,
            offset,
            total_size,
            content_hash,
        } => {
            kotton_device::users::models::model_weights(
                &file_host(runtime, &**sync_resources),
                user_id,
                data,
                offset,
                total_size,
                content_hash,
                file_reassembly,
            )
            .await
        }
        UserRequest::ModelList { user_id } => {
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            kotton_device::users::models::model_list(&runtime.schema_registry, &store).await
        }
        UserRequest::ModelRemove { user_id, model } => {
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            kotton_device::users::models::model_remove(
                &file_host(runtime, &**sync_resources),
                &runtime.schema_registry,
                &store,
                user_id,
                model,
            )
            .await
        }
        UserRequest::ModelUse {
            user_id,
            model,
            rebuild_index,
        } => {
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            kotton_device::users::models::model_use(
                &runtime.schema_registry,
                &store,
                model,
                rebuild_index,
            )
            .await
        }

        // -- QUIC gateway -----------------------------------------------------
        UserRequest::QuicGatewaySet {
            enabled,
            port,
            bind,
            allow,
        } => handlers::device_config::quic_gateway_set(device_db, enabled, port, bind, allow).await,
        UserRequest::QuicGatewayStatus => {
            handlers::device_config::quic_gateway_status(device_db).await
        }
        UserRequest::GetAuthorizedClients { user_id } => {
            handlers::device_config::get_authorized_clients(db, user_id).await
        }
        UserRequest::GetDeviceCert { user_id } => {
            handlers::device_config::get_device_cert(&user_id, runtime.secrets()).await
        }

        // -- HTTP gateway -----------------------------------------------------
        UserRequest::WebShellSet {
            enabled,
            port,
            bind,
            static_dir,
            allow,
        } => {
            let switched_on = enabled == Some(true);
            let resp = handlers::device_config::web_shell_set(
                device_db, enabled, port, bind, static_dir, allow,
            )
            .await?;
            // The setting takes effect now, not at the next boot.
            if switched_on && matches!(resp, UserResponse::Ok) {
                super::ensure_khttpd(ctx).await;
            }
            Ok(resp)
        }
        UserRequest::WebShellStatus => handlers::device_config::web_shell_status(device_db).await,
        // Handled in the outer connection closure like DeviceAdd (they stream).
        UserRequest::DeviceAdmit { .. } => Ok(UserResponse::Error {
            message: "DeviceAdmit must be sent on a dedicated streaming connection".to_string(),
        }),
        UserRequest::DeviceInvite { .. } => Ok(UserResponse::Error {
            message: "DeviceInvite must be sent on a dedicated streaming connection".to_string(),
        }),
        // Handled in the outer connection closure like DeviceAdd (it streams).
        UserRequest::GatewayEnroll { .. } => Ok(UserResponse::Error {
            message: "GatewayEnroll must be sent on a dedicated streaming connection".to_string(),
        }),

        // -- Record operations ------------------------------------------------
        UserRequest::RecordInsert {
            user_id,
            schema_nsid,
            record,
            root,
            app_id,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            // The record store is `record`'s type, resolved from the machine here
            // so the handler never names it.
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            // Which roots this person is in: read here, where
            // the store that holds the set is reachable, and checked by the
            // verb before it touches a row.
            let access = super::record_access::record_access(users, base, &user_id);
            kotton_record::daemon::records::record_insert(
                &runtime.schema_registry,
                &store,
                &user_db,
                &access,
                root,
                schema_nsid,
                record,
                app_id,
            )
            .await
        }

        // -- Import: a person brings their history with them -----------------
        UserRequest::Import {
            user_id,
            format,
            source_name,
            content,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            match format {
                kotton_wire::ipc::ImportFormat::Ics => {
                    kotton_record::daemon::import::import_ics(
                        &runtime.schema_registry,
                        &store,
                        &user_db,
                        user_id,
                        source_name,
                        content,
                    )
                    .await
                }
            }
        }

        UserRequest::RecordQuery {
            user_id,
            schema_nsid,
            field_eq,
            limit,
            offset,
            root,
            app_id,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            // The record store is `record`'s type, resolved from the machine here
            // so the handler never names it.
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            let access = super::record_access::record_access(users, base, &user_id);
            kotton_record::daemon::records::record_query(
                &runtime.schema_registry,
                &store,
                &user_db,
                &access,
                root,
                schema_nsid,
                field_eq,
                limit,
                offset,
                app_id,
            )
            .await
        }

        UserRequest::RecordDelete {
            user_id,
            schema_nsid,
            record_id,
            root,
            app_id,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            // The record store is `record`'s type, resolved from the machine here
            // so the handler never names it.
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            let access = super::record_access::record_access(users, base, &user_id);
            kotton_record::daemon::records::record_delete(
                &runtime.schema_registry,
                &store,
                &user_db,
                &access,
                root,
                schema_nsid,
                record_id,
                app_id,
            )
            .await
        }

        UserRequest::RecordSearch {
            user_id,
            nsid,
            text,
            limit,
            app_id,
        } => {
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            let access = super::record_access::record_access(users, base, &user_id);
            kotton_record::daemon::records::record_search(
                &runtime.schema_registry,
                &store,
                &access,
                nsid,
                text,
                limit,
                app_id,
            )
            .await
        }

        UserRequest::SchemaList { user_id } => {
            kotton_record::daemon::records::schema_list(&runtime.schema_registry, user_id).await
        }

        UserRequest::SchemaRegister {
            user_id,
            definition_json,
            app_id,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            // The record store is `record`'s type, resolved from the machine here
            // so the handler never names it.
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            kotton_record::daemon::records::schema_register(
                &runtime.schema_registry,
                &store,
                &user_db,
                user_id,
                definition_json,
                app_id,
            )
            .await
        }

        UserRequest::SchemaGet { user_id, nsid } => {
            kotton_record::daemon::records::schema_get(&runtime.schema_registry, user_id, nsid)
                .await
        }

        UserRequest::RecordOpen { user_id, url } => {
            let store =
                match record_stores.get_or_open(runtime.base_dir(), &user_id, runtime.secrets()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(UserResponse::Error {
                            message: e.to_string(),
                        })
                    }
                };
            let access = super::record_access::record_access(users, base, &user_id);
            kotton_record::daemon::records::record_open(&runtime.schema_registry, &store, &access, url)
                .await
        }

        // -- Schema grant management ------------------------------------------
        UserRequest::SchemaGrantList { app_id } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::schema_grants::schema_grant_list(&user_db, app_id).await
        }
        UserRequest::SchemaGrantSet {
            app_id,
            nsid,
            can_read,
            can_write,
            can_register,
        } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::schema_grants::schema_grant_set(
                &user_db,
                app_id,
                nsid,
                can_read,
                can_write,
                can_register,
            )
            .await
        }
        UserRequest::SchemaGrantRevoke { app_id, nsid } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::schema_grants::schema_grant_revoke(&user_db, app_id, nsid).await
        }
        UserRequest::SchemaQuotaSet {
            app_id,
            nsid,
            record_quota,
            byte_quota,
        } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::schema_grants::schema_quota_set(
                &user_db,
                app_id,
                nsid,
                record_quota,
                byte_quota,
            )
            .await
        }

        // -- Handler registry -------------------------------------------------
        UserRequest::RegisterHandler { app_id, nsid } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::handlers_registry::handler_register(&user_db, app_id, nsid).await
        }
        UserRequest::UnregisterHandler { app_id, nsid } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::handlers_registry::handler_unregister(&user_db, app_id, nsid).await
        }
        UserRequest::GetHandlerFor { nsid } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::handlers_registry::handler_get_for(&user_db, nsid).await
        }
        UserRequest::ListHandlers => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::handlers_registry::handler_list(&user_db).await
        }
        UserRequest::SetDefaultHandler { app_id, nsid } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::handlers_registry::handler_set_default(&user_db, app_id, nsid).await
        }

        // -- App lifecycle ----------------------------------------------------
        UserRequest::AppGrants { app_id } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_grants(&user_db, base, app_id).await
        }
        UserRequest::AppInstallPreview {
            manifest_toml,
            wasm_bytes,
            ..
        } => kotton_app::daemon::apps::app_install_preview(&manifest_toml, &wasm_bytes),
        UserRequest::AppInstall {
            user_id,
            manifest_toml,
            wasm_bytes,
            approved,
            bindings,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            // Resolve bindings against the daemon's own reading of the manifest.
            // The client named shapes and paths; the grants are built here, so a
            // capability the app never declared has no way in — there is no
            // shape to name. `app_install` still refuses anything outside what
            // the manifest requested, which now covers the `approved` list only.
            let approved = if bindings.is_empty() {
                kotton_schemas::ApprovedCapabilities::approved_by_user(approved)
            } else {
                let manifest = kotton_schemas::AppManifest::from_toml(&manifest_toml)
                    .map_err(|e| std::io::Error::other(format!("manifest parse error: {e}")))?;
                let non_vfs: Vec<_> = approved
                    .into_iter()
                    .filter(|g| !matches!(g.target, kotton_schemas::CapabilityTarget::Vfs { .. }))
                    .collect();
                kotton_schemas::ApprovedCapabilities::from_bindings(
                    &manifest.vfs_shapes(),
                    &bindings,
                    non_vfs,
                )
                .map_err(std::io::Error::other)?
            };
            kotton_app::daemon::apps::app_install(
                &user_db,
                base,
                &user_id,
                manifest_toml,
                wasm_bytes,
                Some(runtime.event_bus()),
                runtime.secrets(),
                approved,
            )
            .await
        }
        UserRequest::AppUninstall { app_id } => {
            // If a long-lived runner is active, send on-terminate before uninstalling.
            if let Some(mut instance) = live_instances.lock().await.remove(&app_id) {
                kotton_app::daemon::apps::terminate_long_lived_instance(&mut instance).await;
            }
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_uninstall(&user_db, base, app_id).await
        }
        UserRequest::AppVerify { app_id } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_verify(&user_db, base, &app_id).await
        }

        // Confined extensions. Separate verbs from the
        // app ones on purpose: different consent story, different world.
        UserRequest::ExtensionInstall {
            user_id,
            manifest_toml,
            wasm_bytes,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            handlers::extensions::extension_install(
                &user_db,
                base,
                &user_id,
                manifest_toml,
                wasm_bytes,
                runtime.secrets(),
            )
            .await
        }
        UserRequest::ExtensionList { user_id } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            handlers::extensions::extension_list(&user_db).await
        }
        UserRequest::ExtensionRemove {
            user_id,
            extension_id,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            handlers::extensions::extension_remove(&user_db, base, &extension_id).await
        }
        UserRequest::AppList => {
            let live_ids: std::collections::HashSet<String> =
                live_instances.lock().await.keys().cloned().collect();
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_list(&user_db, &live_ids).await
        }
        UserRequest::AppRegisterBundle {
            app_id,
            name,
            version,
            capabilities_json,
            bundle_path,
            dev,
        } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_register_bundle(
                &user_db,
                app_id,
                name,
                version,
                capabilities_json,
                bundle_path,
                dev,
            )
            .await
        }
        UserRequest::AppGetBundlePath { app_id } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_get_bundle_path(&user_db, app_id).await
        }
        UserRequest::AppGetRole { role } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_get_role(&user_db, role).await
        }
        UserRequest::AppSetRole { role, app_id } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_app::daemon::apps::app_set_role(&user_db, role, app_id).await
        }
        UserRequest::AppLaunch {
            app_id,
            launch_args,
        } => {
            let user_id = session_user.clone();
            let user_db = user_db_for(runtime, users, user_dbs, base, user_id.as_deref()).await?;
            // The occupant host is built unconditionally and handed to every
            // one of these arms. It is not the gate: `apps.rs` reads the
            // user's own `app_roles` designation to decide whether *this* app
            // is instantiated into `world occupant`, and an app that is not
            // has no `auth` import to call. Deciding it twice, here and there,
            // is how the two answers would come to differ.
            let occupant = occupant_host(
                runtime,
                users,
                sessions,
                base,
                db,
                record_stores,
                ceremonies,
                user_dbs,
                event_log_tasks,
                device_db,
                connected_peers,
                surface_proxy,
                ctx.browser_admissions(),
            );
            let infer =
                super::infer_host::infer_host(runtime, record_stores, user_id.clone(), infer_proxy);
            // The person's kept records (`schema.kept`), for the same person infer
            // answers for: any app may hold `schema.read`, so this is not occupant-gated.
            let records = super::record_access::records_host(runtime, users, base, record_stores, user_id.clone());
            kotton_app::daemon::apps::app_launch(
                &app_host(
                    runtime.event_bus(),
                    surface_proxy,
                    &ctx.runner,
                    base,
                    runtime.secrets(),
                    users,
                    sync_engine.hand_over_signal(),
                ),
                &user_db,
                base,
                Arc::clone(&live_instances),
                app_id,
                launch_args,
                user_id,
                Some(&occupant),
                Some(&infer),
                Some(&records),
            )
            .await
        }
        UserRequest::AppMessage { app_id, msg } => {
            let user_id = session_user.clone();
            let user_db = user_db_for(runtime, users, user_dbs, base, user_id.as_deref()).await?;
            // The occupant host is built unconditionally and handed to every
            // one of these arms. It is not the gate: `apps.rs` reads the
            // user's own `app_roles` designation to decide whether *this* app
            // is instantiated into `world occupant`, and an app that is not
            // has no `auth` import to call. Deciding it twice, here and there,
            // is how the two answers would come to differ.
            let occupant = occupant_host(
                runtime,
                users,
                sessions,
                base,
                db,
                record_stores,
                ceremonies,
                user_dbs,
                event_log_tasks,
                device_db,
                connected_peers,
                surface_proxy,
                ctx.browser_admissions(),
            );
            let infer =
                super::infer_host::infer_host(runtime, record_stores, user_id.clone(), infer_proxy);
            // The person's kept records (`schema.kept`), for the same person infer
            // answers for: any app may hold `schema.read`, so this is not occupant-gated.
            let records = super::record_access::records_host(runtime, users, base, record_stores, user_id.clone());
            kotton_app::daemon::apps::app_message(
                &app_host(
                    runtime.event_bus(),
                    surface_proxy,
                    &ctx.runner,
                    base,
                    runtime.secrets(),
                    users,
                    sync_engine.hand_over_signal(),
                ),
                &user_db,
                base,
                Arc::clone(&live_instances),
                app_id,
                msg,
                user_id,
                Some(&occupant),
                Some(&infer),
                Some(&records),
            )
            .await
        }
        UserRequest::QueryEvents {
            category,
            level,
            since,
            limit,
        } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            let events = crate::db::event_log_db::query_events(
                &user_db,
                category.as_deref(),
                level.as_deref(),
                since,
                limit.unwrap_or(200),
            )
            .await?;
            Ok(UserResponse::EventList { events })
        }

        // -- Event log integrity ----------------------------------------------
        UserRequest::VerifyEventLog { user_id } => {
            use kotton_common::crypto::kdf_labels;
            use kotton_crypto::derive_db_key;

            let master = crate::db::user_db::resolve_master(runtime.secrets(), &user_id)?;
            let hmac_key_opt: Option<[u8; 32]> =
                master.map(|m| derive_db_key(&m, kdf_labels::HMAC_EVENTS));

            match hmac_key_opt {
                None => Ok(UserResponse::Error {
                    message: "no active session key â€” unlock your session first".to_string(),
                }),
                Some(hmac_key) => {
                    let user_db =
                        user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
                    match crate::db::event_log_db::verify_event_log(&user_db, &hmac_key).await {
                        Ok((ok, first_broken_at)) => Ok(UserResponse::EventLogIntegrity {
                            ok,
                            first_broken_at,
                        }),
                        Err(e) => Ok(UserResponse::Error {
                            message: e.to_string(),
                        }),
                    }
                }
            }
        }

        // -- Device PIN / lock ------------------------------------------------
        UserRequest::SetLockPolicy {
            user_id,
            mode,
            auto_lock_minutes,
            pin,
        } => {
            // Any credential-bearing mode seals the vault, not just `Pin`. When
            // `Passphrase` was added this read `matches!(mode, Pin)`, which
            // would have set a passphrase that authenticated correctly while
            // silently leaving the at-rest vault sealed under the *old*
            // credential — two mechanisms for one credential, split, arriving
            // as a bug.
            let seals_vault = matches!(
                mode,
                kotton_wire::ipc::LockMode::Pin | kotton_wire::ipc::LockMode::Passphrase
            );
            // The bar follows what limits guessing on *this* user's vault: their
            // hardware binding, where its key carries an auth policy the chip
            // counts against; nothing, otherwise — the enclave does not count
            // attempts.
            let limiting = kotton_identity::provisioning::attempt_limiting_for_user(
                runtime.as_ref(),
                &user_id,
            );
            // Judged and hashed first, written last. The record names the
            // credential that opens the sealed copy, so it changes only once
            // that copy is written: a weak or missing credential is refused
            // before anything is sealed, and a seal that fails leaves the
            // record as it was — the passphrase on record, or none, is the one
            // the device had before, never one it holds nothing under. The
            // same order `kotton_device::users::recover` keeps.
            let prepared = match lock_policy::prepare_policy(
                mode,
                auto_lock_minutes,
                pin.as_ref().map(|p| p.expose()),
                limiting,
            ) {
                Ok(prepared) => prepared,
                Err(e) => {
                    return Ok(UserResponse::Error {
                        message: e.to_string(),
                    })
                }
            };
            // Keep the at-rest vault in sync with the credential: sealing the
            // three operational roots under the same secret lets a later
            // `UnlockWithPin` restore them after keychain loss.
            // Changing the credential re-seals, which is what makes it
            // changeable rather than merely re-hashed.
            if seals_vault {
                if let Some(credential) = pin.as_ref().map(|p| p.expose()) {
                    if let Err(e) = runtime.set_user_pin(&user_id, credential).await {
                        tracing::warn!(user_id = %user_id, "passphrase not set: vault seal failed: {e:#}");
                        return Ok(UserResponse::Error {
                            message: format!(
                                "the passphrase was not changed: this device could not seal \
                                 the keys it holds for '{user_id}' under the new one ({e:#}). \
                                 The passphrase on record is the one it had before, or none if \
                                 it had none; set the new one again once the cause is fixed."
                            ),
                        });
                    }
                }
            }
            if let Err(e) = prepared.record(base, &user_id) {
                return Ok(UserResponse::Error {
                    message: format!(
                        "the keys this device holds for '{user_id}' are sealed under the new \
                         passphrase, which could not be recorded ({e}); the record still names \
                         the passphrase it had. Until it is set again, an unlock that has to \
                         restore the keys from that copy is refused under either one: the old \
                         passphrase does not open the copy, and the new one is not on record. \
                         Set the new passphrase again while this session holds the keys; once \
                         they leave memory, the recovery phrase restores them: \
                         `kotton id recover {user_id}`."
                    ),
                });
            }
            // A credential was just presented, and the policy it came with may
            // have changed the window's length: arm it now, from the policy
            // just written, rather than leaving the default that adoption
            // applied.
            custody_window::arm(runtime.as_ref(), base, &user_id);
            Ok(UserResponse::LockPolicySet)
        }
        UserRequest::GetLockPolicy { user_id } => match lock_policy::load(base, &user_id) {
            Ok(p) => Ok(UserResponse::LockPolicy {
                mode: p.mode,
                auto_lock_minutes: p.auto_lock_minutes,
            }),
            Err(e) => Ok(UserResponse::Error {
                message: e.to_string(),
            }),
        },
        UserRequest::GetUnlockMethods { user_id } => {
            // `pin_hash` and not the vault: it is `try_unlock_with_pin` that
            // decides whether a PIN opens a session, and that reads the hash.
            // The vault is what a successful unlock then uses to restore the
            // operational roots — a user whose copy does not open under the
            // passphrase on record is refused by `UnlockWithPin`, which says
            // so, rather than told "no passphrase here", which they would know
            // to be false.
            //
            // An unknown user falls to `LockPolicy::default()` — `pin: false`,
            // same as a real user without one. Nothing here distinguishes them.
            let pin = lock_policy::load(base, &user_id)
                .map(|p| p.pin_hash.is_some())
                .unwrap_or(false);
            Ok(UserResponse::UnlockMethods {
                pin,
                recovery_key: true,
            })
        }
        UserRequest::GetUnlockState { user_id } => {
            // The session half is *this connection's*: a token names one user,
            // so "a live session for `user_id`" is "this connection's live
            // session is theirs". Read through `live_session` so an expired
            // token is dropped here exactly as it would be on any other verb.
            let token = conn_session
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| s.token.clone());
            let session = token
                .and_then(|t| sessions::live_session(sessions, &t))
                .filter(|s| s.user_id == user_id);
            // The custody half is the user's, whoever asks. Three states, in
            // the order that makes the third honest: held in memory with an
            // end; nothing held anywhere; or held by the platform keychain with
            // no end, which is readable and is not what "open" promises.
            let custody = match runtime.custody().open_until(&user_id) {
                Some(until) => kotton_wire::ipc::CustodyState::Open { until },
                None => {
                    let in_platform = runtime
                        .secrets()
                        .get_secret(
                            &kotton_common::crypto::kdf_labels::master_secret_keychain_key(
                                &user_id,
                            ),
                        )
                        .ok()
                        .flatten()
                        .is_some();
                    if in_platform {
                        kotton_wire::ipc::CustodyState::InPlatformStore
                    } else {
                        kotton_wire::ipc::CustodyState::Locked
                    }
                }
            };
            Ok(UserResponse::UnlockState {
                session_live: session.is_some(),
                session_until: session.and_then(|s| s.expires_at),
                custody,
            })
        }
        UserRequest::LockCustody { user_id } => {
            custody_window::lock_now(
                runtime,
                users,
                user_dbs,
                record_stores,
                event_log_tasks,
                &user_id,
            )
            .await;
            Ok(UserResponse::CustodyLocked)
        }
        UserRequest::ContactAdd {
            user_id,
            contact_did,
        } => {
            let Some(user_rt) = users.get(&user_id) else {
                return Ok(UserResponse::Error {
                    message: format!("user runtime '{user_id}' is not loaded"),
                });
            };
            match runtime.add_contact(&user_rt, &contact_did).await {
                Ok(()) => Ok(UserResponse::ContactAdded { did: contact_did }),
                Err(e) => Ok(UserResponse::Error {
                    message: e.to_string(),
                }),
            }
        }
        UserRequest::ContactList { user_id } => {
            let Some(user_rt) = users.get(&user_id) else {
                return Ok(UserResponse::Error {
                    message: format!("user runtime '{user_id}' is not loaded"),
                });
            };
            match user_rt.list_contacts().await {
                Ok(contacts) => Ok(UserResponse::ContactListing { contacts }),
                Err(e) => Ok(UserResponse::Error {
                    message: e.to_string(),
                }),
            }
        }
        UserRequest::BindDeviceHardware {
            user_id,
            credential,
        } => match runtime.bind_device(&user_id, credential.expose()).await {
            Ok(()) => Ok(UserResponse::DeviceBound {
                backend: "TPM".to_string(),
            }),
            Err(e) => Ok(UserResponse::Error {
                message: e.to_string(),
            }),
        },
        UserRequest::UnlockWithPin { user_id, pin, repair } => {
            // Clear any stale session on this connection first, but carry its
            // trust-origin across the unlock — the transport is the same
            // connection. Default Local if there was no prior session (PIN unlock is
            // a local-presence ceremony).
            let stale = conn_session.lock().unwrap().take();
            let prior_origin = stale
                .as_ref()
                .map(|s| s.origin)
                .unwrap_or(kotton_wire::ConnTrustOrigin::Local);
            // Carry the principal across the unlock for the same reason as origin:
            // it is the same connection and the same party.
            let prior_principal = stale
                .as_ref()
                .map(|s| s.principal.clone())
                .unwrap_or(kotton_wire::ipc::Principal::LocalOperator);
            if let Some(stale_sess) = stale {
                sessions.write().unwrap().remove(&stale_sess.token);
            }
            match lock_policy::try_unlock_with_pin(base, &user_id, pin.expose(), sessions) {
                Ok(lock_policy::PinAttempt::Unlocked(token)) => {
                    // If the operational roots are absent (cold start / keychain
                    // loss), restore them from the PIN-sealed vault.
                    // The one check both doors make
                    // (`custody_window::restore_roots_if_absent`). A store that
                    // could not say whether it holds the roots, or a sealed copy
                    // that does not open under the passphrase the record
                    // accepted, refuses the unlock, and the session just opened
                    // is closed again.
                    //
                    // With `repair`, the owner asked for more than a restore: a
                    // root the store could not read is written from the vault,
                    // one that read is compared with it, and a mismatch refuses
                    // (`custody_window::repair_roots_from_vault`). It runs here,
                    // after `try_unlock_with_pin` has counted and accepted the
                    // credential, so a repair answers to every guard an unlock
                    // does and is not an uncounted way to try a passphrase.
                    let restored = if repair {
                        custody_window::repair_roots_from_vault(runtime.as_ref(), &user_id, pin.expose())
                            .await
                            .map(Some)
                    } else {
                        custody_window::restore_roots_if_absent(runtime.as_ref(), &user_id, pin.expose())
                            .await
                            .map(|()| None)
                    };
                    let repaired = match restored {
                        Ok(repaired) => repaired,
                        Err(e) => {
                            sessions.write().unwrap().remove(&token);
                            return Ok(UserResponse::Error { message: e.to_string() });
                        }
                    };
                    // The roots are back, and that is not the same as the account
                    // being open: a `UserStore` binds its CEK at load time, so
                    // the resident store may still be keyless. Rebuild and swap
                    // — the same two steps `users::pairing` takes when an
                    // enrollment delivers a CEK after startup,
                    // and the same function the lock screen's door calls, so the
                    // two doors cannot disagree (`custody_window::rekey_resident_store`).
                    custody_window::rekey_resident_store(
                        runtime.as_ref(),
                        users,
                        user_dbs,
                        event_log_tasks,
                        base,
                        &user_id,
                    )
                    .await;
                    // The credential re-arms the custody window — whether the
                    // roots were just restored (adoption armed the default)
                    // or were already held (the window was wherever the last
                    // credential left it). A person who has just unlocked
                    // should not meet a vault that closes before the session
                    // they were just given does.
                    custody_window::arm(runtime.as_ref(), base, &user_id);
                    *conn_session.lock().unwrap() = Some(ConnSessionData {
                        token: token.clone(),
                        scope: None,
                        cek_available: kotton_peer::daemon::nodes::user_has_cek(
                            &user_id,
                            runtime.secrets(),
                        ),
                        origin: prior_origin,
                        principal: prior_principal,
                        browser_key: None,
                    });
                    Ok(UserResponse::UnlockOk {
                        session_token: kotton_wire::ipc::SecretText::new(token),
                        repaired,
                    })
                }
                Ok(lock_policy::PinAttempt::Wrong { attempts_remaining }) => {
                    Ok(UserResponse::UnlockFailed { attempts_remaining })
                }
                Ok(lock_policy::PinAttempt::RateLimited { retry_after_secs }) => {
                    tracing::warn!(
                        user_id = %user_id,
                        retry_after_secs,
                        "PIN unlock refused: attempt budget spent"
                    );
                    Ok(UserResponse::UnlockRateLimited { retry_after_secs })
                }
                Err(e) => Ok(UserResponse::Error {
                    message: e.to_string(),
                }),
            }
        }

        // -- Daemon health ------------------------------------------------
        UserRequest::DaemonStatus => {
            let uptime_secs = started_at.elapsed().as_secs();
            let user_count = users.count() as u32;
            let app_count =
                match user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await {
                    Ok(user_db) => app_registry_db::count_apps(&user_db).await.unwrap_or(0),
                    Err(_) => 0,
                };
            // Event counts come from the caller's own log (events split); a
            // daemon with no resolvable user reports zeros rather than erroring
            // a status probe.
            let (event_count, error_count, last_event_ts) =
                match user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await {
                    Ok(user_db) => (
                        crate::db::event_log_db::count_events(&user_db)
                            .await
                            .unwrap_or(0),
                        crate::db::event_log_db::count_recent_errors(&user_db)
                            .await
                            .unwrap_or(0),
                        crate::db::event_log_db::last_event_timestamp(&user_db)
                            .await
                            .unwrap_or(None),
                    ),
                    Err(_) => (0, 0, None),
                };
            let last_event_secs_ago = last_event_ts
                .map(|ts| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    (now - ts).max(0) as u64
                })
                .unwrap_or(0);
            Ok(UserResponse::DaemonStatusInfo {
                version: kotton_version::VERSION.to_owned(),
                uptime_secs,
                user_count,
                app_count,
                event_count,
                error_count,
                last_event_secs_ago,
            })
        }

        // -- Recovery status -------------------------------------------------
        UserRequest::ConfirmMnemonic { user_id } => {
            match runtime.confirm_mnemonic(&user_id).await {
                Ok(()) => Ok(UserResponse::MnemonicConfirmed),
                Err(e) => Ok(UserResponse::Error {
                    message: e.to_string(),
                }),
            }
        }
        UserRequest::GetRecoveryStatus { user_id } => match runtime.get_recovery_status(&user_id) {
            Ok(status) => Ok(UserResponse::RecoveryStatus {
                mnemonic_confirmed: status.mnemonic_confirmed,
                pin_set: status.pin_set,
                escrow_set: status.escrow_set,
                guardian_count: status.guardian_count,
            }),
            Err(e) => Ok(UserResponse::Error {
                message: e.to_string(),
            }),
        },

        // -- Key health -------------------------------------------------------
        UserRequest::GetKeyHealth { user_id } => match runtime.get_key_health(&user_id) {
            Ok(h) => {
                use kotton_wire::ipc::{KeyHealth, RecoveryLayerStatus};
                Ok(UserResponse::KeyHealthInfo(KeyHealth {
                    root_algorithm: h.root_algorithm,
                    key_version: h.key_version,
                    last_rotated_at: h.last_rotated_at,
                    rotation_policy_days: h.rotation_policy_days,
                    rotation_due: h.rotation_due,
                    recovery_layers: h
                        .recovery_layers
                        .into_iter()
                        .map(|l| RecoveryLayerStatus {
                            layer: l.layer,
                            active: l.active,
                            last_tested_at: l.last_tested_at,
                        })
                        .collect(),
                }))
            }
            Err(e) => Ok(UserResponse::Error {
                message: e.to_string(),
            }),
        },

        // -- Window registry --------------------------------------------------
        UserRequest::WindowOpened {
            app_id,
            instance_id,
            title,
        } => match uuid::Uuid::parse_str(&instance_id) {
            Ok(id) => {
                // The owner comes from the session, never from the request. A
                // client that could name its own owner could claim
                // WindowOwner::System and draw something the shell renders as a
                // login prompt.
                let Some(uid) = session_user.clone() else {
                    return Ok(UserResponse::NoActiveSession);
                };
                kotton_surface::window_opened(
                    &**window_registry,
                    kotton_surface::WindowOwner::User(uid),
                    app_id,
                    id,
                    title,
                );
                Ok(UserResponse::WindowAck)
            }
            Err(e) => Ok(UserResponse::Error {
                message: format!("invalid instance_id: {e}"),
            }),
        },
        UserRequest::WindowClosed { instance_id } => match uuid::Uuid::parse_str(&instance_id) {
            Ok(id) => {
                let Some(uid) = session_user.clone() else {
                    return Ok(UserResponse::NoActiveSession);
                };
                kotton_surface::window_closed(
                    &**window_registry,
                    &kotton_surface::WindowOwner::User(uid),
                    id,
                );
                Ok(UserResponse::WindowAck)
            }
            Err(e) => Ok(UserResponse::Error {
                message: format!("invalid instance_id: {e}"),
            }),
        },
        UserRequest::WindowList => {
            use kotton_wire::ipc::WindowStateDto;
            let Some(uid) = session_user.clone() else {
                return Ok(UserResponse::NoActiveSession);
            };
            let windows = kotton_surface::window_list(
                &**window_registry,
                &kotton_surface::WindowOwner::User(uid),
            )
            .into_iter()
            .map(|w| WindowStateDto {
                app_id: w.app_id,
                instance_id: w.instance_id.to_string(),
                title: w.title,
                badge: w.badge,
                progress: w.progress,
                attention: w.attention,
            })
            .collect();
            Ok(UserResponse::WindowList { windows })
        }

        // -- Trust registry + grant management (Step 8 / identity_model) ------
        UserRequest::TrustAdd { org_did, .. } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::grants::trust_add(&user_db, org_did).await
        }
        UserRequest::TrustRemove { org_did, .. } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::grants::trust_remove(&user_db, org_did).await
        }
        UserRequest::TrustList { .. } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::grants::trust_list(&user_db).await
        }
        UserRequest::GrantRevoke { envelope_id, .. } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::grants::grant_revoke(&user_db, envelope_id).await
        }
        UserRequest::GrantImport { envelope_json, .. } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_grant::daemon::grants::grant_import(&user_db, db, envelope_json).await
        }

        // -- Org identity â€” single-key (Step 9 / identity_model) -------------
        UserRequest::OrgNew { user_id, name } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::orgs::org_new(&user_db, &user_id, name, runtime.secrets()).await
        }
        UserRequest::OrgShow { org_did, .. } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_org::daemon::orgs::org_show(&user_db, org_did).await
        }
        UserRequest::OrgList { user_id } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::orgs::org_list(&user_db, &user_id, runtime.secrets()).await
        }
        UserRequest::OrgGrantIssue {
            user_id,
            org_did,
            member_did,
            caps,
            ttl_secs,
            node_did,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::orgs::org_grant_issue(
                &user_db,
                &user_id,
                org_did,
                member_did,
                caps,
                ttl_secs,
                node_did,
                runtime.secrets(),
            )
            .await
        }
        UserRequest::OrgGrantList { org_did, .. } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            kotton_org::daemon::orgs::org_grant_list(&user_db, org_did).await
        }
        UserRequest::OrgMemberRemove {
            org_did,
            member_did,
            ..
        } => {
            let user_db =
                user_db_for(runtime, users, user_dbs, base, session_user.as_deref()).await?;
            // Two authorities, in the order the combined version used: `org`
            // says which envelopes the member holds, `grant` revokes them, then
            // `org` forgets the tracking rows. A failed revoke leaves those rows
            // intact, so the operation stays retryable.
            let ids =
                kotton_org::daemon::orgs::org_member_envelope_ids(&user_db, &org_did, &member_did)
                    .await?;
            for id in &ids {
                kotton_grant::daemon::db::grant_db::revoke_envelope(db, id).await?;
            }
            kotton_org::daemon::orgs::org_member_forget(
                &user_db,
                org_did,
                member_did,
                ids.len() as u32,
            )
            .await
        }

        // -- A root an org owns: an organisation's records are imported into a root
        UserRequest::OrgRootCreate { user_id, org_did, name } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            let (own_aid, mut set) = match super::org_roots::open_roots(users, base, &user_id) {
                Ok(opened) => opened,
                Err(message) => return Ok(UserResponse::Error { message }),
            };
            super::org_roots::org_root_create(
                &mut set,
                &own_aid,
                &user_db,
                runtime.secrets(),
                &user_id,
                org_did,
                name,
            )
            .await
        }
        UserRequest::OrgRootInvite { user_id, root, member } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            let (own_aid, mut set) = match super::org_roots::open_roots(users, base, &user_id) {
                Ok(opened) => opened,
                Err(message) => return Ok(UserResponse::Error { message }),
            };
            super::org_roots::org_root_invite(
                &mut set,
                &own_aid,
                &user_db,
                db,
                runtime.secrets(),
                &user_id,
                root,
                member,
            )
            .await
        }

        // -- Org identity â€” FROST multi-sig (Step 10 / identity_model) --------
        UserRequest::OrgFrostNew {
            user_id,
            name,
            threshold,
            total,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::frost_orgs::org_frost_new(
                &user_db,
                &user_id,
                name,
                threshold,
                total,
                runtime.secrets(),
            )
            .await
        }
        UserRequest::OrgFrostJoin {
            user_id,
            name,
            org_did,
            share_hex,
            participant_idx,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::frost_orgs::org_frost_join(
                &user_db,
                &user_id,
                name,
                org_did,
                share_hex.expose().to_owned(),
                participant_idx,
                runtime.secrets(),
            )
            .await
        }
        UserRequest::OrgFrostSignBegin {
            user_id,
            org_did,
            member_did,
            caps,
            ttl_secs,
            node_did,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::frost_orgs::org_frost_sign_begin(
                &user_db,
                &user_id,
                org_did,
                member_did,
                caps,
                ttl_secs,
                node_did,
                runtime.secrets(),
            )
            .await
        }
        UserRequest::OrgFrostSignContribute {
            user_id,
            session_id,
            org_did,
            message_hex,
            coordinator_id_hex,
            coordinator_commitment_hex,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::frost_orgs::org_frost_sign_contribute(
                &user_db,
                &user_id,
                session_id,
                org_did,
                message_hex,
                coordinator_id_hex,
                coordinator_commitment_hex,
            )
            .await
        }
        UserRequest::OrgFrostSignFinalize {
            user_id,
            session_id,
            cosigner_id_hex,
            cosigner_commitment_hex,
            cosigner_share_hex,
        } => {
            let user_db = user_db_for(runtime, users, user_dbs, base, Some(&user_id)).await?;
            kotton_org::daemon::frost_orgs::org_frost_sign_finalize(
                &user_db,
                &user_id,
                session_id,
                cosigner_id_hex,
                cosigner_commitment_hex,
                cosigner_share_hex.expose().to_owned(),
            )
            .await
        }

        // -- Peer messaging ---------------------------------------------------
        //
        // The messaging domain asks for six capabilities, and no one object here
        // holds all of them: four are the machine's, and residency is the
        // daemon's own. `DaemonMessageHost` joins them so the domain names
        // neither.
        UserRequest::MessageChannelCreate {
            user_id,
            channel_did,
        } => {
            kotton_msg::daemon::messages::message_channel_create(
                &msg_host(runtime, users, record_stores),
                user_id,
                channel_did,
            )
            .await
        }

        UserRequest::MessageChannelGrantKey {
            user_id,
            channel_did,
            member_did,
            backfill,
        } => {
            kotton_msg::daemon::messages::message_channel_grant_key(
                &msg_host(runtime, users, record_stores),
                user_id,
                channel_did,
                member_did,
                backfill,
            )
            .await
        }

        UserRequest::MessageChannelRemoveMember {
            user_id,
            channel_did,
            member_did,
        } => {
            kotton_msg::daemon::messages::message_channel_remove_member(
                &msg_host(runtime, users, record_stores),
                user_id,
                channel_did,
                member_did,
            )
            .await
        }

        UserRequest::MessageChannelLeave { user_id, channel_did } => {
            kotton_msg::daemon::messages::message_channel_leave(
                &msg_host(runtime, users, record_stores),
                user_id,
                channel_did,
            )
            .await
        }

        UserRequest::MessageSend {
            user_id,
            recipient_did,
            body,
            thread_id,
        } => {
            let resp = kotton_msg::daemon::messages::message_send(
                &msg_host(runtime, users, record_stores),
                user_id,
                recipient_did,
                body,
                thread_id,
            )
            .await;
            if matches!(resp, Ok(UserResponse::MessageSent { .. })) {
                sync_engine.wake_background();
            }
            resp
        }

        UserRequest::MessageChannelSend {
            user_id,
            channel_did,
            body,
        } => {
            let resp = kotton_msg::daemon::messages::message_channel_send(
                &msg_host(runtime, users, record_stores),
                user_id,
                channel_did,
                body,
            )
            .await;
            if matches!(resp, Ok(UserResponse::MessageSent { .. })) {
                sync_engine.wake_background();
            }
            resp
        }

        UserRequest::MessageChannelHistory {
            user_id,
            channel_did,
            before_id,
            limit,
        } => {
            kotton_msg::daemon::messages::message_channel_history(
                &msg_host(runtime, users, record_stores),
                user_id,
                channel_did,
                before_id,
                limit,
            )
            .await
        }

        UserRequest::MessagePollInbox { user_id } => {
            kotton_msg::daemon::messages::message_poll_inbox(
                &msg_host(runtime, users, record_stores),
                user_id,
            )
            .await
        }
        UserRequest::MessageDeliveries { user_id, peer_did } => {
            kotton_msg::daemon::messages::message_deliveries(
                &msg_host(runtime, users, record_stores),
                user_id,
                peer_did,
            )
            .await
        }
        UserRequest::MessageUnreadCount { user_id } => {
            unread_count(runtime, users, record_stores, user_id).await
        }
        UserRequest::MessageMarkRead {
            user_id,
            peer_did,
            filed_at,
            message_id,
        } => mark_read(users, user_id, peer_did, filed_at, message_id).await,
        UserRequest::MessageDecryptDm {
            user_id,
            body,
            nonce,
            ephemeral_pub,
        } => {
            kotton_msg::daemon::messages::message_decrypt_dm(
                &msg_host(runtime, users, record_stores),
                user_id,
                body,
                nonce,
                ephemeral_pub,
            )
            .await
        }
        UserRequest::MessageDecryptChannel {
            user_id,
            channel_did,
            body,
            nonce,
        } => {
            kotton_msg::daemon::messages::message_decrypt_channel(
                &msg_host(runtime, users, record_stores),
                user_id,
                channel_did,
                body,
                nonce,
            )
            .await
        }

        // SubscribeEvents is handled in the outer closure before reaching here;
        // this arm exists only to satisfy exhaustiveness.
        UserRequest::SubscribeEvents { .. } => Ok(UserResponse::Error {
            message: "SubscribeEvents must be sent on a dedicated streaming connection".to_string(),
        }),

        // VfsWatch is also handled in the outer closure.
        UserRequest::VfsWatch { .. } => Ok(UserResponse::Error {
            message: "VfsWatch must be sent on a dedicated streaming connection".to_string(),
        }),

        // The streamed ceremony verbs are handled in the outer closure like
        // SubscribeEvents/VfsWatch; these arms exist only for exhaustiveness.
        UserRequest::DeviceAdd { .. } => Ok(UserResponse::Error {
            message: "DeviceAdd must be sent on a dedicated streaming connection".to_string(),
        }),
        UserRequest::DeviceJoin { .. } => Ok(UserResponse::Error {
            message: "DeviceJoin must be sent on a dedicated streaming connection".to_string(),
        }),
        UserRequest::ContactPairStart { .. } => Ok(UserResponse::Error {
            message: "ContactPairStart must be sent on a dedicated streaming connection"
                .to_string(),
        }),
        UserRequest::ContactPairJoin { .. } => Ok(UserResponse::Error {
            message: "ContactPairJoin must be sent on a dedicated streaming connection".to_string(),
        }),
        // Peer-only: served in `handle_peer_request` to a device the
        // mTLS handshake admitted. There is no IPC caller it makes sense for.
        UserRequest::RecoveryFetch { .. } => Ok(UserResponse::Error {
            message: "RecoveryFetch is served only over a peer connection".to_string(),
        }),
        UserRequest::RecoveryStore { .. } => Ok(UserResponse::Error {
            message: "RecoveryStore is served only over a peer connection".to_string(),
        }),
        // The browser channel's outbound direction: it answers with
        // a stream, so it is served in the acceptor closure like the ceremony
        // verbs, and never here.
        UserRequest::BrowserOutbound { .. } => Ok(UserResponse::Error {
            message: "BrowserOutbound must be sent on a dedicated streaming connection".to_string(),
        }),
        // A relay's introduction is asked by one of the person's devices over a
        // peer connection, never here.
        UserRequest::Introduce { .. } => Ok(UserResponse::Error {
            message: "Introduce is served only over a peer connection, to one of the person's devices"
                .to_string(),
        }),
        // A vault's verbs: a device speaks them *to* its vault
        // over the peer transport, and nothing speaks them to a device.
        UserRequest::HoldDoors { .. } => Ok(UserResponse::Error {
            message: "HoldDoors is a vault's verb, served only over a peer connection".to_string(),
        }),
        UserRequest::TakeDeliveries { .. } => Ok(UserResponse::Error {
            message: "TakeDeliveries is a vault's verb, served only over a peer connection"
                .to_string(),
        }),
        UserRequest::CarryFrame { .. } => Ok(UserResponse::Error {
            message: "CarryFrame is a vault's verb, served only over a peer connection"
                .to_string(),
        }),
        UserRequest::TenantDevice { .. } => Ok(UserResponse::Error {
            message: "TenantDevice is a vault's verb, served only over a peer connection"
                .to_string(),
        }),
        // The browsers a person admitted, and the revoke that un-admits one
        // (Article IV). Both `Local`; the revoke ends the browser's
        // live channel as well as its row — `browser_channel::revoke` says how.
        UserRequest::BrowserDeviceList { user_id } => {
            let db = user_db_for_user(ctx, &user_id).await?;
            let browsers = kotton_device::config::ops::list_browser_devices(&db, &user_id).await?;
            Ok(UserResponse::BrowserDevices { browsers })
        }
        UserRequest::BrowserDeviceRevoke { user_id, name } => {
            let db = user_db_for_user(ctx, &user_id).await?;
            match super::browser_channel::revoke(&ctx.browser_admissions(), &db, &user_id, &name)
                .await?
            {
                Some(channels_closed) => Ok(UserResponse::BrowserDeviceRevoked { channels_closed }),
                None => Ok(UserResponse::Error {
                    message: format!("no browser named '{name}' is admitted for {user_id}"),
                }),
            }
        }
        // Handled in the outer connection closure: WebShellPair streams
        // like DeviceAdd, and BrowserFrame keeps per-connection channel state. These
        // arms exist only for exhaustiveness.
        UserRequest::WebShellPair { .. } => Ok(UserResponse::Error {
            message: "WebShellPair must be sent on a dedicated streaming connection".to_string(),
        }),
        UserRequest::BrowserFrame { .. } => Ok(UserResponse::Error {
            message: "BrowserFrame is handled on the gateway relay connection".to_string(),
        }),
        // The verdict a person gives when they have compared six digits. It is a
        // single response — it fires the parked ceremony's oneshot and says so —
        // so it belongs here, where every caller reaches it: the acceptor
        // closure intercepted it, which meant a browser confirming inside its
        // sealed channel (`dispatch_inner`, which routes single-response verbs
        // through this function) was told the verb "is handled by the
        // streaming-ceremony path" and the ceremony it was in timed out.
        //
        // One implementation, called by both paths — the same move the trust
        // floor makes (`origin_refusal`), and for the same reason: an interception is a second home, and the
        // path that does not pass through it gets the stub.
        UserRequest::PairConfirmCode { token, matches, .. } => {
            kotton_peer::daemon::nodes::confirm_code(pending_confirms, token.expose().to_owned(), matches).await
        }

        // -- Runtime inspection -----------------------------------------------
        UserRequest::DaemonSidecars => {
            handlers::device_config::daemon_sidecars(sidecar_states).await
        }
        UserRequest::IpcSessions => handlers::device_config::ipc_sessions(ipc_sessions).await,

        // -- Network status ---------------------------------------------------
        UserRequest::VfsReport {
            connected_peers: peers,
        } => handlers::device_config::vfs_report(connected_peers, peers).await,
        UserRequest::SyncStatus { user_id } => {
            handlers::device_config::sync_status(
                user_id,
                sidecar_states,
                connected_peers,
                sync_engine,
            )
            .await
        }
        UserRequest::NetworkStatus { user_id } => {
            let relay = runtime.reachability().relay_readout();
            handlers::device_config::network_status(
                db,
                device_db,
                user_id,
                sidecar_states,
                connected_peers,
                relay,
            )
            .await
        }
        UserRequest::ReachStatus { .. } => Ok(handlers::device_config::reach_status(
            runtime.reachability().relay_readout(),
        )),

        // -- Storage mounts hot-reload ----------------------------------------
        UserRequest::StorageReload { user_id } => {
            let Some(user_rt) = users.get(&user_id) else {
                return Ok(UserResponse::Error {
                    message: format!("user runtime '{user_id}' is not loaded"),
                });
            };
            match runtime.rebuild_storage_mounts(&user_rt).await {
                Ok(()) => Ok(UserResponse::Ok),
                Err(e) => Ok(UserResponse::Error {
                    message: e.to_string(),
                }),
            }
        }

        // -- Peer-only sync notifications -------------------------------------
        // These are only dispatched via handle_peer_request; local IPC callers
        // cannot send them.
        UserRequest::SyncAvailable { .. }
        | UserRequest::RecordSyncAvailable { .. }
        | UserRequest::ApplyRecordChangeset { .. }
        | UserRequest::FrostSignRound { .. } => Ok(UserResponse::Error {
            message: "sync notifications are only accepted over peer connections".to_string(),
        }),
        // -- Display server / kuid --------------------------------------------
        // The kuserd → kuid direction had four arms here, returning "surface
        // requests are kuserd→kuid internal protocol". They are gone: those
        // variants are `KuidRequest` now, on kuid's own socket, so the direction
        // rule is the type and there is nothing left to reject.
    }
}

// (load_nat_config moved to kotton_device::config::db)

#[cfg(test)]
mod vfs_watch_opening_frame_tests {
    use super::handle_vfs_watch;
    use kotton_ipc::HandlerOutput;
    use kotton_sync::engine::FsWatchState;
    use kotton_wire::UserResponse;
    use std::sync::Arc;

    /// The refusal this test was written for.
    ///
    /// A watcher that never registered used to open the stream with
    /// `VfsWatchEnd` — the same frame the daemon sends when it is shutting down.
    /// `ksyncd` reads `VfsWatchEnd` as "stop", so inotify instance exhaustion —
    /// the condition a watcher test meets under a loaded suite, and the one the
    /// sidecar's fallback poll exists to survive —
    /// terminated the sidecar, and a restart re-subscribed into the same
    /// immediate end. The two facts now have two frames.
    #[tokio::test]
    async fn a_watcher_that_never_registered_opens_with_failed_not_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_change_tx, change_rx) = tokio::sync::broadcast::channel(16);
        let (_state_tx, state_rx) = tokio::sync::watch::channel(FsWatchState::Failed(Arc::from(
            "too many open files (os error 24)",
        )));

        let out = handle_vfs_watch(dir.path(), "alice".to_string(), vec![], change_rx, state_rx)
            .await
            .expect("the handler builds its stream");

        let HandlerOutput::Stream(mut rx) = out else {
            panic!("VfsWatch is a streaming handler");
        };

        let first = tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
            .await
            .expect("a failed watch answers rather than leaving the subscriber waiting")
            .expect("the handler sends a frame before closing");

        match first {
            UserResponse::VfsWatchFailed { reason } => assert!(
                reason.contains("os error 24"),
                "the frame carries the watcher's own reason, got {reason:?}"
            ),
            UserResponse::VfsWatchEnd => panic!(
                "VfsWatchEnd means the daemon is going away and tells a client to \
                 exit; a watch that could not be established is not that"
            ),
            other => panic!("expected VfsWatchFailed, got {other:?}"),
        }
    }

    /// And a watcher that did register still opens with readiness, so the
    /// failure path above is a branch rather than the only behaviour.
    #[tokio::test]
    async fn a_registered_watcher_opens_with_ready() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_change_tx, change_rx) = tokio::sync::broadcast::channel(16);
        let (_state_tx, state_rx) = tokio::sync::watch::channel(FsWatchState::Watching);

        let out = handle_vfs_watch(dir.path(), "alice".to_string(), vec![], change_rx, state_rx)
            .await
            .expect("the handler builds its stream");

        let HandlerOutput::Stream(mut rx) = out else {
            panic!("VfsWatch is a streaming handler");
        };

        let first = tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
            .await
            .expect("a registered watch answers promptly")
            .expect("the handler sends its opening frame");

        assert!(
            matches!(first, UserResponse::VfsWatchReady),
            "a registered watch opens with VfsWatchReady, got {first:?}"
        );
    }
}
