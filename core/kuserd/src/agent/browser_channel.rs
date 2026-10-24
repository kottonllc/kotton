// SPDX-License-Identifier: AGPL-3.0-or-later
//! The node's end of a browser's sealed channel: the reach tier.
//!
//! `khttpd` relays a browser's WebSocket frames to the daemon as
//! [`UserRequest::BrowserFrame`], one frame in and one out, reading none of them
//! (GW3). This module runs the far end: [`kotton_pair::browser::Issuer`] over
//! those frames, and — once the ceremony establishes — a sealed tunnel through
//! which each inner [`UserRequest`] is dispatched **as the browser**, at `Paired`
//! origin, through the same guard every other caller faces. `Paired`
//! is a step above the `Remote` a gateway or an mTLS peer carries and a step
//! below `Local`: the ceremony below is what earns it, so it is the same fact
//! this module already establishes, read by the floor.
//!
//! The `Issuer` and the tunnel state live on the connection
//! ([`ConnSessionData::browser`]): one browser is one `khttpd`→`kuserd`
//! connection, so the state is exactly the connection's.
//!
//! Admission has two doors, both the pairing ceremony's:
//!
//! - A device key the node has **never seen** waits for a human. The handler
//!   finds the operator's parked [`UserRequest::WebShellPair`] stream (the "desk"
//!   for this user), shows the six-digit SAS there, and blocks on the verdict —
//!   the same [`StreamingConfirmer`]/`PairConfirmCode` rendezvous device pairing
//!   uses. No desk means nobody is watching the node's screen, so an unknown
//!   browser is refused rather than admitted silently.
//! - A **known** key is admitted by its signature over the transcript, with no
//!   human. The node's own signature, which the browser pinned at its first
//!   visit, is what the browser checks to be sure it is still talking to the
//!   node and not the gateway.

use std::collections::HashMap;
use std::sync::Arc;

use kotton_pair::browser::{refused, Issuer, IssuerStep};
use kotton_peer::daemon::nodes::{PendingConfirms, StreamingConfirmer};
use kotton_wire::ipc::{ChannelCall, ChannelFrame, Principal};
use kotton_wire::{UserRequest, UserResponse};
use tokio::sync::mpsc;

use super::{AgentContext, ConnSessionData};

/// One user's parked `WebShellPair` streams, by a token the stream owns. A
/// browser with an unknown key is admitted only if a desk is open here — i.e.
/// a human is watching this node's screen.
pub type BrowserDesks = Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<UserResponse>>>>;

/// Every live browser channel, by a name the gateway gives it.
///
/// One home for both kinds. A browser behind a gateway *device* is keyed by
/// name here because the gateway is on another machine and the connection is
/// not the channel; a browser behind the local gateway is keyed here too, and
/// not on `ConnSessionData`, because of the outbound direction: a channel is reached by **two**
/// connections — one carrying calls in, one carrying frames out — so a channel
/// bound to either of them is a channel the other cannot find.
///
/// **How a channel ends, and what that changed.** The normal case is its
/// outbound stream ending: `khttpd` holds that stream for exactly as long as it
/// holds the browser's socket, so the end of one is the end of the other and the
/// door closes with the transport that opened it. [`CHANNEL_IDLE`] is the floor
/// under that — ten minutes — for a channel nothing is closing. The third is
/// the person's decision: [`revoke`] takes every channel admitted as a
/// credential out of this registry and disarms it, which ends the outbound
/// stream and so the socket, whatever the browser is doing at the time.
///
/// A local channel held on `ConnSessionData` would die with its IPC connection
/// outright. Here, *the door closes with the transport* is a fact about a timer
/// plus a stream rather than about the process table, which is weaker. No way
/// to exploit the difference is known — the session a channel holds is
/// long-lived either way, and a channel is reachable only by a gateway that
/// authenticated for its user and named it — and it is said here rather than
/// left to be noticed.
pub type BrowserChannels = Arc<tokio::sync::Mutex<HashMap<String, ChannelEntry>>>;

pub struct ChannelEntry {
    /// The channel itself.
    ///
    /// Behind a mutex rather than taken out and put back, because two things
    /// now seal into it: the request path answering a call, and a stream
    /// pushing a frame no call is waiting on. Both must seal under one lock —
    /// the AEAD counter is a count of frames sent, so two sealers that do not
    /// exclude each other produce two frames claiming the same nonce, and the
    /// browser can open neither.
    ///
    /// Held across `drive`'s awaits, which is bounded by one request. The one
    /// human-length wait in there is the desk's verdict during admission, and
    /// nothing can be streaming then: a channel that has not established has no
    /// outbound side to contend with.
    channel: Arc<tokio::sync::Mutex<BrowserChannel>>,
    last: std::time::Instant,
    /// The credential this channel was admitted as, once it has been — shared
    /// with the channel, which writes it at admission.
    ///
    /// Outside the channel's mutex so a revoke can find the channels a
    /// credential holds without taking every channel's lock: the lock is held
    /// for as long as a desk takes to answer during admission, which is a
    /// person reading six digits, and a revoke must not wait on a stranger's
    /// ceremony to end a browser it has already decided about.
    admitted: Arc<std::sync::OnceLock<String>>,
}

const CHANNEL_IDLE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// The per-connection state of one browser's channel.
pub struct BrowserChannel {
    issuer: Issuer,
    /// The browser's device key and proposed name, learned at `DeviceHello`.
    device: Option<([u8; 32], String)>,
    /// Whether that key was already registered when it arrived.
    known: bool,
    /// The session minted once the channel establishes; every inner request is
    /// dispatched under it, so it faces the ordinary browser floor.
    session_token: Option<String>,
    credential_id: Option<String>,
    /// The same cell as [`ChannelEntry::admitted`]: set once, at admission.
    admitted: Arc<std::sync::OnceLock<String>>,
    /// Where frames no call is waiting on go: `khttpd`'s second connection,
    /// attached by [`attach_outbound`]. `None` until it attaches, and a stream
    /// started before then has nowhere to put its frames — which is why
    /// `khttpd` attaches before it relays the browser's first frame.
    outbound: Option<mpsc::Sender<UserResponse>>,
}

impl BrowserChannel {
    fn new(
        node_key: ed25519_dalek::SigningKey,
        node_label: String,
        admitted: Arc<std::sync::OnceLock<String>>,
    ) -> Self {
        Self {
            issuer: Issuer::new(node_key, node_label),
            device: None,
            known: false,
            session_token: None,
            credential_id: None,
            admitted,
            outbound: None,
        }
    }

    /// Take away everything the channel's admission gave it: the session it
    /// dispatches under and the direction it pushes frames on.
    ///
    /// Dropping the outbound sender ends `khttpd`'s outbound stream, which is
    /// how `khttpd` learns to drop the browser's socket; a stream pump still
    /// running — a ceremony the browser started before it was revoked — finds
    /// nowhere to push and stops.
    fn disarm(&mut self) {
        self.session_token = None;
        self.credential_id = None;
        self.outbound = None;
    }

    /// Seal `frame` and push it out the channel's own direction.
    ///
    /// The caller holds the channel, so the counter is safe; the send is a
    /// `try_send` because a browser that cannot keep up must not stall the
    /// node's sealing — a dropped frame is visible to the browser as a call
    /// that never ends, and a stalled daemon is not visible at all.
    fn push(&mut self, frame: ChannelFrame) -> bool {
        let Some(tx) = self.outbound.clone() else {
            return false;
        };
        let bytes = match serde_json::to_vec(&frame) {
            Ok(b) => b,
            Err(_) => return false,
        };
        match self.issuer.seal(&bytes) {
            Ok(sealed) => tx
                .try_send(UserResponse::BrowserFrame { bytes: sealed })
                .is_ok(),
            Err(e) => {
                tracing::warn!(error = %e, "browser channel: could not seal an outbound frame");
                false
            }
        }
    }
}

/// Attach `tx` as the outbound side of the channel named `key`.
///
/// Returns false when no such channel exists — `khttpd` opens the outbound
/// connection first, so this creates the channel if it is not there yet and the
/// ceremony's first frame finds it waiting.
pub(super) async fn attach_outbound(
    ctx: &AgentContext,
    key: String,
    tx: mpsc::Sender<UserResponse>,
) {
    let entry = entry_for(ctx, &key).await;
    entry.lock().await.outbound = Some(tx);
}

/// The channel named `key`, created if this is the first thing to ask for it.
async fn entry_for(ctx: &AgentContext, key: &str) -> Arc<tokio::sync::Mutex<BrowserChannel>> {
    // Read the node's name before taking the registry lock: it is a database
    // read, and every channel on this node waits behind that lock.
    let label = node_label(ctx).await;
    let now = std::time::Instant::now();
    let mut g = ctx.browser_channels.lock().await;
    g.retain(|_, e| now.duration_since(e.last) < CHANNEL_IDLE);
    if let Some(e) = g.get_mut(key) {
        e.last = now;
        return Arc::clone(&e.channel);
    }
    let node_key = ctx.runtime.device_signing_key().clone();
    let admitted = Arc::new(std::sync::OnceLock::new());
    let channel = Arc::new(tokio::sync::Mutex::new(BrowserChannel::new(
        node_key,
        label,
        Arc::clone(&admitted),
    )));
    g.insert(
        key.to_string(),
        ChannelEntry {
            channel: Arc::clone(&channel),
            last: now,
            admitted,
        },
    );
    channel
}

/// Drop the channel named `key`. Called when its outbound stream ends, which is
/// when `khttpd` has lost the browser's socket.
pub(super) async fn close_channel(ctx: &AgentContext, key: &str) {
    ctx.browser_channels.lock().await.remove(key);
}

/// **What a browser's revoke reaches, and nothing else** — the one handle both
/// doors that revoke hold (`BrowserDeviceRevoke` at a terminal, and
/// `revoke-browser` on the Devices screen).
///
/// A revoke has to end three things: the row, every session the admission
/// minted, and every channel admitted as it. The last two live in maps this
/// daemon keeps — the principal-session map and the channel registry — and the
/// screen's host held neither. Handing it the maps would hand a guest-facing
/// host every browser's live token and every open channel to answer one verb;
/// this is the verb instead. Its fields are private to this module and its only
/// use is [`revoke`], so *what can the Devices screen do to a browser's
/// admission* is answered by reading one function, the same one the terminal's
/// revoke calls — the rule `interface network`'s readout set for the machine's
/// configuration.
#[derive(Clone)]
pub struct BrowserAdmissions {
    sessions: super::sessions::SessionMap,
    principals: Arc<std::sync::RwLock<HashMap<String, Principal>>>,
    channels: BrowserChannels,
}

impl BrowserAdmissions {
    pub(super) fn new(
        sessions: super::sessions::SessionMap,
        principals: Arc<std::sync::RwLock<HashMap<String, Principal>>>,
        channels: BrowserChannels,
    ) -> Self {
        Self {
            sessions,
            principals,
            channels,
        }
    }
}

impl AgentContext {
    /// The revoke-only handle on this connection's daemon's admissions.
    pub(super) fn browser_admissions(&self) -> BrowserAdmissions {
        BrowserAdmissions::new(
            Arc::clone(&self.sessions),
            Arc::clone(&self.principal_sessions),
            Arc::clone(&self.browser_channels),
        )
    }
}

/// Revoke the browser admitted for `user_id` as `name` (Article IV), and end
/// what its admission is still holding open.
///
/// **Decided here, by the daemon that holds the admission.** Nothing is asked
/// of the browser: it is not told to leave and nothing waits on it to agree.
///
/// A revoked browser could still speak for one reason: its admission had been
/// turned into two things reachable by name, and removing the row reached
/// neither. The session token it minted sat live in the session map, where
/// every inner call resolved it; and its channel sat in the registry under the
/// name the gateway relays to, established and holding that token. So both go,
/// and no call on the browser's path has to consult anything new to refuse it
/// — `CLAUDE.md`'s second design test. A per-call lookup against a revocation
/// set would have been a third guard on a token that should no longer exist.
///
/// - the row, so its next handshake meets an unknown key and waits for a human;
/// - every session minted for its credential, so a call dispatched under one
///   meets the ordinary session guard and is refused `NoActiveSession`;
/// - every channel admitted as it, taken out of the registry — the next sealed
///   frame on that name finds a channel that never established and is refused
///   in the clear — and disarmed, which ends its outbound stream and so the
///   browser's socket.
///
/// Returns the number of channels that were open, or `None` when no browser by
/// that name was admitted.
///
/// `db` is `user_id`'s own database — the one the row is in. Both callers
/// resolve it for the person they already act for; nothing here chooses whose.
pub(super) async fn revoke(
    admissions: &BrowserAdmissions,
    db: &sqlx::SqlitePool,
    user_id: &str,
    name: &str,
) -> std::io::Result<Option<u32>> {
    let Some(credential_id) =
        kotton_device::config::ops::revoke_browser_device(db, user_id, name).await?
    else {
        return Ok(None);
    };

    // The sessions. A browser's principal session is keyed by the credential
    // it was admitted as, and nothing else names that credential, so this is
    // every token that admission ever minted — the live channel's and any a
    // channel since dropped left behind.
    let tokens: Vec<String> = {
        let mut principals = admissions.principals.write().unwrap();
        let tokens: Vec<String> = principals
            .iter()
            .filter(|(_, p)| {
                matches!(p, Principal::Browser { credential_id: c } if *c == credential_id)
            })
            .map(|(t, _)| t.clone())
            .collect();
        for t in &tokens {
            principals.remove(t);
        }
        tokens
    };
    {
        let mut sessions = admissions.sessions.write().unwrap();
        for t in &tokens {
            sessions.remove(t);
        }
    }

    // The channels. Out of the registry under its lock; disarmed after it is
    // released, since disarming takes each channel's own lock and every channel
    // on this node waits behind the registry's.
    let closed: Vec<Arc<tokio::sync::Mutex<BrowserChannel>>> = {
        let mut g = admissions.channels.lock().await;
        let keys: Vec<String> = g
            .iter()
            .filter(|(_, e)| e.admitted.get() == Some(&credential_id))
            .map(|(k, _)| k.clone())
            .collect();
        keys.iter()
            .filter_map(|k| g.remove(k))
            .map(|e| e.channel)
            .collect()
    };
    for channel in &closed {
        channel.lock().await.disarm();
    }
    tracing::info!(
        user_id,
        name,
        sessions = tokens.len(),
        channels = closed.len(),
        "browser revoked"
    );
    Ok(Some(closed.len() as u32))
}

/// Drive one relayed frame. Returns the frame to relay back to the browser.
///
/// `user_id` is the user `khttpd` authenticated for (its bootstrap token names
/// exactly one). `ttl_secs` bounds how long an unknown browser waits for a human.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_frame(
    ctx: &AgentContext,
    caller: kotton_ipc::Caller,
    conn_session: &std::sync::Arc<std::sync::Mutex<Option<ConnSessionData>>>,
    pending_confirms: &PendingConfirms,
    desks: &BrowserDesks,
    channel_id: Option<String>,
    frame: Vec<u8>,
) -> UserResponse {
    // Who is khttpd acting for? Its bootstrap token names one user.
    let user_id = {
        let g = conn_session.lock().unwrap();
        match g
            .as_ref()
            .and_then(|s| kotton_session::service::tokens::live_user(&ctx.sessions, &s.token))
        {
            Some(u) => u,
            None => return sealed_or_plain_refuse("this gateway connection is not authenticated"),
        }
    };
    // A gateway that named its channel is telling us which one; one that did
    // not gets a name of its own, minted once and kept for this connection.
    // Without that, two browsers on two connections would share the key
    // `local:<user>#-` and each would find the other's ceremony half-done — the
    // regression the connection-local channel used to make impossible, and the
    // reason the connection still remembers something.
    let key = match channel_id {
        Some(name) => local_key(&user_id, Some(&name)),
        None => {
            let mut g = conn_session.lock().unwrap();
            let Some(session) = g.as_mut() else {
                return sealed_or_plain_refuse("this gateway connection is not authenticated");
            };
            session
                .browser_key
                .get_or_insert_with(|| {
                    local_key(&user_id, Some(&uuid::Uuid::new_v4().simple().to_string()))
                })
                .clone()
        }
    };
    serve_frame(ctx, &caller, &user_id, pending_confirms, desks, &key, frame).await
}

/// The registry name of a channel reached through the local gateway
/// connection. Namespaced away from a gateway device's key so a relayed
/// channel and a local one can never collide on a name either chose.
pub(super) fn local_key(user_id: &str, channel_id: Option<&str>) -> String {
    format!("local:{user_id}#{}", channel_id.unwrap_or("-"))
}

/// Drive one frame against the channel named `key`, whatever transport it
/// arrived on. Both paths are this function; they differ only in the name.
async fn serve_frame(
    ctx: &AgentContext,
    caller: &kotton_ipc::Caller,
    user_id: &str,
    pending_confirms: &PendingConfirms,
    desks: &BrowserDesks,
    key: &str,
    frame: Vec<u8>,
) -> UserResponse {
    let entry = entry_for(ctx, key).await;
    let (out, pushed) = {
        let mut channel = entry.lock().await;
        let out = drive(
            ctx,
            caller,
            user_id,
            pending_confirms,
            desks,
            &mut channel,
            &frame,
        )
        .await;
        // A channel with an outbound side sends *everything* that way, this
        // reply included.
        //
        // Not tidiness — the seal's counter is implicit, so the browser opens
        // frames strictly in the order the node sealed them. Two writers to one
        // socket can interleave, and an interleaved frame does not decrypt at
        // all. One writer is the only arrangement in which the order they were
        // sealed and the order they arrive are the same sentence.
        //
        // Already sealed by `drive`, so it is pushed as it is rather than
        // through `push`, which would seal it a second time and burn a counter.
        let pushed = match (&out.frame, channel.outbound.clone()) {
            (Some(bytes), Some(tx)) => tx
                .try_send(UserResponse::BrowserFrame {
                    bytes: bytes.clone(),
                })
                .is_ok(),
            // A streamed call answers nothing now; its frames come later, and
            // the gateway is told the call was taken.
            (None, _) => true,
            (Some(_), None) => false,
        };
        (out, pushed)
    };
    // A failed ceremony stays failed: dropping the channel closes its door, and
    // the browser is told by the refusal frame it is being handed.
    if out.terminal {
        close_channel(ctx, key).await;
    }
    // The guard is dropped before the pump starts, because the pump locks the
    // same channel to seal each frame it carries.
    if let Some((id, mut rx)) = out.stream {
        let entry = Arc::clone(&entry);
        tokio::spawn(async move {
            while let Some(resp) = rx.recv().await {
                if !entry.lock().await.push(ChannelFrame::more(id, resp)) {
                    return; // the browser is gone, or cannot keep up
                }
            }
            // The ceremony ended: say so under the same id, so the browser can
            // stop waiting rather than infer it from silence.
            entry.lock().await.push(ChannelFrame::done(id));
        });
    }
    match out.frame {
        Some(bytes) if !pushed => {
            // No outbound side: a browser behind a gateway *device*, whose
            // circuit is request/response with nowhere to put a second
            // direction. It gets the frame inline, exactly as before.
            UserResponse::BrowserFrame { bytes }
        }
        // The gateway holds the socket; it needs to know the frame was taken,
        // not to carry it.
        _ => UserResponse::Ok,
    }
}

/// One frame from a browser behind a gateway device, on the peer path.
///
/// The gateway was admitted by the handshake against its paired key and its
/// posture was checked by the caller; what is left is the same ceremony the
/// local path runs, on state keyed by the gateway and its channel name rather
/// than by an IPC connection. The caller is anonymous to the OS: nothing about
/// a relayed frame names a process, and the dispatch decides by the channel's
/// own session, never by the transport it arrived on.
pub(super) async fn handle_gateway_frame(
    ctx: &AgentContext,
    peer_did: &str,
    user_id: &str,
    channel_id: Option<String>,
    frame: Vec<u8>,
) -> UserResponse {
    let key = format!("{peer_did}#{}", channel_id.as_deref().unwrap_or("-"));
    // The caller is anonymous to the OS: nothing about a relayed frame names a
    // process, and the dispatch decides by the channel's own session, never by
    // the transport it arrived on.
    let caller = kotton_ipc::Caller::anonymous();
    serve_frame(
        ctx,
        &caller,
        user_id,
        &ctx.pending_confirms,
        &ctx.browser_desks,
        &key,
        frame,
    )
    .await
}

struct Out {
    /// The frame to send now, if there is one. `None` when the call's answer
    /// will arrive on the channel's own direction instead — a streamed verb
    /// has nothing to say at the moment it is asked.
    frame: Option<Vec<u8>>,
    terminal: bool,
    /// A stream this frame started: the call's id, and the responses to seal
    /// under it as they arrive.
    stream: Option<(u64, mpsc::Receiver<UserResponse>)>,
}

impl Out {
    fn frame(bytes: Vec<u8>) -> Self {
        Self {
            frame: Some(bytes),
            terminal: false,
            stream: None,
        }
    }
    fn terminal(bytes: Vec<u8>) -> Self {
        Self {
            frame: Some(bytes),
            terminal: true,
            stream: None,
        }
    }
}

async fn drive(
    ctx: &AgentContext,
    caller: &kotton_ipc::Caller,
    user_id: &str,
    pending_confirms: &PendingConfirms,
    desks: &BrowserDesks,
    channel: &mut BrowserChannel,
    frame: &[u8],
) -> Out {
    // An established channel carries sealed inner requests, not handshake frames.
    if channel.issuer.is_established() {
        return match channel.issuer.open(frame) {
            Ok(inner) => match dispatch_inner(ctx, caller, user_id, channel, inner).await {
                // A streamed verb answers nothing now: its frames arrive on the
                // channel's own direction, under the id the call carried.
                Inner::Stream(id, rx) => Out {
                    frame: None,
                    terminal: false,
                    stream: Some((id, rx)),
                },
                Inner::Frame(bytes) => match channel.issuer.seal(&bytes) {
                    Ok(sealed) => Out::frame(sealed),
                    Err(e) => Out::terminal(refused(&format!("seal failed: {e}"))),
                },
            },
            Err(e) => Out::terminal(refused(&format!("bad sealed frame: {e}"))),
        };
    }

    match channel.issuer.receive(frame) {
        Ok(IssuerStep::Send(f)) => Out::frame(f),
        Ok(IssuerStep::DeviceHello {
            device_pub, name, ..
        }) => {
            let known = match user_db(ctx, user_id).await {
                Ok(db) => matches!(
                    kotton_device::config::ops::find_browser_device_id(&db, user_id, &device_pub)
                        .await,
                    Ok(Some(_))
                ),
                Err(_) => false,
            };
            channel.device = Some((device_pub, name));
            channel.known = known;
            match channel.issuer.welcome(known) {
                Ok(f) => Out::frame(f),
                Err(e) => Out::terminal(refused(&format!("{e}"))),
            }
        }
        Ok(IssuerStep::JoinerConfirmed) => {
            admit(ctx, user_id, pending_confirms, desks, channel).await
        }
        Err(e) => Out::terminal(refused(&format!("{e}"))),
    }
}

/// Decide whether to let the browser in, and on yes mint its session.
async fn admit(
    ctx: &AgentContext,
    user_id: &str,
    pending_confirms: &PendingConfirms,
    desks: &BrowserDesks,
    channel: &mut BrowserChannel,
) -> Out {
    let (device_pub, name) = match channel.device.clone() {
        Some(d) => d,
        None => return Out::terminal(refused("no device hello was seen")),
    };
    let db = match user_db(ctx, user_id).await {
        Ok(db) => db,
        Err(e) => return Out::terminal(refused(&format!("{e}"))),
    };

    if !channel.known {
        // A new key: a human on the node's screen must compare the digits. Find
        // the operator's desk; without one, nobody is watching, so refuse.
        let desk = desks.lock().await.get(user_id).cloned();
        let Some(desk) = desk else {
            return Out::terminal(refused(
                "this node is not accepting a new browser right now — open “add a device” on a trusted screen first",
            ));
        };
        let sas = channel.issuer.sas().unwrap_or(0);
        let confirmer = StreamingConfirmer {
            tx: desk,
            token: uuid::Uuid::new_v4().to_string(),
            pending: Arc::clone(pending_confirms),
            ttl: std::time::Duration::from_secs(300),
        };
        use kotton_peer::pair_channel::SasConfirmer as _;
        if !confirmer.confirm(sas, Some(&name)).await {
            return Out::terminal(refused("the person at the node did not confirm the code"));
        }
        if let Err(e) =
            kotton_device::config::ops::add_browser_device(&db, user_id, &name, &device_pub).await
        {
            return Out::terminal(refused(&format!("could not register this browser: {e}")));
        }
    }
    // A known key is touched by the lookup below, which is the whole of what
    // its branch used to do; no human.

    // The credential this admission is bound to: the row, as it stands now.
    //
    // No row is a refusal, never a default. This read and `DeviceHello`'s are
    // two reads, and a revoke between them deletes the row a known key was
    // recognised by — a fallback name here would admit, under a credential no
    // revoke can ever name, exactly the browser that was just revoked.
    let row = |db: Arc<sqlx::SqlitePool>| async move {
        kotton_device::config::ops::find_browser_device_id(&db, user_id, &device_pub)
            .await
            .ok()
            .flatten()
    };
    let Some(credential_id) = row(Arc::clone(&db)).await else {
        return Out::terminal(refused("this browser is not admitted here"));
    };

    // Mint the browser's session. From here every inner request is dispatched
    // under it, so it meets the ordinary Remote floor and the browser scope.
    let token = uuid::Uuid::new_v4().to_string();
    kotton_session::service::tokens::insert(&ctx.sessions, token.clone(), user_id.to_string());
    ctx.principal_sessions.write().unwrap().insert(
        token.clone(),
        Principal::Browser {
            credential_id: credential_id.clone(),
        },
    );
    // What a revoke finds this channel by. Set once: a channel is admitted at
    // most once, since an established issuer never reaches `admit` again.
    let _ = channel.admitted.set(credential_id.clone());

    // Read the row once more, now that the session is where a revoke looks.
    // A revoke deletes the row and then ends what it finds, so either it
    // deleted before this read — and this admission undoes itself — or it
    // deletes after, and finds the session just minted and this channel, whose
    // lock it waits on until this call returns. There is no order in which a
    // revoke passes a session it should have ended.
    if row(db).await.as_deref() != Some(credential_id.as_str()) {
        ctx.principal_sessions.write().unwrap().remove(&token);
        ctx.sessions.write().unwrap().remove(&token);
        return Out::terminal(refused(
            "this browser was revoked while it was being admitted",
        ));
    }
    channel.session_token = Some(token);
    channel.credential_id = Some(credential_id);

    match channel.issuer.accept() {
        Ok(f) => Out::frame(f),
        Err(e) => Out::terminal(refused(&format!("{e}"))),
    }
}

/// Dispatch one inner request under the browser's minted session, so it faces
/// the same floor and scope as any browser session reaching the daemon directly.
async fn dispatch_inner(
    ctx: &AgentContext,
    caller: &kotton_ipc::Caller,
    user_id: &str,
    channel: &BrowserChannel,
    inner: Vec<u8>,
) -> Inner {
    // The plaintext is a `ChannelCall`, not a bare request: the id it carries is
    // what lets the browser place a frame it was not waiting for.
    // A call that does not parse has no id to answer under, so the error goes
    // back under id 0 — the browser has no call outstanding by that number and
    // shows it as a channel error rather than as any call's result.
    let call: ChannelCall = match serde_json::from_slice(&inner) {
        Ok(c) => c,
        Err(e) => {
            return Inner::Frame(frame_json(ChannelFrame::once(
                0,
                UserResponse::Error {
                    message: format!("the browser sent a frame that is not a call: {e}"),
                },
            )))
        }
    };
    let id = call.id;
    // A browser must never tunnel the channel verb inside the channel, nor pair
    // itself. Refuse before the request reaches the floor.
    if matches!(
        call.request,
        UserRequest::BrowserFrame { .. } | UserRequest::WebShellPair { .. }
    ) {
        return Inner::Frame(err_frame(
            id,
            "that verb is not available inside a browser channel",
        ));
    }
    let (Some(token), Some(credential_id)) =
        (channel.session_token.clone(), channel.credential_id.clone())
    else {
        return Inner::Frame(err_frame(id, "the channel is not established"));
    };
    let cek_available = kotton_peer::daemon::nodes::user_has_cek(user_id, ctx.runtime.secrets());
    let conn = ConnSessionData::browser_session(token, cek_available, credential_id);
    let conn = std::sync::Arc::new(std::sync::Mutex::new(Some(conn)));
    // The two verbs at `Paired`, which are streams: the browser
    // asks once and the ceremony answers over the time a person reads three
    // words out and six digits back. They are dispatched here rather than
    // through `handle_request`, for the same reason the acceptor closure
    // dispatches them — `handle_request` returns one response — and they face
    // the same floor first, because a browser reaching a verb above its tier
    // must be refused before the ceremony starts, not after.
    if matches!(
        call.request,
        UserRequest::ContactPairStart { .. } | UserRequest::ContactPairJoin { .. }
    ) {
        if let Some(refusal) =
            super::dispatch::stream_entry_refusal(&ctx.sessions, &conn, &call.request)
        {
            return Inner::Frame(frame_json(ChannelFrame::once(id, refusal)));
        }
        // A stream with nowhere to go must not start. The channel's frames go
        // out its own direction and nowhere else, so on a channel with no
        // outbound side the ceremony would run to completion talking to a
        // dropped `push` — while the node advertised a pairing code at the
        // relay that no one could ever be shown. That is a reservation held
        // for a person who is not there, and on the gateway-device path it
        // also costs the browser its socket: `khttpd`'s relayed loop expects a
        // `BrowserFrame` back and drops the connection on anything else.
        //
        // Refused *before* the handler, because the handler's first act is to
        // reserve. Refusing afterwards would be a check that watches the thing
        // it exists to prevent.
        if channel.outbound.is_none() {
            return Inner::Frame(err_frame(
                id,
                "this channel has no way to carry a ceremony's frames — reopen it and try again",
            ));
        }
        let residency = std::sync::Arc::new(ctx.users.clone())
            as std::sync::Arc<dyn kotton_device::users::residency::Residency>;
        let started = match call.request {
            UserRequest::ContactPairStart {
                user_id: u,
                as_name,
                ttl_seconds,
            } => {
                kotton_device::users::contacts::handle_contact_pair_start(
                    std::sync::Arc::clone(&ctx.runtime),
                    residency,
                    std::sync::Arc::clone(&ctx.pending_confirms),
                    u,
                    as_name,
                    ttl_seconds,
                )
                .await
            }
            UserRequest::ContactPairJoin {
                user_id: u,
                code,
                as_name,
            } => {
                kotton_device::users::contacts::handle_contact_pair_join(
                    std::sync::Arc::clone(&ctx.runtime),
                    residency,
                    std::sync::Arc::clone(&ctx.pending_confirms),
                    u,
                    code.expose().to_owned(),
                    as_name,
                )
                .await
            }
            _ => unreachable!("the match above admits exactly these two"),
        };
        return match started {
            Ok(rx) => Inner::Stream(id, rx),
            Err(e) => Inner::Frame(err_frame(id, &e.to_string())),
        };
    }
    let resp = match super::dispatch::handle_request(ctx, call.request, caller.clone(), conn).await
    {
        Ok(r) => r,
        Err(e) => UserResponse::Error {
            message: e.to_string(),
        },
    };
    Inner::Frame(frame_json(ChannelFrame::once(id, resp)))
}

/// What one inner call produced: a frame to seal now, or a stream whose frames
/// go out the channel's own direction as they arrive.
enum Inner {
    Frame(Vec<u8>),
    Stream(u64, mpsc::Receiver<UserResponse>),
}

fn frame_json(frame: ChannelFrame) -> Vec<u8> {
    serde_json::to_vec(&frame).unwrap_or_else(|_| {
        // The id is already known here, so even the encoder's own failure is
        // answerable under the call that caused it.
        format!(
            r#"{{"id":{},"response":{{"Error":{{"message":"could not encode the response"}}}},"end":true}}"#,
            frame.id
        )
        .into_bytes()
    })
}

fn err_frame(id: u64, message: &str) -> Vec<u8> {
    frame_json(ChannelFrame::once(
        id,
        UserResponse::Error {
            message: message.to_string(),
        },
    ))
}

async fn node_label(ctx: &AgentContext) -> String {
    // The name the person is asked to compare digits against — "Does your PC at
    // home show these same six?" — so it is the device's own name, the one set
    // with `device name`, and never a product word.
    kotton_device::config::ops::resolve_device_name(&ctx.device_db).await
}

async fn user_db(ctx: &AgentContext, user_id: &str) -> std::io::Result<Arc<sqlx::SqlitePool>> {
    super::dispatch::user_db_for_user(ctx, user_id).await
}

/// Before a channel exists there is nothing to seal into, so a refusal is a
/// bare `refused` frame the browser surfaces as a failed connection.
fn sealed_or_plain_refuse(reason: &str) -> UserResponse {
    UserResponse::BrowserFrame {
        bytes: refused(reason),
    }
}
