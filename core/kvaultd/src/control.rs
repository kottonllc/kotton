// SPDX-License-Identifier: AGPL-3.0-or-later
//! The keeper's door: the local control socket (RFC-0084 V8).
//!
//! A person enrols a vault by handing it a pairing code, and the vault joins
//! the ceremony the person's own device is running — blind, so the only thing
//! it keeps from the ceremony is the chain and the sealed recovery copy. Who
//! may hand a code to this socket is the landlord's policy: a shell on the host,
//! a provisioning service, a form behind a payment. After the code, everything
//! is the ordinary ceremony over the network.
//!
//! Beyond joining, the door answers the readouts a landlord needs and nothing
//! of a person's: which nodes a pool is paired with, how much it holds, and
//! which tenants it keeps for — and takes the landlord's two acts over a
//! tenant: the pool's quota, and dropping exactly one (`tenancy`).
//! The door decodes `VaultRequest`, not the device's `UserRequest`: anything
//! else on this socket is unconstructible, which is RFC-0082's rule and the
//! reason a vault can say "absent" rather than "refused".
//!
//! **The door is also where the operator credential is decided** — enrolled by
//! its public half and revoked (`crate::operator`) — and the landlord's four
//! verbs it answers here are the four the operator's key reaches on the peer
//! transport ([`landlord`]): one body, two doors, so the desktop and the
//! terminal cannot come to mean different things by the same verb.

use crate::peer::{capacity, PeerContext};
use kotton_device::users::pairing::JoinPolicy;
use kotton_ipc::{ChannelAcceptor, HandlerOutput};
use kotton_peer::daemon::nodes::PendingConfirms;
use kotton_session::service::tokens::SessionMap;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::{UserRequest, UserResponse, VaultRequest};
use sqlx::SqlitePool;
use std::io;
use std::sync::Arc;

/// How long an invite waits to be admitted when the landlord names no window:
/// a day, at the terminal (`kvaultd invite` without `--ttl`) and from the
/// desktop's shell (`vault invite`). It is also the longest the operator's key
/// may ask for over the wire ([`invite_window`]). The terminal takes any
/// `--ttl` — whoever is at it holds the host — and had no upper bound of its own
/// to share, so the wire's is this default.
pub const INVITE_TTL_SECS: u64 = 24 * 60 * 60;

/// The window an invite the operator's key asks for waits, or why it is
/// refused: longer than a day, or so long that its expiry does not fit in a
/// timestamp.
pub fn invite_window(ttl_seconds: u64, now_secs: u64) -> Result<u64, String> {
    if ttl_seconds > INVITE_TTL_SECS {
        return Err(format!(
            "an invite from the desktop waits at most a day ({INVITE_TTL_SECS}s), and {ttl_seconds}s \
             is longer — the terminal's `kvaultd invite --ttl` names a longer one"
        ));
    }
    now_secs
        .checked_add(ttl_seconds)
        .map(|_| ttl_seconds)
        .ok_or_else(|| format!("an invite of {ttl_seconds}s expires past any timestamp"))
}

/// Why a vault with no relay mints no invite, in the one sentence both doors
/// answer with ([`mint_invite`]). A vault stands where its owner's desktop told
/// it (`crate::reach`), so the sentence names that act and no file.
pub const NO_RELAY: &str = "this vault stands at no relay, so an invite has nowhere to meet — its operator's \
     desktop tells it where to stand: `enrol <the vault's line>` once the desktop operates a relay (`enrol <the relay's line>`)";

pub struct ControlContext {
    pub peer: Arc<PeerContext>,
    pub device_db: Arc<SqlitePool>,
    pub sessions: SessionMap,
    pub pending_confirms: PendingConfirms,
    /// The six digits of each ceremony an operator's invite is waiting in.
    pub shown: Shown,
}

/// The six digits each ceremony an invite minted under an operator's key is
/// waiting in has derived, by the ceremony's token, with the key that minted
/// the invite and the pool it names: what `kvaultd invite` prints on its `sas=`
/// line, kept for that operator's desktop to read (`InviteDigits`), since
/// nobody stands at this vault to read them. A vault admits several operator
/// keys, and each reads the digits of its own invites and no other's. Held
/// only while the ceremony waits; nothing about it outlives it.
#[derive(Clone, Default)]
pub struct Shown(Arc<std::sync::Mutex<std::collections::HashMap<String, Waiting>>>);

/// One ceremony's digits, with whose invite it is and for which pool.
struct Waiting {
    minted_by: [u8; 32],
    pool: String,
    sas: u32,
}

impl Shown {
    fn show(&self, token: &str, minted_by: &[u8; 32], pool: &str, sas: u32) {
        self.held().insert(token.to_string(), Waiting { minted_by: *minted_by, pool: pool.to_string(), sas });
    }

    fn forget(&self, token: &str) {
        self.held().remove(token);
    }

    /// The digits shown for `pool` under invites the operator key `asking`
    /// minted, one per such ceremony waiting.
    pub fn for_pool(&self, asking: &[u8; 32], pool: &str) -> Vec<u32> {
        let mut digits: Vec<u32> = self
            .held()
            .values()
            .filter(|w| &w.minted_by == asking && w.pool == pool)
            .map(|w| w.sas)
            .collect();
        digits.sort_unstable();
        digits
    }

    fn held(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Waiting>> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Serve the control socket until the listener fails.
pub async fn serve(endpoint: IpcEndpoint, ctx: Arc<ControlContext>) -> io::Result<()> {
    // The door's own request type (RFC-0082 rule 2): a verb the vault has not
    // got is not refused here, it fails to decode.
    let server = ChannelAcceptor::<VaultRequest, UserResponse>::listen(endpoint).await?;
    server
        .accept_with_session_streaming::<_, _, String>(move |request, _caller, _conn_session| {
            let ctx = Arc::clone(&ctx);
            async move { dispatch(&ctx, request).await }
        })
        .await
}

async fn dispatch(ctx: &ControlContext, request: VaultRequest) -> io::Result<HandlerOutput<UserResponse>> {
    let peer = &ctx.peer;
    match request {
        VaultRequest::DeviceJoin {
            user_id,
            code,
            as_name,
        } => {
            let users: Arc<dyn kotton_device::users::residency::Residency> =
                Arc::new(peer.pools.clone());
            kotton_device::users::pairing::handle_device_join(
                Arc::clone(&peer.runtime),
                users,
                Arc::clone(&peer.db),
                Arc::clone(&ctx.device_db),
                Arc::clone(&ctx.sessions),
                peer.runtime.paired_keys(),
                Arc::clone(&ctx.pending_confirms),
                user_id,
                code.expose().to_owned(),
                as_name,
                JoinPolicy::BlindOnly,
            )
            .await
        }
        // The join hands the joining client a session token; binding it is the
        // client's next frame. A vault has no verb that needs a session, so the
        // answer is only whether the token is live — nothing is unlocked by it.
        VaultRequest::Authenticate { token, .. } => Ok(HandlerOutput::Single(
            match kotton_session::service::tokens::live_user(&ctx.sessions, token.expose()) {
                Some(user_id) => UserResponse::ActiveSession { user_id },
                None => UserResponse::NoActiveSession,
            },
        )),
        // Which node this is, for the device that will pair it: its stable DID
        // and its signing key. Public by construction.
        VaultRequest::GetNodeIdentity => Ok(HandlerOutput::Single(UserResponse::NodeIdentity {
            device_did: peer.runtime.operational_did(),
            signing_pubkey_hex: hex::encode(peer.runtime.device_signing_pubkey_bytes()),
        })),
        // Admission with nothing listening (RFC-0084 V8): the vault reserves at
        // its relay under the invite's handle and the person's device dials the
        // relay (`DEC-0068`). Blind only, as at the join.
        VaultRequest::DeviceInvite {
            user_id,
            ttl_seconds,
            as_name,
        } => mint_invite(ctx, user_id, ttl_seconds, as_name).await,
        VaultRequest::PairConfirmCode { token, matches, .. } => Ok(HandlerOutput::Single(
            kotton_peer::daemon::nodes::confirm_code(&ctx.pending_confirms, token.expose().to_owned(), matches).await?,
        )),
        VaultRequest::NodeList { user_id } => Ok(HandlerOutput::Single(
            kotton_peer::daemon::nodes::node_list(&peer.db, user_id).await?,
        )),
        VaultRequest::VaultCapacity { user_id } => {
            Ok(HandlerOutput::Single(capacity(peer, &user_id).await))
        }
        // The landlord's number for one tenant, the tenants, and dropping one:
        // the same bodies the operator's key reaches over the wire
        // (`landlord`). No check here: who reaches this socket is the
        // landlord's policy (RFC-0084), and the landlord owns the disk.
        VaultRequest::SetQuota { user_id, quota } => {
            Ok(HandlerOutput::Single(set_quota(peer, &user_id, quota).await))
        }
        VaultRequest::Tenants => Ok(HandlerOutput::Single(tenants(peer).await)),
        VaultRequest::DropTenant { user_id } => {
            Ok(HandlerOutput::Single(drop_tenant(ctx, &user_id).await))
        }
        // Who holds the operator credential. Only this socket decodes these:
        // they have no `UserRequest` twin, so no key on the peer transport —
        // the operator's own included — can enrol one or revoke one.
        VaultRequest::OperatorAdmit { key } => Ok(HandlerOutput::Single(
            match crate::operator::admit(peer, &key).await {
                Ok(()) => UserResponse::Ok,
                Err(e) => UserResponse::Error {
                    message: e.to_string(),
                },
            },
        )),
        VaultRequest::OperatorRevoke { key } => Ok(HandlerOutput::Single(
            match crate::operator::revoke(peer, &key).await {
                Ok(()) => UserResponse::Ok,
                Err(e) => UserResponse::Error {
                    message: e.to_string(),
                },
            },
        )),
        VaultRequest::OperatorRevokeAllBut { keep } => Ok(HandlerOutput::Single(
            match crate::operator::revoke_all_but(peer, &keep).await {
                Ok(_) => UserResponse::Ok,
                Err(e) => UserResponse::Error {
                    message: e.to_string(),
                },
            },
        )),
        VaultRequest::NodeRelay { .. } => Ok(HandlerOutput::Single(UserResponse::NodeRelayResult {
            relay_url: Some(peer.runtime.reachability().nat().relay_url).filter(|u| !u.is_empty()),
            relay_key: peer.runtime.reachability().nat().relay_key,
            // The terminal is told where the vault stands, and no admission key.
            admission: None,
        })),
    }
}

/// The landlord's number for one tenant, answered with the pool's readout.
async fn set_quota(peer: &PeerContext, user_id: &str, quota: u64) -> UserResponse {
    // Not beside a drop of the same name: the row it writes is one the drop
    // sweeps (`PeerContext::tenancy`).
    let _steady = peer.tenancy.read().await;
    match peer.meter.set_pool_quota(&peer.db, user_id, quota).await {
        Ok(()) => capacity(peer, user_id).await,
        Err(e) => UserResponse::Error {
            message: e.to_string(),
        },
    }
}

/// Who this vault keeps for.
async fn tenants(peer: &PeerContext) -> UserResponse {
    match crate::tenancy::list(peer).await {
        Ok(tenants) => UserResponse::VaultTenants { tenants },
        Err(e) => UserResponse::Error {
            message: e.to_string(),
        },
    }
}

/// Ending one tenant (`tenancy::drop_tenant`).
async fn drop_tenant(ctx: &ControlContext, user_id: &str) -> UserResponse {
    match crate::tenancy::drop_tenant(&ctx.peer, &ctx.sessions, user_id).await {
        Ok(tenant) => UserResponse::TenantDropped { tenant },
        Err(e) => UserResponse::Error {
            message: e.to_string(),
        },
    }
}

/// The landlord's verbs as the operator's key says them on the peer
/// transport — called by `peer::handle` only after `peer::reaches` has found
/// the connection's standing to be `Operator`, and for nothing else.
///
/// The four over pools are the door's own bodies — the invite's is
/// [`mint_invite`], so an invite the door refuses is refused here in the same
/// words. The invite answers in one frame where the door streams: the invite
/// itself (`PairAdvertising`), with the ceremony left running here and its six
/// digits confirmed on sight — what `kvaultd invite` does at the terminal,
/// because the person's device is where the digits are compared. What the
/// terminal prints on its `sas=` line for the landlord to read out is kept
/// instead ([`Shown`]) and answered to `InviteDigits`, which the desktop asks
/// once the person's device asks for the digits: the ceremony's frames come
/// after this answer, and the peer transport carries one frame per request.
/// The ceremony admits blind (`JoinPolicy::BlindOnly`), as at the door: the
/// operator credential cannot admit a device as anything else.
///
/// `key` is the operator key the connection authenticated as: the invite's
/// digits are kept under it, and `InviteDigits` answers with those alone.
pub async fn landlord(ctx: &ControlContext, key: &[u8; 32], request: UserRequest) -> UserResponse {
    let peer = &ctx.peer;
    match request {
        UserRequest::SetQuota { user_id, quota } => set_quota(peer, &user_id, quota).await,
        UserRequest::Tenants => tenants(peer).await,
        UserRequest::DropTenant { user_id } => drop_tenant(ctx, &user_id).await,
        UserRequest::StandAt { relays } => {
            match crate::reach::stand_at(&peer.runtime, &peer.db, &ctx.device_db, relays).await {
                Ok(()) => UserResponse::Ok,
                Err(message) => UserResponse::Error { message },
            }
        }
        UserRequest::DeviceInvite {
            user_id,
            ttl_seconds,
            as_name,
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            match invite_window(ttl_seconds, now) {
                Ok(ttl_seconds) => invite_confirmed_on_sight(ctx, key, user_id, ttl_seconds, as_name).await,
                Err(message) => UserResponse::Error { message },
            }
        }
        UserRequest::InviteDigits { user_id } => UserResponse::InviteDigits {
            digits: ctx.shown.for_pool(key, &user_id),
        },
        other => UserResponse::Error {
            message: format!("{} is not one of the landlord's verbs", other.variant_name()),
        },
    }
}

/// Does this vault already hold someone's identity under `user_id` — a
/// person admitted, whose chain and pool it keeps. Read from the registry,
/// the list `provision_joined_user` reads when a ceremony completes: the name
/// it would refuse to a second identity is exactly the name refused here.
/// A name the landlord has only set a number for (an invite not yet taken)
/// holds nobody, and is minted again on request: nothing here tracks a live
/// invite by name, so a second invite for an unjoined name is minted while
/// the first still stands, and if two identities take the two, the second is
/// refused late, at `provision_joined_user`
/// (`TASK-a-device-is-told-it-admitted-a-vault-that-refused-to-keep-it`).
fn keeps_someone_as(peer: &PeerContext, user_id: &str) -> io::Result<bool> {
    let registry = kotton_device::registry::load_users(&peer.runtime.base_dir().join("system"))
        .map_err(|e| io::Error::other(format!("the vault's list of whom it keeps for does not read: {e:#}")))?;
    Ok(registry.users.iter().any(|u| u.user_id == user_id))
}

/// Mint an invite for `user_id`: the one body both doors run — the terminal's
/// `kvaultd invite` through [`dispatch`], the operator's key through
/// [`landlord`] — so neither can mean something the other does not.
///
/// **An invite admits a new person under a name nobody holds here.** One
/// naming a pool this vault already keeps is refused before anything is
/// minted (`TASK-networking-is-the-drawn-one`, 2026-09-23). Before this, such
/// an invite was minted, and whoever took it ran the whole ceremony — six
/// digits, the transfer, `PairingComplete` on their own device — and was
/// refused only at the vault's save, a different identity under a kept name,
/// with nothing said to the landlord who minted it. The tenant's own devices
/// need no invite: the device that admitted each introduces it to the vault
/// under the identity's signature (`crate::devices`).
///
/// **An invite needs a relay to meet at, and a vault that has none says so.**
/// This is the only place a vault checks: `handle_device_invite` takes the URL
/// checked here rather than reading its own, and refuses nothing about it
/// (`TASK-handle-device-invite-refuses-a-missing-relay-after-both-its-callers-already-did`).
/// Before this check the terminal read only that the ceremony closed
/// (`TASK-kvaultd-invite-at-a-vault-with-no-relay-says-only-that-the-ceremony-closed`).
/// The vault's own answer names the act that tells it where to stand — its
/// operator's desktop, never a file
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`).
pub async fn mint_invite(
    ctx: &ControlContext,
    user_id: String,
    ttl_seconds: u64,
    as_name: Option<String>,
) -> io::Result<HandlerOutput<UserResponse>> {
    let peer = &ctx.peer;
    if keeps_someone_as(peer, &user_id)? {
        return Ok(HandlerOutput::Single(UserResponse::Error {
            message: format!(
                "this vault already keeps for '{user_id}' — an invite admits someone new, so it \
                 takes a name nobody holds here; their own devices need none"
            ),
        }));
    }
    let relay_url = peer.runtime.reachability().nat().relay_url;
    if relay_url.is_empty() {
        return Ok(HandlerOutput::Single(UserResponse::Error {
            message: NO_RELAY.to_string(),
        }));
    }
    let users: Arc<dyn kotton_device::users::residency::Residency> = Arc::new(peer.pools.clone());
    kotton_device::users::pairing::handle_device_invite(
        Arc::clone(&peer.runtime),
        relay_url,
        // The invited key its operator told it with the reach set, which it
        // hands every tenant in its answer to `NodeRelay`.
        crate::reach::invited(&peer.runtime),
        users,
        Arc::clone(&peer.db),
        Arc::clone(&ctx.device_db),
        Arc::clone(&ctx.sessions),
        peer.runtime.paired_keys(),
        Arc::clone(&ctx.pending_confirms),
        user_id,
        ttl_seconds,
        as_name,
        JoinPolicy::BlindOnly,
    )
    .await
}

async fn invite_confirmed_on_sight(
    ctx: &ControlContext,
    key: &[u8; 32],
    user_id: String,
    ttl_seconds: u64,
    as_name: Option<String>,
) -> UserResponse {
    let pool = user_id.clone();
    match mint_invite(ctx, user_id, ttl_seconds, as_name).await {
        Ok(HandlerOutput::Stream(mut rx)) => {
            let first = rx.recv().await;
            tokio::spawn(confirmed_on_sight(rx, Arc::clone(&ctx.pending_confirms), ctx.shown.clone(), *key, pool));
            first.unwrap_or_else(|| UserResponse::Error {
                message: "the vault ended the invite before minting it".to_string(),
            })
        }
        Ok(HandlerOutput::Single(answer)) => answer,
        Err(e) => UserResponse::Error {
            message: e.to_string(),
        },
    }
}

/// The rest of an operator's invite, after its first frame: its six digits
/// kept for the desktop of the operator key that minted it (`minted_by`) to
/// read while the ceremony waits, and
/// confirmed on sight; forgotten when it ends, however it ends.
async fn confirmed_on_sight(
    mut rx: tokio::sync::mpsc::Receiver<UserResponse>,
    pending: PendingConfirms,
    shown: Shown,
    minted_by: [u8; 32],
    pool: String,
) {
    let mut showing: Vec<String> = Vec::new();
    while let Some(frame) = rx.recv().await {
        match frame {
            UserResponse::PairShowCode { token, sas, .. } => {
                let token = token.expose().to_owned();
                shown.show(&token, &minted_by, &pool, sas);
                showing.push(token.clone());
                let _ = kotton_peer::daemon::nodes::confirm_code(&pending, token, true).await;
            }
            UserResponse::PairingComplete { .. } | UserResponse::PairFailed { .. } => break,
            _ => {}
        }
    }
    for token in showing {
        shown.forget(&token);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// **An operator's invite keeps its six digits for the operator's desktop
    /// while its ceremony waits, and forgets them when it ends.** Nobody
    /// stands at a vault to read a `sas=` line, so the digits the person
    /// admitting the invite is asked for are read at the desktop
    /// (`InviteDigits`): kept under the key that minted the invite and the
    /// invite's pool, and gone with the ceremony, whether it completed or
    /// failed.
    #[tokio::test]
    async fn an_operators_invite_keeps_its_digits_while_its_ceremony_waits() {
        const A: [u8; 32] = [0xA; 32];
        let shown = Shown::default();
        let pending: PendingConfirms = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let ceremony = tokio::spawn(confirmed_on_sight(rx, pending, shown.clone(), A, "sam".into()));
        assert!(shown.for_pool(&A, "sam").is_empty(), "nothing is shown before a device dials");
        tx.send(UserResponse::PairShowCode { token: kotton_wire::ipc::SecretText::new("t"), sas: 47_291, peer_label: None }).await.unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while shown.for_pool(&A, "sam").is_empty() {
            assert!(std::time::Instant::now() < deadline, "the digits were never kept");
            tokio::task::yield_now().await;
        }
        assert_eq!(shown.for_pool(&A, "sam"), vec![47_291]);
        assert!(shown.for_pool(&A, "alice").is_empty(), "kept under the invite's pool alone");
        tx.send(UserResponse::PairFailed { reason: "the digits did not match".into() }).await.unwrap();
        ceremony.await.expect("the watch ends with the ceremony");
        assert!(shown.for_pool(&A, "sam").is_empty(), "the digits outlived their ceremony");
    }

    /// **One operator key reads none of another's digits.** A vault admits a
    /// set of operator keys; the digits of an invite minted under A are kept
    /// under A, and `InviteDigits` said under B for the same pool answers
    /// none of them, through the landlord's own body — while A, asking the
    /// same, is answered them.
    #[tokio::test]
    async fn one_operator_key_reads_none_of_anothers_invite_digits() {
        const A: [u8; 32] = [0xA; 32];
        const B: [u8; 32] = [0xB; 32];
        let base = crate::instance::tests::a_state_dir();
        let (_door_dir, door) = a_door();
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> = Arc::new(kotton_secret::MemorySecrets::new());
        crate::instance::tests::created(base.path(), secrets.as_ref()).await;
        let vault = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, secrets)
            .await
            .expect("a vault");
        let ctx = &vault.control;
        ctx.shown.show("a-ceremony", &A, "sam", 47_291);
        let digits = |key: [u8; 32]| async move {
            match landlord(ctx, &key, UserRequest::InviteDigits { user_id: "sam".into() }).await {
                UserResponse::InviteDigits { digits } => digits,
                other => panic!("InviteDigits answered {other:?}"),
            }
        };
        assert_eq!(digits(A).await, vec![47_291], "the key that minted the invite reads its digits");
        assert!(digits(B).await.is_empty(), "another operator key read the digits of A's invite");
    }

    /// A door this test owns. On Unix, a socket in a directory under `/tmp`
    /// that the test makes and that goes when the guard drops: joined onto
    /// `TMPDIR`, whose length no test sets, the door failed `SUN_LEN` under a
    /// 104-byte one — the serving task died with the error and the test timed
    /// out on "the door is listening" — and every run left its socket behind
    /// (`TASK-three-unit-tests-join-their-socket-onto-tmpdir-by-hand`).
    pub(crate) fn a_door() -> (Option<tempfile::TempDir>, IpcEndpoint) {
        #[cfg(windows)]
        let id = format!("kvaultd-control-{}-{}", std::process::id(), rand_suffix());
        #[cfg(windows)]
        return (None, IpcEndpoint::NamedPipe(id));
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir_in("/tmp").expect("a directory under /tmp for the door");
            let door = IpcEndpoint::UnixSocket(dir.path().join("control.sock"));
            (Some(dir), door)
        }
    }

    #[cfg(windows)]
    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
    }

    /// **An invite naming a pool this vault already keeps is refused at both
    /// doors, before anything is minted** (`TASK-networking-is-the-drawn-one`,
    /// 2026-09-23). The operator's key over the wire and the terminal's
    /// `kvaultd invite` at the door run one body, so both answer the refusal,
    /// in one frame, with no invite in it. A name nobody holds is not refused
    /// by name: it reaches the ceremony, which a vault with no relay then
    /// refuses for that — so what refuses `alice` is that she is kept, and not
    /// every invite.
    #[tokio::test]
    async fn an_invite_naming_a_kept_pool_is_refused_at_both_doors_before_anything_is_minted() {
        use kotton_device::users::DeviceUsers as _;
        let base = crate::instance::tests::a_state_dir();
        let (_door_dir, door) = a_door();
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> = Arc::new(kotton_secret::MemorySecrets::new());
        crate::instance::tests::created(base.path(), secrets.as_ref()).await;
        let vault = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, secrets)
        .await
        .expect("a vault");
        vault
            .runtime()
            .provision_joined_user("alice", "did:kel:alice")
            .expect("alice is kept here");
        let ctx = &vault.control;
        let invite = |user_id: &str| UserRequest::DeviceInvite {
            user_id: user_id.to_string(),
            ttl_seconds: 60,
            as_name: None,
        };

        match landlord(ctx, &[1u8; 32], invite("alice")).await {
            UserResponse::Error { message } => {
                assert!(message.contains("already keeps for 'alice'"), "{message}")
            }
            other => panic!("the operator's key minted an invite naming a kept pool: {other:?}"),
        }
        match dispatch(
            ctx,
            VaultRequest::DeviceInvite {
                user_id: "alice".into(),
                ttl_seconds: 60,
                as_name: None,
            },
        )
        .await
        {
            Ok(HandlerOutput::Single(UserResponse::Error { message })) => {
                assert!(message.contains("already keeps for 'alice'"), "{message}")
            }
            Ok(HandlerOutput::Single(other)) => panic!("the door answered {other:?}"),
            Ok(HandlerOutput::Stream(_)) => panic!("the terminal's door minted an invite naming a kept pool"),
            Err(e) => panic!("the door failed rather than refusing: {e}"),
        }

        match landlord(ctx, &[1u8; 32], invite("bob")).await {
            UserResponse::Error { message } => {
                assert!(!message.contains("already keeps"), "a new name was refused as kept: {message}");
                // With no relay, the operator's key is told why in the door's words.
                if ctx.peer.runtime.reachability().nat().relay_url.is_empty() {
                    assert_eq!(message, NO_RELAY);
                }
            }
            // A vault told where to stand mints it: also not refused by name.
            UserResponse::PairAdvertising { .. } => {}
            other => panic!("an invite for a new name answered {other:?}"),
        }
    }

    /// **A handler's `Err` reaches the terminal as a frame carrying its text**
    /// (`TASK-an-ipc-door-answers-a-handlers-error-by-closing-with-nothing-said`).
    /// A join handed a code that is not one fails in `handle_device_join` with
    /// an `Err`, which the door used to answer by closing the stream with
    /// nothing on it — `kvaultd join` then printed only that the vault closed
    /// the ceremony. Over the socket, through the acceptor, as the terminal
    /// reads it: the refusal's own words, then the end of the stream.
    #[tokio::test]
    async fn a_join_the_ceremony_refuses_reaches_the_terminal_in_the_refusals_words() {
        use kotton_ipc::IpcClient;
        let base = crate::instance::tests::a_state_dir();
        let (_door_dir, endpoint) = a_door();
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> = Arc::new(kotton_secret::MemorySecrets::new());
        crate::instance::tests::created(base.path(), secrets.as_ref()).await;
        let vault = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), endpoint.clone(), secrets)
        .await
        .expect("a vault");
        let door = tokio::spawn(serve(endpoint.clone(), Arc::clone(&vault.control)));

        let mut client = None;
        for _ in 0..100 {
            if let Ok(c) = IpcClient::<VaultRequest, UserResponse>::connect(endpoint.clone()).await
            {
                client = Some(c);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let client = client.expect("the door is listening");
        let mut rx = client
            .send_streaming(&VaultRequest::DeviceJoin {
                user_id: "alice".into(),
                code: kotton_wire::ipc::SecretText::new("not-a-code"),
                as_name: None,
            })
            .await
            .expect("the request is sent");

        let within = std::time::Duration::from_secs(10);
        let first = tokio::time::timeout(within, rx.recv())
            .await
            .expect("the door answers");
        match first {
            Some(UserResponse::Error { message }) => {
                assert!(message.contains("invalid connection code"), "{message}")
            }
            Some(other) => panic!("the door answered {other:?}"),
            None => panic!("the door closed the stream with nothing said"),
        }
        let after = tokio::time::timeout(within, rx.recv())
            .await
            .expect("the stream ends");
        assert!(after.is_none(), "a frame followed the refusal: {after:?}");
        door.abort();
    }

    /// **An invite over the wire waits at most a day**, and a window whose
    /// expiry would overflow is refused rather than wrapped
    /// (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`).
    #[test]
    fn an_invite_over_the_wire_waits_at_most_a_day() {
        let now = 1_790_000_000;
        assert_eq!(invite_window(120, now), Ok(120));
        assert_eq!(invite_window(INVITE_TTL_SECS, now), Ok(INVITE_TTL_SECS));
        assert!(invite_window(INVITE_TTL_SECS + 1, now).is_err());
        assert!(invite_window(u64::MAX, now).is_err());
        // Within the bound but past any timestamp: refused, never wrapped.
        assert!(invite_window(60, u64::MAX - 1).is_err());
    }
}
