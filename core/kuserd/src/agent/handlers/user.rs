// SPDX-License-Identifier: AGPL-3.0-or-later
//! User lifecycle IPC handlers: CreateUser, LogoutUser, LoginWithRecoveryKey, ListUsers.
use crate::device_users;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_diag::service::{Event, EventCategory, EventLevel, EventScope};
use kotton_session::service::tokens as sessions;
use serde_json::json;
use std::io;

use super::UserResponse;

/// What a door hands over to make an identity: the three facts that differ
/// between the doors, so that adding one is a field and not a ninth argument.
pub(crate) struct NewIdentity {
    /// The id: the directory under `users/`, the registry key. The CLI's door
    /// takes it from the person; the window's mints it
    /// (`device_users::mint_user_id`) and never shows it.
    pub user_id: String,
    /// The credential the identity is sealed under.
    pub passphrase: String,
    /// What the desktop calls the person; `None` from a door that asks for no
    /// name (the CLI's, which names the id instead). The registry's write
    /// normalises it (`device_users::register`); the window's door also
    /// normalises before creation, so a name that does not fit refuses with
    /// nothing made. Kept as a sealed record in the person's store
    /// (`crate::own_name`), and copied beside the id where the launch, the lock
    /// screen and `read-identity` read it. A person's name travels with their
    /// identity.
    pub display_name: Option<String>,
}

pub(crate) async fn create_user(
    runtime: &DeviceRuntime,
    users: &crate::residency::UserRegistry,
    user_dbs: &crate::db::user_db::UserDbMap,
    event_log_tasks: &crate::event_log::EventLogTasks,
    base: &std::path::Path,
    new: NewIdentity,
    sessions: &sessions::SessionMap,
) -> io::Result<UserResponse> {
    let NewIdentity {
        user_id,
        passphrase,
        display_name,
    } = new;
    if let Err(e) = device_users::validate_user_id(&user_id) {
        return Ok(UserResponse::Error {
            message: e.to_string(),
        });
    }
    match runtime.create_user(&user_id, &passphrase).await {
        // Creation hands back the runtime; making it resident is this handler's
        // call, because the registry is the daemon's.
        Ok((result, user_rt)) => {
            // The name is the person's, so it is kept first where their things
            // are kept — a sealed record in their own store, which their other
            // devices receive by sync — and the registry below holds this
            // device's copy of it.
            // A record that cannot be written is reported and does not unwind the
            // identity, for the reason the apps below give — and then this device
            // copies no name either, because a copy with no record behind it would
            // be the source, which the copy never is. The person is greeted by the
            // no-name fallbacks and Settings offers to set it, which writes both.
            let copied = match display_name.as_deref() {
                Some(name) => match crate::own_name::write(&user_rt, name).await {
                    Ok(kept) => kept,
                    Err(e) => {
                        tracing::error!(
                            %user_id, error = %e,
                            "created the identity but could not keep its name with it; set \
                             it again in Settings"
                        );
                        None
                    }
                },
                None => None,
            };
            users.insert(user_id.clone(), user_rt);
            let _ = device_users::register(base, &user_id, &result.did, copied.as_deref());
            let token = uuid::Uuid::new_v4().to_string();
            sessions::insert(sessions, token.clone(), user_id.clone());
            // **The apps come with the identity, not with the recipe that made it.**
            //
            // The daemon's constructor seeds bundled apps for every user it finds at
            // boot, which covers a returning one and misses a new one entirely — an
            // identity created after startup would have no shell and no editor until the
            // next restart. This is the door every creation passes through, so it is where the
            // apps are given.
            //
            // Failure is reported and does not unwind the identity. The person has a real
            // identity either way; what they lack is a surface, and the next boot's seeding
            // pass installs it. Destroying a just-created identity because an app did not
            // install would be the worse of the two.
            match crate::db::user_db::user_agent_db(
                user_dbs,
                base,
                runtime.secrets(),
                &user_id,
                &runtime.schema_registry,
            )
            .await
            {
                Ok(user_db) => {
                    super::super::auto_install_bundled_apps(
                        &user_db,
                        base,
                        &user_id,
                        runtime.secrets(),
                    )
                    .await;
                    // This is the first point this identity's `agent.db` opens with a
                    // key, the same reason `rekey_resident_store` starts the log here, so
                    // an identity made in a running daemon keeps an event log.
                    super::super::spawn_user_event_log(
                        runtime,
                        user_dbs,
                        base,
                        event_log_tasks,
                        &user_id,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::error!(
                        %user_id, error = %e,
                        "created the identity but could not open its database to install its \
                         apps; it will have no shell until the next daemon start"
                    );
                }
            }

            let _ = runtime.event_bus().publish(
                Event::with_payload(
                    EventCategory::Auth,
                    EventLevel::Info,
                    format!("User created: {user_id}"),
                    json!({ "user_id": user_id }),
                )
                .in_scope(EventScope::User(user_id.clone())),
            );
            Ok(UserResponse::UserCreated {
                did: result.did,
                device_fingerprint: result.device_fingerprint,
                session_token: kotton_wire::ipc::SecretText::new(token),
            })
        }
        Err(e) => {
            let _ = runtime.event_bus().publish(
                Event::with_payload(
                    EventCategory::System,
                    EventLevel::Error,
                    format!("CreateUser failed for {user_id}: {e}"),
                    json!({ "user_id": user_id, "error": e.to_string() }),
                )
                .in_scope(EventScope::User(user_id.clone())),
            );
            // A refused credential is recovered by type, not by reading the
            // message. `create_user` assesses before it creates anything, so
            // this arm means nothing was made and the person can simply type a
            // different one — which is a different answer from "the daemon
            // broke", and the guest branches on the difference.
            if let Some(weak) = e.downcast_ref::<kotton_crypto::daily_credential::Weakness>() {
                return Ok(UserResponse::WeakCredential {
                    message: weak.to_string(),
                });
            }
            Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    }
}

pub(crate) async fn logout_user(
    runtime: &DeviceRuntime,
    user_id: String,
    sessions: &sessions::SessionMap,
) -> io::Result<UserResponse> {
    match runtime.logout_user(&user_id).await {
        Ok(_) => {
            let _ = device_users::unregister(runtime.base_dir(), &user_id);
            // Revoke all session tokens belonging to this user so that
            // a stale token cannot be replayed after logout.
            sessions::remove_user(sessions, &user_id);
            Ok(UserResponse::UserLoggedOut)
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Give this identity a recovery phrase, and hand it back once.
///
/// The daemon keeps no copy. The phrase is derived, committed to the KEL as a
/// **growth** of the recovery set, used to seal recovery copies of the random
/// roots, and returned — after which it exists only wherever the person put it.
pub(crate) async fn add_recovery_phrase(
    runtime: &DeviceRuntime,
    db: &std::sync::Arc<sqlx::SqlitePool>,
    user_id: String,
) -> io::Result<UserResponse> {
    match kotton_device::users::commands::add_recovery_phrase(
        runtime.base_dir(),
        runtime.secrets(),
        &user_id,
    )
    .await
    {
        Ok(recovery_key) => {
            let copies_delivered_to = deliver_recovery_copy(runtime, db, &user_id).await;
            Ok(UserResponse::RecoveryPhraseAdded {
                recovery_key: kotton_wire::ipc::SecretText::new(recovery_key),
                copies_delivered_to,
            })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Hand the copy just sealed to every node a drive of the person's is reached
/// through (`kotton_peer::daemon::drives`) — a vault, which holds nothing it can
/// open — so a vault enrolled before the phrase existed can serve a recovery. Best effort, node by node: one that is asleep
/// is logged and skipped, and the caller is told which ones have it.
async fn deliver_recovery_copy(
    runtime: &DeviceRuntime,
    db: &std::sync::Arc<sqlx::SqlitePool>,
    user_id: &str,
) -> Vec<kotton_wire::peer::PairedNode> {
    let Ok(Some(bundle)) =
        kotton_identity::provisioning::read_recovery_bundle_raw(runtime.base_dir(), user_id)
    else {
        return Vec::new();
    };
    let nodes = match kotton_peer::daemon::drives::nodes(db, user_id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "recovery copy: could not list blind nodes");
            return Vec::new();
        }
    };
    // The events that authorize the copy travel with it. Loaded once: it is the
    // same chain for every node, and it is the chain as of the `add_recovery`
    // event this function was called immediately after.
    let chain =
        kotton_identity::kel_store::load_chain(runtime.base_dir(), user_id).unwrap_or_default();
    let mut delivered = Vec::new();
    for node in nodes {
        let label = node.id.clone();
        // Kept because `connect` takes the node by value, and because the whole
        // row is the answer: a wiped device needs every field of it to reach
        // this node again, and the recovery card the shell prints carries it.
        let card = node.clone();
        let outcome = async {
            let client = runtime.dialer().connect(node, user_id).await?;
            match client
                .send(&kotton_wire::UserRequest::RecoveryStore {
                    user_id: user_id.to_string(),
                    bundle: bundle.clone(),
                    kel: chain.clone(),
                })
                .await?
            {
                UserResponse::Ok => Ok(()),
                UserResponse::Error { message } => Err(anyhow::anyhow!(message)),
                other => Err(anyhow::anyhow!("unexpected reply {other:?}")),
            }
        }
        .await;
        match outcome {
            Ok(()) => delivered.push(card),
            Err(e) => {
                tracing::warn!(node = %label, error = %e, "recovery copy not delivered; the node gets it when it is next reachable and the phrase is set again")
            }
        }
    }
    delivered
}

pub(crate) async fn login_with_recovery_key(
    runtime: &DeviceRuntime,
    users: &crate::residency::UserRegistry,
    recovery_key: String,
    device_name: Option<String>,
    user_id: Option<String>,
    sessions: &sessions::SessionMap,
) -> io::Result<UserResponse> {
    match runtime
        .login_with_recovery_key(
            &recovery_key,
            user_id.as_deref(),
            device_name,
            user_id.as_deref().and_then(|u| users.get(u)),
        )
        .await
    {
        Ok((uid, device_fingerprint, user_rt)) => {
            // Login hands back the runtime, so the DID comes from the handle we
            // were given rather than from a second lookup of the user we just
            // logged in.
            let did = user_rt.did().to_string();
            users.insert(uid.clone(), user_rt);
            // An identity arriving by recovery has no display name on this
            // device yet; the shell draws its fallbacks until one is set.
            let _ = device_users::register(runtime.base_dir(), &uid, &did, None);
            let token = uuid::Uuid::new_v4().to_string();
            sessions::insert(sessions, token.clone(), uid.clone());
            let _ = runtime.event_bus().publish(
                Event::with_payload(
                    EventCategory::Auth,
                    EventLevel::Info,
                    format!("Recovery login succeeded: {uid}"),
                    json!({ "user_id": uid, "method": "recovery_key" }),
                )
                .in_scope(EventScope::User(uid.clone())),
            );
            Ok(UserResponse::LoginSuccessful {
                user_id: uid,
                device_fingerprint,
                session_token: kotton_wire::ipc::SecretText::new(token),
            })
        }
        Err(e) => {
            let _ = runtime.event_bus().publish(Event::with_payload(
                EventCategory::Auth,
                EventLevel::Warn,
                // Device-scoped deliberately: a login that failed established
                // no principal, so there is no one to attribute it to. It
                // belongs in the device's log, which is also the only place a
                // pattern of failures against *several* users is visible.
                format!("Recovery login failed: {e}"),
                json!({ "error": e.to_string() }),
            ));
            Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    }
}

/// `Recover`: the verb that makes a cold `login`'s claim good, from the words
/// and the line of the vault that keeps the person's things. The body is
/// `kotton_device::users::recover` — the vault added, the proof, the rotation,
/// the drive recorded after the proof and the node taken back on a refusal, in
/// this one request for every door; this is the daemon's part — the registry it
/// hands over, the event it publishes, the response it shapes.
pub(crate) async fn recover(
    runtime: &DeviceRuntime,
    users: &crate::residency::UserRegistry,
    db: &std::sync::Arc<sqlx::SqlitePool>,
    user_id: String,
    recovery_key: String,
    passphrase: String,
    vault_line: String,
) -> io::Result<UserResponse> {
    match kotton_device::users::recover::recover(runtime, users, db, &user_id, &recovery_key, &passphrase, &vault_line)
        .await
    {
        Ok(done) => {
            // The roots were sealed under the new passphrase and taken into
            // custody; arm the window from the policy just written, as
            // `SetLockPolicy` does, rather than the default adoption applied.
            crate::agent::custody_window::arm(runtime, runtime.base_dir(), &user_id);
            let _ = device_users::register(runtime.base_dir(), &user_id, &done.did, None);
            let _ = runtime.event_bus().publish(
                Event::with_payload(
                    EventCategory::Auth,
                    EventLevel::Warn,
                    format!("Identity recovered onto this device: {user_id}"),
                    json!({
                        "user_id": user_id,
                        "method": "recover",
                        "nodes_admitted": done.nodes_admitted,
                    }),
                )
                .in_scope(EventScope::User(user_id.clone())),
            );
            if done.nodes_admitted == 0 {
                tracing::warn!(
                    user_id = %user_id,
                    "recovered locally, but no paired node admitted this device yet"
                );
            }
            if let Some(why) = done.drive_not_recorded.as_deref() {
                tracing::warn!(user_id = %user_id, "recovered, but {why}");
            }
            Ok(UserResponse::Recovered {
                did: done.did,
                new_key_hex: done.new_key_hex,
                sealed_copy_removed: done.sealed_copy_removed,
                drive_not_recorded: done.drive_not_recorded,
            })
        }
        Err(e) => {
            let _ = runtime.event_bus().publish(Event::with_payload(
                EventCategory::Auth,
                EventLevel::Warn,
                format!("Recovery failed: {e}"),
                json!({ "user_id": user_id, "error": e.to_string() }),
            ));
            Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    }
}

pub(crate) async fn rotate_identity(
    runtime: &DeviceRuntime,
    user_id: String,
    recovery_key: String,
    credential: Option<String>,
) -> io::Result<UserResponse> {
    match runtime
        .rotate_identity_via_mnemonic(&user_id, &recovery_key, credential.as_deref())
        .await
    {
        Ok(new_key_hex) => {
            let _ = runtime.event_bus().publish(
                Event::with_payload(
                    EventCategory::Auth,
                    EventLevel::Warn,
                    format!("Identity key rotated (mnemonic recovery): {user_id}"),
                    json!({ "user_id": user_id, "method": "mnemonic_rotation" }),
                )
                .in_scope(EventScope::User(user_id.clone())),
            );
            // The reach note is signed with the key just retired, so the keeper
            // re-signs it now and hands it — with the key log that proves the new
            // key — to every contact, rather than on its next hourly pass, so a
            // rotated person's contacts learn the new key.
            runtime.reach_changed().notify_one();
            // And the doors this person answers are derived from their key, so
            // they are rebuilt under the new one: a contact who has learned it
            // dials there. One who has not yet sends to the old door and waits
            // in their own outbox until the note reaches them.
            runtime.contacts_changed().notify_one();
            Ok(UserResponse::IdentityRotated { new_key_hex })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Takes only the registry: listing who is resident never needed the machine,
/// because the registry does not live on it.
pub(crate) async fn list_users(users: &crate::residency::UserRegistry) -> io::Result<UserResponse> {
    Ok(UserResponse::UserList { users: users.ids() })
}
