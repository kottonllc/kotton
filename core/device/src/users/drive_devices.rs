// SPDX-License-Identifier: AGPL-3.0-or-later
//! Introducing a person's devices to their drives, and withdrawing them:
//! pairing introduces a device's key to the set a drive admits.
//!
//! A drive — a tenancy on a vault — holds no data keys, so it cannot read the
//! person's member list; it admits the device that enrolled it, and learns of
//! every other one from this. **The device that admits a new device of the
//! person's tells each drive the person has enrolled**, at the ceremony's end,
//! in a `TenantDevice` request signed under the identity; **and `device revoke`
//! withdraws it the same way.** The drive checks the signature against the
//! identity's current key in the key log it keeps (`kvaultd::devices`).
//!
//! Only a device holding the identity's signing key can say this: a device
//! that joined holds a key share, and introduces nobody. That is the device
//! that ran the ceremony, which is the one that calls [`introduce`].
//!
//! Drive by drive and bounded: a drive that is asleep is not told, and what
//! came of each is returned ([`Told`]). At a ceremony's end a drive that was
//! not told is logged and the device is refused there; at revoke the person is
//! told by name which drives still admit the device ([`revoke`]). Nothing
//! tells a drive again later yet.
//!
//! **Which nodes are drives** is the drive record this device keeps
//! ([`kotton_peer::daemon::drives`]: the vault's key and the tenancy, and the
//! node it is reached through), which enrolling a vault and `kotton id recover`
//! both write — never a paired node row's posture, which a vault added by
//! address does not carry.

use crate::DeviceRuntime;
use kotton_wire::ipc::{TenantDeviceAct, TenantDeviceChange, UserRequest, UserResponse};
use kotton_wire::peer::PairedNode;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;

/// How long one drive is given to answer.
const EACH_DRIVE: Duration = Duration::from_secs(15);

/// What telling the person's drives of a device came to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Told {
    /// Every drive the person has enrolled, by its row's id.
    pub drives: Vec<String>,
    /// The drives that took the change.
    pub took: Vec<String>,
    /// The drives that did not, each with why.
    pub missed: Vec<(String, String)>,
    /// Whether this device holds the identity's signing key. Without it no
    /// drive is told anything, and `took` is empty.
    pub holds_identity: bool,
}

impl Told {
    /// Every drive took it — vacuously, when the person has none.
    pub fn all_took(&self) -> bool {
        self.took.len() == self.drives.len()
    }
}

/// Tell each of `user_id`'s drives to admit `device` from now on.
pub async fn introduce(runtime: &DeviceRuntime, db: &Arc<SqlitePool>, user_id: &str, device: &PairedNode) -> Told {
    tell(runtime, db, user_id, device, TenantDeviceAct::Admit).await
}

/// Tell each of `user_id`'s drives to admit `device` no longer.
pub async fn withdraw(runtime: &DeviceRuntime, db: &Arc<SqlitePool>, user_id: &str, device: &PairedNode) -> Told {
    tell(runtime, db, user_id, device, TenantDeviceAct::Withdraw).await
}

/// The identity's signing key, when this device holds it.
fn identity_key(runtime: &DeviceRuntime, user_id: &str) -> Option<ed25519_dalek::SigningKey> {
    kotton_peer::daemon::nodes::load_signing_key(user_id, runtime.secrets()).ok()
}

/// The change, signed under the identity: `None` when this device does not
/// hold the identity's signing key.
pub fn signed_change(
    runtime: &DeviceRuntime,
    user_id: &str,
    device: &PairedNode,
    act: TenantDeviceAct,
) -> Option<(TenantDeviceChange, Vec<u8>)> {
    use ed25519_dalek::Signer as _;
    let identity = identity_key(runtime, user_id)?;
    let change = TenantDeviceChange {
        act,
        device_did: device.device_did.to_string(),
        public_key: device.public_key,
        said_at_ms: u64::try_from(kotton_common::time::now_millis()).unwrap_or(0),
    };
    let signature = identity.sign(&change.signed_bytes(user_id)).to_bytes().to_vec();
    Some((change, signature))
}

/// The nodes `user_id`'s drives are reached through, other than `device`
/// itself, as the drive record names them.
async fn drives_of(db: &Arc<SqlitePool>, user_id: &str, device: &PairedNode) -> std::io::Result<Vec<PairedNode>> {
    let drives = kotton_peer::daemon::drives::nodes(db, user_id).await?;
    Ok(drives.into_iter().filter(|d| d.public_key != device.public_key).collect())
}

async fn tell(
    runtime: &DeviceRuntime,
    db: &Arc<SqlitePool>,
    user_id: &str,
    device: &PairedNode,
    act: TenantDeviceAct,
) -> Told {
    let mut told = Told { holds_identity: identity_key(runtime, user_id).is_some(), ..Told::default() };
    let drives = match drives_of(db, user_id, device).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(user_id, error = %e, "could not list the person's drives to tell them of a device");
            told.missed.push(("(the person's drives)".to_string(), format!("could not be listed: {e}")));
            return told;
        }
    };
    told.drives = drives.iter().map(|d| d.id.clone()).collect();
    if drives.is_empty() {
        return told;
    }
    let Some((change, signature)) = signed_change(runtime, user_id, device, act) else {
        tracing::warn!(user_id, "this device does not hold the identity, so it tells no drive of another device");
        told.missed = told.drives.iter().map(|d| (d.clone(), "this device does not hold the identity".to_string())).collect();
        return told;
    };
    for drive in drives {
        let id = drive.id.clone();
        let request = UserRequest::TenantDevice {
            user_id: user_id.to_string(),
            change: change.clone(),
            signature: signature.clone(),
        };
        let outcome = tokio::time::timeout(EACH_DRIVE, async {
            let client = runtime.dialer().connect(drive, user_id).await.map_err(|e| e.to_string())?;
            match client.send(&request).await.map_err(|e| e.to_string())? {
                UserResponse::Ok => Ok(()),
                UserResponse::Error { message } => Err(message),
                other => Err(format!("unexpected reply {other:?}")),
            }
        })
        .await
        .unwrap_or_else(|_| Err("the drive did not answer in time".to_string()));
        match outcome {
            Ok(()) => told.took.push(id),
            Err(e) => {
                tracing::warn!(user_id, drive = %id, act = ?act, error = %e, "a drive was not told of a device");
                told.missed.push((id, e));
            }
        }
    }
    told
}

/// `device revoke`: withdraw the node from the person's drives, then revoke it
/// here. The one body both the `NodeRevoke` request and the shell's surface
/// run, so neither can mean less than the other.
///
/// **Never success while a drive still admits the device.** On a device that
/// does not hold the identity, with drives to tell, nothing is revoked and the
/// answer says which device can do it. When some drive does not take the
/// withdrawal, the device is still revoked here — the revocation takes effect
/// wherever it can — and the answer is an error naming each drive that still
/// admits it and why, and that running revoke again will not reach them — the
/// row is gone here, so a second run finds no such device — and that nothing
/// retries yet. Telling those drives again is a later queue's; the person is
/// told now.
pub async fn revoke(
    runtime: &DeviceRuntime,
    member_store: &dyn kotton_peer::membership::MemberStore,
    db: &Arc<SqlitePool>,
    user_id: String,
    node_id: String,
) -> std::io::Result<UserResponse> {
    // Read before the row goes: the withdrawal names the device's key.
    // `node_id` is what the person named: the node's DID, or a label one row
    // of theirs carries. A label two rows carry is refused here, before the
    // drives are asked anything, rather than read as whichever row came first.
    let node = kotton_peer::daemon::db::paired_node_named(db, &user_id, &node_id).await?;
    let mut missed: Vec<(String, String)> = Vec::new();
    let is_drive = match node.as_ref() {
        Some(node) => kotton_peer::daemon::drives::is_drive(db, &user_id, node).await?,
        None => false,
    };
    if let Some(node) = node.as_ref().filter(|_| !is_drive) {
        let drives = drives_of(db, &user_id, node).await?;
        if !drives.is_empty() && identity_key(runtime, &user_id).is_none() {
            let names: Vec<String> = drives.iter().map(|d| d.id.clone()).collect();
            return Ok(UserResponse::Error {
                message: format!(
                    "not revoked: '{node_id}' is admitted at {} ({}), and only the device that holds \
                     the identity can withdraw it there. This device does not. Run `device revoke \
                     {node_id}` on the device that holds the identity.",
                    if names.len() == 1 { "a drive" } else { "drives" },
                    names.join(", ")
                ),
            });
        }
        missed = withdraw(runtime, db, &user_id, node).await.missed;
    }
    // The row is named by its DID from here, so the revoke takes the row the
    // drives were just told of.
    let named = node.as_ref().map_or_else(|| node_id.clone(), |n| n.device_did.to_string());
    let revoked = kotton_peer::daemon::nodes::node_revoke(member_store, db, user_id, named, &runtime.paired_keys()).await?;
    if !matches!(revoked, UserResponse::NodeRevoked) || missed.is_empty() {
        return Ok(revoked);
    }
    let still: Vec<String> = missed.iter().map(|(d, why)| format!("{d} ({why})")).collect();
    Ok(UserResponse::Error {
        message: format!(
            "'{node_id}' is revoked on this device, but {} still admit{} it: {}. Running `device \
             revoke` again will not reach {}: the device is no longer listed here, and nothing \
             retries the withdrawal yet. Until {} told, that device can still reach the sealed \
             copy kept there.",
            if missed.len() == 1 { "a drive" } else { "these drives" },
            if missed.len() == 1 { "s" } else { "" },
            still.join("; "),
            if missed.len() == 1 { "it" } else { "them" },
            if missed.len() == 1 { "it is" } else { "they are" },
        ),
    })
}
