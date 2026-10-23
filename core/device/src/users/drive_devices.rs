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
//! Best effort, drive by drive and bounded: a drive that is asleep is logged
//! and skipped, and the device it was not told of is refused there until a
//! later introduction reaches it. Which nodes are drives is the posture the
//! enrolment recorded for them (`blind-storage`).

use crate::DeviceRuntime;
use kotton_schemas::membership::Posture;
use kotton_wire::ipc::{TenantDeviceAct, TenantDeviceChange, UserRequest, UserResponse};
use kotton_wire::peer::PairedNode;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;

/// How long one drive is given to answer.
const EACH_DRIVE: Duration = Duration::from_secs(15);

/// Tell each of `user_id`'s drives to admit `device` from now on. Returns the
/// drives that took it, by their row's id.
pub async fn introduce(runtime: &DeviceRuntime, db: &Arc<SqlitePool>, user_id: &str, device: &PairedNode) -> Vec<String> {
    tell(runtime, db, user_id, device, TenantDeviceAct::Admit).await
}

/// Tell each of `user_id`'s drives to admit `device` no longer.
pub async fn withdraw(runtime: &DeviceRuntime, db: &Arc<SqlitePool>, user_id: &str, device: &PairedNode) -> Vec<String> {
    tell(runtime, db, user_id, device, TenantDeviceAct::Withdraw).await
}

/// Whether `node` is one of the person's drives rather than a device of theirs.
pub fn is_drive(node: &PairedNode) -> bool {
    node.posture.as_deref() == Some(Posture::BlindStorage.as_str())
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
    let identity = kotton_peer::daemon::nodes::load_signing_key(user_id, runtime.secrets()).ok()?;
    let change = TenantDeviceChange {
        act,
        device_did: device.device_did.to_string(),
        public_key: device.public_key,
        said_at: u64::try_from(kotton_common::time::now_secs()).unwrap_or(0),
    };
    let signature = identity.sign(&change.signed_bytes(user_id)).to_bytes().to_vec();
    Some((change, signature))
}

async fn tell(
    runtime: &DeviceRuntime,
    db: &Arc<SqlitePool>,
    user_id: &str,
    device: &PairedNode,
    act: TenantDeviceAct,
) -> Vec<String> {
    let drives = match kotton_peer::daemon::db::list_paired_nodes_with_posture(db, user_id, Posture::BlindStorage.as_str()).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(user_id, error = %e, "could not list the person's drives to tell them of a device");
            return Vec::new();
        }
    };
    let drives: Vec<PairedNode> = drives.into_iter().filter(|d| d.public_key != device.public_key).collect();
    if drives.is_empty() {
        return Vec::new();
    }
    let Some((change, signature)) = signed_change(runtime, user_id, device, act) else {
        tracing::warn!(user_id, "this device does not hold the identity, so it tells no drive of another device");
        return Vec::new();
    };
    let mut told = Vec::new();
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
            Ok(()) => told.push(id),
            Err(e) => tracing::warn!(user_id, drive = %id, act = ?act, error = %e, "a drive was not told of a device"),
        }
    }
    told
}

/// `device revoke`: withdraw the node from the person's drives, then revoke it
/// here. The one body both the `NodeRevoke` request and the shell's surface
/// run, so neither can mean less than the other.
pub async fn revoke(
    runtime: &DeviceRuntime,
    member_store: &dyn kotton_peer::membership::MemberStore,
    db: &Arc<SqlitePool>,
    user_id: String,
    node_id: String,
) -> std::io::Result<UserResponse> {
    // Read before the row goes: the withdrawal names the device's key.
    let node = kotton_peer::daemon::db::get_paired_node_by_id(db, &user_id, &node_id).await?;
    if let Some(node) = node.as_ref().filter(|n| !is_drive(n)) {
        withdraw(runtime, db, &user_id, node).await;
    }
    kotton_peer::daemon::nodes::node_revoke(member_store, db, user_id, node_id, &runtime.paired_keys()).await
}
