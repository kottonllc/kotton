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
use kotton_wire::ipc::{TenantDeviceAct, TenantDeviceChange, UserResponse, VaultPeerRequest};
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
    let change = change_for(device, act, u64::try_from(kotton_common::time::now_millis()).unwrap_or(0));
    let signature = identity.sign(&change.signed_bytes(user_id)).to_bytes().to_vec();
    Some((change, signature))
}

/// The change a drive is told of `device`. Its key is named by the `did:key` the
/// derivation makes of the row's bytes, never by the DID stored beside them,
/// which may be another spelling (kottonllc/kotton#597): a row stands by its
/// bytes, so a device under such a row is admitted at its person's drive as
/// any other is. Where the bytes are no key the row's DID is told as stored,
/// so a withdrawal is matched to what the drive stored for it; an admit under
/// them is refused at the drive, which says why.
pub fn change_for(device: &PairedNode, act: TenantDeviceAct, said_at_ms: u64) -> TenantDeviceChange {
    let device_did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&device.public_key)
        .map(|did| did.to_string())
        .unwrap_or_else(|_| device.device_did.to_string());
    TenantDeviceChange { act, device_did, public_key: device.public_key, said_at_ms }
}

/// A member of the person's set as the node a drive is told of: its DID as
/// stored and its stored bytes, under its label or its DID. `None` when the DID
/// as stored does not read as a DID.
fn member_as_node(member: &kotton_schemas::membership::Member) -> Option<PairedNode> {
    Some(PairedNode {
        id: member.label.clone().unwrap_or_else(|| member.did.clone()),
        device_did: kotton_wire::did::Did::parse(&member.did).ok()?,
        public_key: member.public_key,
        paired_at: 0,
        addresses: Vec::new(),
        relay_url: None,
        posture: member.posture.map(|p| p.as_str().to_string()),
    })
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
        let request = VaultPeerRequest::TenantDevice {
            user_id: user_id.to_string(),
            change: change.clone(),
            signature: signature.clone(),
        };
        let outcome = tokio::time::timeout(EACH_DRIVE, async {
            let client = runtime.dialer().connect(drive, user_id).await.map_err(|e| e.to_string())?;
            drive_took(client.send_to_vault(&request).await.map_err(|e| e.to_string())?)
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

/// What a drive's answer to a device change says: taken, or why not. A
/// vault's refusal to keep for this device under the person's name
/// ([`UserResponse::NotPairedAs`]) is said in its sentence, printed as data and
/// to the bound ([`kotton_wire::note::quoted_cut`]), and decides nothing more
/// than any other refusal here.
fn drive_took(answer: UserResponse) -> Result<(), String> {
    match answer {
        UserResponse::Ok => Ok(()),
        UserResponse::Error { message } => Err(message),
        UserResponse::NotPairedAs { message, .. } => Err(format!("the vault answered: {}", kotton_wire::note::quoted_cut(&message))),
        other => Err(format!("unexpected reply {other:?}")),
    }
}

/// `device revoke`: withdraw the node from the person's drives, then revoke it
/// here. The one body both the `NodeRevoke` request and the shell's surface
/// run, so neither can mean less than the other.
///
/// **What it names is the one resolver's** (`kotton_peer::daemon::nodes::node_named`):
/// a row of the person's, or, asked [`Asked::Locally`] only, an own-device member
/// of their set that no row stands for, by its DID as stored. A member with no
/// row is withdrawn at the person's drives as a row is, from the member's stored
/// bytes and DID ([`change_for`]); a drive matches a withdrawal under bytes that
/// are no key as stored and records nothing (`kvaultd::devices`).
///
/// **Never success while a drive still admits the device.** On a device that
/// does not hold the identity, with drives to tell, nothing is revoked and the
/// answer says which device can do it. When some drive does not take the
/// withdrawal, the device is still revoked here — the revocation takes effect
/// wherever it can — and the answer is an error naming each drive that still
/// admits it and why, and that running revoke again will not reach them — the
/// row is gone here, so a second run finds no such device — and that nothing
/// retries yet. Telling those drives again is a later queue's; the person is
/// told now. Where another row of the person's still holds the revoked row's
/// key (kottonllc/kotton#597, 34A), that is not so: the answer names each such
/// row, says it is still listed, and says that `device revoke` given its name
/// tells the drives of the key again, as it does, since a withdrawal names the
/// key ([`change_for`]) ([`missed_answer`]).
///
/// [`Asked::Locally`]: kotton_peer::daemon::nodes::Asked::Locally
pub async fn revoke(
    runtime: &DeviceRuntime,
    member_store: &dyn kotton_peer::membership::MemberStore,
    db: &Arc<SqlitePool>,
    user_id: String,
    node_id: String,
    asked: kotton_peer::daemon::nodes::Asked,
) -> std::io::Result<UserResponse> {
    use kotton_peer::daemon::nodes::{node_named, revoke_named, Named};
    // Read before anything goes: the withdrawal names the device's key.
    // `node_id` is what the person named, within what the asker reaches
    // (`Asked::reach`). A label two rows carry is refused here, before the
    // drives are asked anything, rather than read as whichever row came first.
    let Some(named) = node_named(db, &user_id, &node_id, asked.reach(member_store)).await? else {
        return Ok(UserResponse::Error {
            message: format!("node '{}' not found for user '{}'", node_id, user_id),
        });
    };
    // What the drives are told of: the row, or each member as a node of its
    // stored bytes and DID. A member whose DID as stored does not read as a DID
    // can be told to no drive, and is said to be missed at each.
    let mut devices: Vec<PairedNode> = Vec::new();
    let mut untold: Vec<String> = Vec::new();
    match &named {
        Named::Row(node) => {
            if !kotton_peer::daemon::drives::is_drive(db, &user_id, node).await? {
                devices.push(node.clone());
            }
        }
        Named::Members(found) => {
            for f in found {
                match member_as_node(&f.member) {
                    Some(node) => devices.push(node),
                    None => untold.push(f.member.did.clone()),
                }
            }
        }
    }
    let mut missed: Vec<(String, String)> = Vec::new();
    for device in &devices {
        let drives = drives_of(db, &user_id, device).await?;
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
    }
    for device in &devices {
        missed.extend(withdraw(runtime, db, &user_id, device).await.missed);
    }
    if !untold.is_empty() {
        for drive in kotton_peer::daemon::drives::nodes(db, &user_id).await? {
            missed.push((drive.id, "the member's DID as stored is not a DID, so it was not told".to_string()));
        }
    }
    // What was resolved is what is revoked: the row the drives were just told
    // of, or the members the set's own listing returned.
    let revoked = revoke_named(member_store, db, &user_id, &named, &runtime.paired_keys()).await?;
    // A row's revoke that leaves another row of the person's under its key
    // answers with an error that names it (kottonllc/kotton#597, 34A). Where a
    // drive was missed too, one answer says both, and says what revoking that
    // row does.
    if !matches!(revoked, UserResponse::NodeRevoked | UserResponse::Error { .. }) || missed.is_empty() {
        return Ok(revoked);
    }
    let still_listed = match &named {
        Named::Row(node) => kotton_peer::daemon::nodes::still_paired_as(
            &kotton_peer::daemon::db::list_paired_nodes(db, &user_id).await?,
            &node.public_key,
        ),
        Named::Members(_) => Vec::new(),
    };
    Ok(UserResponse::Error { message: missed_answer(&node_id, &missed, &still_listed) })
}

/// The answer to a revoke that drives in `missed` did not take, for the device
/// the person named `node_id`. `still_listed` is the name `device revoke` takes
/// to each other row of the person's that still holds the revoked row's key
/// ([`kotton_peer::daemon::nodes::still_paired_as`]).
///
/// With none, a second run of `device revoke` finds no such device, and the
/// answer says so. With some, the device is still listed under each, and
/// revoking one by that name withdraws it at every drive again: a withdrawal
/// names the key ([`change_for`]), whichever row it was revoked through. Each
/// name is printed as data ([`kotton_wire::note::quoted`]).
fn missed_answer(node_id: &str, missed: &[(String, String)], still_listed: &[String]) -> String {
    let one = missed.len() == 1;
    let still: Vec<String> = missed.iter().map(|(d, why)| format!("{d} ({why})")).collect();
    let head = format!(
        "'{node_id}' is revoked on this device, but {} still admit{} it: {}.",
        if one { "a drive" } else { "these drives" },
        if one { "s" } else { "" },
        still.join("; "),
    );
    let until = format!(
        "Until {} told, that device can still reach the sealed copy kept there.",
        if one { "it is" } else { "they are" }
    );
    if still_listed.is_empty() {
        return format!(
            "{head} Running `device revoke` again will not reach {}: the device is no longer listed here, \
             and nothing retries the withdrawal yet. {until}",
            if one { "it" } else { "them" },
        );
    }
    let rows_one = still_listed.len() == 1;
    format!(
        "{head} This device still pairs its key for you as {}, and {} still listed: `device revoke` \
         given {} name removes it here and tells your drives of the key again. {until}",
        still_listed.iter().map(|n| kotton_wire::note::quoted(n)).collect::<Vec<_>>().join(", "),
        if rows_one { "that row is" } else { "those rows are" },
        if rows_one { "its" } else { "each" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A drive's refusal to keep for this device is said in its sentence,
    /// as data and to the bound** (how a device reads a vault's refusal to
    /// keep for it), whichever its kind.
    #[test]
    fn a_drives_refusal_of_a_device_change_is_printed_as_data_and_to_the_bound() {
        use kotton_wire::ipc::NotPairedAsKind;
        let long = "x".repeat(kotton_wire::note::MAX_SAID_CHARS + 2);
        for kind in [NotPairedAsKind::AsAnother, NotPairedAsKind::Unsaid] {
            let said = drive_took(UserResponse::NotPairedAs { kind, message: "no `drive`\nhere".into() });
            assert_eq!(said, Err("the vault answered: `no \\u{60}drive\\u{60}\\nhere`".to_string()), "{kind:?}");
            let said = drive_took(UserResponse::NotPairedAs { kind, message: long.clone() });
            let want = format!("the vault answered: `{}` (cut: 2 more characters)", "x".repeat(kotton_wire::note::MAX_SAID_CHARS));
            assert_eq!(said, Err(want), "{kind:?}");
        }
        assert_eq!(drive_took(UserResponse::Ok), Ok(()));
    }

    /// **The missed-drive answer is as it was where no other row holds the
    /// key**, word for word, for one drive and for two.
    #[test]
    fn the_missed_drive_answer_with_no_second_row_is_unchanged() {
        let one = [("vault".to_string(), "it did not answer".to_string())];
        assert_eq!(
            missed_answer("laptop", &one, &[]),
            "'laptop' is revoked on this device, but a drive still admits it: vault (it did not answer). \
             Running `device revoke` again will not reach it: the device is no longer listed here, and nothing \
             retries the withdrawal yet. Until it is told, that device can still reach the sealed copy kept there."
        );
        let two = [one[0].clone(), ("office".to_string(), "refused".to_string())];
        assert_eq!(
            missed_answer("laptop", &two, &[]),
            "'laptop' is revoked on this device, but these drives still admit it: vault (it did not answer); \
             office (refused). Running `device revoke` again will not reach them: the device is no longer listed \
             here, and nothing retries the withdrawal yet. Until they are told, that device can still reach the \
             sealed copy kept there."
        );
    }

    /// **Where a second row of the person's holds the key, the answer says the
    /// row is still listed and that revoking it by its name tells the drives
    /// again** (kottonllc/kotton#597, 34A), and does not say the device is gone
    /// or that a revoke will not reach it. Each name is printed as data.
    #[test]
    fn the_missed_drive_answer_with_a_second_row_names_it_as_still_listed() {
        let one = [("vault".to_string(), "it did not answer".to_string())];
        for (names, says) in [
            (vec!["old-laptop".to_string()], "as `old-laptop`, and that row is still listed: `device revoke` given its name"),
            (
                vec!["did:key:z6Mk`x".to_string(), "spare".to_string()],
                "as `did:key:z6Mk\\u{60}x`, `spare`, and those rows are still listed: `device revoke` given each name",
            ),
        ] {
            let said = missed_answer("laptop", &one, &names);
            assert!(said.contains(says), "{said}");
            assert!(said.contains("tells your drives of the key again"), "{said}");
            assert!(said.contains("still admits it: vault (it did not answer)"), "{said}");
            assert!(!said.contains("no longer listed") && !said.contains("will not reach"), "{said}");
        }
    }
}
