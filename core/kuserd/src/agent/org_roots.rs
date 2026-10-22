// SPDX-License-Identifier: AGPL-3.0-or-later
//! A root an org owns, and who is let into it.
//!
//! Two verbs, and they are here rather than in any one domain because each composes three:
//! the root set is `store`'s, the org's key and its bookkeeping are `org`'s, and the envelope a
//! person holds and the membership grant they issue are `grant`'s. The daemon holds all three.
//!
//! ## Where ownership is checked
//!
//! **At creation**, [`org_root_create`] refuses an owner that is the person — their AID or
//! their identity DID — and an owner that is not an org this person holds on this device: the
//! project root's owner is an identity that is not any person's (Article VII).
//! **At every invitation**, [`org_root_invite`] asks the root who owns it and accepts
//! `org.invite` only from that identity; the owner is read from the root, never from the
//! request.
//!
//! ## Where membership is checked
//!
//! Membership is the read boundary: [`org_root_invite`] refuses a root the person is not
//! a member of with the record verbs' own answer, so asking cannot tell a root that exists
//! from one that does not.

use std::io;
use std::path::Path;
use std::sync::Arc;

use kotton_store::runtime::roots::{Owner, Residency, RootSet};
use kotton_sys::secret::SecretsStore;
use kotton_wire::ipc::{OrgRootDelegation, UserResponse};
use kotton_wire::{GrantEnvelope, GrantLifetime};
use sqlx::SqlitePool;

/// How long a membership grant is good for before the member must be admitted again — at most;
/// it is capped at the end of the delegation it is issued under (`issue_membership`).
///
/// A year, named here so it can be reviewed rather than written as a literal (`GrantLifetime`'s
/// own argument): it is issued to another party, whom the issuer cannot rely on reaching to
/// revoke, which is the case `GrantLifetime::Seconds` is for.
pub(crate) const MEMBERSHIP_LIFETIME: GrantLifetime = GrantLifetime::Seconds(365 * 24 * 60 * 60);

/// How long the org's `org.invite` delegation lasts before the org must renew it — and no
/// verb renews it today: the next envelope can be held only through `GrantImport`, behind
/// the trusted-issuer registry.
///
/// **This is the revocation bound.** A verifier on another node has no revocation feed to read,
/// so the only way it stops believing a revoked delegate is the delegation's
/// end; and every membership grant a delegate issues is capped at that end. Ninety days is how
/// stale a revocation may be, elsewhere, before it binds — the cost of an invitation that
/// verifies offline, stated as a number a person can shorten.
pub(crate) const DELEGATION_LIFETIME_SECS: i64 = 90 * 24 * 60 * 60;

fn refuse(message: impl Into<String>) -> io::Result<UserResponse> {
    Ok(UserResponse::Error { message: message.into() })
}

/// The person's AID and their root set, the way the record verbs read them.
pub(crate) fn open_roots(
    users: &crate::residency::UserRegistry,
    base: &Path,
    user_id: &str,
) -> Result<(String, RootSet), String> {
    let own_aid = kotton_identity::kel_store::load_chain(base, user_id)
        .ok()
        .and_then(|chain| chain.into_iter().next())
        .map(|e| e.aid.to_string())
        .ok_or_else(|| "this device holds no identity chain for you".to_string())?;
    let store = users
        .get(user_id)
        .ok_or_else(|| "your store is not open — unlock your session first".to_string())?;
    let binding = kotton_identity::provisioning::routing_binding(store.base_dir());
    let set = store.roots(&own_aid, binding.as_deref()).map_err(|e| e.to_string())?;
    Ok((own_aid, set))
}

/// `OrgRootCreate`: a root owned by `org_did`, with the person as its first member, and
/// `org.invite` on it delegated to the person.
///
/// **The one production caller of [`RootSet::add`].** The delegation goes through the org's own
/// issuing path, so a plain org signs at once and a FROST org hands back its ceremony.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn org_root_create(
    set: &mut RootSet,
    own_aid: &str,
    user_db: &Arc<SqlitePool>,
    secrets: &dyn SecretsStore,
    user_id: &str,
    org_did: String,
    name: String,
) -> io::Result<UserResponse> {
    let Some(person) = kotton_identity::owner_did_for(user_id, secrets) else {
        return refuse("identity key not available — unlock your session first");
    };
    if org_did == own_aid || org_did == person {
        return refuse(
            "a project root is owned by its org, not by a person: name the org's identity \
             (`kotton org create` mints one)",
        );
    }
    let plain = kotton_org::daemon::db::org_db::get_org(user_db, &org_did).await?.is_some();
    let frost = kotton_org::daemon::db::frost_db::is_frost_org(user_db, &org_did).await?;
    if !plain && !frost {
        return refuse(format!("{org_did} is not an org you hold on this device"));
    }
    if name.trim().is_empty() {
        return refuse("a root needs a name");
    }

    let root = set
        .add(name, Owner::Identity(org_did.clone()), vec![own_aid.to_owned()], Vec::new(), Residency::Full)
        .map_err(|e| io::Error::other(format!("recording the root: {e}")))?;
    let owner = set
        .get(&root)
        .and_then(|r| r.owner)
        .ok_or_else(|| io::Error::other("the root was recorded without its owner"))?;

    // The org delegates `org.invite` on the new root to the person who made it, through the
    // same issuing path as any org grant.
    let delegated = kotton_org::daemon::orgs::org_grant_issue(
        user_db,
        user_id,
        org_did.clone(),
        person.clone(),
        vec![kotton_schemas::CapabilityGrant::org_invite(&root).display_string()],
        Some(DELEGATION_LIFETIME_SECS),
        None,
        secrets,
    )
    .await?;
    let delegation = match delegated {
        UserResponse::OrgGrantIssued { envelope_id, envelope_json } => {
            let envelope: GrantEnvelope = serde_json::from_str(&envelope_json)
                .map_err(|e| io::Error::other(format!("the org's envelope: {e}")))?;
            kotton_grant::daemon::membership::invite_authority(
                &envelope,
                &owner,
                &root,
                &person,
                kotton_common::time::now_secs(),
            )
            .map_err(|e| io::Error::other(format!("the org's delegation does not hold: {e}")))?;
            // Held as any envelope a person holds is held. Not through `grant_import`, whose
            // trusted-issuer check answers a different question (see `membership`): the root
            // names its owner, and the daemon verified the owner's signature just above.
            kotton_grant::daemon::db::grant_db::store_imported_envelope(user_db, &envelope).await?;
            OrgRootDelegation::Held { envelope_id }
        }
        UserResponse::OrgFrostSignSession {
            session_id,
            message_hex,
            coordinator_id_hex,
            coordinator_commitment_hex,
        } => OrgRootDelegation::Ceremony {
            session_id,
            message_hex,
            coordinator_id_hex,
            coordinator_commitment_hex,
        },
        UserResponse::Error { message } => {
            return refuse(format!(
                "root {root} was created and the org did not delegate org.invite on it: {message}"
            ))
        }
        other => return refuse(format!("the org answered {other:?}")),
    };
    tracing::info!(%root, owner = %owner, "org root created");
    Ok(UserResponse::OrgRootCreated { root, owner, delegation })
}

/// `OrgRootInvite`: admit `member` to `root`, under the `org.invite` the person holds on it
/// from its owner, and issue their membership grant. Refused without it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn org_root_invite(
    set: &mut RootSet,
    own_aid: &str,
    user_db: &Arc<SqlitePool>,
    org_revocations: &SqlitePool,
    secrets: &dyn SecretsStore,
    user_id: &str,
    root: String,
    member: String,
) -> io::Result<UserResponse> {
    // Membership is the read boundary: a root the person is not in answers exactly as one
    // that does not exist does.
    let Some(held) = set.get(&root).filter(|r| r.members.iter().any(|m| m == own_aid)) else {
        return refuse(kotton_record::roots::NotAMember.to_string());
    };
    let Some(owner) = held.owner.clone() else {
        return refuse("this root is yours, not an org's; nobody delegates inviting to it");
    };
    let (Some(person), Some(key)) = (
        kotton_identity::owner_did_for(user_id, secrets),
        kotton_identity::identity_signing_key_for(user_id, secrets),
    ) else {
        return refuse("identity key not available — unlock your session first");
    };
    let now = kotton_common::time::now_secs();

    // The check: an envelope from the root's owner, to this person, carrying `org.invite` on
    // this root — a capability, never a name.
    let Some(authority) = kotton_grant::daemon::membership::held_invite(
        user_db,
        org_revocations,
        &owner,
        &root,
        &person,
        now,
    )
    .await?
    else {
        return refuse(format!(
            "you hold no org.invite on this root from its owner ({owner}); \
             inviting is a capability the org delegates"
        ));
    };

    let grant = kotton_grant::daemon::membership::issue_membership(
        &key,
        authority,
        &root,
        &member,
        MEMBERSHIP_LIFETIME,
        now,
    )
    .map_err(io::Error::other)?;
    let added = set
        .add_member(&root, &member)
        .map_err(|e| io::Error::other(format!("recording the member: {e}")))?;
    // Tracked where the org tracks what it issued, so `kotton org member remove` puts the
    // grant's id on the revocation list. That is all it does today: nothing takes the member
    // back out of the root's `members`: a removed member stays a member of the root.
    kotton_org::daemon::db::org_db::record_member_grant(user_db, &owner, &member, &grant.grant.id)
        .await?;
    let grant_json = serde_json::to_string(&grant)
        .map_err(|e| io::Error::other(format!("serialising the membership grant: {e}")))?;
    tracing::info!(%root, %member, "member admitted to an org root");
    Ok(UserResponse::OrgRootInvited { member, added, grant_json })
}
