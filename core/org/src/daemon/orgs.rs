// SPDX-License-Identifier: AGPL-3.0-or-later
//! Org identity IPC handlers — Step 9 (identity_model sprint).
//!
//! Single-key path only; FROST is Step 10.
//!
//! ## Key custody model
//!
//! Org private key scalars are stored in the OS keychain under the key
//! `kotton:org_key:{org_did}` (hex-encoded 32-byte Ed25519 scalar). They are
//! never written to SQLite. The daemon reads the key from the keychain on every
//! `OrgGrantIssue` call.

use kotton_wire::ipc::UserResponse;
use super::db::{frost_db, org_db};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use kotton_sys::secret::SecretsStore;
use kotton_wire::{
    did::Did,
    ipc::{OrgEntry, OrgGrantEntry},
    GrantEnvelope,
};
use kotton_crypto::DidKeyMethod;
use kotton_schemas::{CapabilityGrant, CapabilityKind, Nsid};
use kotton_common::crypto::kdf_labels;
use kotton_common::time::now_secs;
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use std::io;
use std::sync::Arc;
use uuid::Uuid;

// ── OrgNew ───────────────────────────────────────────────────────────────────

/// Create a new single-key org identity.
///
/// 1. Generate a fresh Ed25519 keypair.
/// 2. Derive the org DID from the public key.
/// 3. Store the private scalar in the OS keychain.
/// 4. Insert the org row in `org_identities`.
/// 5. Return the new org DID.
pub async fn org_new(
    user_db: &Arc<SqlitePool>,
    user_id: &str,
    name: String,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    // Load user identity to record as owner.
    let owner_did = match owner_did_for(user_id, secrets) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity key not available — unlock your session first".to_string(),
            });
        }
    };

    // Generate org keypair.
    let org_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let org_did = DidKeyMethod::from_public_key(&org_sk.verifying_key());
    let org_did_str = org_did.to_string();

    // Persist private key in keychain (hex-encoded).
    let hex_key = hex::encode(org_sk.to_bytes());
    secrets
        .set_secret(&kdf_labels::org_signing_key(&org_did_str), &hex_key)
        .map_err(|e| io::Error::other(format!("keychain write failed: {e}")))?;

    // Insert row in org_identities.
    org_db::insert_org(user_db, &org_did_str, &name, &owner_did).await?;

    tracing::info!(org_did = %org_did_str, %name, "org created");
    Ok(UserResponse::OrgCreated {
        org_did: org_did_str,
    })
}

// ── OrgShow ──────────────────────────────────────────────────────────────────

pub async fn org_show(user_db: &Arc<SqlitePool>, org_did: String) -> io::Result<UserResponse> {
    match org_db::get_org(user_db, &org_did).await? {
        None => Ok(UserResponse::Error {
            message: format!("org not found: {org_did}"),
        }),
        Some((org_did, name, owner_did, created_at)) => Ok(UserResponse::OrgInfo {
            org_did,
            name,
            owner_did,
            created_at,
        }),
    }
}

// ── OrgList ──────────────────────────────────────────────────────────────────

pub async fn org_list(user_db: &Arc<SqlitePool>, user_id: &str, secrets: &dyn SecretsStore) -> io::Result<UserResponse> {
    let owner_did = match owner_did_for(user_id, secrets) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity key not available — unlock your session first".to_string(),
            });
        }
    };

    let rows = org_db::list_orgs(user_db, &owner_did).await?;
    let orgs = rows
        .into_iter()
        .map(|(org_did, name, created_at)| OrgEntry {
            org_did,
            name,
            created_at,
        })
        .collect();

    Ok(UserResponse::OrgList { orgs })
}

// ── OrgGrantIssue ─────────────────────────────────────────────────────────────

/// Issue a `GrantEnvelope` from an org to a member.
///
/// If the org is FROST-keyed, delegates to the FROST signing-begin flow which
/// returns a session ID for the multi-party ceremony instead of a finished
/// envelope.  The caller is responsible for completing the ceremony via
/// `OrgFrostSignContribute` + `OrgFrostSignFinalize`.
// Allowed: the grant's five fields plus the stores, passed through whole to the grant this
// call issues; the struct that would hold them is that grant.
#[allow(clippy::too_many_arguments)]
pub async fn org_grant_issue(
    user_db: &Arc<SqlitePool>,
    user_id: &str,
    org_did: String,
    member_did: String,
    caps: Vec<String>,
    ttl_secs: Option<i64>,
    node_did: Option<String>,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    // Delegate to FROST handler if this is a FROST org.
    if frost_db::is_frost_org(user_db, &org_did).await? {
        return super::frost_orgs::org_frost_sign_begin(
            user_db, user_id, org_did, member_did, caps, ttl_secs, node_did, secrets,
        )
        .await;
    }

    // Load org signing key from keychain.
    let org_sk = match load_org_key(&org_did, secrets) {
        Some(k) => k,
        None => {
            return Ok(UserResponse::Error {
                message: format!(
                    "org key not available for {org_did} — \
                     was this org created on this device?"
                ),
            });
        }
    };

    // Parse capability strings.
    let grants = match parse_caps(&caps) {
        Ok(g) => g,
        Err(e) => return Ok(UserResponse::Error { message: e }),
    };

    // Parse optional node DID.
    let node_did_parsed: Option<Did> = match node_did {
        None => None,
        Some(ref s) => match Did::parse(s) {
            Ok(d) => Some(d),
            Err(e) => {
                return Ok(UserResponse::Error {
                    message: format!("invalid node_did: {e}"),
                });
            }
        },
    };

    // Parse member DID.
    let subject_did = match Did::parse(&member_did) {
        Ok(d) => d,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("invalid member_did: {e}"),
            });
        }
    };

    let issuer_did = DidKeyMethod::from_public_key(&org_sk.verifying_key());
    let now = now_secs();
    let expires_at = ttl_secs.map(|ttl| now + ttl);

    let mut envelope = GrantEnvelope {
        id: Uuid::new_v4().to_string(),
        issuer_did,
        subject_did,
        node_did: node_did_parsed,
        grants,
        issued_at: now,
        expires_at,
        // Not an app grant: this envelope authorises a member of an org, and the
        // app binding (`DEC-0052`) does not apply. `check_grant` refuses an
        // unbound envelope, which is why this must never be stored in
        // `app_grant_envelopes`.
        app_id: None,
        issuer_signature: String::new(),
    };

    // Sign over canonical JSON.
    let canonical = envelope
        .canonical_json()
        .map_err(|e| io::Error::other(format!("canonical_json: {e}")))?;
    let sig = org_sk.sign(canonical.as_bytes());
    envelope.issuer_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let envelope_id = envelope.id.clone();
    let envelope_json = serde_json::to_string(&envelope)
        .map_err(|e| io::Error::other(format!("serialize envelope: {e}")))?;

    // Record in org_members for future revocation.
    org_db::record_member_grant(user_db, &org_did, &member_did, &envelope_id).await?;

    tracing::info!(
        %org_did,
        %member_did,
        %envelope_id,
        "org grant issued"
    );

    Ok(UserResponse::OrgGrantIssued {
        envelope_id,
        envelope_json,
    })
}

// ── OrgGrantList ─────────────────────────────────────────────────────────────

pub async fn org_grant_list(user_db: &Arc<SqlitePool>, org_did: String) -> io::Result<UserResponse> {
    let rows = org_db::list_org_grants(user_db, &org_did).await?;
    let grants = rows
        .into_iter()
        .map(|(member_did, envelope_id, issued_at)| OrgGrantEntry {
            member_did,
            envelope_id,
            issued_at,
        })
        .collect();
    Ok(UserResponse::OrgGrantList { grants })
}

// ── OrgMemberRemove ───────────────────────────────────────────────────────────

/// Revoke all outstanding envelopes issued by `org_did` to `member_did`.
///
/// The org's bookkeeping (`org_members`) is the owner's, in `user_db`
/// (RFC-0063 stage 3b-iv). The revocation itself goes to `org_revocations`,
/// the **machine-wide** list that `grant_import` checks alongside the caller's
/// own — an org's "this envelope is dead" must be visible to the member it was
/// issued to, and that channel is the one deliberately-shared remainder until
/// revocation propagation gets its sync design (same-machine members were only
/// ever protected incidentally; a remote member's daemon never saw this list).
/// Which envelopes a member holds — **the caller revokes them.**
///
/// Split from `org_member_remove` 2026-08-20 (RFC-0080 step 8). Revoking a grant
/// is `grant`'s authority, not `org`'s, and reaching into the shared revocation
/// list was the one thing standing between these handlers and their own crate.
/// Returning the ids keeps the ordering and the failure semantics the combined
/// version had: revocation happens *before* the tracking rows go, so a failed
/// revoke leaves them intact and the operation is retryable.
pub async fn org_member_envelope_ids(
    user_db: &Arc<SqlitePool>,
    org_did: &str,
    member_did: &str,
) -> io::Result<Vec<String>> {
    org_db::get_member_envelope_ids(user_db, org_did, member_did).await
}

/// Forget a member's grant tracking rows, once the caller has revoked them.
pub async fn org_member_forget(
    user_db: &Arc<SqlitePool>,
    org_did: String,
    member_did: String,
    revoked_count: u32,
) -> io::Result<UserResponse> {
    org_db::delete_member_grants(user_db, &org_did, &member_did).await?;
    tracing::info!(%org_did, %member_did, revoked = revoked_count, "org member removed");
    Ok(UserResponse::OrgMemberRemoved { revoked_count })
}

// ── private helpers ───────────────────────────────────────────────────────────

use kotton_identity::owner_did_for;

/// Load an org's Ed25519 signing key from the OS keychain.
///
/// Returns `None` if the key is not present (org not on this device).
fn load_org_key(org_did: &str, secrets: &dyn SecretsStore) -> Option<ed25519_dalek::SigningKey> {
    let hex_key = secrets
        .get_secret(&kdf_labels::org_signing_key(org_did))
        .ok()??;
    let key_bytes: [u8; 32] = hex::decode(&hex_key).ok()?.try_into().ok()?;
    Some(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
}

/// Parse capability strings in display form (`"schema.read:sh.kotton.notes"`,
/// `"vfs.read:/notes"`, `"org.invite:<root>"`) into `CapabilityGrant`s.
pub fn parse_caps(caps: &[String]) -> Result<Vec<CapabilityGrant>, String> {
    caps.iter().map(|s| parse_cap(s)).collect()
}

fn parse_cap(s: &str) -> Result<CapabilityGrant, String> {
    // Format: `<domain>.<kind>:<target>`
    // e.g. `schema.read:sh.kotton.notes` or `vfs.write:/notes`
    let (prefix, target_str) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid capability string (missing ':'): {s:?}"))?;

    // What an org hands a member about one of its roots (RFC-0088 rule 5): the authority to
    // admit people, and membership itself. Their display form is the whole of their parse,
    // so they are matched whole rather than split into a domain and a kind they do not have.
    match prefix {
        "org.invite" | "root.member" if target_str.is_empty() => {
            return Err(format!("{prefix} names no root: {s:?}"));
        }
        "org.invite" => return Ok(CapabilityGrant::org_invite(target_str)),
        "root.member" => return Ok(CapabilityGrant::root_member(target_str)),
        _ => {}
    }

    let (domain, kind_str) = prefix
        .split_once('.')
        .ok_or_else(|| format!("invalid capability string (missing '.' in prefix): {s:?}"))?;

    let kind = match kind_str {
        "read" => CapabilityKind::Read,
        "write" => CapabilityKind::Write,
        other => return Err(format!("unknown capability kind {other:?} in {s:?}")),
    };

    match domain {
        "schema" => {
            let nsid =
                Nsid::new(target_str).map_err(|e| format!("invalid NSID {target_str:?}: {e}"))?;
            Ok(CapabilityGrant::schema(kind, nsid))
        }
        "vfs" => Ok(CapabilityGrant::vfs(kind, target_str)),
        other => Err(format!("unknown capability domain {other:?} in {s:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_caps;
    use kotton_schemas::CapabilityGrant;

    /// The two capabilities an org hands a member about one of its roots parse from their
    /// display form, and one naming no root is refused rather than read as every root.
    #[test]
    fn an_org_parses_the_capabilities_it_hands_a_member_about_a_root() {
        let got = parse_caps(&["org.invite:r1".into(), "root.member:r1".into()]).unwrap();
        let want = [CapabilityGrant::org_invite("r1"), CapabilityGrant::root_member("r1")];
        assert_eq!(
            got.iter().map(|g| g.display_string()).collect::<Vec<_>>(),
            want.iter().map(|g| g.display_string()).collect::<Vec<_>>(),
        );
        assert!(parse_caps(&["org.invite:".into()]).is_err());
        assert!(parse_caps(&["org.admin:r1".into()]).is_err(), "a role name is not a capability");
    }
}
