// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who may let someone into a root, and what the letting-in produces (RFC-0088, "Ownership
//! and membership").
//!
//! A root an org owns is the org's to admit people to. The org does not do that itself each
//! time — its quorum would have to meet for every invitation — so it **delegates**: it issues
//! a grant envelope carrying `org.invite:<root>` to a member, and whoever holds that may let
//! someone in. Letting someone in is issuing them a membership grant, `root.member:<root>`,
//! signed by the holder, with the owner's delegation beside it ([`MembershipGrant`]).
//!
//! ## The capability is checked, never a name
//!
//! Nothing here reads a role. The question asked of an envelope is the one
//! [`CapabilitySet::allows`] answers for every other grant — does it carry
//! `Use` on `OrgInvite { root }` — and the issuer that makes the answer count is the root's
//! **owner**, as the root records it. A person the project calls "maintainer" holds whatever
//! the org delegated to them and nothing more; the word is the project's, in its records
//! (DEC-0038, DEC-0080).
//!
//! ## Revocation, and the bound a verifier can hold
//!
//! Revoking a delegation stops the holder's own daemon at once ([`held_invite`] reads both
//! revocation lists). It does not stop a verifier somewhere else, which has no revocation feed
//! to read (RFC-0073 G8: revocation exists as a shape, with no propagation model). So the
//! delegation is where the bound lives: **a delegation must carry an end** ([`Refusal::Unbounded`]
//! otherwise), and **no membership grant issued under it may outlast it** — [`issue_membership`]
//! caps the grant's expiry at the delegation's, and [`verify_membership`] refuses one that claims
//! more ([`Refusal::OutlivesAuthority`]). A holder whose delegation is revoked keeps their key and
//! can still sign, but nothing they sign verifies past the end the owner put on their authority.
//! Until a revocation feed exists, expiry is the only way a remote verifier learns of a
//! revocation, and the delegation's lifetime is how stale that can be.
//!
//! ## Why the owner, and not the trusted-issuer registry
//!
//! The registry says whose envelopes count *for an app's capabilities on this device*, and a
//! person adds to it. Authority over a root is a different fact with a narrower answer: the
//! root says who owns it, and only that identity's signature can delegate over it. Reading the
//! registry here would let any org the person trusts for anything admit people to any root.

use std::io;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use kotton_schemas::{CapabilityGrant, CapabilityKind, CapabilitySet, CapabilityTarget};
use kotton_wire::did::Did;
use kotton_wire::{GrantEnvelope, GrantLifetime, MembershipGrant};
use sqlx::SqlitePool;

use super::db::grant_db;
use super::grants::verify_envelope_signature;

/// Why an envelope is not authority over a root, or a grant is not membership of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Issued by someone other than the identity the answer needs.
    WrongIssuer,
    /// Issued to someone other than the identity presenting it.
    WrongSubject,
    /// The signature does not verify under the issuer's key.
    BadSignature,
    /// Past its `expires_at`.
    Expired,
    /// Carries no capability on this root of the kind asked for.
    NotGranted,
    /// Issued by a delegate, with no delegation beside it.
    NoAuthority,
    /// A delegation with no end: a revocation could never reach a verifier through expiry.
    Unbounded,
    /// A delegate's grant claims to last longer than the delegation it was issued under.
    OutlivesAuthority,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::WrongIssuer => "issued by an identity that does not own the root",
            Refusal::WrongSubject => "issued to someone else",
            Refusal::BadSignature => "its signature does not verify",
            Refusal::Expired => "it has expired",
            Refusal::NotGranted => "it carries no such capability on this root",
            Refusal::NoAuthority => "its issuer is not the owner and shows no delegation",
            Refusal::Unbounded => "the delegation has no end, so no revocation could ever reach a verifier",
            Refusal::OutlivesAuthority => "it claims to last longer than the delegation it was issued under",
        })
    }
}

fn check(
    envelope: &GrantEnvelope,
    issuer: &str,
    subject: &str,
    kind: CapabilityKind,
    target: CapabilityTarget,
    now: i64,
) -> Result<(), Refusal> {
    if envelope.issuer_did.to_string() != issuer {
        return Err(Refusal::WrongIssuer);
    }
    if envelope.subject_did.to_string() != subject {
        return Err(Refusal::WrongSubject);
    }
    if !verify_envelope_signature(envelope) {
        return Err(Refusal::BadSignature);
    }
    if envelope.expires_at.is_some_and(|at| at <= now) {
        return Err(Refusal::Expired);
    }
    if !CapabilitySet::new(envelope.grants.clone()).allows(&kind, &target) {
        return Err(Refusal::NotGranted);
    }
    Ok(())
}

/// Whether `envelope` gives `holder` the authority to admit people to `root`: issued by the
/// root's `owner`, to `holder`, signed, **bounded in time and unexpired**, and carrying
/// `org.invite:<root>`.
///
/// Revocation is the caller's to ask, against the lists it can read — [`held_invite`] does.
/// A delegation with no `expires_at` is refused: it is the one thing a verifier elsewhere could
/// never stop believing (see the module note).
pub fn invite_authority(
    envelope: &GrantEnvelope,
    owner: &str,
    root: &str,
    holder: &str,
    now: i64,
) -> Result<(), Refusal> {
    check(
        envelope,
        owner,
        holder,
        CapabilityKind::Use,
        CapabilityTarget::OrgInvite { root: root.to_owned() },
        now,
    )?;
    if envelope.expires_at.is_none() {
        return Err(Refusal::Unbounded);
    }
    Ok(())
}

/// The `org.invite` envelope `holder` holds on `root` from its `owner`, if any — the one this
/// person may admit people under.
///
/// Read from the envelopes this person holds (`imported_grant_envelopes`), and skipping any
/// revoked in their own list or in the org-side one, as `grant_import` does.
pub async fn held_invite(
    pool: &SqlitePool,
    org_revocations: &SqlitePool,
    owner: &str,
    root: &str,
    holder: &str,
    now: i64,
) -> io::Result<Option<GrantEnvelope>> {
    for envelope in grant_db::get_imported_envelopes(pool, holder).await? {
        if invite_authority(&envelope, owner, root, holder, now).is_err() {
            continue;
        }
        if grant_db::is_revoked(pool, &envelope.id).await?
            || grant_db::is_revoked(org_revocations, &envelope.id).await?
        {
            continue;
        }
        return Ok(Some(envelope));
    }
    Ok(None)
}

/// Issue `member` a membership grant on `root`, signed by the holder of `authority`, with
/// `authority` beside it.
///
/// `holder_key` must be the key of `authority`'s subject; a grant signed by anyone else would
/// not walk back to the owner, and [`verify_membership`] would say so. The grant ends at
/// `lifetime` or at the delegation's end, whichever is sooner — a delegate cannot admit someone
/// for longer than they were trusted to admit anyone.
pub fn issue_membership(
    holder_key: &ed25519_dalek::SigningKey,
    authority: GrantEnvelope,
    root: &str,
    member: &str,
    lifetime: GrantLifetime,
    now: i64,
) -> Result<MembershipGrant, String> {
    let subject_did = Did::parse(member).map_err(|e| format!("{member:?} is not an identity: {e}"))?;
    let mut grant = GrantEnvelope {
        id: uuid::Uuid::new_v4().to_string(),
        issuer_did: authority.subject_did.clone(),
        subject_did,
        node_did: None,
        grants: vec![CapabilityGrant::root_member(root)],
        issued_at: now,
        expires_at: match (lifetime.expires_at(now), authority.expires_at) {
            (Some(asked), Some(bound)) => Some(asked.min(bound)),
            (None, bound) => bound,
            (asked, None) => asked,
        },
        // Not an app grant: it admits a person to a root (DEC-0052's binding is for apps).
        app_id: None,
        issuer_signature: String::new(),
    };
    let canonical = grant.canonical_json().map_err(|e| format!("canonical_json: {e}"))?;
    grant.issuer_signature = URL_SAFE_NO_PAD.encode(holder_key.sign(canonical.as_bytes()).to_bytes());
    Ok(MembershipGrant { grant, authority: Some(authority) })
}

/// Whether `membership` admits `member` to `root`, on the authority of its `owner`: issued by
/// the owner, or by a holder of the owner's `org.invite` on the same root with that
/// delegation beside it.
pub fn verify_membership(
    membership: &MembershipGrant,
    owner: &str,
    root: &str,
    member: &str,
    now: i64,
) -> Result<(), Refusal> {
    let issuer = membership.grant.issuer_did.to_string();
    let as_member = CapabilityTarget::RootMember { root: root.to_owned() };
    check(&membership.grant, &issuer, member, CapabilityKind::Read, as_member, now)?;
    if issuer == owner {
        return Ok(());
    }
    let authority = membership.authority.as_ref().ok_or(Refusal::NoAuthority)?;
    invite_authority(authority, owner, root, &issuer, now)?;
    // The cap, held where it matters: a grant a revoked holder signs cannot outlive the end
    // the owner put on their authority.
    match (membership.grant.expires_at, authority.expires_at) {
        (Some(ends), Some(bound)) if ends <= bound => Ok(()),
        _ => Err(Refusal::OutlivesAuthority),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_crypto::DidKeyMethod;

    const ROOT: &str = "r0ot";
    const MEMBER: &str = "did:kel:z6MkBobsAid";
    const NOW: i64 = 1_790_000_000;
    /// How long the tests' delegations last.
    const DELEGATION: i64 = 100;

    fn key(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }

    fn did(k: &ed25519_dalek::SigningKey) -> String {
        DidKeyMethod::from_public_key(&k.verifying_key()).to_string()
    }

    /// An envelope from `issuer` to `subject` carrying `grants`, signed by `issuer`.
    fn signed(issuer: &ed25519_dalek::SigningKey, subject: &str, grants: Vec<CapabilityGrant>) -> GrantEnvelope {
        let mut e = GrantEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            issuer_did: Did::parse(&did(issuer)).unwrap(),
            subject_did: Did::parse(subject).unwrap(),
            node_did: None,
            grants,
            issued_at: NOW,
            expires_at: Some(NOW + DELEGATION),
            app_id: None,
            issuer_signature: String::new(),
        };
        let c = e.canonical_json().unwrap();
        e.issuer_signature = URL_SAFE_NO_PAD.encode(issuer.sign(c.as_bytes()).to_bytes());
        e
    }

    /// Re-sign `e` after a test changed it, as its issuer would.
    fn resign(issuer: &ed25519_dalek::SigningKey, mut e: GrantEnvelope) -> GrantEnvelope {
        let c = e.canonical_json().unwrap();
        e.issuer_signature = URL_SAFE_NO_PAD.encode(issuer.sign(c.as_bytes()).to_bytes());
        e
    }

    /// **A membership grant ends when the delegation it was issued under does** — so a holder
    /// whose delegation is revoked, and who keeps their key and their envelope, can mint
    /// nothing a verifier elsewhere believes past the end the owner set. The grant asked for a
    /// year and is capped to the delegation's hundred seconds; past them, it verifies as nothing;
    /// and one forged to claim the year back is refused even before then.
    #[test]
    fn a_membership_grant_ends_when_its_delegation_does() {
        let (org, alice) = (key(1), key(2));
        let delegation = signed(&org, &did(&alice), vec![CapabilityGrant::org_invite(ROOT)]);
        let year = GrantLifetime::Seconds(365 * 24 * 3600);
        let m = issue_membership(&alice, delegation.clone(), ROOT, MEMBER, year, NOW).unwrap();
        assert_eq!(m.grant.expires_at, delegation.expires_at, "capped to the delegation's end");
        verify_membership(&m, &did(&org), ROOT, MEMBER, NOW + DELEGATION - 1).unwrap();
        assert_ne!(
            verify_membership(&m, &did(&org), ROOT, MEMBER, NOW + DELEGATION),
            Ok(()),
            "a grant outlived its delegation"
        );

        // The revoked holder signs the year back in by hand: refused at once.
        let mut forged = m.grant.clone();
        forged.expires_at = Some(NOW + 365 * 24 * 3600);
        let forged = MembershipGrant { grant: resign(&alice, forged), authority: Some(delegation.clone()) };
        assert_eq!(
            verify_membership(&forged, &did(&org), ROOT, MEMBER, NOW),
            Err(Refusal::OutlivesAuthority)
        );
        // …and so is one with no end at all.
        let mut endless = m.grant.clone();
        endless.expires_at = None;
        let endless = MembershipGrant { grant: resign(&alice, endless), authority: Some(delegation.clone()) };
        assert_eq!(verify_membership(&endless, &did(&org), ROOT, MEMBER, NOW), Err(Refusal::OutlivesAuthority));

        // A delegation with no end is no authority: nothing could ever expire it.
        let mut unbounded = delegation;
        unbounded.expires_at = None;
        let unbounded = resign(&org, unbounded);
        assert_eq!(invite_authority(&unbounded, &did(&org), ROOT, &did(&alice), NOW), Err(Refusal::Unbounded));
    }

    /// **A holder of `org.invite` admits someone, and the grant walks back to the owner** —
    /// and only to the owner, only for that root, and only with the delegation beside it.
    #[test]
    fn a_membership_grant_walks_back_to_the_roots_owner() {
        let (org, alice) = (key(1), key(2));
        let delegation = signed(&org, &did(&alice), vec![CapabilityGrant::org_invite(ROOT)]);
        invite_authority(&delegation, &did(&org), ROOT, &did(&alice), NOW).unwrap();

        let m = issue_membership(&alice, delegation.clone(), ROOT, MEMBER, GrantLifetime::UntilRevoked, NOW)
            .unwrap();
        verify_membership(&m, &did(&org), ROOT, MEMBER, NOW).unwrap();

        // Owned by someone else, for another root, for another member: none of them.
        assert_eq!(verify_membership(&m, &did(&key(3)), ROOT, MEMBER, NOW), Err(Refusal::WrongIssuer));
        assert_eq!(verify_membership(&m, &did(&org), "another", MEMBER, NOW), Err(Refusal::NotGranted));
        assert_eq!(verify_membership(&m, &did(&org), ROOT, "did:kel:z6MkEve", NOW), Err(Refusal::WrongSubject));
        // The delegation is what makes it count.
        let orphan = MembershipGrant { grant: m.grant.clone(), authority: None };
        assert_eq!(verify_membership(&orphan, &did(&org), ROOT, MEMBER, NOW), Err(Refusal::NoAuthority));
    }

    /// **The capability is what counts, never a name.** An envelope from the owner carrying
    /// membership, or a schema grant, is not authority to invite — and one carrying
    /// `org.invite` on another root is not authority on this one.
    #[test]
    fn inviting_takes_the_org_invite_capability_on_this_root() {
        let (org, alice) = (key(1), key(2));
        for grants in [
            vec![CapabilityGrant::root_member(ROOT)],
            vec![CapabilityGrant::org_invite("another")],
            vec![],
        ] {
            let e = signed(&org, &did(&alice), grants);
            assert_eq!(invite_authority(&e, &did(&org), ROOT, &did(&alice), NOW), Err(Refusal::NotGranted));
        }
        // Delegated by someone who is not the owner: nothing.
        let e = signed(&key(4), &did(&alice), vec![CapabilityGrant::org_invite(ROOT)]);
        assert_eq!(invite_authority(&e, &did(&org), ROOT, &did(&alice), NOW), Err(Refusal::WrongIssuer));
        // Tampered after signing: nothing.
        let mut e = signed(&org, &did(&alice), vec![CapabilityGrant::org_invite("another")]);
        e.grants = vec![CapabilityGrant::org_invite(ROOT)];
        assert_eq!(invite_authority(&e, &did(&org), ROOT, &did(&alice), NOW), Err(Refusal::BadSignature));
        // Expired: nothing.
        let mut e = signed(&org, &did(&alice), vec![CapabilityGrant::org_invite(ROOT)]);
        e.expires_at = Some(NOW);
        let e = resign(&org, e);
        assert_eq!(invite_authority(&e, &did(&org), ROOT, &did(&alice), NOW), Err(Refusal::Expired));
    }
}
