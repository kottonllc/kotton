// SPDX-License-Identifier: AGPL-3.0-or-later
//! The vault's operator credentials, as the vault keeps them: each enrolled by its public
//! half and revoked (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`).
//!
//! **A set, not one** (`TASK-a-device-has-operators-not-an-operator`). Each
//! operator holds their own credential — minted in their own desktop's store
//! by `mint vault` (DEC-0083) — and enrolling one leaves the others, so
//! handing the vault on is enrol-then-revoke and not a ceremony of its own.
//! Revoking names the key it ends. What each key said over the wire is kept
//! under that key (`operator_acts`, `crate::peer::handle`), so an act is
//! answerable to the operator who took it and never to "the operator".
//!
//! **The set is never emptied** (RFC-0084 V19, fork 3, the owner's ruling of
//! 2026-10-01). A vault is created for its first operator's key and does not
//! start without one, so a door that could revoke the last would make a running
//! vault nobody operates — unowned until it stops, and refusing to start after.
//! Revoking names one key and refuses the last; *every one but* names the key
//! that stays. A leaked credential is replaced by enrolling the new key and
//! then revoking the rest.
//!
//! The credential is a key a landlord's desktop holds, minted there; the vault
//! keeps only the public half, as a row in its machine db (`operator_key`),
//! and admits it at the peer listener's handshake
//! by putting it in the allowlist every paired key is in. What it may say once
//! admitted is not decided here: it is its standing, `PeerStanding::Operator`,
//! and the table in `peer::reaches` gives that standing the landlord's four
//! verbs and nothing a tenant's standing reaches.
//!
//! **Both acts write the row and the allowlist in one step.** Revoking deletes
//! the row — so the next frame on a connection already open is refused by
//! standing, which is read per request — and takes the key out of the
//! allowlist, so the next dial is refused at the handshake. A TLS session
//! resumed after that is
//! `TASK-a-resumed-tls-session-may-skip-the-allowlist-a-revocation-emptied`.
//!
//! Only the landlord's door calls these (`VaultRequest::OperatorAdmit`,
//! `OperatorRevoke`), which no key on the peer transport can name.

use crate::peer::PeerContext;
use std::io;

/// Read a public key as the door takes it: 64 hex characters naming a point
/// on the curve — the `key=` line of the credential file.
pub fn parse_key(key: &str) -> io::Result<[u8; 32]> {
    let bytes: [u8; 32] = hex::decode(key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| io::Error::other("an operator key is 64 hex characters — the key= line"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| io::Error::other("that is not an ed25519 public key"))?;
    Ok(bytes)
}

/// Add `key` to this vault's operator credentials: the row, then the
/// allowlist. Every other operator's key stays enrolled.
pub async fn admit(ctx: &PeerContext, key: &str) -> io::Result<()> {
    let key = parse_key(key)?;
    let new = kotton_peer::daemon::db::enrol_operator_key(&ctx.db, &key).await?;
    ctx.runtime.paired_keys().write().unwrap().insert(key);
    tracing::info!(key = %hex::encode(key), new, "an operator credential is enrolled");
    Ok(())
}

/// The sentence a revocation of the last operator reads.
pub const LAST_OPERATOR: &str = "that is this vault's last operator, and a vault is never left with none: \
     enrol the key that replaces it (`kvaultd operator enrol <key>`), then revoke this one";

/// Revoke one operator credential: the row goes, and the key leaves the
/// allowlist in the same step. Naming a key that is not enrolled is refused, so
/// a typo cannot read as a revocation, and so is naming the last.
pub async fn revoke(ctx: &PeerContext, key: &str) -> io::Result<()> {
    use kotton_peer::daemon::db::Revoked;
    let key = parse_key(key)?;
    match kotton_peer::daemon::db::revoke_operator_key(&ctx.db, &key).await? {
        Revoked::Gone => {}
        Revoked::NotEnrolled => return Err(io::Error::other("that key is not one of this vault's operators")),
        Revoked::Last => return Err(io::Error::other(LAST_OPERATOR)),
    }
    unadmit(ctx, &[key]).await;
    tracing::info!(key = %hex::encode(key), "an operator credential is revoked");
    Ok(())
}

/// Revoke every operator credential but `keep`, which must be enrolled.
/// Returns how many were revoked.
pub async fn revoke_all_but(ctx: &PeerContext, keep: &str) -> io::Result<usize> {
    let keep = parse_key(keep)?;
    let Some(revoked) = kotton_peer::daemon::db::revoke_operator_keys_but(&ctx.db, &keep).await? else {
        return Err(io::Error::other(
            "the key to keep is not one of this vault's operators, so nothing is revoked: \
             a vault is never left with none",
        ));
    };
    unadmit(ctx, &revoked).await;
    tracing::info!(revoked = revoked.len(), "operator credentials are revoked, one kept");
    Ok(revoked.len())
}

/// Take `keys` out of the handshake's allowlist — each one that is not also a
/// tenant's paired device, whose own row still admits it.
async fn unadmit(ctx: &PeerContext, keys: &[[u8; 32]]) {
    for key in keys {
        let paired = kotton_peer::daemon::db::paired_users_for_pubkey(&ctx.db, key)
            .await
            .is_ok_and(|pools| !pools.is_empty());
        if !paired {
            ctx.runtime.paired_keys().write().unwrap().remove(key);
        }
    }
}
