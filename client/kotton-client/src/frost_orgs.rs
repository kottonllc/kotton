// SPDX-License-Identifier: AGPL-3.0-or-later
//! FROST multi-sig org SDK client methods — Step 10 (identity_model sprint).

use std::io;

use super::{UserRequest, UserResponse, KottonClient};

/// Result of `org_grant_issue` — splits the single-key and FROST paths.
#[derive(Debug)]
pub enum OrgGrantIssueResult {
    /// The org is single-key: grant was issued immediately.
    Issued {
        envelope_id: String,
        envelope_json: String,
    },
    /// The org is FROST-keyed: a signing session was opened.
    ///
    /// The caller must drive the ceremony to completion:
    /// 1. Share `session_id`, `message_hex`, `coordinator_id_hex`, and
    ///    `coordinator_commitment_hex` with a co-signer.
    /// 2. The co-signer calls `org_frost_sign_contribute`.
    /// 3. Call `org_frost_sign_finalize` with the co-signer's output.
    FrostSession {
        session_id: String,
        message_hex: String,
        coordinator_id_hex: String,
        coordinator_commitment_hex: String,
    },
}

impl KottonClient {
    // -- FROST key generation -------------------------------------------------

    /// Create a new FROST multi-sig org using the trusted-dealer path.
    ///
    /// Returns `(org_did, shares)` where `shares` is a list of
    /// `(participant_index, key_package_hex)` for participants 2..=total.
    /// Distribute each share to its participant over a confidential channel.
    /// The initiator's share (index 1) is already stored in the daemon.
    pub async fn org_frost_new(
        &mut self,
        user_id: &str,
        name: &str,
        threshold: u16,
        total: u16,
    ) -> io::Result<(String, Vec<(u16, String)>)> {
        match self
            .client
            .send(&UserRequest::OrgFrostNew {
                user_id: user_id.to_string(),
                name: name.to_string(),
                threshold,
                total,
            })
            .await?
        {
            UserResponse::OrgFrostCreated { org_did, shares } => {
                Ok((org_did, shares.into_iter().map(|(idx, share)| (idx, share.expose().to_owned())).collect()))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Import a FROST key share as a non-initiator participant.
    ///
    /// `share_hex` is the `key_package_hex` blob printed by the initiator.
    /// Returns the org DID on success.
    pub async fn org_frost_join(
        &mut self,
        user_id: &str,
        name: &str,
        org_did: &str,
        share_hex: &str,
        participant_idx: u16,
    ) -> io::Result<String> {
        match self
            .client
            .send(&UserRequest::OrgFrostJoin {
                user_id: user_id.to_string(),
                name: name.to_string(),
                org_did: org_did.to_string(),
                share_hex: kotton_wire::ipc::SecretText::new(share_hex),
                participant_idx,
            })
            .await?
        {
            UserResponse::OrgFrostJoined { org_did } => Ok(org_did),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    // -- FROST signing --------------------------------------------------------

    /// Initiate a FROST signing ceremony for a grant (coordinator — round 1).
    ///
    /// Returns `(session_id, message_hex, coordinator_id_hex, coordinator_commitment_hex)`.
    /// Share these with a co-signer so they can call `org_frost_sign_contribute`.
    pub async fn org_frost_sign_begin(
        &mut self,
        user_id: &str,
        org_did: &str,
        member_did: &str,
        caps: Vec<String>,
        ttl_secs: Option<i64>,
        node_did: Option<String>,
    ) -> io::Result<(String, String, String, String)> {
        match self
            .client
            .send(&UserRequest::OrgFrostSignBegin {
                user_id: user_id.to_string(),
                org_did: org_did.to_string(),
                member_did: member_did.to_string(),
                caps,
                ttl_secs,
                node_did,
            })
            .await?
        {
            UserResponse::OrgFrostSignSession {
                session_id,
                message_hex,
                coordinator_id_hex,
                coordinator_commitment_hex,
            } => Ok((session_id, message_hex, coordinator_id_hex, coordinator_commitment_hex)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Co-signer: run both FROST signing rounds and return the contribution.
    ///
    /// Returns `(cosigner_id_hex, cosigner_commitment_hex, cosigner_share_hex)`.
    /// Send these back to the coordinator so they can call `org_frost_sign_finalize`.
    pub async fn org_frost_sign_contribute(
        &mut self,
        user_id: &str,
        session_id: &str,
        org_did: &str,
        message_hex: &str,
        coordinator_id_hex: &str,
        coordinator_commitment_hex: &str,
    ) -> io::Result<(String, String, String)> {
        match self
            .client
            .send(&UserRequest::OrgFrostSignContribute {
                user_id: user_id.to_string(),
                session_id: session_id.to_string(),
                org_did: org_did.to_string(),
                message_hex: message_hex.to_string(),
                coordinator_id_hex: coordinator_id_hex.to_string(),
                coordinator_commitment_hex: coordinator_commitment_hex.to_string(),
            })
            .await?
        {
            UserResponse::OrgFrostContributed {
                cosigner_id_hex,
                cosigner_commitment_hex,
                cosigner_share_hex,
            } => Ok((cosigner_id_hex, cosigner_commitment_hex, cosigner_share_hex.expose().to_owned())),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Coordinator: aggregate and finalise the FROST signing ceremony.
    ///
    /// Returns `(envelope_id, envelope_json)` — the completed `GrantEnvelope`.
    pub async fn org_frost_sign_finalize(
        &mut self,
        user_id: &str,
        session_id: &str,
        cosigner_id_hex: &str,
        cosigner_commitment_hex: &str,
        cosigner_share_hex: &str,
    ) -> io::Result<(String, String)> {
        match self
            .client
            .send(&UserRequest::OrgFrostSignFinalize {
                user_id: user_id.to_string(),
                session_id: session_id.to_string(),
                cosigner_id_hex: cosigner_id_hex.to_string(),
                cosigner_commitment_hex: cosigner_commitment_hex.to_string(),
                cosigner_share_hex: kotton_wire::ipc::SecretText::new(cosigner_share_hex),
            })
            .await?
        {
            UserResponse::OrgFrostSigned {
                envelope_id,
                envelope_json,
            } => Ok((envelope_id, envelope_json)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// Updated `org_grant_issue` that handles both single-key and FROST orgs.
///
/// Add this as an inherent method on `KottonClient` to replace the existing
/// `org_grant_issue` — or call `org_grant_issue_full` when you need to
/// distinguish the two cases.
pub async fn org_grant_issue_full(
    client: &mut KottonClient,
    user_id: &str,
    org_did: &str,
    member_did: &str,
    caps: Vec<String>,
    ttl_secs: Option<i64>,
    node_did: Option<String>,
) -> io::Result<OrgGrantIssueResult> {
    match client
        .client
        .send(&UserRequest::OrgGrantIssue {
            user_id: user_id.to_string(),
            org_did: org_did.to_string(),
            member_did: member_did.to_string(),
            caps,
            ttl_secs,
            node_did,
        })
        .await?
    {
        UserResponse::OrgGrantIssued {
            envelope_id,
            envelope_json,
        } => Ok(OrgGrantIssueResult::Issued {
            envelope_id,
            envelope_json,
        }),
        UserResponse::OrgFrostSignSession {
            session_id,
            message_hex,
            coordinator_id_hex,
            coordinator_commitment_hex,
        } => Ok(OrgGrantIssueResult::FrostSession {
            session_id,
            message_hex,
            coordinator_id_hex,
            coordinator_commitment_hex,
        }),
        UserResponse::Error { message } => Err(io::Error::other(message)),
        got => Err(crate::protocol::unexpected(got)),
    }
}
