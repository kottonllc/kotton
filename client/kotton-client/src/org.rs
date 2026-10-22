// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `org` domain — shared authority: a household, a team, a company.
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut org = client.org("did:key:…");
//! let orgs = org.list().await?;
//! # let _ = orgs;
//! # Ok(())
//! # }
//! ```
//!
//! Two shapes of org live behind one handle. A plain org has a single signing
//! key; a FROST org splits it across `threshold`-of-`total` holders, so no one
//! device can act for the org alone. Both issue the same grant envelopes, which
//! is why they belong to one domain rather than two -- the difference is how a
//! signature is produced, not what authority means.
//!
//! The multi-step `sign_begin` / `sign_contribute` / `sign_finalize` sequence is
//! the FROST ceremony, and its shape is the protocol's: a threshold signature
//! needs a round trip to each cosigner.
//!
//! The domain name is RFC-0054's;
//! grouping the verbs under it is RFC-0055.

use std::io;

use super::{UserRequest, UserResponse, KottonClient};
pub use kotton_wire::ipc::{OrgEntry, OrgGrantEntry};

impl KottonClient {
    // -- Org identity ---------------------------------------------------------

    /// Create a new single-key org identity.
    ///
    /// Returns `(org_did, name)` on success.
    pub async fn org_new(&mut self, user_id: &str, name: &str) -> io::Result<String> {
        match self
            .client
            .send(&UserRequest::OrgNew {
                user_id: user_id.to_string(),
                name: name.to_string(),
            })
            .await?
        {
            UserResponse::OrgCreated { org_did } => Ok(org_did),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return metadata for an org DID.
    ///
    /// Returns `(org_did, name, owner_did, created_at)` or `None` if not found.
    pub async fn org_show(
        &mut self,
        user_id: &str,
        org_did: &str,
    ) -> io::Result<(String, String, String, i64)> {
        match self
            .client
            .send(&UserRequest::OrgShow {
                user_id: user_id.to_string(),
                org_did: org_did.to_string(),
            })
            .await?
        {
            UserResponse::OrgInfo {
                org_did,
                name,
                owner_did,
                created_at,
            } => Ok((org_did, name, owner_did, created_at)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List all org identities owned by `user_id`.
    pub async fn org_list(&mut self, user_id: &str) -> io::Result<Vec<OrgEntry>> {
        match self
            .client
            .send(&UserRequest::OrgList {
                user_id: user_id.to_string(),
            })
            .await?
        {
            UserResponse::OrgList { orgs } => Ok(orgs),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Issue a `GrantEnvelope` from `org_did` to `member_did`.
    ///
    /// Returns `(envelope_id, envelope_json)`. Deliver `envelope_json` to the
    /// member out-of-band so they can `kotton grant import` it.
    pub async fn org_grant_issue(
        &mut self,
        user_id: &str,
        org_did: &str,
        member_did: &str,
        caps: Vec<String>,
        ttl_secs: Option<i64>,
        node_did: Option<String>,
    ) -> io::Result<(String, String)> {
        match self
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
            } => Ok((envelope_id, envelope_json)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List all grants issued by `org_did`.
    pub async fn org_grant_list(
        &mut self,
        user_id: &str,
        org_did: &str,
    ) -> io::Result<Vec<OrgGrantEntry>> {
        match self
            .client
            .send(&UserRequest::OrgGrantList {
                user_id: user_id.to_string(),
                org_did: org_did.to_string(),
            })
            .await?
        {
            UserResponse::OrgGrantList { grants } => Ok(grants),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Revoke all outstanding envelopes issued by `org_did` to `member_did`.
    ///
    /// Returns the number of envelopes that were revoked.
    pub async fn org_member_remove(
        &mut self,
        user_id: &str,
        org_did: &str,
        member_did: &str,
    ) -> io::Result<u32> {
        match self
            .client
            .send(&UserRequest::OrgMemberRemove {
                user_id: user_id.to_string(),
                org_did: org_did.to_string(),
                member_did: member_did.to_string(),
            })
            .await?
        {
            UserResponse::OrgMemberRemoved { revoked_count } => Ok(revoked_count),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

// Moved from network.rs: a threshold signature is an org act, not a network one.
impl KottonClient {
    /// Coordinate a distributed FROST threshold signature over `message` across
    /// this node's own network (RFC-0036): this node signs with its share and
    /// co-signs with every Full own-device member over the peer channel. Returns
    /// the aggregate 64-byte Ed25519 signature, verifiable under the group DID.
    pub async fn threshold_sign(&mut self, user_id: &str, message: &[u8]) -> io::Result<Vec<u8>> {
        let request = UserRequest::ThresholdSign {
            user_id: user_id.to_string(),
            message_hex: hex::encode(message),
        };
        match self.client.send(&request).await? {
            UserResponse::ThresholdSigned { signature_hex } => hex::decode(&signature_hex)
                .map_err(|e| io::Error::other(format!("bad sig hex: {e}"))),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// The `org` domain, bound to one user — the member acting, not the org acted on.
pub struct Org<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `org` domain for a user.
    pub fn org(&mut self, user_id: &str) -> Org<'_> {
        Org { client: self, user_id: user_id.to_string() }
    }
}

impl Org<'_> {
    /// Create an org. See [`KottonClient::org_new`].
    pub async fn create(&mut self, name: &str) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.org_new(&u, name).await
    }

    /// Describe an org. See [`KottonClient::org_show`].
    pub async fn show(&mut self, org_did: &str) -> io::Result<(String, String, String, i64)> {
        let u = self.user_id.clone();
        self.client.org_show(&u, org_did).await
    }

    /// Every org this user belongs to. See [`KottonClient::org_list`].
    pub async fn list(&mut self) -> io::Result<Vec<OrgEntry>> {
        let u = self.user_id.clone();
        self.client.org_list(&u).await
    }

    /// Issue a grant on the org's authority. See [`KottonClient::org_grant_issue`].
    pub async fn issue_grant(
        &mut self,
        org_did: &str,
        member_did: &str,
        caps: Vec<String>,
        ttl_secs: Option<i64>,
        node_did: Option<String>,
    ) -> io::Result<(String, String)> {
        let u = self.user_id.clone();
        self.client.org_grant_issue(&u, org_did, member_did, caps, ttl_secs, node_did).await
    }

    /// Grants the org has issued. See [`KottonClient::org_grant_list`].
    pub async fn grants(&mut self, org_did: &str) -> io::Result<Vec<OrgGrantEntry>> {
        let u = self.user_id.clone();
        self.client.org_grant_list(&u, org_did).await
    }

    /// Remove a member, revoking what they held. See [`KottonClient::org_member_remove`].
    pub async fn remove_member(&mut self, org_did: &str, member_did: &str) -> io::Result<u32> {
        let u = self.user_id.clone();
        self.client.org_member_remove(&u, org_did, member_did).await
    }

    /// Sign as the org. See [`KottonClient::threshold_sign`].
    pub async fn sign(&mut self, message: &[u8]) -> io::Result<Vec<u8>> {
        let u = self.user_id.clone();
        self.client.threshold_sign(&u, message).await
    }

    // -- FROST: authority split across holders --------------------------------

    /// Create a FROST org, splitting the key `threshold`-of-`total`.
    /// See [`KottonClient::org_frost_new`].
    pub async fn frost_create(
        &mut self,
        name: &str,
        threshold: u16,
        total: u16,
    ) -> io::Result<(String, Vec<(u16, String)>)> {
        let u = self.user_id.clone();
        self.client.org_frost_new(&u, name, threshold, total).await
    }

    /// Join a FROST org with your share. See [`KottonClient::org_frost_join`].
    pub async fn frost_join(
        &mut self,
        name: &str,
        org_did: &str,
        share_hex: &str,
        participant_idx: u16,
    ) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.org_frost_join(&u, name, org_did, share_hex, participant_idx).await
    }

    /// Open a threshold signing session. See [`KottonClient::org_frost_sign_begin`].
    pub async fn frost_sign_begin(
        &mut self,
        org_did: &str,
        member_did: &str,
        caps: Vec<String>,
        ttl_secs: Option<i64>,
        node_did: Option<String>,
    ) -> io::Result<(String, String, String, String)> {
        let u = self.user_id.clone();
        self.client.org_frost_sign_begin(&u, org_did, member_did, caps, ttl_secs, node_did).await
    }

    /// Add this holder's share to a session.
    /// See [`KottonClient::org_frost_sign_contribute`].
    pub async fn frost_sign_contribute(
        &mut self,
        session_id: &str,
        org_did: &str,
        message_hex: &str,
        coordinator_id_hex: &str,
        coordinator_commitment_hex: &str,
    ) -> io::Result<(String, String, String)> {
        let u = self.user_id.clone();
        self.client.org_frost_sign_contribute(
            &u, session_id, org_did, message_hex, coordinator_id_hex, coordinator_commitment_hex,
        ).await
    }

    /// Combine the shares into a signature.
    /// See [`KottonClient::org_frost_sign_finalize`].
    pub async fn frost_sign_finalize(
        &mut self,
        session_id: &str,
        cosigner_id_hex: &str,
        cosigner_commitment_hex: &str,
        cosigner_share_hex: &str,
    ) -> io::Result<(String, String)> {
        let u = self.user_id.clone();
        self.client.org_frost_sign_finalize(
            &u, session_id, cosigner_id_hex, cosigner_commitment_hex, cosigner_share_hex,
        ).await
    }
}
