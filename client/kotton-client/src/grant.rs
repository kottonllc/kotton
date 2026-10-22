// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `grant` domain — who the user accepts authority from, and what an app
//! may reach.
//!
//! Reached through [`KottonClient::grant`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut grant = client.grant("did:key:…");
//! let anchors = grant.trust_list().await?;
//! # let _ = anchors;
//! # Ok(())
//! # }
//! ```
//!
//! Two things live here because they answer one question — what may act on this
//! user's data. The trust registry names the org DIDs whose grant envelopes the
//! user will honour at all; the schema grants say what a given app may read,
//! write or register once admitted. Splitting them would put the gate and the
//! aperture in different domains.
//!
//! The domain name is RFC-0054's;
//! grouping the verbs under it is RFC-0055.

use std::io;

use super::{KottonClient, SchemaGrantEntry, UserRequest, UserResponse};

/// The `grant` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Grant<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `grant` domain for a user.
    ///
    /// The trust verbs name the user on the wire. The schema-grant verbs name an
    /// app and carry no `user_id`; the daemon takes the user from the
    /// authenticated session (`agent/dispatch.rs`). See the note on
    /// [`crate::Record`] — the asymmetry is the protocol's.
    pub fn grant(&mut self, user_id: &str) -> Grant<'_> {
        Grant {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Grant<'_> {
    /// Trust an org's DID as a grant issuer. See [`KottonClient::trust_add`].
    pub async fn trust_add(&mut self, org_did: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.trust_add(&u, org_did).await
    }

    /// Stop trusting an org's DID. See [`KottonClient::trust_remove`].
    pub async fn trust_remove(&mut self, org_did: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.trust_remove(&u, org_did).await
    }

    /// Every trusted issuer. See [`KottonClient::trust_list`].
    pub async fn trust_list(&mut self) -> io::Result<Vec<String>> {
        let u = self.user_id.clone();
        self.client.trust_list(&u).await
    }

    /// Revoke a grant envelope. See [`KottonClient::grant_revoke`].
    pub async fn revoke(&mut self, envelope_id: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.grant_revoke(&u, envelope_id).await
    }

    /// Import a grant envelope. See [`KottonClient::grant_import`].
    pub async fn import(&mut self, envelope_json: &str) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.grant_import(&u, envelope_json).await
    }

    /// What an app may reach, per schema. See [`KottonClient::schema_grant_list`].
    pub async fn schema_grants(&mut self, app_id: &str) -> io::Result<Vec<SchemaGrantEntry>> {
        self.client.schema_grant_list(app_id).await
    }

    /// Set what an app may do with a schema. See [`KottonClient::schema_grant_set`].
    pub async fn set_schema(
        &mut self,
        app_id: &str,
        nsid: &str,
        can_read: bool,
        can_write: bool,
        can_register: bool,
    ) -> io::Result<()> {
        self.client
            .schema_grant_set(app_id, nsid, can_read, can_write, can_register)
            .await
    }

    /// Withdraw an app's access to a schema. See [`KottonClient::schema_grant_revoke`].
    pub async fn revoke_schema(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        self.client.schema_grant_revoke(app_id, nsid).await
    }

    /// Bound how much an app may store under a schema. See [`KottonClient::schema_quota_set`].
    pub async fn set_schema_quota(
        &mut self,
        app_id: &str,
        nsid: &str,
        record_quota: i64,
        byte_quota: i64,
    ) -> io::Result<()> {
        self.client
            .schema_quota_set(app_id, nsid, record_quota, byte_quota)
            .await
    }
}

impl KottonClient {
    // -- Trust registry -------------------------------------------------------

    /// Add an org DID to the trusted-issuer registry.
    ///
    /// After this call the daemon will accept `GrantEnvelope`s whose
    /// `issuer_did` matches `org_did` (subject to signature verification).
    pub async fn trust_add(&mut self, user_id: &str, org_did: &str) -> io::Result<()> {
        match self
            .client
            .send(&UserRequest::TrustAdd {
                user_id: user_id.to_string(),
                org_did: org_did.to_string(),
            })
            .await?
        {
            UserResponse::TrustAdded => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Remove an org DID from the trusted-issuer registry.
    pub async fn trust_remove(&mut self, user_id: &str, org_did: &str) -> io::Result<()> {
        match self
            .client
            .send(&UserRequest::TrustRemove {
                user_id: user_id.to_string(),
                org_did: org_did.to_string(),
            })
            .await?
        {
            UserResponse::TrustRemoved => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List all trusted-issuer DIDs for `user_id`.
    pub async fn trust_list(&mut self, user_id: &str) -> io::Result<Vec<String>> {
        match self
            .client
            .send(&UserRequest::TrustList {
                user_id: user_id.to_string(),
            })
            .await?
        {
            UserResponse::TrustedIssuers { dids } => Ok(dids),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    // -- Grant management -----------------------------------------------------

    /// Add `envelope_id` to the local revocation list.
    pub async fn grant_revoke(&mut self, user_id: &str, envelope_id: &str) -> io::Result<()> {
        match self
            .client
            .send(&UserRequest::GrantRevoke {
                user_id: user_id.to_string(),
                envelope_id: envelope_id.to_string(),
            })
            .await?
        {
            UserResponse::GrantRevoked => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Import a cross-DID `GrantEnvelope` (full JSON string).
    ///
    /// The daemon verifies the issuer is trusted and the signature is valid
    /// before storing. Returns the stored envelope's ID on success.
    pub async fn grant_import(
        &mut self,
        user_id: &str,
        envelope_json: &str,
    ) -> io::Result<String> {
        match self
            .client
            .send(&UserRequest::GrantImport {
                user_id: user_id.to_string(),
                envelope_json: envelope_json.to_string(),
            })
            .await?
        {
            UserResponse::GrantImported { envelope_id } => Ok(envelope_id),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
