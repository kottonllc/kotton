// SPDX-License-Identifier: AGPL-3.0-or-later
use std::io;

use super::{HandlerEntry, KottonClient, SchemaGrantEntry, UserRequest, UserResponse};

impl KottonClient {
    // -- Schema registry (M16 v0.4) ------------------------------------------

    /// List the schema NSIDs visible to `user_id`: core plus their own
    /// registrations.
    pub async fn schema_list(&mut self, user_id: &str) -> io::Result<Vec<String>> {
        let request = UserRequest::SchemaList {
            user_id: user_id.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::SchemaList { schemas } => Ok(schemas),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Register an app-supplied schema as `user_id`.
    ///
    /// `definition_json` must be a JSON-encoded `SchemaDefinition`.
    pub async fn schema_register(
        &mut self,
        user_id: &str,
        definition_json: &str,
    ) -> io::Result<()> {
        let request = UserRequest::SchemaRegister {
            user_id: user_id.to_owned(),
            definition_json: definition_json.to_owned(),
            app_id: None,
        };
        match self.client.send(&request).await? {
            UserResponse::SchemaRegistered => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Retrieve the full JSON definition of a schema visible to `user_id`.
    ///
    /// Returns a pretty-printed JSON string, or an error if the NSID is not
    /// registered for this user on this device.
    pub async fn schema_get(&mut self, user_id: &str, nsid: &str) -> io::Result<String> {
        let request = UserRequest::SchemaGet {
            user_id: user_id.to_owned(),
            nsid: nsid.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::SchemaGetResult { definition_json } => Ok(definition_json),
            UserResponse::SchemaNotFound { nsid } => {
                Err(io::Error::other(format!("schema not found: {nsid}")))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    // -- Handler registry ----------------------------------------------------

    /// Register `app_id` as a handler for schema `nsid`.
    ///
    /// The first handler registered for an NSID becomes the default
    /// automatically. Subsequent registrations for the same `(app_id, nsid)`
    /// pair are idempotent.
    pub async fn handler_register(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        let request = UserRequest::RegisterHandler {
            app_id: app_id.to_owned(),
            nsid: nsid.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::HandlerRegistered => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Unregister `app_id` as a handler for schema `nsid`.
    pub async fn handler_unregister(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        let request = UserRequest::UnregisterHandler {
            app_id: app_id.to_owned(),
            nsid: nsid.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::HandlerUnregistered => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the default handler for `nsid`.
    ///
    /// Returns an error if no handler is registered for the NSID.
    pub async fn handler_get_for(&mut self, nsid: &str) -> io::Result<HandlerEntry> {
        let request = UserRequest::GetHandlerFor {
            nsid: nsid.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::HandlerInfo { entry } => Ok(entry),
            UserResponse::HandlerNotFound { nsid } => Err(io::Error::other(format!(
                "no handler registered for '{nsid}'"
            ))),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return all registered handlers.
    pub async fn handler_list(&mut self) -> io::Result<Vec<HandlerEntry>> {
        match self.client.send(&UserRequest::ListHandlers).await? {
            UserResponse::HandlerList { entries } => Ok(entries),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Set `app_id` as the default handler for `nsid`.
    ///
    /// `app_id` must already be registered for `nsid` via `handler_register`.
    pub async fn handler_set_default(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        let request = UserRequest::SetDefaultHandler {
            app_id: app_id.to_owned(),
            nsid: nsid.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::DefaultHandlerSet => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    // -- Schema grant management (RFC-0003) -----------------------------------

    /// List all schema access grants for `app_id`.
    pub async fn schema_grant_list(&mut self, app_id: &str) -> io::Result<Vec<SchemaGrantEntry>> {
        let request = UserRequest::SchemaGrantList {
            app_id: app_id.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::SchemaGrantListResult { grants } => Ok(grants),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Create or update a schema access grant for `(app_id, nsid)`.
    pub async fn schema_grant_set(
        &mut self,
        app_id: &str,
        nsid: &str,
        can_read: bool,
        can_write: bool,
        can_register: bool,
    ) -> io::Result<()> {
        let request = UserRequest::SchemaGrantSet {
            app_id: app_id.to_owned(),
            nsid: nsid.to_owned(),
            can_read,
            can_write,
            can_register,
        };
        match self.client.send(&request).await? {
            UserResponse::SchemaGrantUpdated => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Remove all schema access grants for `(app_id, nsid)`.
    ///
    /// After revocation the app will receive `permission denied` on any
    /// record operation for that NSID.
    pub async fn schema_grant_revoke(&mut self, app_id: &str, nsid: &str) -> io::Result<()> {
        let request = UserRequest::SchemaGrantRevoke {
            app_id: app_id.to_owned(),
            nsid: nsid.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::SchemaGrantRevoked => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Override the write quota limits for `(app_id, nsid)`.
    ///
    /// `record_quota = 0` removes the record count limit.
    /// `byte_quota = 0` removes the byte limit.
    pub async fn schema_quota_set(
        &mut self,
        app_id: &str,
        nsid: &str,
        record_quota: i64,
        byte_quota: i64,
    ) -> io::Result<()> {
        let request = UserRequest::SchemaQuotaSet {
            app_id: app_id.to_owned(),
            nsid: nsid.to_owned(),
            record_quota,
            byte_quota,
        };
        match self.client.send(&request).await? {
            UserResponse::SchemaQuotaUpdated => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
