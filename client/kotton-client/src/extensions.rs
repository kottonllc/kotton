// SPDX-License-Identifier: AGPL-3.0-or-later
//! Client calls for confined extensions (RFC-0049 / RFC-0050).

use std::io;

use kotton_wire::ipc::InstalledExtension;
use kotton_wire::{UserRequest, UserResponse};

use crate::KottonClient;

/// What the daemon decided about a package it just installed.
#[derive(Debug, Clone)]
pub struct InstallOutcome {
    pub extension_id: String,
    pub name: String,
    pub class: String,
    pub content_hash: String,
    /// `false` when the package carried no publisher signature.
    pub signed: bool,
    /// The consent lines the daemon itself produced. Clients display **these**
    /// rather than composing their own, so no surface can show a softer
    /// summary than the one that was enforced.
    pub consent_summary: Vec<String>,
}

impl KottonClient {
    /// Install a confined extension from an already-obtained package.
    ///
    /// The daemon computes the content hash from the bytes, verifies any
    /// publisher signature against it, parses every declared endpoint, and
    /// mints capabilities derived from the extension's class.
    pub async fn extension_install(
        &mut self,
        user_id: &str,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
    ) -> io::Result<InstallOutcome> {
        let request = UserRequest::ExtensionInstall {
            user_id: user_id.to_string(),
            manifest_toml,
            wasm_bytes,
        };
        match self.client.send(&request).await? {
            UserResponse::ExtensionInstalled {
                extension_id,
                name,
                class,
                content_hash,
                signed,
                consent_summary,
            } => Ok(InstallOutcome {
                extension_id,
                name,
                class,
                content_hash,
                signed,
                consent_summary,
            }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    pub async fn extension_list(&mut self, user_id: &str) -> io::Result<Vec<InstalledExtension>> {
        let request = UserRequest::ExtensionList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::ExtensionList { extensions } => Ok(extensions),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Remove an extension and **revoke its grants** — the latter being what
    /// actually removes its authority.
    pub async fn extension_remove(
        &mut self,
        user_id: &str,
        extension_id: &str,
    ) -> io::Result<String> {
        let request = UserRequest::ExtensionRemove {
            user_id: user_id.to_string(),
            extension_id: extension_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::ExtensionRemoved { extension_id } => Ok(extension_id),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
