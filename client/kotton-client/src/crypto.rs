// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `crypto` domain — the health of a user's keys, and moving them forward.
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut crypto = client.crypto("did:key:…");
//! let health = crypto.key_health().await?;
//! # let _ = health;
//! # Ok(())
//! # }
//! ```
//!
//! Two verbs, and both are about the algorithms rather than the key material:
//! nothing here returns a key. Migration exists because the post-quantum answer
//! is not settled, and a platform that cannot move algorithms has decided to
//! stay on today's.

use std::io;

use super::{UserRequest, UserResponse, KeyHealth, KottonClient};

impl KottonClient {
    // -- Crypto health (M26h) ------------------------------------------------

    /// Return key health metadata for `user_id` (algorithm, version,
    /// rotation status, and per-layer recovery coverage).
    pub async fn get_key_health(&mut self, user_id: &str) -> io::Result<KeyHealth> {
        let request = UserRequest::GetKeyHealth {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::KeyHealthInfo(health) => Ok(health),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

}

/// The `crypto` domain, bound to one user.
pub struct Crypto<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `crypto` domain for a user.
    pub fn crypto(&mut self, user_id: &str) -> Crypto<'_> {
        Crypto { client: self, user_id: user_id.to_string() }
    }
}

impl Crypto<'_> {
    /// How healthy this user's keys are. See [`KottonClient::get_key_health`].
    pub async fn key_health(&mut self) -> io::Result<KeyHealth> {
        let u = self.user_id.clone();
        self.client.get_key_health(&u).await
    }

}
