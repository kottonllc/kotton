// SPDX-License-Identifier: AGPL-3.0-or-later
use clap::Args;
use kotton::KottonClient;
use std::io;

/// Authenticate a user and cache a session token.
///
/// Run this once after `kotton user create <name>` — or any time the daemon
/// restarts and invalidates the previous token.  Subsequent `kotton repl`
/// and GUI launches (`just shell`) will authenticate silently from the cache.
#[derive(Args)]
pub struct LoginCommand {
    /// The identity to authenticate as
    pub user_id: String,
}

impl LoginCommand {
    pub async fn execute(self) -> io::Result<()> {
        // connect_as handles the full flow: try the cached token → the PIN, if
        // this identity has one → the recovery phrase → save the new token.
        let _ = KottonClient::connect_as(&self.user_id).await?;
        println!("✓ Logged in as '{}' — session token cached", self.user_id);
        Ok(())
    }
}
