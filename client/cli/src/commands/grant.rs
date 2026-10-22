// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton grant` — grant management sub-commands.
//!
//! ```text
//! kotton grant revoke <envelope_id>         [--user <id>]
//! kotton grant import <path>                [--user <id>]
//! kotton grant import --stdin               [--user <id>]
//! ```

use clap::Subcommand;
use kotton::KottonClient;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GrantCommand {
    /// Add an envelope ID to the local revocation list.
    ///
    /// Any IPC calls from apps whose `GrantEnvelope` matches this ID will be
    /// denied after this point. Revocation is immediately effective and
    /// irreversible on this device.
    Revoke {
        /// The UUID from `GrantEnvelope.id` to revoke.
        envelope_id: String,
        /// User ID to act on.
        #[arg(long)]
        user: String,
    },
    /// Import a cross-DID `GrantEnvelope` issued by an org.
    ///
    /// The envelope must be a JSON file. Pass `--stdin` to read from stdin
    /// instead of a file path. The daemon verifies the issuer is in the
    /// trusted-issuer registry and that the signature is valid before storing.
    Import {
        /// Path to the JSON file containing the `GrantEnvelope`.
        ///
        /// Omit (or use `-`) to read from stdin.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        /// Read the envelope JSON from stdin instead of a file.
        #[arg(long, conflicts_with = "path")]
        stdin: bool,
        /// User ID to act on.
        #[arg(long)]
        user: String,
    },
}

impl GrantCommand {
    fn user(&self) -> &str {
        match self {
            GrantCommand::Revoke { user, .. } | GrantCommand::Import { user, .. } => user,
        }
    }

    pub async fn execute(&self) -> io::Result<()> {
        // Both verbs act as `--user`: the revocation list and the imported envelopes are that
        // person's, and the daemon answers neither on a connection that has not authenticated
        // as them.
        let mut client = KottonClient::connect_as(self.user()).await?;

        match self {
            GrantCommand::Revoke { envelope_id, user } => {
                client.grant_revoke(user, envelope_id).await?;
                println!("✓ Revoked: {envelope_id}");
                Ok(())
            }
            GrantCommand::Import { path, stdin, user } => {
                let json = if *stdin || path.as_deref().map(|p| p == std::path::Path::new("-")).unwrap_or(false) {
                    let mut buf = String::new();
                    io::stdin().read_to_string(&mut buf)?;
                    buf
                } else {
                    match path {
                        Some(p) => std::fs::read_to_string(p)?,
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "provide a path or use --stdin",
                            ));
                        }
                    }
                };

                let envelope_id = client.grant_import(user, &json).await?;
                println!("✓ Imported envelope: {envelope_id}");
                Ok(())
            }
        }
    }
}
