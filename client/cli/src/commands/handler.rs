// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton handler` subcommands — schema handler registration.
//!
//! ```text
//! kotton handler register <app-id> <nsid>     [--user <id>]
//! kotton handler unregister <app-id> <nsid>   [--user <id>]
//! kotton handler get <nsid>                   [--user <id>]
//! kotton handler list                         [--user <id>]
//! kotton handler set-default <app-id> <nsid>  [--user <id>]
//! ```
//!
//! The registry is per person, so every verb acts as someone: `--user`, else `KOTTON_USER`,
//! else the active identity.

use clap::Subcommand;
use kotton::KottonClient;
use std::io;

#[derive(Subcommand)]
pub enum HandlerCommand {
    /// Register an app as a handler for a schema NSID
    Register {
        /// App identifier, e.g. `com.acme.notes-pro`
        app_id: String,
        /// Schema NSID this app can render, e.g. `sh.kotton.notes`
        nsid: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Unregister an app as a handler for a schema NSID
    Unregister {
        /// App identifier
        app_id: String,
        /// Schema NSID
        nsid: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Print the default handler for a schema NSID
    Get {
        /// Schema NSID to look up, e.g. `sh.kotton.notes`
        nsid: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// List all registered handlers
    List {
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Override the default handler for a schema NSID
    SetDefault {
        /// App identifier to make the default
        app_id: String,
        /// Schema NSID
        nsid: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
}

impl HandlerCommand {
    fn user(&self) -> &str {
        match self {
            HandlerCommand::Register { user, .. }
            | HandlerCommand::Unregister { user, .. }
            | HandlerCommand::Get { user, .. }
            | HandlerCommand::List { user }
            | HandlerCommand::SetDefault { user, .. } => user,
        }
    }

    pub async fn execute(&self) -> io::Result<()> {
        // The registry is a person's — which app opens *their* records — and the daemon reads
        // it from the store of whoever this connection authenticated as, so it must be them.
        let mut client = KottonClient::connect_as(self.user()).await?;

        match self {
            HandlerCommand::Register { app_id, nsid, .. } => {
                client.handler_register(app_id, nsid).await?;
                println!("✓ Registered '{}' as handler for '{}'.", app_id, nsid);
            }

            HandlerCommand::Unregister { app_id, nsid, .. } => {
                client.handler_unregister(app_id, nsid).await?;
                println!("✓ Unregistered '{}' from '{}'.", app_id, nsid);
            }

            HandlerCommand::Get { nsid, .. } => match client.handler_get_for(nsid).await {
                Ok(entry) => {
                    println!("Default handler for '{}':", nsid);
                    println!("  app_id:  {}", entry.app_id);
                    println!("  default: {}", entry.is_default);
                }
                Err(e) => {
                    eprintln!("No handler registered for '{}': {}", nsid, e);
                    return Err(e);
                }
            },

            HandlerCommand::List { .. } => {
                let entries = client.handler_list().await?;
                if entries.is_empty() {
                    println!("No handlers registered.");
                } else {
                    println!("{:<40} {:<8} APP", "NSID", "DEFAULT");
                    println!("{}", "-".repeat(72));
                    for e in &entries {
                        println!(
                            "{:<40} {:<8} {}",
                            e.nsid,
                            if e.is_default { "yes" } else { "no" },
                            e.app_id
                        );
                    }
                }
            }

            HandlerCommand::SetDefault { app_id, nsid, .. } => {
                client.handler_set_default(app_id, nsid).await?;
                println!("✓ '{}' is now the default handler for '{}'.", app_id, nsid);
            }
        }

        Ok(())
    }
}
