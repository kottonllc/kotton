// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton schema` subcommands — schema inspection and registration.
//!
//! ```text
//! kotton schema list                  [--user <id>]
//! kotton schema show <nsid>           [--user <id>]
//! kotton schema register <file.json>  [--user <id>]
//! ```
//!
//! The schemas a person sees are core plus their own registrations, so every verb acts as
//! someone: `--user`, else `KOTTON_USER`, else the active identity.

use clap::Subcommand;
use kotton::KottonClient;
use std::io;

#[derive(Subcommand)]
pub enum SchemaCommand {
    /// List the schemas visible to you (core + your own registrations)
    List {
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Print field definitions for a schema
    Show {
        /// Schema NSID to inspect, e.g. `sh.kotton.notes`
        nsid: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Register an app schema from a JSON definition file
    Register {
        /// Path to a JSON file containing a `SchemaDefinition`
        file: std::path::PathBuf,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
}

impl SchemaCommand {
    fn user(&self) -> &str {
        match self {
            SchemaCommand::List { user }
            | SchemaCommand::Show { user, .. }
            | SchemaCommand::Register { user, .. } => user,
        }
    }

    pub async fn execute(&self) -> io::Result<()> {
        // The schema verbs are principal-scoped, and the daemon answers none of them on a
        // connection that has not authenticated as that principal.
        let user_id = self.user();
        let mut client = KottonClient::connect_as(user_id).await?;

        match self {
            SchemaCommand::List { .. } => {
                let schemas = client.schema_list(user_id).await?;
                if schemas.is_empty() {
                    println!("No schemas registered.");
                } else {
                    let mut sorted = schemas;
                    sorted.sort();
                    println!("Registered schemas ({}):", sorted.len());
                    for nsid in &sorted {
                        println!("  {}", nsid);
                    }
                }
            }

            SchemaCommand::Show { nsid, .. } => match client.schema_get(user_id, nsid).await {
                Ok(json) => {
                    println!("{}", json);
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    return Err(e);
                }
            },

            SchemaCommand::Register { file, .. } => {
                let definition_json = std::fs::read_to_string(file).map_err(|e| {
                    io::Error::other(format!("failed to read '{}': {e}", file.display()))
                })?;

                // Validate JSON before sending to daemon.
                serde_json::from_str::<serde_json::Value>(&definition_json).map_err(|e| {
                    io::Error::other(format!("invalid JSON in '{}': {e}", file.display()))
                })?;

                client.schema_register(user_id, &definition_json).await?;
                println!("✓ Schema registered.");
            }
        }

        Ok(())
    }
}
