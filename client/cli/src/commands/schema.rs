// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton schema` subcommands — schema inspection and registration.
//!
//! ```text
//! kotton schema list                  [--user <id>]
//! kotton schema show <schema>         [--user <id>]
//! kotton schema register <file.json>  [--user <id>]
//! ```
//!
//! The schemas a person sees are core plus their own registrations, so every verb acts as
//! someone: `--user`, else `KOTTON_USER`, else the active identity. A schema is named by the
//! key that publishes it: `<publisher>/<name>`, the publisher being the `did:key` of that key,
//! and `register` takes a definition that key signed. `show` takes it whole or as
//! `<petname>/<name>`, the person's own name for the key, resolved on this device by the
//! shell's one parser (`kotton_shell::petnames`), and `list` prints the short form wherever
//! the publisher has a name.

use clap::Subcommand;
use kotton::KottonClient;
use kotton_shell::petnames::{self, SchemaArg};
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
        /// The schema to inspect: `<petname>/<name>` (`kotton/notes`) or `did:key:…/<name>`
        schema: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Register a schema from a JSON definition file, signed by its publisher
    Register {
        /// Path to a JSON file containing a `SchemaDefinition`, its `signature` included
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
                    let names = petnames::read_for_typing(&mut client, user_id).await;
                    let mut sorted: Vec<String> = schemas
                        .iter()
                        .map(|nsid| match kotton_schemas::SchemaId::parse(nsid) {
                            Ok(id) => petnames::said(&id, &names),
                            Err(_) => nsid.clone(),
                        })
                        .collect();
                    sorted.sort();
                    println!("Registered schemas ({}):", sorted.len());
                    for nsid in &sorted {
                        println!("  {}", nsid);
                    }
                }
            }

            SchemaCommand::Show { schema, .. } => {
                let names = petnames::read_for_typing(&mut client, user_id).await;
                let id = SchemaArg::parse(schema).and_then(|arg| arg.resolve(&names)).map_err(|e| {
                    eprintln!("error: {e}");
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                match client.schema_get(user_id, &id.to_string()).await {
                    Ok(json) => {
                        println!("{}", json);
                    }
                    Err(e) => {
                        eprintln!("error: {}", e);
                        return Err(e);
                    }
                }
            }

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
