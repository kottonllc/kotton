// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton extension` — install and manage confined extensions (RFC-0050).
//!
//! ```text
//! kotton extension install <dir>   --user <id>   [--yes]
//! kotton extension list            --user <id>
//! kotton extension remove <id>     --user <id>
//! ```
//!
//! Install takes a **directory** containing `manifest.toml` and
//! `extension.wasm` — the unpacked form of a `.ktx` package. Local-file
//! install touches no network at any step, which is the fully-offline,
//! most-sovereign path (RFC-0050).

use clap::Subcommand;
use kotton::KottonClient;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum ExtensionCommand {
    /// Install an extension from an unpacked package directory.
    ///
    /// The directory must contain `manifest.toml` and `extension.wasm`. The
    /// daemon computes the content hash from the bytes, verifies any publisher
    /// signature against it, and shows you exactly what the extension asked
    /// for before anything is granted.
    Install {
        /// Directory containing `manifest.toml` and `extension.wasm`.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// User ID to install for.
        #[arg(long)]
        user: String,
        /// Skip the confirmation prompt. Intended for scripts; a human
        /// installing an extension should read what it asked for.
        #[arg(long)]
        yes: bool,
    },
    /// List installed extensions.
    List {
        #[arg(long)]
        user: String,
    },
    /// Remove an extension and revoke its grants.
    Remove {
        extension_id: String,
        #[arg(long)]
        user: String,
    },
}

impl ExtensionCommand {
    fn user(&self) -> &str {
        match self {
            ExtensionCommand::Install { user, .. }
            | ExtensionCommand::List { user }
            | ExtensionCommand::Remove { user, .. } => user,
        }
    }

    pub async fn execute(&self) -> io::Result<()> {
        // Every verb acts as `--user`: extensions are installed into that person's store, and
        // the daemon answers none of these on a connection that has not authenticated as them.
        let mut client = KottonClient::connect_as(self.user()).await?;

        match self {
            ExtensionCommand::Install { dir, user, yes } => {
                let manifest_path = dir.join("manifest.toml");
                let wasm_path = dir.join("extension.wasm");
                let manifest_toml = std::fs::read_to_string(&manifest_path).map_err(|e| {
                    io::Error::other(format!("{}: {e}", manifest_path.display()))
                })?;
                let wasm_bytes = std::fs::read(&wasm_path)
                    .map_err(|e| io::Error::other(format!("{}: {e}", wasm_path.display())))?;

                // Show what will be granted, then ask. The daemon re-derives
                // and enforces this independently — the prompt is for the
                // human, never the authority.
                if !yes && !confirm(&manifest_toml)? {
                    println!("Cancelled.");
                    return Ok(());
                }

                let outcome = client
                    .extension_install(user, manifest_toml, wasm_bytes)
                    .await?;

                println!("Installed {} ({})", outcome.name, outcome.extension_id);
                println!("  class:   {}", outcome.class);
                println!("  hash:    {}", &outcome.content_hash[..16]);
                println!(
                    "  signed:  {}",
                    if outcome.signed { "yes" } else { "NO — unsigned package" }
                );
                Ok(())
            }

            ExtensionCommand::List { user } => {
                let extensions = client.extension_list(user).await?;
                if extensions.is_empty() {
                    println!("No extensions installed.");
                    return Ok(());
                }
                for e in &extensions {
                    println!("{} ({}) v{}", e.name, e.extension_id, e.version);
                    println!("  class:     {}", e.class);
                    println!(
                        "  endpoints: {}",
                        if e.endpoints.is_empty() {
                            "none".to_string()
                        } else {
                            e.endpoints.join(", ")
                        }
                    );
                    if !e.credential_slots.is_empty() {
                        println!("  credentials: {}", e.credential_slots.join(", "));
                    }
                    println!(
                        "  publisher: {}",
                        e.publisher_did.as_deref().unwrap_or("UNSIGNED")
                    );
                }
                Ok(())
            }

            ExtensionCommand::Remove {
                extension_id,
                user,
            } => {
                let removed = client.extension_remove(user, extension_id).await?;
                println!("Removed {removed} and revoked its grants.");
                Ok(())
            }
        }
    }
}

/// Print the manifest's own consent summary and ask.
///
/// The summary is produced by `ExtensionManifest::consent_summary()` — the same
/// function the daemon uses — so the CLI cannot show a softer version than what
/// is enforced. If the manifest will not parse, refuse rather than prompting
/// about something we could not read.
fn confirm(manifest_toml: &str) -> io::Result<bool> {
    let manifest = kotton_schemas::ExtensionManifest::from_toml(manifest_toml)
        .map_err(|e| io::Error::other(format!("manifest: {e}")))?;

    println!("This extension is asking for:");
    for line in manifest.consent_summary() {
        println!("  {line}");
    }
    print!("\nInstall? [y/N] ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}
