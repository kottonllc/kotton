// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton config` — device configuration sub-commands.
//!
//! ```text
//! kotton config paths           — show local data directories and socket path
//! kotton config status          — show all device config items as a table
//! kotton config relay set <url> — set relay server URL
//! kotton config relay clear     — remove relay server URL
//! kotton config inference set <on|off>
//!                               — run a model on this machine (RFC-0085)
//! ```

use clap::Subcommand;
use kotton::KottonClient;
use std::io;

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Show local data directories, socket path, and environment in use.
    /// Does not require the daemon to be running.
    Paths,
    /// Show all device-level configuration: relay, TURN, STUN, and what each enables.
    Status,
    /// Relay server configuration.
    #[command(subcommand)]
    Relay(RelaySubcommand),
    /// Whether this machine runs a language model over your own records.
    #[command(subcommand)]
    Inference(InferenceSubcommand),
}

#[derive(Subcommand)]
pub enum InferenceSubcommand {
    /// Turn the inference runtime on or off. Takes effect at the daemon's next
    /// start; `kotton sidecars` says whether it is running now.
    Set {
        /// `on` or `off`.
        state: InferenceState,
    },
}

/// Spelled `on`/`off` rather than a bare flag, so the command reads as the
/// sentence a person means and turning it off is as easy to type as turning it
/// on.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum InferenceState {
    On,
    Off,
}

#[derive(Subcommand)]
pub enum RelaySubcommand {
    /// Set the relay server URL.
    Set {
        /// Relay server URL, e.g. https://relay.kotton.dev
        url: String,
    },
    /// Remove the configured relay server URL.
    Clear,
}

impl ConfigCommand {
    pub async fn execute(&self) -> io::Result<()> {
        if let ConfigCommand::Paths = self {
            let base = kotton_common::paths::base_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "(error resolving path)".to_string());

            let sessions = kotton_common::paths::base_dir()
                .map(|p| p.join("sessions").display().to_string())
                .unwrap_or_else(|_| "(error resolving path)".to_string());

            // The door the client connects to, asked of the one function that
            // composes it — not a join here, which printed `/tmp/<name>.sock`
            // until 2026-09-28 while no daemon bound there
            // (`TASK-config-paths-prints-a-socket-nothing-binds`).
            #[cfg(windows)]
            let socket = kotton_common::paths::pipe_path(&kotton_common::kuserd_ipc_name());
            #[cfg(not(windows))]
            let socket = kotton_common::kuserd_door()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "(error resolving path)".to_string());

            println!("Kotton paths:");
            println!("  base dir:     {base}");
            println!("  sessions:     {sessions}");
            println!("  socket:       {socket}");
            println!();
            println!("Environment:");
            println!(
                "  KOTTON_BASE_DIR   {}",
                std::env::var("KOTTON_BASE_DIR").unwrap_or_else(|_| "(default)".to_string())
            );
            println!(
                "  KDEVICED_IPC_NAME   {}",
                std::env::var("KDEVICED_IPC_NAME").unwrap_or_else(|_| "(default)".to_string())
            );
            println!(
                "  KUSERD_IPC_NAME     {}",
                std::env::var("KUSERD_IPC_NAME").unwrap_or_else(|_| "(default)".to_string())
            );

            return Ok(());
        }

        let mut client = KottonClient::connect().await?;

        match self {
            ConfigCommand::Status => {
                let items = client.config_status().await?;
                if items.is_empty() {
                    println!("No configuration items returned.");
                    return Ok(());
                }

                let key_w = items.iter().map(|i| i.key.len()).max().unwrap_or(3).max(3);
                let val_w = items
                    .iter()
                    .map(|i| i.value.as_deref().unwrap_or("(not set)").len())
                    .max()
                    .unwrap_or(5)
                    .max(5);

                println!(
                    "{:<key_w$}  {:<val_w$}  CAPABILITY",
                    "KEY",
                    "VALUE",
                    key_w = key_w,
                    val_w = val_w,
                );
                println!("{}", "-".repeat(key_w + val_w + 50));

                for item in &items {
                    let value_display = item.value.as_deref().unwrap_or("(not set)");
                    println!(
                        "{:<key_w$}  {:<val_w$}  {}",
                        item.key,
                        value_display,
                        item.capability,
                        key_w = key_w,
                        val_w = val_w,
                    );
                    if !item.configured {
                        println!(
                            "{:<key_w$}  {:<val_w$}  \u{2514}\u{2500} configure: {}",
                            "",
                            "",
                            item.command,
                            key_w = key_w,
                            val_w = val_w,
                        );
                    }
                }
            }

            ConfigCommand::Relay(sub) => match sub {
                RelaySubcommand::Set { url } => {
                    client.node_rendezvous_set(Some(url.as_str())).await?;
                    println!("\u{2713} Relay server set to {}", url);
                }
                RelaySubcommand::Clear => {
                    client.node_rendezvous_set(None).await?;
                    println!("\u{2713} Relay server cleared");
                }
            },

            ConfigCommand::Inference(sub) => match sub {
                InferenceSubcommand::Set { state } => {
                    let enabled = matches!(state, InferenceState::On);
                    client.inference_set(enabled).await?;
                    if enabled {
                        println!(
                            "\u{2713} Inference enabled. It starts with the daemon — restart kuserd, then `kotton sidecars` to see kinferd running."
                        );
                    } else {
                        println!("\u{2713} Inference disabled, from the daemon's next start.");
                    }
                }
            },

            // Paths is handled above before connecting to the daemon.
            ConfigCommand::Paths => unreachable!(),
        }

        Ok(())
    }
}
