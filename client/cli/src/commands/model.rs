// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton model` — the models a person has installed (RFC-0085, `DEC-0073`).
//!
//! ```text
//! kotton model add <weights-file> --manifest <manifest.json> [--user <id>]
//! kotton model ls                                            [--user <id>]
//! kotton model rm  <id|name>                                 [--user <id>]
//! kotton model use <id|name> [--rebuild-index]               [--user <id>]
//! ```
//!
//! ## Kotton ships no weights, so a model arrives as a file and a manifest
//!
//! `DEC-0073`: *"Kotton ships no weights, runs no model server, and holds no key
//! that says which models are real."* So there is nothing to download from here
//! and nothing signed by anyone: the person brings the weights, and the manifest
//! says what they are. The one thing checked is the one thing that can be — the
//! bytes hash to what the manifest says they hash to, which is the model's whole
//! identity (*"a hash needs no voucher"*).
//!
//! **A manifest is required, and the person writes it today.** The suggestion
//! manifests `DEC-0073` says the binary carries would let `add` recognise a known
//! file by its hash alone — but a suggestion names a *particular model*, and which
//! model is a measurement RFC-0085 leaves to its backend step. Inventing hashes
//! ahead of that would be worse than asking. What the shape needs is in
//! `--manifest`'s help.
//!
//! ## The size is shown before anything is written
//!
//! RFC-0085: *"The store is paid by the byte, so a model's size is shown before it
//! is installed."* [`ModelCommand::execute`] prints it — and what it will cost in
//! the store — before the first chunk crosses, then refuses outright anything over
//! the sealed-object ceiling rather than streaming gigabytes into a refusal.

use std::io;
use std::path::PathBuf;

use clap::Subcommand;
use kotton::{hash_file, KottonClient, ModelKind, ModelManifest};

/// The largest object a write may declare — the store's own constant, read from
/// the wire rather than copied here.
///
/// Stated at this surface so the refusal arrives before the transfer rather than
/// after it. It was a second copy of the number until 2026-09-16, kept honest by
/// a test that grepped the store's source file; that test passed while the
/// constant it guarded stopped being the relevant one, so the copy was removed
/// rather than the grep repointed.
use kotton_wire::ipc::MAX_STREAMED_FILE_BYTES;

#[derive(Subcommand)]
pub enum ModelCommand {
    /// Install a model from a weights file on this machine.
    Add {
        /// The weights, as the publisher distributes them (`.gguf`,
        /// `.safetensors`).
        file: PathBuf,
        /// A JSON `ModelManifest` describing those weights.
        ///
        /// Its fields are `name`, `version`, `weights` (the BLAKE3 hex of the
        /// file — `kotton model add` prints it if they disagree), `format`
        /// ("gguf" | "safetensors"), `kind` ("chat" | "embed" | "vision"),
        /// `parameters`, `quantisation`, `size`, `context_window`, `template`,
        /// and `licence` ({ "spdx", "text_hash" }). `publisher` is optional and
        /// is a display string — Kotton holds no key that says which models are
        /// real.
        #[arg(long)]
        manifest: PathBuf,
        /// Identity to install into (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// List the installed models, and which one of each kind answers.
    #[command(name = "ls")]
    List {
        /// Identity to act on (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Remove a model — its manifest and the weights it names.
    #[command(name = "rm")]
    Remove {
        /// The model's name, its hash, or the first characters of its hash.
        model: String,
        /// Identity to act on (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Choose which model of its kind answers.
    Use {
        /// The model's name, its hash, or the first characters of its hash.
        model: String,
        /// Say yes to invalidating the index, which changing the active `embed`
        /// model does. Nothing else needs it: a chat model can be changed
        /// between two questions, and an embedding model cannot — every chunk
        /// the old one produced has to be built again, and two devices' indexes
        /// are only comparable while they name the same embedding model.
        #[arg(long)]
        rebuild_index: bool,
        /// Identity to act on (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
}

impl ModelCommand {
    pub async fn execute(self) -> io::Result<()> {
        let user = match &self {
            ModelCommand::Add { user, .. } => user.clone(),
            ModelCommand::List { user } => user.clone(),
            ModelCommand::Remove { user, .. } => user.clone(),
            ModelCommand::Use { user, .. } => user.clone(),
        };
        let mut client = KottonClient::connect_as(&user).await?;

        match self {
            ModelCommand::Add { file, manifest, .. } => {
                let manifest = read_manifest(&manifest)?;
                let size = std::fs::metadata(&file)?.len();

                if size != manifest.size {
                    return Err(io::Error::other(format!(
                        "{} is {size} bytes and the manifest says {}. \
                         The store is paid by the byte, so these have to agree.",
                        file.display(),
                        manifest.size
                    )));
                }
                if size > MAX_STREAMED_FILE_BYTES {
                    return Err(io::Error::other(format!(
                        "{} is {} and the store accepts at most {} in one object. \
                         Refused here rather than after the transfer: the store \
                         checks the declared size before it writes anything.",
                        file.display(),
                        human_bytes(size),
                        human_bytes(MAX_STREAMED_FILE_BYTES),
                    )));
                }

                // Before anything is written: what it is, and what it costs.
                println!(
                    "{} {} ({}, {} parameters, {}) — {} will be sealed into {user}'s store",
                    manifest.name,
                    manifest.version,
                    kind_str(manifest.kind),
                    human_count(manifest.parameters),
                    manifest.quantisation,
                    human_bytes(size),
                );
                println!("licence: {}", manifest.licence.spdx);

                // The hash is what a model *is*, so it is checked here, against
                // the file, before a byte crosses — and again by the daemon, on
                // what it sealed. This one is the useful message: it can name
                // the file and both hashes.
                let got = hash_file(&file)?;
                if got != manifest.weights {
                    return Err(io::Error::other(format!(
                        "{} hashes to {got}, and the manifest names {}. \
                         These are different weights.",
                        file.display(),
                        manifest.weights
                    )));
                }

                let (id, active) = client.model(&user).add(&file, &manifest).await?;
                println!("installed {id}");
                if active {
                    println!(
                        "it is the {} model that answers on this identity",
                        kind_str(manifest.kind)
                    );
                } else {
                    println!(
                        "another {} model is still the one that answers; \
                         `kotton model use {}` moves it",
                        kind_str(manifest.kind),
                        manifest.name
                    );
                }
                Ok(())
            }

            ModelCommand::List { .. } => {
                let models = client.model(&user).list().await?;
                if models.is_empty() {
                    println!("no models installed — `kotton model add <file> --manifest <file>`");
                    return Ok(());
                }
                let total: u64 = models.iter().map(|m| m.manifest.size).sum();
                for installed in &models {
                    println!(
                        "{} {:<24} {:<7} {:>10}  {}  {}",
                        if installed.active { "*" } else { " " },
                        installed.manifest.name,
                        kind_str(installed.manifest.kind),
                        human_bytes(installed.manifest.size),
                        &installed.manifest.weights[..12.min(installed.manifest.weights.len())],
                        installed.manifest.licence.spdx,
                    );
                }
                println!("\n{} installed, {} in the store", models.len(), human_bytes(total));
                println!("* is the model of its kind that answers");
                Ok(())
            }

            ModelCommand::Remove { model, .. } => {
                client.model(&user).remove(&model).await?;
                println!("removed {model}");
                Ok(())
            }

            ModelCommand::Use {
                model,
                rebuild_index,
                ..
            } => {
                client.model(&user).use_model(&model, rebuild_index).await?;
                println!("{model} is the model of its kind that answers");
                Ok(())
            }
        }
    }
}

/// Read the manifest the person obtained with the weights.
fn read_manifest(path: &std::path::Path) -> io::Result<ModelManifest> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| {
        io::Error::other(format!(
            "{} is not a model manifest: {e}. \
             `kotton model add --help` lists the fields one needs.",
            path.display()
        ))
    })
}

fn kind_str(kind: ModelKind) -> &'static str {
    match kind {
        ModelKind::Chat => "chat",
        ModelKind::Embed => "embed",
        ModelKind::Vision => "vision",
    }
}

/// Bytes as a person reads them. The store is paid by the byte and nobody counts
/// in bytes.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A parameter count as the publisher says it: `1.2B`, `360M`.
fn human_count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.0}M", n as f64 / 1e6)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_read_the_way_a_person_counts_them() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(256 * 1024 * 1024), "256.0 MiB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn parameters_read_the_way_a_publisher_states_them() {
        assert_eq!(human_count(1_200_000_000), "1.2B");
        assert_eq!(human_count(360_000_000), "360M");
        assert_eq!(human_count(42), "42");
    }

    // `the_ceiling_is_the_store_s` stood here until 2026-09-16. It grepped
    // `core/device/src/users/files.rs` for a literal, because this crate could
    // not name that one and so wrote the ceiling down a second time.
    //
    // It is deleted rather than repointed. When the store's cap split by what
    // each number bounds, the literal it grepped was still present and still
    // correct — for a different path — so the test stayed green while the limit
    // it existed to track moved out from under it. A check that passes while its
    // subject has moved is worse than no check.
    //
    // What made it necessary was the second copy, and the second copy is gone:
    // both ends now read `kotton_wire::ipc::MAX_STREAMED_FILE_BYTES`. Two copies
    // cannot disagree when there is one.
}
