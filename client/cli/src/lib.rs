// SPDX-License-Identifier: AGPL-3.0-or-later
use clap::Parser;

pub mod active_identity;
pub mod bridge;
pub mod commands;
use commands::Commands;

/// How every binary in this crate ends: a failure is said as its message, alone,
/// on one line of stderr, and the process exits 1.
///
/// A refusal the daemon writes is written for a person, so it reaches them as it
/// was written — not behind an `Error:` prefix, and not in the debug form a `main`
/// returning `io::Result` prints. The exit code is what tells a script it failed.
/// One function for every `main`, so no subcommand needs to know any of this.
/// Clap's own usage errors exit before this is reached, with clap's code, 2.
pub fn finish(result: std::io::Result<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Top-level CLI entry point — re-exported so `xtask gen-docs` can walk the
/// command tree without duplicating the parser definition.
#[derive(Parser)]
#[command(name = "Kotton")]
#[command(about = "Kotton - Your data sovereignty platform", version = kotton_version::VERSION)]
pub struct Cli {
    /// Machine-readable output: print shapes as JSON instead of styled text. Put it
    /// before the verb (`kotton --json issuer list`). Only the shared verbs that
    /// emit shapes honor it.
    #[arg(long)]
    pub json: bool,
    /// No subcommand → enter the runtime (identity-first). The front door is the
    /// REPL, not a wall of help: bare `kotton` drops you in as your active identity
    /// (or onboards you), exactly like `kotton repl`. Verbs remain for scripting.
    #[command(subcommand)]
    pub command: Option<Commands>,
}
