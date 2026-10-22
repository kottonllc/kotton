// SPDX-License-Identifier: AGPL-3.0-or-later
pub mod commands;
#[cfg(feature = "cli")]
mod completion;
pub mod executor;
mod host;
mod parser;
#[cfg(feature = "cli")]
pub mod secret;
#[cfg(feature = "cli")]
mod shell;
mod state;
#[cfg(feature = "cli")]
mod ui;
#[cfg(feature = "cli")]
pub mod out;
mod utils;

#[cfg(test)]
mod security_tests;

#[cfg(test)]
mod execution_tests;

pub use commands::{Command, CommandOutput, CommandRegistry, ExitCode};
pub use executor::ShellExecutor;
pub use host::ShellHost;
#[cfg(feature = "cli")]
pub use shell::{onboard, Shell};
pub use state::ShellState;
#[cfg(feature = "cli")]
pub use state::Asking;
pub use utils::{expand_vars, normalize_path, parse_command};

/// What the shell prints that a page outside it types or a fixture outside it holds: the
/// lines the operating verbs print ([`TypedLines`]), and the files `app new` writes
/// ([`scaffold_files`]). The pages and the fixture are the tree's that holds them, and it
/// holds them to these (`cargo xtask-docs docs-check`, and xtask's own tests); this crate's
/// tests read nothing outside it.
#[cfg(feature = "cli")]
pub use commands::{scaffold_files, typed_lines, TypedLines, SDK_FROM_REPOSITORY};

/// Return `(name, help_text)` for every shell command, sorted alphabetically.
/// Used by `cargo xtask gen-docs` to emit `docs/shell/reference.md`.
pub fn shell_command_docs() -> Vec<(String, &'static str)> {
    ShellExecutor::new().command_docs()
}
