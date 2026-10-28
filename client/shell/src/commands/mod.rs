// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shell commands module
//!
//! All shell commands (built-ins, VFS operations, system commands) live here.
//! Commands use client APIs from other crates to perform their operations.

use anyhow::Result;
use async_trait::async_trait;

use crate::state::ShellState;

/// Exit code for command execution
#[derive(Debug, Clone, PartialEq)]
pub enum ExitCode {
    Success,
    Code(i32),
    Exit,
}

/// Output from command execution.
///
/// A command produces either legacy string `stdout`/`stderr` **or** a list of
/// [`out::Out`](crate::out::Out) shapes (`out`) that the REPL renders through the
/// Pillar-3 renderer. The shapes channel is the migration target — new/converted
/// commands emit meaning, not strings. It is CLI-only (the guest/WASM build has no
/// terminal renderer).
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub exit_code: ExitCode,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    #[cfg(feature = "cli")]
    pub out: Vec<crate::out::Out>,
}

impl CommandOutput {
    pub fn success() -> Self {
        Self {
            exit_code: ExitCode::Success,
            stdout: None,
            stderr: None,
            #[cfg(feature = "cli")]
            out: Vec::new(),
        }
    }

    pub fn success_with_output(output: String) -> Self {
        Self {
            exit_code: ExitCode::Success,
            stdout: Some(output),
            stderr: None,
            #[cfg(feature = "cli")]
            out: Vec::new(),
        }
    }

    pub fn error(code: i32, message: String) -> Self {
        Self {
            exit_code: ExitCode::Code(code),
            stdout: None,
            stderr: Some(message),
            #[cfg(feature = "cli")]
            out: Vec::new(),
        }
    }

    pub fn exit() -> Self {
        Self {
            exit_code: ExitCode::Exit,
            stdout: None,
            stderr: None,
            #[cfg(feature = "cli")]
            out: Vec::new(),
        }
    }

    /// Emit a list of renderer shapes (Pillar 3). The command chooses *meaning*;
    /// the REPL renders it. Success exit code — a command that also fails carries an
    /// [`Out::Fail`](crate::out::Out::Fail) shape and sets the exit code separately.
    #[cfg(feature = "cli")]
    pub fn shapes(out: Vec<crate::out::Out>) -> Self {
        Self {
            exit_code: ExitCode::Success,
            stdout: None,
            stderr: None,
            out,
        }
    }

    /// A line the tree does not have, said as an [`Out::Fail`](crate::out::Out::Fail)
    /// shape with the usage to try, exit code 2: the command-tree decision's conventions give 0 to done,
    /// 1 to a refusal and 2 to usage, and a verb's own parser is where a line is found
    /// not to be one, in either door.
    #[cfg(feature = "cli")]
    pub fn usage(what: impl Into<String>, try_: Option<String>) -> Self {
        let mut out = Self::fail(what, try_);
        out.exit_code = ExitCode::Code(2);
        out
    }

    /// A failure rendered as an [`Out::Fail`](crate::out::Out::Fail) shape (red
    /// `error:` + an optional `try:` next step), exit code 1. The shape twin of
    /// [`error`](Self::error).
    #[cfg(feature = "cli")]
    pub fn fail(what: impl Into<String>, try_: Option<String>) -> Self {
        Self {
            exit_code: ExitCode::Code(1),
            stdout: None,
            stderr: None,
            out: vec![crate::out::Out::Fail {
                what: what.into(),
                try_,
            }],
        }
    }
}

/// One verb of a noun, as the command-tree decision's tree has it or had it: the word typed after the
/// noun, and whether it is the tree's or a word it retired.
///
/// The table a noun declares ([`Command::verbs`]) is the one list of its verbs: the
/// noun's parser answers each word in it, and `cargo xtask-docs verb-check` reads it
/// from the REPL's registry and from the clap tree's door to the same command, and
/// holds it to the command-tree decision and its table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verb {
    /// The word after the noun: `create`; `""` for the bare noun (`sync`); a
    /// placeholder in angle brackets for a position a name fills (`pin <drive>`).
    pub word: &'static str,
    /// Whether the tree has it, or what replaced it.
    pub is: VerbIs,
}

/// Whether a [`Verb`] is the tree's, or a word the command-tree decision's table retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbIs {
    /// In the command-tree decision, and answered.
    Current,
    /// Retired, and still run as the verb that replaced it, with a line naming it.
    Alias { now: &'static str },
    /// Retired, and refused with a line naming what replaced it; exit 2.
    Gone { now: &'static str },
}

impl Verb {
    pub const fn current(word: &'static str) -> Self {
        Self { word, is: VerbIs::Current }
    }
    pub const fn alias(word: &'static str, now: &'static str) -> Self {
        Self { word, is: VerbIs::Alias { now } }
    }
    pub const fn gone(word: &'static str, now: &'static str) -> Self {
        Self { word, is: VerbIs::Gone { now } }
    }
}

/// The line an alias is answered with beside what it ran: the words typed, and the
/// verb the command-tree decision's tree has for them. A warning, so off a terminal it is on stderr
/// and a script reading stdout reads only the verb's own answer.
#[cfg(feature = "cli")]
pub fn deprecated(was: &str, now: &str) -> crate::out::Out {
    crate::out::Out::Warn {
        what: format!("`{was}` is `{now}` now"),
        consequence: format!("`{was}` is deprecated; type `{now}`"),
    }
}

/// The line a retired word is refused with, exit 2: the words typed, and what the
/// command-tree decision's tree has in their place.
#[cfg(feature = "cli")]
pub fn retired(was: &str, now: &str) -> CommandOutput {
    CommandOutput::usage(format!("`{was}` is gone"), Some(now.to_string()))
}

/// Trait for shell commands
#[async_trait]
pub trait Command: Send + Sync {
    /// Execute the command with given arguments and shell state
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput>;

    /// One-line or multi-line help text shown by `help <cmd>` and used for
    /// generated docs (`cargo xtask gen-docs`).
    fn help_text(&self) -> &'static str {
        ""
    }

    /// Provide tab completion suggestions for this command
    /// Returns a list of possible completions for the given argument at the given position
    fn complete(&self, _args: &[String], _arg_index: usize) -> Vec<String> {
        // Default: no completions
        vec![]
    }

    /// Provide available flags/options for this command
    /// Returns a list of supported flags (e.g., ["-r", "-f", "--recursive"])
    fn flags(&self) -> Vec<&'static str> {
        // Default: no flags
        vec![]
    }

    /// Whether to omit this command from the `help` listing and generated docs.
    /// Still runnable if typed explicitly — this only keeps unfinished/dead-stub
    /// commands out of the surface a user reads. Nothing that doesn't work earns a
    /// place in `help`.
    fn hidden(&self) -> bool {
        false
    }

    /// This noun's verbs, current and retired ([`Verb`]). Empty for a noun the command-tree decision's
    /// rewrite has not reached yet: the check then holds its name and not its verbs.
    fn verbs(&self) -> &'static [Verb] {
        &[]
    }

    /// Whether this noun reads `--json` among its own words (`drive list --json`), so
    /// a door told `--json` hands it the word rather than serializing the shapes.
    fn answers_json(&self) -> bool {
        false
    }

    /// Run this line without a session, when it needs none: `Some` for a line that asks
    /// the daemon nothing and reads nothing of the person's, or one that asks it only
    /// what it answers before anyone is signed in on this device
    /// (`UserRequest::requires_session` is false for every request it sends), connecting
    /// for that itself. A door runs such a line without resolving an identity or
    /// connecting first. `None`, the default, is every line that needs a session, which
    /// the door then connects for and runs through [`Command::execute`].
    ///
    /// `named` is the identity the door was told to act as, if it was told one. A line
    /// that runs here presents no session for it, so on such a line it can only be the
    /// identity the line itself brings to this device (`device join`).
    async fn execute_without_session(
        &self,
        _args: &[String],
        _named: Option<&str>,
    ) -> Option<Result<CommandOutput>> {
        None
    }
}

// Command registry
mod registry;
pub use registry::CommandRegistry;

// Built-in commands
mod cd;
mod echo;
mod env;
mod exit;
mod export;
mod help;
mod unset;

// VFS / data commands — the confined, port-backed core (compiled guest-side too)
mod cat;
mod find;
mod grep;
mod head;
mod ls;
mod mkdir;
mod mv;
mod pwd;
mod rm;
mod rmdir;
mod sort;
mod tail;
mod touch;
mod wc;

// Informational commands
mod clear;
mod daemon;
mod date;
mod secrets;
mod whoami;

// CLI-only commands (terminal TUI / host process / daemon-admin IPC) — not in the guest build
#[cfg(feature = "cli")]
mod app;
#[cfg(feature = "cli")]
mod cp;
#[cfg(feature = "cli")]
mod device;
#[cfg(feature = "cli")]
mod doctor;
#[cfg(feature = "cli")]
mod drive;
#[cfg(feature = "cli")]
mod pin;
#[cfg(feature = "cli")]
mod status;
#[cfg(feature = "cli")]
mod id;
#[cfg(feature = "cli")]
mod issuer;
#[cfg(feature = "cli")]
mod keep;
#[cfg(feature = "cli")]
mod logs;
#[cfg(feature = "cli")]
mod peer;
#[cfg(feature = "cli")]
mod operated;
#[cfg(feature = "cli")]
mod door;
#[cfg(feature = "cli")]
mod relay;
#[cfg(feature = "cli")]
mod session;
#[cfg(feature = "cli")]
mod sync;
#[cfg(feature = "cli")]
mod ted;

// Re-exports — data commands (always compiled)
pub use cd::CdCommand;
pub use echo::EchoCommand;
pub use env::EnvCommand;
pub use exit::ExitCommand;
pub use export::ExportCommand;
pub use help::HelpCommand;
pub use unset::UnsetCommand;

pub use cat::CatCommand;
pub use find::FindCommand;
pub use grep::GrepCommand;
pub use head::HeadCommand;
pub use ls::LsCommand;
pub use mkdir::MkdirCommand;
pub use mv::MvCommand;
pub use pwd::PwdCommand;
pub use rm::RmCommand;
pub use rmdir::RmdirCommand;
pub use sort::SortCommand;
pub use tail::TailCommand;
pub use touch::TouchCommand;
pub use wc::WcCommand;

pub use clear::ClearCommand;
pub use daemon::DaemonCommand;
pub use date::DateCommand;
pub use secrets::SecretsCommand;
pub use whoami::WhoamiCommand;

// Re-exports — CLI-only commands
#[cfg(feature = "cli")]
pub use app::{scaffold_files, AppCommand, SDK_FROM_REPOSITORY};
#[cfg(feature = "cli")]
pub use cp::CpCommand;
#[cfg(feature = "cli")]
pub use device::DeviceCommand;
// The committed-SAS ceremony driver is shared with the onboarding join branch.
#[cfg(feature = "cli")]
pub(crate) use device::join_identity;
#[cfg(feature = "cli")]
pub use doctor::DoctorCommand;
#[cfg(feature = "cli")]
pub use drive::DriveCommand;
#[cfg(feature = "cli")]
pub use pin::PinCommand;
#[cfg(feature = "cli")]
pub use status::StatusCommand;
#[cfg(feature = "cli")]
pub use id::{id_answer, recovery_card, IdAnswer, IdCommand};
#[cfg(feature = "cli")]
pub use issuer::IssuerCommand;
#[cfg(feature = "cli")]
pub use keep::KeepCommand;
#[cfg(feature = "cli")]
pub use logs::LogsCommand;
#[cfg(feature = "cli")]
pub use peer::PeerCommand;
#[cfg(feature = "cli")]
pub use operated::{typed_lines, EnrolCommand, MintCommand, TypedLines, VaultCommand};
#[cfg(feature = "cli")]
pub use door::DoorCommand;
#[cfg(feature = "cli")]
pub use relay::RelayCommand;
#[cfg(feature = "cli")]
pub use session::SessionCommand;
#[cfg(feature = "cli")]
pub use sync::SyncCommand;
#[cfg(feature = "cli")]
pub use ted::TedCommand;
