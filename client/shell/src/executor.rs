// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shell command executor - pure execution logic without I/O
//!
//! This module contains the core command execution logic, separated from
//! the interactive REPL. This makes commands testable without needing a
//! full session/IPC infrastructure.

use anyhow::Result;
use std::sync::Arc;

#[cfg(feature = "cli")]
use crate::commands::{
    AppCommand, CpCommand, DeviceCommand, DoorCommand, DoctorCommand, IdCommand, IssuerCommand, KeepCommand, LogsCommand,
    EnrolCommand, MintCommand, PeerCommand, RelayCommand, SessionCommand, SyncCommand, TedCommand, VaultCommand,
};
use crate::commands::{
    CatCommand, CdCommand, ClearCommand, CommandOutput, CommandRegistry, DaemonCommand,
    DateCommand, EchoCommand, EnvCommand, ExitCode, ExitCommand, ExportCommand, FindCommand,
    GrepCommand, HeadCommand, HelpCommand, LsCommand, MkdirCommand, MvCommand, PwdCommand,
    RmCommand, RmdirCommand, SecretsCommand, SortCommand, TailCommand, TouchCommand, UnsetCommand,
    WcCommand, WhoamiCommand,
};
use crate::parser::{parse_command_chain, ChainOperator};
use crate::host::ShellHost;
use crate::state::ShellState;
use crate::utils::{expand_vars, parse_command};

/// Shell command executor - stateless execution logic
pub struct ShellExecutor {
    /// Command registry
    registry: Arc<CommandRegistry>,
}

impl ShellExecutor {
    /// Create a new executor. State (user_id, client) is carried by ShellState.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Self::build_registry()),
        }
    }

    /// An executor that also answers each of `verbs` it does not run by naming the
    /// one-shot form — `kotton <verb> …` — instead of `command not found`.
    ///
    /// The list comes from the caller because only the caller has a `kotton` binary
    /// to name: the REPL passes the clap tree's verbs (`kotton_cli::bridge::repl_executor`),
    /// so a verb added there is accounted for here without anyone editing this crate.
    pub fn with_one_shots(verbs: impl IntoIterator<Item = String>) -> Self {
        let mut registry = Self::build_registry();
        for verb in verbs {
            registry.register_one_shot(verb);
        }
        Self {
            registry: Arc::new(registry),
        }
    }

    fn build_registry() -> CommandRegistry {
        let mut registry = CommandRegistry::new();

        // Built-in commands
        registry.register("cd", CdCommand);
        registry.register("export", ExportCommand);
        registry.register("unset", UnsetCommand);
        registry.register("env", EnvCommand);
        registry.register("echo", EchoCommand);
        registry.register("help", HelpCommand);
        registry.register("exit", ExitCommand);
        registry.register("quit", ExitCommand); // Alias

        // VFS / data commands — the confined, port-backed core (compiled guest-side too).
        registry.register("pwd", PwdCommand);
        registry.register("ls", LsCommand);
        registry.register("cat", CatCommand);
        registry.register("touch", TouchCommand);
        registry.register("mkdir", MkdirCommand);
        registry.register("rm", RmCommand);
        registry.register("rmdir", RmdirCommand);
        registry.register("mv", MvCommand);
        registry.register("find", FindCommand);
        registry.register("grep", GrepCommand);
        registry.register("wc", WcCommand);
        registry.register("head", HeadCommand);
        registry.register("tail", TailCommand);
        registry.register("sort", SortCommand);

        // Low-stakes informational commands.
        registry.register("whoami", WhoamiCommand);
        registry.register("daemon", DaemonCommand);
        registry.register("secrets", SecretsCommand);
        registry.register("date", DateCommand);
        registry.register("clear", ClearCommand);

        // CLI-only commands (terminal TUI, host process, or daemon admin via the IPC
        // client) — gated out of the guest/WASM build, which runs the engine confined to
        // the `ShellHost` port.
        #[cfg(feature = "cli")]
        {
            registry.register("ted", TedCommand);
            registry.register("cp", CpCommand);
            registry.register("keep", KeepCommand);
            registry.register("logs", LogsCommand);
            registry.register("doctor", DoctorCommand);
            registry.register("app", AppCommand);
            registry.register("issuer", IssuerCommand);
            registry.register("peer", PeerCommand);
            registry.register("device", DeviceCommand);
            registry.register("relay", RelayCommand);
            registry.register("door", DoorCommand);
            registry.register("mint", MintCommand);
            registry.register("enrol", EnrolCommand);
            registry.register("vault", VaultCommand);
            registry.register("session", SessionCommand);
            registry.register("sync", SyncCommand);
            registry.register("id", IdCommand);
        }

        registry
    }
}

impl Default for ShellExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellExecutor {
    /// Get a reference to the command registry (for completion)
    pub fn registry(&self) -> Arc<CommandRegistry> {
        Arc::clone(&self.registry)
    }

    /// Return (name, help_text) for every registered command, sorted by name.
    /// Used by `cargo xtask gen-docs` to emit `docs/shell/reference.md`.
    pub fn command_docs(&self) -> Vec<(String, &'static str)> {
        self.registry.command_docs()
    }

    /// Compute tab completions for `line` typed in `cwd`.
    ///
    /// Returns `(start, candidates)` where `start` is the byte offset into
    /// `line` at which the completion token begins — i.e. the caller replaces
    /// `&line[start..]` with the chosen candidate.
    ///
    /// Listing goes through [`ShellHost`], not through a `KottonClient`, and that
    /// is what lets one implementation serve both callers: the CLI's host talks to
    /// the daemon, the shell app's host is its `files` capability, and neither this
    /// function nor the command registry beneath it knows which it has.
    ///
    /// It used to take a `KottonClient` and be `#[cfg(feature = "cli")]`, which put
    /// it out of reach of the one surface that most needed it — the terminal inside
    /// the shell app, compiled to WASM, where there is no client. It also had **no
    /// callers**: `completion.rs` had grown a second copy for rustyline. DEC-0009
    /// rules that the shell and the CLI share one command surface; completing that
    /// surface twice is the same rule, and this is the one copy.
    pub async fn complete_line(
        &self,
        line: &str,
        cwd: &str,
        host: &dyn ShellHost,
    ) -> (usize, Vec<String>) {
        // ── Command completion (no space yet) ─────────────────────────────
        if !line.contains(' ') {
            let mut names = self.registry.command_names();
            names.sort_unstable();
            let candidates = names.into_iter().filter(|n| n.starts_with(line)).collect();
            return (0, candidates);
        }

        // ── Argument completion ───────────────────────────────────────────
        // Find where the last token starts.
        let start = line.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
        let current_arg = &line[start..];

        // A command may complete its own arguments — `app launch <id>` knows the
        // installed ids, and no amount of path listing would find them. Ask first
        // and fall through to paths only when it has nothing, which is what makes
        // this a superset of the path completion below rather than a choice
        // between them.
        {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if let Some(command) = tokens.first() {
                let trailing_space = line.ends_with(char::is_whitespace);
                let args: Vec<String> =
                    tokens[1..].iter().map(|t| (*t).to_owned()).collect();
                let arg_index = if trailing_space {
                    args.len()
                } else {
                    args.len().saturating_sub(1)
                };
                let own = self.registry.complete_for_command(command, &args, arg_index);
                if !own.is_empty() {
                    return (start, own);
                }
            }
        }

        // Split the token into (parent_dir, name_filter) and record whether
        // the token was typed as an absolute path so we can rebuild correctly.
        let (parent, filter, is_absolute, rel_prefix) = if current_arg.is_empty() {
            // Bare space — list cwd
            (cwd.to_string(), String::new(), false, String::new())
        } else if current_arg.starts_with('/') {
            // Absolute path
            if let Some(slash) = current_arg.rfind('/') {
                let p = &current_arg[..slash];
                let parent = if p.is_empty() { "/" } else { p };
                (
                    parent.to_string(),
                    current_arg[slash + 1..].to_string(),
                    true,
                    String::new(),
                )
            } else {
                (
                    "/".to_string(),
                    current_arg.to_string(),
                    true,
                    String::new(),
                )
            }
        } else if let Some(slash) = current_arg.rfind('/') {
            // Relative path with directory component
            let rel_dir = &current_arg[..slash];
            let abs_parent = if cwd == "/" {
                format!("/{}", rel_dir)
            } else {
                format!("{}/{}", cwd, rel_dir)
            };
            let frag = current_arg[slash + 1..].to_string();
            (abs_parent, frag, false, format!("{}/", rel_dir))
        } else {
            // Simple name — list cwd
            (
                cwd.to_string(),
                current_arg.to_string(),
                false,
                String::new(),
            )
        };

        // List the parent directory through whatever host this shell was built with.
        let paths = host.list_files(&parent).await.unwrap_or_default();

        let parent_depth = if parent == "/" {
            0
        } else {
            parent.split('/').filter(|s| !s.is_empty()).count()
        };
        let target_depth = parent_depth + 1;

        let mut seen = std::collections::HashSet::new();
        let mut candidates = Vec::new();

        for path in &paths {
            let norm = path.replace('\\', "/");
            let is_dir = norm.ends_with('/');
            let trimmed = norm.trim_end_matches('/');
            let parts: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() < target_depth {
                continue;
            }
            let name = parts[target_depth - 1];
            if !name.starts_with(filter.as_str()) || !seen.insert(name.to_string()) {
                continue;
            }
            let suffix = if is_dir { "/" } else { "" };
            let replacement = if is_absolute {
                // Keep absolute — reconstruct with known parent
                if parent == "/" {
                    format!("/{}{}", name, suffix)
                } else {
                    format!("{}/{}{}", parent, name, suffix)
                }
            } else {
                // Keep relative — prepend any slash-containing prefix the user typed
                format!("{}{}{}", rel_prefix, name, suffix)
            };
            candidates.push(replacement);
        }

        (start, candidates)
    }

    /// Execute a command line (may contain chained commands and pipes)
    pub async fn execute_line(&self, state: &mut ShellState, line: &str) -> Result<CommandOutput> {
        // Parse the line into potentially chained commands
        let chain = parse_command_chain(line);

        if chain.is_empty() {
            return Ok(CommandOutput::success());
        }

        let mut last_exit_code = 0;
        let mut prev_operator: Option<ChainOperator> = None;
        let mut combined_stdout = Vec::new();
        let mut combined_stderr = Vec::new();
        // Pillar-3 shapes accumulate across the chain and render together at the end.
        #[cfg(feature = "cli")]
        let mut combined_out: Vec<crate::out::Out> = Vec::new();

        for cmd_chain in chain {
            // Determine if we should execute this command based on the PREVIOUS operator
            let should_execute = match &prev_operator {
                // No previous operator - always execute (first command)
                None => true,
                // Sequential - always execute
                Some(ChainOperator::Sequential) => true,
                // AND - only execute if previous succeeded
                Some(ChainOperator::And) => last_exit_code == 0,
                // OR - only execute if previous failed
                Some(ChainOperator::Or) => last_exit_code != 0,
                // Pipe - always execute (stdin was already set by previous command)
                Some(ChainOperator::Pipe) => true,
            };

            if !should_execute {
                // Short-circuit: skip this command (clear any buffered stdin)
                state.stdin = None;
                prev_operator = cmd_chain.operator.clone();
                continue;
            }

            // Execute the single command
            let output = self
                .execute_single_command(state, &cmd_chain.command)
                .await?;

            // Carry any renderer shapes through to the combined result.
            #[cfg(feature = "cli")]
            combined_out.extend(output.out.iter().cloned());

            // Clear stdin after the command has consumed it
            state.stdin = None;

            // If this command's output should pipe to the next, buffer it in state.stdin
            // and do NOT add it to combined_stdout (it's internal to the pipeline).
            if cmd_chain.operator == Some(ChainOperator::Pipe) {
                state.stdin = output.stdout.clone();
            } else if let Some(stdout) = &output.stdout {
                combined_stdout.push(stdout.clone());
            }

            if let Some(stderr) = &output.stderr {
                combined_stderr.push(stderr.clone());
            }

            // Update exit code
            match output.exit_code {
                ExitCode::Success => {
                    last_exit_code = 0;
                }
                ExitCode::Exit => {
                    state.stdin = None;
                    return Ok(CommandOutput::exit());
                }
                ExitCode::Code(code) => {
                    last_exit_code = code;
                }
            }

            // Update the state's exit code after each command
            state.last_exit_code = last_exit_code;
            state
                .env_vars
                .insert("?".to_string(), last_exit_code.to_string());

            // Save the operator for the next iteration
            prev_operator = cmd_chain.operator.clone();
        }

        Ok(CommandOutput {
            exit_code: ExitCode::Code(last_exit_code),
            stdout: if combined_stdout.is_empty() {
                None
            } else {
                Some(combined_stdout.join("\n"))
            },
            stderr: if combined_stderr.is_empty() {
                None
            } else {
                Some(combined_stderr.join("\n"))
            },
            #[cfg(feature = "cli")]
            out: combined_out,
        })
    }

    /// Execute a single command (no chaining), handling output redirection.
    async fn execute_single_command(
        &self,
        state: &mut ShellState,
        line: &str,
    ) -> Result<CommandOutput> {
        // Expand environment variables in the line
        let expanded = expand_vars(line, &state.env_vars);

        // Parse the command into name and arguments
        let parts = parse_command(&expanded);
        if parts.is_empty() {
            return Ok(CommandOutput::success());
        }

        // Detect and strip output redirection tokens (> file  or  >> file)
        let (command_parts, redirect) = parse_redirect(parts);
        if command_parts.is_empty() {
            return Ok(CommandOutput::success());
        }

        let command_name = command_parts[0].clone();
        let args: Vec<String> = command_parts.into_iter().skip(1).collect();

        // Execute using the registry
        let mut output = self.registry.execute(&command_name, &args, state).await?;

        // Handle output redirection: write stdout to a VFS file
        if let Some((mode, path)) = redirect {
            let resolved = if path.starts_with('/') {
                path.clone()
            } else if state.current_dir == "/" {
                format!("/{}", path)
            } else {
                format!("{}/{}", state.current_dir, path)
            };

            let stdout_text = output.stdout.take().unwrap_or_default();

            let content: Vec<u8> = if mode == RedirectMode::Append {
                // Read existing content for append
                let existing = state.host.read_file(&resolved).await.unwrap_or_default();
                let mut data = existing;
                data.extend_from_slice(stdout_text.as_bytes());
                if !stdout_text.is_empty() && !stdout_text.ends_with('\n') {
                    data.push(b'\n');
                }
                data
            } else {
                stdout_text.into_bytes()
            };

            if let Err(e) = state.host.write_file(&resolved, &content).await {
                return Ok(CommandOutput::error(1, format!("{}: {}", path, e)));
            }

            // Stdout was redirected — return without it. Shapes are messages, not the
            // redirected payload, so they pass through to render.
            return Ok(CommandOutput {
                exit_code: output.exit_code,
                stdout: None,
                stderr: output.stderr,
                #[cfg(feature = "cli")]
                out: output.out,
            });
        }

        Ok(output)
    }
}

/// Output redirection mode
#[derive(Debug, PartialEq)]
enum RedirectMode {
    Overwrite, // >
    Append,    // >>
}

/// Scan command `parts` for `>` / `>>` redirect tokens.
/// Returns `(command_parts_without_redirect, Option<(mode, target_path)>)`.
fn parse_redirect(parts: Vec<String>) -> (Vec<String>, Option<(RedirectMode, String)>) {
    let mut cmd_parts = Vec::new();
    let mut redirect: Option<(RedirectMode, String)> = None;
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == ">>" && i + 1 < parts.len() {
            redirect = Some((RedirectMode::Append, parts[i + 1].clone()));
            i += 2;
        } else if parts[i] == ">" && i + 1 < parts.len() {
            redirect = Some((RedirectMode::Overwrite, parts[i + 1].clone()));
            i += 2;
        } else {
            cmd_parts.push(parts[i].clone());
            i += 1;
        }
    }
    (cmd_parts, redirect)
}
