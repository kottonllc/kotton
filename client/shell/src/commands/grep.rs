// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// grep command - search file contents or stdin for a pattern
pub struct GrepCommand;

#[async_trait]
impl Command for GrepCommand {
    fn help_text(&self) -> &'static str {
        "grep — search for lines matching a pattern\n\nUSAGE:\n  grep <pattern> <file>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        // Usage: grep <pattern> [file]  — file is optional when stdin is piped
        if args.is_empty() {
            return Ok(CommandOutput::error(
                1,
                "Usage: grep <pattern> [file]".to_string(),
            ));
        }

        let pattern = &args[0];

        let content = if args.len() >= 2 {
            // Read from VFS file
            let path = resolve_path(&state.current_dir, &args[1]);
            let data = match state.host.read_file(&path).await {
                Ok(d) => d,
                Err(e) => return Ok(CommandOutput::error(1, format!("grep: {}: {}", args[1], e))),
            };
            match String::from_utf8(data) {
                Ok(s) => s,
                Err(_) => {
                    return Ok(CommandOutput::error(
                        1,
                        "grep: file contains non-UTF-8 data".to_string(),
                    ))
                }
            }
        } else if let Some(stdin) = state.stdin.take() {
            // Use piped stdin
            stdin
        } else {
            return Ok(CommandOutput::error(
                1,
                "grep: no input (pipe or file required)".to_string(),
            ));
        };

        let matches: Vec<String> = content
            .lines()
            .filter(|line| line.contains(pattern.as_str()))
            .map(|line| line.to_string())
            .collect();

        if matches.is_empty() {
            Ok(CommandOutput {
                exit_code: super::ExitCode::Code(1),
                stdout: None,
                stderr: None,
                #[cfg(feature = "cli")]
                out: Vec::new(),
            })
        } else {
            Ok(CommandOutput::success_with_output(matches.join("\n")))
        }
    }
}

fn resolve_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{}", path)
    } else {
        format!("{}/{}", cwd, path)
    }
}
