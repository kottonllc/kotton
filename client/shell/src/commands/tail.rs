// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// tail command - show last N lines of a file or stdin
pub struct TailCommand;

#[async_trait]
impl Command for TailCommand {
    fn help_text(&self) -> &'static str {
        "tail — print the last lines of a file\n\nUSAGE:\n  tail [-n <count>] <file>\n\n  -n <count>   number of lines to print (default: 10)\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        // Parse -n flag: tail [-n N] [file]
        let (num_lines, file_arg) = if args.len() >= 2 && args[0] == "-n" {
            (args[1].parse().unwrap_or(10usize), args.get(2).map(|s| s.as_str()))
        } else {
            (10usize, args.first().map(|s| s.as_str()))
        };

        let content = if let Some(path_str) = file_arg {
            let path = resolve_path(&state.current_dir, path_str);
            let data = match state.host.read_file(&path).await {
                Ok(d) => d,
                Err(e) => return Ok(CommandOutput::error(1, format!("tail: {}: {}", path_str, e))),
            };
            match String::from_utf8(data) {
                Ok(s) => s,
                Err(_) => return Ok(CommandOutput::error(1, "tail: file contains non-UTF-8 data".to_string())),
            }
        } else if let Some(stdin) = state.stdin.take() {
            stdin
        } else {
            return Ok(CommandOutput::error(1, "Usage: tail [-n lines] <file>".to_string()));
        };

        let all_lines: Vec<&str> = content.lines().collect();
        let start = all_lines.len().saturating_sub(num_lines);
        Ok(CommandOutput::success_with_output(all_lines[start..].join("\n")))
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["-n"]
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


