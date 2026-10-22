// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// head command - show first N lines of a file or stdin
pub struct HeadCommand;

#[async_trait]
impl Command for HeadCommand {
    fn help_text(&self) -> &'static str {
        "head — print the first lines of a file\n\nUSAGE:\n  head [-n <count>] <file>\n\n  -n <count>   number of lines to print (default: 10)\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        // Parse -n flag: head [-n N] [file]
        let (num_lines, file_arg) = if args.len() >= 2 && args[0] == "-n" {
            (
                args[1].parse().unwrap_or(10usize),
                args.get(2).map(|s| s.as_str()),
            )
        } else {
            (10usize, args.first().map(|s| s.as_str()))
        };

        let content = if let Some(path_str) = file_arg {
            let path = resolve_path(&state.current_dir, path_str);
            let data = match state.host.read_file(&path).await {
                Ok(d) => d,
                Err(e) => {
                    return Ok(CommandOutput::error(
                        1,
                        format!("head: {}: {}", path_str, e),
                    ))
                }
            };
            match String::from_utf8(data) {
                Ok(s) => s,
                Err(_) => {
                    return Ok(CommandOutput::error(
                        1,
                        "head: file contains non-UTF-8 data".to_string(),
                    ))
                }
            }
        } else if let Some(stdin) = state.stdin.take() {
            stdin
        } else {
            return Ok(CommandOutput::error(
                1,
                "Usage: head [-n lines] <file>".to_string(),
            ));
        };

        let lines: Vec<&str> = content.lines().take(num_lines).collect();
        Ok(CommandOutput::success_with_output(lines.join("\n")))
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
