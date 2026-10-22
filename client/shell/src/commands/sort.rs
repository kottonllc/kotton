// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

pub struct SortCommand;

#[async_trait]
impl Command for SortCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let reverse = args.iter().any(|a| a == "-r");
        let unique = args.iter().any(|a| a == "-u");
        let file_arg = args.iter().find(|a| !a.starts_with('-')).cloned();

        let text = if let Some(path) = file_arg {
            let resolved = if path.starts_with('/') {
                path.clone()
            } else if state.current_dir == "/" {
                format!("/{}", path)
            } else {
                format!("{}/{}", state.current_dir, path)
            };
            let bytes = state
                .host
                .read_file(&resolved)
                .await
                .map_err(|e| anyhow::anyhow!("sort: {e}"))?;
            String::from_utf8_lossy(&bytes).into_owned()
        } else if let Some(stdin) = state.stdin.take() {
            stdin
        } else {
            return Ok(CommandOutput::error(
                1,
                "sort: no input (provide a file path or pipe input)".to_string(),
            ));
        };

        let mut lines: Vec<&str> = text.lines().collect();
        lines.sort_unstable();
        if unique {
            lines.dedup();
        }
        if reverse {
            lines.reverse();
        }

        Ok(CommandOutput::success_with_output(lines.join("\n")))
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["-r", "-u"]
    }

    fn help_text(&self) -> &'static str {
        "sort [-r] [-u] [file]  — sort lines of a VFS file or piped input\n  -r  reverse order\n  -u  remove duplicate lines"
    }
}
