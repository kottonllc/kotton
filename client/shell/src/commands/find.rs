// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// find command - search for files by name pattern
pub struct FindCommand;

#[async_trait]
impl Command for FindCommand {
    fn help_text(&self) -> &'static str {
        "find — search for files matching a pattern\n\nUSAGE:\n  find [path] -name <pattern>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let path_arg = args.first().map(|s| s.as_str()).unwrap_or("/");
        let pattern = args.get(1).map(|s| s.as_str());

        let prefix = if path_arg.starts_with('/') {
            path_arg.trim_end_matches('/').to_string()
        } else if state.current_dir == "/" {
            format!("/{}", path_arg)
        } else {
            format!("{}/{}", state.current_dir, path_arg)
        };

        let paths = match state.host.list_files(&prefix).await {
            Ok(p) => p,
            Err(e) => return Ok(CommandOutput::error(1, format!("find: {}: {}", path_arg, e))),
        };

        let results: Vec<String> = paths
            .into_iter()
            .filter(|p| {
                if let Some(pat) = pattern {
                    p.split('/').next_back().unwrap_or("").contains(pat)
                } else {
                    true
                }
            })
            .collect();

        if results.is_empty() {
            Ok(CommandOutput::success())
        } else {
            Ok(CommandOutput::success_with_output(results.join("\n")))
        }
    }
}

