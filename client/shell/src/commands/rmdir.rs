// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// rmdir command - removes a directory marker
pub struct RmdirCommand;

#[async_trait]
impl Command for RmdirCommand {
    fn help_text(&self) -> &'static str {
        "rmdir — remove an empty directory\n\nUSAGE:\n  rmdir <dir>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            return Ok(CommandOutput::error(1, "Usage: rmdir <dir>".to_string()));
        }
        let dir = resolve_path(&state.current_dir, &args[0]);
        let marker = format!("{}/.keep", dir.trim_end_matches('/'));
        // Remove the .keep marker; ignore not-found errors
        let _ = state.host.delete_file(&marker).await;
        Ok(CommandOutput::success())
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
