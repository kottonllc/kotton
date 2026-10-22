// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// mkdir command - creates a directory (stored as a .keep marker file)
pub struct MkdirCommand;

#[async_trait]
impl Command for MkdirCommand {
    fn help_text(&self) -> &'static str {
        "mkdir — create a directory\n\nUSAGE:\n  mkdir <dir>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            return Ok(CommandOutput::error(1, "Usage: mkdir <dir>".to_string()));
        }
        let dir = resolve_path(&state.current_dir, &args[0]);
        let marker = format!("{}/.keep", dir.trim_end_matches('/'));
        match state.host.write_file(&marker, b"").await {
            Ok(_) => Ok(CommandOutput::success()),
            Err(e) => Ok(CommandOutput::error(
                1,
                format!("mkdir: {}: {}", args[0], e),
            )),
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
