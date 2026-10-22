// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// touch command - creates an empty file
pub struct TouchCommand;

#[async_trait]
impl Command for TouchCommand {
    fn help_text(&self) -> &'static str {
        "touch — create an empty file or update its modification time\n\nUSAGE:\n  touch <file>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            return Ok(CommandOutput::error(1, "Usage: touch <file>".to_string()));
        }
        let path = resolve_path(&state.current_dir, &args[0]);
        match state.host.write_file(&path, b"").await {
            Ok(_) => Ok(CommandOutput::success()),
            Err(e) => Ok(CommandOutput::error(
                1,
                format!("touch: {}: {}", args[0], e),
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
