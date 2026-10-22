// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// cat command - displays file contents
pub struct CatCommand;

#[async_trait]
impl Command for CatCommand {
    fn help_text(&self) -> &'static str {
        "cat — print file contents\n\nUSAGE:\n  cat <file>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            return Ok(CommandOutput::error(1, "Usage: cat <file>".to_string()));
        }
        let path = resolve_path(&state.current_dir, &args[0]);
        match state.host.read_file(&path).await {
            Ok(data) => Ok(CommandOutput::success_with_output(
                String::from_utf8_lossy(&data).to_string(),
            )),
            Err(e) => Ok(CommandOutput::error(1, format!("cat: {}: {}", args[0], e))),
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
