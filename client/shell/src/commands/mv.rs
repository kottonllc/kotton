// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// mv command - move/rename files
pub struct MvCommand;

#[async_trait]
impl Command for MvCommand {
    fn help_text(&self) -> &'static str {
        "mv — move or rename a file\n\nUSAGE:\n  mv <source> <dest>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.len() != 2 {
            return Ok(CommandOutput::error(1, "Usage: mv <source> <destination>".to_string()));
        }
        let src = resolve_path(&state.current_dir, &args[0]);
        let dst = resolve_path(&state.current_dir, &args[1]);

        let data = match state.host.read_file(&src).await {
            Ok(d) => d,
            Err(e) => return Ok(CommandOutput::error(1, format!("mv: {}: {}", args[0], e))),
        };
        if let Err(e) = state.host.write_file(&dst, &data).await {
            return Ok(CommandOutput::error(1, format!("mv: {}: {}", args[1], e)));
        }
        let _ = state.host.delete_file(&src).await;
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
