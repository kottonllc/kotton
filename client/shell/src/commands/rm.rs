// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// rm command - removes files
pub struct RmCommand;

#[async_trait]
impl Command for RmCommand {
    fn help_text(&self) -> &'static str {
        "rm — remove a file or directory\n\nUSAGE:\n  rm <path>\n  rm -r <path>    remove recursively\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            return Ok(CommandOutput::error(1, "Usage: rm [-r] <path>".to_string()));
        }

        let mut path: Option<String> = None;
        for arg in args {
            if !arg.starts_with('-') {
                path = Some(resolve_path(&state.current_dir, arg));
            }
        }

        let path = match path {
            Some(p) => p,
            None => return Ok(CommandOutput::error(1, "rm: no path specified".to_string())),
        };

        match state.host.delete_file(&path).await {
            Ok(_) => Ok(CommandOutput::success()),
            Err(e) => Ok(CommandOutput::error(1, format!("rm: {}: {}", path, e))),
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["-r"]
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


