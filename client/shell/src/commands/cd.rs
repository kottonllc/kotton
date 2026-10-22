// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;
use crate::utils::normalize_path;

/// Built-in cd command - changes current directory
pub struct CdCommand;

#[async_trait]
impl Command for CdCommand {
    fn help_text(&self) -> &'static str {
        "cd — change current directory\n\nUSAGE:\n  cd [path]   change to path (default: /)\n  cd -        switch to previous directory\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let target = match args.first() {
            Some(p) => p.as_str(),
            None => "/",
        };

        let new_dir = if target == "-" {
            state.previous_dir.clone()
        } else if target.starts_with('/') {
            normalize_path(target)
        } else {
            normalize_path(&format!("{}/{}", state.current_dir, target))
        };

        // "/" always exists; skip the daemon round-trip.
        if new_dir != "/" {
            let parent = {
                let pos = new_dir.rfind('/').unwrap_or(0);
                let p = &new_dir[..pos];
                if p.is_empty() { "/" } else { p }.to_string()
            };
            let entry_name = new_dir.rsplit('/').next().unwrap_or(&new_dir);

            let entries = state.host.list_files(&parent).await.unwrap_or_default();

            // An entry is a directory only if it is listed with a trailing '/'.
            let is_dir = entries.iter().any(|e| {
                let norm = e.replace('\\', "/");
                let name = norm.trim_end_matches('/').rsplit('/').next().unwrap_or("");
                name == entry_name && norm.ends_with('/')
            });

            if !is_dir {
                let exists = entries.iter().any(|e| {
                    let norm = e.replace('\\', "/");
                    let name = norm.trim_end_matches('/').rsplit('/').next().unwrap_or("");
                    name == entry_name
                });
                let msg = if exists {
                    format!("cd: not a directory: {}", target)
                } else {
                    format!("cd: no such file or directory: {}", target)
                };
                return Ok(CommandOutput::error(1, msg));
            }
        }

        state.previous_dir = state.current_dir.clone();
        state.current_dir = new_dir;
        // Keep the completer's shared CWD Arc in sync
        *state.cwd.write().unwrap() = state.current_dir.clone();
        Ok(CommandOutput::success())
    }
}
