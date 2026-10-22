// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// ls command - lists files in a directory
pub struct LsCommand;

#[async_trait]
impl Command for LsCommand {
    fn help_text(&self) -> &'static str {
        "ls — list directory contents\n\nUSAGE:\n  ls [path]\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let mut path_arg: Option<&str> = None;
        for arg in args {
            if !arg.starts_with('-') {
                path_arg = Some(arg.as_str());
            }
        }

        let dir = match path_arg {
            Some(p) if p.starts_with('/') => p.to_string(),
            Some(p) if state.current_dir == "/" => format!("/{}", p),
            Some(p) => format!("{}/{}", state.current_dir, p),
            None => state.current_dir.clone(),
        };

        let prefix = if dir == "/" {
            "".to_string()
        } else {
            dir.trim_end_matches('/').to_string()
        };
        // How many path components does the listed directory have?
        // We use this to find the immediate children.
        let prefix_depth = if prefix.is_empty() {
            0usize
        } else {
            prefix.trim_start_matches('/').split('/').count()
        };

        match state.host.list_files(&prefix).await {
            Ok(mut paths) => {
                // Show only names at exactly one level below the listed dir.
                paths.sort();
                let mut seen = std::collections::HashSet::new();
                let names: Vec<String> = paths
                    .iter()
                    .filter(|p| !p.ends_with("/.keep") && !p.ends_with("\\.keep"))
                    .filter_map(|p| {
                        // Normalise to forward slashes for consistent splitting.
                        // Strip trailing '/' before depth check but remember it.
                        let normalised = p.replace('\\', "/");
                        let is_dir = normalised.ends_with('/');
                        let trimmed = normalised.trim_start_matches('/').trim_end_matches('/');
                        let parts: Vec<&str> = trimmed.split('/').collect();
                        if parts.len() == prefix_depth + 1 {
                            parts.last().map(|s| {
                                if is_dir {
                                    format!("{}/", s)
                                } else {
                                    s.to_string()
                                }
                            })
                        } else {
                            None
                        }
                    })
                    .filter(|n| !n.is_empty() && seen.insert(n.clone()))
                    .collect();

                if names.is_empty() {
                    Ok(CommandOutput::success())
                } else {
                    Ok(CommandOutput::success_with_output(names.join("  ")))
                }
            }
            Err(e) => Ok(CommandOutput::error(1, format!("ls: {}", e))),
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["-l", "-a"]
    }
}
