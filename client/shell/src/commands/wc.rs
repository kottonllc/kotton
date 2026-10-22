// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// wc command - count lines, words, and bytes from a file or stdin
pub struct WcCommand;

#[async_trait]
impl Command for WcCommand {
    fn help_text(&self) -> &'static str {
        "wc — count lines, words, and bytes in a file\n\nUSAGE:\n  wc <file>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let (content, label) = if !args.is_empty() {
            let path = resolve_path(&state.current_dir, &args[0]);
            let data = match state.host.read_file(&path).await {
                Ok(d) => d,
                Err(e) => return Ok(CommandOutput::error(1, format!("wc: {}: {}", args[0], e))),
            };
            let text = String::from_utf8(data).unwrap_or_default();
            (text, args[0].clone())
        } else if let Some(stdin) = state.stdin.take() {
            (stdin, String::new())
        } else {
            return Ok(CommandOutput::error(1, "Usage: wc <file>".to_string()));
        };

        let lines = content.lines().count();
        let words = content.split_whitespace().count();
        let bytes = content.len();

        let output = if label.is_empty() {
            format!("  {}  {}  {}", lines, words, bytes)
        } else {
            format!("  {}  {}  {}  {}", lines, words, bytes, label)
        };
        Ok(CommandOutput::success_with_output(output))
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


