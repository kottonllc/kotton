// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput, ExitCode};
use crate::state::ShellState;

/// Built-in exit command - exits the shell
pub struct ExitCommand;

#[async_trait]
impl Command for ExitCommand {
    fn help_text(&self) -> &'static str {
        "exit — exit the kotton shell (alias: quit)\n\nUSAGE:\n  exit\n"
    }

    async fn execute(&self, _args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        Ok(CommandOutput {
            exit_code: ExitCode::Exit,
            stdout: Some("bye".to_string()),
            stderr: None,
            #[cfg(feature = "cli")]
            out: Vec::new(),
        })
    }
}
