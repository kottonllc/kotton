// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// pwd command - shows current working directory
pub struct PwdCommand;

#[async_trait]
impl Command for PwdCommand {
    fn help_text(&self) -> &'static str {
        "pwd — print the current working directory\n\nUSAGE:\n  pwd\n"
    }

    async fn execute(&self, _args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        Ok(CommandOutput::success_with_output(
            state.current_dir.clone(),
        ))
    }
}
