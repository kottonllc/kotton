// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// Built-in unset command - removes environment variables
pub struct UnsetCommand;

#[async_trait]
impl Command for UnsetCommand {
    fn help_text(&self) -> &'static str {
        "unset — unset a shell environment variable\n\nUSAGE:\n  unset <VAR>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            return Ok(CommandOutput::error(
                1,
                "unset: usage: unset VAR".to_string(),
            ));
        }
        state.env_vars.remove(&args[0]);
        Ok(CommandOutput::success())
    }
}
