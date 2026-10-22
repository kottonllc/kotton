// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

pub struct ClearCommand;

#[async_trait]
impl Command for ClearCommand {
    async fn execute(&self, _args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        Ok(CommandOutput::success_with_output(
            "\x1b[2J\x1b[H".to_string(),
        ))
    }

    fn help_text(&self) -> &'static str {
        "clear  — clear the terminal screen"
    }
}
