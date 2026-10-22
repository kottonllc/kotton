// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// Built-in echo command - prints text
pub struct EchoCommand;

#[async_trait]
impl Command for EchoCommand {
    fn help_text(&self) -> &'static str {
        "echo — print arguments to stdout\n\nUSAGE:\n  echo [args...]\n"
    }

    async fn execute(&self, args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        let text = args.join(" ");
        Ok(CommandOutput::success_with_output(text))
    }
}
