// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// Built-in help command - shows help text
pub struct HelpCommand;

#[async_trait]
impl Command for HelpCommand {
    fn help_text(&self) -> &'static str {
        "help [command] — list all commands, or show help for one"
    }

    // Registered so `help` appears in completion + the auto-generated listing. The
    // actual rendering is done by the registry (`CommandRegistry::render_help`) so
    // it derives from the live command set; this body is only a fallback.
    async fn execute(&self, _args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        Ok(CommandOutput::success_with_output(
            "run `help` to list commands, or `help <command>` for details.".to_string(),
        ))
    }
}
