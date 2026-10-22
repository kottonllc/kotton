// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use crate::commands::{Command, CommandOutput};
use crate::state::ShellState;

pub struct DaemonCommand;

#[async_trait]
impl Command for DaemonCommand {
    fn help_text(&self) -> &'static str {
        "daemon — inspect daemon status (temporarily disabled during refactor)\n"
    }

    // Dead stub: errors "temporarily disabled". Keep it out of `help` until it does
    // something real; `doctor` covers daemon status meanwhile.
    fn hidden(&self) -> bool {
        true
    }

    async fn execute(&self, _args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        Ok(CommandOutput::error(
            1,
            "daemon command temporarily disabled during daemon refactor".to_string(),
        ))
    }
}
