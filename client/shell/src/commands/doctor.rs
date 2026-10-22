// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use crate::commands::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

pub struct DoctorCommand;

#[async_trait]
impl Command for DoctorCommand {
    fn help_text(&self) -> &'static str {
        "doctor — check daemon connectivity and print diagnostics\n\nUSAGE:\n  doctor\n"
    }

    async fn execute(&self, _args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let daemon = match state.client.try_lock() {
            Ok(_) => "connected",
            Err(_) => "busy (in use)",
        };
        Ok(CommandOutput::shapes(vec![
            Out::Note("kotton doctor".to_string()),
            Out::Record(vec![
                ("user".to_string(), state.user_id.clone()),
                ("daemon".to_string(), daemon.to_string()),
            ]),
            Out::Hint("extended diagnostics coming soon".to_string()),
        ]))
    }
}
