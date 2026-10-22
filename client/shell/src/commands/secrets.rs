// SPDX-License-Identifier: AGPL-3.0-or-later
//! Secrets command - stub pending full implementation

use anyhow::Result;
use async_trait::async_trait;

use crate::commands::{Command, CommandOutput};
use crate::state::ShellState;

pub struct SecretsCommand;

#[async_trait]
impl Command for SecretsCommand {
    fn help_text(&self) -> &'static str {
        "secrets — manage encrypted secrets (stub, coming soon)\n\nUSAGE:\n  secrets set <key> <value>\n  secrets get <key>\n  secrets list\n  secrets rm <key>\n"
    }

    // Unimplemented stub: keep it out of `help`. And fail (non-zero) rather than
    // returning success for doing nothing — a script that relies on `secrets` must
    // not think it succeeded.
    fn hidden(&self) -> bool {
        true
    }

    async fn execute(&self, _args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        Ok(CommandOutput::error(
            1,
            "secrets: not yet implemented".to_string(),
        ))
    }
}
