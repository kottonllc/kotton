// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// Built-in env command - shows environment variables
pub struct EnvCommand;

#[async_trait]
impl Command for EnvCommand {
    fn help_text(&self) -> &'static str {
        "env — print all shell environment variables\n\nUSAGE:\n  env\n"
    }

    async fn execute(&self, _args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let mut vars: Vec<_> = state.env_vars.iter().collect();
        vars.sort_by_key(|(k, _)| k.as_str());
        let output = vars
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(CommandOutput::success_with_output(output))
    }
}
