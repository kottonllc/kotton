// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// Built-in export command - sets environment variables
pub struct ExportCommand;

#[async_trait]
impl Command for ExportCommand {
    fn help_text(&self) -> &'static str {
        "export — set or display shell environment variables\n\nUSAGE:\n  export             list all variables\n  export VAR=value   set a variable\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            // Show all exported variables
            let mut vars: Vec<_> = state.env_vars.iter().collect();
            vars.sort_by_key(|(k, _)| k.as_str());
            let output = vars
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n");
            return Ok(CommandOutput::success_with_output(output));
        }

        // Parse VAR=value
        let assignment = args.join(" ");
        if let Some(eq_pos) = assignment.find('=') {
            let var_name = assignment[..eq_pos].trim().to_string();
            let value = assignment[eq_pos + 1..].trim().to_string();
            state.env_vars.insert(var_name, value);
            Ok(CommandOutput::success())
        } else {
            Ok(CommandOutput::error(
                1,
                "export: usage: export VAR=value".to_string(),
            ))
        }
    }
}
