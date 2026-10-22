// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use chrono::{Local, Utc};

use super::{Command, CommandOutput};
use crate::state::ShellState;

pub struct DateCommand;

#[async_trait]
impl Command for DateCommand {
    async fn execute(&self, args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        let utc = args.iter().any(|a| a == "--utc" || a == "-u");
        let formatted = if utc {
            Utc::now().to_rfc3339()
        } else {
            Local::now().to_rfc3339()
        };
        Ok(CommandOutput::success_with_output(formatted))
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["--utc", "-u"]
    }

    fn help_text(&self) -> &'static str {
        "date [--utc]  — print current date and time in RFC 3339 format\n  --utc  use UTC instead of local time"
    }
}
