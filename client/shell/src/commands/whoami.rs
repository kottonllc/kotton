// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// `whoami` — who the shell acts as and, where there is a daemon to ask,
/// whether it holds a session for them and whether their vault is open.
///
/// The session and vault lines are the same verb and the same words as
/// `kotton whoami` (`UnlockState::readout`), so the two processes stop
/// disagreeing about what "logged in" means
/// (`TASK-three-things-are-called-being-logged-in`).
pub struct WhoamiCommand;

#[async_trait]
impl Command for WhoamiCommand {
    fn help_text(&self) -> &'static str {
        "whoami — who you act as, whether the daemon holds your session, and whether your vault is open\n\nUSAGE:\n  whoami\n"
    }

    #[cfg(feature = "cli")]
    async fn execute(&self, _args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        use crate::out::Out;
        let mut rows = vec![("acting as".to_string(), state.user_id.clone())];
        let state_now = state
            .client
            .lock()
            .await
            .get_unlock_state(&state.user_id)
            .await
            .map_err(|e| anyhow::anyhow!("whoami: {e}"))?;
        rows.extend(state_now.readout(&state.user_id, kotton_common::time::now_secs()));
        Ok(CommandOutput::shapes(vec![Out::Record(rows)]))
    }

    #[cfg(not(feature = "cli"))]
    async fn execute(&self, _args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        Ok(CommandOutput::success_with_output(state.user_id.clone()))
    }
}
