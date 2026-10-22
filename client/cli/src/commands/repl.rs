// SPDX-License-Identifier: AGPL-3.0-or-later
use clap::Args;
use kotton_shell::Shell;
use std::io;

/// Launch the interactive Kotton REPL
#[derive(Args)]
pub struct ReplCommand {
    /// The identity to launch as. Omit to enter identity-first: you'll be asked
    /// for your key (and it resolves who you are), or offered to create a new
    /// identity.
    pub user_id: Option<String>,
}

impl ReplCommand {
    pub async fn execute(self) -> io::Result<()> {
        // No name → identity-first onboarding (enter your key, or create one).
        let user_id = match self.user_id {
            Some(u) => u,
            None => match kotton_shell::onboard()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?
            {
                Some(uid) => uid,
                // A terminal onboarding action completed (e.g. joining a device) —
                // nothing to drop into yet; exit cleanly.
                None => return Ok(()),
            },
        };
        Shell::new(user_id)
            .with_executor(crate::bridge::repl_executor())
            .start()
            .await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("No such file or directory")
                || msg.contains("The system cannot find the file")
                || msg.contains("Connection refused")
                || msg.contains("os error 2")
            {
                io::Error::other(format!(
                    "could not connect to daemon: the Kotton daemon (kuserd) is not running\n\
                         original error: {msg}"
                ))
            } else {
                io::Error::other(msg)
            }
        })
    }
}
