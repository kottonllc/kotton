// SPDX-License-Identifier: AGPL-3.0-or-later
//! `session` — list and revoke ephemeral session tickets.
//!
//! ```text
//! session list
//! session end <id>
//! ```

use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

pub struct SessionCommand;

#[async_trait]
impl Command for SessionCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;

        match args {
            [sub] if sub == "list" => {
                let sessions = client
                    .list_sessions(&user_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("session list: {e}"))?;

                let rows: Vec<Vec<String>> = sessions
                    .iter()
                    .map(|s| {
                        use kotton_schemas::{CapabilityKind, CapabilityTarget};
                        let has_write = s
                            .grant
                            .grants
                            .iter()
                            .any(|g| g.kind == CapabilityKind::Write);
                        let perm = if has_write { "read-write" } else { "read" };
                        let paths: Vec<&str> = s
                            .grant
                            .grants
                            .iter()
                            .filter_map(|g| {
                                if let CapabilityTarget::Vfs { path } = &g.target {
                                    Some(path.as_str())
                                } else {
                                    None
                                }
                            })
                            .collect::<std::collections::BTreeSet<_>>()
                            .into_iter()
                            .collect();
                        let expires = s
                            .grant
                            .expires_at
                            .map(|t| t.to_string())
                            .unwrap_or_else(|| "never".to_string());
                        let id = if s.revoked {
                            format!("{} (revoked)", s.id)
                        } else {
                            s.id.clone()
                        };
                        vec![id, expires, perm.to_string(), paths.join(", ")]
                    })
                    .collect();
                // Empty → the renderer's one dim "none yet" line.
                Ok(CommandOutput::shapes(vec![Out::Table {
                    columns: vec![
                        "session id".into(),
                        "expires".into(),
                        "permission".into(),
                        "paths".into(),
                    ],
                    rows,
                }]))
            }

            [sub, session_id] if sub == "end" => {
                client
                    .end_session(&user_id, session_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("session end: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: format!("revoked session {session_id}"),
                    subject: String::new(),
                }]))
            }

            _ => Ok(CommandOutput::fail(format!("usage: {USAGE}"), None)),
        }
    }

    fn help_text(&self) -> &'static str {
        HELP
    }
}

const USAGE: &str = "session list | session end <id>";

const HELP: &str = "\
session — manage ephemeral guest session tickets

USAGE:
  session list          list all ephemeral sessions (including revoked)
  session end <id>      revoke a session before it expires

EXAMPLES:
  session list
  session end 550e8400-e29b-41d4-a716-446655440000";
