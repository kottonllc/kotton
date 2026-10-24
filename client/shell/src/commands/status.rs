// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// status — what this device keeps of your drives, when it last synced, and
/// what you should know.
///
/// Read on this device, asking no vault. The protocol's `status` says more —
/// devices, host, what arrived — and grows into it with the tree's rewrite.
pub struct StatusCommand;

#[async_trait]
impl Command for StatusCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if !args.is_empty() {
            return Ok(CommandOutput::fail("status: takes no words", Some("usage: status".into())));
        }
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        let status = client.status(&user_id).await.map_err(|e| anyhow::anyhow!("status: {e}"))?;
        let synced = status.last_sync_at.map_or_else(|| "not since the daemon started".to_string(), |t| format!("at {t} (unix seconds)"));
        let mut out = vec![Out::Record(vec![
            ("last synced".into(), synced),
            ("keeps by default".into(), status.default.said().to_string()),
        ])];
        out.push(Out::Table {
            columns: vec!["drive".into(), "on".into(), "this device keeps".into(), "kept whole on".into()],
            rows: status
                .drives
                .iter()
                .map(|d| {
                    let mut keeps = d.keeps.said().to_string();
                    for f in &d.folders {
                        if let kotton_wire::ipc::PinScope::Folder { folder, .. } = &f.scope {
                            keeps.push_str(&format!(", {folder} {}", f.value.said()));
                        }
                    }
                    vec![
                        d.name.clone(),
                        d.vaults.join(", "),
                        keeps,
                        if d.pinned_whole.is_empty() { "-".into() } else { d.pinned_whole.join(", ") },
                    ]
                })
                .collect(),
        });
        out.extend(super::pin::notices(&status.notices));
        Ok(CommandOutput::shapes(out))
    }

    fn help_text(&self) -> &'static str {
        "status — when this device last synced, what it keeps of each drive, and the notices: a drive no device of yours keeps whole, and this device short of room\n\nUSAGE:\n  status"
    }
}
