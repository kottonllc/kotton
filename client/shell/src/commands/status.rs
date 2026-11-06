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
        Ok(CommandOutput::shapes(said(&status)))
    }

    fn help_text(&self) -> &'static str {
        "status — when this device last synced, what it keeps of each drive, and the notices: a drive no device of yours keeps whole, and this device short of room\n\nUSAGE:\n  status"
    }
}

/// What `status` says, in order: first what the person must know of
/// `personal` (kotton-protocol's storage model; kotton #124) — that it is not found, or found twice,
/// or that no device keeps it whole, so losing the one vault it lives on loses
/// it — then when this device last synced, what it keeps of each drive, and
/// every other notice.
fn said(status: &kotton_wire::ipc::DeviceStatus) -> Vec<Out> {
    use kotton_wire::ipc::{PinNotice, FIRST_DRIVE_NAME};
    let first = |n: &PinNotice| match n {
        PinNotice::NotFound { .. } | PinNotice::Twice { .. } => true,
        PinNotice::NoWholeDevice { drive } => drive == FIRST_DRIVE_NAME,
        PinNotice::ShortOfRoom { .. } => false,
    };
    let (prominent, rest): (Vec<PinNotice>, Vec<PinNotice>) = status.notices.iter().cloned().partition(first);
    let mut out = super::pin::notices(&prominent);
    {
        let synced = status.last_sync_at.map_or_else(|| "not since the daemon started".to_string(), |t| format!("at {t} (unix seconds)"));
        out.push(Out::Record(vec![
            ("last synced".into(), synced),
            ("keeps by default".into(), status.default.said().to_string()),
        ]));
        out.push(Out::Table {
            columns: vec!["drive".into(), "on".into(), "this device keeps".into(), "kept whole on".into()],
            rows: status
                .drives
                .iter()
                .map(|d| {
                    let mut keeps = d.keeps.map_or("nothing yet: its vault holds it", |k| k.said()).to_string();
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
        out.extend(super::pin::notices(&rest));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::said;
    use crate::out::Out;
    use kotton_wire::ipc::{DeviceStatus, PinNotice, PinValue};

    /// **`status` leads with what the person must know of `personal`**
    /// (kotton #124): that no device keeps it whole is said before the
    /// readout, ahead of another drive's notice, which stays after it.
    #[test]
    fn status_leads_with_personal_kept_whole_by_no_device() {
        let status = DeviceStatus {
            last_sync_at: None,
            default: PinValue::Whole,
            drives: Vec::new(),
            notices: vec![
                PinNotice::NoWholeDevice { drive: "photos".into() },
                PinNotice::NoWholeDevice { drive: "personal".into() },
            ],
        };
        let out = said(&status);
        assert!(matches!(&out[0], Out::Warn { what, .. } if what == "no device keeps 'personal' whole"), "{out:?}");
        assert!(matches!(&out[1], Out::Record(_)), "{out:?}");
        assert!(matches!(out.last(), Some(Out::Warn { what, .. }) if what == "no device keeps 'photos' whole"), "{out:?}");
    }
}
