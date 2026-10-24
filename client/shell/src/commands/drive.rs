// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton_wire::ipc::DriveDescriptor;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// drive — your drives: where your things live.
///
/// Usage:
/// ```text
///   drive create <name> [--on <vault>]
///   drive list
///   drive show <name>
///   drive move <name> --to <vault>
/// ```
///
/// The daemon asks the vaults (`kotton_device::users::drive_verbs`); this says
/// what they answered.
pub struct DriveCommand;

const USAGE: &str = "usage: drive create <name> [--on <vault>] | drive list | drive show <name> | drive move <name> --to <vault>";

/// A size as a person reads it; `?` when the vault did not answer.
fn size_said(size: Option<u64>) -> String {
    size.map_or_else(|| "?".to_string(), |b| format!("{b} bytes"))
}

fn table(drives: &[DriveDescriptor]) -> Out {
    Out::Table {
        columns: vec!["drive".into(), "vault".into(), "size".into(), "kept whole on".into()],
        rows: drives
            .iter()
            .map(|d| {
                vec![
                    d.name.clone(),
                    d.vault.clone(),
                    size_said(d.size),
                    if d.pinned_whole.is_empty() { "-".to_string() } else { d.pinned_whole.join(", ") },
                ]
            })
            .collect(),
    }
}

/// The value of `flag` among `rest`, and whether anything else is there.
fn flag_value<'a>(rest: &'a [String], flag: &str) -> Result<Option<&'a str>, ()> {
    match rest {
        [] => Ok(None),
        [f, v] if f == flag => Ok(Some(v.as_str())),
        _ => Err(()),
    }
}

#[async_trait]
impl Command for DriveCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        let said = |verb: &str, e: std::io::Error| anyhow::anyhow!("drive {verb}: {e}");
        match args {
            [sub, name, rest @ ..] if sub == "create" => {
                let Ok(on) = flag_value(rest, "--on") else {
                    return Ok(CommandOutput::fail("drive create: unexpected words", Some(USAGE.into())));
                };
                let drives = client.drive_create(&user_id, name, on).await.map_err(|e| said("create", e))?;
                let vault = drives.first().map(|d| d.vault.clone()).unwrap_or_default();
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: format!("drive made on '{vault}'"),
                    subject: name.clone(),
                }]))
            }
            [sub] if sub == "list" => {
                let drives = client.drive_list(&user_id).await.map_err(|e| said("list", e))?;
                if drives.is_empty() {
                    return Ok(CommandOutput::shapes(vec![Out::Note(
                        "you keep no drive yet — your things live on a drive; `vault invite --me` makes one".into(),
                    )]));
                }
                Ok(CommandOutput::shapes(vec![table(&drives)]))
            }
            [sub, name] if sub == "show" => {
                let drives = client.drive_show(&user_id, name).await.map_err(|e| said("show", e))?;
                Ok(CommandOutput::shapes(
                    drives
                        .iter()
                        .map(|d| {
                            Out::Record(vec![
                                ("drive".into(), d.name.clone()),
                                ("vault".into(), d.vault.clone()),
                                ("vault key".into(), d.vault_key.clone()),
                                ("size".into(), size_said(d.size)),
                                (
                                    "kept whole on".into(),
                                    if d.pinned_whole.is_empty() { "-".into() } else { d.pinned_whole.join(", ") },
                                ),
                            ])
                        })
                        .collect(),
                ))
            }
            [sub, name, flag, to] if sub == "move" && flag == "--to" => {
                let drives = client.drive_move(&user_id, name, to).await.map_err(|e| said("move", e))?;
                let vault = drives.first().map(|d| d.vault.clone()).unwrap_or_else(|| to.clone());
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: format!("drive moved to '{vault}'; your other devices follow it there at their next sync"),
                    subject: name.clone(),
                }]))
            }
            _ => Ok(CommandOutput::fail("drive: unknown form", Some(USAGE.into()))),
        }
    }

    fn complete(&self, _args: &[String], arg_index: usize) -> Vec<String> {
        if arg_index == 0 {
            vec!["create".into(), "list".into(), "show".into(), "move".into()]
        } else {
            vec![]
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["--on", "--to"]
    }

    fn help_text(&self) -> &'static str {
        HELP
    }
}

pub(crate) const HELP: &str = "\
drive — your drives: where your things live

USAGE:
  drive create <name> [--on <vault>]   make a drive on one of your vaults
  drive list                           every drive: where each lives, its size, which devices keep it whole
  drive show <name>                    one drive, on each vault it is kept on
  drive move <name> --to <vault>       carry a drive, sealed, to another of your vaults

A drive is a sealed tree a vault keeps for you; a vault keeps as many as you
make. Its name is sealed under your key: the vault cannot read it. Your first
drive on each vault is `personal`, the tree this device syncs with.

A move copies every sealed object to the other vault under the same key, and
retires the drive where it was only once the other vault holds all of it.
Your other devices follow it at their next sync. `personal` does not move.

FLAGS:
  --on <vault>   the vault to make the drive on: its label, DID or key
                 (needed when you keep drives on more than one)
  --to <vault>   the vault to move the drive to: its label, DID or key

EXAMPLES:
  drive create photos                  # on your one vault
  drive create work --on office-vault  # on the vault labelled office-vault
  drive list
  drive show photos
  drive move photos --to office-vault";
