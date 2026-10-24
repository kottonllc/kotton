// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton::SyncDirection;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// sync — sync this device's drives, or manage this device's rule for a drive.
///
/// Usage:
/// ```text
///   sync [now] [--no-wait]
///   sync [--push | --pull] <remote>
///   sync add <drive> [--push | --pull] [--watch]
///   sync list
///   sync remove <drive>
/// ```
///
/// A device syncs to its person's drives and to nothing else: no device is a
/// sync target, so nothing here names one.
pub struct SyncCommand;

#[async_trait]
impl Command for SyncCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;

        // `--node` named one paired node — another of the person's devices
        // among them. A device is not a sync target, so the form is gone.
        if args.iter().any(|a| a == "--node") {
            return Ok(CommandOutput::fail(
                "sync: `--node` is gone — a device is not a sync target",
                Some("`sync` syncs this device's drives".into()),
            ));
        }

        // `sync` and `sync now [--no-wait]`: this device's drives, now, each
        // in the direction its rule chooses.
        let bare = args.is_empty()
            || (args.first().map(String::as_str) == Some("now")
                && args[1..].iter().all(|a| a == "--no-wait" || a == "-n"));
        if bare {
            let no_wait = args.iter().any(|a| a == "--no-wait" || a == "-n");
            let (job_id, drives) = client
                .sync_drives(&user_id)
                .await
                .map_err(|e| anyhow::anyhow!("sync: {e}"))?;
            if drives == 0 {
                return Ok(CommandOutput::shapes(vec![Out::Note(
                    "this device keeps no drive yet — your things live on a drive; `vault invite --me` makes one"
                        .to_string(),
                )]));
            }
            if no_wait {
                return Ok(CommandOutput::shapes(vec![Out::Note(format!(
                    "syncing {drives} drive(s) (job {job_id})"
                ))]));
            }
            let outcome = client
                .sync_await(&user_id, job_id, 60)
                .await
                .map_err(|e| anyhow::anyhow!("sync: {e}"))?;
            let shape = if outcome.files == 0 {
                Out::Note("already in sync".into())
            } else {
                Out::Confirm {
                    action: format!(
                        "synced {} file(s), {} bytes, with {drives} drive(s)",
                        outcome.files, outcome.bytes
                    ),
                    subject: String::new(),
                }
            };
            return Ok(CommandOutput::shapes(vec![shape]));
        }

        match args {
            // -- This device's rules, one per drive ------------------------------
            [sub, drive, flags @ ..] if sub == "add" => {
                let mut direction = None;
                let mut watch = false;
                for f in flags {
                    match f.as_str() {
                        "--push" => direction = Some(SyncDirection::Push),
                        "--pull" => direction = Some(SyncDirection::Pull),
                        "--watch" | "-w" => watch = true,
                        other => {
                            return Ok(CommandOutput::fail(
                                format!("sync add: unknown flag `{other}`"),
                                Some("usage: sync add <drive> [--push | --pull] [--watch]".into()),
                            ))
                        }
                    }
                }
                let rule = client
                    .configure_sync(&user_id, drive, direction, watch)
                    .await
                    .map_err(|e| anyhow::anyhow!("sync add: {e}"))?;
                return Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: format!(
                        "sync rule kept — {}{}",
                        direction_said(&rule.direction),
                        if rule.watch { ", watching" } else { "" }
                    ),
                    subject: rule.drive,
                }]));
            }
            [sub] if sub == "list" => {
                let rules = client
                    .list_sync_rules(&user_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("sync list: {e}"))?;
                let rows: Vec<Vec<String>> = rules
                    .iter()
                    .map(|r| {
                        vec![
                            if r.drive.is_empty() { format!("(no longer a drive here: {})", r.vault_key) } else { r.drive.clone() },
                            direction_said(&r.direction).to_string(),
                            if r.watch { "yes" } else { "no" }.to_string(),
                        ]
                    })
                    .collect();
                return Ok(CommandOutput::shapes(vec![Out::Table {
                    columns: vec!["drive".into(), "direction".into(), "watch".into()],
                    rows,
                }]));
            }
            [sub, drive] if sub == "remove" => {
                client
                    .remove_sync_rule(&user_id, drive)
                    .await
                    .map_err(|e| anyhow::anyhow!("sync remove: {e}"))?;
                return Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "sync rule removed".into(),
                    subject: drive.clone(),
                }]));
            }

            // -- An ad-hoc sync against a named remote ---------------------------
            _ => {}
        }

        // Parse optional direction flag and required remote name.
        let (direction, remote) = match args {
            [flag, remote] if flag == "--push" => (Some(SyncDirection::Push), remote.clone()),
            [flag, remote] if flag == "--pull" => (Some(SyncDirection::Pull), remote.clone()),
            [remote] if !remote.starts_with('-') => (None, remote.clone()),
            _ => {
                return Ok(CommandOutput::fail(
                    "usage: sync [--push | --pull] <remote>",
                    Some("--push local→remote, --pull remote→local, none = two-way".into()),
                ))
            }
        };

        let dir_label = match &direction {
            Some(SyncDirection::Push) => " [push]",
            Some(SyncDirection::Pull) => " [pull]",
            None => " [bidirectional]",
        };

        match client
            .sync_mount(&user_id, "local", &remote, direction)
            .await
        {
            Ok(result) => {
                let mut out = vec![
                    Out::Confirm {
                        action: format!("synced{dir_label}"),
                        subject: remote.clone(),
                    },
                    Out::Record(vec![
                        ("pushed".into(), result.pushed.to_string()),
                        ("pulled".into(), result.pulled.to_string()),
                        ("skipped".into(), result.skipped.to_string()),
                    ]),
                ];
                if !result.transfers.is_empty() {
                    let rows: Vec<Vec<String>> = result
                        .transfers
                        .iter()
                        .map(|(dir, key, bytes)| {
                            let dir_str = match dir {
                                SyncDirection::Push => "push",
                                SyncDirection::Pull => "pull",
                            };
                            vec![dir_str.to_string(), bytes.to_string(), key.clone()]
                        })
                        .collect();
                    out.push(Out::Table {
                        columns: vec!["dir".into(), "bytes".into(), "key".into()],
                        rows,
                    });
                }
                Ok(CommandOutput::shapes(out))
            }
            Err(e) => Ok(CommandOutput::fail(format!("sync: {e}"), None)),
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["--push", "--pull", "--watch"]
    }

    fn help_text(&self) -> &'static str {
        HELP
    }
}

/// A rule's direction, as a person reads it.
fn direction_said(direction: &Option<SyncDirection>) -> &'static str {
    match direction {
        Some(SyncDirection::Push) => "push",
        Some(SyncDirection::Pull) => "pull",
        None => "both ways",
    }
}

pub(crate) const HELP: &str = "\
sync — keep this device's drives current

USAGE:
  sync [now] [--no-wait]                       sync this device's drives now
  sync [--push | --pull] <remote>              run an ad-hoc sync against a drive or a remote
  sync add <drive> [--push | --pull] [--watch] keep this device's rule for a drive
  sync list                                    list this device's rules
  sync remove <drive>                          remove the rule for a drive

A device syncs to your drives, never to another device: your other devices
get what this one writes by way of a drive.

FLAGS:
  --push    this device sends to the drive only
  --pull    this device takes from the drive only
  (none)    both ways, last-write-wins by modified timestamp
  --watch   sync the drive in the background as well as when asked

EXAMPLES:
  sync                                 # every drive, now
  sync add vault --watch               # keep 'vault' current in the background
  sync add vault --pull                # this device only takes from 'vault'
  sync list                            # show this device's rules
  sync remove vault                    # drop the rule for 'vault'

NOTES:
  The local 'local' mount is always the sync source/destination.
  A drive is named by its node's id, the `id` column of 'device list'.";
