// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton::SyncDirection;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// sync — synchronise the local mount with a named remote, or manage sync rules.
///
/// Usage:
/// ```text
///   sync [--push | --pull] <remote>
///   sync add <node> <path> [--watch]
///   sync list
///   sync remove <node> <path>
/// ```
///
/// With no direction flag the sync is bidirectional (last-write-wins).
pub struct SyncCommand;

#[async_trait]
impl Command for SyncCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;

        // No args → sync with every paired device (your own machines), two-way.
        // A paired node is a remote by its id — the daemon opens it when named
        // (`files::sync_mount`), so this loop names each and nothing more. This
        // is the demo verb: write a file, run `sync`, it's on your other device.
        if args.is_empty() {
            let nodes = client
                .list_nodes(&user_id)
                .await
                .map_err(|e| anyhow::anyhow!("sync: {e}"))?;
            if nodes.is_empty() {
                return Ok(CommandOutput::shapes(vec![Out::Note(
                    "no paired devices yet — run `device add <name>` to add one".to_string(),
                )]));
            }
            let mut rows = Vec::new();
            for n in &nodes {
                match client.sync_mount(&user_id, "local", &n.id, None).await {
                    Ok(r) => rows.push(vec![
                        n.id.clone(),
                        r.pushed.to_string(),
                        r.pulled.to_string(),
                        r.skipped.to_string(),
                    ]),
                    Err(e) => rows.push(vec![n.id.clone(), format!("error: {e}"), String::new(), String::new()]),
                }
            }
            return Ok(CommandOutput::shapes(vec![Out::Table {
                columns: vec![
                    "device".into(),
                    "pushed".into(),
                    "pulled".into(),
                    "skipped".into(),
                ],
                rows,
            }]));
        }

        // `sync now [--node <id>] [--no-wait]` — trigger the daemon's sync engine
        // (the configured rules), rather than the client-driven per-device pass the
        // no-arg `sync` runs. Unified from the former `kotton sync now` (Pillar 4).
        if args.first().map(String::as_str) == Some("now") {
            let node = args
                .windows(2)
                .find(|w| w[0] == "--node")
                .map(|w| w[1].clone());
            let no_wait = args.iter().any(|a| a == "--no-wait" || a == "-n");
            let job_id = client
                .sync_trigger(&user_id, node.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("sync now: {e}"))?;
            if no_wait {
                return Ok(CommandOutput::shapes(vec![Out::Note(format!(
                    "sync enqueued (job {job_id})"
                ))]));
            }
            let outcome = client
                .sync_await(&user_id, job_id, 60)
                .await
                .map_err(|e| anyhow::anyhow!("sync now: {e}"))?;
            let shape = if outcome.files == 0 && outcome.records == 0 {
                Out::Note("already in sync".into())
            } else {
                Out::Confirm {
                    action: format!(
                        "synced {} file(s), {} record(s), {} bytes",
                        outcome.files, outcome.records, outcome.bytes
                    ),
                    subject: String::new(),
                }
            };
            return Ok(CommandOutput::shapes(vec![shape]));
        }

        match args {
            // -- Sync rule subcommands -------------------------------------------
            [sub, node, path] if sub == "add" => {
                let rule = client
                    .configure_sync(&user_id, node, path, false)
                    .await
                    .map_err(|e| anyhow::anyhow!("sync add: {e}"))?;
                return Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "sync rule added".into(),
                    subject: format!("{}:{}", rule.node_id, rule.path),
                }]));
            }
            [sub, node, path, flag]
                if sub == "add" && (flag == "--watch" || flag == "-w") =>
            {
                let rule = client
                    .configure_sync(&user_id, node, path, true)
                    .await
                    .map_err(|e| anyhow::anyhow!("sync add: {e}"))?;
                return Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "sync rule added (watching)".into(),
                    subject: format!("{}:{}", rule.node_id, rule.path),
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
                            r.node_id.clone(),
                            r.path.clone(),
                            if r.watch { "yes" } else { "no" }.to_string(),
                        ]
                    })
                    .collect();
                return Ok(CommandOutput::shapes(vec![Out::Table {
                    columns: vec!["node".into(), "path".into(), "watch".into()],
                    rows,
                }]));
            }
            [sub, node, path] if sub == "remove" => {
                client
                    .remove_sync_rule(&user_id, node, path)
                    .await
                    .map_err(|e| anyhow::anyhow!("sync remove: {e}"))?;
                return Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "sync rule removed".into(),
                    subject: format!("{node}:{path}"),
                }]));
            }

            // -- Legacy remote-backend sync ----------------------------------------
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

pub(crate) const HELP: &str = "\
sync — sync your files across your devices, or against a named remote

USAGE:
  sync                              sync with all your paired devices (two-way)
  sync now [--node <id>] [--no-wait]  trigger the sync engine over your rules
  sync [--push | --pull] <remote>   run an ad-hoc sync against a named remote
  sync add <node> <path> [--watch]  add/update a background sync rule
  sync list                         list sync rules
  sync remove <node> <path>         remove a sync rule

FLAGS (ad-hoc sync):
  --push    transfer local → remote only
  --pull    transfer remote → local only
  (none)    bidirectional, last-write-wins by modified timestamp

FLAGS (add):
  --watch   enable filesystem-watch continuous sync

EXAMPLES:
  sync s3-backup                               # two-way sync with 's3-backup'
  sync --push s3-backup                        # push local changes only
  sync add my-vps /notes --watch         # continuous sync of /notes
  sync list                                    # show all rules
  sync remove my-vps /notes                    # remove the rule

NOTES:
  The local 'local' mount is always the sync source/destination.
  A paired peer's <remote> is the `remote` column of 'peer list'.";
