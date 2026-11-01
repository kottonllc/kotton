// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::{bail, Result};
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// logs — view or stream daemon event logs.
///
/// One verb, two doors: the REPL's `logs` and the terminal's `kotton logs` (the CLI's
/// `bridge::run_verb`) run this one parser on the same words, as the identity each door
/// acts as, so the two answer alike (kotton #355).
///
/// Usage:
///   logs [OPTIONS]
///
/// Options:
///   --level <level>     Minimum log level: trace, debug, info, warn, error (default: info)
///   --category <cat>    Filter by category: vfs, wasm, system, ipc, sync, auth, network, database, storage
///   --since <secs>      Only show events newer than N seconds ago
///   -n <count>          Number of historical entries to show (default: 50; max 500)
///   -f, --follow        Follow live events (streams in real-time; Ctrl-C to stop)
pub struct LogsCommand;

#[async_trait]
impl Command for LogsCommand {
    fn help_text(&self) -> &'static str {
        "logs — view daemon event logs\n\n\
USAGE:\n\
  logs [OPTIONS]\n\n\
OPTIONS:\n\
  --level <level>     Minimum level: trace, debug, info, warn, error  (default: info)\n\
  --category <cat>    Filter by category (e.g. wasm, vfs, auth)\n\
  --since <secs>      Only events from the last N seconds\n\
  -n <count>          Number of entries to show  (default: 50)\n\
  -f, --follow        Stream live events (Ctrl-C to stop)\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        // ── Parse arguments ──────────────────────────────────────────────
        let mut level: Option<String> = Some("info".to_string());
        let mut category: Option<String> = None;
        let mut since_secs: Option<u64> = None;
        let mut count: u32 = 50;
        let mut follow = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--level" => {
                    i += 1;
                    level = args.get(i).cloned();
                }
                "--category" => {
                    i += 1;
                    category = args.get(i).cloned();
                }
                "--since" => {
                    i += 1;
                    match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                        Some(n) => since_secs = Some(n),
                        None => bail!("--since expects a number of seconds"),
                    }
                }
                "-n" => {
                    i += 1;
                    match args.get(i).and_then(|v| v.parse::<u32>().ok()) {
                        Some(n) => count = n,
                        None => bail!("-n expects a positive integer"),
                    }
                }
                "-f" | "--follow" => follow = true,
                other => bail!("unknown argument: {other}"),
            }
            i += 1;
        }

        // Convert --since <secs> to a Unix-seconds cursor.
        let since_ts: Option<i64> = since_secs.map(|s| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(s) as i64
        });

        if follow {
            // ── Streaming mode — frames render live through the emit sink ──
            let mut rx = state
                .client
                .lock()
                .await
                .subscribe_events(category.clone(), level.clone())
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            state.emit(Out::Hint("streaming live events — Ctrl-C to stop".into()));

            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            // Each line is verbatim log content → the Data payload.
                            Some(entry) => state.emit(Out::Data(entry_line(&entry))),
                            None => break, // daemon closed stream
                        }
                    }
                    _ = tokio::signal::ctrl_c() => break,
                }
            }

            Ok(CommandOutput::success())
        } else {
            // ── Historical query → a table (empty → the renderer's "none yet") ──
            let entries = state
                .client
                .lock()
                .await
                .query_events(category, level, since_ts, Some(count))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let rows: Vec<Vec<String>> = entries.iter().map(entry_row).collect();
            Ok(CommandOutput::shapes(vec![Out::Table {
                columns: vec![
                    "time".into(),
                    "level".into(),
                    "category".into(),
                    "message".into(),
                ],
                rows,
            }]))
        }
    }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

/// `time` field of an entry (`yyyy-mm-ddThh:mm:ss`), or `?`.
fn entry_time(entry: &kotton::EventEntry) -> &str {
    entry
        .iso_timestamp
        .as_deref()
        .map(|s| &s[..19])
        .unwrap_or("?")
}

/// A historical entry as table cells: time · level · category · message.
fn entry_row(entry: &kotton::EventEntry) -> Vec<String> {
    vec![
        entry_time(entry).to_string(),
        entry.level.clone(),
        entry.category.clone(),
        entry.message.clone(),
    ]
}

/// A single streamed log line (verbatim, uncolored — the calm palette keeps `red`
/// for the failure marker, not a per-level rainbow).
fn entry_line(entry: &kotton::EventEntry) -> String {
    format!(
        "{}  {:<5}  {:>8}  {}",
        entry_time(entry),
        entry.level,
        entry.category,
        entry.message
    )
}
