// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton ipc` — IPC session inspection sub-commands.
//!
//! ```text
//! kotton ipc sessions [--user <id>]
//! ```

use clap::Subcommand;
use kotton_wire::ipc::IpcSessionInfo;
use kotton::KottonClient;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Subcommand)]
pub enum IpcCommand {
    /// List all currently-authenticated IPC sessions.
    Sessions {
        /// User ID to authenticate as.
        #[arg(long)]
        user: String,
    },
}

impl IpcCommand {
    pub async fn execute(&self) -> io::Result<()> {
        match self {
            IpcCommand::Sessions { user } => sessions(user).await,
        }
    }
}

async fn sessions(user: &str) -> io::Result<()> {
    let mut client = KottonClient::connect_as(user).await?;
    let sessions = client.ipc_sessions().await?;
    print_sessions_table(&sessions);
    Ok(())
}

fn print_sessions_table(sessions: &[IpcSessionInfo]) {
    if sessions.is_empty() {
        println!("(no authenticated sessions)");
        return;
    }

    let w_user = sessions
        .iter()
        .map(|s| s.user_id.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let w_scope = sessions
        .iter()
        .map(|s| {
            s.scope
                .as_deref()
                .map(|v| v.join(", ").len())
                .unwrap_or(6)
        })
        .max()
        .unwrap_or(6)
        .max(6);

    println!(
        "{:<8}  {:<w_user$}  {:<w_scope$}  {:<8}  REQUESTS",
        "TOKEN",
        "USER_ID",
        "SCOPE",
        "SINCE",
        w_user = w_user,
        w_scope = w_scope,
    );
    println!("{}", "\u{2500}".repeat(w_user + w_scope + 36));

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for s in sessions {
        let scope = s
            .scope
            .as_deref()
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "(full)".to_string());
        let since = format_since(s.authenticated_at, now_secs);
        let requests = format_count(s.request_count);

        println!(
            "{:<8}  {:<w_user$}  {:<w_scope$}  {:<8}  {}",
            format!("{}\u{2026}", s.token_prefix),
            s.user_id,
            scope,
            since,
            requests,
            w_user = w_user,
            w_scope = w_scope,
        );
    }
}

/// Render an epoch timestamp as HH:MM:SS wall clock (UTC).
fn format_since(ts: i64, _now: i64) -> String {
    if ts <= 0 {
        return "\u{2014}".to_string();
    }
    let secs_in_day = ts % 86400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Format a u64 with thousands separators (e.g. 1,204).
fn format_count(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
