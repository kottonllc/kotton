// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton sidecars` — show sidecar process state.
//!
//! ```text
//! kotton sidecars [--user <id>]
//! ```
//!
//! Prints a table of every process in the kuserd supervision tree.

use clap::Parser;
use kotton_wire::ipc::SidecarInfo;
use kotton::KottonClient;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
pub struct SidecarsCommand {
    /// User ID to authenticate as.
    #[arg(long)]
    user: String,
}

impl SidecarsCommand {
    pub async fn execute(&self) -> io::Result<()> {
        let mut client = KottonClient::connect_as(&self.user).await?;
        let sidecars = client.daemon_sidecars().await?;
        print_sidecars_table(&sidecars);
        Ok(())
    }
}

fn print_sidecars_table(sidecars: &[SidecarInfo]) {
    // Column widths (padded).
    let w_proc = sidecars
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let w_role = sidecars
        .iter()
        .map(|s| s.role.len())
        .max()
        .unwrap_or(4)
        .max(4);

    // Header
    println!(
        "{:<w_proc$}  {:<w_role$}  {:<7}  {:<8}  {:<6}  {:<8}  UPTIME",
        "PROCESS",
        "ROLE",
        "RUNNING",
        "PID",
        "PORT",
        "RESTARTS",
        w_proc = w_proc,
        w_role = w_role
    );
    println!("{}", "─".repeat(w_proc + w_role + 52));

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for s in sidecars {
        let running = if s.running { "yes" } else { "no" };
        let pid = s
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());
        let port = s
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());
        // kuserd restart_count is always 0 — display as "—".
        let restarts = if s.name == "kuserd" {
            "—".to_string()
        } else {
            s.restart_count.to_string()
        };
        let uptime = s
            .started_at
            .map(|ts| format_duration(now_secs.saturating_sub(ts)))
            .unwrap_or_else(|| "—".to_string());

        println!(
            "{:<w_proc$}  {:<w_role$}  {:<7}  {:<8}  {:<6}  {:<8}  {}",
            s.name,
            s.role,
            running,
            pid,
            port,
            restarts,
            uptime,
            w_proc = w_proc,
            w_role = w_role
        );
        if let Some(reason) = &s.failed {
            println!("{:<w_proc$}  ↳ {}", "", reason, w_proc = w_proc);
        }
    }
}

/// Format a duration in seconds as "Xh Ym" or "Ys" or "—".
fn format_duration(secs: i64) -> String {
    if secs < 0 {
        return "—".to_string();
    }
    let dur = Duration::from_secs(secs as u64);
    let h = dur.as_secs() / 3600;
    let m = (dur.as_secs() % 3600) / 60;
    let s = dur.as_secs() % 60;

    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}
