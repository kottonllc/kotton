// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton net` — display a network status snapshot.
//!
//! ```text
//! kotton net [--user <id>] [--json]
//! ```
//!
//! Calls `NetworkStatus` and formats a human-readable summary of:
//! - Configured peers with live connection state
//! - QUIC and HTTP gateway summaries
//! - Sync state (last sync, pending changes, ksyncd running)
//! - Rendezvous URL

use clap::Parser;
use kotton_wire::ipc::{GatewaySummary, PeerStatus, RelayReadout, RelayState, SyncStatusResult};
use kotton::{KottonClient, NetworkStatusSummary};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
pub struct NetCommand {
    /// User ID to authenticate as.
    #[arg(long)]
    user: String,
    /// Emit raw JSON instead of human-readable output (for scripting).
    #[arg(long)]
    json: bool,
}

impl NetCommand {
    pub async fn execute(&self) -> io::Result<()> {
        let mut client = KottonClient::connect_as(&self.user).await?;
        let status = client.network_status(&self.user).await?;
        let NetworkStatusSummary {
            peers,
            quic_gateway,
            http_gateway,
            rendezvous_url,
            relay,
            sync,
        } = status;

        if self.json {
            let v = serde_json::json!({
                "peers": peers,
                "quic_gateway": quic_gateway,
                "http_gateway": http_gateway,
                "rendezvous_url": rendezvous_url,
                "relay": relay,
                "sync": sync,
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        } else {
            print_net_status(&peers, &quic_gateway, &http_gateway, rendezvous_url.as_deref(), &relay, &sync);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn print_net_status(
    peers: &[PeerStatus],
    quic_gateway: &GatewaySummary,
    http_gateway: &GatewaySummary,
    rendezvous_url: Option<&str>,
    relay: &RelayReadout,
    sync: &SyncStatusResult,
) {
    let connected_count = peers.iter().filter(|p| p.connected).count();

    // -- Peers ---------------------------------------------------------------
    println!(
        "\nPeers ({} configured, {} connected)",
        peers.len(),
        connected_count
    );
    if peers.is_empty() {
        println!("  (none)");
    } else {
        let w_label = peers.iter().map(|p| p.label.len()).max().unwrap_or(5).max(5);
        let w_did = peers.iter().map(|p| abbrev_did(&p.did).len()).max().unwrap_or(16).max(16);
        for p in peers {
            let icon = if p.connected { "\u{2713}" } else { "\u{2717}" };
            let state = if p.connected { "connected" } else { "offline" };
            let seen = p.last_seen_at.map(format_last_seen).unwrap_or_else(|| "unknown".to_string());
            println!(
                "  {icon}  {label:<w_label$}  {did:<w_did$}  {state:<9}  last seen {seen}",
                label = p.label,
                did = abbrev_did(&p.did),
                w_label = w_label,
                w_did = w_did,
            );
        }
    }

    // -- Gateways ------------------------------------------------------------
    println!("\nGateways");
    print_gateway("QUIC", "kquicd", quic_gateway);
    print_gateway("HTTP", "khttpd", http_gateway);

    // -- Sync ----------------------------------------------------------------
    println!("\nSync");
    if sync.ksyncd_running {
        let last = sync
            .last_sync_at
            .map(format_relative)
            .unwrap_or_else(|| "never".to_string());
        println!("  last sync   {last}");
        match sync.pending_changes {
            Some(n) => println!("  pending     {n} changes"),
            None => println!("  pending     not tracked"),
        }
        // Maintenance is what keeps the history log bounded. A log growing
        // without limit looks exactly like a maintained one until you ask.
        let maint = sync
            .last_maintenance_at
            .map(format_relative)
            .unwrap_or_else(|| "not yet this session".to_string());
        println!("  maintained  {maint}");
        println!("  ksyncd      running");
    } else {
        println!("  ksyncd not running \u{2014} sync inactive");
    }

    // -- Rendezvous ----------------------------------------------------------
    println!("\nRendezvous");
    match rendezvous_url {
        Some(url) => println!("  {url}"),
        None => println!("  (not configured)"),
    }
    // The readout (RFC-0083 R6): a state, and the counts it was read from.
    match relay.state {
        RelayState::None => println!("  relay  none \u{2014} not reachable while every device sleeps"),
        RelayState::Up => println!(
            "  relay  up \u{2014} {} of {} reservations held",
            relay.reservations_live, relay.reservations_wanted
        ),
        RelayState::Down => println!(
            "  relay  down \u{2014} 0 of {} reservations held",
            relay.reservations_wanted
        ),
    }

    println!();
}

fn print_gateway(proto: &str, sidecar: &str, gw: &GatewaySummary) {
    if !gw.enabled {
        println!("  {proto:<4}  ({sidecar})  disabled");
        return;
    }
    let status = if gw.running { "running" } else { "enabled, not running" };
    let addr = match (&gw.bind, &gw.port) {
        (Some(bind), Some(port)) => format!("{bind}:{port}"),
        (None, Some(port)) => format!(":{port}"),
        (Some(bind), None) => bind.clone(),
        _ => String::new(),
    };
    let addr_part = if addr.is_empty() { String::new() } else { format!(" on {addr}") };
    println!("  {proto:<4}  ({sidecar})  {status}{addr_part}");
}

fn abbrev_did(did: &str) -> String {
    // Show first 20 chars of DID string, e.g. "did:key:z6Mk..."
    if did.len() <= 20 {
        did.to_string()
    } else {
        format!("{}…", &did[..20])
    }
}

fn format_relative(ts: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let delta = now.saturating_sub(ts);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        let h = delta / 3600;
        format!("{h}h ago")
    } else {
        let d = delta / 86400;
        format!("{d}d ago")
    }
}

fn format_last_seen(ts: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let delta = now.saturating_sub(ts);
    if delta < 3600 {
        // Show HH:MM:SS for recent connections
        let h = (ts / 3600) % 24;
        let m = (ts / 60) % 60;
        let s = ts % 60;
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format_relative(ts)
    }
}
