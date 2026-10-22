// SPDX-License-Identifier: AGPL-3.0-or-later
//! A booted device announces nothing on the local network: no standing presence
//! with the door closed.
//!
//! The local-network door is the only thing that may put this device's name on a LAN,
//! and only while the person holds it open (`runtime::network::local_door`). This holds
//! that no `RuntimeConfig` reaches mDNS around it: `full_node`, the preset a standing
//! `_kotton._tcp` registration would come from, starts and holds no socket on
//! `:5353` — the port every mDNS registration and browse binds.
//!
//! The instrument is the process's own socket table, so the test re-runs its own binary
//! filtered to itself and the child holds exactly one runtime and nothing else — the
//! pattern `tests/tests/suite/local_door.rs` sets out. Linux-only: the table is Linux's.

#![cfg(target_os = "linux")]

use crate::config::{RuntimeConfig, TransportConfig};
use crate::runtime::DeviceRuntime;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

const CHILD: &str = "KOTTON_BOOT_ANNOUNCES_NOTHING_CHILD";
const MARK: &str = "BOOT-MDNS-SOCKETS";
/// `:5353` as `/proc/net/udp` writes a local port.
const MDNS_PORT_HEX: &str = ":14E9";

/// Every UDP socket this process holds on `:5353`, as `proto local-address` lines.
fn mdns_sockets_of_this_process() -> Vec<String> {
    let mine: HashSet<String> = std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter_map(|link| {
            let s = link.to_string_lossy().into_owned();
            s.strip_prefix("socket:[")?.strip_suffix(']').map(str::to_owned)
        })
        .collect();
    let mut found = Vec::new();
    for proto in ["udp", "udp6"] {
        let table = std::fs::read_to_string(format!("/proc/self/net/{proto}")).unwrap_or_default();
        for line in table.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 9 && mine.contains(f[9]) && f[1].ends_with(MDNS_PORT_HEX) {
                found.push(format!("{proto} {}", f[1]));
            }
        }
    }
    found
}

/// `full_node` boots, and nothing on `:5353` is ever held: no mDNS registration, no
/// browse, no discovery mechanism at all.
#[tokio::test]
async fn the_full_node_preset_boots_and_registers_no_mdns_service() {
    if std::env::var_os(CHILD).is_some() {
        // The preset as shipped, with its listener moved to an ephemeral loopback port
        // so the test does not contend for 7734. Discovery is left exactly as the preset
        // names it — that is the thing under test.
        let temp = tempfile::tempdir().unwrap();
        let mut config = RuntimeConfig::full_node(temp.path().join("store"));
        config.transports = vec![TransportConfig::Tcp {
            listen_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            tls: Default::default(),
        }];
        let runtime = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            config,
            std::sync::Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap();
        runtime.start().await.unwrap();

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..30 {
            seen.extend(mdns_sockets_of_this_process());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!("{MARK} {} discoveries {}", seen.len(), runtime.discovery_count());
        for s in &seen {
            println!("  {s}");
        }
        assert!(seen.is_empty(), "full_node holds mDNS sockets: {seen:?}");
        assert_eq!(runtime.discovery_count(), 0, "full_node started a discovery mechanism");
        return;
    }

    let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "runtime::boot_announces_nothing_tests::the_full_node_preset_boots_and_registers_no_mdns_service",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("{MARK} 0 discoveries 0")),
        "the child did not report a clean boot (exit {:?}):\n{stdout}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "the child failed:\n{stdout}");
}
