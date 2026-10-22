// SPDX-License-Identifier: AGPL-3.0-or-later
//! Multi-transport integration test for `DeviceRuntime`.
//!
//! It starts a runtime with TCP and QUIC together, which only this crate can
//! set up.

/// Multi-transport runtime integration test
use crate::config::{RuntimeConfig, TransportConfig};
use crate::runtime::DeviceRuntime;
use std::net::{Ipv4Addr, SocketAddr};

#[tokio::test]
async fn test_runtime_multiple_transports() -> anyhow::Result<()> {
    // Install rustls crypto provider (required for QUIC)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Configure runtime with TCP and QUIC transports
    let mut config = RuntimeConfig::full_node(std::env::temp_dir());
    config.transports = vec![
        TransportConfig::Tcp {
            listen_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            tls: Default::default(),
        },
        TransportConfig::Quic {
            listen_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            ephemeral: true,
            cert_key_id: None,
        },
    ];

    // Create and start runtime
    let temp = tempfile::tempdir()?;
    let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await?;
    runtime.start().await?;

    // Verify both transports were instantiated
    assert_eq!(
        runtime.transport_count(),
        2,
        "Should have TCP and QUIC transports"
    );

    // Verify no active connections yet
    assert_eq!(
        runtime.connection_count().await,
        0,
        "Should have no connections on startup"
    );

    Ok(())
}

#[tokio::test]
async fn test_runtime_websocket_transport() -> anyhow::Result<()> {
    use url::Url;

    // Configure runtime with WebSocket transport only
    let mut config = RuntimeConfig::relay_only();
    config.transports = vec![TransportConfig::WebSocket {
        listen_addr: Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)),
        endpoint: Some(Url::parse("ws://localhost:8080")?),
        auth: None,
    }];

    // Create and start runtime
    let temp = tempfile::tempdir()?;
    let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await?;
    runtime.start().await?;

    // Verify WebSocket transport was instantiated
    assert_eq!(
        runtime.transport_count(),
        1,
        "Should have WebSocket transport"
    );

    Ok(())
}

#[tokio::test]
async fn test_runtime_stubbed_transports() -> anyhow::Result<()> {
    // Configure runtime with stubbed transports (Bluetooth, WebRTC)
    let config = RuntimeConfig {
        transports: vec![
            TransportConfig::Bluetooth {
                service_uuid: "00001101-0000-1000-8000-00805f9b34fb".to_string(),
                adapter: None,
            },
            TransportConfig::WebRtc {
                stun_servers: vec![],
                turn_servers: vec![],
                signaling_url: url::Url::parse("ws://localhost:8081")?,
            },
        ],
        ..Default::default()
    };

    // Create and start runtime
    let temp = tempfile::tempdir()?;
    let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new())).await?;
    runtime.start().await?;

    // Verify stubbed transports were instantiated
    assert_eq!(
        runtime.transport_count(),
        2,
        "Should have Bluetooth and WebRTC stubs"
    );

    Ok(())
}

#[tokio::test]
async fn test_runtime_manual_discovery() {
    use crate::runtime::DeviceRuntime;
    use crate::{DiscoveryMethod, RuntimeConfig};
    use std::net::SocketAddr;

    let config = RuntimeConfig {
        discovery: vec![DiscoveryMethod::Manual {
            peers: vec![
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:8001".parse::<SocketAddr>().unwrap(),
            ],
        }],
        ..Default::default()
    };

    let temp = tempfile::tempdir().unwrap();
    let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new()))
        .await
        .unwrap();
    runtime.start().await.unwrap();

    // Verify runtime has 1 discovery mechanism
    assert_eq!(runtime.discovery_count(), 1);
}

#[tokio::test]
async fn test_runtime_multiple_discoveries() {
    use crate::runtime::DeviceRuntime;
    use crate::{DiscoveryMethod, RuntimeConfig};
    use std::net::SocketAddr;

    let config = RuntimeConfig {
        discovery: vec![
            DiscoveryMethod::Manual {
                peers: vec!["127.0.0.1:8000".parse::<SocketAddr>().unwrap()],
            },
            DiscoveryMethod::Manual {
                peers: vec!["127.0.0.1:8001".parse::<SocketAddr>().unwrap()],
            },
        ],
        ..Default::default()
    };

    let temp = tempfile::tempdir().unwrap();
    let runtime = DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), config, std::sync::Arc::new(kotton_secret::MemorySecrets::new()))
        .await
        .unwrap();
    runtime.start().await.unwrap();

    // Verify runtime has 2 discovery mechanisms
    assert_eq!(runtime.discovery_count(), 2);
}
