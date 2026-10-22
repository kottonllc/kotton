// SPDX-License-Identifier: AGPL-3.0-or-later
//! Transport instantiation helpers
//!
//! Handles creating and configuring transport implementations from TransportConfig.

use crate::config::TransportConfig;
use anyhow::Result;
use kotton_sys::net::{Listener, Transport};
use kotton_diag::{Event, EventBus, EventCategory, EventLevel};
use std::sync::Arc;

/// Transport instantiation result
pub struct TransportInstance {
    pub transport: Box<dyn Transport>,
    pub listener: Option<Box<dyn Listener>>,
    pub name: String,
}

/// Instantiate a transport from configuration
pub async fn instantiate_transport(
    transport_config: &TransportConfig,
    event_bus: &Arc<EventBus>,
) -> Result<TransportInstance> {
    match transport_config {
        TransportConfig::Tcp {
            listen_addr,
            tls: _,
        } => {
            use kotton_net::TcpTransport;

            // TODO: Pass TLS config to TcpTransport
            let transport = TcpTransport::new();

            // Start listener
            let addr = kotton_sys::net::Address::Tcp(*listen_addr);
            let listener = match transport.listen(&addr).await {
                Ok(listener) => {
                    event_bus
                        .publish(Event::new(
                            EventCategory::Network,
                            EventLevel::Info,
                            format!("TCP transport listening on {}", listen_addr),
                        ))
                        .ok();
                    Some(listener)
                }
                Err(e) => {
                    event_bus
                        .publish(Event::new(
                            EventCategory::Network,
                            EventLevel::Error,
                            format!("Failed to start TCP listener: {}", e),
                        ))
                        .ok();
                    None
                }
            };

            Ok(TransportInstance {
                transport: Box::new(transport) as Box<dyn Transport>,
                listener,
                name: format!("TCP({})", listen_addr),
            })
        }

        TransportConfig::Quic {
            listen_addr,
            ephemeral: _,
            cert_key_id: _,
        } => {
            use kotton_net::QuicTransport;

            // TODO: Implement ephemeral cert generation and cert loading from secrets
            let transport = QuicTransport::new()
                .map_err(|e| anyhow::anyhow!("Failed to create QUIC transport: {}", e))?;

            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Info,
                    format!("QUIC transport initialized on {}", listen_addr),
                ))
                .ok();

            Ok(TransportInstance {
                transport: Box::new(transport) as Box<dyn Transport>,
                listener: None, // TODO: Add QUIC listener support
                name: format!("QUIC({})", listen_addr),
            })
        }

        TransportConfig::WebSocket {
            listen_addr,
            endpoint: _,
            auth: _,
        } => {
            use kotton_net::WebSocketTransport;

            let transport = if listen_addr.is_some() {
                WebSocketTransport::with_server()
            } else {
                WebSocketTransport::new()
            };

            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Info,
                    format!(
                        "WebSocket transport initialized (server: {})",
                        listen_addr.is_some()
                    ),
                ))
                .ok();

            Ok(TransportInstance {
                transport: Box::new(transport) as Box<dyn Transport>,
                listener: None, // TODO: Add WebSocket listener support
                name: "WebSocket".to_string(),
            })
        }

        TransportConfig::Bluetooth {
            service_uuid: _,
            adapter: _,
        } => {
            use kotton_net::BluetoothTransport;

            let transport = BluetoothTransport;

            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Debug,
                    "Bluetooth transport registered (stub - not yet implemented)",
                ))
                .ok();

            Ok(TransportInstance {
                transport: Box::new(transport) as Box<dyn Transport>,
                listener: None,
                name: "Bluetooth".to_string(),
            })
        }

        TransportConfig::WebRtc {
            stun_servers: _,
            turn_servers: _,
            signaling_url: _,
        } => {
            use kotton_net::WebRtcTransport;

            let transport = WebRtcTransport;

            event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Debug,
                    "WebRTC transport registered (stub - not yet implemented)",
                ))
                .ok();

            Ok(TransportInstance {
                transport: Box::new(transport) as Box<dyn Transport>,
                listener: None,
                name: "WebRTC".to_string(),
            })
        }
    }
}
