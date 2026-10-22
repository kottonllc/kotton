// SPDX-License-Identifier: AGPL-3.0-or-later
//! Transport layer abstraction
//!
//! Separates "how to establish connections" from "active connection channel".
//! Each transport protocol (TCP, Bluetooth, WebRTC) has different connection semantics.
//!
//! ## Design
//!
//! - **Transport**: How to connect to peers (trait defined here)
//! - **Connection**: Active bidirectional channel (defined in connection.rs)
//! - **Address**: Where to connect (defined in address.rs)
//!
//! ## Example
//!
//! ```rust,no_run
//! use kotton_sys::net::{Transport, Address};
//!
//! async fn connect_example(transport: &dyn Transport) {
//!     let addr = Address::Tcp("127.0.0.1:8080".parse().unwrap());
//!     let connection = transport.connect(&addr).await.unwrap();
//!     // Now have active Connection trait object
//! }
//! ```

use super::address::{Address, AddressType};
use super::connection::Connection;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

pub type TransportResult<T> = Result<T, TransportError>;

/// Transport layer abstraction
///
/// Transports know how to establish connections to peers via different protocols.
/// Each transport supports specific address types and may or may not support listening.
#[async_trait]
pub trait Transport: Send + Sync {
    /// What address types can this transport connect to?
    ///
    /// Example: TcpTransport returns `[AddressType::Tcp]`
    fn supported_address_types(&self) -> &[AddressType];

    /// Can this transport listen for incoming connections?
    ///
    /// Some transports are client-only (e.g., HTTP client).
    fn supports_listening(&self) -> bool;

    /// Establish connection to peer at given address
    ///
    /// Returns active Connection trait object for bidirectional communication.
    ///
    /// # Errors
    ///
    /// - `UnsupportedAddress` if address type not in supported_address_types()
    /// - `ConnectionFailed` if network error during connection
    /// - `Unavailable` if transport hardware/software not available
    async fn connect(&self, address: &Address) -> TransportResult<Box<dyn Connection>>;

    /// Start listening for incoming connections (if supported)
    ///
    /// Returns Listener trait object that can accept() incoming connections.
    ///
    /// # Errors
    ///
    /// - `ListeningNotSupported` if supports_listening() returns false
    /// - `UnsupportedAddress` if address type invalid for listening
    /// - `Unavailable` if cannot bind to address (port in use, etc.)
    async fn listen(&self, bind_addr: &Address) -> TransportResult<Box<dyn Listener>>;

    /// Detect if this transport is available on this device
    ///
    /// Probes hardware/OS capabilities to determine availability.
    /// Called once at startup for capability detection.
    ///
    /// Example checks:
    /// - TCP: Try binding ephemeral port
    /// - Bluetooth: Check if adapter present
    /// - WebRTC: Check if libwebrtc loaded
    fn detect_capability() -> TransportCapability
    where
        Self: Sized;
}

/// Listener for incoming connections
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accept next incoming connection
    ///
    /// Blocks until a connection arrives or listener is closed.
    async fn accept(&self) -> TransportResult<Box<dyn Connection>>;

    /// Local address being listened on
    ///
    /// May differ from bind address (e.g., if port was 0, OS assigns ephemeral port).
    fn local_addr(&self) -> &Address;

    /// Stop listening and close socket
    ///
    /// After close(), accept() will return errors.
    async fn close(&self) -> TransportResult<()>;
}

/// Transport capability detection result
#[derive(Debug, Clone)]
pub struct TransportCapability {
    /// Is this transport available on this device?
    pub available: bool,

    /// If unavailable, why? (optional explanation)
    pub reason: Option<String>,

    /// Transport-specific metadata
    ///
    /// Examples:
    /// - Bluetooth: {"adapter": "hci0", "version": "5.0"}
    /// - TCP: {"max_connections": "1024"}
    pub metadata: HashMap<String, String>,
}

impl TransportCapability {
    /// Create an available capability
    pub fn available() -> Self {
        Self {
            available: true,
            reason: None,
            metadata: HashMap::new(),
        }
    }

    /// Create an unavailable capability with reason
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            reason: Some(reason.into()),
            metadata: HashMap::new(),
        }
    }

    /// Add metadata key-value pair
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Transport errors
#[derive(Debug, Error)]
pub enum TransportError {
    /// Address type not supported by this transport
    #[error("Unsupported address type: {0}")]
    UnsupportedAddress(AddressType),

    /// Transport does not support listening for incoming connections
    #[error("This transport does not support listening for incoming connections")]
    ListeningNotSupported,

    /// Failed to establish connection
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Transport unavailable (hardware/software not present)
    #[error("Transport unavailable: {0}")]
    Unavailable(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Listener is closed
    #[error("Listener is closed")]
    ListenerClosed,

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl fmt::Display for TransportCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.available {
            write!(f, "Available")?;
        } else {
            write!(f, "Unavailable")?;
            if let Some(ref reason) = self.reason {
                write!(f, " ({})", reason)?;
            }
        }

        if !self.metadata.is_empty() {
            write!(f, " [")?;
            for (i, (k, v)) in self.metadata.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}={}", k, v)?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_available() {
        let cap = TransportCapability::available();
        assert!(cap.available);
        assert!(cap.reason.is_none());
        assert!(cap.metadata.is_empty());
    }

    #[test]
    fn test_capability_unavailable() {
        let cap = TransportCapability::unavailable("Hardware not found");
        assert!(!cap.available);
        assert_eq!(cap.reason, Some("Hardware not found".to_string()));
    }

    #[test]
    fn test_capability_with_metadata() {
        let cap = TransportCapability::available()
            .with_metadata("adapter", "hci0")
            .with_metadata("version", "5.0");

        assert!(cap.available);
        assert_eq!(cap.metadata.get("adapter"), Some(&"hci0".to_string()));
        assert_eq!(cap.metadata.get("version"), Some(&"5.0".to_string()));
    }

    #[test]
    fn test_capability_display() {
        let cap = TransportCapability::available().with_metadata("adapter", "eth0");
        assert!(cap.to_string().contains("Available"));
        assert!(cap.to_string().contains("adapter=eth0"));

        let cap = TransportCapability::unavailable("No Bluetooth adapter");
        assert!(cap.to_string().contains("Unavailable"));
        assert!(cap.to_string().contains("No Bluetooth adapter"));
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::UnsupportedAddress(AddressType::Bluetooth);
        assert!(err.to_string().contains("Unsupported address type"));

        let err = TransportError::ListeningNotSupported;
        assert!(err.to_string().contains("does not support listening"));

        let err = TransportError::ConnectionFailed("Timeout".to_string());
        assert!(err.to_string().contains("Connection failed"));
        assert!(err.to_string().contains("Timeout"));
    }
}
