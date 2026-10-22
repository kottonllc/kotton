// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bluetooth transport stub
//!
//! Placeholder implementation for Bluetooth Low Energy (BLE) transport.
//! Returns unavailable() until proper implementation is added in future milestone.
//!
//! Future implementation will support:
//! - BLE GATT services for peer-to-peer communication
//! - Service discovery via UUID
//! - Platform-specific adapters (Windows WinRT, macOS CoreBluetooth, Linux BlueZ)
//! - Pairing and bonding

use async_trait::async_trait;
use kotton_sys::net::{
    Address, AddressType, Connection, Listener, Transport, TransportCapability, TransportError,
    TransportResult,
};

/// Bluetooth Low Energy transport (stub - not yet implemented)
///
/// This is a placeholder that returns unavailable() for all operations.
/// Validates the Transport abstraction for non-IP addressing.
///
/// # Future Implementation
///
/// Will use platform-specific Bluetooth APIs:
/// - **Windows**: windows-rs WinRT Bluetooth LE APIs
/// - **macOS**: CoreBluetooth bindings
/// - **Linux**: BlueZ D-Bus APIs via btleplug
///
/// Will support:
/// - Service discovery by UUID
/// - GATT characteristic read/write for data transfer
/// - Automatic pairing/bonding
/// - Multiple simultaneous connections
pub struct BluetoothTransport;

impl BluetoothTransport {
    /// Create a new Bluetooth transport (always unavailable for now)
    pub fn new() -> Self {
        Self
    }
}

impl Default for BluetoothTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for BluetoothTransport {
    fn supported_address_types(&self) -> &[AddressType] {
        &[AddressType::Bluetooth]
    }

    fn supports_listening(&self) -> bool {
        false // Will be true once implemented
    }

    async fn connect(&self, address: &Address) -> TransportResult<Box<dyn Connection>> {
        match address {
            Address::Bluetooth { .. } => Err(TransportError::Unavailable(
                "Bluetooth transport not yet implemented".to_string(),
            )),
            _ => Err(TransportError::UnsupportedAddress(address.address_type())),
        }
    }

    async fn listen(&self, _bind_addr: &Address) -> TransportResult<Box<dyn Listener>> {
        Err(TransportError::Unavailable(
            "Bluetooth transport not yet implemented".to_string(),
        ))
    }

    fn detect_capability() -> TransportCapability {
        // TODO: Detect actual Bluetooth adapter presence
        // - Windows: Check WinRT Bluetooth availability
        // - macOS: Check CoreBluetooth availability
        // - Linux: Check BlueZ D-Bus service
        TransportCapability::unavailable("Bluetooth transport not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_sys::net::MacAddress;

    #[test]
    fn test_bluetooth_transport_creation() {
        let transport = BluetoothTransport::new();
        assert_eq!(
            transport.supported_address_types(),
            &[AddressType::Bluetooth]
        );
        assert!(!transport.supports_listening());
    }

    #[test]
    fn test_bluetooth_capability_detection() {
        let cap = BluetoothTransport::detect_capability();
        assert!(!cap.available, "Stub should be unavailable");
        assert!(cap.reason.as_ref().unwrap().contains("not yet implemented"));
    }

    #[tokio::test]
    async fn test_bluetooth_connect_unavailable() {
        let transport = BluetoothTransport::new();
        let addr = Address::Bluetooth {
            mac: MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            service_uuid: None,
        };

        let result = transport.connect(&addr).await;
        assert!(result.is_err());
        if let Err(TransportError::Unavailable(msg)) = result {
            assert!(msg.contains("not yet implemented"));
        } else {
            panic!("Expected Unavailable error");
        }
    }

    #[tokio::test]
    async fn test_bluetooth_listen_unavailable() {
        let transport = BluetoothTransport::new();
        let addr = Address::Bluetooth {
            mac: MacAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            service_uuid: None,
        };

        let result = transport.listen(&addr).await;
        assert!(result.is_err());
        if let Err(TransportError::Unavailable(msg)) = result {
            assert!(msg.contains("not yet implemented"));
        } else {
            panic!("Expected Unavailable error");
        }
    }

    #[tokio::test]
    async fn test_bluetooth_unsupported_address() {
        let transport = BluetoothTransport::new();
        let addr = Address::Tcp("127.0.0.1:8080".parse().unwrap());

        let result = transport.connect(&addr).await;
        assert!(result.is_err());
        if let Err(TransportError::UnsupportedAddress(addr_type)) = result {
            assert_eq!(addr_type, AddressType::Tcp);
        } else {
            panic!("Expected UnsupportedAddress error");
        }
    }
}
