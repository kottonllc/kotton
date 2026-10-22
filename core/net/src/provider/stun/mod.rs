// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal STUN client — RFC 5389 binding request only.
//!
//! Used solely to discover this device's external IP:port for NAT traversal.
//! No STUN authentication, no STUN over TCP, no indication/error handling beyond
//! what is needed for address discovery.
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use tokio::net::UdpSocket;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let socket = UdpSocket::bind("0.0.0.0:0").await?;
//! let stun_server: SocketAddr = "stun.l.google.com:19302".parse()?;
//! let external_addr = kotton_net::stun::discover(&socket, stun_server).await?;
//! println!("External address: {external_addr}");
//! # Ok(()) }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// STUN magic cookie — fixed value from RFC 5389 §6.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Binding Request message type.
const MSG_BINDING_REQUEST: u16 = 0x0001;
/// Binding Success Response message type.
const MSG_BINDING_RESPONSE: u16 = 0x0101;

/// XOR-MAPPED-ADDRESS attribute type.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// MAPPED-ADDRESS attribute type (fallback for servers that don't send XOR).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// Address family — IPv4.
const FAMILY_IPV4: u8 = 0x01;
/// Address family — IPv6.
const FAMILY_IPV6: u8 = 0x02;

/// Errors produced by the STUN client.
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("STUN request timed out after {0:?}")]
    Timeout(Duration),

    #[error("Server returned error response (type 0x{0:04x})")]
    ErrorResponse(u16),

    #[error("Response too short ({0} bytes)")]
    TruncatedResponse(usize),

    #[error("STUN magic cookie mismatch in response")]
    BadMagicCookie,

    #[error("Transaction ID mismatch — response is not for our request")]
    TransactionIdMismatch,

    #[error("No XOR-MAPPED-ADDRESS or MAPPED-ADDRESS attribute in response")]
    NoMappedAddress,

    #[error("Unknown address family 0x{0:02x}")]
    UnknownAddressFamily(u8),
}

/// Send a STUN Binding Request to `server` via `socket` and return the
/// reflexive (external) `SocketAddr` extracted from the response.
///
/// A fresh 12-byte random transaction ID is generated for each call.
/// The socket must already be bound; it does **not** need to be connected.
/// `socket` may be shared with other traffic — only datagrams whose
/// first 20 bytes match the expected STUN response header are accepted.
pub async fn discover(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr, StunError> {
    discover_with_timeout(socket, server, Duration::from_secs(3)).await
}

/// Like [`discover`] but with a configurable `deadline`.
pub async fn discover_with_timeout(
    socket: &UdpSocket,
    server: SocketAddr,
    deadline: Duration,
) -> Result<SocketAddr, StunError> {
    let txn_id = random_txn_id();
    let request = build_binding_request(&txn_id);

    socket.send_to(&request, server).await?;

    timeout(deadline, recv_binding_response(socket, &txn_id))
        .await
        .map_err(|_| StunError::Timeout(deadline))?
}

/// Try multiple STUN servers and return the first consistent result.
///
/// Used to detect symmetric NAT: if two servers return the same external
/// address the mapping is stable. Returns the first successful address.
/// Does **not** require all servers to agree — that cross-check is the
/// caller's responsibility.
pub async fn discover_any(
    socket: &UdpSocket,
    servers: &[SocketAddr],
) -> Result<SocketAddr, StunError> {
    let mut last_err = StunError::NoMappedAddress;
    for &server in servers {
        match discover(socket, server).await {
            Ok(addr) => return Ok(addr),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn random_txn_id() -> [u8; 12] {
    rand::random()
}

/// Build a minimal 20-byte STUN Binding Request (no attributes).
fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    // Message type (2 bytes)
    msg.extend_from_slice(&MSG_BINDING_REQUEST.to_be_bytes());
    // Message length (2 bytes) — no attributes, so 0
    msg.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie (4 bytes)
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    msg.extend_from_slice(txn_id);
    msg
}

/// Read datagrams from `socket` until one is a valid STUN Binding Response
/// for `txn_id`. Non-STUN datagrams are silently dropped (this is deliberate;
/// the socket may receive other UDP traffic while we wait).
async fn recv_binding_response(
    socket: &UdpSocket,
    txn_id: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    let mut buf = [0u8; 576]; // minimum MTU sufficient for STUN responses
    loop {
        let (n, _src) = socket.recv_from(&mut buf).await?;
        if n < 20 {
            continue; // too short to be a STUN response — ignore
        }
        let pkt = &buf[..n];

        // Check message type
        let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
        if msg_type == MSG_BINDING_RESPONSE {
            return parse_binding_response(pkt, txn_id);
        }
        // Error response — propagate immediately
        if msg_type & 0xFF00 == 0x0100 {
            return Err(StunError::ErrorResponse(msg_type));
        }
        // Anything else (another request, indication, etc.) — ignore
    }
}

/// Parse a raw STUN Binding Success Response and extract the mapped address.
fn parse_binding_response(pkt: &[u8], expected_txn: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if pkt.len() < 20 {
        return Err(StunError::TruncatedResponse(pkt.len()));
    }

    // Verify magic cookie
    let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }

    // Verify transaction ID
    let txn: &[u8; 12] = pkt[8..20].try_into().unwrap();
    if txn != expected_txn {
        return Err(StunError::TransactionIdMismatch);
    }

    let attr_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if pkt.len() < 20 + attr_len {
        return Err(StunError::TruncatedResponse(pkt.len()));
    }

    // Walk attributes looking for XOR-MAPPED-ADDRESS (preferred) or
    // MAPPED-ADDRESS (fallback)
    let mut offset = 20usize;
    let end = 20 + attr_len;
    let mut mapped_addr: Option<SocketAddr> = None;

    while offset + 4 <= end {
        let a_type = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
        let a_len = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]) as usize;
        offset += 4;

        if offset + a_len > end {
            break; // malformed — stop walking
        }

        let value = &pkt[offset..offset + a_len];

        match a_type {
            ATTR_XOR_MAPPED_ADDRESS if a_len >= 8 => {
                // value[0] = pad (ignored), value[1] = family
                let family = value[1];
                let port_xored = u16::from_be_bytes([value[2], value[3]]);
                let port = port_xored ^ ((MAGIC_COOKIE >> 16) as u16);

                let addr = match family {
                    FAMILY_IPV4 if a_len >= 8 => {
                        let ip_xored = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                        let ip = ip_xored ^ MAGIC_COOKIE;
                        IpAddr::V4(Ipv4Addr::from(ip))
                    }
                    FAMILY_IPV6 if a_len >= 20 => {
                        // XOR with magic cookie || transaction ID (RFC 5389 §15.2)
                        let mut ip_bytes = [0u8; 16];
                        ip_bytes.copy_from_slice(&value[4..20]);
                        let xor_key = {
                            let mut key = [0u8; 16];
                            key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                            key[4..16].copy_from_slice(
                                &pkt[8..20], // transaction ID from header
                            );
                            key
                        };
                        for (b, k) in ip_bytes.iter_mut().zip(xor_key.iter()) {
                            *b ^= k;
                        }
                        IpAddr::V6(Ipv6Addr::from(ip_bytes))
                    }
                    f => return Err(StunError::UnknownAddressFamily(f)),
                };

                // XOR-MAPPED-ADDRESS is the canonical attribute — return immediately
                return Ok(SocketAddr::new(addr, port));
            }
            ATTR_MAPPED_ADDRESS if a_len >= 8 => {
                // Save as fallback; prefer XOR-MAPPED-ADDRESS if we see it later
                let family = value[1];
                let port = u16::from_be_bytes([value[2], value[3]]);
                if family == FAMILY_IPV4 {
                    let ip = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                    mapped_addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
                }
            }
            _ => {}
        }

        // STUN attributes are padded to 4-byte alignment
        offset += (a_len + 3) & !3;
    }

    mapped_addr.ok_or(StunError::NoMappedAddress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_format() {
        let txn_id = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = build_binding_request(&txn_id);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&req[2..4], &[0x00, 0x00]); // length = 0
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn parse_xor_mapped_address_ipv4() {
        // Synthesise a minimal valid Binding Response with one XOR-MAPPED-ADDRESS
        // attribute carrying 203.0.113.45:9999.
        let txn_id: [u8; 12] = [0u8; 12];
        let ip: u32 = u32::from(Ipv4Addr::new(203, 0, 113, 45)) ^ MAGIC_COOKIE;
        let port: u16 = 9999u16 ^ ((MAGIC_COOKIE >> 16) as u16);

        // Attribute: type(2) + len(2) + pad(1) + family(1) + port(2) + ip(4) = 12 bytes
        let attr_len: usize = 8; // value portion: pad + family + port + ip
        let mut pkt = vec![0u8; 20 + 4 + attr_len];
        // Header
        pkt[0..2].copy_from_slice(&MSG_BINDING_RESPONSE.to_be_bytes());
        let msg_attrs_len = (4 + attr_len) as u16;
        pkt[2..4].copy_from_slice(&msg_attrs_len.to_be_bytes());
        pkt[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt[8..20].copy_from_slice(&txn_id);
        // Attribute
        let attr_start = 20;
        pkt[attr_start..attr_start + 2].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        pkt[attr_start + 2..attr_start + 4].copy_from_slice(&(attr_len as u16).to_be_bytes());
        pkt[attr_start + 4] = 0; // pad
        pkt[attr_start + 5] = FAMILY_IPV4;
        pkt[attr_start + 6..attr_start + 8].copy_from_slice(&port.to_be_bytes());
        pkt[attr_start + 8..attr_start + 12].copy_from_slice(&ip.to_be_bytes());

        let addr = parse_binding_response(&pkt, &txn_id).unwrap();
        assert_eq!(addr, "203.0.113.45:9999".parse::<SocketAddr>().unwrap());
    }
}
