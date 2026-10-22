// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal STUN binding responder (RFC 5389) — the relay's own reflexive-address
//! service, so Kotton nodes do not depend on a 3rd-party STUN server.
//!
//! A node sends a Binding Request **from its QUIC socket** to this responder; we
//! echo back the observed UDP source address in an `XOR-MAPPED-ADDRESS` attribute.
//! That is the node's reflexive (public) address *for that socket* — exactly what
//! the client-side `kotton_net::stun` parses. This is the STUN half
//! of "the relay subsumes STUN + TURN" (RFC-0024 / sprint 07; see the sprint spec).
//!
//! We only implement the Binding Request → Success Response path; anything else on
//! the socket is ignored. The wire format mirrors the client codec exactly.

use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;
use tracing::{trace, warn};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const MSG_BINDING_REQUEST: u16 = 0x0001;
const MSG_BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// Validate a datagram as a STUN Binding Request and return its transaction ID.
///
/// Returns `None` for anything that is not a well-formed binding request (so the
/// caller silently ignores other UDP traffic on the socket).
fn parse_binding_request(pkt: &[u8]) -> Option<[u8; 12]> {
    if pkt.len() < 20 {
        return None;
    }
    if u16::from_be_bytes([pkt[0], pkt[1]]) != MSG_BINDING_REQUEST {
        return None;
    }
    if u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]) != MAGIC_COOKIE {
        return None;
    }
    // The 12-byte transaction ID follows the 4-byte magic cookie.
    pkt[8..20].try_into().ok()
}

/// Build a Binding Success Response carrying `mapped` as an `XOR-MAPPED-ADDRESS`.
fn build_binding_response(txn_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    // Attribute value: [reserved, family, x-port(2), x-address(4 or 16)].
    let mut value = Vec::with_capacity(20);
    value.push(0); // reserved / padding
    let x_port = mapped.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    match mapped.ip() {
        IpAddr::V4(v4) => {
            value.push(FAMILY_IPV4);
            value.extend_from_slice(&x_port.to_be_bytes());
            let x_addr = u32::from(v4) ^ MAGIC_COOKIE;
            value.extend_from_slice(&x_addr.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            value.push(FAMILY_IPV6);
            value.extend_from_slice(&x_port.to_be_bytes());
            // XOR key is magic-cookie || transaction-id (RFC 5389 §15.2).
            let mut key = [0u8; 16];
            key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..16].copy_from_slice(txn_id);
            let mut octets = v6.octets();
            for (b, k) in octets.iter_mut().zip(key.iter()) {
                *b ^= *k;
            }
            value.extend_from_slice(&octets);
        }
    }

    let attr_len = value.len() as u16; // 8 (v4) or 20 (v6)
    let msg_len = 4 + attr_len; // attribute header (4) + value

    let mut msg = Vec::with_capacity(20 + 4 + value.len());
    msg.extend_from_slice(&MSG_BINDING_RESPONSE.to_be_bytes());
    msg.extend_from_slice(&msg_len.to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txn_id);
    msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend_from_slice(&attr_len.to_be_bytes());
    msg.extend_from_slice(&value);
    msg
}

/// Run the STUN responder loop on `socket` until the process exits.
///
/// For every valid Binding Request, reply with the observed source address. The
/// socket also carries no other traffic in normal operation; non-STUN datagrams
/// are ignored.
pub async fn run_stun_responder(socket: UdpSocket) {
    let mut buf = [0u8; 576]; // a binding request is 20 bytes; 576 is the STUN floor
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "stun responder: recv failed");
                continue;
            }
        };
        if let Some(txn) = parse_binding_request(&buf[..n]) {
            let resp = build_binding_response(&txn, src);
            match socket.send_to(&resp, src).await {
                Ok(_) => trace!(%src, "stun: binding response sent"),
                Err(e) => warn!(error = %e, %src, "stun responder: send failed"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Decode an XOR-MAPPED-ADDRESS response back to a SocketAddr (mirrors the
    /// client parser) and confirm it round-trips the address we encoded.
    fn decode_xor_mapped(pkt: &[u8], txn_id: &[u8; 12]) -> SocketAddr {
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), MSG_BINDING_RESPONSE);
        assert_eq!(u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]), MAGIC_COOKIE);
        assert_eq!(&pkt[8..20], txn_id);
        let a_type = u16::from_be_bytes([pkt[20], pkt[21]]);
        assert_eq!(a_type, ATTR_XOR_MAPPED_ADDRESS);
        let v = &pkt[24..];
        let family = v[1];
        let port = u16::from_be_bytes([v[2], v[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
        let ip = match family {
            FAMILY_IPV4 => {
                let x = u32::from_be_bytes([v[4], v[5], v[6], v[7]]) ^ MAGIC_COOKIE;
                IpAddr::V4(Ipv4Addr::from(x))
            }
            FAMILY_IPV6 => {
                let mut key = [0u8; 16];
                key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                key[4..16].copy_from_slice(txn_id);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&v[4..20]);
                for (b, k) in octets.iter_mut().zip(key.iter()) {
                    *b ^= *k;
                }
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            f => panic!("unexpected family {f}"),
        };
        SocketAddr::new(ip, port)
    }

    #[test]
    fn rejects_non_binding_request() {
        assert!(parse_binding_request(&[0u8; 10]).is_none()); // too short
        let mut req = vec![0x01, 0x01]; // binding *response* type, not request
        req.extend_from_slice(&[0u8; 18]);
        req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        assert!(parse_binding_request(&req).is_none());
    }

    #[test]
    fn ipv4_response_round_trips() {
        let txn = [7u8; 12];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 45)), 51820);
        let resp = build_binding_response(&txn, addr);
        assert_eq!(decode_xor_mapped(&resp, &txn), addr);
    }

    #[test]
    fn ipv6_response_round_trips() {
        let txn = [9u8; 12];
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 9000);
        let resp = build_binding_response(&txn, addr);
        assert_eq!(decode_xor_mapped(&resp, &txn), addr);
    }
}
