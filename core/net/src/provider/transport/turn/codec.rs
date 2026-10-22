// SPDX-License-Identifier: AGPL-3.0-or-later
//! STUN message codec shared by the TURN client.
//!
//! Implements the RFC 5389 message framing needed for TURN request/response
//! encoding. Does not replicate the binding-request-only STUN client in
//! `stun/mod.rs` — the two serve different purposes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

/// STUN magic cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

// ── Message class (bits 4 and 9 of the 16-bit type field) ───────────────────

/// Decoded STUN message class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgClass {
    Request,
    Indication,
    Success,
    Error,
}

impl MsgClass {
    /// Extract class from raw 16-bit STUN type.
    pub fn from_type(t: u16) -> Self {
        let c0 = (t >> 4) & 0x1;
        let c1 = (t >> 8) & 0x1;
        match c0 | (c1 << 1) {
            0 => MsgClass::Request,
            1 => MsgClass::Indication,
            2 => MsgClass::Success,
            _ => MsgClass::Error,
        }
    }

    fn class_bits(self) -> u16 {
        match self {
            MsgClass::Request => 0x0000,
            MsgClass::Indication => 0x0010,
            MsgClass::Success => 0x0100,
            MsgClass::Error => 0x0110,
        }
    }
}

// ── Message method ───────────────────────────────────────────────────────────

/// STUN/TURN message method.
///
/// Numeric values are in the "compressed" layout occupying bits 0–3, 5–8, 10–13
/// of the type field with the class bits at positions 4 and 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgMethod {
    Binding,          // 0x001
    Allocate,         // 0x003
    Refresh,          // 0x004
    Send,             // 0x006
    Data,             // 0x007
    CreatePermission, // 0x008
    ChannelBind,      // 0x009
    Other(u16),
}

impl MsgMethod {
    fn method_bits(self) -> u16 {
        let m = match self {
            MsgMethod::Binding => 0x001,
            MsgMethod::Allocate => 0x003,
            MsgMethod::Refresh => 0x004,
            MsgMethod::Send => 0x006,
            MsgMethod::Data => 0x007,
            MsgMethod::CreatePermission => 0x008,
            MsgMethod::ChannelBind => 0x009,
            MsgMethod::Other(v) => v,
        };
        // Encode method bits into the STUN type field bit layout:
        // bits 0-3 = method[0-3]
        // bits 5-8 = method[4-7]
        // bits 10-13 = method[8-11]
        let b03 = m & 0x00F;
        let b47 = (m & 0x0F0) >> 4;
        let b811 = (m & 0xF00) >> 8;
        (b03) | (b47 << 5) | (b811 << 10)
    }

    fn from_type(t: u16) -> Self {
        // Reverse the bit layout
        let b03 = t & 0x000F;
        let b47 = (t >> 5) & 0x000F;
        let b811 = (t >> 10) & 0x000F;
        let m = b03 | (b47 << 4) | (b811 << 8);
        match m {
            0x001 => MsgMethod::Binding,
            0x003 => MsgMethod::Allocate,
            0x004 => MsgMethod::Refresh,
            0x006 => MsgMethod::Send,
            0x007 => MsgMethod::Data,
            0x008 => MsgMethod::CreatePermission,
            0x009 => MsgMethod::ChannelBind,
            v => MsgMethod::Other(v),
        }
    }
}

// ── Attribute type constants ─────────────────────────────────────────────────

pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;

// ── Attribute ────────────────────────────────────────────────────────────────

/// A single STUN/TURN attribute.
#[derive(Debug, Clone)]
pub struct Attribute {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

// ── Message ──────────────────────────────────────────────────────────────────

/// A decoded or in-progress STUN/TURN message.
#[derive(Debug)]
pub struct StunMsg {
    pub method: MsgMethod,
    pub class: MsgClass,
    pub txn_id: [u8; 12],
    pub attrs: Vec<Attribute>,
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("Packet too short: {0} bytes")]
    TooShort(usize),
    #[error("STUN magic cookie mismatch")]
    BadMagicCookie,
    #[error("Attribute overflows message boundary")]
    AttrOverflow,
}

impl StunMsg {
    pub fn new(method: MsgMethod, class: MsgClass, txn_id: [u8; 12]) -> Self {
        Self {
            method,
            class,
            txn_id,
            attrs: Vec::new(),
        }
    }

    /// Encode into a STUN message (without MESSAGE-INTEGRITY / FINGERPRINT).
    ///
    /// Callers that need authentication append MESSAGE-INTEGRITY afterward via
    /// `add_message_integrity()` in `client.rs`.
    pub fn encode(&self) -> Vec<u8> {
        // Encode attributes first to know total length
        let mut attr_bytes = Vec::new();
        for attr in &self.attrs {
            attr_bytes.extend_from_slice(&attr.attr_type.to_be_bytes());
            attr_bytes.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
            attr_bytes.extend_from_slice(&attr.value);
            // Pad to 4-byte boundary
            let rem = attr.value.len() % 4;
            if rem != 0 {
                attr_bytes.extend(std::iter::repeat_n(0u8, 4 - rem));
            }
        }

        let msg_type = self.method.method_bits() | self.class.class_bits();
        let mut out = Vec::with_capacity(20 + attr_bytes.len());
        out.extend_from_slice(&msg_type.to_be_bytes());
        out.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.txn_id);
        out.extend_from_slice(&attr_bytes);
        out
    }

    /// Decode a raw packet into a `StunMsg`.
    pub fn decode(pkt: &[u8]) -> Result<Self, CodecError> {
        if pkt.len() < 20 {
            return Err(CodecError::TooShort(pkt.len()));
        }
        let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(CodecError::BadMagicCookie);
        }

        let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
        let attr_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if pkt.len() < 20 + attr_len {
            return Err(CodecError::AttrOverflow);
        }

        let txn_id: [u8; 12] = pkt[8..20].try_into().unwrap();
        let method = MsgMethod::from_type(msg_type);
        let class = MsgClass::from_type(msg_type);

        let mut attrs = Vec::new();
        let mut off = 20usize;
        let end = 20 + attr_len;

        while off + 4 <= end {
            let a_type = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            let a_len = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) as usize;
            off += 4;
            if off + a_len > end {
                return Err(CodecError::AttrOverflow);
            }
            attrs.push(Attribute {
                attr_type: a_type,
                value: pkt[off..off + a_len].to_vec(),
            });
            off += (a_len + 3) & !3; // advance past padding
        }

        Ok(StunMsg {
            method,
            class,
            txn_id,
            attrs,
        })
    }
}

// ── XOR-address helpers ──────────────────────────────────────────────────────

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// Encode a `SocketAddr` as an XOR-mapped-address attribute value.
pub fn encode_xor_address(addr: SocketAddr, txn_id: &[u8; 12]) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let port = a.port() ^ (MAGIC_COOKIE >> 16) as u16;
            let ip_u32 = u32::from(*a.ip()) ^ MAGIC_COOKIE;
            let mut v = vec![0u8, FAMILY_IPV4];
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&ip_u32.to_be_bytes());
            v
        }
        SocketAddr::V6(a) => {
            let port = a.port() ^ (MAGIC_COOKIE >> 16) as u16;
            let ip_bytes = a.ip().octets();
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(txn_id);
            let mut ip_xored = [0u8; 16];
            for (b, (ib, kb)) in ip_xored.iter_mut().zip(ip_bytes.iter().zip(xor_key.iter())) {
                *b = ib ^ kb;
            }
            let mut v = vec![0u8, FAMILY_IPV6];
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&ip_xored);
            v
        }
    }
}

/// Decode an XOR-mapped-address attribute value + transaction ID → `SocketAddr`.
pub fn decode_xor_address(value: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }
    let family = value[1];
    let port_xored = u16::from_be_bytes([value[2], value[3]]);
    let port = port_xored ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return None;
            }
            let ip_xored = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let ip = Ipv4Addr::from(ip_xored ^ MAGIC_COOKIE);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&value[4..20]);
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(txn_id);
            for (b, k) in ip_bytes.iter_mut().zip(xor_key.iter()) {
                *b ^= k;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        _ => None,
    }
}

/// Helper to decode an attribute from an attribute-value-format slice.
pub fn decode_attr(value: &[u8]) -> &[u8] {
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_allocate_request() {
        let txn_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMsg::new(MsgMethod::Allocate, MsgClass::Request, txn_id);
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 20); // no attributes
        let decoded = StunMsg::decode(&encoded).unwrap();
        assert_eq!(decoded.method, MsgMethod::Allocate);
        assert_eq!(decoded.class, MsgClass::Request);
        assert_eq!(decoded.txn_id, txn_id);
    }

    #[test]
    fn xor_address_round_trip_ipv4() {
        let addr: SocketAddr = "203.0.113.45:4567".parse().unwrap();
        let txn_id = [0u8; 12];
        let encoded = encode_xor_address(addr, &txn_id);
        let decoded = decode_xor_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn msg_class_round_trip() {
        // Verify class bits encode/decode correctly for all four classes
        let txn_id = [0u8; 12];
        for class in [
            MsgClass::Request,
            MsgClass::Indication,
            MsgClass::Success,
            MsgClass::Error,
        ] {
            let msg = StunMsg::new(MsgMethod::Binding, class, txn_id);
            let enc = msg.encode();
            let dec = StunMsg::decode(&enc).unwrap();
            assert_eq!(dec.class, class, "class mismatch for {:?}", class);
        }
    }
}
