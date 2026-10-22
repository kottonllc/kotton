// SPDX-License-Identifier: AGPL-3.0-or-later
//! TURN relay client — RFC 5766 client-side implementation.
//!
//! Implements enough of RFC 5766 to relay QUIC datagrams:
//!
//! 1. **Allocate** — request a relay address; handles long-term credential
//!    challenge (401 → authenticated retry).
//! 2. **CreatePermission** — authorize inbound traffic from a peer IP.
//! 3. **ChannelBind** — bind a channel number to a peer address for lower-overhead
//!    ChannelData framing (4-byte header vs 36-byte Send indication).
//! 4. **ChannelData** — send and receive relayed datagrams.
//!
//! # Authentication
//!
//! Uses the RFC 5389 long-term credential mechanism:
//! `key = MD5(username ":" realm ":" password)`
//! `MESSAGE-INTEGRITY = HMAC-SHA1(key, message)`

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace};

use super::codec::{
    decode_xor_address, encode_xor_address, Attribute, CodecError, MsgClass, MsgMethod, StunMsg,
    ATTR_NONCE, ATTR_REALM, ATTR_USERNAME, MAGIC_COOKIE,
};

// ── TURN attribute types ─────────────────────────────────────────────────────

const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019; // value: 17 (UDP) in high byte

// STUN attribute type used by TURN
const ATTR_ERROR_CODE: u16 = 0x0009;

// ── Channel number range ─────────────────────────────────────────────────────

/// Lowest valid TURN channel number (RFC 5766 §11).
const CHANNEL_MIN: u16 = 0x4000;
/// Highest valid TURN channel number.
const CHANNEL_MAX: u16 = 0x7FFF;

// ── Timeouts ─────────────────────────────────────────────────────────────────

/// Timeout for a single TURN request-response round-trip.
const TURN_TIMEOUT: Duration = Duration::from_secs(5);

/// TURN allocation lifetime requested from the server.
const REQUESTED_LIFETIME: u32 = 600; // 10 minutes

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TurnError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TURN request timed out")]
    Timeout,

    #[error("Unexpected TURN response method/class: 0x{0:04x}")]
    UnexpectedResponse(u16),

    #[error("TURN server returned error {code}: {reason}")]
    ServerError { code: u16, reason: String },

    #[error("Missing required attribute 0x{0:04x} in response")]
    MissingAttribute(u16),

    #[error("Server challenged but did not provide NONCE or REALM")]
    BadChallenge,

    #[error("Already allocated — call `allocate()` only once per TurnClient")]
    AlreadyAllocated,

    #[error("Not allocated — call `allocate()` first")]
    NotAllocated,

    #[error("Channel {0} is not bound — call `channel_bind()` first")]
    ChannelNotBound(u16),

    #[error("All channel numbers in use (0x4000–0x7FFF exhausted)")]
    NoChannels,

    #[error("STUN/TURN codec error: {0}")]
    Codec(#[from] CodecError),
}

// ── Allocation ───────────────────────────────────────────────────────────────

/// The relay address granted by the TURN server.
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    /// Address that remote peers must send to in order to reach this client.
    pub relay_addr: SocketAddr,
    /// This client's external address as seen by the TURN server (convenience).
    pub mapped_addr: SocketAddr,
    /// Lifetime granted by the server in seconds.
    pub lifetime_secs: u32,
}

// ── Client ───────────────────────────────────────────────────────────────────

/// RFC 5766 TURN client.
///
/// Constructed once per relay session. Not `Clone`; wrap in `Arc` if sharing
/// across tasks.
#[derive(Debug)]
pub struct TurnClient {
    socket: UdpSocket,
    server: SocketAddr,
    username: String,
    password: String,
    allocation: Option<TurnAllocation>,
    /// Nonce received from the server during auth challenge.
    nonce: Option<Vec<u8>>,
    /// Realm received from the server during auth challenge.
    realm: Option<Vec<u8>>,
    /// channel_number → peer_addr
    channels: Arc<Mutex<HashMap<u16, SocketAddr>>>,
    /// Next channel number to assign.
    next_channel: u16,
}

impl TurnClient {
    /// Create a new TURN client connected to `server` with long-term credentials.
    pub async fn new(
        server: SocketAddr,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, TurnError> {
        let socket = UdpSocket::bind(crate::transport::outbound_bind_addr(server)).await?;
        socket.connect(server).await?;

        Ok(Self {
            socket,
            server,
            username: username.into(),
            password: password.into(),
            allocation: None,
            nonce: None,
            realm: None,
            channels: Arc::new(Mutex::new(HashMap::new())),
            next_channel: CHANNEL_MIN,
        })
    }

    /// Request a relay address from the TURN server.
    ///
    /// Handles the standard 401-challenge → authenticated retry automatically.
    /// Must be called before any other interaction.
    pub async fn allocate(&mut self) -> Result<TurnAllocation, TurnError> {
        if self.allocation.is_some() {
            return Err(TurnError::AlreadyAllocated);
        }

        // Step 1: unauthenticated Allocate
        let txn_id = rand::random::<[u8; 12]>();
        let req = self.build_allocate_request(&txn_id, false);
        self.send_raw(&req).await?;

        let resp = self.recv_for_txn(&txn_id).await?;
        let msg = StunMsg::decode(&resp)?;

        // Check for 401 challenge
        if msg.class == MsgClass::Error {
            let (code, reason) = extract_error_code(&msg);
            if code != 401 {
                return Err(TurnError::ServerError { code, reason });
            }
            // Extract NONCE and REALM for retry
            self.nonce = find_attr(&msg, ATTR_NONCE).map(|v| v.to_vec());
            self.realm = find_attr(&msg, ATTR_REALM).map(|v| v.to_vec());
            if self.nonce.is_none() || self.realm.is_none() {
                return Err(TurnError::BadChallenge);
            }
            debug!("TURN Allocate challenged (401), retrying with credentials");

            // Step 2: authenticated Allocate
            let txn_id2 = rand::random::<[u8; 12]>();
            let req2 = self.build_allocate_request(&txn_id2, true);
            self.send_raw(&req2).await?;
            let resp2 = self.recv_for_txn(&txn_id2).await?;
            let msg2 = StunMsg::decode(&resp2)?;
            return self.parse_allocate_success(&txn_id2, &msg2, &req2);
        }

        // Unauthenticated success (unusual but handle it)
        self.parse_allocate_success(&txn_id, &msg, &req)
    }

    /// Authorize inbound traffic from `peer_ip` through the relay.
    pub async fn create_permission(&self, peer_ip: IpAddr) -> Result<(), TurnError> {
        self.require_allocated()?;

        let txn_id = rand::random::<[u8; 12]>();
        let req = self.build_create_permission(&txn_id, peer_ip);
        self.send_raw(&req).await?;
        let resp = self.recv_for_txn(&txn_id).await?;
        let msg = StunMsg::decode(&resp)?;

        if msg.class == MsgClass::Error {
            let (code, reason) = extract_error_code(&msg);
            return Err(TurnError::ServerError { code, reason });
        }
        debug!(peer_ip = %peer_ip, "TURN CreatePermission OK");
        Ok(())
    }

    /// Bind `channel` (0x4000–0x7FFF) to `peer_addr` for ChannelData framing.
    ///
    /// Auto-assigns the next available channel number and returns it.
    pub async fn channel_bind(&mut self, peer_addr: SocketAddr) -> Result<u16, TurnError> {
        self.require_allocated()?;

        let channel = self.alloc_channel(peer_addr)?;
        let txn_id = rand::random::<[u8; 12]>();
        let req = self.build_channel_bind(&txn_id, channel, peer_addr);
        self.send_raw(&req).await?;
        let resp = self.recv_for_txn(&txn_id).await?;
        let msg = StunMsg::decode(&resp)?;

        if msg.class == MsgClass::Error {
            let (code, reason) = extract_error_code(&msg);
            // Remove the channel from the map on failure
            self.channels.lock().unwrap().remove(&channel);
            return Err(TurnError::ServerError { code, reason });
        }
        debug!(channel, peer_addr = %peer_addr, "TURN ChannelBind OK");
        Ok(channel)
    }

    /// Send `data` to `peer` via an already-bound channel.
    ///
    /// If no channel is bound to `peer`, returns `Err(TurnError::ChannelNotBound)`.
    pub async fn send_channel_data(
        &self,
        peer_addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), TurnError> {
        let channel = self
            .channels
            .lock()
            .unwrap()
            .iter()
            .find_map(|(&ch, &a)| if a == peer_addr { Some(ch) } else { None })
            .ok_or(TurnError::ChannelNotBound(0))?;

        let frame = encode_channel_data(channel, data);
        self.send_raw(&frame).await?;
        trace!(channel, len = data.len(), "TURN ChannelData sent");
        Ok(())
    }

    /// Receive the next datagram, unwrapping ChannelData framing.
    ///
    /// Returns `(data, peer_addr)` on success.
    pub async fn recv(&self) -> Result<(Vec<u8>, SocketAddr), TurnError> {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = self.socket.recv(&mut buf).await?;
            let pkt = &buf[..n];

            // ChannelData: first 2 bytes are channel number in range 0x4000–0x7FFF
            if pkt.len() >= 4 {
                let chan = u16::from_be_bytes([pkt[0], pkt[1]]);
                if (CHANNEL_MIN..=CHANNEL_MAX).contains(&chan) {
                    let data_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                    if pkt.len() >= 4 + data_len {
                        let data = pkt[4..4 + data_len].to_vec();
                        let peer = self
                            .channels
                            .lock()
                            .unwrap()
                            .get(&chan)
                            .copied()
                            .unwrap_or(self.server);
                        trace!(channel = chan, len = data_len, "TURN ChannelData received");
                        return Ok((data, peer));
                    }
                }
            }
            // Drop non-channel-data packets (TURN indications, etc.) silently
        }
    }

    /// Consume the client and return the underlying UDP socket plus the channel
    /// number already bound to `peer_addr`.
    ///
    /// Call this after `allocate()` + `create_permission()` + `channel_bind()`
    /// are complete to hand ownership of the socket to `TurnUdpSocket`.
    /// Returns `Err(TurnError::ChannelNotBound)` if no channel is bound to
    /// `peer_addr`.
    pub fn into_socket_and_channel(
        self,
        peer_addr: SocketAddr,
    ) -> Result<(UdpSocket, u16), TurnError> {
        let channel = self
            .channels
            .lock()
            .unwrap()
            .iter()
            .find_map(|(&ch, &a)| if a == peer_addr { Some(ch) } else { None })
            .ok_or(TurnError::ChannelNotBound(0))?;
        Ok((self.socket, channel))
    }

    /// Return the allocation, or `None` if not yet allocated.
    pub fn allocation(&self) -> Option<&TurnAllocation> {
        self.allocation.as_ref()
    }

    /// Return the relay address, panicking if not yet allocated.
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.allocation.as_ref().map(|a| a.relay_addr)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn require_allocated(&self) -> Result<(), TurnError> {
        if self.allocation.is_none() {
            Err(TurnError::NotAllocated)
        } else {
            Ok(())
        }
    }

    fn alloc_channel(&mut self, peer: SocketAddr) -> Result<u16, TurnError> {
        let channels = self.channels.lock().unwrap();
        // Return existing binding if present
        if let Some((&ch, _)) = channels.iter().find(|(_, &a)| a == peer) {
            return Ok(ch);
        }
        // Find next free channel
        let ch = self.next_channel;
        if ch > CHANNEL_MAX {
            return Err(TurnError::NoChannels);
        }
        self.next_channel += 1;
        drop(channels);
        self.channels.lock().unwrap().insert(ch, peer);
        Ok(ch)
    }

    fn build_allocate_request(&self, txn_id: &[u8; 12], authenticated: bool) -> Vec<u8> {
        let mut attrs = vec![
            // REQUESTED-TRANSPORT: UDP (17), padded to 4 bytes
            Attribute {
                attr_type: ATTR_REQUESTED_TRANSPORT,
                value: vec![17, 0, 0, 0],
            },
            // LIFETIME
            Attribute {
                attr_type: ATTR_LIFETIME,
                value: REQUESTED_LIFETIME.to_be_bytes().to_vec(),
            },
        ];

        if authenticated {
            if let (Some(realm), Some(nonce)) = (self.realm.as_deref(), self.nonce.as_deref()) {
                attrs.push(Attribute {
                    attr_type: ATTR_USERNAME,
                    value: self.username.as_bytes().to_vec(),
                });
                attrs.push(Attribute {
                    attr_type: ATTR_REALM,
                    value: realm.to_vec(),
                });
                attrs.push(Attribute {
                    attr_type: ATTR_NONCE,
                    value: nonce.to_vec(),
                });
            }
        }

        let mut msg = StunMsg::new(MsgMethod::Allocate, MsgClass::Request, *txn_id);
        for a in attrs {
            msg.attrs.push(a);
        }

        let mut encoded = msg.encode();
        if authenticated {
            if let (Some(realm), Some(_nonce)) = (self.realm.as_deref(), self.nonce.as_deref()) {
                add_message_integrity(
                    &mut encoded,
                    &self.username,
                    std::str::from_utf8(realm).unwrap_or(""),
                    &self.password,
                );
            }
        }
        encoded
    }

    fn build_create_permission(&self, txn_id: &[u8; 12], peer_ip: IpAddr) -> Vec<u8> {
        // XOR-PEER-ADDRESS contains only the IP address (port is irrelevant for
        // CreatePermission, but we pass port 0)
        let peer_addr = SocketAddr::new(peer_ip, 0);
        let xor_peer = encode_xor_address(peer_addr, txn_id);

        let mut msg = StunMsg::new(MsgMethod::CreatePermission, MsgClass::Request, *txn_id);
        msg.attrs.push(Attribute {
            attr_type: ATTR_XOR_PEER_ADDRESS,
            value: xor_peer,
        });

        if let (Some(realm), Some(nonce)) = (self.realm.as_deref(), self.nonce.as_deref()) {
            msg.attrs.push(Attribute {
                attr_type: ATTR_USERNAME,
                value: self.username.as_bytes().to_vec(),
            });
            msg.attrs.push(Attribute {
                attr_type: ATTR_REALM,
                value: realm.to_vec(),
            });
            msg.attrs.push(Attribute {
                attr_type: ATTR_NONCE,
                value: nonce.to_vec(),
            });
        }

        let mut encoded = msg.encode();
        if let (Some(realm), Some(_nonce)) = (self.realm.as_deref(), self.nonce.as_deref()) {
            add_message_integrity(
                &mut encoded,
                &self.username,
                std::str::from_utf8(realm).unwrap_or(""),
                &self.password,
            );
        }
        encoded
    }

    fn build_channel_bind(
        &self,
        txn_id: &[u8; 12],
        channel: u16,
        peer_addr: SocketAddr,
    ) -> Vec<u8> {
        let mut ch_bytes = channel.to_be_bytes().to_vec();
        ch_bytes.extend_from_slice(&[0, 0]); // 2 bytes reserved

        let xor_peer = encode_xor_address(peer_addr, txn_id);

        let mut msg = StunMsg::new(MsgMethod::ChannelBind, MsgClass::Request, *txn_id);
        msg.attrs.push(Attribute {
            attr_type: ATTR_CHANNEL_NUMBER,
            value: ch_bytes,
        });
        msg.attrs.push(Attribute {
            attr_type: ATTR_XOR_PEER_ADDRESS,
            value: xor_peer,
        });

        if let (Some(realm), Some(nonce)) = (self.realm.as_deref(), self.nonce.as_deref()) {
            msg.attrs.push(Attribute {
                attr_type: ATTR_USERNAME,
                value: self.username.as_bytes().to_vec(),
            });
            msg.attrs.push(Attribute {
                attr_type: ATTR_REALM,
                value: realm.to_vec(),
            });
            msg.attrs.push(Attribute {
                attr_type: ATTR_NONCE,
                value: nonce.to_vec(),
            });
        }

        let mut encoded = msg.encode();
        if let (Some(realm), Some(_nonce)) = (self.realm.as_deref(), self.nonce.as_deref()) {
            add_message_integrity(
                &mut encoded,
                &self.username,
                std::str::from_utf8(realm).unwrap_or(""),
                &self.password,
            );
        }
        encoded
    }

    fn parse_allocate_success(
        &mut self,
        txn_id: &[u8; 12],
        msg: &StunMsg,
        _raw: &[u8],
    ) -> Result<TurnAllocation, TurnError> {
        if msg.class == MsgClass::Error {
            let (code, reason) = extract_error_code(msg);
            return Err(TurnError::ServerError { code, reason });
        }

        let relay_raw = find_attr(msg, ATTR_XOR_RELAYED_ADDRESS)
            .ok_or(TurnError::MissingAttribute(ATTR_XOR_RELAYED_ADDRESS))?;
        let relay_addr = decode_xor_address(relay_raw, txn_id)
            .ok_or(TurnError::MissingAttribute(ATTR_XOR_RELAYED_ADDRESS))?;

        // XOR-MAPPED-ADDRESS uses attr type 0x0020 (same as in STUN)
        let mapped_raw = find_attr(msg, 0x0020_u16).ok_or(TurnError::MissingAttribute(0x0020))?;
        let mapped_addr =
            decode_xor_address(mapped_raw, txn_id).ok_or(TurnError::MissingAttribute(0x0020))?;

        let lifetime_secs = find_attr(msg, ATTR_LIFETIME)
            .and_then(|v| v.get(0..4))
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(REQUESTED_LIFETIME);

        let alloc = TurnAllocation {
            relay_addr,
            mapped_addr,
            lifetime_secs,
        };
        debug!(relay_addr = %relay_addr, mapped_addr = %mapped_addr, "TURN Allocate OK");
        self.allocation = Some(alloc.clone());
        Ok(alloc)
    }

    async fn send_raw(&self, buf: &[u8]) -> Result<(), TurnError> {
        self.socket.send(buf).await?;
        Ok(())
    }

    async fn recv_for_txn(&self, txn_id: &[u8; 12]) -> Result<Vec<u8>, TurnError> {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = timeout(TURN_TIMEOUT, self.socket.recv(&mut buf))
                .await
                .map_err(|_| TurnError::Timeout)??;

            let pkt = buf[..n].to_vec();
            // Match on STUN header: magic cookie at offset 4
            if pkt.len() >= 20 {
                let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
                if cookie == MAGIC_COOKIE && &pkt[8..20] == txn_id {
                    return Ok(pkt);
                }
            }
            trace!("TURN recv: ignoring non-matching packet ({n} bytes)");
        }
    }
}

// ── ChannelData framing ──────────────────────────────────────────────────────

fn encode_channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    // Pad to 4-byte boundary
    let rem = data.len() % 4;
    if rem != 0 {
        out.extend_from_slice(&vec![0u8; 4 - rem]);
    }
    out
}

// ── MESSAGE-INTEGRITY ────────────────────────────────────────────────────────

/// Append a MESSAGE-INTEGRITY attribute (HMAC-SHA1) to an already-encoded STUN
/// message. The length field in the header is updated to include the attribute.
fn add_message_integrity(buf: &mut Vec<u8>, username: &str, realm: &str, password: &str) {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // Long-term credential key: MD5(username:realm:password)
    let key_str = format!("{}:{}:{}", username, realm, password);
    let key = md5_digest(key_str.as_bytes());

    // Update the length in the header to include the forthcoming MI attribute
    // (type 2 + len 2 + value 20 = 24 bytes), but NOT the FINGERPRINT.
    let current_len = buf.len() - 20; // exclude header
    let mi_len = current_len + 24;
    buf[2] = (mi_len >> 8) as u8;
    buf[3] = (mi_len & 0xFF) as u8;

    // Compute HMAC-SHA1 over the message as modified above
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).expect("HMAC-SHA1 accepts any key length");
    mac.update(buf.as_slice());
    let result = mac.finalize().into_bytes();

    // Append MESSAGE-INTEGRITY attribute (type=0x0008, length=20)
    buf.extend_from_slice(&[0x00, 0x08]);
    buf.extend_from_slice(&[0x00, 0x14]); // length = 20
    buf.extend_from_slice(&result);
}

/// Compute MD5 digest (used for long-term credential key derivation per RFC 5389 §10.2.3).
fn md5_digest(input: &[u8]) -> [u8; 16] {
    md5::compute(input).0
}

// ── Attribute helpers ────────────────────────────────────────────────────────

fn find_attr(msg: &StunMsg, attr_type: u16) -> Option<&[u8]> {
    msg.attrs
        .iter()
        .find(|a| a.attr_type == attr_type)
        .map(|a| a.value.as_slice())
}

fn extract_error_code(msg: &StunMsg) -> (u16, String) {
    // ERROR-CODE attribute: 4 bytes prefix (class in byte 2, number in byte 3)
    // followed by UTF-8 reason
    if let Some(v) = find_attr(msg, ATTR_ERROR_CODE) {
        if v.len() >= 4 {
            let class = (v[2] & 0x07) as u16;
            let number = v[3] as u16;
            let code = class * 100 + number;
            let reason = std::str::from_utf8(&v[4..]).unwrap_or("").to_owned();
            return (code, reason);
        }
    }
    (0, "(no error code)".to_owned())
}
