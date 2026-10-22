// SPDX-License-Identifier: AGPL-3.0-or-later
//! A relay introduces your devices: the dialler hands the other device its local
//! address and a token over the sealed channel the relay carries, the other opens a
//! listener that hears that address and that token and nothing else, and the pair
//! dials direct.
//!
//! Where the parts are:
//!
//! - **The filter and the one-key handshake** are the transport's —
//!   `kotton_net::transport::quic::introduced`. A stranger's datagram is dropped
//!   before QUIC parses a byte of it.
//! - **Asking for an introduction** is the dialler's — [`crate::dialer`] asks once a
//!   relayed connection to one of the person's devices is up, and uses the direct
//!   connection if it opens within [`DIRECT_WITHIN`], the relayed one if not.
//! - **Answering one** is the device's (`kotton_device`'s `open_introduction`),
//!   because the accept loop that serves what arrives is.
//!
//! What the relay sees: the `Introduce` request and its answer travel inside the
//! end-to-end TLS the relay bridges and cannot open, on a circuit named by the
//! pair's rotating handles. It learns that the circuit carried a few
//! hundred bytes, which it knew about every circuit already, and no address.

use kotton_net::transport::quic::introduced::INTRODUCTION_TOKEN_LEN;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// How long the dialler gives the introduction — the ask over the relay, and then
/// the direct handshake — before it keeps the relayed connection instead. A LAN
/// handshake is milliseconds; a pair on two networks never answers, and this is
/// what that costs a relayed dial.
pub const DIRECT_WITHIN: Duration = Duration::from_secs(1);

/// How long an introduced listener waits for its one handshake before it closes.
/// The token is dead after this; a session already open is not, and ends when the
/// pair ends it. Longer than [`DIRECT_WITHIN`], so a dialler still inside its budget
/// never finds the door already shut.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(10);

/// A fresh token for one introduction: 128 bits from the OS.
pub fn new_token() -> [u8; INTRODUCTION_TOKEN_LEN] {
    use rand::RngCore;
    let mut token = [0u8; INTRODUCTION_TOKEN_LEN];
    rand::rngs::OsRng.fill_bytes(&mut token);
    token
}

/// The address an introduced socket binds, on either end: this device's own
/// address on the local network — one interface, never the wildcard — or loopback
/// under [`crate::scope::local_only`], where nothing off the machine is dialled.
/// `None` when the device is on no network it can name, and then there is no
/// introduction and the relayed connection stands.
pub fn introduced_bind_ip() -> Option<IpAddr> {
    if crate::scope::local_only() {
        return Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    crate::local_door::lan_ip_here().map(IpAddr::V4)
}

/// Whether an introduction from a device on `theirs` may be answered by one on
/// `here`: only when both name the **same** router. A private address on another
/// network belongs to a stranger on the dialler's, and a dial aimed at it would put a
/// Kotton handshake in front of them — so a device that cannot name its network, or
/// names another, declines, and the relay carries the pair. Under
/// [`crate::scope::local_only`] both ends are this machine and the rule is moot.
pub fn on_one_network(
    theirs: Option<crate::local_door::RouterKey>,
    here: Option<crate::local_door::RouterKey>,
    local_only: bool,
) -> bool {
    local_only || matches!((theirs, here), (Some(a), Some(b)) if a == b)
}

/// Parse the token an `Introduce` carried.
pub fn parse_token(hex_token: &str) -> Option<[u8; INTRODUCTION_TOKEN_LEN]> {
    hex::decode(hex_token).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_fresh_each_time_and_round_trips_as_hex() {
        let a = new_token();
        assert_ne!(a, new_token());
        assert_eq!(parse_token(&hex::encode(a)), Some(a));
        assert_eq!(parse_token("00"), None);
        assert_eq!(parse_token("not hex"), None);
    }

    /// Two networks, or a network that cannot be named on either side, is no
    /// introduction; one router on both sides is.
    #[test]
    fn an_introduction_is_answered_only_on_one_network() {
        use crate::local_door::RouterKey;
        let home = RouterKey::of_gateway_mac([0x3c, 0x22, 0xfb, 0, 0, 1]);
        let cafe = RouterKey::of_gateway_mac([0x3c, 0x22, 0xfb, 0, 0, 9]);
        assert!(on_one_network(Some(home), Some(home), false));
        assert!(!on_one_network(Some(cafe), Some(home), false));
        assert!(!on_one_network(None, Some(home), false));
        assert!(!on_one_network(Some(home), None, false));
        assert!(!on_one_network(None, None, false));
        assert!(on_one_network(None, None, true), "one machine is one network");
    }

    #[test]
    fn the_listener_outlives_the_dialers_budget() {
        assert!(TOKEN_LIFETIME > DIRECT_WITHIN * 2);
    }
}
