// SPDX-License-Identifier: AGPL-3.0-or-later
//! Choosing the local address an outbound socket binds.
//!
//! A client socket has to be bound before it can dial, and the address it is bound
//! to is not a free choice — it is a consequence of where the packet is going.
//!
//! **Family.** An IPv4 `0.0.0.0` socket cannot dial an IPv6 peer; quinn rejects it
//! as an invalid remote address before anything leaves the host. A fixed IPv4 bind
//! therefore does not merely prefer IPv4, it silently loses every IPv6 peer.
//!
//! **Scope.** A wildcard socket dialing `127.0.0.1` arrives at exactly the same
//! place a loopback socket would, and opens a LAN-facing UDP port to do it. On
//! Windows and macOS that port is what raises the OS firewall dialog — a GUI prompt
//! a background or CI run cannot answer, so the run blocks and reads as slow rather
//! than stuck.
//!
//! Both rules read off the destination, so they belong in one place rather than in
//! each of the four dial sites that used to spell them out.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The address a client socket should bind to before dialing `dest`.
///
/// Matches `dest`'s address family, and narrows to loopback when `dest` is
/// loopback. Port is always 0 — the OS assigns it.
pub fn outbound_bind_addr(dest: SocketAddr) -> SocketAddr {
    match dest.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => (Ipv4Addr::LOCALHOST, 0).into(),
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(ip) if ip.is_loopback() => (Ipv6Addr::LOCALHOST, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind_for(dest: &str) -> SocketAddr {
        outbound_bind_addr(dest.parse().unwrap())
    }

    /// The bug this rule exists for: a fixed IPv4 bind cannot dial an IPv6 peer, so
    /// the family has to come from the destination rather than from a constant.
    #[test]
    fn the_family_follows_the_destination() {
        assert!(bind_for("192.0.2.1:443").is_ipv4());
        assert!(bind_for("[2001:db8::1]:443").is_ipv6());
    }

    /// Dialing this host needs nothing LAN-facing, and opening a LAN-facing socket
    /// to do it is what raises the OS firewall dialog.
    #[test]
    fn a_loopback_destination_is_dialed_from_loopback() {
        assert_eq!(bind_for("127.0.0.1:443").ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(bind_for("127.9.9.9:443").ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(bind_for("[::1]:443").ip(), Ipv6Addr::LOCALHOST);
    }

    /// Anything off this host still needs the wildcard bind: the kernel picks the
    /// source address per route, which is what makes multi-homed hosts work.
    #[test]
    fn anything_else_still_binds_all_interfaces() {
        assert_eq!(bind_for("192.0.2.1:443").ip(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(bind_for("[2001:db8::1]:443").ip(), Ipv6Addr::UNSPECIFIED);
    }

    /// The OS assigns the port; a fixed one would collide the second dial.
    #[test]
    fn the_port_is_always_os_assigned() {
        assert_eq!(bind_for("192.0.2.1:443").port(), 0);
        assert_eq!(bind_for("127.0.0.1:443").port(), 0);
    }
}
