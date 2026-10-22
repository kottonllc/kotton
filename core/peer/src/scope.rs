// SPDX-License-Identifier: AGPL-3.0-or-later
//! How wide this run opens its sockets.
//!
//! Every inbound socket this device binds is a statement about who may reach it,
//! and the default is deliberately wide: zero-config LAN discovery
//! needs an all-interfaces bind and a multicast advertise, or a second machine on
//! the same network cannot find this one without someone finding and typing an
//! address.
//!
//! A same-machine run wants the opposite. Two daemons on one host reach each other
//! over loopback — the joiner dials the address carried in the connection code, and
//! every test in the suite dials `127.0.0.1` — so a LAN-facing socket buys nothing
//! there and costs a GUI firewall dialog on Windows and macOS. That dialog is not a
//! notice a background or CI run can dismiss: the run sits blocked on it and reads
//! as a slow test rather than a stuck one.
//!
//! # Why this is not filed under `pairing`
//!
//! It was, and that is precisely what went wrong. The switch was introduced for the
//! pairing bootstrap listener and named for it, so the *other* sockets a run opens
//! never consulted it — most visibly [`Reachability::bind_peer_listener`], which
//! every two-node integration test binds and which kept raising the dialog the
//! switch existed to prevent. Socket scope is one property of the whole run; it
//! lives here so that the next subsystem to bind a listener finds it.
//!
//! # What honors it
//!
//! - the pairing bootstrap QUIC listener ([`crate::pairing::open_pair_listener`]),
//!   down to the per-family socket bind beneath it
//! - the mDNS pairing advertise and browse (`kuserd`'s pairing handlers)
//! - the QUIC peer listener ([`Reachability::bind_peer_listener`]), and with it the
//!   STUN probe and presence registration — a loopback socket has no reflexive
//!   address worth announcing
//! - the local-network door ([`crate::local_door`]): its listener through
//!   [`Reachability::bind_door_listener`], and its announcement, which the device's
//!   keeper skips
//!
//! # What it cannot reach, and why
//!
//! This module is domain-tier. `kotton-net` is a **primitive**, so nothing
//! in it — the mDNS `ServiceDaemon` most of all — can call up into this switch without
//! inverting the tier. That is the right dependency direction, not an oversight:
//! deciding whether this node wants to be found is policy, and `net`'s job is to
//! provide discovery, not to have an opinion about who is asking.
//!
//! The consequence is that a primitive-tier socket has to be gated by whoever
//! *constructs* it. The boot path constructs none: a standing announcement is
//! something the door has to cover and this switch does not, so boot announces
//! nothing.
//! `kotton-net`'s own unit tests are not gated — three of them build a live daemon and
//! bind `:5353` — so they are `#[ignore]`d instead, which is the only lever a
//! primitive's test module has.
//!
//! [`Reachability::bind_peer_listener`]: crate::reachability::Reachability::bind_peer_listener
//! [`Reachability::bind_door_listener`]: crate::reachability::Reachability::bind_door_listener

use std::net::{Ipv4Addr, Ipv6Addr};

/// True when the run declared itself same-machine: bind loopback, skip multicast.
///
/// Set `KOTTON_PAIR_LOCAL_ONLY=1` (`true` and `yes` are also accepted). The
/// variable keeps its historical `PAIR_` spelling because the `Justfile`, the
/// integration tests, and the docs already set it under that name; what it governs
/// is every socket listed in the module docs, not pairing alone.
///
/// An explicit opt-*out*, never the default: unset, zero-config LAN discovery keeps
/// working, because that feature genuinely needs the wide bind.
pub fn local_only() -> bool {
    matches!(
        std::env::var("KOTTON_PAIR_LOCAL_ONLY").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// The IPv4 address an inbound listener should bind on this run.
///
/// Call this rather than naming an address at the bind site. The peer listener kept
/// raising a firewall dialog for exactly that reason: it spelled `0.0.0.0` itself,
/// so it could not be told otherwise.
pub fn inbound_bind_ip() -> Ipv4Addr {
    bind_ip_for(local_only())
}

/// The IPv6 address an inbound listener should bind on this run.
///
/// The pairing listener binds one socket per address family, so the switch needs a
/// v6 answer as well as a v4 one — without it that listener consulted nothing and
/// spelled `::` itself, which is the failure this module exists to end.
pub fn inbound_bind_ip_v6() -> Ipv6Addr {
    bind_ip_v6_for(local_only())
}

/// The address policy, split out from the environment read so it is testable
/// without mutating process-global state — and so a caller that has already read
/// the switch decides from that one read rather than consulting it twice.
pub(crate) fn bind_ip_for(local_only: bool) -> Ipv4Addr {
    if local_only {
        Ipv4Addr::LOCALHOST
    } else {
        Ipv4Addr::UNSPECIFIED
    }
}

/// The same policy for IPv6. Kept beside its v4 twin rather than derived from it:
/// one place to read when asking what this run binds.
pub(crate) fn bind_ip_v6_for(local_only: bool) -> Ipv6Addr {
    if local_only {
        Ipv6Addr::LOCALHOST
    } else {
        Ipv6Addr::UNSPECIFIED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The v6 half of the policy tracks the v4 half. They are separate functions,
    /// so nothing but a test says they agree.
    #[test]
    fn both_families_narrow_and_widen_together() {
        assert_eq!(bind_ip_v6_for(true), Ipv6Addr::LOCALHOST);
        assert_eq!(bind_ip_v6_for(false), Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            bind_ip_for(true).is_loopback(),
            bind_ip_v6_for(true).is_loopback(),
        );
        assert_eq!(
            bind_ip_for(false).is_unspecified(),
            bind_ip_v6_for(false).is_unspecified(),
        );
    }

    /// The wide bind is the default, because zero-config LAN discovery needs it.
    /// Narrowing it is something a run has to ask for.
    #[test]
    fn the_default_bind_is_all_interfaces() {
        assert_eq!(bind_ip_for(false), Ipv4Addr::UNSPECIFIED);
    }

    /// A same-machine run reaches every peer it has over loopback, so that is all
    /// it opens — the property the firewall dialog was the symptom of losing.
    #[test]
    fn a_same_machine_run_binds_loopback() {
        assert_eq!(bind_ip_for(true), Ipv4Addr::LOCALHOST);
    }
}
