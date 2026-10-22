// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where a listener accepts from: which addresses it binds, and which sources it
//! admits.
//!
//! # Two settings, because they answer two questions
//!
//! The gateways used to carry one setting, `bind`, whose values were `lan` and
//! `public`. Only one of those is an address. `public` means "every interface";
//! `loopback` means "this machine"; but **there is no address that means `lan`** —
//! the interface a home network hangs off has no fixed number, and it changes with
//! DHCP, a VPN, or a second NIC. So the `lan` arm could not be written, and in the
//! code as shipped it was not: both branches returned `0.0.0.0` and an operator who
//! chose the cautious value got the exposure of the bold one.
//!
//! `lan` was never answering *which doors do I open*. It was answering *who do I let
//! in* — a different question, and one with a stable answer, because "a private
//! address" is a property of the peer rather than of this host's interfaces.
//!
//! Separating the two is what every comparable system does. PostgreSQL has
//! `listen_addresses` for the interfaces and `pg_hba.conf` for the source ranges;
//! nginx has `listen` and `allow`/`deny`; Jellyfin — the closest analogue, a
//! self-hosted LAN-first server — keeps "bind to local network address" apart from
//! "local networks", and is explicit that they are not the same control. None of
//! them offers a `lan` bind mode, and the reason is the one above.
//!
//! So: [`BindScope`] is the doors, [`SourceAllowList`] is the guest list, and
//! `lan` decomposes into `bind = all` with `allow = private`, which says the same
//! thing without lying about either half.
//!
//! # This is not the process-wide switch
//!
//! `kotton_peer::scope` answers "how wide does *this run* open its sockets", is set
//! by an environment variable, and exists so a test run raises no firewall dialog.
//! These types answer "how is *this gateway* configured", are set by an operator and
//! stored in the device config. Different audiences, different lifetimes; kept apart
//! deliberately, because collapsing two controls into one is the mistake this module
//! exists to undo.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Which local addresses a listener binds.
///
/// The default is [`BindScope::Loopback`]: a node that has not been told to accept
/// connections from elsewhere should not be reachable from elsewhere. That is the
/// same default PostgreSQL ships (`listen_addresses = localhost`), and for the same
/// reason — the safe end of the range is the one you get by not deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindScope {
    /// This machine only. Nothing off-host can reach the socket, and no OS firewall
    /// dialog is raised, because none is warranted.
    Loopback,
    /// Every interface (`0.0.0.0` / `::`). What the operator's firewall, and the
    /// allow-list beside this setting, are then responsible for narrowing.
    All,
    /// One specific local address. The escape hatch for a multi-homed host that
    /// wants exactly one interface; nothing detects it, the operator names it.
    Addr(IpAddr),
}

impl BindScope {
    /// The IPv4 address to bind. `Addr` holding a v6 address yields `None` — the
    /// caller wanted a family this scope does not name.
    pub fn bind_ipv4(self) -> Option<Ipv4Addr> {
        match self {
            Self::Loopback => Some(Ipv4Addr::LOCALHOST),
            Self::All => Some(Ipv4Addr::UNSPECIFIED),
            Self::Addr(IpAddr::V4(a)) => Some(a),
            Self::Addr(IpAddr::V6(_)) => None,
        }
    }

    /// The IPv6 address to bind, on the same terms as [`Self::bind_ipv4`].
    pub fn bind_ipv6(self) -> Option<Ipv6Addr> {
        match self {
            Self::Loopback => Some(Ipv6Addr::LOCALHOST),
            Self::All => Some(Ipv6Addr::UNSPECIFIED),
            Self::Addr(IpAddr::V6(a)) => Some(a),
            Self::Addr(IpAddr::V4(_)) => None,
        }
    }

    /// True when this scope opens a socket something off this machine could reach —
    /// the condition that raises the OS firewall dialog, and the one worth saying
    /// out loud in a log line at startup.
    pub fn is_offhost(self) -> bool {
        match self {
            Self::Loopback => false,
            Self::All => true,
            Self::Addr(ip) => !ip.is_loopback(),
        }
    }
}

impl fmt::Display for BindScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loopback => f.write_str("loopback"),
            Self::All => f.write_str("all"),
            Self::Addr(ip) => write!(f, "{ip}"),
        }
    }
}

/// Why a stored bind value could not be used.
///
/// Carried rather than swallowed: a bind scope the daemon cannot parse is an
/// operator's stated intent it cannot honour, and guessing is how `lan` came to mean
/// `public`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The value as stored, for an error message that names what is actually wrong.
    pub value: String,
    /// What was expected instead.
    pub expected: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not valid here; expected {}", self.value, self.expected)
    }
}

impl std::error::Error for ParseError {}

const BIND_EXPECTED: &str = "`loopback`, `all`, or a literal IP address";

impl std::str::FromStr for BindScope {
    type Err = ParseError;

    /// Parses a stored bind value. Case- and whitespace-insensitive, because these
    /// are hand-typed; **not** lenient about anything else. An unrecognised value is
    /// an error rather than a fallback: silently treating one as `lan` is the
    /// defect this type replaces.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let v = raw.trim().to_ascii_lowercase();
        match v.as_str() {
            "loopback" | "localhost" => Ok(Self::Loopback),
            "all" | "any" => Ok(Self::All),
            _ => v.parse::<IpAddr>().map(Self::Addr).map_err(|_| ParseError {
                value: raw.to_string(),
                expected: BIND_EXPECTED,
            }),
        }
    }
}

/// One CIDR block: a network address and how many leading bits are significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// True when `ip` falls inside this block.
    ///
    /// A v4 address is never inside a v6 block or the reverse. That is deliberate
    /// rather than an omission: an IPv4-mapped v6 address (`::ffff:10.0.0.1`) must
    /// not slip through a v6 rule that never named the v4 range, so callers
    /// normalise before asking — see [`SourceAllowList::permits`].
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                masked(net.to_bits(), self.prefix_len, 32) == masked(addr.to_bits(), self.prefix_len, 32)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                masked128(net.to_bits(), self.prefix_len) == masked128(addr.to_bits(), self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Keep the top `prefix_len` bits of a 32-bit address, zero the rest.
///
/// Split out because a shift by the full width is undefined in C and a panic in
/// debug Rust, so `/0` and `/32` are the two ends that have to be handled rather
/// than assumed away.
fn masked(bits: u32, prefix_len: u8, width: u8) -> u32 {
    debug_assert!(prefix_len <= width);
    if prefix_len == 0 {
        return 0;
    }
    let shift = width - prefix_len;
    if shift >= 32 {
        0
    } else {
        bits & (u32::MAX << shift)
    }
}

/// The 128-bit twin of [`masked`].
fn masked128(bits: u128, prefix_len: u8) -> u128 {
    debug_assert!(prefix_len <= 128);
    if prefix_len == 0 {
        return 0;
    }
    let shift = 128 - prefix_len;
    if shift >= 128 {
        0
    } else {
        bits & (u128::MAX << shift)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl std::str::FromStr for Cidr {
    type Err = ParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let err = || ParseError {
            value: raw.to_string(),
            expected: "a CIDR block such as `192.168.0.0/16`",
        };
        let text = raw.trim();
        // A bare address is the single-host block, which is what an operator means
        // by writing one and what every other allow-list accepts.
        let (addr_part, len_part) = match text.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (text, None),
        };
        let network: IpAddr = addr_part.trim().parse().map_err(|_| err())?;
        let full = if network.is_ipv4() { 32u8 } else { 128u8 };
        let prefix_len = match len_part {
            None => full,
            Some(l) => l.trim().parse::<u8>().map_err(|_| err())?,
        };
        if prefix_len > full {
            return Err(err());
        }
        Ok(Self { network, prefix_len })
    }
}

/// Which source addresses a listener admits, evaluated per connection.
///
/// Empty means **no source restriction** — every peer that reaches the socket is
/// admitted, and the bind scope alone decides who can reach it. That is the honest
/// default: an allow-list nobody configured should not silently become a filter
/// nobody can see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceAllowList {
    blocks: Vec<Cidr>,
}

/// The private and non-routable ranges, as `private` expands to.
///
/// This is the set that answers "is this peer on my network" without naming an
/// interface: RFC 1918, carrier-grade NAT, link-local, and their v6 counterparts,
/// plus loopback, which must stay admissible or a gateway locks out its own host.
const PRIVATE_BLOCKS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",   // CGNAT — where Tailscale and many ISP LANs live
    "169.254.0.0/16",  // link-local
    "127.0.0.0/8",     // this host
    "fc00::/7",        // unique local
    "fe80::/10",       // link-local
    "::1/128",         // this host
];

impl SourceAllowList {
    /// Every source is admitted; the bind scope is the only narrowing.
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// True when nothing was configured, so every source is admitted.
    pub fn is_unrestricted(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The blocks, for a startup log line that states the policy rather than
    /// implying it.
    pub fn blocks(&self) -> &[Cidr] {
        &self.blocks
    }

    /// Whether a peer at `ip` may proceed.
    ///
    /// An IPv4-mapped v6 source (`::ffff:10.0.0.1`, which is how a dual-stack socket
    /// reports an IPv4 peer) is unmapped first, so a v4 rule matches a v4 peer
    /// however the socket happened to describe it. Without that, `10.0.0.0/8` would
    /// silently fail to match the very peers it names.
    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.blocks.is_empty() {
            return true;
        }
        let ip = unmap_v4(ip);
        self.blocks.iter().any(|b| b.contains(ip))
    }
}

/// Reduce an IPv4-mapped IPv6 address to the IPv4 address it carries.
fn unmap_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

impl std::str::FromStr for SourceAllowList {
    type Err = ParseError;

    /// Parses a comma-separated list. `private` expands to [`PRIVATE_BLOCKS`]; an
    /// empty string is [`Self::unrestricted`]. One bad entry fails the whole list —
    /// a partially-applied allow-list is a policy nobody wrote.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let mut blocks = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry.eq_ignore_ascii_case("private") {
                for b in PRIVATE_BLOCKS {
                    blocks.push(b.parse().expect("PRIVATE_BLOCKS are valid CIDRs"));
                }
            } else {
                blocks.push(entry.parse()?);
            }
        }
        Ok(Self { blocks })
    }
}

/// A stored gateway exposure setting, after the deprecated single-value spellings
/// have been decomposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    /// Which local addresses to bind.
    pub scope: BindScope,
    /// Which sources to admit once bound.
    pub allow: SourceAllowList,
    /// Set when the stored value used a deprecated spelling, naming what to write
    /// instead. Worth a startup warning rather than silence: the operator's config
    /// still says something the code no longer speaks.
    pub deprecated: Option<&'static str>,
}

impl Exposure {
    /// Interpret a stored `bind` value and its companion `allow` value.
    ///
    /// The two legacy spellings are accepted rather than refused, because refusing
    /// would strand every device already configured:
    ///
    /// - `public` → bind every interface, admit every source. Unchanged behaviour.
    /// - `lan` → bind every interface, admit private sources only. This **narrows**
    ///   what the device does, which is the point: it is what the operator asked for
    ///   and did not get.
    ///
    /// Anything else unrecognised is an error, never a fallback.
    pub fn parse(bind: &str, allow: Option<&str>) -> Result<Self, ParseError> {
        let trimmed = bind.trim().to_ascii_lowercase();
        let explicit_allow = allow
            .map(|a| a.parse::<SourceAllowList>())
            .transpose()?;

        let (scope, default_allow, deprecated) = match trimmed.as_str() {
            "lan" => (
                BindScope::All,
                "private".parse().expect("`private` is a valid allow-list"),
                Some("bind = all, allow = private"),
            ),
            "public" => (
                BindScope::All,
                SourceAllowList::unrestricted(),
                Some("bind = all"),
            ),
            _ => (
                bind.parse::<BindScope>()?,
                SourceAllowList::unrestricted(),
                None,
            ),
        };

        Ok(Self {
            scope,
            // An explicit allow-list always wins: an operator who wrote one meant it,
            // including when they are still on a legacy `bind` spelling.
            allow: explicit_allow.unwrap_or(default_allow),
            deprecated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address parses")
    }

    #[test]
    fn the_default_is_this_machine_only() {
        // Not merely a preference: the value you get by not deciding must be the
        // safe end of the range, which is why PostgreSQL ships `localhost` too.
        let e = Exposure::parse("loopback", None).expect("parses");
        assert_eq!(e.scope, BindScope::Loopback);
        assert!(!e.scope.is_offhost());
        assert_eq!(e.scope.bind_ipv4(), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(e.scope.bind_ipv6(), Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn all_binds_every_interface_in_both_families() {
        let s: BindScope = "all".parse().expect("parses");
        assert_eq!(s.bind_ipv4(), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(s.bind_ipv6(), Some(Ipv6Addr::UNSPECIFIED));
        assert!(s.is_offhost());
    }

    #[test]
    fn a_literal_address_names_one_interface_and_only_its_family() {
        let s: BindScope = "192.168.4.68".parse().expect("parses");
        assert_eq!(s.bind_ipv4(), Some(Ipv4Addr::new(192, 168, 4, 68)));
        // Asking a v4 scope for a v6 address is a question it cannot answer; it
        // must not quietly widen to `::`.
        assert_eq!(s.bind_ipv6(), None);
        assert!(s.is_offhost());
    }

    #[test]
    fn a_literal_loopback_is_not_offhost() {
        assert!(!"127.0.0.1".parse::<BindScope>().expect("parses").is_offhost());
        assert!(!"::1".parse::<BindScope>().expect("parses").is_offhost());
    }

    /// The defect this type exists to prevent: an unreadable value silently becoming
    /// the wide bind.
    #[test]
    fn an_unrecognised_bind_value_is_refused_not_guessed() {
        for bad in ["lann", "wan", "", "0.0.0.0.0", "loop back", "yes"] {
            assert!(
                bad.parse::<BindScope>().is_err(),
                "{bad:?} must not parse to a scope",
            );
            assert!(
                Exposure::parse(bad, None).is_err(),
                "{bad:?} must not resolve to an exposure",
            );
        }
    }

    #[test]
    fn hand_typed_spacing_and_case_are_tolerated() {
        assert_eq!("  LoopBack ".parse::<BindScope>().expect("parses"), BindScope::Loopback);
        assert_eq!("ALL".parse::<BindScope>().expect("parses"), BindScope::All);
    }

    #[test]
    fn legacy_lan_narrows_to_what_it_always_claimed() {
        let e = Exposure::parse("lan", None).expect("parses");
        assert_eq!(e.scope, BindScope::All);
        assert!(e.deprecated.is_some(), "a legacy spelling must be reported");
        // The behaviour change that fixes the bug: LAN peers still reach it, the
        // open internet no longer does.
        assert!(e.allow.permits(ip("192.168.1.20")));
        assert!(e.allow.permits(ip("10.1.2.3")));
        assert!(e.allow.permits(ip("127.0.0.1")));
        assert!(!e.allow.permits(ip("8.8.8.8")));
        assert!(!e.allow.permits(ip("203.0.113.7")));
    }

    #[test]
    fn legacy_public_keeps_admitting_everyone() {
        let e = Exposure::parse("public", None).expect("parses");
        assert_eq!(e.scope, BindScope::All);
        assert!(e.allow.is_unrestricted());
        assert!(e.allow.permits(ip("8.8.8.8")));
    }

    /// The two legacy values used to be indistinguishable. That is the bug.
    #[test]
    fn lan_and_public_no_longer_mean_the_same_thing() {
        let lan = Exposure::parse("lan", None).expect("parses");
        let public = Exposure::parse("public", None).expect("parses");
        assert_ne!(lan.allow, public.allow);
        assert!(!lan.allow.permits(ip("8.8.8.8")));
        assert!(public.allow.permits(ip("8.8.8.8")));
    }

    #[test]
    fn an_explicit_allow_list_overrides_a_legacy_default() {
        let e = Exposure::parse("lan", Some("203.0.113.0/24")).expect("parses");
        assert!(e.allow.permits(ip("203.0.113.7")));
        assert!(!e.allow.permits(ip("192.168.1.20")), "the operator replaced the default");
    }

    #[test]
    fn an_empty_allow_list_restricts_nothing() {
        let e = Exposure::parse("all", Some("")).expect("parses");
        assert!(e.allow.is_unrestricted());
        assert!(e.allow.permits(ip("8.8.8.8")));
    }

    #[test]
    fn a_bare_address_is_a_single_host_rule() {
        let list: SourceAllowList = "192.168.1.20".parse().expect("parses");
        assert!(list.permits(ip("192.168.1.20")));
        assert!(!list.permits(ip("192.168.1.21")));
    }

    /// A dual-stack socket reports an IPv4 peer as `::ffff:a.b.c.d`. If that is not
    /// unmapped, a v4 rule silently fails to match the peers it names — the same
    /// v4-mapped hazard the pairing listener binds per-family to avoid.
    #[test]
    fn a_v4_mapped_source_matches_its_v4_rule() {
        let list: SourceAllowList = "10.0.0.0/8".parse().expect("parses");
        assert!(list.permits(ip("::ffff:10.1.2.3")));
        assert!(!list.permits(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn prefix_boundaries_hold_at_both_ends() {
        let all_v4: Cidr = "0.0.0.0/0".parse().expect("parses");
        assert!(all_v4.contains(ip("8.8.8.8")));
        assert!(all_v4.contains(ip("192.168.1.1")));

        let one_host: Cidr = "192.168.1.1/32".parse().expect("parses");
        assert!(one_host.contains(ip("192.168.1.1")));
        assert!(!one_host.contains(ip("192.168.1.2")));

        let all_v6: Cidr = "::/0".parse().expect("parses");
        assert!(all_v6.contains(ip("2001:db8::1")));

        let one_v6: Cidr = "::1/128".parse().expect("parses");
        assert!(one_v6.contains(ip("::1")));
        assert!(!one_v6.contains(ip("::2")));
    }

    #[test]
    fn a_block_never_matches_across_families() {
        let v4: Cidr = "0.0.0.0/0".parse().expect("parses");
        assert!(!v4.contains(ip("2001:db8::1")), "a v4 block must not swallow v6");
        let v6: Cidr = "::/0".parse().expect("parses");
        assert!(!v6.contains(ip("8.8.8.8")), "a v6 block must not swallow v4");
    }

    #[test]
    fn the_v6_private_ranges_are_covered_too() {
        let e = Exposure::parse("lan", None).expect("parses");
        assert!(e.allow.permits(ip("fd00::1")), "unique-local is private");
        assert!(e.allow.permits(ip("fe80::1")), "link-local is private");
        assert!(e.allow.permits(ip("::1")), "the host must not lock itself out");
        assert!(!e.allow.permits(ip("2001:db8::1")), "documentation range is not private");
    }

    #[test]
    fn a_malformed_cidr_fails_the_whole_list() {
        // Half a policy is not a policy: applying the entries that happened to parse
        // would leave a filter nobody wrote.
        for bad in ["192.168.0.0/33", "192.168.0.0/-1", "notanaddress", "10.0.0.0/8, oops"] {
            assert!(bad.parse::<SourceAllowList>().is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_private_set_parses_and_is_not_empty() {
        // Guards the `expect` in the parser: if a block here is ever mistyped, this
        // fails in `cargo test` rather than panicking inside a running gateway.
        let list: SourceAllowList = "private".parse().expect("`private` expands");
        assert_eq!(list.blocks().len(), PRIVATE_BLOCKS.len());
    }

    #[test]
    fn display_round_trips_through_the_parser() {
        for text in ["loopback", "all", "192.168.4.68", "::1"] {
            let scope: BindScope = text.parse().expect("parses");
            assert_eq!(
                scope.to_string().parse::<BindScope>().expect("re-parses"),
                scope,
                "{text} must survive a round trip",
            );
        }
    }
}
