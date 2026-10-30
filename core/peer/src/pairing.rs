// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device enrollment ceremony + supporting codecs.
//!
//! The live enrollment ceremony (`run_enroll_issuer_committed` /
//! `run_enroll_join_committed`) runs the **forward-secret committed handshake**
//! (`crate::pair_channel`) over a bootstrap QUIC connection: the payload rides
//! ephemeral-X25519 ECDH, and the channel is authenticated either by a
//! six-digit SAS (interactive) or an out-of-band pinned code. There is no
//! static–static ECDH seal: it would have no forward secrecy.
//!
//! **The joiner's answer is the ceremony's last frame, and the issuer commits
//! nothing before it.** Every joining ceremony returns what it was handed
//! together with a [`JoinAnswer`]: the joiner writes what it keeps, then
//! answers `kept`, or `refused` with its reason. Every issuing ceremony
//! returns only on `kept` — a refusal, a close, or silence past
//! [`JOINER_KEEPS_WITHIN`] is [`JoinNotKept`] — so its caller records the joiner
//! and introduces it at the person's drives only for a join the joiner kept,
//! and a join the joiner refused leaves the issuer with no row and no
//! introduction. The issuer replies to `kept` with a sealed `heard`, and the
//! joiner calls the join complete only on that reply; any other end — the
//! issuer's give-up, a reset, a relay's close, which a relay may say on its
//! own — is *the other device may not have kept this*. What stays uncertain
//! is the last message, as it always is: a `heard` lost after the issuer sent
//! it leaves a joiner told to check a device that did keep it, never the
//! reverse.
//!
//! This module also holds:
//! * `open_pair_listener` — bind the bootstrap QUIC listener.
//! * `encode/parse_connection_code` (sid + addr, base32) — the hand-carried fallback
//!   for pairing off-LAN or when mDNS discovery is blocked.
//! * `generate/parse_pairing_code` — the address/pubkey codec `open_pair_listener`
//!   uses internally.
//! * `ed25519_to_x25519_{public,private}` — Ed25519↔X25519 conversion, shared with
//!   guest-session and DM encryption.

use crate::contact_pairing::{generate_code, normalize_code, rendezvous_in, RendezvousDomain};
use anyhow::{anyhow, Context, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use kotton_net::extract_ed25519_pubkey_from_cert;
use kotton_net::transport::{rendezvous_dial, rendezvous_reserve};
use kotton_wire::peer::{
    DataKeys, FrostSharePayload, PairedNode, PairingPayload, WarmKeyDelegation,
};
use rand::RngCore;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Pairing code — encodes ephemeral pubkey + expiry as a hex string
// ---------------------------------------------------------------------------

/// Encode a pairing code from an Ed25519 public key, the listener's socket
/// address (host + port), and a Unix expiry timestamp.
///
/// Format (all hex): `{pubkey_hex}-{addr_ip_hex}{addr_port_hex}-{expiry_hex}`
///
/// IPv4: `pubkey(64)` + `-` + `ip4(8)` + `port(4)` + `-` + `expiry(16)` = 95 chars
/// IPv6: `pubkey(64)` + `-` + `ip6(32)` + `port(4)` + `-` + `expiry(16)` = 119 chars
pub fn generate_pairing_code(pubkey: [u8; 32], listen_addr: SocketAddr, expires_at: u64) -> String {
    let exp_bytes = expires_at.to_be_bytes();
    let hex_key = hex::encode(pubkey);
    let hex_exp = hex::encode(exp_bytes);
    let hex_addr = encode_addr(listen_addr);
    format!("{hex_key}-{hex_addr}-{hex_exp}")
}

/// Parse and validate a pairing code produced by [`generate_pairing_code`].
///
/// Returns `(pubkey, listen_addr, expires_at)`.
/// Returns an error if the code is malformed or the TTL has expired.
pub fn parse_pairing_code(code: &str, now: u64) -> Result<([u8; 32], SocketAddr, u64)> {
    // Expected segments: pubkey-addr-expiry
    let parts: Vec<&str> = code.splitn(3, '-').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "malformed pairing code: expected 3 dash-separated segments"
        ));
    }
    let (key_hex, addr_hex, exp_hex) = (parts[0], parts[1], parts[2]);

    // Decode pubkey
    let key_bytes_raw =
        hex::decode(key_hex).context("malformed pairing code: invalid pubkey hex")?;
    if key_bytes_raw.len() != 32 {
        return Err(anyhow!("malformed pairing code: pubkey must be 32 bytes"));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&key_bytes_raw);

    // Decode address
    let listen_addr =
        decode_addr(addr_hex).context("malformed pairing code: invalid address encoding")?;

    // Decode expiry
    let exp_bytes = hex::decode(exp_hex).context("malformed pairing code: invalid expiry hex")?;
    if exp_bytes.len() != 8 {
        return Err(anyhow!("malformed pairing code: expiry must be 8 bytes"));
    }
    let expires_at = u64::from_be_bytes(exp_bytes.try_into().unwrap());

    if now > expires_at {
        return Err(anyhow!(
            "pairing code expired (expired at {expires_at}, now is {now})"
        ));
    }

    Ok((pubkey, listen_addr, expires_at))
}

// ---------------------------------------------------------------------------
// Interim connection code (address + session id, no key material)
// ---------------------------------------------------------------------------

/// Encode a **connection code**: the offer's session id + the issuer's
/// bootstrap address, as Crockford **base32**. Unlike the retired enrollment code it
/// carries **no key material** — the six-digit SAS authenticates the channel, so the
/// code only needs to say *where* and *which offer*. It is the hand-carried stand-in
/// for when mDNS discovery didn't find the peer; there the address is the dial
/// target, so it stays in the code.
///
/// base32 (not hex) because any code that must be *typed* is base32: the alphabet drops the look-alikes (`i l o u`), is case-insensitive, and
/// packs the same bytes into ~20% fewer characters — all of which matter when a human
/// reads the code off one screen and types it on another. The length is still
/// dominated by the 16-byte `sid`; shortening *that* is a separate security decision.
pub fn encode_connection_code(sid: &[u8; 16], addr: SocketAddr) -> String {
    let mut payload = sid.to_vec();
    payload.extend_from_slice(&addr_to_bytes(addr));
    base32_encode(&payload)
}

/// Parse a code from [`encode_connection_code`] into `(sid, addr)`. Tolerant of
/// case, hyphens, and spaces so a human's transcription round-trips.
pub fn parse_connection_code(code: &str) -> Result<([u8; 16], SocketAddr)> {
    let bytes = base32_decode(code).context("malformed connection code")?;
    if bytes.len() < 16 {
        return Err(anyhow!("malformed connection code: too short for a sid"));
    }
    let sid: [u8; 16] = bytes[..16].try_into().unwrap();
    let addr =
        addr_from_bytes(&bytes[16..]).context("malformed connection code: invalid address")?;
    Ok((sid, addr))
}

/// Raw wire bytes for an address — `[ip octets][2-byte big-endian port]`, so 6 bytes
/// for IPv4 and 18 for IPv6. One address encoding, shared by the hex pairing code and
/// the base32 connection code.
fn addr_to_bytes(addr: SocketAddr) -> Vec<u8> {
    let mut buf = match addr {
        SocketAddr::V4(a) => a.ip().octets().to_vec(),
        SocketAddr::V6(a) => a.ip().octets().to_vec(),
    };
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf
}

/// Parse the raw address bytes produced by [`addr_to_bytes`].
fn addr_from_bytes(bytes: &[u8]) -> Result<SocketAddr> {
    match bytes.len() {
        6 => {
            let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            Ok(SocketAddr::from((ip, port)))
        }
        18 => {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&bytes[..16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Ok(SocketAddr::from((ip, port)))
        }
        n => Err(anyhow!("unexpected address byte length {n}")),
    }
}

// Hex form of `addr_to_bytes`, for the contact pairing code.
fn encode_addr(addr: SocketAddr) -> String {
    hex::encode(addr_to_bytes(addr))
}

// Decode an addr from the hex format produced by `encode_addr`.
fn decode_addr(hex_str: &str) -> Result<SocketAddr> {
    addr_from_bytes(&hex::decode(hex_str).context("invalid address hex")?)
}

// Crockford base32 alphabet (lowercase): the digits and letters with the
// ambiguous `i l o u` removed — codes a human must type.
// It lives in `kotton_common::base32` — shared with the
// blinded object keys, which need the same alphabet for a different reason
// (filesystem-safe and short against MAX_PATH, rather than human-typable).

fn base32_encode(data: &[u8]) -> String {
    kotton_common::base32::encode(data)
}

fn base32_decode(code: &str) -> Result<Vec<u8>> {
    kotton_common::base32::decode(code).ok_or_else(|| anyhow!("invalid base32 character in code"))
}

// ---------------------------------------------------------------------------
// Ed25519 ↔ X25519 key conversion (Birkhoff point conversion)
// ---------------------------------------------------------------------------

/// Convert an Ed25519 public key (compressed Edwards point) to an X25519 public
/// key (Montgomery u-coordinate).
///
/// This is the standard "Birkhoff" conversion specified in RFC 7748 §4.1.
pub fn ed25519_to_x25519_public(ed25519_bytes: [u8; 32]) -> Result<X25519PublicKey> {
    let compressed = CompressedEdwardsY(ed25519_bytes);
    let point = compressed
        .decompress()
        .ok_or_else(|| anyhow!("ed25519_to_x25519_public: invalid Edwards point"))?;
    let montgomery = point.to_montgomery();
    Ok(X25519PublicKey::from(montgomery.to_bytes()))
}

/// Convert an Ed25519 signing key seed to an X25519 static secret.
///
/// Ed25519 private keys are seeds — the actual scalar is `SHA-512(seed)[..32]`
/// after clamping. This is the same scalar used by X25519 (same underlying
/// curve, different coordinate system).
///
/// Reference: <https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-23.txt>
/// Section 4.1.
pub fn ed25519_to_x25519_private(signing_key: &SigningKey) -> StaticSecret {
    // Step 1: hash the 32-byte seed with SHA-512
    let seed = signing_key.as_bytes();
    let hash: [u8; 64] = Sha512::digest(seed).into();

    // Step 2: take the first 32 bytes
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);

    // Step 3: clamp (RFC 7748 §5); same clamping as for X25519 keys
    scalar[0] &= 248; // clear the 3 lowest bits
    scalar[31] &= 127; // clear the highest bit
    scalar[31] |= 64; // set the second-highest bit

    StaticSecret::from(scalar)
}

// ---------------------------------------------------------------------------
// Bootstrap QUIC listener
// ---------------------------------------------------------------------------

/// Choose the IP a pairing/connection code should advertise, so a joiner on
/// another machine can dial back. The socket bind is never affected — this only
/// rewrites the address *carried in the code*. Priority:
///
/// 1. **`KOTTON_ADVERTISE_IP`** (`override_ip`), if set to a valid IP — the
///    explicit escape hatch for setups auto-detection can't infer: a multi-homed
///    or VPN host where the wrong interface would be picked, a NAT/port-forwarded
///    public address, or a CI run that wants a deterministic address. It is **not**
///    a path a normal user should ever be told to walk (see [`detect_lan_ip`]).
/// 2. **A detected routable LAN IP** (`detected_lan_ip`), when the listener bound
///    all interfaces (`0.0.0.0`/`::`) — the zero-config default that makes a
///    hand-carried code work across machines on the same network without anyone
///    finding or exporting an IP.
/// 3. **Unchanged** otherwise — e.g. a deliberate loopback bind under
///    `KOTTON_PAIR_LOCAL_ONLY`, or when detection found nothing dialable (an
///    isolated host); the joiner remaps an unspecified IP to loopback, so
///    same-host pairing still works.
///
/// Pure (no env/network) so the precedence is unit-testable; [`advertised_addr`]
/// wires in the real env var + detection.
fn choose_advertised_addr(
    addr: SocketAddr,
    override_ip: Option<IpAddr>,
    detected_lan_ip: Option<IpAddr>,
) -> SocketAddr {
    if let Some(ip) = override_ip {
        return SocketAddr::new(ip, addr.port());
    }
    if addr.ip().is_unspecified() {
        if let Some(ip) = detected_lan_ip {
            return SocketAddr::new(ip, addr.port());
        }
    }
    addr
}

/// Parse `KOTTON_ADVERTISE_IP` into an override IP, warning (once) on a malformed
/// value rather than silently ignoring the operator's intent.
fn advertise_ip_override() -> Option<IpAddr> {
    let raw = std::env::var("KOTTON_ADVERTISE_IP").ok()?;
    match raw.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => {
            tracing::warn!("KOTTON_ADVERTISE_IP='{raw}' is not a valid IP address; ignoring");
            None
        }
    }
}

/// Best-effort discovery of this machine's primary routable LAN IPv4, so the
/// zero-config default (2) in [`choose_advertised_addr`] can fill an all-interfaces
/// bind with an address a peer can actually dial — no operator step required.
///
/// Reads the OS routing table **without emitting a packet**: a UDP socket
/// `connect`ed to an off-link address adopts the source IP the kernel would route
/// from, which we read back via `local_addr`. UDP `connect` only records a default
/// peer — it opens no connection and sends nothing — and needs no reachability,
/// just a route. The destination is a TEST-NET-1 (RFC 5737) address so nothing
/// here implies a dependency on a real host.
///
/// **Limit / why the override seam stays:** this resolves a source IP only when a
/// **default route** exists (the same-Wi-Fi-through-a-router case — always true for
/// the ceremony's target). A gateway-less LAN (two hosts on a bare switch, no router)
/// has no default route; `connect` fails and this returns `None`, and the operator
/// falls back to `KOTTON_ADVERTISE_IP`. IPv4 is probed because the connection code
/// carries a single address and IPv4 is the simplest zero-config choice the
/// dual-stack issuer listener still accepts (discovery, which sees the full
/// advertised set, prefers IPv6 — see `rank_dial_candidates`).
/// Returns `None` unless the result is a plausibly-dialable LAN address.
fn detect_lan_ip() -> Option<IpAddr> {
    use socket2::{Domain, Socket, Type};

    // Deliberately *unbound*. `UdpSocket::bind((0.0.0.0, 0))` is the usual spelling
    // of this trick, and it opens a wildcard socket to ask a routing question —
    // which is the thing that raises the firewall dialog on Windows and macOS, for
    // a socket that never carries a packet. Connecting an unbound datagram socket
    // makes the kernel choose and assign the source address without a `bind(2)`,
    // giving the same answer with nothing to prompt about.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).ok()?;
    let dst: SocketAddr = (Ipv4Addr::new(192, 0, 2, 1), 9).into();
    socket.connect(&dst.into()).ok()?;
    let ip = socket.local_addr().ok()?.as_socket()?.ip();
    is_dialable_pair_addr(&ip).then_some(ip)
}

/// Rewrite `addr`'s IP to a routable address a cross-machine joiner can dial: an
/// explicit `KOTTON_ADVERTISE_IP` override, else an auto-detected LAN IP for an
/// all-interfaces bind. See [`choose_advertised_addr`] for the policy.
fn advertised_addr(addr: SocketAddr) -> SocketAddr {
    let override_ip = advertise_ip_override();
    // Only probe the routing table when detection can actually change the outcome:
    // no override in force, and an unspecified bind to fill in.
    let detected = if override_ip.is_none() && addr.ip().is_unspecified() {
        detect_lan_ip()
    } else {
        None
    };
    choose_advertised_addr(addr, override_ip, detected)
}

/// Bind one UDP socket for a single address family, **never** dual-stack.
///
/// `IPV6_V6ONLY` is set explicitly to `true` on the v6 socket rather than left to
/// the platform default. That is load-bearing, not tidiness: Linux defaults it
/// *off*, so a `[::]` socket would also claim IPv4 traffic and the sibling
/// `0.0.0.0` bind on the same port would then fail with `EADDRINUSE`. Forcing it
/// on is what makes one-socket-per-family work everywhere, and it is the same
/// choice nginx made its default (`ipv6only=on`).
fn bind_single_family(
    family: Family,
    ip: IpAddr,
    port: u16,
) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let bind: SocketAddr = (ip, port).into();
    // Derived from the address rather than from `family`, so the socket's domain and
    // the address it binds cannot disagree now that the address comes from outside.
    let domain = Domain::for_address(bind);
    debug_assert_eq!(
        matches!(family, Family::V6),
        ip.is_ipv6(),
        "bind_single_family: {family:?} was handed {ip}",
    );
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if matches!(family, Family::V6) {
        // Must precede bind. See the note above — this is what keeps the two
        // sockets from colliding, and what keeps v4-mapped addresses out.
        socket.set_only_v6(true)?;
    }
    socket.bind(&bind.into())?;
    let std_sock: std::net::UdpSocket = socket.into();
    std_sock.set_nonblocking(true)?;
    Ok(std_sock)
}

/// One of the two IP address families a pairing listener can bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// How many times to re-draw an ephemeral port when the two families disagree
/// about whether it is free. Each family has its own port space, so a port the
/// kernel handed us on v6 can be in use on v4; that is rare and independent per
/// attempt, so a few tries is plenty.
const EPHEMERAL_PORT_ATTEMPTS: usize = 8;

/// Bind the pairing listener's sockets: **one per address family**, both on the
/// same port, skipping any family the host does not support.
///
/// **Why not one dual-stack socket.** A single `[::]` socket with `IPV6_V6ONLY`
/// cleared is the tempting shortcut, and it is what this used to do. Two reasons
/// serious servers (nginx, Apache, PostgreSQL) bind per family instead, both of
/// which bite here:
///
/// 1. **It is not portable.** OpenBSD refuses v4-mapped addresses outright and
///    will not let `IPV6_V6ONLY` be cleared at all, so the dual-stack bind simply
///    fails there — and a host that *has* IPv6 would have been demoted to IPv4,
///    advertising a family it no longer answers on. Per-family binding has no
///    such cliff: each family is attempted on its own merits.
/// 2. **v4-mapped addresses leak into the application.** On a dual-stack socket an
///    IPv4 peer's `remote_address()` arrives as `::ffff:a.b.c.d`, which is a
///    *different* `SocketAddr` from `a.b.c.d`, sorts as IPv6 in
///    [`rank_dial_candidates`], and slips past the loopback guard in
///    [`is_dialable_pair_addr`] (`Ipv6Addr::is_loopback` matches only `::1`, so
///    `::ffff:127.0.0.1` reads as routable). Those addresses are recorded as a
///    peer's dialable set and used for later sync. With `v6only` on both sockets,
///    an IPv4 peer lands on the v4 socket as a plain v4 address and the whole
///    class is gone **by construction** rather than by normalising after the fact.
///
/// **The advertise invariant becomes structural.** The rule is *listen on every
/// family we advertise*; the caller advertises exactly the families that appear
/// in the returned set, so the two cannot drift. A host with no IPv6 stack binds
/// v4 only and advertises v4 only; a host with both binds both.
///
/// Fails only when **no** family could be bound, or when an explicitly requested
/// port is unavailable — a port conflict must surface, not be papered over.
fn bind_pair_listener_sockets(port: u16) -> Result<Vec<(Family, std::net::UdpSocket)>> {
    // An explicit port is a fixed target: bind what we can on it, no re-draws.
    if port != 0 {
        return collect_family_sockets(port);
    }
    // Port 0: the kernel picks. The families have separate port spaces, so a port
    // free on one can be taken on the other — draw again rather than give up, and
    // rather than silently letting the families land on different ports.
    let mut last_err = None;
    for _ in 0..EPHEMERAL_PORT_ATTEMPTS {
        match collect_family_sockets(0) {
            Ok(socks) => return Ok(socks),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("could not bind a pairing listener on any family")))
}

/// Bind every family the host supports on one shared port. With `port == 0` the
/// first successful bind fixes the port and the second family must match it.
fn collect_family_sockets(port: u16) -> Result<Vec<(Family, std::net::UdpSocket)>> {
    let mut bound: Vec<(Family, std::net::UdpSocket)> = Vec::with_capacity(2);
    let mut skipped: Vec<String> = Vec::new();
    // v6 first so that, on an ephemeral draw, the port comes from the family more
    // likely to be restricted.
    for family in [Family::V6, Family::V4] {
        // Once one family is bound, the other must use the *same* port — a single
        // listener advertises a single port.
        let want = match bound.first() {
            Some((_, sock)) => sock.local_addr().map(|a| a.port()).unwrap_or(port),
            None => port,
        };
        // The switch reaches the socket here rather than inside the bind helper:
        // the helper is mechanism and takes the address it is given, so the one
        // test whose property *is* the wildcard can ask for one explicitly.
        let ip: IpAddr = match family {
            Family::V6 => crate::scope::inbound_bind_ip_v6().into(),
            Family::V4 => crate::scope::inbound_bind_ip().into(),
        };
        match bind_single_family(family, ip, want) {
            Ok(sock) => bound.push((family, sock)),
            Err(e) => {
                // A second-family failure on a shared ephemeral port means the draw
                // was unlucky; propagate so the caller re-draws rather than
                // publishing a half-bound listener.
                if port == 0 && !bound.is_empty() {
                    return Err(anyhow!("ephemeral port {want} unavailable on {family:?}: {e}"));
                }
                skipped.push(format!("{family:?}: {e}"));
            }
        }
    }
    if bound.is_empty() {
        return Err(anyhow!(
            "could not bind a pairing listener on any address family ({})",
            skipped.join("; ")
        ));
    }
    if !skipped.is_empty() {
        tracing::info!(
            "pairing listener bound {} only ({}). Pairing will work over that family; \
             the other is unavailable on this host.",
            bound
                .iter()
                .map(|(f, _)| format!("{f:?}"))
                .collect::<Vec<_>>()
                .join("+"),
            skipped.join("; ")
        );
    }
    Ok(bound)
}

/// The pairing bootstrap listener: one QUIC endpoint per address family the host
/// supports, all sharing one port.
///
/// Replaces the single `quinn::Endpoint` this used to hand back, because a quinn
/// endpoint owns exactly one socket and the listener now owns one per family.
pub struct PairListener {
    endpoints: Vec<quinn::Endpoint>,
    /// The routable address the connection code and mDNS advertise.
    advertised: SocketAddr,
}

impl PairListener {
    /// Await the next inbound connection on **any** bound family.
    ///
    /// `quinn::Endpoint::accept` is cancel-safe — the loser of the `select!` is
    /// dropped without consuming a queued connection — so racing the families is
    /// sound.
    pub async fn accept(&self) -> Option<quinn::Incoming> {
        match self.endpoints.as_slice() {
            [only] => only.accept().await,
            [a, b] => tokio::select! {
                incoming = a.accept() => incoming,
                incoming = b.accept() => incoming,
            },
            // `bind_pair_listener_sockets` guarantees 1..=2; nothing to accept on.
            _ => None,
        }
    }

    /// The address to advertise (connection code, mDNS) — routable, not the
    /// unspecified bind.
    pub fn advertised_addr(&self) -> SocketAddr {
        self.advertised
    }
}

/// Open a bootstrap QUIC listener for an enrollment ceremony.
///
/// Returns `(listen_addr_code, listen_addr, expires_at, endpoint)`. The caller
/// binds the listener here, then passes `endpoint` to the issuer ceremony
/// (`run_enroll_issuer_committed`). The returned code string is the legacy
/// address/pubkey encoding; the committed ceremony ignores it and builds its own
/// connection/pinned-offer code from `listen_addr`.
///
/// # Arguments
/// * `device_key`  — This device's Ed25519 identity signing key.
/// * `port` — UDP port to bind on (`0` = OS-assigned).
/// * `ttl_seconds` — ceremony TTL; encoded in the code as `expires_at`.
pub async fn open_pair_listener(
    device_key: &SigningKey,
    port: u16,
    ttl_seconds: u64,
) -> Result<(String, SocketAddr, u64, PairListener)> {
    let sc = build_bootstrap_server_config_quinn(device_key)?;
    // A quinn endpoint owns one socket, so one endpoint per bound family.
    let (endpoints, bind_addr) = if crate::scope::local_only() {
        // Same-machine dev/CI: IPv4 loopback only — no LAN, no firewall prompt.
        // The joiner dials 127.0.0.1, so a single-family bind is enough.
        let ep = quinn::Endpoint::server(sc, (Ipv4Addr::LOCALHOST, port).into())
            .map_err(|e| anyhow!("bootstrap QUIC bind failed: {e}"))?;
        let addr = ep
            .local_addr()
            .map_err(|e| anyhow!("could not get local address: {e}"))?;
        (vec![ep], addr)
    } else {
        // LAN: one socket per family. mDNS `enable_addr_auto` advertises *every*
        // interface address — IPv4 and the IPv6 ULA — and the issuer must answer
        // on each one it publishes. An IPv4-only bind listened on none of the
        // IPv6 addresses, so a joiner that picked the ULA (the only address
        // routable across some LANs) dialed a socket nobody was on and timed out.
        let socks = bind_pair_listener_sockets(port)?;
        // Every socket shares a port; take the advertisement base from the v4
        // socket when there is one (the detected LAN address is v4, so a v4 bind
        // keeps the code and the socket in the same family).
        let bind_addr = socks
            .iter()
            .find(|(f, _)| matches!(f, Family::V4))
            .or_else(|| socks.first())
            .map(|(_, s)| s.local_addr())
            .transpose()
            .map_err(|e| anyhow!("could not get local address: {e}"))?
            .ok_or_else(|| anyhow!("no pairing socket bound"))?;

        let mut endpoints = Vec::with_capacity(socks.len());
        for (family, sock) in socks {
            let ep = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(sc.clone()),
                sock,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| anyhow!("bootstrap QUIC bind failed on {family:?}: {e}"))?;
            endpoints.push(ep);
        }
        (endpoints, bind_addr)
    };

    // With the all-interfaces bind, `local_addr()` reports an unspecified IP the
    // joiner resolves to loopback — fine same-host, useless across machines. Fill
    // it with a routable address for the code: an auto-detected LAN IP by default
    // (zero-config same-WiFi join), or `KOTTON_ADVERTISE_IP` when set.
    let listen_addr = advertised_addr(bind_addr);

    let my_pubkey = device_key.verifying_key().to_bytes();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + ttl_seconds;

    let code = generate_pairing_code(my_pubkey, listen_addr, expires_at);
    let listener = PairListener {
        endpoints,
        advertised: listen_addr,
    };
    Ok((code, listen_addr, expires_at, listener))
}

// ---------------------------------------------------------------------------
// FROST node enrollment ceremony (the split-path live flow)
// ---------------------------------------------------------------------------

/// What the new device (N) obtains from a successful node enrollment join.
///
/// The key-material fields are `None` for a **blind** (`BlindStorage`) enrollment
/// — a hosted/untrusted node receives a transport identity and a membership
/// relationship but **no** FROST share and **no** data keys, so the provider
/// cannot decrypt. For a `Full` enrollment they are all `Some`.
pub struct JoinedNode {
    /// N's view of the issuer as a paired node.
    pub peer: PairedNode,
    /// N's FROST key-package share — `None` for a blind enrollment.
    pub frost_share: Option<FrostSharePayload>,
    /// The quorum-signed warm-key delegation — `None` for a blind enrollment.
    pub warm_key_delegation: Option<WarmKeyDelegation>,
    /// The operational data-domain roots (the `data` axis) — `None` for a
    /// blind or co-signer enrollment (no decryption, no record sync).
    pub data_keys: Option<DataKeys>,
    /// The group `PublicKeyPackage` (hex) — `None` for a blind enrollment. Needed
    /// to co-sign threshold signatures (a prerequisite of distributed signing).
    pub pubkey_package: Option<String>,
    /// The issuer's root identity DID (always learned from the enrollment code).
    pub root_did: kotton_wire::did::Did,
    /// The issuer's key event log. The joiner stores it and adopts the
    /// `did:kel` AID (`kel[0].aid`) as its user identity. Empty for a blind
    /// enrollment or a `did:key`-only issuer (none exist post-8c).
    pub kel: Vec<kotton_wire::kel::KelEvent>,
    /// The issuer's phrase-sealed recovery copy, for a blind node to keep
    /// (`PairingPayload::BlindRelay::recovery_bundle`). `None` on every other
    /// posture and from an issuer without a phrase.
    pub recovery_bundle: Option<String>,
    /// Present when the joiner was admitted as a gateway.
    pub gateway: Option<kotton_wire::peer::GatewayHandout>,
    /// The person's drives, handed by the admitting device for a `Full` join
    /// (`PairingPayload::FrostShare::drives`); empty on every other posture.
    /// The joiner records each before it answers `PairingComplete`.
    pub drives: Vec<kotton_wire::peer::DriveHandout>,
}

/// Issuer (E) side of FROST node enrollment. Waits for the new device N to
/// connect on `endpoint`, reads N's warm pubkey, builds + seals a `FrostShare`
/// around N's keys, and writes it back. Returns the issuer's retained 2-of-2
/// share (the caller stores it and discards its former 1-of-1 key), the preserved
/// root DID, and E's `PairedNode` view of N.
///
/// `device_key` is E's identity key (its QUIC cert + the ECDH seal); it is also
/// the 1-of-1 root that `issuer_identity_seed` derives, so `device_key ==
/// SigningKey::from_bytes(issuer_identity_seed)`.
/// Issuer-side outcome of an enrollment ceremony.
///
/// `issuer_share` is `Some` only for a `Full` enrollment (the issuer retains its
/// half of the new threshold). A **blind** enrollment performs no FROST split, so
/// there is nothing for the issuer to retain — `issuer_share` is `None`.
pub struct EnrolledNode {
    /// The issuer's retained share + the preserved root DID (`Full` only).
    pub issuer_share: Option<(FrostSharePayload, kotton_wire::did::Did)>,
    /// The group `PublicKeyPackage` (hex) — `Some` for `Full`, `None` for blind.
    /// The issuer persists it so it can later coordinate a threshold signature.
    pub pubkey_package: Option<String>,
    /// The issuer's `PairedNode` view of the joiner.
    pub node: PairedNode,
}

// ---------------------------------------------------------------------------
// Committed-handshake enrollment (forward-secret, SAS-authenticated)
// ---------------------------------------------------------------------------
//
// These are the node-enrollment ceremony (the retired static–static ECDH seal
// path is gone): the payload rides the committed ephemeral-ECDH channel
// (`pair_channel`), so a recorded ceremony plus a later long-term-key compromise
// reveals nothing (closes the audit MEDIUM), and either a six-digit SAS or an
// out-of-band pinned code authenticates the channel. The issuer additionally
// signs the handshake transcript with its **identity** key so the joiner can bind
// the confirmed channel to a specific identity.

/// Domain-separation context for the issuer's transcript attestation signature.
const PAIR_ATTEST_CONTEXT: &[u8] = b"kotton:pair-attest:v1";

/// The bytes the issuer signs / the joiner verifies: `context ‖ transcript`.
fn attest_message(transcript: &kotton_crypto::pair_handshake::Transcript) -> Vec<u8> {
    let mut m = PAIR_ATTEST_CONTEXT.to_vec();
    m.extend_from_slice(&transcript.to_bytes());
    m
}

/// How long the admitting device waits, once it has sent the payload and the
/// attestation, for the joiner to answer whether it kept them.
///
/// The joiner answers after it has written what it was handed — the identity
/// it adopts, its keys, the drives — and a device's first secret store write
/// may wait on its person (a keychain asking to be unlocked), so the bound is
/// the joiner's own window for the dial, the handshake and the six digits
/// (`kotton_device::users::pairing::handle_device_join`), not a network
/// round trip. A joiner still writing when it runs out is told so when it
/// answers: the issuer has stopped listening and kept nothing.
pub const JOINER_KEEPS_WITHIN: Duration = Duration::from_secs(120);

/// The longest refusal the issuer repeats to its person, in characters. The
/// joiner's own copy fits well inside it; a longer one is cut, not refused.
const REFUSAL_SAID_WITHIN: usize = 1024;

/// The ceremony's last frame, joiner to issuer: whether the joiner kept what it
/// was handed. Sealed under the channel's key like every frame after the six
/// digits, so it is the confirmed joiner's word and nobody else's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Answer {
    /// The joiner wrote what it was handed; the issuer may commit.
    Kept,
    /// The joiner refused what it was handed, or could not keep it, and says
    /// why in its person's words.
    Refused { why: String },
}

/// The issuer's reply to [`Answer::Kept`], and the last thing either side
/// says: it heard the answer and commits. Sealed like every frame after the
/// six digits, because the end of a transport is not the issuer's word — a
/// relay forwards no WebSocket close and ends both legs with its own, so a
/// close, however coded, says only what the relay chose to say. Sent only for
/// `kept`: a refusal needs no reply, since the issuer keeps nothing either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reply {
    /// The issuer heard `kept`, and commits.
    Heard,
}

/// Why an admitting device keeps nothing of a ceremony whose payload it sent:
/// the joiner did not say it kept it. The issuer's ceremony returns this
/// before its caller writes the joiner's row or introduces it anywhere, so a
/// join the joiner did not keep is admitted nowhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinNotKept {
    /// The joiner refused what it was handed, and said why (control
    /// characters dropped, cut at [`REFUSAL_SAID_WITHIN`]).
    Refused(String),
    /// The joiner said nothing the issuer could read as an answer: it closed,
    /// answered with something else, or was silent for [`JOINER_KEEPS_WITHIN`].
    Unanswered(String),
}

impl std::fmt::Display for JoinNotKept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinNotKept::Refused(why) => {
                write!(f, "the other device refused what it was handed, and nothing is kept here: {why}")
            }
            JoinNotKept::Unanswered(how) => write!(
                f,
                "the other device did not say it kept what it was handed ({how}), and nothing is kept here"
            ),
        }
    }
}

impl std::error::Error for JoinNotKept {}

/// Read the joiner's answer, waiting at most `within`. `Ok` only for
/// [`Answer::Kept`]; everything else is the [`JoinNotKept`] that says what came.
async fn hear_kept<W, R>(
    channel: &mut crate::pair_channel::EstablishedChannel<W, R>,
    within: Duration,
) -> Result<(), JoinNotKept>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    let frame = match tokio::time::timeout(within, channel.recv_encrypted()).await {
        Err(_) => return Err(JoinNotKept::Unanswered(format!("no answer within {}s", within.as_secs()))),
        Ok(Err(e)) => return Err(JoinNotKept::Unanswered(format!("it closed without answering: {e}"))),
        Ok(Ok(frame)) => frame,
    };
    match serde_json::from_slice::<Answer>(&frame) {
        Ok(Answer::Kept) => Ok(()),
        Ok(Answer::Refused { why }) => Err(JoinNotKept::Refused(
            why.chars().filter(|c| !c.is_control()).take(REFUSAL_SAID_WITHIN).collect(),
        )),
        Err(_) => Err(JoinNotKept::Unanswered("it answered with something that is not an answer".into())),
    }
}

/// A joiner's half of the channel, boxed so one handle serves every transport.
type JoinerChannel = crate::pair_channel::EstablishedChannel<
    Box<dyn AsyncWrite + Unpin + Send>,
    Box<dyn AsyncRead + Unpin + Send>,
>;

/// The joiner's last step: telling the admitting device whether it kept what
/// it was handed. Returned beside the [`JoinedNode`] by every joining
/// ceremony; the caller writes what it was handed, then answers
/// [`kept`](Self::kept), or [`refused`](Self::refused) with the reason its own
/// person is told. The issuer commits — records this device, introduces it at
/// the person's drives, reports `PairingComplete` — only on `kept`.
///
/// Dropping it unanswered closes the ceremony, which the issuer reads as no.
///
/// **Each side reads to the other's end before it lets go.** After its answer
/// the joiner reads the issuer's [`Reply`] and then until the issuer finishes;
/// the issuer, having replied, reads until the joiner lets go. A socket
/// closed over bytes it has not read is reset, and a relay passes a reset on
/// by discarding what it had not yet forwarded — an answer or a reply among
/// it. Neither side sends anything that ends its half before what it must
/// hear has arrived. Every such read is bounded by [`JOINER_KEEPS_WITHIN`].
#[must_use = "the admitting device keeps nothing until it is answered; dropping this answers no"]
pub struct JoinAnswer {
    channel: JoinerChannel,
    /// The QUIC bootstrap connection the channel runs on, held so it outlives
    /// the ceremony's return until the answer is heard; `None` for a relayed
    /// circuit, which the channel's halves hold.
    connection: Option<quinn::Connection>,
}

impl JoinAnswer {
    /// This device kept what it was handed. `Ok` only when the issuer replied,
    /// sealed, that it heard — and so commits. `Err` for every other end: the
    /// issuer stopped waiting ([`JOINER_KEEPS_WITHIN`]) and kept nothing, or
    /// the reply was lost and it did keep this device; this side cannot tell
    /// which, and says so.
    pub async fn kept(self) -> Result<()> {
        self.say(Answer::Kept).await
    }

    /// This device did not keep what it was handed, for `why`, which the
    /// issuer repeats to its person when it hears it. The issuer keeps
    /// nothing either way, so `Err` only when the refusal could not be sent.
    pub async fn refused(self, why: &str) -> Result<()> {
        self.say(Answer::Refused { why: why.to_string() }).await
    }

    async fn say(mut self, answer: Answer) -> Result<()> {
        let kept = answer == Answer::Kept;
        let frame = serde_json::to_vec(&answer).context("serialize the join's answer")?;
        self.channel
            .send_encrypted(&frame)
            .await
            .map_err(|e| anyhow!("the admitting device is no longer listening: {e}"))?;
        // The issuer's reply to `kept`; to a refusal, its end.
        let reply = tokio::time::timeout(JOINER_KEEPS_WITHIN, self.channel.recv_encrypted()).await;
        let heard = match &reply {
            Ok(Ok(frame)) => matches!(serde_json::from_slice::<Reply>(frame), Ok(Reply::Heard)),
            _ => false,
        };
        if heard {
            // Then to the issuer's finish, which follows the reply at once.
            let _ = tokio::time::timeout(JOINER_KEEPS_WITHIN, self.channel.recv_encrypted()).await;
        }
        drop(self.connection);
        match (kept, heard, reply) {
            (false, _, _) | (true, true, _) => Ok(()),
            (true, false, Err(_)) => Err(anyhow!(
                "the admitting device did not reply within {}s that it heard",
                JOINER_KEEPS_WITHIN.as_secs()
            )),
            (true, false, Ok(Err(e))) => Err(anyhow!("the ceremony ended before the admitting device replied that it heard ({e})")),
            (true, false, Ok(Ok(_))) => Err(anyhow!("the admitting device replied with something that is not `heard`")),
        }
    }
}

/// Issuer side of committed-handshake enrollment. Accepts the joiner's bootstrap
/// connection, runs the SAS handshake (via `confirmer`), then — only after both
/// humans confirm — transfers the enrollment payload and an identity attestation
/// over the forward-secret channel, and returns once the joiner answers that it
/// kept them ([`JoinNotKept`] otherwise; see the module's header).
///
/// The issuer's transport (operational) key is baked into `endpoint`'s TLS cert
/// by the caller (`open_pair_listener`); it is what the joiner records as the
/// dialable `PairedNode`. `issuer_identity_key` is the root that the FROST split
/// preserves *and* that signs the attestation.
/// `issuer_name` is **this device's own** name: it is announced to
/// the joiner over the encrypted channel (so the joiner's screen names the device
/// it is joining), never typed by the joiner. The joiner symmetrically announces
/// its own name, which the issuer records as the joiner's `PairedNode.id`.
#[allow(clippy::too_many_arguments)]
pub async fn run_enroll_issuer_committed(
    issuer_identity_key: &SigningKey,
    sid: [u8; 16],
    data_keys: Option<DataKeys>,
    posture: kotton_schemas::membership::Posture,
    issuer_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    listener: PairListener,
    ttl_seconds: u64,
    warm_key_expires_at: i64,
    issuer_kel: Vec<kotton_wire::kel::KelEvent>,
    issuer_recovery_bundle: Option<String>,
    drives: Vec<kotton_wire::peer::DriveHandout>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
) -> Result<EnrolledNode> {
    let timeout = tokio::time::Duration::from_secs(ttl_seconds);
    let incoming = tokio::time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| anyhow!("enroll timed out: no device connected within {ttl_seconds}s"))?
        .ok_or_else(|| anyhow!("enroll bootstrap endpoint closed"))?;
    let connection = incoming
        .await
        .map_err(|e| anyhow!("bootstrap QUIC handshake failed: {e}"))?;
    // The dialer opens the stream; here the joiner dialed.
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|e| anyhow!("accept stream from joiner: {e}"))?;
    let transport = Transport::over_quic(&connection, send, recv)?;
    let enrolled = issuer_over(
        transport,
        None,
        issuer_identity_key,
        sid,
        data_keys,
        posture,
        issuer_name,
        peer_listen_addr,
        warm_key_expires_at,
        issuer_kel,
        issuer_recovery_bundle,
        drives,
        None,
        confirmer,
        JOINER_KEEPS_WITHIN,
    )
    .await;
    // The ceremony is over either way: on `kept` the joiner has read the
    // reply and let go (`issuer_over`), and on anything else it is owed
    // nothing. The close is said rather than left to the idle timeout.
    connection.close(0u32.into(), b"");
    enrolled
}

/// The issuer half with the transport reversed: **this side dials** the joiner's
/// bootstrap listener and opens the stream. For a node that can be reached from
/// anywhere — a gateway on a host, a vault a landlord runs — admitted by a node
/// at home that cannot be: the code the listening node
/// prints carries its address and the session id, and the six digits are the
/// same six. The ceremony does not care who dialed; the payload is chosen by
/// `posture` exactly as when the issuer listens.
#[allow(clippy::too_many_arguments)]
pub async fn run_enroll_issuer_dialing(
    issuer_identity_key: &SigningKey,
    issuer_op_key: &SigningKey,
    sid: [u8; 16],
    peer_addr: SocketAddr,
    issuer_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    posture: kotton_schemas::membership::Posture,
    issuer_kel: Vec<kotton_wire::kel::KelEvent>,
    issuer_recovery_bundle: Option<String>,
    drives: Vec<kotton_wire::peer::DriveHandout>,
    gateway: Option<kotton_wire::peer::GatewayHandout>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
) -> Result<EnrolledNode> {
    let client_config = {
        use kotton_net::build_bootstrap_client_config;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let device_cert = kotton_net::Ed25519DeviceCert::from_signing_key(issuer_op_key)
            .map_err(|e| anyhow!("build device cert: {e}"))?;
        build_bootstrap_client_config(&device_cert, provider)
            .map_err(|e| anyhow!("build bootstrap client config: {e}"))?
    };
    let connection = dial_pairing_listener(&client_config, &[peer_addr]).await?;
    // The joiner speaks first (its hello), so the joiner opens the stream even
    // when it did not dial: a QUIC stream exists for the other side only once
    // bytes flow on it, and an issuer waiting to receive would wait forever.
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|e| anyhow!("accept stream from the listening node: {e}"))?;
    let transport = Transport::over_quic(&connection, send, recv)?;
    let enrolled = issuer_over(
        transport,
        None,
        issuer_identity_key,
        sid,
        None,
        posture,
        issuer_name,
        peer_listen_addr,
        0,
        issuer_kel,
        issuer_recovery_bundle,
        drives,
        gateway,
        confirmer,
        JOINER_KEEPS_WITHIN,
    )
    .await;
    // As the listening issuer closes, and for the same reason.
    connection.close(0u32.into(), b"");
    enrolled
}

// ---------------------------------------------------------------------------
// Relayed enrolment: an invite, and nothing listening on a public port
// ---------------------------------------------------------------------------
//
// The two transports above need one end to be reachable by address, and
// everything awkward about a rented vault was downstream of that: a second
// UDP port to publish, an advertised address a container gets wrong silently,
// a code that carries an address, and a ten-minute window at the host. The
// contact ceremony already meets at a relay with nobody listening:
// three spoken words derive a handle the vault reserves under and a session
// id the handshake binds to, a PAKE keyed by the words keeps out anyone who
// did not hear them, and the relay bridges one circuit between two labels it
// never sees again. This is that rendezvous with the six-digit enrolment payload
// inside — the ceremony's third transport, and the one a home vault behind a
// NAT can use, because nothing about it needs either end to be dialable.
//
// Roles do not line up with who dials, and that is fine: the vault *reserves*
// (it minted the invite) and is the enrolment *joiner*; the person's device
// *dials* and is the enrolment *issuer*, exactly as when it admits a listening
// vault. The channel does not care who opened the circuit.

/// The invite's rendezvous domain: the same words as a contact code would
/// derive a different handle, so the two ceremonies cannot meet by accident.
const ENROL_DOMAIN: RendezvousDomain = RendezvousDomain {
    rendezvous: b"kotton:enrol-rendezvous:v1",
    sid: b"kotton:enrol-sid:v1",
};

/// How long the admitting device keeps trying to reach an invite whose vault
/// is between reservations — the landlord minted it minutes or hours ago and
/// the vault re-reserves if the relay drops the control socket.
const INVITE_DIAL_WINDOW: Duration = Duration::from_secs(20);

/// Domain separation for the operational-key record signed inside the channel.
const OP_KEY_CONTEXT: &[u8] = b"kotton:pair-opkey:v1";

/// The domain a bare *does this relay answer* probe derives its handle in.
///
/// Its own, and not [`ENROL_DOMAIN`] or `CONTACT_DOMAIN`, for the reason those
/// two are separate from each other: a handle that could collide with a live
/// ceremony's would have a probe take the circuit a person was waiting on.
const PROBE_DOMAIN: RendezvousDomain = RendezvousDomain {
    rendezvous: b"kotton:relay-probe-rendezvous:v1",
    sid: b"kotton:relay-probe-sid:v1",
};

/// How long a relay has to answer a probe before it counts as not answering.
///
/// A dial that hangs is a relay that did not answer, from the point of view of
/// the person who just typed its name — so the probe has a deadline rather than
/// inheriting whatever the transport's is.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ask a relay, by its URL, whether it answers — and learn nothing else.
///
/// This is what *pairing a relay by naming it* is made of. A person names a
/// relay; everything else about one is what it answers with when dialled, and a
/// name that answers nothing should be refused rather than written into the
/// device's configuration for the pane to draw as a dark row nobody can explain.
///
/// **It writes nothing to the relay that the relay could read**, which is the
/// line Settings itself prints under the row. The handle is derived from 32
/// random bytes in a domain of its own, so it names nobody, is never used twice,
/// and composes with nothing (Article VII); the reservation is dropped the
/// moment the relay accepts it, before any circuit exists. What the relay
/// learns is that some key it has never seen reserved once — the same thing it
/// learns from every stranger running a ceremony through it.
///
/// `Ok(())` means the relay accepted the reservation. Every other outcome is an
/// error whose text says what went wrong, because the two cases a person cares
/// about — *there is nothing there* and *that is not a relay* — are both
/// "it did not answer" and neither is worth a variant nobody branches on.
pub async fn relay_answers(relay_url: &str) -> Result<()> {
    let url = relay_url.trim().trim_end_matches('/');
    if url.is_empty() {
        return Err(anyhow!("no relay was named"));
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let rv = rendezvous_in(&hex::encode(seed), &PROBE_DOMAIN)?;
    let reservation = tokio::time::timeout(
        PROBE_TIMEOUT,
        // A relay being named holds no key of this device's yet, so the
        // probe presents none: a relay whose rule is narrowed refuses it, and
        // that is its answer.
        rendezvous_reserve(url, &rv.handle, &rv.handle_key, None),
    )
    .await
    .map_err(|_| anyhow!("it did not answer within {}s", PROBE_TIMEOUT.as_secs()))?
    .map_err(|e| anyhow!("{e}"))?;
    // Dropped immediately: the probe is the reservation being *accepted*, and
    // holding one open would be this device advertising a handle it will never
    // meet anyone at.
    drop(reservation);
    Ok(())
}

/// Where an invite's ceremony meets, and the words that are its password: the
/// relay the vault reserves at, and three spoken words.
///
/// **What a person is handed is not this but its code**
/// (`kotton_wire::line::InviteCode::Vault`): the same relay
/// named by its key with this URL as a hint, the words, and the vault's own
/// key. The code is read by the one parser every code shares, and this is the
/// part of it the rendezvous needs ([`Self::of`]). The relay's key is what the
/// admitting device holds the relay to before it dials
/// ([`run_enroll_issuer_relayed`]), and the vault's key what it pins the vault
/// to. Admitting an invite never sets the device's relay: when it has none, the
/// meeting relay is offered in words and taken only on a yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The relay the vault reserves at, as a URL a device can dial.
    pub relay_url: String,
    /// Three spoken words, normalised.
    pub code: String,
}

impl Invite {
    /// A fresh invite at `relay_url`.
    pub fn new(relay_url: &str) -> Self {
        Self {
            relay_url: relay_url.trim().trim_end_matches('/').to_string(),
            code: generate_code(),
        }
    }

    /// Where a vault's invite code meets, and its words; `None` for a relay's
    /// invite, which meets nobody. The words are normalised as both sides
    /// derive the handle from them.
    pub fn of(code: &kotton_wire::line::InviteCode) -> Option<Self> {
        match code {
            kotton_wire::line::InviteCode::Vault { words, relay_hint, .. } => Some(Self {
                relay_url: relay_hint.trim().trim_end_matches('/').to_string(),
                code: normalize_code(words),
            }),
            kotton_wire::line::InviteCode::Relay { .. } => None,
        }
    }

    /// The code a person is handed for this invite: the vault's `key`, the
    /// words, this relay by `relay_key` with its URL as the hint, and the
    /// relay's `invited` admission key when the minting node holds one to hand
    /// on — what the admitting device presents on the ceremony's dial, at a
    /// relay whose rule refuses a stranger.
    pub fn code_for(
        &self,
        key: [u8; 32],
        relay_key: [u8; 32],
        invited: Option<&kotton_net::rendezvous::AdmissionKey>,
    ) -> kotton_wire::line::InviteCode {
        kotton_wire::line::InviteCode::Vault {
            key,
            words: self.code.clone(),
            relay_key,
            relay_hint: self.relay_url.clone(),
            invited: invited.map(kotton_net::rendezvous::AdmissionKey::to_bytes),
        }
    }
}

/// The relay an invite meets at proved another key than its code names, or
/// none: refused before the dial, so nothing — not the handle the words
/// derive, not a byte of the ceremony — reached it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotTheInvitedRelay {
    /// Where it was asked.
    pub url: String,
    /// What it answered, in the prover's words.
    pub why: String,
}

impl std::fmt::Display for NotTheInvitedRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the relay at {} is not the relay the invite names — nothing was handed over ({})", self.url, self.why)
    }
}

impl std::error::Error for NotTheInvitedRelay {}

/// A node's operational key and relay, sent inside the authenticated channel
/// and signed over its transcript — what a TLS certificate proves on the QUIC
/// transports, proven here by the channel instead, because a relayed circuit
/// carries no certificate.
///
/// Why sign at all, when a node that lies about its key only hurts itself
/// (every later dial to it fails the handshake): because the key is what the
/// other side *admits* — `paired_nodes.public_key` is the mTLS allowlist —
/// and an entry that nobody proved they hold is a row that admits nobody
/// today and whoever finds the private half tomorrow. Signing over the
/// transcript also pins the record to this ceremony, as the contact ceremony does.
#[derive(Debug, Serialize, Deserialize)]
struct OpKeyRecord {
    pubkey: [u8; 32],
    /// The relay this node reserves at, for later reach; empty if none.
    relay_url: String,
    sig: Vec<u8>,
}

fn op_key_message(transcript: &[u8], relay_url: &str) -> Vec<u8> {
    let mut m = OP_KEY_CONTEXT.to_vec();
    m.extend_from_slice(transcript);
    m.extend_from_slice(relay_url.as_bytes());
    m
}

/// `transcript` is the channel's transcript bytes — what pins the record to
/// this ceremony.
fn sign_op_key(transcript: &[u8], me: &SelfAnnounce<'_>) -> OpKeyRecord {
    let sig = me.op_key.sign(&op_key_message(transcript, &me.relay_url));
    OpKeyRecord {
        pubkey: me.op_key.verifying_key().to_bytes(),
        relay_url: me.relay_url.clone(),
        sig: sig.to_bytes().to_vec(),
    }
}

fn verify_op_key(transcript: &[u8], record: &OpKeyRecord) -> Result<([u8; 32], Option<String>)> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&record.pubkey)
        .map_err(|e| anyhow!("peer's operational key is not a valid Ed25519 key: {e}"))?;
    let sig_bytes: [u8; 64] = record
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("operational-key signature must be 64 bytes"))?;
    vk.verify_strict(
        &op_key_message(transcript, &record.relay_url),
        &ed25519_dalek::Signature::from_bytes(&sig_bytes),
    )
    .map_err(|_| anyhow!("the peer did not prove it holds the operational key it announced"))?;
    let relay = Some(record.relay_url.clone()).filter(|u| !u.is_empty());
    Ok((record.pubkey, relay))
}

/// What this side says about itself when the transport did not say it for
/// it — the relayed transport only. `None` over QUIC, where the certificate
/// has already presented the key and the record is not sent.
pub struct SelfAnnounce<'a> {
    /// This node's operational key: the one its TLS certificate will present
    /// on every later dial, and the one the other side admits.
    pub op_key: &'a SigningKey,
    /// The relay this node reserves at; empty if none.
    pub relay_url: String,
}

/// The bootstrap under a ceremony: a byte stream, and whatever the transport
/// already established about the other end before the channel ran.
///
/// Over QUIC the peer's operational key is in its certificate and its address
/// is on the socket. Over a relayed circuit neither exists — the relay bridges
/// bytes between two one-time labels — so the channel proves the key
/// ([`OpKeyRecord`]) and the address is whatever the peer announces, which for
/// a vault behind a NAT is nothing, and its relay is how it is reached.
pub struct Transport<W, R> {
    send: W,
    recv: R,
    /// The peer's operational key as the certificate presented it.
    presented_key: Option<[u8; 32]>,
    /// Where the peer was reached, when the transport has an address.
    observed: Option<SocketAddr>,
    /// The spoken code as a PAKE password, on the relayed transport.
    pake: Option<Vec<u8>>,
    /// The operational key the other end must prove, when this side already
    /// holds it from somewhere else (a vault's operator credential pins that
    /// vault). Checked the moment the key is proven — before this
    /// side says anything about itself or hands anything over. See
    /// [`NotThePinnedKey`].
    pinned: Option<[u8; 32]>,
}

/// The node that answered a ceremony proved an operational key other than the
/// one this side was told to expect ([`Transport::pinned_to`]). The ceremony
/// stops where the key is proven, so nothing of this side's — not its own key
/// record, not the payload — was sent. Typed, so the caller that knows *why*
/// the key was pinned can say so in its own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotThePinnedKey {
    /// The key this side expected.
    pub pinned: [u8; 32],
    /// The key the other end proved.
    pub answered: [u8; 32],
}

impl std::fmt::Display for NotThePinnedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the node that answered proved key {}, not the pinned {} — nothing was handed over",
            hex::encode(self.answered),
            hex::encode(self.pinned)
        )
    }
}

impl std::error::Error for NotThePinnedKey {}

/// Refuse a proven key that is not the pinned one. `Ok` when nothing is pinned.
fn held_to_pin(pinned: Option<[u8; 32]>, answered: [u8; 32]) -> Result<()> {
    match pinned {
        Some(pinned) if pinned != answered => Err(NotThePinnedKey { pinned, answered }.into()),
        _ => Ok(()),
    }
}

impl Transport<quinn::SendStream, quinn::RecvStream> {
    /// The QUIC bootstrap: the certificate presents the key, the socket the address.
    fn over_quic(
        connection: &quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Result<Self> {
        let key = extract_peer_pubkey_from_conn(connection)
            .ok_or_else(|| anyhow!("peer did not present a valid Ed25519 TLS certificate"))?;
        Ok(Self {
            send,
            recv,
            presented_key: Some(key),
            observed: Some(connection.remote_address()),
            pake: None,
            pinned: None,
        })
    }
}

impl<W, R> Transport<W, R>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    /// A relayed circuit: nothing presented, the code as the PAKE password.
    pub fn relayed(send: W, recv: R, code: &str) -> Self {
        Self {
            send,
            recv,
            presented_key: None,
            observed: None,
            pake: Some(code.as_bytes().to_vec()),
            pinned: None,
        }
    }
}

impl<W, R> Transport<W, R> {
    /// Hold the other end to `key`: the ceremony is refused with
    /// [`NotThePinnedKey`] the moment it proves any other.
    pub fn pinned_to(mut self, key: Option<[u8; 32]>) -> Self {
        self.pinned = key;
        self
    }
}

/// The issuer half over the relay: dial the invite's handle at its relay as a
/// one-time key, run the ceremony inside the circuit, and return the vault as
/// a paired node reachable through that relay. What `drive enrol <invite>
/// --blind` runs; the six digits are shown and confirmed
/// on this device, as today.
///
/// `relay_key` is the meeting relay's key, from the invite's code: the relay
/// at the invite's URL must prove it before anything is dialled, or the
/// admit is refused with [`NotTheInvitedRelay`].
///
/// `admission` is the relay's *invited* key, from the invite's code when it
/// carries one, and it is presented on this ceremony's one dial and nowhere
/// else: the admitting device is by definition a stranger at the relay, so
/// under *the people I invite* the invite is what admits it.
/// It is not kept: once admitted, the device is handed the relay's current key
/// by the vault's answer to `NodeRelay`, as every tenant is. It comes with what
/// it is ([`crate::relay_keys::Presenting`]): a relay that refuses it at its
/// door ends the dial at once, as [`crate::relay_keys::RefusedAtTheRelay`]
/// saying what was presented, and is not waited out as a vault between
/// reservations — every other failure is, for [`INVITE_DIAL_WINDOW`].
///
/// `pinned` is the vault's key — from the invite's code, and when the person
/// operates the vault, the key their operator credential pins too — and the
/// ceremony is then refused with [`NotThePinnedKey`] if the vault
/// that answers proves any other. That check is what lets `vault invite <v>
/// --me` confirm the six digits without a person: the vault signs its key
/// over this channel's transcript, so a node between the two could present
/// only its own.
#[allow(clippy::too_many_arguments)]
pub async fn run_enroll_issuer_relayed(
    invite: &Invite,
    relay_key: [u8; 32],
    admission: &crate::relay_keys::Presenting,
    issuer_identity_key: &SigningKey,
    issuer_op_key: &SigningKey,
    issuer_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    own_relay_url: &str,
    posture: kotton_schemas::membership::Posture,
    issuer_kel: Vec<kotton_wire::kel::KelEvent>,
    issuer_recovery_bundle: Option<String>,
    drives: Vec<kotton_wire::peer::DriveHandout>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
    pinned: Option<[u8; 32]>,
) -> Result<EnrolledNode> {
    // The relay is held to the key the code names before anything is said to
    // it: a stand-in at the address is refused here, and learns not even the
    // handle the words derive.
    crate::relay_key::prove_relay(&invite.relay_url, Some(&relay_key))
        .await
        .map_err(|e| NotTheInvitedRelay { url: invite.relay_url.clone(), why: e.to_string() })?;
    let rv = rendezvous_in(&invite.code, &ENROL_DOMAIN)?;
    // A key for this dial only: the relay learns a label that names nobody.
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let dial_key = SigningKey::from_bytes(&seed);
    let dial_did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&dial_key.verifying_key().to_bytes())
        .map_err(|e| anyhow!("dial key: {e}"))?
        .to_string();
    let deadline = tokio::time::Instant::now() + INVITE_DIAL_WINDOW;
    let stream = loop {
        let e = match rendezvous_dial(&invite.relay_url, &dial_did, &dial_key, &rv.handle, admission.key()).await {
            Ok(s) => break s,
            Err(e) => e,
        };
        // The relay's one answer to every refusal: it will answer the same
        // to the same key, so it is said now rather than waited out.
        let refused = crate::relay_keys::RefusedAtTheRelay::of(
            &e,
            &invite.relay_url,
            admission,
            crate::relay_keys::FirstContact::VaultInvite,
        );
        match refused {
            Some(refused) => return Err(refused.into()),
            None if tokio::time::Instant::now() < deadline => {
                tracing::debug!(error = %e, "admit by invite: the vault is not reserved yet; retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            None => {
                return Err(anyhow!(
                    "no vault is waiting on that invite at {} ({e}) — check the words, and that the \
                     invite has not expired",
                    invite.relay_url
                ))
            }
        }
    };
    let (read, write) = tokio::io::split(stream);
    issuer_over(
        Transport::relayed(write, read, &invite.code).pinned_to(pinned),
        Some(SelfAnnounce {
            op_key: issuer_op_key,
            relay_url: own_relay_url.to_string(),
        }),
        issuer_identity_key,
        rv.sid,
        None,
        posture,
        issuer_name,
        peer_listen_addr,
        0,
        issuer_kel,
        issuer_recovery_bundle,
        drives,
        None,
        confirmer,
        JOINER_KEEPS_WITHIN,
    )
    .await
}

/// The invite's handle, reserved at its relay: what [`reserve_invite`] holds
/// and [`run_enroll_join_relayed`] waits at.
pub struct ReservedInvite(kotton_net::transport::RendezvousReservation);

/// How long the minting node waits for its relay to take the invite's
/// reservation: a relay that does not answer is one the person minting is
/// told of, and a mint is never held open by it. The same bound, and for the
/// same reason, as naming a relay ([`PROBE_TIMEOUT`]).
const INVITE_RESERVE_WITHIN: Duration = PROBE_TIMEOUT;

/// Why an invite's handle was not reserved — two causes a person acts on
/// differently, so two variants and never one sentence for both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteNotReserved {
    /// The relay answered and refused the reservation by its rule: it reads a
    /// key the minting node did not present.
    Refused(String),
    /// The relay was not reached, or did not answer within
    /// [`INVITE_RESERVE_WITHIN`]: nothing is known of its rule.
    Unreachable(String),
}

/// Reserve under the invite's handle at its relay, presenting `admission`.
/// Made **before** the invite is handed to anyone: a relay whose rule refuses this node refuses the mint, and no code is handed
/// out that its holder would be refused on. Bounded by
/// [`INVITE_RESERVE_WITHIN`], so a relay that does not answer cannot hold the
/// request that asked for the invite.
pub async fn reserve_invite(
    invite: &Invite,
    admission: Option<&kotton_net::rendezvous::AdmissionKey>,
) -> std::result::Result<ReservedInvite, InviteNotReserved> {
    let rv = rendezvous_in(&invite.code, &ENROL_DOMAIN).map_err(|e| InviteNotReserved::Unreachable(e.to_string()))?;
    match tokio::time::timeout(
        INVITE_RESERVE_WITHIN,
        rendezvous_reserve(&invite.relay_url, &rv.handle, &rv.handle_key, admission),
    )
    .await
    {
        Ok(Ok(reservation)) => Ok(ReservedInvite(reservation)),
        Ok(Err(e @ kotton_sys::net::TransportError::AuthenticationFailed(_))) => {
            Err(InviteNotReserved::Refused(e.to_string()))
        }
        Ok(Err(e)) => Err(InviteNotReserved::Unreachable(e.to_string())),
        Err(_) => Err(InviteNotReserved::Unreachable(format!(
            "no answer within {}s",
            INVITE_RESERVE_WITHIN.as_secs()
        ))),
    }
}

/// The joiner half over the relay: wait at the invite's handle, `reserved`
/// ([`reserve_invite`]), for `ttl` for the admitting device to dial, and run
/// the ceremony inside the circuit. What `kvaultd invite` runs at the vault's
/// door. Nothing listens on a public port; the vault is reachable afterwards
/// the way it is reachable for everything else, through its relay.
#[allow(clippy::too_many_arguments)]
pub async fn run_enroll_join_relayed(
    invite: &Invite,
    reserved: ReservedInvite,
    warm_key: &SigningKey,
    node_key: &SigningKey,
    ttl_seconds: u64,
    joiner_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
) -> Result<(JoinedNode, JoinAnswer)> {
    let rv = rendezvous_in(&invite.code, &ENROL_DOMAIN)?;
    let ReservedInvite(reservation) = reserved;
    let stream = tokio::time::timeout(Duration::from_secs(ttl_seconds), reservation.accept_one())
        .await
        .map_err(|_| anyhow!("enroll timed out: nobody admitted this invite within {ttl_seconds}s"))?
        .map_err(|e| anyhow!("relay circuit: {e}"))?;
    let (read, write) = tokio::io::split(stream);
    let (joined, channel) = joiner_over(
        Transport::relayed(write, read, &invite.code),
        Some(SelfAnnounce {
            op_key: node_key,
            relay_url: invite.relay_url.clone(),
        }),
        warm_key,
        rv.sid,
        joiner_name,
        peer_listen_addr,
        confirmer,
        None,
    )
    .await?;
    Ok((joined, JoinAnswer { channel, connection: None }))
}

/// What a node tells the other side of a ceremony about where to dial it, and
/// how the other side completes it.
///
/// Both halves of a ceremony run over a **bootstrap** socket that is torn down
/// when the ceremony ends. Recorded as the peer's address —
/// `connection.remote_address()` — a vault admitted by the real ceremony would
/// sit at its enrolment port (7711), the one socket guaranteed not to answer
/// the protocol the address is for, and a harness that called `peer_add` with
/// the right address straight afterwards would hide it.
///
/// So a node announces the address its **peer listener** actually bound, read
/// back off the socket. A wide bind announces an unspecified IP (`0.0.0.0`),
/// which is the honest answer — *this is my port; which of my addresses is
/// yours to say* — and the other side completes it with the IP this connection
/// reached it on. That IP is known to work in the direction it is needed,
/// because it was just used, which is why no configured public address is
/// consulted here: a device on the LAN records the LAN address and a device on
/// the internet records the public one, each correct for itself.
///
/// It is a **hint, not a credential**, exactly as the device name announced
/// beside it is. Nothing is admitted by it: the peer's operational key is
/// pinned from the ceremony's TLS certificate, so an announced address that is
/// wrong or someone else's produces a dial that fails the handshake.
fn announce_bytes(addr: Option<SocketAddr>) -> Vec<u8> {
    addr.map(|a| a.to_string()).unwrap_or_default().into_bytes()
}

/// The other half of [`announce_bytes`]: an announcement that is absent,
/// unparsable or empty means *nothing announced*, and the observed address
/// stands.
fn parse_announced(bytes: &[u8]) -> Option<SocketAddr> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    match text.parse::<SocketAddr>() {
        Ok(a) => Some(a),
        Err(_) => {
            tracing::warn!(announced = %text, "peer announced an address that does not parse; \
                            using the one this connection came from");
            None
        }
    }
}

/// A peer's operational key as the `did:key` every other surface produces and
/// resolves — multibase, the form `DidKeyMethod::to_public_key` reads back.
///
/// Not `did:key:<64 hex chars>`: that is the same key and not the same string —
/// nothing in the tree can decode it, and `remote_add`, which resolves a paired
/// node *by* its DID, could not find a node the ceremony had just recorded. A
/// harness that called `peer_add` right afterwards with the DID from
/// `get_node_identity` — the multibase form — would hide it, quietly writing the
/// row the rest of the system then used.
fn did_key(pubkey: &[u8; 32]) -> Result<kotton_wire::did::Did> {
    kotton_crypto::DidKeyMethod::from_public_key_bytes(pubkey)
        .map_err(|e| anyhow!("derive did:key for a peer's operational key: {e}"))
}

/// Where to record a peer: what it announced, completed by where it was
/// reached. See [`announce_bytes`]. `None` when there is nothing to record —
/// a relayed ceremony observed no address, and a peer that announced only a
/// port has given it nothing to complete with; such a peer is reached through
/// its relay, which the record carries beside the (empty) address list.
fn dialable_addr(announced: Option<SocketAddr>, observed: Option<SocketAddr>) -> Option<SocketAddr> {
    match (announced, observed) {
        (Some(a), Some(o)) if a.ip().is_unspecified() => Some(SocketAddr::new(o.ip(), a.port())),
        (Some(a), None) if a.ip().is_unspecified() => None,
        (Some(a), _) => Some(a),
        (None, o) => o,
    }
}

/// The issuer's protocol, over an established bootstrap transport.
///
/// **It returns only once the joiner has said it kept what it was handed.**
/// After the payload and the attestation it waits, at most `kept_within`
/// ([`JOINER_KEEPS_WITHIN`] on every live path), for the joiner's answer;
/// a refusal, a close, or silence is [`JoinNotKept`], and the caller then writes
/// nothing and introduces the joiner nowhere. To `kept` it replies a sealed
/// [`Reply::Heard`], finishes, and reads until the joiner lets go (at most
/// [`JOINER_KEEPS_WITHIN`]), so the transport may be dropped as soon as this
/// returns without cutting the reply short.
#[allow(clippy::too_many_arguments)]
async fn issuer_over<W, R>(
    transport: Transport<W, R>,
    me: Option<SelfAnnounce<'_>>,
    issuer_identity_key: &SigningKey,
    sid: [u8; 16],
    data_keys: Option<DataKeys>,
    posture: kotton_schemas::membership::Posture,
    issuer_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    warm_key_expires_at: i64,
    issuer_kel: Vec<kotton_wire::kel::KelEvent>,
    issuer_recovery_bundle: Option<String>,
    drives: Vec<kotton_wire::peer::DriveHandout>,
    gateway: Option<kotton_wire::peer::GatewayHandout>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
    kept_within: Duration,
) -> Result<EnrolledNode>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    use kotton_schemas::membership::Posture;

    let Transport { send, recv, presented_key, observed, pake, pinned } = transport;

    // The committed handshake + human SAS confirmation. Aborts (and transfers
    // nothing) on mismatch/cancel/bad-MAC. Keyed by the code as well where the
    // transport is a relayed circuit anyone could open.
    let mut channel = crate::pair_channel::issuer_establish_with(
        send,
        recv,
        sid,
        issuer_name,
        confirmer,
        pake.as_deref(),
    )
    .await
    .map_err(|e| anyhow!("pairing handshake failed: {e}"))?;

    // Who the joiner is: presented by its certificate, or proven inside the
    // channel where there is none. The record exchange runs only where it is
    // needed, so the QUIC transports' frame order is exactly what it was.
    //
    // A pinned key is held to here, where the key is proven and before this
    // side has sent anything of its own inside the channel.
    let (joiner_node_pubkey, joiner_relay) = match presented_key {
        Some(key) => {
            held_to_pin(pinned, key)?;
            (key, None)
        }
        None => {
            let me = me.ok_or_else(|| anyhow!("a relayed ceremony must announce its own key"))?;
            let theirs: OpKeyRecord = serde_json::from_slice(&channel.recv_encrypted().await?)
                .context("joiner operational-key record")?;
            let transcript = channel.transcript().to_bytes();
            let verified = verify_op_key(&transcript, &theirs)?;
            held_to_pin(pinned, verified.0)?;
            let mine = sign_op_key(&transcript, &me);
            channel
                .send_encrypted(&serde_json::to_vec(&mine).context("serialize op-key record")?)
                .await?;
            verified
        }
    };

    // The joiner sends its fresh warm pubkey over the encrypted channel; the
    // delegation + certificate bind to it.
    let warm_bytes = channel.recv_encrypted().await?;
    let warm_pubkey: [u8; 32] = warm_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("joiner warm pubkey must be 32 bytes"))?;

    // The joiner announces its own device name; the issuer records it as the
    // joiner's label (never types the peer's name).
    let joiner_name = String::from_utf8(channel.recv_encrypted().await?)
        .map_err(|_| anyhow!("joiner device name is not valid UTF-8"))?;
    let joiner_name = clean_device_name(&joiner_name);

    // Where each side's peer listener is, exchanged before the payload so that
    // neither records the bootstrap socket this ceremony is running over. See
    // `announce_bytes`.
    let joiner_announced = parse_announced(&channel.recv_encrypted().await?);
    channel.send_encrypted(&announce_bytes(peer_listen_addr)).await?;

    // Build the posture-appropriate payload (identical to the seal path).
    let issuer_seed = issuer_identity_key.to_bytes();
    let (payload, issuer_share, pubkey_package) = match posture {
        // A gateway holds nothing and is minted by the node (`GatewayMint`), never
        // enrolled by ceremony: there is no payload a ceremony could hand it.
        // A gateway is handed whom it serves and where the node is, and nothing
        // that opens anything. Only the dialing issuer carries a handout; the
        // accepting path never reaches this arm with one.
        Posture::Gateway => match gateway {
            Some(handout) => (PairingPayload::Gateway(handout), None, None),
            None => return Err(anyhow!("a gateway is enrolled by the node dialing it, not the other way")),
        },
        // A blind storage node gets the chain, so it can later admit a
        // device that proves control of the user's root. No key material moves —
        // see the variant's own doc comment for why this leaves the posture blind.
        Posture::BlindStorage => (
            PairingPayload::BlindRelay {
                kel: issuer_kel,
                recovery_bundle: issuer_recovery_bundle,
            },
            None,
            None,
        ),
        Posture::Full | Posture::Cosigner => {
            // Only a `Full` (trusted-hardware, `data`) posture
            // receives the data domain; a `Cosigner` holds the share alone.
            let keys_for_posture = if matches!(posture, Posture::Full) {
                data_keys
            } else {
                None
            };
            let issued = kotton_org::enrollment::build_frost_enrollment(
                &issuer_seed,
                &warm_pubkey,
                keys_for_posture,
                warm_key_expires_at,
                issuer_kel,
            )?;
            // A `Full` device keeps the person's things, and so is handed the
            // drives they live on (`PairingPayload::FrostShare::drives`); a
            // `Cosigner` keeps nothing and is handed none.
            let mut payload = issued.payload;
            if matches!(posture, Posture::Full) {
                if let PairingPayload::FrostShare { drives: handed, .. } = &mut payload {
                    *handed = drives;
                }
            }
            (
                payload,
                Some((issued.issuer_share, issued.root_did)),
                Some(issued.pubkey_package),
            )
        }
    };

    // Transfer the payload, then the identity attestation over the transcript.
    let payload_bytes = serde_json::to_vec(&payload).context("serialize enrollment payload")?;
    channel.send_encrypted(&payload_bytes).await?;

    let signature = issuer_identity_key.sign(&attest_message(channel.transcript()));
    let attestation = kotton_wire::peer::PairAttestation {
        identity_pubkey: issuer_identity_key.verifying_key().to_bytes(),
        signature: signature.to_bytes().to_vec(),
    };
    let attest_bytes = serde_json::to_vec(&attestation).context("serialize attestation")?;
    channel.send_encrypted(&attest_bytes).await?;
    // Nothing is committed on the joiner's behalf until it says it kept what
    // it was handed: a joiner that refuses, closes or stays silent leaves
    // this side with nothing to record and nobody to introduce. This side's
    // finish waits for the answer — over a relay it is a close the joiner
    // would have to read before answering (see `JoinAnswer`).
    hear_kept(&mut channel, kept_within).await?;
    // Heard and kept: say so, sealed — the joiner calls its join complete on
    // this and nothing else — then finish, and read until the joiner lets go,
    // so the reply is not cut short by this side's close. A reply that fails
    // now takes nothing back: the joiner kept, and this side commits; the
    // joiner is told to check here.
    let reply = serde_json::to_vec(&Reply::Heard).context("serialize the issuer's reply")?;
    if let Err(e) = channel.send_encrypted(&reply).await {
        tracing::warn!(error = %e, "the joiner kept the join, but the reply that this side heard was not sent");
    }
    let _ = channel.finish().await;
    let _ = tokio::time::timeout(JOINER_KEEPS_WITHIN, channel.recv_encrypted()).await;

    let node = PairedNode {
        id: joiner_name,
        device_did: did_key(&joiner_node_pubkey)?,
        public_key: joiner_node_pubkey,
        paired_at: now_secs(),
        addresses: dialable_addr(joiner_announced, observed).into_iter().collect(),
        relay_url: joiner_relay,
        posture: Some(posture.as_str().to_string()),
    };
    Ok(EnrolledNode {
        issuer_share,
        pubkey_package,
        node,
    })
}

/// Filter and rank discovered pairing addresses for dialing.
///
/// A dual-stack host advertises many addresses, most of them undialable from
/// another machine. This drops loopback, unspecified, and link-local
/// (`169.254.0.0/16`, `fe80::/10` — routable only with a scope id we don't carry),
/// then prefers **IPv6** (ULA / global) ahead of IPv4.
///
/// IPv6-first follows Happy Eyeballs' preference direction (RFC 8305): on a modern
/// LAN the IPv6 ULA is the sturdier path — hosts on one `/64` reach each other
/// directly with no NAT and no separate-subnet hazard, whereas IPv4 may sit behind
/// client isolation or a different subnet. The dialer bounds each attempt (see
/// `dial_pairing_listener`), so when IPv6 is advertised-but-dead the fall back to
/// IPv4 is quick rather than a full handshake timeout. Empty result → the caller
/// surfaces a clear "no routable address" error instead of a mystery failure.
pub fn rank_dial_candidates(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut dialable: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| is_dialable_pair_addr(&a.ip()))
        .collect();
    // Stable sort: IPv6 first, discovery order preserved within a family.
    dialable.sort_by_key(|a| u8::from(a.is_ipv4()));
    dialable
}

/// Whether a remote pairing address is plausibly dialable from another machine.
fn is_dialable_pair_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_unspecified() && !v4.is_link_local() && !v4.is_broadcast()
        }
        // `fe80::/10` is link-local (needs a scope id we don't carry); ULA
        // (`fc00::/7`, e.g. `fd93::…`) and global IPv6 stay.
        IpAddr::V6(v6) => {
            !v6.is_loopback() && !v6.is_unspecified() && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Per-address dial budget. A LAN handshake completes in milliseconds; this only
/// bounds the wait on a dead-but-advertised address before trying the next family.
const PAIR_DIAL_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Dial the pairing bootstrap listener, trying each candidate in order until one
/// connects.
///
/// The client endpoint is bound per candidate by
/// [`kotton_net::transport::outbound_bind_addr`], which matches the candidate's
/// address family — an IPv4-only `0.0.0.0` bind cannot dial an IPv6 peer, so a
/// single fixed IPv4 bind silently lost every IPv6 offer — and narrows to loopback
/// for a loopback candidate. Candidates should arrive already ranked
/// (`rank_dial_candidates`); this walks them and returns the first live connection,
/// or the last dial error if none answer.
async fn dial_pairing_listener(
    client_config: &quinn::ClientConfig,
    peer_addrs: &[SocketAddr],
) -> Result<quinn::Connection> {
    if peer_addrs.is_empty() {
        return Err(anyhow!("no pairing address to dial"));
    }
    tracing::info!(candidates = ?peer_addrs, "pairing: dialing discovered addresses in order");
    // One line per attempt, folded into the final error so a failed join names
    // every address it tried and why each dropped — the difference between "no
    // IPv4 was advertised" and "IPv4 was tried and timed out" is diagnostic gold.
    let mut attempts: Vec<String> = Vec::new();
    for &addr in peer_addrs {
        let bind = kotton_net::transport::outbound_bind_addr(addr);
        let endpoint = match quinn::Endpoint::client(bind) {
            Ok(e) => e,
            Err(e) => {
                attempts.push(format!("{addr}: client bind failed: {e}"));
                continue;
            }
        };
        match endpoint.connect_with(client_config.clone(), addr, "kotton-pairing") {
            // Bound each attempt: on a LAN a live handshake finishes in
            // milliseconds, so an address advertised-but-dead (a ULA the router
            // won't route) should fall through to the next family in seconds, not
            // after quinn's full idle timeout.
            Ok(connecting) => match tokio::time::timeout(PAIR_DIAL_ATTEMPT_TIMEOUT, connecting).await
            {
                Ok(Ok(conn)) => {
                    tracing::info!(%addr, "pairing: bootstrap connected");
                    return Ok(conn);
                }
                Ok(Err(e)) => attempts.push(format!("{addr}: handshake {e}")),
                Err(_) => attempts.push(format!(
                    "{addr}: no response within {}s",
                    PAIR_DIAL_ATTEMPT_TIMEOUT.as_secs()
                )),
            },
            Err(e) => attempts.push(format!("{addr}: connect {e}")),
        }
    }
    Err(anyhow!(
        "no discovered address answered ({} tried) — {}",
        attempts.len(),
        attempts.join("; ")
    ))
}

/// Joiner side of committed-handshake enrollment. Dials the discovered issuer,
/// runs the handshake, and returns the payload only after verifying the issuer's
/// identity attestation, beside the [`JoinAnswer`] the caller owes the issuer
/// once it has written what it keeps.
///
/// `sid` is the offer's session id (from the mDNS advertisement or the connection
/// code); `peer_addrs` are the ranked bootstrap addresses to try in order.
///
/// `pinned_issuer_root` authenticates the issuer **out-of-band**: when the joiner learned the issuer's identity key from a QR or a
/// connection code, pass it here and the attestation is checked against it —
/// cryptographic MITM protection with **no human SAS needed** (the `confirmer`
/// may auto-confirm). Pass `None` for the rung-1 flow where the human SAS
/// comparison is the authenticator.
///
/// This is the retained **seam** for unattended enrollment: the legacy no-SAS
/// `node enroll`/`node join` verbs that fed a pinned root here were removed with the
/// rest of that surface, so today every caller passes `None`. A future
/// `device add --pinned` (headless / blind-storage provisioning with no human on the
/// joining side) re-enters through this same parameter — the ceremony core keeps the
/// check so the capability can return without re-litigating the handshake.
// Allowed: the ceremony's inputs, as its siblings `run_enroll_join_relayed` and `run_enroll_issuer_committed`.
#[allow(clippy::too_many_arguments)]
pub async fn run_enroll_join_committed(
    node_key: &SigningKey,
    warm_key: &SigningKey,
    sid: [u8; 16],
    peer_addrs: &[SocketAddr],
    joiner_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
    pinned_issuer_root: Option<[u8; 32]>,
) -> Result<(JoinedNode, JoinAnswer)> {
    let client_config = {
        use kotton_net::build_bootstrap_client_config;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let device_cert = kotton_net::Ed25519DeviceCert::from_signing_key(node_key)
            .map_err(|e| anyhow!("build device cert: {e}"))?;
        build_bootstrap_client_config(&device_cert, provider)
            .map_err(|e| anyhow!("build bootstrap client config: {e}"))?
    };
    let connection = dial_pairing_listener(&client_config, peer_addrs).await?;
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow!("open QUIC stream: {e}"))?;
    let transport = Transport::over_quic(&connection, send, recv)?;
    let (joined, channel) = joiner_over(
        transport,
        None,
        warm_key,
        sid,
        joiner_name,
        peer_listen_addr,
        confirmer,
        pinned_issuer_root,
    )
    .await?;
    Ok((joined, JoinAnswer { channel, connection: Some(connection) }))
}

/// The joiner half with the transport reversed: **this side listens** and the
/// issuer dials in (see [`run_enroll_issuer_dialing`]). A gateway on a public
/// host joins this way; the six digits it shows are the six the node types.
pub async fn run_enroll_join_listening(
    warm_key: &SigningKey,
    sid: [u8; 16],
    listener: PairListener,
    ttl_seconds: u64,
    joiner_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
) -> Result<(JoinedNode, JoinAnswer)> {
    let timeout = tokio::time::Duration::from_secs(ttl_seconds);
    let incoming = tokio::time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| anyhow!("enroll timed out: no node dialed within {ttl_seconds}s"))?
        .ok_or_else(|| anyhow!("enroll bootstrap endpoint closed"))?;
    let connection = incoming
        .await
        .map_err(|e| anyhow!("bootstrap QUIC handshake failed: {e}"))?;
    // The joiner speaks first, so it opens the stream — see `run_enroll_issuer_dialing`.
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow!("open QUIC stream to the node: {e}"))?;
    let transport = Transport::over_quic(&connection, send, recv)?;
    let (joined, channel) = joiner_over(
        transport,
        None,
        warm_key,
        sid,
        joiner_name,
        peer_listen_addr,
        confirmer,
        None,
    )
    .await?;
    Ok((joined, JoinAnswer { channel, connection: Some(connection) }))
}

/// The joiner's protocol, over an established bootstrap transport.
///
/// Returns what it was handed, verified, and the channel still open: the
/// caller writes what it keeps and then answers the issuer over it
/// ([`JoinAnswer`]), which commits nothing until then.
#[allow(clippy::too_many_arguments)]
async fn joiner_over<W, R>(
    transport: Transport<W, R>,
    me: Option<SelfAnnounce<'_>>,
    warm_key: &SigningKey,
    sid: [u8; 16],
    joiner_name: &str,
    peer_listen_addr: Option<SocketAddr>,
    confirmer: &dyn crate::pair_channel::SasConfirmer,
    pinned_issuer_root: Option<[u8; 32]>,
) -> Result<(JoinedNode, JoinerChannel)>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let Transport { send, recv, presented_key, observed, pake, pinned: _ } = transport;
    // Boxed here, so the channel the caller answers over is one type whatever
    // carried it.
    let send: Box<dyn AsyncWrite + Unpin + Send> = Box::new(send);
    let recv: Box<dyn AsyncRead + Unpin + Send> = Box::new(recv);

    let mut channel =
        crate::pair_channel::joiner_establish_with(send, recv, sid, confirmer, pake.as_deref())
            .await
            .map_err(|e| anyhow!("pairing handshake failed: {e}"))?;

    // Who the issuer is: its certificate, or its record inside the channel.
    // The joiner speaks first here as everywhere else in this protocol.
    let (issuer_op_pubkey, issuer_relay) = match presented_key {
        Some(key) => (key, None),
        None => {
            let me = me.ok_or_else(|| anyhow!("a relayed ceremony must announce its own key"))?;
            let transcript = channel.transcript().to_bytes();
            let mine = sign_op_key(&transcript, &me);
            channel
                .send_encrypted(&serde_json::to_vec(&mine).context("serialize op-key record")?)
                .await?;
            let theirs: OpKeyRecord = serde_json::from_slice(&channel.recv_encrypted().await?)
                .context("issuer operational-key record")?;
            verify_op_key(&transcript, &theirs)?
        }
    };

    // Send our warm pubkey, then announce our own device name (the issuer records
    // it as this device's label). The issuer's name arrived over the channel
    // during establish (`channel.peer_label()`), so neither side types the other's.
    channel
        .send_encrypted(&warm_key.verifying_key().to_bytes())
        .await?;
    channel
        .send_encrypted(clean_device_name(joiner_name).as_bytes())
        .await?;
    // Then where this node's peer listener is, and read back where the issuer's
    // is. See `announce_bytes`.
    channel.send_encrypted(&announce_bytes(peer_listen_addr)).await?;
    let issuer_announced = parse_announced(&channel.recv_encrypted().await?);
    let payload_bytes = channel.recv_encrypted().await?;
    let payload: PairingPayload =
        serde_json::from_slice(&payload_bytes).context("deserialize enrollment payload")?;
    let attest_bytes = channel.recv_encrypted().await?;
    let attestation: kotton_wire::peer::PairAttestation =
        serde_json::from_slice(&attest_bytes).context("deserialize attestation")?;

    // Verify the attestation binds the issuer's identity to THIS transcript. With
    // no enrollment code carrying the root key, this signature (over the
    // SAS-confirmed transcript) is what identifies whose identity we are joining.
    let identity_vk = ed25519_dalek::VerifyingKey::from_bytes(&attestation.identity_pubkey)
        .map_err(|e| anyhow!("invalid attestation identity key: {e}"))?;
    let sig_bytes: [u8; 64] = attestation
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("attestation signature must be 64 bytes"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    identity_vk
        .verify_strict(&attest_message(channel.transcript()), &signature)
        .map_err(|_| anyhow!("attestation failed to verify (possible MITM or wrong identity)"))?;

    // Rung 2/4: if the issuer's identity key was pinned out-of-band (QR / code),
    // the attested key MUST equal it. This is what authenticates the issuer when
    // there is no human SAS comparison — a MITM would attest its own key and fail.
    if let Some(pin) = pinned_issuer_root {
        if attestation.identity_pubkey != pin {
            return Err(anyhow!(
                "issuer identity does not match the pinned code/QR key (possible MITM)"
            ));
        }
    }

    let root_did =
        kotton_crypto::DidKeyMethod::from_public_key_bytes(&attestation.identity_pubkey)
            .map_err(|e| anyhow!("derive root did: {e}"))?;

    // The issuer announced its own name during establish; adopt it (falling back
    // to a placeholder if it advertised none). Never typed by this device.
    let issuer_name = clean_device_name(channel.peer_label().unwrap_or_default());
    let now = now_secs();
    let issuer_node = PairedNode {
        id: issuer_name,
        device_did: did_key(&issuer_op_pubkey)?,
        public_key: issuer_op_pubkey,
        paired_at: now,
        addresses: dialable_addr(issuer_announced, observed).into_iter().collect(),
        relay_url: issuer_relay,
        // Not announced by the issuer, and not recorded on the row either
        // (`finalize_joined_node`): read as a row from before postures.
        posture: None,
    };
    let warm_pubkey = warm_key.verifying_key().to_bytes();

    let joined = match payload {
        PairingPayload::FrostShare {
            share,
            warm_key_delegation,
            quorum_certificate,
            data_keys,
            pubkey_package,
            kel,
            drives,
        } => {
            kotton_org::enrollment::verify_received_frost_share(
                &warm_key_delegation,
                &share,
                &quorum_certificate,
                &warm_pubkey,
                &root_did,
                now,
            )?;
            // The delivered KEL must resolve to the SAME key that signed the
            // attestation — otherwise a sender could pair a KEL for identity A while
            // signing with key B. Binds the FROST/KEL bundle to the attested identity.
            if !kel.is_empty() {
                let current = kotton_crypto::kel_verify::resolve_current_key(
                    &kel,
                    &kotton_crypto::kel_verify::LocalArbiter,
                    false,
                )
                .map_err(|e| anyhow!("delivered KEL failed to replay: {e}"))?;
                if current != attestation.identity_pubkey {
                    return Err(anyhow!(
                        "delivered KEL resolves to a different key than the attestation"
                    ));
                }
            }
            Ok(JoinedNode {
                peer: issuer_node,
                frost_share: Some(share),
                warm_key_delegation: Some(warm_key_delegation),
                data_keys,
                pubkey_package: Some(pubkey_package),
                root_did,
                kel,
                recovery_bundle: None,
                gateway: None,
                drives,
            })
        }
        PairingPayload::Gateway(handout) => Ok(JoinedNode {
            peer: issuer_node,
            frost_share: None,
            warm_key_delegation: None,
            data_keys: None,
            pubkey_package: None,
            root_did,
            kel: Vec::new(),
            recovery_bundle: None,
            gateway: Some(handout),
            drives: Vec::new(),
        }),
        PairingPayload::BlindRelay {
            kel,
            recovery_bundle,
        } => {
            // The same binding check the FrostShare arm makes, and for the same
            // reason: a sender must not be able to hand over a KEL for identity A
            // while signing the transcript with key B. A blind node that stored an
            // unbound chain would later admit devices for an identity that never
            // enrolled it — the exact hole recovery admission exists to close,
            // reopened at the other end.
            if !kel.is_empty() {
                let current = kotton_crypto::kel_verify::resolve_current_key(
                    &kel,
                    &kotton_crypto::kel_verify::LocalArbiter,
                    false,
                )
                .map_err(|e| anyhow!("delivered KEL failed to replay: {e}"))?;
                if current != attestation.identity_pubkey {
                    return Err(anyhow!(
                        "delivered KEL resolves to a different key than the attestation"
                    ));
                }
            }
            Ok(JoinedNode {
                peer: issuer_node,
                frost_share: None,
                warm_key_delegation: None,
                data_keys: None,
                pubkey_package: None,
                root_did,
                kel,
                recovery_bundle,
                gateway: None,
                drives: Vec::new(),
            })
        }
        other => Err(anyhow!("unexpected enrollment payload, got {other:?}")),
    };
    Ok((joined?, channel))
}

// Build a quinn ServerConfig using the bootstrap (accept-any) TLS profile.
fn build_bootstrap_server_config_quinn(device_key: &SigningKey) -> Result<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let device_cert = kotton_net::Ed25519DeviceCert::from_signing_key(device_key)
        .map_err(|e| anyhow!("build device cert: {e}"))?;
    let sc = kotton_net::build_bootstrap_server_config(&device_cert, provider)
        .map_err(|e| anyhow!("build bootstrap server config: {e}"))?;
    Ok(sc)
}

/// Extract the remote device's Ed25519 public key from a QUIC connection's
/// peer TLS certificate chain.
pub fn extract_peer_pubkey_from_conn(connection: &quinn::Connection) -> Option<[u8; 32]> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let first = certs.first()?;
    extract_ed25519_pubkey_from_cert(first)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use kotton_common::time::now_secs;

/// Normalize a peer-announced device name before it becomes a `PairedNode.id`:
/// trim whitespace, cap at 64 chars, and fall back to `"device"` when the peer
/// advertised nothing usable. The name is cosmetic (a label in the node table),
/// so this only needs to keep it sane — identity rests on the keys, not the name.
fn clean_device_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "device".to_string();
    }
    trimmed.chars().take(64).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Reading a user's local object **as stored** — ciphertext, header and all.
///
/// The pairing ceremony re-wraps per-object DEKs for a guest, which
/// needs the raw `[wrapped_dek][nonce][ciphertext]` blob rather than the
/// decrypted content the ordinary read path returns. Reading the decrypting
/// remote instead is the bug that once left `wrapped_deks` empty.
///
/// A second capability beside [`crate::membership::MemberStore`] rather than a
/// method on it: membership records are one thing, and "hand me the sealed bytes
/// under this path" is another. Whoever hosts the user's data implements both.
#[async_trait::async_trait]
pub trait SealedLocalRead: Send + Sync {
    async fn read_sealed_local(&self, path: &str) -> Option<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn loopback_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)
    }

    // -- committed-handshake enrollment ---------------------------------------

    /// The pairing listener binds on **any** host, whichever families it has.
    ///
    /// This asserts degradation, not a particular family: a dual-stack host binds
    /// both, an IPv6-less host (hardened container, IPv6 off by policy) binds v4
    /// only, and an IPv4-less host binds v6 only. The old single dual-stack socket
    /// failed outright on the middle case with "Address family not supported by
    /// protocol", which made `device add` — the one ceremony a new user cannot
    /// skip — impossible there.
    #[test]
    fn the_pairing_listener_binds_whatever_families_the_host_has() {
        let socks = bind_pair_listener_sockets(0).expect("binds on this host");
        assert!(
            (1..=2).contains(&socks.len()),
            "expected one socket per available family, got {}",
            socks.len()
        );
        for (family, sock) in &socks {
            let addr = sock.local_addr().expect("bound socket has an address");
            assert_ne!(addr.port(), 0, "{family:?} resolved to a real port");
        }
    }

    /// Every bound family shares one port. The connection code and the mDNS offer
    /// each carry a single port, so families landing on different ports would make
    /// one of them unreachable at the advertised address.
    #[test]
    fn all_bound_families_share_one_port() {
        let socks = bind_pair_listener_sockets(0).expect("binds on this host");
        let ports: Vec<u16> = socks
            .iter()
            .map(|(_, s)| s.local_addr().expect("addr").port())
            .collect();
        assert!(
            ports.windows(2).all(|w| w[0] == w[1]),
            "families must share one advertised port, got {ports:?}"
        );
    }

    /// The v6 socket is v6-only, so an IPv4 peer can never arrive as a v4-mapped
    /// address (`::ffff:a.b.c.d`).
    ///
    /// This is the property the whole one-socket-per-family shape exists for. A
    /// mapped address is a *different* `SocketAddr` from the plain v4 one, sorts as
    /// IPv6 in [`rank_dial_candidates`], and defeats the loopback guard in
    /// [`is_dialable_pair_addr`] — `Ipv6Addr::is_loopback` matches only `::1`, so
    /// `::ffff:127.0.0.1` reads as routable and would be recorded as a peer's
    /// dialable address. Binding per family removes the class rather than
    /// normalising after the fact.
    ///
    /// **Why this one is `#[ignore]`d.** Its subject is the wildcard bind itself, so
    /// unlike its neighbours it cannot be narrowed to loopback: `[::1]` and
    /// `127.0.0.1` are different addresses, so a v4 bind on the v6 socket's port
    /// would succeed whether or not `IPV6_V6ONLY` was ever set — the test would pass
    /// with the flag deleted, which is worse than not running. It binds `::` and
    /// `0.0.0.0` on purpose, and so it is excluded from a run that promised to open
    /// nothing off this machine. `cargo test -- --include-ignored` runs it, and
    /// `bind-check` will report the two sockets when it does.
    #[test]
    #[ignore = "binds :: and 0.0.0.0 — the wildcard is the property under test"]
    fn the_v6_socket_never_yields_v4_mapped_peers() {
        let Ok(v6) = bind_single_family(Family::V6, Ipv6Addr::UNSPECIFIED.into(), 0) else {
            // No IPv6 on this host — nothing to assert, and the bind test above
            // already covers that degradation.
            return;
        };
        let port = v6.local_addr().expect("v6 socket has an address").port();

        // Assert v6-only *behaviourally* rather than by reading `IPV6_V6ONLY`
        // back: a v6-only socket leaves the port free for the v4 family, so a v4
        // bind on the same port succeeds; a socket that also claimed IPv4 would
        // collide with `AddrInUse` — the exact collision `set_only_v6(true)` in
        // `bind_single_family` exists to prevent, and the property the whole
        // one-socket-per-family shape depends on. (Reading it back directly would
        // be tidier, but socket2's Windows `getsockopt` wrapper asserts an option
        // length this host does not return, and panics before yielding a value.)
        match bind_single_family(Family::V4, Ipv4Addr::UNSPECIFIED.into(), port) {
            // v4 took the same port → the v6 socket did not claim it → v6-only.
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => panic!(
                "the v6 pairing socket claimed IPv4 too: a v4 bind on its port \
                 collided, so IPv4 peers would arrive v4-mapped"
            ),
            // No IPv4 stack, or an unrelated bind failure: coexistence cannot be
            // observed, so assert nothing — the same posture as the no-IPv6 return.
            Err(_) => {}
        }
    }

    /// The guard the above protects, stated directly: a v4-mapped loopback is not
    /// recognised as loopback, so it must never be allowed to reach the address
    /// table in the first place.
    #[test]
    fn a_v4_mapped_loopback_would_pass_the_dialable_guard() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            is_dialable_pair_addr(&mapped),
            "precondition for the v6-only requirement: Ipv6Addr::is_loopback matches \
             only ::1, so a mapped loopback slips through — which is exactly why the \
             listener must never produce mapped addresses"
        );
        assert!(
            !is_dialable_pair_addr(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "the plain v4 form is correctly rejected"
        );
    }

    /// An explicitly requested port that is taken is an error, not a quiet
    /// re-draw. Hiding a conflict would leave the issuer listening somewhere the
    /// advertised code does not point.
    #[test]
    fn a_taken_explicit_port_is_an_error() {
        let held = bind_pair_listener_sockets(0).expect("first bind");
        let port = held[0].1.local_addr().expect("addr").port();

        assert!(
            bind_pair_listener_sockets(port).is_err(),
            "re-binding a held port must fail rather than silently pick another"
        );
    }

    /// A `Full` posture's data capability, derived from one test byte so the two
    /// domain roots stay distinguishable in assertions.
    fn full_keys(cek: [u8; 32]) -> DataKeys {
        DataKeys {
            cek,
            cek_epoch: 0,
            master_secret: [cek[0] ^ 0xff; 32],
        }
    }

    struct AutoConfirm;
    #[async_trait::async_trait]
    impl crate::pair_channel::SasConfirmer for AutoConfirm {
        async fn confirm(&self, _sas: u32, _peer_label: Option<&str>) -> bool {
            true
        }
    }

    /// Full committed-handshake enrollment over loopback QUIC: the issuer splits
    /// its identity and transfers the FrostShare over the forward-secret channel,
    /// signing the transcript with its identity key; the joiner verifies the
    /// attestation, installs the share, and records the issuer by its op key. This
    /// exercises the whole replacement for the static–static seal.
    #[tokio::test]
    async fn committed_enroll_join_loopback() {
        let issuer_identity = SigningKey::from_bytes(&[11u8; 32]);
        let op_key = SigningKey::from_bytes(&[42u8; 32]);
        let n_node = SigningKey::from_bytes(&[20u8; 32]);
        let n_warm = SigningKey::from_bytes(&[2u8; 32]);
        let cek = [3u8; 32];
        let sid = [9u8; 16];

        let (_code, listen_addr, _expires, endpoint) =
            open_pair_listener(&op_key, 0, 30).await.unwrap();
        let dial = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());

        let issuer_identity_task = issuer_identity.clone();
        let e = tokio::spawn(async move {
            run_enroll_issuer_committed(
                &issuer_identity_task,
                sid,
                Some(full_keys(cek)),
                kotton_schemas::membership::Posture::Full,
                "new-device",
                None,
                endpoint,
                30,
                9_999_999_999,
                vec![],
                None,
                Vec::new(),
                &AutoConfirm,
            )
            .await
        });

        let (joined, answer) =
            run_enroll_join_committed(&n_node, &n_warm, sid, &[dial], "issuer", None, &AutoConfirm, None)
                .await
                .expect("committed join succeeds");
        answer.kept().await.expect("the issuer hears the join kept");
        let enrolled = e.await.unwrap().expect("committed enroll succeeds");
        let (issuer_share, root_did) = enrolled.issuer_share.expect("Full retains a share");

        let issuer_did = kotton_crypto::DidKeyMethod::from_public_key_bytes(
            &issuer_identity.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            joined.root_did, issuer_did,
            "joiner binds to the issuer identity DID"
        );
        assert_eq!(joined.root_did, root_did, "both agree on the root DID");
        assert_eq!(
            joined.peer.public_key,
            op_key.verifying_key().to_bytes(),
            "issuer recorded by its dialable operational key"
        );
        let delivered = joined
            .data_keys
            .expect("a Full join receives the data capability");
        assert_eq!(
            delivered.cek, cek,
            "operational CEK delivered over the channel"
        );
        assert_eq!(
            delivered.master_secret,
            full_keys(cek).master_secret,
            "db-domain root delivered too — the joiner needs it for a matching K_log"
        );
        assert_ne!(
            issuer_share.0,
            joined.frost_share.expect("Full join holds a share").0,
            "issuer and new device hold different shares"
        );
    }

    /// Rung 2/4: with the issuer's identity key pinned out-of-band (a QR / code),
    /// the join succeeds under **auto-confirm** (no human SAS) when the pin matches
    /// the real issuer, and is rejected when the pin is some other key — proving
    /// the pin is a real cryptographic authenticator, not decoration.
    #[tokio::test]
    async fn committed_enroll_pinned_key_authenticates_without_a_sas() {
        let issuer_identity = SigningKey::from_bytes(&[11u8; 32]);
        let op_key = SigningKey::from_bytes(&[42u8; 32]);
        let n_node = SigningKey::from_bytes(&[20u8; 32]);
        let n_warm = SigningKey::from_bytes(&[2u8; 32]);
        let sid = [9u8; 16];
        let issuer_pub = issuer_identity.verifying_key().to_bytes();

        // Correct pin → join succeeds with no human comparison.
        let (_c, listen_addr, _e, endpoint) = open_pair_listener(&op_key, 0, 30).await.unwrap();
        let dial = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());
        let issuer_task = issuer_identity.clone();
        let e = tokio::spawn(async move {
            run_enroll_issuer_committed(
                &issuer_task,
                sid,
                Some(full_keys([3u8; 32])),
                kotton_schemas::membership::Posture::Full,
                "new-device",
                None,
                endpoint,
                30,
                9_999_999_999,
                vec![],
                None,
                Vec::new(),
                &AutoConfirm,
            )
            .await
        });
        let (joined, answer) = run_enroll_join_committed(
            &n_node,
            &n_warm,
            sid,
            &[dial],
            "issuer",
            None,
            &AutoConfirm,
            Some(issuer_pub),
        )
        .await
        .expect("pinned join with the correct key succeeds");
        answer.kept().await.expect("the issuer hears the join kept");
        e.await.unwrap().expect("issuer completes");
        assert_eq!(joined.root_did.to_string(), {
            kotton_crypto::DidKeyMethod::from_public_key_bytes(&issuer_pub)
                .unwrap()
                .to_string()
        });

        // Wrong pin → the attested identity does not match; join is rejected even
        // though the human "confirmed" (auto-confirm true).
        let (_c2, listen_addr2, _e2, endpoint2) = open_pair_listener(&op_key, 0, 30).await.unwrap();
        let dial2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr2.port());
        let issuer_task2 = issuer_identity.clone();
        let e2 = tokio::spawn(async move {
            run_enroll_issuer_committed(
                &issuer_task2,
                sid,
                Some(full_keys([3u8; 32])),
                kotton_schemas::membership::Posture::Full,
                "new-device",
                None,
                endpoint2,
                30,
                9_999_999_999,
                vec![],
                None,
                Vec::new(),
                &AutoConfirm,
            )
            .await
        });
        let wrong_pin = SigningKey::from_bytes(&[99u8; 32])
            .verifying_key()
            .to_bytes();
        let rejected = run_enroll_join_committed(
            &n_node,
            &n_warm,
            sid,
            &[dial2],
            "issuer",
            None,
            &AutoConfirm,
            Some(wrong_pin),
        )
        .await;
        assert!(
            rejected.is_err(),
            "a pin that isn't the real issuer must be rejected"
        );
        let refused = e2.await.unwrap().err().expect("the issuer kept a join the joiner rejected");
        assert!(
            matches!(refused.downcast_ref::<JoinNotKept>(), Some(JoinNotKept::Unanswered(_))),
            "{refused}"
        );
    }

    /// **A join the joiner refuses after the payload leaves the issuer
    /// nothing, over QUIC as over a relay.** The joiner verifies what it was
    /// handed and then refuses it, as `finalize_joined_node` refuses drives it
    /// cannot record: the issuer's ceremony returns the refusal, typed and
    /// carrying the joiner's words, and no `EnrolledNode` for its caller to
    /// record or introduce.
    #[tokio::test]
    async fn committed_enroll_a_refusal_after_the_payload_commits_nothing_on_the_issuer() {
        let issuer_identity = SigningKey::from_bytes(&[11u8; 32]);
        let op_key = SigningKey::from_bytes(&[42u8; 32]);
        let n_node = SigningKey::from_bytes(&[20u8; 32]);
        let n_warm = SigningKey::from_bytes(&[2u8; 32]);
        let sid = [9u8; 16];

        let (_code, listen_addr, _expires, endpoint) = open_pair_listener(&op_key, 0, 30).await.unwrap();
        let dial = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());
        let e = tokio::spawn(async move {
            run_enroll_issuer_committed(
                &issuer_identity,
                sid,
                Some(full_keys([3u8; 32])),
                kotton_schemas::membership::Posture::Full,
                "new-device",
                None,
                endpoint,
                30,
                9_999_999_999,
                vec![],
                None,
                Vec::new(),
                &AutoConfirm,
            )
            .await
        });
        let (joined, answer) =
            run_enroll_join_committed(&n_node, &n_warm, sid, &[dial], "issuer", None, &AutoConfirm, None)
                .await
                .expect("the joiner is handed the payload");
        assert!(joined.frost_share.is_some(), "the payload reached the joiner before it refused");
        answer.refused("the drive at 'vault' cannot be recorded here").await.expect("the issuer hears the refusal");
        let refused = e.await.unwrap().err().expect("the issuer committed a join the joiner refused");
        assert_eq!(
            refused.downcast_ref::<JoinNotKept>(),
            Some(&JoinNotKept::Refused("the drive at 'vault' cannot be recorded here".into()))
        );
    }

    /// **Over QUIC, a `kept` the issuer stopped waiting for is not complete on
    /// the joiner.** The issuer half as `run_enroll_issuer_committed` runs it,
    /// with a short bound in place of [`JOINER_KEEPS_WITHIN`]: it gives up and
    /// closes, and the joiner, answering after, gets no sealed `heard` and
    /// says so — whatever the close looked like.
    #[tokio::test]
    async fn committed_enroll_a_kept_the_issuer_gave_up_on_is_not_complete_on_the_joiner() {
        let issuer_identity = SigningKey::from_bytes(&[11u8; 32]);
        let op_key = SigningKey::from_bytes(&[42u8; 32]);
        let n_node = SigningKey::from_bytes(&[20u8; 32]);
        let n_warm = SigningKey::from_bytes(&[2u8; 32]);
        let sid = [9u8; 16];
        let bound = Duration::from_millis(300);

        let (_code, listen_addr, _expires, listener) = open_pair_listener(&op_key, 0, 30).await.unwrap();
        let dial = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());
        let e = tokio::spawn(async move {
            let connection = listener.accept().await.expect("a joiner dials").await.expect("handshake");
            let (send, recv) = connection.accept_bi().await.expect("the joiner's stream");
            let transport = Transport::over_quic(&connection, send, recv).expect("a presented key");
            let enrolled = issuer_over(
                transport,
                None,
                &issuer_identity,
                sid,
                Some(full_keys([3u8; 32])),
                kotton_schemas::membership::Posture::Full,
                "new-device",
                None,
                9_999_999_999,
                vec![],
                None,
                Vec::new(),
                None,
                &AutoConfirm,
                bound,
            )
            .await;
            connection.close(0u32.into(), b"");
            enrolled.map(|_| ())
        });
        let (_joined, answer) =
            run_enroll_join_committed(&n_node, &n_warm, sid, &[dial], "issuer", None, &AutoConfirm, None)
                .await
                .expect("the joiner is handed the payload");
        let gave_up = e.await.unwrap().expect_err("the issuer committed a join nobody answered");
        assert!(matches!(gave_up.downcast_ref::<JoinNotKept>(), Some(JoinNotKept::Unanswered(_))), "{gave_up}");
        let late = answer.kept().await;
        assert!(late.is_err(), "a `kept` the issuer gave up on was taken as heard");
    }

    /// A wrong SAS on the joiner (human says "codes don't match") aborts before
    /// any payload is transferred — the join returns an error and the issuer does
    /// not complete.
    #[tokio::test]
    async fn committed_enroll_sas_reject_transfers_nothing() {
        struct RejectConfirm;
        #[async_trait::async_trait]
        impl crate::pair_channel::SasConfirmer for RejectConfirm {
            async fn confirm(&self, _sas: u32, _peer_label: Option<&str>) -> bool {
                false
            }
        }

        let issuer_identity = SigningKey::from_bytes(&[11u8; 32]);
        let op_key = SigningKey::from_bytes(&[42u8; 32]);
        let n_node = SigningKey::from_bytes(&[20u8; 32]);
        let n_warm = SigningKey::from_bytes(&[2u8; 32]);
        let sid = [9u8; 16];

        let (_code, listen_addr, _expires, endpoint) =
            open_pair_listener(&op_key, 0, 30).await.unwrap();
        let dial = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());

        let issuer_identity_task = issuer_identity.clone();
        let e = tokio::spawn(async move {
            run_enroll_issuer_committed(
                &issuer_identity_task,
                sid,
                Some(full_keys([3u8; 32])),
                kotton_schemas::membership::Posture::Full,
                "new-device",
                None,
                endpoint,
                30,
                9_999_999_999,
                vec![],
                None,
                Vec::new(),
                &AutoConfirm, // issuer would confirm; the joiner rejects
            )
            .await
        });

        let joined =
            run_enroll_join_committed(&n_node, &n_warm, sid, &[dial], "issuer", None, &RejectConfirm, None)
                .await;
        assert!(joined.is_err(), "a rejected SAS must fail the join");
        let enrolled = e.await.unwrap();
        assert!(
            enrolled.is_err(),
            "issuer must not complete when the joiner rejects"
        );
    }

    // -- pairing code ---------------------------------------------------------

    #[test]
    fn pairing_code_round_trip() {
        let pubkey = [7u8; 32];
        let addr = loopback_addr();
        let expires_at: u64 = 1_999_999_999;
        let code = generate_pairing_code(pubkey, addr, expires_at);
        let (pk2, addr2, exp2) = parse_pairing_code(&code, 1_000_000_000).unwrap();
        assert_eq!(pk2, pubkey);
        assert_eq!(addr2, addr);
        assert_eq!(exp2, expires_at);
    }

    #[test]
    fn connection_code_round_trips() {
        let sid = [0xABu8; 16];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)), 51820);
        let code = encode_connection_code(&sid, addr);
        let (sid2, addr2) = parse_connection_code(&code).unwrap();
        assert_eq!(sid2, sid);
        assert_eq!(addr2, addr);
        // Typed-code hygiene: base32, so none of the look-alike
        // characters a human would fat-finger off another screen.
        assert!(
            !code.contains(['i', 'l', 'o', 'u']),
            "code must avoid ambiguous base32 characters, got {code}"
        );
        // Shorter than the old hex `sid.addr` (32 + 1 + 12 = 45 chars).
        assert!(code.len() < 45, "base32 code should be shorter than hex, got {}", code.len());
        assert!(parse_connection_code("garbage").is_err());
    }

    #[test]
    fn connection_code_transcription_is_forgiving() {
        // A human retypes it uppercased, hyphen-grouped, with an o-for-0 slip — and it
        // still resolves, so a fallback code isn't lost to cosmetic transcription.
        let sid = [0x3Fu8; 16];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 4242);
        let code = encode_connection_code(&sid, addr);
        let messy = format!("{}-{}", &code[..8], &code[8..]).to_uppercase();
        let (sid2, addr2) = parse_connection_code(&messy).unwrap();
        assert_eq!(sid2, sid);
        assert_eq!(addr2, addr);
    }

    #[test]
    fn ipv6_connection_code_round_trips() {
        let sid = [0x11u8; 16];
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4)), 9000);
        let code = encode_connection_code(&sid, addr);
        let (sid2, addr2) = parse_connection_code(&code).unwrap();
        assert_eq!(sid2, sid);
        assert_eq!(addr2, addr);
    }

    #[test]
    fn rank_dial_candidates_drops_undialable_and_prefers_ipv6() {
        // The pathological dual-stack Mac set that made discovery a coin toss.
        let port = 53742;
        let lan_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 4, 68)), port);
        let ula_v6 = SocketAddr::new(
            IpAddr::V6("fd93:2a67:ae68:1:b7a6:fa75:948e:7f3f".parse().unwrap()),
            port,
        );
        let raw = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port), // loopback → drop
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2)), port), // link-local → drop
            SocketAddr::new(IpAddr::V6("fe80::c0c7:4aff:fe58:e382".parse().unwrap()), port), // v6 link-local → drop
            lan_v4, // routable IPv4 → keep, but after the ULA
            ula_v6, // ULA → keep, ranked first (the sturdy same-/64 LAN path)
        ];
        // ULA ahead of IPv4; loopback + both link-locals gone. IPv6-first is what
        // makes the join reach a peer that is only mutually routable over IPv6.
        assert_eq!(rank_dial_candidates(&raw), vec![ula_v6, lan_v4]);
    }

    #[test]
    fn rank_dial_candidates_empty_when_nothing_routable() {
        let port = 9;
        let raw = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), port),
        ];
        assert!(rank_dial_candidates(&raw).is_empty());
    }

    #[test]
    fn choose_advertised_addr_override_wins_even_over_a_concrete_bind() {
        // KOTTON_ADVERTISE_IP is the escape hatch: it replaces the IP regardless of
        // what the socket bound (here a concrete, already-routable address), keeping
        // the OS-assigned port. This is the multi-homed / NAT / CI override path.
        let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 53742);
        let override_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(
            choose_advertised_addr(bound, Some(override_ip), None),
            SocketAddr::new(override_ip, 53742),
        );
    }

    #[test]
    fn choose_advertised_addr_fills_unspecified_bind_with_detected_lan_ip() {
        // The zero-config default: an all-interfaces bind (0.0.0.0) carries a useless
        // unspecified IP; a detected LAN IP replaces it so a cross-machine joiner can
        // dial. Port is preserved.
        let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53742);
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 4, 68));
        assert_eq!(
            choose_advertised_addr(bound, None, Some(lan)),
            SocketAddr::new(lan, 53742),
        );
    }

    #[test]
    fn choose_advertised_addr_leaves_unspecified_when_nothing_detected() {
        // Isolated host (no default route → detection returned None): keep the
        // unspecified address. The joiner remaps it to loopback, so same-host pairing
        // still works — we never advertise a bogus address.
        let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53742);
        assert_eq!(choose_advertised_addr(bound, None, None), bound);
    }

    #[test]
    fn choose_advertised_addr_leaves_concrete_loopback_bind_untouched() {
        // A deliberate loopback bind (KOTTON_PAIR_LOCAL_ONLY) is not unspecified, so
        // with no override it is advertised as-is — we don't second-guess an explicit
        // local-only choice by probing for a LAN IP.
        let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53742);
        let detected = IpAddr::V4(Ipv4Addr::new(192, 168, 9, 9));
        assert_eq!(choose_advertised_addr(bound, None, Some(detected)), bound);
    }

    #[test]
    fn detected_lan_ip_is_always_dialable() {
        // Environment-dependent (a route may or may not exist here), so assert only
        // the invariant that must always hold: if detection yields an address, it is
        // one we'd actually be willing to dial — never loopback/link-local/unspecified.
        if let Some(ip) = detect_lan_ip() {
            assert!(
                is_dialable_pair_addr(&ip),
                "detect_lan_ip returned an undialable address: {ip}"
            );
        }
    }

    #[test]
    fn expired_pairing_code_rejected() {
        let pubkey = [1u8; 32];
        let addr = loopback_addr();
        let expires_at: u64 = 1_000_000_000;
        let code = generate_pairing_code(pubkey, addr, expires_at);
        let result = parse_pairing_code(&code, 1_999_999_999); // now > expires_at
        assert!(result.is_err(), "expired code should be rejected");
    }
}

/// The relayed transport, minus the relay: both halves over an in-memory
/// duplex, the way `contact_pairing` proves its ceremony. What the relay adds
/// is proven where a real relay runs (`tests/suite/vault.rs`).
#[cfg(test)]
mod relayed_tests {
    use super::*;
    use crate::pair_channel::SasConfirmer;
    use async_trait::async_trait;
    use kotton_schemas::membership::Posture;
    use std::sync::Mutex;

    struct Yes(Mutex<Option<u32>>);
    #[async_trait]
    impl SasConfirmer for Yes {
        async fn confirm(&self, sas: u32, _label: Option<&str>) -> bool {
            *self.0.lock().unwrap() = Some(sas);
            true
        }
    }

    fn key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    /// Two byte streams with a relay between them, as `circuit::bridge` in
    /// `infra/relay` behaves: each way is forwarded as it comes, the issuer's
    /// end ends the joiner's leg (a relay forwards no close of its own
    /// bytes, it ends both legs), and the joiner's bytes are still taken after
    /// the issuer is gone, as a relay's socket takes them until it is closed.
    /// So an answer sent after the issuer gave up is sent, and only the reply
    /// is missing. Returns the issuer's end and the joiner's.
    fn a_relay_between() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        use tokio::io::AsyncWriteExt;
        let (issuer, at_issuer) = tokio::io::duplex(1 << 16);
        let (joiner, at_joiner) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let (mut from_issuer, mut to_issuer) = tokio::io::split(at_issuer);
            let (mut from_joiner, mut to_joiner) = tokio::io::split(at_joiner);
            let down = async {
                let _ = tokio::io::copy(&mut from_issuer, &mut to_joiner).await;
                let _ = to_joiner.shutdown().await;
            };
            let up = async {
                let _ = tokio::io::copy(&mut from_joiner, &mut to_issuer).await;
                let _ = to_issuer.shutdown().await;
                let _ = tokio::io::copy(&mut from_joiner, &mut tokio::io::sink()).await;
            };
            tokio::join!(down, up);
        });
        (issuer, joiner)
    }

    /// How the joiner answers once it holds what it was handed.
    enum Answering {
        /// `kept`, at once.
        Kept,
        /// `refused`, with this reason.
        Refused(&'static str),
        /// Drops the answer unsaid, closing the circuit.
        Closes,
        /// Says nothing for this long, then `kept`.
        Late(Duration),
    }

    /// Both halves over a duplex, each keyed by its own copy of the code.
    async fn run(code_issuer: &str, code_joiner: &str) -> (Result<EnrolledNode>, Result<JoinedNode>, u32, u32) {
        run_pinned(code_issuer, code_joiner, |_| None).await
    }

    /// [`run`], with the issuer holding the vault to the key `pin` names, given
    /// the vault's own.
    async fn run_pinned(
        code_issuer: &str,
        code_joiner: &str,
        pin: impl FnOnce([u8; 32]) -> Option<[u8; 32]>,
    ) -> (Result<EnrolledNode>, Result<JoinedNode>, u32, u32) {
        run_answering(code_issuer, code_joiner, pin, Answering::Kept, JOINER_KEEPS_WITHIN).await
    }

    /// [`run_pinned`], with the joiner answering as `answering` and the issuer
    /// waiting for the answer at most `kept_within`. The joiner's result is
    /// `Err` when its answer was not heard.
    async fn run_answering(
        code_issuer: &str,
        code_joiner: &str,
        pin: impl FnOnce([u8; 32]) -> Option<[u8; 32]>,
        answering: Answering,
        kept_within: Duration,
    ) -> (Result<EnrolledNode>, Result<JoinedNode>, u32, u32) {
        let (a, b) = a_relay_between();
        let issuer_identity = key();
        let issuer_op = key();
        let vault_op = key();
        let pinned = pin(vault_op.verifying_key().to_bytes());
        let warm = key();
        let rv_i = rendezvous_in(code_issuer, &ENROL_DOMAIN).unwrap();
        let rv_j = rendezvous_in(code_joiner, &ENROL_DOMAIN).unwrap();
        let yes_i = Yes(Mutex::new(None));
        let yes_j = Yes(Mutex::new(None));
        let issuer_side = async {
            let (read, write) = tokio::io::split(a);
            issuer_over(
                Transport::relayed(write, read, code_issuer).pinned_to(pinned),
                Some(SelfAnnounce { op_key: &issuer_op, relay_url: "http://laptop-relay:7700".into() }),
                &issuer_identity,
                rv_i.sid,
                None,
                Posture::BlindStorage,
                "laptop",
                None,
                0,
                Vec::new(),
                Some("sealed-recovery-copy".into()),
                Vec::new(),
                None,
                &yes_i,
                kept_within,
            )
            .await
        };
        let joiner_side = async {
            let (read, write) = tokio::io::split(b);
            let joined = joiner_over(
                Transport::relayed(write, read, code_joiner),
                Some(SelfAnnounce { op_key: &vault_op, relay_url: "http://host-relay:7700".into() }),
                &warm,
                rv_j.sid,
                "vault",
                Some("0.0.0.0:7710".parse().unwrap()),
                &yes_j,
                None,
            )
            .await;
            let (joined, channel) = joined?;
            let answer = JoinAnswer { channel, connection: None };
            match answering {
                Answering::Kept => answer.kept().await.map(|()| joined),
                Answering::Refused(why) => answer.refused(why).await.map(|()| joined),
                Answering::Closes => {
                    drop(answer);
                    Ok(joined)
                }
                Answering::Late(after) => {
                    tokio::time::sleep(after).await;
                    answer.kept().await.map(|()| joined)
                }
            }
        };
        let (e, j) = tokio::join!(issuer_side, joiner_side);
        let (e, j) = match (&e, &j) {
            (Ok(e2), Ok(j2)) => {
                assert_eq!(e2.node.public_key, vault_op.verifying_key().to_bytes(), "the vault is admitted by the key it proved");
                assert_eq!(j2.peer.public_key, issuer_op.verifying_key().to_bytes(), "the vault records the key the laptop proved");
                (e, j)
            }
            _ => (e, j),
        };
        let si = yes_i.0.lock().unwrap().unwrap_or(u32::MAX);
        let sj = yes_j.0.lock().unwrap().unwrap_or(u32::MAX);
        (e, j, si, sj)
    }

    /// The headline: an invite enrols a blind node over a bare byte stream, with
    /// no certificate and no address on either end. Each side admits the other
    /// by a key proven inside the channel, records the other's relay, and
    /// records **no address** for a peer that announced only a port — that
    /// peer is reached through its relay.
    #[tokio::test]
    async fn an_invite_enrols_a_blind_node_over_a_bare_stream() {
        let code = normalize_code("ripple canyon ember");
        let (e, j, si, sj) = run(&code, &code).await;
        let e = e.expect("issuer");
        let j = j.expect("joiner");
        assert_eq!(si, sj, "one pair of six digits on both screens");
        assert_eq!(e.node.id, "vault");
        assert_eq!(e.node.relay_url.as_deref(), Some("http://host-relay:7700"));
        assert!(e.node.addresses.is_empty(), "a vault that announced 0.0.0.0:7710 over a relay has no dialable address: {:?}", e.node.addresses);
        assert!(e.issuer_share.is_none(), "blind: nothing to retain");
        assert_eq!(j.peer.id, "laptop");
        assert_eq!(j.peer.relay_url.as_deref(), Some("http://laptop-relay:7700"));
        assert!(j.data_keys.is_none() && j.frost_share.is_none(), "blind: no keys crossed");
        assert_eq!(j.recovery_bundle.as_deref(), Some("sealed-recovery-copy"));
        assert_eq!(
            kotton_crypto::DidKeyMethod::to_public_key(&e.node.device_did).unwrap().to_bytes(),
            e.node.public_key,
            "the DID is the proven key's"
        );
    }

    /// A party that did not hear the words cannot pass: the PAKE, not the
    /// handle, is what keeps a stranger out of an invite they stumbled into.
    #[tokio::test]
    async fn the_wrong_words_enrol_nobody() {
        let (e, j, _, _) = run(&normalize_code("ripple canyon ember"), &normalize_code("ripple canyon amber")).await;
        assert!(e.is_err(), "issuer must not complete: {:?}", e.ok().map(|n| n.node.id));
        assert!(j.is_err(), "joiner must not complete: {:?}", j.ok().map(|n| n.peer.id));
    }

    /// **A vault held to the key the operator credential pins is admitted as
    /// any vault is**: the pin is the same key the vault proves.
    #[tokio::test]
    async fn a_vault_that_proves_the_pinned_key_is_admitted() {
        let code = normalize_code("ripple canyon ember");
        let (e, j, _, _) = run_pinned(&code, &code, Some).await;
        assert_eq!(e.expect("issuer").node.id, "vault");
        assert_eq!(j.expect("joiner").recovery_bundle.as_deref(), Some("sealed-recovery-copy"));
    }

    /// **A vault that proves any other key is refused where it proves it, and
    /// is handed nothing.** The issuer stops before its own key
    /// record, so the joiner never completes and holds no recovery copy; the
    /// refusal is typed, carrying both keys, for the caller to name.
    #[tokio::test]
    async fn a_vault_that_proves_another_key_is_refused_and_handed_nothing() {
        let code = normalize_code("ripple canyon ember");
        let other = key().verifying_key().to_bytes();
        let (e, j, _, _) = run_pinned(&code, &code, |_| Some(other)).await;
        let err = e.err().expect("the issuer admitted a vault the pin does not name");
        let refused = err.downcast_ref::<NotThePinnedKey>().expect("the refusal is typed");
        assert_eq!(refused.pinned, other);
        assert_ne!(refused.answered, other);
        assert!(err.to_string().contains("nothing was handed over"), "{err}");
        assert!(j.is_err(), "the joiner completed against an issuer that refused it");
    }

    /// **A joiner that refuses what it was handed leaves the issuer nothing**,
    /// and the issuer is told why in the joiner's words, with nothing that
    /// could steer its person's terminal.
    #[tokio::test]
    async fn a_refusal_after_the_payload_is_heard_and_nothing_is_enrolled() {
        let code = normalize_code("ripple canyon ember");
        let (e, j, _, _) = run_answering(
            &code,
            &code,
            |_| None,
            Answering::Refused("this node is a vault\u{1b}[2J and holds no key"),
            JOINER_KEEPS_WITHIN,
        )
        .await;
        assert!(j.is_ok(), "the joiner's refusal was not heard: {:?}", j.err());
        let err = e.err().expect("the issuer enrolled a node that refused the join");
        assert_eq!(
            err.downcast_ref::<JoinNotKept>(),
            Some(&JoinNotKept::Refused("this node is a vault[2J and holds no key".into())),
            "{err}"
        );
    }

    /// **A joiner that closes without answering leaves the issuer nothing**:
    /// the answer handle dropped unsaid is a no.
    #[tokio::test]
    async fn a_joiner_that_closes_without_answering_enrols_nothing() {
        let code = normalize_code("ripple canyon ember");
        let (e, j, _, _) = run_answering(&code, &code, |_| None, Answering::Closes, JOINER_KEEPS_WITHIN).await;
        assert!(j.is_ok());
        let err = e.err().expect("the issuer enrolled a node that never answered");
        assert!(matches!(err.downcast_ref::<JoinNotKept>(), Some(JoinNotKept::Unanswered(_))), "{err}");
    }

    /// **The issuer's wait for the answer is bounded** ([`JOINER_KEEPS_WITHIN`]
    /// on every live path; a short bound here, through the same parameter):
    /// a joiner silent past it leaves the issuer nothing, the issuer returns
    /// at the bound and not at the joiner's leisure, and the joiner's late
    /// `kept` — sent, into a relay still taking bytes — is not complete,
    /// because no sealed `heard` came back: the relay's end of the circuit
    /// is not the issuer's word.
    #[tokio::test]
    async fn the_issuer_waits_for_the_answer_only_within_its_bound() {
        let bound = Duration::from_millis(300);
        let code = normalize_code("ripple canyon ember");
        let started = std::time::Instant::now();
        let (e, j, _, _) =
            run_answering(&code, &code, |_| None, Answering::Late(bound * 4), bound).await;
        let err = e.err().expect("the issuer enrolled a node that answered past the bound");
        match err.downcast_ref::<JoinNotKept>() {
            Some(JoinNotKept::Unanswered(how)) => assert!(how.contains("no answer within"), "{how}"),
            other => panic!("not the bound's refusal: {other:?} ({err})"),
        }
        assert!(started.elapsed() >= bound, "the issuer stopped waiting before its bound");
        let late = j.err().expect("a late `kept` was taken as heard");
        assert!(late.to_string().contains("before the admitting device replied that it heard"), "{late}");
    }

    /// **A relay that refuses an invite's reservation is told apart from one
    /// that was not reached** (`reserve_invite`): a `403` at the upgrade — the
    /// rule's one refusal — is `Refused`; nothing listening, and a relay that
    /// takes the connection and never answers, are `Unreachable`, the second
    /// within [`INVITE_RESERVE_WITHIN`] and not held open past it.
    #[tokio::test]
    async fn a_relay_that_refuses_an_invite_is_told_apart_from_one_that_does_not_answer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Answers every upgrade as the relay's rule refuses one.
        let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refusing_at = refusing.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = refusing.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = r#"{"error":"not admitted by this relay's rule"}"#;
                let _ = s
                    .write_all(format!("HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
            }
        });
        // Takes the connection and says nothing.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_at = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = silent.accept().await {
                held.push(s);
            }
        });
        // Nothing listens: bound, read back, and let go.
        let gone_at = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();

        let at = |addr: std::net::SocketAddr| Invite::new(&format!("http://{addr}"));
        assert!(
            matches!(reserve_invite(&at(refusing_at), None).await, Err(InviteNotReserved::Refused(_))),
            "a 403 is the relay's refusal"
        );
        assert!(
            matches!(reserve_invite(&at(gone_at), None).await, Err(InviteNotReserved::Unreachable(_))),
            "nothing listening is not a refusal"
        );
        let started = tokio::time::Instant::now();
        assert!(
            matches!(reserve_invite(&at(silent_at), None).await, Err(InviteNotReserved::Unreachable(_))),
            "a relay that never answers is not a refusal"
        );
        assert!(started.elapsed() < INVITE_RESERVE_WITHIN + Duration::from_secs(5), "the reservation was not bounded");
    }

    /// **An invite is handed over as its code, and the ceremony reads back
    /// from it where it meets and under which words** — the words normalised
    /// as both sides derive the handle from them, the relay's URL without a
    /// trailing `/`. A relay's invite meets nobody.
    #[test]
    fn an_invite_is_handed_over_as_its_code_and_reads_back() {
        let inv = Invite::new("https://relay.example:7700/");
        assert_eq!(inv.relay_url, "https://relay.example:7700");
        assert_eq!(inv.code.split('-').count(), 3);
        let code = inv.code_for([1; 32], [2; 32], None);
        let text = code.to_text();
        assert!(text.starts_with("kotton-invite:vault:"), "{text}");
        let read = kotton_wire::line::InviteCode::parse(&text).unwrap();
        assert_eq!(Invite::of(&read), Some(inv.clone()));
        // The relay's invited key, when the minting node may hand it on, rides
        // in the code and reads back as it was handed.
        let invited = kotton_net::rendezvous::AdmissionKey::from_bytes([4; 32]);
        let carrying = kotton_wire::line::InviteCode::parse(&inv.code_for([1; 32], [2; 32], Some(&invited)).to_text()).unwrap();
        assert!(matches!(carrying, kotton_wire::line::InviteCode::Vault { invited: Some(k), .. } if k == [4; 32]), "{carrying:?}");
        assert_eq!(Invite::of(&carrying), Some(inv));
        let relay = kotton_wire::line::InviteCode::Relay { key: [2; 32], hint: "https://relay.example:7700".into(), invited: [3; 32] };
        assert_eq!(Invite::of(&relay), None, "a relay's invite meets nobody");
    }

    /// A record that names a key its signature does not prove is refused,
    /// whatever else the ceremony said: the key is what the other side admits.
    #[test]
    fn an_operational_key_nobody_proved_is_refused() {
        let t = b"this ceremony's transcript".to_vec();
        let honest = key();
        let liar = key();
        let me = SelfAnnounce { op_key: &honest, relay_url: String::new() };
        let mut record = sign_op_key(&t, &me);
        assert!(verify_op_key(&t, &record).is_ok());
        record.pubkey = liar.verifying_key().to_bytes();
        assert!(verify_op_key(&t, &record).is_err());
        let mut relay_swapped = sign_op_key(&t, &me);
        relay_swapped.relay_url = "http://somewhere-else".into();
        assert!(verify_op_key(&t, &relay_swapped).is_err(), "the relay is under the signature too");
    }
}

