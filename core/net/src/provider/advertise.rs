// SPDX-License-Identifier: AGPL-3.0-or-later
//! Resolving the address a node tells the world to reach it at.
//!
//! ## Why this exists
//!
//! A node behind a NAT, or in a container, binds one address and is reached at another. The
//! address it *advertises* is what goes into an enrolment code, and it is the difference
//! between a person's device dialling the host and dialling nothing.
//!
//! Both `khttpd` and `kvaultd` read one from the environment, and before 2026-09-11 they
//! each did it by hand and disagreed about the most important case:
//!
//! ```text
//! khttpd   .map(|a| a.parse().map_err(...))?      // a bad value is an error
//! kvaultd  .and_then(|s| s.parse().ok())          // a bad value is silence
//! ```
//!
//! `kvaultd`'s swallowed it. A typo, or a hostname — which reads like it should work and did
//! not — parsed to `None`, which is what *unset* also means. The vault then started cleanly,
//! printed a code carrying the address it bound inside its container, and the person's laptop
//! could not reach it. Nothing in the output said why. That is the failure this repository
//! keeps finding: a value that resolves to nothing, silently, on the one step a stranger
//! following a README has to get right.
//!
//! ## What this does
//!
//! Numeric `IP:port` is unchanged and still the fast path — it never touches the network.
//! A `host:port` is resolved. Anything else is an error with the text that failed in it.

use std::io;
use std::net::SocketAddr;

/// Resolve an advertised address from `IP:port` or `host:port`.
///
/// **Prefers IPv4 when a name gives both.** A v4 address is reachable by more of the people
/// who will be dialling it; a v6-only host still resolves, because there is no v4 to prefer.
/// This is a reachability guess, and it is the advertised address rather than the bound one,
/// so being wrong costs a re-run with a literal rather than a broken node.
pub async fn resolve_advertise(value: &str) -> io::Result<SocketAddr> {
    let v = value.trim();
    if v.is_empty() {
        return Err(io::Error::other("advertised address is empty"));
    }
    // Numeric, including `[::1]:7711`. No DNS, no await that can hang.
    if let Ok(addr) = v.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // A name. `lookup_host` wants `host:port` and says so if the port is missing.
    let mut found: Option<SocketAddr> = None;
    let addrs = tokio::net::lookup_host(v).await.map_err(|e| {
        io::Error::other(format!(
            "cannot resolve advertised address {v:?}: {e}. Expected `IP:port` (e.g. \
             198.51.100.7:7711) or `host:port`"
        ))
    })?;
    for a in addrs {
        if a.is_ipv4() {
            return Ok(a);
        }
        found.get_or_insert(a);
    }
    found.ok_or_else(|| {
        io::Error::other(format!("advertised address {v:?} resolved to no addresses"))
    })
}

/// Read an advertised address from the environment, or `None` when the variable is unset.
///
/// **Unset is `None`; set-and-unresolvable is an error.** Those were the same thing in
/// `kvaultd` and are not the same thing at all: one is a person who did not need to
/// advertise, the other is a person who tried and will find out when a device cannot dial
/// them.
pub async fn advertise_from_env(var: &str) -> io::Result<Option<SocketAddr>> {
    match std::env::var(var) {
        Err(_) => Ok(None),
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => resolve_advertise(&raw)
            .await
            .map(Some)
            .map_err(|e| io::Error::other(format!("{var}: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The path every VPS takes, and the one that must not have changed.
    #[tokio::test]
    async fn a_numeric_address_resolves_to_itself() {
        let a = resolve_advertise("198.51.100.7:7711").await.expect("v4");
        assert_eq!(a.to_string(), "198.51.100.7:7711");
        let b = resolve_advertise("[2001:db8::1]:7712").await.expect("v6");
        assert_eq!(b.port(), 7712);
        assert!(b.is_ipv6());
        // Whitespace from a shell heredoc or a compose file is not a failure.
        assert_eq!(resolve_advertise("  198.51.100.7:7711 ").await.unwrap().port(), 7711);
    }

    /// **The bug, as a test.** `kvaultd` turned each of these into `None` — the same value
    /// it uses for *unset* — and started anyway.
    #[tokio::test]
    async fn a_malformed_address_is_an_error_not_a_shrug() {
        for bad in ["", "  ", "not-an-address", "198.51.100.7", "198.51.100.7:"] {
            assert!(
                resolve_advertise(bad).await.is_err(),
                "{bad:?} should not resolve; silence here is what made a vault print a code \
                 nobody could dial"
            );
        }
    }

    /// Localhost is the one name that resolves without a network, so it is the one that can
    /// be asserted in a suite that must not reach out. `bind-check` would catch it if it did.
    #[tokio::test]
    async fn a_name_is_resolved_and_v4_is_preferred() {
        let a = resolve_advertise("localhost:7711").await.expect("localhost resolves");
        assert_eq!(a.port(), 7711);
        assert!(a.is_ipv4(), "localhost has both; v4 is the one more dialers can reach");
    }

    /// Unset and set-but-wrong are different answers. They were the same one.
    #[tokio::test]
    async fn unset_is_none_and_unresolvable_is_an_error() {
        let var = "KOTTON_TEST_ADVERTISE_UNSET_XYZ";
        std::env::remove_var(var);
        assert!(advertise_from_env(var).await.expect("unset is fine").is_none());

        std::env::set_var(var, "vault.invalid.example:7711");
        let err = advertise_from_env(var).await.expect_err("a name that cannot resolve");
        assert!(err.to_string().contains(var), "the error names the variable to fix");
        std::env::remove_var(var);
    }
}
