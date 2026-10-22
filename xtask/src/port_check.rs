// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every deployable service can run on one host.
//!
//! ## Why this exists
//!
//! Measured 2026-09-11, while writing a runbook: the **vault** publishes UDP 7710 for as long
//! as it runs, and the **gateway** published UDP 7710 for the minutes its enrolment listener
//! is up. A person renting one host for themselves and a few friends — the ordinary case —
//! could not run both. The vault's binding was overridable and the gateway's was a literal in
//! its compose file, so the only way out was editing a file nobody tells you to edit.
//!
//! Neither README was wrong. Each documented its own port correctly, and nothing compared
//! them. That is the same shape as every other defect found this week: a fact stated in two
//! places with nothing holding them in step.
//!
//! ## What it checks
//!
//! 1. **No two distinct services publish the same host port.** This is the invariant — the
//!    services must compose onto one machine, and docker only catches it at `up` time, on
//!    the user's host, after they have followed a README that promised it would work.
//!
//!    **By service, not by file**, which the first draft got wrong and its own test caught:
//!    `infra/vault/docker-compose.yml` bundles the relay so one command brings up both, and
//!    `infra/relay/docker-compose.yml` is the relay alone. The two files are alternatives, so
//!    7700 appearing in each is correct rather than a conflict. What must not repeat is one
//!    port across two *different* services.
//!
//!    Where one service is defined twice, the two definitions must agree — a relay published
//!    on 7700 in one file and 7701 in the other is a README that lies in one of them.
//!
//! The reference also holds every published port to a port table in `infra/README.md`. This
//! tree has no such page, so that half is not here: a rule over a page that is absent
//! measures nothing.

use std::collections::BTreeMap;
use std::path::Path;

/// The compose files that describe a service somebody runs.
const SERVICES: &[&str] = &["infra/relay", "infra/vault"];

/// One service's ports, grouped by the compose file that declared them — so the two
/// definitions of a service defined twice can be compared against each other.
type PerFile<'a> = BTreeMap<&'a str, Vec<(u16, bool)>>;

/// One published port, and where it was published.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Published {
    pub(crate) port: u16,
    pub(crate) udp: bool,
    pub(crate) file: String,
    /// The compose `services:` key — the relay is the relay wherever it is defined.
    pub(crate) service: String,
}

impl Published {
    fn key(&self) -> (u16, bool) {
        (self.port, self.udp)
    }
    fn label(&self) -> String {
        format!("{}/{}", self.port, if self.udp { "udp" } else { "tcp" })
    }
}

/// Every host port a compose file publishes.
///
/// A `ports:` entry is `"<host>:<container>"`, and the host half is what collides — the
/// container half is private to its own network namespace and may repeat freely. The host
/// half may carry an address (`0.0.0.0:7700`) and a `${VAR:-default}` around it, so the
/// port taken is **the last colon-separated field of the host half**, with any `/udp`
/// suffix belonging to the container half.
pub(crate) fn published_in(text: &str, file: &str) -> Vec<Published> {
    let mut out = Vec::new();
    let mut service = String::new();
    let mut in_services = false;
    for line in text.lines() {
        // Track which service's block we are in. `services:` is at column 0 and each
        // service is its two-space-indented key.
        if !line.starts_with(' ') && line.trim_end().starts_with("services:") {
            in_services = true;
            continue;
        }
        if in_services
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
        {
            service = line.trim().trim_end_matches(':').to_owned();
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_services = false;
        }
        let t = line.trim();
        if !t.starts_with("- \"") || !t.ends_with('"') {
            continue;
        }
        let body = &t[3..t.len() - 1];
        let udp = body.ends_with("/udp");
        let body = body.trim_end_matches("/udp").trim_end_matches("/tcp");
        // Split host half from container half at the LAST colon.
        let Some(cut) = body.rfind(':') else { continue };
        let host = &body[..cut];
        // The host half's own port is its last field, after any bind address and after a
        // `${VAR:-0.0.0.0:7700}` default. Trailing `}` from the substitution goes first.
        let host = host.trim_end_matches('}');
        let Some(p) = host.rsplit(':').next() else {
            continue;
        };
        if let Ok(port) = p.parse::<u16>() {
            out.push(Published {
                port,
                udp,
                file: file.to_owned(),
                service: service.clone(),
            });
        }
    }
    out
}

pub fn run() {
    let mut all: Vec<Published> = Vec::new();
    for dir in SERVICES {
        let path = Path::new(dir).join("docker-compose.yml");
        let Ok(text) = std::fs::read_to_string(&path) else {
            eprintln!("port-check: cannot read {}", path.display());
            std::process::exit(1);
        };
        all.extend(published_in(&text, dir));
    }

    let mut findings: Vec<String> = Vec::new();

    // 1. Collisions across services.
    let mut seen: BTreeMap<(u16, bool), Vec<&Published>> = BTreeMap::new();
    for p in &all {
        seen.entry(p.key()).or_default().push(p);
    }
    for group in seen.values() {
        let mut services: Vec<&str> = group.iter().map(|p| p.service.as_str()).collect();
        services.sort_unstable();
        services.dedup();
        if services.len() > 1 {
            findings.push(format!(
                "{} is published by the `{}` services — they cannot run on one host, and the \
                 ordinary case is one host for yourself and a few friends",
                group[0].label(),
                services.join("` and `")
            ));
        }
    }

    // 1b. One service, defined in two files, must agree about its ports.
    let mut by_service: BTreeMap<&str, PerFile<'_>> = BTreeMap::new();
    for p in &all {
        by_service
            .entry(p.service.as_str())
            .or_default()
            .entry(p.file.as_str())
            .or_default()
            .push(p.key());
    }
    for (svc, per_file) in &by_service {
        if per_file.len() < 2 {
            continue;
        }
        let mut sets: Vec<Vec<(u16, bool)>> = per_file
            .values()
            .map(|v| {
                let mut v = v.clone();
                v.sort_unstable();
                v
            })
            .collect();
        sets.dedup();
        if sets.len() > 1 {
            findings.push(format!(
                "`{svc}` is defined in {} and they publish different ports — one of those \
                 READMEs tells a person the wrong number",
                per_file.keys().copied().collect::<Vec<_>>().join(" and ")
            ));
        }
    }

    if findings.is_empty() {
        println!(
            "port-check: OK — {} published port(s) across {} service(s), none shared, and \
             each service defined twice publishes the same ports in both.",
            all.len(),
            SERVICES.len()
        );
        return;
    }
    findings.sort();
    findings.dedup();
    println!("port-check: {} finding(s):\n", findings.len());
    for f in &findings {
        println!("  {f}");
    }
    println!(
        "\nEvery service in infra/ must compose onto one machine. Take the next free port in \
         the 77xx range, and give it an override variable."
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three shapes a compose file actually writes, all of which appeared in `infra/`
    /// before this gate existed.
    #[test]
    fn the_host_port_is_read_through_every_spelling() {
        let text = concat!(
            "    ports:\n",
            "      - \"80:80\"\n",
            "      - \"${KOTTON_RELAY_BIND:-0.0.0.0:7700}:7700\"\n",
            "      - \"${KOTTON_VAULT_BIND:-0.0.0.0:7710}:7710/udp\"\n",
        );
        let got = published_in(text, "infra/x");
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].port, got[0].udp), (80, false));
        assert_eq!(
            (got[1].port, got[1].udp),
            (7700, false),
            "a ${{VAR:-addr:port}} default"
        );
        assert_eq!(
            (got[2].port, got[2].udp),
            (7710, true),
            "udp is read off the container half"
        );
    }

    /// **The collision that produced this gate.** A literal on one side, a substitution on
    /// the other, and the same host port underneath both.
    #[test]
    fn a_shared_host_port_is_visible_across_two_files() {
        let vault = published_in(
            "      - \"${KOTTON_VAULT_BIND:-0.0.0.0:7710}:7710/udp\"\n",
            "infra/vault",
        );
        let gateway = published_in("      - \"7710:7710/udp\"\n", "infra/gateway");
        assert_eq!(
            vault[0].key(),
            gateway[0].key(),
            "this is the bug, stated as a test"
        );
    }

    /// Same port, different protocol, is not a collision — UDP 7710 and TCP 7710 can both
    /// bind. Without this the gate would report a conflict that does not exist, and a gate
    /// that cries wolf gets switched off.
    #[test]
    fn the_same_number_on_two_protocols_does_not_collide() {
        let a = published_in("      - \"7710:7710/udp\"\n", "infra/a");
        let b = published_in("      - \"7710:7710\"\n", "infra/b");
        assert_ne!(a[0].key(), b[0].key());
    }

    /// The tree as it actually stands passes. This is the test that goes red the
    /// day somebody adds a fourth service and picks a port that is already taken.
    #[test]
    fn the_real_services_compose_onto_one_host() {
        let root = crate::out::root();
        let mut all: Vec<Published> = Vec::new();
        for dir in SERVICES {
            let text = std::fs::read_to_string(root.join(dir).join("docker-compose.yml"))
                .unwrap_or_else(|e| panic!("{dir}/docker-compose.yml: {e}"));
            all.extend(published_in(&text, dir));
        }
        assert!(
            !all.is_empty(),
            "no ports parsed — the gate would pass vacuously"
        );

        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert!(
                    a.key() != b.key() || a.service == b.service,
                    "{} is published by both the `{}` and `{}` services",
                    a.label(),
                    a.service,
                    b.service
                );
            }
        }
    }
}
