// SPDX-License-Identifier: AGPL-3.0-or-later
//! The occupant's network readout — the **read-only** projection behind
//! `interface network`, by which the shell reads the relay and the vaults.
//!
//! ## Why this is a projection and not a pool
//!
//! The relay's address, the bind scope and this machine's name are
//! `device_config` keys in `system/device.db`. That file is **kdeviced's** —
//! device configuration lives there because configuring the machine is device
//! authority — and `interface devices` says in its own words that handing the
//! guest-facing occupant host that pool "is the twenty-line fix and the wrong
//! one", because kuserd opens the file only while the device verbs still run
//! here.
//!
//! Read is not write. Disclosing to the *designated shell* what the person's
//! own device is already paired with adds no authority to any guest. So
//! [`MachineReadout`] is what the occupant host holds instead of the pool: its
//! fields are private to this module, it answers two questions, and there is no
//! setter on it for a guard to have to refuse (`CLAUDE.md`, the second design
//! test).
//!
//! ## Two of the three `device_config` keys were never the right source
//!
//! Three keys in that pool could answer — the relay URL, the bind scope and
//! the device's name. Reading the code says two of them have a better
//! source than the configured value, and the fourth row below is a fact that
//! was never a key at all:
//!
//! | fact | source | why not `device_config` |
//! |---|---|---|
//! | the relay's address | [`Reachability::nat`] | the live config, which a runtime `relay set` has already reached |
//! | whether it answered | [`Reachability::relay_readout`] | a reservation is a live control socket, so *held* is *reachable* |
//! | local reach | [`Reachability::peer_listen_addr`] | where the listener **bound**, not the scope that was asked for |
//! | this device's name | `device_config` | the person set it; there is nowhere else it lives |
//!
//! So exactly one key crosses this seam, and [`MachineReadout::device_name`]
//! is the whole of it.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use kotton_store::runtime::roots::Target;
use kotton_wire::ipc::{RelayReadout, RelayState};
use kotton_wire::peer::PairedNode;
use kotton_wire::runner::{RunnerRelay, RunnerRoot, RunnerVault};
use sqlx::SqlitePool;

/// `device_config` key holding this machine's human name.
///
/// The same constant `handlers::device_config` writes through, spelled again
/// rather than shared because sharing it would mean this module importing the
/// module that *sets* it — and the one property this file has is that it
/// cannot set anything.
const DEVICE_NAME_KEY: &str = "device-name";

/// What the machine will state about itself to a guest that may only read.
///
/// Two questions and no setters. The pool and the connected-peer set behind
/// them are private fields of this module, so `occupant_host.rs` — which is the
/// guest-facing host — can call these two methods and reach neither.
pub(crate) struct MachineReadout {
    /// kdeviced's file. Private, and read through exactly one key below.
    device_db: Arc<SqlitePool>,
    /// The DIDs `ksyncd` last reported a live connection to (`VfsReport`).
    connected: Arc<RwLock<HashSet<String>>>,
}

impl MachineReadout {
    pub(crate) fn new(device_db: Arc<SqlitePool>, connected: Arc<RwLock<HashSet<String>>>) -> Self {
        Self {
            device_db,
            connected,
        }
    }

    /// The name this device answers to, **read without writing**.
    ///
    /// `kotton_device::config::ops::resolve_device_name` is the other reader of
    /// this key and it persists the hostname it falls back to. That write is
    /// right where it is — a name a person can then edit has to exist first —
    /// and wrong here: a readout that writes to kdeviced's file on being looked
    /// at is the thing this projection exists to make impossible.
    pub(crate) async fn device_name(&self) -> String {
        if let Ok(Some(name)) =
            kotton_device::config::db::get_key(self.device_db.as_ref(), DEVICE_NAME_KEY).await
        {
            let name = name.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "this device".to_string())
    }

    /// Whether this device has a live connection to `did` right now.
    pub(crate) fn is_connected(&self, did: &str) -> bool {
        self.connected
            .read()
            .map(|set| set.contains(did))
            .unwrap_or(false)
    }
}

/// The name a relay is reached by: its address without the scheme.
///
/// A relay is reached by name, so the name is the row's identity and there is
/// no handle to show beside it. The port stays — two relays on one host are two
/// relays, and dropping it would render them as one row twice.
pub(crate) fn relay_name(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let no_path = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    no_path.trim().to_string()
}

/// The relay row, or `None` when no relay is named.
///
/// `relays_for` counts this device — only while it holds a live reservation
/// there, because a device the relay is not carrying right now is not carried —
/// plus the paired devices that have **said** they reserve there
/// (`paired_nodes.relay_url`, learned from the peer on every successful
/// connect). A device that has never been asked is not counted: a readout
/// that guesses high tells a person their fleet is carried when half of it may
/// not be. Enrolled vaults are excluded — they reserve at the relay too, and
/// they are not devices.
pub(crate) fn relay_row(
    relay_url: &str,
    readout: RelayReadout,
    nodes: &[PairedNode],
    vault_handles: &HashSet<String>,
) -> Option<RunnerRelay> {
    let name = relay_name(relay_url);
    if name.is_empty() {
        return None;
    }
    let peers = nodes
        .iter()
        .filter(|n| !vault_handles.contains(&n.device_did.to_string()))
        .filter(|n| {
            n.relay_url
                .as_deref()
                .is_some_and(|u| relay_name(u) == name)
        })
        .count() as u32;
    Some(RunnerRelay {
        name,
        reachable: matches!(readout.state, RelayState::Up),
        // This device counts only while the relay is actually holding a
        // reservation for it; a relay that is down carries for nobody here.
        relays_for: peers.saturating_add(u32::from(readout.reservations_live > 0)),
    })
}

/// What a vault holds, in the person's words.
///
/// *everything* when every root the person can name is kept there, the roots
/// they chose otherwise, and *nothing yet* for a vault no root targets — which
/// is a real state, not an impossible one: a vault is enrolled device-wide and
/// a root may be moved off it afterwards.
///
/// The roots here are the ones a guest may be handed, which excludes the core
/// root — core is the index's home rather than a place a person chose to
/// keep somewhere, so counting it would make *everything* unreachable.
pub(crate) fn holds_in_words(handle: &str, roots: &[RunnerRoot]) -> String {
    let kept: Vec<&str> = roots
        .iter()
        .filter(|r| r.targets.iter().any(|t| t.handle == handle))
        .map(|r| r.name.as_str())
        .collect();
    if kept.is_empty() {
        return "nothing yet".to_string();
    }
    if kept.len() == roots.len() {
        return "everything".to_string();
    }
    kept.join(", ")
}

/// The part of a kept vault's operator credential the readout reads: which
/// vault and the name it was minted under — and, from this desktop's record of
/// what it told that vault (`agent::operator`'s *stands at*), the first relay it
/// stands at: the address as a hint and the relay's key. Never the key it is
/// spoken under.
pub(crate) struct Operated {
    pub vault: [u8; 32],
    pub name: String,
    pub relay: Option<String>,
    pub relay_key: Option<[u8; 32]>,
    /// When this desktop told it, Unix seconds; `None` when it told it nothing.
    pub told_at: Option<u64>,
}

/// The part of a kept relay's operator credential the readout reads: its name
/// and the key it proved — what a vault's row is matched to it by; never its URL.
pub(crate) struct OperatedRelay {
    pub name: String,
    pub key: Option<[u8; 32]>,
}

/// One card per relay this person runs, in the order the credentials were
/// kept: its
/// name, its key, its address, and *Standing at it* — every node of the
/// person's this desktop told to stand there, matched by the relay's key and
/// never its URL: each vault whose dated record names it, by the vault's
/// name, and this device (`this_device`, by name) when the relay it reserves
/// at proved that key. Nothing is dialled.
pub(crate) fn operated_relay_rows(
    relays: &[(String, Option<[u8; 32]>, String)],
    vaults: &[Operated],
    told: &dyn Fn(&[u8; 32]) -> Vec<[u8; 32]>,
    this_device: Option<(&str, [u8; 32])>,
) -> Vec<kotton_wire::runner::RunnerOperatedRelay> {
    relays
        .iter()
        .map(|(name, key, address)| {
            let mut standing: Vec<String> = match key {
                Some(k) => vaults.iter().filter(|v| told(&v.vault).contains(k)).map(|v| v.name.clone()).collect(),
                None => Vec::new(),
            };
            let here = matches!((this_device, key), (Some((_, at)), Some(k)) if at == *k);
            if let (true, Some((device, _))) = (here, this_device) {
                standing.push(device.to_string());
            }
            kotton_wire::runner::RunnerOperatedRelay {
                name: name.clone(),
                key: key.map(hex::encode),
                address: address.clone(),
                standing,
                here,
            }
        })
        .collect()
}

/// One row per enrolled vault, in handle order, then one per vault of the
/// person's own that they keep nothing at.
///
/// Every field is read from what this device already holds; nothing here dials
/// anything. `operated` is the vaults whose operator credential this person
/// keeps (`agent::operator::held`): an enrolled vault among them is the
/// person's own, and its row says *yours*; one among them this person has not
/// enrolled is listed too, as *yours* and holding nothing of theirs — the
/// landlord's own vault is theirs whether or not they keep anything on it.
/// `relays` is the relays they operate: a row whose relay URL is one of theirs
/// names it, so its rule can be read and set by that relay's own name. The two
/// capacity numbers are `None` because a device learns them
/// only from the vault's own `VaultCapacity` answer and nothing records that
/// answer yet. `None` is
/// the honest reading: the capacity of a vault nobody has asked is not zero.
pub(crate) fn vault_rows(
    enrolled: &[Target],
    nodes: &[PairedNode],
    roots: &[RunnerRoot],
    connected: &dyn Fn(&str) -> bool,
    operated: &[Operated],
    relays: &[OperatedRelay],
) -> Vec<RunnerVault> {
    let operated: Vec<(String, &Operated)> = operated
        .iter()
        .filter_map(|o| {
            kotton_crypto::DidKeyMethod::from_public_key_bytes(&o.vault)
                .ok()
                .map(|d| (d.to_string(), o))
        })
        .collect();
    let mine = |handle: &str| operated.iter().find(|(did, _)| did == handle).map(|(_, o)| *o);
    let relay_named = |key: Option<[u8; 32]>| {
        let key = key?;
        relays.iter().find(|r| r.key == Some(key)).map(|r| r.name.clone())
    };
    let mut rows: Vec<RunnerVault> = enrolled
        .iter()
        .map(|t| {
            let learned = nodes
                .iter()
                .find(|n| n.device_did.to_string() == t.handle)
                .and_then(|n| n.relay_url.as_deref());
            RunnerVault {
                label: t.label.clone(),
                through: learned.map(relay_name).filter(|n| !n.is_empty()),
                holds: holds_in_words(&t.handle, roots),
                held_bytes: None,
                bought_bytes: None,
                answering: connected(&t.handle),
                yours: mine(&t.handle).is_some(),
                vault_name: mine(&t.handle).map(|o| o.name.clone()),
                // The relay this person operates for it: the one this desktop
                // told it to stand at, by that relay's key.
                relay_name: relay_named(mine(&t.handle).and_then(|o| o.relay_key)),
                stands_at: mine(&t.handle).and_then(|o| o.relay.clone()),
                told_at: mine(&t.handle).and_then(|o| o.told_at),
            }
        })
        .collect();
    for (did, o) in &operated {
        if enrolled.iter().any(|t| &t.handle == did) {
            continue;
        }
        rows.push(RunnerVault {
            label: Some(o.name.clone()),
            through: o.relay.as_deref().map(relay_name).filter(|n| !n.is_empty()),
            holds: "nothing of yours".to_string(),
            held_bytes: None,
            bought_bytes: None,
            answering: connected(did),
            yours: true,
            vault_name: Some(o.name.clone()),
            relay_name: relay_named(o.relay_key),
            stands_at: o.relay.clone(),
            told_at: o.told_at,
        });
    }
    rows
}

/// Whether a peer on the same network can reach this device directly.
///
/// Read from where the peer listener **bound**, not from the bind scope that
/// was configured: a scope that was asked for and refused is exactly the case a
/// person would be misled by. An unspecified address (`0.0.0.0`) is a wide bind
/// and answers yes; a loopback bind, or no listener at all, answers no.
pub(crate) fn local_reach(bound: Option<std::net::SocketAddr>) -> bool {
    bound.is_some_and(|a| !a.ip().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_wire::runner::{RunnerRootMember, RunnerRootTarget};

    /// The DID the fixtures below use for the vault, as a `did:key` string.
    const VAULT: &str = "did:key:z6MkVaultDroplet";
    /// And for the person's other device.
    const PHONE: &str = "did:key:z6MkPhone";

    fn node(did: &str, relay: Option<&str>) -> PairedNode {
        PairedNode {
            id: "a-label".to_owned(),
            device_did: kotton_wire::did::Did::parse(did).expect("a did:key parses"),
            public_key: [0u8; 32],
            paired_at: 1_755_648_000,
            addresses: Vec::new(),
            relay_url: relay.map(str::to_owned),
            posture: None,
        }
    }

    fn root(name: &str, targets: &[&str]) -> RunnerRoot {
        RunnerRoot {
            id: name.to_lowercase(),
            name: name.to_owned(),
            members: vec![RunnerRootMember {
                aid: "did:kel:zMe".to_owned(),
                is_you: true,
            }],
            targets: targets
                .iter()
                .map(|h| RunnerRootTarget {
                    handle: (*h).to_owned(),
                    label: None,
                })
                .collect(),
            residency: kotton_wire::runner::RunnerResidency::Full,
            kept: kotton_wire::runner::RunnerKeeping::Replicated,
            tree_path: String::new(),
            granted: false,
            writable: false,
        }
    }

    /// **A paired relay and an enrolled vault read out whole.**
    ///
    /// The state: a relay this device is paired with, one
    /// other device that says it reserves there, and one vault enrolled
    /// through it. Every field of all three readouts is asserted, because the
    /// shape was right for as long as the readout returned nothing.
    #[test]
    fn a_paired_relay_and_an_enrolled_vault_read_out_whole() {
        let relay_url = "http://droplet.austin.dev:7700";
        let nodes = vec![node(PHONE, Some(relay_url)), node(VAULT, Some(relay_url))];
        let enrolled = vec![Target::new(
            VAULT,
            Some("Vault \u{00b7} droplet".to_owned()),
        )];
        let handles: HashSet<String> = enrolled.iter().map(|t| t.handle.clone()).collect();
        let roots = vec![root("Personal", &[VAULT])];

        let relay = relay_row(
            relay_url,
            RelayReadout {
                state: RelayState::Up,
                reservations_wanted: 2,
                reservations_live: 2,
            },
            &nodes,
            &handles,
        )
        .expect("a relay is named, so there is a row");
        assert_eq!(relay.name, "droplet.austin.dev:7700");
        assert!(relay.reachable);
        // This device plus the phone. **Not three**: the vault reserves there
        // too and is not a device.
        assert_eq!(relay.relays_for, 2);

        let vaults = vault_rows(&enrolled, &nodes, &roots, &|did| did == VAULT, &[], &[]);
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].label.as_deref(), Some("Vault \u{00b7} droplet"));
        assert_eq!(
            vaults[0].through.as_deref(),
            Some("droplet.austin.dev:7700")
        );
        assert_eq!(vaults[0].holds, "everything");
        assert!(vaults[0].answering);
        // Unknown, not zero: nothing on a device records what a vault said
        // about capacity yet.
        assert_eq!(vaults[0].held_bytes, None);
        assert_eq!(vaults[0].bought_bytes, None);
        // No operator credential is kept, so no vault is the person's own.
        assert!(!vaults[0].yours);

        // And this device's own half, which needs no store at all.
        assert!(local_reach(Some("0.0.0.0:4433".parse().expect("an addr"))));
        assert!(!local_reach(Some(
            "127.0.0.1:4433".parse().expect("an addr")
        )));
        assert!(!local_reach(None));
    }

    /// **A vault whose operator credential this person keeps is theirs**, and
    /// one beside it on somebody else's machine is not. The match
    /// is the credential's vault key against the enrolled vault's DID, so a
    /// credential for one vault never marks another. A relay they operate is
    /// named on the row of the vault this desktop told to stand at it, matched
    /// by the relay's key and never its URL.
    #[test]
    fn a_vault_the_person_operates_is_listed_as_theirs_and_names_their_relay_by_its_key() {
        let own = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key().to_bytes();
        let other = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]).verifying_key().to_bytes();
        let did = |k: &[u8; 32]| kotton_crypto::DidKeyMethod::from_public_key_bytes(k).unwrap().to_string();
        let enrolled = vec![
            Target::new(did(&own), Some("droplet".to_owned())),
            Target::new(did(&other), Some("a friend's".to_owned())),
        ];
        let rows = vault_rows(
            &enrolled,
            &[],
            &[],
            &|_| false,
            &[Operated {
                vault: own,
                name: "kotton".to_owned(),
                relay: Some("http://droplet.example.org:7700".to_owned()),
                relay_key: Some([1u8; 32]),
                told_at: Some(1_790_000_000),
            }],
            &[OperatedRelay {
                name: "gate".to_owned(),
                key: Some([1u8; 32]),
            }],
        );
        let yours: Vec<(Option<&str>, bool)> = rows.iter().map(|r| (r.label.as_deref(), r.yours)).collect();
        assert_eq!(yours, vec![(Some("droplet"), true), (Some("a friend's"), false)]);
        // And the row that is yours names the vault its landlord's verbs are
        // spoken to — the credential's name, not the enrolment's label — while
        // the one that is not names none;
        // and the relay by its own name, matched by its key, not by the vault's.
        let names: Vec<(Option<&str>, Option<&str>)> =
            rows.iter().map(|r| (r.vault_name.as_deref(), r.relay_name.as_deref())).collect();
        assert_eq!(names, vec![(Some("kotton"), Some("gate")), (None, None)]);

        // A vault of the person's own that they keep nothing at is still
        // theirs, listed by the name it was given, holding nothing of theirs;
        // and a relay under another key is named on no row.
        let third = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        let rows = vault_rows(
            &enrolled,
            &[],
            &[],
            &|_| false,
            &[Operated {
                vault: third,
                name: "attic".to_owned(),
                relay: Some("http://attic.example.org:7700".to_owned()),
                relay_key: Some([2u8; 32]),
                told_at: None,
            }],
            &[OperatedRelay {
                name: "gate".to_owned(),
                key: Some([1u8; 32]),
            }],
        );
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert!(!rows[0].yours && !rows[1].yours, "neither enrolled vault is the attic");
        assert_eq!(rows[2].label.as_deref(), Some("attic"));
        assert_eq!(rows[2].through.as_deref(), Some("attic.example.org:7700"));
        assert_eq!(rows[2].holds, "nothing of yours");
        assert!(rows[2].yours);
        assert_eq!(rows[2].vault_name.as_deref(), Some("attic"));
        assert!(rows.iter().all(|r| r.relay_name.is_none()), "{rows:?}");
        assert!(rows[0].vault_name.is_none() && rows[1].vault_name.is_none());
    }

    /// **A relay's card is its key, its address, and who stands at it; a
    /// vault's row says where it stands and since when.** The two
    /// vaults told to stand at `gate` by key are listed under it and the one
    /// told of `attic` is not; this device is listed under the relay whose key
    /// its own relay proved, and under no other; a relay that showed no key
    /// has nobody standing at it, since nothing can be told to. A vault's row
    /// carries the address it was told and the date.
    #[test]
    fn a_relays_card_lists_who_stands_at_it_by_key_and_a_vault_says_where_it_stands() {
        let (gate, attic) = ([1u8; 32], [2u8; 32]);
        let vault = |n: u8, name: &str, at: Option<[u8; 32]>| Operated {
            vault: ed25519_dalek::SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes(),
            name: name.to_owned(),
            relay: at.map(|_| "http://203.0.113.9:7700".to_owned()),
            relay_key: at,
            told_at: at.map(|_| 1_790_000_000),
        };
        let vaults = [vault(10, "kotton", Some(gate)), vault(11, "den", Some(gate)), vault(12, "cellar", Some(attic))];
        let told = |v: &[u8; 32]| vaults.iter().find(|o| &o.vault == v).and_then(|o| o.relay_key).into_iter().collect();
        let relays = vec![
            ("gate".to_owned(), Some(gate), "http://203.0.113.9:7700".to_owned()),
            ("attic".to_owned(), Some(attic), "http://198.51.100.4:7700".to_owned()),
            ("old".to_owned(), None, "http://192.0.2.1:7700".to_owned()),
        ];
        let rows = operated_relay_rows(&relays, &vaults, &told, Some(("PC", gate)));
        assert_eq!(rows.iter().map(|r| r.here).collect::<Vec<_>>(), vec![true, false, false], "here by key");
        let read: Vec<(&str, Option<&str>, &str, Vec<&str>)> = rows
            .iter()
            .map(|r| (r.name.as_str(), r.key.as_deref(), r.address.as_str(), r.standing.iter().map(String::as_str).collect()))
            .collect();
        let (g, a) = (hex::encode(gate), hex::encode(attic));
        assert_eq!(
            read,
            vec![
                ("gate", Some(g.as_str()), "http://203.0.113.9:7700", vec!["kotton", "den", "PC"]),
                ("attic", Some(a.as_str()), "http://198.51.100.4:7700", vec!["cellar"]),
                ("old", None, "http://192.0.2.1:7700", vec![]),
            ]
        );

        let rows = vault_rows(&[], &[], &[], &|_| false, &vaults[..1], &[]);
        assert_eq!(rows[0].stands_at.as_deref(), Some("http://203.0.113.9:7700"));
        assert_eq!(rows[0].told_at, Some(1_790_000_000));
        let untold = vault_rows(&[], &[], &[], &|_| false, &[vault(13, "new", None)], &[]);
        assert_eq!((untold[0].stands_at.as_deref(), untold[0].told_at), (None, None));
    }

    /// **No relay named is no row**, which is not the same fact as a row that
    /// could not be read — the surface renders the two differently.
    #[test]
    fn an_unnamed_relay_has_no_row() {
        assert!(relay_row("", RelayReadout::NONE, &[], &HashSet::new()).is_none());
        assert!(relay_row("   ", RelayReadout::NONE, &[], &HashSet::new()).is_none());
    }

    /// **A device that has not said where it reserves is not counted.**
    ///
    /// `paired_nodes.relay_url` is learned from the peer on a successful
    /// connect, so `None` is *never asked*. Counting it would
    /// tell a person their fleet is carried when half of it may not be.
    #[test]
    fn a_device_that_never_said_where_it_reserves_is_not_counted() {
        let url = "http://droplet.austin.dev:7700";
        let relay = relay_row(
            url,
            RelayReadout {
                state: RelayState::Down,
                reservations_wanted: 2,
                reservations_live: 0,
            },
            &[node(PHONE, None)],
            &HashSet::new(),
        )
        .expect("a row");
        // The phone never said where it reserves, and this device holds no live
        // reservation at a relay that is down: carried for nobody, and said so.
        assert_eq!(relay.relays_for, 0);
        assert!(!relay.reachable);
    }

    /// **What a vault holds is *everything*, the roots chosen, or nothing yet.**
    ///
    /// Three answers and not two: a vault no root targets is a real state — a
    /// vault is enrolled device-wide and a root can be moved off it afterwards
    /// — and calling that *everything* or leaving it blank both lie.
    #[test]
    fn what_a_vault_holds_is_everything_or_the_roots_chosen_or_nothing_yet() {
        let personal = root("Personal", &[VAULT]);
        let work = root("Work", &[]);
        assert_eq!(
            holds_in_words(VAULT, std::slice::from_ref(&personal)),
            "everything"
        );
        assert_eq!(
            holds_in_words(VAULT, &[personal.clone(), work.clone()]),
            "Personal"
        );
        assert_eq!(holds_in_words(VAULT, &[work]), "nothing yet");
        // And with no roots at all, which is what a device that cannot open the
        // sealed index answers.
        assert_eq!(holds_in_words(VAULT, &[]), "nothing yet");
    }

    /// **A relay is named by its address without the scheme, and keeps its port.**
    ///
    /// Two relays on one host are two relays; dropping the port would draw them
    /// as one row twice.
    #[test]
    fn a_relay_is_named_by_its_address_without_the_scheme() {
        assert_eq!(
            relay_name("http://droplet.austin.dev:7700"),
            "droplet.austin.dev:7700"
        );
        assert_eq!(relay_name("https://relay.example/path"), "relay.example");
        assert_eq!(relay_name("droplet.austin.dev"), "droplet.austin.dev");
        assert_eq!(relay_name(""), "");
    }
}
