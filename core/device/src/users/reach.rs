// SPDX-License-Identifier: AGPL-3.0-or-later
//! A person's own reach note: what their devices say about where they can be
//! reached, and when one of them re-signs it.
//!
//! The note lists every relay the person's devices hold reservations at, and
//! the person's device keys. It is signed by the identity's current key, kept
//! beside the person's members in their own store — one note, carried to every
//! device of theirs by the sync that carries the members — and re-signed when
//! what it would say changes or half its life has passed. Nobody sees it; the
//! pairing ceremony hands the first one over and the daemon's reach keeper
//! sends the rest.
//!
//! **Each device answers for its own relays** ([`relays_to_list`]): the relay it
//! is on and the one it is forwarding from, exactly as it holds
//! them. A relay the note lists that another of the person's devices put there
//! is kept as that device wrote it, so two devices on two relays both find the
//! note saying what each would say, and neither signs again — two devices on
//! different relays never re-sign one reach note against each other.

use crate::users::DeviceUsers as _;
use crate::DeviceRuntime;
use kotton_crypto::reach_note::{self, AdmitKey, ReachNote, RelayRef};
use kotton_peer::membership::Membership;
use kotton_schemas::membership::{same_relay_address, Member, Posture, Role};
use std::io;

/// The note `user_id` should be holding now, re-signed and kept first if the
/// one held no longer says it. Returns the note and whether it is new.
pub async fn current_note<S: Membership + ?Sized>(
    runtime: &DeviceRuntime,
    store: &S,
    user_id: &str,
    now: u64,
) -> io::Result<(ReachNote, bool)> {
    let did = runtime
        .user_aid(user_id)
        .ok_or_else(|| io::Error::other(format!("no identity for '{user_id}' on this device")))?;
    let key = kotton_peer::daemon::nodes::load_signing_key(user_id, runtime.secrets())?;
    // The key the log resolves to is the only key a contact believes; a device
    // holding a retired one signs nothing (the pairing ceremony refuses on the
    // same ground).
    if let Some(current) = runtime.user_current_key(user_id) {
        if current != key.verifying_key().to_bytes() {
            return Err(io::Error::other(
                "this device's identity key is not the one the key log resolves to — rotate or \
                 recover before signing where you can be reached",
            ));
        }
    }
    let members = store.list_members().await.map_err(io::Error::other)?;
    let devices = device_keys(runtime, &members);
    let others = OtherDevices::of(runtime, user_id, &members);
    let held = store.read_own_reach_note().await.map_err(io::Error::other)?;
    // Carried from only when the person's own key sealed it: the store is
    // theirs, but what sits at that path is bytes until the signature checks,
    // and a carried entry is re-signed under their key. A note that does not
    // verify — a stranger's, one with an entry that is not well formed, one
    // under a key the identity has retired, an expired one — carries nothing,
    // and this device signs from its own relays; the version still climbs
    // past it in `next`. Carrying an entry that fails `verify` would also fail
    // the next note, and every pass would sign again.
    let sealed = held
        .as_ref()
        .filter(|h| reach_note::verify(h, &key.verifying_key().to_bytes(), &did, now).is_ok());
    let relays = relays_to_list(sealed, relays_held(runtime, user_id, now), &others, now);
    match reach_note::next(held.as_ref(), &did, &relays, &devices, &key, now) {
        None => Ok((held.expect("next keeps only what is held"), false)),
        Some(note) => {
            store.write_own_reach_note(&note).await.map_err(io::Error::other)?;
            Ok((note, true))
        }
    }
}

/// The person's other devices that hold reservations of their own, as this
/// device knows them.
#[derive(Debug, Default)]
pub struct OtherDevices {
    /// Whether the person has one: an own device that holds their keys — *full*,
    /// or a member recorded before postures were — other than this device. A
    /// vault, a cosigner and a gateway sign no note and put no relay on one.
    pub any: bool,
    /// The relays those devices last told this device they reserve at
    /// (`RelayKeyring::told_relay`, learned from `NodeRelay` on every connect),
    /// by address. Empty for a device not reached since this one started.
    pub told: Vec<String>,
}

impl OtherDevices {
    /// Read from the person's members — the set every device of theirs holds —
    /// and what each of those devices last told this one.
    pub fn of(runtime: &DeviceRuntime, user_id: &str, members: &[Member]) -> Self {
        let this = runtime.device_signing_pubkey_bytes();
        let keys = runtime.reachability().relay_keys();
        let mut others = Self::default();
        for m in members.iter().filter(|m| {
            m.role == Role::OwnDevice
                && matches!(m.posture, None | Some(Posture::Full))
                && m.public_key != this
        }) {
            others.any = true;
            others.told.extend(keys.told_relay(user_id, &m.public_key));
        }
        others
    }
}

/// The relays the note should list: every relay this device holds (`mine`),
/// exactly as it holds them and first, then — when the person has another
/// device that holds relays of its own — every other relay the `held` note
/// lists, as the device that put it there wrote it.
///
/// `held` is a note that verified under the person's own identity key, and
/// nothing else ([`current_note`] passes `None` for one that did not). That is
/// what *as the device that put it there wrote it* rests on: every entry was
/// proved by one of the person's devices, which holds that key, and signed by
/// it; the note is the union of what their own devices proved, each entry
/// vouched for by the device that proved it, under one key.
///
/// **Each device answers for its own relays, and only for them.** That is what
/// makes it one note. This device knows its own relays whole: the one it is
/// forwarding from, the key each proved, the admission key it offers there. It
/// does not know another device's whole — `NodeRelay` names a device's current
/// relay and not the one it is forwarding from, the key beside it is held in
/// memory only, and a note can arrive by a sync the other device began, which
/// teaches this one nothing about where it reserves. A note built from this
/// device's knowledge of the other would say something different on each, and
/// each would sign it again at every pass. So a relay this device does not hold
/// is the business of the device that put it on the note: it adds its own when
/// they are missing, and this one carries them.
///
/// **A relay nobody holds any more leaves at the next renewal.** A device that
/// moved twice inside a forwarding window, or was removed, takes its relay off
/// nobody's list. When the held note is due for renewal ([`reach_note::renewal_due`])
/// a relay is carried only if one of the person's devices told this one it
/// reserves there; one that did not, but still holds it, adds it again at its
/// own next pass — one note more, and the version settles. Between renewals
/// nothing is dropped, so a pass with nothing changed signs nothing.
///
/// A person with no other device carries nothing: the note is this device's
/// relays, as it was before there could be another.
pub fn relays_to_list(
    held: Option<&ReachNote>,
    mine: Vec<RelayRef>,
    others: &OtherDevices,
    now: u64,
) -> Vec<RelayRef> {
    let mut list = mine;
    let Some(held) = held.filter(|_| others.any) else {
        return list;
    };
    let renewing = reach_note::renewal_due(held, now);
    for r in &held.relays {
        let answered = list.iter().any(|m| same_relay_address(&m.addr, &r.addr));
        let told = others.told.iter().any(|t| same_relay_address(t, &r.addr));
        if !answered && (!renewing || told) && list.len() < reach_note::MAX_RELAYS {
            list.push(r.clone());
        }
    }
    list
}

/// Every relay this device holds reservations at, most-preferred first: the
/// relay it is on, then the one it is forwarding from while that window is open.
/// Each carries the key its relay proved when this device learned it, where one
/// was shown.
///
/// A relay this person operates carries its *invited* key: the note is sealed to each contact, and a contact holding it is admitted
/// there under *the people I invite*. A relay this person is merely invited to
/// carries none — the keyring offers a key on only as its operator — so a
/// contact of a contact is never invited. Read for `user_id` alone: another
/// person on this machine who runs a relay offers nothing on this one's note. A rotation changes the key, so the
/// note differs and is signed again and handed to every contact.
pub fn relays_held(runtime: &DeviceRuntime, user_id: &str, now: u64) -> Vec<RelayRef> {
    let nat = runtime.reachability().nat();
    let keys = runtime.reachability().relay_keys();
    // Each relay with the key it proved when this device learned it, so a
    // contact's card
    // names the relay by its key and holds the address as a hint.
    std::iter::once((nat.relay_url.as_str(), nat.relay_key.clone()))
        .chain(nat.forwarding_relay(now as i64).map(|u| (u, nat.relay_key_previous.clone())))
        .map(|(u, key)| (u.trim(), key))
        .filter(|(u, _)| !u.is_empty())
        .map(|(addr, key)| RelayRef {
            addr: addr.to_string(),
            // Offered on only under the relay's key: a relay recorded with
            // none has no slot in the keyring, and its note carries no key.
            admit: kotton_peer::relay_keys::relay_id(key.as_deref())
                .and_then(|r| keys.offer_for(user_id, &r))
                .map(|k| AdmitKey(k.to_text())),
            key,
        })
        .collect()
}

/// This device's key and every own device in the person's membership set, hex,
/// sorted so the same set always reads the same.
fn device_keys(runtime: &DeviceRuntime, members: &[Member]) -> Vec<String> {
    let mut keys: Vec<String> = members
        .iter()
        .filter(|m| m.role == Role::OwnDevice)
        .map(|m| hex::encode(m.public_key))
        .chain(std::iter::once(hex::encode(runtime.device_signing_pubkey_bytes())))
        .collect();
    keys.sort();
    keys.dedup();
    keys.truncate(reach_note::MAX_DEVICES);
    keys
}

#[cfg(test)]
mod tests {
    //! A relay has a key of its own and proves it, on the device: the key a relay proves where the device learns it is recorded
    //! beside the URL, and the person's reach note carries it.

    use super::*;
    use crate::config::{db as device_config_db, ops, RuntimeConfig};
    use ed25519_dalek::{Signer as _, SigningKey};
    use kotton_wire::rendezvous::{identity_signing_input, RelayIdentity};
    use sqlx::SqlitePool;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A relay that proves `sk` to whoever asks, at a loopback address.
    async fn relay_proving(sk: SigningKey) -> String {
        relay_at(std::sync::Arc::new(std::sync::Mutex::new(Some(sk)))).await
    }

    /// A relay at one loopback address that proves whichever key `who` holds
    /// when asked — so a stand-in can take the address — and, holding none,
    /// hangs up without answering, as a relay that is down does.
    async fn relay_at(who: std::sync::Arc<std::sync::Mutex<Option<SigningKey>>>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                let Some(sk) = who.lock().unwrap().clone() else { continue };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let nonce = req
                        .split_once("nonce=")
                        .and_then(|(_, r)| r.split([' ', '&']).next())
                        .and_then(|h| hex::decode(h).ok())
                        .unwrap_or_default();
                    let body = serde_json::to_string(&RelayIdentity {
                        key: hex::encode(sk.verifying_key().as_bytes()),
                        addr: String::new(),
                        sig: hex::encode(sk.sign(&identity_signing_input(&nonce, "")).to_bytes()),
                    })
                    .unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        url
    }

    /// An address where nothing answers.
    fn silent_url() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    }

    async fn device_config() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE device_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    /// Clause 3: what every learning point does — ask the relay, record the key
    /// it proved beside the URL (`config relay set`, a relay paired by name, an
    /// invite's relay at `drive enrol` each call exactly these two). Leaving it
    /// moves its key beside it into the forwarding slot; a relay that showed no
    /// key is recorded with none, never with the key of the relay before it.
    #[tokio::test]
    async fn a_relay_learned_is_recorded_with_the_key_it_proved_and_leaving_it_moves_the_key() {
        let db = device_config().await;
        let relay = SigningKey::from_bytes(&[1u8; 32]);
        let first = relay_proving(relay.clone()).await;

        let key = ops::learn_relay_key(&first).await.unwrap();
        assert_eq!(key.as_deref(), Some(hex::encode(relay.verifying_key().as_bytes())).as_deref());
        ops::set_coord_url(&db, None, Some(&first), key.as_deref()).await.unwrap();
        let nat = device_config_db::load_nat_config(&db).await.unwrap();
        assert_eq!(nat.relay_url, first);
        assert_eq!(nat.relay_key, key, "the key is recorded beside the URL");

        // The person moves to a relay that shows nothing.
        let second = silent_url();
        let none = ops::learn_relay_key(&second).await.unwrap();
        assert_eq!(none, None, "a relay that does not answer shows no key");
        ops::set_coord_url(&db, Some(&first), Some(&second), none.as_deref()).await.unwrap();
        let nat = device_config_db::load_nat_config(&db).await.unwrap();
        assert_eq!(nat.relay_key, None, "the new relay is not given the old relay's key");
        assert_eq!(nat.relay_url_previous, first);
        assert_eq!(nat.relay_key_previous, key, "the left relay keeps its key beside it");

        // Clearing the relay leaves no key standing for nothing.
        ops::set_coord_url(&db, Some(&second), None, key.as_deref()).await.unwrap();
        assert_eq!(device_config_db::load_nat_config(&db).await.unwrap().relay_key, None);
    }

    /// **Re-stating the relay the device holds is not first sight.** Treated as
    /// first sight, `config relay set <the url it holds>` and a relay paired by
    /// name again would overwrite the recorded key with whatever answered. At [`ops::name_relay`], the one function both verbs call: a
    /// stand-in at the recorded address is refused and the row is unchanged; the
    /// relay down, the recorded key is kept; the relay itself, it is kept; and
    /// clearing then setting is the one way to forget it.
    #[tokio::test]
    async fn re_stating_the_relay_held_expects_its_recorded_key() {
        let db = device_config().await;
        let relay = SigningKey::from_bytes(&[1u8; 32]);
        let stand_in = SigningKey::from_bytes(&[9u8; 32]);
        let who = std::sync::Arc::new(std::sync::Mutex::new(Some(relay.clone())));
        let url = relay_at(who.clone()).await;
        let recorded = Some(hex::encode(relay.verifying_key().as_bytes()));

        assert_eq!(ops::name_relay(&db, None, Some(&url)).await.unwrap(), recorded, "first sight records the key");

        *who.lock().unwrap() = Some(stand_in.clone());
        let err = ops::name_relay(&db, Some(&url), Some(&url)).await.expect_err("a stand-in is refused");
        assert!(err.to_string().contains(&hex::encode(relay.verifying_key().as_bytes())), "naming the key expected: {err}");
        let nat = device_config_db::load_nat_config(&db).await.unwrap();
        assert_eq!((nat.relay_url.as_str(), nat.relay_key.clone()), (url.as_str(), recorded.clone()), "and the row is unchanged");

        *who.lock().unwrap() = None;
        assert_eq!(ops::name_relay(&db, Some(&url), Some(&url)).await.unwrap(), recorded, "a silent relay keeps its key");
        // The lower half keeps it too: an unchanged URL is never written with no key.
        ops::set_coord_url(&db, Some(&url), Some(&url), None).await.unwrap();
        assert_eq!(device_config_db::load_nat_config(&db).await.unwrap().relay_key, recorded);

        *who.lock().unwrap() = Some(relay.clone());
        assert_eq!(ops::name_relay(&db, Some(&url), Some(&url)).await.unwrap(), recorded, "the relay itself is kept");

        // Forgetting is two steps: clear, then set — first sight again.
        *who.lock().unwrap() = Some(stand_in.clone());
        assert_eq!(ops::name_relay(&db, Some(&url), None).await.unwrap(), None);
        assert_eq!(
            ops::name_relay(&db, None, Some(&url)).await.unwrap(),
            Some(hex::encode(stand_in.verifying_key().as_bytes())),
            "after a clear, the relay at the address is met anew"
        );
    }

    /// A reach note re-signed after the key
    /// was recorded carries it — for the relay the device is on and the one it is
    /// forwarding from — so a contact's card holds the relay by its key.
    #[tokio::test]
    async fn a_reach_note_re_signed_after_this_carries_the_key() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            RuntimeConfig::default(),
            std::sync::Arc::new(kotton_secret::MemorySecrets::new()),
        )
        .await
        .unwrap();
        let now = 1_900_000_000u64;
        let identity = SigningKey::from_bytes(&[9u8; 32]);
        let did = "did:keri:Etest";
        let devices = vec![hex::encode([2u8; 32])];

        // Before: the relay recorded with no key, and the note that says so.
        runtime
            .reconfigure_network(kotton_peer::nat::NatNetworkConfig {
                relay_url: "https://relay.one".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let before = relays_held(&runtime, "u", now);
        assert_eq!(before[0].key, None);
        let held = reach_note::next(None, did, &before, &devices, &identity, now).unwrap();

        // After: the relay's key recorded, and a relay being forwarded from with its own.
        let key = hex::encode([7u8; 32]);
        let previous = hex::encode([8u8; 32]);
        runtime
            .reconfigure_network(kotton_peer::nat::NatNetworkConfig {
                relay_url: "https://relay.one".into(),
                relay_key: Some(key.clone()),
                relay_url_previous: "https://relay.zero".into(),
                relay_url_previous_until: now as i64 + 60,
                relay_key_previous: Some(previous.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        let after = relays_held(&runtime, "u", now);
        let note = reach_note::next(Some(&held), did, &after, &devices, &identity, now + 1)
            .expect("a note that no longer says it is signed again");
        assert_eq!(
            note.relays.iter().map(|r| (r.addr.as_str(), r.key.clone())).collect::<Vec<_>>(),
            [("https://relay.one", Some(key)), ("https://relay.zero", Some(previous))]
        );
        reach_note::verify(&note, &identity.verifying_key().to_bytes(), did, now + 1)
            .expect("and the key is inside the signature");
    }

    // ── One note for a person's devices on different relays ─────────────────
    // Neither re-signs it against the other.

    const USER: &str = "u";
    const DID: &str = "did:keri:Etest";

    /// The person's synced store, as both of their devices see it once the sync
    /// has run: one set of members, one `/network/reach-note`.
    #[derive(Default)]
    struct Synced(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl kotton_peer::membership::MemberStore for Synced {
        async fn member_write(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        async fn member_read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.0.lock().unwrap().get(path).cloned().ok_or_else(|| anyhow::anyhow!("nothing at {path}"))
        }
        async fn member_delete(&self, path: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn member_list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            Ok(self.0.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect())
        }
    }

    /// One of the person's devices: its own device key, the person's identity
    /// key, and `nat` as where it reserves.
    async fn device_of(dir: &std::path::Path, identity: &SigningKey, nat: kotton_peer::nat::NatNetworkConfig) -> DeviceRuntime {
        use kotton_sys::secret::SecretsStore as _;
        let secrets = std::sync::Arc::new(kotton_secret::MemorySecrets::new());
        secrets
            .set_secret(
                &kotton_common::crypto::kdf_labels::identity_signing_key(USER),
                &hex::encode(identity.to_bytes()),
            )
            .unwrap();
        let runtime = DeviceRuntime::new_with_secrets(dir.to_path_buf(), RuntimeConfig::default(), secrets).await.unwrap();
        let now = std::time::SystemTime::now();
        crate::registry::save_users(
            &dir.join("system"),
            &crate::registry::UsersRegistry {
                users: vec![crate::registry::UserRecord {
                    user_id: USER.into(),
                    did: DID.into(),
                    did_method: "key".into(),
                    aliases: vec![],
                    created_at: now,
                    last_active: now,
                    versions: Default::default(),
                }],
            },
        )
        .unwrap();
        runtime.reconfigure_network(nat).await.unwrap();
        runtime
    }

    fn on(relay: &str, key: u8) -> kotton_peer::nat::NatNetworkConfig {
        kotton_peer::nat::NatNetworkConfig {
            relay_url: relay.into(),
            relay_key: Some(hex::encode([key; 32])),
            ..Default::default()
        }
    }

    /// `device` as a member of the person's set, as enrolment writes it.
    fn member(device: &DeviceRuntime, name: &str, posture: Option<Posture>) -> Member {
        Member {
            did: format!("did:key:{name}"),
            public_key: device.device_signing_pubkey_bytes(),
            role: Role::OwnDevice,
            admitted_by: kotton_schemas::membership::Ceremony::DeviceEnroll,
            added_at: "2026-10-07T00:00:00Z".into(),
            posture,
            label: Some(name.into()),
            reach: None,
        }
    }

    /// What `note` lists, by address and the key beside it, in no order.
    fn listed(note: &ReachNote) -> std::collections::BTreeSet<(String, Option<String>)> {
        note.relays.iter().map(|r| (r.addr.clone(), r.key.clone())).collect()
    }

    fn at(relay: &str, key: u8) -> (String, Option<String>) {
        (relay.to_string(), Some(hex::encode([key; 32])))
    }

    /// **Two devices of one identity on two relays hold one note that
    /// lists both, and a pass on either with nothing changed signs nothing.**
    ///
    /// The laptop reserves at one relay and the desktop at another; both hold
    /// the person's keys and one synced store. Each signs at most once, to put
    /// its own relay on the note, and then four passes on each — eight in all,
    /// alternating, as two keepers on two machines would run them — leave the
    /// version where it was, listing both relays with their keys. Neither
    /// device has been told where the other reserves: what holds the note still
    /// is each answering for its own relays and carrying the other's, not
    /// anything learned in memory, which a restart empties.
    #[tokio::test]
    async fn two_devices_on_two_relays_hold_one_note_listing_both_and_its_version_stays_put() {
        let identity = SigningKey::from_bytes(&[9u8; 32]);
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let laptop = device_of(da.path(), &identity, on("https://relay.one", 1)).await;
        let desktop = device_of(db.path(), &identity, on("https://relay.two", 2)).await;
        let store = Synced::default();
        store.write_member(&member(&laptop, "laptop", Some(Posture::Full))).await.unwrap();
        store.write_member(&member(&desktop, "desktop", None)).await.unwrap();
        let now = 1_900_000_000u64;

        // Each puts its own relay on the note, once.
        let (first, signed) = current_note(&laptop, &store, USER, now).await.unwrap();
        assert!(signed, "nothing held: the laptop signs");
        let (settled, signed) = current_note(&desktop, &store, USER, now + 1).await.unwrap();
        assert!(signed, "the note lacks the desktop's relay: the desktop adds it");
        assert!(settled.version > first.version);
        assert_eq!(listed(&settled), [at("https://relay.one", 1), at("https://relay.two", 2)].into());
        reach_note::verify(&settled, &identity.verifying_key().to_bytes(), DID, now + 1).expect("signed by the person");

        for pass in 1..=4u64 {
            for (name, device) in [("laptop", &laptop), ("desktop", &desktop)] {
                let (note, signed) = current_note(device, &store, USER, now + pass * 600).await.unwrap();
                assert!(!signed, "pass {pass} on the {name} signed a note with nothing changed: {note:?}");
                assert_eq!(note.version, settled.version, "pass {pass} on the {name} moved the version");
                assert_eq!(listed(&note), listed(&settled), "pass {pass} on the {name}");
            }
        }
    }

    /// **A move is followed once, and a renewal keeps what the other device
    /// told and drops what nobody holds.**
    ///
    /// The desktop moves to a third relay and forwards from the one it left: it
    /// signs once, listing all three, and the laptop — which knows nothing of
    /// the forwarding — carries it and signs nothing. When the forwarding window
    /// closes, nothing is signed for that alone. At the renewal, on the laptop,
    /// the relay the desktop told the laptop it reserves at is kept and the one
    /// it left is dropped; the desktop then finds its relay on the note and
    /// signs nothing either.
    #[tokio::test]
    async fn a_move_is_followed_once_and_a_renewal_drops_only_the_relay_nobody_holds() {
        let identity = SigningKey::from_bytes(&[9u8; 32]);
        let third_key = SigningKey::from_bytes(&[3u8; 32]);
        let third = relay_proving(third_key.clone()).await;
        let third_id = third_key.verifying_key().to_bytes();
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let laptop = device_of(da.path(), &identity, on("https://relay.one", 1)).await;
        let desktop = device_of(db.path(), &identity, on("https://relay.two", 2)).await;
        let store = Synced::default();
        store.write_member(&member(&laptop, "laptop", Some(Posture::Full))).await.unwrap();
        store.write_member(&member(&desktop, "desktop", Some(Posture::Full))).await.unwrap();
        let now = 1_900_000_000u64;
        current_note(&laptop, &store, USER, now).await.unwrap();
        current_note(&desktop, &store, USER, now).await.unwrap();

        // The desktop moves, forwarding from the relay it left for a day.
        let until = now + 24 * 60 * 60;
        desktop
            .reconfigure_network(kotton_peer::nat::NatNetworkConfig {
                relay_url: third.clone(),
                relay_key: Some(hex::encode(third_id)),
                relay_url_previous: "https://relay.two".into(),
                relay_url_previous_until: until as i64,
                relay_key_previous: Some(hex::encode([2u8; 32])),
                ..Default::default()
            })
            .await
            .unwrap();
        let (moved, signed) = current_note(&desktop, &store, USER, now + 60).await.unwrap();
        assert!(signed, "the desktop's new relay is not on the note");
        let three = [at("https://relay.one", 1), at("https://relay.two", 2), (third.clone(), Some(hex::encode(third_id)))];
        assert_eq!(listed(&moved), three.clone().into());
        for t in [now + 120, now + 600, until + 60, until + 3600] {
            for (name, device) in [("laptop", &laptop), ("desktop", &desktop)] {
                let (note, signed) = current_note(device, &store, USER, t).await.unwrap();
                assert!(!signed && note.version == moved.version, "the {name} signed again at {t}: {note:?}");
            }
        }

        // The laptop connects to the desktop and is told where it reserves.
        let desktop_node = kotton_wire::peer::PairedNode {
            id: "desktop".into(),
            device_did: kotton_wire::did::Did::new("key", "desktop"),
            public_key: desktop.device_signing_pubkey_bytes(),
            paired_at: 0,
            addresses: vec![],
            relay_url: Some(third.clone()),
            posture: Some("full".into()),
        };
        assert!(laptop.reachability().relay_keys().learn_proven(USER, &desktop_node, &third, &third_id, None).await);

        // Past half the note's life: the laptop renews.
        let renew = moved.expires_at - reach_note::REACH_NOTE_TTL_SECS / 2 + 1;
        let (renewed, signed) = current_note(&laptop, &store, USER, renew).await.unwrap();
        assert!(signed, "a note past half its life is renewed");
        assert_eq!(
            listed(&renewed),
            [at("https://relay.one", 1), (third.clone(), Some(hex::encode(third_id)))].into(),
            "the relay the desktop told is kept and the one nobody holds is gone"
        );
        let (after, signed) = current_note(&desktop, &store, USER, renew + 60).await.unwrap();
        assert!(!signed && after.version == renewed.version, "the desktop finds its relay and signs nothing: {after:?}");
    }

    /// **A person with one device lists its relays and nothing else**, as the
    /// note did before a second device could put one there. A vault is a
    /// device of theirs that signs no note and reserves for nobody's note, so
    /// with one beside the device a relay the held note lists and this device
    /// does not hold is dropped at once, not carried.
    #[tokio::test]
    async fn a_person_with_one_device_lists_its_relays_and_nothing_else() {
        let identity = SigningKey::from_bytes(&[9u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let desktop = device_of(dir.path(), &identity, on("https://relay.one", 1)).await;
        let store = Synced::default();
        store.write_member(&member(&desktop, "desktop", Some(Posture::Full))).await.unwrap();
        let mut vault = member(&desktop, "vault", Some(Posture::BlindStorage));
        vault.public_key = [4u8; 32];
        store.write_member(&vault).await.unwrap();
        let now = 1_900_000_000u64;

        let left = reach_note::sign(
            DID,
            vec![RelayRef { key: Some(hex::encode([1u8; 32])), addr: "https://relay.one".into(), admit: None },
                 RelayRef { key: None, addr: "https://relay.left".into(), admit: None }],
            vec![],
            now - 60,
            now + reach_note::REACH_NOTE_TTL_SECS,
            &identity,
        );
        store.write_own_reach_note(&left).await.unwrap();
        let (note, signed) = current_note(&desktop, &store, USER, now).await.unwrap();
        assert!(signed, "the held note names a relay this device does not hold");
        assert_eq!(listed(&note), [at("https://relay.one", 1)].into());
        let (again, signed) = current_note(&desktop, &store, USER, now + 600).await.unwrap();
        assert!(!signed && again.version == note.version);
    }

    /// Two full devices of the person, on two relays, sharing one store with
    /// `planted` already held at `/network/reach-note`.
    async fn two_devices_holding(
        planted: &ReachNote,
        da: &std::path::Path,
        db: &std::path::Path,
        identity: &SigningKey,
    ) -> (DeviceRuntime, DeviceRuntime, Synced) {
        let laptop = device_of(da, identity, on("https://relay.one", 1)).await;
        let desktop = device_of(db, identity, on("https://relay.two", 2)).await;
        let store = Synced::default();
        store.write_member(&member(&laptop, "laptop", Some(Posture::Full))).await.unwrap();
        store.write_member(&member(&desktop, "desktop", Some(Posture::Full))).await.unwrap();
        store.write_own_reach_note(planted).await.unwrap();
        (laptop, desktop, store)
    }

    /// **Only what the person's own key sealed is carried.** A note at
    /// `/network/reach-note` signed by a stranger's key, listing a relay with a
    /// well-formed key of the stranger's choosing, is treated as no note: the
    /// laptop signs its own relay, the desktop adds its own, and the stranger's
    /// relay is on neither note — never re-signed under the person's key.
    #[tokio::test]
    async fn a_held_note_a_stranger_signed_carries_nothing() {
        let identity = SigningKey::from_bytes(&[9u8; 32]);
        let stranger = SigningKey::from_bytes(&[66u8; 32]);
        let now = 1_900_000_000u64;
        let planted = reach_note::sign(
            DID,
            vec![RelayRef { key: Some(hex::encode([0xeeu8; 32])), addr: "https://relay.evil".into(), admit: None }],
            vec![],
            now - 60,
            now + reach_note::REACH_NOTE_TTL_SECS,
            &stranger,
        );
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (laptop, desktop, store) = two_devices_holding(&planted, da.path(), db.path(), &identity).await;

        let (first, signed) = current_note(&laptop, &store, USER, now).await.unwrap();
        assert!(signed, "a note this person did not sign is replaced");
        assert_eq!(listed(&first), [at("https://relay.one", 1)].into(), "nothing of the stranger's is carried");
        assert!(first.version > planted.version, "and the version still climbs past what was held");
        let (settled, _) = current_note(&desktop, &store, USER, now + 1).await.unwrap();
        assert_eq!(listed(&settled), [at("https://relay.one", 1), at("https://relay.two", 2)].into());
        for pass in 1..=3u64 {
            for device in [&laptop, &desktop] {
                let (note, signed) = current_note(device, &store, USER, now + pass * 600).await.unwrap();
                assert!(!signed && note.version == settled.version, "pass {pass}: {note:?}");
            }
        }
    }

    /// **A held note that does not verify is signed over once, not at every
    /// pass.** The person's own key signed it, but one entry's admission key is
    /// not a key, so it fails `verify`. Carrying that entry would put it in the
    /// next note too, which would fail again, and each pass would hand every
    /// contact a new version. It is dropped: one re-signing, then the version
    /// holds.
    #[tokio::test]
    async fn a_held_note_with_a_malformed_entry_is_re_signed_once_and_then_holds() {
        let identity = SigningKey::from_bytes(&[9u8; 32]);
        let now = 1_900_000_000u64;
        let planted = reach_note::sign(
            DID,
            vec![
                RelayRef { key: Some(hex::encode([1u8; 32])), addr: "https://relay.one".into(), admit: None },
                RelayRef { key: None, addr: "https://relay.bent".into(), admit: Some(AdmitKey("not a key".into())) },
            ],
            vec![],
            now - 60,
            now + reach_note::REACH_NOTE_TTL_SECS,
            &identity,
        );
        assert!(reach_note::verify(&planted, &identity.verifying_key().to_bytes(), DID, now).is_err());
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (laptop, desktop, store) = two_devices_holding(&planted, da.path(), db.path(), &identity).await;

        let (first, signed) = current_note(&laptop, &store, USER, now).await.unwrap();
        assert!(signed, "a note that does not verify is signed over");
        assert_eq!(listed(&first), [at("https://relay.one", 1)].into(), "the malformed entry is not carried");
        let (settled, _) = current_note(&desktop, &store, USER, now + 1).await.unwrap();
        for pass in 1..=3u64 {
            for device in [&laptop, &desktop] {
                let (note, signed) = current_note(device, &store, USER, now + pass * 600).await.unwrap();
                assert!(!signed && note.version == settled.version, "pass {pass} moved the version: {note:?}");
            }
        }
    }
}
