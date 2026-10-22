// SPDX-License-Identifier: AGPL-3.0-or-later
//! This device's *Operators*, spoken to `kdeviced` from each person's own daemon
//! under a key that is theirs alone
//! (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`).
//!
//! One machine, as `kdeviced` runs it: two people with accounts on one base
//! directory, a `kdeviced` over that base, and one daemon per person — each
//! built for its principal, as `kdeviced` spawns them (RFC-0063). Every act is
//! driven through the occupant host the designated shell calls, and read back
//! from `kdeviced`'s own `operator_acts`.
//!
//! Unix only: the machine stood up here is sockets in a base directory, and
//! a Windows machine's `kdeviced` is a named pipe this harness does not stand
//! up yet.
#![cfg(unix)]

use std::sync::Arc;

use kotton_app::daemon::apps::OccupantHost;
use kotton_device::config::db::RelayChoice;
use kotton_sys::ipc::IpcEndpoint;
use kuserd::agent::Supervision;
use kuserd::DeviceDaemon;

use crate::common::{TestEnv, TEST_PASSPHRASE};

/// A daemon for one person on `env`'s machine, as `kdeviced` would spawn it:
/// the same base and keychain, its own socket, its principal named, and
/// `kdeviced` where the test put it.
async fn daemon_for(env: &TestEnv, principal: &str, kdeviced: &IpcEndpoint) -> DeviceDaemon {
    DeviceDaemon::new_supervised(
        env.base_dir.clone(),
        env.door(&format!("kuserd-{}.sock", uuid::Uuid::new_v4().simple())),
        Arc::clone(&env.secrets),
        RelayChoice::None,
        Supervision {
            principal: Some(principal.to_owned()),
            kdeviced: Some(kdeviced.clone()),
        },
    )
    .await
    .expect("a person's daemon")
}

/// A desk that answers every prompt with `typed`, standing where `kuid` would:
/// on the daemon's end of the pair. Read as JSON, never as a `KuidRequest`, for
/// `channel-check`'s one-acceptor rule — as the landlord's drop test stands one.
async fn a_desk_typing(daemon: &DeviceDaemon, typed: &'static str) -> Arc<std::sync::Mutex<Vec<serde_json::Value>>> {
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (kuid_read, daemon_write) = tokio::io::duplex(64 * 1024);
    let (daemon_read, mut kuid_write) = tokio::io::duplex(64 * 1024);
    let seen = Arc::clone(&asked);
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;
        let mut kuid_read = kuid_read;
        loop {
            let mut len = [0u8; 4];
            if kuid_read.read_exact(&mut len).await.is_err() {
                break;
            }
            let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
            if kuid_read.read_exact(&mut body).await.is_err() {
                break;
            }
            let reply = kotton_wire::FromCompositor::Response(kotton_wire::KuidResponse::SurfaceOk);
            if kotton_ipc::write_frame(&mut kuid_write, &reply).await.is_err() {
                break;
            }
            let frame: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            if let Some(id) = frame["PromptRaise"]["id"].as_u64() {
                seen.lock().unwrap().push(frame["PromptRaise"]["prompt"].clone());
                let answer = kotton_wire::CompositorEvent::PromptAnswered { id, typed: Some(typed.into()) };
                if kotton_ipc::write_frame(&mut kuid_write, &kotton_wire::FromCompositor::Event(answer)).await.is_err() {
                    break;
                }
            }
        }
    });
    daemon.desk().attach(daemon_write, daemon_read).await;
    asked
}

/// **Austin makes Ana an operator and removes her again, each from his own
/// desk, and `kdeviced` keeps both acts under Austin's own key** — the
/// Done-when's test.
///
/// - Each person's daemon speaks with a key minted into their own sealed store:
///   Austin's is the machine's first, and answers for Austin; Ana's is proved
///   and kept as hers, standing for nothing, until Austin names *her*.
/// - *Operators* reads as the board draws it: Austin, *You*; Ana offered by
///   *Add an operator…*; and to Ana, before she is one, nobody.
/// - The add names Ana, never a key, and binds the key Ana's daemon proved.
/// - The removal is asked on the platform's prompt and happens only on Ana's
///   name typed back; with no desk it does not happen at all. The last
///   operator is refused before anything is asked.
/// - Both acts are in `operator_acts` under the key that answers for Austin,
///   which is neither Ana's nor any key but the one in Austin's store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_adds_and_removes_a_person_through_the_occupant_host_under_their_own_key() {
    let mut env = TestEnv::spawn_without_relay().await;
    let (austin_did, _) = env.client.create_user("austin", TEST_PASSPHRASE).await.expect("austin");
    let (ana_did, _) = env.client.create_user("ana", TEST_PASSPHRASE).await.expect("ana");

    // This machine's kdeviced, over the same base and at the door `env`'s own
    // daemon was told. It spawns a kuserd per account at boot; the binary named
    // here does not exist, so it spawns none, and the daemons below stand in
    // for them.
    let kd_endpoint = env.kdeviced.clone();
    let kdeviced = kdeviced::system::SystemDaemon::with_base(
        kd_endpoint.clone(),
        env.base_dir.clone(),
        env.base_dir.join("no-kuserd-here"),
    );
    tokio::spawn(kdeviced.run());
    for _ in 0..200 {
        if kd_endpoint_ready(&kd_endpoint) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    let at_austin = daemon_for(&env, &austin_did, &kd_endpoint).await;
    let at_ana = daemon_for(&env, &ana_did, &kd_endpoint).await;
    at_austin
        .occupant_host()
        .unlock_with_pin("austin", TEST_PASSPHRASE)
        .await
        .expect("austin unlocks at his desk");

    // Austin's key is the machine's first, and answers for him. Read before
    // Ana unlocks, so which of two first keys the empty machine took is not a
    // race this test runs.
    let austin_box = OccupantHost::operators(&at_austin.occupant_host()).await.expect("austin reads");
    at_ana
        .occupant_host()
        .unlock_with_pin("ana", TEST_PASSPHRASE)
        .await
        .expect("ana unlocks at hers");
    assert!(austin_box.operates, "{austin_box:?}");
    assert_eq!(austin_box.operators.len(), 1, "{austin_box:?}");
    assert!(austin_box.operators[0].you && austin_box.operators[0].name == "austin", "{austin_box:?}");
    let ana_handle = austin_box
        .others
        .iter()
        .find(|p| p.name == "ana")
        .unwrap_or_else(|| panic!("Add an operator… offers Ana: {austin_box:?}"))
        .person
        .clone();

    // Ana is not an operator: she is told so and shown nobody — and her key is
    // now kept as hers.
    let ana_box = OccupantHost::operators(&at_ana.occupant_host()).await.expect("ana reads");
    assert!(!ana_box.operates && ana_box.operators.is_empty() && ana_box.others.is_empty(), "{ana_box:?}");
    let removed_before_she_was_one = OccupantHost::operator_remove(&at_ana.occupant_host(), ana_handle.clone()).await;
    assert!(removed_before_she_was_one.is_err(), "a person who is not an operator removes nobody");

    // *Make Ana an operator* — by Ana, never by a key.
    OccupantHost::operator_add(&at_austin.occupant_host(), ana_handle.clone())
        .await
        .expect("Austin makes Ana an operator");
    let two = OccupantHost::operators(&at_austin.occupant_host()).await.expect("austin reads");
    let mut rows: Vec<(&str, bool)> = two.operators.iter().map(|o| (o.name.as_str(), o.you)).collect();
    rows.sort();
    assert_eq!(rows, [("ana", false), ("austin", true)], "{two:?}");
    assert!(two.others.is_empty(), "{two:?}");
    let as_ana = OccupantHost::operators(&at_ana.occupant_host()).await.expect("ana reads");
    assert!(as_ana.operates, "Ana's own key now stands: {as_ana:?}");
    assert!(as_ana.operators.iter().any(|o| o.name == "ana" && o.you), "{as_ana:?}");

    // Removing her is asked on the platform's prompt. With no desk, nothing.
    let refused = OccupantHost::operator_remove(&at_austin.occupant_host(), ana_handle.clone())
        .await
        .expect_err("a removal no one was asked about");
    assert_eq!(refused, kuserd::surface_proxy::NO_DESK);
    assert!(OccupantHost::operators(&at_ana.occupant_host()).await.unwrap().operates, "Ana was removed unasked");
    // A name typed back wrong removes nobody.
    let asked = a_desk_typing(&at_austin, "Ana").await;
    let wrong = OccupantHost::operator_remove(&at_austin.occupant_host(), ana_handle.clone()).await;
    assert!(wrong.is_err(), "Ana is not ana: {wrong:?}");
    assert_eq!(asked.lock().unwrap().last().unwrap()["RemoveOperator"]["name"], "ana");
    assert!(OccupantHost::operators(&at_ana.occupant_host()).await.unwrap().operates);

    let asked = a_desk_typing(&at_austin, "ana").await;
    OccupantHost::operator_remove(&at_austin.occupant_host(), ana_handle.clone())
        .await
        .expect("Austin removes Ana on her name typed back");
    assert_eq!(asked.lock().unwrap().len(), 1, "asked once: {:?}", asked.lock().unwrap());
    assert!(!OccupantHost::operators(&at_ana.occupant_host()).await.unwrap().operates, "Ana is no longer one");

    // The last is refused before the desk is asked anything.
    let asked = a_desk_typing(&at_austin, "austin").await;
    let austin_handle = OccupantHost::operators(&at_austin.occupant_host()).await.unwrap().operators[0].person.clone();
    let last = OccupantHost::operator_remove(&at_austin.occupant_host(), austin_handle)
        .await
        .expect_err("the last operator is never removed");
    assert!(last.contains("last"), "{last}");
    assert!(asked.lock().unwrap().is_empty(), "the desk was asked about the last operator");

    // **Each act is in kdeviced's `operator_acts`, under Austin's own key.**
    let db = kdeviced::db::operators_db::open(&env.base_dir.join("system").join("device.db"))
        .await
        .expect("device.db");
    let operators = kdeviced::db::operators_db::list(&db).await.unwrap();
    let austins: Vec<&str> = operators
        .iter()
        .filter(|o| o.person.as_deref() == Some(austin_did.as_str()))
        .map(|o| o.did.as_str())
        .collect();
    assert_eq!(austins.len(), 1, "Austin holds one key here, his own: {operators:?}");
    let austins_key = austins[0];
    assert!(austins_key.starts_with("did:key:") && austins_key != austin_did, "{austins_key}");
    // And it is the key kept sealed in Austin's own store — not his identity's,
    // not the machine's.
    let austins_store = at_austin.users().get("austin").expect("austin is resident at his desk");
    let seed = kotton_store::runtime::private::read(&austins_store, "device-operator")
        .expect("austin's private objects open")
        .expect("austin's own operator key is kept in his store");
    let seed: [u8; 32] = seed.as_slice().try_into().expect("a 32-byte seed");
    let kept = kotton_crypto::DidKeyMethod::from_public_key(&ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
        .to_string();
    assert_eq!(kept, austins_key, "the key kdeviced keeps for Austin is the one in his sealed store");
    let acts = kdeviced::db::operators_db::acts(&db).await.unwrap();
    let add = acts
        .iter()
        .find(|a| a.act == "OperatorAdd" && a.ok)
        .unwrap_or_else(|| panic!("no add kept: {acts:?}"));
    assert_eq!(add.did, austins_key, "the add is kept under Austin's own key: {acts:?}");
    assert_eq!(add.subject, ana_did, "and names Ana, not a key");
    let remove = acts
        .iter()
        .find(|a| a.act == "SudoersRemove" && a.ok)
        .unwrap_or_else(|| panic!("no removal kept: {acts:?}"));
    assert_eq!(remove.did, austins_key, "the removal is kept under Austin's own key: {acts:?}");
    assert_eq!(remove.subject, ana_did);
    // Neither act, nor any other, was taken under the machine keychain's shared
    // operator key: nothing here ever minted it.
    let machine_key = env
        .secrets
        .get_secret(&kotton_common::crypto::kdf_labels::device_operator_key())
        .unwrap();
    assert!(machine_key.is_none(), "the shared machine key was minted");
    drop(env);
}

fn kd_endpoint_ready(at: &IpcEndpoint) -> bool {
    matches!(at, IpcEndpoint::UnixSocket(path) if path.exists())
}

/// Whether `user`'s own operator key has been minted into their sealed store on
/// `daemon` — the first thing `device_operator::keep` does, before it dials.
fn holds_an_operator_key(daemon: &DeviceDaemon, user: &str) -> bool {
    let store = daemon.users().get(user).expect("the person is resident");
    kotton_store::runtime::private::read(&store, "device-operator")
        .expect("their private objects open")
        .is_some()
}

/// **Only a daemon told its supervisor reaches for `kdeviced` when a person
/// unlocks** (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`,
/// the assessor's ground of 2026-09-25).
///
/// A daemon told neither a principal nor a `kdeviced` socket would otherwise
/// dial the machine's own `kdeviced`, and on a machine whose `kdeviced` has
/// nobody enrolled, its key would become the first operator. The unlock's
/// `keep` mints the person's key before it dials, so a key minted is the trace
/// of a reach: unlocked at a daemon told nothing, none is minted; unlocked at
/// one told a `kdeviced` socket (here, one nobody listens on), one is.
/// Deleting the `supervised` filter in `open_session` turns the first half red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unlock_reaches_for_kdeviced_only_at_a_daemon_told_its_supervisor() {
    let mut env = TestEnv::spawn_without_relay().await;
    env.client.create_user("austin", TEST_PASSPHRASE).await.expect("austin");

    // Told neither: no principal, no kdeviced.
    let untold = DeviceDaemon::new_supervised(
        env.base_dir.clone(),
        env.door(&format!("kuserd-{}.sock", uuid::Uuid::new_v4().simple())),
        Arc::clone(&env.secrets),
        RelayChoice::None,
        Supervision::default(),
    )
    .await
    .expect("an unsupervised daemon");
    untold.occupant_host().unlock_with_pin("austin", TEST_PASSPHRASE).await.expect("austin unlocks");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!holds_an_operator_key(&untold, "austin"), "an unsupervised unlock reached for kdeviced");

    // Told a kdeviced (nobody listening): the unlock reaches, and mints first.
    let told = DeviceDaemon::new_supervised(
        env.base_dir.clone(),
        env.door(&format!("kuserd-{}.sock", uuid::Uuid::new_v4().simple())),
        Arc::clone(&env.secrets),
        RelayChoice::None,
        Supervision { principal: None, kdeviced: Some(env.door("nobody.sock")) },
    )
    .await
    .expect("a daemon told its kdeviced");
    told.occupant_host().unlock_with_pin("austin", TEST_PASSPHRASE).await.expect("austin unlocks");
    let mut minted = false;
    for _ in 0..100 {
        if holds_an_operator_key(&told, "austin") {
            minted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(minted, "a daemon told its kdeviced did not reach for it at unlock");
    drop(env);
}
