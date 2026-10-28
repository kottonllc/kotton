// SPDX-License-Identifier: AGPL-3.0-or-later
//! **What each device keeps of the person's drives** (kotton #55), on real
//! daemons: an in-process `kvaultd::Vault` as the drive, and two device
//! daemons of one person paired through the streamed ceremony.
//!
//! The finish line of Sprint 2 (kotton-dist #12): the second device keeps the
//! drive on demand and one folder whole; a file the first puts in that folder
//! lands on the second at its next pass, and a file put anywhere else lands
//! only as a name in the index, and is fetched when it is opened. Every
//! setting stays on the device that set it; what a device publishes is a
//! whole-keeper claim in the drive for each drive it keeps whole, which the
//! other device reads (kotton #171); the two notices — no device keeps the
//! drive whole, and a device short of room — are said in `status`, from the
//! claims.

use crate::common::{connect_when_ready, enroll_streamed_as, init_crypto};
use crate::vault::{enrol_vault_from, spawn_device, spawn_vault, RunningDevice, RunningVault};
use kotton_schemas::membership::Posture;
use kotton_wire::ipc::{PinNotice, PinScope, PinValue, FIRST_DRIVE_NAME};

const USER: &str = "alice";

/// `sync`, as the bare verb runs it: this device's drives, now.
async fn synced(client: &mut kotton::KottonClient, who: &str) -> kotton_wire::ipc::SyncOutcome {
    let (job, drives) = client.sync_drives(USER).await.unwrap_or_else(|e| panic!("{who}'s sync: {e}"));
    assert!(drives >= 1, "{who} syncs no drive");
    client.sync_await(USER, job, 120).await.unwrap_or_else(|e| panic!("{who}'s sync pass: {e}"))
}

/// Deterministic content, too entropic to share a chunk with anything.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed;
    while out.len() < len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// `line`, typed at the REPL of `device` as the person whose session `token`
/// is, and what it printed — the verb's own words, as a person reads them.
/// Each line is also written to the test's output, as the transcript.
async fn said(device: &RunningDevice, who: &str, token: &str, line: &str) -> String {
    use kotton_shell::ShellState;
    let mut client = kotton::KottonClient::connect_to(device.ipc.clone()).await.expect("a REPL connection");
    client.authenticate(token).await.expect("the REPL's identity");
    let mut state = ShellState::new(USER.to_string(), std::sync::Arc::new(tokio::sync::Mutex::new(client)));
    let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    let out = kotton_cli::bridge::repl_executor()
        .registry()
        .execute(&words[0], &words[1..], &mut state)
        .await
        .unwrap_or_else(|e| panic!("{who}$ {line}: {e}"));
    let mut text: String = out.out.iter().map(kotton_shell::out::render_shape).collect::<Vec<_>>().join("\n");
    for stream in [&out.stdout, &out.stderr].into_iter().flatten() {
        text.push('\n');
        text.push_str(stream);
    }
    let text = without_styling(&text);
    eprintln!("{who}$ {line}\n{text}\n");
    text
}

/// `text` with the terminal's colour codes taken out.
fn without_styling(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn pin(scope: &str) -> PinScope {
    PinScope::parse(scope).expect("a scope")
}

fn no_whole(notices: &[PinNotice]) -> bool {
    notices.iter().any(|n| matches!(n, PinNotice::NoWholeDevice { drive } if drive == FIRST_DRIVE_NAME))
}

/// A: alice's first device, which enrolled the drive; B: a device she pairs
/// after. Returns both, and B's node as A pairs it.
async fn alice_with_two_devices(
    vault: &RunningVault,
) -> (RunningDevice, kotton::KottonClient, RunningDevice, kotton::KottonClient, kotton_wire::peer::PairedNode) {
    let a = spawn_device("device A").await;
    let mut client_a = connect_when_ready(&a.ipc, "client A").await;
    client_a.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user on A");
    let (client_a, _drive) = enrol_vault_from(client_a, "device-a", vault, USER, "vault").await;
    let b = spawn_device("device B").await;
    let client_b = connect_when_ready(&b.ipc, "client B").await;
    let (client_a, client_b, node_b) =
        enroll_streamed_as(client_a, client_b, USER, "device-a", "device-b", Posture::Full).await;
    (a, client_a, b, client_b, node_b)
}

/// **Sprint 2's finish line.** B, paired later, keeps the drive on demand and
/// pins one folder whole. A file A puts in that folder is on B after B's next
/// pass, with no drive asked when B reads it; a file A puts elsewhere is on B
/// as a name in the index only, and is fetched from the drive when B opens
/// it. A reads the claims in the drive, B's settings being B's own: `drive
/// list` and `status` on A say that A keeps the drive whole and B does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_on_demand_keeps_the_folder_it_pins_whole_and_fetches_the_rest_on_open() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (a, mut client_a, b, mut client_b, _node_b) = alice_with_two_devices(&vault).await;

    // A paired later keeps every drive on demand; B says so, and pins a folder.
    let joined = client_b.pin_list(USER).await.expect("B's pins");
    assert_eq!(joined.default, PinValue::OnDemand, "a device paired later keeps drives on demand: {joined:?}");
    client_b.pin_set(USER, pin("default"), Some(PinValue::OnDemand)).await.expect("pin default on-demand");
    let pinned = client_b.pin_set(USER, pin("personal:/photos"), Some(PinValue::Whole)).await.expect("pin personal:/photos whole");
    assert_eq!(pinned.exceptions.len(), 1, "{pinned:?}");
    assert_eq!(pinned.exceptions[0].scope.said(), "personal:/photos");
    synced(&mut client_b, "B").await;

    // Two edits on A, made apart: two passes, two content packs.
    let photo = noise(256 * 1024, 1);
    client_a.write_file(USER, "/photos/trip.jpg", &photo).await.expect("write the photo on A");
    synced(&mut client_a, "A").await;
    client_a.write_file(USER, "/notes/todo.md", b"call the plumber").await.expect("write the note on A");
    synced(&mut client_a, "A").await;

    synced(&mut client_b, "B").await;
    assert!(b.daemon.kept_here(USER, "/photos/trip.jpg").await.unwrap(), "the photo did not land in the folder B pins whole");
    assert!(!b.daemon.kept_here(USER, "/notes/todo.md").await.unwrap(), "the note landed on B, which keeps it on demand");
    assert_eq!(client_b.read_file(USER, "/photos/trip.jpg").await.expect("read the photo on B"), photo);
    let named = client_b.list_files(USER, "/notes").await.expect("B lists /notes");
    assert!(format!("{named:?}").contains("todo.md"), "B's index does not name the note: {named:?}");
    assert_eq!(client_b.read_file(USER, "/notes/todo.md").await.expect("open the note on B"), b"call the plumber");
    assert!(b.daemon.kept_here(USER, "/notes/todo.md").await.unwrap(), "what B opened is not kept");

    // A reads the claims B's and A's passes carried to the drive; B's
    // settings stayed on B.
    synced(&mut client_a, "A").await;
    let drives = client_a.drive_list(USER).await.expect("A's drive list");
    let personal = drives.iter().find(|d| d.name == FIRST_DRIVE_NAME).expect("personal");
    assert_eq!(personal.pinned_whole, ["this device"], "A reads that B does not keep the drive whole: {personal:?}");
    let status = client_a.status(USER).await.expect("A's status");
    let held = status.drives.iter().find(|d| d.name == FIRST_DRIVE_NAME).expect("personal in A's status");
    assert_eq!((held.keeps, held.pinned_whole.clone()), (Some(PinValue::Whole), vec!["this device".to_string()]), "{status:?}");
    assert!(!no_whole(&status.notices), "A keeps the drive whole, and is told otherwise: {:?}", status.notices);
    let b_status = client_b.status(USER).await.expect("B's status");
    let b_held = b_status.drives.iter().find(|d| d.name == FIRST_DRIVE_NAME).expect("personal in B's status");
    assert_eq!(b_held.keeps, Some(PinValue::OnDemand));
    assert_eq!(b_held.pinned_whole.len(), 1, "B reads that A keeps the drive whole: {b_status:?}");
    assert_ne!(b_held.pinned_whole[0], "this device");
    let (token_a, token_b) = (
        client_a.session_token.clone().expect("A's session"),
        client_b.session_token.clone().expect("B's session"),
    );
    let pins = said(&b, "B", &token_b, "pin list").await;
    assert!(pins.contains("personal:/photos") && pins.contains("on-demand"), "{pins}");
    let status = said(&b, "B", &token_b, "status").await;
    assert!(status.contains("/photos whole") && status.contains("device-a"), "{status}");
    said(&a, "A", &token_a, "status").await;
}

/// **The two notices, said in `status`, from the claims each device
/// wrote.** A sets the drive on demand, withdrawing its claim: no device
/// keeps it whole, and A is
/// told at once and B at its next pass. B collects (`pin personal whole`):
/// the notice goes, and B holds a file it never opened. B, given less room
/// than the index and what it keeps whole, says so and names the setting
/// that keeps less. A revokes B: the last whole pin's device is removed, and
/// A is told again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_notices_are_said_in_status_from_the_claims_each_device_wrote() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (_a, mut client_a, b, mut client_b, node_b) = alice_with_two_devices(&vault).await;
    synced(&mut client_a, "A").await;
    synced(&mut client_b, "B").await;
    assert!(!no_whole(&client_b.status(USER).await.expect("B's status").notices), "A keeps the drive whole");

    // The last whole pin set on demand.
    let set = client_a.pin_set(USER, pin("personal"), Some(PinValue::OnDemand)).await.expect("pin personal on-demand on A");
    assert!(no_whole(&set.notices), "A is not told that no device keeps the drive whole: {set:?}");
    synced(&mut client_a, "A").await;
    synced(&mut client_b, "B").await;
    let told = client_b.status(USER).await.expect("B's status");
    assert!(no_whole(&told.notices), "B did not read that A withdrew its claim: {:?}", told.notices);
    let token_b = client_b.session_token.clone().expect("B's session");
    let shown = said(&b, "B", &token_b, "status").await;
    assert!(shown.contains("no device of yours keeps 'personal' whole"), "{shown}");

    // B collects: everything, on B, without opening it.
    client_a.write_file(USER, "/docs/plan.md", b"the plan").await.expect("write on A");
    synced(&mut client_a, "A").await;
    let collected = client_b.pin_set(USER, pin("personal"), Some(PinValue::Whole)).await.expect("pin personal whole on B");
    assert!(!no_whole(&collected.notices), "B keeps the drive whole, and is told nobody does: {collected:?}");
    // The pass the collect started may still be running; a `sync` asked for
    // meanwhile joins it rather than running a second, so B is asked until
    // the pass has landed.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while !b.daemon.kept_here(USER, "/docs/plan.md").await.unwrap() {
        assert!(std::time::Instant::now() < deadline, "collecting did not fetch what B lacked");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    synced(&mut client_b, "B").await;
    synced(&mut client_a, "A").await;
    assert!(!no_whole(&client_a.status(USER).await.expect("A's status").notices), "A did not read B's collect");

    // Room for one pack: B is short, and names the setting that keeps less.
    client_b
        .mount(USER, "vault", "/", "/", Some(kotton_store::pack::PACK_SIZE as u64), vec![])
        .await
        .expect("B's budget for the drive");
    synced(&mut client_b, "B").await;
    let short = client_b.status(USER).await.expect("B's status");
    let room = short.notices.iter().find_map(|n| match n {
        PinNotice::ShortOfRoom { settings, .. } => Some(settings.clone()),
        _ => None,
    });
    assert_eq!(room, Some(vec!["personal".to_string()]), "B is not told it is short, by setting: {:?}", short.notices);
    let shown = said(&b, "B", &token_b, "status").await;
    assert!(shown.contains("short of room for 'personal'") && shown.contains("`pin personal on-demand` keeps less"), "{shown}");

    // The device that keeps it whole is removed.
    client_a.node_revoke(USER, &node_b.id).await.expect("A revokes B");
    let after = client_a.status(USER).await.expect("A's status");
    assert!(no_whole(&after.notices), "B's removal did not tell A: {:?}", after.notices);
}

/// **A made drive is kept whole by no device yet, and `status` says so.** A
/// device keeps no tree of a drive `drive create` makes until drive paths
/// (kotton #58) give it one, so the creating device is not recorded as keeping
/// it whole: `drive create` says nobody keeps it, `status` on both devices
/// says only the vault holds it, and a pin for it is refused with a sentence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_made_drive_is_kept_whole_by_no_device_yet_and_status_says_so() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (a, mut client_a, _b, mut client_b, _node_b) = alice_with_two_devices(&vault).await;
    let made = client_a.drive_create(USER, "photos", None).await.expect("drive create on A");
    assert!(made[0].pinned_whole.is_empty(), "a device is said to keep a drive no device can keep yet: {made:?}");
    let photos_unkept = |notices: &[PinNotice]| notices.iter().any(|n| matches!(n, PinNotice::NoWholeDevice { drive } if drive == "photos"));
    assert!(photos_unkept(&client_a.status(USER).await.expect("A's status").notices), "A is not told only the vault holds photos");
    synced(&mut client_a, "A").await;
    synced(&mut client_b, "B").await;
    assert!(photos_unkept(&client_b.status(USER).await.expect("B's status").notices), "B is not told only the vault holds photos");
    let refused = client_a.pin_set(USER, pin("photos"), Some(PinValue::Whole)).await.expect_err("a pin for a made drive");
    assert!(refused.to_string().contains("keeps no tree of yet"), "{refused}");
    let refused = client_b.pin_set(USER, pin("nowhere:/x"), Some(PinValue::Whole)).await.expect_err("a pin for no drive");
    assert!(refused.to_string().contains("no drive called 'nowhere'"), "{refused}");
    let token_a = client_a.session_token.clone().expect("A's session");
    let shown = said(&a, "A", &token_a, "status").await;
    assert!(shown.contains("no device of yours keeps 'photos' whole") && shown.contains("nothing yet: its vault holds it"), "{shown}");
}

/// **A device publishes its claim and nothing else of its pins, and a claim
/// withdrawn in the second it was made reaches the other device** (kotton
/// #171's rules, on #158). B, on demand, pins a folder whole: A's record store
/// holds no pin setting of anyone's and one claim, A's own. B keeps the drive
/// whole, and A reads it; B flips on demand, whole and on demand again at
/// once, and A reads that B no longer does; whole, on demand and whole again
/// at once, and A reads that it does. Each withdrawal is a delete that
/// replicates, written in the same second as the write before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_publishes_only_its_claim_and_a_withdrawal_in_the_same_second_replicates() {
    init_crypto();
    let vault = spawn_vault("vault").await;
    let (_a, mut client_a, _b, mut client_b, _node_b) = alice_with_two_devices(&vault).await;
    synced(&mut client_a, "A").await;
    synced(&mut client_b, "B").await;
    client_b.pin_set(USER, pin("personal:/photos"), Some(PinValue::Whole)).await.expect("pin personal:/photos whole on B");
    synced(&mut client_b, "B").await;
    synced(&mut client_a, "A").await;
    let pins = client_a.record_query(USER, kotton_common::namespace::NSID_PIN, vec![], None, None).await.expect("A's pin records");
    assert!(pins.is_empty(), "a pin setting reached the drive: {pins:?}");
    let claims = client_a.record_query(USER, kotton_common::namespace::NSID_KEEPS_WHOLE, vec![], None, None).await.expect("A's claims");
    assert_eq!(claims.len(), 1, "B, keeping a folder and not the drive, claims it, or A does not: {claims:?}");

    // What A reads of who keeps the drive whole, once B's and A's passes
    // carry it: asked again until it reads `wanted`, because a `sync` asked
    // while the pass a `pin … whole` started is running joins that pass and
    // may answer before it lands (kotton #146). A claim or a withdrawal that
    // never replicates still fails, at the deadline.
    async fn carried(client_b: &mut kotton::KottonClient, client_a: &mut kotton::KottonClient, wanted: usize, what: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(240);
        loop {
            synced(client_b, "B").await;
            synced(client_a, "A").await;
            let drives = client_a.drive_list(USER).await.expect("A's drive list");
            let read = drives.into_iter().find(|d| d.name == FIRST_DRIVE_NAME).expect("personal").pinned_whole;
            if read.len() == wanted {
                assert!(read.contains(&"this device".to_string()), "{read:?}");
                return;
            }
            assert!(std::time::Instant::now() < deadline, "{what}: A reads {read:?}");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    async fn flip(client_b: &mut kotton::KottonClient, values: &[PinValue]) {
        for value in values {
            client_b.pin_set(USER, pin("personal"), Some(*value)).await.expect("pin personal on B");
        }
    }
    flip(&mut client_b, &[PinValue::Whole]).await;
    carried(&mut client_b, &mut client_a, 2, "A does not read that B keeps the drive whole").await;
    flip(&mut client_b, &[PinValue::OnDemand, PinValue::Whole, PinValue::OnDemand]).await;
    carried(&mut client_b, &mut client_a, 1, "B's withdrawal did not reach A").await;
    flip(&mut client_b, &[PinValue::Whole, PinValue::OnDemand, PinValue::Whole]).await;
    carried(&mut client_b, &mut client_a, 2, "B's claim made again did not reach A").await;
}
