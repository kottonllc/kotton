// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — the project's records in a root its org owns (RFC-0088, phase one;
//! `TASK-the-project-records-are-imported-into-a-root`).
//!
//! Through the verbs a person actually reaches, against a real daemon:
//!
//!  - the project root is created under the org's identity, and the person is a member of it
//!    and is not its owner;
//!  - inviting runs under `org.invite` on the root, issued by its owner, and is refused
//!    without it;
//!  - import and export run as the converter's principal, under a grant on the schema, and
//!    are refused without one;
//!  - the ten-record fixture goes into the root and comes back byte for byte, and a second
//!    import changes no row.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::common::cli::{said, Cli};
use crate::common::TestEnv;
use kotton::{records_export, records_import, ImportReport, KottonClient, OrgRootDelegation};
use kotton_record_file::row::NSID;
use kotton_record_file::schema::{self, PRINCIPAL};

const ALICE: &str = "alice";

/// A person on their own daemon, with an org and the project root under it — what
/// `kotton org create` and `kotton records init` leave behind.
struct Project {
    env: TestEnv,
    /// Alice's identity DID (`did:key:…`), the one her org grants name her by — as her
    /// org's own row records her.
    did: String,
    /// Alice's AID (`did:kel:…`), the one a root's members hold.
    aid: String,
    org: String,
    root: String,
    delegation: OrgRootDelegation,
}

impl Project {
    fn client(&mut self) -> &mut KottonClient {
        &mut self.env.client
    }
}

async fn project() -> Project {
    project_on(TestEnv::spawn().await).await
}

/// [`project`], on a daemon whose apps run in the real `kotton-runner` — for the one test
/// that launches the records app itself.
async fn project_on(mut env: TestEnv) -> Project {
    env.client.create_user(ALICE, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let recovery = env.client.add_recovery_phrase(ALICE).await.expect("add_recovery_phrase");
    env.client
        .login_with_recovery_key(&recovery, Some(ALICE.to_string()), None)
        .await
        .expect("login");
    let aid = kotton_identity::kel_store::load_chain(&env.base_dir, ALICE)
        .expect("alice's chain")
        .into_iter()
        .next()
        .expect("an inception event")
        .aid
        .to_string();

    // `kotton records init`, step by step.
    let org = env.client.org_new(ALICE, "kotton").await.expect("org create");
    let (_, _, did, _) = env.client.org_show(ALICE, &org).await.expect("org show");
    assert!(did.starts_with("did:key:") && aid.starts_with("did:kel:"), "{did} / {aid}");
    env.client
        .schema_register(ALICE, &schema::definition().to_string())
        .await
        .expect("the record schema registers");
    let made = env.client.org_root_create(ALICE, &org, "kotton").await.expect("records init");
    env.client
        .schema_grant_set(PRINCIPAL, NSID, true, true, false)
        .await
        .expect("the converter is granted the schema");
    Project { env, did, aid, org, root: made.root, delegation: made.delegation }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/record-file/tests/fixtures/records")
}

/// Every `*.md` in `dir`, by name, as bytes.
fn files_in(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .map(|p| (p.file_name().unwrap().to_str().unwrap().to_owned(), std::fs::read(&p).unwrap()))
        .collect()
}

/// Each row's `updated_at`, by id, as the daemon holds it.
async fn stamps(client: &mut KottonClient) -> BTreeMap<String, i64> {
    client
        .record_search(ALICE, Some(NSID), None, Some(100_000))
        .await
        .expect("search the schema")
        .into_iter()
        .map(|r| (r["id"].as_str().unwrap().to_owned(), r["updated_at"].as_i64().unwrap()))
        .collect()
}

// ── ownership ─────────────────────────────────────────────────────────────────

/// **The project root is created under the org's identity, and a person's identity is not its
/// owner** (RFC-0088 rule 5). Alice made it, is in it, and can write in it — and it is the
/// org's: neither her AID nor her identity DID owns it, and neither can be named as its owner.
#[tokio::test]
async fn the_project_root_is_the_orgs_and_the_person_is_a_member_not_its_owner() {
    let mut p = project().await;
    let owner = {
        let (org, root) = (p.org.clone(), p.root.clone());
        let again = p.client().org_root_create(ALICE, &org, "second").await.expect("a second project root");
        assert_ne!(again.root, root);
        again.owner
    };
    assert_eq!(owner, p.org, "the root is the org's");
    assert_ne!(owner, p.aid, "the person's AID is not the root's owner");
    assert_ne!(owner, p.did, "the person's identity DID is not the root's owner");

    // Neither of the person's own identities can be made a project root's owner, and nor can
    // an org this person does not hold.
    for not_an_org in [p.aid.clone(), p.did.clone(), "did:key:z6MkNoSuchOrgOnThisDevice".to_string()] {
        let refused = p.client().org_root_create(ALICE, &not_an_org, "mine").await;
        assert!(refused.is_err(), "{not_an_org} was accepted as a project root's owner");
    }

    // She is a member: the record verbs let her write in it and read it back.
    let root = p.root.clone();
    let text = "# T\n\n**Status:** open\n\nbody\n";
    let row = kotton_record_file::row::to_row("TASK-t", text).unwrap();
    p.client()
        .record_insert_in(ALICE, Some(&root), Some(PRINCIPAL), NSID, row)
        .await
        .expect("a member writes in the root");
    let back = p
        .client()
        .record_query_in(ALICE, Some(&root), Some(PRINCIPAL), NSID, vec![], None, None)
        .await
        .unwrap();
    assert_eq!(back.len(), 1);
}

// ── invitation ────────────────────────────────────────────────────────────────

/// **`kotton records invite` issues a membership grant under `org.invite`, and refuses without
/// it.** The grant walks back to the org, not to Alice; once the delegation she holds is
/// revoked, the same verb refuses the next person.
#[tokio::test]
async fn inviting_runs_under_org_invite_and_is_refused_without_it() {
    let mut p = project().await;
    let root = p.root.clone();
    let OrgRootDelegation::Held { envelope_id } = p.delegation.clone() else {
        panic!("a plain org delegates at once");
    };

    let bob = "did:kel:z6MkBobsAidForTheProject";
    let (added, grant_json) = p.client().org_root_invite(ALICE, &root, bob).await.expect("alice invites bob");
    assert!(added);
    let grant: kotton_wire::MembershipGrant = serde_json::from_str(&grant_json).unwrap();
    kotton_grant::daemon::membership::verify_membership(&grant, &p.org, &root, bob, kotton_common::time::now_secs())
        .expect("bob's grant walks back to the org");
    assert_eq!(grant.grant.issuer_did.to_string(), p.did, "signed by the holder of org.invite");
    let authority = grant.authority.as_ref().expect("a delegate's grant carries its delegation");
    assert_eq!(authority.issuer_did.to_string(), p.org, "the authority is the org's, not Alice's");
    assert_eq!(authority.subject_did.to_string(), p.did);
    // The delegation has an end, and the grant does not outlast it: that end is how long a
    // verifier elsewhere can go on believing a delegate whose authority was revoked.
    let bound = authority.expires_at.expect("the org's delegation is bounded in time");
    let ends = grant.grant.expires_at.expect("a membership grant has an end");
    assert!(ends <= bound, "the grant ends at {ends}, after its delegation's {bound}");

    // Without it: the delegation is revoked, and the verb refuses.
    p.client().grant_revoke(ALICE, &envelope_id).await.expect("revoke the delegation");
    let refused = p
        .client()
        .org_root_invite(ALICE, &root, "did:kel:z6MkCarolsAid")
        .await
        .expect_err("an invitation with no org.invite");
    assert!(refused.to_string().contains("org.invite"), "{refused}");

    // And a root she is not in answers as one that does not exist.
    let unknown = p.client().org_root_invite(ALICE, "no-such-root", bob).await.unwrap_err();
    assert!(unknown.to_string().contains("no root"), "{unknown}");
}

/// **`kotton records invite` names its invitee as every verb that names a contact does.** From
/// the terminal, Alice invites Bob by the name `kotton contact list` shows; the terminal prints
/// the AID the name stood for, and the grant it prints is Bob's.
#[tokio::test]
async fn a_contact_is_invited_by_name_from_the_terminal_and_their_aid_is_printed() {
    let mut p = project_on(TestEnv::spawn_cli_reachable().await).await;
    let mut bob = KottonClient::connect_to(p.env.endpoint.clone()).await.expect("connect");
    let (bob_aid, _) = bob.create_user("bob", crate::common::TEST_PASSPHRASE).await.expect("create bob");
    assert!(bob_aid.starts_with("did:kel:"), "{bob_aid}");
    p.client().contact_add(ALICE, &bob_aid).await.expect("bob is alice's contact");
    let cli = Cli::for_env(&p.env);
    cli.seed_session(ALICE, p.env.client.session_token.as_deref().expect("alice logged in"));

    let invited = cli.run(&["records", "invite", "bob", "--root", &p.root, "--user", ALICE]);
    assert!(invited.status.success(), "`kotton records invite` by name failed.\n{}", said(&invited));
    let stdout = String::from_utf8_lossy(&invited.stdout).into_owned();
    assert!(
        stdout.lines().next() == Some(format!("✓ bob ({bob_aid}) is a member of the project's root").as_str()),
        "the invitation names whom the name resolved to.\n{}",
        said(&invited)
    );
    let grant_json = stdout.lines().skip_while(|l| !l.starts_with('{')).collect::<Vec<_>>().join("\n");
    let grant: kotton_wire::MembershipGrant = serde_json::from_str(&grant_json).expect("the grant is printed");
    kotton_grant::daemon::membership::verify_membership(&grant, &p.org, &p.root, &bob_aid, kotton_common::time::now_secs())
        .expect("the grant is bob's, and walks back to the org");
}

/// **A FROST org owns a root the same way, and delegates `org.invite` by its quorum.** The
/// root is the threshold identity's; until the ceremony finishes nobody holds `org.invite`
/// on it, so the verb refuses — the delegation is what makes an invitation possible, not the
/// act of having created the root.
#[tokio::test]
async fn a_frost_org_owns_its_root_and_delegates_by_ceremony() {
    let mut p = project().await;
    let (frost, _shares) = p.client().org_frost_new(ALICE, "kotton-team", 2, 3).await.expect("a FROST org");
    let made = p.client().org_root_create(ALICE, &frost, "kotton").await.expect("a root under a FROST org");
    assert_eq!(made.owner, frost);
    assert_ne!(made.owner, p.did);
    assert!(
        matches!(made.delegation, OrgRootDelegation::Ceremony { .. }),
        "a threshold org signs by ceremony: {:?}",
        made.delegation
    );
    let refused = p
        .client()
        .org_root_invite(ALICE, &made.root, "did:kel:z6MkBobsAid")
        .await
        .expect_err("an invitation before the quorum delegated org.invite");
    assert!(refused.to_string().contains("org.invite"), "{refused}");
}

// ── the grant on the schema ───────────────────────────────────────────────────

/// **Import and export run under a grant on the schema, and refuse without one.**
#[tokio::test]
async fn import_and_export_are_refused_without_the_grant_on_the_schema() {
    let mut p = project().await;
    let root = p.root.clone();
    let out = tempfile::tempdir().unwrap();
    p.client().schema_grant_revoke(PRINCIPAL, NSID).await.expect("revoke the converter's grant");

    let import = records_import(p.client(), ALICE, &root, &fixture_dir()).await;
    assert!(import.is_err(), "imported with no grant on the schema: {import:?}");
    let export = records_export(p.client(), ALICE, &root, out.path()).await;
    assert!(export.is_err(), "exported with no grant on the schema: {export:?}");

    p.client().schema_grant_set(PRINCIPAL, NSID, true, true, false).await.unwrap();
    assert_eq!(records_import(p.client(), ALICE, &root, &fixture_dir()).await.unwrap().inserted, 10);
    assert_eq!(records_export(p.client(), ALICE, &root, out.path()).await.unwrap(), 10);
}

// ── the round trip ────────────────────────────────────────────────────────────

/// **Ten fixture records, every field and every kind, go into the root and come back byte
/// for byte — and a second import changes no row.** The second import is compared by each
/// row's `updated_at` as well as by the report, a second later, so a rewrite of identical
/// content could not pass as a no-op.
#[tokio::test]
async fn ten_fixture_records_round_trip_through_the_project_root() {
    let mut p = project().await;
    let root = p.root.clone();

    let first = records_import(p.client(), ALICE, &root, &fixture_dir()).await.expect("import");
    assert_eq!(first, ImportReport { inserted: 10, replaced: 0, unchanged: 0 });

    let out = tempfile::tempdir().unwrap();
    assert_eq!(records_export(p.client(), ALICE, &root, out.path()).await.expect("export"), 10);
    assert_eq!(files_in(out.path()), files_in(&fixture_dir()), "the export is not the fixture, byte for byte");

    let before = stamps(p.client()).await;
    assert_eq!(before.len(), 10);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let second = records_import(p.client(), ALICE, &root, &fixture_dir()).await.expect("import again");
    assert_eq!(second, ImportReport { inserted: 0, replaced: 0, unchanged: 10 });
    assert_eq!(stamps(p.client()).await, before, "a second import rewrote a row");

    // A file changed on disk is replaced by name, and only that one.
    let edited = tempfile::tempdir().unwrap();
    for (name, bytes) in files_in(&fixture_dir()) {
        std::fs::write(edited.path().join(&name), bytes).unwrap();
    }
    let role = edited.path().join("ROLE-a-fixture-role.md");
    let text = std::fs::read_to_string(&role).unwrap().replace("**Status:**  decided", "**Status:**  superseded");
    std::fs::write(&role, text).unwrap();
    let third = records_import(p.client(), ALICE, &root, edited.path()).await.expect("import an edit");
    assert_eq!(third, ImportReport { inserted: 0, replaced: 1, unchanged: 9 });
}

// ── the app (RFC-0088 phase two) ──────────────────────────────────────────────

/// The text a launch drew: every string in its `0x02` mutation batches, which is where a
/// Dioxus guest's words travel. Unescaped once, so a title with an apostrophe reads as
/// itself.
fn drawn(patches: &[Vec<u8>]) -> String {
    patches
        .iter()
        .filter(|p| p.first() == Some(&0x02))
        .map(|p| String::from_utf8_lossy(&p[1..]).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
        .replace("\\u2019", "\u{2019}")
}

/// What one launch of `app_id` on the request `args` drew.
async fn view(client: &mut KottonClient, app_id: &str, args: &[(&str, &str)]) -> String {
    let args = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    drawn(&client.app_launch(app_id, args).await.expect("launch a view").patches)
}

/// The records app as it ships, or a failure that names the command that builds it.
fn records_app() -> (String, Vec<u8>) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/apps/kotton-records");
    let manifest = std::fs::read_to_string(dir.join("manifest.toml")).expect("the records app's manifest");
    let wasm = std::fs::read(dir.join("app.wasm")).unwrap_or_else(|e| {
        panic!(
            "the records app is not built, so this test cannot launch it.\n  missing: {} ({e})\n  \
             fix:     cargo xtask build-apps",
            dir.join("app.wasm").display()
        )
    });
    (manifest, wasm)
}

/// **The records app draws the imported root, and reads nothing without its grant**
/// (RFC-0088 phase two; `TASK-the-records-app-browses-the-project-root-in-kuid`).
///
/// End to end, through everything between the files and the drawn document: a real daemon,
/// the project root under its org, the ten fixture records imported into it by the converter,
/// the records app installed from `guest/apps/kotton-records`, and the real confined runner
/// launching it. Its launch commits the list; the list names every one of the ten records and
/// ends with the reach line, *records in kotton, and nothing else* — the root by the person's
/// word for it. Launched on one record, it draws that record's body.
///
/// The control is the same app installed with nothing approved: the same launch, the same
/// root, and the host does not link `kotton:app/schema` into it at all, so it cannot start —
/// what the first launch drew came through the grant and not around it.
#[tokio::test]
async fn the_records_app_draws_the_imported_root_and_nothing_without_its_grant() {
    use crate::common::InstallApprovingAll as _;
    let mut p = project_on(TestEnv::spawn_with_real_runner().await).await;
    let root = p.root.clone();
    records_import(p.client(), ALICE, &root, &fixture_dir()).await.expect("import the ten");
    let titles: Vec<String> = files_in(&fixture_dir())
        .values()
        .map(|b| {
            String::from_utf8_lossy(b)
                .lines()
                .find_map(|l| l.strip_prefix("# "))
                .expect("a title")
                .to_owned()
        })
        .collect();

    let (manifest, wasm) = records_app();
    let (app_id, _, _) = p
        .client()
        .app_install_approving_all(ALICE, manifest.clone(), wasm.clone())
        .await
        .expect("install the records app, approving the one grant it asks for");
    assert_eq!(app_id, "sh.kotton.records");

    let list = drawn(&p.client().app_launch(&app_id, vec![]).await.expect("launch").patches);
    for title in &titles {
        let first_words: String = title.chars().take(24).collect();
        assert!(list.contains(&first_words), "the list did not draw {title:?}:\n{list}");
    }
    assert!(list.contains("10 records"), "the rail does not count the ten");
    assert!(
        list.contains("This app can see records in kotton, and nothing else"),
        "the reach line is not the manifest's, in the root's own word:\n{list}"
    );

    // One record, by the launch's own request.
    let rfc = files_in(&fixture_dir())
        .keys()
        .find(|n| n.starts_with("RFC-"))
        .map(|n| n.trim_end_matches(".md").to_owned())
        .expect("an RFC in the fixture");
    let record = drawn(
        &p.client()
            .app_launch(&app_id, vec![("view".into(), "record".into()), ("name".into(), rfc.clone())])
            .await
            .expect("launch on one record")
            .patches,
    );
    assert!(record.contains("<dt>") || record.contains("\"dt\""), "no header drawn for {rfc}");
    assert!(!record.contains("No record called"), "{rfc} was not found in the root:\n{record}");

    // And the other three views, over the same imported rows: the search finds a fixture
    // record by a word of its title, the board groups them, and About reads the manifest.
    let word = titles[0].split_whitespace().max_by_key(|w| w.len()).unwrap().to_lowercase();
    let search = view(p.client(), &app_id, &[("view", "search"), ("q", &word)]).await;
    assert!(search.contains(&format!("\u{201c}{word}\u{201d}")), "the search view did not draw its query");
    assert!(!search.contains("Nothing matches"), "a word of a fixture title found nothing:\n{search}");
    let board = view(p.client(), &app_id, &[("view", "board")]).await;
    assert!(board.contains("Awaiting you") && board.contains("Blocked"), "the board's groups were not drawn");
    let about = view(p.client(), &app_id, &[("view", "about")]).await;
    assert!(about.contains("sh.kotton.governance.record"), "About does not name the schema");
    assert!(about.contains("About this app"));

    // The control: nothing approved, the same root, and nothing read.
    p.client().app_uninstall(&app_id).await.expect("uninstall");
    let preview = p.client().app_install_preview(ALICE, manifest.clone(), wasm.clone()).await.unwrap();
    assert!(!preview.requested.is_empty(), "the manifest asks for its schema");
    p.client()
        .app_install(ALICE, manifest, wasm, vec![], vec![])
        .await
        .expect("install with nothing approved");
    // Refused before a call can be made: with no schema grant approved, the host does not
    // add `kotton:app/schema` to this instance's linker at all (`DeclaredInterfaces`), so
    // the component cannot be instantiated, and nothing it could have drawn exists.
    let refused = p.client().app_launch(&app_id, vec![]).await;
    let why = match refused {
        Ok(out) => panic!("an app with no grant launched and drew:\n{}", drawn(&out.patches)),
        Err(e) => e.to_string(),
    };
    assert!(why.contains("kotton:app/schema"), "refused, but not for want of the schema grant: {why}");
}
