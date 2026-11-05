// SPDX-License-Identifier: AGPL-3.0-or-later
//! A request is answered as the session user its gate read, once (#428).
//!
//! `handle_request` used to read the session twice: once for the guard, and
//! again for the user it handed the verb. A session that ended between the two
//! reads passed the guard and reached the verb with no user, and the per-user
//! database answered "no user" with whichever user happened to be loaded. On a
//! device holding two identities, that is one person's records delivered to
//! another's connection.
//!
//! Every test here boots a daemon holding alice and bob, each with something in
//! their own database that names its owner, and asks from alice's connection.

use super::*;
use kotton_wire::ipc::Principal;

const PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";
const ALICE_SESSION: &str = "alice-session";

/// A daemon booted at `base` holding alice and bob, both unlocked.
pub(super) async fn alice_and_bob(base: &Path) -> super::super::DeviceDaemon {
    let keychain: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
        Arc::new(kotton_secret::MemorySecrets::new());
    let runtime = DeviceRuntime::new_with_secrets(
        base.to_path_buf(),
        kotton_device::config::RuntimeConfig::default(),
        keychain.clone(),
    )
    .await
    .unwrap();
    runtime.create_user("alice", PASSPHRASE).await.unwrap();
    runtime.create_user("bob", PASSPHRASE).await.unwrap();
    drop(runtime);
    #[cfg(unix)]
    let endpoint = kotton_sys::ipc::IpcEndpoint::UnixSocket(base.join("kuserd.sock"));
    #[cfg(windows)]
    let endpoint = kotton_sys::ipc::IpcEndpoint::NamedPipe(format!(
        "kotton-test-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let daemon = super::super::DeviceDaemon::new_with_base_secrets_and_relay(
        base.to_path_buf(),
        endpoint,
        keychain,
        kotton_device::config::db::RelayChoice::None,
    )
    .await
    .expect("the daemon boots");
    for user in ["alice", "bob"] {
        let resp = handle_request(
            &daemon.agent_context(),
            UserRequest::UnlockWithPin {
                user_id: user.into(),
                pin: kotton_wire::ipc::SecretText::new(PASSPHRASE),
                repair: false,
            },
            Caller::anonymous(),
            Arc::new(Mutex::new(None)),
        )
        .await
        .unwrap();
        assert!(matches!(resp, UserResponse::UnlockOk { .. }), "{user} unlocks: {resp:?}");
    }
    daemon
}

/// `user`'s own agent database, opened by name.
pub(super) async fn db_of(ctx: &super::super::AgentContext, user: &str) -> Arc<SqlitePool> {
    crate::db::user_db::user_agent_db(
        &ctx.user_dbs,
        &ctx.base,
        ctx.runtime.secrets(),
        user,
        &ctx.runtime.schema_registry,
    )
    .await
    .unwrap_or_else(|e| panic!("{user}'s database opens: {e}"))
}

/// One event in `user`'s own log, whose message names them.
async fn an_event_of(ctx: &super::super::AgentContext, user: &str) {
    sqlx::query(
        "INSERT INTO events (id, category, level, message, payload, timestamp) \
         VALUES (?, 'system', 'info', ?, NULL, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(format!("{user}'s event"))
    .bind(kotton_common::time::now_secs() as i64)
    .execute(&*db_of(ctx, user).await)
    .await
    .unwrap_or_else(|e| panic!("an event in {user}'s log: {e}"));
}

/// Alice's connection: a local operator holding `ALICE_SESSION`.
fn alices_connection() -> Arc<Mutex<Option<ConnSessionData>>> {
    let principal = Principal::LocalOperator;
    Arc::new(Mutex::new(Some(ConnSessionData {
        origin: principal.trust_origin(),
        token: ALICE_SESSION.to_string(),
        scope: None,
        cek_available: true,
        principal,
        browser_key: None,
    })))
}

fn query_events() -> UserRequest {
    UserRequest::QueryEvents { category: None, level: None, since: None, limit: None }
}

fn messages(resp: &UserResponse) -> Vec<String> {
    match resp {
        UserResponse::EventList { events } => events.iter().map(|e| e.message.clone()).collect(),
        other => panic!("expected an event list, got {other:?}"),
    }
}

/// **A request whose session ends between the gate and the verb is answered as
/// the user the gate read, never from another loaded user (#428).**
///
/// The seam is the one `handle_request` is built from: the gate
/// ([`request_entry`]) reads the session and hands on its user, and the verb
/// ([`answer_request`]) is answered as that user. Alice's session is ended
/// between the two, which is the window the second read used to open. The
/// verb answers from alice's own log, the one her session was live for when it
/// was checked: her event, and nothing of bob's. Asked again with the session
/// gone, the gate refuses. And a session verb handed no user is an error,
/// never a fallback ([`handed`]).
#[tokio::test]
async fn a_session_that_ends_after_the_gate_is_answered_as_the_user_the_gate_read() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    an_event_of(&ctx, "alice").await;
    an_event_of(&ctx, "bob").await;
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    let conn = alices_connection();

    let Entry::Session(user) = request_entry(&ctx, &query_events(), &conn) else {
        panic!("the gate passes alice's live session and hands on her user");
    };
    assert_eq!(user.as_str(), "alice");

    ctx.sessions.write().unwrap().remove(ALICE_SESSION);

    let resp = answer_request(&ctx, query_events(), Caller::anonymous(), Arc::clone(&conn), Some(user))
        .await
        .expect("answered");
    let said = messages(&resp);
    assert!(said.contains(&"alice's event".to_string()), "alice's own log answered: {said:?}");
    assert!(!said.contains(&"bob's event".to_string()), "bob's event reached alice's connection: {said:?}");

    let again = handle_request(&ctx, query_events(), Caller::anonymous(), conn).await.expect("answered");
    assert!(matches!(again, UserResponse::NoActiveSession), "the session has gone: {again:?}");

    assert!(handed(&None).is_err(), "a session verb handed no user is an error, not a fallback");
}

/// **With alice's session gone and bob loaded, alice's `QueryEvents` is refused
/// and carries nothing of bob's.**
#[tokio::test]
async fn a_query_from_a_session_that_has_gone_is_refused_with_nothing_of_another_users() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    an_event_of(&ctx, "bob").await;
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    ctx.sessions.write().unwrap().remove(ALICE_SESSION);
    assert!(ctx.users.get("bob").is_some(), "bob is loaded");

    let resp = handle_request(&ctx, query_events(), Caller::anonymous(), alices_connection())
        .await
        .expect("answered");
    assert!(matches!(resp, UserResponse::NoActiveSession), "refused: {resp:?}");
    assert!(!format!("{resp:?}").contains("bob"), "the refusal carries bob's data: {resp:?}");
}

/// A connection holding `token`, at local-operator origin.
pub(super) fn a_connection(token: &str) -> Arc<Mutex<Option<ConnSessionData>>> {
    let principal = Principal::LocalOperator;
    Arc::new(Mutex::new(Some(ConnSessionData {
        origin: principal.trust_origin(),
        token: token.to_string(),
        scope: None,
        cek_available: true,
        principal,
        browser_key: None,
    })))
}

/// `request` from alice's live session, through the door's one-frame path.
async fn from_alice(ctx: &super::super::AgentContext, request: UserRequest) -> UserResponse {
    handle_request(ctx, request, Caller::anonymous(), alices_connection())
        .await
        .expect("answered")
}

/// **A request naming another user is refused (#428).**
///
/// The Extension verbs name a user and require a session, so the session
/// guard holds the name to the session's user (`target_user_id`), as it does
/// every other such verb. From alice's session, naming bob or naming nobody
/// is the guard's refusal, and nothing of bob's is answered; naming alice is
/// answered from her own database.
#[tokio::test]
async fn a_request_naming_another_user_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    let bobs = db_of(&ctx, "bob").await;
    crate::db::extension_registry_db::insert_extension(
        &bobs,
        &crate::db::extension_registry_db::ExtensionRow {
            extension_id: "org.bob.fetcher".into(),
            name: "bob's fetcher".into(),
            version: "1.0.0".into(),
            class: "fetcher".into(),
            description: "bob's own".into(),
            wasm_path: "/nowhere".into(),
            content_hash: "0".into(),
            publisher_did: None,
            network_json: None,
            credential_slots: vec![],
            installed_at: 0,
        },
    )
    .await
    .expect("bob's extension is registered");
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());

    for named in ["", "bob"] {
        for request in [
            UserRequest::ExtensionList { user_id: named.into() },
            UserRequest::ExtensionRemove { user_id: named.into(), extension_id: "org.bob.fetcher".into() },
            UserRequest::ExtensionInstall { user_id: named.into(), manifest_toml: String::new(), wasm_bytes: vec![] },
        ] {
            let verb = request.variant_name();
            let resp = from_alice(&ctx, request).await;
            assert!(
                matches!(resp, UserResponse::NoActiveSession),
                "{verb} naming {named:?} from alice's session is refused: {resp:?}"
            );
        }
    }
    let kept = crate::db::extension_registry_db::list_extensions(&bobs).await.expect("bob's list reads");
    assert_eq!(kept.len(), 1, "bob's extension is still registered");

    let own = from_alice(&ctx, UserRequest::ExtensionList { user_id: "alice".into() }).await;
    assert!(
        matches!(own, UserResponse::ExtensionList { ref extensions } if extensions.is_empty()),
        "alice's own (empty) list: {own:?}"
    );
}

/// **`AddRecoveryPhrase` naming another user is refused, and that user's key
/// log is unchanged.**
#[tokio::test]
async fn add_recovery_phrase_naming_another_user_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    let chain_len = || kotton_identity::kel_store::load_chain(&ctx.base, "bob").expect("bob's log reads").len();
    let before = chain_len();

    let resp = from_alice(&ctx, UserRequest::AddRecoveryPhrase { user_id: "bob".into() }).await;
    assert!(matches!(resp, UserResponse::NoActiveSession), "refused: {resp:?}");
    assert_eq!(chain_len(), before, "bob's key log was appended to");
}

/// **`StorageReload` naming another user is refused** by the session guard,
/// which answers before any handler runs, so nothing is reloaded.
#[tokio::test]
async fn storage_reload_naming_another_user_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());

    let resp = from_alice(&ctx, UserRequest::StorageReload { user_id: "bob".into() }).await;
    assert!(matches!(resp, UserResponse::NoActiveSession), "refused: {resp:?}");
}

/// **A contact ceremony naming another user is refused, and no contact is
/// admitted.** Both verbs are answered as a stream; the refusal is the
/// stream's one frame, the opening never runs, so no ceremony waits on a
/// confirmation and bob's contacts are as they were.
#[tokio::test]
async fn a_contact_ceremony_naming_another_user_is_refused() {
    use super::super::streamed::{answer, VfsWatchSource};
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());
    sessions::insert(&ctx.sessions, "bob-session".to_string(), "bob".to_string());
    let bobs_contacts = || async {
        let resp = handle_request(
            &ctx,
            UserRequest::ContactList { user_id: "bob".into() },
            Caller::anonymous(),
            a_connection("bob-session"),
        )
        .await
        .expect("answered");
        format!("{resp:?}")
    };
    let before = bobs_contacts().await;

    let (changes, _) = tokio::sync::broadcast::channel(16);
    let (_watching, watcher) = tokio::sync::watch::channel(kotton_sync::engine::FsWatchState::Watching);
    for request in [
        UserRequest::ContactPairStart { user_id: "bob".into(), as_name: None, ttl_seconds: 60 },
        UserRequest::ContactPairJoin {
            user_id: "bob".into(),
            code: kotton_wire::ipc::SecretText::new("ABCD-EFGH"),
            as_name: None,
        },
    ] {
        let verb = request.variant_name();
        let vfs = VfsWatchSource { changes: &changes, watcher: &watcher };
        let mut stream = answer(&ctx, &request, &alices_connection(), vfs)
            .await
            .unwrap_or_else(|| panic!("{verb}: answered as a stream"))
            .unwrap_or_else(|e| panic!("{verb}: {e}"));
        let mut frames = vec![];
        while let Ok(Some(frame)) = tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv()).await {
            frames.push(frame);
        }
        assert_eq!(
            format!("{frames:?}"),
            format!("{:?}", vec![UserResponse::NoActiveSession]),
            "{verb} naming bob from alice's session is refused"
        );
        assert!(ctx.pending_confirms.lock().await.is_empty(), "{verb}: a ceremony is waiting");
    }
    assert_eq!(bobs_contacts().await, before, "bob's contacts changed");
}
