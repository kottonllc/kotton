// SPDX-License-Identifier: AGPL-3.0-or-later
//! The person's roots, as the record verbs need them.
//!
//! A record belongs to exactly one root, and a root's membership is who may
//! read it. The record verbs are `record`'s, and `record` does not depend on
//! the store that holds the root set — so the daemon, which holds both, reads
//! the set here and hands over two facts: which root is Personal, and which
//! roots the person is a member of. [`kotton_record::roots::RootAccess`] does
//! the rest, once, before any verb runs.
//!
//! **Opened per request, not cached.** The meaning half of the index is sealed
//! under the person's keys, and a membership that changed since the last read
//! must be the one the next read obeys. A cache is a second copy of who may
//! read, and the day it disagreed with the index it would be the one obeyed.

use std::path::Path;

use kotton_record::roots::RootAccess;
use kotton_store::runtime::roots::RootSet;

/// The two facts the record verbs need, read out of a person's root set.
///
/// Unresolved when the set has no root that adopted today's tree — which a set
/// `RootSet::open` returned never lacks, and which is answered the safe way if
/// it ever does: Personal's rows, and no named root.
pub(crate) fn access_from(set: &RootSet, own_aid: &str) -> RootAccess {
    match set.personal() {
        Some(personal) => RootAccess::new(personal.id, set.member_roots(own_aid)),
        None => RootAccess::unresolved(),
    }
}

/// This person's record access, read out of their own store.
///
/// The same three steps [`super::app_host::user_runner_roots`] takes — the AID
/// from the local chain, the loaded store, the sealed index — and the same
/// answer when any of them is missing: *this device cannot say*, which for
/// records is [`RootAccess::unresolved`] — Personal's rows as they always were,
/// and every named root refused.
pub(crate) fn record_access(
    users: &crate::residency::UserRegistry,
    base: &Path,
    user_id: &str,
) -> RootAccess {
    let Some(own_aid) = kotton_identity::kel_store::load_chain(base, user_id)
        .ok()
        .and_then(|chain| chain.into_iter().next())
        .map(|e| e.aid.to_string())
    else {
        return RootAccess::unresolved();
    };
    let Some(store) = users.get(user_id) else {
        return RootAccess::unresolved();
    };
    let binding = kotton_identity::provisioning::routing_binding(store.base_dir());
    match store.roots(&own_aid, binding.as_deref()) {
        Ok(set) => access_from(&set, &own_aid),
        Err(e) => {
            tracing::warn!(%e, user = %user_id, "records: could not open this person's roots");
            RootAccess::unresolved()
        }
    }
}

/// One schema's records kept in every root this person is a member of, each
/// named by the person's word for its root — the daemon's half of
/// `schema.kept`.
///
/// **Membership is read here, from `set`, and nowhere else.** The app named no
/// root, so the selection is [`RootAccess::read`] of none: every root the
/// person is in, and no row from one they are not — the same selection the
/// person's own record verbs make. The app's schema grant was checked by the
/// sandbox before the frame was written.
///
/// **A root travels as its name, never its id**, which is the rule
/// `an_event_written_into_two_roots_reads_back_only_from_its_own` already holds
/// for the IPC verbs: an app holds no root, so an id is only a join key. A row
/// whose root has no name in the set — which a set that answered the selection
/// cannot produce — is left out rather than labelled with a guess.
///
/// A schema nobody registered on this device has no rows in the store, so it
/// answers an empty list rather than an error: *nothing kept here* is the truth.
pub(crate) async fn kept(
    registry: &std::sync::RwLock<kotton_record::SchemaRegistry>,
    store: &kotton_record::SqliteRecordStore,
    set: &RootSet,
    own_aid: &str,
    nsid: &str,
) -> Result<Vec<kotton_wire::runner::RunnerKeptRecord>, String> {
    let parsed = kotton_schemas::Nsid::new(nsid).map_err(|e| format!("{nsid}: {e}"))?;
    if registry.read().map_err(|e| e.to_string())?.get(&parsed).is_none() {
        return Ok(Vec::new());
    }
    let access = access_from(set, own_aid);
    let names: std::collections::HashMap<String, String> =
        set.all().into_iter().map(|r| (r.id, r.name)).collect();
    let rows = kotton_record::record_cmds::Record::new(registry, store)
        .within(&access, None)
        .map_err(|e| e.to_string())?
        .query(nsid, vec![], None, None, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .filter_map(|mut body| {
            let id = body["_id"].as_str()?.to_owned();
            let root = names.get(body["_root"].as_str()?)?.clone();
            if let Some(obj) = body.as_object_mut() {
                obj.remove("_id");
                obj.remove("_root");
                obj.remove("_filed_at");
            }
            Some(kotton_wire::runner::RunnerKeptRecord { id, data: body.to_string(), root })
        })
        .collect())
}

/// The records host for one person: [`kept`] behind the store and index the
/// daemon holds for them (`kotton_app::daemon::apps::RecordsHost`).
pub struct DaemonRecordsHost<'a> {
    runtime: &'a kotton_device::DeviceRuntime,
    users: &'a crate::residency::UserRegistry,
    base: &'a Path,
    record_stores: &'a crate::residency::RecordStores,
    /// Whose records. `None` when nobody is unlocked, which the host answers
    /// in words rather than with an empty list: *could not look* is not
    /// *nothing there*.
    user_id: Option<String>,
}

/// The one person loaded on this device, or nobody — never a guess between two.
///
/// The compositor's paths have no session to name the person whose instance an
/// input or a launch belongs to, and `UserRegistry::any` answers *any one loaded
/// user*, in no defined order: on a device with two people loaded that is a coin
/// toss over whose records an app is handed. So those paths ask this, and with
/// two people loaded the records host has nobody and says so; the paths that do
/// carry a session pass its user straight through.
pub(crate) fn the_one_loaded(ids: Vec<String>) -> Option<String> {
    match <[String; 1]>::try_from(ids) {
        Ok([only]) => Some(only),
        Err(_) => None,
    }
}

/// Build the records host for whoever the instance was launched for.
pub fn records_host<'a>(
    runtime: &'a kotton_device::DeviceRuntime,
    users: &'a crate::residency::UserRegistry,
    base: &'a Path,
    record_stores: &'a crate::residency::RecordStores,
    user_id: Option<String>,
) -> DaemonRecordsHost<'a> {
    DaemonRecordsHost { runtime, users, base, record_stores, user_id }
}

#[async_trait::async_trait]
impl kotton_app::daemon::apps::RecordsHost for DaemonRecordsHost<'_> {
    async fn kept_records(
        &self,
        nsid: &str,
    ) -> Result<Vec<kotton_wire::runner::RunnerKeptRecord>, String> {
        let user = self
            .user_id
            .as_deref()
            .ok_or(
                "no one person's records are open to this instance: nobody is unlocked, or more \
                 than one person is and nothing says whose instance this is",
            )?;
        let own_aid = kotton_identity::kel_store::load_chain(self.base, user)
            .ok()
            .and_then(|chain| chain.into_iter().next())
            .map(|e| e.aid.to_string())
            .ok_or("no identity names this person, so their roots cannot be read")?;
        let person = self
            .users
            .get(user)
            .ok_or("this person's store is not loaded, so their roots cannot be read")?;
        let binding = kotton_identity::provisioning::routing_binding(person.base_dir());
        let set = person
            .roots(&own_aid, binding.as_deref())
            .map_err(|e| format!("this person's roots would not open: {e}"))?;
        let store = self
            .record_stores
            .get_or_open(self.runtime.base_dir(), user, self.runtime.secrets())
            .map_err(|e| e.to_string())?;
        kept(&self.runtime.schema_registry, &store, &set, &own_aid, nsid).await
    }
}

#[cfg(test)]
mod tests {
    use super::access_from;
    use kotton_record::daemon::records::{record_delete, record_insert, record_open, record_query, record_search};
    use kotton_record::{SchemaRegistry, SqliteRecordStore};
    use kotton_store::runtime::roots::{Owner, Residency, RootSet};
    use kotton_store::runtime::user::UserStore;
    use kotton_store::runtime::UserKeys;
    use kotton_wire::ipc::UserResponse;
    use serde_json::json;
    use std::sync::{Arc, RwLock};

    const AID: &str = "did:kel:z6MkPersonsOwnAid";
    const SOMEONE_ELSE: &str = "did:kel:z6MkSomeoneElse";
    const CALENDAR: &str = "sh.kotton.calendar";
    /// An app holding `schema.read` and `schema.write` on calendar and nothing
    /// else — the grant is what it may see, and it is not a membership.
    const APP: &str = "sh.kotton.shell";

    struct Person {
        _temp: tempfile::TempDir,
        set: RootSet,
        registry: Arc<RwLock<SchemaRegistry>>,
        store: Arc<SqliteRecordStore>,
        user_db: Arc<sqlx::SqlitePool>,
        family: String,
        theirs: String,
    }

    /// A person with Personal, a Family root they are in, and a root they are
    /// not a member of — which exists only through `RootSet::add`, test-only
    /// today, and is exactly the state membership has to hold against.
    async fn person() -> Person {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let user = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir,
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let mut set = user.roots(AID, None).unwrap();
        let family = set
            .add("Family", Owner::ThePerson, vec![AID.into(), SOMEONE_ELSE.into()], Vec::new(), Residency::Full)
            .unwrap();
        let theirs = set
            .add("Theirs", Owner::ThePerson, vec![SOMEONE_ELSE.into()], Vec::new(), Residency::Full)
            .unwrap();

        let user_db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE schema_grants (
                app_id TEXT NOT NULL, nsid TEXT NOT NULL,
                can_read INTEGER NOT NULL DEFAULT 0, can_write INTEGER NOT NULL DEFAULT 0,
                can_register INTEGER NOT NULL DEFAULT 0,
                record_quota INTEGER NOT NULL DEFAULT 50000,
                byte_quota INTEGER NOT NULL DEFAULT 104857600,
                record_count INTEGER NOT NULL DEFAULT 0, byte_count INTEGER NOT NULL DEFAULT 0,
                granted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (app_id, nsid))",
        )
        .execute(&user_db)
        .await
        .unwrap();
        kotton_grant::daemon::db::schema_grants_db::set_grant(&user_db, APP, CALENDAR, true, true, false)
            .await
            .unwrap();

        Person {
            _temp: temp,
            set,
            registry: Arc::new(RwLock::new(SchemaRegistry::new())),
            store: Arc::new(SqliteRecordStore::in_memory().unwrap()),
            user_db: Arc::new(user_db),
            family,
            theirs,
        }
    }

    impl Person {
        async fn add(&self, root: Option<&str>, title: &str) -> UserResponse {
            record_insert(
                &self.registry,
                &self.store,
                &self.user_db,
                &access_from(&self.set, AID),
                root.map(str::to_owned),
                CALENDAR.into(),
                json!({ "title": title, "date": "2026-09-24" }),
                Some(APP.into()),
            )
            .await
            .unwrap()
        }

        async fn list(&self, root: Option<&str>) -> Result<Vec<String>, String> {
            match record_query(
                &self.registry,
                &self.store,
                &self.user_db,
                &access_from(&self.set, AID),
                root.map(str::to_owned),
                CALENDAR.into(),
                vec![],
                None,
                None,
                Some(APP.into()),
            )
            .await
            .unwrap()
            {
                UserResponse::RecordQueryResult { records } => {
                    let mut t: Vec<String> = records
                        .iter()
                        .map(|r| r["title"].as_str().unwrap().to_owned())
                        .collect();
                    t.sort();
                    Ok(t)
                }
                UserResponse::Error { message } => Err(message),
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    /// **An event written into two roots reads back from each only from its
    /// own** — a record belongs to a root, held through the record verbs a
    /// caller actually reaches, with a schema grant in force.
    ///
    /// The default read is the person's view across the roots they are in: an
    /// app holding `schema.read` on calendar sees calendar rows in both, because
    /// the person is a member of both, and the grant is unchanged by either.
    #[tokio::test]
    async fn an_event_written_into_two_roots_reads_back_only_from_its_own() {
        let p = person().await;
        let personal = p.set.personal().unwrap().id;

        assert!(matches!(p.add(None, "dentist").await, UserResponse::RecordInserted { .. }));
        assert!(matches!(
            p.add(Some(&p.family), "school play").await,
            UserResponse::RecordInserted { .. }
        ));

        assert_eq!(p.list(Some(&personal)).await.unwrap(), vec!["dentist"]);
        assert_eq!(p.list(Some(&p.family)).await.unwrap(), vec!["school play"]);
        assert_eq!(p.list(None).await.unwrap(), vec!["dentist", "school play"]);

        // And each row says which root it is in, in the root's own id — to the
        // person (no app id), and never to an app: a root id is a durable
        // identifier, and an app has no root it could name with it.
        let ask = |app: Option<String>| {
            let access = access_from(&p.set, AID);
            let (registry, store, user_db) = (p.registry.clone(), p.store.clone(), p.user_db.clone());
            async move {
                let UserResponse::RecordQueryResult { records } = record_query(
                    &registry, &store, &user_db, &access, None,
                    CALENDAR.into(), vec![], None, None, app,
                )
                .await
                .unwrap() else { panic!() };
                records
            }
        };
        for r in ask(None).await {
            let want = if r["title"] == "dentist" { &personal } else { &p.family };
            assert_eq!(r["_root"].as_str(), Some(want.as_str()), "{r}");
            assert!(r["_filed_at"].is_i64(), "the person is told where each row was filed: {r}");
        }
        // Nor when the person's devices filed each row: attention data an app
        // has no use for.
        for r in ask(Some(APP.into())).await {
            assert!(r.get("_root").is_none(), "an app was handed a root id: {r}");
            assert!(r.get("_filed_at").is_none(), "an app was handed a filing time: {r}");
        }
        let UserResponse::RecordQueryResult { records } = record_search(
            &p.registry, &p.store, &access_from(&p.set, AID), None, None, None, Some(APP.into()),
        )
        .await
        .unwrap() else { panic!() };
        assert!(!records.is_empty());
        assert!(records.iter().all(|r| r.get("root").is_none()), "search handed an app a root id");
    }

    /// **A row in a root the person is not a member of is not readable through
    /// any verb.** The row is put there directly — no verb will write it,
    /// which is asserted first — and then every verb that reads, and the one
    /// that deletes, is asked for it: query by default and by name, search,
    /// open by URL, and delete. None of them reaches it, and the grant the app
    /// holds on the schema does not change that.
    #[tokio::test]
    async fn a_row_in_a_root_the_person_is_not_a_member_of_is_not_readable_through_any_verb() {
        use kotton_record::RecordStore as _;
        let p = person().await;

        // No verb writes into it.
        let refused = p.add(Some(&p.theirs), "their secret").await;
        assert!(matches!(refused, UserResponse::Error { .. }), "{refused:?}");

        // Put a row there the way a replicated one would arrive.
        let nsid = kotton_schemas::nsid::Nsid::new(CALENDAR).unwrap();
        let def = p.registry.read().unwrap().get(&nsid).unwrap().clone();
        p.store.create_table(&def).await.unwrap();
        let id = p
            .store
            .insert_in(&nsid, Some(p.theirs.clone()), json!({ "title": "their secret" }))
            .await
            .unwrap();
        p.add(None, "dentist").await;

        // Query: by default, and by naming the root.
        assert_eq!(p.list(None).await.unwrap(), vec!["dentist"]);
        assert!(p.list(Some(&p.theirs)).await.is_err(), "a non-member root was queried by name");

        // Search, across every schema.
        let access = access_from(&p.set, AID);
        let UserResponse::RecordQueryResult { records } =
            record_search(&p.registry, &p.store, &access, None, None, None, None).await.unwrap()
        else {
            panic!()
        };
        assert!(
            records.iter().all(|r| r["body"]["title"] != "their secret"),
            "search returned a non-member root's row: {records:?}"
        );

        // Open, by the URL that names it exactly.
        let url = format!("kotton://records/{CALENDAR}/{id}");
        let opened = record_open(&p.registry, &p.store, &access, url).await.unwrap();
        assert!(matches!(opened, UserResponse::RecordOpenNotFound { .. }), "{opened:?}");

        // Delete, by default and by naming the root.
        for root in [None, Some(p.theirs.clone())] {
            let gone = record_delete(
                &p.registry, &p.store, &p.user_db, &access, root,
                CALENDAR.into(), id.clone(), Some(APP.into()),
            )
            .await
            .unwrap();
            assert!(matches!(gone, UserResponse::Error { .. }), "{gone:?}");
        }
        // …and the row is still there, untouched, for its own members.
        let still = p
            .store
            .query(
                &nsid,
                kotton_record::RecordFilter::new()
                    .roots(kotton_record::RootSelection::only(p.theirs.clone())),
            )
            .await
            .unwrap();
        assert_eq!(still.len(), 1);
    }

    /// **The compositor never guesses whose records an app is handed.** One
    /// person loaded is that person; nobody, or two, is nobody — never whichever
    /// the registry's map happens to yield first.
    #[test]
    fn the_compositor_hands_records_only_to_the_one_person_loaded() {
        assert_eq!(super::the_one_loaded(vec!["alice".into()]), Some("alice".into()));
        assert_eq!(super::the_one_loaded(vec![]), None);
        assert_eq!(super::the_one_loaded(vec!["alice".into(), "bob".into()]), None);
    }

    /// **`schema.kept` answers the schema's rows in every root the person is
    /// in, each by the root's name, and no row from a root they are not.**
    ///
    /// The app that asks holds no root and names none, so this is the whole of
    /// its reach into the person's records: Personal's row and Family's row,
    /// labelled *Personal*-or-its-successor and *Family*, and never the row put
    /// straight into a root the person is not a member of. No root id leaves.
    /// A schema nobody registered answers empty, not an error.
    #[tokio::test]
    async fn kept_records_are_every_member_roots_rows_by_name_and_no_other() {
        use kotton_record::RecordStore as _;
        let p = person().await;
        let personal = p.set.personal().unwrap();

        // Registered, so the store will hold rows of it.
        assert!(matches!(p.add(None, "dentist").await, UserResponse::RecordInserted { .. }));
        assert!(matches!(
            p.add(Some(&p.family), "school play").await,
            UserResponse::RecordInserted { .. }
        ));
        // A row in a root the person is not in, put there the way a replicated
        // one would arrive — no verb writes it.
        let nsid = kotton_schemas::Nsid::new(CALENDAR).unwrap();
        p.store
            .insert_in(&nsid, Some(p.theirs.clone()), json!({ "title": "their secret", "date": "2026-09-24" }))
            .await
            .unwrap();

        let rows = super::kept(&p.registry, &p.store, &p.set, AID, CALENDAR).await.unwrap();
        let mut seen: Vec<(String, String)> = rows
            .iter()
            .map(|r| {
                let body: serde_json::Value = serde_json::from_str(&r.data).unwrap();
                assert!(
                    body.get("_root").is_none() && body.get("_id").is_none() && body.get("_filed_at").is_none(),
                    "{body}"
                );
                (body["title"].as_str().unwrap().to_owned(), r.root.clone())
            })
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("dentist".to_owned(), personal.name.clone()),
                ("school play".to_owned(), "Family".to_owned()),
            ],
            "kept records reached a root the person is not in, or lost one they are"
        );
        for r in &rows {
            assert_ne!(r.root, p.family, "a root id left the daemon");
            assert_ne!(r.root, personal.id, "a root id left the daemon");
        }

        let none = super::kept(&p.registry, &p.store, &p.set, AID, "sh.kotton.nobody-registered")
            .await
            .expect("an unregistered schema is an empty answer");
        assert!(none.is_empty());
    }
}
