// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests for the record domain, driven through a real machine.
//!
//! This file holds no production wrappers. A wrapper would forward to
//! `kotton_record` with one mount look-up in front of it, and the daemon — the
//! only side holding both a user's store and the record domain — does that
//! look-up itself.
//!
//! What is left is the tests, and they are worth keeping where they can reach a
//! `DeviceRuntime`: they exercise logging, applying and snapshotting a record
//! log across two real stores, which no unit test in `core/record` can set up.
//! They belong in the integration suite when this crate dissolves.

#[cfg(test)]
mod record_log_tests {
/// The unlock credential these fixtures create identities with — five BIP-39
/// words, 55.00 bits by the wordlist path. Mirrors the integration suite's
/// `TEST_PASSPHRASE`; a literal rather than a shared import because this crate
/// does not depend on the test harness.
const TEST_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

    use crate::users::DeviceUsers as _;
    use anyhow::Result;
    use kotton_store::runtime::user::UserStore;

    /// The three-line composition the daemon does: resolve the mount that
    /// carries the log, then hand it and the record store to `kotton_record`.
    ///
    /// Test helpers rather than production code, and that is the point — what they do is
    /// small enough that the caller should be doing it, and the daemon does.
    async fn mount_of(user: &UserStore, mount: &str) -> std::sync::Arc<dyn kotton_sys::store::SyncableStore> {
        user.get_remote(mount).expect("mount present")
    }

    async fn log_records(
        user: &UserStore,
        store: &std::sync::Arc<kotton_record::SqliteRecordStore>,
        mount: &str,
    ) -> Result<Option<u64>> {
        let m = mount_of(user, mount).await;
        kotton_record::replication::log_records(store, m.as_ref()).await
    }

    async fn apply_record_segments(
        rt: &DeviceRuntime,
        user: &UserStore,
        store: &std::sync::Arc<kotton_record::SqliteRecordStore>,
        mount: &str,
    ) -> Result<usize> {
        let m = mount_of(user, mount).await;
        kotton_record::replication::apply_record_segments(&rt.schema_registry, store, m.as_ref())
            .await
    }

    async fn snapshot_records(
        rt: &DeviceRuntime,
        user: &UserStore,
        store: &std::sync::Arc<kotton_record::SqliteRecordStore>,
        mount: &str,
        keep_full_secs: u64,
    ) -> Result<Option<kotton_sys::store::SnapshotSummary>> {
        let m = mount_of(user, mount).await;
        kotton_record::replication::snapshot_records(
            &rt.schema_registry,
            store,
            m.as_ref(),
            keep_full_secs,
        )
        .await
    }

    /// Open a user's record store directly.
    ///
    /// Tests do not want the daemon's cache — they want a store. The cache is
    /// `kuserd`'s because a map of open per-user stores is a path to user data,
    /// and `core/device`, where `DeviceRuntime` lives, may hold none. Opening one is `kotton_record`'s, and always was.
    fn record_store(rt: &DeviceRuntime, user_id: &str) -> std::sync::Arc<kotton_record::SqliteRecordStore> {
        std::sync::Arc::new(
            kotton_record::open::user_record_store(rt.base_dir(), user_id, rt.secrets())
                .expect("open record store"),
        )
    }

    /// Register a schema, resolving this user's store the way the daemon does.
    ///
    /// Not a `pub` wrapper: `core/record`'s daemon tier serves the record and
    /// schema verbs. This one had no production caller either,
    /// but seven test call sites here use it as setup, so it stays as what it
    /// actually is: a test helper, off the crate's public surface.
    async fn schema_register(
        rt: &DeviceRuntime,
        user_id: &str,
        definition_json: &str,
    ) -> Result<()> {
        let store = record_store(rt, user_id);
        kotton_record::schema_cmds::schema_register(
            &rt.schema_registry,
            &store,
            definition_json,
            user_id,
        )
        .await
    }
    // Explicit, because the lib target no longer names these now that the record
    // and replication verbs have moved — so they cannot arrive via `super::*`.
    use crate::DeviceRuntime;
    // RecordStore is a trait: the tests call `store.query(..)`, which needs it in
    // scope even though no line here names it.
    use kotton_record::record_store::{ChangesetRow, RecordFilter, RecordStore as _};
    use kotton_schemas::nsid::Nsid;
    use kotton_schemas::definition::SchemaDefinition;
    use kotton_schemas::field::{FieldType, SchemaField};
    use serde_json::json;
    use tempfile::TempDir;

    /// Create a user and hand back their runtime.
    ///
    /// This used to insert into the daemon's user registry and have the test
    /// read the runtime straight back out. That round-trip was the only thing
    /// in this crate naming that type, and it never tested residency — the
    /// verbs below take a runtime, so a runtime is what a test needs. (The type
    /// is not spelled here on purpose: the move is checked with `grep`, and a
    /// mention in prose is a false positive.)
    ///
    /// Returning it directly also puts a known hazard out of reach:
    /// a helper that registers can forget to hand the registry back, and one
    /// that returns the thing cannot.
    async fn create_resident(rt: &DeviceRuntime, user_id: &str) -> std::sync::Arc<UserStore> {
        let (_, user_rt) = rt.create_user(user_id, TEST_PASSPHRASE).await.unwrap();
        user_rt
    }

    async fn make_runtime(temp: &TempDir) -> DeviceRuntime {
        let secrets = std::sync::Arc::new(kotton_secret::MemorySecrets::new());
        DeviceRuntime::new_with_secrets(
            temp.path().to_path_buf(),
            crate::config::RuntimeConfig::default(),
            secrets,
        )
        .await
        .unwrap()
    }

    /// A test schema in a *test* namespace.
    ///
    /// This used to name `sh.kotton.notes` with a single field, while the real
    /// core schema has five. It appeared to register and did not: the
    /// version-equal branch returned Ok as a no-op, so every test below ran
    /// against the core definition rather than this one. Naming an owned
    /// namespace makes the registration real and the tests mean what they say.
    fn notes_schema() -> (Nsid, SchemaDefinition) {
        let nsid = Nsid::new("com.test.notes").unwrap();
        let def = SchemaDefinition::new(
            nsid.clone(),
            1,
            vec![SchemaField::required("title", FieldType::String)],
        );
        (nsid, def)
    }

    /// Every changeset row currently carried by the user's history log.
    async fn logged_rows(alice: &UserStore) -> Vec<ChangesetRow> {
        let mount = alice.get_remote("local").unwrap();
        mount
            .scan_record_segments()
            .await
            .unwrap()
            .into_iter()
            .flat_map(|s| s.rows)
            .map(|p| serde_json::from_slice::<ChangesetRow>(&p).unwrap())
            .collect()
    }

    /// The producer seals the store's records into the log, logs only what is
    /// new on later passes, and no-ops when nothing is unlogged — including for
    /// records written within the same wall-clock second, which a `> timestamp`
    /// cursor would silently drop.
    #[tokio::test]
    async fn log_records_appends_new_records_and_dedups_by_version() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let alice = create_resident(&rt, "alice").await;

        let store = record_store(&rt, "alice");
        let (nsid, def) = notes_schema();
        store.create_table(&def).await.unwrap();

        // Two records back to back — almost certainly the same second.
        store.insert(&nsid, json!({"title": "one"})).await.unwrap();
        store.insert(&nsid, json!({"title": "two"})).await.unwrap();

        let seq = log_records(&alice, &record_store(&rt, "alice"), "local").await.unwrap();
        assert!(seq.is_some(), "a logging mount appends a record segment");
        assert_eq!(
            logged_rows(&alice).await.len(),
            2,
            "both records logged despite a shared second"
        );

        // Idle re-run: nothing unlogged, no duplicate segment.
        assert_eq!(log_records(&alice, &record_store(&rt, "alice"), "local").await.unwrap(), None);
        assert_eq!(logged_rows(&alice).await.len(), 2);

        // A third record logs only itself.
        store.insert(&nsid, json!({"title": "three"})).await.unwrap();
        assert!(log_records(&alice, &record_store(&rt, "alice"), "local").await.unwrap().is_some());
        let mut titles: Vec<String> = logged_rows(&alice)
            .await
            .iter()
            .map(|r| r.body["title"].as_str().unwrap().to_string())
            .collect();
        titles.sort();
        assert_eq!(titles, ["one", "three", "two"]);
    }

    /// A store with no changes at all produces no segment.
    #[tokio::test]
    async fn log_records_on_an_empty_store_is_a_no_op() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let alice = create_resident(&rt, "alice").await;
        assert_eq!(log_records(&alice, &record_store(&rt, "alice"), "local").await.unwrap(), None);
    }

    /// The applier merges the rows the log carries into the store, creating the
    /// table from the registry, and is idempotent on re-run — the consumer half
    /// of the round trip, exercised as a peer's segment would deliver it.
    #[tokio::test]
    async fn apply_record_segments_merges_logged_rows_and_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let alice = create_resident(&rt, "alice").await;

        // The schema must be known so the applier can create the table.
        let (nsid, def) = notes_schema();
        schema_register(&rt, "alice", &serde_json::to_string(&def).unwrap())
            .await
            .unwrap();

        // Simulate replication delivering a peer's record segment: append the
        // sealed rows to the log directly, without touching the store.
        let mount = alice.get_remote("local").unwrap();
        let row = ChangesetRow {
            id: "rec-1".to_string(),
            schema_nsid: nsid.as_str().to_string(),
            body: json!({"title": "from a peer"}),
            updated_at: 100,
            revision: 0,
            deleted_at: None,
            root: None,
            filed_at: None,
        };
        mount
            .append_record_segment(&[serde_json::to_vec(&row).unwrap()])
            .await
            .unwrap();

        // Applying both creates the table (from the registry) and merges the
        // row — the query below can only succeed because the applier made the
        // table, which is the create-then-merge path under test.
        assert_eq!(apply_record_segments(&rt, &alice, &record_store(&rt, "alice"), "local").await.unwrap(), 1);
        let store = record_store(&rt, "alice");
        let recs = store.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].body["title"], "from a peer");

        // Re-applying does not error or double-insert (LWW idempotence).
        apply_record_segments(&rt, &alice, &record_store(&rt, "alice"), "local").await.unwrap();
        assert_eq!(store.query(&nsid, RecordFilter::new()).await.unwrap().len(), 1);
    }

    /// The producer and applier compose over the same log: a record inserted on
    /// one store is logged, and applying that log into a *second, empty* store
    /// materialises it — the round trip that record sync will run across
    /// devices, here with two stores sharing one mount's pack set.
    #[tokio::test]
    async fn a_logged_record_materialises_in_a_second_store() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let alice = create_resident(&rt, "alice").await;
        let (nsid, def) = notes_schema();
        schema_register(&rt, "alice", &serde_json::to_string(&def).unwrap())
            .await
            .unwrap();

        // "Device A": populate the store and log it.
        let store_a = record_store(&rt, "alice");
        store_a.create_table(&def).await.unwrap();
        store_a.insert(&nsid, json!({"title": "shared"})).await.unwrap();
        assert!(log_records(&alice, &record_store(&rt, "alice"), "local").await.unwrap().is_some());

        // "Device B": a fresh, empty record store over the same log. Applying
        // the log materialises A's record into it.
        let store_b = kotton_record::SqliteRecordStore::open(
            &temp.path().join("device-b-records.db"),
            None,
        )
        .unwrap();
        store_b.create_table(&def).await.unwrap();
        assert!(store_b.query(&nsid, RecordFilter::new()).await.unwrap().is_empty());

        let mount = alice.get_remote("local").unwrap();
        let logged: Vec<ChangesetRow> = mount
            .scan_record_segments()
            .await
            .unwrap()
            .into_iter()
            .flat_map(|s| s.rows)
            .map(|p| serde_json::from_slice::<ChangesetRow>(&p).unwrap())
            .collect();
        store_b.merge_changeset(logged).await.unwrap();

        let recs = store_b.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].body["title"], "shared");
    }

    /// `snapshot_records` collapses the accrued record segments
    /// into one current-state base (bounding the log a blind node cannot prune),
    /// and a fresh store rebuilt from the post-snapshot pack set reconstructs
    /// exactly that state — including a delete that must stay deleted.
    #[tokio::test]
    async fn snapshot_records_bounds_the_log_and_a_second_store_recovers() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let alice = create_resident(&rt, "alice").await;
        let (nsid, def) = notes_schema();
        schema_register(&rt, "alice", &serde_json::to_string(&def).unwrap())
            .await
            .unwrap();

        let store = record_store(&rt, "alice");
        store.create_table(&def).await.unwrap();

        // Two records, logged; then delete one, logged — several segments accrue,
        // and the deleted record leaves a tombstone in the current state.
        let id_a = store.insert(&nsid, json!({"title": "alpha"})).await.unwrap();
        store.insert(&nsid, json!({"title": "beta"})).await.unwrap();
        assert!(log_records(&alice, &record_store(&rt, "alice"), "local").await.unwrap().is_some());
        store.delete(&nsid, &id_a).await.unwrap();
        assert!(log_records(&alice, &record_store(&rt, "alice"), "local").await.unwrap().is_some());

        let mount = alice.get_remote("local").unwrap();
        assert!(
            mount.scan_record_segments().await.unwrap().len() >= 2,
            "at least two record segments accrued before the snapshot"
        );

        // keep_full = 0 subsumes every segment into one base. The base is the
        // current merged state: beta live, alpha a tombstone.
        let summary = snapshot_records(&rt, &alice, &record_store(&rt, "alice"), "local", 0)
            .await
            .unwrap()
            .expect("a logging mount snapshots");
        assert!(
            summary.segments_subsumed >= 2,
            "the accrued segments were subsumed, not left to grow"
        );
        assert_eq!(summary.records_captured, 2, "beta and alpha's tombstone");

        // L5 recovery: a fresh, empty store rebuilt purely from the pack set
        // reconstructs current state — beta present, the deleted alpha absent.
        // (LWW idempotence means it converges whether or not compaction has yet
        // reclaimed the subsumed segments the scan still physically sees.)
        let store_b = kotton_record::SqliteRecordStore::open(
            &temp.path().join("recovered-records.db"),
            None,
        )
        .unwrap();
        store_b.create_table(&def).await.unwrap();
        let base: Vec<ChangesetRow> = mount
            .scan_record_segments()
            .await
            .unwrap()
            .into_iter()
            .flat_map(|s| s.rows)
            .map(|p| serde_json::from_slice::<ChangesetRow>(&p).unwrap())
            .collect();
        store_b.merge_changeset(base).await.unwrap();

        let recs = store_b.query(&nsid, RecordFilter::new()).await.unwrap();
        assert_eq!(recs.len(), 1, "only the live record survives recovery");
        assert_eq!(recs[0].body["title"], "beta");
    }
    /// Article IX seals `sh.kotton.*`. The registry has always refused it, but as
    /// its *last* step — the migration ran first, so a proposal naming a core
    /// schema at a higher version altered every open store's table and was only
    /// then rejected, leaving tables migrated for a definition nothing accepted.
    #[tokio::test]
    async fn a_core_schema_is_refused_before_anything_is_migrated() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let _alice = create_resident(&rt, "alice").await;

        // Same NSID as the core schema, higher version — the shape that used to
        // reach `migrate_table`.
        let mut def = kotton_schemas::core::CoreSchema::Notes.definition();
        def.version = 99;
        let json = serde_json::to_string(&def).unwrap();

        let err = schema_register(&rt, "alice", &json)
            .await
            .expect_err("a core NSID must be refused");
        let msg = err.to_string();
        assert!(msg.contains("core schema"), "unhelpful error: {msg}");
        assert!(msg.contains("Article IX"), "the reason should say why: {msg}");

        // And the sealed definition is untouched.
        let reg = rt.schema_registry.read().unwrap();
        let live = reg.get(&def.nsid).expect("core schema still registered");
        assert_eq!(live.version, 1, "the core definition must not have moved");
    }

    /// A version upgrade migrates the caller's table and lands in the registry.
    /// Pins the fix for a latent bug: `SchemaRegistry::register` used to refuse
    /// any existing NSID, so an upgrade migrated the store's table and then
    /// failed to update the registry — tables moved, registry stale, caller got
    /// an error.
    #[tokio::test]
    async fn a_version_upgrade_migrates_and_updates_the_registry() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let _alice = create_resident(&rt, "alice").await;

        let nsid = Nsid::new("com.acme.upgradeable").unwrap();
        let v1 = SchemaDefinition::new(
            nsid.clone(),
            1,
            vec![SchemaField::required("title", FieldType::String)],
        );
        schema_register(&rt, "alice", &serde_json::to_string(&v1).unwrap())
            .await
            .unwrap();
        let store = record_store(&rt, "alice");
        store.create_table(&v1).await.unwrap();

        let v2 = SchemaDefinition::new(
            nsid.clone(),
            2,
            vec![
                SchemaField::required("title", FieldType::String),
                SchemaField::nullable("subtitle", FieldType::String),
            ],
        );
        schema_register(&rt, "alice", &serde_json::to_string(&v2).unwrap())
            .await
            .expect("an additive upgrade must succeed end to end");

        let reg = rt.schema_registry.read().unwrap();
        assert_eq!(
            reg.get(&nsid).unwrap().version,
            2,
            "the registry must carry the upgraded definition"
        );
    }

    /// The seal is narrow. A developer's own namespace is not gated at all —
    /// no approval, no allowlist — which is what makes reverse-domain NSIDs
    /// permissionless and lets an app declare and host its own schemas.
    #[tokio::test]
    async fn an_app_namespace_registers_freely() {
        let temp = TempDir::new().unwrap();
        let rt = make_runtime(&temp).await;
        let _alice = create_resident(&rt, "alice").await;

        let nsid = Nsid::new("com.acme.pinnable-note").unwrap();
        let def = SchemaDefinition::new(
            nsid.clone(),
            1,
            vec![SchemaField::required("title", FieldType::String)],
        );
        let json = serde_json::to_string(&def).unwrap();

        schema_register(&rt, "alice", &json)
            .await
            .expect("an app namespace needs no permission");

        let reg = rt.schema_registry.read().unwrap();
        assert!(reg.is_app(&nsid));
    }
}
