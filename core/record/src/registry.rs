// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory schema registry.
//!
//! The registry is the single authoritative source of truth for schema
//! definitions within a running daemon process.
//!
//! ## Lifecycle
//!
//! 1. **Construction** — [`SchemaRegistry::new`] populates the core Kotton
//!    schemas from [`kotton_schemas::core::CoreSchema::all()`].
//! 2. **Registration** — [`SchemaRegistry::register`] adds an app schema,
//!    recording the registering user as an owner.
//!
//! **This registry is in-memory, and a registration is no longer lost with it.**
//! It is rebuilt from the sealed core set at every start, and the user's own
//! registrations are put back on top: [`crate::daemon::records::schema_register`]
//! writes each accepted definition to the `app_schemas` table (migration `0004`)
//! and `kuserd`'s `hydrate_schema_registry` loads them when that user's database
//! opens. Closed by `TASK-custom-schemas-do-not-survive-a-restart`; re-measured
//! 2026-09-15 while building the `.ics` importer, which declares a shape at
//! import time and would otherwise write records nobody could read the next
//! morning.
//!
//! *This paragraph said the opposite until 2026-09-15 — "nothing reads or writes
//! it — measured 2026-08-16" — which was true when written and is the reason it
//! is dated here rather than stated flatly.* What is still one process-wide
//! registry rather than one per user is `IDEA-schema-registry-is-machine-wide`.
//!
//! **What does not travel is the declaration itself.** A registration lives in
//! *this device's* `app_schemas`, so a paired device that receives records of a
//! custom shape skips them until something declares it there too — see
//! `IDEA-imported-records-have-nowhere-to-say-where-they-came-from`.
//!
//! Core schemas (`sh.kotton.*`) are **sealed** — any attempt to register a
//! schema that conflicts with a core NSID returns [`SchemaError::CoreConflict`].
//!
//! ## Ownership
//!
//! App schemas record **which users registered them**, and the scoped accessors
//! ([`SchemaRegistry::list_for`], [`SchemaRegistry::get_for`]) answer for one
//! user: core schemas plus that user's own registrations. NSIDs are
//! reverse-domain app names, so an unscoped list is a readout of which apps the
//! other people on a machine run — the authority defect the scoping exists to
//! close. The unscoped [`get`](SchemaRegistry::get) and
//! [`list`](SchemaRegistry::list) remain for the daemon's own paths (table
//! creation during replication, record validation), which act on a store already
//! resolved to one user.

use std::collections::{HashMap, HashSet};

use kotton_schemas::{core::CoreSchema, definition::SchemaDefinition, nsid::Nsid};
use thiserror::Error;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// The NSID collides with a built-in core schema (sealed, cannot be overridden).
    #[error("schema '{0}' conflicts with a sealed core schema")]
    CoreConflict(String),

    /// The proposed version is lower than the one already registered.
    #[error("schema '{0}' is registered at version {1}, proposed version {2} is a downgrade")]
    Downgrade(String, u32, u32),

    /// The schema definition is structurally invalid.
    #[error("invalid schema: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, SchemaError>;

// ── SchemaRegistry ────────────────────────────────────────────────────────────

/// In-memory registry of schema definitions.
///
/// Thread-safety: `SchemaRegistry` is `Send + Sync` because both inner maps
/// contain only value types.  Concurrent mutation should be handled by the
/// caller (e.g. wrap in `tokio::sync::RwLock`).
pub struct SchemaRegistry {
    /// Built-in `sh.kotton.*` schemas — immutable after construction.
    core: HashMap<Nsid, SchemaDefinition>,
    /// App-supplied schemas, each carrying the users who registered it.
    app: HashMap<Nsid, AppSchema>,
}

/// An app-supplied schema and the users who registered it.
///
/// Owners are a set rather than a single user because two users on one machine
/// can install the same app; each registration joins the set, and the scoped
/// accessors answer for whoever is asking.
struct AppSchema {
    def: SchemaDefinition,
    owners: HashSet<String>,
}

impl SchemaRegistry {
    /// Create a new registry pre-populated with all six core Kotton schemas.
    ///
    /// # Core schemas
    ///
    /// | NSID | Version |
    /// |------|---------|
    /// | `sh.kotton.notes` | 1 |
    /// | `sh.kotton.contacts` | 1 |
    /// | `sh.kotton.calendar` | 1 |
    /// | `sh.kotton.messages` | 1 |
    /// | `sh.kotton.tasks` | 1 |
    /// | `sh.kotton.clipboard` | 1 |
    pub fn new() -> Self {
        let mut core = HashMap::new();
        for cs in CoreSchema::all() {
            let def = cs.definition();
            core.insert(def.nsid.clone(), def);
        }
        Self {
            core,
            app: HashMap::new(),
        }
    }

    /// Register an app-supplied schema on behalf of `owner`.
    ///
    /// - A new NSID is inserted with `owner` as its first owner.
    /// - The same version again joins `owner` to the owner set (idempotent for
    ///   a user who already registered it — the second-user-installs-the-same-app
    ///   case).
    /// - A higher version **replaces** the definition and joins `owner`. Callers
    ///   are responsible for validating the migration against the owner's store
    ///   first ([`crate::schema_cmds::schema_register`] does). An earlier version
    ///   of this method refused any existing NSID, so a version upgrade migrated
    ///   tables and then failed to update the registry.
    ///
    /// # Errors
    ///
    /// - [`SchemaError::CoreConflict`] if the NSID belongs to the `sh.kotton.*` namespace.
    /// - [`SchemaError::Downgrade`] if the proposed version is lower than the
    ///   registered one.
    pub fn register(&mut self, def: SchemaDefinition, owner: &str) -> Result<()> {
        let nsid = &def.nsid;
        if self.core.contains_key(nsid) {
            return Err(SchemaError::CoreConflict(nsid.as_str().to_owned()));
        }
        match self.app.get_mut(nsid) {
            None => {
                self.app.insert(
                    def.nsid.clone(),
                    AppSchema {
                        owners: HashSet::from([owner.to_owned()]),
                        def,
                    },
                );
            }
            Some(existing) if def.version < existing.def.version => {
                return Err(SchemaError::Downgrade(
                    nsid.as_str().to_owned(),
                    existing.def.version,
                    def.version,
                ));
            }
            Some(existing) => {
                if def.version > existing.def.version {
                    existing.def = def;
                }
                existing.owners.insert(owner.to_owned());
            }
        }
        Ok(())
    }

    /// Re-admit definitions loaded from storage, for `owner`.
    ///
    /// Not a loop over [`register`](Self::register), which applies the core-seal
    /// and version rules a stored row already passed. This is the restart path:
    /// rows were judged when they were first registered, and re-judging them
    /// from a partial view would drop a user's schemas for failing a check they
    /// already passed.
    ///
    /// **Nothing here can fail.** `forked_from` is provenance (schemas fork, they do
    /// not extend), so load order does not matter and an origin that no longer exists is
    /// ordinary rather than broken. The returned vector is the NSIDs that were
    /// dropped, and it is always empty — kept in the signature because the
    /// caller logs it and a future rule (a corrupt definition, say) would want
    /// somewhere to say so.
    pub fn load_persisted(
        &mut self,
        defs: impl IntoIterator<Item = SchemaDefinition>,
        owner: &str,
    ) -> Vec<String> {
        for def in defs {
            if self.core.contains_key(&def.nsid) {
                // A core NSID in app storage predates the seal or was written
                // by hand. The compiled-in definition wins, always.
                continue;
            }
            match self.app.get_mut(&def.nsid) {
                Some(existing) => {
                    if def.version > existing.def.version {
                        existing.def = def.clone();
                    }
                    existing.owners.insert(owner.to_owned());
                }
                None => {
                    self.app.insert(
                        def.nsid.clone(),
                        AppSchema {
                            owners: HashSet::from([owner.to_owned()]),
                            def,
                        },
                    );
                }
            }
        }

        Vec::new()
    }

    /// Look up a schema by NSID.
    ///
    /// Checks core schemas first, then app schemas. Unscoped — for the daemon's
    /// own paths, which act on a store already resolved to one user.
    pub fn get(&self, nsid: &Nsid) -> Option<&SchemaDefinition> {
        self.core.get(nsid).or_else(|| self.app.get(nsid).map(|a| &a.def))
    }

    /// Look up a schema by NSID **as `user`**: core schemas, or an app schema
    /// this user registered. Another user's registration answers `None`,
    /// indistinguishable from the schema not existing.
    pub fn get_for(&self, user: &str, nsid: &Nsid) -> Option<&SchemaDefinition> {
        self.core.get(nsid).or_else(|| {
            self.app
                .get(nsid)
                .filter(|a| a.owners.contains(user))
                .map(|a| &a.def)
        })
    }

    /// Return all registered schemas (core + app), in unspecified order.
    /// Unscoped — see [`get`](Self::get).
    pub fn list(&self) -> Vec<&SchemaDefinition> {
        self.core
            .values()
            .chain(self.app.values().map(|a| &a.def))
            .collect()
    }

    /// Return the schemas visible **to `user`**: core plus this user's own
    /// registrations, in unspecified order.
    pub fn list_for(&self, user: &str) -> Vec<&SchemaDefinition> {
        self.core
            .values()
            .chain(
                self.app
                    .values()
                    .filter(|a| a.owners.contains(user))
                    .map(|a| &a.def),
            )
            .collect()
    }

    /// Return the number of registered schemas.
    pub fn len(&self) -> usize {
        self.core.len() + self.app.len()
    }

    /// Return `true` if no schemas are registered (not possible in practice since
    /// the five core schemas are always present).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return `true` if `nsid` refers to a sealed core schema.
    pub fn is_core(&self, nsid: &Nsid) -> bool {
        self.core.contains_key(nsid)
    }

    /// Return `true` if `nsid` refers to an app-supplied schema.
    pub fn is_app(&self, nsid: &Nsid) -> bool {
        self.app.contains_key(nsid)
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::{
        definition::SchemaDefinition,
        field::{FieldType, SchemaField},
        nsid::Nsid,
    };

    /// `SchemaDefinition` carries no `PartialEq`, and deriving one on a shared
    /// type for a test's convenience is the wrong trade — compare the wire form.
    fn json(def: &SchemaDefinition) -> String {
        serde_json::to_string(def).expect("a definition serializes")
    }

    /// Build a minimal app schema for testing.
    fn app_schema(nsid: &str) -> SchemaDefinition {
        SchemaDefinition {
            nsid: Nsid::new(nsid).unwrap(),
            version: 1,
            fields: vec![SchemaField {
                name: "content".to_owned(),
                field_type: FieldType::String,
                nullable: false,
                default: None,
            }],
            forked_from: None,
            description: Some("Test app schema".to_owned()),
        }
    }

    // ── Initial state ─────────────────────────────────────────────────────

    /// A fresh registry holds the core set and nothing else.
    ///
    /// Counted against `CoreSchema::all()` rather than a literal. These four
    /// tests said `8`, `9`, `9` and `10` until 2026-09-16, when a ninth core
    /// schema (`sh.kotton.model`, RFC-0085) broke all four at once and none of
    /// them was about the number — every one is about *core, plus the app
    /// schemas this test registered*. A literal is a second copy of a fact that
    /// lives in another crate, and `core.rs`'s own test exists because that
    /// count had already drifted to three different values at once.
    #[test]
    fn new_registry_has_all_core_schemas() {
        let registry = SchemaRegistry::new();
        let core = CoreSchema::all().len();
        assert_eq!(registry.core.len(), core, "the core set, all of it");
        assert_eq!(
            registry.len(),
            core,
            "total should match core count before any app schemas"
        );
    }

    #[test]
    fn core_nsids_are_present() {
        let registry = SchemaRegistry::new();
        for nsid_str in [
            "sh.kotton.notes",
            "sh.kotton.contacts",
            "sh.kotton.calendar",
            "sh.kotton.messages",
            "sh.kotton.tasks",
            "sh.kotton.clipboard",
        ] {
            let nsid = Nsid::new(nsid_str).unwrap();
            assert!(
                registry.get(&nsid).is_some(),
                "missing core schema: {nsid_str}"
            );
            assert!(
                registry.is_core(&nsid),
                "{nsid_str} should be marked as core"
            );
        }
    }

    // ── register ──────────────────────────────────────────────────────────

    #[test]
    fn register_app_schema_succeeds() {
        let mut registry = SchemaRegistry::new();
        let def = app_schema("io.myapp.posts");
        registry.register(def, "alice").unwrap();
        assert_eq!(registry.len(), CoreSchema::all().len() + 1);
    }

    #[test]
    fn register_core_conflict_is_error() {
        let mut registry = SchemaRegistry::new();
        let def = app_schema("sh.kotton.notes");
        let err = registry.register(def, "alice").unwrap_err();
        assert!(
            matches!(err, SchemaError::CoreConflict(_)),
            "expected CoreConflict, got {err:?}"
        );
    }

    /// A second user registering the same schema joins the owner set — the
    /// two-users-install-the-same-app case — rather than erroring.
    #[test]
    fn register_same_schema_by_second_user_joins_owners() {
        let mut registry = SchemaRegistry::new();
        registry.register(app_schema("io.myapp.posts"), "alice").unwrap();
        registry.register(app_schema("io.myapp.posts"), "bob").unwrap();

        let nsid = Nsid::new("io.myapp.posts").unwrap();
        assert!(registry.get_for("alice", &nsid).is_some());
        assert!(registry.get_for("bob", &nsid).is_some());
        assert_eq!(
            registry.len(),
            CoreSchema::all().len() + 1,
            "one schema, two owners"
        );
    }

    /// A higher version replaces the definition. The old shape of `register`
    /// refused any existing NSID, so an upgrade migrated the store tables and
    /// then failed to update the registry.
    #[test]
    fn register_higher_version_replaces_definition() {
        let mut registry = SchemaRegistry::new();
        registry.register(app_schema("io.myapp.posts"), "alice").unwrap();

        let mut v2 = app_schema("io.myapp.posts");
        v2.version = 2;
        registry.register(v2, "alice").unwrap();

        let nsid = Nsid::new("io.myapp.posts").unwrap();
        assert_eq!(registry.get(&nsid).unwrap().version, 2);
    }

    #[test]
    fn register_downgrade_is_error() {
        let mut registry = SchemaRegistry::new();
        let mut v2 = app_schema("io.myapp.posts");
        v2.version = 2;
        registry.register(v2, "alice").unwrap();

        let err = registry
            .register(app_schema("io.myapp.posts"), "alice")
            .unwrap_err();
        assert!(
            matches!(err, SchemaError::Downgrade(_, 2, 1)),
            "expected Downgrade, got {err:?}"
        );
    }

    // ── get / list ────────────────────────────────────────────────────────

    // ── forked_from is provenance, and nothing enforces it (DEC-0027) ─────

    /// Build an app schema recording that it was forked from `origin`.
    fn fork_of(nsid: &str, origin: &str) -> SchemaDefinition {
        let mut def = app_schema(nsid);
        def.forked_from = Some(Nsid::new(origin).unwrap());
        def
    }

    #[test]
    fn a_fork_of_a_schema_that_does_not_exist_registers_fine() {
        // Under the old subtype model this was refused, because a child of a
        // missing parent was unreachable by query. A fork is reachable under its
        // own NSID, and an origin that has since been retired is ordinary.
        let mut registry = SchemaRegistry::new();
        registry
            .register(fork_of("com.test.orphan", "com.test.long-gone"), "alice")
            .expect("provenance is not a dependency");
        assert!(registry.get(&Nsid::new("com.test.orphan").unwrap()).is_some());
    }

    #[test]
    fn a_fork_can_name_itself_without_anything_hanging() {
        // Nothing walks the chain, so a loop in provenance is meaningless rather
        // than dangerous. The old cycle check existed to protect a walk that no
        // longer happens.
        let mut registry = SchemaRegistry::new();
        registry
            .register(fork_of("com.test.loop", "com.test.loop"), "alice")
            .expect("provenance is not traversed");
    }

    #[test]
    fn forking_a_core_schema_records_the_origin_and_changes_nothing_else() {
        let mut registry = SchemaRegistry::new();
        registry
            .register(fork_of("com.test.pinnable", "sh.kotton.notes"), "alice")
            .unwrap();

        let def = registry
            .get(&Nsid::new("com.test.pinnable").unwrap())
            .expect("registered");
        assert_eq!(
            def.forked_from.as_ref().map(|n| n.as_str()),
            Some("sh.kotton.notes"),
            "the origin is recorded so forks can be counted"
        );
    }

    #[test]
    fn load_order_does_not_matter() {
        // Storage has no order that respects provenance, and now it does not
        // need one: nothing is validated against anything else on load.
        let mut registry = SchemaRegistry::new();
        let dropped = registry.load_persisted(
            vec![
                fork_of("com.test.later", "com.test.earlier"),
                app_schema("com.test.earlier"),
            ],
            "alice",
        );
        assert!(dropped.is_empty());
        assert!(registry.get(&Nsid::new("com.test.later").unwrap()).is_some());
        assert!(registry.get(&Nsid::new("com.test.earlier").unwrap()).is_some());
    }

    #[test]
    fn a_load_keeps_a_fork_whose_origin_is_absent() {
        let mut registry = SchemaRegistry::new();
        let dropped =
            registry.load_persisted(vec![fork_of("com.test.kept", "com.test.gone")], "alice");
        assert!(dropped.is_empty(), "a retired origin is not a reason to drop records");
        assert!(registry.get(&Nsid::new("com.test.kept").unwrap()).is_some());
    }

    #[test]
    fn a_definition_persisted_as_extends_still_loads() {
        // The rename must not orphan rows already written to `app_schemas`.
        let json = r#"{"nsid":"com.test.legacy","version":1,
            "fields":[{"name":"content","type":"string","nullable":false}],
            "extends":"sh.kotton.notes"}"#;
        let def: SchemaDefinition = serde_json::from_str(json).expect("the alias reads it");
        assert_eq!(
            def.forked_from.as_ref().map(|n| n.as_str()),
            Some("sh.kotton.notes")
        );
    }

    #[test]
    fn a_load_never_overrides_a_core_schema() {
        // A core NSID sitting in app storage predates the seal or was written by
        // hand; the compiled-in definition wins.
        let mut registry = SchemaRegistry::new();
        let core_nsid = Nsid::new("sh.kotton.notes").unwrap();
        let before = json(registry.get(&core_nsid).expect("core schema present"));

        let mut impostor = app_schema("sh.kotton.notes");
        impostor.description = Some("not the real one".to_owned());
        let dropped = registry.load_persisted(vec![impostor], "alice");

        assert!(dropped.is_empty());
        assert_eq!(json(registry.get(&core_nsid).unwrap()), before);
    }

    #[test]
    fn loading_the_same_schema_for_a_second_user_joins_the_owners() {
        let mut registry = SchemaRegistry::new();
        registry.load_persisted(vec![app_schema("com.test.shared")], "alice");
        registry.load_persisted(vec![app_schema("com.test.shared")], "bob");

        let nsid = Nsid::new("com.test.shared").unwrap();
        assert!(registry.get_for("alice", &nsid).is_some());
        assert!(registry.get_for("bob", &nsid).is_some());
    }

    #[test]
    fn a_loaded_schema_answers_queries_the_way_a_registered_one_does() {
        // The point of the whole exercise: after a restart the registry must be
        // indistinguishable from one that never lost the registration.
        let mut restarted = SchemaRegistry::new();
        restarted.load_persisted(vec![app_schema("com.test.survivor")], "alice");

        let mut never_restarted = SchemaRegistry::new();
        never_restarted
            .register(app_schema("com.test.survivor"), "alice")
            .unwrap();

        let nsid = Nsid::new("com.test.survivor").unwrap();
        assert_eq!(
            json(restarted.get(&nsid).unwrap()),
            json(never_restarted.get(&nsid).unwrap())
        );
        assert_eq!(restarted.list_for("alice").len(), never_restarted.list_for("alice").len());
    }

    #[test]
    fn get_returns_app_schema_after_register() {
        let mut registry = SchemaRegistry::new();
        let def = app_schema("net.example.todos");
        registry.register(def.clone(), "alice").unwrap();

        let nsid = Nsid::new("net.example.todos").unwrap();
        let found = registry.get(&nsid).unwrap();
        assert_eq!(found.nsid.as_str(), "net.example.todos");
        assert_eq!(found.version, 1);
    }

    #[test]
    fn get_unknown_nsid_returns_none() {
        let registry = SchemaRegistry::new();
        let nsid = Nsid::new("io.unknown.schema").unwrap();
        assert!(registry.get(&nsid).is_none());
    }

    #[test]
    fn list_returns_all_schemas() {
        let mut registry = SchemaRegistry::new();
        registry.register(app_schema("org.test.alpha"), "alice").unwrap();
        registry.register(app_schema("org.test.beta"), "alice").unwrap();
        assert_eq!(registry.list().len(), CoreSchema::all().len() + 2);
    }

    // ── scoped accessors ──────────────────────────────────────────────────

    /// Another user's registration is invisible — same answer as a schema that
    /// does not exist, so the accessor discloses nothing either way.
    #[test]
    fn another_users_schema_is_indistinguishable_from_absent() {
        let mut registry = SchemaRegistry::new();
        registry.register(app_schema("io.myapp.posts"), "alice").unwrap();

        let nsid = Nsid::new("io.myapp.posts").unwrap();
        assert!(registry.get_for("bob", &nsid).is_none());
        assert!(
            registry
                .list_for("bob")
                .iter()
                .all(|d| d.nsid.as_str() != "io.myapp.posts"),
            "bob's list must not contain alice's registration"
        );
        // Core schemas are visible to everyone regardless.
        assert_eq!(registry.list_for("bob").len(), registry.core.len());
    }

    // ── JSON round-trip (for daemon DB persistence) ───────────────────────

    #[test]
    fn schema_definition_serializes_to_json_and_back() {
        let def = app_schema("io.myapp.notes");
        let json = serde_json::to_string(&def).expect("SchemaDefinition should serialize to JSON");
        let restored: SchemaDefinition =
            serde_json::from_str(&json).expect("JSON should deserialize back to SchemaDefinition");
        assert_eq!(restored.nsid.as_str(), "io.myapp.notes");
        assert_eq!(restored.version, def.version);
        assert_eq!(restored.fields.len(), def.fields.len());
    }
}
