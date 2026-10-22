// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `app` domain's **daemon tier** — the IPC verbs, and the tables behind them.
//!
//! Moved here from `kuserd` 2026-08-21, following `org`, `grant` and `msg`.
//!
//! ## What had to happen first
//!
//! Unlike `grant`, this one was not free. `apps.rs` named three things from the
//! daemon: the event bus, `SurfaceProxy` (the `kuid` compositor client), and
//! `device/users.json`. [`apps::AppHost`] replaced all three, and the
//! compositor's best-effort failure model — RFC-0018's, spelled `.await.ok()`
//! at seven call sites — moved into the trait's return type where it is stated
//! once.
//!
//! A fourth blocker was smaller and stranger: `extension_registry_db` imported
//! `db_err` from `app_registry_db`, which read as a domain coupling and would
//! have become a cross-crate dependency for a two-line error mapper. It turned
//! out **seven** modules each defined their own copy.
//!
//! ## Tables, and the one that stayed
//!
//! `app_registry_db`, `role_db` and `handler_registry_db` come along, per the
//! rule `org` established: a domain's daemon tier owns its own tables. The
//! **migrations stay** with the daemon — one numbered sequence against one
//! database, and splitting a sequence across crates would make its ordering a
//! function of the dependency graph.
//!
//! `app_data_db` stayed behind at that move and was deleted on 2026-09-03. The
//! reasoning recorded here was right — the per-app isolation it described does
//! hold, via a path `apps.rs` builds inline, and what was stranded was its note
//! that `db_key` does nothing. What the note underrated is that the stranded
//! part was a *false security claim*, not a stale comment: the module said
//! isolation survived a bypassed capability check because "the key would be
//! wrong", and there was no key. `TASK-app-data-db-is-unreferenced` carries the
//! resolution; the corrected caveat lives on `open_app_data_pool`.
pub mod apps;
pub mod db;
/// Which app handles which nsid. Its table moved here with the crate; the
/// handler followed once it was the only thing left naming it from `kuserd`.
pub mod handlers_registry;
