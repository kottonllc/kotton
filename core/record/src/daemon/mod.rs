// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `record` domain's daemon tier — the IPC verbs.
//!
//! What is here is the verb surface — insert, query, delete, open, search, and
//! the schema verbs beside them — and, since 2026-08-21, one table.
//!
//! `SqliteRecordStore` is already this crate's (`provider/`), and the per-user
//! *grant* checks these verbs run belong to `grant`, reached as a dependency.
//! What `db/` adds is `app_schemas`: the durable form of the schema registry, so
//! a registration survives a restart. It is here rather than in `kuserd` for the
//! reason `core/grant` gives — a handler cannot move without its tables, and a
//! domain crate reaching into `06_daemon` would invert the tier.
pub mod db;
pub mod import;
pub mod records;
