// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `grant` domain's **daemon tier** — the IPC verbs, and the tables behind them.
//!
//! Moved here from `kuserd` 2026-08-20, following the pattern `core/org`
//! established as the first domain of RFC-0080 step 8.
//!
//! ## Why the tables came too
//!
//! A handler cannot move without its tables: every one reaches `kuserd`'s
//! database layer, and a domain crate depending on `06_daemon` would invert the
//! tier. The ruling that follows is **a domain's daemon tier owns its own
//! tables** — `trusted_issuers`, the revocation list, the imported envelopes and
//! the schema grants all answer "on whose authority does this act?" with
//! *grant's*.
//!
//! ## What stayed in the daemon, and why that is not a compromise
//!
//! The **migrations** did. They are one numbered sequence against a single
//! per-user database, and splitting a sequence across crates would make its
//! ordering a function of the dependency graph. `core/org` left `0013` and
//! `0014` behind for the same reason. The split that matters is the one the org
//! module states: *which* database is the daemon's decision (RFC-0063 scopes it
//! per user), and *what is in it* is the domain's. So these functions take a
//! `SqlitePool` rather than a path.
//!
//! ## Why this domain was ready
//!
//! Both handlers were already at **zero** references to the runtime crate, and
//! both table modules named nothing from `kuserd` at all — only `kotton_wire`,
//! `kotton_common` and `sqlx`. RFC-0080 listed them as "free — but blocked on
//! `grant` not existing". This crate is that blocker removed; `apps.rs` imports
//! `grant_db` and could not follow its own domain until this existed.
pub mod db;
pub mod grants;
pub mod membership;
pub mod schema_grants;
