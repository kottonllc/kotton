// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `grant` domain's tables.
//!
//! Opened against the per-user agent database the daemon hands in, so these
//! functions take a pool rather than a path: *which* database is the daemon's
//! decision (RFC-0063 scopes it per user), and *what is in it* is this domain's.
pub mod grant_db;
pub mod schema_grants_db;
