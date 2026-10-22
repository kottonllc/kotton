// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `app` domain's tables.
//!
//! Opened against the per-user agent database the daemon hands in, so these
//! take a pool rather than a path: *which* database is the daemon's decision
//! (RFC-0063 scopes it per user), and *what is in it* is this domain's.

/// Map a `sqlx` error to `io::Error`.
///
/// A local copy rather than a reach back into `kuserd`: this was one of seven
/// identical definitions across that crate's db modules, and the one
/// `extension_registry_db` happened to import — which is what made a two-line
/// helper look like a domain dependency when this crate was extracted.
pub(crate) fn db_err(e: sqlx::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

pub mod app_registry_db;
pub mod handler_registry_db;
pub mod role_db;
