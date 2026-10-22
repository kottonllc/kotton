// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `org` domain's **daemon tier** — the IPC verbs, and the tables behind them.
//!
//! Moved here from `kuserd` 2026-08-20 as the first domain of RFC-0080 step 8,
//! and it establishes the pattern the other domains copy.
//!
//! ## Why the tables came too
//!
//! Step 8 originally read as "hoist the handlers", which understated it: every
//! handler reaches `kuserd`'s database layer, and a domain crate depending on
//! `06_daemon` would invert the tier. So a handler cannot move without its
//! tables, and the ruling that follows is **a domain's daemon tier owns its own
//! tables**. `org_identities`, `org_grants` and the FROST rows answer "on whose
//! authority does this act?" with *org's*, so they live here.
//!
//! Precedent: `kotton-record` already carries `SqliteRecordStore`. SQL in a
//! domain crate is not new; what is new is the table being owned by the domain
//! whose authority it records rather than by whoever happened to open the file.
//!
//! ## What deliberately stayed behind
//!
//! Two cross-domain calls stood between these handlers and this crate, and
//! neither belonged to `org`:
//!
//! - `owner_did_for` derived a DID from a keychain key while living in a
//!   *database* module and touching no database. It is `identity`'s, and moved
//!   there.
//! - Revoking a grant envelope is `grant`'s authority. [`orgs::org_member_remove`]
//!   was split so this tier reports **which** envelopes a member holds and the
//!   daemon revokes them — see [`orgs::org_member_envelope_ids`].
//!
//! Both were found by measuring the step's edges rather than its line counts,
//! and both are improvements that the move forced rather than costs it imposed.

pub mod db;
pub mod frost_orgs;
pub mod orgs;
