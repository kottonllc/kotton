// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `peer` domain's **daemon tier** — the fleet's IPC verbs and its tables.
//!
//! It is here, not in `kuserd`, by a criterion — `peer -> kotton-runtime ->
//! kotton-device -> kotton-peer` would be a cycle cargo refuses:
//!
//! > **A handler moves into its domain iff it names nothing from the runtime
//! > crate.**
//!
//! Three narrowings make that hold, each a correction rather than a cost:
//! dialing is [`crate::dialer::Dialer`], membership is
//! [`crate::membership::MemberStore`] (it is not the machine's — it is the
//! source of truth for principals admitted to *the user's network*), and
//! reading a sealed object is [`crate::pairing::SealedLocalRead`].
//!
//! The handler and its database module travel together: a domain crate
//! depending on `06_daemon` would invert the tier, and a table answers *"on
//! whose authority does this act?"* the same way its verbs do.
//!
//! ## What stayed in the daemon
//!
//! - **Three ceremony entry points** — `handle_device_add`, `handle_device_join`
//!   and `finalize_joined_node` — hold the daemon's `SessionMap`. They are the
//!   ceremony's plumbing: a spawned task, an mpsc channel to the client, and on
//!   join a minted session, because a joining device holds no mnemonic to log in
//!   with. The asymmetry with [`nodes::finalize_enrolled_node`], which moved, is
//!   real: **joining an existing identity issues a session; enrolling does not.**
//! - **The tests**, which build a runtime to make a user resident. Moving them
//!   would re-create the very cycle this escaped.
//!
//! Both follow once `agent::sessions` is consolidated into `core/session`.

pub mod db;
pub mod drives;
pub mod nodes;
