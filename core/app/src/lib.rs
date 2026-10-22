// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `app` domain — installed programs, and what they are allowed to be.
//!
//! An app is a confined WASM guest (RFC-0012, RFC-0068). This domain owns its
//! registration, the roles it may hold, which nsids it handles, and the
//! lifecycle of a running instance — launch, message, input, close.
//!
//! **It owns none of the confinement.** The sandbox is `wasm`'s, the grants
//! that bound a running app are `grant`'s, and the surface it draws on is
//! reached through a host trait rather than named. What is left here is the
//! question RFC-0080 asks of every domain: *on whose authority does this act?*
//! An app acts on **the authority the user delegated to it**, which is why
//! installation, roles and handler registration live together — they are all
//! answers to "what may this app be", and none of them is the app's own to
//! decide.
pub mod daemon;
pub mod extension_host;
pub mod extension_install;
pub mod fetch_session;
pub mod provision;
pub mod quarantine;
