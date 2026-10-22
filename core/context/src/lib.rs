// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-user and per-device context — **data and handles, never behaviour**.
//!
//! RFC-0060
//! replaces the `UserRuntime` god-struct with this plus per-domain handles. It sits
//! below every domain so all of them may depend on it, which is only possible
//! because it references `sys` traits and `common` types and never a provider.
//!
//! ## The rule
//!
//! **This crate may hold data and handles. It may not hold behaviour.**
//!
//! A method here that does something to a domain is the god-struct arriving by a
//! different door. Accessors are fine; anything that reads a file, opens a store,
//! or signs an event is not.
//!
//! ## Key material
//!
//! `cek` and `path_key` are private. They are reached through
//! [`UserContext::sealing_keys`], so a reader can answer "what can touch the
//! user's key" by finding that call rather than reading every method on a
//! sixteen-thousand-line struct. Within one trusted process this is legibility
//! and discipline rather than enforcement — the honest claim, and still a large
//! improvement on a public field.

use std::path::{Path, PathBuf};

/// The identity a node writes history segments under (RFC-0046).
///
/// The DID is the **device's**, not the user's: segments are per-writer, every
/// device in a fleet is a distinct writer, and conflict detection resolves ties
/// on this value. Pairing the DID with the key makes "this node logs" one
/// representable state rather than two fields that can disagree.
#[derive(Clone)]
pub struct LogIdentity {
    pub writer_did: String,
    pub k_log: [u8; 32],
}

/// Everything a user's domains act upon, and nothing they do.
pub struct UserContext {
    user_id: String,
    did: String,
    base_dir: PathBuf,
    cek: Option<[u8; 32]>,
    path_key: Option<[u8; 32]>,
    log: Option<LogIdentity>,
}

/// The key material a sealing or opening domain needs.
///
/// Handed out as a unit because the two are derived together and a caller
/// holding one without the other cannot do anything correct with it.
#[derive(Clone, Copy)]
pub struct SealingKeys<'a> {
    pub cek: &'a [u8; 32],
    pub path_key: &'a [u8; 32],
}

impl UserContext {
    pub fn new(
        user_id: impl Into<String>,
        did: impl Into<String>,
        base_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            did: did.into(),
            base_dir: base_dir.into(),
            cek: None,
            path_key: None,
            log: None,
        }
    }

    /// Attach key material. Separate from [`Self::new`] because a
    /// `BlindStorage` legitimately has none (RFC-0036).
    pub fn with_keys(mut self, cek: Option<[u8; 32]>, path_key: Option<[u8; 32]>) -> Self {
        self.cek = cek;
        self.path_key = path_key;
        self
    }

    pub fn with_log(mut self, log: Option<LogIdentity>) -> Self {
        self.log = log;
        self
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Key material, for the domains that seal or open data.
    ///
    /// `None` on a node whose posture withholds it — a blind storage node holds
    /// ciphertext it cannot read, which is the point of the posture rather than
    /// a failure to configure one.
    pub fn sealing_keys(&self) -> Option<SealingKeys<'_>> {
        match (&self.cek, &self.path_key) {
            (Some(cek), Some(path_key)) => Some(SealingKeys { cek, path_key }),
            _ => None,
        }
    }

    /// The history-log writer identity, for the domains that append to it.
    pub fn log_identity(&self) -> Option<&LogIdentity> {
        self.log.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_context_without_keys_yields_none() {
        let ctx = UserContext::new("alice", "did:key:z6Mk", "/tmp/alice");
        assert!(ctx.sealing_keys().is_none());
        assert_eq!(ctx.user_id(), "alice");
    }

    /// Both keys or neither — a caller holding one cannot do anything correct.
    #[test]
    fn half_a_key_pair_is_not_sealing_material() {
        let ctx = UserContext::new("alice", "did:key:z6Mk", "/tmp/alice")
            .with_keys(Some([7u8; 32]), None);
        assert!(ctx.sealing_keys().is_none());
    }

    #[test]
    fn both_keys_present_yields_material() {
        let ctx = UserContext::new("alice", "did:key:z6Mk", "/tmp/alice")
            .with_keys(Some([7u8; 32]), Some([9u8; 32]));
        let keys = ctx.sealing_keys().expect("both present");
        assert_eq!(keys.cek[0], 7);
        assert_eq!(keys.path_key[0], 9);
    }
}
