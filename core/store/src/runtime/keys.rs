// SPDX-License-Identifier: AGPL-3.0-or-later
//! The leaf keys a user's storage stack is built from.
//!
//! These live in `store` because `store` is where sealing is *applied* — the
//! stack that [`crate::stack::build_local_store`] assembles is the thing they
//! configure, and the crates that can name key material are to be as few and
//! as obvious as possible. `key-reach-check`'s
//! allowlist is the mechanical form of that, and `core/store` is the entry it
//! is meant to end at.

use kotton_context::LogIdentity;

/// The leaf keys a user's storage stack needs, grouped so that adding one does
/// not rewrite every constructor call site.
///
/// Deliberately holds **derived** keys rather than the roots they come from:
/// `master_secret` is borrowed long enough to derive and then dropped, matching
/// how the record store already treats it (`get_or_create_record_store` fetches
/// it, derives a db key, and retains neither).
///
/// **No `Default`, deliberately.** A default-constructed `UserKeys` is *keyless*,
/// which is a real posture — a blind storage node — but reads at a call site as
/// "sensible defaults". Three separate test suites took it as the latter and
/// spent their lives validating unencrypted storage, including the persistence
/// test that calls itself the most important in the codebase. Every site must now
/// say which it means: [`UserKeys::keyless`] or [`UserKeys::new`] with a key.
#[derive(Clone)]
pub struct UserKeys {
    /// Content-encryption key — seals object contents.
    pub cek: Option<[u8; 32]>,
    /// Path-blinding key — blinds object keys.
    pub path_key: Option<[u8; 32]>,
    /// Who this node writes history as, and the key it seals it under.
    /// `None` on a node that appends no history.
    pub log: Option<LogIdentity>,
}

impl UserKeys {
    /// Build from the operational CEK. The path-blinding key is derived from
    /// the CEK — a path is object metadata, so it lives in the object domain,
    /// which also means a node needs nothing beyond
    /// the CEK it already holds to blind and read paths.
    pub fn new(cek: Option<[u8; 32]>) -> Self {
        Self {
            cek,
            path_key: cek
                .as_ref()
                .map(kotton_crypto::path_blind::derive_path_blind_key),
            log: None,
        }
    }

    /// Keys for a node that holds **none**.
    ///
    /// Two situations produce this, and they are not the same: a blind storage node or
    /// cosigner, keyless by design so it can hold a user's data without reading
    /// it; or a device whose keys are simply absent because
    /// it is locked. A runtime built this way refuses VFS content either way —
    /// see `SealedOnlyStorage` — and can move only material sealed elsewhere.
    ///
    /// Named rather than reached through `Default` so the choice is visible where
    /// it is made; see the note on [`UserKeys`] for what that cost before.
    pub fn keyless() -> Self {
        Self::new(None)
    }

    /// Enable history logging, deriving `K_log` from `master_secret`.
    ///
    /// Separate from [`new`] because the two roots are separate: `cek` is the
    /// object-domain root and `master_secret` the db-domain one, and a node can
    /// hold the first without the second. A blind storage node is exactly that node —
    /// it carries segments it cannot open, so it never calls this.
    ///
    /// `master_secret` is borrowed to derive and not retained, matching how the
    /// path key is handled beside it.
    ///
    /// [`new`]: Self::new
    pub fn with_log(mut self, writer_did: impl Into<String>, master_secret: &[u8; 32]) -> Self {
        self.log = Some(LogIdentity {
            writer_did: writer_did.into(),
            k_log: kotton_crypto::derive_history_log_key(master_secret),
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyless_derives_no_path_key() {
        let k = UserKeys::keyless();
        assert!(k.cek.is_none());
        assert!(k.path_key.is_none(), "no CEK means nothing to derive from");
        assert!(k.log.is_none());
    }

    #[test]
    fn a_cek_always_brings_a_path_key() {
        // The path key is derived from the CEK, so the two cannot
        // disagree about whether this node can blind. Half a pair is not a state
        // `new` can produce.
        let k = UserKeys::new(Some([7u8; 32]));
        assert!(k.path_key.is_some());
    }

    #[test]
    fn with_log_is_additive_and_leaves_the_object_domain_alone() {
        let before = UserKeys::new(Some([7u8; 32]));
        let after = before.clone().with_log("did:key:zWriter", &[9u8; 32]);
        assert_eq!(after.cek, before.cek);
        assert_eq!(after.path_key, before.path_key);
        assert_eq!(after.log.as_ref().unwrap().writer_did, "did:key:zWriter");
    }
}
