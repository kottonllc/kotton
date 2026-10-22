// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daemon's implementation of [`SealedLocalRead`].
//!
//! Ephemeral pairing re-wraps per-path DEKs to a guest's session key, and to do
//! that it needs the **raw on-disk blob** — `[wrapped_dek:40][nonce:12][ciphertext]`
//! — rather than the plaintext the encryption layer would hand back. Reading
//! raw means naming a filesystem, and naming a filesystem means naming a host
//! OS.
//!
//! **That is the whole reason this type exists here.** `core/store` must not
//! name a host OS — it takes a `Filesystem` so a bare-metal
//! port stays a substitution rather than a rewrite — and `core/peer` names none
//! today either. The daemon is a consumer and legitimately knows what it is
//! running on, so `OsFilesystem` is supplied at this edge and nowhere below it.
//!
//! This is the same arrangement as [`crate::agent::file_host`]: *the trait
//! travels with the domain, the implementation stays with whoever can satisfy
//! it.*

use kotton_peer::pairing::SealedLocalRead;
use kotton_store::runtime::user::UserStore;

/// One user's store, presented as the one raw read ephemeral pairing needs.
///
/// Borrowed rather than owned, and scoped to a single user: the caller has
/// already resolved *which* user this request is for, so this type cannot reach
/// a second one.
pub struct DaemonSealedRead<'a> {
    pub store: &'a UserStore,
}

#[async_trait::async_trait]
impl SealedLocalRead for DaemonSealedRead<'_> {
    async fn read_sealed_local(&self, path: &str) -> Option<Vec<u8>> {
        self.store
            .read_raw_local_object(path, kotton_fs::OsFilesystem)
            .await
    }
}
