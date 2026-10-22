// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-boot obscuring of durable identifiers in log output.
//!
//! The address store is deliberately ephemeral — in memory, TTL-evicted, and gone
//! on restart (see [`crate::store`]). Writing a DID into a log line puts a durable
//! copy of the same `(identity → address)` mapping into a stream that outlives the
//! store, is shipped to aggregators, and is retained by policy rather than by TTL.
//!
//! Article VII binds that: an operator "may not accumulate a record of user
//! behavior from the act of providing the service," and "no identifier it presents
//! shall be usable to join one disclosure to another." A log line naming a
//! permanent DID is exactly such a join.
//!
//! [`tag`] replaces the identifier with a short digest under a salt that is random
//! per process and never persisted, exposed, or logged. Within one relay lifetime
//! an operator can still follow a single device across its requests, which is what
//! debugging actually needs. Across restarts — and between any log line and a real
//! identity — the link is unrecoverable by anyone, the operator included.
//!
//! There is deliberately no way to configure the salt. A fixed salt would restore
//! cross-restart correlation, which is the property being removed.

use std::fmt;
use std::sync::OnceLock;

use rand::RngCore;
use sha2::{Digest, Sha256};

/// The per-process salt. Random, never persisted, never logged.
fn salt() -> &'static [u8; 32] {
    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    SALT.get_or_init(|| {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    })
}

/// A short, unlinkable stand-in for a durable identifier in a log line.
///
/// Rendered as 12 lowercase hex characters. Distinct within a process; meaningless
/// outside it.
pub struct Tag([u8; 6]);

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Obscure a durable identifier for logging.
///
/// Use this for anything that identifies a device or a user across requests — DIDs,
/// fingerprints, inbox owners. Do not log the raw value alongside it; a single line
/// carrying both defeats the point for every line that ever followed.
pub fn tag(id: &str) -> Tag {
    let mut hasher = Sha256::new();
    hasher.update(salt());
    hasher.update(id.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 6];
    out.copy_from_slice(&digest[..6]);
    Tag(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_id_tags_consistently_within_a_process() {
        let did = "did:key:z6MkfooBarBaz";
        assert_eq!(tag(did).to_string(), tag(did).to_string());
    }

    #[test]
    fn distinct_ids_tag_distinctly() {
        assert_ne!(
            tag("did:key:z6MkAAA").to_string(),
            tag("did:key:z6MkBBB").to_string()
        );
    }

    #[test]
    fn tag_does_not_contain_the_identifier() {
        let did = "did:key:z6MkfooBarBaz";
        let rendered = tag(did).to_string();
        assert!(!rendered.contains(did));
        assert!(!rendered.contains("z6Mk"));
    }

    #[test]
    fn tag_renders_as_twelve_hex_chars() {
        let rendered = tag("did:key:z6Mkanything").to_string();
        assert_eq!(rendered.len(), 12);
        assert!(rendered.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
