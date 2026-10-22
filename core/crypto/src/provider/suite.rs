// SPDX-License-Identifier: AGPL-3.0-or-later
//! Concrete [`CryptoSuite`] implementations.
//!
//! ## Ed25519Suite
//!
//! Wraps the existing `ed25519_dalek` keypair + signer.  Deterministic
//! signing (RFC 8032).  32-byte public key.  Algorithm tag `"ed25519-v1"`.
//!
//! ## There is one suite, and the trait is the point
//!
//! An ML-DSA-65 suite and a cross-certification blob lived here until
//! 2026-08-26. They were removed, and what they were *for* stayed:
//! [`CryptoSuite`], `algorithm_id()` stamped into every persisted artifact, and
//! versioned HKDF labels. That trio is the migration handle — RFC-0001 and
//! RFC-0075 ID9 both name a versioned dispatch hook as the point where an
//! algorithm changes — and it costs nothing to keep.
//!
//! What the implementation cost is recorded in
//! `IDEA-the-post-quantum-path-is-built-beside-the-identity`: it could not be
//! adopted (the KEL's `KeyState` is 32 bytes of Ed25519, and an ML-DSA key is
//! 1952), it wrote files nothing read, it missed the `verify_strict` hardening
//! the live path got, and it held the whole workspace on a `0.1.0-rc.7`
//! dependency. Owner, 2026-08-26: *"We don't know the problems we're trying to
//! solve for right now anyway for post quantum. So I think we leave the seam,
//! so crypto changes and post quantum are easy."*
//!
//! `TestSuite` below keeps the seam honest. A trait with exactly one
//! implementation drifts into that implementation's assumptions — which is how
//! `KeyState` ended up 32 bytes wide — so the tests exercise the contract
//! against a second suite whose keys and signatures are deliberately the wrong
//! size for Ed25519.

use crate::ed25519::Ed25519Keypair;
use ed25519_dalek::{Signature as Ed25519Sig, Signer as _, SigningKey};
use kotton_sys::CryptoSuite;

// ── Library version tags ──────────────────────────────────────────────────────

/// Version fingerprint for the Ed25519 library.
///
/// Keep this in sync with `ed25519-dalek` in `Cargo.toml`.  The
/// `determinism_canary` test uses this tag as one of its assertions.
/// If the canary fails after a library bump, the upgrade is NOT a drop-in
/// replacement (see M25e upgrade protocol).
pub const ED25519_LIBRARY_TAG: &str = "ed25519-dalek@2.1.0";

// ── Ed25519Suite ──────────────────────────────────────────────────────────────

/// A [`CryptoSuite`] backed by a deterministic Ed25519 keypair.
///
/// The keypair is derived from the 32-byte seed on every method call.
/// Re-deriving is cheap and keeps the struct small (only the seed is stored).
#[derive(Clone)]
pub struct Ed25519Suite {
    seed: [u8; 32],
}

impl Ed25519Suite {
    /// Construct from a 32-byte seed (typically an HKDF output).
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

impl CryptoSuite for Ed25519Suite {
    fn algorithm_id(&self) -> &'static str {
        "ed25519-v1"
    }

    fn seed_bytes(&self) -> [u8; 32] {
        self.seed
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sk = self.signing_key();
        sk.sign(msg).to_bytes().to_vec()
    }

    fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Ed25519Sig::from_bytes(&sig_bytes);
        let vk = self.signing_key().verifying_key();
        // verify_strict rejects malleable / non-canonical signatures (audit).
        vk.verify_strict(msg, &sig).is_ok()
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let keygen = Ed25519Keypair::new();
        keygen
            .from_seed(&self.seed)
            .map(|(_, pk)| pk)
            .unwrap_or_default()
    }

    fn library_tag(&self) -> &'static str {
        ED25519_LIBRARY_TAG
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared contract tests that every CryptoSuite must satisfy.
    fn crypto_suite_contract<S: CryptoSuite>(suite: S) {
        let msg = b"kotton contract test message";

        // sign + verify round-trip
        let sig = suite.sign(msg);
        assert!(suite.verify(msg, &sig), "verify(sign(msg)) must be true");

        // wrong message fails
        assert!(!suite.verify(b"wrong message", &sig), "wrong msg must fail");

        // truncated signature fails
        assert!(!suite.verify(msg, &sig[..sig.len() / 2]));

        // empty signature fails
        assert!(!suite.verify(msg, &[]));

        // public key is non-empty
        let pk = suite.public_key_bytes();
        assert!(!pk.is_empty());

        // seed round-trip
        assert_eq!(suite.seed_bytes(), suite.seed_bytes());
    }

    #[test]
    fn ed25519_contract() {
        let seed = [7u8; 32];
        crypto_suite_contract(Ed25519Suite::new(seed));
    }

    #[test]
    fn ed25519_deterministic_keys() {
        let seed = [42u8; 32];
        let a = Ed25519Suite::new(seed);
        let b = Ed25519Suite::new(seed);
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_eq!(a.sign(b"msg"), b.sign(b"msg"));
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let a = Ed25519Suite::new([1u8; 32]);
        let b = Ed25519Suite::new([2u8; 32]);
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());

        let c = TestSuite::new([1u8; 32]);
        let d = TestSuite::new([2u8; 32]);
        assert_ne!(c.public_key_bytes(), d.public_key_bytes());
    }

    // ── M25e: Determinism canary ──────────────────────────────────────────────
    //
    // These tests pin the EXACT byte output produced by the current library
    // versions from a fixed seed.  They are the CI gate for crypto library
    // upgrades.
    //
    // If either test fails after a `Cargo.toml` bump, the upgrade is NOT a
    // drop-in replacement.  Follow the M25e upgrade protocol:
    //   1. Use the old library to decrypt / re-derive all data.
    //   2. Re-encrypt under the new key (HKDF label bump: v1 → v2).
    //   3. Only then merge the bump.
    //
    // To regenerate these expected values after an intentional migration:
    //   cargo test -p kotton-providers-crypto determinism_canary -- --nocapture
    // (temporarily remove the assert_eq! lines; add them back with new values)

    /// Fixed canary seed — never used for production keys.
    const CANARY_SEED: [u8; 32] = [0xc4u8; 32];
    /// Fixed canary message used for signature pinning.
    const CANARY_MSG: &[u8] = b"kotton-determinism-canary-v1";

    #[test]
    fn determinism_canary_ed25519() {
        let suite = Ed25519Suite::new(CANARY_SEED);

        // Pin the public key.
        let pk_hex = hex::encode(suite.public_key_bytes());

        // Pin the signature (Ed25519 is RFC-8032 deterministic).
        let sig_hex = hex::encode(suite.sign(CANARY_MSG));

        // Library tag must match the Cargo.toml entry.
        assert_eq!(suite.library_tag(), ED25519_LIBRARY_TAG);

        // ── Pinned values (ed25519-dalek 2.1.0) ─────────────────────────────
        // Regenerate by running this test with --nocapture if you intentionally
        // upgrade the library AND have completed the M25e migration procedure.
        assert_eq!(
            pk_hex, "dc517ff527e7bcfab067f2cc61bbef8e75f9ba8e1332ad3d42f8938e0045ed89",
            "ed25519 public key changed — library upgrade broke determinism"
        );
        assert_eq!(
            sig_hex,
            "078c554169bd613e78266f995f28fb231a2e18a94452683a13444120254d\
             63919de3f6c816f65b29c57dde3d2dd822ca89c5c8ea5b2c5e8062ff961b51310105",
            "ed25519 signature changed — library upgrade broke determinism"
        );
    }

    // ── M25e: CryptoSuite determinism contract ────────────────────────────────
    //
    // Generic determinism verifier.  Run for every CryptoSuite implementation.
    // Fails if: non-deterministic signing, non-canonical public key encoding,
    // or HKDF derivation from seed_bytes() produces different output.

    fn assert_suite_deterministic<S: CryptoSuite>(a: S, b: S) {
        // seed_bytes() must be identical
        assert_eq!(
            a.seed_bytes(),
            b.seed_bytes(),
            "seed_bytes() must be identical for same-seed instances"
        );

        // public_key_bytes() must be identical
        let pk_a = a.public_key_bytes();
        let pk_b = b.public_key_bytes();
        assert_eq!(
            pk_a, pk_b,
            "public_key_bytes() must be identical for same-seed instances"
        );

        // sign() must be identical (both suites use deterministic signing)
        let msg = b"kotton determinism contract";
        let sig_a = a.sign(msg);
        let sig_b = b.sign(msg);
        assert_eq!(
            sig_a, sig_b,
            "sign() must be identical for same-seed instances (non-determinism detected)"
        );

        // verify must accept the cross-instance signature
        assert!(
            a.verify(msg, &sig_b),
            "a.verify(msg, b.sign(msg)) must succeed — same seed, same key"
        );

        // HKDF derivation from seed_bytes() must be stable
        let derived_a = crate::kdf::derive_master_secret(&a.seed_bytes());
        let derived_b = crate::kdf::derive_master_secret(&b.seed_bytes());
        assert_eq!(
            derived_a, derived_b,
            "derive_master_secret(seed_bytes()) must be identical"
        );
    }

    #[test]
    fn ed25519_suite_is_fully_deterministic() {
        let seed = [0xdeu8; 32];
        assert_suite_deterministic(Ed25519Suite::new(seed), Ed25519Suite::new(seed));
    }

    #[test]
    fn test_suite_is_fully_deterministic() {
        let seed = [0xefu8; 32];
        assert_suite_deterministic(TestSuite::new(seed), TestSuite::new(seed));
    }

    /// A second suite, so the trait cannot quietly become Ed25519.
    ///
    /// This exists because of how `KeyState` went wrong. That struct holds
    /// `group_key: [u8; 32]` — the right size for exactly one algorithm — so the
    /// identity layer can rotate keys and cannot change algorithm, and nothing
    /// caught it, because there was never a second shape to fail against.
    ///
    /// So this one is deliberately the wrong size in both directions: a
    /// **48-byte** public key and a **96-byte** signature, neither of which is
    /// Ed25519's 32 and 64. Any `[u8; 32]`, any `signature.len() != 64`, any
    /// `try_into()` on a fixed array that creeps into the seam's callers fails
    /// here rather than three years from now.
    ///
    /// It is not cryptography and must never leave `#[cfg(test)]`. `sign` is a
    /// keyed BLAKE3 tag, which is enough to exercise the contract — sign,
    /// verify, reject a wrong message, reject a truncated signature — and
    /// nothing more.
    struct TestSuite {
        seed: [u8; 32],
    }

    impl TestSuite {
        fn new(seed: [u8; 32]) -> Self {
            Self { seed }
        }

        /// 96 bytes: three chained BLAKE3 blocks, so the length is unmistakably
        /// not a signature size any real suite here uses.
        fn tag(&self, msg: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(96);
            for round in 0u8..3 {
                let mut h = blake3::Hasher::new();
                h.update(&self.seed);
                h.update(&[round]);
                h.update(msg);
                out.extend_from_slice(h.finalize().as_bytes());
            }
            out
        }
    }

    impl CryptoSuite for TestSuite {
        fn algorithm_id(&self) -> &'static str {
            "test-only-v1"
        }
        fn seed_bytes(&self) -> [u8; 32] {
            self.seed
        }
        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            self.tag(msg)
        }
        fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
            signature.len() == 96 && self.tag(msg) == signature
        }
        /// 48 bytes — not 32, on purpose.
        fn public_key_bytes(&self) -> Vec<u8> {
            let mut h = blake3::Hasher::new();
            h.update(b"test-only-pk");
            h.update(&self.seed);
            let mut out = h.finalize().as_bytes().to_vec();
            out.truncate(32);
            out.extend_from_slice(&self.seed[..16]);
            out
        }
        fn library_tag(&self) -> &'static str {
            "test-only"
        }
    }

    #[test]
    fn test_suite_contract() {
        crypto_suite_contract(TestSuite::new([21u8; 32]));
    }

    /// The seam is only real if a suite may have a different shape.
    ///
    /// Stated as an assertion rather than a comment, because "the trait is
    /// algorithm-agnostic" is exactly the kind of claim that stays in a doc
    /// comment while the code stops honouring it.
    #[test]
    fn a_suite_need_not_have_ed25519_shaped_keys() {
        let ed = Ed25519Suite::new([5u8; 32]);
        let other = TestSuite::new([5u8; 32]);
        assert_eq!(ed.public_key_bytes().len(), 32);
        assert_eq!(ed.sign(b"m").len(), 64);
        assert_ne!(other.public_key_bytes().len(), ed.public_key_bytes().len());
        assert_ne!(other.sign(b"m").len(), ed.sign(b"m").len());
    }
}
