// SPDX-License-Identifier: AGPL-3.0-or-later
//! Algorithm-agnostic signing suite abstraction.
//!
//! [`CryptoSuite`] decouples the key-derivation hierarchy and the IPC layer
//! from any specific signature algorithm.  Today the only implementation is
//! `Ed25519Suite`.  When CRQC timelines warrant it, another suite drops in here
//! without touching the rest of the stack — that is what this trait is for, and
//! it is the whole of Kotton's post-quantum position
//! (`IDEA-the-post-quantum-path-is-built-beside-the-identity`).
//!
//! One caveat the trait cannot state for itself: the seam stops at the identity
//! layer. `kotton_wire::kel::KeyState` holds `group_key: [u8; 32]`, so the KEL
//! can rotate keys and cannot change algorithm. Adopting a suite with a
//! different key size means giving `KeyState` an algorithm first.
//!
//! # Invariants
//!
//! Every suite is parameterised by a 32-byte *seed*.  The seed is derived from
//! the user's BIP-39 mnemonic via `HKDF(mnemonic_seed32, label)` and is **never
//! stored on disk**.  The same seed always produces the same keypair, so the
//! suite is deterministic across restarts.
//!
//! HKDF info labels are versioned ("kotton:master:v1", "kotton:master:v2", …).
//! Bumping the label re-derives a completely different key without touching the
//! mnemonic, which is the correct migration handle for algorithm rotation.

/// A self-contained signing suite derived from a single 32-byte seed.
///
/// Implementations must be deterministic: given the same seed, `sign`,
/// `verify`, and `public_key_bytes` must produce consistent results.
///
/// # Thread safety
///
/// `CryptoSuite` requires `Send + Sync` so suites can be stored in shared
/// state across Tokio tasks.
pub trait CryptoSuite: Send + Sync {
    /// Short stable identifier written into every persisted artifact that
    /// contains material derived from this suite, e.g. `"ed25519-v1"` or
    /// `"ed25519-v1"`.
    ///
    /// Never changes for a given implementation.  Used by migration tooling
    /// to detect algorithm mismatches in stored files.
    fn algorithm_id(&self) -> &'static str;

    /// The 32-byte canonical seed from which all keys are derived.
    ///
    /// This is the HKDF output — **not** the raw mnemonic seed.  It is never
    /// stored; it is re-derived from the mnemonic at the start of each
    /// authenticated session.
    fn seed_bytes(&self) -> [u8; 32];

    /// Sign `msg` and return the raw signature bytes.
    ///
    /// The output format is algorithm-specific (64 bytes for Ed25519,
    /// ~3293 bytes for ML-DSA-65).  Callers that persist signatures must
    /// also persist the [`algorithm_id`][CryptoSuite::algorithm_id] so that
    /// the correct verifier can be selected on replay.
    fn sign(&self, msg: &[u8]) -> Vec<u8>;

    /// Return `true` iff `signature` is a valid signature over `msg`.
    ///
    /// Returns `false` (not an error) for any malformed input so callers do
    /// not need to distinguish "bad bytes" from "bad signature".
    fn verify(&self, msg: &[u8], signature: &[u8]) -> bool;

    /// The serialised public key in the algorithm's canonical byte format.
    ///
    /// - Ed25519: 32 bytes (compressed Ristretto point)
    /// - ML-DSA-65: 1952 bytes (FIPS 204 encoding)
    fn public_key_bytes(&self) -> Vec<u8>;

    /// The crate name and semver version that implements this suite.
    ///
    /// Format: `"<crate-name>@<version>"`, e.g. `"ed25519-dalek@2.1.0"`.
    ///
    /// This value is written into `device/identity.json` at key-generation time.
    /// On startup the daemon compares the stored tag with this constant and logs
    /// a warning if they differ — prompting the operator to run the determinism
    /// canary before serving any user data.  The determinism test is the actual
    /// gate; this field is an early-warning complement.
    ///
    /// **Maintenance rule:** update this constant in the concrete impl whenever
    /// the underlying library is bumped in `Cargo.toml`.  If the
    /// `determinism_canary` test fails after that bump the change is **not** a
    /// drop-in — treat it as a tier-3 algorithm change (M25e upgrade protocol).
    fn library_tag(&self) -> &'static str;
}
