// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `identity` domain — who the user is, and how they prove it again after
//! losing a device.
//!
//! An identity is a DID and the key history behind it. It survives every device,
//! and Kotton has no identity authority to appeal to, so recovery lives here
//! rather than behind a support desk.
//!
//! ## What is deliberately *not* here
//!
//! Provisioning a user *on a device* — `create_user`, `logout_user`,
//! `login_with_recovery_key` — reads as identity work and is not. Those start
//! and stop a user's runtime, touch the device's own DID and routing table, and
//! mutate the registry of running users.
//! RFC-0054 assigns
//! that to `device`: *"the machine: sudoers, **user session lifecycle**, device
//! identity and name, daemon lifecycle"*. They stay in the runtime until a
//! `core/device` exists to receive them.
//!
//! The test that separates the two: these four functions need a base directory
//! and, for rotation, the secrets store. Nothing else. The three that stay need
//! the device's identity and the live runtime registry.

/// The Key Event Log — the append-only record of an identity's key history.
///
/// Moved here from `05_runtime` (RFC-0060). It was already pure: 63 lines of lib
/// over `kotton_crypto` and `kotton_wire`, with no `crate::` paths. A KEL is
/// identity material by definition, so this is the domain it names.
pub mod provisioning;
pub mod host;
pub mod kel_store;
pub mod recovery;
pub mod retired_keys;

/// The DID derived from a user's identity signing key in the keychain — the
/// value org rows record as `owner_did`. `None` when the key is absent (a locked
/// user, or a dev reset).
///
/// *Moved here from `kuserd`'s `db/user_db.rs` 2026-08-20.* It lived in a
/// database module and **touched no database** — it reads the keychain and
/// derives a DID, which is this domain's whole job. Its own doc there said "one
/// home for a helper that lived in two"; this is the home that was meant. Found
/// by RFC-0080 step 8's edge measurement, which listed it as one of exactly two
/// cross-domain calls standing between `org`'s handlers and their crate.
pub fn owner_did_for(
    user_id: &str,
    secrets: &dyn kotton_sys::secret::SecretsStore,
) -> Option<String> {
    let sk = identity_signing_key_for(user_id, secrets)?;
    Some(kotton_crypto::DidKeyMethod::from_public_key(&sk.verifying_key()).to_string())
}

/// The user's identity signing key from the keychain — the key [`owner_did_for`] names.
/// `None` when it is absent (a locked user, or a dev reset).
///
/// What a person signs with when they act under authority someone delegated to that DID:
/// admitting a member to a root under the org's `org.invite` (RFC-0088) signs the
/// membership grant with it, so the grant walks back to the delegation by key.
pub fn identity_signing_key_for(
    user_id: &str,
    secrets: &dyn kotton_sys::secret::SecretsStore,
) -> Option<ed25519_dalek::SigningKey> {
    let hex_key = secrets
        .get_secret(&kotton_common::crypto::kdf_labels::identity_signing_key(user_id))
        .ok()??;
    let key_bytes: [u8; 32] = hex::decode(&hex_key).ok()?.try_into().ok()?;
    Some(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
}

pub use host::ProvisioningHost;
