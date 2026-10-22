// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-schemas` — user record schema definitions for the Kotton data layer.
//!
//! This crate provides the vocabulary that apps and the daemon use to describe
//! structured user data. It is distinct from `kotton-wire`, which contains
//! IPC wire types.
//!
//! ## What lives here
//!
//! - [`Nsid`] — validated reverse-domain schema identifiers (`sh.kotton.notes`)
//! - [`SchemaDefinition`] — a versioned, typed field declaration for a record table
//! - [`CapabilityGrant`] — the minimum-surface access grants apps must declare
//! - [`CapabilitySet`] — a set of grants with `allows(kind, target)` checking
//! - [`core`] — the five standard schemas compiled into the daemon
//!
//! ## Layer rule
//!
/// This crate must never depend on `05_runtime` or higher. It sits at layer 01
/// below `kotton-wire` and is imported by everything above it.
pub mod app_manifest;
pub mod extension_manifest;
pub mod capability;
pub mod core;
pub mod definition;
pub mod field;
pub mod membership;
pub mod nsid;
pub mod record_url;

pub use app_manifest::{AppKind, AppManifest, CapabilityShape};
pub use extension_manifest::{
    CredentialSlot, ExtensionClass, ExtensionManifest, ExtensionManifestError, ExtensionPublisher,
    NetworkDeclaration,
};
pub use capability::{
    normalize_vfs_path, ApprovedCapabilities, CallDirection, CapabilityGrant, CapabilityKind,
    CapabilitySet, CapabilityTarget, ConsentSource, MediaDevice, MessageDirection, to_object_key,
};
pub use core::CoreSchema;
pub use definition::SchemaDefinition;
pub use field::{FieldType, SchemaField};
pub use membership::{Ceremony, Member, Posture, Role};
pub use nsid::{Nsid, NsidError};
pub use record_url::{RecordUrl, RecordUrlError};
