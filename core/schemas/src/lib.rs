// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-schemas` — user record schema definitions for the Kotton data layer.
//!
//! This crate provides the vocabulary that apps and the daemon use to describe
//! structured user data. It is distinct from `kotton-wire`, which contains
//! IPC wire types.
//!
//! ## What lives here
//!
//! - [`SchemaId`] — a schema's identity, `<publisher>/<name>`: the `did:key` of the key that
//!   publishes it ([`Publisher`]) and its name under that key ([`SchemaName`]), as the
//!   protocol's decision *A schema is named by the key that publishes it* writes them
//! - [`SchemaDefinition`] — a revisioned, typed field declaration for a record table, with
//!   its digest ([`canonical`], RFC 8785, then BLAKE3) and its publisher's signature beside it
//! - [`AppId`] — an app's reverse-domain id, which is not a schema's identity
//! - [`CapabilityGrant`] — the minimum-surface access grants apps must declare
//! - [`CapabilitySet`] — a set of grants with `allows(kind, target)` checking
//! - [`core`] — the core set compiled into the daemon, the files under `schemas/kotton/`
//! - [`ModelManifest`] — a model as content, the body of a `model` record
//!
//! ## Layer rule
//!
/// This crate must never depend on `05_runtime` or higher. It sits at layer 01
/// below `kotton-wire` and is imported by everything above it.
pub mod app_id;
pub mod app_manifest;
pub mod canonical;
pub mod capability;
pub mod core;
pub mod definition;
pub mod extension_manifest;
pub mod field;
pub mod membership;
pub mod model_manifest;
pub mod petname;
pub mod record_url;
pub mod schema_id;

pub use app_id::{AppId, AppIdError};
pub use app_manifest::{
    app_signed_message, app_signed_message_for, canonical_manifest, manifest_digest, AppKind,
    AppManifest, CapabilityShape, ManifestCanonicalError, APP_SIGNATURE_DOMAIN,
    APP_SIGNED_MESSAGE_LEN,
};
pub use canonical::{canonical_json, CanonicalError};
pub use capability::{
    normalize_vfs_path, to_object_key, ApprovedCapabilities, CallDirection, CapabilityGrant,
    CapabilityKind, CapabilitySet, CapabilityTarget, ConsentSource, MediaDevice,
    MessageDirection,
};
pub use core::CoreSchema;
pub use definition::{DigestError, SchemaDefinition};
pub use extension_manifest::{
    CredentialSlot, ExtensionClass, ExtensionManifest, ExtensionManifestError,
    ExtensionPublisher, NetworkDeclaration,
};
pub use field::{FieldType, SchemaField};
pub use membership::{Ceremony, Member, Posture, Role};
pub use model_manifest::{Licence, ModelFormat, ModelKind, ModelManifest};
pub use petname::{Petname, PetnameError, Petnames};
pub use record_url::{RecordUrl, RecordUrlError};
pub use schema_id::{
    Publisher, PublisherError, SchemaId, SchemaIdError, SchemaName, SchemaNameError,
};
