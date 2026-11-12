// SPDX-License-Identifier: AGPL-3.0-or-later
//! App manifest — parsed from `manifest.toml`.
//!
//! An app manifest declares identity, version, handler registrations, and the
//! capability grants the app requires. The daemon presents grants to the user
//! before installation.
//!
//! ## Format
//!
//! ```toml
//! [app]
//! id = "com.acme.notes-pro"
//! name = "Notes Pro"
//! version = "1.0.0"
//! handler_for = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
//!
//! [capabilities]
//! "schema.read"  = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
//! "schema.write" = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
//! "files.read"   = ["/exports"]
//! "network.fetch" = []   # presence enables outbound network; value list is ignored
//! ```
//!
//! ## What the publisher signs
//!
//! A `[publisher]` block carries a `did` and a `signature`. The signature is over the
//! manifest and the code together: [`APP_SIGNATURE_DOMAIN`] (`kotton-app-v1`), one zero
//! byte, the BLAKE3 of the manifest's canonical form with `[publisher]` set aside
//! ([`canonical_manifest`]), and the BLAKE3 of `app.wasm`, 78 bytes
//! ([`app_signed_message`]). A signed manifest holds no key outside the types below: one that
//! does has no canonical form, and is not signed by its publisher. The daemon's check of the
//! signature is `kotton_app::app_signature`.

use std::collections::HashMap;

use crate::{
    capability::CapabilitySet, CallDirection, CapabilityGrant, CapabilityKind, CapabilityTarget,
    AppId, AppIdError, MediaDevice, MessageDirection, SchemaId, SchemaIdError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing an [`AppManifest`].
#[derive(Debug, Error)]
pub enum ManifestError {
    /// The TOML could not be deserialized.
    #[error("manifest TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// A capability key is not recognised.
    #[error("unknown capability key {0:?}; expected schema.read, schema.write, files.read, files.write, network.fetch, media.microphone, media.camera, media.screen, call.initiate, call.receive, messages.send, messages.receive, events.subscribe, or ui.custom")]
    UnknownCapabilityKey(String),

    /// A schema named under `capabilities` is not a schema identity.
    #[error("invalid schema identity {0:?}: {1}")]
    InvalidSchemaId(String, SchemaIdError),

    /// The app `id` field is not a valid app id.
    #[error("invalid app id {0:?}: {1}")]
    InvalidAppId(String, AppIdError),

    /// The `handler_for` list names something that is not a schema identity.
    #[error("invalid handler_for entry {0:?}: {1}")]
    InvalidHandlerSchema(String, SchemaIdError),
    /// The manifest claims to handle, or asks for `schema.read` or `schema.write` on, a schema
    /// kept from every app ([`crate::CoreSchema::is_kept_from_apps`]). Refused at parse, so at
    /// every install and sideload, rather than stored and refused later: an app that declared
    /// it would be installed holding a claim nothing will honour.
    #[error("{claim} names {schema}, which no app may claim: {refusal}")]
    KeptFromApps {
        /// Which declaration named it: `handler_for`, `schema.read` or `schema.write`.
        claim: &'static str,
        /// The schema it named.
        schema: SchemaId,
        /// The refusal the schema's own words give.
        refusal: String,
    },
    /// A `[[capabilities]]` entry named a resource kind this host does not know.
    ///
    /// An error rather than a skip: a host that silently ignored an unknown
    /// `type` would install the app, report success, and grant nothing — the
    /// failure mode where the user believes they approved something.
    #[error("capability shape '{0}' has unknown type '{1}' (expected \"vfs-tree\")")]
    UnknownShapeType(String, String),
    /// A `[[capabilities]]` entry used an access verb other than read/write.
    #[error("capability shape '{0}' has unknown access '{1}' (expected \"read\" or \"write\")")]
    UnknownShapeAccess(String, String),
    /// Two `[[capabilities]]` entries share an id, so a binding could not say
    /// which it meant.
    #[error("capability shape id '{0}' is declared twice")]
    DuplicateShapeId(String),
}

// ── Raw TOML shape ────────────────────────────────────────────────────────────

/// The manifest as written, and, with `[publisher]` set aside, the types its canonical form
/// is serialised through ([`canonical_manifest`]). So every field the parse reads is one the
/// canonical form writes, and a field left out of the TOML is left out of the form rather
/// than written as its default: what is signed is what was written.
#[derive(Debug, Deserialize, Serialize)]
struct RawManifest {
    app: RawApp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capabilities: Option<RawCapabilities>,
    /// Set aside: never under the canonical form, which the signature in it is over.
    #[serde(default, skip_serializing)]
    publisher: Option<RawPublisher>,
}

/// Both manifest forms, because both must parse.
///
/// `[capabilities]` — a table of `"shape.verb" = [targets]` — is what every
/// manifest in the tree uses and what every installed app carries on disk, so it
/// cannot stop working. `[[capabilities]]` is RFC-0021's ratified form, which
/// adds the words a consent prompt needs: a `label`, a `desc`, and an `id` the
/// author chose rather than one derived from position.
///
/// Untagged: TOML distinguishes a table from an array of tables, so serde picks
/// without a discriminator. A manifest using both is a manifest that parses as
/// one of them and silently drops the other, so it is rejected below.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum RawCapabilities {
    /// RFC-0021: `[[capabilities]]` with a shape per entry. Tried first —
    /// an empty `[capabilities]` table and an absent one are indistinguishable,
    /// and the flat form is the safe fallback.
    Shapes(Vec<RawShape>),
    /// The flat form: `"files.read" = ["/notes"]`.
    Flat(HashMap<String, Vec<String>>),
}

impl Default for RawCapabilities {
    fn default() -> Self {
        Self::Flat(HashMap::new())
    }
}

/// One `[[capabilities]]` entry.
#[derive(Debug, Deserialize, Serialize)]
struct RawShape {
    /// The author's name for this resource, e.g. `"home"`. Unique per manifest.
    id: String,
    /// What kind of resource. Only `vfs-tree` is understood today; anything else
    /// is a manifest error rather than a silent skip, so the vocabulary can grow
    /// without an old host quietly granting nothing and reporting success.
    #[serde(rename = "type")]
    kind: String,
    /// `["read"]`, `["write"]`, or both.
    access: Vec<String>,
    /// The path the author suggests. A default, never a requirement — the user
    /// binds it at install.
    default: String,
    /// A short name for a person, e.g. `"Notes storage"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// One sentence on what the app does there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    desc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPublisher {
    did: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawApp {
    id: String,
    name: String,
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handler_for: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
}

// ── Public types ──────────────────────────────────────────────────────────────
/// How the app process is managed at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AppKind {
    /// One-shot subprocess per message (default).
    #[default]
    Subprocess,
    /// Persistent subprocess kept alive across messages.
    LongLived,
}
/// Parsed app identity metadata.
#[derive(Debug, Clone)]
pub struct AppMeta {
    /// Reverse-domain app identifier: `com.acme.notes-pro`.
    pub id: AppId,
    /// Human-readable display name.
    pub name: String,
    /// Semver-like version string (stored as string, not parsed).
    pub version: String,
    /// The schemas this app registers as a handler for, by identity.
    pub handler_for: Vec<SchemaId>,
}

/// A parsed app manifest, ready for sandbox construction.
#[derive(Debug, Clone)]
pub struct AppManifest {
    /// App identity metadata.
    pub app: AppMeta,
    /// How the runtime process is managed.
    pub kind: AppKind,
    /// All capability grants the app declared. Enforced at the binding layer.
    pub capabilities: CapabilitySet,
    /// Shapes as the author declared them, empty when the flat form was used.
    ///
    /// Private to `vfs_shapes()`, which falls back to deriving them. Kept
    /// separate from `capabilities` because a shape carries what a grant cannot:
    /// which grants belong to the *same* resource, and what to call it.
    declared_shapes: Vec<CapabilityShape>,
    /// `true` if the app has declared the `network.fetch` capability.
    pub network_fetch: bool,
    /// `true` if the app has declared `media.microphone` capability.
    pub media_microphone: bool,
    /// `true` if the app has declared `media.camera` capability.
    pub media_camera: bool,
    /// `true` if the app has declared `media.screen` capability.
    pub media_screen: bool,
    /// `true` if the app has declared `call.initiate` capability.
    pub call_initiate: bool,
    /// `true` if the app has declared `call.receive` capability.
    pub call_receive: bool,
    /// `true` if the app has declared `messages.send` capability.
    pub messages_send: bool,
    /// `true` if the app has declared `messages.receive` capability.
    pub messages_receive: bool,
    /// `true` if the app declared `ui.custom` (`ui.custom = []`), asking to
    /// render its own surfaces as a confined component. Nothing reads this
    /// flag, and no host call checks the `Ui` grant it adds.
    pub ui_custom: bool,
    /// `true` if the app has declared the `events.subscribe` capability.
    pub events_subscribe: bool,
    /// `true` if the app has declared the `apps.launch` capability — the right
    /// to launch other installed apps as separate confined guests.
    pub apps_launch: bool,
    /// Publisher DID declared in the `[publisher]` section, if present.
    pub publisher_did: Option<String>,
    /// Publisher Ed25519 signature (base64), if present: over the message
    /// [`app_signed_message`] makes of the manifest's canonical form and the code's digest.
    pub publisher_signature: Option<String>,
}

/// One bindable resource an app declared — a *shape*, in RFC-0021's word.
///
/// RFC-0021 has the user bind a declared shape to a resource they choose, with
/// the manifest's value as a suggestion. That needs a name for the shape that
/// survives the user changing where it points, which a `CapabilityGrant` cannot
/// provide: a grant is `(kind, target)`, so moving the target makes it a
/// different grant and the daemon cannot tell a rebinding from a widening
/// ([`TASK-the-subset-rule-forbids-the-binding`]).
///
/// **The id is derived, not declared**, and that is a deliberate narrowing of
/// what that record proposed. It said the binding needed RFC-0021's
/// `[[capabilities]]` grammar with an explicit `id`. It does not: it needs a
/// stable *identity*, and the manifest already determines one. The grammar is
/// needed for `label` and `desc` — how a prompt reads — which is presentation,
/// not the security property. Separating those two turned a change touching
/// every installed manifest into one touching none.
///
/// [`TASK-the-subset-rule-forbids-the-binding`]: https://kotton.sh/records/TASK-the-subset-rule-forbids-the-binding
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityShape {
    /// Stable identity.
    ///
    /// Declared by the author in the `[[capabilities]]` form (`"home"`). Derived
    /// in the flat form as `vfs:<n>`, **with the targets sorted** —
    /// `capabilities` deserializes into a `HashMap` there, whose iteration order
    /// is not stable, and an id that moved between reads would silently rebind
    /// an app to a different resource on reinstall.
    pub id: String,
    /// What may be done here. One resource, possibly both kinds.
    ///
    /// Was a single `kind` until 2026-09-03, which made `files.read` and
    /// `files.write` on one path two shapes with two ids. RFC-0021 treats that
    /// as one resource with `access = ["read", "write"]`, which is also how a
    /// person thinks about it: you choose where your notes live once, not once
    /// for reading and again for writing.
    pub access: Vec<CapabilityKind>,
    /// The path the manifest suggested. A default, not a requirement.
    pub default_target: String,
    /// A short name for a person, e.g. `"Notes storage"`.
    ///
    /// `None` in the flat form, which has nowhere to put one. A prompt falls
    /// back to the path; a guest asking for its label gets the id.
    ///
    /// **Safe to hand a guest**, unlike the path: a label names the *shape*, is
    /// written by the app author, and is identical across every install, so two
    /// apps holding it have nothing to join on
    /// (`TASK-the-root-path-is-handed-to-the-guest`).
    pub label: Option<String>,
    /// One sentence on what the app does there, for the consent prompt.
    pub desc: Option<String>,
}

impl AppManifest {
    /// The VFS resources this app declared, as bindable shapes.
    ///
    /// From the `[[capabilities]]` entries when the manifest used that form —
    /// ids, labels and descriptions as the author wrote them. Otherwise derived
    /// from the flat form, one shape per distinct path, sorted so identity is a
    /// function of the manifest's content and not of a `HashMap` walk.
    pub fn vfs_shapes(&self) -> Vec<CapabilityShape> {
        if !self.declared_shapes.is_empty() {
            return self.declared_shapes.clone();
        }

        // Derived: group the flat form's grants by path, so one path with read
        // and write is one shape with both, not two shapes.
        let mut by_path: Vec<(String, Vec<CapabilityKind>)> = Vec::new();
        for grant in self.capabilities.iter() {
            let CapabilityTarget::Vfs { path } = &grant.target else {
                continue;
            };
            match by_path.iter_mut().find(|(p, _)| p == path) {
                Some((_, kinds)) => {
                    if !kinds.contains(&grant.kind) {
                        kinds.push(grant.kind.clone());
                    }
                }
                None => by_path.push((path.clone(), vec![grant.kind.clone()])),
            }
        }
        by_path.sort_by(|a, b| a.0.cmp(&b.0));

        by_path
            .into_iter()
            .enumerate()
            .map(|(i, (path, mut access))| {
                // Sort the kinds too: `allows` does not care, but a shape whose
                // access list reordered between reads would make the manifest's
                // rendering unstable for no reason.
                access.sort_by_key(|k| format!("{k:?}"));
                CapabilityShape {
                    id: format!("vfs:{i}"),
                    access,
                    default_target: path,
                    label: None,
                    desc: None,
                }
            })
            .collect()
    }
}

impl AppManifest {
    /// Parse an `AppManifest` from a TOML string.
    pub fn from_toml(src: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = toml::from_str(src)?;

        // Validate app id
        let id = AppId::new(&raw.app.id)
            .map_err(|e| ManifestError::InvalidAppId(raw.app.id.clone(), e))?;

        // Validate handler_for entries
        let handler_for = raw
            .app
            .handler_for
            .unwrap_or_default()
            .iter()
            .map(|s| SchemaId::parse(s).map_err(|e| ManifestError::InvalidHandlerSchema(s.clone(), e)))
            .collect::<Result<Vec<_>, _>>()?;
        for schema in &handler_for {
            refuse_if_kept("handler_for", schema)?;
        }

        let meta = AppMeta {
            id,
            name: raw.app.name,
            version: raw.app.version,
            handler_for,
        };

        let kind = match raw.app.kind.as_deref() {
            Some("long-lived") => AppKind::LongLived,
            _ => AppKind::Subprocess,
        };

        // Build capability grants from the capabilities table
        let mut grants: Vec<CapabilityGrant> = Vec::new();
        let mut network_fetch = false;
        let mut media_microphone = false;
        let mut media_camera = false;
        let mut media_screen = false;
        let mut call_initiate = false;
        let mut call_receive = false;
        let mut messages_send = false;
        let mut messages_receive = false;
        let mut ui_custom = false;
        let mut events_subscribe = false;
        let mut apps_launch = false;

        // `[[capabilities]]` entries, if the manifest used that form. Turned
        // into the same grants the flat form produces, so everything downstream
        // — checks, envelopes, the linker — sees one vocabulary.
        let mut declared_shapes: Vec<CapabilityShape> = Vec::new();
        let flat = match &raw.capabilities.unwrap_or_default() {
            RawCapabilities::Flat(map) => map.clone(),
            RawCapabilities::Shapes(shapes) => {
                for shape in shapes {
                    if shape.kind != "vfs-tree" {
                        return Err(ManifestError::UnknownShapeType(
                            shape.id.clone(),
                            shape.kind.clone(),
                        ));
                    }
                    if declared_shapes.iter().any(|s| s.id == shape.id) {
                        return Err(ManifestError::DuplicateShapeId(shape.id.clone()));
                    }
                    let mut access = Vec::new();
                    for verb in &shape.access {
                        let kind = match verb.as_str() {
                            "read" => CapabilityKind::Read,
                            "write" => CapabilityKind::Write,
                            other => {
                                return Err(ManifestError::UnknownShapeAccess(
                                    shape.id.clone(),
                                    other.to_owned(),
                                ))
                            }
                        };
                        grants.push(CapabilityGrant::vfs(kind.clone(), &shape.default));
                        access.push(kind);
                    }
                    declared_shapes.push(CapabilityShape {
                        id: shape.id.clone(),
                        access,
                        default_target: shape.default.clone(),
                        label: shape.label.clone(),
                        desc: shape.desc.clone(),
                    });
                }
                HashMap::new()
            }
        };

        for (key, values) in &flat {
            match key.as_str() {
                "schema.read" => {
                    for id_str in values {
                        let id = SchemaId::parse(id_str)
                            .map_err(|e| ManifestError::InvalidSchemaId(id_str.clone(), e))?;
                        refuse_if_kept("schema.read", &id)?;
                        grants.push(CapabilityGrant::schema(CapabilityKind::Read, id));
                    }
                }
                "schema.write" => {
                    for id_str in values {
                        let id = SchemaId::parse(id_str)
                            .map_err(|e| ManifestError::InvalidSchemaId(id_str.clone(), e))?;
                        refuse_if_kept("schema.write", &id)?;
                        grants.push(CapabilityGrant::schema(CapabilityKind::Write, id));
                    }
                }
                "files.read" => {
                    for path in values {
                        grants.push(CapabilityGrant::vfs(CapabilityKind::Read, path));
                    }
                }
                "files.write" => {
                    for path in values {
                        grants.push(CapabilityGrant::vfs(CapabilityKind::Write, path));
                    }
                }
                // Action capabilities (H1): emit a `Use`-kind grant into the set so
                // they are minted into the signed GrantEnvelope (signature + expiry)
                // and become revocable — the same path as schema/VFS. The booleans
                // remain the enforcement point until H1 slice 2 routes the host
                // functions through `check_grant`.
                "network.fetch" => {
                    network_fetch = true;
                    grants.push(CapabilityGrant::action(CapabilityTarget::Network));
                }
                "media.microphone" => {
                    media_microphone = true;
                    grants.push(CapabilityGrant::media(MediaDevice::Microphone));
                }
                "media.camera" => {
                    media_camera = true;
                    grants.push(CapabilityGrant::media(MediaDevice::Camera));
                }
                "media.screen" => {
                    media_screen = true;
                    grants.push(CapabilityGrant::media(MediaDevice::Screen));
                }
                "call.initiate" => {
                    call_initiate = true;
                    grants.push(CapabilityGrant::call(CallDirection::Initiate));
                }
                "call.receive" => {
                    call_receive = true;
                    grants.push(CapabilityGrant::call(CallDirection::Receive));
                }
                "messages.send" => {
                    messages_send = true;
                    grants.push(CapabilityGrant::messages(MessageDirection::Send));
                }
                "messages.receive" => {
                    messages_receive = true;
                    grants.push(CapabilityGrant::messages(MessageDirection::Receive));
                }
                "events.subscribe" => {
                    events_subscribe = true;
                    grants.push(CapabilityGrant::action(CapabilityTarget::Events));
                }
                "apps.launch" => {
                    apps_launch = true;
                    grants.push(CapabilityGrant::action(CapabilityTarget::AppLaunch));
                }
                "ui.custom" => {
                    ui_custom = true;
                    grants.push(CapabilityGrant::action(CapabilityTarget::Ui));
                }
                // RFC-0085. No boolean beside it, deliberately: the flags above
                // are the pre-RFC-0068 enforcement point that `check_grant` is
                // replacing, and a new one would be a second reading of the same
                // declaration for something to disagree with later. The grant in
                // the set is the whole declaration, and
                // `DeclaredInterfaces::from` is what reads it.
                "infer.run" => {
                    grants.push(CapabilityGrant::action(CapabilityTarget::Infer));
                }
                other => {
                    return Err(ManifestError::UnknownCapabilityKey(other.to_owned()));
                }
            }
        }

        let (publisher_did, publisher_signature) = match raw.publisher {
            Some(p) => (Some(p.did), Some(p.signature)),
            None => (None, None),
        };

        Ok(AppManifest {
            declared_shapes,
            app: meta,
            kind,
            capabilities: CapabilitySet::new(grants),
            network_fetch,
            media_microphone,
            media_camera,
            media_screen,
            call_initiate,
            call_receive,
            messages_send,
            messages_receive,
            ui_custom,
            events_subscribe,
            apps_launch,
            publisher_did,
            publisher_signature,
        })
    }

    /// The app's reverse-domain identifier.
    pub fn app_id(&self) -> &str {
        self.app.id.as_str()
    }
}

/// [`ManifestError::KeptFromApps`] if `schema` is kept from every app, naming the declaration
/// that named it.
fn refuse_if_kept(claim: &'static str, schema: &SchemaId) -> Result<(), ManifestError> {
    match crate::CoreSchema::kept_from_apps(&schema.to_string()) {
        Some(kept) => Err(ManifestError::KeptFromApps {
            claim,
            schema: schema.clone(),
            refusal: kept.kept_from_apps_refusal(),
        }),
        None => Ok(()),
    }
}

// ── What the publisher signs ──────────────────────────────────────────────────

/// The tag an app's publisher signature opens its message with: the signed message is these
/// 13 ASCII bytes, one zero byte, the 32-byte digest of the manifest's canonical form
/// ([`manifest_digest`]), and the 32-byte BLAKE3 of the app's code (`app.wasm`), 78 bytes
/// in all ([`app_signed_message`]). The tag says what the signature is the publisher's word
/// for, so a signature the same key makes for anything else (a schema's, under
/// `kotton-schema-v1`, or 32 bytes of code digest alone) is not an app's. The `v1` is the
/// message's form, not an app's version.
pub const APP_SIGNATURE_DOMAIN: &[u8; 13] = b"kotton-app-v1";

/// The length of an app's signed message: the tag, one zero byte, and two 32-byte digests.
pub const APP_SIGNED_MESSAGE_LEN: usize = 13 + 1 + 32 + 32;

/// Why a manifest has no canonical form, and so cannot carry a publisher's signature.
#[derive(Debug, Error)]
pub enum ManifestCanonicalError {
    /// The TOML does not parse, or does not parse as the manifest's types.
    #[error("manifest TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    /// The manifest holds a key its types do not: it would be read past the signature, so
    /// the manifest has no canonical form.
    #[error("the manifest's `{key}` is not a key of an app manifest, so the manifest has no canonical form and is not signed by its publisher")]
    KeyOutsideTypes {
        /// Where the key is, as a dotted TOML path (`app.role`).
        key: String,
    },
    /// A value the manifest's types write otherwise than the TOML holds it.
    #[error("the manifest's `{key}` is not written as an app manifest's types write it, so the manifest has no canonical form and is not signed by its publisher")]
    ValueDiffers {
        /// Where the value is, as a dotted TOML path.
        key: String,
    },
    /// The types' serialisation has no RFC 8785 form (a number that is not an exact integer).
    #[error("{0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
}

impl ManifestCanonicalError {
    /// The key the manifest does not canonicalise at, when one is to blame.
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::KeyOutsideTypes { key } | Self::ValueDiffers { key } => Some(key),
            Self::Toml(_) | Self::Canonical(_) => None,
        }
    }
}

/// The manifest's canonical form: what its publisher's signature covers of it.
///
/// The TOML is read as a generic table and `[publisher]` is set aside. What remains is read
/// through the manifest's own types and written back as the JSON they serialise to, in the
/// form RFC 8785 gives (the one a schema's definition is digested in, [`crate::canonical`],
/// with its refusal of numbers that are not exact integers). The table and the types' JSON
/// must then be the same: a key the types lack, or a value they write otherwise, means the
/// manifest has no canonical form, and the error names the key. So nothing a reader could
/// find in a signed manifest lies outside what was signed. Order and whitespace in the TOML
/// do not reach the form, and neither does how a string was quoted.
///
/// A manifest that carries no signature never needs this: [`AppManifest::from_toml`] still
/// parses one with a key outside its types, and drops the key.
pub fn canonical_manifest(manifest_toml: &str) -> Result<String, ManifestCanonicalError> {
    let mut table: toml::Table = toml::from_str(manifest_toml)?;
    table.remove("publisher");
    let written = serde_json::to_value(&table)
        .map_err(|_| ManifestCanonicalError::ValueDiffers { key: "(the manifest)".to_owned() })?;
    let typed: RawManifest = toml::Value::Table(table).try_into()?;
    let typed = serde_json::to_value(&typed).expect("the manifest's types serialise to JSON");
    if let Some(e) = first_difference(&written, &typed, &mut String::new()) {
        return Err(e);
    }
    Ok(crate::canonical::canonical_json(&typed)?)
}

/// BLAKE3 over the manifest's canonical form ([`canonical_manifest`]).
pub fn manifest_digest(manifest_toml: &str) -> Result<[u8; 32], ManifestCanonicalError> {
    Ok(*blake3::hash(canonical_manifest(manifest_toml)?.as_bytes()).as_bytes())
}

/// The message an app's publisher signs: [`APP_SIGNATURE_DOMAIN`], one zero byte, the
/// manifest's digest ([`manifest_digest`]), and the code's digest (BLAKE3 of `app.wasm`).
pub fn app_signed_message(manifest_digest: &[u8; 32], code_digest: &[u8; 32]) -> [u8; APP_SIGNED_MESSAGE_LEN] {
    let mut m = [0u8; APP_SIGNED_MESSAGE_LEN];
    m[..13].copy_from_slice(APP_SIGNATURE_DOMAIN);
    m[14..46].copy_from_slice(manifest_digest);
    m[46..].copy_from_slice(code_digest);
    m
}

/// The message an app's publisher signs for `manifest_toml` and its code, `code`
/// ([`app_signed_message`] over [`manifest_digest`] and BLAKE3 of `code`).
pub fn app_signed_message_for(
    manifest_toml: &str,
    code: &[u8],
) -> Result<[u8; APP_SIGNED_MESSAGE_LEN], ManifestCanonicalError> {
    Ok(app_signed_message(&manifest_digest(manifest_toml)?, blake3::hash(code).as_bytes()))
}

/// The first place `written` (the TOML as a table) and `typed` (the types' serialisation of
/// it) part, as the error that names it; `None` when they are the same.
fn first_difference(
    written: &serde_json::Value,
    typed: &serde_json::Value,
    path: &mut String,
) -> Option<ManifestCanonicalError> {
    use serde_json::Value;
    match (written, typed) {
        (Value::Object(w), Value::Object(t)) => {
            let mut keys: Vec<&String> = w.keys().chain(t.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let len = path.len();
                push_key(path, key);
                let found = match (w.get(key), t.get(key)) {
                    (Some(_), None) => Some(ManifestCanonicalError::KeyOutsideTypes { key: path.clone() }),
                    (Some(w), Some(t)) => first_difference(w, t, path),
                    (None, _) => Some(ManifestCanonicalError::ValueDiffers { key: path.clone() }),
                };
                if found.is_some() {
                    return found;
                }
                path.truncate(len);
            }
            None
        }
        (Value::Array(w), Value::Array(t)) if w.len() == t.len() => {
            for (i, (w, t)) in w.iter().zip(t).enumerate() {
                let len = path.len();
                path.push_str(&format!("[{i}]"));
                if let Some(found) = first_difference(w, t, path) {
                    return Some(found);
                }
                path.truncate(len);
            }
            None
        }
        (w, t) if w == t => None,
        _ => Some(ManifestCanonicalError::ValueDiffers { key: path.clone() }),
    }
}

/// `key` appended to a dotted TOML path, quoted when it is not a bare key.
fn push_key(path: &mut String, key: &str) {
    if !path.is_empty() {
        path.push('.');
    }
    let bare = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        path.push_str(key);
    } else {
        path.push_str(&serde_json::Value::String(key.to_owned()).to_string());
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityTarget;

    /// A manifest that claims to handle, or asks to read or write, a schema kept from apps is
    /// refused by name, for `secret`, `access-log` and `petname`; the same manifest naming notes
    /// parses.
    #[test]
    fn a_manifest_naming_a_schema_kept_from_apps_is_refused() {
        use kotton_common::namespace::{NSID_ACCESS_LOG, NSID_NOTES, NSID_PETNAME, NSID_SECRET};
        for kept in [NSID_SECRET, NSID_ACCESS_LOG, NSID_PETNAME] {
            for (claim, body) in [
                ("handler_for", format!("handler_for = [\"{kept}\"]\n\n[capabilities]\n")),
                ("schema.read", format!("\n[capabilities]\n\"schema.read\" = [\"{kept}\"]\n")),
                ("schema.write", format!("\n[capabilities]\n\"schema.write\" = [\"{kept}\"]\n")),
            ] {
                let toml = format!("[app]\nid = \"com.example.keys\"\nname = \"Keys\"\nversion = \"1.0.0\"\n{body}");
                let err = AppManifest::from_toml(&toml).expect_err("a kept schema is refused");
                let said = err.to_string();
                assert!(matches!(err, ManifestError::KeptFromApps { .. }), "{claim}: {said}");
                assert!(said.contains(claim) && said.contains(kept), "{said}");
            }
        }
        let toml = format!(
            "[app]\nid = \"com.example.notes\"\nname = \"N\"\nversion = \"1.0.0\"\nhandler_for = [\"{NSID_NOTES}\"]\n\n[capabilities]\n\"schema.read\" = [\"{NSID_NOTES}\"]\n"
        );
        AppManifest::from_toml(&toml).expect("notes is any app's to ask for");
    }

    const EXAMPLE: &str = r#"
[app]
id = "com.acme.notes-pro"
name = "Notes Pro"
version = "1.0.0"
handler_for = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]

[capabilities]
"schema.read"  = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
"schema.write" = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
"files.read"   = ["/exports"]
"#;

    #[test]
    fn parse_example() {
        let m = AppManifest::from_toml(EXAMPLE).unwrap();
        assert_eq!(m.app_id(), "com.acme.notes-pro");
        assert_eq!(m.app.name, "Notes Pro");
        assert_eq!(m.app.version, "1.0.0");
        assert_eq!(m.app.handler_for.len(), 1);
        assert_eq!(m.app.handler_for[0].to_string(), "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes");
        assert!(!m.network_fetch);
        assert_eq!(m.capabilities.len(), 3);
        assert!(m.publisher_did.is_none());
        assert!(m.publisher_signature.is_none());
    }

    #[test]
    fn capability_set_allows() {
        let m = AppManifest::from_toml(EXAMPLE).unwrap();
        let notes = SchemaId::from_static(kotton_common::namespace::NSID_NOTES);
        assert!(m.capabilities.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Schema {
                nsid: notes.clone()
            }
        ));
        assert!(m.capabilities.allows(
            &CapabilityKind::Write,
            &CapabilityTarget::Schema {
                nsid: notes.clone()
            }
        ));
        let contacts = SchemaId::from_static(kotton_common::namespace::NSID_CONTACTS);
        assert!(!m.capabilities.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Schema { nsid: contacts }
        ));
        assert!(m.capabilities.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Vfs {
                path: "/exports".to_string()
            }
        ));
        assert!(m.capabilities.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Vfs {
                path: "/exports/report.pdf".to_string()
            }
        ));
        assert!(!m.capabilities.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Vfs {
                path: "/private".to_string()
            }
        ));
    }

    #[test]
    fn network_fetch_flag() {
        let src = r#"
[app]
id = "com.acme.web-browser"
name = "Browser"
version = "0.1.0"

[capabilities]
"network.fetch" = []
"#;
        let m = AppManifest::from_toml(src).unwrap();
        assert!(m.network_fetch);
        // H1: the action capability is now also a `Use` grant in the set (so it
        // is minted into the signed envelope), not only a boolean.
        assert_eq!(m.capabilities.len(), 1);
        assert!(m
            .capabilities
            .allows(&CapabilityKind::Use, &CapabilityTarget::Network));
    }

    #[test]
    fn call_receive_and_messages_flags() {
        let src = r#"
[app]
id = "com.acme.comms"
name = "Comms"
version = "0.1.0"

[capabilities]
"call.initiate"   = []
"call.receive"    = []
"messages.send"   = []
"messages.receive" = []
"#;
        let m = AppManifest::from_toml(src).unwrap();
        assert!(m.call_initiate);
        assert!(m.call_receive);
        assert!(m.messages_send);
        assert!(m.messages_receive);
        // H1: each is now also a `Use` grant in the set (minted into the envelope).
        assert_eq!(m.capabilities.len(), 4);
        assert!(m.capabilities.allows(
            &CapabilityKind::Use,
            &CapabilityTarget::Call {
                direction: CallDirection::Initiate
            }
        ));
        assert!(m.capabilities.allows(
            &CapabilityKind::Use,
            &CapabilityTarget::Messages {
                direction: MessageDirection::Receive
            }
        ));
    }

    #[test]
    fn apps_launch_flag() {
        let src = r#"
[app]
id = "sh.kotton.shell"
name = "Shell"
version = "0.1.0"

[capabilities]
"apps.launch" = []
"#;
        let m = AppManifest::from_toml(src).unwrap();
        assert!(m.apps_launch);
        // H1: also a `Use` grant in the set (minted into the envelope).
        assert_eq!(m.capabilities.len(), 1);
        assert!(m
            .capabilities
            .allows(&CapabilityKind::Use, &CapabilityTarget::AppLaunch));

        // Absent by default.
        let bare = AppManifest::from_toml(
            r#"
[app]
id = "com.acme.leaf"
name = "Leaf"
version = "0.1.0"
"#,
        )
        .unwrap();
        assert!(!bare.apps_launch);
    }

    #[test]
    fn publisher_section_parsed() {
        let src = r#"
[app]
id = "com.acme.signed-app"
name = "Signed App"
version = "1.0.0"

[publisher]
did = "did:key:z6MkTest"
signature = "aGVsbG8="

[capabilities]
"schema.read" = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
"#;
        let m = AppManifest::from_toml(src).unwrap();
        assert_eq!(m.publisher_did.as_deref(), Some("did:key:z6MkTest"));
        assert_eq!(m.publisher_signature.as_deref(), Some("aGVsbG8="));
    }

    #[test]
    fn unknown_capability_key_is_rejected() {
        let src = r#"
[app]
id = "com.acme.app"
name = "App"
version = "1.0.0"

[capabilities]
"system.exec" = []
"#;
        let err = AppManifest::from_toml(src).unwrap_err();
        assert!(matches!(err, ManifestError::UnknownCapabilityKey(_)));
    }

    #[test]
    fn invalid_app_id_is_rejected() {
        let src = r#"
[app]
id = "NotAnAppId"
name = "Bad"
version = "1.0.0"
"#;
        let err = AppManifest::from_toml(src).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidAppId(_, _)));
    }

    // ── What the publisher signs ─────────────────────────────────────────────

    /// [`EXAMPLE`]'s canonical form.
    const EXAMPLE_CANONICAL: &str = r#"{"app":{"handler_for":["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"],"id":"com.acme.notes-pro","name":"Notes Pro","version":"1.0.0"},"capabilities":{"files.read":["/exports"],"schema.read":["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"],"schema.write":["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]}}"#;

    #[test]
    fn the_canonical_form_is_the_types_json_in_rfc_8785_form() {
        assert_eq!(canonical_manifest(EXAMPLE).unwrap(), EXAMPLE_CANONICAL);
        assert_eq!(manifest_digest(EXAMPLE).unwrap(), *blake3::hash(EXAMPLE_CANONICAL.as_bytes()).as_bytes());
    }

    /// Order, whitespace, comments, quoting and `[publisher]` do not reach the form.
    #[test]
    fn a_reordered_or_respaced_manifest_has_the_same_digest() {
        let reordered = r#"
# The same manifest, written otherwise.
[capabilities]
"files.read" = [ '/exports' ]
"schema.write"="did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"
"schema.read" = [
    "did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes",
]

[publisher]
did = "did:key:z6MkTest"
signature = "aGVsbG8="

[app]
version   =   "1.0.0"
handler_for = ["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]
name = 'Notes Pro'
id = "com.acme.notes-pro"
"#;
        // A string where a list is: not the same manifest, and not one the types read.
        assert!(canonical_manifest(reordered).is_err());
        let reordered = reordered.replace(
            r#""schema.write"="did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes""#,
            r#""schema.write"=["did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes"]"#,
        );
        assert_eq!(canonical_manifest(&reordered).unwrap(), EXAMPLE_CANONICAL);
        assert_eq!(manifest_digest(&reordered).unwrap(), manifest_digest(EXAMPLE).unwrap());
    }

    #[test]
    fn a_changed_value_changes_the_digest() {
        let digest = manifest_digest(EXAMPLE).unwrap();
        for (from, to) in [
            ("Notes Pro", "Notes Pro "),
            ("\"/exports\"", "\"/\""),
            ("version = \"1.0.0\"", "version = \"1.0.1\""),
            ("\"files.read\"   = [\"/exports\"]", "\"files.read\"   = [\"/exports\"]\n\"network.fetch\" = []"),
        ] {
            let changed = EXAMPLE.replace(from, to);
            assert_ne!(changed, EXAMPLE, "{from}");
            assert_ne!(manifest_digest(&changed).unwrap(), digest, "{from} -> {to}");
        }
        // A list absent and a list present but empty are written as they are.
        let bare = "[app]\nid = \"com.acme.a\"\nname = \"A\"\nversion = \"1\"\n";
        let empty = format!("{bare}handler_for = []\n");
        assert_eq!(canonical_manifest(bare).unwrap(), r#"{"app":{"id":"com.acme.a","name":"A","version":"1"}}"#);
        assert_eq!(canonical_manifest(&empty).unwrap(), r#"{"app":{"handler_for":[],"id":"com.acme.a","name":"A","version":"1"}}"#);
    }

    /// A key outside the types is named, wherever it is; the manifest still parses, as an
    /// unsigned one is read.
    #[test]
    fn a_key_outside_the_types_has_no_canonical_form_and_is_named() {
        let bare = "[app]\nid = \"com.acme.a\"\nname = \"A\"\nversion = \"1\"\n";
        for (extra, key) in [
            (format!("{bare}role = \"shell\"\n"), "app.role"),
            (format!("homepage = \"https://example.com\"\n{bare}"), "homepage"),
            (format!("{bare}\n[extra]\nx = 1\n"), "extra"),
            (format!("{bare}\n[capabilities]\n\"files.read\" = [\"/\"]\n\n[app.more]\nx = \"y\"\n"), "app.more"),
            (
                format!("{bare}\n[[capabilities]]\nid = \"home\"\ntype = \"vfs-tree\"\naccess = [\"read\"]\ndefault = \"/notes\"\nicon = \"x\"\n"),
                "capabilities[0].icon",
            ),
        ] {
            let err = canonical_manifest(&extra).expect_err(key);
            assert!(matches!(&err, ManifestCanonicalError::KeyOutsideTypes { key: k } if k == key), "{key}: {err}");
            assert_eq!(err.key(), Some(key));
            assert!(err.to_string().contains(&format!("`{key}`")), "{err}");
            AppManifest::from_toml(&extra).expect("an unsigned manifest with a key outside its types still parses");
        }
        // Inside `[publisher]`, set aside, a key is not the form's.
        let publisher = format!("{bare}\n[publisher]\ndid = \"d\"\nsignature = \"s\"\nnote = \"n\"\n");
        assert_eq!(canonical_manifest(&publisher).unwrap(), canonical_manifest(bare).unwrap());
    }

    /// The system shell's manifest in this tree carries `role` under `[app]`, which nothing
    /// reads: it parses, unsigned, and has no canonical form, so it could not be signed.
    #[test]
    fn the_shell_fixture_is_unsigned_and_would_not_canonicalise() {
        let shell = include_str!("../../../tests/fixtures/shell-manifest/manifest.toml");
        let m = AppManifest::from_toml(shell).unwrap();
        assert!(m.publisher_did.is_none() && m.publisher_signature.is_none());
        let err = canonical_manifest(shell).unwrap_err();
        assert_eq!(err.key(), Some("app.role"), "{err}");
    }

    /// The signed message is exactly the tag, one zero byte, and the two digests: 78 bytes.
    #[test]
    fn the_signed_message_is_the_tag_a_zero_byte_and_two_digests() {
        let manifest: [u8; 32] = core::array::from_fn(|i| i as u8 + 0xa0);
        let code: [u8; 32] = core::array::from_fn(|i| i as u8 + 0x10);
        let m = app_signed_message(&manifest, &code);
        assert_eq!(m.len(), 78);
        let mut expected = b"kotton-app-v1\0".to_vec();
        expected.extend_from_slice(&manifest);
        expected.extend_from_slice(&code);
        assert_eq!(m.as_slice(), expected.as_slice());
        let made = app_signed_message_for(EXAMPLE, b"code").unwrap();
        assert_eq!(made, app_signed_message(&manifest_digest(EXAMPLE).unwrap(), blake3::hash(b"code").as_bytes()));
    }
}
