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
//! handler_for = ["sh.kotton.notes"]
//!
//! [capabilities]
//! "schema.read"  = ["sh.kotton.notes"]
//! "schema.write" = ["sh.kotton.notes"]
//! "files.read"   = ["/exports"]
//! "network.fetch" = []   # presence enables outbound network; value list is ignored
//! ```

use std::collections::HashMap;

use crate::{
    capability::CapabilitySet, CallDirection, CapabilityGrant, CapabilityKind, CapabilityTarget,
    MediaDevice, MessageDirection, Nsid, NsidError,
};
use serde::Deserialize;
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

    /// An NSID in the manifest is invalid.
    #[error("invalid NSID {0:?}: {1}")]
    InvalidNsid(String, NsidError),

    /// The app `id` field is not a valid NSID.
    #[error("invalid app id {0:?}: {1}")]
    InvalidAppId(String, NsidError),

    /// The `handler_for` list contains an invalid NSID.
    #[error("invalid handler_for entry {0:?}: {1}")]
    InvalidHandlerNsid(String, NsidError),
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

#[derive(Debug, Deserialize)]
struct RawManifest {
    app: RawApp,
    #[serde(default)]
    capabilities: RawCapabilities,
    #[serde(default)]
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
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
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
    #[serde(default)]
    label: Option<String>,
    /// One sentence on what the app does there.
    #[serde(default)]
    desc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPublisher {
    did: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct RawApp {
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    handler_for: Vec<String>,
    #[serde(default)]
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
    pub id: Nsid,
    /// Human-readable display name.
    pub name: String,
    /// Semver-like version string (stored as string, not parsed).
    pub version: String,
    /// NSIDs this app registers as a handler for.
    pub handler_for: Vec<Nsid>,
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
    /// Publisher Ed25519 signature (base64) over `BLAKE3(app.wasm)`, if present.
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
        let id = Nsid::new(&raw.app.id)
            .map_err(|e| ManifestError::InvalidAppId(raw.app.id.clone(), e))?;

        // Validate handler_for entries
        let handler_for = raw
            .app
            .handler_for
            .iter()
            .map(|s| Nsid::new(s).map_err(|e| ManifestError::InvalidHandlerNsid(s.clone(), e)))
            .collect::<Result<Vec<_>, _>>()?;

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
        let flat = match &raw.capabilities {
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
                    for nsid_str in values {
                        let nsid = Nsid::new(nsid_str)
                            .map_err(|e| ManifestError::InvalidNsid(nsid_str.clone(), e))?;
                        grants.push(CapabilityGrant::schema(CapabilityKind::Read, nsid));
                    }
                }
                "schema.write" => {
                    for nsid_str in values {
                        let nsid = Nsid::new(nsid_str)
                            .map_err(|e| ManifestError::InvalidNsid(nsid_str.clone(), e))?;
                        grants.push(CapabilityGrant::schema(CapabilityKind::Write, nsid));
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityTarget;

    const EXAMPLE: &str = r#"
[app]
id = "com.acme.notes-pro"
name = "Notes Pro"
version = "1.0.0"
handler_for = ["sh.kotton.notes"]

[capabilities]
"schema.read"  = ["sh.kotton.notes"]
"schema.write" = ["sh.kotton.notes"]
"files.read"   = ["/exports"]
"#;

    #[test]
    fn parse_example() {
        let m = AppManifest::from_toml(EXAMPLE).unwrap();
        assert_eq!(m.app_id(), "com.acme.notes-pro");
        assert_eq!(m.app.name, "Notes Pro");
        assert_eq!(m.app.version, "1.0.0");
        assert_eq!(m.app.handler_for.len(), 1);
        assert_eq!(m.app.handler_for[0].as_str(), "sh.kotton.notes");
        assert!(!m.network_fetch);
        assert_eq!(m.capabilities.len(), 3);
        assert!(m.publisher_did.is_none());
        assert!(m.publisher_signature.is_none());
    }

    #[test]
    fn capability_set_allows() {
        let m = AppManifest::from_toml(EXAMPLE).unwrap();
        let notes = Nsid::from_static("sh.kotton.notes");
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
        let contacts = Nsid::from_static("sh.kotton.contacts");
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
"schema.read" = ["sh.kotton.notes"]
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
id = "NotAnNsid"
name = "Bad"
version = "1.0.0"
"#;
        let err = AppManifest::from_toml(src).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidAppId(_, _)));
    }
}
