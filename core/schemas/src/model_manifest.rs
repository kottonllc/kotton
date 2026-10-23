// SPDX-License-Identifier: AGPL-3.0-or-later
//! A model's manifest: the body of a `sh.kotton.model` record.
//!
//! *"A model is a hash-named, signed artifact with a manifest — its licence, its
//! size, its prompt shape, what it can do — installed by the person and kept as
//! a sealed object in their store."* This type is that manifest, and nothing
//! more: it **carries no authority**. Whoever is handed a manifest has been told
//! what to expect of some bytes, not been given permission to do anything.
//!
//! ## Why it is the protocol's, and here
//!
//! A manifest is something a person obtains, sends to their daemon
//! (`kotton model add`), stores as a record and syncs to every device they own.
//! That is the protocol's vocabulary — what crosses between processes and what
//! is kept — so it lives beside the record schema it is the body of
//! ([`crate::core`]'s `sh.kotton.model`), as [`crate::AppManifest`] and
//! [`crate::ExtensionManifest`] do. A test below holds the two field for field.
//!
//! The inference runtime (`kotton-infer`) keeps a manifest type of its own,
//! because its crate is held by `infer-check` to an allow-list of serde and
//! thiserror and may not link this one. The user daemon, the one process that
//! links both, is where a stored manifest becomes the backend's; nothing else
//! — not the wire, the device daemon, the client, the relay or the vault — links
//! the inference runtime to name a model.
//!
//! ## What is not here
//!
//! - **Verifying the publisher's signature.** That is a decision about whether
//!   to install, made by `kotton model add` against the person's own trust.
//!   [`ModelManifest::publisher`] is carried so it can be reported, never so a
//!   reader of this type can decide.
//! - **The installation's two facts**, `active` and `installed_at`: they are
//!   about this person's installation, not about the model, and the record
//!   carries them beside these fields.

use serde::{Deserialize, Serialize};

/// The weights file format a backend must be able to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFormat {
    Gguf,
    Safetensors,
}

/// What a model is for. One manifest shape, three kinds: the embedding model is a
/// model like any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelKind {
    Chat,
    Embed,
    /// Named because the manifest shape must already admit it; the model itself
    /// waits on the photo surface. No backend accepts one today.
    Vision,
}

/// The licence the weights carry, as an identifier and a hash of the text.
///
/// *"A model's weights are content, with a stated licence, a hash and a size,
/// installed by the person."* The hash is here so the text the person agreed to
/// is the text that shipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Licence {
    /// SPDX identifier, e.g. `Apache-2.0`.
    pub spdx: String,
    /// Hex digest of the licence text as distributed.
    pub text_hash: String,
}

/// Everything the person and a runtime need to know about a model.
///
/// The identity of a model is [`ModelManifest::weights`] — the hash of the
/// sealed object — not its name. Two manifests naming the same hash describe
/// the same model however they spell it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelManifest {
    /// For the person. Carries no authority: a model called `system` is a model
    /// called `system`.
    pub name: String,
    pub version: String,
    /// Hex hash of the sealed object holding the weights — the model's identity.
    pub weights: String,
    pub format: ModelFormat,
    pub kind: ModelKind,
    /// Parameter count, as the publisher states it.
    pub parameters: u64,
    /// e.g. `Q4_K_M`. A string because the vocabulary belongs to the format.
    pub quantisation: String,
    /// Bytes on disk. Shown before installing, because the store is paid by the
    /// byte.
    pub size: u64,
    /// How many tokens this model can be shown at once — the budget a host
    /// trims its passages to before asking. `u32` is the guest world's width
    /// (`model-info.context-window`), so the two cannot disagree.
    pub context_window: u32,
    /// The prompt shape the model expects; the host copies it into the context
    /// it composes, so a guest never supplies it.
    pub template: String,
    pub licence: Licence,
    /// Detached signature over the manifest, where the publisher signed one.
    /// Carried, never checked here — see this module's header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoreSchema, FieldType};

    fn manifest(publisher: Option<&str>) -> ModelManifest {
        ModelManifest {
            name: "fixture".into(),
            version: "1".into(),
            weights: "ab".repeat(32),
            format: ModelFormat::Gguf,
            kind: ModelKind::Chat,
            parameters: 1,
            quantisation: "Q4_K_M".into(),
            size: 1,
            context_window: 4096,
            template: "{question}".into(),
            licence: Licence { spdx: "Apache-2.0".into(), text_hash: "cd".repeat(32) },
            publisher: publisher.map(str::to_string),
        }
    }

    /// The record schema `sh.kotton.model` opens with this type's fields, name
    /// for name, and its `licence` facet is [`Licence`]'s: a record body
    /// deserialises straight back into a manifest.
    #[test]
    fn the_model_record_schema_is_the_manifest_field_for_field() {
        let def = CoreSchema::Model.definition();
        let body = serde_json::to_value(manifest(Some("sig"))).unwrap();
        let mut keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
        let mut schema: Vec<&str> = def.fields.iter().take(keys.len()).map(|f| f.name.as_str()).collect();
        // A JSON map's order is serde_json's to choose; the set is what must agree.
        keys.sort_unstable();
        schema.sort_unstable();
        assert_eq!(keys, schema, "the manifest's fields and the schema's first {} differ", keys.len());
        let rest: Vec<&str> = def.fields.iter().skip(keys.len()).map(|f| f.name.as_str()).collect();
        assert_eq!(rest, ["active", "installed_at"], "the schema's fields past the manifest's are the host's two");

        let Some(FieldType::Record(facet)) = def.field("licence").map(|f| &f.field_type) else {
            panic!("the schema's licence is not a record facet");
        };
        let mut facet: Vec<&str> = facet.iter().map(|f| f.name.as_str()).collect();
        let licence = serde_json::to_value(&manifest(None).licence).unwrap();
        let mut licence: Vec<&str> = licence.as_object().unwrap().keys().map(String::as_str).collect();
        facet.sort_unstable();
        licence.sort_unstable();
        assert_eq!(facet, licence);
        assert!(def.field("publisher").is_some_and(|f| f.nullable), "an unsigned manifest stores no publisher");
    }

    /// The JSON a person writes and the daemon stores: lowercase enums, and no
    /// `publisher` key when there is no signature.
    #[test]
    fn a_manifest_round_trips_as_the_record_body() {
        for m in [manifest(None), manifest(Some("sig"))] {
            let json = serde_json::to_value(&m).unwrap();
            assert_eq!(json["format"], "gguf");
            assert_eq!(json["kind"], "chat");
            assert_eq!(json.get("publisher").is_some(), m.publisher.is_some());
            assert_eq!(serde_json::from_value::<ModelManifest>(json).unwrap(), m);
        }
    }
}
