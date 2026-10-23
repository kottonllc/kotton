// SPDX-License-Identifier: AGPL-3.0-or-later
//! Installing a model: the manifest as a record, the weights as the sealed
//! object it names: the model as content.
//!
//! ```text
//! kotton model add <file> --manifest <file>   → this module's `model_add`
//! kotton model ls                             → `model_list`
//! kotton model rm  <id|name>                  → `model_remove`
//! kotton model use <id|name>                  → `model_use`
//! ```
//!
//! ## The weights are the daemon's object, not a file of the person's
//!
//! The cohesion rule: *no surface introduces a principal, a store, a sharing
//! model or a sync path of its own.* A model is a record and a sealed
//! object like anything else the person owns, so this module opens no database
//! and writes no table: the manifest goes in through
//! [`kotton_record::record_cmds::Record::insert`], the verb an app uses, and the
//! weights through the store's own daemon-object verbs on the `local` mount.
//! Both sync and both recover because they are the store's, not this module's.
//!
//! What this module does decide is **one key**, [`model_object_path`], and it
//! is outside the person's tree, so no `files` grant reaches it.
//! Weights are content-addressed and the daemon verifies them; a person never
//! edits one and an app never has a reason to name one, which makes them the
//! daemon's kind of object by the same test the membership set and read marks
//! passed. At `files/models/<hash>.weights`, a guest holding `files.write` on
//! `/` could overwrite an installed model's weights and the first loader would
//! read the guest's bytes. Every path a person or an app can name resolves
//! beneath `PERSON_TREE_ROOT`, and
//! `/models/<hash>.weights` there is an ordinary file of theirs this module
//! never reads.
//!
//! ## What verifies the weights, and where
//!
//! *A file install is verified against that hash before it is sealed.* [`model_weights`] is the only writer of the key, it derives the
//! key from the hash the caller declares (the caller names bytes, never a
//! place), and it commits the stream only if it hashes to that — so an object
//! at a model's key is verified before it exists.
//!
//! [`model_add`] hashes the object again before a manifest record is written,
//! **in ranges**, so a multi-gigabyte model is never whole in memory. A
//! presence check was considered instead, and this is not one:
//! the key is also reachable by replication — a paired device of the
//! person's own pushes sealed objects at raw keys — and a re-hash at the one
//! moment a model is named is the cheaper place to hold that than every loader.
//!
//! ## One model per kind answers
//!
//! *One model per kind is active, and the person chooses it.*
//! `active` is a field on the manifest record, so the choice travels to every
//! device the person owns — which the `embed` kind needs, since *"the manifest of
//! the embedding model is what makes two devices' indexes comparable"*.
//! [`model_use`] is what moves it, and it holds one
//! model per kind by clearing the others in the same pass.

use std::io;
use std::sync::{Arc, RwLock};

use kotton_schemas::{ModelKind, ModelManifest};
use kotton_record::{registry::SchemaRegistry, record_cmds::Record, SqliteRecordStore};
use kotton_wire::ipc::{InstalledModel, UserResponse, MAX_STREAMED_FILE_BYTES};
use serde_json::{json, Value};

use super::files::{accept_chunk, ChunkOutcome, FileHost, SealedReassembly, MAX_BUFFERED_FILE_BYTES};

/// The NSID a manifest record is written under.
const MODEL_NSID: &str = kotton_common::namespace::NSID_MODEL;

/// How much of a model's weights one ranged read takes while `model_add`
/// re-hashes them.
const VERIFY_RANGE_BYTES: u64 = 4 * 1024 * 1024;

/// The daemon's key for a model's weights: `models/<hash>.weights`, in the
/// store's own key space and **outside the person's tree**, so no `files`
/// grant reaches it.
///
/// Written only by [`model_weights`], read by [`model_add`], deleted by
/// [`model_remove`], all through the store's daemon-object verbs. The same
/// spelling in the person's tree, `/models/<hash>.weights`, is
/// `files/models/<hash>.weights` in the store — another key, and an ordinary
/// file of theirs.
///
/// `None` unless `weights_hash` is a BLAKE3 hex digest — 64 lowercase hex
/// characters — because the hash is the caller's and the key is derived from
/// it: a "hash" of `../files/notes/a` would otherwise name a key in the
/// person's tree.
pub fn model_object_path(weights_hash: &str) -> Option<String> {
    let is_digest = weights_hash.len() == 64
        && weights_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    is_digest.then(|| format!("models/{weights_hash}.weights"))
}

fn not_a_digest(hash: &str) -> UserResponse {
    UserResponse::Error {
        message: format!(
            "'{hash}' is not a weights hash — a model is named by the BLAKE3 of its \
             weights, 64 lowercase hex characters"
        ),
    }
}


/// What a person's installed models look like to a caller.
///
/// The manifest, unchanged, plus the two facts the manifest cannot carry.
fn installed_from_body(body: &Value) -> Option<InstalledModel> {
    let manifest: ModelManifest = serde_json::from_value(body.clone()).ok()?;
    Some(InstalledModel {
        active: body.get("active").and_then(Value::as_bool).unwrap_or(false),
        installed_at: body
            .get("installed_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        manifest,
    })
}

/// Every model this person has installed, newest listing order left to the caller.
async fn installed(
    registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
) -> anyhow::Result<Vec<InstalledModel>> {
    let rows = Record::new(registry, store)
        .query(MODEL_NSID, Vec::new(), None, None, None)
        .await?;
    Ok(rows.iter().filter_map(installed_from_body).collect())
}

/// Find the one model `needle` names, by weights hash, hash prefix, or name.
///
/// Ambiguity is refused rather than resolved by order: two models whose names or
/// hash prefixes both match is a question only the person can answer, and picking
/// the first would remove or activate something they did not name.
fn resolve<'a>(models: &'a [InstalledModel], needle: &str) -> Result<&'a InstalledModel, String> {
    if needle.is_empty() {
        return Err("name a model: `kotton model ls` lists them".to_string());
    }
    let matches: Vec<&InstalledModel> = models
        .iter()
        .filter(|m| {
            m.manifest.weights == needle
                || m.manifest.name == needle
                || (needle.len() >= 4 && m.manifest.weights.starts_with(needle))
        })
        .collect();
    match matches.len() {
        0 => Err(format!(
            "no installed model matches '{needle}' — `kotton model ls` lists them"
        )),
        1 => Ok(matches[0]),
        _ => {
            let names: Vec<String> = matches
                .iter()
                .map(|m| format!("{} ({})", m.manifest.name, &m.manifest.weights[..8.min(m.manifest.weights.len())]))
                .collect();
            Err(format!(
                "'{needle}' matches {} models — {}. Name one by its full hash.",
                matches.len(),
                names.join(", ")
            ))
        }
    }
}

/// The body of a manifest record: the manifest's own fields, plus the host's two.
fn record_body(manifest: &ModelManifest, active: bool, installed_at: &str) -> anyhow::Result<Value> {
    let mut body = serde_json::to_value(manifest)?;
    let obj = body
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("a manifest serialises to an object"))?;
    // The weights hash is the record id: two manifests naming one hash describe
    // the same model however they spell the name.
    obj.insert("id".to_string(), json!(manifest.weights));
    obj.insert("active".to_string(), json!(active));
    obj.insert("installed_at".to_string(), json!(installed_at));
    Ok(body)
}

fn no_such_user(user_id: &str) -> UserResponse {
    UserResponse::Error {
        message: format!("user '{user_id}' not found"),
    }
}

/// Take one chunk of a model's weights into the daemon's object for the hash
/// they declare (`UserRequest::ModelWeights`).
///
/// The chunks stream into the store as they arrive and are hashed on the way
/// past; the object commits only when the whole stream is `content_hash`, so
/// until then nothing is at [`model_object_path`] under any name. A store that
/// cannot stream buffers under [`MAX_BUFFERED_FILE_BYTES`] and refuses above it
/// — a clean refusal rather than an out-of-memory.
///
/// Reassembly shares `WriteFile`'s map and its rules (in order, one declared
/// size, no overrun, reaped when abandoned), keyed apart by `"model"` so a
/// person's file and a model with one hash never share a buffer.
#[allow(clippy::too_many_arguments)]
pub async fn model_weights(
    host: &dyn FileHost,
    user_id: String,
    data: Vec<u8>,
    offset: u64,
    total_size: u64,
    content_hash: String,
    reassembly: &SealedReassembly,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(no_such_user(&user_id));
    };
    let Some(key) = model_object_path(&content_hash) else {
        return Ok(not_a_digest(&content_hash));
    };
    if total_size == 0 {
        return Ok(UserResponse::Error {
            message: "a model's weights are not empty".to_string(),
        });
    }
    if total_size > MAX_STREAMED_FILE_BYTES {
        return Ok(UserResponse::Error {
            message: format!(
                "weights too large: {total_size} bytes exceeds the \
                 {MAX_STREAMED_FILE_BYTES}-byte ceiling"
            ),
        });
    }

    let mut new_sink = None;
    if offset == 0 {
        match user_store.begin_daemon_object_write(&key).await {
            Ok(sink) => new_sink = sink,
            Err(e) => {
                return Ok(UserResponse::Error {
                    message: format!("could not begin writing the weights: {e}"),
                })
            }
        }
        if new_sink.is_none() && total_size > MAX_BUFFERED_FILE_BYTES {
            return Ok(UserResponse::Error {
                message: format!(
                    "weights too large to buffer: {total_size} bytes exceeds \
                     {MAX_BUFFERED_FILE_BYTES} and this store offers no streaming ingest"
                ),
            });
        }
    }

    let buffer_key = (user_id, "model".to_string(), key.clone(), content_hash.clone());
    let mismatch = |got: &str| UserResponse::Error {
        message: format!(
            "the weights hash to {got}, not the {content_hash} they were declared as; \
             nothing was installed"
        ),
    };
    match accept_chunk(reassembly, &buffer_key, &data, offset, total_size, new_sink).await {
        ChunkOutcome::NeedMore => Ok(UserResponse::Ok),
        ChunkOutcome::Reject(why) => Ok(UserResponse::Error {
            message: why.to_string(),
        }),
        // Dropped uncommitted on a mismatch: no key resolves to the bytes.
        ChunkOutcome::CompleteStreamed { mut sink, hash } => {
            if hash != content_hash {
                return Ok(mismatch(&hash));
            }
            match sink.commit().await {
                Ok(()) => Ok(UserResponse::Ok),
                Err(e) => Ok(UserResponse::Error {
                    message: format!("the weights failed to commit: {e}"),
                }),
            }
        }
        ChunkOutcome::Complete(full) => {
            let got = blake3::hash(&full).to_hex().to_string();
            if got != content_hash {
                return Ok(mismatch(&got));
            }
            match user_store.write_daemon_object(&key, &full).await {
                Ok(()) => Ok(UserResponse::Ok),
                Err(e) => Ok(UserResponse::Error {
                    message: e.to_string(),
                }),
            }
        }
    }
}

/// The BLAKE3 and length of the object at `key`, read in ranges so a
/// multi-gigabyte model is never whole in memory.
async fn hash_daemon_object(
    store: &kotton_store::runtime::user::UserStore,
    key: &str,
) -> anyhow::Result<(String, u64)> {
    let mut hasher = blake3::Hasher::new();
    let (first, total) = store.read_daemon_object_range(key, 0, VERIFY_RANGE_BYTES).await?;
    hasher.update(&first);
    let mut read = first.len() as u64;
    while read < total {
        let (bytes, _) = store
            .read_daemon_object_range(key, read, VERIFY_RANGE_BYTES)
            .await?;
        if bytes.is_empty() {
            anyhow::bail!("the object ended at {read} of the {total} bytes it reports");
        }
        hasher.update(&bytes);
        read += bytes.len() as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), read))
}

/// Install a model: verify the sealed weights, then write the manifest record.
///
/// The weights are already in the store when this runs — [`model_weights`] put
/// them at [`model_object_path`], and committed them only at the hash they were
/// declared as. This re-hashes what is at the manifest's key, in ranges, and
/// only then does a manifest record exist.
pub async fn model_add(
    host: &dyn FileHost,
    registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_id: String,
    manifest: ModelManifest,
    installed_at: String,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(no_such_user(&user_id));
    };

    let Some(key) = model_object_path(&manifest.weights) else {
        return Ok(not_a_digest(&manifest.weights));
    };
    let (got, len) = match hash_daemon_object(&user_store, &key).await {
        Ok(found) => found,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!(
                    "the weights this manifest names are not in the store — \
                     `kotton model add` sends them first: {e}"
                ),
            })
        }
    };
    if got != manifest.weights {
        return Ok(UserResponse::Error {
            message: format!(
                "the weights object for {} holds bytes that hash to {got}; \
                 refusing to install. `kotton model rm {}` removes the stray object.",
                manifest.weights, manifest.weights
            ),
        });
    }
    if len != manifest.size {
        return Ok(UserResponse::Error {
            message: format!(
                "this manifest says {} bytes and the weights are {len}; \
                 the store is paid by the byte, so the number a person is shown before \
                 installing has to be the number they pay for",
                manifest.size,
            ),
        });
    }

    let existing = match installed(registry, store).await {
        Ok(models) => models,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    // The first model of a kind answers, because nothing else can. A second one
    // does not displace it: the choice is the person's, and an
    // install that silently changed which model answers would be the swap
    // Article XII forbids, performed by the person's own hand without telling
    // them. `kotton model use` is how it moves.
    let already_active = existing
        .iter()
        .any(|m| m.active && m.manifest.kind == manifest.kind && m.manifest.weights != manifest.weights);
    let active = !already_active;

    let body = match record_body(&manifest, active, &installed_at) {
        Ok(body) => body,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    match Record::new(registry, store).insert(MODEL_NSID, body).await {
        Ok(id) => Ok(UserResponse::ModelInstalled { id, active }),
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Every model this person has installed, and which one of each kind answers.
pub async fn model_list(
    registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
) -> io::Result<UserResponse> {
    match installed(registry, store).await {
        Ok(mut models) => {
            models.sort_by(|a, b| {
                kind_str(a.manifest.kind)
                    .cmp(kind_str(b.manifest.kind))
                    .then_with(|| a.manifest.name.cmp(&b.manifest.name))
            });
            Ok(UserResponse::ModelList { models })
        }
        Err(e) => Ok(UserResponse::Error {
            message: e.to_string(),
        }),
    }
}

/// Uninstall: the manifest record and the weights object it names, together.
///
/// Tolerant of either being absent, because the two are written in sequence and
/// a failure between them leaves one without the other. Removing what is there
/// is the behaviour that makes that state recoverable; refusing because the pair
/// is incomplete would strand it.
pub async fn model_remove(
    host: &dyn FileHost,
    registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    user_id: String,
    needle: String,
) -> io::Result<UserResponse> {
    let Some(user_store) = host.user_store(&user_id) else {
        return Ok(no_such_user(&user_id));
    };

    let models = match installed(registry, store).await {
        Ok(models) => models,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };

    // A stray object with no record — the half-installed state above, or an
    // install refused after its weights landed — is named by its own hash and
    // removed by it. Nothing else could reach it.
    let (hash, had_record) = match resolve(&models, &needle) {
        Ok(model) => (model.manifest.weights.clone(), true),
        Err(why) => {
            if model_object_path(&needle).is_none() {
                return Ok(UserResponse::Error { message: why });
            }
            (needle.clone(), false)
        }
    };

    if had_record {
        if let Err(e) = Record::new(registry, store).delete(MODEL_NSID, &hash).await {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            });
        }
    }
    let Some(key) = model_object_path(&hash) else {
        return Ok(not_a_digest(&hash));
    };
    match user_store.delete_daemon_object(&key).await {
        Ok(()) => Ok(UserResponse::Ok),
        // The record is gone either way; an object that was never there is the
        // half-installed state, not a failure to report as one.
        Err(_) if had_record => Ok(UserResponse::Ok),
        Err(e) => Ok(UserResponse::Error {
            message: format!("nothing installed matches '{needle}', and no weights object is there: {e}"),
        }),
    }
}

/// Choose which model of its kind answers.
///
/// `confirmed` is the person saying yes to the one change that is not like the
/// others: switching the active `embed` model invalidates every index chunk the
/// old one produced, and is what makes two devices' indexes stop being
/// comparable. A chat model can be swapped between two
/// questions; an embedding model cannot, and a surface that made them look
/// identical would be lying about the cost of one of them.
pub async fn model_use(
    registry: &Arc<RwLock<SchemaRegistry>>,
    store: &Arc<SqliteRecordStore>,
    needle: String,
    confirmed: bool,
) -> io::Result<UserResponse> {
    let models = match installed(registry, store).await {
        Ok(models) => models,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            })
        }
    };
    let chosen = match resolve(&models, &needle) {
        Ok(model) => model.clone(),
        Err(why) => return Ok(UserResponse::Error { message: why }),
    };

    if chosen.manifest.kind == ModelKind::Embed && !confirmed {
        if let Some(current) = models
            .iter()
            .find(|m| m.active && m.manifest.kind == ModelKind::Embed && m.manifest.weights != chosen.manifest.weights)
        {
            return Ok(UserResponse::Error {
                message: format!(
                    "'{}' is the active embed model, and changing it invalidates every index \
                     chunk it produced — they have to be built again before the assistant can \
                     answer, and two devices' indexes are only comparable while they name the \
                     same embedding model. Pass --rebuild-index to change it anyway.",
                    current.manifest.name
                ),
            });
        }
    }

    let verb = Record::new(registry, store);
    for model in models.iter().filter(|m| m.manifest.kind == chosen.manifest.kind) {
        let should_be_active = model.manifest.weights == chosen.manifest.weights;
        if model.active == should_be_active {
            continue;
        }
        let body = match record_body(&model.manifest, should_be_active, &model.installed_at) {
            Ok(body) => body,
            Err(e) => {
                return Ok(UserResponse::Error {
                    message: e.to_string(),
                })
            }
        };
        if let Err(e) = verb.insert(MODEL_NSID, body).await {
            return Ok(UserResponse::Error {
                message: e.to_string(),
            });
        }
    }

    Ok(UserResponse::ModelInstalled {
        id: chosen.manifest.weights.clone(),
        active: true,
    })
}

/// The kind, as the person sees it and as the record stores it.
fn kind_str(kind: ModelKind) -> &'static str {
    match kind {
        ModelKind::Chat => "chat",
        ModelKind::Embed => "embed",
        ModelKind::Vision => "vision",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::{Licence, ModelFormat};

    fn manifest(name: &str, kind: ModelKind, weights: &str) -> ModelManifest {
        ModelManifest {
            name: name.to_string(),
            version: "1".to_string(),
            weights: weights.to_string(),
            format: ModelFormat::Gguf,
            kind,
            parameters: 1_000_000_000,
            quantisation: "Q4_K_M".to_string(),
            size: 8,
            context_window: 4096,
            template: "{question}".to_string(),
            licence: Licence {
                spdx: "Apache-2.0".to_string(),
                text_hash: "00".to_string(),
            },
            publisher: None,
        }
    }

    fn model(name: &str, kind: ModelKind, weights: &str, active: bool) -> InstalledModel {
        InstalledModel {
            manifest: manifest(name, kind, weights),
            active,
            installed_at: "2026-09-16T00:00:00Z".to_string(),
        }
    }

    /// A record body is the manifest's own fields, so it deserialises straight
    /// back into one — which is what "the manifest is what gets stored" means.
    #[test]
    fn a_record_body_round_trips_to_the_manifest_it_stores() {
        let original = manifest("gemma", ModelKind::Chat, "aa".repeat(32).as_str());
        let body = record_body(&original, true, "2026-09-16T00:00:00Z").expect("body");
        let back: ModelManifest = serde_json::from_value(body.clone()).expect("round trip");
        assert_eq!(back, original);
        assert_eq!(body["active"], json!(true));
        assert_eq!(body["id"], json!(original.weights));
        assert_eq!(body["installed_at"], json!("2026-09-16T00:00:00Z"));
    }

    #[test]
    fn a_model_resolves_by_name_by_hash_and_by_prefix() {
        let hash = "a".repeat(64);
        let models = vec![model("gemma", ModelKind::Chat, &hash, true)];
        assert_eq!(resolve(&models, "gemma").unwrap().manifest.weights, hash);
        assert_eq!(resolve(&models, &hash).unwrap().manifest.weights, hash);
        assert_eq!(resolve(&models, "aaaa").unwrap().manifest.weights, hash);
        assert!(resolve(&models, "aa").is_err(), "a two-character prefix is not a name");
        assert!(resolve(&models, "").is_err());
        assert!(resolve(&models, "nothing").is_err());
    }

    /// The daemon's key for the weights is outside the person's tree, and a
    /// "hash" that is not a BLAKE3 digest names no key — it is the caller's,
    /// and the key is derived from it.
    #[test]
    fn the_weights_key_is_the_daemons_and_only_a_digest_names_one() {
        let hash = "0123456789abcdef".repeat(4);
        let key = model_object_path(&hash).expect("a digest names a key");
        assert_eq!(key, format!("models/{hash}.weights"));
        assert!(
            !key.starts_with(kotton_store::runtime::user::files::PERSON_TREE_ROOT),
            "the weights' key is in the person's tree: {key}"
        );
        for bad in ["../files/notes/a", "", &"A".repeat(64), &"a".repeat(65), &"g".repeat(64)] {
            assert!(model_object_path(bad).is_none(), "'{bad}' named a key");
        }
    }

    /// Two matches is a question, not a choice this code may make for the person
    /// — removing or activating the wrong one is the failure it prevents.
    #[test]
    fn an_ambiguous_name_is_refused_rather_than_picked() {
        let models = vec![
            model("gemma", ModelKind::Chat, &"a".repeat(64), true),
            model("gemma", ModelKind::Embed, &"b".repeat(64), true),
        ];
        let err = resolve(&models, "gemma").expect_err("ambiguous");
        assert!(err.contains("matches 2 models"), "{err}");
    }
}
