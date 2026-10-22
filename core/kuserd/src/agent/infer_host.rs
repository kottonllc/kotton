// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daemon's side of `interface infer`.
//!
//! [`DaemonInferHost`] answers what only the daemon can: **which models are
//! active**. That is a fact in the person's sealed store, reachable only under an
//! unlocked context, and it is the join the rule needs —
//!
//! > *One model per kind is active, chosen by the person; `models()` answers with
//! > the active ones; and a guest may name only what `models()` showed it.*
//!
//! The store holds the first clause. The sandbox holds the third, against a list
//! it was given. This file is what makes that list the store's answer rather than
//! something the runner decided, and until it existed the two halves held on
//! either side of a seam nothing crossed.
//!
//! ## What answers here and what does not
//!
//! `models` is complete. `embed` and `generate` reach the runtime through
//! [`InferProxy`] and answer `no-runtime` when nothing is attached — which is the
//! truthful answer on a machine where `inference.enabled` is false, where no
//! model is installed, or where `kinferd` has died and not yet been restarted.
//!
//! **The answering path itself is not built here, and that is a division of
//! the work rather than a gap this file leaves.** Selection, labelling, citation
//! resolution and streaming to a surface are the **answer** step; loading a
//! model's weights out of the store and into `kinferd` rides with the **backend**
//! step, because what a load costs and what shape it takes depend on the backend
//! that was chosen — the trait's signature changes when a real one lands, from
//! bytes to a handed descriptor. Wiring a load against the stub now
//! would be building against a consumer that is about to be replaced.

use std::sync::Arc;

use kotton_app::daemon::apps::InferHost;
use kotton_wire::ipc::UserResponse;
use kotton_wire::runner::{
    RunnerInferError, RunnerInferOptions, RunnerMetering, RunnerModelInfo, RunnerModelKind,
    RunnerPassage,
};

use crate::infer_proxy::InferProxy;
use kotton_device::DeviceRuntime;

/// Answers inference verbs for a guest, from the person's own store.
pub struct DaemonInferHost<'a> {
    runtime: &'a DeviceRuntime,
    record_stores: &'a crate::residency::RecordStores,
    /// Whose models these are. `None` when no session is open, which is not an
    /// error: a guest asking on a locked machine is told there is no runtime,
    /// because from where it stands there is not.
    user_id: Option<String>,
    proxy: &'a Arc<InferProxy>,
}

fn kind_to_wire(k: kotton_infer::ModelKind) -> RunnerModelKind {
    match k {
        kotton_infer::ModelKind::Chat => RunnerModelKind::Chat,
        kotton_infer::ModelKind::Embed => RunnerModelKind::Embed,
        kotton_infer::ModelKind::Vision => RunnerModelKind::Vision,
    }
}

#[async_trait::async_trait]
impl InferHost for DaemonInferHost<'_> {
    async fn models(&self) -> Result<Vec<RunnerModelInfo>, RunnerInferError> {
        let Some(user_id) = self.user_id.as_deref() else {
            return Ok(Vec::new());
        };
        let store = self
            .record_stores
            .get_or_open(self.runtime.base_dir(), user_id, self.runtime.secrets())
            .map_err(|e| RunnerInferError::Runtime(e.to_string()))?;

        let listed =
            kotton_device::users::models::model_list(&self.runtime.schema_registry, &store)
                .await
                .map_err(|e| RunnerInferError::Runtime(e.to_string()))?;

        let models = match listed {
            UserResponse::ModelList { models } => models,
            UserResponse::Error { message } => return Err(RunnerInferError::Runtime(message)),
            other => {
                return Err(RunnerInferError::Runtime(format!(
                    "model_list answered with an unrelated response ({other:?})"
                )))
            }
        };

        // **The active ones only.** A person may have three chat models in their
        // store; which one answers is their choice and is a field on the
        // manifest record. Listing all of them would hand the guest the choice,
        // which is the thing the rule refuses — and it would do it here, in
        // the one place that could not be caught by the sandbox's check, because
        // that check is against exactly this list.
        Ok(models
            .into_iter()
            .filter(|m| m.active)
            .map(|m| RunnerModelInfo {
                id: m.manifest.weights,
                name: m.manifest.name,
                version: m.manifest.version,
                kind: kind_to_wire(m.manifest.kind),
                context_window: m.manifest.context_window,
            })
            .collect())
    }

    async fn embed(&self, model: &str, _text: &str) -> Result<Vec<f32>, RunnerInferError> {
        self.runtime_for(model).await?;
        Err(RunnerInferError::NoRuntime)
    }

    async fn generate(
        &self,
        model: &str,
        _question: &str,
        _passages: Vec<RunnerPassage>,
        _options: RunnerInferOptions,
    ) -> Result<u64, RunnerInferError> {
        self.runtime_for(model).await?;
        Err(RunnerInferError::NoRuntime)
    }

    async fn next_token(
        &self,
        _generation: u64,
    ) -> Result<(Option<String>, Option<RunnerMetering>), RunnerInferError> {
        // No generation can have been started, so any handle names one that does
        // not exist. Said as `no-runtime` rather than invented as a new variant:
        // the guest's taxonomy is what a guest branches on, and there is nothing
        // it could do differently.
        Err(RunnerInferError::NoRuntime)
    }

    async fn drop_generation(&self, _generation: u64) {}
}

impl DaemonInferHost<'_> {
    /// The two checks a call naming a model must pass before it reaches a
    /// runtime, run here rather than trusted from the runner.
    ///
    /// **The model check is deliberately duplicated.** The sandbox already
    /// refuses a model `models()` did not list, and that check is the one a test
    /// drives against a permissive runtime. This one is against the store, and it
    /// exists because a runner is a process that executes untrusted WASM: a frame
    /// arriving here is evidence of what the runner sent, not of what the guest
    /// was allowed to ask. Two checks in two places with two different sources of
    /// truth is the shape the rule needs; one check trusting the other's answer
    /// is a single point that a compromised runner walks past.
    async fn runtime_for(&self, model: &str) -> Result<(), RunnerInferError> {
        let active = self.models().await?;
        if !active.iter().any(|m| m.id == model) {
            return Err(RunnerInferError::NoSuchModel(model.to_string()));
        }
        if !self.proxy.is_attached().await {
            return Err(RunnerInferError::NoRuntime);
        }
        Ok(())
    }
}

/// Build the inference host, as `occupant_host` builds the occupant's.
pub fn infer_host<'a>(
    runtime: &'a DeviceRuntime,
    record_stores: &'a crate::residency::RecordStores,
    user_id: Option<String>,
    proxy: &'a Arc<InferProxy>,
) -> DaemonInferHost<'a> {
    DaemonInferHost {
        runtime,
        record_stores,
        user_id,
        proxy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::residency::{DaemonUserResources, RecordStores, UserRegistry};
    use kotton_device::config::RuntimeConfig;
    use kotton_device::users::DeviceUsers as _;
    use kotton_device::DeviceRuntime;
    use kotton_infer::{Licence, ModelFormat, ModelKind, ModelManifest};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Five BIP-39 words, as `files_tests.rs` uses; a literal rather than a
    /// shared import because this crate does not depend on the test harness.
    const TEST_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

    async fn env() -> (
        tempfile::TempDir,
        Arc<DeviceRuntime>,
        UserRegistry,
        RecordStores,
    ) {
        let users = UserRegistry::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            Arc::new(kotton_secret::MemorySecrets::new());
        let rt = DeviceRuntime::new_with_secrets(
            dir.path().to_owned(),
            RuntimeConfig::default(),
            secrets,
        )
        .await
        .expect("DeviceRuntime");
        let (_, alice_rt) = rt
            .create_user("alice", TEST_PASSPHRASE)
            .await
            .expect("create_user");
        users.insert("alice".to_string(), alice_rt);
        (dir, Arc::new(rt), users, RecordStores::new())
    }

    fn manifest(name: &str, kind: ModelKind, weights: &str) -> ModelManifest {
        ModelManifest {
            name: name.to_string(),
            version: "1".to_string(),
            weights: weights.to_string(),
            format: ModelFormat::Gguf,
            kind,
            parameters: 1_000_000_000,
            quantisation: "q4".to_string(),
            size: 4,
            context_window: 4096,
            template: "{question}".to_string(),
            licence: Licence {
                spdx: "MIT".to_string(),
                text_hash: String::new(),
            },
            publisher: None,
        }
    }

    /// The guest is shown the active model of each kind and nothing else.
    ///
    /// **This is the join that carries the store's choice to the guest.** The
    /// store decides which model answers — `model_add` makes the first of a kind
    /// active and a second does not displace it — and this host is what carries
    /// that decision to the guest.
    ///
    /// The assertion that matters is the *absence* of `second-chat`. A port that
    /// listed everything installed would hand the guest the choice, which is what
    /// the rule refuses — and it would do it in the one place the sandbox's own
    /// check could not catch it, because `AppState::model_it_was_shown` checks
    /// against exactly this list.
    ///
    /// **Proven red** by replacing the `active` filter in [`DaemonInferHost::models`]
    /// with one that admits everything: the list comes back
    /// `["first-chat", "second-chat", "first-embed"]` and this fails on the third
    /// assertion, which is the one that carries the rule.
    #[tokio::test]
    async fn a_guest_is_shown_the_active_model_of_each_kind_and_no_other() {
        let (_d, rt, users, record_stores) = env().await;
        // One `RecordStores` for both the file host and the inference host: two
        // caches would mean the test asserting against records the host never saw.
        let resources = DaemonUserResources::new(
            users.clone(),
            record_stores.clone(),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
            Arc::clone(&rt),
        );
        let store = record_stores
            .get_or_open(rt.base_dir(), "alice", rt.secrets())
            .expect("store opens under the unlocked context");

        // Two chat models — the first answers and the second does not displace
        // it — and one embed model, which answers for its own kind.
        //
        // The weights go in first, as `kotton model add` does it: `model_add`
        // refuses a manifest whose object is not already in the store and whose
        // hash does not match, which is the verify-before-seal rule and
        // is why the fixture bytes are hashed rather than named.
        let reassembly: kotton_device::users::files::SealedReassembly =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        for (name, kind, byte) in [
            ("first-chat", ModelKind::Chat, 0x31u8),
            ("second-chat", ModelKind::Chat, 0x32u8),
            ("first-embed", ModelKind::Embed, 0x33u8),
        ] {
            let body = vec![byte; 4];
            let weights = blake3::hash(&body).to_hex().to_string();
            let host = crate::agent::file_host::file_host(&rt, &*resources);
            let wrote = kotton_device::users::models::model_weights(
                &host,
                "alice".to_string(),
                body.clone(),
                0,
                body.len() as u64,
                weights.clone(),
                &reassembly,
            )
            .await
            .expect("write the weights");
            match wrote {
                kotton_wire::ipc::UserResponse::Ok => {}
                other => panic!("weights for {name} did not land: {other:?}"),
            }
            let weights = weights.as_str();
            let host = crate::agent::file_host::file_host(&rt, &*resources);
            let added = kotton_device::users::models::model_add(
                &host,
                &rt.schema_registry,
                &store,
                "alice".to_string(),
                manifest(name, kind, weights),
                chrono::Utc::now().to_rfc3339(),
            )
            .await
            .expect("model_add");
            // The response, not just the `io::Result`: `model_add` reports a
            // refusal as `UserResponse::Error`, so an `expect` on the outer
            // result alone would let a failed install pass silently.
            match added {
                kotton_wire::ipc::UserResponse::ModelInstalled { .. } => {}
                other => panic!("install of {name} was refused: {other:?}"),
            }
        }

        let proxy = Arc::new(InferProxy::new());
        let infer = infer_host(&rt, &record_stores, Some("alice".to_string()), &proxy);
        let shown = infer.models().await.expect("models");

        let names: Vec<&str> = shown.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names.contains(&"first-chat"),
            "the active chat model must be shown: {names:?}"
        );
        assert!(
            names.contains(&"first-embed"),
            "one model per *kind*, so the embed model answers too: {names:?}"
        );
        assert!(
            !names.contains(&"second-chat"),
            "a model the person did not make active must not be offered: {names:?}"
        );
        assert_eq!(shown.len(), 2, "exactly one per kind: {names:?}");
    }
}
