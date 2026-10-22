// SPDX-License-Identifier: AGPL-3.0-or-later
//! Install, list, and remove confined extensions.
//!
//! Deliberately a sibling of [`super::apps`] rather than an extension of it. An
//! app declares which of the user's data it wants; an extension declares which
//! *class* it is, and the class selects the WIT world that decides what it can
//! reach at all. Keeping the handlers apart keeps the two consent stories from
//! being rendered by one code path that forgets to discriminate.
//!
//! Everything security-relevant already happened before this module runs:
//! `kotton_store::runtime::extension_install::verify_package` computes the
//! content hash from the bytes, verifies the publisher signature, parses every
//! declared endpoint against the enforcer's own parser, and derives the grants
//! from the class. This module is the plumbing over that decision — write the
//! package, insert the row, mint and store the envelope.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kotton_app::extension_install::{verify_package, VerifiedExtension};
use kotton_common::time::now_secs;
use kotton_schemas::NetworkDeclaration;
use kotton_sys::secret::SecretsStore;
use kotton_wire::ipc::InstalledExtension;
use kotton_wire::UserResponse;
use sqlx::SqlitePool;
use tokio::fs;

use crate::db::extension_registry_db::{self as exdb, ExtensionRow};
use kotton_app::daemon::apps::{build_signed_envelope, verify_publisher_signature};
use kotton_grant::daemon::db::grant_db;
use kotton_wire::GrantLifetime;

/// Where an extension's package lives: `{base}/extensions/{id}/extension.wasm`.
fn wasm_path_for(base: &Path, extension_id: &str) -> PathBuf {
    base.join("extensions")
        .join(extension_id)
        .join("extension.wasm")
}

fn manifest_path_for(base: &Path, extension_id: &str) -> PathBuf {
    base.join("extensions")
        .join(extension_id)
        .join("manifest.toml")
}

/// The declared network posture, serialized **as consented**.
///
/// Stored rather than re-read from the on-disk manifest at load, so an edit to
/// that file cannot widen what the user approved.
fn network_json(v: &VerifiedExtension) -> Option<String> {
    match &v.manifest.network {
        NetworkDeclaration::None => None,
        NetworkDeclaration::Endpoints { patterns, .. } => {
            serde_json::to_string(&serde_json::json!({ "endpoints": patterns })).ok()
        }
    }
}

fn endpoints_of(row: &ExtensionRow) -> Vec<String> {
    row.network_json
        .as_deref()
        .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
        .and_then(|v| {
            v.get("endpoints").and_then(|e| e.as_array()).map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// `user_db` is the caller's per-user agent database:
/// the registry row and the grant envelope both live there.
pub(crate) async fn extension_install(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    user_id: &str,
    manifest_toml: String,
    wasm_bytes: Vec<u8>,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    // The whole security decision, in one call. Signature verification is
    // injected so the pure layer stays free of crypto-provider wiring.
    let verified = verify_package(&manifest_toml, &wasm_bytes, |did, sig, hash| {
        verify_publisher_signature(did, sig, hash)
    })
    .map_err(|e| io::Error::other(format!("extension rejected: {e}")))?;

    let extension_id = verified.manifest.id.clone();
    if !verified.signed {
        tracing::warn!(%extension_id, "installing unsigned extension");
    }

    let wasm_path = wasm_path_for(base, &extension_id);
    if let Some(parent) = wasm_path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    fs::write(&wasm_path, &wasm_bytes).await?;
    fs::write(
        &manifest_path_for(base, &extension_id),
        manifest_toml.as_bytes(),
    )
    .await?;

    let row = ExtensionRow {
        extension_id: extension_id.clone(),
        name: verified.manifest.name.clone(),
        version: verified.manifest.version.clone(),
        class: verified.manifest.class.world().to_string(),
        description: verified.manifest.description.clone(),
        wasm_path: wasm_path.to_string_lossy().into_owned(),
        content_hash: verified.content_hash.clone(),
        publisher_did: verified.manifest.publisher.as_ref().map(|p| p.did.clone()),
        network_json: network_json(&verified),
        credential_slots: verified
            .manifest
            .credentials
            .iter()
            .map(|c| c.slot.clone())
            .collect(),
        installed_at: now_secs(),
    };
    exdb::insert_extension(user_db, &row).await?;

    // The capabilities were derived from the class, not requested. Signing them
    // into an envelope is what makes them authority: the registry row is a
    // record, the envelope is the grant.
    if let Some(envelope) = build_signed_envelope(
        base,
        user_id,
        &extension_id,
        verified.grants.iter().cloned().collect(),
        secrets,
        // Same reasoning as app_install: signed once, never re-issued, so an
        // expiry here is a fuse rather than a control.
        GrantLifetime::UntilRevoked,
    ) {
        if let Err(e) = grant_db::store_envelope(user_db, &extension_id, &envelope).await {
            tracing::warn!(%extension_id, "failed to store grant envelope: {e}");
        }
    } else {
        tracing::debug!(%extension_id, %user_id, "identity key unavailable; no GrantEnvelope");
    }

    tracing::info!(%extension_id, class = %row.class, signed = verified.signed, "extension installed");
    Ok(UserResponse::ExtensionInstalled {
        extension_id,
        name: verified.manifest.name.clone(),
        class: row.class.clone(),
        content_hash: verified.content_hash.clone(),
        signed: verified.signed,
        consent_summary: verified.consent_summary(),
    })
}

pub(crate) async fn extension_list(user_db: &Arc<SqlitePool>) -> io::Result<UserResponse> {
    let rows = exdb::list_extensions(user_db).await?;
    Ok(UserResponse::ExtensionList {
        extensions: rows
            .iter()
            .map(|r| InstalledExtension {
                extension_id: r.extension_id.clone(),
                name: r.name.clone(),
                version: r.version.clone(),
                class: r.class.clone(),
                description: r.description.clone(),
                content_hash: r.content_hash.clone(),
                publisher_did: r.publisher_did.clone(),
                endpoints: endpoints_of(r),
                credential_slots: r.credential_slots.clone(),
                installed_at: r.installed_at,
            })
            .collect(),
    })
}

/// Remove an extension.
///
/// Order matters: **revoke the grants first.** The signed envelope is the
/// authority, not the registry row — so if anything below fails partway, the
/// extension has already lost its capabilities rather than merely looking
/// uninstalled while retaining them.
pub(crate) async fn extension_remove(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    extension_id: &str,
) -> io::Result<UserResponse> {
    if exdb::get_extension(user_db, extension_id).await?.is_none() {
        return Err(io::Error::other(format!(
            "extension '{extension_id}' is not installed"
        )));
    }

    grant_db::delete_envelopes_for_app(user_db, extension_id).await?;
    exdb::delete_extension(user_db, extension_id).await?;

    let dir = base.join("extensions").join(extension_id);
    if let Err(e) = fs::remove_dir_all(&dir).await {
        // The grants are gone, which is the part that matters; a leftover
        // directory is untidy, not dangerous.
        tracing::warn!(%extension_id, "package directory not removed: {e}");
    }

    tracing::info!(%extension_id, "extension removed and grants revoked");
    Ok(UserResponse::ExtensionRemoved {
        extension_id: extension_id.to_string(),
    })
}
