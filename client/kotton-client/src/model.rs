// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `model` domain — the models a person has installed (RFC-0085,
//! `DEC-0073`).
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut models = client.model("did:key:…");
//! for installed in models.list().await? {
//!     println!("{} {}", installed.manifest.name, installed.active);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Installing is two calls, and the weights are the daemon's
//!
//! The weights go in through their own chunked door
//! ([`KottonClient::seal_model_weights`], the `ModelWeights` verb), and then
//! the manifest is written as a record ([`KottonClient::model_add`]). The
//! caller names the weights' hash and never a path: the daemon keeps them at
//! its own key for that hash, outside the person's tree, and commits them only
//! if the stream hashes to it — so the hash the caller declares is
//! `ModelManifest::weights`, and the daemon's check on the way in is the
//! manifest's verification (`DEC-0073`).
//!
//! Until 2026-09-24 the weights went in through the ordinary `WriteFile`, to a
//! path in the person's tree — which is a path a guest granted `files.write`
//! on `/` could overwrite after the install
//! (`TASK-a-models-weights-are-the-daemons-and-no-files-grant-reaches-them`).

use std::io;
use std::path::Path;

use kotton_wire::ipc::InstalledModel;

use super::{KottonClient, UserRequest, UserResponse};
use kotton_schemas::ModelManifest;

/// The `model` domain, bound to one user.
pub struct Model<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `model` domain for a user.
    pub fn model(&mut self, user_id: &str) -> Model<'_> {
        Model {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Model<'_> {
    /// Seal a weights file into this user's store, then install its manifest.
    ///
    /// Returns the model's id (its weights hash) and whether it is now the model
    /// of its kind that answers.
    pub async fn add(
        &mut self,
        weights_file: &Path,
        manifest: &ModelManifest,
    ) -> io::Result<(String, bool)> {
        let u = self.user_id.clone();
        self.client.seal_model_weights(&u, weights_file, &manifest.weights).await?;
        self.client.model_add(&u, manifest).await
    }

    /// Every model this user has installed.
    pub async fn list(&mut self) -> io::Result<Vec<InstalledModel>> {
        let u = self.user_id.clone();
        self.client.model_list(&u).await
    }

    /// Remove a model — its manifest record and the weights it names.
    pub async fn remove(&mut self, model: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.model_remove(&u, model).await
    }

    /// Choose which model of its kind answers.
    pub async fn use_model(&mut self, model: &str, rebuild_index: bool) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.model_use(&u, model, rebuild_index).await
    }
}

impl KottonClient {
    /// Stream a weights file from disk into the daemon's object for its hash.
    ///
    /// A weights file is the largest thing this protocol carries, so it is read
    /// from disk in chunks and never held whole in this process, and the daemon
    /// streams the chunks into the store as they land and never holds it
    /// either. No path is named: the daemon derives its key from
    /// `content_hash`, outside the person's tree.
    pub async fn seal_model_weights(
        &mut self,
        user_id: &str,
        source: &Path,
        content_hash: &str,
    ) -> io::Result<u64> {
        use tokio::io::AsyncReadExt as _;

        const CHUNK: usize = 4 * 1024 * 1024;
        let total_size = tokio::fs::metadata(source).await?.len();

        let mut file = tokio::fs::File::open(source).await?;
        let mut buf = vec![0u8; CHUNK];
        let mut offset = 0u64;
        loop {
            let mut filled = 0usize;
            // `read` may return a short read on any file; a short chunk in the
            // middle of the stream is not an error but it is also not the end,
            // so fill the buffer before framing one.
            while filled < CHUNK {
                let n = file.read(&mut buf[filled..]).await?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            let request = UserRequest::ModelWeights {
                user_id: user_id.to_string(),
                data: buf[..filled].to_vec(),
                offset,
                total_size,
                content_hash: content_hash.to_string(),
            };
            match self.client.send(&request).await? {
                UserResponse::Ok => {}
                UserResponse::Error { message } => return Err(io::Error::other(message)),
                got => return Err(crate::protocol::unexpected(got)),
            }
            offset += filled as u64;
            if offset >= total_size {
                break;
            }
        }
        Ok(offset)
    }

    /// Write the manifest record for weights already sealed into the store.
    pub async fn model_add(
        &mut self,
        user_id: &str,
        manifest: &ModelManifest,
    ) -> io::Result<(String, bool)> {
        let request = UserRequest::ModelAdd {
            user_id: user_id.to_string(),
            manifest: manifest.clone(),
        };
        match self.client.send(&request).await? {
            UserResponse::ModelInstalled { id, active } => Ok((id, active)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Every model this user has installed.
    pub async fn model_list(&mut self, user_id: &str) -> io::Result<Vec<InstalledModel>> {
        let request = UserRequest::ModelList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::ModelList { models } => Ok(models),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Remove a model and the weights it names.
    pub async fn model_remove(&mut self, user_id: &str, model: &str) -> io::Result<()> {
        let request = UserRequest::ModelRemove {
            user_id: user_id.to_string(),
            model: model.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Choose which model of its kind answers.
    pub async fn model_use(
        &mut self,
        user_id: &str,
        model: &str,
        rebuild_index: bool,
    ) -> io::Result<()> {
        let request = UserRequest::ModelUse {
            user_id: user_id.to_string(),
            model: model.to_string(),
            rebuild_index,
        };
        match self.client.send(&request).await? {
            UserResponse::ModelInstalled { .. } => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// The BLAKE3 of a file on disk, read in chunks.
///
/// A model is gigabytes, so this never holds the file: the hash a person's
/// manifest is checked against must be computable on a machine that cannot hold
/// the model in memory.
pub fn hash_file(path: &Path) -> io::Result<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// The hash a manifest is checked against is computed without holding the
    /// file, so it has to agree with the one-shot hash the daemon computes over
    /// the reassembled bytes.
    #[test]
    fn a_streamed_hash_is_the_hash_of_the_whole_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("weights.gguf");
        // Larger than the 1 MiB read buffer, so more than one update runs.
        let body: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::File::create(&path)
            .expect("create")
            .write_all(&body)
            .expect("write");

        assert_eq!(
            hash_file(&path).expect("hash"),
            blake3::hash(&body).to_hex().to_string()
        );
    }
}
