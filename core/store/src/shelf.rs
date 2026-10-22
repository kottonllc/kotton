// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shelves a node's mounts rest on.
//!
//! [`Shelves`] is the seam: it is asked for the raw backend of each local mount
//! when a store is created or reloaded, and the sealed stack is built over what
//! it answers. On a device the answer is a directory through the host's
//! filesystem — [`LocalShelves`] here. On a rented vault the landlord may
//! answer with a bucket instead ([`S3Shelves`](crate::provider::s3::S3Shelves)),
//! and nothing above the stack can tell the difference, which is the property:
//! a device that pushes to a vault is not told, and cannot ask, where its packs
//! rest.
//!
//! The filesystem arrives as a parameter rather than being named here, for the
//! reason `stack` gives: this crate must not know a host OS exists.

use kotton_sys::fs::Filesystem;
use kotton_sys::store::{Shelves, SyncableStore};
use std::path::Path;
use std::sync::Arc;

/// One shelf per mount, each a directory at the path the mount's configuration
/// names, written through the host's filesystem.
#[derive(Clone)]
pub struct LocalShelves<F>(pub F);

impl<F: Filesystem + Clone + 'static> Shelves for LocalShelves<F> {
    fn open(&self, _user_id: &str, _mount: &str, path: &Path) -> Arc<dyn SyncableStore> {
        Arc::new(crate::provider::LocalObjectStorage::new(
            path.to_path_buf(),
            self.0.clone(),
        ))
    }
}
