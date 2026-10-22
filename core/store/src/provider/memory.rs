// SPDX-License-Identifier: AGPL-3.0-or-later
/// In-memory object storage for testing
use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// In-memory object storage (for testing)
#[derive(Clone)]
pub struct MemoryObjectStorage {
    /// In-memory storage (key -> data)
    storage: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryObjectStorage {
    /// Create new in-memory object storage
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryObjectStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ObjectStorage for MemoryObjectStorage {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        let key_str = key.to_string_lossy().to_string();
        let storage = self.storage.read().unwrap();
        storage
            .get(&key_str)
            .map(|data| Bytes::from(data.clone()))
            .ok_or(ObjectStorageError::NotFound(key_str))
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        let key_str = key.to_string_lossy().to_string();
        let mut storage = self.storage.write().unwrap();
        storage.insert(key_str, data.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        let key_str = key.to_string_lossy().to_string();
        let mut storage = self.storage.write().unwrap();
        storage
            .remove(&key_str)
            .ok_or(ObjectStorageError::NotFound(key_str))?;
        Ok(())
    }

    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let prefix_str = prefix.to_string_lossy().to_string();
        let storage = self.storage.read().unwrap();
        let mut result = Vec::new();

        for (key, data) in storage.iter() {
            if prefix_str.is_empty() || key.starts_with(&prefix_str) {
                result.push(ObjectMetadata {
                    key: key.clone(),
                    is_dir: false,
                    size: data.len() as u64,
                    modified: None,
                });
            }
        }

        Ok(result)
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        let key_str = key.to_string_lossy().to_string();
        let storage = self.storage.read().unwrap();
        storage
            .get(&key_str)
            .map(|data| ObjectMetadata {
                key: key_str.clone(),
                is_dir: false,
                size: data.len() as u64,
                modified: None,
            })
            .ok_or(ObjectStorageError::NotFound(key_str))
    }

    fn backend_name(&self) -> &str {
        "memory"
    }
}

/// Identity — an in-memory store applies no sealing, so the stored bytes are the
/// sealed view. Used as the inner store in tests that assert sync moves
/// ciphertext.
#[async_trait]
impl SealedObjectAccess for MemoryObjectStorage {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.get(key).await
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.put(key, blob).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryObjectStorage::new();
        let key = Path::new("test.txt");
        let data = b"Hello";

        storage.put(key, data).await.unwrap();
        let retrieved = storage.get(key).await.unwrap();
        assert_eq!(&retrieved[..], data);

        storage.delete(key).await.unwrap();
        assert!(storage.get(key).await.is_err());
    }

    #[tokio::test]
    async fn satisfies_object_storage_contract() {
        contracts::run_all(MemoryObjectStorage::new()).await;
    }
}
