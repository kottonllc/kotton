// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory secrets provider.
//!
//! Simple HashMap-based implementation, holding nothing across a process exit.
//!
//! Chiefly for tests, which inject it directly. It is also what
//! [`crate::secrets_for_base_dir`] selects for a **throwaway root** — a base
//! directory under the system temp dir — and that is why this is compiled into
//! every build rather than gated behind `test-utils`. A real install still gets
//! [`crate::OsSecrets`]; the choice is made in one place, and the reasoning for
//! it lives there.

use kotton_sys::secret::{SecretsResult, SecretsStore};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// In-memory secrets store for testing only
pub struct MemorySecrets {
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

impl MemorySecrets {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemorySecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretsStore for MemorySecrets {
    fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
        Ok(self.secrets.read().unwrap().get(key).cloned())
    }

    fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        self.secrets
            .write()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        self.secrets.write().unwrap().remove(key);
        Ok(())
    }
}
