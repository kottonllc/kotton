// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which pools this vault keeps, live in this process.
//!
//! A vault is multi-tenant by construction (RFC-0084 V6): one process, many
//! people, each a pool keyed by the user id the pairing named. The map is the
//! vault's own bookkeeping — the device crate may name a user's store and may
//! not enumerate one, so the collection lives here, in the binary that decides
//! who is asking.

use kotton_device::users::residency::Residency;
use kotton_store::runtime::user::UserStore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The pools resident in this vault, by user id. Cloneable handle, shared map.
#[derive(Clone, Default)]
pub struct Pools {
    stores: Arc<RwLock<HashMap<String, Arc<UserStore>>>>,
}

impl Pools {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ids(&self) -> Vec<String> {
        self.stores.read().unwrap().keys().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.stores.read().unwrap().len()
    }

    pub fn all(&self) -> Vec<(String, Arc<UserStore>)> {
        self.stores
            .read()
            .unwrap()
            .iter()
            .map(|(id, s)| (id.clone(), Arc::clone(s)))
            .collect()
    }

    pub fn remove(&self, user_id: &str) -> bool {
        self.stores.write().unwrap().remove(user_id).is_some()
    }
}

impl Residency for Pools {
    fn insert(&self, user_id: String, store: Arc<UserStore>) {
        self.stores.write().unwrap().insert(user_id, store);
    }

    fn get(&self, user_id: &str) -> Option<Arc<UserStore>> {
        self.stores.read().unwrap().get(user_id).cloned()
    }
}
