// SPDX-License-Identifier: AGPL-3.0-or-later
//! One bootstrap token per sidecar *start*, not per supervision.
//!
//! A process-scoped token binds to the first pid that presents it
//! (`kotton_session::service::tokens::PidClaim`), which is what makes it a
//! credential for one process. A supervisor that minted one token and then
//! restarted the sidecar under it would refuse every restart: `refusing a
//! process-scoped token presented from a different process`, three times, and
//! then supervision would give up.
//!
//! So each start mints its own, and the one before it is forgotten: a token
//! that was never presented is not a session anybody should be able to find.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};

use crate::agent::sessions;

pub(crate) struct SidecarToken {
    sessions: sessions::SessionMap,
    /// Where a gateway's tokens are also listed, so its sessions read as
    /// `Remote`. `None` for a sidecar that is not a gateway.
    gateway_tokens: Option<Arc<RwLock<HashSet<String>>>>,
    user_id: String,
    last: Mutex<Option<String>>,
}

impl SidecarToken {
    pub(crate) fn new(
        sessions: sessions::SessionMap,
        gateway_tokens: Option<Arc<RwLock<HashSet<String>>>>,
        user_id: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions,
            gateway_tokens,
            user_id,
            last: Mutex::new(None),
        })
    }

    /// A fresh process-scoped token for the start about to happen. The previous
    /// one is removed first, presented or not.
    pub(crate) fn mint(&self) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut last = self.last.lock().unwrap();
        if let Some(old) = last.take() {
            self.sessions.write().unwrap().remove(&old);
            if let Some(g) = &self.gateway_tokens {
                g.write().unwrap().remove(&old);
            }
        }
        sessions::insert_process_scoped(&self.sessions, token.clone(), self.user_id.clone());
        if let Some(g) = &self.gateway_tokens {
            g.write().unwrap().insert(token.clone());
        }
        *last = Some(token.clone());
        token
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn each_start_gets_its_own_token_and_the_last_is_forgotten() {
        let sessions: sessions::SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let gateway = Arc::new(RwLock::new(HashSet::new()));
        let t = SidecarToken::new(
            Arc::clone(&sessions),
            Some(Arc::clone(&gateway)),
            "alice".into(),
        );
        let first = t.mint();
        assert!(sessions.read().unwrap().contains_key(&first));
        assert!(gateway.read().unwrap().contains(&first));
        let second = t.mint();
        assert_ne!(first, second);
        assert!(
            !sessions.read().unwrap().contains_key(&first),
            "the unpresented token is gone"
        );
        assert!(!gateway.read().unwrap().contains(&first));
        assert!(sessions.read().unwrap().contains_key(&second));
        assert_eq!(
            sessions.read().unwrap().get(&second).unwrap().user_id,
            "alice"
        );
    }
}
