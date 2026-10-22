// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory [`WindowRegistry`] implementation.
//!
//! This is the authoritative store for open WASM app windows. The daemon holds one
//! instance; shell windows (dock, hub) reach it through the verbs in
//! [`crate::commands`].

use crate::{WindowOwner, WindowRegistry, WindowState, WindowStateChanged};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use uuid::Uuid;

/// Channel capacity — enough for a burst of open/close events without blocking.
const CHANNEL_CAPACITY: usize = 64;

/// Default in-memory window registry, held by `kuserd` (the daemon with a
/// surface; the device runtime carries none).
pub struct InMemoryWindowRegistry {
    state: RwLock<HashMap<Uuid, WindowState>>,
    tx: broadcast::Sender<WindowStateChanged>,
}

impl InMemoryWindowRegistry {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Arc::new(Self {
            state: RwLock::new(HashMap::new()),
            tx,
        })
    }
}

impl Default for InMemoryWindowRegistry {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            state: RwLock::new(HashMap::new()),
            tx,
        }
    }
}

impl WindowRegistry for InMemoryWindowRegistry {
    fn window_opened(
        &self,
        owner: WindowOwner,
        app_id: String,
        instance_id: Uuid,
        title: String,
    ) {
        let ws = WindowState {
            owner,
            app_id,
            instance_id,
            title,
            badge: None,
            progress: None,
            attention: false,
        };
        {
            let mut map = self.state.write().unwrap();
            map.insert(instance_id, ws.clone());
        }
        let _ = self.tx.send(WindowStateChanged::Opened(ws));
    }

    fn window_closed(&self, owner: &WindowOwner, instance_id: Uuid) {
        // Remove only if the caller owns it. Checked under the write lock so a
        // concurrent open cannot slip between the look-up and the removal.
        let removed = {
            let mut map = self.state.write().unwrap();
            match map.get(&instance_id) {
                Some(ws) if ws.owner == *owner => map.remove(&instance_id),
                _ => None,
            }
        };
        if removed.is_some() {
            let _ = self
                .tx
                .send(WindowStateChanged::Closed { instance_id });
        }
    }

    fn window_list(&self, viewer: &WindowOwner) -> Vec<WindowState> {
        self.state
            .read()
            .unwrap()
            .values()
            .filter(|ws| viewer.may_see(&ws.owner))
            .cloned()
            .collect()
    }

    fn subscribe(&self) -> broadcast::Receiver<WindowStateChanged> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(did: &str) -> WindowOwner {
        WindowOwner::User(did.to_string())
    }

    /// The property the owner dimension exists for: a window title is user
    /// content, and one user must not read another's.
    #[test]
    fn a_user_sees_only_their_own_windows() {
        let reg = InMemoryWindowRegistry::new();
        let (alice, bob) = (user("did:key:alice"), user("did:key:bob"));

        reg.window_opened(
            alice.clone(),
            "sh.kotton.notes".into(),
            Uuid::new_v4(),
            "Tax Return 2025".into(),
        );
        reg.window_opened(
            bob.clone(),
            "sh.kotton.notes".into(),
            Uuid::new_v4(),
            "Shopping list".into(),
        );

        let seen: Vec<_> = reg.window_list(&alice);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].title, "Tax Return 2025");

        let seen: Vec<_> = reg.window_list(&bob);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].title, "Shopping list");
    }

    /// A system surface is not visible to a user, in either direction. This is
    /// what keeps a login prompt out of a user's window list, and a user's
    /// windows out of whatever renders the lock screen.
    #[test]
    fn system_and_user_windows_do_not_see_each_other() {
        let reg = InMemoryWindowRegistry::new();
        let alice = user("did:key:alice");

        reg.window_opened(
            WindowOwner::System,
            "sh.kotton.lock".into(),
            Uuid::new_v4(),
            "Unlock".into(),
        );
        reg.window_opened(
            alice.clone(),
            "sh.kotton.notes".into(),
            Uuid::new_v4(),
            "Notes".into(),
        );

        assert_eq!(reg.window_list(&alice).len(), 1);
        assert_eq!(reg.window_list(&alice)[0].title, "Notes");
        assert_eq!(reg.window_list(&WindowOwner::System).len(), 1);
        assert_eq!(reg.window_list(&WindowOwner::System)[0].title, "Unlock");
    }

    /// Closing is scoped too. An instance id is an unguessable UUID, but that is
    /// a property of the id rather than of the boundary — a leaked or logged id
    /// should not let one user close another's window.
    #[test]
    fn a_user_cannot_close_another_users_window() {
        let reg = InMemoryWindowRegistry::new();
        let (alice, bob) = (user("did:key:alice"), user("did:key:bob"));
        let id = Uuid::new_v4();

        reg.window_opened(alice.clone(), "sh.kotton.notes".into(), id, "Notes".into());

        reg.window_closed(&bob, id);
        assert_eq!(reg.window_list(&alice).len(), 1, "bob must not close alice's window");

        reg.window_closed(&WindowOwner::System, id);
        assert_eq!(reg.window_list(&alice).len(), 1, "system must not close it either");

        reg.window_closed(&alice, id);
        assert!(reg.window_list(&alice).is_empty(), "the owner closes it");
    }
}
