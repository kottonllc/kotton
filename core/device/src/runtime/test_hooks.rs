// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pauses a test sets on a runtime it holds, to put two devices' verbs in an
//! order it chooses (kotton #143). Debug builds only: a release build has no
//! field, no type and no call for them. Nothing reaches them over any wire;
//! only in-process code holding the [`DeviceRuntime`](super::DeviceRuntime)
//! does, which is a test's.

use tokio::sync::oneshot;

/// A pause a verb takes, once, when a test has set it.
struct Pause {
    reached: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

/// The pauses a test has set on this runtime.
#[derive(Default)]
pub struct TestHooks {
    move_listed: std::sync::Mutex<Option<Pause>>,
}

impl TestHooks {
    /// Pause this device's next `drive move` once it has listed every vault
    /// and before it holds anything. The first receiver fires when the move
    /// is there; sending on the second lets it go on.
    pub fn pause_next_move_after_listing(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached, at) = oneshot::channel();
        let (go, release) = oneshot::channel();
        *self.move_listed.lock().unwrap() = Some(Pause { reached, release });
        (at, go)
    }

    /// Where a move pauses, when a test set it to.
    pub(crate) async fn move_listed(&self) {
        let pause = self.move_listed.lock().unwrap().take();
        if let Some(Pause { reached, release }) = pause {
            let _ = reached.send(());
            let _ = release.await;
        }
    }
}
