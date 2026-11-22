// SPDX-License-Identifier: AGPL-3.0-or-later
// Provisioning is `kotton_device::users`: `device` names `UserStore`, so those
// are inherent methods on `DeviceRuntime`, not an extension trait here.
pub mod agent;
pub mod bundled;
pub mod db;
pub mod device_users;
pub mod error;
pub mod event_log;
pub mod infer_proxy;
// What an installed Kotton finds beside its own daemon: the shell it stages at start
// — so a friend can install Kotton without a toolchain.
pub mod installed;
// The person's name, as a sealed record in their store; `device_users` holds
// each device's copy.
pub mod own_name;
// `lock_policy` is `kotton_session::lock_policy` — whether a PIN
// unlocks a session is that crate's question, not the daemon's.
pub mod residency;
pub mod surface_proxy;

pub use agent::DeviceDaemon;
pub use error::{DaemonError, Result};

/// What a closure logged, as the lines a log prints them in: for the tests
/// that hold what a log line may say.
#[cfg(test)]
pub(crate) fn logged(f: impl FnOnce()) -> String {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Caught(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Caught {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let caught = Caught::default();
    let writer = caught.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = caught.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}
