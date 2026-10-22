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
