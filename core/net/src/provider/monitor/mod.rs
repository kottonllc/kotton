// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network monitoring implementations
//!
//! Platform-specific monitors for detecting network topology changes.

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsNetworkMonitor;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOSNetworkMonitor;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxNetworkMonitor;

mod r#static;
pub use r#static::StaticNetworkMonitor;

/// OS-specific network monitor (alias to platform implementation)
#[cfg(target_os = "windows")]
pub type OsNetworkMonitor = WindowsNetworkMonitor;

#[cfg(target_os = "macos")]
pub type OsNetworkMonitor = MacOSNetworkMonitor;

#[cfg(target_os = "linux")]
pub type OsNetworkMonitor = LinuxNetworkMonitor;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub type OsNetworkMonitor = StaticNetworkMonitor;
