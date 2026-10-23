// SPDX-License-Identifier: AGPL-3.0-or-later
//! One enforcement per operating system, behind the vocabulary in
//! [`crate::sandbox`].
//!
//! The shape follows `core/net`'s monitor, which is the tree's existing answer
//! to a thing that is genuinely different per platform: a module per operating
//! system and a module for every other one, selected by `cfg` so that the
//! platform Kotton cannot confine is a compile-time fact rather than a runtime
//! branch somebody can be talked out of.
//!
//! | Platform | Mechanism | Measured |
//! |---|---|---|
//! | Linux, x86-64 or aarch64 | Landlock for the filesystem; seccomp-BPF refusing `socket(2)`, the calls that use a socket, and `io_uring` | yes — `core/proc`'s own tests and the integration suite |
//! | Windows | an AppContainer with no capabilities, an ACE per grant for its SID, and a job object, attached at `CreateProcessW` to a child created suspended — **written and compiled, not reached by [`confine`](crate::sandbox::confine)**, which still returns [`SandboxError::Unsupported`](crate::sandbox::SandboxError::Unsupported): stable Rust gives a `Command` no way to carry the attribute list the container rides on (`windows.rs`, "Why `confine` still refuses") | yes — `core/proc`'s own tests, the probes in `windows.rs`, run on `windows-latest` on every pull request (`.github/workflows/windows.yml`); what is measured is the container spawned by those probes, not one reached through `confine` |
//! | anything else | [`SandboxError::Unsupported`](crate::sandbox::SandboxError::Unsupported) — the caller decides, and `kinferd`'s refuses | n/a |
//!
//! macOS has a mechanism for this (Seatbelt) and no provider here. It is its own
//! record, filed rather than guessed at: a confinement nobody can run is a
//! claim, and a claim in this position is worse than a refusal, because the
//! refusal is at least true. That is also why the Windows row says what it
//! says.
//!
//! The architecture half of the `cfg` is not fussiness. A seccomp filter names
//! syscalls by number and checks `seccomp_data.arch` against the one it was
//! built for, so a filter compiled for the wrong architecture is not a weaker
//! filter — it is a filter that matches nothing.

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod linux;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) use linux::{confine, AVAILABLE};

/// What a profile becomes on Windows, as data — compiled wherever the tests
/// run, so the translation is checked on the machines that cannot run it.
#[cfg(any(windows, test))]
mod appcontainer;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{confine, AVAILABLE};

#[cfg(not(any(
    windows,
    all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
mod unsupported;
#[cfg(not(any(
    windows,
    all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
pub(crate) use unsupported::{confine, AVAILABLE};
