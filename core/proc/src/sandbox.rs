// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a confined child is *granted*, said once and without a platform in it.
//!
//! `DEC-0074` rules that a process running a stranger's file is a guest and is
//! confined like one, and names `core/proc` as where that lives. This module is
//! the vocabulary; [`provider::sandbox`](crate::provider::sandbox) is the
//! enforcement, one implementation per operating system.
//!
//! # Two callers, and the profile is not shaped around either
//!
//! `kinferd` parses a weights file a stranger wrote. `kotton-runner` executes
//! WASM a third party shipped, on every launch of every app. `DEC-0074` §1 is
//! explicit that *a profile written after a choice describes that choice instead
//! of constraining it*, so nothing here is derived from what either process
//! happens to want. A [`Profile`] starts at [`Profile::nothing`] — no path, no
//! device, and no socket but a private pair — and a caller says what it adds, in
//! one line each, where a reader can count them.
//!
//! # There is no way to ask for the network
//!
//! Not a default, not a builder nobody calls: the type cannot express it. Both
//! of Kotton's confined processes are reached over a descriptor handed to them
//! at spawn and neither has any business with an address, and `Article VIII`
//! says no app reaches the network directly at all. A grant that cannot be
//! written is a grant no reviewer has to check for — the second design test in
//! `CLAUDE.md` applied to this file's own surface. If a confined process ever
//! genuinely needs an endpoint, that is a decision with a record, and the record
//! is what adds the constructor.
//!
//! # A sandbox is per-platform, and where there is none the answer is no
//!
//! [`confine`] returns [`SandboxError::Unsupported`] on an operating system
//! `core/proc` has no profile for, and `kinferd`'s caller refuses to spawn.
//! `DEC-0074` §1 accepts that cost in as many words: *where Kotton cannot
//! confine, it does not run a stranger's weights*. The alternative — spawning
//! unconfined and logging about it — is the shape that makes a sandbox
//! decorative.
//!
//! The runner's caller refuses on `Unsupported` on Linux and nowhere else, and
//! the second half is a stated concession rather than this module's policy:
//! whether §1 reaches every guest app, and so the desktop itself on a platform
//! with no provider, is an owner decision escalated on
//! `TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there`, and
//! until it is made those platforms keep the one layer they always had. This
//! module answers the same way either way; what a caller does with the answer
//! is at the call site, where a reader can see it.

use std::path::PathBuf;

/// What a confined process may do with one path.
///
/// Read implies neither write nor execute, and none of them implies the
/// network, which this vocabulary cannot say at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Open for reading, and list it if it is a directory.
    Read,
    /// Read, and create, write, truncate and remove beneath it.
    Write,
    /// Read and execute — the image of the program itself, and the shared
    /// libraries its loader resolves on the way in.
    Execute,
    /// Read, write and drive a device node.
    ///
    /// Unused by either caller today and present deliberately: `DEC-0074` §3
    /// splits the inference runtime into a parse half with no device and an
    /// execute half that may hold the graphics one, and a profile that could
    /// not say "this half, not that one" would have to be widened later by
    /// whoever writes the split — which is the retrofit §1 forbids. Exercised
    /// by `provider::sandbox`'s tests against `/dev/null`.
    Device,
}

/// One path and what may be done beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The path granted. It must exist when [`confine`] is called — see
    /// [`SandboxError::NoSuchGrant`].
    pub path: PathBuf,
    /// What is permitted beneath it.
    pub reach: Reach,
}

/// Everything a confined child is allowed, and by omission everything it is not.
///
/// Built by addition from [`Profile::nothing`], so the reach of a spawn is the
/// list of lines at its call site and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    purpose: String,
    grants: Vec<Grant>,
}

impl Profile {
    /// The floor: no path, no device, and no socket but a private pair.
    ///
    /// On Linux that means `socket(2)`, `connect`, `bind`, `listen`, `accept`
    /// and the three `io_uring` calls return `EPERM`, and only
    /// `socketpair(AF_UNIX, …)` succeeds — each measured against the kernel in
    /// `core/proc/tests/sandbox.rs`. It is a list of the routes known to make
    /// an endpoint, not a proof that there are no others: `io_uring` was one
    /// nobody had listed until 2026-09-23 (`DEC-0074`).
    ///
    /// `purpose` names the confined process for diagnostics — it is not a
    /// policy key, and nothing reads it to decide anything.
    pub fn nothing(purpose: impl Into<String>) -> Self {
        Self {
            purpose: purpose.into(),
            grants: Vec::new(),
        }
    }

    /// The program the child is about to become.
    ///
    /// Confinement is applied between `fork` and `execve`, so without this the
    /// `execve` itself is the first thing denied. What else an image needs to
    /// start — a dynamic loader and the system libraries it resolves — is a
    /// platform fact and belongs to the platform's provider, not to this list.
    pub fn executing(self, exe: impl Into<PathBuf>) -> Self {
        self.granting(exe, Reach::Execute)
    }

    /// One path the child may read, and nothing outside it.
    pub fn reading(self, path: impl Into<PathBuf>) -> Self {
        self.granting(path, Reach::Read)
    }

    /// One path the child may read and write beneath.
    pub fn writing(self, path: impl Into<PathBuf>) -> Self {
        self.granting(path, Reach::Write)
    }

    /// One device node the child may open and drive.
    pub fn device(self, path: impl Into<PathBuf>) -> Self {
        self.granting(path, Reach::Device)
    }

    fn granting(mut self, path: impl Into<PathBuf>, reach: Reach) -> Self {
        self.grants.push(Grant {
            path: path.into(),
            reach,
        });
        self
    }

    /// What this profile is for, for a diagnostic.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Every grant, in the order the caller wrote it.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }
}

/// Why a spawn was not confined — and therefore why it did not happen.
///
/// Every variant is a refusal. None of them is a reason to continue: a caller
/// that treats one as a warning has reinvented the unconfined spawn these
/// records exist to end.
#[derive(Debug)]
pub enum SandboxError {
    /// This operating system has no profile in `core/proc`.
    ///
    /// `DEC-0074` §1: where Kotton cannot confine, it does not run a stranger's
    /// file. The remedy is a provider for the platform, not a flag.
    Unsupported {
        /// The purpose the refused profile named.
        purpose: String,
        /// The operating system, as `std::env::consts::OS` reports it.
        os: &'static str,
    },
    /// The platform has a provider, but this kernel will not enforce it.
    ///
    /// A kernel without Landlock, or a seccomp that will not load a filter, is
    /// the same answer as no provider at all — the process would run
    /// unconfined.
    Unavailable {
        /// The purpose the refused profile named.
        purpose: String,
        /// What the kernel said, in the provider's words.
        reason: String,
    },
    /// A grant named a path that does not exist.
    ///
    /// Confinement names an inode, so a grant on a path that is not there yet
    /// cannot be written without silently widening it to whichever ancestor
    /// *does* exist. The caller creates what it owns before it spawns; a
    /// missing path is its bug and says so here rather than surfacing later as
    /// a child that cannot open its own database.
    NoSuchGrant {
        /// The purpose the refused profile named.
        purpose: String,
        /// The path that was granted and is not there.
        path: PathBuf,
    },
    /// The kernel refused part of the profile.
    Refused {
        /// The purpose the refused profile named.
        purpose: String,
        /// Which step — creating the ruleset, adding a rule, loading a filter.
        step: &'static str,
        /// The errno the kernel returned.
        source: std::io::Error,
    },
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { purpose, os } => write!(
                f,
                "{purpose} cannot be confined on {os}: core/proc has no sandbox for this platform, \
                 and DEC-0074 §1 rules that where Kotton cannot confine it does not run a \
                 stranger's code"
            ),
            Self::Unavailable { purpose, reason } => write!(
                f,
                "{purpose} cannot be confined on this kernel: {reason}"
            ),
            Self::NoSuchGrant { purpose, path } => write!(
                f,
                "{purpose} was granted {}, which does not exist; a grant names an inode, so the \
                 caller creates what it owns before it spawns",
                path.display()
            ),
            Self::Refused {
                purpose,
                step,
                source,
            } => write!(f, "{purpose}: the kernel refused {step}: {source}"),
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Confine `cmd` to `profile`, so that the process it spawns has exactly the
/// reach the profile names and no other.
///
/// The confinement is prepared here, in the parent, and applied in the child
/// between `fork` and `execve`. That order matters twice: the child never runs
/// a single instruction unconfined, and the child needs no sandbox code of its
/// own — a process cannot be trusted to confine itself, and `kinferd` and
/// `kotton-runner` do not have to be.
///
/// Returns [`Err`] rather than confining partially. A caller's only correct
/// response is to not spawn.
pub fn confine(
    cmd: &mut tokio::process::Command,
    profile: &Profile,
) -> Result<(), SandboxError> {
    crate::provider::sandbox::confine(cmd, profile)
}

/// Whether this build has a sandbox for the platform it is running on.
///
/// For a test or a diagnostic to say *why* it is not running, rather than a
/// caller to decide whether to bother — [`confine`] is the only thing that
/// decides, and it decides by refusing.
pub fn available() -> bool {
    crate::provider::sandbox::AVAILABLE
}
