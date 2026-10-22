// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every operating system with no profile in `core/proc`.
//!
//! `DEC-0074` §1, in as many words: *where Kotton cannot confine, it does not
//! run a stranger's weights. That is a product cost and it is accepted.* This
//! file is that sentence compiled. It has no configuration, because the shape
//! that rots a sandbox is the one where an unconfined spawn is a setting away.

use crate::sandbox::{Profile, SandboxError};

/// There is no sandbox here.
pub(crate) const AVAILABLE: bool = false;

pub(crate) fn confine(
    _cmd: &mut tokio::process::Command,
    profile: &Profile,
) -> Result<(), SandboxError> {
    Err(SandboxError::Unsupported {
        purpose: profile.purpose().to_string(),
        os: std::env::consts::OS,
    })
}
