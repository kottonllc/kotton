// SPDX-License-Identifier: AGPL-3.0-or-later
//! Static conventions and constants for Kotton
//!
//! This crate defines deterministic conventions that are foundational to Kotton:
//! - Directory structure and paths
//! - Namespace conventions — [`namespace`]
//! - Port assignments (future)

/// Name of the storage mount every node creates at startup.
///
/// Reserved — [`kotton_runtime`] refuses it as a user-chosen remote name. It is
/// a constant rather than a literal because it was previously compared as a
/// string in several places, where a typo produced a runtime "remote not found"
/// instead of a compile error.
///
/// Note that VFS operations no longer name a store at all (RFC-0058); this
/// remains for the replication paths, which legitimately address one.
pub const LOCAL_MOUNT: &str = "local";

/// What `kuserd` logs when the window is gone and the daemon is staying up.
///
/// `TASK-quit-kotton-stops-the-daemon-and-closing-the-window-does-not`. The
/// recipe (`cargo xtask run::desktop`) waits on the daemon, so the only thing it
/// can say about the window is what it reads in the daemon's output — and a
/// recipe grepping for a sentence written somewhere else is a line that stops
/// printing the day somebody rewords a log message, with nothing failing.
///
/// So the sentence is one constant, `kuserd` logs it and the recipe matches it,
/// and `the_recipe_reads_the_lines_the_daemon_writes` in `xtask` holds the two
/// together. It is a *convention between two processes*, which is what this
/// crate is for.
pub const KUID_LEFT_LINE: &str = "the window closed; the daemon is still running";

/// What `kuserd` logs when it is stopping because the person quit.
///
/// The other half of [`KUID_LEFT_LINE`], and read by the recipe for the same
/// reason: it is how a person reading the terminal can tell *the daemon ended
/// because I asked it to* from *the daemon died*.
pub const DAEMON_QUIT_LINE: &str = "Quit Kotton: the daemon is stopping";

pub mod base32;
pub mod crypto;
pub mod fs;
pub mod listen;
pub mod namespace;
pub mod paths;
pub mod time;

// Re-export commonly used items
pub use paths::{
    base_dir, default_base_dir, kdeviced_ipc_name, kuserd_ipc_name, sessions_dir,
    user_apps_dir,
    user_config_dir,
    user_contracts_dir, user_daemon_dir, user_dir, user_identity_file, user_vfs_dir, users_dir,
};

#[cfg(unix)]
pub use paths::{daemon_socket_path, kdeviced_door, kuserd_door, runtime_dir};
#[cfg(unix)]
pub use paths::kuserd_socket_from_env;
