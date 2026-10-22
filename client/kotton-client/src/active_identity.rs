// SPDX-License-Identifier: AGPL-3.0-or-later
//! The **active identity** — which identity this device's surfaces act as when
//! nothing names one. A per-device preference, one file beside the rest of
//! Kotton's local data, and **the device's truth**: the CLI resolves its actor
//! from it, and the shell's in-memory `user_id` is a cache of it
//! (`TASK-three-things-are-called-being-logged-in`, "the other half").
//!
//! It lived in the CLI until 2026-09-13, which is why the shell could create an
//! identity and leave `kotton whoami` saying *no active identity set*: the
//! shell is a dependency of the CLI and could not reach the module that owned
//! the file. Both surfaces now read and write the same one through here
//! (`TASK-the-shell-does-not-initialise-the-active-identity`).
//!
//! The actor is never *guessed*: there is no default name. [`initialise`] sets
//! it only when nothing is set, from a name the person just chose; [`set`] is
//! the explicit choice (`id use`).

use kotton_common::base_dir;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn active_identity_path() -> io::Result<PathBuf> {
    let dir = base_dir().map_err(|e| io::Error::other(e.to_string()))?;
    Ok(dir.join("active_identity"))
}

/// The persisted active identity, if one is set.
pub fn get() -> Option<String> {
    get_in(&active_identity_path().ok()?)
}

/// Persist `name` as the active identity (creating the data dir if needed).
pub fn set(name: &str) -> io::Result<()> {
    set_in(&active_identity_path()?, name)
}

/// Set `name` as the active identity **only if none is set**.
///
/// The difference from [`set`] is the whole of it: this never overwrites a choice
/// a person made. `id use` is the choice; this is the initialisation.
///
/// **Why initialisation is not a guess.** This module's rule is that the actor is
/// never guessed, and it was written against the old silent
/// `default_value = "default"` — a name nobody had chosen, standing in for one
/// that might exist. The first identity on a device is not that: it is a
/// determination, made by the person, in the command they just ran. Leaving it
/// unset instead puts `kotton id use <name>` in front of every walked path on a
/// device with exactly one identity, which is every runbook in the tree — and on
/// a *recovering* device it was worse than an extra step, because `peer add` was
/// the next command and had no session, no identity and no way to be told one
/// except a flag the printed card did not carry
/// (`TASK-three-things-are-called-being-logged-in`, "Corrected 2026-09-11", and
/// `TASK-add-recovery-prints-the-card`).
///
/// **Why it still never overwrites, now that the card carries the flag
/// (2026-10-06).** That last sentence was the case for initialising, and it
/// left a hole: on a device that *already* acts as someone, `id login <name>`
/// keeps it acting as them, so the card's bare `peer add` put the node in their
/// pool, succeeded, and left `id recover` no node to ask
/// (`TASK-recovery-onto-a-device-with-another-identity-adds-the-node-to-that-identitys-pool`).
/// The record offered two answers: the card names the identity, or recovery
/// refuses where the active one is another. The card names it — each node's
/// line is `kotton peer --user <name> add …`, the flag before `add`
/// (`kotton_shell::commands::recovery_card`) — so recovery reads nothing from
/// this file and works the same on a wiped device and on one someone else is
/// using. A refusal would send the person back to the terminal to run `id use`
/// for a line the card could have spelled whole. And overwriting here, the
/// third way out, would let a recovery silently change who every later bare
/// command on the device acts as: someone's choice, undone by a command that
/// was not about them. Which identity a device acts as stays what `id use`
/// says.
///
/// Best effort: a device whose data dir is unwritable has bigger problems than
/// this preference, and failing the command the person actually ran would be the
/// wrong way to tell them.
pub fn initialise(name: &str) {
    let Ok(path) = active_identity_path() else {
        return;
    };
    if let Err(e) = initialise_in(&path, name) {
        eprintln!("  (could not remember '{name}' as this device's identity: {e})");
    }
}

// The three, against an explicit file — what the public verbs resolve the
// device's path for, and what the tests drive without touching the process's
// environment.

fn get_in(path: &Path) -> Option<String> {
    let name = fs::read_to_string(path).ok()?.trim().to_string();
    (!name.is_empty()).then_some(name)
}

fn set_in(path: &Path, name: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)?;
    }
    fs::write(path, name.trim())
}

fn initialise_in(path: &Path, name: &str) -> io::Result<()> {
    if get_in(path).is_some() {
        return Ok(());
    }
    set_in(path, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule both surfaces rely on: the first identity is remembered, and a
    /// later `initialise` never overrides a choice — only `set` does.
    #[test]
    fn initialise_remembers_the_first_and_never_the_second() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("active_identity");

        assert_eq!(get_in(&path), None, "a fresh device has no actor");
        initialise_in(&path, "avery").unwrap();
        assert_eq!(get_in(&path).as_deref(), Some("avery"));

        initialise_in(&path, "sam").unwrap();
        assert_eq!(get_in(&path).as_deref(), Some("avery"), "initialise is not a choice");

        set_in(&path, " sam \n").unwrap();
        assert_eq!(get_in(&path).as_deref(), Some("sam"), "`id use` is, and it trims");
    }
}
