// SPDX-License-Identifier: AGPL-3.0-or-later
//! Client-side **active identity** — which identity the CLI acts as when neither
//! `--user` nor `KOTTON_USER` is given.
//!
//! The file and its three verbs (`get`, `set`, `initialise`) are the SDK's
//! (`kotton::active_identity`) since 2026-09-13, because the shell needs them too
//! and the shell cannot depend on this crate. What stays here is the CLI's own
//! use of them: resolving the actor into `KOTTON_USER` for clap, and the first
//! line of `whoami`.
//!
//! Resolution is wired without touching every command: [`apply_to_env`] runs once
//! at startup and, if `KOTTON_USER` is unset, populates it from the active
//! identity. clap's existing `env = "KOTTON_USER"` on each command then resolves
//! it, and an explicit `--user` flag still wins (flag beats env). So the order is
//! `--user → KOTTON_USER → active identity`, with a clear required-arg error if
//! nothing resolves.

pub use kotton::active_identity::{get, initialise, set};

/// Print the identity the CLI acts as — the first line of `whoami`. Names the
/// active identity and where it came from, or guides the user to set one. The
/// session and vault lines are `commands::whoami`, from the daemon.
pub fn print_whoami() {
    // Runs after `apply_to_env`, so KOTTON_USER holds the resolved actor (an
    // explicit --user/env, or the active identity it was populated from).
    match std::env::var("KOTTON_USER").ok().filter(|v| !v.is_empty()) {
        Some(name) => {
            println!("you are acting as: {name}");
            if get().as_deref() == Some(name.as_str()) {
                println!("  active identity — change with `kotton id use <name>`");
            } else {
                let active = get().unwrap_or_else(|| "none".to_string());
                println!("  from --user / KOTTON_USER (active identity: {active})");
            }
        }
        None => {
            println!("no active identity set.");
            println!("  run `kotton id use <name>` to choose one, or pass --user <name>.");
        }
    }
}

/// If `KOTTON_USER` is unset, populate it from the persisted active identity.
/// Call once at startup, before clap parses argv. No-op if the env var is already
/// set (an explicit env or `--user` flag always wins) or no active identity exists
/// (the command's required `--user` then fails cleanly — never a silent default).
pub fn apply_to_env() {
    let env_set = std::env::var("KOTTON_USER")
        .ok()
        .is_some_and(|v| !v.is_empty());
    if !env_set {
        if let Some(active) = get() {
            std::env::set_var("KOTTON_USER", active);
        }
    }
}
