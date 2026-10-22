// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton whoami` — the three things a person means by "logged in", on one
//! screen, each with its remedy (`TASK-three-things-are-called-being-logged-in`).
//!
//! | line | what it is | where it lives |
//! |---|---|---|
//! | acting as | the active identity, a local preference | `active_identity` |
//! | session | whether the daemon will answer for that name | the daemon, via `GetUnlockState` |
//! | vault | whether the identity's keys are in custody | the same verb |
//!
//! The daemon lines come from one verb, and the words are the SDK's
//! (`UnlockState::readout`), so the shell's `whoami` says the same thing.
//!
//! It never prompts. A readout that opened a session would be answering a
//! different question from the one asked; `resume_cached_session` uses the
//! cached token if there is one and reports its absence otherwise.

use kotton::KottonClient;
use kotton_common::time::now_secs;
use std::io;

pub async fn run() -> io::Result<()> {
    crate::active_identity::print_whoami();
    let Some(user) = std::env::var("KOTTON_USER").ok().filter(|v| !v.is_empty()) else {
        return Ok(());
    };
    let mut client = match KottonClient::connect().await {
        Ok(c) => c,
        Err(e) => {
            println!("  daemon      not reachable ({e}) — start it with `kotton`");
            return Ok(());
        }
    };
    client.resume_cached_session(&user).await?;
    let state = client.get_unlock_state(&user).await?;
    for (label, value) in state.readout(&user, now_secs()) {
        println!("  {label:<11} {value}");
    }
    Ok(())
}
