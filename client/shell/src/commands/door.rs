// SPDX-License-Identifier: AGPL-3.0-or-later
//! `door` — the local-network door: whether this device listens and announces on the
//! network it is on (`TASK-the-local-network-is-a-door-opened-on-purpose-for-ten-minutes-and-a-relay-introduces-your-devices`).
//!
//! Three answers to one question, as the Settings row has them: `closed` (the
//! default everywhere), `10m` (open here, then shut by itself) and `always` (kept open
//! on this one network, for a home with no relay — every device on it can see it).

use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

pub struct DoorCommand;

#[async_trait]
impl Command for DoorCommand {
    fn help_text(&self) -> &'static str {
        "door [status | closed | 10m | always] — open this device to your devices on this network"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let answer = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
            [] | ["status"] => None,
            [word @ ("closed" | "10m" | "always")] => Some((*word).to_owned()),
            _ => {
                return Ok(CommandOutput::fail(
                    "usage: door [status | closed | 10m | always]",
                    None,
                ))
            }
        };
        let mut client = state.client.lock().await;
        let door = client
            .local_door(answer)
            .await
            .map_err(|e| anyhow::anyhow!("door: {e}"))?;
        let said = match (door.answer.as_str(), door.remaining_secs) {
            ("10m", Some(s)) => format!("open · {} minutes left, then closed", s.div_ceil(60)),
            ("always", _) => "always open on this network — every device here can see it".into(),
            _ => "closed".into(),
        };
        let mut record = vec![("door".into(), said)];
        if !door.network_known {
            record.push((
                "network".into(),
                "not recognised — always is not available here".into(),
            ));
        }
        Ok(CommandOutput::shapes(vec![Out::Record(record)]))
    }
}
