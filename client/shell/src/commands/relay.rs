// SPDX-License-Identifier: AGPL-3.0-or-later
//! `relay` — configure this device's rendezvous relay from inside the runtime,
//! instead of a `KOTTON_RELAY_URL` env var.
//!
//! A relay is a provider-blind rendezvous point: it lets your devices (and, later,
//! your contacts) find each other by DID without knowing IPs — it routes ciphertext
//! and never sees your keys or data (RFC-0024). The value persists in the device
//! config DB (which the daemon reads at startup, ahead of the env), so you set it
//! once. The per-user *cascade* of relays — your own → a friend's → community — is
//! the planned generalization (IDEA-relay-cascade).
//!
//! A relay you run is also made and operated from here — `mint relay` and
//! `enrol <its line>` make it, `relay rule` and `relay invite` operate it, under
//! that relay's own operator credential (DEC-0087); see [`super::operated`].

use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

pub struct RelayCommand;

/// A line of `relay` for this device's own relay, read: what [`RelayCommand`] runs once
/// none of the operator's verbs ([`super::operated::relay_operator`]) has read it, and
/// `set` is none of those.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Line<'a> {
    /// `relay` or `relay status`.
    Status,
    /// `relay set <code>`: a relay's line or a relay's invite, to stand this device there,
    /// held to the key the code names.
    SetCode(&'a str),
    /// `relay set <url>`.
    SetUrl(&'a str),
    /// `relay clear`.
    Clear,
}

/// The words after `relay`, as a [`Line`], or `None` for the usage refusal. The one
/// reading of this device's verbs: [`RelayCommand`] runs what it gives, and a test reads
/// a printed `relay set` back through it.
pub(super) fn read<'a>(words: &[&'a str]) -> Option<Line<'a>> {
    match words {
        [] | ["status"] => Some(Line::Status),
        ["set", code] if code.starts_with("kotton-") => Some(Line::SetCode(code)),
        ["set", url] => Some(Line::SetUrl(url)),
        ["clear"] => Some(Line::Clear),
        _ => None,
    }
}

#[async_trait]
impl Command for RelayCommand {
    fn help_text(&self) -> &'static str {
        "relay [set <url> | set <line or invite> | clear | status | rule [<r>] [<rule>] | invite [<r>] | rotate [<r>] | forget [<r>]] — configure the rendezvous relay, and operate a relay of your own, or forget one whose host is gone; <r> only when this desktop operates more than one relay. rotate gives the relay a new key for the people you invite, after you type its name back: the key before is read until the next rotation, so a second one refuses a device that has not reconnected to its vault since the first; it finishes a drop made at `kvaultd drop`, which names it. mint and enrol make one; relay and vault operate one: `mint relay`, then `enrol <its line>`, makes one"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        // The operator's verbs for a relay of your own (DEC-0087), under its
        // own credential; `set`, `clear` and `status` are this device's.
        if let Some(out) = super::operated::relay_operator(&words, state).await {
            return out;
        }
        let mut client = state.client.lock().await;

        match read(&words) {
            // `relay` / `relay status` — show the configured relay + reachability.
            Some(Line::Status) => {
                let info = client
                    .node_rendezvous_status()
                    .await
                    .map_err(|e| anyhow::anyhow!("relay: {e}"))?;
                let url = info
                    .url
                    .unwrap_or_else(|| "(none — direct connections only)".to_string());
                let reach = match info.server_reachable {
                    Some(true) => "reachable",
                    Some(false) => "unreachable",
                    None => "not yet contacted",
                };
                Ok(CommandOutput::shapes(vec![Out::Record(vec![
                    ("relay".into(), url),
                    ("status".into(), reach.into()),
                ])]))
            }

            // `relay set <code>` — a relay's line or a relay's invite: stand
            // this device there, held to the key the code names.
            Some(Line::SetCode(code)) => {
                let user_id = state.user_id.clone();
                client
                    .relay_stand(&user_id, code)
                    .await
                    .map_err(|e| anyhow::anyhow!("relay set: {e}"))?;
                let at = kotton_wire::line::Code::parse(code)
                    .map(|c| match c {
                        kotton_wire::line::Code::Line(l) => l.hint,
                        kotton_wire::line::Code::Invite(kotton_wire::line::InviteCode::Relay { hint, .. }) => hint,
                        kotton_wire::line::Code::Invite(kotton_wire::line::InviteCode::Vault { relay_hint, .. }) => relay_hint,
                    })
                    .unwrap_or_default();
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "relay set, held to the key its code names".into(),
                    subject: at,
                }]))
            }

            // `relay set <url>` — point this device at a rendezvous relay.
            Some(Line::SetUrl(url)) => {
                client
                    .node_rendezvous_set(Some(url))
                    .await
                    .map_err(|e| anyhow::anyhow!("relay set: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "relay set".into(),
                    subject: url.to_string(),
                }]))
            }

            // `relay clear` — remove the relay; fall back to direct-only.
            Some(Line::Clear) => {
                client
                    .node_rendezvous_set(None)
                    .await
                    .map_err(|e| anyhow::anyhow!("relay clear: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "relay cleared — direct connections only".into(),
                    subject: String::new(),
                }]))
            }

            None => Ok(CommandOutput::fail(
                format!("usage: relay [set <url> | clear | status] | {}", super::operated::RELAY_OPERATOR_USAGE),
                None,
            )),
        }
    }
}
