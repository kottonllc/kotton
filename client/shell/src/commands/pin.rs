// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton_wire::ipc::{PinNotice, PinReadout, PinScope, PinValue};

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// pin — what this device keeps of your drives.
///
/// Usage:
/// ```text
///   pin default whole|on-demand
///   pin <drive>[:/<folder>] whole|on-demand|default
///   pin list
/// ```
///
/// The daemon writes each setting as a record in your drive and keeps what it
/// says (`kotton_device::users::pins`); this says what it answered.
pub struct PinCommand;

const USAGE: &str =
    "usage: pin default whole|on-demand | pin <drive>[:/<folder>] whole|on-demand|default | pin list";

/// The notices, each as a warning the person reads.
pub(crate) fn notices(notices: &[PinNotice]) -> Vec<Out> {
    notices
        .iter()
        .map(|n| Out::Warn {
            what: match n {
                PinNotice::NoWholeDevice { drive } => format!("no device keeps '{drive}' whole"),
                PinNotice::ShortOfRoom { drive, .. } => format!("short of room for '{drive}'"),
            },
            consequence: n.said(),
        })
        .collect()
}

fn readout(pins: &PinReadout) -> Vec<Out> {
    let mut rows = vec![vec!["default".to_string(), pins.default.said().to_string()]];
    rows.extend(pins.exceptions.iter().map(|s| vec![s.scope.said(), s.value.said().to_string()]));
    let mut out = vec![Out::Table { columns: vec!["this device keeps".into(), "".into()], rows }];
    out.extend(notices(&pins.notices));
    out
}

#[async_trait]
impl Command for PinCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        match args {
            [sub] if sub == "list" => {
                let pins = client.pin_list(&user_id).await.map_err(|e| anyhow::anyhow!("pin list: {e}"))?;
                Ok(CommandOutput::shapes(readout(&pins)))
            }
            [scope, value] => {
                let scope = match PinScope::parse(scope) {
                    Ok(s) => s,
                    Err(e) => return Ok(CommandOutput::fail(format!("pin: {e}"), Some(USAGE.into()))),
                };
                let value = match value.as_str() {
                    "default" => None,
                    word => match PinValue::parse(word) {
                        Some(v) => Some(v),
                        None => {
                            return Ok(CommandOutput::fail(
                                format!("pin: '{word}' is not whole, on-demand or default"),
                                Some(USAGE.into()),
                            ))
                        }
                    },
                };
                let pins = client
                    .pin_set(&user_id, scope.clone(), value)
                    .await
                    .map_err(|e| anyhow::anyhow!("pin {}: {e}", scope.said()))?;
                let action = match (value, &scope) {
                    (Some(PinValue::Whole), PinScope::Default) => "this device keeps every drive it has not been told about whole".to_string(),
                    (Some(PinValue::Whole), _) => "kept whole on this device; collecting what it lacks now".to_string(),
                    (Some(PinValue::OnDemand), _) => "kept on demand on this device: its index, and what you open".to_string(),
                    (None, _) => "follows the setting above it on this device".to_string(),
                };
                let mut out = vec![Out::Confirm { action, subject: scope.said() }];
                out.extend(notices(&pins.notices));
                Ok(CommandOutput::shapes(out))
            }
            _ => Ok(CommandOutput::fail("pin: unknown form", Some(USAGE.into()))),
        }
    }

    fn complete(&self, _args: &[String], arg_index: usize) -> Vec<String> {
        match arg_index {
            0 => vec!["default".into(), "list".into()],
            1 => vec!["whole".into(), "on-demand".into(), "default".into()],
            _ => vec![],
        }
    }

    fn help_text(&self) -> &'static str {
        HELP
    }
}

pub(crate) const HELP: &str = "\
pin — what this device keeps of your drives

USAGE:
  pin default whole|on-demand                       this device's default, for every drive it has not been told about
  pin <drive>[:/<folder>] whole|on-demand|default   set a drive or a folder the other way on this device
  pin list                                          this device's default and exceptions, and the notices

Every device of yours sees every drive. Whole keeps every file's content on
this device; on demand keeps the index — every name, and where its content is
— and fetches a file's content when it is opened. The nearest setting wins: a
folder's over its drive's over this device's default, and `default` follows
the one above. Your first device starts at whole; a device paired later at on
demand. The device that creates a drive keeps it whole.

`pin <drive> whole` collects: this device fetches what it lacks of the drive
now. Each setting is a record in your drive, sealed like everything else, so
your other devices read it and the vault cannot.

You are told when no device of yours keeps a drive whole, and when this device
runs short of room for what it keeps whole, with the setting that keeps less.

EXAMPLES:
  pin default on-demand
  pin personal:/photos whole
  pin personal:/photos default
  pin personal whole            # collect all my things
  pin list";
