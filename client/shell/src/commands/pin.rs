// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton_wire::ipc::{PinNotice, PinReadout, PinScope, PinValue};

use super::{Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::ShellState;

/// pin — what this device keeps of your drives.
///
/// Usage:
/// ```text
///   pin default whole|on-demand
///   pin <drive>[:/<folder>] whole|on-demand|default
///   pin list [--json]
/// ```
///
/// The command-tree decision's "What this device holds". The daemon writes each setting as a record
/// in your drive and keeps what it says (`kotton_device::users::pins`); this says
/// what it answered. [`parse`] is the one parser for these words, in either door.
pub struct PinCommand;

const USAGE: &str =
    "usage: pin default whole|on-demand | pin <drive>[:/<folder>] whole|on-demand|default | pin list [--json]";

/// The verbs: `default`, a drive or a folder of one, and `list`.
const VERBS: &[Verb] = &[Verb::current("default"), Verb::current("<drive>"), Verb::current("list")];

/// A line of `pin`, parsed: `list`, or a setting (`None` follows the one above).
#[derive(Debug, PartialEq, Eq)]
enum Line {
    List { json: bool },
    Set { scope: PinScope, value: Option<PinValue> },
}

/// The words after `pin`, as a [`Line`], or the usage refusal (exit 2).
fn parse(args: &[String]) -> Result<Line, CommandOutput> {
    let json = args.iter().any(|a| a == "--json");
    let words: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--json").collect();
    let usage = |what: String| Err(CommandOutput::usage(what, Some(USAGE.into())));
    match words.as_slice() {
        ["list"] => Ok(Line::List { json }),
        _ if json => usage("pin: `--json` is for `pin list`".into()),
        [scope, value] => {
            let scope = match PinScope::parse(scope) {
                Ok(s) => s,
                Err(e) => return usage(format!("pin: {e}")),
            };
            let value = match *value {
                "default" => None,
                word => match PinValue::parse(word) {
                    Some(v) => Some(v),
                    None => return usage(format!("pin: '{word}' is not whole, on-demand or default")),
                },
            };
            Ok(Line::Set { scope, value })
        }
        _ => usage("pin: unknown form".into()),
    }
}

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
        let line = match parse(args) {
            Ok(line) => line,
            Err(usage) => return Ok(usage),
        };
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        match line {
            Line::List { json } => {
                let pins = client.pin_list(&user_id).await.map_err(|e| anyhow::anyhow!("pin list: {e}"))?;
                if json {
                    return Ok(CommandOutput::shapes(vec![Out::Data(serde_json::to_string_pretty(&pins)?)]));
                }
                Ok(CommandOutput::shapes(readout(&pins)))
            }
            Line::Set { scope, value } => {
                let pins = client
                    .pin_set(&user_id, scope.clone(), value)
                    .await
                    .map_err(|e| anyhow::anyhow!("pin {}: {e}", scope.said()))?;
                let action = match (value, &scope) {
                    (Some(PinValue::Whole), PinScope::Default) => {
                        "this device keeps every drive it has not been told about whole".to_string()
                    }
                    (Some(PinValue::Whole), _) => "kept whole on this device; collecting what it lacks now".to_string(),
                    (Some(PinValue::OnDemand), _) => {
                        "kept on demand on this device: its index, and what you open".to_string()
                    }
                    (None, _) => "follows the setting above it on this device".to_string(),
                };
                let mut out = vec![Out::Confirm { action, subject: scope.said() }];
                out.extend(notices(&pins.notices));
                Ok(CommandOutput::shapes(out))
            }
        }
    }

    /// A line this noun's parser refuses is answered here, before any door connects:
    /// a usage line, or a retired word with the verb that replaced it, is the parser's
    /// to say and asks the daemon nothing, so it exits 2 with no session and no identity.
    /// Only a line that parses opens a session.
    async fn execute_without_session(&self, args: &[String], _named: Option<&str>) -> Option<Result<CommandOutput>> {
        parse(args).err().map(Ok)
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

    fn verbs(&self) -> &'static [Verb] {
        VERBS
    }

    fn answers_json(&self) -> bool {
        true
    }
}

pub(crate) const HELP: &str = "\
pin — what this device keeps of your drives

USAGE:
  pin default whole|on-demand                       this device's default, for every drive it has not been told about
  pin <drive>[:/<folder>] whole|on-demand|default   set a drive or a folder the other way on this device
  pin list [--json]                                 this device's default and exceptions, and the notices

  whole       keep on this device: every file's content is here, opened or not
  on-demand   fetch when opened: this device keeps the index — every name, and
              where its content is — and fetches a file's content when it is opened
  default     follow the setting above: a folder its drive's, a drive this device's default

Every device of yours sees every drive. The nearest setting wins: a folder's
over its drive's over this device's default. Your first device starts at
whole; a device paired later at on demand. Pins hold for `personal` today: a
device keeps no tree of a drive made with `drive create` yet, so its vault
alone holds it, and `status` says so.

`pin <drive> whole` collects: this device fetches what it lacks of the drive
now. A pinned file brings the pack it was written in: whatever else was written
beside it at the same sync comes with it, and stays while the pin does. Each
setting is a record in your drive, sealed like everything else, so your other
devices read it and the vault cannot.

You are told when no device of yours keeps a drive whole, and when this device
runs short of room for what it keeps whole, with the setting that keeps less.

FLAGS:
  --json   `list`: this device's default, exceptions and notices, as JSON on stdout

Exit 0 when done, 1 when refused (the reason on stderr), 2 for a line that is
not one of the above.

EXAMPLES:
  pin default on-demand         # fetch when opened, unless told otherwise
  pin personal:/photos whole    # keep this folder on this device
  pin personal:/photos default
  pin personal whole            # collect all my things
  pin list";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ExitCode;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    /// Every verb the table declares is a line this parser answers.
    #[test]
    fn every_declared_verb_parses() {
        assert_eq!(
            parse(&words("default on-demand")).ok(),
            Some(Line::Set { scope: PinScope::Default, value: Some(PinValue::OnDemand) })
        );
        assert_eq!(
            parse(&words("personal whole")).ok(),
            Some(Line::Set { scope: PinScope::Drive { drive: "personal".into() }, value: Some(PinValue::Whole) })
        );
        assert!(matches!(
            parse(&words("personal:/photos default")),
            Ok(Line::Set { scope: PinScope::Folder { .. }, value: None })
        ));
        assert_eq!(parse(&words("list")).ok(), Some(Line::List { json: false }));
        assert_eq!(parse(&words("list --json")).ok(), Some(Line::List { json: true }));
        assert_eq!(VERBS.len(), 3, "a verb was declared that this test does not parse");
    }

    #[test]
    fn a_line_that_is_not_one_exits_two() {
        for line in ["", "list everything", "personal", "personal sometimes", "personal whole --json"] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "`pin {line}`");
        }
    }

    /// The familiar words beside the tree's: "keep on this device" for whole, "fetch
    /// when opened" for on demand.
    #[test]
    fn the_help_says_whole_and_on_demand_in_the_words_people_know() {
        assert!(HELP.contains("whole       keep on this device"), "{HELP}");
        assert!(HELP.contains("on-demand   fetch when opened"), "{HELP}");
    }
}
