// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{deprecated, retired, Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::ShellState;

/// sync — sync this device's drives, now.
///
/// Usage:
/// ```text
///   sync [--no-wait]
/// ```
///
/// The command-tree decision: "`sync` syncs this device's drives, now." A device syncs to its
/// person's drives and to nothing else: no device is a sync target, so nothing
/// here names one. The words the command-tree decision's table retires are answered by [`parse`],
/// the one parser for these words in either door: `sync now` runs `sync` with a
/// line naming it; the rules by drive (`sync add|list|remove`), the ad-hoc sync
/// against a named remote and `--node` are refused, exit 2, with the verb that
/// took their place. What a device keeps of a drive is `pin`'s, and the drives
/// are `drive`'s (the drive decision).
pub struct SyncCommand;

/// The verbs: the bare noun, and the words the table retired.
const VERBS: &[Verb] = &[
    Verb::current(""),
    Verb::alias("now", "sync"),
    Verb::gone("add", "pin"),
    Verb::gone("list", "pin list"),
    Verb::gone("remove", "pin"),
    Verb::gone("<remote>", "sync"),
];

const USAGE: &str = "usage: sync [--no-wait]";

/// What `sync` is now, said where a retired word is refused.
const SYNC_IS: &str = "`sync` syncs this device's drives, now; a device is not a sync target";
/// Where a rule's work went.
const PIN_IS: &str =
    "what this device keeps of a drive is `pin <drive> whole|on-demand|default`; `pin list` says it, and `drive list` lists your drives";

/// A line of `sync`, parsed: this device's drives, now, and whether it was typed
/// under the retired `sync now`.
#[derive(Debug, PartialEq, Eq)]
struct Line {
    no_wait: bool,
    was_now: bool,
}

/// The words after `sync`, as a [`Line`], or the refusal (exit 2).
fn parse(args: &[String]) -> Result<Line, CommandOutput> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let no_wait = |rest: &[&str]| rest.iter().all(|a| *a == "--no-wait" || *a == "-n");
    if words.contains(&"--node") {
        return Err(retired("sync --node", SYNC_IS));
    }
    match words.as_slice() {
        rest if no_wait(rest) => Ok(Line { no_wait: !rest.is_empty(), was_now: false }),
        ["now", rest @ ..] if no_wait(rest) => Ok(Line { no_wait: !rest.is_empty(), was_now: true }),
        ["add", ..] => Err(retired("sync add", PIN_IS)),
        ["list"] => Err(retired("sync list", PIN_IS)),
        ["remove", ..] => Err(retired("sync remove", PIN_IS)),
        ["--push" | "--pull", remote] => Err(retired(&format!("sync {} {remote}", words[0]), SYNC_IS)),
        [remote] if !remote.starts_with('-') => Err(retired(&format!("sync {remote}"), SYNC_IS)),
        _ => Err(CommandOutput::usage("sync: unknown form", Some(USAGE.into()))),
    }
}

#[async_trait]
impl Command for SyncCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let line = match parse(args) {
            Ok(line) => line,
            Err(refused) => return Ok(refused),
        };
        let mut out = Vec::new();
        if line.was_now {
            out.push(deprecated("sync now", "sync"));
        }
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        let (job_id, drives) = client
            .sync_drives(&user_id)
            .await
            .map_err(|e| anyhow::anyhow!("sync: {e}"))?;
        if drives == 0 {
            out.push(Out::Note(
                "this device keeps no drive yet — your things live on a drive; `vault invite --me` makes one".to_string(),
            ));
            return Ok(CommandOutput::shapes(out));
        }
        if line.no_wait {
            out.push(Out::Note(format!("syncing {drives} drive(s) (job {job_id})")));
            return Ok(CommandOutput::shapes(out));
        }
        let outcome = client
            .sync_await(&user_id, job_id, 60)
            .await
            .map_err(|e| anyhow::anyhow!("sync: {e}"))?;
        out.push(if outcome.files == 0 {
            Out::Note("already in sync".into())
        } else {
            Out::Confirm {
                action: format!(
                    "synced {} file(s), {} bytes, with {drives} drive(s)",
                    outcome.files, outcome.bytes
                ),
                subject: String::new(),
            }
        });
        Ok(CommandOutput::shapes(out))
    }

    /// A line this noun's parser refuses is answered here, before any door connects:
    /// a usage line, or a retired word with the verb that replaced it, is the parser's
    /// to say and asks the daemon nothing, so it exits 2 with no session and no identity.
    /// Only a line that parses opens a session.
    async fn execute_without_session(&self, args: &[String], _named: Option<&str>) -> Option<Result<CommandOutput>> {
        parse(args).err().map(Ok)
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["--no-wait"]
    }

    fn help_text(&self) -> &'static str {
        HELP
    }

    fn verbs(&self) -> &'static [Verb] {
        VERBS
    }
}

pub(crate) const HELP: &str = "\
sync — sync this device's drives, now

USAGE:
  sync [--no-wait]

A device syncs to your drives, never to another device: your other devices
get what this one writes by way of a drive. What this device keeps of each
drive is `pin`'s: `pin list` says it.

FLAGS:
  --no-wait   start the sync and return; `status` says when it last synced

Exit 0 when done, 1 when refused (the reason on stderr), 2 for a line that is
not the one above.

RETIRED:
  sync now                 is `sync`, and still runs it
  sync add|remove          gone: what this device keeps of a drive is `pin <drive>`
  sync list                gone: what it keeps is listed by `pin list`
  sync [--push|--pull] <remote>
                           gone: `sync` syncs this device's drives
  sync --node <id>         gone: a device is not a sync target";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{ExitCode, VerbIs};

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn bare_sync_is_this_devices_drives_now() {
        assert_eq!(parse(&words("")).ok(), Some(Line { no_wait: false, was_now: false }));
        assert_eq!(parse(&words("--no-wait")).ok(), Some(Line { no_wait: true, was_now: false }));
    }

    /// `sync now` is aliased: it runs `sync`, and says so.
    #[test]
    fn sync_now_runs_sync_under_its_old_name() {
        assert_eq!(parse(&words("now")).ok(), Some(Line { no_wait: false, was_now: true }));
        assert_eq!(parse(&words("now -n")).ok(), Some(Line { no_wait: true, was_now: true }));
    }

    /// Every retired word is refused, exit 2, naming what took its place.
    #[test]
    fn a_retired_word_is_refused_naming_the_verb_that_replaced_it() {
        for (line, names) in [
            ("add vault --watch", "pin <drive>"),
            ("list", "pin list"),
            ("remove vault", "pin <drive>"),
            ("vault", "`sync` syncs this device's drives"),
            ("--pull vault", "`sync` syncs this device's drives"),
            ("now --node did:key:z6Mk", "a device is not a sync target"),
        ] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "`sync {line}`");
            let said = format!("{:?}", refused.out);
            assert!(said.contains(names), "`sync {line}` was refused without naming {names}: {said}");
        }
    }

    #[test]
    fn the_table_declares_each_word_the_parser_answers() {
        for v in VERBS {
            let line = match v.word {
                "<remote>" => "vault".to_string(),
                w => w.to_string(),
            };
            let parsed = parse(&words(&line));
            match v.is {
                VerbIs::Current | VerbIs::Alias { .. } => assert!(parsed.is_ok(), "`sync {line}`"),
                VerbIs::Gone { .. } => assert!(parsed.is_err(), "`sync {line}`"),
            }
        }
    }
}
