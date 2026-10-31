// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton_schemas::membership::Posture;
use kotton_wire::ipc::DriveDescriptor;

use super::device::ENROL_POSTURES;
use super::{Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::ShellState;

/// drive — your drives: where your things live.
///
/// Usage:
/// ```text
///   drive create <name> [--on <vault>]
///   drive list [--json]
///   drive show <name> [--json]
///   drive move <name> --to <vault> [--from <vault>]
///   drive enrol <invite>
/// ```
///
/// The command-tree decision's "Drives" line, but `export`, which waits on the vault's cut. The
/// daemon asks the vaults (`kotton_device::users::drive_verbs`); this says what
/// they answered. `enrol` is the tenant's side of a vault's invite, the ceremony `device admit`
/// named until the command-tree decision's table retired that word: `device admit` is now
/// refused with a line naming this one (exit 2, before any session, in both doors). `drive
/// enrol` sends the same request (`DeviceAdmit`), so the retirement moved no reach; the tree
/// has one word for it.
///
/// [`parse`] is the one parser for these words: `kotton drive …` hands it the
/// words after the noun (`kotton_cli::bridge`), and the REPL hands it the same.
pub struct DriveCommand;

const USAGE: &str = "usage: drive create <name> [--on <vault>] | drive list [--json] | drive show <name> [--json] | \
                     drive move <name> --to <vault> [--from <vault>] | drive enrol <invite>";

/// The verbs, the command-tree decision's "Drives" line less `export`.
const VERBS: &[Verb] = &[
    Verb::current("create"),
    Verb::current("list"),
    Verb::current("show"),
    Verb::current("move"),
    Verb::current("enrol"),
];

/// A line of `drive`, parsed.
#[derive(Debug, PartialEq, Eq)]
enum Line<'a> {
    Create { name: &'a str, on: Option<&'a str> },
    List { json: bool },
    Show { name: &'a str, json: bool },
    Move { name: &'a str, to: &'a str, from: Option<&'a str> },
    Enrol { invite: String, posture: Option<Posture> },
}

/// What `drive enrol` says when no invite is among the words.
pub(super) const ENROL_USAGE: &str = "usage: drive enrol <invite>";

/// The invite among the words after `enrol` and the posture the one flag asked for, if any.
/// The one place the invite is found: exactly one word that is not a flag (not empty, not
/// starting with `-`), and at most one flag, which must be a key of
/// [`ENROL_POSTURES`](super::device::ENROL_POSTURES), the table that owns the vocabulary;
/// the posture is that key's value, so there is no second reader to disagree. A repeated flag
/// is a second flag. `None` (no invite, a second word, an odd invite, an unknown or a second
/// flag) is the usage refusal. This is grammar; the daemon remains the only guard on posture.
pub(super) fn split_invite(words: impl IntoIterator<Item = String>) -> Option<(String, Option<Posture>)> {
    let mut invite = None;
    let mut posture = None;
    for w in words {
        if w.starts_with("--") {
            let (_, p) = ENROL_POSTURES.iter().find(|(word, _)| *word == w)?;
            if posture.replace(*p).is_some() {
                return None;
            }
        } else if w.is_empty() || w.starts_with('-') || invite.replace(w).is_some() {
            return None;
        }
    }
    invite.map(|i| (i, posture))
}

/// The words after `drive`, as a [`Line`], or the usage refusal (exit 2).
fn parse(args: &[String]) -> Result<Line<'_>, CommandOutput> {
    let json = args.iter().any(|a| a == "--json");
    let words: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--json").collect();
    let usage = |what: &str| Err(CommandOutput::usage(what.to_string(), Some(USAGE.into())));
    if json && !matches!(words.first(), Some(&"list") | Some(&"show")) {
        return usage("drive: `--json` is for `drive list` and `drive show`");
    }
    match words.as_slice() {
        ["create", name] => Ok(Line::Create { name, on: None }),
        ["create", name, "--on", on] => Ok(Line::Create { name, on: Some(on) }),
        ["create", ..] => usage("drive create: unexpected words"),
        ["list"] => Ok(Line::List { json }),
        ["show", name] => Ok(Line::Show { name, json }),
        ["move", name, "--to", to] => Ok(Line::Move { name, to, from: None }),
        ["move", name, "--to", to, "--from", from] | ["move", name, "--from", from, "--to", to] => {
            Ok(Line::Move { name, to, from: Some(from) })
        }
        ["move", ..] => usage("drive move: needs --to <vault>"),
        ["enrol", rest @ ..] => match split_invite(rest.iter().map(|w| w.to_string())) {
            Some((invite, posture)) => Ok(Line::Enrol { invite, posture }),
            None => usage(ENROL_USAGE),
        },
        _ => usage("drive: unknown form"),
    }
}

/// A size as a person reads it; `?` when the vault did not answer.
fn size_said(size: Option<u64>) -> String {
    size.map_or_else(|| "?".to_string(), |b| format!("{b} bytes"))
}

/// A drive's name as the person reads it, a move's unfinished tree marked.
fn name_said(d: &DriveDescriptor) -> String {
    if d.unfinished {
        format!("{} (unfinished move: not the drive)", d.name)
    } else {
        d.name.clone()
    }
}

/// How many leading characters of a drive's id `drive list` prints: enough to
/// tell two drives of one name apart at a glance; `drive show` prints it whole.
const ID_SHOWN: usize = 8;

/// A drive's id as `drive show` prints it; `-` for a drive this device
/// recorded before ids, until its vault's next listing.
fn id_said(d: &DriveDescriptor) -> String {
    d.id.clone().unwrap_or_else(|| "-".to_string())
}

/// A drive's id as `drive list` prints it: its first [`ID_SHOWN`] characters.
fn id_short(d: &DriveDescriptor) -> String {
    id_said(d).chars().take(ID_SHOWN).collect()
}

fn table(drives: &[DriveDescriptor]) -> Out {
    Out::Table {
        columns: vec!["drive".into(), "id".into(), "vault".into(), "size".into(), "kept whole on".into()],
        rows: drives
            .iter()
            .map(|d| {
                vec![
                    name_said(d),
                    id_short(d),
                    d.vault.clone(),
                    size_said(d.size),
                    if d.pinned_whole.is_empty() { "-".to_string() } else { d.pinned_whole.join(", ") },
                ]
            })
            .collect(),
    }
}

/// What `drive move` says when the vault the drive left listed keys that are
/// not storage keys: the move refused them and carried everything else
/// (kotton #274).
fn refused_said(n: u32) -> String {
    let (keys, are) = if n == 1 { ("key", "is") } else { ("keys", "are") };
    format!(
        "the vault the drive left listed {n} {keys} that {are} not a storage key; the move refused {} and carried \
         everything else",
        if n == 1 { "it" } else { "them" }
    )
}

/// What `--json` prints: the descriptors the daemon answered, as they cross, a
/// payload on stdout.
fn json(drives: &[DriveDescriptor]) -> Result<CommandOutput> {
    Ok(CommandOutput::shapes(vec![Out::Data(serde_json::to_string_pretty(drives)?)]))
}

/// Run a parsed line of `drive`.
async fn run(line: Line<'_>, state: &mut ShellState) -> Result<CommandOutput> {
    let user_id = state.user_id.clone();
    let client = std::sync::Arc::clone(&state.client);
    let said = |verb: &str, e: std::io::Error| anyhow::anyhow!("drive {verb}: {e}");
    match line {
        Line::Create { name, on } => {
            let drives = client.lock().await.drive_create(&user_id, name, on).await.map_err(|e| said("create", e))?;
            let vault = drives.first().map(|d| d.vault.clone()).unwrap_or_default();
            Ok(CommandOutput::shapes(vec![Out::Confirm {
                action: format!("drive made on '{vault}'"),
                subject: name.to_string(),
            }]))
        }
        Line::List { json: as_json } => {
            let drives = client.lock().await.drive_list(&user_id).await.map_err(|e| said("list", e))?;
            if as_json {
                return json(&drives);
            }
            if drives.is_empty() {
                return Ok(CommandOutput::shapes(vec![Out::Note(
                    "you keep no drive yet — your things live on a drive; `vault invite --me` makes one".into(),
                )]));
            }
            Ok(CommandOutput::shapes(vec![table(&drives)]))
        }
        Line::Show { name, json: as_json } => {
            let drives = client.lock().await.drive_show(&user_id, name).await.map_err(|e| said("show", e))?;
            if as_json {
                return json(&drives);
            }
            Ok(CommandOutput::shapes(
                drives
                    .iter()
                    .map(|d| {
                        Out::Record(vec![
                            ("drive".into(), name_said(d)),
                            ("id".into(), id_said(d)),
                            ("vault".into(), d.vault.clone()),
                            ("vault key".into(), d.vault_key.clone()),
                            ("size".into(), size_said(d.size)),
                            (
                                "kept whole on".into(),
                                if d.pinned_whole.is_empty() { "-".into() } else { d.pinned_whole.join(", ") },
                            ),
                        ])
                    })
                    .collect(),
            ))
        }
        Line::Move { name, to, from } => {
            let moved = client.lock().await.drive_move(&user_id, name, to, from).await.map_err(|e| said("move", e))?;
            let vault = moved.drives.first().map(|d| d.vault.clone()).unwrap_or_else(|| to.to_string());
            let mut out = vec![Out::Confirm {
                action: format!("drive moved to '{vault}'; your other devices follow it there at their next sync"),
                subject: name.to_string(),
            }];
            if moved.keys_refused > 0 {
                out.push(Out::Note(refused_said(moved.keys_refused)));
            }
            Ok(CommandOutput::shapes(out))
        }
        // The ceremony takes the lock for itself.
        Line::Enrol { invite, posture } => super::device::enrol_vault(&invite, posture, state).await,
    }
}

#[async_trait]
impl Command for DriveCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        match parse(args) {
            Ok(line) => run(line, state).await,
            Err(usage) => Ok(usage),
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
        if arg_index == 0 {
            VERBS.iter().map(|v| v.word.to_string()).collect()
        } else {
            vec![]
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["--on", "--to", "--from", "--json"]
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
drive — your drives: where your things live

USAGE:
  drive create <name> [--on <vault>]   make a drive on one of your vaults
  drive list [--json]                  every drive: its id, where it lives, its size, which devices keep it whole
  drive show <name> [--json]           one drive, on each vault it is kept on
  drive move <name> --to <vault> [--from <vault>]
                                       carry a drive, sealed, to another of your vaults
  drive enrol <invite>                 take a vault's invite: the vault keeps drives for you

A drive is a sealed tree a vault keeps for you; a vault keeps as many as you
make. Its name is sealed under your key: the vault cannot read it. Your first
drive on each vault is `personal`, the tree this device syncs with.

A move copies every sealed object to the other vault under the same key, and
retires the drive where it was only once the other vault holds all of it.
Your other devices follow it at their next sync. A move that fails leaves the
drive where it was; a copy the other vault would not take back is listed as an
unfinished move, and moving the drive there again clears it. A move cut off
after the other vault has the drive is finished by running it again. `personal`
does not move.

`enrol` takes the invite a vault's landlord gave you (`vault invite <name>`
at theirs): this device meets the vault at the invite's relay, and you type
the six digits they read out. The vault keeps sealed what you put on a drive
there and can read none of it. It asks nothing else.

FLAGS:
  --on <vault>   the vault to make the drive on: its label, DID or key
                 (needed when you keep drives on more than one)
  --to <vault>   the vault to move the drive to: its label, DID or key
  --from <vault> the copy to move, where two drives of yours share a name
  --json         `list` and `show`: what the vaults answered, as JSON on stdout

Exit 0 when done, 1 when refused (the reason on stderr), 2 for a line that is
not one of the above.

EXAMPLES:
  drive create photos                  # on your one vault
  drive create work --on office-vault  # on the vault labelled office-vault
  drive list
  drive show photos
  drive move photos --to office-vault
  drive list --json
  drive enrol <invite>                 # the invite the landlord gave you";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ExitCode;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    /// Every verb the table declares is a line this parser answers, so the table the
    /// verb check reads and the words the parser takes are one list.
    #[test]
    fn every_declared_verb_parses() {
        for (verb, line) in [
            ("create", "create photos --on office"),
            ("list", "list"),
            ("show", "show photos"),
            ("move", "move photos --to office"),
            ("enrol", "enrol https://relay.example#amber-otter-kite"),
        ] {
            assert!(VERBS.iter().any(|v| v.word == verb), "{verb} is not declared");
            assert!(parse(&words(line)).is_ok(), "`drive {line}` did not parse");
        }
        assert_eq!(VERBS.len(), 5, "a verb was declared that this test does not parse");
    }

    #[test]
    fn json_is_a_word_of_list_and_show_and_of_nothing_else() {
        assert_eq!(parse(&words("list --json")).ok(), Some(Line::List { json: true }));
        assert_eq!(parse(&words("--json show photos")).ok(), Some(Line::Show { name: "photos", json: true }));
        assert_eq!(parse(&words("list")).ok(), Some(Line::List { json: false }));
        let refused = parse(&words("create photos --json")).expect_err("--json on create");
        assert_eq!(refused.exit_code, ExitCode::Code(2));
    }

    /// `enrol` takes one invite and the flags the daemon knows; anything else is usage, before a session.
    #[test]
    fn enrol_refuses_a_second_word_and_an_unknown_flag() {
        for line in ["enrol CODE extra", "enrol CODE --frob"] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "`drive {line}`");
        }
        for line in ["enrol CODE --blind", "enrol --cosigner CODE", "enrol CODE --full"] {
            assert!(parse(&words(line)).is_ok(), "`drive {line}` did not parse");
        }
    }

    /// The command-tree decision: 2 is usage. A line the tree does not have exits 2, in either door.
    #[test]
    fn a_line_that_is_not_one_exits_two() {
        for line in ["", "frobnicate", "create", "move photos", "show", "enrol", "export photos /tmp/x"] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "`drive {line}`");
        }
    }

    #[test]
    fn enrol_hands_the_ceremony_the_invite_and_the_flags() {
        for line in ["enrol CODE --blind", "enrol --blind CODE"] {
            assert_eq!(
                parse(&words(line)).ok(),
                Some(Line::Enrol { invite: "CODE".into(), posture: Some(Posture::BlindStorage) }),
                "{line}"
            );
        }
        assert_eq!(
            parse(&words("enrol CODE")).ok(),
            Some(Line::Enrol { invite: "CODE".into(), posture: None })
        );
        // Posture flags that would hold keys still reach the ceremony: the daemon refuses them.
        for (flag, posture) in [("--cosigner", Posture::Cosigner), ("--full", Posture::Full)] {
            for line in [format!("enrol CODE {flag}"), format!("enrol {flag} CODE")] {
                assert_eq!(
                    parse(&words(&line)).ok(),
                    Some(Line::Enrol { invite: "CODE".into(), posture: Some(posture) }),
                    "{line}"
                );
            }
        }
    }

    /// The grammar is the table's keys: each is accepted, and a word outside it is not.
    #[test]
    fn split_invite_accepts_exactly_the_tables_flags() {
        for (flag, posture) in ENROL_POSTURES {
            assert_eq!(split_invite(words(&format!("CODE {flag}"))), Some(("CODE".into(), Some(posture))), "{flag}");
        }
        for flag in ["--frob", "--Blind", "--", "--blind=1"] {
            assert_eq!(split_invite(words(&format!("CODE {flag}"))), None, "{flag}");
        }
    }

    /// One posture flag at most: two, or the same one twice, is usage, exit 2, before any session.
    #[test]
    fn enrol_with_two_posture_flags_is_usage_exit_two() {
        for line in ["enrol CODE --blind --cosigner", "enrol --full CODE --blind", "enrol CODE --blind --blind"] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "{line}");
        }
    }

    /// An invite that is empty or starts with `-` is not an invite.
    #[test]
    fn enrol_with_a_dash_word_or_an_empty_word_for_an_invite_is_usage() {
        assert!(split_invite(vec!["-x".to_string()]).is_none());
        assert!(split_invite(vec![String::new()]).is_none());
    }

    /// An `enrol` line with only flags has no invite: usage, exit 2, before any session.
    #[test]
    fn enrol_with_only_flags_is_usage_exit_two() {
        let refused = parse(&words("enrol --blind")).expect_err("no invite");
        assert_eq!(refused.exit_code, ExitCode::Code(2));
    }

    /// `drive list` names each drive's id by its first characters, and a
    /// drive recorded before ids by `-`; `--json` carries the whole id.
    #[test]
    fn list_names_each_drives_id_and_json_carries_it_whole() {
        let described = |id: Option<String>| DriveDescriptor {
            id,
            name: "photos".into(),
            vault: "home".into(),
            vault_key: "00".repeat(32),
            size: None,
            pinned_whole: vec![],
            unfinished: false,
        };
        let drives = [described(Some("ab".repeat(16))), described(None)];
        let Out::Table { columns, rows } = table(&drives) else { panic!("drive list is a table") };
        assert_eq!(columns[1], "id");
        assert_eq!((rows[0][1].as_str(), rows[1][1].as_str()), ("abababab", "-"));
        let out = json(&drives).unwrap();
        let Some(Out::Data(text)) = out.out.first() else { panic!("--json is data") };
        let back: Vec<DriveDescriptor> = serde_json::from_str(text).unwrap();
        assert_eq!(back[0].id.as_deref(), Some("ab".repeat(16).as_str()));
    }

    #[test]
    fn the_help_names_every_declared_verb() {
        for v in VERBS {
            assert!(HELP.contains(&format!("drive {}", v.word)), "the help does not name `drive {}`", v.word);
        }
    }
}
