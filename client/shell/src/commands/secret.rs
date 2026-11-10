// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secret` — the person's keychain: passwords and tokens, as records.
//!
//! The command-tree decision's keychain line: `secret set|get|list|rm|generate`. A secret is a
//! record of Kotton's `secret` schema ([`NSID_SECRET`]: `label`, `value`, `kind`, `note`), in
//! Personal, put and read through the record requests the daemon already answers
//! (`RecordInsert`, `RecordQuery`, `RecordDelete`), each naming Personal by its word
//! ([`PERSONAL_ROOT`]) and no app. So the noun adds no reach and no request. It rides sealed
//! in the record log of `personal`, as every record does, and is read on another device after
//! a `sync` on each. The schema is kept from every app
//! (`kotton_schemas::CoreSchema::is_kept_from_apps`): only these verbs, and `record`, at the
//! person's own terminal, reach it.
//!
//! **A value never travels on argv** (where the shell's history and the process list would
//! hold it): `set` reads it at a hidden prompt at a terminal, asked twice, and from one line
//! of stdin otherwise. It is held in [`Value`], whose `Debug` says nothing of it, and is
//! printed by `get` alone, as the one line on stdout. No refusal here says it.
//!
//! **One record per label.** `set` on a label Personal holds writes that record again, under
//! the id the store gave it; a label is never a record's id, so it is never written into a
//! record's URL. Two records under one label (each device set it before either synced) are one
//! again at the next `set`, which keeps the newest record's id and removes the other.
//!
//! [`parse`] is the one parser for these words: `kotton secret …` hands it the words after the
//! noun (`kotton_cli::bridge`), and the REPL hands it the same.

use anyhow::Result;
use async_trait::async_trait;
use kotton_common::namespace::NSID_SECRET;
use kotton_wire::ipc::PERSONAL_ROOT;

use super::{Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::{Asking, ShellState};

pub struct SecretCommand;

const USAGE: &str = "usage: secret set <label> [--kind password|token] [--note <text>] | secret get <label> | \
                     secret list | secret rm <label> | secret generate <label> [--length <n>] \
                     [--kind password|token] [--note <text>]";

/// The verbs: the command-tree decision's keychain line.
const VERBS: &[Verb] = &[
    Verb::current("set"),
    Verb::current("get"),
    Verb::current("list"),
    Verb::current("rm"),
    Verb::current("generate"),
];

/// How long a generated value is unless `--length` says.
const GENERATED_LENGTH: usize = 32;
/// The shortest and longest value `generate` makes.
const GENERATED_BOUNDS: (usize, usize) = (8, 256);
/// What a generated value is drawn from: letters and digits, less those read as one another
/// (`0` `O` `o`, `1` `l` `I`). 56 characters, about 5.8 bits each.
const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
/// The longest note `list` shows whole; a longer one is cut there.
const NOTE_SHOWN: usize = 40;

/// What a secret is: a password, or a token. The schema's `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Password,
    Token,
}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Kind::Password => "password",
            Kind::Token => "token",
        }
    }
}

/// A secret's value. `Debug` says it is there and nothing of it, so a value held here is never
/// written by a `{:?}`.
#[derive(Clone, PartialEq, Eq)]
struct Value(String);

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Value(<hidden>)")
    }
}

/// A line of `secret`, parsed. No line carries a value: `set` reads it after the line.
#[derive(Debug, PartialEq)]
enum Line {
    Set { label: String, kind: Option<Kind>, note: Option<String> },
    Get { label: String },
    List,
    Rm { label: String },
    Generate { label: String, length: usize, kind: Option<Kind>, note: Option<String> },
}

/// A label as a word: not empty, not a flag, with no control character.
fn label_word(word: &str) -> Option<String> {
    (!word.is_empty() && !word.starts_with('-') && !word.chars().any(char::is_control))
        .then(|| word.to_string())
}

/// The words after `secret`, as a [`Line`], or the usage refusal (exit 2).
///
/// A refusal never repeats a word it did not take: the word after `set <label>` is most
/// likely the value, typed where it must not be, and saying it back would print it.
fn parse(args: &[String]) -> Result<Line, CommandOutput> {
    let usage = |what: String| Err(CommandOutput::usage(what, Some(USAGE.into())));
    let Some((verb, rest)) = args.split_first() else {
        return usage("secret: which verb?".into());
    };
    if !matches!(verb.as_str(), "set" | "get" | "list" | "rm" | "generate") {
        return usage(format!("secret: '{verb}' is not a verb of secret"));
    }
    let mut kind = None;
    let mut note = None;
    let mut length = None;
    let mut words: Vec<&str> = Vec::new();
    let mut it = rest.iter();
    while let Some(w) = it.next() {
        let takes = |flag: &str| matches!((verb.as_str(), flag), ("set" | "generate", "--kind" | "--note") | ("generate", "--length"));
        match w.as_str() {
            flag @ ("--kind" | "--note" | "--length") if takes(flag) => {
                let Some(said) = it.next() else {
                    return usage(format!("secret {verb}: `{flag}` needs a word after it"));
                };
                match flag {
                    "--kind" => {
                        if kind.is_some() {
                            return usage(format!("secret {verb}: `--kind` is said once"));
                        }
                        kind = Some(match said.as_str() {
                            "password" => Kind::Password,
                            "token" => Kind::Token,
                            other => {
                                return usage(format!("secret {verb}: a kind is `password` or `token`, not '{other}'"))
                            }
                        });
                    }
                    "--note" => {
                        if note.is_some() {
                            return usage(format!("secret {verb}: `--note` is said once"));
                        }
                        note = Some(said.clone());
                    }
                    _ => {
                        if length.is_some() {
                            return usage("secret generate: `--length` is said once".into());
                        }
                        let (least, most) = GENERATED_BOUNDS;
                        match said.parse::<usize>() {
                            Ok(n) if (least..=most).contains(&n) => length = Some(n),
                            _ => {
                                return usage(format!(
                                    "secret generate: `--length` is a number of characters from {least} to {most}"
                                ))
                            }
                        }
                    }
                }
            }
            // Not said back for `set`, whose stray word may be the value.
            flag if flag.starts_with("--") && verb == "set" => {
                return usage("secret set: takes `--kind` and `--note`, and no other flag".into())
            }
            flag if flag.starts_with("--") => {
                return usage(format!("secret {verb}: `{flag}` is not a flag of secret {verb}"))
            }
            other => words.push(other),
        }
    }
    let label = |word: &str| label_word(word);
    match (verb.as_str(), words.as_slice()) {
        ("list", []) => Ok(Line::List),
        ("get", [w]) => match label(w) {
            Some(label) => Ok(Line::Get { label }),
            None => usage(format!("secret get: '{w}' is not a label")),
        },
        ("rm", [w]) => match label(w) {
            Some(label) => Ok(Line::Rm { label }),
            None => usage(format!("secret rm: '{w}' is not a label")),
        },
        ("set", [w]) => match label(w) {
            Some(label) => Ok(Line::Set { label, kind, note }),
            None => usage("secret set: that is not a label".into()),
        },
        // The value is never a word of the line. Said without repeating what was typed.
        ("set", [_, _, ..]) => Err(CommandOutput::usage(
            "secret set: takes a label and no value: a value on the line would be kept in your \
             shell's history and shown in the process list",
            Some("`secret set <label>` asks for the value hidden, or reads one line of stdin".into()),
        )),
        ("generate", [w]) => match label(w) {
            Some(label) => Ok(Line::Generate { label, length: length.unwrap_or(GENERATED_LENGTH), kind, note }),
            None => usage(format!("secret generate: '{w}' is not a label")),
        },
        ("get" | "rm" | "set" | "generate", []) => usage(format!("secret {verb}: which label?")),
        _ => usage(format!("secret {verb}: unexpected words")),
    }
}

/// A value drawn from the OS's random source: `length` characters of [`ALPHABET`], each
/// taken from a byte below the largest multiple of the alphabet's size, so none is likelier
/// than another.
fn generate(length: usize) -> std::io::Result<Value> {
    use kotton_sys::crypto::RandomSource as _;
    let rng = kotton_crypto::provider::OsRandom::new();
    let bound = 256 - (256 % ALPHABET.len());
    let mut out = String::with_capacity(length);
    while out.len() < length {
        let bytes = rng.random_bytes(length * 2).map_err(|e| std::io::Error::other(e.to_string()))?;
        for b in bytes {
            if (b as usize) < bound && out.len() < length {
                out.push(ALPHABET[b as usize % ALPHABET.len()] as char);
            }
        }
    }
    Ok(Value(out))
}

/// Why no value was read for `set`.
#[derive(Debug, PartialEq, Eq)]
enum NoValue {
    /// Nothing was entered, or stdin held no line.
    Empty,
    /// The two entries at the terminal differed.
    Differed,
}

/// The value for `set <label>`, read as [`Asking`] says: at the terminal, hidden and asked
/// twice; from one line of stdin when nobody is at one, the line's end not kept; or from an
/// answer given beforehand. The value is kept as entered: a space at either end is the
/// value's.
fn read_value(asking: &mut Asking, label: &str) -> std::io::Result<Result<Value, NoValue>> {
    let entered = match asking {
        Asking::Terminal => {
            let first = rpassword::prompt_password(crate::ui::ask(&format!("value of '{label}' (hidden)")))?;
            if first.is_empty() {
                return Ok(Err(NoValue::Empty));
            }
            let again = rpassword::prompt_password(crate::ui::ask("again, to confirm"))?;
            if again != first {
                return Ok(Err(NoValue::Differed));
            }
            first
        }
        Asking::Nobody => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let line = line.strip_suffix('\n').unwrap_or(&line);
            line.strip_suffix('\r').unwrap_or(line).to_string()
        }
        Asking::Given(answers) => answers.pop_front().unwrap_or_default(),
    };
    Ok(if entered.is_empty() { Err(NoValue::Empty) } else { Ok(Value(entered)) })
}

/// A secret's record as Personal holds it: its id, and its fields but the value.
struct Held {
    id: String,
    label: String,
    kind: String,
    note: Option<String>,
}

impl Held {
    fn of(record: &serde_json::Value) -> Self {
        let text = |k: &str| record[k].as_str().map(str::to_string);
        Self {
            id: text("_id").or_else(|| text("id")).unwrap_or_default(),
            label: text("label").unwrap_or_default(),
            kind: text("kind").unwrap_or_default(),
            note: text("note"),
        }
    }
}

/// The records under `label` in Personal, newest first, as the daemon answers them.
async fn under(client: &mut kotton::KottonClient, user_id: &str, label: &str) -> std::io::Result<Vec<serde_json::Value>> {
    let by_label = vec![("label".to_string(), serde_json::json!(label))];
    client.record_query_in(user_id, Some(PERSONAL_ROOT), None, NSID_SECRET, by_label, None, None).await
}

/// Put `value` under `label` in Personal: a new record, or the one already there written again
/// under its own id, any other under the label removed. `kind` and `note` not said keep what
/// the record held; a new one is a password with no note.
async fn put(
    client: &mut kotton::KottonClient,
    user_id: &str,
    label: &str,
    value: Value,
    kind: Option<Kind>,
    note: Option<String>,
) -> std::io::Result<bool> {
    let held: Vec<Held> = under(client, user_id, label).await?.iter().map(Held::of).collect();
    let was = held.first();
    let kind = kind.map(|k| k.word().to_string()).or_else(|| was.map(|h| h.kind.clone())).unwrap_or_else(|| Kind::Password.word().into());
    let note = note.or_else(|| was.and_then(|h| h.note.clone()));
    let mut body = serde_json::json!({ "label": label, "value": value.0, "kind": kind, "note": note });
    if let Some(was) = was {
        body["id"] = serde_json::json!(was.id);
    }
    client.record_insert_in(user_id, Some(PERSONAL_ROOT), None, NSID_SECRET, body).await?;
    for other in held.iter().skip(1) {
        client.record_delete_in(user_id, Some(PERSONAL_ROOT), None, NSID_SECRET, &other.id).await?;
    }
    Ok(was.is_some())
}

/// A note as `list` shows it: whole up to [`NOTE_SHOWN`] characters, cut there with `…`.
fn note_shown(note: Option<&str>) -> String {
    match note {
        None => String::new(),
        Some(n) if n.chars().count() <= NOTE_SHOWN => n.to_string(),
        Some(n) => format!("{}…", n.chars().take(NOTE_SHOWN - 1).collect::<String>()),
    }
}

/// Run a parsed line of `secret`. A refusal is exit 1, with the daemon's reason.
async fn run(line: Line, state: &mut ShellState) -> Result<CommandOutput> {
    let user_id = state.user_id.clone();
    let refused = |verb: &str, e: std::io::Error| CommandOutput::fail(format!("secret {verb}: {e}"), None);
    let none_by = |label: &str| {
        CommandOutput::fail(format!("no secret '{label}' in personal"), Some("`secret list` lists the labels".into()))
    };
    let kept = "kept in personal; your other devices read it after a `sync` on each";
    match line {
        Line::Set { label, kind, note } => {
            let value = match read_value(&mut state.asking, &label) {
                Ok(Ok(value)) => value,
                Ok(Err(NoValue::Empty)) => {
                    return Ok(CommandOutput::fail(
                        format!("secret set: no value was given for '{label}'; nothing was kept"),
                        Some("at a terminal it is asked for, hidden; otherwise it is the first line of stdin".into()),
                    ))
                }
                Ok(Err(NoValue::Differed)) => {
                    return Ok(CommandOutput::fail(
                        format!("secret set: the two entries for '{label}' differed; nothing was kept"),
                        None,
                    ))
                }
                Err(e) => return Ok(refused("set", e)),
            };
            let mut client = state.client.lock().await;
            match put(&mut client, &user_id, &label, value, kind, note).await {
                Ok(replaced) => Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: format!("secret {}{kept}", if replaced { "replaced, " } else { "" }),
                    subject: label,
                }])),
                Err(e) => Ok(refused("set", e)),
            }
        }
        Line::Generate { label, length, kind, note } => {
            let mut client = state.client.lock().await;
            match under(&mut client, &user_id, &label).await {
                Ok(held) if !held.is_empty() => {
                    return Ok(CommandOutput::fail(
                        format!("secret generate: personal already keeps a secret '{label}'; it was left as it is"),
                        Some(format!("`secret set {label}` replaces it; `secret rm {label}` removes it")),
                    ))
                }
                Ok(_) => {}
                Err(e) => return Ok(refused("generate", e)),
            }
            let value = match generate(length) {
                Ok(v) => v,
                Err(e) => return Ok(refused("generate", e)),
            };
            match put(&mut client, &user_id, &label, value, kind, note).await {
                Ok(_) => Ok(CommandOutput::shapes(vec![
                    Out::Confirm { action: format!("secret of {length} characters generated, {kept}"), subject: label.clone() },
                    Out::Hint(format!("`secret get {label}` prints it")),
                ])),
                Err(e) => Ok(refused("generate", e)),
            }
        }
        Line::Get { label } => {
            let mut client = state.client.lock().await;
            match under(&mut client, &user_id, &label).await {
                Ok(held) => match held.first().and_then(|r| r["value"].as_str()) {
                    Some(value) => Ok(CommandOutput::shapes(vec![Out::Data(value.to_string())])),
                    None => Ok(none_by(&label)),
                },
                Err(e) => Ok(refused("get", e)),
            }
        }
        Line::List => {
            let mut client = state.client.lock().await;
            let records = match client
                .record_query_in(&user_id, Some(PERSONAL_ROOT), None, NSID_SECRET, vec![], None, None)
                .await
            {
                Ok(r) => r,
                Err(e) => return Ok(refused("list", e)),
            };
            let mut held: Vec<Held> = records.iter().map(Held::of).collect();
            held.sort_by(|a, b| a.label.cmp(&b.label));
            held.dedup_by(|a, b| a.label == b.label);
            Ok(CommandOutput::shapes(vec![Out::Table {
                columns: vec!["label".into(), "kind".into(), "note".into()],
                rows: held.iter().map(|h| vec![h.label.clone(), h.kind.clone(), note_shown(h.note.as_deref())]).collect(),
            }]))
        }
        Line::Rm { label } => {
            let mut client = state.client.lock().await;
            let held: Vec<Held> = match under(&mut client, &user_id, &label).await {
                Ok(r) => r.iter().map(Held::of).collect(),
                Err(e) => return Ok(refused("rm", e)),
            };
            if held.is_empty() {
                return Ok(none_by(&label));
            }
            for h in &held {
                if let Err(e) = client.record_delete_in(&user_id, Some(PERSONAL_ROOT), None, NSID_SECRET, &h.id).await {
                    return Ok(refused("rm", e));
                }
            }
            Ok(CommandOutput::shapes(vec![Out::Confirm {
                action: "secret removed; your other devices see it gone after their next sync".into(),
                subject: label,
            }]))
        }
    }
}

#[async_trait]
impl Command for SecretCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        match parse(args) {
            Ok(line) => run(line, state).await,
            Err(usage) => Ok(usage),
        }
    }

    /// A line this noun's parser refuses is answered here, before any door connects, exit 2.
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
        vec!["--kind", "--note", "--length"]
    }

    fn help_text(&self) -> &'static str {
        HELP
    }

    fn verbs(&self) -> &'static [Verb] {
        VERBS
    }
}

/// `secrets`, the stub that stood where the keychain is now: gone for `secret`. Hidden from
/// `help`, which lists what runs; refused, exit 2, before any session.
pub struct SecretsGone;

const SECRET_IS: &str = "`secret set|get|list|rm|generate` keeps your passwords and tokens";

#[async_trait]
impl Command for SecretsGone {
    async fn execute(&self, _args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        Ok(super::retired("secrets", SECRET_IS))
    }

    async fn execute_without_session(&self, _args: &[String], _named: Option<&str>) -> Option<Result<CommandOutput>> {
        Some(Ok(super::retired("secrets", SECRET_IS)))
    }

    fn hidden(&self) -> bool {
        true
    }
}

pub(crate) const HELP: &str = "\
secret — your keychain: passwords and tokens, read from every device

USAGE:
  secret set <label> [--kind password|token] [--note <text>]   keep a secret under a label
  secret get <label>                                         print its value on stdout
  secret list                                                every label, its kind and note
  secret rm <label>                                          remove a secret
  secret generate <label> [--length <n>] [--kind …] [--note …]   make one and keep it

A secret is a record in your first drive, `personal`, sealed at each sync:
one kept on one device is read on another after a `sync` on each. The vault
keeps it sealed under your key and can read none of it. No app is granted it,
reads it, or finds it in a search: it is reached here, at your own terminal.

`set` never takes the value on the line, where your shell's history and the
process list would keep it. At a terminal it asks for the value, hidden, and
asks again to confirm; otherwise it reads the first line of stdin. One label
is one secret: `set` on a label you keep replaces its value, and keeps its
kind and note unless you give them. A new secret is a password, with no note.

`get` prints the value alone, one line on stdout, so it pipes. `list` never
prints a value. `generate` makes a value of 56 letters and digits that are not
read as one another, 32 characters long unless `--length` (8 to 256) says,
from this computer's random source, and keeps it under a label you do not
keep yet; it does not print it.

FLAGS:
  --kind password|token  `set`, `generate`: what the secret is (a new one is a password)
  --note <text>          `set`, `generate`: a line about it, shown by `list`
  --length <n>           `generate`: how many characters, 8 to 256 (32)

Exit 0 when done, 1 when refused, when no secret has the label, or when no
value was given (the reason on stderr), 2 for a line that is not one of the
above.

EXAMPLES:
  secret set bank
  secret set deploy --kind token --note \"the CI deploy key\" < token.txt
  secret get bank
  secret list
  secret generate wifi --length 24
  secret rm bank";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ExitCode;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    fn said(out: &CommandOutput) -> String {
        format!("{:?}", out.out)
    }

    /// Every declared verb parses, each to its line, with its flags.
    #[test]
    fn every_declared_verb_parses() {
        assert_eq!(parse(&words("set bank")).unwrap(), Line::Set { label: "bank".into(), kind: None, note: None });
        assert_eq!(
            parse(&words("set ci --kind token --note deploy")).unwrap(),
            Line::Set { label: "ci".into(), kind: Some(Kind::Token), note: Some("deploy".into()) }
        );
        assert_eq!(parse(&words("get bank")).unwrap(), Line::Get { label: "bank".into() });
        assert_eq!(parse(&words("list")).unwrap(), Line::List);
        assert_eq!(parse(&words("rm bank")).unwrap(), Line::Rm { label: "bank".into() });
        assert_eq!(
            parse(&words("generate wifi")).unwrap(),
            Line::Generate { label: "wifi".into(), length: GENERATED_LENGTH, kind: None, note: None }
        );
        assert_eq!(
            parse(&words("generate wifi --length 12 --kind password")).unwrap(),
            Line::Generate { label: "wifi".into(), length: 12, kind: Some(Kind::Password), note: None }
        );
        for verb in VERBS {
            let line = if verb.word == "list" { "list".to_string() } else { format!("{} bank", verb.word) };
            assert!(parse(&words(&line)).is_ok(), "{line}");
        }
    }

    /// `set` takes a label and no value: a second word is refused, exit 2, and the refusal
    /// does not say the word, which is most likely the value.
    #[test]
    fn set_takes_no_value_and_does_not_say_one_back() {
        for line in ["set bank hunter2", "set bank --kind token hunter2", "set bank hunter2 more"] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "{line}");
            assert!(!said(&refused).contains("hunter2"), "the refusal said the value: {}", said(&refused));
        }
    }

    /// A line that is not one exits 2: no verb, an unknown verb, no label, a flag of another
    /// verb, a kind that is not one, a length out of bounds.
    #[test]
    fn a_line_that_is_not_one_exits_two() {
        for line in [
            "",
            "show bank",
            "get",
            "set",
            "list extra",
            "get bank --kind token",
            "set bank --length 12",
            "set bank --kind passkey",
            "generate wifi --length 4",
            "generate wifi --length 1000",
            "generate wifi --length many",
            "rm --bank",
            "set bank --note",
        ] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "{line}");
        }
    }

    /// A generated value is as long as asked, drawn from the alphabet alone, and not the same
    /// twice.
    #[test]
    fn a_generated_value_is_its_length_from_the_alphabet() {
        let a = generate(32).unwrap();
        let b = generate(32).unwrap();
        assert_eq!(a.0.len(), 32);
        assert!(a.0.bytes().all(|c| ALPHABET.contains(&c)), "{}", a.0);
        assert_ne!(a, b);
        assert!(!ALPHABET.iter().any(|c| b"0Oo1lI".contains(c)));
        assert_eq!(ALPHABET.len(), 56);
    }

    /// A value's `Debug` says nothing of it.
    #[test]
    fn a_values_debug_says_nothing_of_it() {
        let printed = format!("{:?}", Value("hunter2".into()));
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    /// An answer given is the value as given; none, or an empty one, is no value.
    #[test]
    fn a_value_is_read_as_given_and_an_empty_one_is_none() {
        let mut asking = Asking::Given([" spaced ".to_string(), String::new()].into_iter().collect());
        assert_eq!(read_value(&mut asking, "bank").unwrap(), Ok(Value(" spaced ".into())));
        assert_eq!(read_value(&mut asking, "bank").unwrap(), Err(NoValue::Empty));
        assert_eq!(read_value(&mut asking, "bank").unwrap(), Err(NoValue::Empty));
    }

    /// A note is shown whole up to its bound and cut after it.
    #[test]
    fn a_long_note_is_cut_in_the_list() {
        assert_eq!(note_shown(None), "");
        assert_eq!(note_shown(Some("short")), "short");
        let long = "x".repeat(NOTE_SHOWN + 5);
        let shown = note_shown(Some(&long));
        assert_eq!(shown.chars().count(), NOTE_SHOWN);
        assert!(shown.ends_with('…'));
    }

    /// `secrets` is gone for `secret`, before any session.
    #[tokio::test]
    async fn secrets_is_gone_for_secret() {
        let refused = SecretsGone.execute_without_session(&words("set k v"), None).await.expect("refused").unwrap();
        assert_eq!(refused.exit_code, ExitCode::Code(2));
        assert!(said(&refused).contains("secret set"), "{}", said(&refused));
    }
}
