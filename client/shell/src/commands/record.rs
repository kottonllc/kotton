// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton_schemas::nsid::Nsid;

use super::{retired, Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::ShellState;

/// record — your records: typed, sealed, in `personal`, read from every device.
///
/// Usage:
/// ```text
///   record list --schema <nsid> [--json]
///   record get --schema <nsid> <id>
///   record put --schema <nsid> <json>
///   record rm --schema <nsid> <id>
/// ```
///
/// The command-tree decision's "Records and schemas" line, but `import` and `export`, which
/// wait for a follow-up. Each verb is one request the daemon already answers (`RecordQuery`,
/// `RecordOpen`, `RecordInsert`, `RecordDelete`), so the noun adds no reach: what it reads and
/// writes is the person's own records, in Personal, which ride sealed in the record log of
/// the tree this device keeps of `personal` (`kotton_record::replication`). A record put here
/// is read on another device after a `sync` on each, wherever `personal` lives. A schema is
/// cited by its NSID; this device must know it (a core schema, or one `schema register`ed).
///
/// `record open <url>` is gone for `record get`: the command-tree decision's table.
///
/// [`parse`] is the one parser for these words: `kotton record …` hands it the words after
/// the noun (`kotton_cli::bridge`), and the REPL hands it the same.
pub struct RecordCommand;

const USAGE: &str = "usage: record list --schema <nsid> [--json] | record get --schema <nsid> <id> | \
                     record put --schema <nsid> <json> | record rm --schema <nsid> <id>";

/// The verbs: the command-tree decision's "Records and schemas" line less `import` and
/// `export`, and `open`, which its table retired for `get`.
const VERBS: &[Verb] = &[
    Verb::current("list"),
    Verb::current("get"),
    Verb::current("put"),
    Verb::current("rm"),
    Verb::gone("open", "record get"),
];

/// What `record open` is now, said where it is refused.
const GET_IS: &str = "`record get --schema <nsid> <id>` reads one record, by its schema and its id";

/// A line of `record`, parsed.
#[derive(Debug, PartialEq)]
enum Line {
    List { schema: Nsid, json: bool },
    Get { schema: Nsid, id: String },
    Put { schema: Nsid, body: serde_json::Value },
    Rm { schema: Nsid, id: String },
}

/// A record's id as a word: not empty, not a flag, and without the `/` that would end it in
/// the record's URL (`kotton://records/<nsid>/<id>`, which `get` asks by).
fn id_word(word: &str) -> Option<String> {
    (!word.is_empty() && !word.starts_with('-') && !word.contains('/')).then(|| word.to_string())
}

/// The words after `record`, as a [`Line`], or the usage refusal (exit 2). `--schema <nsid>`
/// may stand anywhere after the verb; it is said once, and every verb needs it.
fn parse(args: &[String]) -> Result<Line, CommandOutput> {
    let usage = |what: String| Err(CommandOutput::usage(what, Some(USAGE.into())));
    let Some((verb, rest)) = args.split_first() else {
        return usage("record: which verb?".into());
    };
    if verb == "open" {
        return Err(retired("record open", GET_IS));
    }
    if !matches!(verb.as_str(), "list" | "get" | "put" | "rm") {
        return usage(format!("record: '{verb}' is not a verb of record"));
    }
    let mut schema = None;
    let mut json = false;
    let mut words: Vec<&str> = Vec::new();
    let mut it = rest.iter();
    while let Some(w) = it.next() {
        match w.as_str() {
            "--schema" => {
                let Some(name) = it.next() else { return usage(format!("record {verb}: `--schema` needs an NSID")) };
                if schema.is_some() {
                    return usage(format!("record {verb}: `--schema` is said once"));
                }
                match Nsid::new(name) {
                    Ok(n) => schema = Some(n),
                    Err(e) => return usage(format!("record {verb}: '{name}' is not an NSID: {e}")),
                }
            }
            "--json" => json = true,
            other => words.push(other),
        }
    }
    let Some(schema) = schema else {
        return usage(format!("record {verb}: needs --schema <nsid>"));
    };
    if json && verb != "list" {
        return usage("record: `--json` is for `record list`; `record get` prints the record as JSON".into());
    }
    match (verb.as_str(), words.as_slice()) {
        ("list", []) => Ok(Line::List { schema, json }),
        ("get", [id]) => match id_word(id) {
            Some(id) => Ok(Line::Get { schema, id }),
            None => usage(format!("record get: '{id}' is not a record's id")),
        },
        ("rm", [id]) => match id_word(id) {
            Some(id) => Ok(Line::Rm { schema, id }),
            None => usage(format!("record rm: '{id}' is not a record's id")),
        },
        ("put", [body]) => match serde_json::from_str::<serde_json::Value>(body) {
            Ok(body) if body.is_object() => Ok(Line::Put { schema, body }),
            _ => usage("record put: the record is one JSON object, quoted as one word".into()),
        },
        _ => usage(format!("record {verb}: unexpected words")),
    }
}

/// A record's body as `record list` prints it: compact, without the id the row's own column
/// says and the fields the daemon adds to an answer (`_id`, `_filed_at`, `_root`).
fn body_said(record: &serde_json::Value) -> String {
    let mut body = record.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.retain(|k, _| k != "id" && !k.starts_with('_'));
    }
    body.to_string()
}

/// A record's id as the daemon answered it: `_id`, which every queried row carries.
fn id_said(record: &serde_json::Value) -> String {
    record["_id"].as_str().or_else(|| record["id"].as_str()).unwrap_or("-").to_string()
}

fn table(records: &[serde_json::Value]) -> Out {
    Out::Table {
        columns: vec!["id".into(), "record".into()],
        rows: records.iter().map(|r| vec![id_said(r), body_said(r)]).collect(),
    }
}

/// Run a parsed line of `record`. A refusal is exit 1, with the daemon's reason.
async fn run(line: Line, state: &mut ShellState) -> Result<CommandOutput> {
    let user_id = state.user_id.clone();
    let mut client = state.client.lock().await;
    let refused = |verb: &str, e: std::io::Error| CommandOutput::fail(format!("record {verb}: {e}"), None);
    match line {
        Line::List { schema, json } => {
            let records = match client.record_query(&user_id, schema.as_str(), vec![], None, None).await {
                Ok(r) => r,
                Err(e) => return Ok(refused("list", e)),
            };
            if json {
                return Ok(CommandOutput::shapes(vec![Out::Data(serde_json::to_string_pretty(&records)?)]));
            }
            Ok(CommandOutput::shapes(vec![table(&records)]))
        }
        Line::Get { schema, id } => {
            let url = format!("kotton://records/{schema}/{id}");
            match client.record_open(&user_id, &url).await {
                Ok(Some((_, record))) => {
                    Ok(CommandOutput::shapes(vec![Out::Data(serde_json::to_string_pretty(&record)?)]))
                }
                Ok(None) => Ok(CommandOutput::fail(
                    format!("no record '{id}' under {schema}"),
                    Some(format!("`record list --schema {schema}` lists the ids")),
                )),
                Err(e) => Ok(refused("get", e)),
            }
        }
        Line::Put { schema, body } => match client.record_insert(&user_id, schema.as_str(), body).await {
            Ok(id) => Ok(CommandOutput::shapes(vec![Out::Data(id)])),
            Err(e) => Ok(refused("put", e)),
        },
        Line::Rm { schema, id } => match client.record_delete(&user_id, schema.as_str(), &id).await {
            Ok(()) => Ok(CommandOutput::shapes(vec![Out::Confirm {
                action: "record removed; your other devices see it gone after their next sync".into(),
                subject: id,
            }])),
            Err(e) => Ok(refused("rm", e)),
        },
    }
}

#[async_trait]
impl Command for RecordCommand {
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
            VERBS.iter().filter(|v| v.is == super::VerbIs::Current).map(|v| v.word.to_string()).collect()
        } else {
            vec![]
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["--schema", "--json"]
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
record — your records: typed, sealed, read from every device

USAGE:
  record list --schema <nsid> [--json]   every record of a schema: its id and its fields
  record get --schema <nsid> <id>        one record, as JSON on stdout
  record put --schema <nsid> <json>      write a record; prints its id
  record rm --schema <nsid> <id>         remove a record

A record is a JSON object of a schema's fields, kept on this device and
sealed into your first drive, `personal`, at each sync: a record put on one
device is read on another after a `sync` on each, and wherever `personal` is
moved. The vault keeps it sealed under your key and can read none of it: not
its fields, its id, or its schema's name. A schema is named by its NSID
(`sh.kotton.notes`); this device must know it, as a core schema or one
`schema register` added.

`put` with an `id` among the fields writes that record again; without one it
makes a new record and prints the id it was given. `rm` removes it on every
device at their next sync.

FLAGS:
  --schema <nsid>  the schema the record is of; every verb needs it
  --json           `list`: the records the daemon answered, as JSON on stdout

Exit 0 when done, 1 when refused or when no record has the id (the reason on
stderr), 2 for a line that is not one of the above.

EXAMPLES:
  record put --schema sh.kotton.notes '{\"title\":\"milk\",\"body\":\"two pints\"}'
  record list --schema sh.kotton.notes
  record get --schema sh.kotton.notes <id>
  record rm --schema sh.kotton.notes <id>";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ExitCode;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    const NOTES: &str = "sh.kotton.notes";

    fn notes() -> Nsid {
        Nsid::new(NOTES).unwrap()
    }

    /// Every current verb the table declares is a line this parser answers, so the table the
    /// verb check reads and the words the parser takes are one list.
    #[test]
    fn every_declared_verb_parses() {
        for (verb, line) in [
            ("list", "list --schema sh.kotton.notes"),
            ("get", "get --schema sh.kotton.notes abc"),
            ("put", r#"put --schema sh.kotton.notes {"title":"t"}"#),
            ("rm", "rm --schema sh.kotton.notes abc"),
        ] {
            assert!(VERBS.iter().any(|v| v.word == verb && v.is == crate::commands::VerbIs::Current), "{verb}");
            assert!(parse(&words(line)).is_ok(), "`record {line}` did not parse");
        }
        assert_eq!(VERBS.len(), 5, "a verb was declared that this test does not parse");
    }

    /// `--schema` stands anywhere after the verb, and each verb reads what it names.
    #[test]
    fn each_verb_reads_its_schema_and_its_word() {
        assert_eq!(parse(&words("list --schema sh.kotton.notes")).ok(), Some(Line::List { schema: notes(), json: false }));
        assert_eq!(parse(&words("list --json --schema sh.kotton.notes")).ok(), Some(Line::List { schema: notes(), json: true }));
        assert_eq!(parse(&words("get abc --schema sh.kotton.notes")).ok(), Some(Line::Get { schema: notes(), id: "abc".into() }));
        assert_eq!(parse(&words("rm --schema sh.kotton.notes abc")).ok(), Some(Line::Rm { schema: notes(), id: "abc".into() }));
        let put = vec!["put".to_string(), "--schema".into(), NOTES.into(), r#"{"title": "two words"}"#.into()];
        assert_eq!(parse(&put).ok(), Some(Line::Put { schema: notes(), body: serde_json::json!({ "title": "two words" }) }));
    }

    /// The command-tree decision: 2 is usage. A line the tree does not have exits 2, before any session.
    #[test]
    fn a_line_that_is_not_one_exits_two() {
        for line in [
            "",
            "frobnicate",
            "list",
            "get abc",
            "list --schema",
            "list --schema not-an-nsid",
            "list --schema sh.kotton.notes extra",
            "list --schema sh.kotton.notes --schema sh.kotton.tasks",
            "get --schema sh.kotton.notes",
            "get --schema sh.kotton.notes a b",
            "get --schema sh.kotton.notes --json abc",
            "get --schema sh.kotton.notes -x",
            "get --schema sh.kotton.notes a/b",
            "rm --schema sh.kotton.notes",
            "put --schema sh.kotton.notes",
            "put --schema sh.kotton.notes not-json",
            "put --schema sh.kotton.notes [1,2]",
            "put --schema sh.kotton.notes --json {}",
            "import --schema sh.kotton.notes x.ics",
            "export --schema sh.kotton.notes out",
        ] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "`record {line}`");
        }
    }

    /// `record open` is gone for `record get`: refused, exit 2, with the line naming it.
    #[test]
    fn open_is_gone_for_get() {
        let refused = parse(&words("open kotton://records/sh.kotton.notes/abc")).expect_err("open");
        assert_eq!(refused.exit_code, ExitCode::Code(2));
        let Some(Out::Fail { what, try_ }) = refused.out.first() else { panic!("a refusal is a Fail") };
        // The retired word, built from its two words: a literal naming it is the sweep's to refuse.
        assert_eq!(*what, format!("`{}` is gone", ["record", "open"].join(" ")));
        assert!(try_.as_deref().is_some_and(|t| t.contains("`record get --schema <nsid> <id>`")), "{try_:?}");
    }

    /// `record list` names each record by the id the daemon answered and prints its fields
    /// without the ones the daemon adds; `--json` carries the answer whole.
    #[test]
    fn list_names_each_id_and_prints_the_fields_it_was_given() {
        let answered = serde_json::json!({
            "id": "r1", "title": "milk", "_id": "r1", "_filed_at": 7, "_root": "p0"
        });
        let Out::Table { columns, rows } = table(&[answered]) else { panic!("record list is a table") };
        assert_eq!(columns, ["id", "record"]);
        assert_eq!(rows, [["r1".to_string(), r#"{"title":"milk"}"#.to_string()]]);
    }
}
