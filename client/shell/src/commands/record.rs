// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use kotton_schemas::SchemaId;
use kotton_wire::ipc::PERSONAL_ROOT;

use super::{retired, Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::ShellState;

/// record — your records: typed, sealed, in `personal`, read from every device.
///
/// Usage:
/// ```text
///   record list --schema <publisher>/<name> [--json]
///   record get --schema <publisher>/<name> <id>
///   record put --schema <publisher>/<name> <json>
///   record rm --schema <publisher>/<name> <id>
/// ```
///
/// The command-tree decision's "Records and schemas" line, but `import` and `export`, which
/// wait for #454. Each verb is one request the daemon already answers (`RecordQuery`, `get`
/// by the id, `RecordInsert`, `RecordDelete`), so the noun adds no reach. **Each names
/// Personal** ([`PERSONAL_ROOT`]): it reads, writes and removes the person's own records in
/// Personal and none in another root they are a member of, such as an organisation's. Those
/// ride sealed in the record log of the tree this device keeps of `personal`
/// (`kotton_record::replication`). A record put here
/// is read on another device after a `sync` on each, wherever `personal` lives. A schema is
/// cited by its identity, `<publisher>/<name>`, the publisher being the `did:key` of the key
/// that publishes it; this device must know it (a core schema, or one `schema register`ed).
///
/// `record open <url>` is gone for `record get`: the command-tree decision's table.
///
/// [`parse`] is the one parser for these words: `kotton record …` hands it the words after
/// the noun (`kotton_cli::bridge`), and the REPL hands it the same.
pub struct RecordCommand;

const USAGE: &str = "usage: record list --schema <schema> [--json] | record get --schema <schema> <id> | \
                     record put --schema <schema> <json> | record rm --schema <schema> <id>";

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
const GET_IS: &str = "`record get --schema <schema> <id>` reads one record, by its schema and its id";

/// A line of `record`, parsed.
#[derive(Debug, PartialEq)]
enum Line {
    List { schema: SchemaId, json: bool },
    Get { schema: SchemaId, id: String },
    Put { schema: SchemaId, body: serde_json::Value },
    Rm { schema: SchemaId, id: String },
}

/// A record's id as a word: not empty, not a flag, and without the `/` that would end it in
/// the record's URL (`kotton://records/<publisher>/<name>/<id>`, which `get` asks by).
fn id_word(word: &str) -> Option<String> {
    (!word.is_empty() && !word.starts_with('-') && !word.contains('/')).then(|| word.to_string())
}

/// The words after `record`, as a [`Line`], or the usage refusal (exit 2). `--schema <schema>`
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
                let Some(name) = it.next() else {
                    return usage(format!("record {verb}: `--schema` needs a schema, `<publisher>/<name>`"))
                };
                if schema.is_some() {
                    return usage(format!("record {verb}: `--schema` is said once"));
                }
                match SchemaId::parse(name) {
                    Ok(n) => schema = Some(n),
                    Err(e) => return usage(format!("record {verb}: '{name}' is not a schema identity: {e}")),
                }
            }
            "--json" => json = true,
            other => words.push(other),
        }
    }
    let Some(schema) = schema else {
        return usage(format!("record {verb}: needs --schema <publisher>/<name>"));
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
            Ok(body) if body.is_object() => match body.get("id") {
                None => Ok(Line::Put { schema, body }),
                Some(serde_json::Value::String(id)) if id_word(id).is_some() => Ok(Line::Put { schema, body }),
                Some(id) => usage(format!(
                    "record put: the `id` {id} is not a record's id: a string, not empty, not starting with `-`, without `/`"
                )),
            },
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

/// A record as `record get` and `record list --json` print it: as the row holds it, its `id`
/// among its fields, without the fields the daemon adds to an answer (`_id`, `_filed_at`,
/// `_root`). Every verb here names Personal, so `_root` would be Personal's id on every row
/// this surface can show: no information, and a durable identifier written to a stream meant
/// for piping, which `record put` of the printed record would then store as a field.
fn as_held(record: &serde_json::Value) -> serde_json::Value {
    let mut held = record.clone();
    if let Some(obj) = held.as_object_mut() {
        obj.retain(|k, _| !k.starts_with('_'));
    }
    held
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
            let records = match client
                .record_query_in(&user_id, Some(PERSONAL_ROOT), None, &schema.to_string(), vec![], None, None)
                .await
            {
                Ok(r) => r,
                Err(e) => return Ok(refused("list", e)),
            };
            if json {
                let held: Vec<serde_json::Value> = records.iter().map(as_held).collect();
                return Ok(CommandOutput::shapes(vec![Out::Data(serde_json::to_string_pretty(&held)?)]));
            }
            Ok(CommandOutput::shapes(vec![table(&records)]))
        }
        Line::Get { schema, id } => {
            // By the id, in Personal: `RecordOpen` names no root, and would reach a record in
            // any root the person is in. An unknown schema is the daemon's refusal, said as it.
            let by_id = vec![("id".to_string(), serde_json::json!(id))];
            match client.record_query_in(&user_id, Some(PERSONAL_ROOT), None, &schema.to_string(), by_id, Some(1), None).await {
                Ok(found) if !found.is_empty() => {
                    Ok(CommandOutput::shapes(vec![Out::Data(serde_json::to_string_pretty(&as_held(&found[0]))?)]))
                }
                Ok(_) => Ok(CommandOutput::fail(
                    format!("no record '{id}' under {schema}"),
                    Some(format!("`record list --schema {schema}` lists the ids")),
                )),
                Err(e) => Ok(refused("get", e)),
            }
        }
        Line::Put { schema, body } => match client
            .record_insert_in(&user_id, Some(PERSONAL_ROOT), None, &schema.to_string(), body)
            .await
        {
            Ok(id) => Ok(CommandOutput::shapes(vec![Out::Data(id)])),
            Err(e) => Ok(refused("put", e)),
        },
        Line::Rm { schema, id } => match client
            .record_delete_in(&user_id, Some(PERSONAL_ROOT), None, &schema.to_string(), &id)
            .await
        {
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
  record list --schema <schema> [--json]   every record of a schema: its id and its fields
  record get --schema <schema> <id>        one record, as JSON on stdout
  record put --schema <schema> <json>      write a record; prints its id
  record rm --schema <schema> <id>         remove a record

A record is a JSON object of a schema's fields, kept on this device and
sealed into your first drive, `personal`, at each sync: a record put on one
device is read on another after a `sync` on each, and wherever `personal` is
moved. The vault keeps it sealed under your key and can read none of it: not
its fields, its id, or its schema's name. A schema is named by the key that
publishes it: `<publisher>/<name>`, the publisher being the `did:key` of that
key, so Kotton's notes are `did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes`.
This device must know the schema, as a core schema or one `schema register` added.

These are your own records, in Personal: a record in another root you are a
member of, such as an organisation's project, is not listed, read, written or
removed here.

`put` with an `id` among the fields writes that record again; without one it
makes a new record and prints the id it was given. `rm` removes it on every
device at their next sync.

FLAGS:
  --schema <schema>  the schema the record is of, `<publisher>/<name>`; every verb needs it
  --json           `list`: the records the daemon answered, as JSON on stdout

Exit 0 when done, 1 when refused or when no record has the id (the reason on
stderr), 2 for a line that is not one of the above.

EXAMPLES:
  record put --schema did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes '{\"title\":\"milk\",\"body\":\"two pints\"}'
  record list --schema did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes
  record get --schema did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes <id>
  record rm --schema did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes <id>";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ExitCode;

    const NOTES: &str = kotton_common::namespace::NSID_NOTES;
    const TASKS: &str = kotton_common::namespace::NSID_TASKS;

    fn notes() -> SchemaId {
        SchemaId::from_static(NOTES)
    }

    /// `line`, with `NOTES` and `TASKS` where the line says them, split into words.
    fn words(line: &str) -> Vec<String> {
        line.replace("NOTES", NOTES).replace("TASKS", TASKS).split_whitespace().map(str::to_string).collect()
    }

    /// Every current verb the table declares is a line this parser answers, so the table the
    /// verb check reads and the words the parser takes are one list.
    #[test]
    fn every_declared_verb_parses() {
        for (verb, line) in [
            ("list", "list --schema NOTES"),
            ("get", "get --schema NOTES abc"),
            ("put", r#"put --schema NOTES {"title":"t"}"#),
            ("rm", "rm --schema NOTES abc"),
        ] {
            assert!(VERBS.iter().any(|v| v.word == verb && v.is == crate::commands::VerbIs::Current), "{verb}");
            assert!(parse(&words(line)).is_ok(), "`record {line}` did not parse");
        }
        assert_eq!(VERBS.len(), 5, "a verb was declared that this test does not parse");
    }

    /// `--schema` stands anywhere after the verb, and each verb reads what it names.
    #[test]
    fn each_verb_reads_its_schema_and_its_word() {
        assert_eq!(parse(&words("list --schema NOTES")).ok(), Some(Line::List { schema: notes(), json: false }));
        assert_eq!(parse(&words("list --json --schema NOTES")).ok(), Some(Line::List { schema: notes(), json: true }));
        assert_eq!(parse(&words("get abc --schema NOTES")).ok(), Some(Line::Get { schema: notes(), id: "abc".into() }));
        assert_eq!(parse(&words("rm --schema NOTES abc")).ok(), Some(Line::Rm { schema: notes(), id: "abc".into() }));
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
            "list --schema not-a-schema",
            "list --schema sh.kotton.notes",
            "list --schema NOTES extra",
            "list --schema NOTES --schema TASKS",
            "get --schema NOTES",
            "get --schema NOTES a b",
            "get --schema NOTES --json abc",
            "get --schema NOTES -x",
            "get --schema NOTES a/b",
            "rm --schema NOTES",
            "put --schema NOTES",
            "put --schema NOTES not-json",
            "put --schema NOTES [1,2]",
            "put --schema NOTES --json {}",
            "import --schema NOTES x.ics",
            "export --schema NOTES out",
        ] {
            let refused = parse(&words(line)).expect_err(line);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "`record {line}`");
        }
    }

    /// `put` takes an `id` field only as a record's id: a string `get` and `rm` could name.
    /// Anything else is usage, exit 2, before any session.
    #[test]
    fn put_refuses_an_id_that_is_not_a_records_id() {
        let put = |body: &str| vec!["put".to_string(), "--schema".into(), NOTES.into(), body.into()];
        for body in [r#"{"id":42}"#, r#"{"id":null}"#, r#"{"id":""}"#, r#"{"id":"a/b"}"#, r#"{"id":"-x"}"#, r#"{"id":["a"]}"#] {
            let refused = parse(&put(body)).expect_err(body);
            assert_eq!(refused.exit_code, ExitCode::Code(2), "{body}");
        }
        assert_eq!(
            parse(&put(r#"{"id":"r1","title":"t"}"#)).ok(),
            Some(Line::Put { schema: notes(), body: serde_json::json!({ "id": "r1", "title": "t" }) })
        );
    }

    /// `record open` is gone for `record get`: refused, exit 2, with the line naming it.
    #[test]
    fn open_is_gone_for_get() {
        let refused = parse(&words("open kotton://records/NOTES/abc")).expect_err("open");
        assert_eq!(refused.exit_code, ExitCode::Code(2));
        let Some(Out::Fail { what, try_ }) = refused.out.first() else { panic!("a refusal is a Fail") };
        // The retired word, built from its two words: a literal naming it is the sweep's to refuse.
        assert_eq!(*what, format!("`{}` is gone", ["record", "open"].join(" ")));
        assert!(try_.as_deref().is_some_and(|t| t.contains("`record get --schema <schema> <id>`")), "{try_:?}");
    }

    /// `record list` names each record by the id the daemon answered and prints its fields
    /// without the ones the daemon adds; `get` and `list --json` print the record as the row
    /// holds it, `id` kept, and none of the daemon's fields: no `_root`, which is Personal's
    /// id on every row these verbs can show.
    #[test]
    fn list_names_each_id_and_prints_the_fields_it_was_given() {
        let answered = serde_json::json!({
            "id": "r1", "title": "milk", "_id": "r1", "_filed_at": 7, "_root": "p0"
        });
        let Out::Table { columns, rows } = table(std::slice::from_ref(&answered)) else { panic!("record list is a table") };
        assert_eq!(columns, ["id", "record"]);
        assert_eq!(rows, [["r1".to_string(), r#"{"title":"milk"}"#.to_string()]]);
        assert_eq!(as_held(&answered), serde_json::json!({ "id": "r1", "title": "milk" }));
    }
}
