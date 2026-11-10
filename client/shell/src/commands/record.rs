// SPDX-License-Identifier: AGPL-3.0-or-later
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use kotton::ImportFormat;
use kotton_common::namespace::NSID_IMPORTED_CALENDAR;
use kotton_schemas::SchemaId;

use crate::petnames::{said, SchemaArg};
use kotton_wire::ipc::PERSONAL_ROOT;

use super::{retired, Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::ShellState;

/// record — your records: typed, sealed, in `personal`, read from every device.
///
/// Usage:
/// ```text
///   record list --schema <schema> [--json]
///   record get --schema <schema> <id>
///   record put --schema <schema> <json>
///   record rm --schema <schema> <id>
///   record import --schema <schema> <path>
///   record export --schema <schema> <path>
/// ```
///
/// The command-tree decision's "Records and schemas" line. Each verb asks only what the
/// daemon already answers (`RecordQuery`, `get` by the id, `RecordInsert`, `RecordDelete`,
/// and `Import` for an `.ics`), so the noun adds no reach. **Each names
/// Personal** ([`PERSONAL_ROOT`]): it reads, writes and removes the person's own records in
/// Personal and none in another root they are a member of, such as an organisation's. Those
/// ride sealed in the record log of the tree this device keeps of `personal`
/// (`kotton_record::replication`). A record put here
/// is read on another device after a `sync` on each, wherever `personal` lives. A schema is
/// cited by its identity, `<publisher>/<name>`, the publisher being the `did:key` of the key
/// that publishes it, or as `<petname>/<name>`, the person's own name for that key, resolved
/// on this device ([`crate::petnames`]); this device must know it (a core schema, or one
/// `schema register`ed).
///
/// `record open <url>` is gone for `record get`: the command-tree decision's table.
///
/// **`import` and `export` take a path on this computer** (kotton #454), read and written by
/// this process, the one the person typed it at, relative to the directory it runs in; the
/// path is never sent to the daemon. A file is JSON Lines, one record per line as `record
/// get` prints it: its `id` among its fields and none of the daemon's `_`-fields, so an
/// export carries no identifier the record did not already have, and an import of it puts
/// each record by its own id. A line whose record Personal already holds as written is not put
/// again, so a second import of the same file changes nothing; a line whose record has changed
/// since replaces it, and a record removed since comes back (a line without an `id` is a new
/// record each time, as `put` makes one).
/// The one other format is an `.ics` calendar, by the file's extension: its bytes and its file
/// name go to the daemon's reader (`Import`), which writes [`NSID_IMPORTED_CALENDAR`]
/// records, the only schema an `.ics` imports as.
///
/// [`parse`] is the one parser for these words: `kotton record …` hands it the words after
/// the noun (`kotton_cli::bridge`), and the REPL hands it the same.
pub struct RecordCommand;

const USAGE: &str = "usage: record list --schema <schema> [--json] | record get --schema <schema> <id> | \
                     record put --schema <schema> <json> | record rm --schema <schema> <id> | \
                     record import --schema <schema> <path> | record export --schema <schema> <path>";

/// The verbs: the command-tree decision's "Records and schemas" line, and `open`, which its
/// table retired for `get`.
const VERBS: &[Verb] = &[
    Verb::current("list"),
    Verb::current("get"),
    Verb::current("put"),
    Verb::current("rm"),
    Verb::current("import"),
    Verb::current("export"),
    Verb::gone("open", "record get"),
];

/// The most this hands the daemon in one request: an `.ics` whole, or one line of a JSON Lines
/// file, each record of which is a request of its own. `MAX_FRAME_LEN` in `core/ipc` is 32 MiB
/// and a frame past it closes the connection, so a larger one would fail as a dropped
/// connection with nothing saying why; bytes cost about four bytes of JSON each, hence the
/// quarter.
const MAX_REQUEST_BYTES: u64 = 6 * 1024 * 1024;

/// Records asked of the daemon at a time by `export`, so a schema of many records is never
/// one answer past the frame bound.
const EXPORT_PAGE: usize = 256;

/// What `record open` is now, said where it is refused.
const GET_IS: &str = "`record get --schema <schema> <id>` reads one record, by its schema and its id";

/// A line of `record`, parsed.
///
/// Generic over the schema: [`parse`] gives a line of the schema as typed ([`SchemaArg`]),
/// and [`run`] resolves it against the person's petnames into a line of the identity.
#[derive(Debug, PartialEq)]
enum Line<S = SchemaArg> {
    List { schema: S, json: bool },
    Get { schema: S, id: String },
    Put { schema: S, body: serde_json::Value },
    Rm { schema: S, id: String },
    Import { schema: S, path: PathBuf, format: FileFormat },
    Export { schema: S, path: PathBuf },
}

impl<S> Line<S> {
    /// The schema the line names.
    fn schema(&self) -> &S {
        match self {
            Self::List { schema, .. }
            | Self::Get { schema, .. }
            | Self::Put { schema, .. }
            | Self::Rm { schema, .. }
            | Self::Import { schema, .. }
            | Self::Export { schema, .. } => schema,
        }
    }

    /// The same line, of `to` in place of its schema.
    fn with<T>(self, to: T) -> Line<T> {
        match self {
            Self::List { json, .. } => Line::List { schema: to, json },
            Self::Get { id, .. } => Line::Get { schema: to, id },
            Self::Put { body, .. } => Line::Put { schema: to, body },
            Self::Rm { id, .. } => Line::Rm { schema: to, id },
            Self::Import { path, format, .. } => Line::Import { schema: to, path, format },
            Self::Export { path, .. } => Line::Export { schema: to, path },
        }
    }
}

/// What a file of records is, by its extension: an `.ics` calendar, or JSON Lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileFormat {
    JsonLines,
    Ics,
}

impl FileFormat {
    /// The format a path's extension names. An iCalendar file by any of its extensions is
    /// `.ics`; anything else is read and written as JSON Lines, under the schema `--schema`
    /// names, so nothing is guessed of what a record means.
    fn of(path: &Path) -> Self {
        let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        match ext.as_str() {
            "ics" | "ical" | "ifb" | "icalendar" => Self::Ics,
            _ => Self::JsonLines,
        }
    }
}

/// A record's id as a word: not empty, not a flag, and without the `/` that would end it in
/// the record's URL (`kotton://records/<publisher>/<name>/<id>`, which `get` asks by).
fn id_word(word: &str) -> Option<String> {
    (!word.is_empty() && !word.starts_with('-') && !word.contains('/')).then(|| word.to_string())
}

/// Why a text is not a record's body.
#[derive(Debug, PartialEq)]
enum NotARecord {
    /// Not one JSON object.
    NotAnObject,
    /// An object whose `id` is not a record's id, as JSON.
    Id(String),
}

impl std::fmt::Display for NotARecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => f.write_str("a record is one JSON object"),
            Self::Id(id) => write!(
                f,
                "the `id` {id} is not a record's id: a string, not empty, not starting with `-`, without `/`"
            ),
        }
    }
}

/// A record's body, as `put` takes it and `import` takes each line: one JSON object, whose
/// `id`, if it has one, is a record's id.
fn a_record(text: &str) -> Result<serde_json::Value, NotARecord> {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(body) if body.is_object() => match body.get("id") {
            None => Ok(body),
            Some(serde_json::Value::String(id)) if id_word(id).is_some() => Ok(body),
            Some(id) => Err(NotARecord::Id(id.to_string())),
        },
        _ => Err(NotARecord::NotAnObject),
    }
}

/// Why a line of a file is not one `import` puts.
#[derive(Debug, PartialEq)]
enum NotALine {
    /// Longer, in bytes, than one request carries.
    TooLong(usize),
    /// Not a record's body, as `put` takes one.
    NotARecord(NotARecord),
    /// A field beginning with `_`: those are the daemon's, added to an answer, and none is a
    /// record's (kotton #459 is the daemon's half).
    DaemonField(String),
}

impl std::fmt::Display for NotALine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong(len) => {
                write!(f, "the line is {len} bytes; a record is put in one request of at most {MAX_REQUEST_BYTES}")
            }
            Self::NotARecord(why) => why.fmt(f),
            Self::DaemonField(key) => write!(
                f,
                "the field `{key}` begins with `_`, which marks a field the daemon adds to an answer, not a record's"
            ),
        }
    }
}

/// A line of a file as `import` checks it before anything is put: within one request, a
/// record's body as `put` takes one, and no top-level field beginning with `_`.
fn a_line(text: &str) -> Result<serde_json::Value, NotALine> {
    if text.len() as u64 > MAX_REQUEST_BYTES {
        return Err(NotALine::TooLong(text.len()));
    }
    let body = a_record(text).map_err(NotALine::NotARecord)?;
    let daemons = body.as_object().and_then(|fields| fields.keys().find(|k| k.starts_with('_')));
    match daemons {
        Some(key) => Err(NotALine::DaemonField(key.clone())),
        None => Ok(body),
    }
}

/// Write `text` to `path` as a new file, the person's: never over one already there, and on
/// unix readable by its owner only. A write that fails partway removes what it wrote, and the
/// error says whether it could.
fn write_new(path: &Path, text: &str) -> std::io::Result<()> {
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut file = open.open(path)?;
    if let Err(e) = file.write_all(text.as_bytes()).and_then(|()| file.sync_all()) {
        drop(file);
        let removed = match std::fs::remove_file(path) {
            Ok(()) => "the partial file was removed".to_string(),
            Err(r) => format!("the partial file could not be removed: {r}"),
        };
        return Err(std::io::Error::new(e.kind(), format!("{e}; {removed}")));
    }
    Ok(())
}

/// A path on this computer as a word: not empty and not a flag.
fn path_word(word: &str) -> Option<PathBuf> {
    (!word.is_empty() && !word.starts_with('-')).then(|| PathBuf::from(word))
}

/// What an `.ics` imports as, said where another schema is refused for one.
fn ics_is() -> String {
    format!(
        "an .ics file imports as `{NSID_IMPORTED_CALENDAR}`: `record import --schema {NSID_IMPORTED_CALENDAR} <path>`. \
         The calendar schema has no field for an event's recurrence, zone or all-day flag"
    )
}

/// The refusal of an `.ics` import under any schema but the one an `.ics` is read as, or
/// `None`. `typed` is the schema as the person typed it.
fn ics_refused(format: FileFormat, schema: &SchemaId, typed: String) -> Option<CommandOutput> {
    (format == FileFormat::Ics && schema.to_string() != NSID_IMPORTED_CALENDAR).then(|| {
        CommandOutput::usage(format!("record import: an .ics file is not read as {typed} records"), Some(ics_is()))
    })
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
    if !matches!(verb.as_str(), "list" | "get" | "put" | "rm" | "import" | "export") {
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
                    return usage(format!("record {verb}: `--schema` needs a schema, {}", crate::petnames::FORMS))
                };
                if schema.is_some() {
                    return usage(format!("record {verb}: `--schema` is said once"));
                }
                match SchemaArg::parse(name) {
                    Ok(n) => schema = Some(n),
                    Err(e) => return usage(format!("record {verb}: {e}")),
                }
            }
            "--json" => json = true,
            other => words.push(other),
        }
    }
    let Some(schema) = schema else {
        return usage(format!("record {verb}: needs --schema <schema>, {}", crate::petnames::FORMS));
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
        ("put", [body]) => match a_record(body) {
            Ok(body) => Ok(Line::Put { schema, body }),
            Err(NotARecord::NotAnObject) => usage("record put: the record is one JSON object, quoted as one word".into()),
            Err(why) => usage(format!("record put: {why}")),
        },
        ("import", [path]) => match path_word(path) {
            Some(path) => {
                let format = FileFormat::of(&path);
                // The whole identity is held here; a short one when it is resolved (`run`).
                if let SchemaArg::Full(id) = &schema {
                    if let Some(refused) = ics_refused(format, id, id.to_string()) {
                        return Err(refused);
                    }
                }
                Ok(Line::Import { schema, path, format })
            }
            None => usage(format!("record import: '{path}' is not a path")),
        },
        ("export", [path]) => match path_word(path) {
            Some(path) if FileFormat::of(&path) == FileFormat::Ics => usage(format!(
                "record export: '{}' names an .ics file; an export is JSON Lines, one record per line",
                path.display()
            )),
            Some(path) => Ok(Line::Export { schema, path }),
            None => usage(format!("record export: '{path}' is not a path")),
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

/// The record `id` of `schema` as Personal holds it, as `record get` prints it, or `None` if
/// Personal holds none by that id (never put, or removed). By the id, in Personal:
/// `RecordOpen` names no root, and would reach a record in any root the person is in.
async fn held_by_id(
    client: &mut kotton::KottonClient,
    user_id: &str,
    schema: &SchemaId,
    id: &str,
) -> std::io::Result<Option<serde_json::Value>> {
    let by_id = vec![("id".to_string(), serde_json::json!(id))];
    let found =
        client.record_query_in(user_id, Some(PERSONAL_ROOT), None, &schema.to_string(), by_id, Some(1), None).await?;
    Ok(found.first().map(as_held))
}

fn table(records: &[serde_json::Value]) -> Out {
    Out::Table {
        columns: vec!["id".into(), "record".into()],
        rows: records.iter().map(|r| vec![id_said(r), body_said(r)]).collect(),
    }
}

/// Run a parsed line of `record`: its schema resolved against the person's petnames
/// ([`crate::petnames::read`]), then the verb. A schema the petnames do not resolve is refused,
/// exit 2, saying why; a refusal of the verb is exit 1, with the daemon's reason. A schema is
/// printed in the short form wherever the publisher has a name ([`said`]).
async fn run(line: Line, state: &mut ShellState) -> Result<CommandOutput> {
    let user_id = state.user_id.clone();
    let mut client = state.client.lock().await;
    let names = crate::petnames::read(&mut client, &user_id).await;
    let resolved = match line.schema().resolve(&names) {
        Ok(id) => id,
        Err(why) => return Ok(CommandOutput::usage(format!("record: {why}"), None)),
    };
    if let Line::Import { format, .. } = &line {
        if let Some(refused) = ics_refused(*format, &resolved, said(&resolved, &names)) {
            return Ok(refused);
        }
    }
    let shown = said(&resolved, &names);
    let line = line.with(resolved);
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
            // An unknown schema is the daemon's refusal, said as it.
            match held_by_id(&mut client, &user_id, &schema, &id).await {
                Ok(Some(held)) => Ok(CommandOutput::shapes(vec![Out::Data(serde_json::to_string_pretty(&held)?)])),
                Ok(None) => Ok(CommandOutput::fail(
                    format!("no record '{id}' under {shown}"),
                    Some(format!("`record list --schema {shown}` lists the ids")),
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
        Line::Import { schema, path, format: FileFormat::JsonLines } => {
            // Two passes before any put: every line is checked, then every record a line
            // names by its `id` is read as Personal holds it. So a file that is not records,
            // or a read the daemon refuses, writes nothing.
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => return Ok(CommandOutput::fail(format!("record import: {}: {e}", path.display()), None)),
            };
            let mut records = Vec::new();
            for (n, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                match a_line(line) {
                    Ok(body) => records.push((n + 1, body)),
                    Err(why) => {
                        return Ok(CommandOutput::fail(
                            format!("record import: {} line {}: {why}; nothing was imported", path.display(), n + 1),
                            Some("a file of records is JSON Lines: one record per line, as `record export` writes".into()),
                        ))
                    }
                }
            }
            // A line whose record is held as written is not put: a put is a new revision,
            // which every device syncs, so putting it again would change what each holds for
            // nothing. A line whose record differs replaces it; one not held (never put, or
            // removed since) puts it.
            let mut puts = Vec::new();
            let mut as_written = 0usize;
            for (n, body) in records {
                let replaces = match body.get("id").and_then(serde_json::Value::as_str) {
                    None => false,
                    Some(id) => match held_by_id(&mut client, &user_id, &schema, id).await {
                        Ok(Some(held)) if held == body => {
                            as_written += 1;
                            continue;
                        }
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(e) => {
                            return Ok(CommandOutput::fail(
                                format!("record import: {} line {n}: {e}; nothing was imported", path.display()),
                                None,
                            ))
                        }
                    },
                };
                puts.push((n, body, replaces));
            }
            let replaced = puts.iter().filter(|(_, _, replaces)| *replaces).count();
            let total = puts.len();
            for (put, (n, body, _)) in puts.into_iter().enumerate() {
                if let Err(e) = client.record_insert_in(&user_id, Some(PERSONAL_ROOT), None, &schema.to_string(), body).await {
                    return Ok(CommandOutput::fail(
                        format!("record import: {} line {n}: {e}; {put} of {total} record(s) were put before it", path.display()),
                        Some("a record already held as written is not put again, so importing the file again puts only the rest".into()),
                    ));
                }
            }
            Ok(CommandOutput::shapes(vec![Out::Confirm {
                action: format!(
                    "into personal: {total} record(s) put, {replaced} of them replacing one that differed; {as_written} already held as written, not put"
                ),
                subject: shown,
            }]))
        }
        Line::Import { schema, path, format: FileFormat::Ics } => {
            match std::fs::metadata(&path) {
                Ok(meta) if meta.len() > MAX_REQUEST_BYTES => {
                    return Ok(CommandOutput::fail(
                        format!(
                            "record import: {} is {} bytes; an .ics is read in one request of at most {MAX_REQUEST_BYTES}",
                            path.display(),
                            meta.len()
                        ),
                        Some("split the calendar and import the parts".into()),
                    ))
                }
                Ok(_) => {}
                Err(e) => return Ok(CommandOutput::fail(format!("record import: {}: {e}", path.display()), None)),
            }
            let content = match std::fs::read(&path) {
                Ok(c) => c,
                Err(e) => return Ok(CommandOutput::fail(format!("record import: {}: {e}", path.display()), None)),
            };
            // The file's name, which the daemon keeps as each event's provenance; never the
            // path, which says where the person keeps things and would ride every record to
            // every device.
            let source_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "import".into());
            let (wrote, imported, skipped) = match client.import(&user_id, ImportFormat::Ics, &source_name, content).await {
                Ok(done) => done,
                Err(e) => return Ok(refused("import", e)),
            };
            if wrote != schema.to_string() {
                return Ok(CommandOutput::fail(
                    format!("record import: the daemon wrote {imported} event(s) as {wrote}, not {shown}"),
                    Some(format!("`record list --schema {wrote}` lists them")),
                ));
            }
            let mut out = vec![Out::Confirm {
                action: format!("{imported} event(s) imported into personal from {source_name}"),
                subject: shown,
            }];
            if skipped > 0 {
                // Never folded into the total: only the person can say whether the ones that
                // did not make it mattered.
                out.push(Out::Warn {
                    what: format!("{skipped} event(s) skipped"),
                    consequence: "the file gave them no start time a record can hold".into(),
                });
            }
            Ok(CommandOutput::shapes(out))
        }
        Line::Export { schema, path } => {
            // Paged by offset: a record filed while the export runs can shift a page, so a line
            // may be written twice or a record missed. Harmless to an import of the file, which
            // puts each line by its id; a record missed is in the next export.
            let mut held = Vec::new();
            loop {
                let page = match client
                    .record_query_in(
                        &user_id,
                        Some(PERSONAL_ROOT),
                        None,
                        &schema.to_string(),
                        vec![],
                        Some(EXPORT_PAGE),
                        Some(held.len()),
                    )
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return Ok(refused("export", e)),
                };
                let last = page.len() < EXPORT_PAGE;
                held.extend(page.iter().map(as_held));
                if last {
                    break;
                }
            }
            // Newest first is how the daemon answers; a file reads oldest first, so an import
            // of it puts the records in the order they were made.
            held.reverse();
            let mut text = String::new();
            for record in &held {
                text.push_str(&record.to_string());
                text.push('\n');
            }
            // A file already there is the person's, and is not written over; the one written is
            // theirs too, readable by them only.
            if let Err(e) = write_new(&path, &text) {
                return Ok(CommandOutput::fail(
                    format!("record export: {}: {e}", path.display()),
                    (e.kind() == std::io::ErrorKind::AlreadyExists)
                        .then(|| "an export writes a new file; name one that is not there".to_string()),
                ));
            }
            Ok(CommandOutput::shapes(vec![Out::Confirm {
                action: format!("{} record(s) of {shown} exported", held.len()),
                subject: path.display().to_string(),
            }]))
        }
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

/// `import`, the word that read an `.ics` before `record import` did: gone for it (kotton
/// #454, the command-tree decision's table). Both doors register it, so `kotton import …` and
/// the REPL's `import …` give the one refusal, exit 2, before any session; it is hidden from
/// `help`, which lists what runs.
pub struct ImportGone;

/// What `import` is now, said where it is refused.
fn import_is() -> String {
    format!("`record import --schema {NSID_IMPORTED_CALENDAR} <path>` reads an .ics file into your records")
}

#[async_trait]
impl Command for ImportGone {
    async fn execute(&self, _args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
        Ok(retired("import", &import_is()))
    }

    async fn execute_without_session(&self, _args: &[String], _named: Option<&str>) -> Option<Result<CommandOutput>> {
        Some(Ok(retired("import", &import_is())))
    }

    fn hidden(&self) -> bool {
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
  record import --schema <schema> <path>   put each record of a file into your records
  record export --schema <schema> <path>   write your records of a schema to a new file

A record is a JSON object of a schema's fields, kept on this device and
sealed into your first drive, `personal`, at each sync: a record put on one
device is read on another after a `sync` on each, and wherever `personal` is
moved. The vault keeps it sealed under your key and can read none of it: not
its fields, its id, or its schema's name. A schema is named by the key that
publishes it: `did:key:…/<name>`, the `did:key` of that key and the name, so
Kotton's notes are `did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes`.
Type it whole, or as `<petname>/<name>`, your own name for the key: `kotton`
names Kotton's key on every device, so those notes are `kotton/notes`. A
petname is resolved on this device; one no key has, or one you gave several
keys, is refused. This device must know the schema, as a core schema or one
`schema register` added.

These are your own records, in Personal: a record in another root you are a
member of, such as an organisation's project, is not listed, read, written or
removed here.

`put` with an `id` among the fields writes that record again; without one it
makes a new record and prints the id it was given. `rm` removes it on every
device at their next sync.

`import` and `export` take a path on this computer, relative to the directory
you run them in; it is read or written here and never sent to the daemon. The
file is JSON Lines: one record per line, as `get` prints it, its `id` among
its fields. `export` writes a new file, readable by you only, and will not
write over one. `import` puts a line with an `id` by that id: a second import
of the same file changes nothing; a line whose record has changed since
replaces it; a record removed since comes back. A line without an `id` is a
new record each time. An `.ics` file (by its extension) imports as calendar
events, under the schema an `.ics` is read as, `kotton/import.calendar.event`.
It keeps an event's recurrence, zone and all-day flag, which the calendar
schema has no field for.

FLAGS:
  --schema <schema>  the schema the records are of, `<petname>/<name>` or
                     `did:key:…/<name>`; every verb needs it
  --json           `list`: the records the daemon answered, as JSON on stdout

Exit 0 when done, 1 when refused, when no record has the id, or when a file
cannot be read or written (the reason on stderr), 2 for a line that is not one
of the above.

EXAMPLES:
  record put --schema kotton/notes '{\"title\":\"milk\",\"body\":\"two pints\"}'
  record list --schema kotton/notes
  record list --schema did:key:z6MkiDN8JjmwvSCGfrmH9YdvBuJxVGyyEWBvECCp3cfDgCMB/notes
  record get --schema kotton/notes <id>
  record rm --schema kotton/notes <id>
  record export --schema kotton/notes notes.jsonl
  record import --schema kotton/notes notes.jsonl
  record import --schema kotton/import.calendar.event calendar.ics";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ExitCode;

    const NOTES: &str = kotton_common::namespace::NSID_NOTES;
    const TASKS: &str = kotton_common::namespace::NSID_TASKS;

    fn notes() -> SchemaArg {
        SchemaArg::Full(SchemaId::from_static(NOTES))
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
            ("import", "import --schema NOTES notes.jsonl"),
            ("export", "export --schema NOTES notes.jsonl"),
        ] {
            assert!(VERBS.iter().any(|v| v.word == verb && v.is == crate::commands::VerbIs::Current), "{verb}");
            assert!(parse(&words(line)).is_ok(), "`record {line}` did not parse");
        }
        assert_eq!(VERBS.len(), 7, "a verb was declared that this test does not parse");
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
            "import --schema NOTES",
            "import --schema NOTES a b",
            "import --schema NOTES -x",
            "import --schema NOTES --json a.jsonl",
            "export --schema NOTES",
            "export --schema NOTES a b",
            "export --schema NOTES out.ics",
            "export --schema NOTES --json out",
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

    /// `import` and `export` take one path, as typed, and the format is the extension's: an
    /// `.ics` by any of its names is a calendar, read only as the schema it imports as;
    /// anything else is JSON Lines.
    #[test]
    fn import_and_export_take_a_path_and_its_format_is_its_extension() {
        assert_eq!(
            parse(&words("import --schema NOTES ../notes.jsonl")).ok(),
            Some(Line::Import { schema: notes(), path: "../notes.jsonl".into(), format: FileFormat::JsonLines })
        );
        assert_eq!(
            parse(&words("export notes --schema NOTES")).ok(),
            Some(Line::Export { schema: notes(), path: "notes".into() })
        );
        for name in ["cal.ics", "CAL.ICS", "cal.ical", "cal.ifb", "cal.icalendar"] {
            let line = vec!["import".to_string(), "--schema".into(), NSID_IMPORTED_CALENDAR.into(), name.into()];
            assert_eq!(
                parse(&line).ok(),
                Some(Line::Import {
                    schema: SchemaArg::Full(SchemaId::from_static(NSID_IMPORTED_CALENDAR)),
                    path: name.into(),
                    format: FileFormat::Ics
                }),
                "{name}"
            );
        }
        // The calendar schema, for an .ics, is refused with the line that would read it.
        let calendar = vec![
            "import".to_string(),
            "--schema".into(),
            kotton_common::namespace::NSID_CALENDAR.into(),
            "cal.ics".into(),
        ];
        let refused = parse(&calendar).expect_err("calendar for an .ics");
        assert_eq!(refused.exit_code, ExitCode::Code(2));
        let Some(Out::Fail { try_, .. }) = refused.out.first() else { panic!("a refusal is a Fail") };
        let want = format!("`record import --schema {NSID_IMPORTED_CALENDAR} <path>`");
        assert!(try_.as_deref().is_some_and(|t| t.contains(&want)), "{try_:?}");
    }

    /// `--schema` takes the short form too, `<petname>/<name>`, parsed by the one parser and
    /// resolved when the line runs; a word that is neither form is usage, exit 2.
    #[test]
    fn the_short_form_parses() {
        let SchemaArg::Short { petname, name } = SchemaArg::parse("kotton/notes").unwrap() else { panic!("short") };
        let short = SchemaArg::Short { petname, name };
        assert_eq!(
            parse(&words("list --schema kotton/notes")).ok(),
            Some(Line::List { schema: short.clone(), json: false })
        );
        assert_eq!(
            parse(&words("import --schema kotton/import.calendar.event cal.ics")).ok().map(|l| l.with(())),
            Some(Line::Import { schema: (), path: "cal.ics".into(), format: FileFormat::Ics })
        );
        for line in ["list --schema kotton", "list --schema kotton/Notes", "list --schema /notes"] {
            assert_eq!(parse(&words(line)).expect_err(line).exit_code, ExitCode::Code(2), "{line}");
        }
    }

    /// A line of a file is a record as `put` takes one: an object, whose `id` is a record's.
    #[test]
    fn a_line_is_a_record_as_put_takes_one() {
        assert_eq!(a_record(r#"{"id":"r1","title":"t"}"#), Ok(serde_json::json!({ "id": "r1", "title": "t" })));
        assert_eq!(a_record(r#"{"title":"t"}"#), Ok(serde_json::json!({ "title": "t" })));
        assert_eq!(a_record("[1]"), Err(NotARecord::NotAnObject));
        assert_eq!(a_record("not json"), Err(NotARecord::NotAnObject));
        assert_eq!(a_record(r#"{"id":"a/b"}"#), Err(NotARecord::Id("\"a/b\"".into())));
    }

    /// A line longer than one request carries is refused before anything is put, by its
    /// length; a line at the bound is a record like any other.
    #[test]
    fn a_line_longer_than_one_request_is_refused() {
        let line = |len: usize| {
            let frame = r#"{"title":""#.len() + r#""}"#.len();
            format!(r#"{{"title":"{}"}}"#, "x".repeat(len - frame))
        };
        let bound = MAX_REQUEST_BYTES as usize;
        assert!(a_line(&line(bound)).is_ok());
        assert_eq!(a_line(&line(bound + 1)), Err(NotALine::TooLong(bound + 1)));
        assert!(NotALine::TooLong(bound + 1).to_string().contains(&MAX_REQUEST_BYTES.to_string()));
    }

    /// A line may not carry a field beginning with `_`: those are the daemon's, and an export
    /// writes none. The refusal names the field; a `_` below the top level is a record's own.
    #[test]
    fn a_line_with_a_daemon_field_is_refused_by_its_name() {
        for (line, key) in [(r#"{"id":"r1","_root":"p0"}"#, "_root"), (r#"{"title":"t","_id":"x"}"#, "_id")] {
            let refused = a_line(line).expect_err(line);
            assert_eq!(refused, NotALine::DaemonField(key.into()));
            assert!(refused.to_string().contains(&format!("`{key}`")), "{refused}");
        }
        assert!(a_line(r#"{"title":"t","meta":{"_x":1}}"#).is_ok());
        assert_eq!(a_line("[1]"), Err(NotALine::NotARecord(NotARecord::NotAnObject)));
    }

    /// An export is a new file, never written over one, and on unix its owner's only.
    #[test]
    fn an_export_is_a_new_file_and_the_persons() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("notes.jsonl");
        write_new(&path, "{}\n").expect("written");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "{}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "an export is readable by its owner only, not {mode:o}");
        }
        let again = write_new(&path, "other\n").expect_err("written over");
        assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "{}\n");
    }

    /// `import` is gone for `record import`: refused, exit 2, with the line that reads an
    /// `.ics`.
    #[tokio::test]
    async fn import_is_gone_for_record_import() {
        let refused = ImportGone.execute_without_session(&words("cal.ics"), None).await.expect("refused").unwrap();
        assert_eq!(refused.exit_code, ExitCode::Code(2));
        let Some(Out::Fail { what, try_ }) = refused.out.first() else { panic!("a refusal is a Fail") };
        assert_eq!(what, "`import` is gone");
        let want = format!("`record import --schema {NSID_IMPORTED_CALENDAR} <path>`");
        assert!(try_.as_deref().is_some_and(|t| t.contains(&want)), "{try_:?}");
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
