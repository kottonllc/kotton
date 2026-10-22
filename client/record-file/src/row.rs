// SPDX-License-Identifier: AGPL-3.0-or-later
//! A record file and its row, in both directions, byte for byte (RFC-0088 rule 2).
//!
//! ## The shape of a file, as the converter reads it
//!
//! A record file is three parts, and the one parser in [`crate::header`] already says where
//! each one starts:
//!
//! ```text
//! # <title>            ← the lead: the title line and whatever sits before the header
//! <lead>
//! **Key:** value \     ← the header block: the first run of `**Key:**` lines
//! **Key:** value
//! <body>               ← everything after the block's last newline
//! ```
//!
//! Six records open with their header and put the title in the body; their lead is absent
//! and their title is read where the board has always read it.
//!
//! ## What the row holds, and why a `form`
//!
//! The row holds each value **once**: the fields the schema names (`status`, `region`, …),
//! every other header line in `header_rest` in order, and the body. That is RFC-0088's table,
//! and it is not quite enough to reproduce the file — the table has no place for *where* a
//! named field's line sat among the others, for the spaces a writer put after `**Key:**`, or
//! for the continuation backslash. Those are form, not content, so they sit in one field,
//! `form`, that says per line which key it was, its padding and its tail, and says what came
//! between the title and the header. A value is never stored twice: `form` names keys and
//! never holds a value, so the named field is the one copy a reader filters on and the one
//! copy export writes.
//!
//! ## The board and the converter read the same line
//!
//! A named value is taken from the header block, and the import **refuses** a file whose
//! named field the board would read from somewhere else — a second header run after a blank
//! line, or a field line down in the body. That is the only way `header_field_whole` and
//! this converter can disagree, and a refusal keeps the claim "they never disagree" true by
//! construction rather than by luck.

use serde_json::{json, Map, Value};

use crate::header;

/// The schema every row belongs to (RFC-0088, "The schema").
///
/// An extension schema under the project's own namespace: it carries this project's
/// vocabulary and makes no interoperability claim, and it is not in `kotton_schemas::core`
/// (Article IX — no core schema is touched).
pub const NSID: &str = "sh.kotton.governance.record";

/// The header keys the schema names, the field each fills, and whether it is a list.
///
/// A list is split on `", "` and joined on it again, which is the identity on every string —
/// so a list field round-trips whatever its writer typed, and a value written the standard
/// way (`core, client`) reads as the list it means.
pub const NAMED: &[(&str, &str, bool)] = &[
    ("Status", "status", false),
    ("Type", "type", false),
    ("Region", "region", true),
    ("Domains", "domains", true),
    ("Blocked-by", "blocked_by", false),
    ("Built", "built", false),
    ("Evidence", "evidence", true),
    ("Authority", "authority", false),
    ("Serves", "serves", false),
    ("Security", "security", false),
    ("Opened", "opened", false),
    ("Updated", "updated", false),
];

/// Why a file is not a row, or a row is not a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The name cannot be a file in a records directory: empty, hidden, or carrying a path
    /// separator. Refused both ways, because a row's name is the file export writes, and a
    /// row can arrive from another member of the root.
    BadName(String),
    /// No `**Key:**` line anywhere.
    NoHeader,
    /// The header's last line is the file's last byte, so there is no newline to end it.
    HeaderEndsTheFile,
    /// Text sits before the header and it does not open with the title line.
    OpensWithNeither,
    /// The board reads this named field from a line outside the header block, so a row
    /// holding the block's value would disagree with it.
    FieldOutsideHeader(String),
    /// A row that is not the shape this converter writes.
    NotARow(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadName(n) => write!(f, "{n:?} is not a record name (a file stem with no path in it)"),
            Error::NoHeader => f.write_str("no `**Key:** value` header line"),
            Error::HeaderEndsTheFile => f.write_str("the header is the last line and has no newline after it"),
            Error::OpensWithNeither => {
                f.write_str("text before the header that does not open with the `# ` title line")
            }
            Error::FieldOutsideHeader(k) => write!(
                f,
                "`**{k}:**` is read by the board from a line outside the header block; \
                 move it into the header so the board and the row read the same line"
            ),
            Error::NotARow(why) => write!(f, "not a governance record row: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether `name` can be a record's file stem: non-empty, not hidden, and naming no path.
pub fn is_record_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// One header line, taken apart at the byte boundaries the parser reads.
struct Line<'a> {
    key: &'a str,
    pad: &'a str,
    value: &'a str,
    tail: &'a str,
}

fn split_line(l: &str) -> Option<Line<'_>> {
    let rest = l.strip_prefix("**")?;
    let end = rest.find(":**")?;
    let key = &rest[..end];
    let after = &rest[end + 3..];
    let value = header::value_of(after);
    let pad = &after[..after.len() - after.trim_start().len()];
    // The value is cut from both ends only, so where it is not empty it starts where the
    // padding stops. Checked rather than assumed: a line this cannot take apart is refused.
    let tail_at = pad.len() + value.len();
    if after.get(pad.len()..tail_at).is_none_or(|v| v != value) {
        return None;
    }
    Some(Line { key, pad, value, tail: &after[tail_at..] })
}

fn named(key: &str) -> Option<(&'static str, bool)> {
    NAMED.iter().find(|(k, _, _)| *k == key).map(|(_, f, list)| (*f, *list))
}

/// Read a record file into a row of [`NSID`].
///
/// `name` is the file's stem, and it is the row's identity: the row's `id` is the name, so
/// importing the same file again replaces this row rather than adding one.
pub fn to_row(name: &str, text: &str) -> Result<Value, Error> {
    if !is_record_name(name) {
        return Err(Error::BadName(name.to_owned()));
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let block = header::block(&lines).ok_or(Error::NoHeader)?;
    if block.end == lines.len() {
        return Err(Error::HeaderEndsTheFile);
    }
    let start_byte: usize = lines[..block.start].iter().map(|l| l.len() + 1).sum();
    let body_byte: usize = start_byte + lines[block.clone()].iter().map(|l| l.len() + 1).sum::<usize>();
    let before = &text[..start_byte];
    let body = &text[body_byte..];

    let title = header::title_of(text).unwrap_or_else(|| name.to_owned());
    let lead = if before.is_empty() {
        None
    } else {
        let first = format!("# {title}\n");
        match before.strip_prefix(first.as_str()) {
            Some(lead) => Some(lead.to_owned()),
            None => return Err(Error::OpensWithNeither),
        }
    };

    let mut row = Map::new();
    row.insert("id".into(), json!(name));
    row.insert("name".into(), json!(name));
    row.insert("kind".into(), json!(header::kind_of(name)));
    row.insert("title".into(), json!(title));

    let mut rest = Vec::new();
    let mut form_lines = Vec::new();
    for l in &lines[block.clone()] {
        let line = split_line(l).ok_or_else(|| Error::NotARow(format!("cannot take apart {l:?}")))?;
        match named(line.key) {
            Some((field, list)) if !row.contains_key(field) => {
                let v = if list {
                    if line.value.is_empty() {
                        json!([])
                    } else {
                        json!(line.value.split(", ").collect::<Vec<_>>())
                    }
                } else {
                    json!(line.value)
                };
                // The board reads the first `**Key:**` line in the whole file, whole or by its
                // first word; this block line must be that line.
                if header::header_field_whole(text, line.key) != line.value
                    || header::header_field(text, line.key) != header::header_field(l, line.key)
                {
                    return Err(Error::FieldOutsideHeader(line.key.to_owned()));
                }
                row.insert(field.into(), v);
            }
            _ => rest.push(json!({ "key": line.key, "value": line.value })),
        }
        form_lines.push(json!({ "key": line.key, "pad": line.pad, "tail": line.tail }));
    }
    // A named field absent from the block must be absent to the board too.
    for (key, field, _) in NAMED {
        if !row.contains_key(*field) && !header::header_field_whole(text, key).is_empty() {
            return Err(Error::FieldOutsideHeader((*key).to_owned()));
        }
    }

    row.insert("header_rest".into(), Value::Array(rest));
    row.insert("body".into(), json!(body));
    let mut form = Map::new();
    if let Some(lead) = lead {
        form.insert("lead".into(), json!(lead));
    }
    form.insert("lines".into(), Value::Array(form_lines));
    row.insert("form".into(), Value::Object(form));
    Ok(Value::Object(row))
}

fn text_of<'a>(row: &'a Value, field: &str) -> Result<&'a str, Error> {
    row.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::NotARow(format!("`{field}` is not a string")))
}

/// Write a row of [`NSID`] back to its file: `(name, text)`, where the file is `<name>.md`.
///
/// The exact inverse of [`to_row`]: for every file `to_row` accepts,
/// `to_file(&to_row(name, text)?)` is `(name, text)` byte for byte.
pub fn to_file(row: &Value) -> Result<(String, String), Error> {
    let name = text_of(row, "name")?;
    if !is_record_name(name) {
        return Err(Error::BadName(name.to_owned()));
    }
    let body = text_of(row, "body")?;
    let form = row
        .get("form")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::NotARow("no `form`".into()))?;
    let lines = form
        .get("lines")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::NotARow("`form` has no `lines`".into()))?;
    let rest = row
        .get("header_rest")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::NotARow("no `header_rest`".into()))?;

    let mut out = String::new();
    match form.get("lead") {
        None | Some(Value::Null) => {}
        Some(Value::String(lead)) => {
            out.push_str("# ");
            out.push_str(text_of(row, "title")?);
            out.push('\n');
            out.push_str(lead);
        }
        Some(_) => return Err(Error::NotARow("`form.lead` is not a string".into())),
    }

    let mut placed: Vec<&str> = Vec::new();
    let mut rest = rest.iter();
    for line in lines {
        let key = text_of(line, "key")?;
        let pad = text_of(line, "pad")?;
        let tail = text_of(line, "tail")?;
        let value = match named(key) {
            Some((field, list)) if !placed.contains(&field) => {
                placed.push(field);
                match row.get(field) {
                    Some(Value::String(s)) if !list => s.clone(),
                    Some(Value::Array(items)) if list => items
                        .iter()
                        .map(|i| i.as_str().ok_or_else(|| Error::NotARow(format!("`{field}` holds a non-string"))))
                        .collect::<Result<Vec<_>, _>>()?
                        .join(", "),
                    _ => return Err(Error::NotARow(format!("`form` places `{key}` and `{field}` is not set"))),
                }
            }
            _ => {
                let entry = rest
                    .next()
                    .ok_or_else(|| Error::NotARow(format!("`form` places `{key}` and `header_rest` has run out")))?;
                if text_of(entry, "key")? != key {
                    return Err(Error::NotARow(format!("`header_rest` is out of order at `{key}`")));
                }
                text_of(entry, "value")?.to_owned()
            }
        };
        out.push_str("**");
        out.push_str(key);
        out.push_str(":**");
        out.push_str(pad);
        out.push_str(&value);
        out.push_str(tail);
        out.push('\n');
    }
    if rest.next().is_some() {
        return Err(Error::NotARow("`header_rest` holds a line `form` does not place".into()));
    }
    for (_, field, _) in NAMED {
        if !placed.contains(field) && row.get(*field).is_some_and(|v| !v.is_null()) {
            return Err(Error::NotARow(format!("`{field}` is set and `form` gives it no line")));
        }
    }
    out.push_str(body);
    Ok((name.to_owned(), out))
}

/// The fields a row has, without the ones a store adds when it answers (`_id`, `_root`).
///
/// What an import compares, so that asking for a row and writing the same row back is seen
/// as the no-op it is.
pub fn content(row: &Value) -> Value {
    match row {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(k, _)| !k.starts_with('_'))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(name: &str, text: &str) {
        let row = to_row(name, text).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (back_name, back) = to_file(&row).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(back_name, name);
        assert_eq!(back, text, "{name} did not come back byte for byte");
    }

    #[test]
    fn a_plain_record_round_trips_and_reads_as_the_board_reads_it() {
        let text = "# A thing\n\n**Status:**    open \\\n**Region:**    core, client \\\n**Power:**     legislative \\\n**Updated:**   2026-09-23\n\nBody.\n";
        let row = to_row("TASK-a-thing", text).unwrap();
        assert_eq!(row["kind"], "task");
        assert_eq!(row["title"], "A thing");
        assert_eq!(row["status"], "open");
        assert_eq!(row["region"], json!(["core", "client"]));
        assert_eq!(row["header_rest"], json!([{ "key": "Power", "value": "legislative" }]));
        assert_eq!(row["body"], "\nBody.\n");
        assert!(row.get("security").is_none(), "an absent field is absent, not empty");
        round("TASK-a-thing", text);
    }

    /// The board reads `Updated:` from the second run, so a row holding the first run's
    /// silence would disagree with it. Refused, not guessed.
    #[test]
    fn a_named_field_outside_the_header_block_is_refused() {
        let text = "# R\n\n**Status:** open \\\n**Built:** none\n\n**Updated:** 2026-09-07\n\nbody\n";
        assert_eq!(to_row("RFC-0001-r", text), Err(Error::FieldOutsideHeader("Updated".into())));
        // An unnamed key down there is body, and nobody's field.
        let text = "# R\n\n**Status:** open\n\n**Decision:** later\n";
        round("DEC-0001-r", text);
    }

    /// Export writes `<name>.md` into a directory, and a row can come from another member of
    /// the root, so a name that is a path is refused in both directions.
    #[test]
    fn a_name_that_is_a_path_is_never_a_file() {
        let text = "# T\n\n**Status:** open\n\nb\n";
        for bad in ["../escape", "a/b", "", ".hidden", "x\\y"] {
            assert_eq!(to_row(bad, text), Err(Error::BadName(bad.into())), "{bad}");
        }
        let mut row = to_row("TASK-fine", text).unwrap();
        row["name"] = json!("../../outside");
        assert_eq!(to_file(&row), Err(Error::BadName("../../outside".into())));
    }

    #[test]
    fn a_row_that_does_not_account_for_its_lines_is_refused() {
        let text = "# T\n\n**Status:** open \\\n**Power:** judicial\n\nb\n";
        let mut row = to_row("TASK-t", text).unwrap();
        row["header_rest"] = json!([]);
        assert!(matches!(to_file(&row), Err(Error::NotARow(_))));
        let mut row = to_row("TASK-t", text).unwrap();
        row["security"] = json!("key custody");
        assert!(matches!(to_file(&row), Err(Error::NotARow(_))), "a value with no line was dropped");
    }

    #[test]
    fn the_shapes_a_file_cannot_have_are_named() {
        assert_eq!(to_row("TASK-x", "# T\n\nno header\n"), Err(Error::NoHeader));
        assert_eq!(to_row("TASK-x", "# T\n\n**Status:** open"), Err(Error::HeaderEndsTheFile));
        assert_eq!(to_row("TASK-x", "preface\n# T\n**Status:** open\n"), Err(Error::OpensWithNeither));
    }
}
