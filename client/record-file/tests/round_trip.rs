// SPDX-License-Identifier: AGPL-3.0-or-later
//! The converter against files, not strings: the ten-record fixture, and every record the
//! repository holds (RFC-0088 rule 2 — the markdown file is the wire format).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kotton_record_file::row::{to_file, to_row, NAMED};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/records")
}

/// Every `*.md` file in `dir`, as `(stem, text)`, in name order.
fn records_in(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .map(|p| {
            let stem = p.file_stem().unwrap().to_str().unwrap().to_owned();
            (stem, std::fs::read_to_string(&p).unwrap())
        })
        .collect();
    out.sort();
    out
}

/// **The fixture: ten records, every kind, every named field, every shape a real record
/// has — imported to rows, exported, and compared byte for byte.**
///
/// The shapes are the ones the project's own record set held: a lead that
/// is not one blank line (71 records), a header before the title (6), a continuation mark on
/// the last header line (22), a middle line without one (1), an empty value ending in a bare
/// backslash (2), no final newline (6), two final newlines (29), and a second run of fields
/// after a blank line that names nothing the schema does.
#[test]
fn ten_fixture_records_come_back_byte_for_byte() {
    let files = records_in(&fixture_dir());
    assert_eq!(files.len(), 10, "the fixture is ten records");

    let mut kinds = BTreeSet::new();
    let mut fields = BTreeSet::new();
    let (mut with_lead, mut header_first, mut with_rest) = (false, false, false);
    for (name, text) in &files {
        let row = to_row(name, text).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (back_name, back) = to_file(&row).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(&back_name, name);
        assert_eq!(back.as_bytes(), text.as_bytes(), "{name} did not come back byte for byte");

        kinds.insert(row["kind"].as_str().unwrap().to_owned());
        for (_, field, _) in NAMED {
            if row.get(*field).is_some() {
                fields.insert(*field);
            }
        }
        match row["form"].get("lead") {
            Some(_) => with_lead = true,
            None => header_first = true,
        }
        with_rest |= !row["header_rest"].as_array().unwrap().is_empty();
    }
    assert_eq!(
        kinds,
        ["dec", "idea", "paper", "rfc", "role", "task"].map(String::from).into(),
        "every kind"
    );
    assert_eq!(fields.len(), NAMED.len(), "every named field, in some record: {fields:?}");
    assert!(with_lead && header_first && with_rest);

    // One record carries all twelve at once, so a field's line among the others is exercised.
    let every = to_row(
        "TASK-a-fixture-task-carrying-every-named-field",
        &files.iter().find(|(n, _)| n.contains("every-named-field")).unwrap().1,
    )
    .unwrap();
    for (_, field, _) in NAMED {
        assert!(every.get(*field).is_some(), "the every-field fixture lacks `{field}`");
    }
}
