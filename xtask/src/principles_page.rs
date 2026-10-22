// SPDX-License-Identifier: AGPL-3.0-or-later
//! The principles page's table, as `constitution-check` reads it.
//!
//! `docs/design/principles.md` says which principles a build check holds: a row whose State
//! cell is `enforced`. `constitution-check` runs its inspections from a table of its own, each
//! paired with the number of the principle it stands for. This module reads the page's table
//! and compares the two sets, so a principle the page marks enforced with no inspection behind
//! it, or an inspection for a principle the page does not mark, refuses the gate instead of
//! passing unseen.
//!
//! The reader is exact about the table's shape and refuses a row it cannot read, naming the
//! line. It never skips one: a skipped row is a principle that silently left the comparison.
//! So the table runs from its delimiter to the first blank line, every line in that run is a
//! row starting at column one or is refused (an indented row, or text GFM would render as a
//! row), and a line shaped like a row anywhere after that blank line is refused too.

/// The page, relative to the repository root.
pub const PAGE: &str = "docs/design/principles.md";

/// The table's header and delimiter rows, exactly as the page writes them.
const HEADER: &str = "| № | Principle | What it means | Held by | State |";
const DELIMITER: &str = "| --- | --- | --- | --- | --- |";
const CELLS: usize = 5;

/// The one State the check reads as "a build check holds this".
const ENFORCED: &str = "enforced";

/// One row of the page's table.
#[derive(Debug, PartialEq, Eq)]
pub struct Principle {
    /// Its number, a Roman numeral as the page writes it.
    pub number: String,
    /// Its name, without the bold markers.
    pub name: String,
    /// Its State cell, verbatim.
    pub state: String,
    /// Whether the State cell is exactly `enforced`.
    pub enforced: bool,
}

/// Reads every row of the page's principles table, in order.
///
/// Refuses, naming the line, when the header is missing or appears twice, when the delimiter
/// row does not follow it, when a line between the delimiter and the first blank line is not a
/// row starting at column one, when a line shaped like a row follows that blank line, or when
/// a row is not five cells, is not numbered next in order, has a name that is not one bold run,
/// or has a State that begins with `enforced` without being exactly that.
pub fn read(page: &str) -> Result<Vec<Principle>, String> {
    let lines: Vec<&str> = page.lines().collect();
    let headers: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim_end() == HEADER)
        .map(|(i, _)| i)
        .collect();
    let header = match headers.as_slice() {
        [one] => *one,
        [] => return Err(format!("no line is the principles table's header `{HEADER}`")),
        [first, second, ..] => {
            return Err(format!(
                "the principles table's header appears more than once (lines {} and {})",
                first + 1,
                second + 1
            ))
        }
    };
    match lines.get(header + 1) {
        Some(l) if l.trim_end() == DELIMITER => {}
        other => {
            return Err(format!(
                "line {}: expected the table's delimiter row `{DELIMITER}` under its header, \
                 found `{}`",
                header + 2,
                other.unwrap_or(&"")
            ))
        }
    }

    // The rows: every line from the delimiter down to the first blank one. GFM reads any
    // non-blank line directly under a row as one more row, so each such line is read as a row
    // or refused; none ends the table quietly.
    let mut principles = Vec::new();
    let mut end = lines.len();
    for (i, line) in lines.iter().enumerate().skip(header + 2) {
        let lineno = i + 1;
        let row = line.trim_end();
        if row.trim_start().is_empty() {
            end = i;
            break;
        }
        if !row.starts_with('|') {
            return Err(if row.trim_start().starts_with('|') {
                format!(
                    "line {lineno}: the row `{row}` is indented; a row of the principles \
                     table starts at column one"
                )
            } else {
                format!(
                    "line {lineno}: `{row}` sits directly under the principles table's rows, \
                     so it renders as one more row; end the table with a blank line"
                )
            });
        }
        principles.push(read_row(row, principles.len() + 1).map_err(|why| {
            format!("line {lineno}: cannot read the row `{row}`: {why}")
        })?);
    }
    // After the table, a line shaped like a row is a principle the page may show and this
    // reader would not count.
    for (i, line) in lines.iter().enumerate().skip(end) {
        if line.trim_start().starts_with('|') {
            return Err(format!(
                "line {}: `{}` is shaped like a row of the principles table, after the \
                 blank line that ends it at line {}; every row sits in the one table, with no \
                 blank line between rows",
                i + 1,
                line.trim_end(),
                end + 1
            ));
        }
    }
    if principles.is_empty() {
        return Err(format!(
            "line {}: the principles table has a header and no rows",
            header + 3
        ));
    }
    Ok(principles)
}

/// Reads one row, which must be the `ordinal`-th.
fn read_row(row: &str, ordinal: usize) -> Result<Principle, String> {
    let inner = row
        .strip_prefix('|')
        .and_then(|r| r.strip_suffix('|'))
        .ok_or("a row begins and ends with `|`")?;
    let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
    if cells.len() != CELLS {
        return Err(format!("expected {CELLS} cells, found {}", cells.len()));
    }
    let (number, name, state) = (cells[0], cells[1], cells[4]);

    let expected = roman(ordinal);
    if number != expected {
        return Err(format!(
            "its number is `{number}`, and the row in this place is numbered `{expected}`"
        ));
    }
    let name = name
        .strip_prefix("**")
        .and_then(|n| n.strip_suffix("**"))
        .filter(|n| !n.is_empty() && !n.contains('*'))
        .ok_or_else(|| format!("its name `{name}` is not one bold run `**Name**`"))?;

    let enforced = state == ENFORCED;
    if !enforced
        && state
            .replace('*', "")
            .to_lowercase()
            .starts_with(ENFORCED)
    {
        return Err(format!(
            "its State `{state}` begins with `{ENFORCED}` and is not exactly `{ENFORCED}`, \
             so whether a build check holds it cannot be read"
        ));
    }
    Ok(Principle {
        number: number.to_string(),
        name: name.to_string(),
        state: state.to_string(),
        enforced,
    })
}

/// `n` in Roman numerals, for the table's numbering (1 to 3999).
fn roman(mut n: usize) -> String {
    const DIGITS: [(usize, &str); 13] = [
        (1000, "M"),
        (900, "CM"),
        (500, "D"),
        (400, "CD"),
        (100, "C"),
        (90, "XC"),
        (50, "L"),
        (40, "XL"),
        (10, "X"),
        (9, "IX"),
        (5, "V"),
        (4, "IV"),
        (1, "I"),
    ];
    let mut out = String::new();
    for (value, digits) in DIGITS {
        while n >= value {
            out.push_str(digits);
            n -= value;
        }
    }
    out
}

/// Where the page and the check's inspections disagree, one line per principle: each the page
/// marks enforced that nothing inspects, then each inspected that the page does not mark
/// enforced or does not have. Empty when they agree.
pub fn drift(page: &[Principle], inspected: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for p in page.iter().filter(|p| p.enforced) {
        if !inspected.contains(&p.number.as_str()) {
            found.push(format!(
                "Principle {} ({}): {PAGE} marks it enforced, and constitution-check has no \
                 inspection for it. Write the inspection, or set its State on the page to \
                 what does hold it.",
                p.number, p.name
            ));
        }
    }
    let mut seen: Vec<&str> = Vec::new();
    for &number in inspected {
        if seen.contains(&number) {
            continue;
        }
        seen.push(number);
        match page.iter().find(|p| p.number == number) {
            Some(p) if p.enforced => {}
            Some(p) => found.push(format!(
                "Principle {} ({}): constitution-check inspects it, and {PAGE} does not mark \
                 it enforced (its State is `{}`). Mark it enforced on the page if the \
                 inspection holds it, or retire the inspection.",
                p.number, p.name, p.state
            )),
            None => found.push(format!(
                "Principle {number}: constitution-check inspects it, and {PAGE} has no \
                 principle numbered {number}."
            )),
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page whose table holds `rows`, with prose either side as the real page has.
    fn page(rows: &[&str]) -> String {
        format!(
            "# Principles\n\nProse above the table.\n\n{HEADER}\n{DELIMITER}\n{}\n\nProse below.\n",
            rows.join("\n")
        )
    }

    const I: &str = "| I | **Ownership is structural** | m | h | design holds |";
    const II: &str = "| II | **The node is the root of trust** | m | h | enforced |";
    const III: &str = "| III | **Identity is self-sovereign** | m | h | enforced |";
    const III_LABELLED: &str = "| III | **Identity is self-sovereign** | m | h | labelled |";

    fn enforced(principles: &[Principle]) -> Vec<&str> {
        principles
            .iter()
            .filter(|p| p.enforced)
            .map(|p| p.number.as_str())
            .collect()
    }

    #[test]
    fn a_page_that_agrees_with_the_inspections_has_no_drift() {
        let read = read(&page(&[I, II, III])).expect("the fixture reads");
        assert_eq!(enforced(&read), vec!["II", "III"]);
        assert_eq!(drift(&read, &["II", "II", "III"]), Vec::<String>::new());
    }

    #[test]
    fn a_principle_marked_enforced_with_no_inspection_is_refused_naming_it() {
        let read = read(&page(&[I, II, III])).expect("the fixture reads");
        let found = drift(&read, &["II"]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("Principle III (Identity is self-sovereign): ")
                && found[0].contains("marks it enforced, and constitution-check has no inspection"),
            "{found:?}"
        );
    }

    #[test]
    fn an_inspected_principle_the_page_does_not_mark_enforced_is_refused_naming_it() {
        let read = read(&page(&[I, II, III_LABELLED])).expect("the fixture reads");
        let found = drift(&read, &["II", "III"]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("Principle III (Identity is self-sovereign): ")
                && found[0].contains("does not mark it enforced (its State is `labelled`)"),
            "{found:?}"
        );
    }

    #[test]
    fn an_inspected_principle_the_page_does_not_have_is_refused_naming_it() {
        let read = read(&page(&[I, II])).expect("the fixture reads");
        let found = drift(&read, &["II", "XIV"]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("Principle XIV: "), "{found:?}");
    }

    /// Every row the reader cannot read refuses the page, naming the row; none is skipped.
    #[test]
    fn a_row_the_reader_cannot_read_is_refused_naming_the_row() {
        let unreadable = [
            // A cell short.
            ("| II | **The node is the root of trust** | m | enforced |", "expected 5 cells, found 4"),
            // A pipe inside a cell is a sixth cell, not text.
            ("| II | **The node is the root of trust** | a | b | c | enforced |", "expected 5 cells, found 6"),
            // Numbered out of order.
            ("| IV | **Access is explicit and revocable** | m | h | enforced |", "numbered `II`"),
            // A name that is not one bold run.
            ("| II | The node is the root of trust | m | h | enforced |", "is not one bold run"),
            // A State that reads as enforced and is not exactly that.
            ("| II | **The node is the root of trust** | m | h | Enforced |", "begins with `enforced`"),
            ("| II | **The node is the root of trust** | m | h | enforced; partly |", "begins with `enforced`"),
            ("| II | **The node is the root of trust** | m | h | **enforced** |", "begins with `enforced`"),
            // Not closed by a pipe.
            ("| II | **The node is the root of trust** | m | h | enforced", "begins and ends with `|`"),
        ];
        for (row, why) in unreadable {
            let err = read(&page(&[I, row])).expect_err(row);
            assert!(
                err.contains(&format!("cannot read the row `{row}`")) && err.contains(why),
                "for {row}: {err}"
            );
            assert!(err.starts_with("line 8: "), "the row is the page's eighth line: {err}");
        }
    }

    /// GFM renders an indented row as part of the table; the reader refuses it rather than
    /// stopping above it and leaving the rows under it uncounted.
    #[test]
    fn an_indented_row_is_refused_naming_the_line() {
        let indented = "  | II | **The node is the root of trust** | m | h | labelled |";
        let err = read(&page(&[I, indented, III])).unwrap_err();
        assert!(
            err.starts_with("line 8: ") && err.contains("is indented") && err.contains("column one"),
            "{err}"
        );
    }

    /// A row after a blank line is outside the table, and is refused rather than ignored.
    #[test]
    fn a_row_after_the_blank_line_that_ends_the_table_is_refused_naming_the_line() {
        let err = read(&page(&[I, "", III])).unwrap_err();
        assert!(
            err.starts_with("line 9: ") && err.contains("after the blank line that ends it at line 8"),
            "{err}"
        );
        let indented_later = page(&[I, II, "", "Prose.", "", "   | III | **x** | m | h | enforced |"]);
        assert!(read(&indented_later).unwrap_err().starts_with("line 12: "));
    }

    /// Text directly under the rows renders as one more row in GFM, so it is refused too.
    #[test]
    fn text_directly_under_the_rows_is_refused_naming_the_line() {
        let err = read(&page(&[I, "Not a row."])).unwrap_err();
        assert!(
            err.starts_with("line 8: ") && err.contains("end the table with a blank line"),
            "{err}"
        );
    }

    #[test]
    fn a_table_whose_shape_is_not_the_expected_one_is_refused() {
        let no_header = "# Principles\n\n| № | Principle | State |\n| --- | --- | --- |\n| I | **x** | enforced |\n";
        assert!(read(no_header).unwrap_err().starts_with("no line is the principles table's header"));

        let twice = format!("{}\n{}", page(&[I]), page(&[I]));
        assert!(read(&twice).unwrap_err().contains("appears more than once"));

        let no_delimiter = format!("{HEADER}\n{I}\n");
        let err = read(&no_delimiter).unwrap_err();
        assert!(err.starts_with("line 2: expected the table's delimiter row"), "{err}");

        let no_rows = format!("{HEADER}\n{DELIMITER}\n\nProse.\n");
        assert!(read(&no_rows).unwrap_err().contains("has a header and no rows"));
    }

    /// The page the gate reads parses whole, and marks enforced exactly the principles the
    /// check's inspections stand for.
    #[test]
    fn the_real_page_parses_to_the_real_set() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask crate has a parent workspace dir");
        let text = std::fs::read_to_string(root.join(PAGE)).expect("the principles page reads");
        let principles = read(&text).unwrap_or_else(|e| panic!("{PAGE}: {e}"));
        assert_eq!(principles.len(), 13, "the page states thirteen principles");
        assert_eq!(principles[12].number, "XIII");
        let inspected: Vec<&str> = crate::INSPECTIONS.iter().map(|i| i.principle).collect();
        assert_eq!(drift(&principles, &inspected), Vec::<String>::new());
    }

    #[test]
    fn numerals_are_the_tables_numbering() {
        let got: Vec<String> = (1..=14).map(roman).collect();
        assert_eq!(
            got,
            ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII", "XIII", "XIV"]
        );
    }
}
