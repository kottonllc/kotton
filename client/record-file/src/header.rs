// SPDX-License-Identifier: AGPL-3.0-or-later
//! The record header, read and written in one place.
//!
//! ## Why this exists
//!
//! 244 records are governed by 26 gates, and the type that models them was private, 3,049
//! lines into a 4,454-line `main.rs`. Reading was already half-shared — `header_field` and
//! `header_field_whole` — but **writing never was**. Every place that mutated a header did it
//! by `push_str` with a hardcoded column:
//!
//! ```text
//! out.push_str(&format!("**Updated:**    {today} \\\n"));
//! ```
//!
//! Four spaces aligns `**Updated:**` to column 16, which is the narrow convention. Records
//! also use column 19. Running `escalate` on a wide record therefore produced a header whose
//! own fields disagreed — reproduced on `RFC-0081` on 2026-08-25, where `Status` stayed at 19
//! and `Blocked-by`, `Decision` and `Updated` arrived at 16.
//!
//! That is a small defect and a large symptom: a header is a *format*, and a format with no
//! single implementation drifts by construction. `DOC-STANDARD` already says as much about
//! the prose — *"a format that is merely documented produces confident wrong answers"*.
//!
//! ## Why it is a crate and not an `xtask` module
//!
//! It was `xtask`'s `record_header` and half of `xtask`'s `record` until 2026-09-23, when
//! `TASK-the-project-records-are-imported-into-a-root` gave the header a second reader: the
//! converter that maps a record file to a row of `sh.kotton.governance.record` and back
//! (RFC-0088 rule 2). The RFC's condition is that the board and the converter **never
//! disagree about a field**, and the only way that holds by construction is one parser. A
//! second copy in the converter would be the thing this module was extracted to end, so the
//! parser moved to where both can reach it and `xtask` reads it from here. It moved with one
//! change: [`kind_of`] learned `ROLE-` and `PAPER-`, so a file carrying either prefix is that
//! kind to the board too, where it had been an `idea` (`DOC-STANDARD`'s Kind table, dated
//! 2026-09-23). No record carries either prefix, which is why the board did not move.
//!
//! ## What is deliberately not here
//!
//! No validation and no field vocabulary: `rfc-check` and `field-check` own "the value must
//! be legal". This module knows **where a header field's value is, and how to put one there
//! without disturbing the rest**; [`crate::row`] knows which fields the schema names.

/// Whether a line is a header field: `**Key:** value`.
pub fn is_field(l: &str) -> bool {
    l.starts_with("**") && l.contains(":**")
}

/// The header block: the first contiguous run of `**Key:**` lines, as a range of line
/// indices into `text.split('\n')`.
///
/// This is the block [`alignment`] has always learned the column from — the definition is
/// that one, stated once so the converter can place a line back where it was. `None` when
/// the text has no field line at all.
pub fn block(lines: &[&str]) -> Option<std::ops::Range<usize>> {
    let start = lines.iter().position(|l| is_field(l))?;
    let len = lines[start..].iter().take_while(|l| is_field(l)).count();
    Some(start..start + len)
}

/// The column a record aligns its header values to, inferred from the header itself.
///
/// Inferred rather than fixed because both conventions are in live use and neither is wrong —
/// what is wrong is a single record using both. The widest field wins: a header aligned to 19
/// has at least one field that needs 19, and narrowing it would be the same defect pointed the
/// other way.
///
/// `None` when there is no header to learn from, which is the caller's cue to leave alignment
/// alone rather than impose one.
pub fn alignment(text: &str) -> Option<usize> {
    // The header is a contiguous run of `**Key:**` lines somewhere after the title, so scan
    // from the first one and stop at the first line that is not. Scanning the whole file
    // instead would let a bold run in the body vote on the header's column.
    text.lines()
        .skip_while(|l| !is_field(l))
        .take_while(|l| is_field(l))
        .filter_map(|l| {
            let end = l.find(":**")? + 3;
            let rest = &l[end..];
            let pad = rest.len() - rest.trim_start().len();
            // A field with no padding at all carries no opinion about the column.
            (pad > 0).then_some(end + pad)
        })
        .max()
}

/// Render one header line at `col`, or with a single space when `col` is `None` or too narrow.
///
/// Never panics on a long key: a field name wider than the record's column gets one space
/// rather than a negative pad. Misalignment is a cosmetic loss; a crash inside a gate is not.
pub fn line(key: &str, value: &str, col: Option<usize>) -> String {
    let head = format!("**{key}:**");
    let pad = col.map(|c| c.saturating_sub(head.len()).max(1)).unwrap_or(1);
    format!("{head}{}{value}", " ".repeat(pad))
}

/// A header line's value, as every reader here takes it: the text after `**Key:**`, trimmed,
/// with the line-continuation backslash removed.
///
/// One function because [`header_field_whole`] and the converter must cut the same bytes.
pub fn value_of(after_key: &str) -> &str {
    after_key.trim().trim_end_matches('\\').trim()
}

/// Read one header field **whole**, for values that are phrases rather than
/// tokens. [`header_field`] takes the first word, which is right for a vocabulary
/// (`accepted`, `partial`) and wrong for anything a human writes as prose —
/// `Security: capability confinement` would silently become `capability`.
pub fn header_field_whole(text: &str, key: &str) -> String {
    let bold = format!("**{key}:**");
    text.lines()
        .find(|l| l.starts_with(&bold))
        .map(|l| value_of(l.trim_start_matches(&bold[..])).to_string())
        .unwrap_or_default()
}

/// Read one `**Key:** value` header field, tolerating the legacy `_Key: value_` form.
pub fn header_field(text: &str, key: &str) -> String {
    let bold = format!("**{key}:**");
    let italic = format!("_{key}:");
    text.lines()
        .find(|l| l.starts_with(&bold) || l.starts_with(&italic))
        .map(|l| {
            l.trim_start_matches(&bold[..])
                .trim_start_matches(&italic[..])
                .trim()
                .trim_end_matches('\\')
                .trim()
                .trim_start_matches(['*', '_'])
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches([',', '.', '_', '*'])
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}

/// A record's kind, from its file stem. **The prefix is the kind** — not a field
/// (`DOC-STANDARD`, "Kind — the filename prefix").
///
/// `ROLE-` and `PAPER-` are the two kinds RFC-0088's schema names beyond the four the
/// record set held. Nothing in that set carried either, so adding them
/// changed no board; anything else is an `idea`, as it always was.
pub fn kind_of(stem: &str) -> &'static str {
    if stem.starts_with("RFC-") {
        "rfc"
    } else if stem.starts_with("DEC-") {
        "dec"
    } else if stem.starts_with("TASK-") {
        "task"
    } else if stem.starts_with("ROLE-") {
        "role"
    } else if stem.starts_with("PAPER-") {
        "paper"
    } else {
        "idea"
    }
}

/// A record's title: its first `# ` heading, wherever it is, or `None`.
///
/// Wherever it is, because six records open with their header and put the heading after it,
/// and the board has always found theirs.
pub fn title_of(text: &str) -> Option<String> {
    text.lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l[2..].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NARROW: &str = "# T\n\n**Status:**     open \\\n**Blocked-by:** nothing \\\n**Updated:**    2026-08-01\n\nbody\n";
    const WIDE: &str = "# T\n\n**Status:**        open \\\n**Blocked-by:**    nothing \\\n**Updated:**       2026-08-01\n\nbody\n";

    #[test]
    fn alignment_is_inferred_from_the_record_not_assumed() {
        assert_eq!(alignment(NARROW), Some(16));
        assert_eq!(alignment(WIDE), Some(19));
        assert_eq!(alignment("# T\n\nno header here\n"), None);
    }

    /// A bold run in the body must not vote on the header's column — the header is the
    /// contiguous run of fields after the title, not every bold line in the file.
    #[test]
    fn the_body_does_not_vote_on_alignment() {
        let doc = format!("{NARROW}\n**Note:**                        a bold body line\n");
        assert_eq!(alignment(&doc), Some(16));
    }

    /// The defect this module exists for. Reproduced on `RFC-0081` 2026-08-25: `escalate`
    /// wrote column 16 into a column-19 record, leaving a header disagreeing with itself.
    #[test]
    fn a_line_is_rendered_at_the_records_own_column() {
        assert_eq!(line("Updated", "2026-08-25", Some(16)), "**Updated:**    2026-08-25");
        assert_eq!(line("Updated", "2026-08-25", Some(19)), "**Updated:**       2026-08-25");
        assert_eq!(line("Blocked-by", "owner", Some(19)), "**Blocked-by:**    owner");
    }

    /// A key wider than the record's column must not produce a negative pad. Misalignment is
    /// cosmetic; a panic inside a gate stops every branch.
    #[test]
    fn an_overlong_key_does_not_panic() {
        assert_eq!(line("AVeryLongFieldNameIndeed", "v", Some(4)), "**AVeryLongFieldNameIndeed:** v");
        assert_eq!(line("Status", "v", None), "**Status:** v");
    }

    /// The block is the run [`alignment`] reads, and nothing after its first gap.
    #[test]
    fn the_block_is_the_first_run_of_field_lines() {
        let lines: Vec<&str> = NARROW.split('\n').collect();
        assert_eq!(block(&lines), Some(2..5));
        let lines: Vec<&str> = "no header\n".split('\n').collect();
        assert_eq!(block(&lines), None);
    }

    /// The whole value and the first word are two readings of one line, and both skip the
    /// continuation backslash.
    #[test]
    fn a_field_is_read_whole_or_by_its_first_word() {
        let t = "# T\n\n**Status:**   superseded (2026-08-18, collapsed) \\\n**Built:** n/a\n";
        assert_eq!(header_field_whole(t, "Status"), "superseded (2026-08-18, collapsed)");
        assert_eq!(header_field(t, "Status"), "superseded");
        assert_eq!(header_field_whole(t, "Built"), "n/a");
        assert_eq!(header_field_whole(t, "Absent"), "");
    }

    #[test]
    fn the_prefix_is_the_kind() {
        assert_eq!(kind_of("RFC-0088-x"), "rfc");
        assert_eq!(kind_of("DEC-0080-x"), "dec");
        assert_eq!(kind_of("TASK-x"), "task");
        assert_eq!(kind_of("IDEA-x"), "idea");
        assert_eq!(kind_of("ROLE-x"), "role");
        assert_eq!(kind_of("PAPER-x"), "paper");
        assert_eq!(kind_of("anything-else"), "idea");
    }
}
