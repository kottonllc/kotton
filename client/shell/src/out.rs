// SPDX-License-Identifier: AGPL-3.0-or-later
//! The output shape language (terminal UX Pillar 3).
//!
//! Commands emit **meaning, not strings**: a small closed vocabulary of shapes.
//! The renderer — the only place that knows how anything looks — turns them into
//! styled terminal output. A command *cannot* look off-brand because it never
//! chooses how it looks; restyling is one edit here, and `--json` is one match.
//!
//! Two channels:
//! - **messages** — styled by the renderer; on a non-TTY they reroute to stderr and
//!   drop color, so `cmd | grep` stays POSIX-honest.
//! - **payloads** (`Data`/`Reveal`) — verbatim; never wrapped, colored, or
//!   re-flowed. `Data` is the only shape a pipe consumes.
//!
//! The enum is **closed** on purpose: a command whose output "doesn't fit" ten
//! shapes triggers a design conversation, not a new `println!`.

use crate::ui;
use colored::Colorize;
use serde::Serialize;
use std::io::IsTerminal;

/// A single unit of command output. Emit these; never `println!`.
///
/// `Serialize` gives `--json` for free (externally-tagged, snake_case): a command's
/// `Vec<Out>` becomes a JSON array like `[{"table":{"columns":[…],"rows":[…]}}]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Out {
    // ── messages (styled; reroute to stderr / strip color off-TTY) ──────────────
    /// A completed action: `synced 3 files → node-b`.
    Confirm { action: String, subject: String },
    /// Aligned label/value pairs: `whoami`, `device show`, `net status`.
    Record(Vec<(String, String)>),
    /// A table; zero rows renders one dim "none yet" line.
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// Wrapped prose.
    Note(String),
    /// A dim next-step line: `try: …`.
    Hint(String),
    /// Proceeds anyway, but names the consequence.
    Warn { what: String, consequence: String },
    /// Transient status (`connecting…`).
    Progress(String),
    /// A failure, with an optional next step.
    Fail { what: String, try_: Option<String> },

    // ── payloads (verbatim; the only shapes on stdout in a pipe) ────────────────
    /// File/pipe content: `cat`, `grep`, `ls`, `echo`, `wc`. Never styled or wrapped.
    Data(String),
    /// Security display — recovery words, the SAS digits, pairing codes. Shown
    /// verbatim so a line break never corrupts it.
    Reveal(String),
}

impl Out {
    /// Payloads (`Data`/`Reveal`) are verbatim and always go to stdout — the only
    /// shapes a pipe consumes. Everything else is a message.
    fn is_payload(&self) -> bool {
        matches!(self, Out::Data(_) | Out::Reveal(_))
    }
}

/// Render one shape to a styled string (no trailing newline). Pure — the IO and
/// stream routing live in [`render`], so this is unit-testable.
pub fn render_shape(out: &Out) -> String {
    match out {
        Out::Confirm { action, subject } => {
            if subject.is_empty() {
                format!("{}{action}", ui::MARGIN)
            } else {
                format!(
                    "{}{action} {} {}",
                    ui::MARGIN,
                    "→".dimmed(),
                    ui::notable(subject)
                )
            }
        }
        Out::Record(pairs) => {
            let width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            pairs
                .iter()
                .map(|(k, v)| {
                    let label = format!("{k:width$}");
                    format!("{}{}  {v}", ui::ROW_MARGIN, label.dimmed())
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        Out::Table { columns, rows } => render_table(columns, rows),
        Out::Note(text) => ui::wrap(text)
            .into_iter()
            .map(|line| format!("{}{}", ui::MARGIN, line.bold()))
            .collect::<Vec<_>>()
            .join("\n"),
        Out::Hint(text) => format!("{}{}", ui::ROW_MARGIN, text.dimmed()),
        Out::Warn { what, consequence } => {
            format!("{}{what} {}", ui::MARGIN, format!("({consequence})").dimmed())
        }
        Out::Progress(text) => format!("{}{}", ui::MARGIN, text.dimmed()),
        Out::Fail { what, try_ } => {
            let head = format!("{}{} {what}", ui::MARGIN, "error:".red());
            match try_ {
                Some(t) => format!("{head}\n{}{}", ui::ROW_MARGIN, format!("try: {t}").dimmed()),
                None => head,
            }
        }
        // Payloads: verbatim.
        Out::Data(text) => text.clone(),
        Out::Reveal(text) => format!("{}{}", ui::ROW_MARGIN, text.bold()),
    }
}

/// Render a table: dim lowercase heads, aligned columns, no borders. Zero rows →
/// one dim "none yet" line (empty states are a renderer rule, not each command's).
///
/// Columns take their natural width, then — if the row would overflow the terminal —
/// the widest columns are shrunk (never below [`MIN_COL`]) and their cells truncated
/// with `…`, so a table always fits its terminal instead of wrapping into mush.
fn render_table(columns: &[String], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return format!("{}{}", ui::ROW_MARGIN, "none yet".dimmed());
    }
    /// A column never shrinks below this — narrower than this and a cell is noise.
    const MIN_COL: usize = 6;
    let cols = columns.len();

    // Natural widths from headers + cells.
    let mut widths = vec![0usize; cols];
    for (i, c) in columns.iter().enumerate() {
        widths[i] = c.chars().count();
    }
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    // Fit to the terminal: shrink the widest shrinkable column, one column at a time,
    // until the row (cells + two-space separators, after the row margin) fits.
    let budget = ui::term_width()
        .saturating_sub(ui::ROW_MARGIN.len())
        .saturating_sub(2 * cols.saturating_sub(1));
    while widths.iter().sum::<usize>() > budget {
        let Some(i) = widths
            .iter()
            .enumerate()
            .filter(|(_, w)| **w > MIN_COL)
            .max_by_key(|(_, w)| **w)
            .map(|(i, _)| i)
        else {
            break; // every column already at the floor; let it overflow gracefully
        };
        widths[i] -= 1;
    }

    let format_row = |cells: &mut dyn Iterator<Item = String>| {
        let line = cells
            .enumerate()
            .map(|(i, cell)| format!("{:width$}", truncate(&cell, widths[i]), width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ");
        format!("{}{}", ui::ROW_MARGIN, line.trim_end())
    };

    let mut lines = Vec::new();
    lines.push(
        format_row(&mut columns.iter().map(|c| c.to_lowercase()))
            .dimmed()
            .to_string(),
    );
    for row in rows {
        lines.push(format_row(&mut row.iter().take(cols).cloned()));
    }
    lines.join("\n")
}

/// Truncate `s` to `width` display columns, marking the cut with a trailing `…`.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let kept: String = s.chars().take(width - 1).collect();
    format!("{kept}…")
}

/// Render a sequence of shapes to the terminal. Payloads print verbatim to stdout
/// (the pipe channel); messages print styled — to stdout on a TTY, to stderr
/// otherwise, so only `Data`/`Reveal` flow through a pipe. Color auto-strips
/// off-TTY / under `NO_COLOR` via the `colored` crate.
pub fn render(outs: &[Out], actor: Option<&str>) {
    let tty = std::io::stdout().is_terminal();
    for out in outs {
        let mut text = render_shape(out);
        // Actor echo (Pillar 1): trail a state-changing result with who acted, in the
        // dim tier — `synced 3 files → node-b · as austin`. Passed by the CLI (a
        // one-shot with no persistent prompt); the REPL passes None because its
        // identity-first prompt already shows the actor.
        if let (Out::Confirm { .. }, Some(a)) = (out, actor) {
            text.push_str(&format!(" {}", format!("· as {a}").dimmed()));
        }
        if out.is_payload() || tty {
            println!("{text}");
        } else {
            eprintln!("{text}");
        }
    }
}

/// Render the shapes as a JSON array to stdout (the `--json` path). The human
/// output never serves two masters: the same `Out` a person sees is what a script
/// parses. Falls back to `render` if serialization somehow fails.
pub fn render_json(outs: &[Out]) {
    match serde_json::to_string_pretty(outs) {
        Ok(json) => println!("{json}"),
        Err(_) => render(outs, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_are_data_and_reveal_only() {
        assert!(Out::Data("x".into()).is_payload());
        assert!(Out::Reveal("472 913".into()).is_payload());
        assert!(!Out::Note("x".into()).is_payload());
        assert!(!Out::Confirm {
            action: "synced".into(),
            subject: "node-b".into()
        }
        .is_payload());
    }

    #[test]
    fn data_is_verbatim() {
        // A pipe payload must pass through untouched — no margin, no styling.
        assert_eq!(render_shape(&Out::Data("a\tb".into())), "a\tb");
    }

    #[test]
    fn empty_table_is_a_single_none_line() {
        let out = Out::Table {
            columns: vec!["name".into()],
            rows: vec![],
        };
        let s = render_shape(&out);
        assert!(s.contains("none yet"));
        assert_eq!(s.lines().count(), 1);
    }

    #[test]
    fn table_aligns_and_lowercases_heads() {
        // colored strips ANSI when not a TTY (tests run non-TTY), so we can assert
        // on the plain text.
        let out = Out::Table {
            columns: vec!["Name".into(), "State".into()],
            rows: vec![
                vec!["austin".into(), "active".into()],
                vec!["bob".into(), "idle".into()],
            ],
        };
        let s = render_shape(&out);
        assert!(s.contains("name"), "heads lowercased");
        // Aligned: the header and rows share the same column start.
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("austin"));
    }

    #[test]
    fn json_is_externally_tagged_snake_case() {
        // --json: a person's Out and a script's JSON are the same source.
        let confirm = serde_json::to_string(&Out::Confirm {
            action: "synced".into(),
            subject: "node-b".into(),
        })
        .unwrap();
        assert_eq!(confirm, r#"{"confirm":{"action":"synced","subject":"node-b"}}"#);
        let note = serde_json::to_string(&Out::Note("hi".into())).unwrap();
        assert_eq!(note, r#"{"note":"hi"}"#);
        let table = serde_json::to_string(&Out::Table {
            columns: vec!["a".into()],
            rows: vec![vec!["1".into()]],
        })
        .unwrap();
        assert_eq!(table, r#"{"table":{"columns":["a"],"rows":[["1"]]}}"#);
    }

    #[test]
    fn truncate_marks_the_cut_with_ellipsis() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly-ten", 11), "exactly-ten");
        assert_eq!(truncate("did:key:abcdef", 10), "did:key:a…");
        assert_eq!(truncate("abc", 1), "…");
    }

    #[test]
    fn wide_table_never_exceeds_a_narrow_terminal() {
        // A 64-char DID must not blow the row past the terminal; it truncates instead.
        let wide = "did:key:9646e10858a341718ce233bc5bda1bb4fa90e363aa801755c519b0f72454350f";
        let out = Out::Table {
            columns: vec!["device".into(), "did".into()],
            rows: vec![vec!["nicoles-macbook-air.local".into(), wide.into()]],
        };
        let s = render_shape(&out);
        // No rendered line (margin + cells) should exceed a conservative terminal.
        for line in s.lines() {
            assert!(
                line.chars().count() <= ui::term_width().max(80),
                "line overflows terminal: {line:?}"
            );
        }
    }

    #[test]
    fn fail_with_try_has_two_lines() {
        let out = Out::Fail {
            what: "no active identity".into(),
            try_: Some("id use <name>".into()),
        };
        let s = render_shape(&out);
        assert_eq!(s.lines().count(), 2);
        assert!(s.contains("try: id use <name>"));
    }
}
