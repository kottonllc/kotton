// SPDX-License-Identifier: AGPL-3.0-or-later
//! Presentation layer for the terminal runtime.
//!
//! Owns **all** display concerns — indentation, the content-column width (with
//! wrapping), the input affordance, and the color tiers — so content stays
//! semantic. Callers pass plain text and never embed leading spaces, a `$`, or
//! manual line breaks; if a message is long, [`body`] wraps it. Section spacing is
//! composed by the caller via [`blank`]. This is why a prompt string is just its
//! question — the renderer, not the content, decides how it looks.
//! (TERMINAL-RUNTIME-PIVOT.)
//!
//! **What a wrapped line keeps** (kottonllc/kotton#597, 56B and 57A;
//! kottonllc/kotton#654). [`wrap`], which [`body`] and `Out::Note` print through,
//! re-flows a line by its words, and keeps whole what is between a line's
//! delimiters ([`DELIMITERS`]): a name as [`kotton_wire::note::quoted`] prints it,
//! and a command to type. Every character between a delimiter and its close is
//! written as handed, and no line break is written between them; a span with no
//! close holds the rest of its line. A span that does not fit what is left of a line
//! starts the next, and a line wider than the column is written whole and left for
//! the terminal to fold. Words outside a span re-flow as before, and no word changes.

use colored::{ColoredString, Colorize};

/// Left margin for top-level lines (header, body, prompts).
pub(crate) const MARGIN: &str = "  ";
/// Left margin for the indented detail block (rows, hints, literals).
pub(crate) const ROW_MARGIN: &str = "    ";
/// Maximum content column width. Prose never sprawls wider than this even on a
/// very wide terminal (long measures hurt readability); a narrower terminal wraps
/// to its own width instead. The margin is added on top of the content column.
pub(crate) const WIDTH_MAX: usize = 72;
/// Minimum content column width: a terminal narrower than this still wraps prose to
/// this measure, and the terminal folds what is wider than itself.
pub(crate) const WIDTH_MIN: usize = 24;
/// The characters that open a span [`wrap`] keeps whole, each closed by itself: the
/// backtick, around a name by [`kotton_wire::note::quoted`] and around a command to
/// type. A delimiter a name moves to is added here and nowhere else in the renderer.
pub(crate) const DELIMITERS: &[char] = &['`'];
/// Column where a row's value begins (so labels of different lengths align).
pub(crate) const LABEL_COL: usize = 6;

/// The terminal's column count, or a sane default when there is no terminal
/// (output piped or redirected). Never returns an unusably small value.
pub(crate) fn term_width() -> usize {
    crossterm::terminal::size()
        .map(|(cols, _)| cols as usize)
        .unwrap_or(80)
        .max(20)
}

/// The content column for wrapped prose: the terminal width minus the left margin,
/// clamped to [`WIDTH_MAX`] so lines stay a readable measure on wide terminals.
pub(crate) fn content_width() -> usize {
    term_width().saturating_sub(MARGIN.len()).clamp(WIDTH_MIN, WIDTH_MAX)
}

/// Saturated action green — reserved for the next action / input point.
const ACTION: (u8, u8, u8) = (125, 184, 96);
/// Desaturated "notable" green — identity, node, the wordmark.
const NOTABLE: (u8, u8, u8) = (143, 166, 128);

/// Paint text as the action accent. Use only for the input/action point.
pub fn action(s: &str) -> ColoredString {
    s.truecolor(ACTION.0, ACTION.1, ACTION.2)
}

/// Paint text as a notable point of interest (muted green).
pub fn notable(s: &str) -> ColoredString {
    s.truecolor(NOTABLE.0, NOTABLE.1, NOTABLE.2)
}

/// A blank line — the section separator, composed by the caller.
pub fn blank() {
    println!();
}

/// The wordmark + tagline header (notable wordmark, dim tagline).
pub fn header(wordmark: &str, tagline: &str) {
    println!("{MARGIN}{} {}", notable(wordmark), tagline.dimmed());
}

/// Body text — semantic, dim, wrapped to the content width. Pass a whole sentence;
/// the renderer breaks it into lines.
pub fn body(text: &str) {
    for line in wrap(text) {
        println!("{MARGIN}{}", line.dimmed());
    }
}

/// A "<prefix> <name>" line: dim prefix, notable name. For greetings/confirmations
/// where the identity is the point of interest (e.g. "welcome back, austin").
pub fn greet(prefix: &str, name: &str) {
    println!("{MARGIN}{} {}", prefix.dimmed(), notable(name).bold());
}

/// A detail row in the indented block: dim label, caller-colored value, optional
/// dim trailing fragment (e.g. a did). Values align regardless of label length.
pub fn row(label: &str, value: ColoredString, trailing: Option<&str>) {
    let lbl = format!("{label:width$}", width = LABEL_COL);
    match trailing {
        Some(t) => println!("{ROW_MARGIN}{}{value}  {}", lbl.dimmed(), t.dimmed()),
        None => println!("{ROW_MARGIN}{}{value}", lbl.dimmed()),
    }
}

/// A dim hint line at the indented-block margin (e.g. the help/exit line).
pub fn hint(text: &str) {
    println!("{ROW_MARGIN}{}", text.dimmed());
}

/// A menu choice line: a notable key + dim description (e.g. "j  join …").
pub fn option(key: &str, desc: &str) {
    println!("{ROW_MARGIN}{}  {}", notable(key), desc.dimmed());
}

/// A bold, un-wrapped line at the indented-block margin — for content that must be
/// shown verbatim (e.g. the recovery words).
pub fn literal(text: &str) {
    println!("{ROW_MARGIN}{}", text.bold());
}

/// Build an input prompt for `rpassword` / `readline`: margin + the semantic
/// question + the green `$` action affordance. The caller passes only the
/// question — no spaces, no `$`.
pub fn ask(question: &str) -> String {
    format!("{MARGIN}{question} {} ", action("$").bold())
}

/// Redraw a transient countdown bar in place (carriage return, no newline) for a
/// timed wait — e.g. the pairing offer window. The bar drains toward empty as the
/// deadline nears, and shows the remaining `M:SS`. TTY-only: callers guard, since a
/// redrawing bar is noise in a pipe. Pair with [`clear_line`] before the next line.
pub fn countdown(remaining: std::time::Duration, total: std::time::Duration) {
    use std::io::Write;
    const CELLS: usize = 20;
    let frac = if total.is_zero() {
        0.0
    } else {
        (remaining.as_secs_f64() / total.as_secs_f64()).clamp(0.0, 1.0)
    };
    let filled = ((frac * CELLS as f64).ceil() as usize).min(CELLS);
    let bar = notable(&"█".repeat(filled)).to_string() + &"░".repeat(CELLS - filled).dimmed();
    let secs = remaining.as_secs();
    let clock = format!("{}:{:02} left", secs / 60, secs % 60);
    print!("\r{MARGIN}{bar}  {}", clock.dimmed());
    let _ = std::io::stdout().flush();
}

/// Erase the current terminal line and return the cursor to its start, so a
/// transient status drawn with [`countdown`] is replaced cleanly by the next line.
pub fn clear_line() {
    use std::io::Write;
    print!("\r\x1b[2K");
    let _ = std::io::stdout().flush();
}

/// Word-wrap `text` to the terminal's content width (see [`content_width`]),
/// keeping each span between [`DELIMITERS`] whole (see [`wrap_to`]).
pub(crate) fn wrap(text: &str) -> Vec<String> {
    wrap_to(text, content_width())
}

/// Word-wrap `text` to `width` characters. A word is a run with no whitespace
/// outside a span: a span, with what is written against it, is one word, so every
/// character between a delimiter and its close is written as handed and no line
/// break falls between them. A span with no close holds the rest of `text`. A word
/// that does not fit what is left of a line starts the next; one wider than `width`
/// is a line of its own, written whole. Whitespace outside a span separates words, as
/// one space.
pub(crate) fn wrap_to(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in words(text) {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// The words of `text` as [`wrap_to`] reads them: split at whitespace outside a span,
/// each span between a delimiter and its close (or the end of `text`) held in its word.
fn words(text: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    let mut open: Option<char> = None;
    for (i, c) in text.char_indices() {
        match open {
            Some(d) if c == d => open = None,
            Some(_) => {}
            None if c.is_whitespace() => {
                if let Some(s) = start.take() {
                    words.push(&text[s..i]);
                }
            }
            None => {
                start.get_or_insert(i);
                if DELIMITERS.contains(&c) {
                    open = Some(c);
                }
            }
        }
    }
    if let Some(s) = start {
        words.push(&text[s..]);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::{wrap_to, WIDTH_MAX, WIDTH_MIN};

    /// The words-only wrap this renderer had before spans: what a line with no
    /// delimiter must still be given.
    fn by_spaces(text: &str, width: usize) -> Vec<String> {
        let mut lines = Vec::new();
        let mut cur = String::new();
        for word in text.split_whitespace() {
            if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
                lines.push(std::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        if !cur.is_empty() {
            lines.push(cur);
        }
        if lines.is_empty() {
            lines.push(String::new());
        }
        lines
    }

    /// **Words outside a span re-flow as before** (kottonllc/kotton#654): a line with no
    /// delimiter is wrapped at every width as the words-only wrap wraps it.
    #[test]
    fn words_outside_a_span_reflow_as_before() {
        let prose = "it reaches home with no digits shown from now on,   and\tthe  terminal folds \
                     what is wider than itself: averyveryveryverylongwordthatfitsnowidthatall here.";
        for width in [1, WIDTH_MIN, 40, WIDTH_MAX] {
            assert_eq!(wrap_to(prose, width), by_spaces(prose, width), "{width}");
        }
        assert_eq!(wrap_to("", WIDTH_MIN), vec![String::new()]);
        assert_eq!(wrap_to("   ", WIDTH_MIN), vec![String::new()]);
    }

    /// **A span is written as handed, on one line** (kottonllc/kotton#597, 56B;
    /// kottonllc/kotton#654): the spaces between its delimiters are kept as they are and
    /// no break falls among them; a span that does not fit what is left of a line starts
    /// the next, with what is written against it; one wider than the column is a line of
    /// its own; and a span with no close holds the rest of its line.
    #[test]
    fn a_span_is_written_as_handed_on_one_line() {
        assert_eq!(
            wrap_to("say `my  phone` names no key", WIDTH_MIN),
            vec!["say `my  phone` names no", "key"]
        );
        assert_eq!(
            wrap_to("a line that ends with `device revoke attic`.", WIDTH_MIN),
            vec!["a line that ends with", "`device revoke attic`."]
        );
        let did = "`device revoke did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX`";
        assert_eq!(
            wrap_to(&format!("type {did} to remove it"), WIDTH_MAX),
            vec!["type".to_string(), did.to_string(), "to remove it".to_string()]
        );
        assert_eq!(
            wrap_to("an open `span with   no close runs on", WIDTH_MIN),
            vec!["an open", "`span with   no close runs on"]
        );
    }
}
