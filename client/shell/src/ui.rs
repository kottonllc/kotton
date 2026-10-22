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

use colored::{ColoredString, Colorize};

/// Left margin for top-level lines (header, body, prompts).
pub(crate) const MARGIN: &str = "  ";
/// Left margin for the indented detail block (rows, hints, literals).
pub(crate) const ROW_MARGIN: &str = "    ";
/// Maximum content column width. Prose never sprawls wider than this even on a
/// very wide terminal (long measures hurt readability); a narrower terminal wraps
/// to its own width instead. The margin is added on top of the content column.
pub(crate) const WIDTH_MAX: usize = 72;
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
    term_width().saturating_sub(MARGIN.len()).clamp(24, WIDTH_MAX)
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

/// Word-wrap `text` to the terminal's content width (see [`content_width`]).
pub(crate) fn wrap(text: &str) -> Vec<String> {
    let width = content_width();
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
