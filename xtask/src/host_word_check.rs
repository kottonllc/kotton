// SPDX-License-Identifier: AGPL-3.0-or-later
//! `host-word-check`: what a person reads says *host* for the machine, and *instance*, *relay*
//! or *vault* for what runs on it — never *box*.
//!
//! A relay and a vault are two instances under two keys even on one machine (`docs/design/
//! nodes.md`), and a word for "the machine that runs every service" taught the opposite. The
//! pages a person meets first, the essays, the design, the guides, the installer, the
//! artboards the window is drawn from, and the copy of the shell, the CLI, the window, the
//! release tooling, the relay and the daemons were rewritten without it, and so were the
//! messages and fixtures of their tests; this keeps the word from coming back.
//!
//! **What it reads, every line:** every `*.md` at the root — `README.md`, `CONTRIBUTING.md`,
//! `CLAUDE.md` and their kin; every `.md` under `papers/`, the two essays and their index;
//! every `.md` under `docs/design/`, `docs/design/decisions/` among them; every file under
//! `docs/use/` and `infra/release/`; `infra/README.md` and every `infra/*/README.md`; and the
//! two generated references, `docs/cli/reference.md` and `docs/shell/reference.md` — which
//! carry the CLI's help, its doc comments included, as a person sees it.
//!
//! **What it reads, string literals only:** every `.rs` file under `client/shell/src/` and
//! `client/cli/src/`; the window's, under `guest/apps/kotton-shell/logic/src/`; the lines
//! `cargo xtask` prints, under `xtask/src/`; the relay's, under `infra/relay/src/` and
//! `infra/relay/tests/`; and every crate under `core/` but `kuid`, its `src/` and its
//! `tests/` — a server's and a daemon's sentences reach a person as an error or a hint, and a
//! test's message and fixture are what a contributor reads when one fails. A literal is what
//! a person can be shown; an identifier (`Box::new`, a test named for the case it holds) and a
//! comment are not, so neither is read. A literal may be a stylesheet, so CSS's own words that
//! hold *box* (`box-shadow`, `border-box`, …) are not the word inside one.
//!
//! **What it reads, the text a page shows:** every `.html` file under `ui/ink/`, the artboards
//! the window is drawn from, so a sentence there is the next one the window says. What lies
//! between tags is read, and so is the value of an attribute a page shows (the ten in
//! [`SHOWN`]: `alt`, `aria-label`, `placeholder`, `title`, `value` and their kin); a tag's
//! name, its other attributes (`class`, `id`, `style`, `href`) and a comment are markup, not
//! copy. A `<style>` element's
//! text lies between tags, so CSS's words are not the word there either. The rest of `ui/` is
//! not read: `tokens.css` is a stylesheet whose comments speak of CSS's box model,
//! `portal-reference.html` renders the tokens rather than a screen, and `ui/ink/README.md` is
//! the narrative of the boards, which quotes the owner's own words as written.
//!
//! **What it does not read.** `core/kuid`, because there the word is not copy: its literals
//! are stylesheets and the raster tests over them, where a box is CSS's box model. `DCO.md`,
//! the Developer Certificate of Origin, a text copied verbatim that cannot be reworded. And
//! nine files under the paths above that hold the word as their subject: the four decisions
//! that are about the word itself — 0003, which retires it, and 0013, 0015 and 0016, which draw
//! this check around more of the tree and name what still holds it as an identifier (the
//! refused credential's `box=` line, `Role::Box`, CSS's box model) — and a decision is not
//! edited after it is made; this check's own tests, which plant it; the compose file's test,
//! which names the retired recipes to hold that they are gone; `peer`'s `operator.rs`, which
//! reads the refused credential form's `box` line, a format, to name what it dropped; `wire`'s
//! `line.rs`, whose tests hand the parser a line of kind `box` to hold that it is refused; and
//! `record`'s SQLite store, whose tests keep a note titled *boxes*.
//!
//! The word is *box* or *boxes*, whole (`\bbox(es)?\b`, any case), so *box's* is found and
//! *sandbox*, *inbox* and *boxed* are not. It exits 1 naming the file and line of each
//! finding.

use std::path::{Path, PathBuf};

/// Trees read whole, every file, recursively.
const TREES: &[&str] = &["docs/use", "infra/release"];

/// Trees whose `.md` files are read whole, recursively: the essays and the design.
const MD_TREES: &[&str] = &["papers", "docs/design"];

/// Files read whole, by path; every `*.md` at the root is read beside them.
const FILES: &[&str] = &["infra/README.md", "docs/cli/reference.md", "docs/shell/reference.md"];

/// Trees whose `.rs` files are read for string literals only: every crate under `core/` but
/// `kuid`, by its `src/` and its `tests/`, beside the shell, the CLI, the window, `xtask` and
/// the relay. `docs-present-check` reads the comments of the same trees.
pub const RUST_TREES: &[&str] = &[
    "client/shell/src",
    "client/cli/src",
    "guest/apps/kotton-shell/logic/src",
    "xtask/src",
    "infra/relay/src",
    "infra/relay/tests",
    "core/app/src",
    "core/common/src",
    "core/context/src",
    "core/crypto/src",
    "core/device/src",
    "core/device/tests",
    "core/diag/src",
    "core/fs/src",
    "core/grant/src",
    "core/identity/src",
    "core/infer/src",
    "core/ipc/src",
    "core/kdeviced/src",
    "core/khttpd/src",
    "core/kinferd/src",
    "core/kquicd/src",
    "core/ksyncd/src",
    "core/kuserd/src",
    "core/kvaultd/src",
    "core/kvaultd/tests",
    "core/msg/src",
    "core/net/src",
    "core/org/src",
    "core/outbound/src",
    "core/pair/src",
    "core/peer/src",
    "core/proc/src",
    "core/proc/tests",
    "core/record/src",
    "core/schemas/src",
    "core/sealed/src",
    "core/secret/src",
    "core/session/src",
    "core/store/src",
    "core/store/tests",
    "core/surface/src",
    "core/sync/src",
    "core/sys/src",
    "core/time/src",
    "core/wasm/src",
    "core/wire/src",
];

/// Trees whose `.html` files are read for the text a page shows ([`html_text`]).
const HTML_TREES: &[&str] = &["ui/ink"];

/// The attributes whose value a page shows a person.
const SHOWN: &[&str] = &[
    "alt",
    "aria-description",
    "aria-label",
    "aria-roledescription",
    "aria-valuetext",
    "content",
    "label",
    "placeholder",
    "title",
    "value",
];

/// Files under the paths above that hold the word as their subject, not as copy, or that are
/// copied verbatim and cannot be reworded.
const NOT_READ: &[&str] = &[
    // The Developer Certificate of Origin, a text copied verbatim.
    "DCO.md",
    // The decisions about the word itself: 0003 retires it, and 0013, 0015 and 0016 draw this
    // check around more of the tree and name what holds it as an identifier or as CSS's. A
    // decision is not edited after it is made.
    "docs/design/decisions/0003-the-machine-is-a-host-and-what-runs-on-it-is-an-instance.md",
    "docs/design/decisions/0013-host-word-check-reads-the-window-xtask-and-the-daemons-whose-copy-reaches-a-person.md",
    "docs/design/decisions/0015-host-word-check-reads-the-artboards.md",
    "docs/design/decisions/0016-host-word-check-reads-every-crate-under-core-but-the-display-server.md",
    // This check's own tests, which plant the word.
    "xtask/src/host_word_check.rs",
    // Names the retired `box` recipes to hold that the compose file does not.
    "xtask/src/compose_file_tests.rs",
    // Reads the refused credential form's `box` line, a format, to name what it dropped.
    "core/peer/src/operator.rs",
    // Hands the parser a line of kind `box` to hold that it is refused.
    "core/wire/src/line.rs",
    // Keeps a note titled *boxes*, the ordinary noun, as a record's title.
    "core/record/src/provider/sqlite_record_store.rs",
];

/// CSS's words that hold *box*: inside a Rust literal or an artboard's text, either of which
/// may be a stylesheet, they are not the word.
const CSS_WORDS: &[&str] =
    &["box-decoration-break", "box-shadow", "box-sizing", "border-box", "content-box", "padding-box"];

pub fn run(root: &Path) {
    let found = findings(root);
    if found.is_empty() {
        println!(
            "host-word-check: OK — {} files a person reads say host, instance, relay or vault, never box",
            files(root).len()
        );
        return;
    }
    for f in &found {
        eprintln!("{f}");
    }
    eprintln!(
        "\nhost-word-check: {} finding(s). Say *host* for the machine, and *instance*, *relay* or \
         *vault* for what runs on it.",
        found.len()
    );
    std::process::exit(1);
}

/// Every file the check reads, relative to `root` with `/` separators, sorted.
pub fn files(root: &Path) -> Vec<String> {
    let rel = |p: &Path| p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/");
    let mut out = Vec::new();
    for tree in TREES {
        let mut found = Vec::new();
        walk(&root.join(tree), &mut found);
        out.extend(found.iter().map(|p| rel(p)));
    }
    for tree in MD_TREES {
        let mut found = Vec::new();
        walk(&root.join(tree), &mut found);
        out.extend(found.iter().filter(|p| p.extension().is_some_and(|x| x == "md")).map(|p| rel(p)));
    }
    for file in FILES {
        if root.join(file).is_file() {
            out.push(file.to_string());
        }
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            if e.path().is_file() && e.path().extension().is_some_and(|x| x == "md") {
                out.push(rel(&e.path()));
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(root.join("infra")) {
        for e in entries.flatten() {
            let readme = e.path().join("README.md");
            if e.path().is_dir() && readme.is_file() {
                out.push(rel(&readme));
            }
        }
    }
    for tree in RUST_TREES {
        let mut found = Vec::new();
        walk(&root.join(tree), &mut found);
        out.extend(
            found
                .iter()
                .filter(|p| p.extension().is_some_and(|x| x == "rs"))
                .map(|p| rel(p)),
        );
    }
    for tree in HTML_TREES {
        let mut found = Vec::new();
        walk(&root.join(tree), &mut found);
        out.extend(found.iter().filter(|p| p.extension().is_some_and(|x| x == "html")).map(|p| rel(p)));
    }
    out.retain(|p| !NOT_READ.contains(&p.as_str()));
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// `file:line: what` for every finding, in file order.
pub fn findings(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for rel in files(root) {
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else { continue };
        let hits = if rel.ends_with(".rs") {
            string_literals(&text).into_iter().flat_map(|(line, lit)| in_text(&without_css(&lit), line)).collect()
        } else if rel.ends_with(".html") && HTML_TREES.iter().any(|t| rel.starts_with(&format!("{t}/"))) {
            in_text(&without_css(&html_text(&text)), 1)
        } else {
            in_text(&text, 1)
        };
        for (line, word) in hits {
            out.push(format!("{rel}:{line}: says `{word}`"));
        }
    }
    out
}

/// `lit` with each of [`CSS_WORDS`] blanked to spaces of its length, so the lines stay.
pub fn without_css(lit: &str) -> String {
    let mut out = lit.to_string();
    for word in CSS_WORDS {
        out = out.replace(word, &" ".repeat(word.len()));
    }
    out
}

/// The text of an HTML page that a person is shown, with its markup blanked to spaces and its
/// newlines kept, so a finding names the line it is on: what lies between tags, and the value
/// of each attribute in [`SHOWN`]. A tag's name, its other attributes and a comment are
/// blanked. A `<` that does not open a tag, a comment or a declaration is text.
pub fn html_text(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let blank = |out: &mut String, ch: char| out.push(if ch == '\n' { '\n' } else { ' ' });
    let mut i = 0;
    while i < c.len() {
        let opens = c[i] == '<' && c.get(i + 1).is_some_and(|n| n.is_ascii_alphabetic() || matches!(n, '/' | '!'));
        if !opens {
            out.push(c[i]);
            i += 1;
            continue;
        }
        if c[i..].starts_with(&['<', '!', '-', '-']) {
            let end = (i + 4..c.len()).find(|&k| c[k..].starts_with(&['-', '-', '>'])).map_or(c.len(), |k| k + 3);
            c[i..end].iter().for_each(|&ch| blank(&mut out, ch));
            i = end;
            continue;
        }
        // The `<` and the tag's name, then each attribute, to the `>` outside a quoted value.
        while i < c.len() && !c[i].is_whitespace() && c[i] != '>' {
            blank(&mut out, c[i]);
            i += 1;
        }
        loop {
            while i < c.len() && (c[i].is_whitespace() || c[i] == '/') {
                blank(&mut out, c[i]);
                i += 1;
            }
            if i >= c.len() {
                break;
            }
            if c[i] == '>' {
                blank(&mut out, c[i]);
                i += 1;
                break;
            }
            let start = i;
            while i < c.len() && !c[i].is_whitespace() && !matches!(c[i], '=' | '>' | '/') {
                blank(&mut out, c[i]);
                i += 1;
            }
            let name = c[start..i].iter().collect::<String>().to_ascii_lowercase();
            while i < c.len() && c[i].is_whitespace() {
                blank(&mut out, c[i]);
                i += 1;
            }
            if c.get(i) != Some(&'=') {
                continue;
            }
            blank(&mut out, '=');
            i += 1;
            while i < c.len() && c[i].is_whitespace() {
                blank(&mut out, c[i]);
                i += 1;
            }
            let quote = match c.get(i) {
                Some(&q @ ('"' | '\'')) => {
                    blank(&mut out, q);
                    i += 1;
                    Some(q)
                }
                _ => None,
            };
            let shown = SHOWN.contains(&name.as_str());
            while i < c.len() && quote.map_or(!c[i].is_whitespace() && c[i] != '>', |q| c[i] != q) {
                if shown {
                    out.push(c[i]);
                } else {
                    blank(&mut out, c[i]);
                }
                i += 1;
            }
            if quote.is_some() && i < c.len() {
                blank(&mut out, c[i]);
                i += 1;
            }
        }
    }
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Each whole *box* or *boxes* in `text`, any case, as the line it is on (counting from
/// `first`) and the word as written.
pub fn in_text(text: &str, first: usize) -> Vec<(usize, String)> {
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    let mut line = first;
    for i in 0..chars.len() {
        if chars[i] == '\n' {
            line += 1;
            continue;
        }
        if lower[i..].len() < 3 || lower[i..i + 3] != ['b', 'o', 'x'] || (i > 0 && is_word(chars[i - 1])) {
            continue;
        }
        let mut end = i + 3;
        if lower.get(end..end + 2) == Some(&['e', 's'][..]) && !chars.get(end + 2).copied().is_some_and(is_word) {
            end += 2;
        }
        if chars.get(end).copied().is_some_and(is_word) {
            continue;
        }
        out.push((line, chars[i..end].iter().collect()));
    }
    out
}

/// The string literals in Rust source — `"…"`, `b"…"`, `r#"…"#` and `br"…"` — each with the
/// line it starts on, its escapes read as a space. Comments, char literals and lifetimes are
/// stepped over, so a quote inside one starts nothing.
pub fn string_literals(src: &str) -> Vec<(usize, String)> {
    lex(src).0
}

/// The comments in Rust source — `//`, `///`, `//!` and `/* … */`, nested ones whole — each with
/// the line it starts on and its text from the opening `//` or `/*` on, newlines kept. A string
/// literal, a char literal and a lifetime are stepped over, so a `//` inside a string starts
/// nothing.
pub fn comments(src: &str) -> Vec<(usize, String)> {
    lex(src).1
}

/// Pieces of Rust source, each with the line it starts on.
type Pieces = Vec<(usize, String)>;

/// One pass over Rust source: its string literals, then its comments.
fn lex(src: &str) -> (Pieces, Pieces) {
    let c: Vec<char> = src.chars().collect();
    let ident = |k: usize| k < c.len() && is_word(c[k]);
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '\n' => {
                line += 1;
                i += 1;
            }
            '/' if c.get(i + 1) == Some(&'/') => {
                let start = i;
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
                notes.push((line, c[start..i].iter().collect()));
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                let (first, start) = (line, i);
                let mut depth = 0;
                while i < c.len() {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if c[i] == '\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
                notes.push((first, c[start..i].iter().collect()));
            }
            '\'' => {
                // A char literal — `'x'` or `'\…'` — or else a lifetime or a label.
                if c.get(i + 1) == Some(&'\\') {
                    // Past the quote, the backslash and the escaped char, which may be a quote.
                    i += 3;
                    while i < c.len() && c[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                } else if c.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            'r' if !ident(i.wrapping_sub(1)) || (i >= 1 && c[i - 1] == 'b' && !ident(i.wrapping_sub(2))) => {
                let mut k = i + 1;
                while c.get(k) == Some(&'#') {
                    k += 1;
                }
                if c.get(k) != Some(&'"') {
                    i += 1;
                    continue;
                }
                let hashes = k - i - 1;
                let (start, mut lit) = (line, String::new());
                k += 1;
                while k < c.len() {
                    if c[k] == '"' && (1..=hashes).all(|h| c.get(k + h) == Some(&'#')) {
                        k += 1 + hashes;
                        break;
                    }
                    if c[k] == '\n' {
                        line += 1;
                    }
                    lit.push(c[k]);
                    k += 1;
                }
                out.push((start, lit));
                i = k;
            }
            '"' => {
                let (start, mut lit) = (line, String::new());
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        if c.get(i + 1) == Some(&'\n') {
                            line += 1;
                            lit.push('\n');
                        } else {
                            lit.push(' ');
                        }
                        i += 2;
                        continue;
                    }
                    if c[i] == '\n' {
                        line += 1;
                    }
                    lit.push(c[i]);
                    i += 1;
                }
                i += 1;
                out.push((start, lit));
            }
            _ => i += 1,
        }
    }
    (out, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    /// One file of each kind the check reads, each saying *host* and the words that only look
    /// like the one refused.
    const CLEAN: &[(&str, &str)] = &[
        ("docs/use/run-a-relay.md", "# Run a relay\n\nOn the host, as root. Your sandbox, your inbox, a boxed set.\n"),
        ("docs/use/nested/page.md", "The instance is a relay.\n"),
        ("infra/release/install-server.sh", "#!/bin/sh\n# as root, on the host\necho \"already on this host\"\n"),
        ("infra/release/README.txt", "A host runs the vault.\n"),
        ("infra/README.md", "# infra\n\nNo host? Read the guides.\n"),
        ("infra/relay/README.md", "| File | On the host |\n"),
        ("docs/cli/reference.md", "# Command-Line Help for `kotton`\n"),
        ("docs/shell/reference.md", "# Shell Command Reference\n"),
        ("client/shell/src/commands/mint.rs", "fn mint() -> &'static str { \"On the host, as root:\" }\n"),
        ("client/cli/src/kotton.rs", "fn main() { println!(\"{}\", \"the vault's line\"); }\n"),
        (
            "guest/apps/kotton-shell/logic/src/components/overlays/settings.rs",
            "const A: &str = \"The vault printed six digits in its own terminal\";\n",
        ),
        ("xtask/src/release_server.rs", "fn f() { println!(\"a fix reaches a host only as a release\"); }\n"),
        ("core/device/src/users/pairing.rs", "const A: &str = \"On the host, `kvaultd invite sam`\";\n"),
        ("core/kuserd/src/agent/operator.rs", "const A: &str = \"the vault did not answer\";\n"),
        ("core/kvaultd/src/peer.rs", "const A: &str = \"said under the vault's operator credential\";\n"),
        ("core/wasm/src/sandbox.rs", "const A: &str = \"a host's landlord verbs are not available\";\n"),
        ("core/app/src/daemon/apps.rs", "const A: &str = \"people at a host\";\n"),
        (
            "ui/ink/Settings-networks-invite.dc.html",
            "<p style=\"margin: 0; box-sizing: border-box;\">Their data is sealed before the vault sees it.</p>\n",
        ),
        ("core/grant/src/lib.rs", "const A: &str = \"a grant the vault holds\";\n"),
        ("core/peer/src/pairing.rs", "const A: &str = \"http://host-relay:7700\";\n"),
        ("core/kvaultd/tests/install.rs", "const A: &str = \"the scratch host's root\";\n"),
        ("infra/relay/src/admission.rs", "const A: &str = \"`systemctl start kotton-relay` on a host\";\n"),
        ("README.md", "# Kotton\n\nA rented host runs your relay and your vault.\n"),
        ("CONTRIBUTING.md", "# Contributing\n\nA sandbox, an inbox.\n"),
        ("CLAUDE.md", "# CLAUDE.md\n\nThe host keeps what it cannot open.\n"),
        ("papers/confinement-thesis.md", "# The confinement thesis\n\nA host keeps what it cannot open.\n"),
        ("docs/design/nodes.md", "# Nodes\n\nA relay and a vault are two instances, even on one host.\n"),
        ("docs/design/decisions/0001-a-relay.md", "# 0001: A relay\n\nThe relay on your host is yours.\n"),
    ];

    #[test]
    fn a_clean_tree_passes() {
        let dir = tree(CLEAN);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        assert_eq!(files(dir.path()).len(), CLEAN.len());
    }

    /// **The word, planted in each kind of path read, is refused by file and line** — in prose,
    /// in a fenced command, in a script's comment and its output, in a README of each kind, in
    /// each reference, and in each form of Rust string literal, a literal over several lines
    /// named by the line the word is on.
    #[test]
    fn each_path_kind_is_refused_by_file_and_line() {
        let planted: &[(&str, &str, &str)] = &[
            ("docs/use/run-a-relay.md", "On the box, as root.", "box"),
            ("docs/use/nested/page.md", "```sh\nscp it root@box:\n```", "box"),
            ("infra/release/install-server.sh", "# when the BOX has none", "BOX"),
            ("infra/release/install-server.sh", "made=\"already on this box\"", "box"),
            ("infra/release/README.txt", "Two boxes, one person.", "boxes"),
            ("infra/release/allowed_signers", "# the box's key", "box"),
            ("infra/README.md", "**Starting from nothing — no box?**", "box"),
            ("infra/vault/README.md", "| File | On a Box |", "Box"),
            ("docs/cli/reference.md", "* `reset` — wipe this box", "box"),
            ("docs/shell/reference.md", "mint — make the key a box runs", "box"),
            ("client/shell/src/commands/mint.rs", "const A: &str = \"the box's line\";", "box"),
            ("client/cli/src/kotton.rs", "const B: &[u8] = b\"a box\";", "box"),
            ("client/cli/src/kotton.rs", "const C: &str = r#\"a \"quoted\" box\"#;", "box"),
            ("client/shell/src/commands/mint.rs", "const D: &str = \"a line\\nbox\";", "box"),
            (
                "guest/apps/kotton-shell/logic/src/components/overlays/settings.rs",
                "p { \"The box printed six digits in its own terminal, on the \" }",
                "box",
            ),
            ("guest/apps/kotton-shell/logic/src/view.rs", "const E: &str = \"Invite \\u{2014} asking the box\";", "box"),
            ("xtask/src/release_server.rs", "fn g() { println!(\"a fix reaches a box only as a release\"); }", "box"),
            ("xtask/src/doctor.rs", "const F: &str = \"the target a box runs\";", "box"),
            ("core/device/src/users/pairing.rs", "const G: &str = \"At the box, `kvaultd invite sam`\";", "box"),
            ("core/kuserd/src/agent/operator.rs", "const H: &str = \"the box did not answer\";", "box"),
            ("core/kvaultd/src/peer.rs", "const I: &str = \"said under the box's operator credential\";", "box"),
            ("core/wasm/src/sandbox.rs", "const J: &str = \"a box's landlord verbs are not available\";", "box"),
            ("core/app/src/daemon/apps.rs", "const K: &str = \"people at a box\";", "box"),
            ("core/app/src/daemon/apps.rs", "const L: &str = \"box-shadow: 0 1px red; on the box\";", "box"),
            ("ui/ink/Settings-networks-invite.dc.html", "<span class=\"note\">The box never learns it.</span>", "box"),
            ("ui/ink/Pairing.dc.html", "<input placeholder=\"x\" value=\"the box's name\">", "box"),
            ("ui/ink/Home.dc.html", "<img alt='A box, awake' src=\"box.png\">", "box"),
            ("ui/ink/Notice.dc.html", "<style>.n { box-shadow: none; }</style><b>On the box</b>", "box"),
            ("core/grant/src/lib.rs", "const M: &str = \"a grant the box holds\";", "box"),
            ("core/peer/src/pairing.rs", "const N: &str = \"http://box-relay:7700\";", "box"),
            ("core/kvaultd/tests/install.rs", "fn t() { assert!(false, \"{} is inside the box\", 1); }", "box"),
            ("core/common/src/paths.rs", "const O: &[&str] = &[\"for the box it installs\"];", "box"),
            ("infra/relay/src/admission.rs", "const P: &str = \"`systemctl start kotton-relay` on a box\";", "box"),
            ("infra/relay/tests/install.rs", "const Q: &str = \"an empty root at <dir>/box\";", "box"),
            ("README.md", "Run it on a rented box.", "box"),
            ("CONTRIBUTING.md", "A box is a host.", "box"),
            ("CLAUDE.md", "The BOX keeps it.", "BOX"),
            ("AGENTS.md", "One box per agent.", "box"),
            ("papers/confinement-thesis.md", "The box keeps what it cannot open.", "box"),
            ("papers/README.md", "Two essays, two boxes.", "boxes"),
            ("docs/design/nodes.md", "One box runs every service.", "box"),
            ("docs/design/decisions/0001-a-relay.md", "The relay on your box is yours.", "box"),
            ("docs/design/decisions/README.md", "A Box is a host.", "Box"),
        ];
        for (path, line, says) in planted {
            let mut files: Vec<(&str, String)> = CLEAN.iter().map(|(p, t)| (*p, t.to_string())).collect();
            let before = match files.iter_mut().find(|(p, _)| p == path) {
                Some((_, t)) => {
                    let before = t.lines().count();
                    t.push_str(&format!("{line}\n"));
                    before
                }
                None => {
                    files.push((path, format!("{line}\n")));
                    0
                }
            };
            // The line the word is on, counted in the file as planted.
            let at = before + line.lines().position(|l| l.contains(says)).unwrap() + 1;
            let borrowed: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
            let dir = tree(&borrowed);
            let found = findings(dir.path());
            assert_eq!(found, vec![format!("{path}:{at}: says `{says}`")], "{path}: {line:?}");
        }

        let dir = tree(&[("client/cli/src/help.rs", "const H: &str = \"one\n  two\n  three box\";\n")]);
        assert_eq!(findings(dir.path()), vec!["client/cli/src/help.rs:3: says `box`".to_string()]);
    }

    /// **A sentence in an artboard is refused by file and line**: the invite artboard's own
    /// sentence, on the line it is drawn on, under the markup a `.dc.html` carries.
    #[test]
    fn a_sentence_in_an_artboard_is_refused_by_file_and_line() {
        let board = "<!doctype html>\n\
<html lang=\"en\"><head><title>Invite someone</title></head>\n\
<body><div style=\"width: 460px; box-shadow: 0 24px 48px rgba(0,0,0,0.5);\">\n\
<p style=\"margin: 0;\">One invite joins them to the whole network. Her data is sealed before the box sees \
it, and the box counts bytes and nothing else.</p>\n\
</div></body></html>\n";
        let dir = tree(&[("ui/ink/Settings-networks-invite.dc.html", board)]);
        assert_eq!(
            findings(dir.path()),
            vec![
                "ui/ink/Settings-networks-invite.dc.html:4: says `box`".to_string(),
                "ui/ink/Settings-networks-invite.dc.html:4: says `box`".to_string(),
            ]
        );
    }

    /// **Markup in an artboard is not copy, and CSS's words are not the word there**: an inline
    /// `style` that says `box-shadow` or `border-box`, a `<style>` element that does, a class or
    /// an id named *box*, an `href` or `src` naming a file, and a comment. The text a page shows
    /// keeps its lines, so what follows them is named by the line it is on.
    #[test]
    fn markup_and_css_words_in_an_artboard_are_not_the_word() {
        let board = "<!-- the box,\n  drawn -->\n\
<style>.card { box-sizing: border-box; box-shadow: 0 1px red; }</style>\n\
<div class=\"box\" id='box' style=\"box-shadow: 0 18px 48px rgba(0,0,0,0.55); box-sizing: border-box\">\n\
<a href=\"box.html\"><img src=box.png alt=\"A vault, awake\"></a> 2 < 3 and 4 > 1\n\
<span title=\"the host\">The vault counts bytes.</span></div>\n";
        let dir = tree(&[("ui/ink/Settings-networks-yours.dc.html", board)]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        let text = html_text(board);
        assert_eq!(text.lines().count(), board.lines().count());
        assert!(text.contains("A vault, awake") && text.contains("2 < 3 and 4 > 1"), "{text:?}");
        assert!(text.contains("the host") && text.contains("The vault counts bytes."), "{text:?}");
        assert_eq!(in_text(&without_css(&html_text(&format!("{board}<p>a box</p>\n"))), 1), vec![(7, "box".to_string())]);
    }

    /// **An identifier or a comment in Rust is not copy**: `Box::new`, a variant named `Box`, a
    /// test named for the box it once held, a doc comment and a block comment that say the word,
    /// and a char literal or lifetime that a quote-counting reader would take for a string.
    #[test]
    fn an_identifier_or_a_comment_in_rust_is_not_refused() {
        let src = "\
/// A box, in a doc comment.
// a box, in a line comment
/* a box /* nested box */ still a box */
enum Role { Box, Vault }
fn recovery_works_while_the_boxs_relay_is_down<'a>(x: &'a str) -> Box<dyn Fn()> {
    let quote = '\"';
    let escaped = '\\'';
    let box_count = 1;
    let _ = (quote, escaped, box_count, Role::Box);
    Box::new(move || println!(\"{x} on the host\"))
}
";
        let dir = tree(&[("client/shell/src/commands/device.rs", src), ("client/cli/src/kctl.rs", src)]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        assert_eq!(string_literals(src), vec![(10, "{x} on the host".to_string())]);
    }

    /// Only the paths named are read: the four decisions about the word itself, the
    /// certificate of origin copied verbatim, a file beside the essays or the design that is
    /// not Markdown, a root page's sibling that is not Markdown, the boards' narrative, the
    /// tokens and their reference rendering, the display server's stylesheets, the three files
    /// under `core/` whose subject is the word — the refused credential form's key, the
    /// parser's refused kind, a note titled *boxes* — a crate's sources outside `src/` and
    /// `tests/`, a scenario's own sources, a stylesheet beside the window's sources, and the
    /// two xtask files whose subject is the word may say what they say.
    #[test]
    fn a_path_outside_the_named_ones_is_not_read() {
        let dir = tree(&[
            ("docs/design/decisions/0003-the-machine-is-a-host-and-what-runs-on-it-is-an-instance.md", "a *box*"),
            (
                "docs/design/decisions/0013-host-word-check-reads-the-window-xtask-and-the-daemons-whose-copy-reaches-a-person.md",
                "the refused credential's `box=` line",
            ),
            ("docs/design/decisions/0015-host-word-check-reads-the-artboards.md", "the CSS box model"),
            (
                "docs/design/decisions/0016-host-word-check-reads-every-crate-under-core-but-the-display-server.md",
                "a note titled *boxes*",
            ),
            ("DCO.md", "the box"),
            ("papers/LICENSE", "the box"),
            ("docs/design/nodes.svg", "<text>the box</text>"),
            ("Justfile", "# the box"),
            ("core/kuid/src/main.rs", "const X: &str = \"a scrollable box\";"),
            ("core/peer/src/operator.rs", "pub const FIRST_FORM_NAME: &str = \"box\";"),
            ("core/wire/src/line.rs", "const X: &str = \":box:\";"),
            ("core/record/src/provider/sqlite_record_store.rs", "const X: &str = \"boxes\";"),
            ("core/kvaultd/benches/install.rs", "const X: &str = \"the box\";"),
            ("guest/apps/kotton-shell/logic/src/style.css", ".check-box { flex:none; }"),
            ("guest/apps/kotton-shell/logic/Cargo.toml", "# the box"),
            ("xtask/src/host_word_check.rs", "const X: &str = \"On the box, as root.\";"),
            ("xtask/src/compose_file_tests.rs", "const X: &[&str] = &[\"box::\", \"release::box\"];"),
            ("infra/relay/benches/install.rs", "const X: &str = \"the box\";"),
            ("infra/scenarios/conductor/src/main.rs", "const X: &str = \"the box\";"),
            ("infra/scenarios/rental.yml", "# the box"),
            ("infra/relay/nested/README.md", "the box"),
            ("client/shell/README.md", "the box"),
            ("ui/ink/README.md", "so every 'box' that you have is a vault and a relay"),
            ("ui/ink/Settings-networks-invite.png", "the box"),
            ("ui/tokens.css", "/* a box that IS a thing */ * { box-sizing: border-box; }"),
            ("ui/portal-reference.html", "<p>the box</p>"),
        ]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
    }

    /// **A literal may be a stylesheet**: CSS's words that hold *box* are not the word inside
    /// one, and the word beside them still is. In prose they are read as written.
    #[test]
    fn css_words_in_a_literal_are_not_the_word() {
        let css = "const S: &str = \".card { box-sizing: border-box; box-shadow: 0 1px red; \\
                   background-clip: padding-box; box-decoration-break: clone; }\";\n";
        let dir = tree(&[("guest/apps/kotton-shell/logic/src/style.rs", css)]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        assert_eq!(in_text(&without_css("a box-shadow\non the box"), 1), vec![(2, "box".to_string())]);
        let dir = tree(&[("docs/use/page.md", "Its box-shadow.\n")]);
        assert_eq!(findings(dir.path()), vec!["docs/use/page.md:1: says `box`".to_string()]);
    }

    /// **Every crate under `core/` but `kuid` is read, by its `src/` and its `tests/`**, as
    /// the module says: a crate added beside them is outside the check until it is named
    /// here, and this names it.
    #[test]
    fn every_core_crate_but_kuid_is_read() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent");
        let mut missing = Vec::new();
        for crate_dir in std::fs::read_dir(root.join("core")).unwrap().flatten() {
            let name = crate_dir.file_name().to_string_lossy().into_owned();
            for tree in ["src", "tests"] {
                let path = format!("core/{name}/{tree}");
                if name != "kuid" && crate_dir.path().join(tree).is_dir() && !RUST_TREES.contains(&path.as_str()) {
                    missing.push(path);
                }
            }
        }
        missing.sort();
        assert_eq!(missing, Vec::<String>::new(), "trees under core/ that host-word-check does not read");
        assert!(!RUST_TREES.iter().any(|t| t.starts_with("core/kuid/")), "kuid's literals are stylesheets");
    }

    #[test]
    fn the_word_is_whole_and_any_case() {
        let words = |t: &str| in_text(t, 1).into_iter().map(|(_, w)| w).collect::<Vec<_>>();
        assert_eq!(words("box Box BOX boxes box's (box) box-shadow"), ["box", "Box", "BOX", "boxes", "box", "box", "box"]);
        assert!(words("sandbox inbox boxed boxer Dropbox box_count boxes_x tbox").is_empty());
        assert_eq!(in_text("a\nb\n  box", 4), vec![(6, "box".to_string())]);
    }

    /// **The comments are lexed in the same pass as the literals**, each with the line it
    /// starts on and its text from the opening `//` or `/*`: a line comment, a doc comment, an
    /// inner doc comment, a block over two lines with a nested block inside, and a trailing
    /// comment after code — and no `//` inside a string, a raw string or a char literal.
    #[test]
    fn comments_are_lexed_with_their_lines() {
        let src = "\
//! inner
/// outer
const S: &str = \"not // a comment\";
const R: &str = r#\"nor // this\"#;
const C: char = '/';
/* a block
   /* nested */ still */
fn f() {} // trailing
";
        assert_eq!(
            comments(src),
            vec![
                (1, "//! inner".to_string()),
                (2, "/// outer".to_string()),
                (6, "/* a block\n   /* nested */ still */".to_string()),
                (8, "// trailing".to_string()),
            ]
        );
        assert_eq!(
            string_literals(src),
            vec![(3, "not // a comment".to_string()), (4, "nor // this".to_string())]
        );
    }
}
