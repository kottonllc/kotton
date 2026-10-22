// SPDX-License-Identifier: AGPL-3.0-or-later
//! `token-block-check` — one definition of a design value, and only one.
//!
//! `ui/README.md` states the rule this enforces:
//!
//! > A colour, a radius, a font stack, or a spacing value exists here or it does
//! > not exist. A component reaches for `var(--color-text)`. It never writes a hex
//! > code, and it never declares a token block of its own. When a second
//! > definition appears somewhere, that is not a shortcut — it is the beginning of
//! > a shell that looks like a different product from the design system it was
//! > supposed to be built from.
//!
//! It was a rule addressed to a reader, and on 2026-09-07 a reader wrote one
//! anyway: `client/web/assets/ink.css` declared eight neutrals as literal hex,
//! under a comment saying they were the tokens' values. They were, that day. The
//! phone and the desktop then spent three days disagreeing about what "primary
//! text" meant, and nothing anywhere said so.
//!
//! ## What it checks
//!
//! Any stylesheet that is not `ui/tokens.css` **declaring** a property in the
//! token namespaces **in a root scope**. Using one — `var(--color-text)` — is the
//! whole point and is never flagged; the check is on the left-hand side of a
//! declaration.
//!
//! ## Why root scope, and not every declaration
//!
//! Because that is where the rule actually bites. A block on `:root`, `html`,
//! `[data-theme]` or `[data-form-factor]` *defines the system* for everything
//! below it — which is what `ink.css` did, and how a phone and a desktop came to
//! disagree about what "primary text" meant.
//!
//! A block scoped to a class cannot do that. It redefines values for whatever
//! carries the class and nothing else. The case that proves the distinction is
//! real is already in the tree: `style.css` declares two complete alternate
//! neutral ramps under `.warmth-half` and `.warmth-quarter`, and they exist so the
//! gallery can put three chroma levels side by side and let somebody *choose*.
//! Flagging those would be flagging the design work this rule exists to protect.
//!
//! The loophole is real and small: a rogue palette scoped to some `.app-root`
//! would pass. It would also have to be applied by a component, in a repository
//! where components are reviewed and the gallery renders what they draw.
//!
//! ## And a guest app that ignores the system
//!
//! A second rule, added 2026-09-10 after the first one passed `kotton-editor`
//! clean. That app includes no tokens at all — its own `style.css`, eight raw
//! hex values, its own font stack, a `#f4f1ea` cream ground that matches nothing
//! else in the product. It declared no *token*, so the rule above had nothing to
//! say about it.
//!
//! That is the failure this whole gate exists to prevent, arriving by the other
//! door: not one design system defined twice, but a surface that never joined
//! it. With a calendar, an editor, a word processor and a spreadsheet ahead,
//! that is the thing that produces a hodgepodge.
//!
//! So a stylesheet under `guest/` must not write a literal colour. It reaches for
//! `var(--color-…)` like every other surface, or the value does not exist.
//!
//! ## And a token that does not exist
//!
//! A third rule, and the cheapest of the three. `var(--color-text-tertiary)` is
//! a design value; `var(--color-text-tertiery)` is nothing at all — CSS drops
//! the declaration and the element inherits, so a typo in a token name produces
//! a surface that renders, looks *nearly* right, and says nothing. That is the
//! same silent-resolution failure as the two above, at the reference end instead
//! of the declaration end.
//!
//! So every namespaced `var(--...)` in any stylesheet here must name something
//! `ui/tokens.css` declares. A file's own local custom properties are its
//! business and are left alone; a value claiming to come from the design system
//! has to actually come from it.
//!
//! `client/web/assets/tokens.css` is exempt *and* checked: it is staged from the
//! source by `cargo xtask build-web` (`DEC-0062`), so it is allowed to declare
//! everything, and it must be byte-identical. A stale copy is the same failure in
//! slower motion.

use std::path::{Path, PathBuf};

/// The prefixes a design value lives under. A `--kotton-app-thing` local to one
/// component is not a design token and is not this check's business.
const NAMESPACES: &[&str] = &[
    "--color-",
    "--neutral-",
    "--space-",
    "--text-",
    "--fs-",
    "--radius-",
    "--font-",
    "--leading-",
    "--tracking-",
    "--weight-",
    "--elevation-",
    "--dur-",
    "--ease-",
    "--hit-",
    "--focus-",
    "--mist-",
    "--btn-",
    "--consent-",
    // `--fill-lift` and `--fill-lift-edge`, the material a control on a coloured
    // ground is made of (2026-09-21). Added with them: a namespace this list
    // does not know about is a namespace the typo rule cannot see, and
    // `var(--fill-lfit)` would render as nothing at all with no error — the
    // exact silent resolution the third rule above exists to catch.
    "--fill-",
    // `--desk-ground`, `--desk-horizon` and the two glows — the stops the
    // desktop's drawn ground is made of (2026-09-21,
    // `TASK-the-desk-is-a-drawn-ground-and-not-a-flat-colour`). Added with them
    // for the reason above it: the shell's `#desk` rule is four `var(--desk-…)`
    // in a stack of gradients, and `var(--desk-glow-warn)` would render as
    // nothing at all — a ground that quietly loses a layer, which is the one
    // failure nobody would report because the desk would still look like a
    // desk.
    "--desk-",
    // `--dock-tint-*`, `--dock-tile*`, `--dock-badge-*` and the two heights —
    // the dock's own Tier 3 set (2026-09-21,
    // `TASK-the-shell-draws-its-glyphs-from-one-sheet-and-the-dock-style-is-a-setting`).
    // The namespace existed for three tokens the compositor parses and no
    // stylesheet read, so nothing was checking it; the shell's `#dock` rules
    // read eleven of them now, and `var(--dock-tint-calender)` would render as
    // nothing at all — a tile that silently loses its hue, which is the one
    // failure nobody reports because a dock in the monochrome style is a dock
    // somebody may have chosen.
    "--dock-",
    // `--tint-red` and its four neighbours: the spectrum at the stop a theme's
    // ground can carry, which the Tier 3 set above points at. Here for the same
    // reason, one layer up.
    "--tint-",
];

const SOURCE: &str = "ui/tokens.css";
const STAGED: &str = "client/web/assets/tokens.css";

pub fn run() {
    // Every path below is the repository's, whatever directory this was started in.
    let root = crate::out::root();
    if let Err(e) = std::env::set_current_dir(&root) {
        eprintln!("token-block-check: cannot enter {}: {e}", root.display());
        std::process::exit(1);
    }
    let source = match std::fs::read_to_string(SOURCE) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("token-block-check: cannot read {SOURCE}: {e}");
            std::process::exit(1);
        }
    };

    let mut sheets = stylesheets();
    sheets.sort();

    // Every design value the source declares, so a reference can be checked
    // against it. Read from the file rather than a list here: a list would be a
    // second definition, which is the thing this gate exists to stop.
    let declared = declared_tokens(&source);

    let mut findings: Vec<String> = Vec::new();

    for sheet in &sheets {
        let rel = sheet.strip_prefix("./").unwrap_or(sheet);
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if rel_s == SOURCE {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(sheet) else {
            continue;
        };

        // The staged copy: allowed to declare, required to match.
        if rel_s == STAGED {
            if text != source {
                findings.push(format!(
                    "{rel_s} is not what {SOURCE} says. It is staged by `cargo xtask build-web`; \
                     run that rather than editing it."
                ));
            }
            continue;
        }

        let mut scope = Scope::default();
        let guest = rel_s.starts_with("guest/");
        for (n, line) in text.lines().enumerate() {
            // A guest surface writes no literal colour, anywhere in the file —
            // not only in a root scope, because a hard-coded background on one
            // component is exactly how an app stops looking like Kotton.
            if guest {
                if let Some(hex) = literal_colour(line) {
                    findings.push(format!(
                        "{rel_s}:{}: writes the literal colour `{hex}`. A guest surface reaches \
                         for a token — `var(--color-surface)`, `var(--color-text)` — so that it \
                         still looks like Kotton after the palette moves.",
                        n + 1
                    ));
                }
            }
            // A reference to a design value that does not exist. Checked in
            // every sheet, root scope or not, because the failure has nothing to
            // do with where the reference sits.
            for name in token_refs(line) {
                if NAMESPACES.iter().any(|ns| name.starts_with(ns)) && !declared.contains(&name) {
                    findings.push(format!(
                        "{rel_s}:{}: reads `var({name})`, which {SOURCE} does not declare. CSS \
                         drops the declaration silently, so this renders as almost-right rather \
                         than as an error.",
                        n + 1
                    ));
                }
            }
            for (selector, decl) in scope.declarations_in(line) {
                if root_scope(&selector) && NAMESPACES.iter().any(|ns| decl.starts_with(ns)) {
                    findings.push(format!(
                        "{rel_s}:{}: `{selector}` declares `{decl}` — a design value lives in \
                         {SOURCE} or it does not exist. Reach for it with `var({decl})`.",
                        n + 1
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        println!(
            "token-block-check: OK — {} stylesheet(s) scanned: {SOURCE} is the only one that \
             declares a design value, no guest sheet writes a literal colour, and every \
             `var(--)` reference names one of {} tokens it declares.",
            sheets.len(),
            declared.len()
        );
        return;
    }
    eprintln!("token-block-check: {} finding(s).\n", findings.len());
    for f in &findings {
        eprintln!("  {f}");
    }
    eprintln!(
        "\nA second definition is not a shortcut. It is how one surface starts looking like a\n\
         different product from the system it was built from — see ui/README.md."
    );
    std::process::exit(1);
}

/// Every property name a line declares.
///
/// Deliberately crude, and it only has to be right about the left-hand side: a
/// declaration is `--name:` at the start of a statement. `var(--name)` never
/// matches because the `--` is not the first thing after `{` or `;`.
///
/// **Per statement, not per line.** The first draft returned one name per line
/// and `tokens.css` writes ramps four to a line — `--space-0: 0;  --space-1:
/// 4px;  --space-2: 8px;` — so three quarters of the palette was invisible to
/// this gate. The reference rule below caught it immediately, by reporting 218
/// tokens as undeclared that are declared on line 209. The gate that reads the
/// source has to read all of it.
fn declarations(line: &str) -> Vec<&str> {
    line.split([';', '{'])
        .filter_map(|stmt| {
            let t = stmt.trim_start();
            if !t.starts_with("--") {
                return None;
            }
            let name = t.split(':').next()?.trim();
            (!name.is_empty() && name.len() > 2).then_some(name)
        })
        .collect()
}

/// The first property name a line declares — what a per-line report quotes.
fn declaration(line: &str) -> Option<&str> {
    declarations(line).into_iter().next()
}

/// Every design value `ui/tokens.css` declares, by name.
fn declared_tokens(source: &str) -> std::collections::HashSet<String> {
    source
        .lines()
        .flat_map(declarations)
        .map(str::to_owned)
        .collect()
}

/// Every `var(--name)` a line reads.
fn token_refs(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find("var(") {
        rest = &rest[i + 4..];
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if name.starts_with("--") {
            out.push(name);
        }
    }
    out
}

/// The literal colour a line writes, if it writes one.
///
/// Hex, `rgb(`/`rgba(`, `hsl(`/`hsla(`. Deliberately not every colour keyword:
/// `transparent`, `inherit` and `currentColor` are structural rather than a
/// palette choice, and flagging them would teach people to ignore this.
fn literal_colour(line: &str) -> Option<String> {
    let t = line.trim();
    if t.starts_with("/*") || t.starts_with("*") || t.starts_with("//") {
        return None;
    }
    // A line *declaring* a custom property is a token, and tokens are the first
    // rule's business — including the two alternate ramps `style.css` declares
    // under `.warmth-half` and `.warmth-quarter` so the gallery can put three
    // chroma levels side by side. Those are the design work this gate protects.
    // What this rule is about is a *component* writing a colour: `background:
    // #f4f1ea`, which is how an app stops looking like Kotton.
    if declaration(t).is_some_and(|d| d.starts_with("--")) {
        return None;
    }
    let bytes = t.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' {
            let hex: String = t[i + 1..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            // `#id` selectors are not colours; a colour is 3, 4, 6 or 8 digits
            // and is followed by something that ends a value.
            if matches!(hex.len(), 3 | 4 | 6 | 8) {
                let after = t[i + 1 + hex.len()..].chars().next().unwrap_or(';');
                if matches!(after, ';' | ' ' | ')' | ',' | '}') {
                    return Some(format!("#{hex}"));
                }
            }
        }
    }
    for f in ["rgb(", "rgba(", "hsl(", "hsla("] {
        if let Some(i) = t.find(f) {
            let end = t[i..].find(')').map(|e| i + e + 1).unwrap_or(t.len());
            return Some(t[i..end].to_string());
        }
    }
    None
}

/// Which selector the reader is inside, carried across lines.
///
/// The first draft was a `String` updated by an `opens_block` that only matched a
/// line **ending** in `{`. So `:root { --color-x: red; }` — one line, a complete
/// rule — opened no block this gate could see, its declaration was attributed to
/// whatever selector came before it, and a second token block written that way
/// passed clean. The whole point of the check is that a second definition cannot
/// be written; "not on one line" was not the rule.
///
/// It walks segments broken at `{` and `}` instead. Depth is deliberately not
/// tracked: `@media (...) { :root { ... } }` should report `:root`, and taking
/// the most recently opened selector gives that.
#[derive(Default)]
struct Scope {
    /// The selector text accumulated since the last `{` or `}` — a selector may
    /// span lines.
    pending: String,
    /// The selector of the innermost block opened so far.
    current: String,
}

impl Scope {
    /// Every `(selector, declaration)` this line contributes, advancing the scope.
    fn declarations_in(&mut self, line: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut rest = line;
        loop {
            let brace = rest.find(['{', '}']);
            let (before, sep, after) = match brace {
                Some(i) => (&rest[..i], rest.as_bytes()[i], &rest[i + 1..]),
                None => (rest, 0u8, ""),
            };
            // Text before a brace is either declarations (inside a block) or
            // selector text (between blocks). It is both often enough —
            // `.a { color: red } .b {` — that the cheap way to tell them apart
            // is to try each: a `--name:` statement is a declaration, and
            // whatever is left contributes to the next selector.
            for d in declarations(before) {
                out.push((self.current.clone(), d.to_owned()));
            }
            self.pending.push_str(before);
            match sep {
                b'{' => {
                    let sel = self.pending.trim();
                    // `--x: {` is not a selector; nor is the tail of a
                    // declaration list. A selector is what precedes an opening
                    // brace with no `:` ... `;` statement in it.
                    let sel = sel.rsplit(';').next().unwrap_or(sel).trim();
                    if !sel.is_empty() && !sel.starts_with("--") {
                        self.current = sel.to_owned();
                    }
                    self.pending.clear();
                }
                b'}' => {
                    self.pending.clear();
                    self.current.clear();
                }
                _ => return out,
            }
            rest = after;
        }
    }
}

/// Whether a selector defines the system rather than one component's corner of it.
fn root_scope(selector: &str) -> bool {
    let s = selector.trim();
    s.split(',').map(str::trim).any(|part| {
        part.starts_with(":root")
            || part == "html"
            || part == "body"
            || part.starts_with("[data-theme")
            || part.starts_with("[data-form-factor")
            // The third axis (2026-09-21,
            // `TASK-an-increased-contrast-theme-is-one-more-block`). A block on
            // `[data-contrast="more"]` defines the system for everything below
            // it exactly as a theme block does, so a second palette written
            // there is the `ink.css` failure with a newer selector.
            || part.starts_with("[data-contrast")
    })
}

/// Every stylesheet in the repository: the ones git tracks, the ones it would track
/// (untracked and not ignored), and the staged copy, which is ignored and still checked.
///
/// **Asked of git, not walked.** This walked the filesystem from `.` with a list of
/// directories to skip — `target`, `.git`, `node_modules`, `gallery`, `prebuilt`, each added
/// after something was found the hard way — and the list never named `.claude/worktrees`, so
/// from the primary checkout it reported every linked worktree's `ui/tokens.css` 105
/// times while every agent inside a worktree saw green
/// (`TASK-token-block-check-walks-into-sibling-worktrees`). A deny-list of places that are
/// not the repository needs a new entry whenever a new kind of output appears — `out/`
/// would have been the sixth. What the repository *is* is enumerable, and git already
/// answers it: worktrees, build output and every ignored copy are excluded by
/// construction, so the verdict is the same from every checkout of one commit.
fn stylesheets() -> Vec<PathBuf> {
    let listed = std::process::Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.css"])
        .output();
    let listed = match listed {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            eprintln!(
                "token-block-check: `git ls-files` failed, so there is nothing to check against: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("token-block-check: cannot run git: {e}");
            std::process::exit(1);
        }
    };
    let mut sheets: Vec<PathBuf> = listed
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(String::from_utf8_lossy(p).into_owned()))
        // A tracked file deleted in the working tree is still listed by `--cached`.
        .filter(|p| p.is_file())
        .collect();
    // The staged copy is `.gitignore`d because `cargo xtask build-web` writes it, and it is
    // exactly the one ignored file this gate must read: it may declare, and must match.
    if Path::new(STAGED).is_file() && !sheets.iter().any(|p| p == Path::new(STAGED)) {
        sheets.push(PathBuf::from(STAGED));
    }
    sheets
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The door's timer is the token file's number**, so the row and the daemon cannot
    /// disagree about how long ten minutes is: `--door-open-minutes` in `ui/tokens.css` is
    /// `kotton_peer::local_door::DOOR_OPEN_FOR`. Held here, where the token file is, and not
    /// in `kotton-peer`, because a release of the daemon ships without `ui/`.
    #[test]
    fn the_door_timer_is_the_token_files_number() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent");
        let tokens = std::fs::read_to_string(root.join(SOURCE)).expect("ui/tokens.css is readable");
        let at = tokens
            .find("--door-open-minutes:")
            .expect("ui/tokens.css carries --door-open-minutes");
        let rest = &tokens[at + "--door-open-minutes:".len()..];
        let minutes: u64 = rest[..rest.find(';').expect("a ; ends the value")]
            .trim()
            .parse()
            .expect("a whole number of minutes");
        assert_eq!(
            std::time::Duration::from_secs(minutes * 60),
            kotton_peer::local_door::DOOR_OPEN_FOR
        );
    }

    /// Every `(selector, declaration)` a sheet contributes, as the gate sees it.
    fn scoped(css: &str) -> Vec<(String, String)> {
        let mut scope = Scope::default();
        css.lines().flat_map(|l| scope.declarations_in(l)).collect()
    }

    /// What the gate would report against rule 1: a design value declared in a
    /// root scope somewhere that is not the source.
    fn second_blocks(css: &str) -> Vec<String> {
        scoped(css)
            .into_iter()
            .filter(|(sel, decl)| {
                root_scope(sel) && NAMESPACES.iter().any(|ns| decl.starts_with(ns))
            })
            .map(|(_, decl)| decl)
            .collect()
    }

    /// **The hole that shipped.** `opens_block` matched only a line *ending* in
    /// `{`, so a complete rule written on one line opened no block the gate could
    /// see and its declaration was attributed to whatever came before. A second
    /// token block was one newline away from passing.
    #[test]
    fn a_token_block_written_on_one_line_is_caught() {
        assert_eq!(
            second_blocks(":root { --color-rogue: red; }"),
            ["--color-rogue"]
        );
    }

    #[test]
    fn a_token_block_written_across_lines_is_caught() {
        assert_eq!(
            second_blocks(":root {\n  --color-rogue: red;\n}"),
            ["--color-rogue"]
        );
    }

    /// **The other hole.** `tokens.css` writes ramps four to a line, and the
    /// first parser returned one name per line — so three quarters of the palette
    /// was invisible both as a declaration to report and as a token to check a
    /// reference against.
    #[test]
    fn every_declaration_on_a_line_is_seen_not_just_the_first() {
        assert_eq!(
            second_blocks(":root {\n  --color-a: red; --color-b: blue;\n}"),
            ["--color-a", "--color-b"]
        );
        assert!(declared_tokens("  --space-1: 4px;  --space-2: 8px;").contains("--space-2"));
    }

    /// Every axis the token file branches on is a root scope, including the
    /// one added last.
    ///
    /// A second palette does not have to be written under `:root` to be a
    /// second palette: `[data-contrast="more"]` re-maps the system for
    /// everything below it the way a theme does, and a sheet that declared one
    /// would be `ink.css` again with a newer selector. Pinned rather than
    /// trusted, because the cost of missing an axis here is a gate that passes
    /// while the thing it exists to stop is in the tree.
    #[test]
    fn every_branching_axis_counts_as_a_root_scope() {
        for selector in [
            ":root",
            "html",
            "[data-theme=\"light\"]",
            ":root[data-form-factor=\"handheld\"]",
            "[data-theme=\"light\"][data-contrast=\"more\"]",
            ":root, [data-theme], [data-form-factor], [data-contrast]",
        ] {
            assert!(root_scope(selector), "`{selector}` should be a root scope");
        }
        assert!(!root_scope(".thing"));
        assert!(!root_scope(".warmth-half"));
        assert_eq!(
            second_blocks("[data-contrast=\"more\"] { --color-rogue: red; }"),
            ["--color-rogue"]
        );
    }

    /// A wrapped at-rule reports the inner selector, which is the one that says
    /// whether this is the system or a component.
    #[test]
    fn a_root_scope_nested_in_an_at_rule_is_caught() {
        let css = "@media (min-width:1px) { [data-theme=\"dark\"] { --color-rogue: red; } }";
        assert_eq!(second_blocks(css), ["--color-rogue"]);
    }

    /// The control that makes the four above mean something: a component's own
    /// custom property is not a design value and is nobody's business here. If
    /// this ever goes red the gate has started crying wolf, and a gate that
    /// cries wolf gets switched off.
    #[test]
    fn a_component_scope_is_not_a_second_definition() {
        assert!(second_blocks(".thing { --color-rogue: red; }").is_empty());
        assert!(
            second_blocks(":root { --color-a: red; }\n.thing { --color-b: blue; }")
                .iter()
                .eq(["--color-a"].iter())
        );
    }

    /// Rule 3, both ways. A name the source declares resolves; a typo of it does
    /// not — and CSS answers a typo by dropping the declaration in silence.
    #[test]
    fn a_reference_is_checked_against_what_the_source_declares() {
        let source = ":root {\n  --color-text: #fff; --color-text-tertiary: #888;\n}";
        let declared = declared_tokens(source);
        assert!(declared.contains("--color-text-tertiary"));
        assert!(!declared.contains("--color-text-tertiery"));
        assert_eq!(
            token_refs("  color: var(--color-text-tertiary);"),
            ["--color-text-tertiary"]
        );
        assert_eq!(
            token_refs("  padding: var(--space-2) var(--space-3);"),
            ["--space-2", "--space-3"]
        );
    }

    /// Rule 2. A guest writing a colour is caught; the structural keywords and a
    /// token *declaration* are not, or the rule would be noise.
    #[test]
    fn a_guest_colour_is_a_literal_and_a_token_is_not() {
        assert_eq!(
            literal_colour("  background: #f4f1ea;").as_deref(),
            Some("#f4f1ea")
        );
        assert_eq!(
            literal_colour("  color: rgb(12, 34, 56);").as_deref(),
            Some("rgb(12, 34, 56)")
        );
        assert!(literal_colour("  background: var(--color-bg);").is_none());
        assert!(literal_colour("  background: transparent;").is_none());
        // `#bar` is an id selector, not a three-digit hex.
        assert!(literal_colour("#bar {").is_none());
    }
}
