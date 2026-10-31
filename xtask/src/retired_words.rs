// SPDX-License-Identifier: AGPL-3.0-or-later
//! `verb-check`'s sweep: no line a person reads names a word a verb table retired, except to
//! point from it to the word that replaced it.
//!
//! A noun's verb table (`kotton_shell::Command::verbs`) is where a word is retired: `sync now`
//! is kept as an alias of `sync`, `sync add` is gone for `pin`, `device admit` is gone for
//! `drive enrol`. The tree then runs or refuses the old word by name, and
//! `verb-check` holds that. What the table cannot hold is the copy written before the
//! retirement: a hint, a help line, an error that still tells a person to type the old word.
//! That copy runs (an alias answers it, with a line saying it is deprecated) or exits 2 (a
//! gone word), and either way it teaches the word the tree has stopped answering for. This
//! sweep refuses it, so the next retirement cannot leave one behind.
//!
//! **Why it is `verb-check`'s and not `host-word-check`'s or `claim-check`'s.** The words it
//! refuses are not a list of its own: they are every `Alias` and `Gone` entry of every table
//! the REPL's registry declares, read where `verb-check` already reads them, so a word retired
//! tomorrow is refused tomorrow with no second list to keep. `host-word-check` refuses a fixed
//! vocabulary and builds without the command trees; `claim-check` holds that a command a page
//! gives is one the binary has, and an alias is one it has. A guard filed under either would
//! need its own copy of the tables, which is the stale list this exists to prevent. It reads
//! with `host-word-check`'s reader — the same files ([`crate::host_word_check::paths_read`])
//! and the same literal lexer — so "what a person reads" means one thing in both.
//!
//! **What a person reads.** Every line of the pages `host-word-check` reads whole (the root
//! `*.md`, `infra/release/`, `infra/*/README.md`, the generated CLI reference), and every
//! string literal of the Rust trees it reads for literals (the shell, the CLI, `xtask`, the
//! relay, every crate under `core/` but `kuid`), as it prints: a `\` at a line's end joins
//! the next line, a `\n` escape breaks one. A comment and an identifier are not read, and
//! neither is the argument vector a program builds word by word (`&["sync", "now"]`): one
//! literal is one thing a person can be shown, and a word split across two is not a line.
//!
//! **What it names.** A retired word is the noun and the word, whole (`sync now`, `kotton sync
//! now`, `sync add|list|remove`; not `async now`, `sync nowhere` or `sync now-ish`). A
//! placeholder (`sync <remote>`) and the bare noun are not words a sentence can name. Case does
//! not matter (`Device admit` opens a sentence), and the gap between noun and word is any run
//! of Unicode whitespace (a no-break space, a tab), as a person reads it.
//!
//! **What may name one.** A line that points from it to its replacement: the line also holds a
//! backticked command that starts with the word the table names in its place (`` `sync now`
//! is `sync` ``, `` `device admit` was the name of `drive enrol <invite>` ``). The command must be
//! the replacement whole: `drive enrol` for `device admit`, `pin list` for `sync list`. Where
//! the replacement is a bare noun the retired word's own (`sync now` is `sync`), any command of
//! that noun counts, since the noun alone is the answer (`sync <remote>` is one). Where it is a
//! different bare noun (`sync add` is `pin`), the command must carry an argument
//! (`pin <drive>`): the noun alone leaves the reader to find its verb. The advice
//! says it with the placeholder of that noun's table (`pin <drive>`), or `<argument>` for a noun
//! whose table has none. The argument is a
//! word that is neither a flag nor one of that noun's current verbs, which the tables hold
//! (`pin list` and `pin --help` are other answers, not the one `sync add` got). That is the only
//! reason to say a retired word, and it is how the help and the reference say it. And the
//! first argument of the shell's two helpers that answer a retired word ([`HELPERS`]:
//! `deprecated(was, now)` and `retired(was, now)`), which print the replacement beside it.
//! A verb table names a retired word alone (`Verb::alias("now", "sync")`), not as a noun and
//! a word, so it is not read as one.
//!
//! **On a help page, the bare word names it.** A page's section headed by the noun's own
//! command (`` ## `Kotton device` ``, as the generated reference heads each `--help`) is that
//! noun's page: its `about`, its arguments and its shell help all speak of the noun, so a
//! backticked span opening on a word the noun's table retired (`` `admit <invite>` ``) names
//! that word as surely as `device admit` does. Only a backticked span counts, since the words
//! retired are ordinary ones (`now`, `list`) that prose uses for other things.
//!
//! **What a line says of a retired word's fate is not read here.** Whether a word still runs
//! (`Alias`) or is refused (`Gone`) is the table's, and the one place that states it for every
//! word, a noun's help, is generated from the table: `kotton_shell::CommandRegistry::help_of`
//! prints the noun's `help_text` and then a `RETIRED:` block built from its verbs, in both doors
//! and in the generated reference, and two tests hold that no `help_text` and no clap `about` or
//! argument help writes a sentence about a retired word of its own noun. #207 asked this sweep to
//! also read the fate a sentence gives a word; a phrase list read up to the next retired word
//! refused true lines (`` `sync now` is `sync`; `sync <remote>` is gone ``, `` `device admit` is
//! gone (`drive enrol <invite>` is run instead) ``), since it charged the word with what the
//! sentence said of its replacement, a placeholder form or a negation. That is the lesson from the
//! closed verb-check prose heuristic: a prose reading moves the misread rather than removing it.
//! So the fate is held by construction where it is stated, and prose outside the help is read
//! only for whether it points to the replacement.
//!
//! **What it does not read.** [`NOT_READ`]: the files whose subject is the retired words
//! themselves. And [`STILL_RUNS`]: a printed line that names a retired word because the
//! code beside it still runs it, each with the issue that moves it. An entry is the line's exact
//! text, not its file, so a new literal saying the word in the same file is read; an entry whose
//! line is gone or edited is refused, naming the text it looked for: re-key it or drop it, so the
//! list only shrinks.

use std::collections::BTreeMap;
use std::path::Path;

use crate::verb_check::Is;

/// The shell's helpers that answer a retired word: the literal that is their first argument is
/// the word typed, printed beside its replacement (`client/shell/src/commands/mod.rs`).
pub const HELPERS: &[&str] = &["deprecated", "retired"];

/// Files whose subject is the retired words, each with why.
pub const NOT_READ: &[(&str, &str)] = &[
    (
        "xtask/src/verb_check.rs",
        "its fixture is the command-tree decision's Today column, which lists the retired words",
    ),
    ("xtask/src/retired_words.rs", "its tests plant the words"),
];

/// A printed line that names a retired word because the code beside it still runs it: the file,
/// the word, the line's exact text (what the literal prints, trimmed), and the issue that moves
/// it off the word. Keyed on the line and not the file, so a new literal saying the word in the
/// same file is read.
pub const STILL_RUNS: &[(&str, &str, &str, &str)] = &[
    ("xtask/src/main.rs", "sync add", "sync add failed:", "#178: `demo::sync` still drives `sync add <path> --to <node>`"),
    ("xtask/src/main.rs", "sync now", "sync now failed:", "#178: `demo::sync` still drives `sync now`"),
];

/// A word a table retired: the noun, the word after it, what replaced it, and how it is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    pub noun: String,
    pub word: String,
    pub now: String,
    pub gone: bool,
    /// The current verbs of the noun `now` names (not placeholders): a word after that noun
    /// that is one of these is a verb, not the argument a bare replacement needs.
    pub now_verbs: Vec<String>,
    /// The first current placeholder entry of that noun's table (`<drive>` for `pin`), what a bare
    /// replacement is said with; `None` when the noun has none.
    pub now_placeholder: Option<String>,
}

impl Retired {
    /// The noun and the word, as a person types them: `sync now`.
    pub fn was(&self) -> String {
        format!("{} {}", self.noun, self.word)
    }

    /// Whether the replacement is another noun, bare (`sync add` -> `pin`): the noun whose verb
    /// the reader must still pick, so a command naming it needs an argument.
    fn bare_other(&self) -> bool {
        let mut now = self.now.split_whitespace();
        now.next().is_some_and(|n| !n.eq_ignore_ascii_case(&self.noun)) && now.next().is_none()
    }

    /// The command a finding tells a person to say: a line the rule accepts. A bare other noun
    /// is said with an argument, the placeholder of that noun's table (`pin <drive>`), or `<argument>`
    /// when the table holds none, since the noun alone is refused.
    pub fn suggestion(&self) -> String {
        if self.bare_other() {
            format!("{} {}", self.now, self.now_placeholder.as_deref().unwrap_or("<argument>"))
        } else {
            self.now.clone()
        }
    }
}

/// Every word the tables retire, but placeholders and the bare noun, in table order.
pub fn retired(tables: &BTreeMap<String, Vec<(String, Is)>>) -> Vec<Retired> {
    let mut out = Vec::new();
    for (noun, table) in tables {
        for (word, is) in table {
            if word.is_empty() || word.starts_with('<') {
                continue;
            }
            let (now, gone) = match is {
                Is::Current => continue,
                Is::Alias(now) => (now, false),
                Is::Gone(now) => (now, true),
            };
            let target = now.split_whitespace().next().unwrap_or_default();
            let now_verbs = tables
                .get(target)
                .map(|t| {
                    t.iter()
                        .filter(|(w, is)| matches!(is, Is::Current) && !w.is_empty() && !w.starts_with('<'))
                        .map(|(w, _)| w.to_lowercase())
                        .collect()
                })
                .unwrap_or_default();
            let now_placeholder = tables
                .get(target)
                .and_then(|t| t.iter().find(|(w, is)| matches!(is, Is::Current) && w.starts_with('<')))
                .map(|(w, _)| w.clone());
            out.push(Retired { noun: noun.clone(), word: word.clone(), now: now.clone(), gone, now_verbs, now_placeholder });
        }
    }
    out
}

/// `file:line: what` for every line a person reads that names a retired word and not its
/// replacement, and for every [`STILL_RUNS`] entry that is stale.
pub fn findings(root: &Path, retired: &[Retired]) -> Vec<String> {
    let mut out = Vec::new();
    let mut used = vec![false; STILL_RUNS.len()];
    for rel in crate::host_word_check::paths_read(root) {
        if NOT_READ.iter().any(|(p, _)| *p == rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else { continue };
        let lines: Vec<(Printed, Option<String>)> = if rel.ends_with(".rs") {
            printed(&text).into_iter().map(|p| (p, None)).collect()
        } else {
            let mut subject = None;
            text.lines()
                .enumerate()
                .map(|(i, l)| {
                    if let Some(heading) = section_heading(l) {
                        subject = heading;
                    }
                    ((l.chars().collect(), vec![i + 1; l.chars().count()]), subject.clone())
                })
                .collect()
        };
        for ((chars, at), subject) in lines {
            let line_text: String = chars.iter().collect();
            for (i, r) in unpointed(&chars, retired, subject.as_deref()) {
                let was = r.was();
                if let Some(k) = STILL_RUNS.iter().position(|(p, w, l, _)| *p == rel && *w == was && *l == line_text.trim()) {
                    used[k] = true;
                    continue;
                }
                let kept = if r.gone { "refuses it, exit 2" } else { "still runs it as an alias" };
                out.push(format!(
                    "{rel}:{}: says `{was}`, a word `{}`'s verb table retired for `{}` (the tree {kept}): \
                     say `{}`, or name it beside the old word",
                    at[i], r.noun, r.now, r.suggestion()
                ));
            }
        }
    }
    for (k, (path, word, text, why)) in STILL_RUNS.iter().enumerate() {
        if !used[k] {
            out.push(format!(
                "{path}: listed as still running `{word}` ({why}), but no printed line there reads `{text}` with it: \
                 re-key the entry to the line's new text, or drop it"
            ));
        }
    }
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// `c` lower-cased, one char to one char (a char whose lower case is longer keeps its first).
fn lower(c: &[char]) -> Vec<char> {
    c.iter().map(|c| c.to_lowercase().next().unwrap_or(*c)).collect()
}

/// Whether `chars` holds `needle` (already lower-cased) at `at`, in any case.
fn matches_at(chars: &[char], at: usize, needle: &[char]) -> bool {
    chars.get(at..at + needle.len()).is_some_and(|w| lower(w) == needle)
}

/// The subject a page's heading line opens, when it is one of level one or two: `Some(noun)`
/// for a heading that is the noun's own command (`` ## `Kotton device` ``), `Some(None)` for any
/// other, which ends the section before it; `None` for a line that is no such heading.
fn section_heading(line: &str) -> Option<Option<String>> {
    let level = line.chars().take_while(|c| *c == '#').count();
    if !(1..=2).contains(&level) || !line[level..].starts_with(' ') {
        return None;
    }
    let title = line[level..].trim();
    let words: Vec<&str> = title.strip_prefix('`').and_then(|t| t.strip_suffix('`')).unwrap_or("").split_whitespace().collect();
    Some(match words.as_slice() {
        [kotton, noun] if kotton.eq_ignore_ascii_case("kotton") => Some(noun.to_lowercase()),
        _ => None,
    })
}

/// The backticked spans of `chars`, each as the index after its opening tick and of its
/// closing one.
fn backticked(chars: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(open) = chars[i..].iter().position(|c| *c == '`').map(|p| p + i) {
        let Some(close) = chars[open + 1..].iter().position(|c| *c == '`').map(|p| p + open + 1) else { break };
        out.push((open + 1, close));
        i = close + 1;
    }
    out
}

/// Each retired word `chars` names whole, as the index it starts at: the noun and the word,
/// and, on the page whose subject is the noun, the bare word opening a backticked span.
fn named(chars: &[char], retired: &[Retired], subject: Option<&str>) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (k, r) in retired.iter().enumerate() {
        if subject.is_some_and(|s| s.eq_ignore_ascii_case(&r.noun)) {
            let word = lower(&r.word.chars().collect::<Vec<_>>());
            for (open, _) in backticked(chars) {
                if matches_at(chars, open, &word) && !chars.get(open + word.len()).copied().is_some_and(is_word) {
                    out.push((open, k));
                }
            }
        }
        let noun = lower(&r.noun.chars().collect::<Vec<_>>());
        let word = lower(&r.word.chars().collect::<Vec<_>>());
        for i in 0..chars.len() {
            if (i > 0 && is_word(chars[i - 1])) || !matches_at(chars, i, &noun) {
                continue;
            }
            let mut j = i + noun.len();
            let gap = j;
            while chars.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            if j == gap || !matches_at(chars, j, &word) {
                continue;
            }
            if chars.get(j + word.len()).copied().is_some_and(is_word) {
                continue;
            }
            out.push((i, k));
        }
    }
    out
}

/// The retired words `chars` names without pointing to their replacement: each as the index
/// it starts at and the word.
fn unpointed<'a>(chars: &[char], retired: &'a [Retired], subject: Option<&str>) -> Vec<(usize, &'a Retired)> {
    let found = named(chars, retired, subject);
    if found.is_empty() {
        return Vec::new();
    }
    // The backticked commands of the line that are not themselves a retired word.
    let mut commands: Vec<Vec<String>> = Vec::new();
    for (open, close) in backticked(chars) {
        let span = &chars[open..close];
        if !named(span, retired, None).iter().any(|(at, _)| *at == 0 || span[..*at].iter().collect::<String>().trim().eq_ignore_ascii_case("kotton")) {
            let text: String = span.iter().collect();
            let mut words: Vec<String> = text.split_whitespace().map(str::to_string).collect();
            if words.first().is_some_and(|w| w.eq_ignore_ascii_case("kotton")) {
                words.remove(0);
            }
            commands.push(words);
        }
    }
    let mut out: Vec<(usize, &Retired)> = found
        .into_iter()
        .map(|(at, k)| (at, &retired[k]))
        .filter(|(_, r)| {
            let now: Vec<String> = r.now.split_whitespace().map(str::to_lowercase).collect();
            let bare_other = r.bare_other();
            // A replacement that is another noun, bare (`sync add` -> `pin`), is the noun
            // whose verb the reader must still pick: the command names it with an argument,
            // which is neither one of that noun's verbs (`pin list` is another answer) nor a
            // flag (`pin --help`, `pin -h`).
            commands.iter().all(|c| {
                let named = c.len() >= now.len() && c.iter().zip(&now).all(|(a, b)| a.to_lowercase() == *b);
                let argument = !bare_other
                    || c.get(1).is_some_and(|a| !a.starts_with('-') && !r.now_verbs.contains(&a.to_lowercase()));
                !(named && argument)
            })
        })
        .collect();
    out.sort_by_key(|(at, _)| *at);
    out
}

/// Whether the literal opening at `at` is the first argument of a call to one of [`HELPERS`].
fn helper_argument(c: &[char], at: usize) -> bool {
    let mut k = at;
    while k > 0 && c[k - 1].is_whitespace() {
        k -= 1;
    }
    if k == 0 || c[k - 1] != '(' {
        return false;
    }
    k -= 1;
    while k > 0 && c[k - 1].is_whitespace() {
        k -= 1;
    }
    HELPERS.iter().any(|h| {
        let h: Vec<char> = h.chars().collect();
        k >= h.len() && c[k - h.len()..k] == h[..] && !(k > h.len() && is_word(c[k - h.len() - 1]))
    })
}

/// A printed line: its characters, and the source line each is on.
type Printed = (Vec<char>, Vec<usize>);

/// The string literals of Rust source as they print, line by line, but the first argument of a
/// call to one of [`HELPERS`].
fn printed(src: &str) -> Vec<Printed> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    for (line, at) in crate::host_word_check::string_literal_starts(src) {
        if !helper_argument(&c, at) {
            out.extend(printed_literal(&c, at, line));
        }
    }
    out
}

/// The `\u{..}` or `\xNN` escape whose backslash is at `k`, as the char it prints and its
/// length in source chars; `None` when it is malformed (no closing brace within the literal, a
/// non-hex digit, more than six digits, a value that is no char, a `\x` above 0x7F), which
/// then prints as the default does and never reads past the digits.
fn escape(c: &[char], k: usize) -> Option<(char, usize)> {
    match c.get(k + 1)? {
        'u' => {
            if c.get(k + 2) != Some(&'{') {
                return None;
            }
            let close = (k + 3..(k + 3 + 11).min(c.len())).find(|&e| c[e] == '}')?;
            let hex: String = c[k + 3..close].iter().filter(|h| **h != '_').collect();
            if hex.is_empty() || hex.len() > 6 || !c[k + 3..close].iter().all(|h| h.is_ascii_hexdigit() || *h == '_') {
                return None;
            }
            Some((char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?, close + 1 - k))
        }
        'x' => {
            let hex: String = c.get(k + 2..k + 4)?.iter().collect();
            if !hex.chars().all(|h| h.is_ascii_hexdigit()) {
                return None;
            }
            let v = u8::from_str_radix(&hex, 16).ok().filter(|v| *v <= 0x7f)?;
            Some((char::from(v), 4))
        }
        _ => None,
    }
}

/// The literal opening at `at` (its `"`, or a raw string's `r`), on source line `line`, as the
/// lines it prints.
fn printed_literal(c: &[char], at: usize, mut line: usize) -> Vec<Printed> {
    let mut out: Vec<Printed> = vec![(Vec::new(), Vec::new())];
    let push = |out: &mut Vec<Printed>, ch: char, line: usize| {
        let last = out.last_mut().expect("one line at least");
        last.0.push(ch);
        last.1.push(line);
    };
    if c[at] == 'r' {
        let mut k = at + 1;
        while c.get(k) == Some(&'#') {
            k += 1;
        }
        let hashes = k - at - 1;
        k += 1;
        while k < c.len() {
            if c[k] == '"' && (1..=hashes).all(|h| c.get(k + h) == Some(&'#')) {
                break;
            }
            if c[k] == '\n' {
                line += 1;
                out.push((Vec::new(), Vec::new()));
            } else {
                push(&mut out, c[k], line);
            }
            k += 1;
        }
        return out;
    }
    let mut k = at + 1;
    while k < c.len() && c[k] != '"' {
        if c[k] == '\\' {
            match c.get(k + 1) {
                // A line continuation: the newline and the next line's leading space print nothing.
                Some('\n') | Some('\r') if c.get(k + 1) == Some(&'\n') || c.get(k + 2) == Some(&'\n') => {
                    k += 1;
                    while k < c.len() && c[k].is_whitespace() {
                        if c[k] == '\n' {
                            line += 1;
                        }
                        k += 1;
                    }
                    continue;
                }
                Some('n') => out.push((Vec::new(), Vec::new())),
                Some('u') if escape(c, k).is_some() => {
                    let (ch, len) = escape(c, k).expect("guarded");
                    push(&mut out, ch, line);
                    k += len;
                    continue;
                }
                Some('x') if escape(c, k).is_some() => {
                    let (ch, len) = escape(c, k).expect("guarded");
                    push(&mut out, ch, line);
                    k += len;
                    continue;
                }
                Some(e @ ('"' | '\\' | '\'')) => push(&mut out, *e, line),
                _ => push(&mut out, ' ', line),
            }
            k += 2;
            continue;
        }
        if c[k] == '\n' {
            line += 1;
            out.push((Vec::new(), Vec::new()));
        } else {
            push(&mut out, c[k], line);
        }
        k += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tables as the tree declares them: `sync`'s retired words, a placeholder among them,
    /// and `device`'s.
    fn tables() -> BTreeMap<String, Vec<(String, Is)>> {
        let mut t = BTreeMap::new();
        t.insert(
            "sync".to_string(),
            vec![
                ("".to_string(), Is::Current),
                ("now".to_string(), Is::Alias("sync".into())),
                ("add".to_string(), Is::Gone("pin".into())),
                ("list".to_string(), Is::Gone("pin list".into())),
                ("remove".to_string(), Is::Gone("pin".into())),
                ("<remote>".to_string(), Is::Gone("sync".into())),
            ],
        );
        // `device admit` is gone, as `client/shell/src/commands/device.rs` declares it.
        t.insert("device".to_string(), vec![("admit".to_string(), Is::Gone("drive enrol".into()))]);
        // `pin`'s table as the shell declares it (`client/shell/src/commands/pin.rs`).
        t.insert(
            "pin".to_string(),
            vec![("default".to_string(), Is::Current), ("<drive>".to_string(), Is::Current), ("list".to_string(), Is::Current)],
        );
        t
    }

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        // The files STILL_RUNS names, saying their words, so a fixture's findings are its own.
        let main = dir.path().join("xtask/src/main.rs");
        if !main.exists() {
            std::fs::create_dir_all(main.parent().unwrap()).unwrap();
            std::fs::write(main, "fn d() { bail!(\"sync add failed:\\n x\"); bail!(\"sync now failed:\\n x\"); }\n").unwrap();
        }
        dir
    }

    fn found(files: &[(&str, &str)]) -> Vec<String> {
        findings(tree(files).path(), &retired(&tables()))
    }

    #[test]
    fn the_retired_words_are_the_tables_alias_and_gone_entries_but_placeholders() {
        let words: Vec<String> = retired(&tables()).iter().map(Retired::was).collect();
        assert_eq!(words, ["device admit", "sync now", "sync add", "sync list", "sync remove"]);
    }

    /// **The line #186 found**, as it stood: a daemon's error naming `device admit` and not
    /// `drive enrol`, refused by file and line; and the line as it stands now passes.
    #[test]
    fn the_daemons_device_admit_hint_is_refused() {
        let before = "fn f() -> io::Error {\n    io::Error::other(\n        \"this is a vault's invite: it is admitted, not stood at — `device admit <invite> --blind`\",\n    )\n}\n";
        assert_eq!(
            found(&[("core/kuserd/src/agent/handlers/device_config.rs", before)]),
            vec![
                "core/kuserd/src/agent/handlers/device_config.rs:3: says `device admit`, a word `device`'s verb table \
                 retired for `drive enrol` (the tree refuses it, exit 2): say `drive enrol`, or name it beside the old word"
                    .to_string()
            ]
        );
        let after = before.replace("device admit", "drive enrol");
        assert_eq!(found(&[("core/kuserd/src/agent/handlers/device_config.rs", &after)]), Vec::<String>::new());
    }

    /// **The deprecation lines and the tables are not refused**: the first argument of
    /// `deprecated` and `retired`, through a path or not, and a table's words, which name the
    /// retired word alone. A function of another name, or the helper's second argument, is read.
    #[test]
    fn the_helpers_first_argument_and_the_tables_are_not_read() {
        let src = "\
const VERBS: &[Verb] = &[Verb::alias(\"now\", \"sync\"), Verb::gone(\"add\", \"pin\")];
const D: &[Verb] = &[Verb::alias(\"admit\", \"drive enrol\")];
fn f() {
    out.push(deprecated(\"sync now\", \"sync\"));
    answer.out.insert(0, super::deprecated(\"device admit\", \"drive enrol\"));
    let _ = retired (
        \"sync add\", PIN_IS);
    let _ = Err(retired(\"sync list\", PIN_IS));
}
";
        assert_eq!(found(&[("client/shell/src/commands/sync.rs", src)]), Vec::<String>::new());
        let src = "fn f() { not_deprecated(\"sync now\"); deprecated(\"x\", \"sync remove\"); }\n";
        let got = found(&[("client/shell/src/commands/sync.rs", src)]);
        assert_eq!(got.len(), 2, "{got:#?}");
        assert!(got[0].contains("says `sync now`") && got[1].contains("says `sync remove`"), "{got:#?}");
    }

    /// **A line that points from the old word to the new one passes; the pointer must be on
    /// the line.** A help table's row, a sentence joined by `\` over two source lines, a
    /// replacement with its arguments, and `kotton` before either. A `\n` breaks the line, so
    /// the replacement on the next printed line is not beside it; and the old word in
    /// backticks does not count as naming the new one.
    #[test]
    fn a_line_pointing_to_the_replacement_passes_and_must_hold_it() {
        let src = "\
const H: &str = \"\\
  sync now                 is `sync`, and still runs it
  sync add|remove          gone: what this device keeps of a drive is `pin <drive>`
  sync list                gone: what it keeps is listed by `pin list`
\";
const D: &str = \"A vault's invite is `drive enrol \\
     <invite>` (`device admit` was its name).\";
const K: &str = \"`kotton sync list` is `kotton pin list --json` now\";
";
        assert_eq!(found(&[("client/shell/src/commands/sync.rs", src)]), Vec::<String>::new());
        let src = "const H: &str = \"`sync now` runs it\\nthe verb is `sync`\";\nconst I: &str = \"type `sync now`\";\n";
        let got = found(&[("client/shell/src/commands/sync.rs", src)]);
        assert_eq!(got.len(), 2, "{got:#?}");
        assert!(got[0].starts_with("client/shell/src/commands/sync.rs:1: says `sync now`"), "{got:#?}");
        assert!(got[1].starts_with("client/shell/src/commands/sync.rs:2: says `sync now`"), "{got:#?}");
        // `sync add`'s replacement is `pin`, not `sync`.
        let got = found(&[("client/cli/src/x.rs", "const A: &str = \"`sync add` is `sync` now\";\n")]);
        assert_eq!(got.len(), 1, "{got:#?}");
    }

    /// **The word is the noun and the word, whole.**
    #[test]
    fn the_word_is_whole() {
        let src = "const A: &[&str] = &[\"async now\", \"sync nowhere\", \"sync now-ish\", \"resync add\", \"sync-add\", \"device admits\", \"syncnow\"];\n";
        assert_eq!(found(&[("client/cli/src/x.rs", src)]), Vec::<String>::new());
        let src = "const A: &[&str] = &[\"kotton sync now\", \"sync add|list\", \"sync  remove\", \"(device admit)\"];\n";
        let got = found(&[("client/cli/src/x.rs", src)]);
        assert_eq!(got.len(), 4, "{got:#?}");
    }

    /// **What is not a line a person reads is not read**: a comment, an identifier, the
    /// argument vector a program builds word by word, a placeholder's word, and a page
    /// outside the ones `host-word-check` reads.
    #[test]
    fn a_comment_an_identifier_an_argv_and_an_unread_page_are_not_read() {
        let src = "\
/// `sync now` was the verb.
// device admit
fn sync_now() { run(&[\"sync\", \"now\", \"--user\", \"demo\"]); let _ = \"sync <remote>\"; }
";
        assert_eq!(
            found(&[
                ("client/cli/src/x.rs", src),
                ("docs/design/sync.md", "Type `sync now`.\n"),
                ("core/kuid/src/main.rs", "const A: &str = \"sync now\";\n"),
            ]),
            Vec::<String>::new()
        );
    }

    /// **A page is read line by line**, as the reference and the root pages print.
    #[test]
    fn a_page_is_read_line_by_line() {
        let got = found(&[
            ("README.md", "# Kotton\n\nThen run `kotton sync now`.\n"),
            ("docs/cli/reference.md", "  sync now                 is `sync`, and still runs it\n"),
            ("infra/release/README.txt", "Run `device admit <invite>`\nthen `drive enrol`.\n"),
        ]);
        assert_eq!(got.len(), 2, "{got:#?}");
        assert!(got[0].starts_with("README.md:3: says `sync now`"), "{got:#?}");
        assert!(got[1].starts_with("infra/release/README.txt:1: says `device admit`"), "{got:#?}");
    }

    /// **A file whose subject is the words is not read, and an entry that still runs one is
    /// held to it**: once the file no longer says the word, the entry is refused.
    #[test]
    fn the_files_not_read_and_a_stale_still_runs_entry() {
        assert_eq!(found(&[("xtask/src/verb_check.rs", "const T: &str = \"| `sync now` | `sync` |\";\n")]), Vec::<String>::new());
        let got = found(&[("xtask/src/main.rs", "fn d() { bail!(\"sync now failed:\\n x\"); }\n")]);
        assert_eq!(got.len(), 1, "{got:#?}");
        assert!(got[0].starts_with("xtask/src/main.rs: listed as still running `sync add`"), "{got:#?}");
    }

    /// **A finding's own suggestion is a line the sweep accepts**, for every retired word, and
    /// for a bare other noun it is the noun with an argument, not the noun alone.
    #[test]
    fn a_findings_suggestion_is_a_line_the_rule_accepts() {
        let t = tables();
        for r in retired(&t) {
            let got = found_with(&t, &format!("type `{}`\n", r.was()));
            assert_eq!(got.len(), 1, "{got:#?}");
            let say = got[0].split("say `").nth(1).and_then(|s| s.split('`').next()).expect("a suggestion");
            let composed = found_with(&t, &format!("`{}` is `{say}`\n", r.was()));
            assert!(composed.is_empty(), "{}: the suggestion `{say}` is refused: {composed:#?}", r.was());
        }
        let got = found_with(&t, "type `sync add`\n");
        assert!(got[0].contains("say `pin <drive>`"), "{got:#?}");
        // A noun whose table holds no placeholder falls back to `<argument>`.
        let mut bare = tables();
        bare.get_mut("pin").unwrap().retain(|(w, _)| !w.starts_with('<'));
        let got = found_with(&bare, "type `sync add`\n");
        assert!(got[0].contains("say `pin <argument>`"), "{got:#?}");
        // A retired placeholder listed first (`sync`'s `<remote>` is gone) is not the advice: the
        // first current one is.
        let mut t = tables();
        t.insert("vault".to_string(), vec![("<old>".to_string(), Is::Gone("pin".into())), ("<name>".to_string(), Is::Current)]);
        t.insert("drive".to_string(), vec![("open".to_string(), Is::Gone("vault".into()))]);
        let got = found_with(&t, "type `drive open`\n");
        assert!(got[0].contains("say `vault <name>`"), "{got:#?}");
        assert!(found_with(&t, "`drive open` is `vault <name>`\n").is_empty());
    }

    /// **A STILL_RUNS entry whose line was edited names the text it looked for**, and says to
    /// re-key or drop it; the edited line is itself refused.
    #[test]
    fn an_edited_still_runs_line_names_the_text_looked_for() {
        let main = "fn d() { bail!(\"sync add failed again:\\n x\"); bail!(\"sync now failed:\\n x\"); }\n";
        let got = found(&[("xtask/src/main.rs", main)]);
        assert_eq!(got.len(), 2, "{got:#?}");
        assert!(got[0].starts_with("xtask/src/main.rs:1: says `sync add`"), "{got:#?}");
        assert!(got[1].contains("`sync add failed:`") && got[1].contains("re-key"), "{got:#?}");
    }

    /// **Case and whitespace are not a way round**: a sentence-start capital, a no-break space
    /// and a tab between noun and word are the words, and are refused.
    #[test]
    fn case_and_any_whitespace_gap_are_the_word() {
        let src = "const A: &[&str] = &[\"Device admit <invite>\", \"sync\u{a0}now\", \"SYNC\\u{2003}Add\", \"sync\tremove\", \"device\\u{2003}admit\", \"sync\\x20now\"];\n";
        let got = found(&[("client/cli/src/x.rs", src)]);
        let said: Vec<&str> = got.iter().map(|g| g.split('`').nth(1).unwrap()).collect();
        assert_eq!(said, ["device admit", "sync now", "sync add", "sync remove", "device admit", "sync now"], "{got:#?}");
        let page = found(&[("README.md", "Sync\tnow, then\nDevice admit it.\nSync  Now\n")]);
        assert_eq!(page.len(), 3, "{page:#?}");
        assert!(page[0].starts_with("README.md:1: says `sync now`"), "{page:#?}");
        // Whole-word still holds in any case.
        assert_eq!(found(&[("README.md", "Async now, SYNC NOWHERE\n")]), Vec::<String>::new());
    }

    /// **A CRLF file prints as an LF one**: `\` before `\r\n` joins the lines, so noun and word
    /// across the continuation are one line.
    #[test]
    fn a_crlf_continuation_joins_the_lines() {
        let src = "const A: &str = \"type `sync \\\r\n     now`\";\nconst B: &str = \"`sync \\\r\n  now` is `sync`\";\n";
        assert!(src.contains("\\\r\n"));
        let got = found(&[("client/cli/src/x.rs", src)]);
        assert_eq!(got.len(), 1, "{got:#?}");
        assert!(got[0].starts_with("client/cli/src/x.rs:1: says `sync now`"), "{got:#?}");
    }

    /// **STILL_RUNS exempts a line, not a file**: the two `demo::sync` lines pass; a new
    /// literal in the same file saying either word is refused.
    #[test]
    fn still_runs_is_the_line_not_the_file() {
        let main = "fn d() { bail!(\"sync add failed:\\n x\"); bail!(\"sync now failed:\\n x\"); }\nfn n() { hint(\"run sync add first\"); hint(\"then `sync now`\"); }\n";
        let got = found(&[("xtask/src/main.rs", main)]);
        assert_eq!(got.len(), 2, "{got:#?}");
        assert!(got.iter().all(|g| g.starts_with("xtask/src/main.rs:2: says")), "{got:#?}");
    }

    /// **The pointer is the replacement whole.** "run `sync now` or `sync <remote>`" passes
    /// (the replacement is the bare noun); a `sync add` line naming only `pin` is refused, and
    /// one naming `pin <drive>` passes; a verbed replacement needs its verb.
    #[test]
    fn the_pointer_is_the_replacement_whole() {
        let ok = |s: &str| found(&[("README.md", s)]);
        assert_eq!(ok("run `sync now` or `sync <remote>`\n"), Vec::<String>::new());
        assert_eq!(ok("`sync add` is `pin <drive> whole`\n"), Vec::<String>::new());
        assert_eq!(ok("`sync add` is `pin <drive>`\n"), Vec::<String>::new());
        assert_eq!(ok("`sync add` is `kotton pin <drive> on-demand`\n").len(), 0);
        assert_eq!(ok("`sync add` is `pin`\n").len(), 1);
        assert_eq!(ok("`sync add` is gone: use `pin list`\n").len(), 1);
        assert_eq!(ok("`sync add` is gone, see `pin --help`\n").len(), 1);
        assert_eq!(ok("`sync add` is gone, see `pin -h`\n").len(), 1);
        assert_eq!(ok("`sync add` is `Kotton pin <drive>`\n").len(), 0);
        assert_eq!(ok("`sync add` is `Pin`\n").len(), 1);
        // `sync list` -> `pin list`; `drive enrol` for `device admit`.
        assert_eq!(ok("`sync list` is `pin`\n").len(), 1);
        assert_eq!(ok("`device admit` is `drive`\n").len(), 1);
        assert_eq!(ok("`device admit` is `drive enrol <invite>`\n").len(), 0);
    }

    /// **On the noun's own page, the bare word in backticks names it**: under the heading
    /// the reference gives `kotton device --help`, `` `admit` `` is `device admit`; under
    /// another noun's heading, after the next heading, and in prose (`now`), it is not.
    #[test]
    fn the_bare_word_names_it_on_the_nouns_own_page() {
        let page = "\
## `Kotton device`

Pair with `device add`. `admit <invite>` was the vault's word.
###### **Arguments:**
* `<ARGS>` — `Admit` it
## `Kotton sync`

It syncs, now. `list` it.
## `Kotton pin`

`admit` and `now` and `list`
";
        let got = found(&[("docs/cli/reference.md", page)]);
        let said: Vec<(&str, &str)> = got.iter().map(|g| (g.split(": says").next().unwrap(), g.split('`').nth(1).unwrap())).collect();
        assert_eq!(
            said,
            [("docs/cli/reference.md:3", "device admit"), ("docs/cli/reference.md:5", "device admit"), ("docs/cli/reference.md:8", "sync list")],
            "{got:#?}"
        );
        // A Rust literal has no page, and a heading that is not the noun's command alone opens none.
        assert_eq!(found(&[("client/cli/src/x.rs", "const A: &str = \"`admit <invite>`\";\n")]), Vec::<String>::new());
        assert_eq!(found(&[("README.md", "# `kotton device admit`\n`admit`\n### `Kotton device`\n`admit`\n")]).len(), 1);
    }

    /// **A malformed escape never panics**: an unclosed `\u{`, a non-hex `\u{zz}`, a short or
/// out-of-range `\x`, at the end of a file or not; a word beside one is still read.
    #[test]
    fn a_malformed_escape_is_text_and_never_a_panic() {
        for src in ["const A: &str = \"x \\u{", "const A: &str = \"\\u{zz}\"", "const A: &str = \"\\x", "const A: &str = \"\\xff\\u{110000}\\u{1234567}\\u{\"\n"] {
            let _ = found(&[("client/cli/src/x.rs", src)]);
        }
        let got = found(&[("client/cli/src/x.rs", "const A: &str = \"\\u{zz} sync now \\xg1 \\u{\";\nconst B: &str = \"sync\\xff now\";\nconst C: &str = \"x\\u{\";\n// }\n")]);
        assert_eq!(got.len(), 1, "{got:#?}");
        assert!(got[0].starts_with("client/cli/src/x.rs:1: says `sync now`"), "{got:#?}");
    }

    /// **The pointer rule holds for every retired word, not only `pin`'s**: `<replacement>
    /// <arg>` points (a bare other noun needs the argument; a verbed one is itself whole);
    /// `<noun> <verb>` and a flag after a bare other noun do not.
    #[test]
    fn the_pointer_rule_holds_for_every_retired_word() {
        let t = tables();
        for r in retired(&t) {
            let line = |cmd: &str| found_with(&t, &format!("`{}` is `{cmd}`\n", r.was()));
            let target = r.now.split_whitespace().next().unwrap();
            // Independent of `Retired::bare_other`, on purpose: a second statement of the rule.
            let bare_other = r.now.split_whitespace().count() == 1 && target != r.noun;
            assert_eq!(line(&r.now).is_empty(), !bare_other, "{}: the replacement alone", r.was());
            assert!(line(&format!("{} <arg>", r.now)).is_empty(), "{}: with an argument", r.was());
            assert!(line(&format!("kotton {} <arg>", r.now.to_uppercase())).is_empty(), "{}: kotton, any case", r.was());
            if bare_other {
                assert!(!line(&format!("{} --help", r.now)).is_empty(), "{}: a flag is no argument", r.was());
                assert!(!line(&format!("{} -h", r.now)).is_empty(), "{}: a short flag is no argument", r.was());
                for v in &r.now_verbs {
                    assert!(!line(&format!("{} {v}", r.now)).is_empty(), "{}: `{v}` is a verb", r.was());
                }
            }
        }
    }

    fn found_with(t: &BTreeMap<String, Vec<(String, Is)>>, page: &str) -> Vec<String> {
        findings(tree(&[("README.md", page)]).path(), &retired(t))
    }

    /// **Every path and helper named here is one the tree holds**: a moved file would read as
    /// nothing and pass, and a renamed helper would make every deprecation line a finding.
    #[test]
    fn every_named_path_and_helper_exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent");
        for path in NOT_READ.iter().map(|(p, _)| *p).chain(STILL_RUNS.iter().map(|(p, _, _, _)| *p)) {
            assert!(root.join(path).is_file(), "{path} is not in this tree");
        }
        let shell = std::fs::read_to_string(root.join("client/shell/src/commands/mod.rs")).unwrap();
        for h in HELPERS {
            assert!(shell.contains(&format!("pub fn {h}(was: &str, now: &str)")), "the shell has no `{h}(was, now)`");
        }
    }
}
