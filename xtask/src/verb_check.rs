// SPDX-License-Identifier: AGPL-3.0-or-later
//! `verb-check`: the command tree is the command-tree decision's, in both of its doors.
//!
//! The command-tree decision — kotton-protocol's
//! `rfcs/0003-the-first-release-is-a-platform-a-stranger-can-use-from-the-command-line.md` —
//! fixes the nouns and the verbs, and says the CLI and the REPL are one parser: "a check
//! holds the two trees equal". This is that check, while the shell
//! lives in this repository (it moves with the tree to kotton-cli). It reads three things:
//!
//! - **The clap tree**, `kotton_cli::Cli`: every subcommand and alias, hidden ones too, and
//!   whether it is a door to the shell verb of its name (a `--user` and raw words, handed to
//!   `bridge::run_verb`) rather than a parser of its own.
//! - **The REPL's registry**, `bridge::repl_executor`: every name it registers, and the verb
//!   table each noun declares (`kotton_shell::Command::verbs`). The table is read from the
//!   registry the REPL runs and from the one the clap door runs (`ShellExecutor::new`), so a
//!   verb registered in one and not the other is named.
//! - **The command-tree decision**: the nouns and verbs its Decision's "What a person can
//!   do" names, and the "Today" column of its table ([`Rfc::parse`]).
//!
//! And it holds, failing by name:
//!
//! 1. every name either tree registers is in the Decision or a Today cell, or is
//!    [`UNPLACED`], each with the issue that gives it a place;
//! 2. for each noun the rewrite has reached ([`HELD`]): the noun is in both trees and the
//!    clap one is a door to the REPL's, so the two run one parser; every verb its table
//!    calls current is in the Decision, every verb it retires is in a Today cell and names
//!    a Decision noun as its replacement, every verb the Decision names is current in the
//!    table but those [`DEFERRED`], and every verb a Today cell names is in the table;
//! 3. for any other noun with a table (`device`, for the word the table moved to `drive`):
//!    every retired verb is in a Today cell and names a Decision noun;
//! 4. for every noun: a word retired for another noun alone (`sync add` is `pin`) points at a
//!    noun whose table holds a current `<…>` entry (`pin <drive>`), since that is what a person
//!    is told to type after the noun; a replacement whose noun has none names the verb itself
//!    (`sync list` is `pin list`) ([`bare_other`], [`placeholder`]).
//!
//! **Where the decision is read from.** kotton-protocol's checkout, at
//! `$KOTTON_PROTOCOL_DIR` or beside this one (`../kotton-protocol`), when there is one. kotton-protocol is not
//! readable from this repository's pull-request gate, and its prose is not this tree's to
//! copy (its pages are under their own licence), so what the check needs of the decision — the
//! words, not the text — is also held here, in [`PINNED`], with the commit it was read at.
//! With a checkout, the check reads the decision there and fails if the words held here are not
//! what it reads, printing the table to paste; without one, it says so and holds the trees
//! to the words held here. The seam back is a checkout in the gate, when kotton-protocol is
//! readable from it.

use std::collections::{BTreeMap, BTreeSet};

/// The nouns the command-tree decision's rewrite has reached: their verbs are held both ways.
pub const HELD: &[&str] = &["drive", "pin", "sync"];

/// Verbs of a held noun the Decision names and the binary does not have yet, each with why.
pub const DEFERRED: &[(&str, &str, &str)] =
    &[("drive", "export", "the command-tree decision names it; the binary does not have it yet (#182)")];

/// Names a tree registers that the command-tree decision gives no place, each with the issue
/// that will.
pub const UNPLACED: &[(&str, &str)] = &[
    ("ipc", "hidden; no row in the command-tree decision's table (#176)"),
    ("shell", "hidden alias of `repl`; no row in the command-tree decision's table (#176)"),
    ("sidecars", "hidden; no row in the command-tree decision's table (#176)"),
    ("vfs", "hidden; no row in the command-tree decision's table (#176)"),
];

/// What the check reads of the command-tree decision: the names a person types first, and the
/// verbs of each noun, from the Decision and from the Today column.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rfc {
    pub decision_names: BTreeSet<String>,
    pub decision_verbs: BTreeMap<String, BTreeSet<String>>,
    pub today_names: BTreeSet<String>,
    pub today_verbs: BTreeMap<String, BTreeSet<String>>,
}

/// One verb of a noun's table, as the check reads it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Is {
    Current,
    Alias(String),
    Gone(String),
}

/// What the check reads of the two trees.
#[derive(Debug, Clone, Default)]
pub struct Trees {
    /// Every clap subcommand and alias, and whether it is a door to the shell verb of its name.
    pub clap: BTreeMap<String, bool>,
    /// Every name the REPL's registry registers.
    pub repl: BTreeSet<String>,
    /// Each noun's table, as the REPL's registry holds it.
    pub repl_tables: BTreeMap<String, Vec<(String, Is)>>,
    /// Each noun's table, as the registry the clap door runs holds it.
    pub clap_tables: BTreeMap<String, Vec<(String, Is)>>,
}

/// The `<…>` a verb's position is filled by, cut at what follows the name (`<drive>[:/<folder>]`
/// is `<drive>`), or the word.
fn verb_word(word: &str) -> String {
    match word.strip_prefix('<') {
        Some(rest) => {
            let name: String = rest.chars().take_while(|c| !matches!(c, '>' | '[' | ':')).collect();
            format!("<{name}>")
        }
        None => word.to_string(),
    }
}

/// The verbs a span's words after the noun name: the first word outside `[…]` and not a flag,
/// split at `|` and `/`; `""` when there is none, the bare noun.
fn verbs_after(words: &[&str]) -> Vec<String> {
    let mut depth = 0i32;
    for w in words {
        let opens = w.matches('[').count() as i32;
        let closes = w.matches(']').count() as i32;
        let outside = depth == 0 && !w.starts_with('[');
        depth += opens - closes;
        if !outside || w.starts_with('-') {
            continue;
        }
        if w.starts_with('<') {
            return vec![verb_word(w)];
        }
        return w.split(['|', '/']).filter(|v| !v.is_empty()).map(verb_word).collect();
    }
    vec![String::new()]
}

/// The backticked spans of `text`, each with whether the text before it ends on `·`.
fn spans(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut rest = text;
    let mut before = String::new();
    while let Some(open) = rest.find('`') {
        before.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        let chained = before.trim_end().ends_with('·');
        out.push((after[..close].replace("\\|", "|"), chained));
        before.clear();
        rest = &after[close + 1..];
    }
    out
}

impl Rfc {
    /// Read the command-tree decision's text: the Decision's "What a person can do" and the table's Today
    /// column.
    ///
    /// **The Decision** is paragraphs, each a run of spans. The first span heads it: of two
    /// words or more (`drive create <name>`), its first is the paragraph's noun, and a span
    /// after a `·` is that noun's verb (`· `list``), or a noun of its own when it has a verb
    /// of its own (`· `message send <contact>``); of one word (`ls`), the spans after a `·`
    /// are names of their own (the files' verbs). A span anywhere else is a whole form
    /// (`` `identity rotate` ``). **A Today cell** is spans of whole forms, `/` and `|`
    /// between verbs (`sync add/list/remove`).
    pub fn parse(text: &str) -> Rfc {
        let mut rfc = Rfc::default();
        let decision = section(text, "### What a person can do");
        for paragraph in decision.split("\n\n") {
            let joined = paragraph.split_whitespace().collect::<Vec<_>>().join(" ");
            let mut noun: Option<String> = None;
            for (i, (span, chained)) in spans(&joined).into_iter().enumerate() {
                let words: Vec<&str> = span.split_whitespace().collect();
                let Some(first) = words.first().copied() else { continue };
                let whole = |rfc: &mut Rfc, words: &[&str]| {
                    rfc.decision_names.insert(words[0].to_string());
                    rfc.decision_verbs.entry(words[0].to_string()).or_default().extend(verbs_after(&words[1..]));
                };
                if i == 0 {
                    if words.len() > 1 {
                        noun = Some(first.to_string());
                    }
                    whole(&mut rfc, &words);
                    continue;
                }
                match (&noun, chained) {
                    (Some(n), true) if first == n => whole(&mut rfc, &words),
                    (Some(_), true) if words.len() > 1 && !words[1].starts_with(['<', '[', '-']) => {
                        whole(&mut rfc, &words)
                    }
                    (Some(n), true) => {
                        let n = n.clone();
                        rfc.decision_verbs.entry(n).or_default().extend(verbs_after(&words));
                    }
                    _ => whole(&mut rfc, &words),
                }
            }
        }
        let mut in_table = false;
        for line in text.lines() {
            if line.starts_with("| Today |") {
                in_table = true;
                continue;
            }
            if !in_table {
                continue;
            }
            if !line.starts_with('|') {
                break;
            }
            let cells: Vec<&str> = split_row(line);
            let Some(today) = cells.first() else { continue };
            if today.trim_start().starts_with("---") {
                continue;
            }
            for (span, _) in spans(today) {
                let words: Vec<&str> = span.split_whitespace().collect();
                let Some(first) = words.first() else { continue };
                if !first.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                    continue;
                }
                rfc.today_names.insert(first.to_string());
                rfc.today_verbs.entry(first.to_string()).or_default().extend(verbs_after(&words[1..]));
            }
        }
        rfc
    }

    /// Whether `name` has a place: the Decision or a Today cell names it first.
    fn places(&self, name: &str) -> bool {
        self.decision_names.contains(name) || self.today_names.contains(name)
    }

    fn decision(&self, noun: &str) -> BTreeSet<String> {
        self.decision_verbs.get(noun).cloned().unwrap_or_default()
    }

    fn today(&self, noun: &str) -> BTreeSet<String> {
        self.today_verbs.get(noun).cloned().unwrap_or_default()
    }

    /// What the check holds of the decision: every name, the held nouns' Decision verbs, and every
    /// noun's Today verbs. Two readings that agree here hold the trees to the same words.
    pub fn held(&self) -> Rfc {
        Rfc {
            decision_names: self.decision_names.clone(),
            decision_verbs: HELD.iter().map(|n| (n.to_string(), self.decision(n))).collect(),
            today_names: self.today_names.clone(),
            today_verbs: self.today_verbs.clone(),
        }
    }

    /// The [`PINNED`] table that holds these words, to paste over the one in this file.
    pub fn to_rust(&self) -> String {
        let list = |s: &BTreeSet<String>| s.iter().map(|w| format!("{w:?}")).collect::<Vec<_>>().join(", ");
        let map = |m: &BTreeMap<String, BTreeSet<String>>| {
            m.iter().map(|(n, v)| format!("        ({n:?}, &[{}]),\n", list(v))).collect::<String>()
        };
        format!(
            "pub const PINNED: Pinned = Pinned {{\n    commit: \"<kotton-protocol commit>\",\n    \
             decision_names: &[{}],\n    decision_verbs: &[\n{}    ],\n    today_names: &[{}],\n    \
             today_verbs: &[\n{}    ],\n}};",
            list(&self.decision_names),
            map(&self.decision_verbs),
            list(&self.today_names),
            map(&self.today_verbs),
        )
    }
}

/// The lines of `text` from the heading `head` to the next heading of its level.
fn section<'a>(text: &'a str, head: &str) -> &'a str {
    let Some(start) = text.find(head) else { return "" };
    let body = &text[start + head.len()..];
    let level = head.split(' ').next().unwrap_or("###");
    let end = body.find(&format!("\n{level} ")).unwrap_or(body.len());
    &body[..end]
}

/// A Markdown table row's cells, `\|` kept inside its cell.
fn split_row(line: &str) -> Vec<&str> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cells = Vec::new();
    let mut start = 0;
    let bytes = inner.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'|' && (i == 0 || bytes[i - 1] != b'\\') {
            cells.push(&inner[start..i]);
            start = i + 1;
        }
    }
    cells.push(&inner[start..]);
    cells
}

/// The words of the command-tree decision this check holds the trees to, held here for a gate that cannot read
/// kotton-protocol ([`Rfc::held`] of the decision at `commit`).
pub struct Pinned {
    pub commit: &'static str,
    pub decision_names: &'static [&'static str],
    pub decision_verbs: &'static [(&'static str, &'static [&'static str])],
    pub today_names: &'static [&'static str],
    pub today_verbs: &'static [(&'static str, &'static [&'static str])],
}

impl Pinned {
    pub fn rfc(&self) -> Rfc {
        let set = |s: &[&str]| s.iter().map(|w| w.to_string()).collect::<BTreeSet<_>>();
        let map = |m: &[(&str, &[&str])]| m.iter().map(|(n, v)| (n.to_string(), set(v))).collect();
        Rfc {
            decision_names: set(self.decision_names),
            decision_verbs: map(self.decision_verbs),
            today_names: set(self.today_names),
            today_verbs: map(self.today_verbs),
        }
    }
}

include!("verb_check_pinned.rs");

/// The other noun a replacement names alone, if it does: `pin` for `sync add`, gone for `pin`.
/// `None` for a replacement that names its verb (`pin list`) or is the word's own noun
/// (`sync now` is `sync`). After that noun, a person still has to pick what to type.
pub fn bare_other<'a>(noun: &str, now: &'a str) -> Option<&'a str> {
    let mut words = now.split_whitespace();
    match (words.next(), words.next()) {
        (Some(target), None) if target != noun => Some(target),
        _ => None,
    }
}

/// The first current `<…>` entry of `noun`'s table (`<drive>` for `pin`): what a replacement
/// naming `noun` alone is said with, in the help's `RETIRED:` block and in the retired-words
/// sweep's advice. `None` when the noun has no table or its table has none.
pub fn placeholder<'a>(tables: &'a BTreeMap<String, Vec<(String, Is)>>, noun: &str) -> Option<&'a str> {
    tables.get(noun)?.iter().find(|(w, is)| *is == Is::Current && w.starts_with('<')).map(|(w, _)| w.as_str())
}

/// The verb table of the command `registry` registers as `name`, as the check reads it.
#[cfg(feature = "cli-docs")]
pub fn table_of(registry: &kotton_cli::shell::CommandRegistry, name: &str) -> Vec<(String, Is)> {
    use kotton_cli::shell::VerbIs;
    registry
        .verbs_of(name)
        .iter()
        .map(|v| {
            let is = match v.is {
                VerbIs::Current => Is::Current,
                VerbIs::Alias { now } => Is::Alias(now.to_string()),
                VerbIs::Gone { now } => Is::Gone(now.to_string()),
            };
            (v.word.to_string(), is)
        })
        .collect()
}

/// Every table `registry` holds, by the name it is registered as; a name with no verbs has none.
#[cfg(feature = "cli-docs")]
pub fn tables_of(registry: &kotton_cli::shell::CommandRegistry) -> BTreeMap<String, Vec<(String, Is)>> {
    registry
        .command_names()
        .into_iter()
        .filter_map(|name| {
            let t = table_of(registry, &name);
            (!t.is_empty()).then_some((name, t))
        })
        .collect()
}

/// A verb as a person types it: `drive create`, and the bare noun as `sync`.
fn form(noun: &str, verb: &str) -> String {
    if verb.is_empty() {
        format!("`{noun}`")
    } else {
        format!("`{noun} {verb}`")
    }
}

/// Every way the trees and the decision disagree, each naming the name or the verb.
pub fn findings(rfc: &Rfc, trees: &Trees) -> Vec<String> {
    let mut out = Vec::new();
    let unplaced: BTreeMap<&str, &str> = UNPLACED.iter().copied().collect();

    // 1. Every name has a place.
    let mut names: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for name in trees.clap.keys() {
        names.entry(name).or_default().push("the clap tree");
    }
    for name in &trees.repl {
        names.entry(name).or_default().push("the REPL's registry");
    }
    for (name, doors) in &names {
        if rfc.places(name) || unplaced.contains_key(name) {
            continue;
        }
        out.push(format!(
            "`{name}` ({}) has no place in the command-tree decision: neither its Decision nor a Today cell names it",
            doors.join(" and ")
        ));
    }
    for (name, why) in UNPLACED {
        if !names.contains_key(name) {
            out.push(format!("`{name}` is listed as unplaced ({why}), and neither tree registers it: drop it"));
        } else if rfc.places(name) {
            out.push(format!("`{name}` is listed as unplaced ({why}), and the command-tree decision now places it: drop it"));
        }
    }

    // 2 and 3. The tables.
    let tables: BTreeSet<&String> = trees.repl_tables.keys().chain(trees.clap_tables.keys()).collect();
    for noun in HELD {
        let in_clap = trees.clap.get(*noun);
        if in_clap.is_none() {
            out.push(format!("`{noun}` is in the command-tree decision's tree and not in the clap tree"));
        }
        if !trees.repl.contains(*noun) {
            out.push(format!("`{noun}` is in the command-tree decision's tree and not in the REPL's registry"));
        }
        if in_clap == Some(&false) {
            out.push(format!(
                "`kotton {noun}` parses its own words: it is not the REPL's `{noun}`, so the two doors are two parsers"
            ));
        }
    }
    for noun in tables {
        let empty = Vec::new();
        let repl = trees.repl_tables.get(noun).unwrap_or(&empty);
        let clap = trees.clap_tables.get(noun).unwrap_or(&empty);
        for (word, is) in repl {
            if !clap.contains(&(word.clone(), is.clone())) {
                out.push(format!("{} is in the REPL's tree and not the clap tree's", form(noun, word)));
            }
        }
        for (word, is) in clap {
            if !repl.contains(&(word.clone(), is.clone())) {
                out.push(format!("{} is in the clap tree and not the REPL's", form(noun, word)));
            }
        }
        let held = HELD.contains(&noun.as_str());
        let decision = rfc.decision(noun);
        let today = rfc.today(noun);
        for (word, is) in repl {
            match is {
                Is::Current if held && !decision.contains(word) => out.push(format!(
                    "{} is in the tree and the command-tree decision's Decision does not name it",
                    form(noun, word)
                )),
                Is::Current => {}
                Is::Alias(now) | Is::Gone(now) => {
                    if !today.contains(word) {
                        out.push(format!(
                            "{} is kept as a retired word, and no Today cell of the command-tree decision's table names it",
                            form(noun, word)
                        ));
                    }
                    let replacement = now.split_whitespace().next().unwrap_or("");
                    if !rfc.decision_names.contains(replacement) {
                        out.push(format!(
                            "{} names `{now}` as what replaced it, and the command-tree decision's Decision has no `{replacement}`",
                            form(noun, word)
                        ));
                    }
                    // 4. A replacement naming another noun alone is said with that noun's
                    // placeholder; one whose noun has none must name the verb.
                    if let Some(target) = bare_other(noun, now) {
                        if placeholder(&trees.repl_tables, target).is_none() {
                            out.push(format!(
                                "{} names `{now}` alone as what replaced it, and `{target}`'s table holds no current `<…>` entry, \
                                 so nothing after `{target}` says what to type: name the verb (as `sync list` names `pin list`), \
                                 or give `{target}` a placeholder",
                                form(noun, word)
                            ));
                        }
                    }
                }
            }
        }
        if !held {
            continue;
        }
        for word in &decision {
            let deferred = DEFERRED.iter().any(|(n, v, _)| n == noun && v == word);
            let current = repl.iter().any(|(w, is)| w == word && *is == Is::Current);
            if !current && !deferred {
                out.push(format!("{} is in the command-tree decision's Decision and not in the binary", form(noun, word)));
            }
            if current && deferred {
                out.push(format!("{} is listed as deferred, and the binary has it: drop it", form(noun, word)));
            }
        }
        for word in &today {
            if !repl.iter().any(|(w, _)| w == word) {
                out.push(format!(
                    "{} is in the command-tree decision's Today column, and the tree neither runs it under the new verb nor refuses it by name",
                    form(noun, word)
                ));
            }
        }
    }
    for noun in HELD {
        if !trees.repl_tables.contains_key(*noun) {
            out.push(format!("`{noun}` declares no verbs, so neither tree can be held to the command-tree decision's"));
        }
    }
    out
}

/// the command-tree decision's text from kotton-protocol's checkout, and where it was read, if there is one.
pub fn protocol_rfc(root: &std::path::Path) -> Option<(String, std::path::PathBuf)> {
    let dir = std::env::var_os("KOTTON_PROTOCOL_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("..").join("kotton-protocol"));
    let rfcs = dir.join("rfcs");
    let entry = std::fs::read_dir(&rfcs)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("0003-") && n.ends_with(".md")))?;
    Some((std::fs::read_to_string(&entry).ok()?, entry))
}

/// The decision the trees are held to, and any finding about where it came from.
pub fn the_rfc(root: &std::path::Path) -> (Rfc, Vec<String>) {
    let pinned = PINNED.rfc();
    match protocol_rfc(root) {
        Some((text, at)) => {
            let read = Rfc::parse(&text).held();
            if read == pinned {
                println!("verb-check: the command-tree decision read at {}; the words held here match it.", at.display());
                (read, Vec::new())
            } else {
                let finding = format!(
                    "the command-tree decision at {} is not what xtask/src/verb_check_pinned.rs holds (read at kotton-protocol {}). \
                     If the decision changed, paste this over it with the commit it was read at:\n\n{}",
                    at.display(),
                    PINNED.commit,
                    read.to_rust()
                );
                (read, vec![finding])
            }
        }
        None => {
            println!(
                "verb-check: no kotton-protocol checkout (set KOTTON_PROTOCOL_DIR, or check it out beside this one); \
                 the trees are held to the words of the command-tree decision held here, read at kotton-protocol {}.",
                PINNED.commit
            );
            (pinned, Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parts of the command-tree decision the check reads, in its own shape: two Decision paragraphs and
    /// rows of the table. The words are the decision's.
    const DECISION: &str = "\
## Decision

### What a person can do

**Drives.** `drive create <name> [--on <vault>]` · `list` (where each lives) · `show` · `move <drive> --to <vault>`
(under the same key) · `export <drive> <path>` · `enrol <line>`
(accept a host's vault).

**What this device holds.** `pin default whole|on-demand` (this device's default) · `pin <drive>[:/<folder>]
whole|on-demand|default` (the nearest setting wins; `default` follows the one above) · `pin list`. `pin <drive>
whole` is \"collect all my things\". `sync` syncs this device's drives, now.

**Files.** `ls` · `cat` · `cp` · `find [path] [-name <glob>]` · `trash list|restore|empty`.

**Contacts and messages.** `contact pair` · `join <code>` · `list` · `message send <contact> <text>` · `inbox`.

### Where it runs

`not-a-verb` here.

## Consequences

| Today | At `v0.1.0` |
|---|---|
| `id create/list/use` | `identity …`, unchanged |
| `device admit <vault invite>` | `drive enrol` |
| `keep` | `cp -r <folder> <drive>:/` |
| `door status\\|closed\\|10m\\|always` | `device receive off\\|10m\\|always` |
| `sync add/list/remove` | `pin` and `drive` |
| `sync` (all paired devices) | `sync` |
| `sync now [--node <id>] [--no-wait]` | `sync` |
| `sync [--push\\|--pull] <remote>` | `sync` |
| `host:` | kept in the REPL only |

- after the table.
";

    fn set(words: &[&str]) -> BTreeSet<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn the_decision_is_read_noun_by_noun() {
        let rfc = Rfc::parse(DECISION);
        assert_eq!(rfc.decision("drive"), set(&["create", "list", "show", "move", "export", "enrol"]));
        assert_eq!(rfc.decision("pin"), set(&["default", "<drive>", "list"]));
        assert_eq!(rfc.decision("sync"), set(&[""]));
        // A verb after a noun of its own stays the paragraph's: the reading is permissive
        // there, and exact for the held nouns, whose paragraphs are one noun each.
        assert_eq!(rfc.decision("contact"), set(&["pair", "join", "list", "inbox"]));
        assert_eq!(rfc.decision("message"), set(&["send"]));
        for name in ["drive", "pin", "sync", "ls", "cat", "cp", "find", "trash", "contact", "message"] {
            assert!(rfc.decision_names.contains(name), "{name}: {:?}", rfc.decision_names);
        }
        assert!(!rfc.decision_names.contains("list"), "a verb read as a name: {:?}", rfc.decision_names);
        assert!(!rfc.decision_names.contains("not-a-verb"), "read past the section");
    }

    #[test]
    fn the_today_column_is_read_cell_by_cell() {
        let rfc = Rfc::parse(DECISION);
        assert_eq!(rfc.today("sync"), set(&["add", "list", "remove", "", "now", "<remote>"]));
        assert_eq!(rfc.today("device"), set(&["admit"]));
        assert_eq!(rfc.today("door"), set(&["status", "closed", "10m", "always"]));
        assert_eq!(rfc.today("id"), set(&["create", "list", "use"]));
        assert!(rfc.today_names.contains("keep") && rfc.today_names.contains("host:"));
        assert!(!rfc.today_names.contains("identity"), "read the second column: {:?}", rfc.today_names);
    }

    /// The trees, small: the shell's tables ([`crate::verb_tables`]) in both doors, and a name
    /// from each door.
    fn trees() -> Trees {
        let tables = crate::verb_tables::tables();
        let mut clap: BTreeMap<String, bool> = ["drive", "pin", "sync", "device", "keep"].iter().map(|n| (n.to_string(), true)).collect();
        for (name, _) in UNPLACED {
            clap.insert(name.to_string(), false);
        }
        Trees {
            clap,
            repl: set(&["drive", "pin", "sync", "device", "keep", "cat", "ls"]),
            repl_tables: tables.clone(),
            clap_tables: tables,
        }
    }

    #[test]
    fn the_trees_as_left_hold() {
        assert_eq!(findings(&Rfc::parse(DECISION), &trees()), Vec::<String>::new());
    }

    /// **The test #43 asks for.** A verb registered with no row in the decision is refused, by name.
    #[test]
    fn a_registered_verb_with_no_row_is_refused_by_name() {
        let mut t = trees();
        t.repl.insert("frobnicate".into());
        let found = findings(&Rfc::parse(DECISION), &t);
        assert!(
            found.iter().any(|f| f.starts_with("`frobnicate` (the REPL's registry) has no place in the command-tree decision")),
            "{found:#?}"
        );
        let mut t = trees();
        t.clap.insert("frobnicate".into(), true);
        let found = findings(&Rfc::parse(DECISION), &t);
        assert!(found.iter().any(|f| f.starts_with("`frobnicate` (the clap tree) has no place")), "{found:#?}");
    }

    #[test]
    fn a_held_nouns_verb_the_decision_lacks_is_refused_by_name() {
        let mut t = trees();
        for tables in [&mut t.repl_tables, &mut t.clap_tables] {
            tables.get_mut("drive").unwrap().push(("frob".into(), Is::Current));
        }
        let found = findings(&Rfc::parse(DECISION), &t);
        assert_eq!(found, vec!["`drive frob` is in the tree and the command-tree decision's Decision does not name it".to_string()]);
    }

    #[test]
    fn a_verb_in_one_door_and_not_the_other_is_named() {
        let mut t = trees();
        t.repl_tables.get_mut("pin").unwrap().retain(|(w, _)| w != "list");
        let found = findings(&Rfc::parse(DECISION), &t);
        assert!(found.contains(&"`pin list` is in the clap tree and not the REPL's".to_string()), "{found:#?}");
        assert!(found.contains(&"`pin list` is in the command-tree decision's Decision and not in the binary".to_string()), "{found:#?}");
    }

    #[test]
    fn a_decision_verb_absent_from_the_binary_is_named() {
        let mut t = trees();
        for tables in [&mut t.repl_tables, &mut t.clap_tables] {
            tables.get_mut("drive").unwrap().retain(|(w, _)| w != "enrol");
        }
        let found = findings(&Rfc::parse(DECISION), &t);
        assert_eq!(found, vec!["`drive enrol` is in the command-tree decision's Decision and not in the binary".to_string()]);
    }

    #[test]
    fn a_today_verb_neither_run_nor_refused_is_named() {
        let mut t = trees();
        for tables in [&mut t.repl_tables, &mut t.clap_tables] {
            tables.get_mut("sync").unwrap().retain(|(w, _)| w != "add");
        }
        let found = findings(&Rfc::parse(DECISION), &t);
        assert_eq!(
            found,
            vec!["`sync add` is in the command-tree decision's Today column, and the tree neither runs it under the new verb nor refuses it by name".to_string()]
        );
    }

    #[test]
    fn a_retired_word_must_be_in_a_today_cell_and_name_a_decision_noun() {
        let mut t = trees();
        for tables in [&mut t.repl_tables, &mut t.clap_tables] {
            tables.get_mut("device").unwrap().push(("befriend".into(), Is::Gone("friend add".into())));
        }
        let found = findings(&Rfc::parse(DECISION), &t);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found[0].contains("no Today cell"), "{found:#?}");
        assert!(found[1].contains("has no `friend`"), "{found:#?}");
    }

    #[test]
    fn a_held_noun_the_clap_tree_parses_itself_is_two_parsers() {
        let mut t = trees();
        t.clap.insert("drive".into(), false);
        let found = findings(&Rfc::parse(DECISION), &t);
        assert_eq!(
            found,
            vec!["`kotton drive` parses its own words: it is not the REPL's `drive`, so the two doors are two parsers".to_string()]
        );
    }

    #[test]
    fn an_unplaced_name_nobody_registers_is_stale() {
        let mut t = trees();
        t.clap.remove("vfs");
        let found = findings(&Rfc::parse(DECISION), &t);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("`vfs` is listed as unplaced"), "{found:#?}");
    }

    /// **A word retired for another noun alone needs a placeholder there.** `sync add` is gone
    /// for `pin`, which is a full answer only because `pin`'s table holds a current `<drive>`:
    /// without it, `sync add` and `sync remove` are refused by name, and `sync list` (gone for
    /// `pin list`, which names its verb) and `sync now` (its own noun) are not. A retired
    /// placeholder does not count, and the rule reads every noun's table, not only the held.
    #[test]
    fn a_word_retired_to_a_bare_noun_needs_a_current_placeholder_there() {
        let mut t = trees();
        for tables in [&mut t.repl_tables, &mut t.clap_tables] {
            tables.get_mut("pin").unwrap().retain(|(w, _)| w != "<drive>");
        }
        let found = findings(&Rfc::parse(DECISION), &t);
        let bare: Vec<&String> = found.iter().filter(|f| f.contains("alone as what replaced it")).collect();
        assert_eq!(bare.len(), 2, "{found:#?}");
        assert!(bare[0].starts_with("`sync add` names `pin` alone as what replaced it, and `pin`'s table holds no current `<…>` entry"), "{found:#?}");
        assert!(bare[0].contains("name the verb (as `sync list` names `pin list`)"), "{found:#?}");
        assert!(bare[1].starts_with("`sync remove` names `pin` alone"), "{found:#?}");
        // A retired placeholder is not one a person can type; a noun with no table has none.
        let mut t = trees();
        for tables in [&mut t.repl_tables, &mut t.clap_tables] {
            let pin = tables.get_mut("pin").unwrap();
            pin.retain(|(w, _)| w != "<drive>");
            pin.push(("<old>".into(), Is::Gone("pin list".into())));
            tables.get_mut("device").unwrap().push(("keep".into(), Is::Alias("drive".into())));
        }
        let found = findings(&Rfc::parse(DECISION), &t);
        let bare: Vec<&String> = found.iter().filter(|f| f.contains("alone as what replaced it")).collect();
        assert_eq!(bare.len(), 3, "{found:#?}");
        assert!(bare[0].starts_with("`device keep` names `drive` alone"), "{found:#?}");
    }

    /// The table held here reads back as itself, so what is pasted from a mismatch is what
    /// the next run compares.
    #[test]
    fn the_pinned_words_cover_every_held_noun() {
        let pinned = PINNED.rfc();
        for noun in HELD {
            assert!(!pinned.decision(noun).is_empty(), "{noun} has no Decision verbs held");
        }
        assert!(pinned.today("sync").contains("add"));
        assert!(pinned.today("device").contains("admit"));
    }
}
