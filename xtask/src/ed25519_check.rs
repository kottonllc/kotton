// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ed25519-check`: every Ed25519 check made with `ed25519-dalek` is strict, and `verify_strict`
//! is called in one file in the tree, the relay's workspace included: `kotton-ed25519`'s, whose
//! `VerifyingKey::verify` every other check goes through.
//!
//! The handshake signature on a peer connection (`core/net`'s TLS verifiers) and the signature
//! the threshold-signing provider's `aggregate` returns are checked through the same type. The
//! threshold library (`frost-ed25519`, over `frost-core`) is a dependency of `kotton-crypto`
//! alone, whose provider (`core/crypto/src/provider/frost.rs`) hands every group key and
//! signature to that type, and the library's own signature checks are refused like the
//! unstrict one. The threshold library is every package from outside the tree that depends on
//! `frost-core`, directly or through another such package, as the lockfiles record it:
//! `frost-core` itself, `frost-ed25519` and `frost-rerandomized` at 2.2.0, and whatever a
//! lockfile gains that reaches it.
//!
//! ## What holds it
//!
//! Two things, one typed and one textual.
//!
//! - **The workspace's `clippy.toml`** refuses `ed25519_dalek::Verifier::verify` and the
//!   inherent `ed25519_dalek::SigningKey::verify`: the two ways to make the unstrict check with
//!   the library's features the tree turns on. It refuses the threshold library's own checks of
//!   a group signature too ([`THRESHOLD_REFUSED`]), in `kotton-crypto` as everywhere: its
//!   provider checks through the rule's type. Clippy resolves the call, so a trait brought in
//!   under any name, a generic bound or a fully qualified call is refused as surely as
//!   `key.verify(..)`. `just lint` runs clippy over the workspace and over the relay's own
//!   workspace, `--all-targets`, so tests are held too, and with `-D warnings`, so a refusal
//!   fails the gate.
//! - **This check** holds what clippy cannot hold of itself:
//!   - the file is there and names every refused method in its top-level `disallowed-methods`,
//!     and no other `clippy.toml` or `.clippy.toml` (at the root or below it) shadows it;
//!   - the two lint runs are there: in the `Justfile` and `just/`, a `cargo clippy` run over
//!     the workspace and one with `--manifest-path infra/relay/Cargo.toml`, each
//!     `--all-targets` with `-D warnings` after `--`;
//!   - nothing lowers the refusal but the one exemption named here ([`EXEMPTION`]): no `allow`
//!     or `expect` of the lint, of a group that holds it, or of `warnings` ([`LOWERED`]), in an
//!     attribute (read without its whitespace) or a manifest's `[lints]` (a tool's table, a
//!     lint's own table with `level`, a dotted key or an inline table); and, in the files that
//!     configure or run the lint, no `-A`/`--allow` of those, no `--cap-lints` and no
//!     `CLIPPY_CONF_DIR`;
//!   - no manifest turns on a feature of the library that adds a check other than the two
//!     methods `clippy.toml` names, or loosens the strict one ([`FEATURES`]);
//!   - no manifest but [`THRESHOLD_HOME`] lists a package of the threshold library (each
//!     package a lockfile records as depending on [`THRESHOLD_CORE`], read by
//!     `threshold_packages`), in any dependency table, renamed or not; the root manifest's
//!     `[workspace.dependencies]` entry declares its version and is not a dependency. So no
//!     crate but `kotton-crypto` can name the library, and its signatures reach the rest of the
//!     tree only through the provider;
//!   - the seam: `verify_strict` is called in [`SEAM`] and in no other file under the code
//!     roots, the relay's included; every other check is `kotton_ed25519::VerifyingKey::verify`
//!     or reaches it.
//!
//! ## What it reads
//!
//! Every `.rs` file and `Cargo.toml` under the code roots (`tree::CODE_ROOTS`), tests
//! included; and, for what lowers the lint, the root manifest, `Justfile`, `just/*.just`, every
//! cargo configuration (`.cargo/config.toml` or `.cargo/config`) at the root or under the code
//! roots, and the workflows; and, for what the threshold library is, the root's `Cargo.lock`
//! and every `Cargo.lock` under the code roots (the relay's). It skips its own source, whose
//! tests spell what it refuses.
//!
//! Every `Cargo.toml` and `clippy.toml` is parsed as TOML (the `toml` crate), so how an entry
//! is spelled does not matter there: a dependency inline or in table form, renamed or not, in
//! any dependency table, the root manifest's `[workspace.dependencies]` entry included, and a
//! `[lints]` level as a tool's table, a lint's own table, a dotted key or an inline table, are
//! each read the same way. A dependency inherited from the workspace is read under the name
//! the member gives it. A manifest or `clippy.toml` that does not parse is a finding, naming
//! the file. The rest is read as text, skipping comment lines: attributes in `.rs` files, and
//! the lines of the `Justfile`, `just/`, the cargo configurations and the workflows.
//!
//! ## What it does not read
//!
//! What it reads as text it reads file by file, so there it is a list of spellings, and these
//! are outside it:
//!
//! - an attribute in a file brought in by `include!` that is not a `.rs` file under the code
//!   roots, and an `allow` built by a macro;
//! - a lint level, `CLIPPY_CONF_DIR` or a flag set in the environment at run time (`just lint`
//!   and the workflows set none);
//! - a clippy run reached other than as a `cargo clippy` line in the `Justfile` or `just/`
//!   (through a variable, say);
//! - a feature turned on by a crate outside the tree (for the workspace,
//!   `workspace-hack-check` holds the resolved feature set to `tools/workspace-hack`'s
//!   manifest, which this reads).
//!
//! What holds the rule at its cause is `kotton_ed25519::VerifyingKey`, which offers only the
//! strict check. While a crate other than `kotton-ed25519` depends on the library, the library's
//! other check is reachable from it, and this check and the lint are what refuse it (#564).

use std::collections::BTreeSet;
use std::path::Path;

use toml::{Table, Value};

use crate::user_database_check::{rel, walk};

/// The file that holds the refusal, at the root of the tree.
const CLIPPY_TOML: &str = "clippy.toml";

/// The methods it refuses: the two ways to make the unstrict check with the library's features
/// the tree turns on ([`FEATURES`] holds that no other is turned on).
const REFUSED: &[&str] = &["ed25519_dalek::Verifier::verify", "ed25519_dalek::SigningKey::verify"];

/// The library, by its package name.
const LIBRARY: &str = "ed25519-dalek";

/// The core of the threshold-signing library, by its package name. The library is this package
/// and every package from outside the tree that depends on it, directly or through another
/// such package (`threshold_packages`): each of them reaches the core's own checks, as
/// `frost-ed25519` and `frost-rerandomized` re-export it.
const THRESHOLD_CORE: &str = "frost-core";

/// The one manifest that lists the threshold library: `kotton-crypto`'s, whose provider hands
/// every group key and signature to the Ed25519 rule.
const THRESHOLD_HOME: &str = "core/crypto/Cargo.toml";

/// The threshold library's own checks of a group signature, read from `frost-core` 2.2.0's
/// source: a key's `verify`, the batch verifier's two, and the ciphersuite's
/// `verify_signature`, which the others call. `frost-ed25519`'s names for these types are
/// aliases, so clippy resolves a call through them to these paths.
const THRESHOLD_REFUSED: &[&str] = &[
    "frost_core::VerifyingKey::verify",
    "frost_core::batch::Verifier::verify",
    "frost_core::batch::Item::verify_single",
    "frost_core::Ciphersuite::verify_signature",
];

/// The library's features that no manifest turns on, read from `ed25519-dalek` 2.2.0's source:
/// each adds a way to check a signature other than the two methods in [`REFUSED`], or
/// loosens the strict check itself.
const FEATURES: &[(&str, &str)] = &[
    ("batch", "adds verify_batch"),
    ("digest", "adds verify_prehashed, the DigestVerifier impl and the context checks"),
    ("hazmat", "adds raw_verify, raw_verify_prehashed and verify_stream"),
    ("legacy_compatibility", "has every check, verify_strict included, accept an S that is not reduced"),
];

/// The one file that calls `verify_strict`: `kotton-ed25519`, beneath `kotton-pair`, which
/// every crate in the tree and the relay reach.
const SEAM: &str = "core/ed25519/src/lib.rs";

/// The one place the lint is allowed: (file, the test it is allowed on). The test holds the
/// difference between the strict check and the other one, so it makes the other one.
const EXEMPTION: (&str, &str) = (
    "core/ed25519/src/lib.rs",
    "fn the_library_s_other_check_accepts_what_the_rule_refuses",
);

/// This check's own source, whose tests spell what it refuses.
const THIS: &str = "xtask/src/ed25519_check.rs";

/// What names the lint in a manifest's `[lints]` or on a command line.
const OFF: &[&str] = &["disallowed_methods", "disallowed-methods"];

/// The lint levels whose `allow` or `expect` turns the refusal off: the lint, the groups that
/// hold it, and `warnings`, which holds every lint.
const LOWERED: &[&str] = &[
    "clippy::disallowed_methods",
    "clippy::disallowed-methods",
    "clippy::style",
    "clippy::all",
    "warnings",
];

pub fn run(root: &Path) {
    let (count, found) = findings(root);
    if found.is_empty() {
        println!("{}", ok_line(count));
        return;
    }
    for f in &found {
        eprintln!("ed25519-check: {f}");
    }
    eprintln!("{}", failure_footer());
    std::process::exit(1);
}

/// The line printed when the tree holds the rule.
fn ok_line(count: usize) -> String {
    format!(
        "ed25519-check: OK: {count} source file(s); every check made with {LIBRARY} is strict: clippy.toml \
         refuses the unstrict check and the threshold library's own checks, {THRESHOLD_HOME} alone lists \
         the threshold library, both clippy runs are --all-targets with -D warnings, nothing lowers that but one named exemption, no manifest turns on \
         a feature that adds another check, and verify_strict is called in one file in the tree, the relay \
         included ({SEAM})."
    )
}

/// The text printed after the findings when the tree breaks the rule.
fn failure_footer() -> String {
    format!(
        "\nEvery Ed25519 check made with {LIBRARY} is strict, and verify_strict is called in one file in the \
         tree, the relay included: {SEAM}. Check through kotton_ed25519::VerifyingKey::verify. The threshold \
         library is a dependency of {THRESHOLD_HOME} alone, whose provider checks its signatures the same way."
    )
}

/// What the tree breaks of the rule, and how many source files it read.
fn findings(root: &Path) -> (usize, Vec<String>) {
    let mut files = Vec::new();
    for r in crate::tree::CODE_ROOTS {
        walk(&root.join(r), &mut files);
    }
    files.sort();
    let mut sources = Vec::new();
    let mut manifests = Vec::new();
    let mut shadows = Vec::new();
    let mut elsewhere = Vec::new();
    let mut locks = Vec::new();
    for path in &files {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if name == "Cargo.lock" {
            locks.push(path.clone());
            continue;
        }
        if name == CLIPPY_TOML || name == ".clippy.toml" {
            shadows.push(rel(root, path));
            continue;
        }
        if is_cargo_config(path) {
            elsewhere.push(path.clone());
            continue;
        }
        let rs = path.extension().is_some_and(|e| e == "rs");
        if !rs && name != "Cargo.toml" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            return (0, vec![format!("could not read {}", path.display())]);
        };
        if rs {
            sources.push((rel(root, path), text));
        } else {
            manifests.push((rel(root, path), text));
        }
    }
    if sources.is_empty() {
        return (0, vec!["found no .rs file under the code roots. Run from the workspace root.".into()]);
    }
    for extra in ["Cargo.toml", "Justfile", ".cargo/config.toml", ".cargo/config"] {
        elsewhere.push(root.join(extra));
    }
    walk(&root.join("just"), &mut elsewhere);
    walk(&root.join(".github/workflows"), &mut elsewhere);
    // The root's lockfile is the workspace's, and is read whatever the walk found.
    let mut lockfiles = Vec::new();
    match std::fs::read_to_string(root.join("Cargo.lock")) {
        Ok(text) => lockfiles.push(("Cargo.lock".to_string(), text)),
        Err(_) => return (0, vec!["Cargo.lock is not at the root of the tree, so the threshold library cannot be read".into()]),
    }
    for path in &locks {
        let Ok(text) = std::fs::read_to_string(path) else {
            return (0, vec![format!("could not read {}", path.display())]);
        };
        lockfiles.push((rel(root, path), text));
    }
    let mut others = Vec::new();
    for path in &elsewhere {
        if let Ok(text) = std::fs::read_to_string(path) {
            others.push((rel(root, path), text));
        }
    }

    // Clippy reads `.clippy.toml` in a directory as readily as `clippy.toml`.
    if root.join(".clippy.toml").exists() {
        shadows.push(".clippy.toml".to_string());
    }
    let config = std::fs::read_to_string(root.join(CLIPPY_TOML)).ok();
    let mut found = config_findings(config.as_deref(), &shadows);
    found.extend(allowance_findings(&sources, &manifests, &others));
    found.extend(lint_run_findings(&others));
    let root_manifest: Vec<(String, String)> = others.iter().filter(|(f, _)| f == "Cargo.toml").cloned().collect();
    found.extend(feature_findings(manifests.iter().chain(&root_manifest)));
    match threshold_packages(&lockfiles) {
        Ok(threshold) => found.extend(threshold_findings(manifests.iter().chain(&root_manifest), &threshold)),
        Err(e) => found.push(e),
    }
    found.extend(seam_findings(&sources));
    (sources.len(), found)
}

/// Whether `path` is a cargo configuration: `config.toml` or `config` in a `.cargo` directory.
fn is_cargo_config(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let parent = path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_string());
    parent.as_deref() == Some(".cargo") && (name == "config.toml" || name == "config")
}

/// `clippy.toml` is at the root, names every refused method in its top-level
/// `disallowed-methods`, and no other shadows it.
fn config_findings(config: Option<&str>, shadows: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    match config {
        None => out.push(format!("{CLIPPY_TOML} is not at the root of the tree")),
        Some(text) => match parse(text) {
            Err(e) => out.push(format!("{CLIPPY_TOML}: {e}")),
            Ok(config) => {
                // An entry is a path, or a table with one: `"a::b"` or `{ path = "a::b", .. }`.
                let named: Vec<&str> = config
                    .get("disallowed-methods")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().or_else(|| v.get("path").and_then(Value::as_str)))
                    .collect();
                for m in REFUSED.iter().chain(THRESHOLD_REFUSED) {
                    if !named.contains(m) {
                        out.push(format!("{CLIPPY_TOML} does not refuse `{m}` (disallowed-methods)"));
                    }
                }
            }
        },
    }
    for s in shadows {
        out.push(format!("{s}: a clippy configuration beside or below the root's, which clippy would read instead"));
    }
    out
}

/// The lint levels each `allow(..)` or `expect(..)` in `src` names, by the line (0-based) it
/// opens on. Whitespace is not read, so `allow (warnings)` and `clippy :: all` are read as
/// `allow(warnings)` and `clippy::all`, and an attribute is read to its closing parenthesis
/// across lines. Lines starting with `//` are skipped.
fn lowered_attributes(src: &str) -> Vec<(usize, Vec<String>)> {
    let chars: Vec<(char, usize)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .flat_map(|(i, l)| l.chars().filter(|c| !c.is_whitespace()).map(move |c| (c, i)))
        .collect();
    let text: String = chars.iter().map(|(c, _)| *c).collect();
    let at_char: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
    let mut out = Vec::new();
    for opener in ["allow(", "expect("] {
        for (byte, _) in text.match_indices(opener) {
            let first = at_char.binary_search(&byte).unwrap_or(0);
            // Not `disallow(` or another word ending in it.
            if first > 0 && (chars[first - 1].0.is_alphanumeric() || chars[first - 1].0 == '_') {
                continue;
            }
            let mut inner = String::new();
            let mut depth = 1;
            for (c, _) in &chars[first + opener.len()..] {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                inner.push(*c);
            }
            let named: Vec<String> = inner
                .split(',')
                .filter(|t| LOWERED.contains(t) || OFF.contains(t))
                .map(str::to_string)
                .collect();
            if !named.is_empty() {
                out.push((chars[first].1, named));
            }
        }
    }
    out.sort();
    out
}

/// The lint runs `just lint` makes, in the Justfile and `just/`: a workspace clippy run (one
/// without `--manifest-path`) and the relay's (`--manifest-path infra/relay/Cargo.toml`) are
/// each there, and each such run is `--all-targets` with `-D warnings` after `--`. A run is a
/// `cargo clippy` line, with any lines it continues with `\`; comment lines are skipped.
fn lint_run_findings(others: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let (mut workspace, mut relay) = (0, 0);
    for (file, text) in others.iter().filter(|(f, _)| f == "Justfile" || f.starts_with("just/")) {
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let start = i;
            let mut run = lines[i].trim().to_string();
            i += 1;
            while run.ends_with('\\') && i < lines.len() {
                run.pop();
                run.push(' ');
                run.push_str(lines[i].trim());
                i += 1;
            }
            if run.starts_with('#') || !run.contains("cargo clippy") {
                continue;
            }
            let words: Vec<&str> = run.split_whitespace().collect();
            let is_relay = words.windows(2).any(|w| w[0] == "--manifest-path" && w[1] == "infra/relay/Cargo.toml")
                || words.contains(&"--manifest-path=infra/relay/Cargo.toml");
            if is_relay {
                relay += 1;
            } else if words.iter().any(|w| w.starts_with("--manifest-path")) {
                continue;
            } else {
                workspace += 1;
            }
            let (before, after) = match words.iter().position(|w| *w == "--") {
                Some(at) => (&words[..at], &words[at + 1..]),
                None => (&words[..], &[][..]),
            };
            let denied = after.windows(2).any(|w| w[0] == "-D" && w[1] == "warnings") || after.contains(&"-Dwarnings");
            let which = if is_relay { "the relay's" } else { "the workspace's" };
            if !before.contains(&"--all-targets") {
                out.push(format!("{file}:{}: {which} clippy run is not --all-targets", start + 1));
            }
            if !denied {
                out.push(format!("{file}:{}: {which} clippy run does not hold -D warnings after --", start + 1));
            }
        }
    }
    if workspace == 0 {
        out.push("Justfile: no clippy run over the workspace".to_string());
    }
    if relay == 0 {
        out.push("Justfile: no clippy run over the relay (--manifest-path infra/relay/Cargo.toml)".to_string());
    }
    out
}

/// What, in a file that configures or runs the lint, turns the refusal off, by line: an
/// `-A`/`--allow` of a level in [`LOWERED`] or of the lint (read across lines, so a flag and
/// its value split over an array or a continued line are one), `--cap-lints`, or
/// `CLIPPY_CONF_DIR`. Comment lines (starting with `#`) are skipped.
fn lowered_on_command_line(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut tokens: Vec<(usize, String)> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        for word in ["CLIPPY_CONF_DIR", "--cap-lints"] {
            if line.contains(word) {
                out.push((i + 1, word.to_string()));
            }
        }
        let spaced: String = line
            .chars()
            .map(|c| if matches!(c, '"' | '\'' | ',' | '[' | ']' | '=' | '`' | '(' | ')' | '\\') { ' ' } else { c })
            .collect();
        tokens.extend(spaced.split_whitespace().map(|t| (i + 1, t.to_string())));
    }
    let lowered = |t: &str| LOWERED.contains(&t) || OFF.iter().any(|w| t.ends_with(w));
    for (n, (line, t)) in tokens.iter().enumerate() {
        let next = tokens.get(n + 1).map(|(_, t)| t.as_str()).unwrap_or("");
        if (t == "-A" || t == "--allow") && lowered(next) {
            out.push((*line, format!("{t} {next}")));
        } else if t.strip_prefix("-A").is_some_and(lowered) {
            out.push((*line, t.clone()));
        }
    }
    out
}

/// Nothing turns the lint off but [`EXEMPTION`], and that is there, once, on its test.
fn allowance_findings(sources: &[(String, String)], manifests: &[(String, String)], others: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut exempt = 0;
    for (file, src) in sources {
        if file == THIS {
            continue;
        }
        let lines: Vec<&str> = src.lines().collect();
        let mut seen = None;
        for (i, _) in lowered_attributes(src) {
            if seen == Some(i) {
                continue;
            }
            seen = Some(i);
            let text = lines[i];
            let on_exempt_test = file == EXEMPTION.0
                && text.trim() == "#[allow(clippy::disallowed_methods)]"
                && lines[i + 1..]
                    .iter()
                    .find(|l| !l.trim_start().starts_with("#["))
                    .is_some_and(|l| l.contains(EXEMPTION.1));
            if on_exempt_test {
                exempt += 1;
                continue;
            }
            out.push(format!("{file}:{}: turns off the refusal of the unstrict check: {}", i + 1, text.trim()));
        }
    }
    if exempt != 1 {
        out.push(format!(
            "{}: the one exemption is `#[allow(clippy::disallowed_methods)]` on `{}`, once; found {exempt}",
            EXEMPTION.0, EXEMPTION.1
        ));
    }
    for (file, text) in manifests.iter().chain(others) {
        if !is_manifest(file) {
            // A file that runs the lint, read as text: a line that names the lint.
            for (i, line) in text.lines().enumerate() {
                let t = line.trim();
                if !t.starts_with('#') && OFF.iter().any(|w| t.contains(w)) {
                    out.push(format!("{file}:{}: turns off the refusal of the unstrict check: {t}", i + 1));
                }
            }
            continue;
        }
        // A manifest, parsed: a `[lints]` entry in any of its forms is one (table, tool.lint,
        // level). A manifest that does not parse is `feature_findings`' finding.
        let Ok(m) = Manifest::read(text) else { continue };
        for (table, lint, level) in &m.lints {
            let lowers = level == "allow" || level == "expect";
            let the_lint = OFF.iter().any(|w| *lint == format!("clippy.{w}"));
            let group = matches!(lint.as_str(), "clippy.all" | "clippy.style" | "rust.warnings");
            if the_lint && !lowers {
                out.push(format!(
                    "{file}: [{table}] {lint} = \"{level}\": sets the refusal's level, which clippy.toml and -D warnings hold"
                ));
            } else if (the_lint || group) && lowers {
                out.push(format!("{file}: [{table}] {lint} = \"{level}\": turns off the refusal of the unstrict check"));
            }
        }
    }
    for (file, text) in others {
        for (line, what) in lowered_on_command_line(text) {
            let at = format!("{file}:{line}: ");
            if !out.iter().any(|f| f.starts_with(&at)) {
                out.push(format!("{at}turns off the refusal of the unstrict check: {what}"));
            }
        }
    }
    out
}

/// No manifest turns on a feature in [`FEATURES`] of [`LIBRARY`]: on the dependency itself
/// (inline or table form, renamed or not) or through a feature of its own (`dalek/feature`).
/// A manifest that does not parse is a finding: what it turns on cannot be read.
fn feature_findings<'a>(manifests: impl Iterator<Item = &'a (String, String)>) -> Vec<String> {
    let mut out = Vec::new();
    for (file, text) in manifests {
        let parsed = match Manifest::read(text) {
            Ok(m) => m,
            Err(e) => {
                out.push(format!("{file}: {e}"));
                continue;
            }
        };
        let names: Vec<&str> = parsed.deps.iter().filter(|d| d.package == LIBRARY).map(|d| d.key.as_str()).collect();
        let mut refuse = |at: String, feature: &str| {
            if let Some((f, why)) = FEATURES.iter().find(|(f, _)| *f == feature) {
                out.push(format!("{file}: {at} turns on {LIBRARY}'s `{f}` feature, which {why}"));
            }
        };
        for d in parsed.deps.iter().filter(|d| d.package == LIBRARY) {
            for f in &d.features {
                refuse(format!("[{}] {}", d.table, d.key), f);
            }
        }
        for (name, value) in &parsed.feature_values {
            let Some((dep, feature)) = value.split_once('/') else { continue };
            let dep = dep.trim_end_matches('?');
            if dep == LIBRARY || names.contains(&dep) {
                refuse(format!("[features] {name}"), feature);
            }
        }
    }
    out
}

/// The threshold library, by package name: [`THRESHOLD_CORE`] and every package the lockfiles
/// record from outside the tree (one with a `source`) that depends on a package of the library,
/// read to a fixed point so a package that reaches the core through another is one. A package
/// of the tree (no `source`; `kotton-crypto` among them) is not the library: it is held by the
/// manifest rule instead. A lockfile that does not parse is a finding, naming the file.
fn threshold_packages(lockfiles: &[(String, String)]) -> Result<BTreeSet<String>, String> {
    // (name, the names it depends on), for each package from outside the tree.
    let mut outside: Vec<(String, Vec<String>)> = Vec::new();
    for (file, text) in lockfiles {
        let lock = parse(text).map_err(|e| format!("{file}: {e}"))?;
        for p in lock.get("package").and_then(Value::as_array).into_iter().flatten() {
            if p.get("source").is_none() {
                continue;
            }
            let Some(name) = p.get("name").and_then(Value::as_str) else { continue };
            // An entry is `name`, `name version` or `name version (source)`.
            let deps = p
                .get("dependencies")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(|d| d.split_whitespace().next())
                .map(str::to_string)
                .collect();
            outside.push((name.to_string(), deps));
        }
    }
    let mut library = BTreeSet::from([THRESHOLD_CORE.to_string()]);
    loop {
        let before = library.len();
        for (name, deps) in &outside {
            if deps.iter().any(|d| library.contains(d)) {
                library.insert(name.clone());
            }
        }
        if library.len() == before {
            return Ok(library);
        }
    }
}

/// No manifest but [`THRESHOLD_HOME`] lists a package of the threshold library (`threshold`,
/// from `threshold_packages`), in any dependency table, inline or table form, renamed or not.
/// The root manifest's `[workspace.dependencies]` entry declares the version a member inherits
/// and is not a dependency, so it is not a finding. A manifest that does not parse is
/// `feature_findings`' finding.
fn threshold_findings<'a>(
    manifests: impl Iterator<Item = &'a (String, String)>,
    threshold: &BTreeSet<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (file, text) in manifests {
        if file == THRESHOLD_HOME {
            continue;
        }
        let Ok(m) = Manifest::read(text) else { continue };
        for d in m.deps.iter().filter(|d| threshold.contains(&d.package)) {
            if file == "Cargo.toml" && d.table == "workspace.dependencies" {
                continue;
            }
            out.push(format!(
                "{file}: [{}] {} lists {}: the threshold library is a dependency of {THRESHOLD_HOME} alone; \
                 use its provider, kotton_crypto::frost",
                d.table, d.key, d.package
            ));
        }
    }
    out
}

/// `verify_strict` is called in [`SEAM`] and in no other file. Comment lines are skipped, and
/// so is this check's own source, whose tests spell what it refuses.
fn seam_findings(sources: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seam_calls = 0;
    for (file, src) in sources {
        if file == THIS {
            continue;
        }
        for (i, text) in src.lines().enumerate() {
            if text.trim_start().starts_with("//") || !text.contains("verify_strict") {
                continue;
            }
            if file == SEAM {
                seam_calls += 1;
                continue;
            }
            out.push(format!(
                "{file}:{}: calls verify_strict outside {SEAM}; check through kotton_ed25519::VerifyingKey::verify",
                i + 1
            ));
        }
    }
    if seam_calls == 0 {
        out.push(format!("{SEAM}: the seam calls no verify_strict"));
    }
    out
}

/// Whether a file, by its relative path, is a crate's or the workspace's manifest.
fn is_manifest(file: &str) -> bool {
    file == "Cargo.toml" || file.ends_with("/Cargo.toml")
}

/// `text` parsed as TOML, or why it does not parse (the parser's message and the line).
fn parse(text: &str) -> Result<Table, String> {
    text.parse::<Table>().map_err(|e| {
        let line = e.span().map(|s| text[..s.start.min(text.len())].lines().count().max(1));
        let at = line.map(|l| format!(" at line {l}")).unwrap_or_default();
        format!("does not parse as TOML{at}, so nothing in it can be read: {}", e.message().trim())
    })
}

/// A dependency as a manifest names it: the key it is named by, the package it is, the
/// features it turns on, and the table it is in (`dependencies`, `workspace.dependencies`,
/// `target.'cfg(unix)'.dev-dependencies`, ..).
struct Dep {
    key: String,
    package: String,
    features: Vec<String>,
    table: String,
}

/// What this check reads of a parsed `Cargo.toml`: its dependencies in
/// every dependency table, the values of its `[features]`, and its lint levels.
struct Manifest {
    deps: Vec<Dep>,
    /// (the feature, a value it turns on).
    feature_values: Vec<(String, String)>,
    /// (the table, `tool.lint`, its level), from `[lints]` and `[workspace.lints]`. A tool's
    /// table, a lint's own table with `level`, a dotted key and an inline table all parse to
    /// the same shape, so each is read the same way.
    lints: Vec<(String, String, String)>,
}

/// The dependency tables, as cargo spells them (the `_` forms are cargo's older spelling, which
/// it still reads).
const DEPENDENCY_TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies", "dev_dependencies", "build_dependencies"];

impl Manifest {
    fn read(text: &str) -> Result<Manifest, String> {
        let t = parse(text)?;
        let table = |v: Option<&Value>| v.and_then(Value::as_table).cloned().unwrap_or_default();
        let strings = |v: Option<&Value>| -> Vec<String> {
            v.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()
        };
        let mut m = Manifest {
            deps: Vec::new(),
            feature_values: Vec::new(),
            lints: Vec::new(),
        };

        // Every dependency table: at the top, under `workspace`, and under each target.
        let workspace = table(t.get("workspace"));
        let mut tables: Vec<(String, Table)> = Vec::new();
        for kind in DEPENDENCY_TABLES {
            tables.push((kind.to_string(), table(t.get(*kind))));
            tables.push((format!("workspace.{kind}"), table(workspace.get(*kind))));
            for (cfg, target) in table(t.get("target")) {
                tables.push((format!("target.'{cfg}'.{kind}"), table(target.get(*kind))));
            }
        }
        for (name, deps) in tables {
            for (key, entry) in deps {
                // `name = "1"` names the package by its key and turns on no feature.
                let package = entry.get("package").and_then(Value::as_str).unwrap_or(&key).to_string();
                let features = strings(entry.get("features"));
                m.deps.push(Dep { key, package, features, table: name.clone() });
            }
        }

        for (feature, values) in table(t.get("features")) {
            for v in strings(Some(&values)) {
                m.feature_values.push((feature.clone(), v));
            }
        }

        for (name, lints) in [("lints", table(t.get("lints"))), ("workspace.lints", table(workspace.get("lints")))] {
            // `[lints] workspace = true` is a bool, not a tool's table, and sets nothing here.
            for (tool, levels) in lints {
                for (lint, level) in table(Some(&levels)) {
                    let level = level.as_str().or_else(|| level.get("level").and_then(Value::as_str)).unwrap_or("");
                    m.lints.push((format!("{name}.{tool}"), format!("{tool}.{lint}"), level.to_string()));
                }
            }
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(file: &str, src: &str) -> Vec<(String, String)> {
        vec![(file.to_string(), src.to_string())]
    }

    const EXEMPT_SRC: &str = "#[cfg(test)]\nmod tests {\n    /// Why.\n    #[test]\n    #[allow(clippy::disallowed_methods)]\n    fn the_library_s_other_check_accepts_what_the_rule_refuses() {}\n}\n";

    #[test]
    fn the_printed_text_names_no_check_as_outside_the_rule() {
        for text in [ok_line(1), failure_footer()] {
            assert!(!text.contains("#564"), "{text}");
            assert!(!text.contains("outside"), "{text}");
        }
    }

    #[test]
    fn the_config_names_both_methods_and_is_not_shadowed() {
        let good = GOOD_CONFIG;
        assert!(config_findings(Some(good), &[]).is_empty());
        let one_only = GOOD_CONFIG.replace("  { path = \"ed25519_dalek::SigningKey::verify\"", "  # { path = \"ed25519_dalek::SigningKey::verify\"");
        assert_eq!(config_findings(Some(&one_only), &[]).len(), 1);
        assert_eq!(config_findings(None, &[]).len(), 1);
        assert_eq!(config_findings(Some(good), &["infra/relay/clippy.toml".into()]).len(), 1);
    }

    #[test]
    fn the_one_exemption_passes_and_any_other_allow_is_a_finding() {
        assert!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &[], &[]).is_empty());

        // The same allow anywhere else, or on another test, is a finding.
        let elsewhere = EXEMPT_SRC.replace("fn the_library_s_other_check", "fn another_check");
        assert_eq!(allowance_findings(&one(EXEMPTION.0, &elsewhere), &[], &[]).len(), 2);
        let mut two = one(EXEMPTION.0, EXEMPT_SRC);
        two.push(("core/msg/src/x.rs".into(), "#![allow(clippy::disallowed_methods)]\n".into()));
        assert_eq!(allowance_findings(&two, &[], &[]).len(), 1);

        // A lint group that holds it, allowed, is a finding.
        let mut group = one(EXEMPTION.0, EXEMPT_SRC);
        group.push(("core/msg/src/x.rs".into(), "#[allow(clippy::style)]\nfn f() {}\n".into()));
        assert_eq!(allowance_findings(&group, &[], &[]).len(), 1);

        // So is turning it off in a manifest or on the command line.
        let manifest = vec![("Cargo.toml".to_string(), "[workspace.lints.clippy]\ndisallowed_methods = \"allow\"\n".to_string())];
        assert_eq!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &manifest, &[]).len(), 1);
        let style = vec![("core/msg/Cargo.toml".to_string(), "[lints.clippy]\nstyle = \"allow\"\n".to_string())];
        assert_eq!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &style, &[]).len(), 1);
        let just = vec![("Justfile".to_string(), "lint:\n    cargo clippy -- -A clippy::disallowed_methods\n".to_string())];
        assert_eq!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &[], &just).len(), 1);

        // And the exemption gone is a finding: the allowance does not outlive its test.
        assert_eq!(allowance_findings(&one(EXEMPTION.0, "fn f() {}\n"), &[], &[]).len(), 1);
    }

    #[test]
    fn verify_strict_outside_the_seam_is_a_finding() {
        let seam = (SEAM.to_string(), "pub fn verify() { key.verify_strict(m, s) }\n".to_string());
        let comment = ("core/msg/src/a.rs".to_string(), "// verify_strict, in prose\n".to_string());
        let this = (THIS.to_string(), "let s = \"key.verify_strict(m, s)\";\n".to_string());
        assert!(seam_findings(&[seam.clone(), comment, this]).is_empty());

        // Anywhere else: a crate that links kotton-crypto, one beneath it, and the relay.
        for file in ["core/msg/src/envelope.rs", "core/crypto/src/provider/ed25519.rs", "core/pair/src/browser.rs", "infra/relay/src/auth.rs"] {
            let other = (file.to_string(), "fn f() {\n    key.verify_strict(m, s)\n}\n".to_string());
            let found = seam_findings(&[seam.clone(), other]);
            assert_eq!(found.len(), 1, "{file}: {found:?}");
            assert!(found[0].starts_with(&format!("{file}:2:")), "{found:?}");
        }

        // A seam that no longer calls verify_strict is a finding.
        assert_eq!(seam_findings(&[(SEAM.to_string(), "pub fn verify() {}\n".to_string())]).len(), 1);
    }

    /// The whole check, over a tree: a second file that calls `verify_strict`, in the
    /// workspace or in the relay, fails it.
    #[test]
    fn a_second_file_calling_verify_strict_fails_the_check() {
        for file in ["core/pair/src/browser.rs", "infra/relay/src/auth.rs"] {
            let found = findings_with(file, "pub fn check() { key.verify_strict(m, s) }\n");
            assert_eq!(found.len(), 1, "{file}: {found:#?}");
            assert!(found[0].starts_with(&format!("{file}:1: calls verify_strict outside {SEAM}")), "{found:#?}");
        }
    }

    #[test]
    fn an_allow_or_expect_of_warnings_is_a_finding() {
        let with = |src: &str| {
            let mut v = one(EXEMPTION.0, EXEMPT_SRC);
            v.push(("core/msg/src/x.rs".into(), src.into()));
            allowance_findings(&v, &[], &[]).len()
        };
        // On an item, a module and a crate; allowed or expected; alone, beside another lint,
        // under cfg_attr, and over several lines.
        assert_eq!(with("#[allow(warnings)]\nfn f() {}\n"), 1);
        assert_eq!(with("mod m {\n    #![allow(warnings)]\n}\n"), 1);
        assert_eq!(with("#![allow(warnings)]\n"), 1);
        assert_eq!(with("#[expect(warnings)]\nfn f() {}\n"), 1);
        assert_eq!(with("#[allow(dead_code, warnings)]\nfn f() {}\n"), 1);
        assert_eq!(with("#![cfg_attr(test, allow(unused, warnings))]\n"), 1);
        assert_eq!(with("#[allow(\n    dead_code,\n    warnings,\n)]\nfn f() {}\n"), 1);
        // The lint and its groups, as before.
        assert_eq!(with("#[expect(clippy::disallowed_methods)]\nfn f() {}\n"), 1);
        assert_eq!(with("#[allow(clippy::all)]\nfn f() {}\n"), 1);
        // A lint that does not hold the refusal is not a finding.
        assert_eq!(with("#[allow(dead_code, clippy::needless_return)]\nfn f() {}\n"), 0);
        assert_eq!(with("#[allow(unused_must_use)]\nfn warnings() {}\n"), 0);
    }

    #[test]
    fn the_files_that_run_the_lint_lower_nothing() {
        let with = |file: &str, text: &str| {
            let others = vec![(file.to_string(), text.to_string())];
            allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &[], &others).len()
        };
        // `-A warnings`, in each spelling, in the Justfile, a recipe module, a workflow and a
        // cargo configuration, on a command line or in RUSTFLAGS or CLIPPY_ARGS.
        assert_eq!(with("Justfile", "lint:\n    cargo clippy --all-targets -- -D warnings -A warnings\n"), 1);
        assert_eq!(with("just/lint.just", "x:\n    cargo clippy -- -Awarnings\n"), 1);
        assert_eq!(with(".github/workflows/lint.yml", "env:\n  RUSTFLAGS: \"--allow=warnings\"\n"), 1);
        assert_eq!(with("Justfile", "export CLIPPY_ARGS := \"--allow clippy::all\"\n"), 1);
        assert_eq!(with(".cargo/config.toml", "[build]\nrustflags = [\n    \"-A\",\n    \"warnings\",\n]\n"), 1);
        assert_eq!(with("Justfile", "lint:\n    cargo clippy -- \\\n        -A \\\n        warnings\n"), 1);
        // `--cap-lints`.
        assert_eq!(with("infra/relay/.cargo/config.toml", "[build]\nrustflags = [\"--cap-lints\", \"warn\"]\n"), 1);
        assert_eq!(with(".github/workflows/lint.yml", "      - run: RUSTFLAGS='--cap-lints allow' just lint\n"), 1);
        // CLIPPY_CONF_DIR, which points clippy past the root's clippy.toml.
        assert_eq!(with("just/lint.just", "export CLIPPY_CONF_DIR := \"/tmp\"\n"), 1);
        assert_eq!(with(".cargo/config.toml", "[env]\nCLIPPY_CONF_DIR = \"x\"\n"), 1);
        // Holding warnings as errors, and a comment, are not findings.
        assert_eq!(with("Justfile", "# -A warnings, CLIPPY_CONF_DIR\nlint:\n    cargo clippy --all-targets -- -D warnings\n"), 0);
        assert_eq!(with(".github/workflows/lint.yml", "env:\n  RUSTFLAGS: -D warnings\n"), 0);
    }

    #[test]
    fn a_lints_table_allowing_warnings_is_a_finding() {
        let with = |text: &str| {
            let manifests = vec![("core/msg/Cargo.toml".to_string(), text.to_string())];
            allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &manifests, &[]).len()
        };
        assert_eq!(with("[lints.rust]\nwarnings = \"allow\"\n"), 1);
        assert_eq!(with("[workspace.lints.rust]\nwarnings = { level = \"expect\", priority = 1 }\n"), 1);
        assert_eq!(with("[lints.rust]\nunsafe_code = \"allow\"\n"), 0);
    }

    #[test]
    fn a_feature_that_adds_a_check_is_a_finding() {
        let with = |text: &str| feature_findings([("core/msg/Cargo.toml".to_string(), text.to_string())].iter()).len();
        // The features that add a check other than the two clippy.toml refuses, or loosen the
        // strict one.
        let named: Vec<&str> = FEATURES.iter().map(|(f, _)| *f).collect();
        assert_eq!(named, ["batch", "digest", "hazmat", "legacy_compatibility"]);
        for f in named {
            // Inline, on the workspace's entry or a member's, in a target's table.
            assert_eq!(with(&format!("[dependencies]\ned25519-dalek = {{ version = \"2\", features = [\"rand_core\", \"{f}\"] }}\n")), 1, "{f}");
            assert_eq!(with(&format!("[workspace.dependencies]\ned25519-dalek = {{ version = \"2\", features = [\"{f}\"] }}\n")), 1, "{f}");
            assert_eq!(with(&format!("[dev-dependencies]\ned25519-dalek = {{ workspace = true, features = [\n    \"{f}\",\n] }}\n")), 1, "{f}");
            assert_eq!(with(&format!("[target.'cfg(unix)'.dependencies]\ned25519-dalek = {{ version = \"2\", features = [\"{f}\"] }}\n")), 1, "{f}");
            // In table form, and renamed.
            assert_eq!(with(&format!("[dependencies.ed25519-dalek]\nversion = \"2\"\nfeatures = [\"{f}\"]\n")), 1, "{f}");
            assert_eq!(with(&format!("[dependencies]\ndalek = {{ package = \"ed25519-dalek\", version = \"2\", features = [\"{f}\"] }}\n")), 1, "{f}");
            assert_eq!(with(&format!("[dependencies.dalek]\npackage = \"ed25519-dalek\"\nfeatures = [\"{f}\"]\n")), 1, "{f}");
            // Through a feature of the crate's own, by name or by its rename.
            assert_eq!(with(&format!("[features]\nfast = [\"ed25519-dalek/{f}\"]\n[dependencies]\ned25519-dalek = \"2\"\n")), 1, "{f}");
            assert_eq!(with(&format!("[features]\nfast = [\"dalek?/{f}\"]\n[dependencies]\ndalek = {{ package = \"ed25519-dalek\", version = \"2\", optional = true }}\n")), 1, "{f}");
            // The same feature of another crate is not a finding.
            assert_eq!(with(&format!("[dependencies]\nother = {{ version = \"1\", features = [\"{f}\"] }}\n")), 0, "{f}");
        }
        // The features the tree turns on are not findings: workspace-hack's line as it is.
        assert_eq!(with("[dependencies]\ned25519-dalek = { version = \"2.2.0\", default-features = false, features = [\"alloc\", \"default\", \"fast\", \"rand_core\", \"std\", \"zeroize\"] }\n"), 0);
    }

    const GOOD_CONFIG: &str = "disallowed-methods = [\n  { path = \"ed25519_dalek::Verifier::verify\", reason = \"r\" },\n  { path = \"ed25519_dalek::SigningKey::verify\", reason = \"r\" },\n  { path = \"frost_core::VerifyingKey::verify\", reason = \"r\" },\n  { path = \"frost_core::batch::Verifier::verify\", reason = \"r\" },\n  { path = \"frost_core::batch::Item::verify_single\", reason = \"r\" },\n  { path = \"frost_core::Ciphersuite::verify_signature\", reason = \"r\" },\n]\n";
    const GOOD_JUSTFILE: &str = "lint:\n    # cargo clippy, in prose\n    cargo clippy --all-targets -- -D warnings\n    cargo clippy --manifest-path infra/relay/Cargo.toml --target-dir {{relay_target}} --all-targets -- -D warnings\n";

    /// A tree that holds, at `dir`: `clippy.toml`, the seam with the exemption in it, a root manifest
    /// and a Justfile, each as the tree has it in the part this check reads.
    fn a_tree(dir: &Path) {
        let write = |path: &str, text: &str| {
            let path = dir.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(CLIPPY_TOML, GOOD_CONFIG);
        write(SEAM, &format!("pub fn verify() {{ key.verify_strict(m, s) }}\n{EXEMPT_SRC}"));
        write("core/ed25519/Cargo.toml", "[package]\nname = \"kotton-ed25519\"\n");
        write("Cargo.toml", "[workspace.dependencies]\ned25519-dalek = { version = \"2.1\", features = [\"rand_core\"] }\n");
        write("Justfile", GOOD_JUSTFILE);
        write("Cargo.lock", FIXTURE_LOCK);
    }

    /// The threshold library's entries as the workspace's `Cargo.lock` records them at 2.2.0,
    /// trimmed to the edges that matter, with `kotton-crypto` depending on it and a member
    /// depending on `kotton-crypto`.
    const FIXTURE_LOCK: &str = "version = 4

[[package]]
name = \"frost-core\"
version = \"2.2.0\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
dependencies = [
 \"hex\",
]

[[package]]
name = \"frost-ed25519\"
version = \"2.2.0\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
dependencies = [
 \"curve25519-dalek\",
 \"frost-core\",
 \"frost-rerandomized\",
 \"rand_core 0.6.4\",
]

[[package]]
name = \"frost-rerandomized\"
version = \"2.2.0\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
dependencies = [
 \"frost-core\",
 \"hex\",
]

[[package]]
name = \"hex\"
version = \"0.4.3\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"

[[package]]
name = \"kotton-crypto\"
version = \"0.1.0\"
dependencies = [
 \"frost-ed25519\",
]

[[package]]
name = \"kotton-org\"
version = \"0.1.0\"
dependencies = [
 \"kotton-crypto\",
]
";

    /// [`FIXTURE_LOCK`] with `extra` appended: packages a lockfile gains.
    fn lock_with(extra: &str) -> String {
        format!("{FIXTURE_LOCK}\n{extra}")
    }

    /// The findings of [`a_tree`] with each (path, text) written over it.
    fn findings_with_all(files: &[(&str, &str)]) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        a_tree(dir.path());
        for (path, text) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        findings(dir.path()).1
    }

    fn findings_with(path: &str, text: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        a_tree(dir.path());
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
        findings(dir.path()).1
    }

    #[test]
    fn a_tree_as_the_fixture_has_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        a_tree(dir.path());
        let (count, found) = findings(dir.path());
        assert_eq!(count, 1);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn the_root_manifests_workspace_entry_is_read_for_features() {
        for (f, _) in FEATURES {
            let inline = format!("[workspace.dependencies]\ned25519-dalek = {{ version = \"2.1\", features = [\"rand_core\", \"{f}\"] }}\n");
            assert_eq!(findings_with("Cargo.toml", &inline).len(), 1, "{f}");
            let table = format!("[workspace.dependencies.ed25519-dalek]\nversion = \"2.1\"\nfeatures = [\n    \"{f}\",\n]\n");
            assert_eq!(findings_with("Cargo.toml", &table).len(), 1, "{f}");
        }
    }

    #[test]
    fn a_root_dot_clippy_toml_is_a_finding() {
        let found = findings_with(".clippy.toml", "");
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with(".clippy.toml:"), "{found:#?}");
    }

    #[test]
    fn the_methods_are_read_only_under_disallowed_methods() {
        assert!(config_findings(Some(GOOD_CONFIG), &[]).is_empty());
        // Named under another key, or under a table's key of the same name, is not refusing.
        let other_key = GOOD_CONFIG.replace("disallowed-methods", "disallowed-types");
        let every = REFUSED.len() + THRESHOLD_REFUSED.len();
        assert_eq!(config_findings(Some(&other_key), &[]).len(), every);
        let in_a_table = format!("[elsewhere]\n{GOOD_CONFIG}");
        assert_eq!(config_findings(Some(&in_a_table), &[]).len(), every);
        let split = "disallowed-methods = [\n  { path = \"ed25519_dalek::Verifier::verify\", reason = \"r\" },\n  { path = \"frost_core::VerifyingKey::verify\", reason = \"r\" },\n  { path = \"frost_core::batch::Verifier::verify\", reason = \"r\" },\n  { path = \"frost_core::batch::Item::verify_single\", reason = \"r\" },\n  { path = \"frost_core::Ciphersuite::verify_signature\", reason = \"r\" },\n]\nmsrv = \"1.80\" # ed25519_dalek::SigningKey::verify\ndisallowed-types = [\"ed25519_dalek::SigningKey::verify\"]\n";
        assert_eq!(config_findings(Some(split), &[]).len(), 1);
    }

    #[test]
    fn whitespace_in_an_attribute_is_not_read() {
        let with = |src: &str| {
            let mut v = one(EXEMPTION.0, EXEMPT_SRC);
            v.push(("core/msg/src/x.rs".into(), src.into()));
            allowance_findings(&v, &[], &[]).len()
        };
        assert_eq!(with("#[allow (warnings)]\nfn f() {}\n"), 1);
        assert_eq!(with("#[ expect ( warnings ) ]\nfn f() {}\n"), 1);
        assert_eq!(with("#[allow(clippy :: all)]\nfn f() {}\n"), 1);
        assert_eq!(with("#[allow(clippy:: disallowed_methods)]\nfn f() {}\n"), 1);
        assert_eq!(with("#![allow(dead_code, clippy ::\n    style)]\n"), 1);
        assert_eq!(with("#[allow\n(warnings)]\nfn f() {}\n"), 1);
        assert_eq!(with("#[allow (dead_code)]\nfn f() {}\n"), 0);
        assert_eq!(with("fn disallow (warnings: u8) {}\n"), 0);
    }

    #[test]
    fn a_lint_set_in_table_form_or_by_dotted_key_is_a_finding() {
        let with = |text: &str| {
            let manifests = vec![("core/msg/Cargo.toml".to_string(), text.to_string())];
            allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &manifests, &[]).len()
        };
        assert_eq!(with("[lints.clippy.style]\nlevel = \"allow\"\npriority = -1\n"), 1);
        assert_eq!(with("[workspace.lints.clippy.all]\nlevel = \"expect\"\n"), 1);
        assert_eq!(with("[lints.rust.warnings]\nlevel = \"allow\"\n"), 1);
        assert_eq!(with("[lints.clippy.disallowed_methods]\nlevel = \"allow\"\n"), 1);
        assert_eq!(with("[lints]\nclippy.style = \"allow\"\n"), 1);
        assert_eq!(with("[workspace.lints]\nrust.warnings = { level = \"allow\" }\n"), 1);
        assert_eq!(with("[lints]\nclippy = { all = \"allow\" }\n"), 1);
        assert_eq!(with("[ lints . clippy ]\nstyle = \"allow\"\n"), 1);
        // Held, or another lint, or inherited, is not a finding.
        assert_eq!(with("[lints.clippy.style]\nlevel = \"deny\"\n"), 0);
        assert_eq!(with("[lints]\nclippy.needless_return = \"allow\"\nrust.unsafe_code = \"allow\"\n"), 0);
        assert_eq!(with("[lints]\nworkspace = true\n"), 0);
    }

    #[test]
    fn the_lint_runs_are_held() {
        let with = |text: &str| lint_run_findings(&[("Justfile".to_string(), text.to_string())]);
        assert!(with(GOOD_JUSTFILE).is_empty(), "{:#?}", with(GOOD_JUSTFILE));
        // The workspace run without --all-targets, or without -D warnings after `--`.
        assert_eq!(with(&GOOD_JUSTFILE.replace("cargo clippy --all-targets --", "cargo clippy --")).len(), 1);
        assert_eq!(with(&GOOD_JUSTFILE.replace("cargo clippy --all-targets -- -D warnings\n", "cargo clippy --all-targets\n")).len(), 1);
        assert_eq!(with(&GOOD_JUSTFILE.replace("cargo clippy --all-targets -- -D warnings\n", "cargo clippy --all-targets -- -W warnings\n")).len(), 1);
        // The workspace run gone, or only in a comment.
        assert_eq!(with(&GOOD_JUSTFILE.replace("    cargo clippy --all-targets -- -D warnings\n", "    # cargo clippy --all-targets -- -D warnings\n")).len(), 1);
        // The relay's run gone, or without -D warnings, or without --all-targets.
        let relay_gone: String = GOOD_JUSTFILE.lines().filter(|l| !l.contains("infra/relay")).map(|l| format!("{l}\n")).collect();
        assert_eq!(with(&relay_gone).len(), 1);
        assert_eq!(with(&GOOD_JUSTFILE.replace("--all-targets -- -D warnings\n", "--all-targets -- -D warnings -A clippy::pedantic\n").replace("relay_target}} --all-targets -- -D warnings", "relay_target}} --all-targets")).len(), 1);
        assert_eq!(with(&GOOD_JUSTFILE.replace("relay_target}} --all-targets", "relay_target}}")).len(), 1);
        // A run continued over lines is one run, and `-Dwarnings` is `-D warnings`.
        let continued = "lint:\n    cargo clippy \\\n        --all-targets \\\n        -- -Dwarnings\n    cargo clippy --manifest-path infra/relay/Cargo.toml --all-targets -- -D warnings\n";
        assert!(with(continued).is_empty(), "{:#?}", with(continued));
        // In a recipe module as well as the Justfile; and through the whole check.
        let module = lint_run_findings(&[
            ("Justfile".to_string(), "mod lint 'just/lint.just'\n".to_string()),
            ("just/lint.just".to_string(), GOOD_JUSTFILE.replace("--all-targets -- -D warnings\n    cargo", "-- -D warnings\n    cargo")),
        ]);
        assert_eq!(module.len(), 1, "{module:#?}");
        assert!(module[0].starts_with("just/lint.just:3:"), "{module:#?}");
        assert_eq!(findings_with("Justfile", &relay_gone).len(), 1);
    }

    /// A root manifest as the tree's is shaped: a `members` array over several lines whose
    /// entries carry trailing comments (one with a bracket in it), and only then
    /// `[workspace.dependencies]`.
    fn a_root_with_members(dependencies: &str) -> String {
        format!(
            "[workspace]\nresolver = \"2\"\nmembers = [\n    # core/ — grouped by authority\n    \"core/crypto\", # the seam's crate\n    \"core/msg\",    # a [bracket] in a comment\n\n    # tools\n    \"tools/pty-drive\",\n]\n\n[workspace.package]\nlicense = \"AGPL-3.0-or-later\"\n\n{dependencies}"
        )
    }

    #[test]
    fn a_root_manifest_with_a_commented_members_array_is_read_past_it() {
        for (f, _) in FEATURES {
            let inline = a_root_with_members(&format!(
                "[workspace.dependencies]\nserde = \"1\" # serialization\ned25519-dalek = {{ version = \"2.1\", features = [\"rand_core\", \"{f}\"] }}\n"
            ));
            let found = findings_with("Cargo.toml", &inline);
            assert_eq!(found.len(), 1, "{f}: {found:#?}");
            assert!(found[0].starts_with("Cargo.toml:"), "{found:#?}");
            let table = a_root_with_members(&format!(
                "[workspace.dependencies.ed25519-dalek]\nversion = \"2.1\"\nfeatures = [\n    \"rand_core\", # the default\n    \"{f}\",\n]\n"
            ));
            assert_eq!(findings_with("Cargo.toml", &table).len(), 1, "{f}");
        }
        // The same root with only the features the tree turns on holds.
        let good = a_root_with_members("[workspace.dependencies]\ned25519-dalek = { version = \"2.1\", features = [\"rand_core\"] }\n");
        assert!(findings_with("Cargo.toml", &good).is_empty(), "{:#?}", findings_with("Cargo.toml", &good));
    }

    #[test]
    fn a_member_manifest_with_a_commented_array_is_read_past_it() {
        for (f, _) in FEATURES {
            let member = |deps: &str| {
                format!("[package]\nname = \"kotton-msg\"\nkeywords = [\n    \"crypto\", # a keyword\n    \"msg\",    # [another]\n]\n\n{deps}")
            };
            let inline = member(&format!("[dependencies]\ned25519-dalek = {{ workspace = true, features = [\"{f}\"] }}\n"));
            let found = findings_with("core/msg/Cargo.toml", &inline);
            assert_eq!(found.len(), 1, "{f}: {found:#?}");
            assert!(found[0].starts_with("core/msg/Cargo.toml:"), "{found:#?}");
            let table = member(&format!("[dependencies.ed25519-dalek]\nworkspace = true\nfeatures = [\"{f}\"]\n"));
            assert_eq!(findings_with("core/msg/Cargo.toml", &table).len(), 1, "{f}");
        }
    }

    /// The reader finds the library's entry in the tree's own root manifest: a reader that
    /// silently reads nothing there fails here, not only when a feature is added.
    #[test]
    fn the_real_root_manifest_names_the_library() {
        let text = std::fs::read_to_string(crate::out::root().join("Cargo.toml")).unwrap();
        let m = Manifest::read(&text).unwrap();
        let entry = m.deps.iter().find(|d| d.package == LIBRARY && d.table == "workspace.dependencies");
        let entry = entry.unwrap_or_else(|| panic!("no {LIBRARY} entry read in the root manifest's [workspace.dependencies]"));
        assert!(entry.features.iter().any(|f| f == "rand_core"), "{:?}", entry.features);
    }

    #[test]
    fn a_manifest_or_config_that_does_not_parse_is_a_finding() {
        for path in ["Cargo.toml", "core/msg/Cargo.toml", CLIPPY_TOML] {
            let found = findings_with(path, "[dependencies\ned25519-dalek = { features = [\"digest\" }\n");
            assert!(
                found.iter().any(|f| f.starts_with(&format!("{path}: does not parse"))),
                "{path}: {found:#?}"
            );
        }
    }

    /// Each of the threshold library's own checks, gone from `clippy.toml`, is a finding.
    #[test]
    fn the_config_refuses_the_threshold_librarys_checks() {
        assert_eq!(THRESHOLD_REFUSED.len(), 4);
        for m in THRESHOLD_REFUSED {
            let line = format!("  {{ path = \"{m}\", reason = \"r\" }},\n");
            assert!(GOOD_CONFIG.contains(&line), "{m}");
            let without = GOOD_CONFIG.replace(&line, "");
            let found = config_findings(Some(&without), &[]);
            assert_eq!(found, [format!("{CLIPPY_TOML} does not refuse `{m}` (disallowed-methods)")], "{m}");
        }
    }

    /// A manifest other than kotton-crypto's that lists the threshold library fails the whole
    /// check, in any dependency table, inline or table form, renamed or not; kotton-crypto's,
    /// and the root's `[workspace.dependencies]` entry, do not.
    #[test]
    fn a_manifest_other_than_kotton_cryptos_listing_the_threshold_library_is_a_finding() {
        let member = |deps: &str| format!("[package]\nname = \"kotton-org\"\n\n{deps}");
        for package in ["frost-ed25519", "frost-core", "frost-rerandomized"] {
            for deps in [
                format!("[dependencies]\n{package} = {{ workspace = true }}\n"),
                format!("[dev-dependencies]\n{package} = \"2.2\"\n"),
                format!("[build-dependencies]\n{package} = \"2.2\"\n"),
                format!("[target.'cfg(unix)'.dependencies]\n{package} = {{ workspace = true }}\n"),
                format!("[dependencies.{package}]\nworkspace = true\n"),
                format!("[dependencies]\nthreshold = {{ package = \"{package}\", version = \"2.2\", optional = true }}\n"),
            ] {
                for file in ["core/org/Cargo.toml", "core/kuserd/Cargo.toml", "infra/relay/Cargo.toml"] {
                    let found = findings_with(file, &member(&deps));
                    assert_eq!(found.len(), 1, "{file}: {deps}: {found:#?}");
                    assert!(found[0].starts_with(&format!("{file}: [")), "{found:#?}");
                    assert!(found[0].contains(&format!("lists {package}")), "{found:#?}");
                }
                assert!(findings_with(THRESHOLD_HOME, &member(&deps)).is_empty(), "{deps}");
            }
            // The root's version declaration is not a dependency; a dependency of the root is.
            let declared = format!("[workspace.dependencies]\ned25519-dalek = {{ version = \"2.1\", features = [\"rand_core\"] }}\n{package} = {{ version = \"2.2\", features = [\"serde\"] }}\n");
            assert!(findings_with("Cargo.toml", &declared).is_empty(), "{package}");
            let depended = format!("{declared}[dependencies]\n{package} = {{ workspace = true }}\n");
            assert_eq!(findings_with("Cargo.toml", &depended).len(), 1, "{package}");
        }
        // Another package is not a finding.
        assert!(findings_with("core/org/Cargo.toml", &member("[dependencies]\nfrost = \"1\"\n")).is_empty());
    }

    /// `frost-rerandomized`, which `frost-ed25519` pulls and which re-exports the core, is the
    /// threshold library: a manifest other than kotton-crypto's that lists it is a finding, in
    /// the fixture and by the tree's own `Cargo.lock`.
    #[test]
    fn a_manifest_listing_frost_rerandomized_is_a_finding() {
        let manifest = "[package]\nname = \"kotton-org\"\n\n[dependencies]\nfrost-rerandomized = \"2.2\"\n";
        let found = findings_with("core/org/Cargo.toml", manifest);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("core/org/Cargo.toml: [dependencies] frost-rerandomized lists frost-rerandomized"), "{found:#?}");
        assert!(findings_with(THRESHOLD_HOME, manifest).is_empty());

        let root = crate::out::root();
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let library = threshold_packages(&[("Cargo.lock".to_string(), lock)]).unwrap();
        for p in ["frost-core", "frost-ed25519", "frost-rerandomized"] {
            assert!(library.contains(p), "{p}: {library:?}");
        }
    }

    /// A package a lockfile gains that depends on the core, directly or through another such
    /// package, is the threshold library without this check naming it; one that does not is
    /// not. The relay's lockfile is read as the root's is.
    #[test]
    fn a_package_a_lockfile_gains_that_reaches_the_core_is_the_threshold_library() {
        let gained = "[[package]]\nname = \"frost-p256\"\nversion = \"2.2.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"frost-core\",\n]\n\n\
                      [[package]]\nname = \"threshold-wrapper\"\nversion = \"0.3.0\"\nsource = \"git+https://example.invalid/w#0\"\ndependencies = [\n \"frost-p256 2.2.0\",\n]\n\n\
                      [[package]]\nname = \"unrelated\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"hex\",\n]\n";
        let member = |p: &str| format!("[package]\nname = \"kotton-org\"\n\n[dependencies]\n{p} = \"1\"\n");
        for lockfile in ["Cargo.lock", "infra/relay/Cargo.lock"] {
            let lock = lock_with(gained);
            for p in ["frost-p256", "threshold-wrapper"] {
                let found = findings_with_all(&[(lockfile, &lock), ("core/org/Cargo.toml", &member(p))]);
                assert_eq!(found.len(), 1, "{lockfile}: {p}: {found:#?}");
                assert!(found[0].contains(&format!("lists {p}")), "{found:#?}");
            }
            let found = findings_with_all(&[(lockfile, &lock), ("core/org/Cargo.toml", &member("unrelated"))]);
            assert!(found.is_empty(), "{lockfile}: {found:#?}");
        }
        // Without the lockfile's entries, the same manifests are not findings: the rule follows
        // the lockfile, not a list.
        for p in ["frost-p256", "threshold-wrapper"] {
            assert!(findings_with("core/org/Cargo.toml", &member(p)).is_empty(), "{p}");
        }
    }

    /// A package of the tree is not the threshold library, though it depends on it: a member
    /// depends on kotton-crypto, which is the provider the rule sends every caller to.
    #[test]
    fn a_package_of_the_tree_is_not_the_threshold_library() {
        let library = threshold_packages(&[("Cargo.lock".to_string(), FIXTURE_LOCK.to_string())]).unwrap();
        let expected: BTreeSet<String> = ["frost-core", "frost-ed25519", "frost-rerandomized"].map(str::to_string).into();
        assert_eq!(library, expected);
        let member = "[package]\nname = \"kotton-org\"\n\n[dependencies]\nkotton-crypto = { path = \"../crypto\" }\n";
        assert!(findings_with("core/org/Cargo.toml", member).is_empty());
    }

    /// A lockfile that does not parse is a finding naming it, and so is a missing root one.
    #[test]
    fn a_lockfile_that_does_not_parse_or_is_missing_is_a_finding() {
        for lockfile in ["Cargo.lock", "infra/relay/Cargo.lock"] {
            let found = findings_with(lockfile, "[[package]\nname = \"x\"\n");
            assert!(found.iter().any(|f| f.starts_with(&format!("{lockfile}: does not parse"))), "{lockfile}: {found:#?}");
        }
        let dir = tempfile::tempdir().unwrap();
        a_tree(dir.path());
        std::fs::remove_file(dir.path().join("Cargo.lock")).unwrap();
        let found = findings(dir.path()).1;
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("Cargo.lock is not at the root"), "{found:#?}");
    }

    /// The tree as it is: every hold above holds.
    #[test]
    fn the_tree_holds() {
        let (count, found) = findings(&crate::out::root());
        assert!(count > 0);
        assert!(found.is_empty(), "{found:#?}");
    }
}
