// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ed25519-check`: every Ed25519 check made with `ed25519-dalek`, the tree's signature library,
//! is strict, and goes through one seam.
//!
//! Not under this rule yet: the check of the handshake signature on a peer connection, which
//! rustls makes with ring in `core/net`'s TLS verifiers, and the threshold-signing provider's
//! `aggregate`, which `frost_ed25519` checks itself. Both are #564's.
//!
//! ## What holds it
//!
//! Two things, one typed and one textual.
//!
//! - **The workspace's `clippy.toml`** refuses `ed25519_dalek::Verifier::verify` and the
//!   inherent `ed25519_dalek::SigningKey::verify`: the two ways to make the unstrict check with
//!   the library's features the tree turns on. Clippy resolves the call, so a trait brought in
//!   under any name, a generic bound or a fully qualified call is refused as surely as
//!   `key.verify(..)`. `just lint` runs clippy over the workspace and over the relay's own
//!   workspace, `--all-targets`, so tests are held too, and with `-D warnings`, so a refusal
//!   fails the gate.
//! - **This check** holds what clippy cannot hold of itself:
//!   - the file is there and names both methods, and no other `clippy.toml` shadows it for a
//!     crate below it;
//!   - nothing lowers the refusal but the one exemption named here ([`EXEMPTION`]): no `allow`
//!     or `expect` of the lint, of a group that holds it, or of `warnings` ([`LOWERED`]), in an
//!     attribute or a manifest's `[lints]`; and, in the files that configure or run the lint,
//!     no `-A`/`--allow` of those, no `--cap-lints` and no `CLIPPY_CONF_DIR`;
//!   - no manifest turns on a feature of the library that adds a check other than the two
//!     methods `clippy.toml` names, or loosens the strict one ([`FEATURES`]);
//!   - the seam: in a crate that depends on `kotton-crypto` a check is
//!     `kotton_crypto::ed25519::verify`, so `verify_strict` is called in [`SEAM`] and, outside
//!     it, only in a crate that does not link `kotton-crypto` (`kotton-pair`, below it, and the
//!     relay).
//!
//! ## What it reads
//!
//! Every `.rs` file and `Cargo.toml` under the code roots (`tree::CODE_ROOTS`), tests
//! included; and, for what lowers the lint, the root manifest, `Justfile`, `just/*.just`, every
//! cargo configuration (`.cargo/config.toml` or `.cargo/config`) at the root or under the code
//! roots, and the workflows. It skips comment lines, and its own source, whose tests spell
//! what it refuses. A manifest's dependency is read in inline and in table form, renamed or
//! not; a dependency inherited from the workspace is read under the name the member gives it.
//! It reads text: an `allow` built by a macro, a lint level or `CLIPPY_CONF_DIR` set in an
//! environment at run time, and a feature turned on by a crate outside the tree are outside it
//! (for the workspace, `workspace-hack-check` holds the resolved feature set to
//! `tools/workspace-hack`'s manifest, which this reads). `just lint` and the workflows set none.

use std::path::Path;

use crate::user_database_check::{rel, walk};

/// The file that holds the refusal, at the root of the tree.
const CLIPPY_TOML: &str = "clippy.toml";

/// The methods it refuses: the two ways to make the unstrict check with the library's features
/// the tree turns on ([`FEATURES`] holds that no other is turned on).
const REFUSED: &[&str] = &["ed25519_dalek::Verifier::verify", "ed25519_dalek::SigningKey::verify"];

/// The library, by its package name.
const LIBRARY: &str = "ed25519-dalek";

/// The library's features that no manifest turns on, read from `ed25519-dalek` 2.2.0's source:
/// each adds a way to check a signature other than the two methods in [`REFUSED`], or
/// loosens the strict check itself.
const FEATURES: &[(&str, &str)] = &[
    ("batch", "adds verify_batch"),
    ("digest", "adds verify_prehashed, the DigestVerifier impl and the context checks"),
    ("hazmat", "adds raw_verify, raw_verify_prehashed and verify_stream"),
    ("legacy_compatibility", "has every check, verify_strict included, accept an S that is not reduced"),
];

/// The one function every crate that depends on `kotton-crypto` calls for an Ed25519 check.
const SEAM: &str = "core/crypto/src/provider/ed25519.rs";

/// The one place the lint is allowed: (file, the test it is allowed on). The test holds the
/// difference between the strict check and the other one, so it makes the other one.
const EXEMPTION: (&str, &str) = (
    "core/crypto/src/schema_signature.rs",
    "fn a_small_order_publisher_key_with_a_forged_signature_is_refused",
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
        println!(
            "ed25519-check: OK: {count} source file(s); every check made with {LIBRARY} is strict: clippy.toml \
             refuses the unstrict check, nothing lowers that but one named exemption, no manifest turns on \
             a feature that adds another check, and verify_strict is called only in the seam and in crates \
             that do not link kotton-crypto. The handshake's check and aggregate are #564's."
        );
        return;
    }
    for f in &found {
        eprintln!("ed25519-check: {f}");
    }
    eprintln!(
        "\nEvery Ed25519 check made with {LIBRARY}, the tree's signature library, is strict: \
         kotton_crypto::ed25519::verify ({SEAM}) in a crate that depends on kotton-crypto, verify_strict \
         in one that does not. (The handshake's check and aggregate are #564's.)"
    );
    std::process::exit(1);
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
    for path in &files {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
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
    let mut others = Vec::new();
    for path in &elsewhere {
        if let Ok(text) = std::fs::read_to_string(path) {
            others.push((rel(root, path), text));
        }
    }

    let config = std::fs::read_to_string(root.join(CLIPPY_TOML)).ok();
    let mut found = config_findings(config.as_deref(), &shadows);
    found.extend(allowance_findings(&sources, &manifests, &others));
    let root_manifest: Vec<(String, String)> = others.iter().filter(|(f, _)| f == "Cargo.toml").cloned().collect();
    found.extend(feature_findings(manifests.iter().chain(&root_manifest)));
    found.extend(seam_findings(&sources, &crates_linking_crypto(&manifests)));
    (sources.len(), found)
}

/// Whether `path` is a cargo configuration: `config.toml` or `config` in a `.cargo` directory.
fn is_cargo_config(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let parent = path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_string());
    parent.as_deref() == Some(".cargo") && (name == "config.toml" || name == "config")
}

/// `clippy.toml` is at the root, names every refused method, and no other shadows it.
fn config_findings(config: Option<&str>, shadows: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    match config {
        None => out.push(format!("{CLIPPY_TOML} is not at the root of the tree")),
        Some(text) => {
            let code: String = text.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n");
            for m in REFUSED {
                if !code.contains(&format!("path = \"{m}\"")) {
                    out.push(format!("{CLIPPY_TOML} does not refuse `{m}` (disallowed-methods)"));
                }
            }
        }
    }
    for s in shadows {
        out.push(format!("{s}: a clippy configuration below the root's, which the crates under it would read instead"));
    }
    out
}

/// The lint levels an `allow(..)` or `expect(..)` starting on `lines[i]` names, read to its
/// closing parenthesis across lines.
fn lowered_in_attribute(lines: &[&str], i: usize) -> Vec<String> {
    let mut out = Vec::new();
    let text = lines[i];
    for opener in ["allow(", "expect("] {
        let mut from = 0;
        while let Some(at) = text[from..].find(opener) {
            let start = from + at + opener.len();
            from = start;
            // Not `disallow(` or another word ending in it.
            let before = text[..start - opener.len()].chars().last();
            if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let mut inner = String::new();
            let mut depth = 1;
            'lines: for (n, line) in lines[i..].iter().enumerate() {
                let rest = if n == 0 { &text[start..] } else { line };
                for c in rest.chars() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break 'lines;
                            }
                        }
                        _ => {}
                    }
                    inner.push(c);
                }
                inner.push(' ');
                if n > 20 {
                    break;
                }
            }
            for token in inner.split(|c: char| c == ',' || c.is_whitespace()) {
                let token = token.trim();
                if LOWERED.contains(&token) || OFF.contains(&token) {
                    out.push(token.to_string());
                }
            }
        }
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
        for (i, text) in lines.iter().enumerate() {
            if text.trim_start().starts_with("//") {
                continue;
            }
            if lowered_in_attribute(&lines, i).is_empty() {
                continue;
            }
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
        let mut lints = None;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.starts_with('#') {
                continue;
            }
            if t.starts_with('[') {
                lints = ["clippy", "rust"].into_iter().find(|tool| t.ends_with(&format!("lints.{tool}]")));
                continue;
            }
            let key = t.split('=').next().unwrap_or("").trim().trim_matches('"');
            let lowers = t.contains("allow") || t.contains("expect");
            let group = match lints {
                Some("clippy") => (key == "all" || key == "style") && lowers,
                Some(_) => key == "warnings" && lowers,
                None => false,
            };
            if OFF.iter().any(|w| t.contains(w)) || group {
                out.push(format!("{file}:{}: turns off the refusal of the unstrict check: {t}", i + 1));
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
fn feature_findings<'a>(manifests: impl Iterator<Item = &'a (String, String)>) -> Vec<String> {
    let mut out = Vec::new();
    for (file, text) in manifests {
        let parsed = Manifest::read(text);
        let names: Vec<&str> = parsed.deps.iter().filter(|d| d.package == LIBRARY).map(|d| d.key.as_str()).collect();
        let mut refuse = |line: usize, feature: &str| {
            if let Some((f, why)) = FEATURES.iter().find(|(f, _)| *f == feature) {
                out.push(format!("{file}:{line}: turns on {LIBRARY}'s `{f}` feature, which {why}"));
            }
        };
        for d in parsed.deps.iter().filter(|d| d.package == LIBRARY) {
            for f in &d.features {
                refuse(d.line, f);
            }
        }
        for (line, value) in &parsed.feature_values {
            let Some((dep, feature)) = value.split_once('/') else { continue };
            let dep = dep.trim_end_matches('?');
            if dep == LIBRARY || names.contains(&dep) {
                refuse(*line, feature);
            }
        }
    }
    out
}

/// `verify_strict` is called in [`SEAM`], and elsewhere only in a crate that does not link
/// `kotton-crypto`. `crypto_crates` holds the directories of the crates that do, and
/// `kotton-crypto`'s own.
fn seam_findings(sources: &[(String, String)], crypto_crates: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seam_calls = 0;
    for (file, src) in sources {
        let linked = crypto_crates.iter().any(|dir| file.starts_with(&format!("{dir}/")));
        for (i, text) in src.lines().enumerate() {
            if text.trim_start().starts_with("//") || !text.contains("verify_strict") {
                continue;
            }
            if file == SEAM {
                seam_calls += 1;
                continue;
            }
            if linked {
                out.push(format!(
                    "{file}:{}: calls verify_strict in a crate that links kotton-crypto; call kotton_crypto::ed25519::verify",
                    i + 1
                ));
            }
        }
    }
    if seam_calls == 0 {
        out.push(format!("{SEAM}: the seam calls no verify_strict"));
    }
    out
}

/// The directories (relative, `/`-separated) of `kotton-crypto` and every crate whose manifest
/// names it.
fn crates_linking_crypto(manifests: &[(String, String)]) -> Vec<String> {
    manifests
        .iter()
        .filter(|(_, text)| manifest_links_crypto(text))
        .map(|(file, _)| file.strip_suffix("Cargo.toml").unwrap_or(file).trim_end_matches('/').to_string())
        .collect()
}

/// Whether a manifest is `kotton-crypto`'s or names it as a dependency of any kind.
fn manifest_links_crypto(text: &str) -> bool {
    let m = Manifest::read(text);
    m.package.as_deref() == Some("kotton-crypto") || m.deps.iter().any(|d| d.package == "kotton-crypto")
}

/// A dependency as a manifest names it: the key it is named by, the package it is, the
/// features it turns on, and the line it starts on.
struct Dep {
    key: String,
    package: String,
    features: Vec<String>,
    line: usize,
}

/// What this check reads of a `Cargo.toml`: its package's name, its dependencies in every
/// dependency table (inline and table form), and the values of its `[features]`.
struct Manifest {
    package: Option<String>,
    deps: Vec<Dep>,
    feature_values: Vec<(usize, String)>,
}

impl Manifest {
    fn read(text: &str) -> Manifest {
        let mut m = Manifest { package: None, deps: Vec::new(), feature_values: Vec::new() };
        let mut section = String::new();
        // A dependency in table form: its index in `deps`.
        let mut table_dep: Option<usize> = None;
        for (line, key, value) in entries(text) {
            if key.is_empty() {
                section = value;
                table_dep = None;
                if let Some(name) = dependency_table(&section) {
                    m.deps.push(Dep { key: name.clone(), package: name, features: Vec::new(), line });
                    table_dep = Some(m.deps.len() - 1);
                }
                continue;
            }
            if let Some(at) = table_dep {
                match key.as_str() {
                    "package" => m.deps[at].package = strings(&value).into_iter().next().unwrap_or_default(),
                    "features" => m.deps[at].features = strings(&value),
                    _ => {}
                }
            } else if is_dependency_section(&section) {
                let value = value.trim();
                let (package, features) = if value.starts_with('{') {
                    (inline_value(value, "package").and_then(|v| strings(&v).into_iter().next()), inline_value(value, "features").map(|v| strings(&v)).unwrap_or_default())
                } else {
                    (None, Vec::new())
                };
                m.deps.push(Dep { package: package.unwrap_or_else(|| key.clone()), key, features, line });
            } else if section == "features" {
                for s in strings(&value) {
                    m.feature_values.push((line, s));
                }
            } else if section == "package" && key == "name" {
                m.package = strings(&value).into_iter().next();
            }
        }
        m
    }
}

/// Whether a section is a dependency table: `dependencies`, `dev-dependencies` or
/// `build-dependencies`, under `workspace` or a `target` or at the top.
fn is_dependency_section(section: &str) -> bool {
    ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .any(|d| section == *d || section.ends_with(&format!(".{d}")))
}

/// The dependency a section names in table form (`dependencies.name`), if it names one.
fn dependency_table(section: &str) -> Option<String> {
    let (table, name) = section.rsplit_once('.')?;
    is_dependency_section(table).then(|| name.trim_matches('"').trim_matches('\'').to_string())
}

/// A manifest's entries as (line, key, value): a section header is ("", its name), and a value
/// that spans lines (an array) is read to its close. Comment lines are skipped.
fn entries(text: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let line = i + 1;
        i += 1;
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            let name = t.trim_start_matches('[').split(']').next().unwrap_or("").trim();
            let name = name.split('.').map(|p| p.trim()).collect::<Vec<_>>().join(".");
            out.push((line, String::new(), name));
            continue;
        }
        let Some((key, value)) = t.split_once('=') else { continue };
        let mut value = value.trim().to_string();
        while depth(&value) > 0 && i < lines.len() {
            let next = lines[i].trim();
            i += 1;
            if !next.starts_with('#') {
                value.push(' ');
                value.push_str(next);
            }
        }
        out.push((line, key.trim().trim_matches('"').trim_matches('\'').to_string(), value));
    }
    out
}

/// How many brackets and braces `text` leaves open, outside strings.
fn depth(text: &str) -> i32 {
    let mut d = 0;
    let mut quote = None;
    for c in text.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '[' | '{') => d += 1,
            (None, ']' | '}') => d -= 1,
            (None, '#') => break,
            _ => {}
        }
    }
    d
}

/// The quoted strings in `value`, in order.
fn strings(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote = None;
    let mut cur = String::new();
    for c in value.chars() {
        match quote {
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => break,
            Some(q) if c == q => {
                out.push(std::mem::take(&mut cur));
                quote = None;
            }
            Some(_) => cur.push(c),
            None => {}
        }
    }
    out
}

/// The value of `key` in an inline table `{ .. }`, to the next top-level comma.
fn inline_value(table: &str, key: &str) -> Option<String> {
    let inner = table.trim().strip_prefix('{')?.trim_end().strip_suffix('}')?;
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut d = 0;
    let mut quote = None;
    for c in inner.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '[' | '{') => d += 1,
            (None, ']' | '}') => d -= 1,
            (None, ',') if d == 0 => {
                parts.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    parts.push(cur);
    parts.into_iter().find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k.trim().trim_matches('"') == key).then(|| v.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(file: &str, src: &str) -> Vec<(String, String)> {
        vec![(file.to_string(), src.to_string())]
    }

    const EXEMPT_SRC: &str = "#[cfg(test)]\nmod tests {\n    /// Why.\n    #[test]\n    #[allow(clippy::disallowed_methods)]\n    fn a_small_order_publisher_key_with_a_forged_signature_is_refused() {}\n}\n";

    #[test]
    fn the_config_names_both_methods_and_is_not_shadowed() {
        let good = "disallowed-methods = [\n  { path = \"ed25519_dalek::Verifier::verify\", reason = \"r\" },\n  { path = \"ed25519_dalek::SigningKey::verify\", reason = \"r\" },\n]\n";
        assert!(config_findings(Some(good), &[]).is_empty());
        let one_only = "disallowed-methods = [\n  { path = \"ed25519_dalek::Verifier::verify\", reason = \"r\" },\n  # { path = \"ed25519_dalek::SigningKey::verify\" },\n]\n";
        assert_eq!(config_findings(Some(one_only), &[]).len(), 1);
        assert_eq!(config_findings(None, &[]).len(), 1);
        assert_eq!(config_findings(Some(good), &["infra/relay/clippy.toml".into()]).len(), 1);
    }

    #[test]
    fn the_one_exemption_passes_and_any_other_allow_is_a_finding() {
        assert!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &[], &[]).is_empty());

        // The same allow anywhere else, or on another test, is a finding.
        let elsewhere = EXEMPT_SRC.replace("fn a_small_order", "fn another_small_order");
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
    fn verify_strict_outside_the_seam_in_a_crate_linking_crypto_is_a_finding() {
        let crypto = vec!["core/crypto".to_string(), "core/msg".to_string()];
        let seam = (SEAM.to_string(), "pub fn verify() { key.verify_strict(m, s) }\n".to_string());
        let pair = ("core/pair/src/browser.rs".to_string(), "vk.verify_strict(msg, &sig)\n".to_string());
        let relay = ("infra/relay/src/auth.rs".to_string(), "key.verify_strict(m, s)\n".to_string());
        let comment = ("core/msg/src/a.rs".to_string(), "// verify_strict, in prose\n".to_string());
        assert!(seam_findings(&[seam.clone(), pair, relay, comment], &crypto).is_empty());

        let in_msg = ("core/msg/src/envelope.rs".to_string(), "fn f() {\n    key.verify_strict(m, s)\n}\n".to_string());
        let found = seam_findings(&[seam.clone(), in_msg], &crypto);
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("core/msg/src/envelope.rs:2:"), "{found:?}");

        let in_crypto = ("core/crypto/src/warm_key.rs".to_string(), "key.verify_strict(m, s)\n".to_string());
        assert_eq!(seam_findings(&[seam, in_crypto], &crypto).len(), 1);

        // A seam that no longer calls verify_strict is a finding.
        assert_eq!(seam_findings(&[(SEAM.to_string(), "pub fn verify() {}\n".to_string())], &crypto).len(), 1);
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

    #[test]
    fn a_manifest_links_crypto_by_name_or_by_dependency() {
        assert!(manifest_links_crypto("[package]\nname = \"kotton-crypto\"\n"));
        assert!(manifest_links_crypto("[dependencies]\nkotton-crypto = { path = \"../crypto\" }\n"));
        assert!(manifest_links_crypto("[dev-dependencies]\nkotton-crypto = { path = \"../crypto\", features = [\"test-utils\"] }\n"));
        assert!(!manifest_links_crypto("[dependencies]\nkotton-pair = { path = \"../pair\" }\n# kotton-crypto = {}\n"));
        // In table form, renamed, and in a target's table.
        assert!(manifest_links_crypto("[dependencies.kotton-crypto]\npath = \"../crypto\"\n"));
        assert!(manifest_links_crypto("[dependencies]\ncrypto = { package = \"kotton-crypto\", path = \"../crypto\" }\n"));
        assert!(manifest_links_crypto("[dev-dependencies.crypto]\npackage = \"kotton-crypto\"\npath = \"../crypto\"\n"));
        assert!(manifest_links_crypto("[target.'cfg(unix)'.dependencies]\nkotton-crypto = { path = \"../crypto\" }\n"));
        // A feature that names it is not a dependency, and another package's name is not it.
        assert!(!manifest_links_crypto("[package]\nname = \"kotton-msg\"\n[features]\nx = [\"kotton-crypto\"]\n"));
    }

    /// The tree as it is: every hold above holds.
    #[test]
    fn the_tree_holds() {
        let (count, found) = findings(&crate::out::root());
        assert!(count > 0);
        assert!(found.is_empty(), "{found:#?}");
    }
}
