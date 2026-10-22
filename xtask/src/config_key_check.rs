// SPDX-License-Identifier: AGPL-3.0-or-later
//! `config-key-check`: a device-config key that nothing in the product can set.
//!
//! ## Why this exists
//!
//! `kuserd` decided at boot whether to run an inference runtime by reading
//! `device_config`'s `inference.enabled`, and **nothing in the tree ever wrote
//! that key**. Every writer of `device_config` is a named wrapper —
//! `set_coord_url`, `set_turn_url`, `set_quic_gateway`, `set_web_shell` — and
//! there is no generic `kotton config set`, so the flag was a switch with no
//! handle: read on every boot, settable by no person and no test
//! (`TASK-a-config-key-that-nothing-can-set`).
//!
//! That is a specific and repeatable failure, not a typo. A reader is written
//! first, because the reader is the interesting half — it is where the
//! behaviour lives — and the writer is left for "the CLI step". The reader
//! compiles, the default branch is taken forever, and the feature **reports as
//! shipped**: the boot log says the sidecar is off, which is exactly what it
//! would say if somebody had turned it off.
//!
//! Nothing catches it. It is not a type error (both halves take `&str`), not a
//! dead-code warning (the reader runs), and not a test failure (the test
//! exercises the reader against a hand-seeded row). The only thing that can see
//! it is a check that compares the set of keys *read* against the set of keys
//! *written*, which is what this is.
//!
//! ## What it checks
//!
//! Across every Rust source under [`CODE_ROOTS`](crate::tree::CODE_ROOTS), each
//! call to the `device_config` accessor pair —
//! [`kotton_device::config::db::get_key`] and `set_key` — is read for the key it
//! names. A key that is read and never written is a violation.
//!
//! **The key may be a literal or a `const`.** The record's `Done when:` says
//! "by the same literal (`set_key`) or a documented setter", and a named
//! wrapper writing `INFERENCE_ENABLED_KEY` is that documented setter: the const
//! is resolved to its string, so `get_key(db, K)` and `set_key(db, K)` match.
//! Resolving constants is what lets the named-wrapper convention — which this
//! repository wants, because a generic setter would let a caller write a key no
//! reader knows about — survive the check instead of being punished by it.
//!
//! **A key expression that is neither is a failure, not a pass.** `set_key(db,
//! key, v)` with `key` a parameter is a generic setter wearing a wrapper's
//! clothes: it would make every key look written and this check report OK over
//! nothing. So an unresolved key expression is reported by name and line.
//!
//! ## What it cannot see, stated rather than left to be discovered
//!
//! Its view is the accessor pair. `device_config` is an ordinary table and
//! `load_nat_config` reads seven keys out of it with a raw
//! `SELECT … WHERE key IN (…)`; those are outside this check and three of them
//! have no writer either. That is filed, not hidden —
//! `TASK-three-device-config-keys-are-read-and-never-written` carries it. The
//! reason not to widen the check to SQL today is that parsing a query string for
//! key names is a second parser with its own blind spots, and the accessor pair
//! is where new keys are actually added.
//!
//! ## Exemptions cost a record
//!
//! [`NO_WRITER_YET`] is the list of keys deliberately read with no writer. Each
//! entry names a record that must exist on disk, so an exemption is a tracked
//! debt rather than a silence, and a stale one — a key that has since gained a
//! writer, or stopped being read — fails the gate. A list that can only be added
//! to is a list that rots into a permanent allowance.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Where a caller of the `device_config` accessors can live.
///
/// [`CODE_ROOTS`](crate::tree::CODE_ROOTS) minus `xtask`, for two reasons that
/// point the same way: the gate harness does not depend on `kotton-device` and
/// so cannot reach the accessor at all, and this file's own tests hold
/// `get_key(db, "…")` fixtures that are not call sites. A check that reads its
/// own test data as evidence reports the defects it was written to describe.
const SCAN_ROOTS: &[&str] = &[
    "core", "client", "system", "guest", "infra", "tools", "tests",
];

/// The accessor pair this check reads. Both live in `core/device/src/config/db.rs`.
const READER: &str = "get_key";
const WRITER: &str = "set_key";

/// A key read with no writer on purpose, and why, in words a reader can check.
///
/// The exemption costs a reason, not a citation: the list is the one place this gate can be
/// weakened, so each entry says what the missing setter costs a person, and is deleted the
/// day a writer lands (the check fails on a stale entry, both ways round).
struct NoWriterYet {
    key: &'static str,
    why: &'static str,
}

/// Keys that are read and deliberately not writable yet.
///
/// Each was found by this check's first red run and is a real instance of the
/// same defect the check exists for. They are exempted rather than fixed here
/// because giving each one a setter is a CLI verb in someone else's domain —
/// the display server, NAT configuration, the peer listener — and widening a
/// gate into three feature changes is two pieces of work with the second one
/// unasked for.
const NO_WRITER_YET: &[NoWriterYet] = &[
    NoWriterYet {
        key: "display-server.enabled",
        why: "read at boot by `kuserd` to decide whether to spawn `kuid`; defaults on, so \
              the unsettable direction is *off* — a person cannot run headless",
    },
    NoWriterYet {
        key: "stun_urls",
        why: "reported by `kotton config status` and read by `load_nat_config`; the row \
              says `configured: false` on every machine that has ever existed",
    },
    NoWriterYet {
        key: "peer-listen-port",
        why: "`load_peer_listen_port` reads it at daemon start; the only way to set the \
              port is the `KOTTON_PEER_LISTEN_PORT` env var, which does not persist",
    },
];

/// One call site, and the key it names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    file: String,
    line: usize,
    key: KeyExpr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyExpr {
    /// A literal, or a `const` that resolved to exactly one literal.
    Resolved(String),
    /// Anything else — the source text, so the message can name it.
    Unresolved(String),
}

/// What one pass over the sources found.
#[derive(Debug, Default)]
struct Scan {
    reads: Vec<Site>,
    writes: Vec<Site>,
    /// `const` names that resolved to more than one distinct string.
    ambiguous: BTreeMap<String, BTreeSet<String>>,
}

pub fn run() {
    let root = crate::out::root();
    let files = rust_files(&root);
    if files.is_empty() {
        eprintln!(
            "config-key-check: found no Rust sources under {SCAN_ROOTS:?}. Either the tree \
             moved or this is not a checkout — and a check that inspects nothing reports OK."
        );
        std::process::exit(1);
    }

    let sources: Vec<(String, String)> = files
        .iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            std::fs::read_to_string(p).ok().map(|t| (rel, t))
        })
        .collect();

    let scan = scan(&sources);
    report(&scan);
}

// ---------------------------------------------------------------------------
// The scan — a pure function over (path, text), so the tests can plant a tree
// ---------------------------------------------------------------------------

fn scan(sources: &[(String, String)]) -> Scan {
    let mut global: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (_, text) in sources {
        collect_str_consts(text, &mut global);
    }

    let mut out = Scan::default();
    for (path, text) in sources {
        // The file's own constants win. Without that, `USER` — fifteen different
        // strings across the test harness — would make every call site in a file
        // that happens to define one ambiguous. Ambiguity is only interesting
        // when a *call site* actually reaches a name with two meanings.
        let mut local: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        collect_str_consts(text, &mut local);

        for (accessor, is_read) in [(READER, true), (WRITER, false)] {
            for (line, arg) in call_sites(text, accessor) {
                let key = resolve(&arg, &local, &global, &mut out.ambiguous);
                let site = Site {
                    file: path.clone(),
                    line,
                    key,
                };
                if is_read {
                    out.reads.push(site);
                } else {
                    out.writes.push(site);
                }
            }
        }
    }
    out
}

/// `const NAME: &str = "value";` — including `pub`, `pub(crate)` and `static`.
///
/// Deliberately shallow: one line, one string literal. A key assembled at
/// runtime is not a constant, and pretending to resolve one would be the
/// confidently-wrong answer this whole gate family exists to prevent — it stays
/// [`KeyExpr::Unresolved`] and is reported.
fn collect_str_consts(text: &str, out: &mut BTreeMap<String, BTreeSet<String>>) {
    for raw in text.lines() {
        let t = raw.trim();
        let t = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);
        let t = match t
            .strip_prefix("const ")
            .or_else(|| t.strip_prefix("static "))
        {
            Some(rest) => rest,
            None => continue,
        };
        let Some((name, rest)) = t.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        let Some((ty, value)) = rest.split_once('=') else {
            continue;
        };
        if !ty.contains("str") {
            continue;
        }
        let value = value.trim().trim_end_matches(';').trim();
        if let Some(lit) = string_literal(value) {
            out.entry(name.to_string()).or_default().insert(lit);
        }
    }
}

/// Every call to `name(…)` in `text`, as `(line, second-argument-source)`.
///
/// The definition is skipped — `pub async fn get_key(db: &SqlitePool, key: &str)`
/// would otherwise read as a call naming the key `key`.
fn call_sites(text: &str, name: &str) -> Vec<(usize, String)> {
    let bytes = text.as_bytes();
    let needle = format!("{name}(");
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(off) = text[from..].find(&needle) {
        let at = from + off;
        from = at + needle.len();

        // `xget_key(` is a different function; so is `get_key_package(`, which
        // this already excludes by requiring the `(`.
        if at > 0 {
            let prev = bytes[at - 1] as char;
            if prev.is_alphanumeric() || prev == '_' {
                continue;
            }
        }
        // The declaration of the accessor itself.
        if text[..at].trim_end().ends_with("fn") {
            continue;
        }
        let open = at + name.len();
        let Some(args) = balanced(text, open) else {
            continue;
        };
        let Some(second) = split_top_level(&args).into_iter().nth(1) else {
            continue;
        };
        out.push((
            text[..at].matches('\n').count() + 1,
            second.trim().to_string(),
        ));
    }
    out
}

/// The text between the `(` at `open` and its matching `)`, string literals respected.
fn balanced(text: &str, open: usize) -> Option<String> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in text[open..].char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[open + 1..open + i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Split an argument list on commas that are not inside a nested group or a string.
fn split_top_level(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    let mut cur = String::new();
    for c in args.chars() {
        if in_str {
            cur.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                cur.push(c);
            }
            // Angle brackets are deliberately not depth: `->` and a bare `>`
            // comparison are far likelier inside an argument than a turbofish
            // carrying a comma, and `balanced` counts the same three pairs.
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn resolve(
    expr: &str,
    local: &BTreeMap<String, BTreeSet<String>>,
    global: &BTreeMap<String, BTreeSet<String>>,
    ambiguous: &mut BTreeMap<String, BTreeSet<String>>,
) -> KeyExpr {
    let expr = expr.trim();
    if let Some(lit) = string_literal(expr) {
        return KeyExpr::Resolved(lit);
    }
    let ident = expr.rsplit("::").next().unwrap_or(expr).trim();
    if let Some(values) = local.get(ident).or_else(|| global.get(ident)) {
        if values.len() == 1 {
            return KeyExpr::Resolved(values.iter().next().cloned().unwrap_or_default());
        }
        ambiguous.insert(ident.to_string(), values.clone());
    }
    KeyExpr::Unresolved(expr.to_string())
}

/// `"…"` with no escapes, which every key in this table is. An escaped literal
/// returns `None` rather than a guess.
fn string_literal(s: &str) -> Option<String> {
    let s = s.trim();
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains('\\') && !inner.contains('"')).then(|| inner.to_string())
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for r in SCAN_ROOTS {
        let mut stack = vec![root.join(r)];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    if p.file_name().is_some_and(|n| n == "target" || n == ".git") {
                        continue;
                    }
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

fn report(scan: &Scan) {
    let written: BTreeSet<&str> = scan
        .writes
        .iter()
        .filter_map(|s| match &s.key {
            KeyExpr::Resolved(k) => Some(k.as_str()),
            KeyExpr::Unresolved(_) => None,
        })
        .collect();

    let mut read_at: BTreeMap<&str, Vec<&Site>> = BTreeMap::new();
    for s in &scan.reads {
        if let KeyExpr::Resolved(k) = &s.key {
            read_at.entry(k.as_str()).or_default().push(s);
        }
    }

    let exempt: BTreeMap<&str, &NoWriterYet> = NO_WRITER_YET.iter().map(|e| (e.key, e)).collect();

    let unsettable: Vec<&str> = read_at
        .keys()
        .copied()
        .filter(|k| !written.contains(k) && !exempt.contains_key(k))
        .collect();

    let unresolved: Vec<&Site> = scan
        .reads
        .iter()
        .chain(scan.writes.iter())
        .filter(|s| matches!(s.key, KeyExpr::Unresolved(_)))
        .collect();

    // A stale exemption, both ways round.
    let mut stale: Vec<String> = Vec::new();
    for e in NO_WRITER_YET {
        if written.contains(e.key) {
            stale.push(format!("`{}` now has a writer — delete its entry", e.key));
        } else if !read_at.contains_key(e.key) {
            stale.push(format!(
                "`{}` is no longer read anywhere — delete its entry",
                e.key
            ));
        }
        if e.why.trim().is_empty() {
            stale.push(format!("`{}` gives no reason", e.key));
        }
    }

    if read_at.is_empty() {
        eprintln!(
            "config-key-check: found no `{READER}` call with a key it could resolve. The \
             accessor moved, or the parser is broken — and a check that inspects nothing \
             reports success."
        );
        std::process::exit(1);
    }

    if unsettable.is_empty()
        && unresolved.is_empty()
        && stale.is_empty()
        && scan.ambiguous.is_empty()
    {
        println!(
            "config-key-check: OK — {} device-config key(s) read, every one of them writable \
             or exempt.",
            read_at.len()
        );
        // The exemptions are printed on the *green* run, not hidden behind a
        // failure. A debt nobody is shown is a debt nobody pays, and these three
        // are real instances of the defect this gate exists for.
        for e in NO_WRITER_YET {
            println!("  not yet writable: `{}` — {}", e.key, e.why);
        }
        return;
    }

    if !unsettable.is_empty() {
        eprintln!(
            "config-key-check: {} device-config key(s) are read and nothing can set them:\n",
            unsettable.len()
        );
        for k in &unsettable {
            eprintln!("  `{k}`");
            for s in read_at.get(k).into_iter().flatten() {
                eprintln!("      read at {}:{}", s.file, s.line);
            }
        }
        eprintln!(
            "\nA flag read and never written is a switch nothing can flip, and it reports as a \
             feature: the default branch is taken forever and the log says \"off\", which is \
             what it would say if a person had turned it off.\n\n\
             Give it a named writer beside its reader — `set_inference` in \
             `core/device/src/config/ops.rs` is the shape — and a product path that reaches \
             it. If it is deliberately unsettable for now, add it to `NO_WRITER_YET` in \
             xtask/src/config_key_check.rs with the record that owns the gap."
        );
    }

    if !unresolved.is_empty() {
        eprintln!(
            "\nconfig-key-check: {} call(s) name a key this check cannot resolve:\n",
            unresolved.len()
        );
        for s in &unresolved {
            if let KeyExpr::Unresolved(e) = &s.key {
                eprintln!("  {}:{} — `{e}`", s.file, s.line);
            }
        }
        eprintln!(
            "\nA key that is a variable is a generic setter wearing a wrapper's clothes: it \
             makes every key look written and this check report OK over nothing. Name the key \
             at the call site, as a literal or a `const … : &str`."
        );
    }

    if !scan.ambiguous.is_empty() {
        eprintln!(
            "\nconfig-key-check: {} const name(s) resolve to more than one key:\n",
            scan.ambiguous.len()
        );
        for (name, values) in &scan.ambiguous {
            eprintln!("  `{name}` → {values:?}");
        }
        eprintln!("\nThe check will not guess which one a call site meant. Rename one of them.");
    }

    if !stale.is_empty() {
        eprintln!("\nconfig-key-check: {} stale exemption(s):\n", stale.len());
        for s in &stale {
            eprintln!("  {s}");
        }
        eprintln!("\nAn exemption list that can only be added to rots into a permanent allowance.");
    }

    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(files: &[(&str, &str)]) -> Vec<(String, String)> {
        files
            .iter()
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .collect()
    }

    fn unsettable(scan: &Scan) -> Vec<String> {
        let written: BTreeSet<String> = scan
            .writes
            .iter()
            .filter_map(|s| match &s.key {
                KeyExpr::Resolved(k) => Some(k.clone()),
                KeyExpr::Unresolved(_) => None,
            })
            .collect();
        let mut out: Vec<String> = scan
            .reads
            .iter()
            .filter_map(|s| match &s.key {
                KeyExpr::Resolved(k) if !written.contains(k) => Some(k.clone()),
                _ => None,
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// **The red run, kept.** This is `core/kuserd/src/agent/mod.rs` and
    /// `core/device/src/config/ops.rs` as they stood at `d1c6824b^` — the tree
    /// `TASK-a-config-key-that-nothing-can-set` was filed against, where
    /// `inference.enabled` had a reader at boot and no writer anywhere.
    ///
    /// A gate written green proves nothing, and several in this repository
    /// carry a note saying so. This one was run against that commit's real tree
    /// before it was run against this one.
    #[test]
    fn red_on_the_defect_it_was_written_for() {
        let scan = scan(&src(&[
            (
                "core/kuserd/src/agent/mod.rs",
                r#"
                let inference_enabled =
                    kotton_device::config::db::get_key(this.device_db.as_ref(), "inference.enabled")
                        .await
                        .ok()
                        .flatten()
                        .map(|v| v == "true")
                        .unwrap_or(false);
                "#,
            ),
            (
                "core/device/src/config/ops.rs",
                r#"
                const RELAY_URL_KEY: &str = "relay_url";
                pub async fn set_coord_url(db: &SqlitePool, url: Option<&str>) -> io::Result<()> {
                    device_config_db::set_key(db, RELAY_URL_KEY, url).await
                }
                "#,
            ),
        ]));
        assert_eq!(unsettable(&scan), vec!["inference.enabled".to_string()]);
    }

    /// And green once the named wrapper exists — which is the fix that landed,
    /// and the reason constants are resolved rather than demanded as literals.
    #[test]
    fn a_named_wrapper_is_a_writer() {
        let scan = scan(&src(&[(
            "core/device/src/config/ops.rs",
            r#"
            const INFERENCE_ENABLED_KEY: &str = "inference.enabled";
            pub async fn set_inference(db: &SqlitePool, enabled: bool) -> io::Result<()> {
                device_config_db::set_key(db, INFERENCE_ENABLED_KEY, Some(v)).await
            }
            pub async fn inference(db: &SqlitePool) -> io::Result<bool> {
                Ok(device_config_db::get_key(db, INFERENCE_ENABLED_KEY).await?.is_some())
            }
            "#,
        )]));
        assert!(unsettable(&scan).is_empty(), "{:?}", unsettable(&scan));
    }

    /// A literal reader and a const writer are the same key. This is the cross
    /// case the fix actually produced for a while, and the one a literal-only
    /// check would have reported as a defect.
    #[test]
    fn a_literal_read_matches_a_const_write() {
        let scan = scan(&src(&[
            ("a.rs", r#"get_key(db, "quic-gateway.enabled")"#),
            (
                "b.rs",
                "const GW: &str = \"quic-gateway.enabled\";\nset_key(db, GW, Some(v))",
            ),
        ]));
        assert!(unsettable(&scan).is_empty(), "{:?}", unsettable(&scan));
    }

    /// The accessor's own declaration is not a call site. Without this the
    /// check reads `key: &str` as a key named `key` and reports it unresolved
    /// on every run.
    #[test]
    fn the_declaration_is_not_a_call() {
        let scan = scan(&src(&[(
            "core/device/src/config/db.rs",
            "pub async fn get_key(db: &SqlitePool, key: &str) -> io::Result<Option<String>> {}\n\
             pub async fn set_key(db: &SqlitePool, key: &str, value: Option<&str>) {}",
        )]));
        assert!(scan.reads.is_empty(), "{:?}", scan.reads);
        assert!(scan.writes.is_empty(), "{:?}", scan.writes);
    }

    /// `get_key_package` and `get_key_health` are different functions that this
    /// check must not read as device config. Both exist in the tree.
    #[test]
    fn a_longer_name_is_a_different_function() {
        let scan = scan(&src(&[(
            "a.rs",
            "frost_db::get_key_package(user_db, &org_did)\n\
             kotton_crypto::key_health::get_key_health(a, b)",
        )]));
        assert!(scan.reads.is_empty(), "{:?}", scan.reads);
    }

    /// A key that is a variable is the hole this check would otherwise have: a
    /// generic setter makes every key look written.
    #[test]
    fn a_variable_key_is_unresolved_not_written() {
        let scan = scan(&src(&[(
            "a.rs",
            "pub async fn config_set(db: &SqlitePool, key: &str, v: &str) {\n\
             \x20   set_key(db, key, Some(v)).await\n}\nget_key(db, \"some.key\")",
        )]));
        assert!(
            matches!(scan.writes[0].key, KeyExpr::Unresolved(_)),
            "{:?}",
            scan.writes
        );
        assert_eq!(unsettable(&scan), vec!["some.key".to_string()]);
    }

    /// Two consts with one name, different values, and a call site in neither
    /// file: the check refuses to pick, rather than resolving to whichever one
    /// sorted first.
    #[test]
    fn an_ambiguous_const_is_reported() {
        let scan = scan(&src(&[
            ("a.rs", "const K: &str = \"one\";"),
            ("b.rs", "const K: &str = \"two\";"),
            ("c.rs", "get_key(db, K)"),
        ]));
        assert!(scan.ambiguous.contains_key("K"), "{:?}", scan.ambiguous);
        assert!(
            matches!(scan.reads[0].key, KeyExpr::Unresolved(_)),
            "{:?}",
            scan.reads
        );
    }

    /// The file's own `const` wins over a same-named one elsewhere. `USER` is
    /// fifteen different strings across the test harness; without this, every
    /// call site in a file that defines one would read as ambiguous and the
    /// gate would be noise on its first run. It was.
    #[test]
    fn a_local_const_shadows_a_colliding_one() {
        let scan = scan(&src(&[
            ("harness.rs", "const USER: &str = \"alice\";"),
            (
                "ops.rs",
                "const USER: &str = \"user.name\";\nget_key(db, USER)\nset_key(db, USER, None)",
            ),
        ]));
        assert!(scan.ambiguous.is_empty(), "{:?}", scan.ambiguous);
        assert_eq!(
            scan.reads[0].key,
            KeyExpr::Resolved("user.name".to_string())
        );
        assert!(unsettable(&scan).is_empty(), "{:?}", unsettable(&scan));
    }

    /// A multi-line call still yields its key — `get_key(\n  db,\n  KEY,\n)`.
    #[test]
    fn a_call_may_span_lines() {
        let scan = scan(&src(&[(
            "a.rs",
            "device_config_db::get_key(\n    db.as_ref(),\n    \"web-shell.bind\",\n)",
        )]));
        assert_eq!(scan.reads.len(), 1);
        assert_eq!(
            scan.reads[0].key,
            KeyExpr::Resolved("web-shell.bind".to_string())
        );
    }

    /// Every exemption gives a reason, and names its key once. The list is the one place
    /// this gate can be weakened, so the weakening has to cost a sentence a reader can check.
    #[test]
    fn every_exemption_gives_a_reason_once() {
        let mut seen = std::collections::BTreeSet::new();
        for e in NO_WRITER_YET {
            assert!(!e.why.trim().is_empty(), "exemption `{}` has no reason", e.key);
            assert!(seen.insert(e.key), "exemption `{}` is listed twice", e.key);
        }
    }
}
