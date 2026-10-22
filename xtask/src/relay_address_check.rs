// SPDX-License-Identifier: AGPL-3.0-or-later
//! `relay-address-check`: a relay's address is compared in one place.
//!
//! ## Why this exists
//!
//! `kotton_schemas::membership::same_relay_address` says it is *the* comparison of a relay's
//! address: space around either side and a trailing `/` are not part of it, and an empty
//! address is no relay's. Nothing held it there. The vault stand unit added a second,
//! `operator::same_address`, which trimmed only `/`, and the two disagreed about surrounding
//! space, about an empty address, and about `/` against empty. The Fable review of `3f8911bf`
//! found it and it was deleted on that branch — by a reader, which is the one observer that
//! does not come back for the next one.
//!
//! Where the comparison decides which admission key is presented at which relay
//! (`kotton_peer::relay_keys::supplied`), or which relay a vault is said to have moved to, two
//! spellings of it make a security property depend on which function a caller reached for.
//! RFC-0084 V9 names a relay by its key and compares an address only where the question is
//! *where*; this holds that the *where* question has one answer.
//! `TASK-a-relay-address-is-compared-in-one-place`.
//!
//! ## What it checks
//!
//! Over every `.rs` file under [`ROOTS`], with comments and string contents blanked first:
//!
//! 1. **No `==` or `!=` has an operand normalised by `trim_end_matches('/')`**, except inside
//!    [`COMPARATOR`]. An operand is normalised when it contains the call itself, or names a
//!    binding whose `let` initialiser does — directly, through a closure
//!    (`let bare = |s| s.trim_end_matches('/')` then `bare(a) == …`), or through another such
//!    binding. So the normalisation and the comparison may sit on different lines of one
//!    function and are still one finding. `"/"` is read as the same call as `'/'`.
//! 2. **Every function that normalises is pinned in [`BASELINE`], by name and count, and
//!    nothing else normalises.** A new normalisation site fails; one that moved or went away
//!    fails too, so the pin says what the tree holds rather than what it once held.
//!
//! ## What a text check cannot see, and why rule 2 is there
//!
//! Rule 1 follows a value only as far as a `let` inside the same function. It does not see a
//! normalised value returned from a function, stored in a field, or passed to a helper and
//! compared there — a second comparator under another name (`fn same_host(a, b)` that calls a
//! pinned builder and compares what comes back) is invisible to it. It does not read `.eq(`,
//! `matches!`, `assert_eq!`, a `HashMap` keyed by the normalised string, `strip_suffix('/')`,
//! or a URL parser's own normalisation.
//!
//! Rule 2 is what bounds that. Every normalisation in scope is pinned to the function that
//! does it, and each pinned function is a request-path or URL builder that returns a string to
//! dial, not a verdict — so a new way of normalising an address cannot land without a person
//! adding it to [`BASELINE`] by name, in a diff a reviewer reads, beside the sentence that
//! says a comparison belongs in `same_relay_address`. What remains unguarded is a comparison
//! over the *output* of a pinned builder, done somewhere else; that is the residual, and it
//! is stated here rather than implied away.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Where a relay address is compared or built. `core/net` is here so its request-path
/// builders are pinned rather than merely unexamined.
const ROOTS: &[&str] = &["core/kuserd", "core/peer", "core/schemas", "core/net"];

/// The one comparison of a relay's address: (file, function).
const COMPARATOR: (&str, &str) = ("core/schemas/src/membership.rs", "same_relay_address");

/// Every function in [`ROOTS`] that normalises a relay address with `trim_end_matches('/')`,
/// and how many times. Each is a builder that returns something to dial, except
/// [`COMPARATOR`] itself.
///
/// Adding a row is a review question, not a formality: a function that normalises in order
/// to *compare* belongs in `same_relay_address` instead.
const BASELINE: &[(&str, &str, usize)] = &[
    // The comparison itself.
    ("core/schemas/src/membership.rs", "same_relay_address", 1),
    // Request-path builders: `<relay>/identity`, `/operator`, the rendezvous base,
    // and the `ws://` base a circuit dials.
    (
        "core/net/src/provider/rendezvous/admission.rs",
        "say_as_operator",
        1,
    ),
    ("core/net/src/provider/rendezvous/client.rs", "new", 1),
    (
        "core/net/src/provider/rendezvous/identity.rs",
        "fetch_relay_identity",
        1,
    ),
    (
        "core/net/src/provider/transport/relayed.rs",
        "ws_base_of",
        1,
    ),
    // A probe's dial address, and an invite's relay as written and as read back.
    ("core/peer/src/pairing.rs", "relay_answers", 1),
    ("core/peer/src/pairing.rs", "new", 1),
    ("core/peer/src/pairing.rs", "of", 1),
];

/// One finding, already worded.
type Finding = String;

pub fn run(root: &Path) {
    let files = match rust_files(root) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("relay-address-check: {e}");
            std::process::exit(1);
        }
    };
    if files.is_empty() {
        eprintln!(
            "relay-address-check: read no `.rs` file under {}. Run from the workspace root — a \
             check that inspects nothing reports success.",
            ROOTS.join(", ")
        );
        std::process::exit(1);
    }
    let findings = check(&files, BASELINE);
    if findings.is_empty() {
        println!(
            "relay-address-check: OK — {} file(s), {} pinned normalisation site(s), one \
             comparator (`{}`).",
            files.len(),
            BASELINE.iter().map(|b| b.2).sum::<usize>(),
            COMPARATOR.1
        );
        return;
    }
    eprintln!("relay-address-check: {} finding(s):\n", findings.len());
    for f in &findings {
        eprintln!("  {f}");
    }
    eprintln!(
        "\nA relay's address is compared by `kotton_schemas::membership::same_relay_address` \
         and nowhere else: a relay is named by its key, and its address is compared only \
         where the question is *where*, which has one answer. Call \
         it rather than trimming and comparing. A new request-path builder that trims `/` and \
         compares nothing is pinned in xtask/src/relay_address_check.rs::BASELINE."
    );
    std::process::exit(1);
}

/// Every `.rs` file under [`ROOTS`], as (repo-relative path with `/`, contents).
fn rust_files(root: &Path) -> Result<Vec<(String, String)>, String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let rd =
            std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in rd {
            let p = entry.map_err(|e| e.to_string())?.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&p, out)?;
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    for r in ROOTS {
        walk(&root.join(r), &mut paths)?;
    }
    paths.sort();
    let mut out = Vec::new();
    for p in paths {
        let text =
            std::fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        let rel = p.strip_prefix(root).unwrap_or(&p);
        let rel = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>();
        out.push((rel.join("/"), text));
    }
    Ok(out)
}

/// Both rules over `files`, against `baseline`.
fn check(files: &[(String, String)], baseline: &[(&str, &str, usize)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (path, text) in files {
        let scan = scan(text);
        for (fname, n) in &scan.sites {
            *found.entry((path.clone(), fname.clone())).or_default() += n;
        }
        for c in scan.comparisons {
            if (path.as_str(), c.function.as_str()) == COMPARATOR {
                continue;
            }
            findings.push(format!(
                "{path}:{} in `{}` compares a relay address it trimmed of `/` itself: `{}`",
                c.line, c.function, c.text
            ));
        }
    }
    let pinned: BTreeMap<(String, String), usize> = baseline
        .iter()
        .map(|(p, f, n)| ((p.to_string(), f.to_string()), *n))
        .collect();
    let keys: BTreeSet<&(String, String)> = found.keys().chain(pinned.keys()).collect();
    for k in keys {
        let (have, want) = (
            found.get(k).copied().unwrap_or(0),
            pinned.get(k).copied().unwrap_or(0),
        );
        if have == want {
            continue;
        }
        let (path, f) = k;
        findings.push(if want == 0 {
            format!(
                "{path}: `{f}` normalises a relay address with `trim_end_matches('/')` \
                 {have} time(s) and is not pinned. If it builds a request path, pin it; if it \
                 compares, call `same_relay_address`."
            )
        } else {
            format!(
                "{path}: `{f}` is pinned to {want} normalisation(s) and has {have}. Update the \
                 pin to what the tree holds."
            )
        });
    }
    findings
}

/// What one file holds.
#[derive(Debug, Default)]
struct Scan {
    /// Normalisation sites, by enclosing function (`<item>` outside any).
    sites: BTreeMap<String, usize>,
    /// `==`/`!=` with a normalised operand.
    comparisons: Vec<Comparison>,
}

#[derive(Debug)]
struct Comparison {
    function: String,
    line: usize,
    text: String,
}

fn scan(src: &str) -> Scan {
    let code = blank(src);
    let b = code.as_bytes();
    let fns = functions(b);
    let norms = normalisations(b);
    let mut out = Scan::default();

    // Innermost function containing `at`: the span with the latest start.
    let enclosing = |at: usize| -> Option<&(String, usize, usize)> {
        fns.iter()
            .filter(|(_, s, e)| *s <= at && at < *e)
            .max_by_key(|(_, s, _)| *s)
    };

    for &n in &norms {
        let name = enclosing(n).map_or("<item>".to_string(), |f| f.0.clone());
        *out.sites.entry(name).or_default() += 1;
    }

    // Rule 1, per function that normalises.
    let mut done: BTreeSet<usize> = BTreeSet::new();
    for &n in &norms {
        let Some((name, start, end)) = enclosing(n).cloned() else {
            continue;
        };
        if !done.insert(start) {
            continue;
        }
        let here: Vec<usize> = norms
            .iter()
            .copied()
            .filter(|&m| enclosing(m).is_some_and(|f| f.1 == start))
            .collect();
        let tainted = tainted(b, start, end, &here);
        for (at, lhs, rhs) in comparisons(b, start, end) {
            let normalised = |r: &std::ops::Range<usize>| {
                here.iter().any(|m| r.contains(m))
                    || idents(&code[r.clone()])
                        .iter()
                        .any(|i| tainted.contains(*i))
            };
            if normalised(&lhs) || normalised(&rhs) {
                let text = code[lhs.start..rhs.end]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                out.comparisons.push(Comparison {
                    function: name.clone(),
                    line: 1 + b[..at].iter().filter(|&&c| c == b'\n').count(),
                    text,
                });
            }
        }
    }
    out
}

/// `src` with comments and string contents replaced by spaces, byte for byte, so every offset
/// and line number still holds. A string or char literal that is exactly `/` is kept, so
/// `trim_end_matches("/")` reads like `trim_end_matches('/')`; any other char literal is
/// blanked so a `'{'` does not unbalance a brace count.
fn blank(src: &str) -> String {
    let s = src.as_bytes();
    let mut o = s.to_vec();
    let mut i = 0;
    let wipe = |o: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut o[from..to.min(s.len())] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < s.len() {
        let c = s[i];
        if c == b'/' && s.get(i + 1) == Some(&b'/') {
            let e = s[i..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(s.len(), |p| i + p);
            wipe(&mut o, i, e);
            i = e;
        } else if c == b'/' && s.get(i + 1) == Some(&b'*') {
            let (mut d, mut j) = (1, i + 2);
            while j < s.len() && d > 0 {
                if s[j] == b'/' && s.get(j + 1) == Some(&b'*') {
                    d += 1;
                    j += 2;
                } else if s[j] == b'*' && s.get(j + 1) == Some(&b'/') {
                    d -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            wipe(&mut o, i, j);
            i = j;
        } else if c == b'r'
            && (i == 0 || !ident(s[i - 1]) || (s[i - 1] == b'b' && (i < 2 || !ident(s[i - 2]))))
            && matches!(s.get(i + 1), Some(b'#') | Some(b'"'))
        {
            // Raw string: r"…", r#"…"#, br#"…"#.
            let mut j = i + 1;
            let mut hashes = 0;
            while s.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if s.get(j) != Some(&b'"') {
                i += 1;
                continue;
            }
            let body = j + 1;
            let mut k = body;
            loop {
                if k >= s.len() {
                    break;
                }
                if s[k] == b'"'
                    && s[k + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&h| h == b'#')
                        .count()
                        == hashes
                {
                    break;
                }
                k += 1;
            }
            wipe(&mut o, body, k);
            i = k + 1 + hashes;
        } else if c == b'"' {
            let body = i + 1;
            let mut k = body;
            while k < s.len() && s[k] != b'"' {
                k += if s[k] == b'\\' { 2 } else { 1 };
            }
            if &s[body..k.min(s.len())] != b"/" {
                wipe(&mut o, body, k);
            }
            i = k + 1;
        } else if c == b'\'' {
            // A char literal is `'x'` or `'\…'`; anything else is a lifetime.
            let close = if s.get(i + 1) == Some(&b'\\') {
                s[i + 2..]
                    .iter()
                    .take(10)
                    .position(|&c| c == b'\'')
                    .map(|p| i + 2 + p)
            } else if s.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else if s.get(i + 1).is_some_and(|c| !c.is_ascii()) {
                s[i + 1..]
                    .iter()
                    .take(5)
                    .position(|&c| c == b'\'')
                    .map(|p| i + 1 + p)
            } else {
                None
            };
            match close {
                Some(e) => {
                    if &s[i + 1..e] != b"/" {
                        wipe(&mut o, i + 1, e);
                    }
                    i = e + 1;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(o).expect("blanking replaces whole bytes with spaces")
}

/// Offsets of each `trim_end_matches('/')` / `trim_end_matches("/")` in blanked code.
fn normalisations(b: &[u8]) -> Vec<usize> {
    const CALL: &[u8] = b"trim_end_matches";
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find(b, CALL, i) {
        i = p + CALL.len();
        let mut j = skip_ws(b, i);
        if b.get(j) != Some(&b'(') {
            continue;
        }
        j = skip_ws(b, j + 1);
        let quoted =
            |q: u8| b.get(j) == Some(&q) && b.get(j + 1) == Some(&b'/') && b.get(j + 2) == Some(&q);
        if !(quoted(b'\'') || quoted(b'"')) {
            continue;
        }
        if b.get(skip_ws(b, j + 3)) == Some(&b')') {
            out.push(p);
        }
    }
    out
}

/// Every function with a body: (name, body-open offset, one past body-close).
fn functions(b: &[u8]) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find(b, b"fn", i) {
        i = p + 2;
        let word_before = p > 0 && (b[p - 1].is_ascii_alphanumeric() || b[p - 1] == b'_');
        if word_before || !b.get(p + 2).is_some_and(|c| c.is_ascii_whitespace()) {
            continue;
        }
        let n0 = skip_ws(b, p + 2);
        let n1 = n0
            + b[n0..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                .count();
        if n1 == n0 {
            continue;
        }
        let name = String::from_utf8_lossy(&b[n0..n1]).into_owned();
        // The body opens at the first `{` outside the signature's () and []; a `;` there first
        // means a declaration with no body. `[u8; 32]` is why the depth is counted.
        let mut d = 0i32;
        let mut j = n1;
        let mut open = None;
        while j < b.len() {
            match b[j] {
                b'(' | b'[' => d += 1,
                b')' | b']' => d -= 1,
                b'{' if d == 0 => {
                    open = Some(j);
                    break;
                }
                b';' if d == 0 => break,
                _ => {}
            }
            j += 1;
        }
        let Some(open) = open else { continue };
        if let Some(close) = matching(b, open) {
            out.push((name, open, close + 1));
        }
    }
    out
}

/// The `}` that closes the `{` at `open`.
fn matching(b: &[u8], open: usize) -> Option<usize> {
    let mut d = 0i32;
    for (k, &c) in b.iter().enumerate().skip(open) {
        match c {
            b'{' => d += 1,
            b'}' => {
                d -= 1;
                if d == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

/// The names bound, in `start..end`, by a `let` whose initialiser holds a normalisation in
/// `sites` or names something already bound so — to a fixpoint.
fn tainted(b: &[u8], start: usize, end: usize, sites: &[usize]) -> BTreeSet<String> {
    let code = std::str::from_utf8(b).expect("blanked code is ascii-safe");
    let lets = lets(b, start, end);
    let mut t: BTreeSet<String> = BTreeSet::new();
    loop {
        let before = t.len();
        for (pattern, init) in &lets {
            let spine = spine(b, init.clone());
            let on = |at: usize| spine[at - init.start];
            let hit = sites.iter().any(|&s| init.contains(&s) && on(s))
                || word_offsets(code, init.clone()).any(|(at, w)| on(at) && t.contains(w));
            if hit {
                t.extend(pattern.iter().cloned());
            }
        }
        if t.len() == before {
            return t;
        }
    }
}

/// For each byte of `r`, whether it is outside every call's argument list within `r`.
///
/// This is what keeps `let resp = client.get(format!("{}/x", url.trim_end_matches('/')))`
/// from making `resp` — and then `resp.status()` — a relay address: a value passed *into* a
/// call is not what the call returns. A tuple, a block, a match arm and a closure body are on
/// the spine; a `(` right after a name, a `!`, a `)`, a `]` or a `>` (not `=>`, not `->`)
/// opens a call.
fn spine(b: &[u8], r: std::ops::Range<usize>) -> Vec<bool> {
    let mut stack: Vec<bool> = Vec::new();
    let mut out = Vec::with_capacity(r.len());
    for k in r.clone() {
        let c = b[k];
        if c == b'(' || c == b'[' || c == b'{' {
            let prev = (r.start..k).rev().find(|&j| !b[j].is_ascii_whitespace());
            // `=> (` and `-> (` are an arm and a return type, not a call through a `>`.
            let arrow = |j: usize| b[j] == b'>' && j > 0 && matches!(b[j - 1], b'=' | b'-');
            let call = c == b'('
                && prev.is_some_and(|j| {
                    !arrow(j) && (is_ident(b[j]) || matches!(b[j], b'!' | b')' | b']' | b'>'))
                });
            out.push(!stack.contains(&true));
            stack.push(call);
            continue;
        }
        if c == b')' || c == b']' || c == b'}' {
            stack.pop();
        }
        out.push(!stack.contains(&true));
    }
    out
}

/// Every identifier in `r` of `code`, with its offset.
fn word_offsets(code: &str, r: std::ops::Range<usize>) -> impl Iterator<Item = (usize, &str)> {
    let s = &code[r.clone()];
    let mut out = Vec::new();
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if is_ident(bytes[i]) && (i == 0 || !is_ident(bytes[i - 1])) {
            let e = i + bytes[i..].iter().take_while(|&&c| is_ident(c)).count();
            if !bytes[i].is_ascii_digit() {
                out.push((r.start + i, &s[i..e]));
            }
            i = e;
        } else {
            i += 1;
        }
    }
    out.into_iter()
}

/// Every `let` in `start..end`: (names in its pattern, its initialiser's range).
fn lets(b: &[u8], start: usize, end: usize) -> Vec<(Vec<String>, std::ops::Range<usize>)> {
    let code = std::str::from_utf8(b).expect("blanked code is ascii-safe");
    let mut out = Vec::new();
    let mut i = start;
    while let Some(p) = find(&b[..end], b"let", i) {
        i = p + 3;
        let bounded = (p == 0 || !is_ident(b[p - 1]))
            && b.get(p + 3).is_some_and(|c| c.is_ascii_whitespace());
        if !bounded {
            continue;
        }
        // The pattern runs to the first lone `=` at depth 0; the initialiser to the `;` at
        // the depth the `let` stands at.
        let mut d = 0i32;
        let mut j = p + 3;
        let mut eq = None;
        let mut semi = None;
        while j < end {
            match b[j] {
                b'(' | b'[' | b'{' => d += 1,
                b')' | b']' | b'}' => {
                    d -= 1;
                    if d < 0 {
                        break;
                    }
                }
                b'=' if d == 0 && eq.is_none() => {
                    let lone = b.get(j + 1) != Some(&b'=')
                        && b.get(j + 1) != Some(&b'>')
                        && !matches!(b[j - 1], b'=' | b'!' | b'<' | b'>');
                    if lone {
                        eq = Some(j);
                    }
                }
                b';' if d == 0 => {
                    semi = Some(j);
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        let (Some(eq), Some(semi)) = (eq, semi) else {
            continue;
        };
        let pat = &code[p + 3..eq];
        // A type annotation is not a name: cut at a `:` at depth 0.
        let mut d = 0i32;
        let cut = pat
            .char_indices()
            .find(|&(_, c)| {
                match c {
                    '(' | '[' | '<' => d += 1,
                    ')' | ']' | '>' => d -= 1,
                    _ => {}
                }
                c == ':' && d == 0
            })
            .map_or(pat.len(), |(k, _)| k);
        let names = idents(&pat[..cut])
            .into_iter()
            .filter(|n| !matches!(*n, "mut" | "ref" | "_"))
            .filter(|n| !n.starts_with(|c: char| c.is_ascii_uppercase()))
            .map(str::to_string)
            .collect();
        out.push((names, eq + 1..semi));
    }
    out
}

/// Every `==` / `!=` in `start..end`: (offset, left operand, right operand).
///
/// An operand stops at a `;`, `,`, `{`, `}`, `=>`, a lone `=`, `&&`, `|`, or a bracket it did
/// not open — so `relay.is_empty() || n != N` has `n` as its left operand, not `relay`.
fn comparisons(
    b: &[u8],
    start: usize,
    end: usize,
) -> Vec<(usize, std::ops::Range<usize>, std::ops::Range<usize>)> {
    let mut out = Vec::new();
    let mut i = start;
    while i + 1 < end {
        let is_op = b[i + 1] == b'='
            && matches!(b[i], b'=' | b'!')
            && b.get(i + 2) != Some(&b'=')
            && !(b[i] == b'=' && i > 0 && matches!(b[i - 1], b'=' | b'!' | b'<' | b'>'));
        if !is_op {
            i += 1;
            continue;
        }
        // Left.
        let mut d = 0i32;
        let mut l = i;
        while l > start {
            let c = b[l - 1];
            match c {
                b')' | b']' => d += 1,
                b'(' | b'[' => {
                    if d == 0 {
                        break;
                    }
                    d -= 1;
                }
                b';' | b',' | b'{' | b'}' | b'|' if d == 0 => break,
                b'&' if d == 0 && l >= 2 && b[l - 2] == b'&' => break,
                b'=' if d == 0 => break,
                b'>' if d == 0 && l >= 2 && b[l - 2] == b'=' => break,
                _ => {}
            }
            l -= 1;
        }
        // Right.
        let mut d = 0i32;
        let mut r = i + 2;
        while r < end {
            let c = b[r];
            match c {
                b'(' | b'[' => d += 1,
                b')' | b']' => {
                    if d == 0 {
                        break;
                    }
                    d -= 1;
                }
                b';' | b',' | b'{' | b'}' | b'|' if d == 0 => break,
                b'&' if d == 0 && b.get(r + 1) == Some(&b'&') => break,
                b'=' if d == 0 => break,
                _ => {}
            }
            r += 1;
        }
        out.push((i, l..i, i + 2..r));
        i += 2;
    }
    out
}

fn idents(s: &str) -> Vec<&str> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty() && !w.starts_with(|c: char| c.is_ascii_digit()))
        .collect()
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while b.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
        i += 1;
    }
    i
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KUSERD: &str = "core/kuserd/src/agent/fake.rs";

    fn findings_in(path: &str, src: &str, baseline: &[(&str, &str, usize)]) -> Vec<Finding> {
        check(&[(path.to_string(), src.to_string())], baseline)
    }

    /// The shape `operator::same_address` had: trim `/` on both sides and compare.
    #[test]
    fn a_second_comparator_in_kuserd_fails() {
        let src = "fn same_address(a: &str, b: &str) -> bool {\n    \
                   a.trim_end_matches('/') == b.trim_end_matches('/')\n}\n";
        let f = findings_in(KUSERD, src, &[(KUSERD, "same_address", 2)]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].contains("fake.rs:2") && f[0].contains("same_address"),
            "{f:?}"
        );
    }

    #[test]
    fn the_normalisation_and_the_comparison_on_different_lines_still_fail() {
        let src = "fn moved(url: &str, hint: &str) -> bool {\n\
                   let bare = url.trim().trim_end_matches('/');\n\
                   let other = hint;\n\
                   \n\
                   if other != bare { return true; }\n\
                   false\n}\n";
        let f = findings_in(KUSERD, src, &[(KUSERD, "moved", 1)]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("fake.rs:5"), "{f:?}");
    }

    #[test]
    fn a_closure_and_a_second_binding_are_followed() {
        let src = "fn f(a: &str, b: &str) -> bool {\n\
                   let bare = |s: &str| s.trim().trim_end_matches(\"/\").to_string();\n\
                   let a = bare(a);\n\
                   !a.is_empty() && a == b.to_string()\n}\n";
        let f = findings_in(KUSERD, src, &[(KUSERD, "f", 1)]);
        assert_eq!(f.len(), 1, "{f:?}");
    }

    /// `joining.rs`'s shape: the trim sits in a match arm inside the `let`.
    #[test]
    fn a_binding_made_through_a_match_is_followed() {
        let src = "fn g(name: &str, own: &str) -> bool {\n\
                   let (scheme, host) = match name.split_once(\"://\") {\n\
                   Some((s, h)) => (s, h.trim_end_matches('/')),\n\
                   None => (\"http\", name.trim_end_matches('/')),\n\
                   };\n\
                   host == own\n}\n";
        let f = findings_in(KUSERD, src, &[(KUSERD, "g", 2)]);
        assert_eq!(f.len(), 1, "{f:?}");
    }

    /// `Invite::parse`'s shape: a normalised binding and an unrelated `!=` in one condition.
    #[test]
    fn a_comparison_of_something_else_beside_a_normalised_binding_does_not_fire() {
        let src = "fn parse(text: &str) -> Option<()> {\n\
                   let relay = text.trim().trim_end_matches('/');\n\
                   if relay.is_empty() || code.split('-').count() != WORDS { return None; }\n\
                   let n = if relay.len() == 0 { 1 } else { 2 };\n\
                   Some(())\n}\n";
        assert!(
            findings_in(KUSERD, src, &[(KUSERD, "parse", 1)]).len() == 1,
            "`relay.len() == 0` is over the normalised binding and must fire"
        );
        let src = src.replace("let n = if relay.len() == 0 { 1 } else { 2 };\n", "");
        assert_eq!(
            findings_in(KUSERD, &src, &[(KUSERD, "parse", 1)]),
            Vec::<String>::new()
        );
    }

    /// `fetch_relay_identity`'s shape: the address goes into a request, and the request's
    /// status is compared. What a call returns is not what was passed into it.
    #[test]
    fn a_value_passed_into_a_call_does_not_make_its_result_an_address() {
        let src = "async fn fetch(relay_url: &str) -> bool {\n\
                   let resp = client.get(format!(\"{}/identity\", relay_url.trim_end_matches('/'))).send();\n\
                   let status = resp.status();\n\
                   status == NOT_FOUND\n}\n";
        assert_eq!(
            findings_in(KUSERD, src, &[(KUSERD, "fetch", 1)]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn comments_and_strings_are_not_code() {
        let src = "fn h() {\n\
                   // a.trim_end_matches('/') == b.trim_end_matches('/')\n\
                   let s = \"a.trim_end_matches('/') == b\";\n\
                   /* x.trim_end_matches('/') != y */\n}\n";
        assert_eq!(findings_in(KUSERD, src, &[]), Vec::<String>::new());
    }

    #[test]
    fn the_comparator_is_exempt_and_only_where_it_lives() {
        let src = "pub fn same_relay_address(a: &str, b: &str) -> bool {\n\
                   let bare = |s: &str| s.trim().trim_end_matches('/').to_string();\n\
                   let a = bare(a);\n\
                   !a.is_empty() && a == bare(b)\n}\n";
        let here = [(COMPARATOR.0, COMPARATOR.1, 1)];
        assert_eq!(findings_in(COMPARATOR.0, src, &here), Vec::<String>::new());
        let there = [(KUSERD, COMPARATOR.1, 1)];
        assert_eq!(
            findings_in(KUSERD, src, &there).len(),
            1,
            "same name, another file"
        );
    }

    #[test]
    fn a_normalisation_nobody_pinned_fails() {
        let src = "fn build(u: &str) -> String { format!(\"{}/x\", u.trim_end_matches('/')) }\n";
        let f = findings_in(KUSERD, src, &[]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("not pinned"), "{f:?}");
        assert_eq!(
            findings_in(KUSERD, src, &[(KUSERD, "build", 1)]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_pinned_site_that_went_away_fails() {
        let f = findings_in(KUSERD, "fn build() {}\n", &[(KUSERD, "build", 1)]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].contains("pinned to 1") && f[0].contains("has 0"),
            "{f:?}"
        );
    }

    #[test]
    fn an_array_type_in_a_signature_does_not_end_it() {
        let src = "fn k(key: [u8; 32], a: &str, b: &str) -> bool {\n\
                   a.trim_end_matches('/') == b\n}\n";
        assert_eq!(findings_in(KUSERD, src, &[(KUSERD, "k", 1)]).len(), 1);
    }

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    /// The baseline files, as they are: they build request paths and compare nothing.
    #[test]
    fn the_baseline_files_do_not_fire() {
        let files: BTreeSet<&str> = BASELINE.iter().map(|b| b.0).collect();
        for path in files {
            let text = std::fs::read_to_string(repo().join(path)).expect(path);
            let scan = scan(&text);
            let loose: Vec<_> = scan
                .comparisons
                .iter()
                .filter(|c| (path, c.function.as_str()) != COMPARATOR)
                .collect();
            assert!(loose.is_empty(), "{path}: {loose:?}");
            assert!(
                !scan.sites.is_empty(),
                "{path} is pinned and normalises nothing"
            );
        }
    }

    /// The comparator itself is seen comparing — so exempting it is exempting something.
    #[test]
    fn the_comparator_is_read_as_a_comparison() {
        let text = std::fs::read_to_string(repo().join(COMPARATOR.0)).unwrap();
        assert!(scan(&text)
            .comparisons
            .iter()
            .any(|c| c.function == COMPARATOR.1));
    }

    #[test]
    fn the_tree_passes() {
        let files = rust_files(&repo()).unwrap();
        assert!(files.len() > 50, "read {} files", files.len());
        assert_eq!(check(&files, BASELINE), Vec::<String>::new());
    }
}
