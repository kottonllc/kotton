// SPDX-License-Identifier: AGPL-3.0-or-later
//! Catch a Unix-only API used where Windows will also compile it.
//!
//! # What the compiler holds now, and what this still holds
//!
//! The honest gate is a compiler on Windows, and it exists: `.github/workflows/windows.yml`
//! runs `cargo build --workspace --locked` on `windows-latest` on every pull request, and the
//! tests of the library crates it names. Everything that build compiles is held there, by
//! rustc, and better than a grep can: an alias, a re-export, a macro, the mirror case.
//!
//! The job also compiles every test target of the workspace (`cargo test --workspace
//! --no-run`), the daemons', xtask's and the integration suite's included. So this stays
//! for two things only:
//!
//! - **`infra/`.** The relay is a workspace of its own, released for Linux alone, and is
//!   not built on Windows. A Unix-only path there is read by this and by nothing else.
//! - **Before the pull request.** This runs in `just lint`, on the contributor's own Linux
//!   machine, in seconds. A Windows build there is not available: `ring`'s build script needs a
//!   Windows C toolchain, and neither clang nor mingw satisfied it in the Linux container this
//!   was written in. The Windows job answers the whole question once the pull request is
//!   open; this answers the narrow form of it before a push.
//!
//! It leaves when the relay is either built on Windows or excluded from these roots by a
//! reason written beside it, and a contributor's slower answer is judged good enough.
//!
//! # What it can and cannot see
//!
//! It sees a Unix-only path named in code that no `#[cfg(unix)]` covers. That is
//! exactly `TASK-nothing-checks-the-windows-build`'s example — an `IpcEndpoint`
//! arm naming a `#[cfg(unix)]` variant unconditionally — and exactly the defect
//! that prompted it: `tokio::net::unix::OwnedWriteHalf` as a struct field,
//! shipped 2026-08-27, found by a person running `just desktop::build` on
//! Windows rather than by anything in the gate.
//!
//! It cannot see: a Unix-only type reached through an alias or a re-export, a
//! `cfg!(unix)` runtime branch that still names the item on both arms, anything
//! produced by a macro, or a Windows-only API used unguarded (the mirror case —
//! worth adding, and not yet measured because the tree is developed on Linux).
//! It also reads each file alone, so a file guarded only by its parent's
//! `#[cfg(unix)] mod` line reads as unguarded: see [`guarded_whole`].
//! **And it cannot see a guard that should no longer exist.** Measured 2026-08-27,
//! hours after this gate landed: `supervise_kuid` had a `#[cfg(windows)]` arm that
//! logged "the surface channel has no handed transport on this platform" and ran
//! the daemon headless. The premise was true when written and false by the time it
//! merged — pipes work on both platforms — but the stub was *correctly guarded*, so
//! this check saw a well-formed `#[cfg]` split and passed. Windows compiled, ran,
//! and drew nothing, and again it took a person running the binary to find it.
//!
//! That is the shape of the blind spot: this gate asks "is every Unix-only path
//! guarded?", which is a question about compilation. "Does this platform actually
//! do the thing?" is a question about behaviour, and no grep answers it. A
//! `#[cfg(windows)]` stub is the exact construct that satisfies the first question
//! while failing the second, which makes it worse than an unguarded path — that at
//! least fails loudly at build time.
//!
//! Passing this is not "it builds on Windows": the Windows job is. Failing it is a real defect.

/// Paths that exist only on Unix. Substring-matched against source lines.
const UNIX_ONLY: &[&str] = &[
    "std::os::unix",
    "std::os::fd",
    "tokio::net::unix",
    "UnixStream",
    "UnixListener",
    "UnixDatagram",
    "OwnedFd",
    "from_raw_fd",
    "PermissionsExt",
];

const ROOTS: &[&str] = &[
    "core", "client", "tools", "xtask", "tests", "infra",
];

/// True if `line` is a `#[cfg(…)]` or `#![cfg(…)]` whose predicate is false
/// whenever the target is Windows — the region it opens is one Windows will not
/// compile.
///
/// The predicate is evaluated, not searched for a word: `target_os = "linux"` is
/// narrower than `unix` and names neither `unix` nor `windows`, and `any(unix,
/// windows)` names `unix` and guards nothing
/// (`TASK-windows-check-does-not-read-a-target-os-guard-or-one-past-line-20`). A
/// predicate wrapped over several lines is not read, and reads as no guard.
fn is_unix_guard(line: &str) -> bool {
    guard_and_rest(line).is_some()
}

/// If `line` opens with a guard (see [`is_unix_guard`]), what follows its `]` on the
/// same line — a comment, or the start of the item it covers.
fn guard_and_rest(line: &str) -> Option<&str> {
    let t = line.trim();
    let rest = t.strip_prefix("#![cfg").or_else(|| t.strip_prefix("#[cfg"))?;
    let group = balanced(rest)?;
    let after = rest[group.len()..].strip_prefix(']')?;
    (on_windows(&group[1..group.len() - 1]) == Some(false)).then_some(after)
}

/// The parenthesised group `s` opens with, through its match, reading past string and
/// char literals (see [`outside_literals`]).
fn balanced(s: &str) -> Option<&str> {
    if !s.starts_with('(') {
        return None;
    }
    let mut depth = 0i32;
    for (i, c) in outside_literals(s) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// What a `cfg` predicate is when the target is Windows: `Some(true)`,
/// `Some(false)`, or `None` where it depends on something else (a feature, `test`,
/// an architecture). `target_os` other than `"windows"` is false there, and so are
/// `unix` and `target_family = "unix"` or `"wasm"`.
fn on_windows(pred: &str) -> Option<bool> {
    let p = pred.trim();
    let args = |name: &str| {
        p.strip_prefix(name)
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix('('))
            .and_then(|r| r.strip_suffix(')'))
            .map(|inner| {
                split_top_level(inner)
                    .into_iter()
                    .filter(|a| !a.trim().is_empty())
                    .map(on_windows)
                    .collect::<Vec<_>>()
            })
    };
    if let Some(v) = args("all") {
        return if v.contains(&Some(false)) {
            Some(false)
        } else if v.iter().all(|x| *x == Some(true)) {
            Some(true)
        } else {
            None
        };
    }
    if let Some(v) = args("any") {
        return if v.contains(&Some(true)) {
            Some(true)
        } else if v.iter().all(|x| *x == Some(false)) {
            Some(false)
        } else {
            None
        };
    }
    if let Some(v) = args("not") {
        return match v.as_slice() {
            [x] => x.map(|b| !b),
            _ => None,
        };
    }
    match p.split_once('=') {
        Some((key, value)) => {
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "target_os" | "target_family" => Some(value == "windows"),
                _ => None,
            }
        }
        None => match p {
            "windows" => Some(true),
            "unix" => Some(false),
            _ => None,
        },
    }
}

/// `args` split at its top-level commas, read outside literals: `target_os = "("` holds no
/// bracket.
fn split_top_level(args: &str) -> Vec<&str> {
    let (mut parts, mut depth, mut start) = (Vec::new(), 0i32, 0);
    for (i, c) in outside_literals(args) {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&args[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&args[start..]);
    parts
}

/// Strip trailing line comments and whole-line comments so a needle mentioned in
/// prose is not a finding. A `//` inside a string or char literal is not a comment
/// ([`outside_literals`]); until 2026-09-27 it ended the line, which could hide a
/// needle after it — a missed finding, the direction a gate must not err in.
fn code_of(line: &str) -> &str {
    let t = line.trim_start();
    if t.starts_with("//") || t.starts_with("*") || t.starts_with("/*") {
        return "";
    }
    let kept = outside_literals(line);
    match kept
        .windows(2)
        .find(|w| w[0].1 == '/' && w[1].1 == '/' && w[1].0 == w[0].0 + 1)
    {
        Some(w) => &line[..w[0].0],
        None => line,
    }
}

/// True if `code` opens a `const`/`static` table of string literals.
///
/// Matches `const NAME: &[&str] = &[` and the `static` form, which is how both
/// checkers in this tree hold the names they grep for. Deliberately narrow: a
/// table of any other element type is not covered, because the reason this
/// exists is that a `&str` naming an API is not a use of it.
fn is_str_table_open(code: &str) -> bool {
    let t = code.trim_start();
    (t.starts_with("const ") || t.starts_with("static "))
        && t.contains("&[&str]")
        && t.trim_end().ends_with("&[")
}

/// The fix the failure message offers. It names only what [`guarded_whole`] and
/// the per-item guard accept; `a_file_guarded_the_way_the_message_says_passes`
/// holds the two together.
const FIX: &str =
    "Guard each with `#[cfg(unix)]` and give Windows an arm. A file that is Unix-only\n\
     whole carries an inner `#![cfg(unix)]` before its first item; a `#[cfg(unix)]` on the\n\
     parent's `mod` line is not read. A change that builds on Linux and not on Windows\n\
     is half a tree.";

/// True if the file carries an inner `#![cfg(…)]` guard, which guards everything
/// in it. Read where rustc reads one: among the inner attributes before the first
/// item, after comments and a module doc of any length. It read only the first 20
/// lines until 2026-09-27, and a 21-line doc put a guard out of its view
/// (`TASK-windows-check-does-not-read-a-target-os-guard-or-one-past-line-20`).
///
/// A `#[cfg(unix)] mod` line in the parent guards the file just as well, and
/// this does not read it: resolving `mod` lines to files is what a compiler
/// does, and `TASK-the-windows-gate-is-a-grep-and-should-be-a-compiler` is where
/// that goes. Until then a split module carries the inner attribute, and the
/// message in [`FIX`] says so rather than offering the parent's line.
fn guarded_whole(src: &str) -> bool {
    let (mut in_comment, mut in_attr) = (false, 0i32);
    for l in src.lines() {
        let t = l.trim();
        if in_comment {
            in_comment = !t.contains("*/");
        } else if in_attr > 0 {
            in_attr += brackets(t);
        } else if t.is_empty() || t.starts_with("//") {
        } else if t.starts_with("/*") {
            in_comment = !t.contains("*/");
        } else if t.starts_with("#![") {
            if is_unix_guard(t) {
                return true;
            }
            // An inner attribute wrapped over lines: read past it to its close.
            in_attr = brackets(t);
        } else {
            // The first item, or an outer attribute on it: no inner attribute follows.
            return false;
        }
    }
    false
}

/// The item a pending `#[cfg(unix)]` covers, read line by line until it ends.
///
/// It ends where its first `{` opens a block (the guard then holds to the block's
/// close), at a `;` outside brackets, or where the enclosing scope closes. A `,`
/// outside brackets ends a field, a match arm or a variant — and not a `fn`,
/// `struct`, `enum`, `union`, `trait`, `impl` or `mod` header, whose wrapped
/// parameters and `where` bounds end their lines with `,` before its `{` arrives.
/// String and char literals are read as single tokens ([`outside_literals`]), here
/// and in the brace depth [`scan`] holds a block guard by. Not read: a raw string
/// that holds a `"`, and a string that spans lines — either can put a bracket or a
/// brace in a literal on the wrong side, which can hold a guard too long and hide a
/// finding. Angle brackets are not counted: a generic wrapped over lines can end a
/// field early, which reports a finding rather than hides one.
struct Item {
    header: bool,
    brackets: i32,
}

impl Item {
    fn starting(code: &str) -> Item {
        let mut t = code.trim_start();
        if let Some(rest) = t.strip_prefix("pub(") {
            t = rest.split_once(')').map_or("", |(_, r)| r);
        }
        // The keyword that leads the item, past its qualifiers, and not followed by a
        // `:` — `union: u8,` is a field named `union`, and ends at its comma.
        let qualifier = |w: &str| {
            matches!(w, "pub" | "async" | "unsafe" | "const" | "extern" | "default" | "\"C\"")
        };
        let mut words = t.split_whitespace().skip_while(|w| qualifier(w));
        let lead = words.next().unwrap_or("");
        let keyword = lead.split(['<', '(', ':', '{']).next().unwrap_or("");
        let header = matches!(keyword, "fn" | "struct" | "enum" | "union" | "trait" | "impl" | "mod")
            && !lead[keyword.len()..].starts_with(':')
            && !words.next().is_some_and(|w| w.starts_with(':'));
        Item { header, brackets: 0 }
    }

    /// Read one more line of the item; true if the item ends on it.
    fn ends_on(&mut self, code: &str) -> bool {
        for (_, c) in outside_literals(code) {
            match c {
                '(' | '[' => self.brackets += 1,
                ')' | ']' => self.brackets -= 1,
                ';' if self.brackets <= 0 => return true,
                ',' if self.brackets <= 0 && !self.header => return true,
                '}' if self.brackets <= 0 => return true,
                _ => {}
            }
        }
        false
    }
}

/// The characters of one line of code outside its string and char literals, with their
/// byte offsets; the literals are dropped whole: `'['` is not a bracket and `'"'` does not
/// open a string. A lifetime (`'a`, `'static`) is not a char literal and is kept. A string
/// left open at the end of the line is dropped to the end.
fn outside_literals(code: &str) -> Vec<(usize, char)> {
    let c: Vec<(usize, char)> = code.char_indices().collect();
    let at = |i: usize| c.get(i).map(|p| p.1);
    let (mut out, mut i) = (Vec::new(), 0);
    while i < c.len() {
        match c[i].1 {
            '"' => {
                i += 1;
                while i < c.len() && c[i].1 != '"' {
                    i += if c[i].1 == '\\' { 2 } else { 1 };
                }
                i += 1;
            }
            // `'\n'`, `'\''`, `'\u{..}'`: to the closing quote after the escape.
            '\'' if at(i + 1) == Some('\\') => {
                i += 3;
                while i < c.len() && c[i].1 != '\'' {
                    i += 1;
                }
                i += 1;
            }
            '\'' if at(i + 2) == Some('\'') => i += 3,
            _ => {
                out.push(c[i]);
                i += 1;
            }
        }
    }
    out
}

/// `[` less `]` on one line, outside literals.
fn brackets(line: &str) -> i32 {
    outside_literals(line)
        .iter()
        .map(|(_, c)| match c {
            '[' => 1,
            ']' => -1,
            _ => 0,
        })
        .sum()
}

/// Every Unix-only path in `src` that no guard covers, as the lines the gate prints.
fn scan(file: &str, src: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let mut depth: i32 = 0;
    // Depths at which a guard is currently open.
    let mut guarded_until: Vec<i32> = Vec::new();
    let mut pending_guard = false;
    // The item a pending guard covers, once its first line is read: see `Item`.
    let mut item: Option<Item> = None;
    // Inside a `const NAME: &[&str] = &[ .. ];` — see `is_str_table_open`.
    let mut in_str_table = false;

    for (n, line) in src.lines().enumerate() {
        let code = code_of(line);

        if is_unix_guard(line) {
            pending_guard = true;
        }

        // Outside literals, as the item reader counts: a `"{"` or `'}'` is not where a
        // guarded block opens or closes
        // (`TASK-windows-check-counts-a-brace-inside-a-literal-as-a-block-boundary`).
        let braces = outside_literals(code);
        let opens = braces.iter().filter(|(_, c)| *c == '{').count() as i32;
        let closes = braces.iter().filter(|(_, c)| *c == '}').count() as i32;

        let guarded = !guarded_until.is_empty() || pending_guard;

        // A table of string literals names these paths, it does not
        // call them: `const SOCKET_NAMES: &[&str] = &["UnixListener", ..]`
        // compiles identically on Windows. Two checkers in this tree hold
        // their needles that way — this one, and `infer-check`, which
        // greps `core/infer` and `core/kinferd` for socket names
        // (RFC-0085) — and both were reported as unguarded usage.
        //
        // Scoped to the table rather than to the file. The first fix
        // skipped `windows_check.rs` whole, then `infer_check.rs` whole
        // beside it; a file-wide skip means a real `UnixStream::connect`
        // written anywhere else in a checker is exempt too, which is
        // more than the trap needs and exactly where a gate quietly
        // stops holding. Nothing is exempt now — only lines between a
        // `&[&str]` table's opening and its `];`, in every file alike.
        if is_str_table_open(code) {
            in_str_table = true;
        } else if in_str_table && code.trim_start().starts_with("];") {
            in_str_table = false;
        }

        if !guarded && !in_str_table {
            for needle in UNIX_ONLY {
                if code.contains(needle) {
                    findings.push(format!(
                        "{}:{}: `{}` with no #[cfg(unix)] above it\n      {}",
                        file,
                        n + 1,
                        needle,
                        line.trim()
                    ));
                    break;
                }
            }
        }

        if pending_guard && opens > 0 {
            // The guard covers a block: hold it until depth returns.
            guarded_until.push(depth);
            pending_guard = false;
            item = None;
        } else if let Some(item_code) = pending_guard
            .then(|| match guard_and_rest(line) {
                // A guard with its item on the same line: the item starts after the `]`.
                Some(rest) => code_of(rest),
                None if line.trim().starts_with("#[") => "",
                None => code,
            })
            .filter(|c| !c.trim().is_empty())
        {
            // Attributes are skipped rather than treated as the item:
            // `#[cfg(unix)]` followed by `#[tokio::test]` followed by the fn
            // is the ordinary shape, and the first draft cleared the guard on
            // the second attribute and reported every guarded test in the tree.
            //
            // And the item is read to its end, not to its first line. A
            // signature rustfmt wraps puts `fn as_the_owner(` alone on the line
            // after the guard; clearing there left the body's `use` unguarded
            // (`TASK-windows-check-drops-a-guard-at-a-wrapped-fn-signature`).
            let it = item.get_or_insert_with(|| Item::starting(item_code));
            if it.ends_on(item_code) {
                pending_guard = false;
                item = None;
            }
        }

        depth += opens - closes;
        while guarded_until.last().is_some_and(|d| depth <= *d) {
            guarded_until.pop();
        }
    }
    findings
}

/// The verdict over what [`run`] read. A scan of zero files is a refusal, not a pass: a tree
/// nobody read is not a clean one, and neither is a count of zero
/// (`TASK-windows-check-passes-from-any-cwd-but-the-repo-root`).
fn verdict(scanned: usize, findings: &[String]) -> Result<String, String> {
    if scanned == 0 {
        return Err("windows-check: read 0 Rust files — nothing was measured.\n\
             None of the roots it walks held a Rust file it could read. \
             A count of zero is not a clean tree."
            .to_string());
    }
    if findings.is_empty() {
        return Ok(format!(
            "windows-check: OK — no unguarded Unix-only path in {scanned} Rust file(s).\n\
             (A grep, not a compiler: see the module doc for what it cannot see.)"
        ));
    }
    let mut msg = format!(
        "windows-check: {} Unix-only usage(s) that Windows will also compile:\n\n",
        findings.len()
    );
    for f in findings {
        msg.push_str(&format!("  {f}\n"));
    }
    msg.push_str(&format!("\n{FIX}"));
    Err(msg)
}

pub fn run() {
    let mut findings: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    // Anchored at the checkout, not the process's working directory: run from `xtask/`, none of
    // `ROOTS` resolves relative to it and the walk read nothing
    // (`TASK-windows-check-passes-from-any-cwd-but-the-repo-root`).
    let repo = crate::out::root();

    for root in ROOTS {
        if !repo.join(root).exists() {
            continue;
        }
        // Through the one `rg` reader: an `rg` that cannot start or errors is a refusal, not
        // zero files (`TASK-windows-check-and-seam-check-report-clean-when-rg-cannot-run`).
        let args = ["-l", "-t", "rust", "-e", "", root];
        let found = match crate::rg::search(&repo, args) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "windows-check: nothing was measured under `{root}` — {e}\n\
                     A tree nobody read is not a clean one."
                );
                std::process::exit(1);
            }
        };
        for file in found.stdout().lines() {
            let Ok(src) = std::fs::read_to_string(repo.join(file)) else {
                continue;
            };
            scanned += 1;

            if guarded_whole(&src) {
                continue;
            }
            findings.extend(scan(file, &src));
        }
    }

    match verdict(scanned, &findings) {
        Ok(ok) => println!("{ok}"),
        Err(refusal) => {
            eprintln!("{refusal}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TASK-windows-check-passes-from-any-cwd-but-the-repo-root`: zero files read is a
    /// refusal, whatever the findings list says.
    #[test]
    fn a_scan_of_zero_files_is_refused_not_passed() {
        let refused = verdict(0, &[]).unwrap_err();
        assert!(refused.contains("read 0 Rust files"));
        assert!(!refused.contains("OK"));
        assert!(verdict(1, &[]).unwrap().contains("OK"));
        assert!(verdict(1, &["a.rs:1: x".to_string()]).is_err());
    }

    /// The shape `infra/relay/src/operator_file_tests.rs` has: a module doc, then
    /// a Unix-only `use`. `TASK-the-relays-operator-file-tests-trip-windows-check`.
    /// The path is split with `concat!` so this fixture is not itself a finding.
    const SPLIT_MODULE: &str = concat!(
        "// SPDX-License-Identifier: AGPL-3.0-or-later\n",
        "//! Tests that only mean anything on Unix.\n",
        "//!\n",
        "//! Several lines of doc before the code starts.\n",
        "\n",
        "use std::os::",
        "unix::fs::MetadataExt as _;\n",
    );

    #[test]
    fn a_file_guarded_the_way_the_message_says_passes() {
        let guarded = SPLIT_MODULE.replace("\nuse ", "\n#![cfg(unix)]\n\nuse ");
        assert_ne!(guarded, SPLIT_MODULE);
        assert!(guarded_whole(&guarded));
        assert!(FIX.contains("#![cfg(unix)]"));
        assert!(FIX.contains("before its first item"));
    }

    /// A parent's `#[cfg(unix)] mod` line guards the file, and the file cannot
    /// say so: this gate reads each file alone. The message must not offer it.
    #[test]
    fn the_message_does_not_offer_a_guard_the_gate_does_not_read() {
        assert!(!guarded_whole(SPLIT_MODULE));
        assert!(!FIX.contains("the parent declares"));
        assert!(FIX.contains("is not read"));
    }

    /// `TASK-windows-check-drops-a-guard-at-a-wrapped-fn-signature`: the shape of
    /// `as_the_owner` in `infra/relay/src/admission.rs`. rustfmt wraps the signature,
    /// so the line after the guard is `fn as_the_owner(` — not the item's end — and
    /// the body's first line is a Unix-only `use` the fn's guard covers.
    const WRAPPED_FN: &str = concat!(
        "#[cfg(unix)]\n",
        "fn as_the_owner(\n",
        "    dir: &Path,\n",
        "    uid: u32,\n",
        ") -> anyhow::Result<String> {\n",
        "    use std::os::",
        "unix::process::CommandExt as _;\n",
        "    Ok(String::new())\n",
        "}\n",
    );

    #[test]
    fn a_guard_over_a_wrapped_fn_signature_covers_its_body() {
        assert_eq!(scan("f.rs", WRAPPED_FN), Vec::<String>::new());
        // A `where` clause ends its lines with `,` too, and is still the signature.
        let with_where = WRAPPED_FN.replace(
            ") -> anyhow::Result<String> {\n",
            ") -> anyhow::Result<String>\nwhere\n    T: Send,\n{\n",
        );
        assert_eq!(scan("f.rs", &with_where), Vec::<String>::new());
    }

    /// What the guard must still let go of: the item it covered has ended, so the
    /// next one is read. A field ends at its `,`, a statement at its `;` — also when
    /// a call inside it wraps — and the last variant at the enclosing `}`.
    #[test]
    fn a_guard_ends_with_the_item_it_covered() {
        let unguarded = concat!("    b: std::os::", "unix::net::Unix", "Stream,\n");
        let field = format!("struct S {{\n    #[cfg(unix)]\n    a: u8,\n{unguarded}}}\n");
        assert_eq!(scan("f.rs", &field).len(), 1, "the second field is not guarded");
        let stmt = format!(
            "fn f() {{\n    #[cfg(unix)]\n    let x = g(\n        1,\n    );\n    let {unguarded}}}\n"
        );
        assert_eq!(scan("f.rs", &stmt).len(), 1, "the second statement is not guarded");
        let tail = format!("enum E {{\n    #[cfg(unix)]\n    A\n}}\nstruct T {{\n{unguarded}}}\n");
        assert_eq!(scan("f.rs", &tail).len(), 1, "the next item is not guarded");
    }

    /// `TASK-windows-check-does-not-read-a-target-os-guard-or-one-past-line-20`: the
    /// shape of `core/kvaultd/tests/a_verb_finds_the_installed_vault.rs`, whose inner
    /// `#![cfg(target_os = "linux")]` sits on line 22 under its module doc. rustc
    /// reads an inner attribute anywhere before the first item, and so does this.
    #[test]
    fn an_inner_target_os_guard_after_a_doc_of_any_length_guards_the_file() {
        for guard in [
            "#![cfg(target_os = \"linux\")]",
            "#![cfg(target_os = \"macos\")]",
            "#![cfg(all(unix, target_os = \"linux\"))]",
            "#![cfg(unix)]",
        ] {
            let late = SPLIT_MODULE.replace(
                "\nuse ",
                &format!("\n{}{guard}\n\nuse ", "//! doc\n".repeat(40)),
            );
            assert!(guarded_whole(&late), "{guard} after 40 lines of doc");
        }
    }

    /// And a `target_os` guard on one item covers it, as `unix` does.
    #[test]
    fn a_target_os_guard_on_an_item_covers_it() {
        let item = concat!(
            "#[cfg(target_os = \"linux\")]\n",
            "fn f() {\n",
            "    use std::os::",
            "unix::fs::MetadataExt as _;\n",
            "}\n",
        );
        assert_eq!(scan("f.rs", item), Vec::<String>::new());
    }

    /// Judicial review of this branch: a char literal is one token. `'['` counted as an
    /// open bracket and `'"'` as an open string, so the `,` or `;` that ends the guarded
    /// item was read as nested, and the guard held over the unguarded `use` after it —
    /// the shape `tests/tests/suite/ipc_hardening.rs` has around line 252. A lifetime
    /// is not a char literal. And `union` names a field as well as an item.
    #[test]
    fn a_char_literal_or_a_field_named_union_does_not_hold_a_guard_open() {
        let after = concat!("    use std::os::", "unix::fs::Permissions", "Ext as _;\n");
        let arm = format!(
            "fn f() {{\n    let t = match e {{\n        #[cfg(unix)]\n        A(p) => p\n            .map(|c: char| c == '[')\n            .unwrap_or(false),\n        B => false,\n    }};\n{after}}}\n"
        );
        assert_eq!(scan("f.rs", &arm).len(), 1, "the use after the match is not guarded");
        let quote = format!("fn f() {{\n    #[cfg(unix)]\n    let q = '\"';\n{after}}}\n");
        assert_eq!(scan("f.rs", &quote).len(), 1, "the use after the quote is not guarded");
        let escaped = format!("fn f() {{\n    #[cfg(unix)]\n    let q = '\\'';\n{after}}}\n");
        assert_eq!(scan("f.rs", &escaped).len(), 1, "an escaped quote is one char");
        let lifetime = format!("fn f() {{\n    #[cfg(unix)]\n    let q: &'static str = g(\n        1,\n    );\n{after}}}\n");
        assert_eq!(scan("f.rs", &lifetime).len(), 1, "a lifetime is not a char literal");
        let union = format!("struct S {{\n    #[cfg(unix)]\n    union: u8,\n{after}}}\n");
        assert_eq!(scan("f.rs", &union).len(), 1, "a field named union ends at its comma");
    }

    /// `TASK-windows-check-counts-a-brace-inside-a-literal-as-a-block-boundary`: the
    /// depth that says where a guarded block ends is counted outside literals too. A
    /// `{` in a literal inside the block must not hold the guard past its close, and a
    /// `}` in one must not release it early.
    #[test]
    fn a_brace_inside_a_literal_is_not_a_block_boundary() {
        let after = concat!("use std::os::", "unix::fs::Permissions", "Ext as _;\n");
        for body in [
            "fn f() -> &'static str { \"{\" }\n",
            "fn f() {\n    let a = '{';\n}\n",
            "fn f() {\n    println!(\"{{\");\n}\n",
        ] {
            let src = format!("#[cfg(unix)]\n{body}{after}");
            assert_eq!(scan("f.rs", &src).len(), 1, "the use after the block is not guarded:\n{src}");
        }
        for inner in ["let s = \"}\";", "let c = '}';"] {
            let src = format!("#[cfg(unix)]\nfn f() {{\n    {inner}\n    {after}}}\n");
            assert_eq!(scan("f.rs", &src), Vec::<String>::new(), "the use inside the block is guarded:\n{src}");
        }
    }

    /// Assessor, round three: a predicate is split at its commas outside literals too.
    /// `target_os = "("` swallowed the comma after it, so `any(target_os = "(", windows)`
    /// — true on Windows — read as one false arm and a guard, and hid the path under it.
    /// And an inner attribute's brackets are counted outside literals, so a `"]"` in one
    /// does not end it early.
    #[test]
    fn a_bracket_inside_a_literal_in_an_attribute_is_not_read_as_one() {
        assert!(!is_unix_guard("#[cfg(any(target_os = \"(\", windows))]"));
        let src = concat!(
            "#[cfg(any(target_os = \"(\", windows))]\n",
            "use std::os::",
            "unix::fs::Permissions",
            "Ext as _;\n"
        );
        assert_eq!(scan("f.rs", src).len(), 1);
        assert!(guarded_whole("#![doc = \"]\"]\n#![cfg(unix)]\nuse x;\n"));
        assert!(guarded_whole("#![doc = concat!(\n    \"[\",\n)]\n#![cfg(unix)]\nuse x;\n"));
    }

    /// A `//` inside a string is not a comment: the needle after it is read.
    #[test]
    fn a_slash_pair_in_a_string_does_not_end_the_line() {
        let line = concat!("let u = (\"http://x\", std::os::", "unix::fs::chown(p, None, None));\n");
        assert_eq!(scan("f.rs", line).len(), 1);
        assert_eq!(code_of(concat!("let a = 1; // Unix", "Stream")), "let a = 1; ");
    }

    /// A guard is read to its `]`, not to the line's end: a comment after it, or the
    /// item it covers on the same line, leaves it a guard — as the word search did.
    /// And a same-line item ends there, so the line after it is read.
    #[test]
    fn a_guard_with_more_on_its_line_is_still_a_guard() {
        assert!(is_unix_guard("#[cfg(unix)] // only unix has uids"));
        assert!(is_unix_guard("#[cfg(target_os = \"linux\")] fn f() {}"));
        let same_line = concat!("#[cfg(unix)] use std::os::", "unix::fs::MetadataExt as _;\n");
        assert_eq!(scan("f.rs", same_line), Vec::<String>::new());
        let then = format!("{same_line}{}", concat!("use std::os::", "unix::fs::Permissions", "Ext as _;\n"));
        assert_eq!(scan("f.rs", &then).len(), 1, "the next line is not guarded");
    }

    /// What is not a guard: a predicate Windows can satisfy. `not(target_os = "linux")`
    /// is true on Windows; `any(unix, windows)` is too; `cfg_attr` guards nothing. And an
    /// inner attribute after the first item is not the file's — rustc refuses it there.
    #[test]
    fn a_predicate_windows_can_satisfy_is_not_a_guard() {
        for line in [
            "#[cfg(not(target_os = \"linux\"))]",
            "#[cfg(target_os = \"windows\")]",
            "#[cfg(any(unix, windows))]",
            "#[cfg(not(unix))]",
            "#[cfg(test)]",
            "#[cfg_attr(unix, allow(dead_code))]",
            "#[cfg(target_family = \"windows\")]",
        ] {
            assert!(!is_unix_guard(line), "{line}");
        }
        for line in [
            "#[cfg(unix)]",
            "#[cfg(not(windows))]",
            "#[cfg(target_family = \"unix\")]",
            "#[cfg(all(test, unix))]",
            "#[cfg(all(target_os = \"linux\", target_env = \"gnu\"))]",
            "#[cfg(not(any(windows, target_os = \"linux\")))]",
            "    #[cfg(any(target_os = \"linux\", target_os = \"macos\"))]",
        ] {
            assert!(is_unix_guard(line), "{line}");
        }
        let after_item = SPLIT_MODULE.replace("\nuse ", "\nfn first() {}\n#![cfg(unix)]\nuse ");
        assert!(!guarded_whole(&after_item));
    }
}
