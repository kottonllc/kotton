// SPDX-License-Identifier: AGPL-3.0-or-later
//! `infer-check`: the inference runtime can open nothing, and the crates under
//! it link nothing that could.
//!
//! RFC-0085 IN1 separates the weights parser from the daemon on one argument:
//! *"a weights file is untrusted input parsed by a large runtime, and the
//! process that parses it must not be the process that can open the store."*
//! Two of that record's done criteria are mechanical, and this is where they are
//! met:
//!
//! - *"`core/infer` links no crate that opens a socket, and a gate proves it."*
//! - *"`kinferd` … is reached only over a pipe the daemon handed it, never a
//!   named socket."*
//!
//! ## What this refuses, and what it does not
//!
//! Stated first because it has been read wrong. This check **reads source text
//! and dependency graphs**. It confines no process: a parser bug inside
//! `kinferd` runs with whatever the operating system allows a child of `kuserd`,
//! and nothing here narrows that. That wider limit is
//! `TASK-kinferd-is-confined-by-a-grep-and-not-by-the-os`. Reading a green line
//! from this gate as *"the weights parser is confined"* is the failure mode
//! RFC-0085 finding 9 is about; it means *"nothing these two crates link and
//! nothing they name can open a socket or reach a key"*, which is a smaller and
//! still useful claim.
//!
//! ## Why an allow-list, for both crates
//!
//! `vault-check` names four crates a vault may not link, which is the right
//! shape for *"a vault has no apps"* — the forbidden things are known and few.
//! "Opens a socket" is not like that: the set is every networking crate that
//! exists plus every one published tomorrow, and a deny-list of the ones someone
//! thought of passes the rest silently. So this check inverts it. **Both**
//! [`INFER_ALLOWED`] and [`KINFERD_ALLOWED`] are read against an *entire*
//! dependency closure, and a crate arriving by any route — a new direct
//! dependency, a new dependency of a dependency, or a feature switched back on —
//! fails the build until somebody looks at it.
//!
//! That is still not enough on its own, because `std::net::TcpStream` needs no
//! dependency at all. The source part greps both crates' sources for the names a
//! socket is opened by — from `std` as well as from anything else — so the rule
//! holds whether the reach arrives as a crate or as a line.
//!
//! ## `kinferd` was held by a deny-list until 2026-09-16, and is not now
//!
//! Until RFC-0085's **the backend** step, `kinferd`'s closure was 130 crates: it
//! linked `kotton-wire` for the frames, which reached `kotton-pair`'s whole
//! crypto stack it never called, and the acceptor half of `kotton-ipc`, which
//! reached `tokio/net` and `socket2`. Nobody could allow-list that, so the check
//! held `kinferd` by the weaker shape this file's own argument rejects: an
//! allow-list over its *direct* dependencies plus two deny-lists. The gap was
//! not theoretical — with the acceptor's feature restored, `socket2` and `mio`
//! entered the closure and the check printed **OK**.
//!
//! That step landed. The frames moved to `core/infer`, `kotton-ipc` put its
//! acceptor behind `os-provider`, and `kotton-sys` stopped asking `tokio` for
//! `full`. Measured 2026-09-16: **73 crates**, no crypto crate and no socket
//! crate among them. So [`KINFERD_ALLOWED`] is that closure, written down, and
//! the concession is deleted rather than widened — which is what the record that
//! opened this, `TASK-infer-check-holds-kinferd-by-a-deny-list`, asked for.
//!
//! ### What went away with it
//!
//! `KEYLESS_FORBIDDEN` named seven crates `kinferd` may not reach —
//! `kotton-context`, `kotton-store`, `kotton-sealed`, `kotton-record`,
//! `kotton-identity`, `kotton-secret`, `kotton-crypto`. It is **deleted, not
//! moved**: none of the seven is on [`KINFERD_ALLOWED`], so a closure that
//! reaches one fails on the allow-list first, and by a rule that also catches
//! the eighth crate nobody listed. Keeping it would have been a second guard
//! against the same reach, which is the shape `CLAUDE.md`'s second design test
//! exists to stop. Proven, not asserted: the probe that first justified it —
//! `kotton-grant` added to `core/ipc`, reaching `kotton-crypto` through a
//! permitted crate — is still red here.
//!
//! `key-reach-check` holds the key half from the other end — `core/context`'s —
//! and names neither of these crates, which is RFC-0085's criterion stated as an
//! observation rather than a rule. This one is the rule.
//!
//! ## The one deny-list left, and what it is for
//!
//! [`SYSCALL_NAMES`] is a source grep for `libc::` and `nix::`, and it survives
//! the fold on purpose. Both crates are **on** [`KINFERD_ALLOWED`] — they arrive
//! through `kotton-sys`, and an allow-list entry says somebody read the crate.
//! What was read is that each is one `use` away from `socket(2)` in a process
//! whose whole design is that it cannot open one, so the entry is admitted for
//! what `kotton-sys` needs and refused as something `kinferd`'s own source may
//! name. That is one judgement in two halves, not a leftover deny-list over an
//! unjudged set: the set it ranges over is two crates long and both are named
//! above it.
//!
//! The seam back is a smaller closure, not a longer grep. **37 of the 73 crates
//! arrive through `kotton-sys`**, which `kinferd` links only because
//! `kotton-ipc`'s codec half does — including `url` and its ICU stack, `chrono`,
//! `uuid`, and `libc` and `nix` themselves. If the codec stops linking
//! `kotton-sys`, [`SYSCALL_NAMES`] has nothing left to range over and goes too:
//! `TASK-the-ipc-codec-drags-kotton-sys-into-every-pipe-reader`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every crate `core/infer` may have in its dependency closure.
///
/// Not "every crate that is not a networking crate" — **every crate**. An entry
/// here is a statement that someone read what it does. The list is short because
/// the crate is meant to be: a trait, three data types, and a stub.
const INFER_ALLOWED: &[&str] = &[
    "kotton-infer",
    "serde",
    "serde_core",
    "serde_derive",
    "thiserror",
    "thiserror-impl",
    // The proc-macro chain the two derives bring. No runtime presence at all:
    // they run in the compiler, not in the process that parses weights.
    "proc-macro2",
    "quote",
    "syn",
    "unicode-ident",
];

/// Every crate `core/kinferd` may have in its dependency closure.
///
/// The same statement as [`INFER_ALLOWED`], over the larger set: 73 crates,
/// `cargo tree -p kinferd -e normal --no-dedupe` on 2026-09-16, root excluded.
/// It is a closure and not a manifest, so a crate that arrives inside `tokio`'s
/// or `kotton-ipc`'s tree is on this list or the build fails — which is the
/// whole difference from the `KINFERD_DIRECT` it replaced.
///
/// **What is not here, and is the point:** no crypto crate, no store crate, no
/// socket crate. `socket2` and `mio` are absent because `kotton-ipc`'s acceptor
/// sits behind its `os-provider` feature and `kinferd` takes
/// `default-features = false`; restoring that default puts both in the closure,
/// and this list is what notices.
///
/// Grouped by where each crate enters. A group comment is the judgement; adding
/// an entry means writing which group it joins and why that group needs it.
const KINFERD_ALLOWED: &[&str] = &[
    // --- `kotton-infer`, and the closure `INFER_ALLOWED` already judged. The
    // trait, the model manifest, the composed context and the stub backend.
    "kotton-infer",
    "serde",
    "serde_core",
    "serde_derive",
    "thiserror",
    "thiserror-impl",
    // The proc-macro chain, shared by every group below. Compiler-time only:
    // none of it is present in the process that parses weights.
    "proc-macro2",
    "quote",
    "syn",
    "unicode-ident",
    "synstructure",
    // --- `kotton-ipc`, codec half only. Length-prefixed JSON frames on a
    // descriptor the daemon handed over. `os-provider` is off, so the listener,
    // the client and `ChannelAcceptor` are not compiled and `tokio/net` is not
    // requested.
    "kotton-ipc",
    "async-trait",
    "serde_json",
    "itoa",
    "memchr",
    "zmij",
    // --- The async runtime: `rt`, `macros`, `io-std`, `io-util`. No `net`, so
    // no `mio` and no reactor — read the absence of `mio` from this list as the
    // feature set being what the manifest says it is.
    "tokio",
    "tokio-macros",
    "bytes",
    "pin-project-lite",
    "cfg-if",
    // --- Tracing, and the subscriber `main` installs to write to stderr.
    "tracing",
    "tracing-core",
    "tracing-attributes",
    "tracing-log",
    "tracing-subscriber",
    "log",
    "once_cell",
    "lazy_static",
    "matchers",
    "regex-automata",
    "regex-syntax",
    "sharded-slab",
    "thread_local",
    "nu-ansi-term",
    "smallvec",
    // --- `kotton-sys`, reached through `kotton-ipc`'s codec. 37 of the 73
    // crates here are this group, and none of them is anything `kinferd` calls;
    // the module header names the task that removes the edge. Two of them are
    // raw-syscall crates and `SYSCALL_NAMES` refuses `kinferd`'s source naming
    // either — allow-listed for what `kotton-sys` does with them, not for what
    // this crate may.
    "kotton-sys",
    "libc",
    "nix",
    "bitflags",
    "anyhow",
    "getrandom",
    "uuid",
    "chrono",
    "iana-time-zone",
    "num-traits",
    "displaydoc",
    // `url`, and the ICU stack `idna` brings for IDNA normalisation. Parsing,
    // not resolving: none of it opens anything.
    "url",
    "idna",
    "idna_adapter",
    "form_urlencoded",
    "percent-encoding",
    "icu_collections",
    "icu_locale_core",
    "icu_normalizer",
    "icu_normalizer_data",
    "icu_properties",
    "icu_properties_data",
    "icu_provider",
    "litemap",
    "potential_utf",
    "stable_deref_trait",
    "tinystr",
    "utf8_iter",
    "writeable",
    "yoke",
    "yoke-derive",
    "zerofrom",
    "zerofrom-derive",
    "zerotrie",
    "zerovec",
    "zerovec-derive",
];

/// Names by which a socket is opened, whatever it is opened from.
///
/// `std::net` is why this half exists: a crate with no dependencies at all can
/// still bind a port. The list is of *shapes* rather than crates for that
/// reason, and it is checked against source text, so it also catches a socket
/// reached through a re-export.
const SOCKET_NAMES: &[&str] = &[
    "std::net",
    "tokio::net",
    "TcpListener",
    "TcpStream",
    "UdpSocket",
    "UnixListener",
    "UnixStream",
    "UnixDatagram",
    "IpcEndpoint",
    "ChannelAcceptor",
    "socket2",
    "SocketAddr",
];

/// The two raw-syscall crates [`KINFERD_ALLOWED`] admits, refused as source.
///
/// `libc` and `nix` arrive through `kotton-sys`, which `kinferd` links because
/// `kotton-ipc`'s codec does. Allow-listing them says somebody read them, and
/// what was read is that either one is a `use` away from `socket(2)` — so they
/// are admitted for `kotton-sys`'s use and refused for `kinferd`'s own. That is
/// one judgement in two halves rather than a deny-list: the set is these two,
/// and both are named on the allow-list above.
///
/// The measurement this came from (2026-09-15, opening
/// `TASK-infer-check-holds-kinferd-by-a-deny-list`): appending
/// `let _ = libc::socket(2, 1, 0); let _ = nix::sys::socket::socket;` to
/// `core/kinferd/src/main.rs` left this gate green until this list existed.
///
/// The entry is the crate path rather than the syscall, so `libc::bind` and
/// `libc::accept` are refused by the same entry that refuses `libc::socket` and
/// nobody has to keep a list of syscalls current.
///
/// **What it does not catch:** an aliased import (`use libc as c;`). That is a
/// grep's floor. The fix is the edge, not a longer grep — if `kotton-ipc`'s
/// codec stops linking `kotton-sys`, neither crate is in the closure and this
/// list has nothing to range over.
const SYSCALL_NAMES: &[&str] = &["libc::", "nix::"];

pub fn infer_check() {
    let mut problems: Vec<String> = Vec::new();

    let infer = Path::new("core/infer");
    let kinferd = Path::new("core/kinferd");
    for dir in [infer, kinferd] {
        if !dir.exists() {
            eprintln!(
                "infer-check: {} not found. Run from the workspace root — this check has \
                 not looked at anything.",
                dir.display()
            );
            std::process::exit(1);
        }
    }

    // 1. `core/infer`'s whole closure is on the allow-list.
    //
    // `--no-dedupe` repeats a crate once per path to it, which is what makes the
    // *paths* visible; the count reported below is of distinct crates, because a
    // number that counts one crate four times is a number a reader has to
    // discount rather than read.
    let tree = cargo_tree(&[
        "tree",
        "-p",
        "kotton-infer",
        "-e",
        "normal",
        "--prefix",
        "none",
        "--no-dedupe",
    ]);
    let seen = crate_names(&tree, &[]);
    if seen.is_empty() {
        eprintln!(
            "infer-check: `cargo tree` named no crate at all, which cannot be true while \
             `kotton-infer` exists. The parse is broken and this check is vacuous."
        );
        std::process::exit(1);
    }
    for name in &seen {
        if !INFER_ALLOWED.contains(&name.as_str()) {
            problems.push(format!(
                "core/infer links `{name}`, which is not on infer-check's allow-list. If it \
                 opens no socket, add it to INFER_ALLOWED in xtask/src/infer_check.rs and \
                 say why the crate needs it; if it does, this crate may not have it: the \
                 inference engine has no way to reach the network (docs/design/apps.md, \
                 *Inference is a guest too*)."
            ));
        }
    }

    // 2. `kinferd`'s whole closure is on its own allow-list.
    //
    // A closure and not a manifest: the reach this gate exists to refuse has
    // arrived through a permitted crate every time it has been measured, and
    // once through a feature rather than a line, which no reading of
    // `core/kinferd/Cargo.toml` can see.
    let kinferd_tree = cargo_tree(&[
        "tree",
        "-p",
        "kinferd",
        "-e",
        "normal",
        "--prefix",
        "none",
        "--no-dedupe",
    ]);
    let closure = crate_names(&kinferd_tree, &["kinferd"]);
    if closure.is_empty() {
        eprintln!(
            "infer-check: `cargo tree -p kinferd` named no dependency at all, which cannot \
             be true while core/kinferd/Cargo.toml has a [dependencies] table. The parse is \
             broken and this half is vacuous."
        );
        std::process::exit(1);
    }
    for name in &closure {
        if !KINFERD_ALLOWED.contains(&name.as_str()) {
            problems.push(format!(
                "core/kinferd reaches `{name}`, which is not on infer-check's allow-list \
                 for it. `cargo tree -p kinferd -e normal -i {name}` shows by what route. \
                 The weights parser opens no socket, holds no key material and names no \
                 store (docs/design/apps.md, *Inference is a guest too*) — if `{name}` is \
                 none of those, add it to \
                 KINFERD_ALLOWED in xtask/src/infer_check.rs with the group it joins and \
                 why that group needs it; if it is, remove the edge rather than the rule."
            ));
        }
    }

    // 3. Neither crate names a socket, in either direction, and neither names a
    //    raw-syscall crate its closure happens to carry.
    let mut files: Vec<PathBuf> = Vec::new();
    collect_rs(&infer.join("src"), &mut files);
    collect_rs(&kinferd.join("src"), &mut files);
    if files.is_empty() {
        eprintln!(
            "infer-check: found no Rust source under core/infer/src or core/kinferd/src. \
             Nothing was measured."
        );
        std::process::exit(1);
    }
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // A doc comment saying *why* there is no socket here is the thing
            // this check exists to make true, not a violation of it.
            if trimmed.starts_with("//") {
                continue;
            }
            for name in SOCKET_NAMES {
                if line.contains(name) {
                    problems.push(format!(
                        "{}:{}  names `{name}` — the inference runtime is reached over the \
                         pipe pair `kuserd` hands it at spawn, and opens nothing itself \
                         (docs/design/threat-model.md, *The inference engine*).",
                        display(file),
                        n + 1
                    ));
                }
            }
            for name in SYSCALL_NAMES {
                if line.contains(name) {
                    problems.push(format!(
                        "{}:{}  names `{name}` — a raw-syscall crate, one `use` away from \
                         `socket(2)`. `libc` and `nix` are on KINFERD_ALLOWED because \
                         `kotton-sys` needs them, not because this source may name them; \
                         that admission is what makes this line the rule \
                         (docs/design/threat-model.md, *The inference engine*).",
                        display(file),
                        n + 1
                    ));
                }
            }
        }
    }

    if problems.is_empty() {
        println!(
            "infer-check: OK — core/infer's closure is {} crate(s) and core/kinferd's is \
             {}, every one of them on its crate's allow-list; {} source file(s) across the \
             two name no socket and no raw-syscall crate. This is a dependency and source \
             audit — it confines no process.",
            seen.len(),
            closure.len(),
            files.len()
        );
        return;
    }

    eprintln!(
        "infer-check: the weights parser opens nothing (docs/design/apps.md, *Inference is a guest too*).\n"
    );
    for p in &problems {
        eprintln!("  x {p}");
    }
    eprintln!(
        "\nA local model server on a socket is the shape most desktop tooling takes, and \
         the design refuses it for the reason CLAUDE.md's second test gives: \
         a port on the loopback interface is reachable by every process of that user, and \
         the guard is unnecessary once there is nothing to connect to."
    );
    std::process::exit(1);
}

/// `cargo tree`, or a refusal.
///
/// `vault-check` treated a failed `cargo tree` as "nothing forbidden found" and
/// printed OK until 2026-09-28, when it moved onto `wx_check::closure`
/// (`TASK-vault-check-reports-ok-when-cargo-tree-fails`). That is a gate
/// reporting a clean run over an unmeasured one, and it is the failure this
/// repository names most often, so this one refuses instead — at every call
/// site, which is why it is a function rather than a `match` copied once per
/// tree this check walks.
fn cargo_tree(args: &[&str]) -> String {
    let rendered = args.join(" ");
    match Command::new("cargo").args(args).output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        Ok(out) => {
            eprintln!(
                "infer-check: `cargo {rendered}` failed ({}). Nothing was measured.\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("infer-check: could not run `cargo {rendered}`: {e}. Nothing was measured.");
            std::process::exit(1);
        }
    }
}

/// The distinct crate names in a `--prefix none` tree, minus `skip`.
///
/// `skip` is how the root is dropped from a `--depth 1` render, where the first
/// line is the crate being asked about rather than one of its dependencies.
pub(crate) fn crate_names(tree: &str, skip: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in tree.lines() {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if name.is_empty() || name.starts_with('[') || skip.contains(&name) {
            continue;
        }
        out.insert(name.to_string());
    }
    out
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}
