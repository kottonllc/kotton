// SPDX-License-Identifier: AGPL-3.0-or-later
//! `infer-check`: the inference runtime's crate, `core/infer`, links nothing that could open a
//! socket and names nothing that does.
//!
//! A weights file is untrusted input parsed by a large runtime, and the process that parses it
//! must not be the process that can open the store. `core/infer` is the crate that runtime is
//! built on here: the trait, its data types and the frames, linked by `kuserd`, `device`,
//! `wire` and the client. This holds the part of that which is mechanical: **`core/infer`
//! links no crate that opens a socket, and names no socket in its own source.**
//!
//! ## What this refuses, and what it does not
//!
//! This check **reads source text and a dependency graph**. It confines no process. A green
//! line means *"nothing `core/infer` links and nothing it names can open a socket"*, which is a
//! smaller claim than *"the weights parser is confined"*, and still a useful one.
//!
//! ## Why an allow-list
//!
//! "Opens a socket" is every networking crate that exists plus every one published tomorrow,
//! and a deny-list of the ones someone thought of passes the rest silently. So
//! [`INFER_ALLOWED`] is read against the crate's *entire* dependency closure, and a crate
//! arriving by any route — a new direct dependency, a new dependency of a dependency, or a
//! feature switched back on — fails the build until somebody looks at it.
//!
//! That is not enough on its own, because `std::net::TcpStream` needs no dependency at all. The
//! source half greps the crate for the names a socket is opened by, so the rule holds whether
//! the reach arrives as a crate or as a line. A raw-syscall crate (`libc`, `nix`) is not on the
//! allow-list, so naming one in source needs an edge the closure half already refuses.
//!
//! The process that runs the runtime, `kinferd`, is not in this tree, and neither is a check of
//! its closure: a check of a crate that is absent would measure nothing.

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

pub fn infer_check() {
    let mut problems: Vec<String> = Vec::new();

    let infer = Path::new("core/infer");
    if !infer.exists() {
        eprintln!(
            "infer-check: {} not found. Run from the workspace root — this check has not \
             looked at anything.",
            infer.display()
        );
        std::process::exit(1);
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
                 inference engine has no way to reach the network."
            ));
        }
    }

    // 2. The crate names no socket, in either direction.
    let mut files: Vec<PathBuf> = Vec::new();
    collect_rs(&infer.join("src"), &mut files);
    if files.is_empty() {
        eprintln!("infer-check: found no Rust source under core/infer/src. Nothing was measured.");
        std::process::exit(1);
    }
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            // A doc comment saying *why* there is no socket here is the thing
            // this check exists to make true, not a violation of it.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for name in SOCKET_NAMES {
                if line.contains(name) {
                    problems.push(format!(
                        "{}:{}  names `{name}` — the inference runtime is reached over the \
                         pipe pair `kuserd` hands it at spawn, and opens nothing itself.",
                        display(file),
                        n + 1
                    ));
                }
            }
        }
    }

    if problems.is_empty() {
        println!(
            "infer-check: OK — core/infer's closure is {} crate(s), every one of them on its \
             allow-list, and its {} source file(s) name no socket. This is a dependency and \
             source audit — it confines no process.",
            seen.len(),
            files.len()
        );
        return;
    }

    eprintln!("infer-check: the inference runtime opens nothing.\n");
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
