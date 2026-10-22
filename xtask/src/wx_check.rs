// SPDX-License-Identifier: AGPL-3.0-or-later
//! `wx-check`: a server whose unit says `MemoryDenyWriteExecute=yes` links no crate that
//! emits code at run time.
//!
//! Both units say it — `infra/relay/kotton-relay.service` and
//! `infra/vault/kotton-vault.service` — on the strength of a trace and a `cargo tree` that
//! named no JIT crate in either closure on the day it was added
//! (`TASK-the-relay-and-the-vault-units-leave-ten-directives-unset-that-nobody-has-run`).
//! The kernel holds the directive; nothing held the fact it stands on. A JIT reached
//! later through any dependency would pass every gate and surface only on the host, as
//! `EPERM` from `mmap` or `mprotect` at the first call that maps code. This is the reader
//! that makes that fact checkable where the dependency is added
//! (`TASK-nothing-holds-the-relay-and-the-vault-to-a-dependency-closure-without-a-jit`).
//!
//! ## What it reads
//!
//! The servers are [`release_server::SERVERS`] — the table `release-server` builds from, so a
//! third server is held here the day it can be released. For each, its unit's `[Service]`
//! section: a unit that does not say `MemoryDenyWriteExecute=yes` makes no claim this gate
//! holds, and the run says so rather than passing it silently. (That both units make it is
//! `release_server`'s `each_unit_takes_away_what_its_binary_never_reaches_for`, not a second
//! copy here.) For each that does, the closure `cargo tree -e normal,no-proc-macro` resolves
//! for [`release_server::TARGET`] — the target the archive ships for — with default
//! features, which is what `release-server` builds. Proc-macros are left out by that flag,
//! not by `-e normal`: they are normal dependencies that run inside rustc on the builder,
//! never under the unit. Build scripts are build edges and `-e normal` leaves them out. The
//! relay is its own workspace, so it is read by its manifest path.
//!
//! ## Why a deny-list, when `infer-check` argues for an allow-list
//!
//! `infer-check` inverts to an allow-list because it is the *only* guard: nothing confines
//! `kinferd`, so a socket crate the list missed is a reach nobody stops. Here the guard is the
//! kernel. A code-emitting crate this list misses still cannot map writable code on the host —
//! the directive refuses it there, loudly, at start or at first use. A miss moves a failure
//! later; it never lets one through. So the list's job is to name the failure early, and a
//! miss costs a late diagnosis, not a property.
//!
//! An allow-list would hold a stronger claim — nothing unknown enters — at a price this gate
//! does not need to pay: the vault's closure is 366 crates and the relay's 151 (distinct
//! names, `-e normal,no-proc-macro --target x86_64-unknown-linux-musl`, measured 2026-09-28), and every dependency bump would add
//! lines somebody approves without being able to tell whether the new crate emits code. The
//! crates that do are few and announce it in their names, which is what makes a deny-list a
//! set somebody can finish writing down.
//!
//! ## Extending it
//!
//! Add the crate's name to [`CODE_EMITTERS`]. An entry names a family: `cranelift` refuses
//! `cranelift` and every `cranelift-*`. A crate belongs here when its purpose is to emit and
//! map machine code in the running process; one that merely *can* (a regex engine with an
//! optional JIT that falls back when refused) does not, because the directive's refusal is
//! then silent and harmless, and naming it would be a finding nobody can act on.

use std::path::Path;
use std::process::Command;

use crate::release_server::{self, Server};

/// Crates that emit machine code at run time. Each entry refuses its name and its `-`
/// family. Extend it as the module header says.
pub(crate) const CODE_EMITTERS: &[&str] = &[
    // WebAssembly runtimes that compile ahead of calls, and their code generators.
    "wasmtime",
    "cranelift",
    "wasmer",
    "wasmedge-sys",
    // LLVM bindings, and the other general code generators.
    "llvm-sys",
    "inkwell",
    "gccjit",
    "gccjit_sys",
    "dynasmrt",
    // Script engines that JIT.
    "v8",
    "mozjs",
    "luajit-src",
];

/// Whether `krate` is on [`CODE_EMITTERS`], by name or by family.
fn emitter(krate: &str) -> Option<&'static str> {
    CODE_EMITTERS.iter().copied().find(|e| {
        krate == *e || krate.strip_prefix(e).is_some_and(|rest| rest.starts_with('-'))
    })
}

/// Every crate on [`CODE_EMITTERS`] in a `cargo tree --prefix none` listing, once each, read
/// by `infer-check`'s own parser.
fn emitters_in(tree: &str) -> Vec<String> {
    crate::infer_check::crate_names(&runtime(tree), &[])
        .into_iter()
        .filter(|k| emitter(k).is_some())
        .collect()
}

/// The lines of a `--prefix none` listing that name code which runs in the process: every
/// one but a proc-macro, which runs inside rustc on the builder. [`EDGES`] already leaves
/// them out of the tree this gate asks for; this holds the finding to the same rule
/// whatever listing it is handed.
fn runtime(tree: &str) -> String {
    tree.lines()
        .filter(|l| !l.trim_end().ends_with("(proc-macro)"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The edges read: normal dependencies, less proc-macros. `-e normal` alone keeps them —
/// a proc-macro is a normal dependency — and one under a listed family (wasmtime's export
/// macros) was named as a code emitter it is not
/// (`TASK-wx-check-names-a-proc-macro-as-a-code-emitter-and-offers-dropping-the-directive`).
const EDGES: &str = "normal,no-proc-macro";

/// The closure `server` ships for `target` along `edges`, as `cargo tree --prefix none`
/// lists it. This gate reads [`EDGES`]; `release-server`'s C notice reads build edges too
/// ([`release_server::C_EDGES`]); `vault-check` reads the vault's normal edges for every
/// target — one reader, three questions. An error when cargo cannot say: a tree nobody read
/// is not a clean one.
pub(crate) fn closure(root: &Path, server: &Server, target: &str, edges: &str) -> Result<String, String> {
    let out = Command::new("cargo")
        .arg("tree")
        .args(server.selector())
        .args(["-e", edges, "--prefix", "none", "--target", target])
        .current_dir(root)
        .output()
        .map_err(|e| format!("could not start cargo: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`cargo tree {}` failed:\n{}",
            server.selector().join(" "),
            String::from_utf8_lossy(&out.stderr).trim_end()
        ));
    }
    let tree = String::from_utf8_lossy(&out.stdout).into_owned();
    if tree.trim().is_empty() {
        return Err(format!("`cargo tree {}` listed nothing", server.selector().join(" ")));
    }
    Ok(tree)
}

pub(crate) fn wx_check() {
    let root = Path::new(".");
    let mut failed = false;
    let mut held = Vec::new();
    for server in release_server::SERVERS {
        let unit = match server.unit_text(root) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("wx-check: {e}");
                failed = true;
                continue;
            }
        };
        if release_server::unit_value(&unit, "MemoryDenyWriteExecute").as_deref() != Some("yes") {
            println!(
                "wx-check: {} does not say MemoryDenyWriteExecute=yes, so {} is held to nothing here.",
                server.unit_src(),
                server.binary
            );
            continue;
        }
        let tree = match closure(root, &server, release_server::TARGET, EDGES) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("wx-check: {}: {e}", server.binary);
                failed = true;
                continue;
            }
        };
        let found = emitters_in(&tree);
        if found.is_empty() {
            held.push(server.binary);
            continue;
        }
        failed = true;
        let mut families: Vec<&str> = Vec::new();
        for family in found.iter().filter_map(|k| emitter(k)) {
            if !families.contains(&family) {
                families.push(family);
            }
        }
        eprintln!(
            "wx-check: {} links the code-emitting famil{} {} ({}), and {} says \
             MemoryDenyWriteExecute=yes, so the kernel will refuse the mapping on the host.",
            server.binary,
            if families.len() == 1 { "y" } else { "ies" },
            families.join(", "),
            found.join(", "),
            server.unit_src()
        );
        let [flag, what] = server.selector();
        eprintln!(
            "  `cargo tree {flag} {what} -e {EDGES} --target {} -i {}` shows the path. Remove the \
             dependency, or drop the directive from the unit in the same commit and say why.",
            release_server::TARGET,
            // The first one the tree reaches, depth first: the one nearest what named it.
            runtime(&tree)
                .lines()
                .filter_map(|l| l.split_whitespace().next())
                .find(|k| emitter(k).is_some())
                .unwrap_or(&found[0])
        );
    }
    if failed {
        std::process::exit(1);
    }
    if held.is_empty() {
        eprintln!(
            "wx-check: no server's unit says MemoryDenyWriteExecute=yes, so nothing was held. \
             If the directive was dropped on purpose, drop this gate from `just lint` with it."
        );
        std::process::exit(1);
    }
    println!(
        "wx-check: OK — {} link{} none of {} code-emitting crate families ({}), for {}.",
        held.join(" and "),
        if held.len() == 1 { "s" } else { "" },
        CODE_EMITTERS.len(),
        CODE_EMITTERS.join(", "),
        release_server::TARGET
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_refuses_its_name_and_its_family_and_nothing_that_only_shares_a_prefix() {
        assert_eq!(emitter("wasmtime"), Some("wasmtime"));
        assert_eq!(emitter("cranelift-codegen"), Some("cranelift"));
        assert_eq!(emitter("wasmer-compiler-llvm"), Some("wasmer"));
        assert_eq!(emitter("v8"), Some("v8"));
        assert_eq!(emitter("wasmtimer"), None);
        assert_eq!(emitter("v8-like"), Some("v8"));
        assert_eq!(emitter("tokio"), None);
        assert_eq!(emitter("kotton-wasm"), None);
    }

    #[test]
    fn a_planted_emitter_deep_in_a_tree_is_named_once() {
        let tree = "kvaultd v0.1.0 (/k/core/kvaultd)\n\
                    tokio v1.0.0\n\
                    some-plugin-host v0.3.0\n\
                    wasmtime v25.0.0\n\
                    cranelift-codegen v0.112.0\n\
                    wasmtime v25.0.0 (*)\n";
        assert_eq!(emitters_in(tree), ["cranelift-codegen", "wasmtime"]);
        assert!(emitters_in("kvaultd v0.1.0\ntokio v1.0.0\n").is_empty());
    }

    #[test]
    fn a_proc_macro_under_a_listed_family_is_not_a_finding() {
        // A proc-macro runs inside rustc on the builder, never under the unit, so the
        // directive cannot refuse it and naming it would offer dropping the directive as a
        // remedy for nothing (TASK-wx-check-names-a-proc-macro-as-a-code-emitter-and-offers-dropping-the-directive).
        let tree = "kvaultd v0.1.0 (/k/core/kvaultd)\n\
                    serde_derive v1.0.0 (proc-macro)\n\
                    wasmtime-internal-versioned-export-macros v47.0.0 (proc-macro)\n";
        assert!(emitters_in(tree).is_empty());
    }
}
