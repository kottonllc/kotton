// SPDX-License-Identifier: AGPL-3.0-or-later
//! Principle VIII, *one sandbox for everyone*, as `constitution-check` reads the tree.
//!
//! An app reaches what its linker holds and nothing else. So the fact that holds the principle
//! is the linker the sandbox builds for an app, and the first inspection reads it; the others
//! read what that linker is built from and what the project's own apps declare:
//!
//! 1. **The linker.** In `core/wasm/src`, a linker gets WASI only from
//!    `add_wasi_without_sockets` in `sandbox.rs`, which is defined, called, and calls exactly
//!    the per-interface `add_to_linker` functions [`WASI_ADDS`] lists by full path, and no
//!    other function whose name ends in `add_to_linker`. No other function there adds a WASI
//!    interface; nothing calls a function that adds all of WASI at once (`add_to_linker_async`
//!    and its kin, by any path or none), names `wasmtime_wasi_http`, or adds a `sockets`
//!    interface; and no `use` imports a WASI path by a glob. Names are resolved through the
//!    file's `use` declarations, so an alias does not hide one. The rule reads every file of
//!    the crate alike: the fetcher's linker, in `extension.rs`, gets its WASI from the same
//!    function an app's does, and [`OTHER_LINKERS`], which would name a function let add all
//!    of WASI at once, names none.
//! 2. **The contract.** `world app` and `world occupant` in
//!    `guest/sdk/kotton-app/wit/kotton-app.wit` import exactly the interfaces they name today
//!    ([`APP_IMPORTS`], [`OCCUPANT_IMPORTS`]), and every interface either world reaches by a
//!    `use` is one it imports. `world fetcher`, an extension's, is not read.
//! 3. **The project's own apps' crates.** These are declarations: no crate under `guest/apps`
//!    declares, in any form Cargo reads, or resolves in its `Cargo.lock`, a crate on the list
//!    [`NETWORK_CRATES`], or `tokio` with its `net` feature; and none of their sources names
//!    `std::net`, `tokio::net` or the WASI socket and HTTP bindings, in a path (its `use`
//!    aliases resolved) or in any leaf of a `use` tree, or `wasi:sockets` or `wasi:http` in a
//!    literal or a WIT file.
//! 4. **What they ask for.** Every capability a bundled app's manifest declares links an
//!    interface `world app` imports, or links none; none links `external-net`, the fetcher's
//!    door to the internet. The capability keys are read from the manifest schema
//!    (`core/schemas/src/app_manifest.rs`) and each is classified in [`MANIFEST_KEYS`], so a
//!    key the schema grows is refused until it is classified here, and a manifest whose
//!    capabilities cannot be read is refused rather than passed.
//!
//! **What they cannot see.** They read text. A crate a guest app reaches by a path dependency
//! is read through the app's `Cargo.lock`, which names its packages and not their features or
//! sources; a dependency's own `std::net` is stopped by the linker at instantiation, not here.
//! The list of network crates is a list: a network crate it does not name passes the crate
//! rule, and the linker is what holds. Both TOML files are read by [`crate::toml_read`],
//! because xtask's own code has no TOML parser to call.

use std::path::Path;

use crate::toml_read;
use crate::user_database_check::{code_only, rel, walk};

/// The contract.
pub(crate) const WIT: &str = "guest/sdk/kotton-app/wit/kotton-app.wit";
/// The manifest schema, whose keys [`MANIFEST_KEYS`] classifies.
pub(crate) const MANIFEST_SCHEMA: &str = "core/schemas/src/app_manifest.rs";
/// The project's own apps, one directory each with a `manifest.toml`.
pub(crate) const BUNDLED_APPS: &str = "guest/apps";

/// What `world app` imports, exactly. Adding one is a change to principle VIII and is
/// argued as one.
pub(crate) const APP_IMPORTS: &[&str] = &[
    "schema", "files", "system", "surface", "media", "call", "messages", "apps", "infer",
];
/// What `world occupant` adds to `world app`, exactly, on the same terms.
pub(crate) const OCCUPANT_IMPORTS: &[&str] = &[
    "auth",
    "layer-surface",
    "devices",
    "contacts",
    "grants",
    "roots",
    "network",
    "joining",
    "landlord",
    "operators",
];

/// Crates whose purpose is to reach the network.
pub(crate) const NETWORK_CRATES: &[&str] = &[
    "reqwest",
    "hyper",
    "hyper-util",
    "ureq",
    "isahc",
    "surf",
    "attohttpc",
    "curl",
    "h2",
    "h3",
    "quinn",
    "mio",
    "socket2",
    "tungstenite",
    "tokio-tungstenite",
    "async-tungstenite",
    "wasi-http",
    "wasmtime-wasi-http",
    "wstd",
    "waki",
    "spin-sdk",
];
/// `tokio` features that bring its sockets.
const TOKIO_NETWORK_FEATURES: &[&str] = &["net", "full"];
/// Paths in Rust source that name the network.
const NETWORK_PATHS: &[&str] = &[
    "std::net",
    "tokio::net",
    "async_std::net",
    "mio::net",
    "wasi::sockets",
    "wasi::http",
    "wasip2::sockets",
    "wasip2::http",
];
/// WASI packages that name the network, as WIT spells them.
const NETWORK_PACKAGES: &[&str] = &["wasi:sockets", "wasi:http"];

/// Every capability key the manifest schema knows, and the interface it links: `None` for a
/// grant that links no interface at all.
pub(crate) const MANIFEST_KEYS: &[(&str, Option<&str>)] = &[
    ("schema.read", Some("schema")),
    ("schema.write", Some("schema")),
    ("files.read", Some("files")),
    ("files.write", Some("files")),
    ("media.microphone", Some("media")),
    ("media.camera", Some("media")),
    ("media.screen", Some("media")),
    ("call.initiate", Some("call")),
    ("call.receive", Some("call")),
    ("messages.send", Some("messages")),
    ("messages.receive", Some("messages")),
    ("apps.launch", Some("apps")),
    ("infer.run", Some("infer")),
    // The fetcher world's interface: an app world never imports it.
    ("network.fetch", Some("external-net")),
    // A role's marker and a flag: the sandbox links nothing for either.
    ("events.subscribe", None),
    ("ui.custom", None),
];
/// What a `[[capabilities]]` entry of the one type the schema knows links.
const SHAPE_TYPES: &[(&str, &str)] = &[("vfs-tree", "files")];

// ── The contract ─────────────────────────────────────────────────────────────

/// One top-level `world` or `interface` in a WIT file and what it names at its own level.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct WitBlock {
    pub kind: String,
    pub name: String,
    /// `import X;`, each with its line.
    pub imports: Vec<(String, usize)>,
    /// `include X;`, each with its line.
    pub includes: Vec<(String, usize)>,
    /// The interface each `use X.{…};` names, with its line.
    pub uses: Vec<(String, usize)>,
}

/// Every top-level `world` and `interface` in `text`.
///
/// A statement is read whole, up to its `;`, so an inline import (`import f: func();`) or a
/// package path (`wasi:http/outgoing-handler@0.2.0`) is its name as written, and matches no
/// interface this file defines.
pub(crate) fn wit_blocks(text: &str) -> Vec<WitBlock> {
    let mut blocks: Vec<WitBlock> = Vec::new();
    let mut depth = 0i32;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("");
        let mut stmt = line.trim();
        // A feature gate before a statement (`@unstable(feature = x) import y;`).
        while stmt.starts_with('@') {
            stmt = match stmt.find(')') {
                Some(at) => stmt[at + 1..].trim_start(),
                None => stmt.trim_start_matches(|c: char| !c.is_whitespace()).trim_start(),
            };
        }
        if depth == 0 {
            for kind in ["world", "interface"] {
                if let Some(rest) = stmt.strip_prefix(kind).filter(|r| r.starts_with(' ')) {
                    let name = rest.trim().trim_end_matches('{').trim().to_string();
                    blocks.push(WitBlock { kind: kind.into(), name, ..Default::default() });
                }
            }
        } else if depth == 1 {
            if let Some(b) = blocks.last_mut() {
                let named = |rest: &str| rest.trim().trim_end_matches(';').trim().to_string();
                if let Some(rest) = stmt.strip_prefix("import ") {
                    b.imports.push((named(rest), i + 1));
                } else if let Some(rest) = stmt.strip_prefix("include ") {
                    b.includes.push((named(rest), i + 1));
                } else if let Some(rest) = stmt.strip_prefix("use ") {
                    let path = rest.rsplit_once(".{").map_or(rest, |(p, _)| p);
                    b.uses.push((named(path), i + 1));
                }
            }
        }
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
    }
    blocks
}

/// What in the contract refuses Article VIII's contract rule.
pub(crate) fn contract_findings(text: &str) -> Vec<String> {
    let blocks = wit_blocks(text);
    let mut out = Vec::new();
    let world = |name: &str| blocks.iter().find(|b| b.kind == "world" && b.name == name);
    let interface = |name: &str| blocks.iter().find(|b| b.kind == "interface" && b.name == name);
    let (Some(app), Some(occupant)) = (world("app"), world("occupant")) else {
        out.push(format!(
            "constitution-check is BROKEN: {WIT}: could not find `world app` and `world \
             occupant`. What an app may import is unread — repoint the check."
        ));
        return out;
    };

    let mut pinned = |b: &WitBlock, imports: &[&str], includes: &[&str]| {
        for (name, line) in &b.imports {
            if !imports.contains(&name.as_str()) {
                out.push(format!(
                    "Article VIII: {WIT} line {line}: `world {}` imports `{name}`, which is not \
                     among the interfaces it offers today ({}). An app reaches only what its \
                     contract offers, and the contract offers no network; a new import is a \
                     change to that principle, argued by adding it to constitution-check.",
                    b.name,
                    imports.join(", ")
                ));
            }
        }
        for want in imports {
            if !b.imports.iter().any(|(n, _)| n == want) {
                out.push(format!(
                    "constitution-check is BROKEN: {WIT}: `world {}` no longer imports `{want}`. \
                     Take it out of the check's list, so a manifest that asks for it is refused.",
                    b.name
                ));
            }
        }
        let got: Vec<&str> = b.includes.iter().map(|(n, _)| n.as_str()).collect();
        if got != includes {
            let line = b.includes.first().map_or(0, |(_, l)| *l);
            out.push(format!(
                "Article VIII: {WIT} line {line}: `world {}` includes {got:?}, and it includes \
                 {includes:?} and nothing else today. An include imports everything the other \
                 world does.",
                b.name
            ));
        }
    };
    pinned(app, APP_IMPORTS, &[]);
    pinned(occupant, OCCUPANT_IMPORTS, &["app"]);

    // What each world reaches through a `use`, its own or an imported interface's.
    let occupant_all: Vec<&str> = APP_IMPORTS.iter().chain(OCCUPANT_IMPORTS).copied().collect();
    for (b, offered) in [(app, APP_IMPORTS.to_vec()), (occupant, occupant_all)] {
        for (target, line) in &b.uses {
            if !offered.contains(&target.as_str()) {
                out.push(format!(
                    "Article VIII: {WIT} line {line}: `world {}` uses `{target}`, which it does \
                     not import; a `use` imports the interface it names.",
                    b.name
                ));
            }
        }
        for name in &offered {
            let Some(iface) = interface(name) else {
                out.push(format!(
                    "Article VIII: {WIT}: `world {}` imports `{name}`, and the contract defines \
                     no interface by that name.",
                    b.name
                ));
                continue;
            };
            for (target, line) in &iface.uses {
                if !offered.contains(&target.as_str()) {
                    out.push(format!(
                        "Article VIII: {WIT} line {line}: `interface {name}` uses `{target}`, so \
                         `world {}` imports it through `{name}` without naming it.",
                        b.name
                    ));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Article VIII: the app and occupant worlds offer only the interfaces they name today.
pub(crate) fn the_contract_offers_no_network(root: &Path, violations: &mut Vec<String>) {
    if let Some(text) = crate::read_required(root, WIT, violations) {
        violations.extend(contract_findings(&text));
    }
}

// ── The linker ───────────────────────────────────────────────────────────────

/// The sandbox's crate, whose linkers are read.
pub(crate) const SANDBOX_SRC: &str = "core/wasm/src";
/// The file that builds an app's linker.
pub(crate) const APP_LINKER_FILE: &str = "core/wasm/src/sandbox.rs";
/// The one function that adds WASI to a linker, an app's or the fetcher's.
pub(crate) const APP_WASI_FN: &str = "add_wasi_without_sockets";
/// Functions under [`SANDBOX_SRC`] let add all of WASI at once, by file and function, with
/// why: none. Every linker the crate builds, an app's and the fetcher's, gets its WASI from
/// [`APP_WASI_FN`], so nothing there may hold a socket. A function named here would be the one
/// place in its file such a call is let pass, and naming one is a change to principle VIII,
/// argued as one.
pub(crate) const OTHER_LINKERS: &[(&str, &str, &str)] = &[];
/// Every WASI interface a linker gets, an app's or the fetcher's, by the full path of the
/// function that adds it: exactly what `add_wasi_without_sockets` calls, its aliases resolved.
/// Adding one here is a change to principle VIII and is argued as one.
pub(crate) const WASI_ADDS: &[&str] = &[
    "wasmtime_wasi_io::bindings::wasi::io::error::add_to_linker",
    "wasmtime_wasi_io::bindings::wasi::io::poll::add_to_linker",
    "wasmtime_wasi_io::bindings::wasi::io::streams::add_to_linker",
    "wasmtime_wasi::p2::bindings::filesystem::types::add_to_linker",
    "wasmtime_wasi::p2::bindings::filesystem::preopens::add_to_linker",
    "wasmtime_wasi::p2::bindings::clocks::wall_clock::add_to_linker",
    "wasmtime_wasi::p2::bindings::clocks::monotonic_clock::add_to_linker",
    "wasmtime_wasi::p2::bindings::random::random::add_to_linker",
    "wasmtime_wasi::p2::bindings::random::insecure::add_to_linker",
    "wasmtime_wasi::p2::bindings::random::insecure_seed::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::exit::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::environment::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::stdin::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::stdout::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::stderr::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::terminal_input::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::terminal_output::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::terminal_stdin::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::terminal_stdout::add_to_linker",
    "wasmtime_wasi::p2::bindings::cli::terminal_stderr::add_to_linker",
];
/// Functions that add every WASI interface at once, sockets among them.
const WHOLE_WASI: &[&str] = &[
    "add_to_linker_async",
    "add_to_linker_sync",
    "add_to_linker_with_options_async",
    "add_to_linker_with_options_sync",
];
/// The crates WASI's bindings come from.
const WASI_CRATES: &[&str] = &["wasmtime_wasi", "wasmtime_wasi_io", "wasmtime_wasi_http"];

/// One path in Rust code (`a::b::c`, a leading `::` dropped), with its line and position.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RustPath {
    pub path: String,
    pub line: usize,
    pub at: usize,
}

/// Every path in `code`, which is [`code_only`]'s output: identifiers joined by `::`, with any
/// space around the `::`.
pub(crate) fn rust_paths(code: &str) -> Vec<RustPath> {
    let c: Vec<char> = code.chars().collect();
    let word = |k: usize| k < c.len() && (c[k].is_alphanumeric() || c[k] == '_');
    let mut line_at = vec![1usize; c.len() + 1];
    for i in 0..c.len() {
        line_at[i + 1] = line_at[i] + usize::from(c[i] == '\n');
    }
    let skip_ws = |mut k: usize| {
        while k < c.len() && c[k].is_whitespace() {
            k += 1;
        }
        k
    };
    let colons = |k: usize| c.get(k) == Some(&':') && c.get(k + 1) == Some(&':');
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let leading = colons(i) && (i == 0 || !(word(i - 1) || c[i - 1] == ':' || c[i - 1] == '>'));
        let start_word = word(i) && (i == 0 || !word(i - 1)) && !c[i].is_ascii_digit();
        if !leading && !start_word {
            i += 1;
            continue;
        }
        if leading && !word(skip_ws(i + 2)) {
            i += 2;
            continue;
        }
        let begin = i;
        let mut k = if leading { skip_ws(i + 2) } else { i };
        let mut path = String::new();
        loop {
            let s = k;
            while word(k) {
                k += 1;
            }
            path.extend(&c[s..k]);
            let next = skip_ws(k);
            if colons(next) && word(skip_ws(next + 2)) {
                path.push_str("::");
                k = skip_ws(next + 2);
            } else {
                break;
            }
        }
        out.push(RustPath { path, line: line_at[begin], at: begin });
        i = k.max(begin + 1);
    }
    out
}

/// Every `use` declaration in `code` ([`code_only`]'s output), each leaf of its tree as a full
/// path with the name it is bound to, and the line the `use` is on. `self` names its parent.
pub(crate) fn use_leaves(code: &str) -> Vec<(String, String, usize)> {
    let c: Vec<char> = code.chars().collect();
    let word = |k: usize| k < c.len() && (c[k].is_alphanumeric() || c[k] == '_');
    let mut out = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < c.len() {
        if c[i] == '\n' {
            line += 1;
        }
        let is_use = c[i..].starts_with(&['u', 's', 'e'])
            && (i == 0 || !word(i - 1))
            && c.get(i + 3).is_some_and(|n| n.is_whitespace() || *n == ':' || *n == '{');
        if !is_use {
            i += 1;
            continue;
        }
        let mut k = i + 3;
        while k < c.len() && c[k] != ';' {
            k += 1;
        }
        let tree: String = c[i + 3..k.min(c.len())].iter().collect();
        for (path, name) in expand_use(&tight_tree(&tree)) {
            out.push((path, name, line));
        }
        line += c[i..k.min(c.len())].iter().filter(|ch| **ch == '\n').count();
        i = k + 1;
    }
    out
}

/// `code` with every `use` declaration blanked to spaces, newlines kept, so the paths left are
/// the ones the code uses; the declarations are read by [`use_leaves`].
fn without_uses(code: &str) -> String {
    let c: Vec<char> = code.chars().collect();
    let word = |k: usize| k < c.len() && (c[k].is_alphanumeric() || c[k] == '_');
    let mut out: Vec<char> = c.clone();
    let mut i = 0;
    while i < c.len() {
        let is_use = c[i..].starts_with(&['u', 's', 'e'])
            && (i == 0 || !word(i - 1))
            && c.get(i + 3).is_some_and(|n| n.is_whitespace() || *n == ':' || *n == '{');
        if !is_use {
            i += 1;
            continue;
        }
        while i < c.len() && c[i] != ';' {
            if c[i] != '\n' {
                out[i] = ' ';
            }
            i += 1;
        }
    }
    out.into_iter().collect()
}

/// A use tree with its space taken out, but the one around `as`.
fn tight_tree(tree: &str) -> String {
    let words: Vec<&str> = tree.split_whitespace().collect();
    let mut out = String::new();
    for w in words {
        let joins = |c: char| matches!(c, ':' | '{' | '}' | ',');
        if !out.is_empty() && !out.ends_with(joins) && !w.starts_with(joins) {
            out.push(' ');
        }
        out.push_str(w);
    }
    out.trim_start_matches("::").to_string()
}

/// The leaves of a tight use tree, each `(path, bound name)`.
fn expand_use(tree: &str) -> Vec<(String, String)> {
    fn go(prefix: &str, tree: &str, out: &mut Vec<(String, String)>) {
        let mut depth = 0;
        let mut start = 0;
        let bytes: Vec<char> = tree.chars().collect();
        let mut items = Vec::new();
        for (i, ch) in bytes.iter().enumerate() {
            match ch {
                '{' => depth += 1,
                '}' => depth -= 1,
                ',' if depth == 0 => {
                    items.push(bytes[start..i].iter().collect::<String>());
                    start = i + 1;
                }
                _ => {}
            }
        }
        items.push(bytes[start..].iter().collect());
        let join = |a: &str, b: &str| match (a.is_empty(), b.is_empty()) {
            (true, _) => b.to_string(),
            (_, true) => a.to_string(),
            _ => format!("{a}::{b}"),
        };
        for item in items {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if let Some(open) = item.find('{') {
                let head = item[..open].trim_end_matches("::");
                let inner = item[open + 1..].strip_suffix('}').unwrap_or(&item[open + 1..]);
                go(&join(prefix, head), inner, out);
                continue;
            }
            let (path, alias) = match item.split_once(" as ") {
                Some((p, a)) => (p.trim(), Some(a.trim())),
                None => (item, None),
            };
            let full = if path == "self" { prefix.to_string() } else { join(prefix, path) };
            let name = alias
                .map(str::to_string)
                .unwrap_or_else(|| full.rsplit("::").next().unwrap_or(&full).to_string());
            out.push((full, name));
        }
    }
    let mut out = Vec::new();
    go("", tree, &mut out);
    out
}

/// Each `fn` in `code` with the span of its body.
fn fn_bodies(code: &str) -> Vec<(String, usize, usize)> {
    let c: Vec<char> = code.chars().collect();
    let word = |k: usize| k < c.len() && (c[k].is_alphanumeric() || c[k] == '_');
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < c.len() {
        if !(c[i] == 'f' && c[i + 1] == 'n' && (i == 0 || !word(i - 1)) && c[i + 2].is_whitespace()) {
            i += 1;
            continue;
        }
        let mut k = i + 2;
        while k < c.len() && c[k].is_whitespace() {
            k += 1;
        }
        let s = k;
        while word(k) {
            k += 1;
        }
        let name: String = c[s..k].iter().collect();
        while k < c.len() && c[k] != '{' && c[k] != ';' {
            k += 1;
        }
        if name.is_empty() || k >= c.len() || c[k] == ';' {
            i = k.max(i + 1);
            continue;
        }
        let open = k;
        let mut depth = 0;
        while k < c.len() {
            match c[k] {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        out.push((name, open, k));
        i += 2;
    }
    out
}

/// The name a `use` binds, mapped to the path it names, for every `use` in `code`; a path
/// whose first segment is one of these names is read as the path it stands for.
pub(crate) fn resolver(code: &str) -> impl Fn(&str) -> String {
    let aliases: Vec<(String, String)> = use_leaves(code)
        .into_iter()
        .filter(|(path, name, _)| name != "*" && name != "_" && path != name)
        .map(|(path, name, _)| (name, path))
        .collect();
    move |path: &str| {
        let mut segs: Vec<String> = path.split("::").map(str::to_string).collect();
        for _ in 0..4 {
            match aliases.iter().find(|(name, _)| *name == segs[0]) {
                Some((_, full)) => {
                    let mut new: Vec<String> = full.split("::").map(str::to_string).collect();
                    new.extend(segs.drain(1..));
                    segs = new;
                }
                None => break,
            }
        }
        segs.join("::")
    }
}

/// What in one file of the sandbox's crate refuses Article VIII's linker rule, given whether
/// it is [`APP_LINKER_FILE`]; each as `line N: why`.
///
/// `other_linker` names the one function in this file, if any, whose body may add all of WASI
/// at once ([`OTHER_LINKERS`]); it must be there, exactly once, and do so.
pub(crate) fn linker_findings(src: &str, is_app_linker_file: bool, other_linker: Option<&str>) -> Vec<String> {
    let code = code_only(src);
    let mut out = Vec::new();
    let resolve = resolver(&code);
    // A glob of a WASI path leaves its names unresolvable, so none is allowed.
    for (path, name, line) in use_leaves(&code) {
        let full = resolve(&path);
        let first = full.split("::").next().unwrap_or("");
        if name == "*" && WASI_CRATES.contains(&first) {
            out.push(format!(
                "line {line}: imports `{path}` by a glob. A WASI name used through a glob cannot be \
                 read for what it adds; name each item."
            ));
        }
    }
    let bodies = fn_bodies(&code);
    let in_fn = |at: usize| {
        bodies.iter().filter(|(_, s, e)| *s <= at && at <= *e).min_by_key(|(_, s, e)| e - s).map(|(n, _, _)| n.as_str())
    };
    let mut added: Vec<String> = Vec::new();
    let mut other_linker_adds = 0;
    for p in rust_paths(&without_uses(&code)) {
        let full = resolve(&p.path);
        let segs: Vec<&str> = full.split("::").collect();
        let last = *segs.last().unwrap_or(&"");
        if WHOLE_WASI.contains(&last) {
            if other_linker.is_some() && in_fn(p.at) == other_linker {
                other_linker_adds += 1;
                continue;
            }
            out.push(format!(
                "line {}: calls `{}`, which adds every WASI interface to a linker, sockets among \
                 them. A linker here adds WASI only through `{APP_WASI_FN}`.",
                p.line, p.path
            ));
            continue;
        }
        if segs.contains(&"wasmtime_wasi_http") {
            out.push(format!(
                "line {}: names `{}`. No linker here links WASI HTTP.",
                p.line, p.path
            ));
            continue;
        }
        let adds = last.starts_with("add_to_linker");
        if adds && segs.contains(&"sockets") {
            out.push(format!(
                "line {}: calls `{}`, which links a WASI socket interface. An app gets no socket.",
                p.line, p.path
            ));
            continue;
        }
        let in_wasi_fn = is_app_linker_file && in_fn(p.at) == Some(APP_WASI_FN);
        if in_wasi_fn && last == "add_to_linker" {
            if WASI_ADDS.contains(&full.as_str()) {
                added.push(full);
            } else {
                out.push(format!(
                    "line {}: `{APP_WASI_FN}` calls `{}` (`{full}`), which is not one of the \
                     interfaces the check lists for an app's linker. It adds exactly those.",
                    p.line, p.path
                ));
            }
            continue;
        }
        if adds && WASI_CRATES.contains(&segs[0]) && !in_wasi_fn {
            out.push(format!(
                "line {}: `{}` adds a WASI interface (`{full}`) to a linker outside \
                 `{APP_WASI_FN}`. An app's WASI comes from that one function, which adds exactly \
                 the interfaces the check lists.",
                p.line,
                in_fn(p.at).unwrap_or("code outside any function")
            ));
        }
    }
    if let Some(name) = other_linker {
        let defined = bodies.iter().filter(|(n, _, _)| n == name).count();
        if defined != 1 || other_linker_adds == 0 {
            out.push(format!(
                "constitution-check is BROKEN: `OTHER_LINKERS` names `fn {name}` here, and it is \
                 defined {defined} times and adds all of WASI {other_linker_adds} times. The \
                 exception is one function that does; repoint it or take it out."
            ));
        }
    }
    if is_app_linker_file {
        let defined = bodies.iter().any(|(n, _, _)| n == APP_WASI_FN);
        let chars: Vec<char> = code.chars().collect();
        let called = rust_paths(&code).iter().filter(|p| p.path == APP_WASI_FN).any(|p| {
            let before: String = chars[p.at.saturating_sub(8)..p.at].iter().collect();
            let after = chars[(p.at + APP_WASI_FN.len()).min(chars.len())..].iter().find(|c| !c.is_whitespace());
            !before.trim_end().ends_with("fn") && in_fn(p.at) != Some(APP_WASI_FN) && after == Some(&'(')
        });
        if !defined || !called {
            out.push(format!(
                "constitution-check is BROKEN: {APP_LINKER_FILE}: expected `fn {APP_WASI_FN}`, \
                 called to build an app's linker (defined: {defined}, called: {called}). What an \
                 app's linker holds is unread — repoint the check."
            ));
        } else {
            for want in WASI_ADDS {
                if !added.iter().any(|a| a == want) {
                    out.push(format!(
                        "constitution-check is BROKEN: {APP_LINKER_FILE}: `{APP_WASI_FN}` no \
                         longer adds `{want}`. Take it out of `WASI_ADDS`, so the list is what \
                         the function adds."
                    ));
                }
            }
        }
    }
    out
}

/// Article VIII: a linker in the sandbox's crate adds WASI only through
/// `add_wasi_without_sockets`, which adds exactly the interfaces [`WASI_ADDS`] lists, and
/// nothing there adds all of WASI at once or imports a WASI path by a glob.
pub(crate) fn the_app_linker_links_no_socket(root: &Path, violations: &mut Vec<String>) {
    let mut files = Vec::new();
    walk(&root.join(SANDBOX_SRC), &mut files);
    let mut saw_app_linker = false;
    for path in files.iter().filter(|p| p.extension().is_some_and(|x| x == "rs")) {
        let rel = rel(root, path);
        let other = OTHER_LINKERS.iter().find(|(f, ..)| *f == rel).map(|(_, function, _)| *function);
        let Some(text) = crate::read_required(root, &rel, violations) else { continue };
        let is_app = rel == APP_LINKER_FILE;
        saw_app_linker |= is_app;
        for why in linker_findings(&text, is_app, other) {
            if why.starts_with("constitution-check is BROKEN") {
                violations.push(format!("{why} ({rel})"));
            } else {
                violations.push(format!("Article VIII: {rel} {why}"));
            }
        }
    }
    if !saw_app_linker {
        violations.push(format!(
            "constitution-check is BROKEN: `{APP_LINKER_FILE}` was not found under `{SANDBOX_SRC}`. \
             What an app's linker holds is unread — repoint the check."
        ));
    }
    for (file, ..) in OTHER_LINKERS {
        if !root.join(file).is_file() {
            violations.push(format!(
                "constitution-check is BROKEN: `OTHER_LINKERS` names `{file}`, which is gone. Take \
                 it out, so the list names only what it leaves unread."
            ));
        }
    }
}

// ── The project's own apps ───────────────────────────────────────────────────

/// The crates a `Cargo.toml` declares as dependencies, by package name and with their line,
/// in every table Cargo reads one from: `[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`, their `target.<cfg>.` and `workspace.` forms, as a key, a dotted
/// key, an inline table or a table of its own, a rename through `package` read. A `tokio`
/// whose features bring its sockets is listed once more, as `tokio/net`.
pub(crate) fn declared_crates(toml: &str) -> Result<Vec<(String, usize)>, String> {
    let doc = toml_read::read(toml)?;
    let kinds = ["dependencies", "dev-dependencies", "build-dependencies"];
    let dep_at = |path: &[String]| -> Option<usize> {
        (0..path.len().saturating_sub(1)).find(|&i| {
            kinds.contains(&path[i].as_str())
                && (i == 0 || (i == 1 && path[0] == "workspace") || (i == 2 && path[0] == "target"))
        })
    };
    // Each dependency by its key path: its package, its line, whether it brings sockets.
    let mut deps: Vec<(Vec<String>, String, usize, bool)> = Vec::new();
    let mut note = |key: &[String], line: usize| -> usize {
        match deps.iter().position(|(k, ..)| k == key) {
            Some(at) => at,
            None => {
                deps.push((key.to_vec(), key[key.len() - 1].clone(), line, false));
                deps.len() - 1
            }
        }
    };
    let mut idx = Vec::new();
    for (path, line) in &doc.tables {
        if let Some(i) = dep_at(path) {
            note(&path[..=i + 1], *line);
        }
    }
    for e in &doc.entries {
        if let Some(i) = dep_at(&e.path) {
            let at = note(&e.path[..=i + 1], e.line);
            idx.push((at, e.path[i + 2..].to_vec(), e.value.clone()));
        }
    }
    for (at, rest, value) in idx {
        match rest.as_slice() {
            [k] if k == "package" => {
                if let Some(p) = toml_read::string(&value) {
                    deps[at].1 = p;
                }
            }
            [k] if k == "features"
                && toml_read::strings(&value).iter().any(|f| TOKIO_NETWORK_FEATURES.contains(&f.as_str())) =>
            {
                deps[at].3 = true;
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (_, package, line, sockets) in deps {
        if package == "tokio" && sockets {
            out.push(("tokio/net".to_string(), line));
        }
        out.push((package, line));
    }
    out.sort_by_key(|(_, line)| *line);
    Ok(out)
}

/// Every package a `Cargo.lock` resolved, with its line.
pub(crate) fn locked_packages(lock: &str) -> Vec<(String, usize)> {
    lock.lines()
        .enumerate()
        .filter_map(|(i, l)| {
            let v = l.trim().strip_prefix("name = ")?;
            Some((v.trim_matches('"').to_string(), i + 1))
        })
        .collect()
}

/// Where Rust source names the network, each as `(line, what)`: every path in its code and
/// every leaf of its `use` trees, comments and literals blanked first, matched against
/// [`NETWORK_PATHS`] as a whole path or a prefix of one; and `wasi:sockets` or `wasi:http` in
/// a literal.
pub(crate) fn network_uses(src: &str) -> Vec<(usize, String)> {
    let code = code_only(src);
    let mut out: Vec<(usize, String)> = Vec::new();
    let hit = |path: &str| {
        NETWORK_PATHS
            .iter()
            .find(|n| path == **n || path.starts_with(&format!("{n}::")))
            .map(|n| n.to_string())
    };
    let mut found: Vec<(usize, String)> = use_leaves(&code)
        .into_iter()
        .filter_map(|(path, _, line)| hit(&path).map(|n| (line, n)))
        .collect();
    let resolve = resolver(&code);
    found.extend(
        rust_paths(&without_uses(&code)).into_iter().filter_map(|p| hit(&resolve(&p.path)).map(|n| (p.line, n))),
    );
    for (line, lit) in crate::host_word_check::string_literals(src) {
        for pkg in NETWORK_PACKAGES {
            if lit.contains(pkg) {
                found.push((line, pkg.to_string()));
            }
        }
    }
    found.sort();
    for f in found {
        if !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

/// Article VIII: no crate under `guest/apps` declares or resolves a network crate, or uses
/// the network in its sources.
pub(crate) fn no_bundled_app_reaches_the_network(root: &Path, violations: &mut Vec<String>) {
    let apps = root.join(BUNDLED_APPS);
    let mut files = Vec::new();
    walk(&apps, &mut files);
    let manifests: Vec<_> = files.iter().filter(|p| p.file_name().is_some_and(|n| n == "Cargo.toml")).collect();
    if manifests.is_empty() {
        violations.push(format!(
            "constitution-check is BROKEN: no `Cargo.toml` under `{BUNDLED_APPS}`. Article VIII's \
             crate rule is passing over nothing — repoint it."
        ));
    }
    for path in &manifests {
        let rel = rel(root, path);
        let Some(text) = crate::read_required(root, &rel, violations) else { continue };
        let declared = match declared_crates(&text) {
            Ok(d) => d,
            Err(why) => {
                violations.push(format!(
                    "constitution-check is BROKEN: cannot read {rel}: {why}. What it depends on \
                     is unread."
                ));
                continue;
            }
        };
        for (name, line) in declared {
            if name == "tokio/net" {
                violations.push(format!(
                    "Article VIII: {rel} line {line}: depends on `tokio` with a feature that \
                     brings its sockets. No app of the project's reaches the network."
                ));
            } else if NETWORK_CRATES.contains(&name.as_str()) {
                violations.push(format!(
                    "Article VIII: {rel} line {line}: depends on `{name}`, a crate whose purpose \
                     is to reach the network. No app of the project's reaches the network."
                ));
            }
        }
        // Each app crate is a workspace of its own, so its resolved graph is beside it.
        let own_workspace = toml_read::read(&text)
            .map(|d| d.tables.iter().any(|(p, _)| p.len() == 1 && p[0] == "workspace"))
            .unwrap_or(false);
        if own_workspace {
            let lock_rel = rel.replace("Cargo.toml", "Cargo.lock");
            if let Some(lock) = crate::read_required(root, &lock_rel, violations) {
                for (name, line) in locked_packages(&lock) {
                    if NETWORK_CRATES.contains(&name.as_str()) {
                        violations.push(format!(
                            "Article VIII: {lock_rel} line {line}: resolves `{name}`, a crate \
                             whose purpose is to reach the network. No app of the project's \
                             reaches the network, by its own dependencies or another's."
                        ));
                    }
                }
            }
        }
    }
    for path in files.iter().filter(|p| p.extension().is_some_and(|x| x == "rs" || x == "wit")) {
        let rel = rel(root, path);
        let Some(text) = crate::read_required(root, &rel, violations) else { continue };
        let found: Vec<(usize, String)> = if rel.ends_with(".wit") {
            text.lines()
                .enumerate()
                .flat_map(|(i, l)| {
                    NETWORK_PACKAGES.iter().filter(|p| l.contains(*p)).map(move |p| (i + 1, p.to_string()))
                })
                .collect()
        } else {
            network_uses(&text)
        };
        for (line, what) in found {
            violations.push(format!(
                "Article VIII: {rel} line {line}: names `{what}`. No app of the project's \
                 reaches the network."
            ));
        }
    }
}

// ── What they ask for ────────────────────────────────────────────────────────

/// The capability keys a manifest declares, each with its line: the flat form's keys as
/// written, and each `[[capabilities]]` entry as `type:<its type>`. `Err` names what cannot be
/// read: a manifest that is not TOML, a capability that is not a key of the flat table or an
/// entry of the array, or an entry with no `type`.
pub(crate) fn declared_capabilities(manifest: &str) -> Result<Vec<(String, usize)>, String> {
    let doc = toml_read::read(manifest)?;
    let mut out = Vec::new();
    let mut typed: Vec<String> = Vec::new();
    for e in doc.entries.iter().filter(|e| e.path[0] == "capabilities") {
        let shape = e.path.get(1).is_some_and(|s| s.starts_with('['));
        match (e.path.len(), shape) {
            (2, false) => out.push((e.path[1].clone(), e.line)),
            (3, true) if e.path[2] == "type" => {
                let ty = toml_read::string(&e.value)
                    .ok_or(format!("line {}: a `[[capabilities]]` type is not a string", e.line))?;
                typed.push(e.path[1].clone());
                out.push((format!("type:{ty}"), e.line));
            }
            (3.., true) => {}
            _ => {
                return Err(format!(
                    "line {}: `{}` is not a capability the manifest's parser reads",
                    e.line,
                    e.path.join(".")
                ))
            }
        }
    }
    for (path, line) in &doc.tables {
        if path[0] != "capabilities" || path.len() == 1 {
            continue;
        }
        if path.len() == 2 && path[1].starts_with('[') {
            if !typed.contains(&path[1]) {
                return Err(format!("line {line}: a `[[capabilities]]` entry has no `type`"));
            }
        } else {
            return Err(format!(
                "line {line}: `[{}]` is not a table the manifest's parser reads",
                path.join(".")
            ));
        }
    }
    Ok(out)
}

/// The capability keys the manifest schema's parser matches on.
pub(crate) fn schema_keys(src: &str) -> Vec<String> {
    src.lines()
        .filter_map(|l| {
            let key = l.trim().strip_suffix("=> {")?.trim().strip_prefix('"')?.strip_suffix('"')?;
            key.contains('.').then(|| key.to_string())
        })
        .collect()
}

/// What in one bundled manifest refuses Article VIII's manifest rule, each as `line N: why`;
/// `Err` when its capabilities cannot be read.
pub(crate) fn manifest_findings(manifest: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (key, line) in declared_capabilities(manifest)? {
        let links = match key.strip_prefix("type:") {
            Some(ty) => match SHAPE_TYPES.iter().find(|(t, _)| *t == ty) {
                Some((_, iface)) => Some(*iface),
                None => {
                    out.push(format!(
                        "line {line}: declares a `[[capabilities]]` entry of type `{ty}`, which \
                         constitution-check does not know to link anything the app world offers."
                    ));
                    continue;
                }
            },
            None => match MANIFEST_KEYS.iter().find(|(k, _)| *k == key) {
                Some((_, links)) => *links,
                None => {
                    out.push(format!(
                        "line {line}: declares `{key}`, which links no interface constitution-check \
                         knows; a bundled app asks only for what `world app` offers."
                    ));
                    continue;
                }
            },
        };
        if let Some(iface) = links {
            if !APP_IMPORTS.contains(&iface) {
                out.push(format!(
                    "line {line}: declares `{key}`, which links `{iface}`, an interface `world \
                     app` does not import. An app of the project's asks only for what every app \
                     may be given, and none of that is the network."
                ));
            }
        }
    }
    Ok(out)
}

/// Article VIII: every capability a bundled app declares links an app-world interface or
/// none.
pub(crate) fn every_bundled_app_asks_only_for_the_world(root: &Path, violations: &mut Vec<String>) {
    // The schema's keys and the classification here are one set, or a key is unclassified.
    if let Some(src) = crate::read_required(root, MANIFEST_SCHEMA, violations) {
        let keys = schema_keys(&src);
        if keys.is_empty() {
            violations.push(format!(
                "constitution-check is BROKEN: {MANIFEST_SCHEMA}: found no capability key the \
                 manifest parser matches on. Article VIII's manifest rule is unverified — \
                 repoint it."
            ));
        }
        for key in &keys {
            if !MANIFEST_KEYS.iter().any(|(k, _)| k == key) {
                violations.push(format!(
                    "constitution-check is BROKEN: {MANIFEST_SCHEMA} parses the capability `{key}`, \
                     and constitution-check does not say what it links. Classify it in \
                     `MANIFEST_KEYS`."
                ));
            }
        }
        for (key, _) in MANIFEST_KEYS {
            if !keys.iter().any(|k| k == key) {
                violations.push(format!(
                    "constitution-check is BROKEN: `MANIFEST_KEYS` classifies `{key}`, and \
                     {MANIFEST_SCHEMA} no longer parses it. Take it out."
                ));
            }
        }
    }

    let Ok(entries) = std::fs::read_dir(root.join(BUNDLED_APPS)) else {
        violations.push(format!(
            "constitution-check is BROKEN: cannot read `{BUNDLED_APPS}`. Article VIII's manifest \
             rule is unverified."
        ));
        return;
    };
    let mut read = 0;
    let mut dirs: Vec<_> = entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    for dir in dirs {
        let rel = format!("{}/manifest.toml", rel(root, &dir));
        let Some(text) = crate::read_required(root, &rel, violations) else { continue };
        read += 1;
        match manifest_findings(&text) {
            Ok(found) => {
                for why in found {
                    violations.push(format!("Article VIII: {rel} {why}"));
                }
            }
            Err(why) => violations.push(format!(
                "constitution-check is BROKEN: cannot read the capabilities of {rel}: {why}. What \
                 it asks for is unread, which is not a pass."
            )),
        }
    }
    if read == 0 {
        violations.push(format!(
            "constitution-check is BROKEN: no app under `{BUNDLED_APPS}`. Article VIII's manifest \
             rule is passing over nothing — repoint it."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    /// A contract shaped like the real one: the two worlds with their pinned imports.
    fn contract(extra_app: &str, extra_iface: &str) -> String {
        let mut s = String::from("package kotton:app;\n\n");
        for name in APP_IMPORTS.iter().chain(OCCUPANT_IMPORTS) {
            s.push_str(&format!("/// {name}, with a {{brace}} in its doc.\ninterface {name} {{\n  f: func();\n"));
            if *name == "surface" {
                s.push_str(extra_iface);
            }
            s.push_str("}\n\n");
        }
        s.push_str("interface external-net {\n  request: func();\n}\n\n");
        s.push_str("world app {\n");
        for name in APP_IMPORTS {
            s.push_str(&format!("  import {name};\n"));
        }
        s.push_str("  use surface.{f};\n");
        s.push_str(extra_app);
        s.push_str("  export on-launch: func() -> result<_, string>;\n}\n\n");
        s.push_str("world occupant {\n  include app;\n");
        for name in OCCUPANT_IMPORTS {
            s.push_str(&format!("  import {name};\n"));
        }
        s.push_str("}\n\nworld fetcher {\n  import external-net;\n}\n");
        s
    }

    #[test]
    fn the_contract_as_it_stands_has_no_finding() {
        assert_eq!(contract_findings(&contract("", "")), Vec::<String>::new());
    }

    #[test]
    fn a_world_level_statement_is_read_with_its_line_and_whole() {
        let blocks = wit_blocks("world app {\n  import wasi:http/outgoing-handler@0.2.0;\n  use wasi:sockets/network@0.2.0.{ip};\n  @unstable(feature = x) import f: func();\n}\n");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].imports, [("wasi:http/outgoing-handler@0.2.0".to_string(), 2), ("f: func()".to_string(), 4)]);
        assert_eq!(blocks[0].uses, [("wasi:sockets/network@0.2.0".to_string(), 3)]);
    }

    #[test]
    fn a_network_import_on_the_app_world_is_refused_naming_its_line() {
        let text = contract("  import wasi:http/outgoing-handler@0.2.0;\n", "");
        let v = contract_findings(&text);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("`world app` imports `wasi:http/outgoing-handler@0.2.0`"), "{}", v[0]);
    }

    #[test]
    fn the_fetchers_interface_reached_through_a_use_is_refused() {
        let v = contract_findings(&contract("", "  use external-net.{request};\n"));
        assert!(v.iter().any(|m| m.contains("`interface surface` uses `external-net`")), "{v:#?}");
        let v = contract_findings(&contract("  use wasi:sockets/network.{ip};\n", ""));
        assert!(v.iter().any(|m| m.contains("`world app` uses `wasi:sockets/network`")), "{v:#?}");
    }

    #[test]
    fn a_contract_without_its_worlds_is_a_broken_check_not_a_pass() {
        let v = contract_findings("interface schema {}\n");
        assert!(v.iter().any(|m| m.contains("BROKEN")), "{v:#?}");
    }

    #[test]
    fn a_dependency_is_read_in_every_form_cargo_takes() {
        let toml = "[package]\nname = \"x\"\n\n[ dependencies ]\nkotton-app = { path = \"../sdk\" }\n\
                    web = { version = \"0.12\", package = \"reqwest\" }\n\
                    tokio = { version = \"1\", features = [\n  \"rt\",\n  \"net\",\n] }\n\
                    ureq.version = \"2\"\n\n\
                    [target.'cfg(unix)'.dev-dependencies]\nsocket2 = \"0.5\"\n\n\
                    [ dependencies . hyper ]\nversion = \"1\"\n\n[workspace.dependencies]\nmio = \"1\"\n\n[features]\nnet = []\n";
        let got: Vec<(String, usize)> = declared_crates(toml).unwrap();
        let want: Vec<(String, usize)> = [
            ("kotton-app", 5),
            ("reqwest", 6),
            ("tokio/net", 7),
            ("tokio", 7),
            ("ureq", 11),
            ("socket2", 14),
            ("hyper", 16),
            ("mio", 20),
        ]
        .iter()
        .map(|(n, l)| (n.to_string(), *l))
        .collect();
        assert_eq!(got, want);
        let quiet = "[dependencies]\ntokio = { version = \"1\", features = [\"rt\", \"macros\"] }\n";
        assert_eq!(declared_crates(quiet).unwrap(), [("tokio".to_string(), 2)]);
        assert!(declared_crates("[dependencies\nx = 1\n").is_err());
    }

    #[test]
    fn network_paths_are_found_in_every_shape_a_use_or_a_path_takes() {
        let src = "// std::net in a comment\n\
                   use std::{\n    net::TcpStream,\n};\n\
                   use ::std::net::UdpSocket;\n\
                   use std::{io::{Read, Write}, net::TcpStream as T};\n\
                   use tokio :: net;\n\
                   use std::net::{self, Ipv4Addr};\n\
                   fn f() {\n    my_std::net::x();\n    let s = \"std::net\";\n    ::std::net::TcpStream::connect(a);\n    std\n        ::net::UdpSocket::bind(b);\n}\n\
                   wit_bindgen::generate!({ inline: \"world w { import wasi:sockets/tcp; }\" });\n";
        let got = network_uses(src);
        let want: Vec<(usize, String)> = [
            (2, "std::net"),
            (5, "std::net"),
            (6, "std::net"),
            (7, "tokio::net"),
            (8, "std::net"),
            (12, "std::net"),
            (13, "std::net"),
            (16, "wasi:sockets"),
        ]
        .iter()
        .map(|(l, n)| (*l, n.to_string()))
        .collect();
        assert_eq!(got, want);
        assert!(network_uses("use std::{io, fs};\nfn f() { std::io::stdin(); }\n").is_empty());
    }

    #[test]
    fn a_network_path_reached_through_an_alias_is_found() {
        let src = "use std as s;\nuse std::net as n;\nfn f() {\n    s::net::TcpStream::connect(a);\n    n::UdpSocket::bind(b);\n}\n";
        assert_eq!(
            network_uses(src),
            [(2, "std::net".to_string()), (4, "std::net".to_string()), (5, "std::net".to_string())]
        );
    }

    #[test]
    fn a_use_tree_expands_to_its_leaves() {
        let leaves = expand_use(&tight_tree(" std::{ io::{self, Read}, net::TcpStream as T, fs }"));
        assert_eq!(
            leaves,
            [
                ("std::io".to_string(), "io".to_string()),
                ("std::io::Read".to_string(), "Read".to_string()),
                ("std::net::TcpStream".to_string(), "T".to_string()),
                ("std::fs".to_string(), "fs".to_string()),
            ]
        );
    }

    #[test]
    fn a_bundled_app_with_a_network_crate_is_refused_and_one_without_is_not() {
        let clean = [
            ("guest/apps/a/manifest.toml", "[app]\nid = \"sh.x.a\"\n"),
            ("guest/apps/a/logic/Cargo.toml", "[package]\nname = \"a\"\n[dependencies]\nserde = \"1\"\n[workspace]\n"),
            ("guest/apps/a/logic/Cargo.lock", "[[package]]\nname = \"serde\"\n"),
            ("guest/apps/a/logic/src/lib.rs", "pub fn f() {}\n"),
        ];
        let mut v = Vec::new();
        no_bundled_app_reaches_the_network(tree(&clean).path(), &mut v);
        assert_eq!(v, Vec::<String>::new());

        let mut dirty = clean.to_vec();
        dirty[1].1 = "[package]\nname = \"a\"\n[dependencies]\nreqwest.version = \"0.12\"\n[workspace]\n";
        dirty[2].1 = "[[package]]\nname = \"serde\"\n\n[[package]]\nname = \"mio\"\n";
        let mut v = Vec::new();
        no_bundled_app_reaches_the_network(tree(&dirty).path(), &mut v);
        assert_eq!(v.len(), 2, "{v:#?}");
        assert!(v[0].starts_with("Article VIII: guest/apps/a/logic/Cargo.toml line 4: depends on `reqwest`"), "{}", v[0]);
        assert!(v[1].starts_with("Article VIII: guest/apps/a/logic/Cargo.lock line 5: resolves `mio`"), "{}", v[1]);
    }

    #[test]
    fn a_cargo_manifest_that_cannot_be_read_is_a_broken_check() {
        let dir = tree(&[("guest/apps/a/logic/Cargo.toml", "[package\nname = \"a\"\n")]);
        let mut v = Vec::new();
        no_bundled_app_reaches_the_network(dir.path(), &mut v);
        assert!(v.iter().any(|m| m.contains("BROKEN") && m.contains("cannot read guest/apps/a/logic/Cargo.toml")), "{v:#?}");
    }

    #[test]
    fn an_app_crate_whose_lock_is_missing_is_a_broken_check() {
        let dir = tree(&[("guest/apps/a/logic/Cargo.toml", "[package]\nname = \"a\"\n[workspace]\n")]);
        let mut v = Vec::new();
        no_bundled_app_reaches_the_network(dir.path(), &mut v);
        assert!(v.iter().any(|m| m.contains("BROKEN") && m.contains("Cargo.lock")), "{v:#?}");
    }

    #[test]
    fn a_manifest_is_read_in_both_forms_and_any_spacing() {
        let flat = "[app]\nid = \"sh.x\"\nrole = \"shell\"\n\n[ capabilities ]\n# a comment = no\n\"files.read\" = [\"/\"]\n\"schema.read\"  = [\n  \"sh.x.a\",\n]\n'apps.launch' = []\n";
        assert_eq!(
            declared_capabilities(flat).unwrap(),
            [("files.read".to_string(), 7), ("schema.read".to_string(), 8), ("apps.launch".to_string(), 11)]
        );
        let shapes = "[app]\nid = \"sh.x\"\n\n[[ capabilities ]]\nid = \"docs\"\ntype = \"vfs-tree\"\naccess = [\"read\"]\n";
        assert_eq!(declared_capabilities(shapes).unwrap(), [("type:vfs-tree".to_string(), 6)]);
        let inline = "capabilities = { \"network.fetch\" = [] }\n";
        assert_eq!(declared_capabilities(inline).unwrap(), [("network.fetch".to_string(), 1)]);
    }

    #[test]
    fn a_manifest_whose_capabilities_cannot_be_read_is_refused_not_passed() {
        for text in [
            "[capabilities\n\"files.read\" = []\n",
            "[capabilities]\nnetwork.fetch = []\n",
            "[capabilities.network]\nfetch = []\n",
            "[[capabilities]]\nid = \"x\"\n",
            "capabilities = [ { type = \"vfs-tree\" } ]\n",
        ] {
            assert!(declared_capabilities(text).is_err(), "{text:?}");
        }
        let dir = tree(&[
            ("guest/apps/a/manifest.toml", "[app]\nid = \"sh.x\"\n[capabilities\n\"network.fetch\" = []\n"),
            (MANIFEST_SCHEMA, "\"files.read\" => {\n"),
        ]);
        let mut v = Vec::new();
        every_bundled_app_asks_only_for_the_world(dir.path(), &mut v);
        assert!(v.iter().any(|m| m.contains("BROKEN: cannot read the capabilities of guest/apps/a/manifest.toml")), "{v:#?}");
    }

    #[test]
    fn a_manifest_asking_for_the_network_or_an_unknown_capability_is_refused() {
        assert_eq!(
            manifest_findings("[capabilities]\n\"files.read\" = [\"/\"]\n\"events.subscribe\" = [\"*\"]\n\"infer.run\" = []\n").unwrap(),
            Vec::<String>::new()
        );
        let v = manifest_findings("[capabilities]\n\"network.fetch\" = []\n\"system.exec\" = []\n").unwrap();
        assert_eq!(v.len(), 2, "{v:#?}");
        assert!(v[0].starts_with("line 2: declares `network.fetch`, which links `external-net`"), "{}", v[0]);
        assert!(v[1].starts_with("line 3: declares `system.exec`, which links no interface"), "{}", v[1]);
        let v = manifest_findings("[[capabilities]]\nid = \"x\"\ntype = \"socket\"\n").unwrap();
        assert_eq!(v.len(), 1, "{v:#?}");
    }

    #[test]
    fn every_classified_key_links_an_interface_the_contract_defines_or_none() {
        for (key, links) in MANIFEST_KEYS {
            if let Some(iface) = links {
                assert!(
                    APP_IMPORTS.contains(iface) || *iface == "external-net",
                    "`{key}` is classified as linking `{iface}`, which no world here names"
                );
            }
        }
    }

    #[test]
    fn the_schemas_keys_are_read_from_its_match_arms() {
        let src = "match key.as_str() {\n    \"schema.read\" => {\n    \"read\" => CapabilityKind::Read,\n    other => {\n}\n\"files.read\" = [\"/x\"]\n";
        assert_eq!(schema_keys(src), ["schema.read"]);
    }

    /// An app linker's file shaped like the real one: WASI added one interface at a time in the
    /// one function, through the real file's aliases, which `load` calls, and Kotton's own
    /// interfaces beside it.
    fn linker_file(load_body: &str, wasi_extra: &str) -> String {
        let adds: String = WASI_ADDS
            .iter()
            .map(|full| {
                let short = full
                    .replace("wasmtime_wasi_io::bindings::wasi::io", "wasi_io")
                    .replace("wasmtime_wasi::p2::bindings::", "");
                format!("    {short}::<T, X>(l, |t| t)?;\n")
            })
            .collect();
        format!(
            "use wasmtime_wasi::{{WasiCtx, WasiView}};\n\
             async fn load() {{\n    let mut linker: Linker<AppState> = Linker::new(&engine);\n{load_body}\n    kotton::app::surface::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s)?;\n}}\n\
             /// Calls `wasmtime_wasi::p2::add_to_linker_async` in a comment, which is no call.\n\
             fn add_wasi_without_sockets(linker: &mut Linker<AppState>) -> Result<(), E> {{\n\
                 use wasmtime_wasi::cli::{{WasiCli, WasiCliView as _}};\n\
                 use wasmtime_wasi::p2::bindings::{{cli, clocks, filesystem, random}};\n\
                 use wasmtime_wasi_io::bindings::wasi::io as wasi_io;\n\
                 let l = linker;\n{adds}{wasi_extra}\n\
                 Ok(())\n}}\n"
        )
    }

    #[test]
    fn a_glob_of_wasi_and_a_bare_whole_wasi_call_are_refused() {
        let body = "    use wasmtime_wasi::p2::*;\n    add_to_linker_async(&mut linker)?;";
        let v = linker_findings(&linker_file(body, ""), true, None);
        assert!(v.iter().any(|m| m.starts_with("line 4: imports `wasmtime_wasi::p2::*` by a glob")), "{v:#?}");
        assert!(v.iter().any(|m| m.starts_with("line 5: calls `add_to_linker_async`")), "{v:#?}");
        let v = linker_findings("use wasmtime_wasi::p2 as w;\nuse w::*;\n", false, None);
        assert_eq!(v.len(), 1, "a glob through an alias of a WASI path: {v:#?}");
    }

    #[test]
    fn only_the_named_function_of_another_linker_may_add_all_of_wasi() {
        let src = "impl FetcherExtension {\n    pub async fn load() {\n        wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;\n        Fetcher::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s)?;\n    }\n}\n";
        assert_eq!(linker_findings(src, false, Some("load")), Vec::<String>::new());
        let more = format!("{src}pub(crate) fn link_all(l: &mut L) {{\n    wasmtime_wasi::p2::add_to_linker_async(l)?;\n}}\n");
        let v = linker_findings(&more, false, Some("load"));
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].starts_with("line 8: calls `wasmtime_wasi::p2::add_to_linker_async`"), "{}", v[0]);
        let v = linker_findings(src, false, Some("build"));
        assert!(v.iter().any(|m| m.contains("BROKEN") && m.contains("defined 0 times")), "{v:#?}");
        assert_eq!(linker_findings(src, false, None).len(), 1, "with no exception the call is refused");
    }

    /// With no other linker named, the fetcher's file is read as the rest of the crate is: its
    /// linker built through the one function passes, and all of WASI added there is refused at
    /// its line, with no exception left to report as broken.
    #[test]
    fn the_fetchers_linker_is_held_to_the_one_function_like_any_other() {
        const FETCHER: &str = "core/wasm/src/extension.rs";
        let fetcher = |wasi: &str| {
            format!(
                "impl FetcherExtension {{\n    pub async fn load() {{\n        {wasi}(&mut linker)?;\n        \
                 Fetcher::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s)?;\n    }}\n}}\n"
            )
        };
        let sandbox = linker_file("    add_wasi_without_sockets(&mut linker)?;", "");
        assert!(OTHER_LINKERS.iter().all(|(f, ..)| *f != FETCHER), "the fetcher's linker is named as an exception");

        let shared = fetcher("crate::sandbox::add_wasi_without_sockets");
        let dir = tree(&[(APP_LINKER_FILE, &sandbox), (FETCHER, &shared)]);
        let mut v = Vec::new();
        the_app_linker_links_no_socket(dir.path(), &mut v);
        assert_eq!(v, Vec::<String>::new());

        let whole = fetcher("wasmtime_wasi::p2::add_to_linker_async");
        let dir = tree(&[(APP_LINKER_FILE, &sandbox), (FETCHER, &whole)]);
        let mut v = Vec::new();
        the_app_linker_links_no_socket(dir.path(), &mut v);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].starts_with(
                "Article VIII: core/wasm/src/extension.rs line 3: calls `wasmtime_wasi::p2::add_to_linker_async`"
            ),
            "{}",
            v[0]
        );
    }

    #[test]
    fn a_whole_world_binding_in_the_one_function_is_refused() {
        let extra = "    wasmtime_wasi::p2::bindings::Command::add_to_linker::<T, _>(l, |t| t)?;\n";
        let v = linker_findings(&linker_file("    add_wasi_without_sockets(&mut linker)?;", extra), true, None);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("calls `wasmtime_wasi::p2::bindings::Command::add_to_linker`"), "{}", v[0]);
        assert!(v[0].contains("not one of the interfaces the check lists"), "{}", v[0]);
    }

    #[test]
    fn a_listed_interface_the_function_no_longer_adds_is_a_broken_check() {
        let src = linker_file("    add_wasi_without_sockets(&mut linker)?;", "")
            .replace("    cli::stdin::add_to_linker::<T, X>(l, |t| t)?;\n", "");
        let v = linker_findings(&src, true, None);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("BROKEN") && v[0].contains("cli::stdin::add_to_linker"), "{}", v[0]);
    }

    #[test]
    fn the_app_linker_as_it_stands_has_no_finding() {
        let src = linker_file("    add_wasi_without_sockets(&mut linker)?;", "");
        assert_eq!(linker_findings(&src, true, None), Vec::<String>::new());
    }

    #[test]
    fn all_of_wasi_added_to_an_app_linker_is_refused() {
        let src = linker_file("    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;", "");
        let v = linker_findings(&src, true, None);
        assert!(v.iter().any(|m| m.starts_with("line 4: calls `wasmtime_wasi::p2::add_to_linker_async`")), "{v:#?}");
        assert!(v.iter().any(|m| m.contains("BROKEN") && m.contains("called: false")), "{v:#?}");
        let v = linker_findings("use wasmtime_wasi::p2;\nfn f() { p2::add_to_linker_sync(&mut l); }\n", false, None);
        assert_eq!(v.len(), 1, "{v:#?}");
    }

    #[test]
    fn a_socket_or_http_interface_added_in_the_one_function_is_refused() {
        let extra = "use wasmtime_wasi::p2::bindings::sockets;\nsockets::tcp::add_to_linker::<T, WasiSockets>(l, T::sockets)?;\n";
        let v = linker_findings(&linker_file("    add_wasi_without_sockets(&mut linker)?;", extra), true, None);
        assert!(v.iter().any(|m| m.contains("`sockets::tcp::add_to_linker`, which links a WASI socket interface")), "{v:#?}");
        let extra = "wasmtime_wasi_http::add_only_http_to_linker_async(l)?;\n";
        let v = linker_findings(&linker_file("    add_wasi_without_sockets(&mut linker)?;", extra), true, None);
        assert!(v.iter().any(|m| m.contains("names `wasmtime_wasi_http::add_only_http_to_linker_async`")), "{v:#?}");
    }

    #[test]
    fn a_wasi_interface_added_outside_the_one_function_is_refused() {
        let body = "    add_wasi_without_sockets(&mut linker)?;\n    wasmtime_wasi::p2::bindings::cli::stdin::add_to_linker::<T, WasiCli>(&mut linker, T::cli)?;";
        let v = linker_findings(&linker_file(body, ""), true, None);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("`load` adds a WASI interface"), "{}", v[0]);
    }

    #[test]
    fn an_app_linker_file_without_the_one_function_is_a_broken_check() {
        let v = linker_findings("fn load() { kotton::app::surface::add_to_linker(&mut l)?; }\n", true, None);
        assert!(v.iter().any(|m| m.contains("BROKEN") && m.contains("defined: false")), "{v:#?}");
    }

    #[test]
    fn rust_paths_are_read_across_space_and_from_a_leading_root() {
        let got: Vec<(String, usize)> = rust_paths("let a = ::std :: net::X;\nfoo::<T>::bar(); b.c\n    ::d();\n")
            .into_iter()
            .map(|p| (p.path, p.line))
            .collect();
        assert_eq!(
            got,
            [
                ("let".to_string(), 1),
                ("a".to_string(), 1),
                ("std::net::X".to_string(), 1),
                ("foo".to_string(), 2),
                ("T".to_string(), 2),
                ("bar".to_string(), 2),
                ("b".to_string(), 2),
                ("c::d".to_string(), 2),
            ]
        );
    }

    /// The rules hold on the tree as it is: the gate is green before anything is planted.
    #[test]
    fn the_real_tree_keeps_every_app_in_the_one_sandbox() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut v = Vec::new();
        the_app_linker_links_no_socket(root, &mut v);
        the_contract_offers_no_network(root, &mut v);
        no_bundled_app_reaches_the_network(root, &mut v);
        every_bundled_app_asks_only_for_the_world(root, &mut v);
        assert_eq!(v, Vec::<String>::new());
    }
}
