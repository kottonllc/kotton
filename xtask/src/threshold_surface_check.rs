// SPDX-License-Identifier: AGPL-3.0-or-later
//! `threshold-surface-check`: no public item of `kotton-crypto` names a crate of the threshold
//! library.
//!
//! The threshold library is a dependency of `kotton-crypto` alone (`ed25519-check` holds that
//! no other crate links it), and the crate's surface over it is the tree's own types: hex
//! strings in, hex strings and `kotton_crypto::ed25519::VerifyingKey` out, `FrostError` for a
//! failure. A public item that named one of the library's types would hand it to every
//! dependent all the same, without the dependent linking anything. This check reads the crate's
//! modules as rustc finds them and refuses any such item.
//!
//! ## What counts
//!
//! - **The library** is what `ed25519-check` reads it to be, through the same function
//!   (`ed25519_check::threshold_library`): `frost-core` and every package a lockfile read
//!   records as depending on a package of the library, a path or `[patch]` copy included.
//!   **Its crates** are each such package's name with `-` read as `_`, and the key of every
//!   entry of `kotton-crypto`'s manifest that is such a package, renamed or inherited from the
//!   workspace; and, crate-wide, the alias a crate-root `extern crate … as …` gives one.
//! - **The modules** are the crate root its manifest names (`[lib] path`, or `src/lib.rs`) and
//!   every module it declares, resolved as rustc resolves them: `name.rs` or `name/mod.rs`
//!   beside a file that owns its directory (the root, a `mod.rs`, a file a `#[path]` brought
//!   in), under a directory named for the file otherwise; and a `#[path]` wherever a module is
//!   declared, inline modules included, relative to the declaring file's directory or, inside
//!   an inline module, to that module's directory. A declared file that cannot be read or
//!   parsed, both candidates existing, a module declared by a `#[cfg_attr]`ed `path`, and a
//!   module file declared inside a body are refused, not skipped. A module under
//!   `#[cfg(test)]` is not read.
//! - **A name of the library** is a path that resolves to one of its crates, as rustc resolves
//!   names: from a crate (`::frost_core`, or bare), from a name the module binds to the library
//!   (a `use`, renamed or not, `self` in a group, an `extern crate … as …`, a type alias whose
//!   type names the library, or a glob of a module that binds one), or through `self::`,
//!   `super::` and `crate::` to a module and on to such a name there, private or not. So a
//!   child file that names its parent's private `use frost_ed25519 as frost;` as
//!   `super::frost::Identifier` names the library, and so does a path through a module a glob
//!   brought in. A bare name that any module of the same file binds to the library is read as
//!   the library in that whole file, beside whatever else it names there. A name a block binds
//!   is read inside that block's items.
//! - **Resolution settles.** Bindings are read to a fixed point across every module. Only a
//!   name a scope certainly holds in the type namespace shadows what a glob brings in: a child
//!   module, type alias, struct, union, enum, trait, trait alias or `extern crate` with no
//!   `#[cfg]` or `#[cfg_attr]` on it. A `use` may bind a value or a macro only, beside which
//!   rustc keeps the glob's type, so a name a `use` binds reads as both its own targets and the
//!   glob's; and an item under a `#[cfg]` may not be built, so it shadows nothing. Neither ends
//!   the walk out to the scopes around a body. Nor does anything a body holds: a body is read
//!   as one scope of the items of every block under its item, which rustc scopes each to its
//!   own block, so a body declares nothing and its names join the scopes' around it. A name's
//!   targets only grow from round to round, so the reading reaches the same end whatever order
//!   the modules are read in. A crate whose bindings are still growing after [`ROUNDS`] rounds
//!   is refused, not read.
//! - **A public item** is one written `pub`, in whatever module: a function's signature
//!   (parameters, return, generics and their bounds), a constant's or static's type, a pub
//!   item of an `extern` block, a struct's or union's generics and `pub` fields, every field
//!   of a pub enum and its generics, a pub trait's generics, supertraits and item signatures,
//!   and any field with `#[from]` in any struct or enum (its derived `From` impl is public).
//!   Every trait impl is counted, and an inherent impl's generics, type and `pub` items, wherever
//!   the impl is, a function's body included: an impl has no visibility of its own. A `use`,
//!   type alias or `extern crate` with any visibility but private that names the library, or
//!   that globs a module binding a name to it, is counted too: it would let another module
//!   name the library without saying so. A glob import from the library is refused at any
//!   visibility and in any scope: it binds names this check cannot see.
//! - Bodies are not otherwise counted: a function may use the library inside.
//!
//! Each refusal names the file and line, the item, and the path that names the library.
//!
//! ## What it does not see
//!
//! - Items a macro writes: a `macro_rules!` expansion, an attribute macro's output, and a
//!   derive's impl, whether it writes a `From` (a derive other than `thiserror`'s `#[from]`)
//!   or any other trait. A path inside a macro's arguments is not read either.
//! - A `#[cfg]` is not evaluated: every module but a `#[cfg(test)]` one is read, whatever else
//!   its attributes say, and an item under a `#[cfg]` or `#[cfg_attr]` shadows no name.
//! - A library crate whose `[lib]` names it other than its package's name, unless
//!   `kotton-crypto`'s manifest gives it a key by that name.
//! - Types only inferred: an `impl Trait` return names what it names, and nothing it hides.
//! - An item the parser keeps verbatim: `syn` holds an item it does not model as tokens, and
//!   no path inside it is read.
//!
//! ## Line numbers
//!
//! The lock's `proc-macro2` is built without span locations, so `syn` gives no line. Before
//! parsing, a pass over the text with comments and string contents blanked (the blanking
//! `relay-address-check` uses) writes an attribute holding the line before every item
//! keyword that starts an item, and the check reads it back off the item. A variant's or
//! field's line is the first after its item's that spells its name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use syn::visit::{self, Visit};
use syn::{Attribute, Ident, ImplItem, Item, ItemMod, TraitItem, UseTree, Visibility};

use crate::debug_check::{join, normalise};
use crate::ed25519_check::{threshold_crate_names, threshold_library, THRESHOLD_HOME};
use crate::relay_address_check::blank;

/// The attribute [`mark`] writes before an item: `#[MARK = line]`.
const MARK: &str = "__threshold_surface_line";

/// The words that start an item, before which [`mark`] writes the line.
const STARTS: &[&str] =
    &["pub", "fn", "struct", "enum", "union", "type", "trait", "impl", "use", "extern", "mod", "const", "static", "unsafe", "async"];

/// The most rounds name resolution takes before the crate is refused. A name's targets only
/// grow, and each round reads the modules in the order they are declared, so a crate settles in
/// about as many rounds as its longest chain of imports read against that order, plus one that
/// finds nothing new; the tree's crate settles in a handful.
const ROUNDS: usize = 64;

pub fn run(root: &Path) {
    let read = |path: &str| std::fs::read_to_string(root.join(path)).ok();
    let (report, crates, lists) = match crates_of(root) {
        Ok((crates, lib, lists)) => (check(&lib, &crates, &read), crates, lists),
        Err(e) => {
            eprintln!("threshold-surface-check: {e}");
            std::process::exit(1);
        }
    };
    if let Some(e) = vacuous(lists, &report) {
        eprintln!("threshold-surface-check: {e}");
        std::process::exit(1);
    }
    if report.found.is_empty() {
        println!(
            "threshold-surface-check: OK: {} module(s) of kotton-crypto in {} file(s) read; no public item names \
             a crate of the threshold library ({}), which the crate binds {} name(s) to inside.",
            report.modules,
            report.files,
            crates.iter().cloned().collect::<Vec<_>>().join(", "),
            report.bound
        );
        return;
    }
    for f in &report.found {
        eprintln!("threshold-surface-check: {f}");
    }
    eprintln!(
        "\nNo public item of kotton-crypto names a type of the threshold library: a dependent names the tree's \
         own types only. Convert inside the crate, as provider::frost does, and keep the library's types \
         private."
    );
    std::process::exit(1);
}

/// A clean report that read nothing it guards: the manifest lists the library, yet no module
/// binds a name to it, so the reading has missed where the crate uses it.
fn vacuous(lists: bool, report: &Report) -> Option<String> {
    (lists && report.found.is_empty() && report.bound == 0).then(|| {
        format!(
            "kotton-crypto's manifest lists the threshold library, but none of the {} module(s) read binds a name to \
             it, so the check has not read where the crate uses it",
            report.modules
        )
    })
}

/// Whether the manifest `t` gives the crate's own code a dependency keyed by one of `crates`.
fn lists_library(t: &toml::Table, crates: &BTreeSet<String>) -> bool {
    let keyed = |d: Option<&toml::Value>| {
        d.and_then(|d| d.as_table()).is_some_and(|d| d.keys().any(|k| crates.contains(&k.replace('-', "_"))))
    };
    keyed(t.get("dependencies"))
        || t.get("target").and_then(|t| t.as_table()).is_some_and(|ts| ts.values().any(|v| keyed(v.get("dependencies"))))
}

/// The library's crate names, the crate root of [`THRESHOLD_HOME`] (repo-relative), and whether
/// its manifest lists the library.
fn crates_of(root: &Path) -> Result<(BTreeSet<String>, String, bool), String> {
    let library = threshold_library(root)?.library;
    let read = |p: &str| std::fs::read_to_string(root.join(p)).map_err(|e| format!("{p}: {e}"));
    let home = read(THRESHOLD_HOME)?;
    let crates = threshold_crate_names(&read("Cargo.toml")?, &home, &library)?;
    let dir = THRESHOLD_HOME.strip_suffix("Cargo.toml").unwrap_or(THRESHOLD_HOME).trim_end_matches('/');
    let table = home.parse::<toml::Table>().ok();
    let lib = table
        .as_ref()
        .and_then(|t| t.get("lib")?.get("path")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "src/lib.rs".to_string());
    let lists = table.as_ref().is_some_and(|t| lists_library(t, &crates));
    Ok((crates, normalise(&join(dir, &lib)), lists))
}

/// What one run found.
#[derive(Debug, Default)]
struct Report {
    files: usize,
    modules: usize,
    /// How many names the crate's modules bind to the library.
    bound: usize,
    found: Vec<String>,
}

/// The crate whose root is `lib`, read through `read` (a repo-relative path to its text), held
/// to the rule with `crates` as the library's crate names.
fn check(lib: &str, crates: &BTreeSet<String>, read: &dyn Fn(&str) -> Option<String>) -> Report {
    let mut files = BTreeMap::new();
    let mut found = Vec::new();
    discover(lib, &Dir::owning(lib), read, &mut files, &mut found, &mut Vec::new());
    let Some(root) = files.get(lib) else {
        return Report { found, ..Report::default() };
    };
    let mut c = Crate { files: &files, crates: crates.clone(), modules: Vec::new(), found, file_names: BTreeMap::new() };
    c.build(root.file.items.iter().collect(), lib, "crate".into(), Within::Root, Some(Dir::owning(lib)), &mut vec![lib.to_string()]);
    c.global();
    if let Err(rounds) = c.bind(ROUNDS) {
        c.found.push(format!(
            "{lib}: the imports of the crate rooted here do not settle: its bindings were still growing after {rounds} \
             rounds of name resolution, so its public items cannot be read"
        ));
        return Report { files: files.len(), modules: c.modules.len(), bound: 0, found: c.found };
    }
    for m in 0..c.modules.len() {
        c.exposures(m);
    }
    let bound = c.modules.iter().map(|m| m.bindings.values().filter(|t| t.contains(&Target::Library)).count()).sum();
    Report { files: files.len(), modules: c.modules.len(), bound, found: c.found }
}

// ---------------------------------------------------------------------------------------------
// Files

/// A file read: its parse, with [`mark`]'s attributes, and its text blanked, for lines.
struct Loaded {
    file: syn::File,
    blank: String,
}

/// Where a module's files are found, as rustc keeps it: the directory, and the name a file
/// that does not own its directory puts between (`a.rs` declares `b` at `a/b.rs`).
#[derive(Clone)]
struct Dir {
    dir: String,
    relative: Option<String>,
}

impl Dir {
    /// The directory of a file that owns it: the crate root, a `mod.rs`, a `#[path]` file.
    fn owning(file: &str) -> Dir {
        Dir { dir: file.rsplit_once('/').map_or(String::new(), |(d, _)| d.to_string()), relative: None }
    }

    /// The directory of the inline module `m` declared here.
    fn inline(&self, m: &ItemMod) -> Dir {
        match path_attr(&m.attrs) {
            // Rustc reads an inline module's `#[path]` as its directory.
            Some(p) => Dir { dir: normalise(&join(&self.dir, &p)), relative: None },
            None => Dir { dir: join(&self.base(), &m.ident.to_string()), relative: None },
        }
    }

    fn base(&self) -> String {
        match &self.relative {
            Some(r) => join(&self.dir, r),
            None => self.dir.clone(),
        }
    }

    /// The file `mod name;` names here, and where that file's own modules are; `exists` says
    /// which candidates there are.
    fn child(&self, m: &ItemMod, exists: &dyn Fn(&str) -> bool) -> Result<(String, Dir), String> {
        if let Some(p) = path_attr(&m.attrs) {
            let file = normalise(&join(&self.dir, &p));
            return if exists(&file) {
                let dir = Dir::owning(&file);
                Ok((file, dir))
            } else {
                Err(format!("`#[path = \"{p}\"] mod {};` names {file}, which cannot be read", m.ident))
            };
        }
        let base = self.base();
        let name = m.ident.to_string();
        let flat = normalise(&join(&base, &format!("{name}.rs")));
        let nested = normalise(&join(&base, &format!("{name}/mod.rs")));
        match (exists(&flat), exists(&nested)) {
            (true, false) => Ok((flat, Dir { dir: base, relative: Some(name) })),
            (false, true) => Ok((nested, Dir { dir: normalise(&join(&base, &name)), relative: None })),
            (true, true) => Err(format!("`mod {name};` names both {flat} and {nested}, which rustc refuses")),
            (false, false) => Err(format!("`mod {name};` names {flat} or {nested}, and neither can be read")),
        }
    }
}

/// Read and parse `path` and every module file it declares, into `files`.
fn discover(
    path: &str,
    at: &Dir,
    read: &dyn Fn(&str) -> Option<String>,
    files: &mut BTreeMap<String, Loaded>,
    found: &mut Vec<String>,
    stack: &mut Vec<String>,
) {
    if stack.iter().any(|p| p == path) {
        found.push(format!("{path}: declares itself as its own module, through {}", stack.join(" -> ")));
        return;
    }
    if files.contains_key(path) {
        return;
    }
    let Some(text) = read(path) else {
        found.push(format!("{path}: cannot be read, so the module it holds cannot be checked"));
        return;
    };
    let file = match syn::parse_file(&mark(&text)) {
        Ok(f) => f,
        Err(e) => {
            found.push(format!("{path}: does not parse ({e}), so the module it holds cannot be checked"));
            return;
        }
    };
    stack.push(path.to_string());
    discover_items(path, &file.items, at, read, files, found, stack);
    stack.pop();
    files.insert(path.to_string(), Loaded { file, blank: blank(&text) });
}

fn discover_items(
    path: &str,
    items: &[Item],
    at: &Dir,
    read: &dyn Fn(&str) -> Option<String>,
    files: &mut BTreeMap<String, Loaded>,
    found: &mut Vec<String>,
    stack: &mut Vec<String>,
) {
    for item in items {
        let Item::Mod(m) = item else { continue };
        if is_cfg_test(&m.attrs) {
            continue;
        }
        if cfg_attr_path(&m.attrs) {
            found.push(format!(
                "{path}:{}: `mod {}` takes its path from a `#[cfg_attr]`, which this check does not evaluate",
                line_of(&m.attrs).unwrap_or(0),
                m.ident
            ));
            continue;
        }
        match &m.content {
            Some((_, inner)) => discover_items(path, inner, &at.inline(m), read, files, found, stack),
            None => match at.child(m, &|p| files.contains_key(p) || read(p).is_some()) {
                Ok((file, dir)) => discover(&file, &dir, read, files, found, stack),
                Err(e) => found.push(format!("{path}:{}: {e}", line_of(&m.attrs).unwrap_or(0))),
            },
        }
    }
}

/// `src` with `#[MARK = line]` written before each word of [`STARTS`] that starts an item: after
/// `;`, `{`, `}` or `]`, or at the start, read on the text with comments and strings blanked.
/// `unsafe` and `async` count only before `fn`, `impl`, `trait` or `extern` (`unsafe { .. }` and
/// `async { .. }` are blocks); `const` and `static` not before a block or a closure; `union`
/// only before a name.
fn mark(src: &str) -> String {
    let blanked = blank(src);
    let b = blanked.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let word_at = |i: usize| {
        let mut j = i;
        while j < b.len() && is_id(b[j]) {
            j += 1;
        }
        j
    };
    let next_word = |from: usize| -> (&str, Option<u8>) {
        let mut k = from;
        while k < b.len() && b[k].is_ascii_whitespace() {
            k += 1;
        }
        let e = word_at(k);
        (&blanked[k..e], b.get(k).copied())
    };
    let mut out = String::with_capacity(src.len() + src.len() / 8);
    let (mut last, mut line, mut i) = (0usize, 1usize, 0usize);
    let mut before: Option<u8> = None;
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if is_id(c) {
            let j = word_at(i);
            let word = &blanked[i..j];
            let at_start = matches!(before, None | Some(b';' | b'{' | b'}' | b']'));
            if at_start && STARTS.contains(&word) {
                let (next, first) = next_word(j);
                let starts = match word {
                    "unsafe" | "async" => matches!(next, "fn" | "impl" | "trait" | "extern" | "unsafe"),
                    "const" | "static" => !matches!(first, Some(b'{' | b'|')) && next != "move",
                    "union" => first.is_some_and(|f| f.is_ascii_alphabetic() || f == b'_'),
                    _ => true,
                };
                if starts {
                    out.push_str(&src[last..i]);
                    out.push_str(&format!("#[{MARK} = {line}] "));
                    last = i;
                }
            }
            before = Some(b'a');
            i = j;
            continue;
        }
        before = Some(c);
        i += 1;
    }
    out.push_str(&src[last..]);
    out
}

/// The line [`mark`] wrote on an item's attributes.
fn line_of(attrs: &[Attribute]) -> Option<usize> {
    attrs.iter().find_map(|a| match &a.meta {
        syn::Meta::NameValue(nv) if nv.path.is_ident(MARK) => match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => i.base10_parse().ok(),
            _ => None,
        },
        _ => None,
    })
}

/// The first line from `from` on of `blanked` that spells `word` as a word.
fn word_line(blanked: &str, word: &str, from: usize) -> Option<usize> {
    let is_id = |c: char| c.is_ascii_alphanumeric() || c == '_';
    blanked.lines().enumerate().skip(from.saturating_sub(1)).find_map(|(n, l)| {
        l.match_indices(word)
            .any(|(at, _)| {
                !l[..at].chars().next_back().is_some_and(is_id) && !l[at + word.len()..].chars().next().is_some_and(is_id)
            })
            .then_some(n + 1)
    })
}

fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("cfg") && matches!(&a.meta, syn::Meta::List(l) if l.tokens.to_string() == "test"))
}

/// Whether an item may be compiled out: it carries a `#[cfg]` or a `#[cfg_attr]`, which this
/// check does not evaluate.
fn conditional(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("cfg") || a.path().is_ident("cfg_attr"))
}

fn cfg_attr_path(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg_attr")
            && matches!(&a.meta, syn::Meta::List(l) if l.tokens.clone().into_iter().any(|t| t.to_string() == "path"))
    })
}

fn path_attr(attrs: &[Attribute]) -> Option<String> {
    attrs.iter().find_map(|a| match &a.meta {
        syn::Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
            _ => None,
        },
        _ => None,
    })
}

// ---------------------------------------------------------------------------------------------
// Modules and names

/// What a name or a path resolves to, as far as this check needs: the library, a module of the
/// crate, or anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Library,
    Module(usize),
    Other,
}

/// Every target a name or a path may resolve to: it names the library if any of them is.
type Targets = BTreeSet<Target>;

fn one(t: Target) -> Targets {
    Targets::from([t])
}

/// A scope: a module of the crate, or the items of a body (a function's, a constant's, an
/// impl's or a trait's functions'), which sees its enclosing scope's names.
struct Module<'a> {
    file: String,
    /// `crate::a::b`, or the enclosing module's with the body it is in.
    name: String,
    /// The module `self` names here: this one, or a body's enclosing module.
    home: usize,
    /// The module `super` names from [`Module::home`].
    parent: Option<usize>,
    /// For a body, the scope around it.
    outer: Option<usize>,
    /// It is in a body, so its items are not nameable: only impls and `#[from]` count.
    in_body: bool,
    items: Vec<&'a Item>,
    children: BTreeMap<String, usize>,
    /// The names the scope certainly holds in the type namespace, read off its items: its child
    /// modules, type aliases, structs, unions, enums, traits, trait aliases and `extern crate`s,
    /// each without a `#[cfg]` or `#[cfg_attr]`. These shadow a glob's names, and a name declared
    /// here is not looked up around. A `use` is not among them: it may bind a value or a macro
    /// only, beside which the glob's type stands, so its targets join the glob's. A body declares
    /// nothing, since it holds the items of every block under its item, each scoped by rustc to
    /// its own block.
    declared: BTreeSet<String>,
    bindings: BTreeMap<String, Targets>,
}

/// Where a scope is declared: it is the crate root, a module declared in a scope, or a body
/// of an item of a scope.
#[derive(Clone, Copy)]
enum Within {
    Root,
    Module(usize),
    Body(usize),
}

struct Crate<'a> {
    files: &'a BTreeMap<String, Loaded>,
    /// The library's crate names, and the aliases a crate-root `extern crate` gives them.
    crates: BTreeSet<String>,
    modules: Vec<Module<'a>>,
    found: Vec<String>,
    /// For each file, the names any of its scopes binds to the library.
    file_names: BTreeMap<String, BTreeSet<String>>,
}

/// The items a body holds, its nested bodies' items left to those items.
#[derive(Default)]
struct BodyItems<'a> {
    items: Vec<&'a Item>,
}

impl<'a> Visit<'a> for BodyItems<'a> {
    fn visit_item(&mut self, i: &'a Item) {
        self.items.push(i);
    }
}

fn body_items(item: &Item) -> Vec<&Item> {
    let mut v = BodyItems::default();
    match item {
        Item::Fn(f) => v.visit_block(&f.block),
        Item::Const(c) => v.visit_expr(&c.expr),
        Item::Static(s) => v.visit_expr(&s.expr),
        Item::Impl(i) => {
            for it in &i.items {
                match it {
                    ImplItem::Fn(f) => v.visit_block(&f.block),
                    ImplItem::Const(c) => v.visit_expr(&c.expr),
                    _ => {}
                }
            }
        }
        Item::Trait(t) => {
            for it in &t.items {
                match it {
                    TraitItem::Fn(f) => {
                        if let Some(b) = &f.default {
                            v.visit_block(b);
                        }
                    }
                    TraitItem::Const(c) => {
                        if let Some((_, e)) = &c.default {
                            v.visit_expr(e);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    v.items
}

fn item_attrs(i: &Item) -> &[Attribute] {
    match i {
        Item::Const(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        Item::Fn(x) => &x.attrs,
        Item::ForeignMod(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::Mod(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::TraitAlias(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Union(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        _ => &[],
    }
}

fn item_ident(i: &Item) -> Option<&Ident> {
    match i {
        Item::Const(x) => Some(&x.ident),
        Item::Enum(x) => Some(&x.ident),
        Item::ExternCrate(x) => Some(&x.ident),
        Item::Fn(x) => Some(&x.sig.ident),
        Item::Mod(x) => Some(&x.ident),
        Item::Static(x) => Some(&x.ident),
        Item::Struct(x) => Some(&x.ident),
        Item::Trait(x) => Some(&x.ident),
        Item::Type(x) => Some(&x.ident),
        Item::Union(x) => Some(&x.ident),
        _ => None,
    }
}

impl<'a> Crate<'a> {
    /// A scope for `items`, and every module and body it holds.
    fn build(&mut self, items: Vec<&'a Item>, file: &str, name: String, within: Within, at: Option<Dir>, stack: &mut Vec<String>) -> usize {
        let idx = self.modules.len();
        let (home, parent, outer, in_body) = match within {
            Within::Root => (idx, None, None, false),
            Within::Module(d) => (idx, Some(self.modules[d].home), None, self.modules[d].in_body),
            Within::Body(o) => {
                let h = self.modules[o].home;
                (h, self.modules[h].parent, Some(o), true)
            }
        };
        self.modules.push(Module {
            file: file.to_string(),
            name: name.clone(),
            home,
            parent,
            outer,
            in_body,
            items: items.clone(),
            children: BTreeMap::new(),
            declared: BTreeSet::new(),
            bindings: BTreeMap::new(),
        });
        for item in &items {
            if let Item::Mod(m) = item {
                if is_cfg_test(&m.attrs) || cfg_attr_path(&m.attrs) {
                    continue;
                }
                let child_name = format!("{name}::{}", m.ident);
                let child = match (&m.content, &at) {
                    (Some((_, inner)), _) => {
                        let dir = at.as_ref().map(|d| d.inline(m));
                        self.build(inner.iter().collect(), file, child_name, Within::Module(idx), dir, stack)
                    }
                    (None, Some(d)) => {
                        let files = self.files;
                        let Ok((path, dir)) = d.child(m, &|p| files.contains_key(p)) else { continue };
                        let Some(loaded) = files.get(&path) else { continue };
                        if stack.contains(&path) {
                            continue;
                        }
                        stack.push(path.clone());
                        let c = self.build(loaded.file.items.iter().collect(), &path, child_name, Within::Module(idx), Some(dir), stack);
                        stack.pop();
                        c
                    }
                    (None, None) => {
                        self.found.push(format!(
                            "{file}:{}: `mod {};` declares a module file inside a body ({}), which this check does \
                             not read",
                            line_of(&m.attrs).unwrap_or(0),
                            m.ident,
                            self.modules[idx].name
                        ));
                        continue;
                    }
                };
                self.modules[idx].children.insert(m.ident.to_string(), child);
            }
            let inner = body_items(item);
            if !inner.is_empty() {
                let what = item_ident(item).map_or_else(|| "an impl".to_string(), |i| i.to_string());
                self.build(inner, file, format!("{name}::{{body of {what}}}"), Within::Body(idx), None, stack);
            }
        }
        // A body scope gathers the items of every block under an item into one scope, where
        // rustc scopes each to its own block, so it declares nothing.
        let body = matches!(within, Within::Body(_));
        let mut declared = BTreeSet::new();
        for item in &items {
            if body || conditional(item_attrs(item)) {
                continue;
            }
            let name = match item {
                Item::Mod(m) if self.modules[idx].children.contains_key(&m.ident.to_string()) => &m.ident,
                Item::ExternCrate(e) => e.rename.as_ref().map_or(&e.ident, |(_, a)| a),
                Item::Type(x) => &x.ident,
                Item::Struct(x) => &x.ident,
                Item::Union(x) => &x.ident,
                Item::Enum(x) => &x.ident,
                Item::Trait(x) => &x.ident,
                Item::TraitAlias(x) => &x.ident,
                _ => continue,
            };
            declared.insert(name.to_string());
        }
        declared.remove("_");
        self.modules[idx].declared = declared;
        idx
    }

    /// Add to the library's crates the aliases a crate-root `extern crate` gives them, which
    /// rustc puts in every module's scope.
    fn global(&mut self) {
        let mut more = Vec::new();
        for item in &self.modules[0].items {
            if let Item::ExternCrate(e) = item {
                if let Some((_, alias)) = &e.rename {
                    if self.crates.contains(&e.ident.to_string()) {
                        more.push(alias.to_string());
                    }
                }
            }
        }
        self.crates.extend(more);
    }

    /// What `name` names in scope `m`: its bindings and child module there and, until a scope
    /// that declares the name itself, in the scopes around it as well. A name only a glob or a
    /// `use` brought in, or only an item under a `#[cfg]`, does not end the walk, so an outer
    /// scope's reading of it is kept beside the scope's own.
    fn lookup(&self, m: usize, name: &str) -> Targets {
        let mut out = Targets::new();
        let mut at = Some(m);
        while let Some(i) = at {
            let s = &self.modules[i];
            out.extend(s.bindings.get(name).into_iter().flatten().copied());
            out.extend(s.children.get(name).map(|c| Target::Module(*c)));
            if s.declared.contains(name) {
                break;
            }
            at = s.outer;
        }
        out
    }

    fn first(&self, m: usize, name: &str, leading_colon: bool) -> Targets {
        if leading_colon {
            return one(if self.crates.contains(name) { Target::Library } else { Target::Other });
        }
        let home = self.modules[m].home;
        match name {
            "crate" => one(Target::Module(0)),
            "self" => one(Target::Module(home)),
            "super" => one(self.modules[home].parent.map_or(Target::Other, Target::Module)),
            "Self" => one(Target::Other),
            _ if self.crates.contains(name) => one(Target::Library),
            _ => {
                let mut t = self.lookup(m, name);
                if self.file_names.get(&self.modules[m].file).is_some_and(|n| n.contains(name)) {
                    t.insert(Target::Library);
                }
                if t.is_empty() {
                    t.insert(Target::Other);
                }
                t
            }
        }
    }

    fn step(&self, from: &Targets, name: &str) -> Targets {
        let mut out = Targets::new();
        for t in from {
            match *t {
                Target::Module(x) => match name {
                    "super" => {
                        out.insert(self.modules[x].parent.map_or(Target::Other, Target::Module));
                    }
                    "self" => {
                        out.insert(*t);
                    }
                    _ => {
                        let s = &self.modules[x];
                        let mut here: Targets = s.bindings.get(name).cloned().unwrap_or_default();
                        here.extend(s.children.get(name).map(|c| Target::Module(*c)));
                        if here.is_empty() {
                            here.insert(Target::Other);
                        }
                        out.extend(here);
                    }
                },
                other => {
                    out.insert(other);
                }
            }
        }
        out
    }

    fn resolve(&self, m: usize, path: &syn::Path) -> Targets {
        let mut segs = path.segments.iter().map(|s| s.ident.to_string());
        let Some(head) = segs.next() else { return one(Target::Other) };
        segs.fold(self.first(m, &head, path.leading_colon.is_some()), |t, s| self.step(&t, &s))
    }

    /// The first path `visit` meets, read in scope `m`, that names the library.
    fn names(&self, m: usize, visit: impl FnOnce(&mut Finder<'_, 'a>)) -> Option<String> {
        let mut f = Finder { c: self, m, found: None };
        visit(&mut f);
        f.found
    }

    /// What `tree` binds, read in `m`: (name, targets) for each leaf, and every glob's targets.
    fn use_tree(
        &self,
        m: usize,
        tree: &UseTree,
        leading_colon: bool,
        prefix: Option<(&Targets, &Ident)>,
        out: &mut Vec<(String, Targets)>,
        globs: &mut Targets,
    ) {
        let at = |id: &Ident| match prefix {
            None => self.first(m, &id.to_string(), leading_colon),
            Some((t, _)) => self.step(t, &id.to_string()),
        };
        match tree {
            UseTree::Path(p) => {
                let t = at(&p.ident);
                self.use_tree(m, &p.tree, leading_colon, Some((&t, &p.ident)), out, globs);
            }
            UseTree::Name(n) if n.ident == "self" => {
                if let Some((t, id)) = prefix {
                    out.push((id.to_string(), t.clone()));
                }
            }
            UseTree::Name(n) => out.push((n.ident.to_string(), at(&n.ident))),
            UseTree::Rename(r) if r.ident == "self" => {
                if let Some((t, _)) = prefix {
                    out.push((r.rename.to_string(), t.clone()));
                }
            }
            UseTree::Rename(r) => out.push((r.rename.to_string(), at(&r.ident))),
            UseTree::Glob(_) => match prefix {
                Some((t, _)) => globs.extend(t.iter().copied()),
                None => {
                    globs.insert(Target::Other);
                }
            },
            UseTree::Group(g) => {
                for t in &g.items {
                    self.use_tree(m, t, leading_colon, prefix, out, globs);
                }
            }
        }
    }

    /// Whether module `x` binds any name to the library.
    fn binds_library(&self, x: usize) -> bool {
        self.modules[x].bindings.values().any(|t| t.contains(&Target::Library))
    }

    /// The names scope `m`'s items bind, read with the bindings as they stand. A glob brings in
    /// the globbed module's bindings and child modules, but not a name the scope declares.
    fn bindings_of(&self, m: usize) -> BTreeMap<String, Targets> {
        let declared = &self.modules[m].declared;
        let mut out: BTreeMap<String, Targets> = BTreeMap::new();
        let mut put = |name: &str, t: &Targets, glob: bool| {
            if name == "_" || (glob && declared.contains(name)) {
                return;
            }
            out.entry(name.to_string()).or_default().extend(t.iter().copied());
        };
        for item in &self.modules[m].items {
            match item {
                Item::Use(u) => {
                    let (mut leaves, mut globs) = (Vec::new(), Targets::new());
                    self.use_tree(m, &u.tree, u.leading_colon.is_some(), None, &mut leaves, &mut globs);
                    for (n, t) in &leaves {
                        put(n, t, false);
                    }
                    for g in globs {
                        if let Target::Module(x) = g {
                            let s = &self.modules[x];
                            for (n, t) in &s.bindings {
                                put(n, t, true);
                            }
                            for (n, c) in &s.children {
                                put(n, &one(Target::Module(*c)), true);
                            }
                        }
                    }
                }
                Item::ExternCrate(e) => {
                    let name = e.rename.as_ref().map_or_else(|| e.ident.to_string(), |(_, a)| a.to_string());
                    let t = if e.ident == "self" {
                        Target::Module(0)
                    } else if self.crates.contains(&e.ident.to_string()) {
                        Target::Library
                    } else {
                        Target::Other
                    };
                    put(&name, &one(t), false);
                }
                Item::Type(t) => {
                    let lib = self.names(m, |f| {
                        f.visit_generics(&t.generics);
                        f.visit_type(&t.ty);
                    });
                    put(&t.ident.to_string(), &one(if lib.is_some() { Target::Library } else { Target::Other }), false);
                }
                _ => {}
            }
        }
        out
    }

    /// Every scope's bindings, to a fixed point: a binding may lead to another, in any module.
    /// Each round adds what the scopes' items bind, read with the bindings as they stand, to
    /// what they already bind, and nothing is taken away. That merge is what makes the reading
    /// terminate whether or not each step of it is monotone: the bindings only grow, within a
    /// finite set of scopes, names and targets, so they stop growing. Every step of the reading
    /// does in fact only gain targets as the bindings gain them, so the end is the same whatever
    /// order the scopes are read in. The rounds it took, or `Err(limit)` if the bindings still
    /// grew in the last of `limit` rounds.
    fn bind(&mut self, limit: usize) -> Result<usize, usize> {
        for round in 1..=limit {
            let mut changed = false;
            for m in 0..self.modules.len() {
                for (n, t) in self.bindings_of(m) {
                    let have = self.modules[m].bindings.entry(n).or_default();
                    let before = have.len();
                    have.extend(t);
                    changed |= have.len() != before;
                }
            }
            let mut file_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for s in &self.modules {
                let names = file_names.entry(s.file.clone()).or_default();
                names.extend(s.bindings.iter().filter(|(_, t)| t.contains(&Target::Library)).map(|(n, _)| n.clone()));
            }
            if file_names != self.file_names {
                self.file_names = file_names;
                changed = true;
            }
            if !changed {
                return Ok(round);
            }
        }
        Err(limit)
    }

    /// The line of `item` in scope `m`'s file.
    fn line(&self, m: usize, item: &Item) -> usize {
        line_of(item_attrs(item))
            .or_else(|| {
                let blanked = &self.files.get(&self.modules[m].file)?.blank;
                word_line(blanked, &item_ident(item)?.to_string(), 1)
            })
            .unwrap_or(0)
    }

    /// The line, from `from` on, that spells `word`.
    fn line_after(&self, m: usize, word: &str, from: usize) -> usize {
        self.files.get(&self.modules[m].file).and_then(|l| word_line(&l.blank, word, from)).unwrap_or(from)
    }

    fn say(&mut self, m: usize, line: usize, what: String, named: String) {
        let file = &self.modules[m].file;
        self.found.push(format!("{file}:{line}: {what} names the threshold library (`{named}`)"));
    }

    /// The items of scope `m` that put the library on the crate's surface.
    fn exposures(&mut self, m: usize) {
        let in_body = self.modules[m].in_body;
        let items = self.modules[m].items.clone();
        let mut out: Vec<(usize, String, String)> = Vec::new();
        for item in items {
            let line = self.line(m, item);
            let say = |out: &mut Vec<(usize, String, String)>, what: String, named: Option<String>| {
                if let Some(n) = named {
                    out.push((line, what, n));
                }
            };
            match item {
                Item::Use(u) => {
                    let (mut leaves, mut globs) = (Vec::new(), Targets::new());
                    self.use_tree(m, &u.tree, u.leading_colon.is_some(), None, &mut leaves, &mut globs);
                    let text = quote_tree(&u.tree);
                    if globs.contains(&Target::Library) {
                        out.push((line, format!("`use {text}` imports by glob, so binds names this check cannot see, and"), text.clone()));
                    }
                    if !in_body && !is_private(&u.vis) {
                        if leaves.iter().any(|(_, t)| t.contains(&Target::Library)) {
                            out.push((line, format!("`use {text}`, not private,"), text.clone()));
                        } else if globs.iter().any(|g| matches!(g, Target::Module(x) if self.binds_library(*x))) {
                            out.push((line, format!("`use {text}`, not private, globs a module that binds a name to the library: it"), text));
                        }
                    }
                }
                Item::ExternCrate(e) if !in_body && !is_private(&e.vis) && self.crates.contains(&e.ident.to_string()) => {
                    out.push((line, format!("`extern crate {}`, not private,", e.ident), e.ident.to_string()));
                }
                Item::Type(t) if !in_body && !is_private(&t.vis) => say(
                    &mut out,
                    format!("type {}, not private,", t.ident),
                    self.names(m, |f| {
                        f.visit_generics(&t.generics);
                        f.visit_type(&t.ty);
                    }),
                ),
                Item::Fn(f) if !in_body && is_pub(&f.vis) => {
                    say(&mut out, format!("pub fn {}", f.sig.ident), self.names(m, |v| v.visit_signature(&f.sig)));
                }
                Item::Const(c) if !in_body && is_pub(&c.vis) => {
                    say(&mut out, format!("pub const {}", c.ident), self.names(m, |v| v.visit_type(&c.ty)));
                }
                Item::Static(s) if !in_body && is_pub(&s.vis) => {
                    say(&mut out, format!("pub static {}", s.ident), self.names(m, |v| v.visit_type(&s.ty)));
                }
                Item::ForeignMod(fm) if !in_body => {
                    for fi in &fm.items {
                        let (what, named) = match fi {
                            syn::ForeignItem::Fn(f) if is_pub(&f.vis) => {
                                (format!("pub fn {} of an extern block", f.sig.ident), self.names(m, |v| v.visit_signature(&f.sig)))
                            }
                            syn::ForeignItem::Static(s) if is_pub(&s.vis) => {
                                (format!("pub static {} of an extern block", s.ident), self.names(m, |v| v.visit_type(&s.ty)))
                            }
                            _ => continue,
                        };
                        say(&mut out, what, named);
                    }
                }
                Item::Struct(s) => {
                    let public = !in_body && is_pub(&s.vis);
                    if public {
                        say(&mut out, format!("pub struct {}'s generics", s.ident), self.names(m, |v| v.visit_generics(&s.generics)));
                    }
                    for (n, field) in s.fields.iter().enumerate() {
                        let from = has_from(&field.attrs);
                        if (public && is_pub(&field.vis)) || from {
                            let fname = field.ident.as_ref().map_or_else(|| n.to_string(), |i| i.to_string());
                            if let Some(named) = self.names(m, |v| v.visit_type(&field.ty)) {
                                let at = field.ident.as_ref().map_or(line, |i| self.line_after(m, &i.to_string(), line));
                                let how = if from { "with #[from]" } else { "pub" };
                                out.push((at, format!("struct {}'s field {fname}, {how},", s.ident), named));
                            }
                        }
                    }
                }
                Item::Union(u) if !in_body && is_pub(&u.vis) => {
                    say(&mut out, format!("pub union {}'s generics", u.ident), self.names(m, |v| v.visit_generics(&u.generics)));
                    for field in &u.fields.named {
                        if is_pub(&field.vis) {
                            if let Some(named) = self.names(m, |v| v.visit_type(&field.ty)) {
                                let fname = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                                out.push((self.line_after(m, &fname, line), format!("pub union {}'s field {fname}", u.ident), named));
                            }
                        }
                    }
                }
                Item::Enum(e) => {
                    let public = !in_body && is_pub(&e.vis);
                    for variant in &e.variants {
                        let named = self.names(m, |v| {
                            for field in &variant.fields {
                                if public || has_from(&field.attrs) {
                                    v.visit_type(&field.ty);
                                }
                            }
                        });
                        if let Some(named) = named {
                            let at = self.line_after(m, &variant.ident.to_string(), line);
                            let what = if public { "pub enum" } else { "enum" };
                            out.push((at, format!("{what} {}'s variant {}", e.ident, variant.ident), named));
                        }
                    }
                    if public {
                        say(&mut out, format!("pub enum {}'s generics", e.ident), self.names(m, |v| v.visit_generics(&e.generics)));
                    }
                }
                Item::Trait(t) if !in_body && is_pub(&t.vis) => say(
                    &mut out,
                    format!("pub trait {}", t.ident),
                    self.names(m, |v| {
                        v.visit_generics(&t.generics);
                        for bound in &t.supertraits {
                            v.visit_type_param_bound(bound);
                        }
                        for inner in &t.items {
                            match inner {
                                TraitItem::Fn(f) => v.visit_signature(&f.sig),
                                TraitItem::Type(ty) => {
                                    v.visit_generics(&ty.generics);
                                    for bound in &ty.bounds {
                                        v.visit_type_param_bound(bound);
                                    }
                                    if let Some((_, default)) = &ty.default {
                                        v.visit_type(default);
                                    }
                                }
                                TraitItem::Const(c) => v.visit_type(&c.ty),
                                _ => {}
                            }
                        }
                    }),
                ),
                Item::Impl(i) => {
                    let of_trait = i.trait_.is_some();
                    let public_items = i.items.iter().any(|it| match it {
                        ImplItem::Fn(f) => is_pub(&f.vis),
                        ImplItem::Const(c) => is_pub(&c.vis),
                        ImplItem::Type(t) => is_pub(&t.vis),
                        _ => false,
                    });
                    if of_trait || public_items {
                        let named = self.names(m, |v| {
                            v.visit_generics(&i.generics);
                            v.visit_type(&i.self_ty);
                            if let Some((_, path, _)) = &i.trait_ {
                                v.visit_path(path);
                            }
                            for inner in &i.items {
                                match inner {
                                    ImplItem::Fn(f) if of_trait || is_pub(&f.vis) => v.visit_signature(&f.sig),
                                    ImplItem::Const(c) if of_trait || is_pub(&c.vis) => v.visit_type(&c.ty),
                                    ImplItem::Type(ty) if of_trait || is_pub(&ty.vis) => v.visit_type(&ty.ty),
                                    _ => {}
                                }
                            }
                        });
                        let what = match &i.trait_ {
                            Some((_, p, _)) => format!("impl {} for {}", last(p), type_name(&i.self_ty)),
                            None => format!("impl {} (its pub items)", type_name(&i.self_ty)),
                        };
                        say(&mut out, what, named);
                    }
                }
                _ => {}
            }
        }
        for (line, what, named) in out {
            self.say(m, line, what, named);
        }
    }
}

/// Finds a path that names the library, read in one scope.
struct Finder<'c, 'a> {
    c: &'c Crate<'a>,
    m: usize,
    found: Option<String>,
}

impl<'ast> Visit<'ast> for Finder<'_, '_> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if self.found.is_none() && self.c.resolve(self.m, path).contains(&Target::Library) {
            let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
            let lead = if path.leading_colon.is_some() { "::" } else { "" };
            self.found = Some(format!("{lead}{}", segs.join("::")));
        }
        visit::visit_path(self, path);
    }
}

fn is_pub(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn is_private(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Inherited)
}

fn has_from(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("from"))
}

fn last(p: &syn::Path) -> String {
    p.segments.last().map(|s| s.ident.to_string()).unwrap_or_default()
}

fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => last(&p.path),
        _ => "a type".into(),
    }
}

/// A `use` tree as it is written, for a message.
fn quote_tree(tree: &UseTree) -> String {
    match tree {
        UseTree::Path(p) => format!("{}::{}", p.ident, quote_tree(&p.tree)),
        UseTree::Name(n) => n.ident.to_string(),
        UseTree::Rename(r) => format!("{} as {}", r.ident, r.rename),
        UseTree::Glob(_) => "*".into(),
        UseTree::Group(g) => format!("{{{}}}", g.items.iter().map(quote_tree).collect::<Vec<_>>().join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIB: &str = "src/lib.rs";

    fn crates() -> BTreeSet<String> {
        ["frost_core", "frost_ed25519"].map(str::to_string).into()
    }

    /// The findings over `files`, the first being the crate root.
    fn tree(files: &[(&str, &str)]) -> Vec<String> {
        let map: BTreeMap<String, String> = files.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect();
        check(files[0].0, &crates(), &|p| map.get(p).cloned()).found
    }

    /// The findings over one file, the crate root.
    fn exposed(src: &str) -> Vec<String> {
        tree(&[(LIB, src)])
    }

    // -- A public item, a trait impl, a `#[from]` field or a re-export that names the library is
    // refused; a private item or a body is not.

    #[test]
    fn an_error_variant_carrying_the_library_error_is_refused() {
        let found = exposed(
            "#[derive(Debug, thiserror::Error)]\npub enum FrostError {\n    #[error(\"FROST: {0}\")]\n    \
             Frost(#[from] frost_ed25519::Error),\n    #[error(\"x\")]\n    Serialise(String),\n}\n",
        );
        assert_eq!(
            found,
            ["src/lib.rs:4: pub enum FrostError's variant Frost names the threshold library (`frost_ed25519::Error`)"]
        );
    }

    #[test]
    fn a_name_bound_by_use_or_alias_is_refused_in_a_public_signature() {
        let found = exposed(
            "use frost_ed25519 as frost;\nuse frost::keys::{self, KeyPackage};\ntype Share = frost::round2::SignatureShare;\n\
             pub fn a() -> frost::Identifier { todo!() }\npub fn b(_: &KeyPackage) {}\npub fn c(_: Vec<Share>) {}\n\
             pub fn d() -> keys::PublicKeyPackage { todo!() }\npub fn e() -> ::frost_core::Error<X> { todo!() }\n",
        );
        assert_eq!(
            found,
            [
                "src/lib.rs:4: pub fn a names the threshold library (`frost::Identifier`)",
                "src/lib.rs:5: pub fn b names the threshold library (`KeyPackage`)",
                "src/lib.rs:6: pub fn c names the threshold library (`Share`)",
                "src/lib.rs:7: pub fn d names the threshold library (`keys::PublicKeyPackage`)",
                "src/lib.rs:8: pub fn e names the threshold library (`::frost_core::Error`)",
            ]
        );
    }

    #[test]
    fn a_trait_impl_a_from_field_or_a_re_export_is_refused() {
        let found = exposed(
            "impl From<frost_ed25519::Error> for E { fn from(_: frost_ed25519::Error) -> Self { E } }\n\
             struct Private(#[from] frost_ed25519::Error);\npub(crate) use frost_ed25519::Identifier;\n\
             pub(crate) type Id = frost_ed25519::Identifier;\npub use frost_core;\nuse frost_ed25519::keys::*;\n",
        );
        assert_eq!(found.len(), 6, "{found:#?}");
        assert!(found[0].starts_with("src/lib.rs:1: impl From for E"), "{found:#?}");
        assert!(found[1].starts_with("src/lib.rs:2: struct Private's field 0, with #[from],"), "{found:#?}");
        assert!(found[2].starts_with("src/lib.rs:3: `use frost_ed25519::Identifier`, not private,"), "{found:#?}");
        assert!(found[3].starts_with("src/lib.rs:4: type Id, not private,"), "{found:#?}");
        assert!(found[4].starts_with("src/lib.rs:5: `use frost_core`, not private,"), "{found:#?}");
        assert!(found[5].starts_with("src/lib.rs:6: `use frost_ed25519::keys::*` imports by glob"), "{found:#?}");
    }

    #[test]
    fn a_private_item_or_a_body_is_not_counted() {
        let found = exposed(
            "use frost_ed25519 as frost;\nfn private(_: frost::Identifier) {}\n\
             pub fn body() -> u16 { let _ = frost::Identifier::try_from(1u16); 1 }\n\
             pub struct S { inner: frost::Identifier }\nenum Inner { A(frost::Error) }\n\
             pub(crate) fn crate_only(_: frost::Identifier) {}\n#[cfg(test)]\nmod tests { pub fn t(_: frost::Identifier) {} }\n",
        );
        assert!(found.is_empty(), "{found:#?}");
    }

    /// The rest of what was counted: consts, statics, unions, an enum's generics, a trait, an
    /// inherent impl's items, a non-private `extern crate`, an alias of an alias, a pub item in a
    /// private module, and a struct's generics and pub fields.
    #[test]
    fn every_other_public_item_is_counted() {
        let cases = [
            ("pub const C: frost_ed25519::Identifier = X;\n", "pub const C"),
            ("pub static S: Option<frost_ed25519::Identifier> = None;\n", "pub static S"),
            ("pub union U { pub a: frost_ed25519::Identifier }\n", "pub union U's field a"),
            ("pub union U<T: frost_core::Ciphersuite> { a: u8 }\n", "pub union U's generics"),
            ("extern \"C\" {\n    pub fn f(_: frost_ed25519::Identifier);\n}\n", "pub fn f of an extern block"),
            ("extern \"C\" {\n    pub static S: frost_core::Identifier;\n}\n", "pub static S of an extern block"),
            ("pub enum E<T: frost_ed25519::Ciphersuite> { A(T) }\n", "pub enum E's generics"),
            ("pub trait T: frost_ed25519::Ciphersuite {}\n", "pub trait T"),
            ("pub trait T { fn f(&self) -> frost_ed25519::Identifier; }\n", "pub trait T"),
            ("pub trait T { type A: frost_core::Ciphersuite; }\n", "pub trait T"),
            ("pub trait T { const C: frost_core::Identifier; }\n", "pub trait T"),
            ("struct S;\nimpl S { pub fn f(&self) -> frost_ed25519::Identifier { todo!() } }\n", "impl S (its pub items)"),
            ("pub(crate) extern crate frost_ed25519;\n", "`extern crate frost_ed25519`, not private,"),
            ("extern crate frost_ed25519 as f;\npub fn g(_: f::Identifier) {}\n", "pub fn g"),
            ("type A = frost_ed25519::Identifier;\ntype B = Vec<A>;\npub fn g(_: B) {}\n", "pub fn g"),
            ("mod private {\n    pub fn g(_: frost_ed25519::Identifier) {}\n}\n", "pub fn g"),
            ("pub struct S<T: frost_core::Ciphersuite>(T);\n", "pub struct S's generics"),
            ("pub struct S { pub key: frost_core::Identifier }\n", "struct S's field key, pub,"),
            ("pub fn g<T>(_: T) where T: frost_core::Ciphersuite {}\n", "pub fn g"),
            ("pub fn g() -> impl frost_core::Ciphersuite { todo!() }\n", "pub fn g"),
        ];
        for (src, what) in cases {
            let found = exposed(src);
            assert_eq!(found.len(), 1, "{src}: {found:#?}");
            assert!(found[0].contains(&format!(": {what} names the threshold library")), "{src}: {found:#?}");
        }
    }

    // -- A name of the library reached through another module, a glob, a `#[path]` or a body is
    // refused, and so is a module file that cannot be read.

    #[test]
    fn a_path_through_self_super_or_crate_to_a_private_binding_is_refused() {
        let found = exposed(
            "use frost_ed25519 as frost;\nmod inner {\n    pub fn a() -> super::frost::Identifier { todo!() }\n}\n\
             pub fn b() -> self::frost::Identifier { todo!() }\npub fn c() -> crate::frost::Identifier { todo!() }\n\
             mod deep { mod deeper { pub fn d() -> super::super::frost::Error { todo!() } } }\n",
        );
        assert_eq!(found.len(), 4, "{found:#?}");
        assert!(found[0].starts_with("src/lib.rs:5: pub fn b names the threshold library (`self::frost::Identifier`)"), "{found:#?}");
        assert!(found[1].starts_with("src/lib.rs:6: pub fn c names the threshold library (`crate::frost::Identifier`)"), "{found:#?}");
        assert!(found[2].starts_with("src/lib.rs:3: pub fn a names the threshold library (`super::frost::Identifier`)"), "{found:#?}");
        assert!(found[3].starts_with("src/lib.rs:7: pub fn d names the threshold library (`super::super::frost::Error`)"), "{found:#?}");
    }

    #[test]
    fn a_parent_s_private_use_named_from_a_child_file_is_refused() {
        let found = tree(&[
            (LIB, "mod provider;\n"),
            ("src/provider/mod.rs", "use frost_ed25519 as frost;\nmod frost_impl;\nmod alias;\n"),
            ("src/provider/frost_impl.rs", "use super::frost;\n\npub fn a(_: frost::Identifier) {}\n"),
            ("src/provider/alias.rs", "pub fn b(_: crate::provider::frost::Identifier) {}\n"),
        ]);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found.iter().any(|f| f.starts_with("src/provider/frost_impl.rs:3: pub fn a")), "{found:#?}");
        assert!(found.iter().any(|f| f.starts_with("src/provider/alias.rs:1: pub fn b")), "{found:#?}");
    }

    #[test]
    fn a_root_extern_crate_alias_is_the_library_in_every_module() {
        let found = tree(&[
            (LIB, "extern crate frost_ed25519 as threshold;\nmod a;\n"),
            ("src/a.rs", "pub fn f(_: threshold::Identifier) {}\npub fn g(_: ::threshold::Identifier) {}\n"),
        ]);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found[0].starts_with("src/a.rs:1: pub fn f"), "{found:#?}");
        assert!(found[1].starts_with("src/a.rs:2: pub fn g"), "{found:#?}");
    }

    #[test]
    fn a_path_attribute_is_resolved_as_rustc_resolves_it_wherever_it_is() {
        let body = "pub fn f(_: frost_ed25519::Identifier) {}\n";
        // In a file that owns its directory, beside it.
        let found = tree(&[(LIB, "#[path = \"elsewhere/x.rs\"]\nmod x;\n"), ("src/elsewhere/x.rs", body)]);
        assert_eq!(found, ["src/elsewhere/x.rs:1: pub fn f names the threshold library (`frost_ed25519::Identifier`)"]);
        // In a file that does not, still beside it; and a `#[path]` file owns its directory.
        let found = tree(&[
            (LIB, "mod a;\n"),
            ("src/a.rs", "#[path = \"p/y.rs\"]\nmod y;\n"),
            ("src/p/y.rs", "mod z;\n"),
            ("src/p/z.rs", body),
        ]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("src/p/z.rs:1: pub fn f"), "{found:#?}");
        // Inside an inline module of a file that does not own its directory: under both names.
        let found = tree(&[(LIB, "mod a;\n"), ("src/a.rs", "mod m {\n    #[path = \"q.rs\"]\n    mod q;\n}\n"), ("src/a/m/q.rs", body)]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("src/a/m/q.rs:1: pub fn f"), "{found:#?}");
        // An inline module's own `#[path]` is its directory.
        let found = tree(&[(LIB, "#[path = \"d\"]\nmod m {\n    mod r;\n}\n"), ("src/d/r.rs", body)]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("src/d/r.rs:1: pub fn f"), "{found:#?}");
        // A module of a file that does not own its directory is under its name.
        let found = tree(&[(LIB, "mod a;\n"), ("src/a.rs", "mod b;\n"), ("src/a/b.rs", body)]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].starts_with("src/a/b.rs:1: pub fn f"), "{found:#?}");
    }

    #[test]
    fn a_module_that_cannot_be_read_is_refused_not_skipped() {
        let found = tree(&[(LIB, "mod gone;\n")]);
        assert_eq!(found, ["src/lib.rs:1: `mod gone;` names src/gone.rs or src/gone/mod.rs, and neither can be read"]);
        let found = tree(&[(LIB, "#[path = \"x.rs\"]\nmod gone;\n")]);
        assert!(found[0].contains("names src/x.rs, which cannot be read"), "{found:#?}");
        let found = tree(&[(LIB, "mod two;\n"), ("src/two.rs", ""), ("src/two/mod.rs", "")]);
        assert!(found[0].contains("which rustc refuses"), "{found:#?}");
        let found = tree(&[(LIB, "mod bad;\n"), ("src/bad.rs", "pub fn (\n")]);
        assert!(found[0].starts_with("src/bad.rs: does not parse"), "{found:#?}");
        let found = tree(&[(LIB, "#[cfg_attr(unix, path = \"u.rs\")]\nmod m;\n")]);
        assert!(found[0].contains("takes its path from a `#[cfg_attr]`"), "{found:#?}");
        let found = tree(&[(LIB, "fn f() {\n    #[path = \"x.rs\"]\n    mod m;\n}\n"), ("src/x.rs", "")]);
        assert!(found.iter().any(|f| f.contains("inside a body")), "{found:#?}");
        let found = tree(&[(LIB, "#[path = \"lib.rs\"]\nmod again;\n")]);
        assert!(found[0].contains("declares itself"), "{found:#?}");
    }

    #[test]
    fn a_re_export_through_a_module_or_a_glob_of_one_is_refused() {
        let found = exposed(
            "mod inner {\n    pub(crate) use frost_ed25519::Identifier;\n}\npub use inner::Identifier as Id;\n\
             pub use inner::*;\nmod quiet {\n    use frost_ed25519::Error;\n}\npub fn f(_: quiet::Error) {}\n",
        );
        assert_eq!(found.len(), 4, "{found:#?}");
        assert!(found[0].starts_with("src/lib.rs:4: `use inner::Identifier as Id`, not private,"), "{found:#?}");
        assert!(found[1].starts_with("src/lib.rs:5: `use inner::*`, not private, globs a module"), "{found:#?}");
        assert!(found[2].starts_with("src/lib.rs:9: pub fn f"), "{found:#?}");
        assert!(found[3].starts_with("src/lib.rs:2: `use frost_ed25519::Identifier`, not private,"), "{found:#?}");
    }

    #[test]
    fn a_name_a_glob_of_a_module_brings_in_is_read() {
        let found = tree(&[
            (LIB, "mod provider;\npub use provider::*;\npub fn f(_: crate::frost::frost::Identifier) {}\nmod child;\n"),
            ("src/provider/mod.rs", "pub mod frost;\n"),
            ("src/provider/frost.rs", "use frost_ed25519 as frost;\n"),
            ("src/child.rs", "use super::*;\n\npub fn g(_: frost::frost::Error) {}\n"),
        ]);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found[0].starts_with("src/lib.rs:3: pub fn f"), "{found:#?}");
        assert!(found[1].starts_with("src/child.rs:3: pub fn g"), "{found:#?}");
    }

    #[test]
    fn an_impl_or_a_from_field_inside_a_body_is_refused() {
        let found = exposed(
            "pub struct E;\nfn hidden() {\n    use frost_ed25519 as f;\n    impl From<f::Error> for E {\n        fn from(_: f::Error) -> Self { E }\n    }\n    \
             #[derive(thiserror::Error)]\n    enum Local {\n        A(#[from] f::Error),\n    }\n    pub fn not_nameable(_: f::Error) {}\n}\n\
             const _: () = {\n    impl E {\n        pub fn g(&self) -> frost_core::Identifier { todo!() }\n    }\n};\n",
        );
        assert_eq!(found.len(), 3, "{found:#?}");
        assert!(found[0].starts_with("src/lib.rs:4: impl From for E"), "{found:#?}");
        assert!(found[1].starts_with("src/lib.rs:9: enum Local's variant A"), "{found:#?}");
        assert!(found[2].starts_with("src/lib.rs:14: impl E (its pub items)"), "{found:#?}");
    }

    #[test]
    fn a_glob_from_the_library_is_refused_at_any_visibility_in_any_scope() {
        let found = exposed("fn f() {\n    use frost_ed25519::*;\n}\nmod m {\n    use frost_core::keys::*;\n}\n");
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found[0].starts_with("src/lib.rs:2: `use frost_ed25519::*` imports by glob"), "{found:#?}");
        assert!(found[1].starts_with("src/lib.rs:5: `use frost_core::keys::*` imports by glob"), "{found:#?}");
    }

    #[test]
    fn a_name_of_the_crate_s_own_is_not_the_library() {
        let found = tree(&[
            (
                LIB,
                "mod provider;\npub use provider::*;\npub use provider::frost::FrostError;\n\
                 pub fn f(_: crate::frost::FrostError) {}\npub type R = Result<(), frost::FrostError>;\n",
            ),
            ("src/provider/mod.rs", "pub mod frost;\npub use self::frost::FrostError as E;\n"),
            (
                "src/provider/frost.rs",
                "use frost_ed25519 as frost;\nuse frost_ed25519::Identifier;\npub enum FrostError { Frost(String) }\n\
                 pub fn sign(_: &str) -> Result<String, FrostError> { todo!() }\nfn private(_: Identifier) {}\n",
            ),
        ]);
        assert!(found.is_empty(), "{found:#?}");
    }

    /// A bare name any module of a file binds to the library is the library in the whole file,
    /// so a module of the same file named like it is refused where it is named bare.
    #[test]
    fn a_bare_name_bound_anywhere_in_the_file_is_the_library_there() {
        let found = exposed(
            "pub mod frost {\n    use frost_ed25519 as frost;\n    pub enum FrostError { Frost(String) }\n}\n\
             pub fn f(_: frost::FrostError) {}\npub fn g(_: crate::frost::FrostError) {}\n",
        );
        assert_eq!(found, ["src/lib.rs:5: pub fn f names the threshold library (`frost::FrostError`)"]);
    }

    #[test]
    fn the_marks_hold_the_lines_and_leave_the_parse_as_it_was() {
        let src = "// pub fn not_an_item\nconst S: &str = \"; pub fn\";\nfn f() {\n    unsafe { g() }\n    let _ = async { 1 };\n    \
                   let c = static || 1;\n}\npub(crate) unsafe fn h() {}\nunion U { a: u8 }\nfn k() { union(1); }\n";
        let marked = mark(src);
        assert_eq!(marked.matches(MARK).count(), 5, "{marked}");
        let file = syn::parse_file(&marked).unwrap();
        let lines: Vec<Option<usize>> = file.items.iter().map(|i| line_of(item_attrs(i))).collect();
        assert_eq!(lines, [Some(2), Some(3), Some(8), Some(9), Some(10)]);
    }

    // -- Resolution settles.

    /// The findings over `files`, read on a thread: a reading that does not return within a few
    /// seconds fails the test instead of hanging the suite.
    fn settled(files: &[(&str, &str)]) -> Vec<String> {
        let owned: Vec<(String, String)> = files.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect();
        let (send, recv) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let borrowed: Vec<(&str, &str)> = owned.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
            let _ = send.send(tree(&borrowed));
        });
        recv.recv_timeout(std::time::Duration::from_secs(10)).expect("name resolution returns")
    }

    /// A module's glob of its own child module, which binds a name like the child's to the
    /// library: the child shadows the glob's name, so the glob's path stays the child, and the
    /// glob is refused as globbing a module that binds a name to the library.
    #[test]
    fn a_glob_of_a_child_that_binds_the_child_s_name_settles_and_is_refused() {
        let found = settled(&[
            (LIB, "mod provider;\n"),
            ("src/provider/mod.rs", "pub mod frost;\npub use frost::*;\n"),
            ("src/provider/frost.rs", "use frost_ed25519 as frost;\n"),
        ]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].starts_with("src/provider/mod.rs:2: `use frost::*`, not private, globs a module that binds a name to the library"),
            "{found:#?}"
        );
    }

    /// The same shape with no library in it settles and passes.
    #[test]
    fn a_glob_that_brings_in_its_own_path_s_name_settles_and_passes() {
        let found = settled(&[(LIB, "mod a {\n    pub mod g {\n        pub use std::fmt as a;\n    }\n}\npub use a::g::*;\n")]);
        assert!(found.is_empty(), "{found:#?}");
    }

    /// A glob's name beside a `use` of a fn by that name: the `use` binds the value only, so the
    /// glob's type-namespace name still stands, and a path through it names the library.
    #[test]
    fn a_use_beside_a_glob_does_not_shadow_the_glob_s_name() {
        let found = settled(&[
            (LIB, "mod a;\nmod util;\n"),
            ("src/util.rs", "pub fn frost() {}\n"),
            ("src/a.rs", "use frost_ed25519 as frost;\nmod child;\n"),
            ("src/a/child.rs", "use super::*;\nuse crate::util::frost;\npub fn f(_: frost::Identifier) {}\n"),
        ]);
        assert_eq!(found, ["src/a/child.rs:3: pub fn f names the threshold library (`frost::Identifier`)"]);
    }

    /// A module or a struct under a `#[cfg]` beside a glob may not be built, so it does not
    /// shadow the glob's name.
    #[test]
    fn an_item_under_a_cfg_does_not_shadow_a_glob_s_name() {
        let base = [(LIB, "mod a;\n"), ("src/a.rs", "use frost_ed25519 as frost;\nmod child;\n")];
        let module = settled(
            &[
                &base[..],
                &[
                    ("src/a/child.rs", "use super::*;\n#[cfg(feature = \"x\")]\nmod frost;\npub fn f(_: frost::Identifier) {}\n"),
                    ("src/a/child/frost.rs", "pub struct Identifier;\n"),
                ],
            ]
            .concat(),
        );
        assert_eq!(module, ["src/a/child.rs:4: pub fn f names the threshold library (`frost::Identifier`)"]);
        let structure = settled(
            &[
                &base[..],
                &[("src/a/child.rs", "use super::*;\n#[cfg(feature = \"x\")]\nstruct frost;\npub fn f(_: frost::Identifier) {}\n")],
            ]
            .concat(),
        );
        assert_eq!(structure, ["src/a/child.rs:4: pub fn f names the threshold library (`frost::Identifier`)"]);
    }

    /// A `use` in a body does not end the walk out of it: the body's impl names the library
    /// through the enclosing module's `frost`, which the body's `use` of a fn leaves standing.
    #[test]
    fn a_use_in_a_body_leaves_an_outer_path_to_the_library_standing() {
        let found = settled(&[(
            LIB,
            "mod util {\n    pub fn frost() {}\n}\npub mod frost {\n    pub use frost_ed25519::Identifier;\n}\npub fn h() {\n    \
             use crate::util::frost;\n    pub struct S;\n    impl S {\n        pub fn i(_: frost::Identifier) {}\n    }\n    frost();\n}\n",
        )]);
        assert_eq!(
            found,
            [
                "src/lib.rs:5: `use frost_ed25519::Identifier`, not private, names the threshold library \
                 (`frost_ed25519::Identifier`)",
                "src/lib.rs:10: impl S (its pub items) names the threshold library (`frost::Identifier`)",
            ]
        );
    }

    /// A body is read as one scope of every block under its item, so a struct in one block does
    /// not shadow, for an impl beside the block, the module's name that leads to the library.
    #[test]
    fn a_name_in_one_block_of_a_body_does_not_hide_the_module_s_name_from_another() {
        let found = settled(&[
            (LIB, "mod a;\n"),
            ("src/a.rs", "use frost_ed25519 as frost;\nmod b;\n"),
            (
                "src/a/b.rs",
                "use crate::a as up;\npub struct S;\npub fn h() {\n    { struct up; }\n    \
                 impl S { pub fn i(_: up::frost::Identifier) {} }\n}\n",
            ),
        ]);
        assert_eq!(found, ["src/a/b.rs:5: impl S (its pub items) names the threshold library (`up::frost::Identifier`)"]);
    }

    /// A chain of globs takes a round per link, read in the order the modules are declared; a
    /// bound under that refuses, naming the crate, and the check's bound reads it whole.
    #[test]
    fn resolution_that_does_not_settle_within_its_bound_is_refused() {
        let src = "pub use a::*;\nmod a {\n    pub use super::b::*;\n}\nmod b {\n    pub use frost_ed25519 as k;\n}\n";
        let map: BTreeMap<String, String> = [(LIB.to_string(), src.to_string())].into();
        let read = |p: &str| map.get(p).cloned();
        let mut files = BTreeMap::new();
        discover(LIB, &Dir::owning(LIB), &read, &mut files, &mut Vec::new(), &mut Vec::new());
        let fresh = || {
            let mut c = Crate { files: &files, crates: crates(), modules: Vec::new(), found: Vec::new(), file_names: BTreeMap::new() };
            c.build(files[LIB].file.items.iter().collect(), LIB, "crate".into(), Within::Root, Some(Dir::owning(LIB)), &mut Vec::new());
            c
        };
        assert_eq!(fresh().bind(2), Err(2));
        let mut c = fresh();
        assert_eq!(c.bind(ROUNDS), Ok(4));
        assert!(c.modules[0].bindings.get("k").is_some_and(|t| t.contains(&Target::Library)), "{:?}", c.modules[0].bindings);
        let found = exposed(src);
        assert_eq!(found.len(), 3, "{found:#?}");
    }

    /// A crate whose manifest lists the library but whose modules bind no name to it read
    /// nothing the check guards, and is refused; one that binds a name, or does not list it, is not.
    #[test]
    fn a_reading_that_binds_no_name_to_a_listed_library_is_refused() {
        let report = check(LIB, &crates(), &|p| (p == LIB).then(|| "pub fn f() {}\n".to_string()));
        assert!(report.found.is_empty() && report.bound == 0, "{report:?}");
        assert!(vacuous(true, &report).is_some_and(|e| e.contains("binds a name to it")), "{report:?}");
        assert_eq!(vacuous(false, &report), None);
        let report = check(LIB, &crates(), &|p| (p == LIB).then(|| "use frost_ed25519 as f;\n".to_string()));
        assert_eq!(report.bound, 1, "{report:?}");
        assert_eq!(vacuous(true, &report), None);
        let manifest = |t: &str| t.parse::<toml::Table>().unwrap();
        assert!(lists_library(&manifest("[dependencies]\nfrost-ed25519 = \"2\"\n"), &crates()));
        assert!(lists_library(&manifest("[target.'cfg(unix)'.dependencies]\nfrost-core = \"2\"\n"), &crates()));
        assert!(!lists_library(&manifest("[dev-dependencies]\nfrost-core = \"2\"\n"), &crates()));
    }

    // -- The real tree.

    /// The tree's own crate passes, the walk reaches the module that uses the library, and that
    /// module's names for it are seen: the check reads what it says it reads.
    #[test]
    fn the_tree_s_crate_passes_and_its_names_for_the_library_are_seen() {
        let root = crate::out::root();
        let (crates, lib, lists) = crates_of(&root).unwrap();
        assert!(crates.contains("frost_core") && crates.contains("frost_ed25519"), "{crates:?}");
        assert!(lists, "the crate's manifest lists the library");
        let read = |p: &str| std::fs::read_to_string(root.join(p)).ok();
        let report = check(&lib, &crates, &read);
        assert!(report.found.is_empty(), "{:#?}", report.found);
        assert_eq!(vacuous(lists, &report), None);

        let mut files = BTreeMap::new();
        discover(&lib, &Dir::owning(&lib), &read, &mut files, &mut Vec::new(), &mut Vec::new());
        assert!(files.contains_key("core/crypto/src/provider/frost.rs"), "{:?}", files.keys());
        let mut c = Crate { files: &files, crates, modules: Vec::new(), found: Vec::new(), file_names: BTreeMap::new() };
        c.build(files[&lib].file.items.iter().collect(), &lib, "crate".into(), Within::Root, Some(Dir::owning(&lib)), &mut Vec::new());
        c.global();
        let rounds = c.bind(ROUNDS).expect("the tree's crate settles");
        assert!(rounds <= 8, "the tree's crate took {rounds} rounds");
        let frost = c.modules.iter().find(|m| m.name == "crate::provider::frost").expect("the provider's module");
        for name in ["frost", "Identifier", "KeyPackage"] {
            assert!(frost.bindings.get(name).is_some_and(|t| t.contains(&Target::Library)), "{name}: {:?}", frost.bindings);
        }
    }

    /// Both checks read the library through one function: a path copy of a package built on the
    /// core, which a lockfile records without a `source`, is the library for this check as for
    /// `ed25519-check`, under its package's name and under the key the crate's manifest gives it.
    #[test]
    fn the_library_is_read_as_ed25519_check_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let lock = "version = 4\n\n[[package]]\nname = \"frost-copy\"\nversion = \"2.2.0\"\ndependencies = [\n \"frost-core\",\n]\n\n\
                    [[package]]\nname = \"frost-core\"\nversion = \"2.2.0\"\nsource = \"registry+x\"\n\n\
                    [[package]]\nname = \"frost-ed25519\"\nversion = \"2.2.0\"\nsource = \"registry+x\"\ndependencies = [\n \"frost-core\",\n]\n";
        std::fs::write(dir.path().join("Cargo.lock"), lock).unwrap();
        let library = threshold_library(dir.path()).unwrap().library;
        let root = "[workspace.dependencies]\nfrost-ed25519 = \"2.2\"\n";
        let home = "[package]\nname = \"kotton-crypto\"\n\n[dependencies]\nfrost-ed25519 = { workspace = true }\n\
                    threshold = { package = \"frost-copy\", path = \"../copy\" }\n";
        let names = threshold_crate_names(root, home, &library).unwrap();
        let expected: BTreeSet<String> = ["frost_copy", "frost_core", "frost_ed25519", "threshold"].map(str::to_string).into();
        assert_eq!(names, expected);
        let found = check(LIB, &names, &|p| (p == LIB).then(|| "pub fn f(_: threshold::Key) {}\n".to_string())).found;
        assert_eq!(found, ["src/lib.rs:1: pub fn f names the threshold library (`threshold::Key`)"]);
    }
}
