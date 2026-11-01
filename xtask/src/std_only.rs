// SPDX-License-Identifier: AGPL-3.0-or-later
//! The files xtask compiles from another crate's source, and the test that holds each to
//! naming nothing but `std` (kotton #306).
//!
//! xtask compiles three readers from their owners' source by `#[path]` rather than linking
//! the owner: kotton-wire's reader of a recorded surface (`wire_check::recorded_surface`),
//! `kvaultd`'s reader of its settings file (`release_server::settings`) and the finder of
//! systemd's parser (`release_server::systemds_parser`). A dependency on the owner would
//! build its whole closure into every `cargo xtask`; what lets one source compile in both
//! crates is that it names nothing but `std`.
//!
//! **What held that claim before this file was the build, and only half of it.** A
//! `use crate::…` in a shared file fails xtask's build. A name both crates already link —
//! `serde_json`, which xtask and kotton-wire both depend on — compiles on both sides, and
//! the claim rots silently: the next change to xtask's dependencies, or to the owner's, is
//! what breaks, far from the line that caused it.
//!
//! **Parsed, not scanned.** [`analyze`] parses a file with `syn` and walks the tree, so a
//! path is a path wherever the grammar puts one — after `->`, `=>` or a comparison, in a
//! type, a bound, a pattern, an `impl … for`, a qualified `<T as x::Y>::`, an attribute —
//! and a comment or a string never is. Two character lexers before this one each read some
//! `>` before a `::` as mid-path; the parser has no such guess to make. Each path's root is
//! held: the ident after a leading `::`, or the first segment of a path of two or more
//! segments, and the root of every `use` (each root of a `{…}` group) and `extern crate`.
//!
//! **What a root may be.** `std`, `core`, `alloc`, `super`, `self`, `Self`; a primitive
//! type; a name of the standard prelude (`Vec::new`, `Option::Some`); a lint tool
//! (`clippy::…`); and a name the file itself gives meaning — an item it declares (`mod`,
//! `fn`, `struct`, `enum`, `union`, `type`, `trait`, `const`, `static`, `macro_rules!`), a
//! generic parameter, or a name a `use` from `std`, `core`, `alloc`, `self` or `super` binds
//! (`use std::path::{self, Path}`, `use std::io as sio`). The local names are collected
//! file-wide, not per scope: a file that declares `mod serde_json {}` anywhere may write
//! `serde_json::x` anywhere. That over-admits only a name the file declares itself, which
//! a reader sees in the same file.
//!
//! **`crate` and `$crate` are refused.** Each names whichever crate is compiling the file,
//! which is a different crate on each side; a path through either is a dependency on that
//! crate's layout, the thing `#[path]` sharing exists to avoid.
//!
//! **Macros.** A macro's input is tokens, not a tree. When it parses as comma-separated
//! expressions (`format!`, `assert_eq!`, `vec!`) or, in an attribute, as metas
//! (`derive(serde::Serialize)`), it is walked as those. Otherwise — a `macro_rules!` body,
//! `matches!` — its tokens are read: an ident followed by `::` and not preceded by one, the
//! ident after a `::` that nothing path-like precedes, and `$crate`. A `>` before `::` is
//! read as mid-path only when it closes a `<` that opened generics (`Vec::<u8>::new`,
//! `<T as X>::y`); any other `>` (of `->`, `=>`, a comparison) leaves the `::` leading. In
//! tokens the reading leans to holding: an ambiguous root is reported, not passed.
//!
//! **What a shared file pulls in is the same claim.** [`check`] follows each file a shared
//! file compiles into itself and holds it the same way: an out-of-line `mod x;` with
//! `#[path = "…"]` (resolved as rustc does — from the file's directory, or under an inline
//! `mod a { … }` from `a/`, or from an inline module's own `#[path]`), and `include!("…")`
//! (from the including file's directory). An out-of-line `mod x;` with no `#[path]` is
//! refused: where it loads from depends on where the file sits in the crate compiling it.
//! One whose only `path` is under `cfg_attr` is followed and also refused, since where that
//! cfg is off it loads unpathed.
//!
//! **A test, not a guard in the build.** The build cannot say this: it resolves names
//! against whatever the compiling crate links, and both crates link more than `std`. The
//! check is over the source, before any crate's dependencies are in the picture, so it runs
//! in `cargo test -p xtask` and needs no compile of the owners. `syn` is a dev-dependency of
//! xtask for it; `cargo xtask` builds none of it.
//!
//! **The list cannot miss an include.** [`STD_ONLY`] is the one list; the includes are in
//! `wire_check.rs` and `release_server.rs`, each beside the module that uses it, and
//! `the_list_is_every_include_from_outside_xtask` holds the list to every `#[path]` and
//! `include!` under `xtask/src` that names a file outside `xtask/`, so a fourth one that is
//! not listed fails rather than going unread.
//!
//! **Out of scope: xtask's integration tests.** `xtask/tests/release_server_gate.rs`
//! compiles `infra/relay/tests/common/settings_corpus.rs` by `#[path]`. It is a test
//! target, not the `cargo xtask` binary: it builds with dev-dependencies and only under
//! `cargo test`, so a crate it names reaches no `cargo xtask` run, and that file makes no
//! claim to name only `std`. The scan reads `xtask/src` only, for that reason.

use proc_macro2::{Spacing, TokenStream, TokenTree};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use syn::ext::IdentExt;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

/// A list of identifiers as their names.
macro_rules! idents {
    ($($name:ident),* $(,)?) => { &[$(stringify!($name)),*] };
}

/// Every file xtask compiles from another crate's source, from the repository root. Each
/// names nothing but `std` (see the module doc); `the_list_is_every_include_from_outside_xtask`
/// holds this list to the attributes themselves.
pub(crate) const STD_ONLY: &[&str] = &[
    // `wire_check::recorded_surface`: the one reader of a recorded wire surface.
    "core/wire/src/recorded_surface.rs",
    // `release_server::settings`: `kvaultd`'s reader of `vault.env`.
    "core/kvaultd/src/settings.rs",
    // `release_server::systemds_parser`: where systemd's own settings parser is.
    "infra/relay/tests/common/systemds_parser.rs",
];

/// The roots a path in a shared file may start from: the standard library and the file's
/// own modules.
const ROOTS: &[&str] = &["std", "core", "alloc", "super", "self", "Self"];

/// Primitive types, whose associated items (`u8::MAX`, `str::from_utf8`) name no crate.
const PRIMITIVES: &[&str] = &[
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32",
    "i64", "i128", "isize", "f32", "f64",
];

/// The standard prelude's names that a path can start from without a `use`. Written as
/// identifiers, which is what they are, and stringified: one of them would otherwise be a
/// string literal that `host-word-check` reads as prose.
const PRELUDE: &[&str] = idents!(
    Option, Some, None, Result, Ok, Err, Vec, String, Box, ToString, ToOwned, Clone, Copy,
    Default, Drop, Eq, PartialEq, Ord, PartialOrd, Iterator, IntoIterator, Extend,
    FromIterator, DoubleEndedIterator, ExactSizeIterator, Fn, FnMut, FnOnce, From, Into,
    TryFrom, TryInto, AsRef, AsMut, Send, Sync, Sized, Unpin,
);

/// Tool namespaces of lint and diagnostic attributes (`#[allow(clippy::…)]`): not crates.
const TOOLS: &[&str] = &["clippy", "rustfmt", "rustdoc", "diagnostic"];

/// Keywords that can stand before a leading `::` in tokens (`return ::x::y()`).
const KEYWORDS: &[&str] = &[
    "as", "break", "const", "dyn", "else", "for", "if", "impl", "in", "let", "match", "move",
    "mut", "pub", "ref", "return", "static", "type", "unsafe", "where", "while", "yield",
];

/// What a file compiles into itself, by the 1-based line it is written on.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Include {
    /// A `mod`'s `#[path = "…"]`, resolved against the file's directory as rustc does.
    Path(PathBuf),
    /// `include!("…")`: the file it names, from the file's directory.
    Macro(PathBuf),
    /// An out-of-line `mod name;` that loads unpathed: with no `path`, or (when the second
    /// field is true) with one only under `cfg_attr`.
    Unpathed(String, bool),
    /// A `path` or `include!` whose argument is not a plain string literal.
    Opaque,
}

/// What [`analyze`] finds in one file.
#[derive(Debug, Default)]
pub(crate) struct Analysis {
    /// Every path root outside what the file may name, with its line, in file order.
    pub roots: Vec<(usize, String)>,
    /// Every file the file compiles into itself, and every unpathed `mod`.
    pub includes: Vec<(usize, Include)>,
}

/// Parse `source` and find every root outside `std` and every include, or why it does not
/// parse.
pub(crate) fn analyze(source: &str) -> Result<Analysis, String> {
    let file = syn::parse_file(source).map_err(|e| {
        let at = e.span().start();
        format!("does not parse at {}:{}: {e}", at.line, at.column + 1)
    })?;
    let mut local = Local::default();
    local.visit_file(&file);
    let mut walk = Walk { local: local.names, dirs: Vec::new(), out: Analysis::default() };
    walk.visit_file(&file);
    walk.out.roots.sort();
    walk.out.roots.dedup();
    walk.out.includes.sort_by_key(|(line, _)| *line);
    Ok(walk.out)
}

/// Every finding for `file` and each file it compiles into itself, followed to the end: a
/// path from outside `std`, an unpathed out-of-line `mod`, an include whose argument cannot
/// be read, or a file that cannot be read or parsed. Empty when all of it names nothing but
/// `std`.
pub(crate) fn check(file: &Path) -> Vec<String> {
    let mut findings = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut next = vec![file.to_path_buf()];
    while let Some(file) = next.pop() {
        if seen.contains(&file) {
            continue;
        }
        seen.push(file.clone());
        let shown = file.display();
        let analysis = match std::fs::read_to_string(&file).map_err(|e| e.to_string()).and_then(|t| analyze(&t)) {
            Ok(a) => a,
            Err(e) => {
                findings.push(format!("{shown}: cannot be held: {e}"));
                continue;
            }
        };
        for (line, root) in analysis.roots {
            findings.push(format!("{shown}:{line}: names `{root}`, which is not `std`"));
        }
        let dir = file.parent().unwrap_or(Path::new("."));
        for (line, include) in analysis.includes {
            match include {
                Include::Path(p) | Include::Macro(p) => next.push(dir.join(p)),
                Include::Unpathed(name, cfg_only) => findings.push(format!(
                    "{shown}:{line}: `mod {name};` {}, so where it loads from depends on the \
                     crate compiling this file; give it a `#[path]` or write it inline",
                    if cfg_only { "has a `path` only under `cfg_attr`" } else { "has no `#[path]`" }
                )),
                Include::Opaque => findings.push(format!(
                    "{shown}:{line}: a `path` or `include!` that is not a plain string, so the \
                     file it names cannot be held"
                )),
            }
        }
    }
    findings
}

/// The names the file itself gives meaning, collected before the walk that holds roots.
#[derive(Default)]
struct Local {
    names: BTreeSet<String>,
}

impl Local {
    fn add(&mut self, ident: &syn::Ident) {
        self.names.insert(ident.unraw().to_string());
    }
}

impl<'a> Visit<'a> for Local {
    fn visit_item_mod(&mut self, i: &'a syn::ItemMod) {
        self.add(&i.ident);
        visit::visit_item_mod(self, i);
    }
    fn visit_item_fn(&mut self, i: &'a syn::ItemFn) {
        self.add(&i.sig.ident);
        visit::visit_item_fn(self, i);
    }
    fn visit_item_struct(&mut self, i: &'a syn::ItemStruct) {
        self.add(&i.ident);
        visit::visit_item_struct(self, i);
    }
    fn visit_item_enum(&mut self, i: &'a syn::ItemEnum) {
        self.add(&i.ident);
        visit::visit_item_enum(self, i);
    }
    fn visit_item_union(&mut self, i: &'a syn::ItemUnion) {
        self.add(&i.ident);
        visit::visit_item_union(self, i);
    }
    fn visit_item_type(&mut self, i: &'a syn::ItemType) {
        self.add(&i.ident);
        visit::visit_item_type(self, i);
    }
    fn visit_item_trait(&mut self, i: &'a syn::ItemTrait) {
        self.add(&i.ident);
        visit::visit_item_trait(self, i);
    }
    fn visit_item_const(&mut self, i: &'a syn::ItemConst) {
        self.add(&i.ident);
        visit::visit_item_const(self, i);
    }
    fn visit_item_static(&mut self, i: &'a syn::ItemStatic) {
        self.add(&i.ident);
        visit::visit_item_static(self, i);
    }
    fn visit_item_macro(&mut self, i: &'a syn::ItemMacro) {
        if let Some(ident) = &i.ident {
            self.add(ident);
        }
        visit::visit_item_macro(self, i);
    }
    fn visit_type_param(&mut self, i: &'a syn::TypeParam) {
        self.add(&i.ident);
        visit::visit_type_param(self, i);
    }
    fn visit_const_param(&mut self, i: &'a syn::ConstParam) {
        self.add(&i.ident);
        visit::visit_const_param(self, i);
    }
    fn visit_item_use(&mut self, i: &'a syn::ItemUse) {
        let std_rooted = i.leading_colon.is_none() && use_roots(&i.tree).iter().all(|(_, r)| ROOTS.contains(&r.as_str()))
            || i.leading_colon.is_some()
                && use_roots(&i.tree).iter().all(|(_, r)| matches!(r.as_str(), "std" | "core" | "alloc"));
        if std_rooted {
            bound_names(&i.tree, &mut self.names);
        }
    }
}

/// Each root of a use tree, with its ident's line: `std::a::{b, c}` has `std`;
/// `{std::fs, serde::Serialize}` has both.
fn use_roots(tree: &syn::UseTree) -> Vec<(usize, String)> {
    let at = |i: &syn::Ident| (i.span().start().line, i.unraw().to_string());
    match tree {
        syn::UseTree::Path(p) => vec![at(&p.ident)],
        syn::UseTree::Name(n) => vec![at(&n.ident)],
        syn::UseTree::Rename(r) => vec![at(&r.ident)],
        syn::UseTree::Glob(_) => Vec::new(),
        syn::UseTree::Group(g) => g.items.iter().flat_map(use_roots).collect(),
    }
}

/// Every name a use tree brings into scope: each leaf, a rename's new name, and the module
/// segments along the way (`use std::path::{self, Path}` binds `path` and `Path`).
fn bound_names(tree: &syn::UseTree, out: &mut BTreeSet<String>) {
    match tree {
        syn::UseTree::Path(p) => {
            out.insert(p.ident.unraw().to_string());
            bound_names(&p.tree, out);
        }
        syn::UseTree::Name(n) => {
            out.insert(n.ident.unraw().to_string());
        }
        syn::UseTree::Rename(r) => {
            out.insert(r.rename.unraw().to_string());
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(g) => g.items.iter().for_each(|t| bound_names(t, out)),
    }
}

/// The walk that holds roots and finds includes.
struct Walk {
    local: BTreeSet<String>,
    /// The inline modules the walk is inside, each as the directory segment it adds for an
    /// out-of-line `mod` under it: its own `#[path]`, or its name.
    dirs: Vec<String>,
    out: Analysis,
}

impl Walk {
    fn allowed(&self, root: &str) -> bool {
        ROOTS.contains(&root)
            || PRIMITIVES.contains(&root)
            || PRELUDE.contains(&root)
            || TOOLS.contains(&root)
            || self.local.contains(root)
    }

    fn root(&mut self, ident: &syn::Ident, leading_colon: bool) {
        let name = ident.unraw().to_string();
        let held = if leading_colon { !matches!(name.as_str(), "std" | "core" | "alloc") } else { !self.allowed(&name) };
        if held {
            self.out.roots.push((ident.span().start().line, name));
        }
    }

    /// A path's root, unless `skip_root` (a qualified path whose `<T>::` is its root).
    fn path(&mut self, path: &syn::Path, skip_root: bool) {
        if !skip_root {
            if let Some(first) = path.segments.first() {
                if path.leading_colon.is_some() || path.segments.len() > 1 {
                    self.root(&first.ident, path.leading_colon.is_some());
                }
            }
        }
        for segment in &path.segments {
            self.visit_path_arguments(&segment.arguments);
        }
    }

    fn qualified(&mut self, qself: Option<&syn::QSelf>, path: &syn::Path) {
        if let Some(q) = qself {
            self.visit_qself(q);
        }
        self.path(path, qself.is_some_and(|q| q.position == 0));
    }

    /// Tokens that do not parse as expressions or metas, read for path roots (see the
    /// module doc, "Macros").
    fn tokens(&mut self, stream: TokenStream) {
        let toks: Vec<TokenTree> = stream.into_iter().collect();
        let punct = |i: usize, c: char| matches!(toks.get(i), Some(TokenTree::Punct(p)) if p.as_char() == c);
        let colons = |i: usize| {
            matches!(toks.get(i), Some(TokenTree::Punct(p)) if p.as_char() == ':' && p.spacing() == Spacing::Joint)
                && punct(i + 1, ':')
        };
        let ident = |i: usize| match toks.get(i) {
            Some(TokenTree::Ident(id)) => Some(id.clone()),
            _ => None,
        };
        // `<` that open generics (after `::`, or where no operand stands before them), and
        // whether each `>` closed one.
        let mut open = 0usize;
        let mut closes = vec![false; toks.len()];
        let mut i = 0;
        while i < toks.len() {
            match &toks[i] {
                TokenTree::Group(g) => self.tokens(g.stream()),
                TokenTree::Punct(p) if p.as_char() == '$' => {
                    if let Some(id) = ident(i + 1) {
                        if id == "crate" {
                            self.out.roots.push((id.span().start().line, "$crate".into()));
                        }
                        i += 2;
                        continue;
                    }
                }
                TokenTree::Punct(p) if p.as_char() == '<' => {
                    let operand_before = i > 0
                        && matches!(&toks[i - 1], TokenTree::Ident(id) if !KEYWORDS.contains(&id.to_string().as_str()))
                        || i > 0 && matches!(&toks[i - 1], TokenTree::Literal(_) | TokenTree::Group(_));
                    let after_colons = i >= 2 && colons(i - 2);
                    if after_colons || !operand_before {
                        open += 1;
                    }
                }
                TokenTree::Punct(p) if p.as_char() == '>' => {
                    let arrow = i > 0
                        && matches!(&toks[i - 1], TokenTree::Punct(q) if matches!(q.as_char(), '-' | '=') && q.spacing() == Spacing::Joint);
                    if !arrow && open > 0 {
                        open -= 1;
                        closes[i] = true;
                    }
                }
                _ if colons(i) => {
                    if punct(i + 2, '<') {
                        i += 2;
                        continue; // turbofish: generic arguments, not a segment
                    }
                    let leading = match toks.get(i.wrapping_sub(1)).filter(|_| i > 0) {
                        None => true,
                        Some(TokenTree::Ident(id)) => {
                            let word = id.to_string();
                            if KEYWORDS.contains(&word.as_str()) {
                                true
                            } else {
                                let continues = i >= 3 && colons(i - 3) || i >= 2 && punct(i - 2, '$') || i >= 2 && punct(i - 2, '.');
                                if !continues {
                                    self.token_root(id, false);
                                }
                                false
                            }
                        }
                        Some(TokenTree::Punct(q)) if q.as_char() == '>' => !closes[i - 1],
                        Some(_) => true,
                    };
                    if leading {
                        if let Some(id) = ident(i + 2) {
                            self.token_root(&id, true);
                        }
                    }
                    i += 2;
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn token_root(&mut self, ident: &proc_macro2::Ident, leading_colon: bool) {
        let name = ident.to_string();
        let name = name.strip_prefix("r#").unwrap_or(&name).to_string();
        let held = if leading_colon { !matches!(name.as_str(), "std" | "core" | "alloc") } else { !self.allowed(&name) };
        if held {
            self.out.roots.push((ident.span().start().line, name));
        }
    }

    /// A string-literal argument (`path = "…"`, `include!("…")`), or `Opaque`.
    fn literal(expr: &syn::Expr) -> Option<String> {
        match expr {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
            _ => None,
        }
    }
}

/// A `path` a `mod` was given: none, a plain string, or (`Err`) something else.
type Given = Option<Result<String, ()>>;

/// A `mod`'s `path`: the one written plain, and the one under a `cfg_attr`; each `Err`
/// when not a plain string.
fn mod_paths(attrs: &[syn::Attribute]) -> (Given, Given) {
    let (mut plain, mut cfg) = (None, None);
    for attr in attrs {
        if attr.path().is_ident("path") {
            plain = Some(match &attr.meta {
                syn::Meta::NameValue(nv) => Walk::literal(&nv.value).ok_or(()),
                _ => Err(()),
            });
        } else if attr.path().is_ident("cfg_attr") {
            if let Ok(metas) = attr.parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated) {
                for meta in metas.iter().skip(1) {
                    if let syn::Meta::NameValue(nv) = meta {
                        if nv.path.is_ident("path") {
                            cfg = Some(Walk::literal(&nv.value).ok_or(()));
                        }
                    }
                }
            }
        }
    }
    (plain, cfg)
}

impl<'a> Visit<'a> for Walk {
    fn visit_item_use(&mut self, i: &'a syn::ItemUse) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        let leading = i.leading_colon.is_some();
        for (line, root) in use_roots(&i.tree) {
            let ok = if leading {
                matches!(root.as_str(), "std" | "core" | "alloc")
            } else {
                ROOTS.contains(&root.as_str()) || self.local.contains(&root)
            };
            if !ok {
                self.out.roots.push((line, root));
            }
        }
    }

    fn visit_item_extern_crate(&mut self, i: &'a syn::ItemExternCrate) {
        let name = i.ident.unraw().to_string();
        if !matches!(name.as_str(), "std" | "core" | "alloc" | "self") {
            self.out.roots.push((i.ident.span().start().line, name));
        }
    }

    fn visit_path(&mut self, p: &'a syn::Path) {
        self.path(p, false);
    }

    fn visit_expr_path(&mut self, e: &'a syn::ExprPath) {
        for attr in &e.attrs {
            self.visit_attribute(attr);
        }
        self.qualified(e.qself.as_ref(), &e.path);
    }

    fn visit_type_path(&mut self, t: &'a syn::TypePath) {
        self.qualified(t.qself.as_ref(), &t.path);
    }

    fn visit_item_mod(&mut self, m: &'a syn::ItemMod) {
        for attr in &m.attrs {
            self.visit_attribute(attr);
        }
        let line = m.ident.span().start().line;
        let name = m.ident.unraw().to_string();
        let (plain, cfg) = mod_paths(&m.attrs);
        let under: PathBuf = self.dirs.iter().collect();
        match &m.content {
            None => {
                for given in [&plain, &cfg].into_iter().flatten() {
                    self.out.includes.push((
                        line,
                        match given {
                            Ok(p) => Include::Path(under.join(p)),
                            Err(()) => Include::Opaque,
                        },
                    ));
                }
                if plain.is_none() {
                    self.out.includes.push((line, Include::Unpathed(name, cfg.is_some())));
                }
            }
            Some((_, items)) => {
                let segment = match &plain {
                    Some(Ok(p)) => p.clone(),
                    _ => name,
                };
                self.dirs.push(segment);
                for item in items {
                    self.visit_item(item);
                }
                self.dirs.pop();
            }
        }
    }

    fn visit_macro(&mut self, m: &'a syn::Macro) {
        self.visit_path(&m.path);
        if m.path.is_ident("include") {
            let line = m.path.span().start().line;
            let what = m.parse_body::<syn::Expr>().ok().as_ref().and_then(Walk::literal);
            self.out.includes.push((line, what.map_or(Include::Opaque, |p| Include::Macro(p.into()))));
            return;
        }
        match m.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
            Ok(exprs) => exprs.iter().for_each(|e| self.visit_expr(e)),
            Err(_) => self.tokens(m.tokens.clone()),
        }
    }

    fn visit_meta_list(&mut self, l: &'a syn::MetaList) {
        self.visit_path(&l.path);
        match l.parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated) {
            Ok(metas) => metas.iter().for_each(|m| self.visit_meta(m)),
            Err(_) => self.tokens(l.tokens.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent").to_path_buf()
    }

    fn roots(src: &str) -> Vec<String> {
        analyze(src).unwrap_or_else(|e| panic!("{e}\n{src}")).roots.into_iter().map(|(_, r)| r).collect()
    }

    fn includes(src: &str) -> Vec<(usize, Include)> {
        analyze(src).unwrap_or_else(|e| panic!("{e}\n{src}")).includes
    }

    /// Each file xtask compiles from another crate, and every file it compiles into itself,
    /// names nothing but `std`, read from the tree.
    #[test]
    fn every_file_xtask_compiles_by_path_names_only_std() {
        for file in STD_ONLY {
            let findings = check(&repo().join(file));
            assert!(
                findings.is_empty(),
                "{file} is compiled into xtask by `#[path]` and must name nothing but `std`, \
                 `core`, `alloc`, `super` or `self`:\n{}",
                findings.join("\n")
            );
        }
    }

    /// The list is every `#[path]` and `include!` under `xtask/src` that names a file
    /// outside `xtask/`, resolved from the file it is in: one that is not listed would go
    /// unread, and a listed file nothing includes would be held for no reason. Reads
    /// `xtask/src` only: `xtask/tests/` is out of scope (see the module doc).
    #[test]
    fn the_list_is_every_include_from_outside_xtask() {
        let root = repo().canonicalize().unwrap();
        let mut included = BTreeSet::new();
        let mut dirs = vec![root.join("xtask/src")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let analysis = analyze(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                for (_, include) in analysis.includes {
                    let target = match include {
                        Include::Path(t) | Include::Macro(t) => t,
                        Include::Unpathed(..) => continue,
                        Include::Opaque => panic!("{}: an include that is not a plain string", path.display()),
                    };
                    let file = dir.join(&target).canonicalize().unwrap_or_else(|e| panic!("{}: {e}", target.display()));
                    let rel = file.strip_prefix(&root).expect("an include inside the repository");
                    if !rel.starts_with("xtask") {
                        included.insert(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        let listed: BTreeSet<String> = STD_ONLY.iter().map(|s| s.to_string()).collect();
        assert_eq!(included, listed, "the includes from outside xtask/ (left) are not `STD_ONLY` (right)");
    }

    /// Every spelling of a `path` and an `include!` is read, resolved as rustc resolves it,
    /// and nothing that only looks like one.
    #[test]
    fn every_spelling_of_a_path_attribute_is_read() {
        let src = r##"//! Not one: #[path = "doc.rs"] mod doc;
#[path="tight.rs"]
mod tight;
#[ path = "spaced.rs" ]
pub(crate) mod spaced;
#[cfg_attr(unix, path = "cfg.rs")]
mod cfg;
#[doc = "x"]
#[path = concat!("raw", ".rs")]
mod raw;
fn f() -> String { let path = "p"; format!("{path}{x}", x = path) }
include ! ( "inc.rs" );
const S: &str = "#[path = \"string.rs\"]";
mod inline { #[path = "nested.rs"] mod nested; mod deeper { #[path = "deep.rs"] mod deep; } }
#[path = "elsewhere"]
mod moved { #[path = "in_moved.rs"] mod m; }
mod bare;
"##;
        assert_eq!(
            includes(src),
            [
                (3, Include::Path("tight.rs".into())),
                (5, Include::Path("spaced.rs".into())),
                (7, Include::Path("cfg.rs".into())),
                (7, Include::Unpathed("cfg".into(), true)),
                (10, Include::Opaque),
                (12, Include::Macro("inc.rs".into())),
                (14, Include::Path("inline/nested.rs".into())),
                (14, Include::Path("inline/deeper/deep.rs".into())),
                (16, Include::Path("elsewhere/in_moved.rs".into())),
                (17, Include::Unpathed("bare".into(), false)),
            ]
        );
    }

    /// A planted `use serde_json` in a scratch copy of each listed file is found, by line:
    /// the import both crates link, which compiles on both sides and so is the one the
    /// build cannot catch.
    #[test]
    fn a_planted_use_serde_json_in_a_scratch_copy_is_found() {
        let scratch = tempfile::tempdir().unwrap();
        for file in STD_ONLY {
            let text = std::fs::read_to_string(repo().join(file)).unwrap();
            let copy = scratch.path().join(Path::new(file).file_name().unwrap());
            std::fs::write(&copy, format!("{text}\nuse serde_json::Value;\n")).unwrap();
            let planted = std::fs::read_to_string(&copy).unwrap();
            let line = planted.lines().count();
            assert_eq!(analyze(&planted).unwrap().roots, [(line, "serde_json".to_string())], "{file}");
            assert_eq!(
                check(&copy),
                [format!("{}:{line}: names `serde_json`, which is not `std`", copy.display())],
                "{file}"
            );
        }
    }

    /// What a shared file compiles into itself is held as the file is: a `#[path]` module
    /// (under an inline module, from its directory) and an `include!` are followed into the
    /// files they name, an out-of-line `mod` with no `#[path]` is refused, and a file that
    /// does not parse is refused rather than passed.
    #[test]
    fn what_a_shared_file_pulls_in_is_held_too() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path();
        std::fs::create_dir(dir.join("inner")).unwrap();
        let put = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
        put(
            "a.rs",
            "#[path = \"b.rs\"]\nmod b;\ninclude!(\"c.rs\");\nmod d;\n#[path = \"gone.rs\"]\nmod gone;\n\
             mod inner { #[path = \"e.rs\"] mod e; }\n#[path = \"broken.rs\"]\nmod broken;\n",
        );
        put("b.rs", "use serde_json::Value;\n#[path = \"a.rs\"]\nmod again;\n");
        put("c.rs", "fn f() { serde::x(); }\n");
        put("inner/e.rs", "fn f() -> ::serde_json::Value { todo!() }\n");
        put("e.rs", "// the wrong e.rs: read only if the inline module's directory is ignored\n");
        put("broken.rs", "fn f( {\n");
        let findings = check(&dir.join("a.rs")).join("\n");
        for want in [
            "b.rs:1: names `serde_json`",
            "c.rs:1: names `serde`",
            "a.rs:4: `mod d;` has no `#[path]`",
            "gone.rs: cannot be held",
            "e.rs:1: names `serde_json`",
            "broken.rs: cannot be held: does not parse",
        ] {
            assert!(findings.contains(want), "{want} not in:\n{findings}");
        }
        assert_eq!(findings.lines().count(), 6, "{findings}");
    }

    /// Every spelling of a dependency is found: a leading `::` after anything the grammar
    /// allows before a path (`->`, `=>`, a comparison, `+`, `dyn`, `return`, `[`, `:`), a
    /// group, `crate`, `$crate`, `extern crate`, a `use` in a body or under `cfg`, a raw
    /// identifier, and a path in code, an attribute, a type, a bound, a `where` clause, an
    /// `impl … for`, a qualified path or a macro's input.
    #[test]
    fn every_spelling_of_a_crate_outside_std_is_found() {
        let cases: &[(&str, &[&str])] = &[
            ("use ::serde_json::Value;", &["serde_json"]),
            ("use {std::fs, serde::Serialize};", &["serde"]),
            ("pub(crate) use crate::wire::X;", &["crate"]),
            ("extern crate serde_json;", &["serde_json"]),
            ("fn f() { use serde_json::Value; }", &["serde_json"]),
            ("#[cfg(test)]\nuse serde_json::Value;", &["serde_json"]),
            ("#[cfg(test)]\nmod tests { use serde_json::Value; }", &["serde_json"]),
            ("use r#serde_json::Value;", &["serde_json"]),
            ("fn f() { r#serde_json::x(); }", &["serde_json"]),
            ("fn f() { ::r#serde_json::x(); }", &["serde_json"]),
            ("fn f() { serde_json::json!(1); }", &["serde_json"]),
            ("fn f() -> String { ::serde_json::to_string(&1).unwrap() }", &["serde_json"]),
            ("fn f() -> String { :: serde_json :: to_string(&1).unwrap() }", &["serde_json"]),
            ("fn f() { let _ = serde_json ::to_string(&1); }", &["serde_json"]),
            ("fn f() -> ::serde_json::Value { todo!() }", &["serde_json"]),
            ("fn f(x: u8) { match x { _ => ::serde_json::x(), } }", &["serde_json"]),
            ("fn f(x: u8) -> bool { x > ::serde_json::N }", &["serde_json"]),
            ("fn f<T: Copy + ::serde::Serialize>() {}", &["serde"]),
            ("fn f(_: &dyn ::serde::Serialize) {}", &["serde"]),
            ("fn f<T>() where T: serde::Serialize {}", &["serde"]),
            ("fn f<T>() where T:serde::Serialize {}", &["serde"]),
            ("impl ::serde::Serialize for X {}", &["serde"]),
            ("impl serde::Serialize for S {}", &["serde"]),
            ("#[derive(::serde::Serialize)] struct S;", &["serde"]),
            ("#[derive(serde::Serialize)]\nstruct S;", &["serde"]),
            ("#[cfg_attr(test, derive(serde::Serialize))]\nstruct S;", &["serde"]),
            ("fn f(x: ::serde_json::Value, _: [::serde::X; 1]) {}", &["serde", "serde_json"]),
            ("fn f() -> u8 { return ::serde::x(); }", &["serde"]),
            ("fn f(_: Vec<serde_json::Value>) {}", &["serde_json"]),
            ("fn f() { <u8 as serde::Serialize>::serialize; }", &["serde"]),
            ("fn f() { let _ = matches!(x, serde::A); }", &["serde"]),
            ("fn f() { assert_eq!(1, ::serde_json::N); }", &["serde_json"]),
            ("macro_rules! m { () => { $crate::wire::X } }", &["$crate"]),
            ("macro_rules! m { () => { serde_json::json!(1) } }", &["serde_json"]),
            ("macro_rules! m { ($x:expr) => { $x > ::serde_json::N } }", &["serde_json"]),
            ("macro_rules! m { () => { fn f() -> ::serde::X {} } }", &["serde"]),
            ("macro_rules! m { () => { 1 => ::serde::x() } }", &["serde"]),
            ("fn f<'a>(x: &'a str) -> &'a str { x }\nfn g() { serde_json::x(); }", &["serde_json"]),
            ("const Q: u8 = b'\"'; fn g() { serde_json::x(); }", &["serde_json"]),
            ("fn g() { 'a: loop { break 'a; } serde_json::x(); }", &["serde_json"]),
        ];
        for (src, want) in cases {
            assert_eq!(roots(src), *want, "{src}");
        }
        assert_eq!(analyze("\n\nfn f() { let _ = kvaultd::settings::x(); }").unwrap().roots, [(3, "kvaultd".to_string())]);
    }

    /// The file's own names are its own: a module, item, generic parameter or `std` binding
    /// it declares may start a path, by that name, and nothing else is admitted by them.
    #[test]
    fn a_name_the_file_gives_meaning_may_start_a_path() {
        assert_eq!(roots("mod serde_json { pub fn x() {} }\nfn f() { serde_json::x(); }"), Vec::<String>::new());
        assert_eq!(roots("use std::{io as sio};\nfn f() { sio::stdin(); }"), Vec::<String>::new());
        assert_eq!(roots("use std::path;\nfn f() { path::Path::new(\"\"); }"), Vec::<String>::new());
        assert_eq!(roots("fn f<T: Default>() -> T { T::default() }"), Vec::<String>::new());
        assert_eq!(roots("enum K { A }\nfn f() -> K { K::A }"), Vec::<String>::new());
        // A name bound by a `use` from outside `std` admits nothing: the `use` is held.
        assert_eq!(roots("use serde_json as sj;\nfn f() { sj::x(); }"), ["serde_json", "sj"]);
    }

    /// What names only `std` reads clean: the standard library and the file's own modules
    /// by any spelling, primitives, prelude names, turbofish, qualified paths, lint tools,
    /// and a crate's name inside a comment, a doc or a string.
    #[test]
    fn what_names_only_std_is_not_held() {
        let src = r##"//! Read by `kvaultd::settings::env_file_pairs`.
use std::path::{self, Path};
use std::{fs, io::Read};
/* serde_json::Value, /* nested */ still a comment */
#[allow(clippy::too_many_lines)]
fn f(s: &str) -> usize {
    let q = '"'; let e = '\''; let _ = (q, e);
    let _ = "serde_json::to_string"; let _ = r#"serde::x "quoted""#;
    let _ = std::path::PathBuf::new(); let _ = ::std::fs::read("x");
    let _: Vec<u8> = s.bytes().collect::<Vec<_>>();
    let _ = Vec::<u8>::new(); let _ = <u8 as std::str::FromStr>::from_str("1");
    let _ = <Vec<u8>>::new(); let _ = String::from("x"); let _ = Option::<u8>::None;
    let _ = core::mem::size_of::<u8>() + alloc_free(s);
    assert_eq!(1, std::cmp::min(1, 2), "{}", path::MAIN_SEPARATOR);
    let _ = matches!(s.len(), 0 | 1) && 2 > ::core::cmp::max(1, 0);
    u8::MAX as usize + str::len(s) + std :: cmp :: max(1, 2)
}
fn alloc_free(_: &str) -> usize { Path::new("").as_os_str().len() + fs::metadata("").map_or(0, |_| 0) }
impl std::fmt::Display for Path2 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Self::g(f) } }
struct Path2;
impl Path2 { fn g(_: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) } }
mod tests { use super::*; fn g() { let _ = self::super::f(""); let _ = super::alloc_free; } }
"##;
        assert_eq!(roots(src), Vec::<String>::new());
        assert_eq!(includes(src), []);
        // Every prelude name, as a path root (built from the list: one is a word
        // `host-word-check` reads in a literal).
        for name in PRELUDE {
            assert_eq!(roots(&format!("fn f() {{ let _ = {name}::x; }}")), Vec::<String>::new(), "{name}");
        }
    }
}
