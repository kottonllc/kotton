// SPDX-License-Identifier: AGPL-3.0-or-later
//! No public item of this crate names a type of the threshold library.
//!
//! The threshold library is a dependency of this crate alone (`ed25519-check` holds that no
//! other crate links it), and its own surface is the tree's own types: hex strings in, hex
//! strings and [`VerifyingKey`](crate::ed25519::VerifyingKey) out, [`FrostError`] for a
//! failure. A public item that named one of the library's types would hand it to every
//! dependent all the same, without the dependent linking anything. This test reads the crate's
//! modules, as `lib.rs` declares them, and fails on any such item.
//!
//! [`FrostError`]: crate::provider::frost::FrostError
//!
//! ## What counts
//!
//! - **The library** is `frost-core` and every package `Cargo.lock` records as depending on a
//!   package of the library, as `ed25519-check` reads it, named as Rust names a crate.
//! - **A name of the library** in a file is a path that starts at one of those crates, or at a
//!   name the file's `use` items bind to a path that does (so `frost` after
//!   `use frost_ed25519 as frost;`), or at a type alias in the file whose type names the library.
//!   A glob import from the library is refused: it binds names the check cannot see.
//! - **A public item** is one written `pub`, wherever its module is: a function's signature, a
//!   constant's or static's type, a type alias, a struct's or union's `pub` fields and any field
//!   with `#[from]` (whose derived `From` impl is public), every field of an enum, a trait's
//!   signatures, an inherent impl's generics and its `pub` items' signatures. Every trait impl is
//!   counted, whatever its type's visibility, because an impl has none of its own. A `use`, type
//!   alias or `extern crate` with any visibility but private that names the library is counted
//!   too: it would let another module name the library without saying so.
//! - Bodies are not counted: a function may use the library inside. Modules under `#[cfg(test)]`
//!   are not counted, and neither are items a macro writes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// The package the threshold library is built on; `ed25519-check` names it the same way.
const THRESHOLD_CORE: &str = "frost-core";

/// The crates of the threshold library, as Rust names them, read from `lock`.
fn library_crates(lock: &str) -> BTreeSet<String> {
    struct Package {
        name: String,
        published: bool,
        dependencies: Vec<String>,
    }
    let mut packages = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut package = Package { name: String::new(), published: false, dependencies: Vec::new() };
        let mut in_dependencies = false;
        for line in block.lines() {
            let line = line.trim();
            if in_dependencies {
                if line == "]" {
                    in_dependencies = false;
                } else if let Some(name) = line.trim_matches(|c| c == '"' || c == ',').split(' ').next() {
                    package.dependencies.push(name.to_string());
                }
            } else if let Some(name) = line.strip_prefix("name = ") {
                package.name = name.trim_matches('"').to_string();
            } else if line.starts_with("source = ") {
                package.published = true;
            } else if line == "dependencies = [" {
                in_dependencies = true;
            }
        }
        packages.push(package);
    }
    let mut library: BTreeSet<String> = [THRESHOLD_CORE.to_string()].into();
    loop {
        let before = library.len();
        for p in &packages {
            if p.published && p.dependencies.iter().any(|d| library.contains(d)) {
                library.insert(p.name.clone());
            }
        }
        if library.len() == before {
            break;
        }
    }
    library.into_iter().map(|n| n.replace('-', "_")).collect()
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && matches!(&a.meta, syn::Meta::List(l) if l.tokens.to_string() == "test")
    })
}

fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|a| match &a.meta {
        syn::Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
            _ => None,
        },
        _ => None,
    })
}

/// The names that lead to the library in one file.
struct Names<'a> {
    crates: &'a BTreeSet<String>,
    local: BTreeSet<String>,
}

impl Names<'_> {
    fn leads(&self, ident: &syn::Ident, leading_colon: bool) -> bool {
        let id = ident.to_string();
        self.crates.contains(&id) || (!leading_colon && self.local.contains(&id))
    }

    fn names_library(&self, path: &syn::Path) -> bool {
        path.segments.first().is_some_and(|s| self.leads(&s.ident, path.leading_colon.is_some()))
    }

    /// Whether anything `node` holds names the library.
    fn in_node(&self, visit: impl FnOnce(&mut Finder<'_>)) -> bool {
        let mut finder = Finder { names: self, found: false };
        visit(&mut finder);
        finder.found
    }

    /// The names `tree` binds that lead to the library; whether it takes a glob from it.
    /// `from_library` says whether the path above `tree` leads to the library, and `parent` is
    /// its last segment, which `self` in a group binds.
    fn bound(
        &self,
        tree: &syn::UseTree,
        leading_colon: bool,
        from_library: Option<bool>,
        parent: Option<&syn::Ident>,
        out: &mut BTreeSet<String>,
    ) -> bool {
        let leads = |ident: &syn::Ident| {
            if ident == "self" {
                from_library == Some(true) && parent.is_some()
            } else {
                from_library.unwrap_or_else(|| self.leads(ident, leading_colon))
            }
        };
        let name = |ident: &syn::Ident| match parent {
            Some(p) if ident == "self" => p.to_string(),
            _ => ident.to_string(),
        };
        match tree {
            syn::UseTree::Path(p) => self.bound(&p.tree, leading_colon, Some(leads(&p.ident)), Some(&p.ident), out),
            syn::UseTree::Name(n) => {
                if leads(&n.ident) {
                    out.insert(name(&n.ident));
                }
                false
            }
            syn::UseTree::Rename(r) => {
                if leads(&r.ident) {
                    out.insert(r.rename.to_string());
                }
                false
            }
            syn::UseTree::Glob(_) => from_library == Some(true),
            syn::UseTree::Group(g) => g
                .items
                .iter()
                .fold(false, |glob, t| self.bound(t, leading_colon, from_library, parent, out) | glob),
        }
    }

    /// Every name `items` bind to the library, to a fixed point (an alias may lead to another).
    fn collect(&mut self, items: &[syn::Item], label: &str, found: &mut Vec<String>) {
        loop {
            let before = self.local.len();
            let mut more = BTreeSet::new();
            let mut globs = Vec::new();
            self.walk_bindings(items, &mut more, &mut globs);
            self.local.extend(more);
            if self.local.len() == before {
                for glob in globs {
                    found.push(format!("{label}: `use {glob}` imports the threshold library by glob"));
                }
                break;
            }
        }
    }

    fn walk_bindings(&self, items: &[syn::Item], more: &mut BTreeSet<String>, globs: &mut Vec<String>) {
        for item in items {
            match item {
                syn::Item::Use(u) => {
                    if self.bound(&u.tree, u.leading_colon.is_some(), None, None, more) {
                        globs.push(quote_tree(&u.tree));
                    }
                }
                syn::Item::ExternCrate(e) => {
                    if self.crates.contains(&e.ident.to_string()) {
                        if let Some((_, alias)) = &e.rename {
                            more.insert(alias.to_string());
                        }
                    }
                }
                syn::Item::Type(t) => {
                    if self.in_node(|f| f.visit_type(&t.ty)) {
                        more.insert(t.ident.to_string());
                    }
                }
                syn::Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                    if let Some((_, inner)) = &m.content {
                        self.walk_bindings(inner, more, globs);
                    }
                }
                _ => {}
            }
        }
    }
}

/// A `use` tree as it is written, for a message.
fn quote_tree(tree: &syn::UseTree) -> String {
    match tree {
        syn::UseTree::Path(p) => format!("{}::{}", p.ident, quote_tree(&p.tree)),
        syn::UseTree::Name(n) => n.ident.to_string(),
        syn::UseTree::Rename(r) => format!("{} as {}", r.ident, r.rename),
        syn::UseTree::Glob(_) => "*".into(),
        syn::UseTree::Group(g) => format!("{{{}}}", g.items.iter().map(quote_tree).collect::<Vec<_>>().join(", ")),
    }
}

struct Finder<'a> {
    names: &'a Names<'a>,
    found: bool,
}

impl<'ast> Visit<'ast> for Finder<'_> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if self.names.names_library(path) {
            self.found = true;
        }
        syn::visit::visit_path(self, path);
    }
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

fn is_private(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Inherited)
}

fn has_from(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("from"))
}

/// The public items of `items` that name the library, pushed onto `found` as `label: what`.
fn exposures(items: &[syn::Item], names: &Names<'_>, label: &str, found: &mut Vec<String>) {
    let mut inner_found = Vec::new();
    let mut say = |what: String| found.push(format!("{label}: {what} names the threshold library"));
    for item in items {
        match item {
            syn::Item::Fn(f) if is_pub(&f.vis) => {
                if names.in_node(|v| v.visit_signature(&f.sig)) {
                    say(format!("pub fn {}", f.sig.ident));
                }
            }
            syn::Item::Const(c) if is_pub(&c.vis) => {
                if names.in_node(|v| v.visit_type(&c.ty)) {
                    say(format!("pub const {}", c.ident));
                }
            }
            syn::Item::Static(s) if is_pub(&s.vis) => {
                if names.in_node(|v| v.visit_type(&s.ty)) {
                    say(format!("pub static {}", s.ident));
                }
            }
            syn::Item::Type(t) if !is_private(&t.vis) => {
                if names.in_node(|v| {
                    v.visit_generics(&t.generics);
                    v.visit_type(&t.ty)
                }) {
                    say(format!("type {}, not private,", t.ident));
                }
            }
            syn::Item::Struct(s) => {
                let public = is_pub(&s.vis);
                if names.in_node(|v| {
                    if public {
                        v.visit_generics(&s.generics);
                    }
                    for field in &s.fields {
                        if (public && is_pub(&field.vis)) || has_from(&field.attrs) {
                            v.visit_type(&field.ty);
                        }
                    }
                }) {
                    say(format!("struct {}", s.ident));
                }
            }
            syn::Item::Union(u) if is_pub(&u.vis) => {
                if names.in_node(|v| {
                    v.visit_generics(&u.generics);
                    for field in &u.fields.named {
                        if is_pub(&field.vis) {
                            v.visit_type(&field.ty);
                        }
                    }
                }) {
                    say(format!("pub union {}", u.ident));
                }
            }
            syn::Item::Enum(e) => {
                let public = is_pub(&e.vis);
                for variant in &e.variants {
                    if names.in_node(|v| {
                        for field in &variant.fields {
                            if public || has_from(&field.attrs) {
                                v.visit_type(&field.ty);
                            }
                        }
                    }) {
                        say(format!("enum {}'s variant {}", e.ident, variant.ident));
                    }
                }
                if public && names.in_node(|v| v.visit_generics(&e.generics)) {
                    say(format!("pub enum {}'s generics", e.ident));
                }
            }
            syn::Item::Trait(t) if is_pub(&t.vis) => {
                if names.in_node(|v| {
                    v.visit_generics(&t.generics);
                    for bound in &t.supertraits {
                        v.visit_type_param_bound(bound);
                    }
                    for inner in &t.items {
                        match inner {
                            syn::TraitItem::Fn(f) => v.visit_signature(&f.sig),
                            syn::TraitItem::Type(ty) => {
                                v.visit_generics(&ty.generics);
                                for bound in &ty.bounds {
                                    v.visit_type_param_bound(bound);
                                }
                                if let Some((_, default)) = &ty.default {
                                    v.visit_type(default);
                                }
                            }
                            syn::TraitItem::Const(c) => v.visit_type(&c.ty),
                            _ => {}
                        }
                    }
                }) {
                    say(format!("pub trait {}", t.ident));
                }
            }
            syn::Item::Impl(i) => {
                let of_trait = i.trait_.is_some();
                let public_items = i.items.iter().any(|it| match it {
                    syn::ImplItem::Fn(f) => is_pub(&f.vis),
                    syn::ImplItem::Const(c) => is_pub(&c.vis),
                    _ => false,
                });
                if (of_trait || public_items)
                    && names.in_node(|v| {
                        v.visit_generics(&i.generics);
                        v.visit_type(&i.self_ty);
                        if let Some((_, path, _)) = &i.trait_ {
                            v.visit_path(path);
                        }
                        for inner in &i.items {
                            match inner {
                                syn::ImplItem::Fn(f) if of_trait || is_pub(&f.vis) => v.visit_signature(&f.sig),
                                syn::ImplItem::Const(c) if of_trait || is_pub(&c.vis) => v.visit_type(&c.ty),
                                syn::ImplItem::Type(ty) if of_trait || is_pub(&ty.vis) => v.visit_type(&ty.ty),
                                _ => {}
                            }
                        }
                    })
                {
                    let what = if of_trait { "trait impl" } else { "inherent impl" };
                    say(format!("{what} for {}", type_name(&i.self_ty)));
                }
            }
            syn::Item::Use(u) if !is_private(&u.vis) => {
                let mut bound = BTreeSet::new();
                let glob = names.bound(&u.tree, u.leading_colon.is_some(), None, None, &mut bound);
                if glob || !bound.is_empty() || use_leads(names, &u.tree, u.leading_colon.is_some()) {
                    say(format!("use {}, not private,", quote_tree(&u.tree)));
                }
            }
            syn::Item::ExternCrate(e) if !is_private(&e.vis) => {
                if names.crates.contains(&e.ident.to_string()) {
                    say(format!("extern crate {}, not private,", e.ident));
                }
            }
            syn::Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    exposures(inner, names, &format!("{label} mod {}", m.ident), &mut inner_found);
                }
            }
            _ => {}
        }
    }
    found.extend(inner_found);
}

/// Whether a `use` tree starts at the library, including `use frost_ed25519;` (which binds the
/// crate's own name, not a new one).
fn use_leads(names: &Names<'_>, tree: &syn::UseTree, leading_colon: bool) -> bool {
    match tree {
        syn::UseTree::Path(p) => names.leads(&p.ident, leading_colon),
        syn::UseTree::Name(n) => names.leads(&n.ident, leading_colon),
        syn::UseTree::Rename(r) => names.leads(&r.ident, leading_colon),
        syn::UseTree::Glob(_) => false,
        syn::UseTree::Group(g) => g.items.iter().any(|t| use_leads(names, t, leading_colon)),
    }
}

fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
        _ => "a type".into(),
    }
}

/// What one file's items expose of the library, and the names the file binds to it.
fn check_file(file: &syn::File, crates: &BTreeSet<String>, label: &str) -> (Vec<String>, BTreeSet<String>) {
    let mut names = Names { crates, local: BTreeSet::new() };
    let mut found = Vec::new();
    names.collect(&file.items, label, &mut found);
    exposures(&file.items, &names, label, &mut found);
    (found, names.local)
}

/// The files of the crate's modules, as `lib.rs` declares them, without `#[cfg(test)]` modules.
fn module_files(src: &Path) -> Vec<PathBuf> {
    fn child(dir: &Path, m: &syn::ItemMod) -> PathBuf {
        if let Some(p) = path_attr(&m.attrs) {
            return dir.join(p);
        }
        let flat = dir.join(format!("{}.rs", m.ident));
        if flat.exists() { flat } else { dir.join(m.ident.to_string()).join("mod.rs") }
    }
    fn walk(items: &[syn::Item], dir: &Path, out: &mut Vec<PathBuf>) {
        for item in items {
            let syn::Item::Mod(m) = item else { continue };
            if is_cfg_test(&m.attrs) {
                continue;
            }
            match &m.content {
                Some((_, inner)) => walk(inner, &dir.join(m.ident.to_string()), out),
                None => {
                    let file = child(dir, m);
                    visit(&file, out);
                }
            }
        }
    }
    fn visit(file: &Path, out: &mut Vec<PathBuf>) {
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let parsed = syn::parse_file(&text).unwrap_or_else(|e| panic!("parse {}: {e}", file.display()));
        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        let dir = match stem {
            "lib" | "mod" | "main" => file.parent().unwrap().to_path_buf(),
            _ => file.with_extension(""),
        };
        out.push(file.to_path_buf());
        walk(&parsed.items, &dir, out);
    }
    let mut out = Vec::new();
    visit(&src.join("lib.rs"), &mut out);
    out
}

#[test]
fn no_public_item_of_the_crate_names_a_type_of_the_threshold_library() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock = std::fs::read_to_string(manifest.join("../../Cargo.lock")).expect("read the workspace's Cargo.lock");
    let crates = library_crates(&lock);
    assert!(
        crates.contains("frost_core") && crates.contains("frost_ed25519"),
        "the lockfile names the threshold library: {crates:?}"
    );

    let src = manifest.join("src");
    let files = module_files(&src);
    let frost = src.join("provider/frost.rs");
    assert!(files.contains(&frost), "the walk reaches the module that uses the library: {files:#?}");

    let mut found = Vec::new();
    for file in &files {
        let label = file.strip_prefix(manifest).unwrap_or(file).display().to_string();
        let text = std::fs::read_to_string(file).unwrap();
        let (exposed, local) = check_file(&syn::parse_file(&text).unwrap(), &crates, &label);
        if *file == frost {
            assert!(
                local.contains("frost") && local.contains("Identifier"),
                "the check sees the names the module binds to the library: {local:?}"
            );
        }
        found.extend(exposed);
    }
    assert!(found.is_empty(), "public items name the threshold library:\n{}", found.join("\n"));
}

/// The check's refusals, on files written to make each one.
mod refusals {
    use super::*;

    fn exposed(src: &str) -> Vec<String> {
        let crates: BTreeSet<String> = ["frost_core", "frost_ed25519"].map(str::to_string).into();
        check_file(&syn::parse_file(src).unwrap(), &crates, "f.rs").0
    }

    #[test]
    fn an_error_variant_carrying_the_library_error_is_refused() {
        let found = exposed(
            "#[derive(Debug, thiserror::Error)]\npub enum FrostError {\n    #[error(\"FROST: {0}\")]\n    \
             Frost(#[from] frost_ed25519::Error),\n    #[error(\"x\")]\n    Serialise(String),\n}\n",
        );
        assert_eq!(found, ["f.rs: enum FrostError's variant Frost names the threshold library"]);
    }

    #[test]
    fn a_name_bound_by_use_or_alias_is_refused_in_a_public_signature() {
        let found = exposed(
            "use frost_ed25519 as frost;\nuse frost::keys::{self, KeyPackage};\ntype Share = frost::round2::SignatureShare;\n\
             pub fn a() -> frost::Identifier { todo!() }\npub fn b(_: &KeyPackage) {}\npub fn c(_: Vec<Share>) {}\n\
             pub fn d() -> keys::PublicKeyPackage { todo!() }\npub fn e() -> ::frost_core::Error<X> { todo!() }\n",
        );
        assert_eq!(found.len(), 5, "{found:#?}");
    }

    #[test]
    fn a_trait_impl_a_from_field_or_a_re_export_is_refused() {
        let found = exposed(
            "impl From<frost_ed25519::Error> for E { fn from(_: frost_ed25519::Error) -> Self { E } }\n\
             struct Private(#[from] frost_ed25519::Error);\npub(crate) use frost_ed25519::Identifier;\n\
             pub(crate) type Id = frost_ed25519::Identifier;\npub use frost_core;\nuse frost_ed25519::keys::*;\n",
        );
        assert_eq!(found.len(), 6, "{found:#?}");
        assert!(found[0].contains("glob"), "{found:#?}");
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

    #[test]
    fn the_library_is_every_published_package_built_on_the_core() {
        let lock = "[[package]]\nname = \"frost-core\"\nversion = \"2.2.0\"\nsource = \"registry+x\"\n\n\
                    [[package]]\nname = \"frost-rerandomized\"\nversion = \"2.2.0\"\nsource = \"registry+x\"\ndependencies = [\n \"frost-core\",\n]\n\n\
                    [[package]]\nname = \"frost-ed25519\"\nversion = \"2.2.0\"\nsource = \"registry+x\"\ndependencies = [\n \"frost-rerandomized\",\n \"sha2\",\n]\n\n\
                    [[package]]\nname = \"kotton-crypto\"\nversion = \"0.1.0\"\ndependencies = [\n \"frost-ed25519\",\n]\n";
        let crates = library_crates(lock);
        let expected: BTreeSet<String> = ["frost_core", "frost_ed25519", "frost_rerandomized"].map(str::to_string).into();
        assert_eq!(crates, expected);
    }
}
