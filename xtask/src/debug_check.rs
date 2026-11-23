// SPDX-License-Identifier: AGPL-3.0-or-later
//! `debug-check`: no answer is printed by `Debug` outside tests.
//!
//! ## Why this exists
//!
//! The rule for what a reader says of an answer: an answer it did not ask for is said by its
//! name and no field (`kotton_wire::ipc::unasked`, or the answer's own `name()`); another
//! node's text is printed through `kotton_wire::note::quoted_cut`; this device's own daemon's
//! `Error` is said by its message, as written. `Debug` of an answer prints every field of it,
//! another node's text among them, neither quoted nor cut. Each file's sites were held by a
//! test of that file, and where each site builds its own string a site could go back to
//! `{other:?}` with every test still passing. This check holds the rule at every site, and at a
//! site not yet written.
//!
//! ## What it reads
//!
//! Every `.rs` file git tracks under [`crate::tree::CODE_ROOTS`], parsed with `syn`, except
//! test code:
//!
//! - a file under a `tests` or `benches` directory (the rule `recovery-set-check` uses);
//! - a file whose first lines say `#![cfg(test)]`;
//! - a file a `#[cfg(test)] mod name;` declaration brings in (resolved as rustc resolves it:
//!   `name.rs` or `name/mod.rs` beside a `lib.rs`, `main.rs`, `mod.rs`, `build.rs` or a file
//!   of a `bin` or `examples` directory, under a directory named for the file otherwise, or
//!   the `#[path]` it names), and every file such a file declares in turn;
//! - an item or statement under an attribute that holds only in a test build: `#[cfg(test)]`,
//!   `#[cfg(all(test, ..))]`, or a test attribute (`#[test]`, `#[tokio::test]`, any attribute
//!   whose last segment is `test`).
//!
//! `#[cfg(any(test, ..))]` is read as code: it is compiled outside tests when its other
//! condition holds. A file the parser cannot read is refused, not skipped.
//!
//! ## What it refuses
//!
//! A `Debug` formatting of an expression known to be an answer ([`ANSWERS`], held to the wire
//! crate by a test: every enum of it the rule there names is in [`ANSWERS`] or in the test's
//! list of the wire's enums that are not another party's answer):
//!
//! - in a macro of the `format!` family (`format!`, `format_args!`, `print!`, `println!`,
//!   `eprint!`, `eprintln!`, `write!`, `writeln!`, `panic!`, `unreachable!`, `todo!`,
//!   `unimplemented!`, `assert!` and its kin, `anyhow!`, `bail!`, `ensure!`), a placeholder
//!   whose type ends in `?` (`{:?}`, `{:#?}`, `{:x?}`), whether it takes its argument by
//!   position (`{:?}`, `{0:?}`), by name (`{a:?}`, `a = answer`) or captures it inline
//!   (`{other:?}`), counting `.*` precisions as the compiler does;
//! - in a `tracing` macro (`trace!`, `debug!`, `info!`, `warn!`, `error!`, `event!`, `span!`
//!   and the `*_span!` forms), a field written `?expr` or `name = ?expr`, and a placeholder of
//!   its message as above;
//! - any argument of `dbg!`.
//!
//! Each finding names the file and line, the macro, the enclosing function, the form as
//! written, the expression, why it is known to be an answer, and the sayer to use instead: for
//! an answer `variant_names!` names ([`NAMED`]), `kotton_wire::ipc::unasked` or its `name()`;
//! for a relay client's error, its `Display`; for any other, a name of its own.
//!
//! ## How it knows an answer
//!
//! There is no type checker here, so "known" is read from the syntax, and only from these:
//!
//! - a binding (a `let`, a function or closure parameter) whose declared type names one of
//!   [`ANSWERS`], directly or through a reference, a tuple, a slice or array, or the type
//!   argument of `Option`, `Result`, `Box`, `Arc`, `Rc`, `Vec` or `VecDeque`;
//! - `self` in an `impl` of one of them;
//! - a binding at the place in a pattern where that pattern, or another arm of the same
//!   `match`, names one of their variants (`other` beside `UserResponse::Error { .. }`;
//!   `Ok(other)` beside `Ok(UserResponse::Ok)`; `answer @ UserResponse::Ok`). A binding
//!   inside the variant (the `message` of `Error { message }`) is a field, not the answer;
//! - a binding of the whole value of a scrutinee already known, in a `match`, `if let`,
//!   `while let` or `for`;
//! - a local or parameter whose name a `match`, `if let`, `while let`, `let .. else` or
//!   `matches!` in the same function reads against one of their variants;
//! - a field access whose field a struct in the same file declares with one of their types;
//! - a path, a call or a struct literal that names one of their variants;
//!
//! and each of these through `&`, `*`, parentheses, `?` and `.clone()`, `.as_ref()`,
//! `.as_deref()`, `.as_mut()`, `.borrow()`, `.to_owned()`, `.unwrap()` and `.expect(..)`.
//! Scopes are lexical: a block, an arm, a closure or a function binds its own names, and a
//! binding of a name with none of these shadows the name. A type is matched by its last
//! segment, so a type of another crate that bears an answer's name is read as that answer.
//!
//! ## What it does not see
//!
//! A pass is not more than this. It does not see a value whose type is only inferred (a
//! `let` from a call's result that nothing in the function matches against an answer's
//! variants; a binding inside a wrapper pattern, `Some(x)`, of a value known only by its
//! declared type), a type alias or a re-export under another name, a variant brought in by
//! `use Type::*` and matched bare, a struct field declared in another file, a format string a
//! macro builds (`concat!`, a `const`), a `Debug` reached through a `{}` of a type whose
//! `Display` calls `Debug`, a print inside a `macro_rules!` body (its `$` fragments do not
//! parse), an `impl Debug` that is not derived, and `Debug` written by hand
//! (`fmt::Debug::fmt(&answer, f)`, `.fmt(f)`). Nor does it see the arguments a
//! `#[tracing::instrument]` records by `Debug`, a `tracing::field::debug(answer)` value, an
//! answer printed inside a tuple (`(name, answer)`) or a `Some(answer)`, an answer reached
//! through an index (`answers[0]`) or `.err()`/`.ok()`, or a tuple struct's field (`s.0`). A
//! format or `tracing` macro whose arguments do not parse is refused rather than passed.
//!
//! ## The owed list
//!
//! The sites main still prints this way are [`OWED_FILE`], one entry per site, keyed by the
//! file, the enclosing function's name and the expression as printed (not by line, so an
//! unrelated edit leaves the key as it was), with the number of sites under that key and the
//! row of the rule each belongs to. A finding an entry covers passes. Refused: a finding no
//! entry covers; an entry that covers no finding (the site is fixed, so its entry goes); an
//! entry whose count is not what the check finds; and, against the merge base with
//! `origin/main` (read from git objects as `tier-check` reads its lists), an entry the merge
//! base does not hold or a count larger than the merge base's. A merge base with no
//! [`OWED_FILE`] while `origin/main` has one is refused, with the remedy of merging
//! `origin/main`, as `tier-check` refuses one without its lists. Only when neither the merge
//! base nor `origin/main` holds the file is it taken as arriving, and then the list it is
//! compared with is what the check finds on the merge base's own tree, read from git objects:
//! an entry for a site the merge base does not print is refused as an entry it does not hold.
//! Once main holds the file that reading is never reached again, so it cannot be used to add
//! an entry.
//!
//! ## Line numbers
//!
//! The lock's `proc-macro2` is built without span locations, so `syn` gives no line. Before
//! parsing, a pass over the text with comments and string contents blanked (the blanking
//! `relay-address-check` uses) appends the line to the name of every macro invocation
//! (`name!(`, `name![`, `name!{`), and the check reads it back off the parsed macro's name.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use syn::ext::IdentExt;
use syn::parse::discouraged::Speculative;
use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Block, Expr, FnArg, Ident, ImplItem, Item, ItemMod, LitStr, Macro, Member, Meta, Pat, Stmt, Token, TraitItem, Type};
use toml::Value;

use crate::recovery_set_check::is_test_file;
use crate::relay_address_check::blank;
use crate::tier_check::{file_at, git, merge_base, short, MAIN_REF};

/// The sites still owed, repo-relative.
pub(crate) const OWED_FILE: &str = "xtask/debug-owed.toml";

/// The answers, by the name of their type: kuserd's, the device daemon's, kuid's and the
/// inference daemon's answers; the app runner's output and its calls to the host, and the
/// host's ops and replies to the runner; a pairing payload another device sent, and the
/// joiner's answer at the end of pairing (`Answer`, the name the handshake responder's answer
/// also bears); the handshake initiator's reply to an ask for events; a contact's answer to a
/// delivery; a relay's answer to its operator; and a relay client's error, which carries the
/// relay's own words.
///
/// Every enum of the wire crate a `variant_names!` names, and every public one whose name ends
/// in `Response`, `Answer` or `Reply`, is here or in the tests' `NOT_ANSWERS`: a test reads the
/// wire crate and holds the two lists to it.
pub(crate) const ANSWERS: &[&str] = &[
    "UserResponse",
    "DeviceResponse",
    "KuidResponse",
    "RunnerOutput",
    "RunnerHostCall",
    "PairingPayload",
    "RendezvousError",
    "ContactResponse",
    "RelayOperatorResponse",
    "Answer",
    "AskReply",
    "RunnerHostReply",
    "RunnerOp",
    "InferResponse",
];

/// The answers `variant_names!` gives a `name()` and `kotton_wire::Named`, so `unasked` takes
/// them; a test holds this to the wire crate.
const NAMED: &[&str] = &["UserResponse", "DeviceResponse", "KuidResponse", "PairingPayload", "RunnerOp", "RunnerHostReply"];

/// The relay client's error, whose `Display` prints the relay's words through `quoted_cut`.
const RELAY_ERROR: &str = "RendezvousError";

/// The types whose type argument a declared type is read through.
// Each is the type's identifier, `stringify!`d: a name in code, not a word a person reads.
const WRAPPERS: &[&str] = &[
    stringify!(Option),
    stringify!(Result),
    stringify!(Box),
    stringify!(Arc),
    stringify!(Rc),
    stringify!(Vec),
    stringify!(VecDeque),
];

/// The methods an expression is read through: each answers the value it was called on, or a
/// borrow or copy of it.
const THROUGH: &[&str] = &["clone", "as_ref", "as_deref", "as_mut", "borrow", "to_owned", "unwrap", "expect"];

/// The `tracing` macros.
const TRACING: &[&str] = &[
    "trace", "debug", "info", "warn", "error", "event", "span", "trace_span", "debug_span", "info_span",
    "warn_span", "error_span",
];

/// The rule's other rows, ending every remedy.
const REST: &str = "another node's text through `kotton_wire::note::quoted_cut`, and this device's \
    own daemon's `Error` by its message as written";

/// What to say instead, where the answer's type is not known.
const REMEDY: &str = "Say an answer not asked for by its name and no field \
    (`kotton_wire::ipc::unasked(&answer)` for an answer `variant_names!` names, a name of its own \
    for one it does not), a relay client's error by its `Display`, another node's text through \
    `kotton_wire::note::quoted_cut`, and this device's own daemon's `Error` by its message as \
    written";

/// What to say instead of a `ty`, by what `ty` has.
fn remedy(ty: &str) -> String {
    let sayer = if NAMED.contains(&ty) {
        format!("Say a `{ty}` not asked for by its name and no field (`kotton_wire::ipc::unasked(&answer)` or `answer.name()`)")
    } else if ty == RELAY_ERROR {
        format!("Say a `{ty}` by its `Display`, which prints the relay's words through `kotton_wire::note::quoted_cut`")
    } else {
        format!(
            "Say a `{ty}` not asked for by a name of its own and no field (a word for each variant, as \
             `variant_names!` gives the wire's answers)"
        )
    };
    format!("{sayer}; {REST}")
}

/// What the line-marking pass appends to a macro's name, before the line.
const MARK: &str = "__debug_check_line_";

/// The macros of the `format!` family, and how many arguments come before the format string.
fn format_skip(name: &str) -> Option<usize> {
    match name {
        "format" | "format_args" | "print" | "println" | "eprint" | "eprintln" | "panic" | "unreachable" | "todo"
        | "unimplemented" | "anyhow" | "bail" => Some(0),
        "write" | "writeln" | "ensure" | "assert" | "debug_assert" => Some(1),
        "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne" => Some(2),
        _ => None,
    }
}

/// One `Debug` print of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) file: String,
    /// `None` where the line-marking pass did not reach the macro's name.
    pub(crate) line: Option<usize>,
    pub(crate) function: String,
    pub(crate) mac: String,
    /// The placeholder or field as written: `{:?}`, `{other:?}`, `answer = ?other`.
    pub(crate) form: String,
    pub(crate) expression: String,
    pub(crate) why: String,
    /// The answer's type, by name.
    pub(crate) ty: String,
}

impl Finding {
    fn key(&self) -> Key {
        (self.file.clone(), self.function.clone(), self.expression.clone())
    }

    fn at(&self) -> String {
        match self.line {
            Some(l) => format!("{}:{l}", self.file),
            None => format!("{} (line not placed)", self.file),
        }
    }

    /// The finding, worded, with the remedy.
    pub(crate) fn said(&self) -> String {
        format!(
            "{}: `{}!` in fn `{}` prints `{}` by Debug (`{}`), and {}. {}",
            self.at(),
            self.mac,
            self.function,
            self.expression,
            self.form,
            self.why,
            remedy(&self.ty)
        )
    }
}

/// What an owed entry is keyed by: file, enclosing function, expression.
type Key = (String, String, String);

// ---------------------------------------------------------------------------------------------
// Line marks

/// The words that are no macro's name, though `!(` may follow one (`if !(a && b)`).
const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false",
    "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self",
    "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "yield",
];

/// `src` with every macro invocation's name followed by [`MARK`] and its 1-based line.
fn mark(src: &str) -> String {
    let blanked = blank(src);
    let b = blanked.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = String::with_capacity(src.len() + src.len() / 8);
    let (mut last, mut line, mut i) = (0usize, 1usize, 0usize);
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if is_id(c) && (i == 0 || !is_id(b[i - 1])) {
            let mut j = i;
            while j < b.len() && is_id(b[j]) {
                j += 1;
            }
            if (c.is_ascii_alphabetic() || c == b'_') && !KEYWORDS.contains(&&blanked[i..j]) {
                let mut k = j;
                while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                    k += 1;
                }
                if b.get(k) == Some(&b'!') {
                    let mut m = k + 1;
                    while m < b.len() && b[m].is_ascii_whitespace() {
                        m += 1;
                    }
                    if matches!(b.get(m), Some(b'(' | b'[' | b'{')) {
                        out.push_str(&src[last..j]);
                        out.push_str(MARK);
                        out.push_str(&line.to_string());
                        last = j;
                    }
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out.push_str(&src[last..]);
    out
}

/// A macro's name without its mark, and the line the mark holds.
fn named(m: &Macro) -> Option<(String, Option<usize>)> {
    let s = m.path.segments.last()?.ident.to_string();
    Some(match s.split_once(MARK) {
        Some((n, l)) => (n.to_string(), l.parse().ok()),
        None => (s, None),
    })
}

// ---------------------------------------------------------------------------------------------
// Test code

/// Whether `attrs` hold only in a test build.
fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        let path = a.path();
        if path.segments.last().is_some_and(|s| s.ident == "test") {
            return true;
        }
        path.is_ident("cfg") && a.parse_args::<Meta>().is_ok_and(|m| requires_test(&m))
    })
}

/// Whether a `cfg` predicate holds only in a test build: `test`, or an `all(..)` holding one.
fn requires_test(m: &Meta) -> bool {
    match m {
        Meta::Path(p) => p.is_ident("test"),
        Meta::List(l) if l.path.is_ident("all") => l
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|ms| ms.iter().any(requires_test)),
        _ => false,
    }
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

fn impl_item_attrs(i: &ImplItem) -> &[Attribute] {
    match i {
        ImplItem::Const(x) => &x.attrs,
        ImplItem::Fn(x) => &x.attrs,
        ImplItem::Type(x) => &x.attrs,
        ImplItem::Macro(x) => &x.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(i: &TraitItem) -> &[Attribute] {
    match i {
        TraitItem::Const(x) => &x.attrs,
        TraitItem::Fn(x) => &x.attrs,
        TraitItem::Type(x) => &x.attrs,
        TraitItem::Macro(x) => &x.attrs,
        _ => &[],
    }
}

/// A `mod name;` declaration: the inline modules around it, its name, and its `#[path]`.
#[derive(Debug, Clone)]
struct ModDecl {
    inline: Vec<String>,
    name: String,
    path: Option<String>,
}

fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_string(),
        (_, true) => a.to_string(),
        _ => format!("{a}/{b}"),
    }
}

/// `path` with `.` and `..` components resolved.
fn normalise(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

/// The files `decl`, made in `file`, can name.
fn targets(file: &str, decl: &ModDecl) -> Vec<String> {
    let (dir, fname) = file.rsplit_once('/').unwrap_or(("", file));
    let stem = fname.strip_suffix(".rs").unwrap_or(fname);
    let owns = matches!(fname, "mod.rs" | "lib.rs" | "main.rs" | "build.rs")
        || dir == "bin"
        || dir.ends_with("/bin")
        || dir == "examples"
        || dir.ends_with("/examples");
    let base = if owns { dir.to_string() } else { join(dir, stem) };
    let inline = decl.inline.join("/");
    match &decl.path {
        Some(p) if decl.inline.is_empty() => vec![normalise(&join(dir, p))],
        Some(p) => vec![normalise(&join(&join(&base, &inline), p))],
        None => {
            let at = join(&base, &inline);
            vec![normalise(&join(&at, &format!("{}.rs", decl.name))), normalise(&join(&at, &format!("{}/mod.rs", decl.name)))]
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Types and patterns

/// The answer `ty` names, read through references, tuples, slices, arrays and [`WRAPPERS`].
fn carries(ty: &Type) -> Option<String> {
    match ty {
        Type::Reference(r) => carries(&r.elem),
        Type::Paren(p) => carries(&p.elem),
        Type::Group(g) => carries(&g.elem),
        Type::Slice(s) => carries(&s.elem),
        Type::Array(a) => carries(&a.elem),
        Type::Ptr(p) => carries(&p.elem),
        Type::Tuple(t) => t.elems.iter().find_map(carries),
        Type::Path(p) => {
            let last = p.path.segments.last()?;
            let name = last.ident.to_string();
            if ANSWERS.contains(&name.as_str()) {
                return Some(name);
            }
            if !WRAPPERS.contains(&name.as_str()) {
                return None;
            }
            let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
                return None;
            };
            args.args.iter().find_map(|a| match a {
                syn::GenericArgument::Type(t) => carries(t),
                _ => None,
            })
        }
        _ => None,
    }
}

/// The answer whose variant `path` names (`UserResponse::Ok`, `kotton_wire::UserResponse::Ok`).
fn variant_of(path: &syn::Path) -> Option<String> {
    let n = path.segments.len();
    if n < 2 {
        return None;
    }
    let ty = path.segments[n - 2].ident.to_string();
    ANSWERS.contains(&ty.as_str()).then_some(ty)
}

/// One step into a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// The `i`th field of a tuple variant, by the variant's name (`Ok(_)` is `("Ok", 0)`).
    Variant(String, usize),
    /// A named field of a struct pattern.
    Field(String, String),
    Index(usize),
    Slice,
}

/// Where in a pattern something is.
type Place = Vec<Step>;

fn last_name(path: &syn::Path) -> String {
    path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default()
}

fn member(m: &Member) -> String {
    match m {
        Member::Named(i) => i.to_string(),
        Member::Unnamed(i) => i.index.to_string(),
    }
}

fn deeper(at: &Place, step: Step) -> Place {
    let mut p = at.clone();
    p.push(step);
    p
}

/// Every place in `pat` where it names an answer's variant, and which answer.
fn answers_in(pat: &Pat, at: &Place, out: &mut Vec<(Place, String)>) {
    match pat {
        Pat::Path(p) => {
            if let Some(t) = variant_of(&p.path) {
                out.push((at.clone(), t));
            }
        }
        Pat::TupleStruct(p) => {
            if let Some(t) = variant_of(&p.path) {
                out.push((at.clone(), t));
            }
            let v = last_name(&p.path);
            for (i, e) in p.elems.iter().enumerate() {
                answers_in(e, &deeper(at, Step::Variant(v.clone(), i)), out);
            }
        }
        Pat::Struct(p) => {
            if let Some(t) = variant_of(&p.path) {
                out.push((at.clone(), t));
            }
            let v = last_name(&p.path);
            for f in &p.fields {
                answers_in(&f.pat, &deeper(at, Step::Field(v.clone(), member(&f.member))), out);
            }
        }
        Pat::Ident(p) => {
            if let Some((_, sub)) = &p.subpat {
                answers_in(sub, at, out);
            }
        }
        Pat::Or(p) => p.cases.iter().for_each(|c| answers_in(c, at, out)),
        Pat::Paren(p) => answers_in(&p.pat, at, out),
        Pat::Reference(p) => answers_in(&p.pat, at, out),
        Pat::Type(p) => answers_in(&p.pat, at, out),
        Pat::Tuple(p) => {
            for (i, e) in p.elems.iter().enumerate() {
                answers_in(e, &deeper(at, Step::Index(i)), out);
            }
        }
        Pat::Slice(p) => p.elems.iter().for_each(|e| answers_in(e, &deeper(at, Step::Slice), out)),
        _ => {}
    }
}

/// Every name `pat` binds, and where.
fn bindings(pat: &Pat, at: &Place, out: &mut Vec<(String, Place)>) {
    match pat {
        Pat::Ident(p) => {
            out.push((p.ident.to_string(), at.clone()));
            if let Some((_, sub)) = &p.subpat {
                bindings(sub, at, out);
            }
        }
        Pat::TupleStruct(p) => {
            let v = last_name(&p.path);
            for (i, e) in p.elems.iter().enumerate() {
                bindings(e, &deeper(at, Step::Variant(v.clone(), i)), out);
            }
        }
        Pat::Struct(p) => {
            let v = last_name(&p.path);
            for f in &p.fields {
                bindings(&f.pat, &deeper(at, Step::Field(v.clone(), member(&f.member))), out);
            }
        }
        Pat::Or(p) => p.cases.iter().for_each(|c| bindings(c, at, out)),
        Pat::Paren(p) => bindings(&p.pat, at, out),
        Pat::Reference(p) => bindings(&p.pat, at, out),
        Pat::Type(p) => bindings(&p.pat, at, out),
        Pat::Tuple(p) => {
            for (i, e) in p.elems.iter().enumerate() {
                bindings(e, &deeper(at, Step::Index(i)), out);
            }
        }
        Pat::Slice(p) => p.elems.iter().for_each(|e| bindings(e, &deeper(at, Step::Slice), out)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------
// Expressions

/// The single name `e` reads, through what [`THROUGH`] and the transparent forms allow.
fn root_ident(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(p) if p.qself.is_none() => p.path.get_ident().map(|i| i.to_string()),
        Expr::Reference(r) => root_ident(&r.expr),
        Expr::Paren(p) => root_ident(&p.expr),
        Expr::Group(g) => root_ident(&g.expr),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => root_ident(&u.expr),
        Expr::MethodCall(m) if THROUGH.contains(&m.method.to_string().as_str()) => root_ident(&m.receiver),
        _ => None,
    }
}

fn path_text(p: &syn::Path) -> String {
    let segs = p.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
    if p.leading_colon.is_some() {
        format!("::{segs}")
    } else {
        segs
    }
}

/// `e` as text, for the shapes [`Walker::known`] admits.
fn text(e: &Expr) -> String {
    match e {
        Expr::Path(p) => path_text(&p.path),
        Expr::Field(f) => format!("{}.{}", text(&f.base), member(&f.member)),
        Expr::Reference(r) => format!("&{}{}", if r.mutability.is_some() { "mut " } else { "" }, text(&r.expr)),
        Expr::Paren(p) => format!("({})", text(&p.expr)),
        Expr::Group(g) => text(&g.expr),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => format!("*{}", text(&u.expr)),
        Expr::Try(t) => format!("{}?", text(&t.expr)),
        Expr::MethodCall(m) => {
            format!("{}.{}({})", text(&m.receiver), m.method, if m.args.is_empty() { "" } else { ".." })
        }
        Expr::Call(c) => format!("{}(..)", text(&c.func)),
        Expr::Struct(s) => format!("{} {{ .. }}", path_text(&s.path)),
        _ => "..".to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Macro bodies

/// A format string and where its arguments are in [`Body`]'s expressions.
struct Fmt {
    lit: String,
    positional: Vec<usize>,
    named: Vec<(String, usize)>,
}

/// A macro's arguments, as read.
enum Body {
    Format { exprs: Vec<Expr>, fmt: Option<Fmt> },
    /// `debug` holds each `?expr` field: its name, if written, and the expression's index.
    Tracing { exprs: Vec<Expr>, debug: Vec<(Option<String>, usize)>, fmt: Option<Fmt> },
    Dbg { exprs: Vec<Expr> },
    Matches { exprs: Vec<Expr>, pat: Pat },
    Other { exprs: Vec<Expr>, stmts: Vec<Vec<Stmt>> },
}

impl Body {
    fn exprs(&self) -> &[Expr] {
        match self {
            Body::Format { exprs, .. }
            | Body::Tracing { exprs, .. }
            | Body::Dbg { exprs }
            | Body::Matches { exprs, .. }
            | Body::Other { exprs, .. } => exprs,
        }
    }

    fn stmts(&self) -> &[Vec<Stmt>] {
        match self {
            Body::Other { stmts, .. } => stmts,
            _ => &[],
        }
    }
}

/// The name a named argument's left side gives.
fn arg_name(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

/// The format arguments after the string, into `exprs` and `fmt`.
fn format_args(args: impl IntoIterator<Item = Expr>, exprs: &mut Vec<Expr>, fmt: &mut Fmt) {
    for e in args {
        match e {
            Expr::Assign(a) => match arg_name(&a.left) {
                Some(n) => {
                    fmt.named.push((n, exprs.len()));
                    exprs.push(*a.right);
                }
                None => exprs.push(Expr::Assign(a)),
            },
            e => {
                fmt.positional.push(exprs.len());
                exprs.push(e);
            }
        }
    }
}

fn format_body(input: ParseStream, skip: usize) -> syn::Result<Body> {
    let args = Punctuated::<Expr, Token![,]>::parse_terminated(input)?;
    let mut exprs = Vec::new();
    let mut iter = args.into_iter();
    for _ in 0..skip {
        match iter.next() {
            Some(e) => exprs.push(e),
            None => return Ok(Body::Format { exprs, fmt: None }),
        }
    }
    let Some(first) = iter.next() else {
        return Ok(Body::Format { exprs, fmt: None });
    };
    let lit = match &first {
        Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
        _ => None,
    };
    let Some(lit) = lit else {
        exprs.push(first);
        exprs.extend(iter);
        return Ok(Body::Format { exprs, fmt: None });
    };
    let mut fmt = Fmt { lit, positional: Vec::new(), named: Vec::new() };
    format_args(iter, &mut exprs, &mut fmt);
    Ok(Body::Format { exprs, fmt: Some(fmt) })
}

fn comma(input: ParseStream) -> syn::Result<()> {
    if !input.is_empty() {
        input.parse::<Token![,]>()?;
    }
    Ok(())
}

/// A `tracing` field's name: a string, or identifiers joined by `.`.
fn field_key(input: ParseStream) -> syn::Result<String> {
    if input.peek(LitStr) {
        return Ok(input.parse::<LitStr>()?.value());
    }
    let mut key = input.call(Ident::parse_any)?.to_string();
    while input.peek(Token![.]) {
        input.parse::<Token![.]>()?;
        key.push('.');
        key.push_str(&input.call(Ident::parse_any)?.to_string());
    }
    Ok(key)
}

fn tracing_body(input: ParseStream, name: &str) -> syn::Result<Body> {
    let mut exprs = Vec::new();
    let mut debug = Vec::new();
    let mut fmt = None;
    // `target: ..`, `parent: ..`, `name: ..`.
    while input.peek(Ident::peek_any) && input.peek2(Token![:]) && !input.peek2(Token![::]) {
        input.call(Ident::parse_any)?;
        input.parse::<Token![:]>()?;
        exprs.push(input.parse::<Expr>()?);
        comma(input)?;
    }
    if name == "event" || name == "span" {
        exprs.push(input.parse::<Expr>()?);
        comma(input)?;
    }
    if name.ends_with("span") && !input.is_empty() {
        exprs.push(input.parse::<Expr>()?);
        comma(input)?;
    }
    while !input.is_empty() {
        if input.peek(Token![?]) {
            input.parse::<Token![?]>()?;
            debug.push((None, exprs.len()));
            exprs.push(input.parse()?);
        } else if input.peek(Token![%]) {
            input.parse::<Token![%]>()?;
            exprs.push(input.parse()?);
        } else if input.peek(LitStr) && !input.peek2(Token![=]) {
            let lit: LitStr = input.parse()?;
            let mut f = Fmt { lit: lit.value(), positional: Vec::new(), named: Vec::new() };
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
                let rest = Punctuated::<Expr, Token![,]>::parse_terminated(input)?;
                format_args(rest, &mut exprs, &mut f);
            }
            fmt = Some(f);
            break;
        } else if input.peek(syn::token::Brace) {
            exprs.push(input.parse()?);
        } else {
            let key = field_key(input)?;
            if input.peek(Token![=]) && !input.peek(Token![==]) && !input.peek(Token![=>]) {
                input.parse::<Token![=]>()?;
                if input.peek(Token![?]) {
                    input.parse::<Token![?]>()?;
                    debug.push((Some(key), exprs.len()));
                    exprs.push(input.parse()?);
                } else if input.peek(Token![%]) {
                    input.parse::<Token![%]>()?;
                    exprs.push(input.parse()?);
                } else {
                    exprs.push(input.parse()?);
                }
            }
        }
        comma(input)?;
    }
    Ok(Body::Tracing { exprs, debug, fmt })
}

fn matches_body(input: ParseStream) -> syn::Result<Body> {
    let mut exprs = vec![input.parse::<Expr>()?];
    input.parse::<Token![,]>()?;
    let pat = Pat::parse_multi_with_leading_vert(input)?;
    if input.peek(Token![if]) {
        input.parse::<Token![if]>()?;
        exprs.push(input.parse()?);
    }
    comma(input)?;
    Ok(Body::Matches { exprs, pat })
}

/// Whatever in an unknown macro's tokens parses: the whole as a list of expressions or as
/// statements, or else each bracketed group, recursively.
fn scan(input: ParseStream, exprs: &mut Vec<Expr>, stmts: &mut Vec<Vec<Stmt>>) -> syn::Result<()> {
    let fork = input.fork();
    if let Ok(list) = Punctuated::<Expr, Token![,]>::parse_terminated(&fork) {
        input.advance_to(&fork);
        exprs.extend(list);
        return Ok(());
    }
    let fork = input.fork();
    if let Ok(s) = Block::parse_within(&fork) {
        if fork.is_empty() {
            input.advance_to(&fork);
            stmts.push(s);
            return Ok(());
        }
    }
    while !input.is_empty() {
        if input.peek(syn::token::Brace) {
            let c;
            syn::braced!(c in input);
            scan(&c, exprs, stmts)?;
        } else if input.peek(syn::token::Paren) {
            let c;
            syn::parenthesized!(c in input);
            scan(&c, exprs, stmts)?;
        } else if input.peek(syn::token::Bracket) {
            let c;
            syn::bracketed!(c in input);
            scan(&c, exprs, stmts)?;
        } else {
            input.step(|c| c.token_tree().map(|(_, rest)| ((), rest)).ok_or_else(|| c.error("no token")))?;
        }
    }
    Ok(())
}

fn other_body(m: &Macro) -> Body {
    m.parse_body_with(|input: ParseStream| {
        let (mut exprs, mut stmts) = (Vec::new(), Vec::new());
        scan(input, &mut exprs, &mut stmts)?;
        Ok(Body::Other { exprs, stmts })
    })
    .unwrap_or(Body::Other { exprs: Vec::new(), stmts: Vec::new() })
}

/// `m`'s arguments, and whether a macro of a family the check reads could not be read.
fn parse_body(name: &str, m: &Macro) -> (Body, bool) {
    if name == "macro_rules" {
        // A definition's body is not code until it is expanded, and its `$` fragments do not
        // parse: it is not read.
        return (Body::Other { exprs: Vec::new(), stmts: Vec::new() }, false);
    }
    let read = if let Some(skip) = format_skip(name) {
        Some(m.parse_body_with(|i: ParseStream| format_body(i, skip)))
    } else if TRACING.contains(&name) {
        Some(m.parse_body_with(|i: ParseStream| tracing_body(i, name)))
    } else if name == "dbg" {
        Some(
            m.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                .map(|p| Body::Dbg { exprs: p.into_iter().collect() }),
        )
    } else if name == "matches" {
        Some(m.parse_body_with(matches_body))
    } else {
        None
    };
    match read {
        Some(Ok(b)) => (b, false),
        Some(Err(_)) => (other_body(m), name != "matches"),
        None => (other_body(m), false),
    }
}

// ---------------------------------------------------------------------------------------------
// Format strings

#[derive(Debug, PartialEq)]
enum Arg {
    Next,
    Index(usize),
    Name(String),
}

#[derive(Debug, PartialEq)]
struct Placeholder {
    text: String,
    arg: Arg,
    /// A `.*` precision, which takes the next positional argument first.
    star: bool,
    debug: bool,
}

/// The placeholders of a format string, `{{` and `}}` aside.
fn placeholders(fmt: &str) -> Vec<Placeholder> {
    let mut out = Vec::new();
    let mut chars = fmt.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '}' {
            if chars.peek().is_some_and(|(_, n)| *n == '}') {
                chars.next();
            }
            continue;
        }
        if c != '{' {
            continue;
        }
        if chars.peek().is_some_and(|(_, n)| *n == '{') {
            chars.next();
            continue;
        }
        let mut end = None;
        for (j, d) in chars.by_ref() {
            if d == '}' {
                end = Some(j);
                break;
            }
        }
        let Some(end) = end else { break };
        let inner = &fmt[i + 1..end];
        let (arg, spec) = inner.split_once(':').unwrap_or((inner, ""));
        let arg = arg.trim();
        let arg = if arg.is_empty() {
            Arg::Next
        } else if let Ok(n) = arg.parse() {
            Arg::Index(n)
        } else {
            Arg::Name(arg.trim_start_matches("r#").to_string())
        };
        out.push(Placeholder {
            text: fmt[i..=end].to_string(),
            arg,
            star: spec.contains(".*"),
            debug: spec.ends_with('?'),
        });
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The walk

/// Names a function reads against an answer's variants, before it is walked.
#[derive(Default)]
struct Scrutinees {
    found: BTreeMap<String, String>,
}

impl Scrutinees {
    fn note(&mut self, e: &Expr, pats: &[&Pat]) {
        let mut a = Vec::new();
        for p in pats {
            answers_in(p, &Vec::new(), &mut a);
        }
        if let (Some(name), Some((_, ty))) = (root_ident(e), a.first()) {
            self.found.entry(name).or_insert_with(|| ty.clone());
        }
    }
}

impl<'ast> Visit<'ast> for Scrutinees {
    fn visit_item(&mut self, _: &'ast Item) {}

    fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
        let pats: Vec<&Pat> = m.arms.iter().map(|a| &a.pat).collect();
        self.note(&m.expr, &pats);
        visit::visit_expr_match(self, m);
    }

    fn visit_expr_let(&mut self, l: &'ast syn::ExprLet) {
        self.note(&l.expr, &[&l.pat]);
        visit::visit_expr_let(self, l);
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        if let Some(init) = &l.init {
            self.note(&init.expr, &[&l.pat]);
        }
        visit::visit_local(self, l);
    }

    fn visit_macro(&mut self, m: &'ast Macro) {
        let Some((name, _)) = named(m) else { return };
        let (body, _) = parse_body(&name, m);
        if let Body::Matches { exprs, pat } = &body {
            self.note(&exprs[0], &[pat]);
        }
        for e in body.exprs() {
            self.visit_expr(e);
        }
        for ss in body.stmts() {
            for s in ss {
                self.visit_stmt(s);
            }
        }
    }
}

/// Struct fields in a file declared with an answer's type: field name, then the answer.
#[derive(Default)]
struct Fields {
    map: BTreeMap<String, String>,
}

impl<'ast> Visit<'ast> for Fields {
    fn visit_item(&mut self, i: &'ast Item) {
        if !test_only(item_attrs(i)) {
            visit::visit_item(self, i);
        }
    }

    fn visit_item_struct(&mut self, s: &'ast syn::ItemStruct) {
        if let syn::Fields::Named(n) = &s.fields {
            for f in &n.named {
                if let (Some(id), Some(t)) = (&f.ident, carries(&f.ty)) {
                    self.map.insert(id.to_string(), t);
                }
            }
        }
    }
}

/// Why a binding or an expression is known to be an answer, and which answer.
#[derive(Debug, Clone)]
struct Why {
    why: String,
    ty: String,
}

impl Why {
    fn new(why: String, ty: &str) -> Self {
        Why { why, ty: ty.to_string() }
    }
}

/// One file's walk.
struct Walker {
    file: String,
    fields: BTreeMap<String, String>,
    /// Each scope's names: `Some(why)` for a binding known to be an answer, `None` for one
    /// that shadows a name.
    scopes: Vec<HashMap<String, Option<Why>>>,
    scrutinees: Vec<BTreeMap<String, String>>,
    fns: Vec<String>,
    impls: Vec<Option<String>>,
    inline: Vec<String>,
    findings: Vec<Finding>,
    unread: Vec<String>,
    test_mods: Vec<ModDecl>,
    mods: Vec<ModDecl>,
}

impl Walker {
    fn new(file: &str, fields: BTreeMap<String, String>) -> Self {
        Walker {
            file: file.to_string(),
            fields,
            scopes: vec![HashMap::new()],
            scrutinees: Vec::new(),
            fns: Vec::new(),
            impls: Vec::new(),
            inline: Vec::new(),
            findings: Vec::new(),
            unread: Vec::new(),
            test_mods: Vec::new(),
            mods: Vec::new(),
        }
    }

    fn push(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop(&mut self) {
        self.scopes.pop();
    }

    fn lookup(&self, name: &str) -> Option<Why> {
        self.scopes.iter().rev().find_map(|s| s.get(name)).cloned().flatten()
    }

    fn function_name(&self) -> String {
        self.fns.last().cloned().unwrap_or_else(|| "(no function)".to_string())
    }

    /// Why `e` is known to be an answer, with its text; `None` when it is not known.
    fn known(&self, e: &Expr) -> Option<(String, Why)> {
        let why = match e {
            Expr::Path(p) if p.qself.is_none() => match p.path.get_ident() {
                Some(id) => {
                    let name = id.to_string();
                    self.lookup(&name).map(|w| Why::new(format!("`{name}` {}", w.why), &w.ty))?
                }
                None => variant_of(&p.path).map(|t| Why::new(format!("`{}` names a `{t}`", path_text(&p.path)), &t))?,
            },
            Expr::Field(f) => {
                let Member::Named(m) = &f.member else { return None };
                let t = self.fields.get(&m.to_string())?;
                Why::new(format!("`{m}` is a field this file declares with `{t}`"), t)
            }
            Expr::Reference(r) => self.known(&r.expr)?.1,
            Expr::Paren(p) => self.known(&p.expr)?.1,
            Expr::Group(g) => self.known(&g.expr)?.1,
            Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => self.known(&u.expr)?.1,
            Expr::Try(t) => self.known(&t.expr)?.1,
            Expr::MethodCall(m) if THROUGH.contains(&m.method.to_string().as_str()) => self.known(&m.receiver)?.1,
            Expr::Call(c) => match &*c.func {
                Expr::Path(p) => variant_of(&p.path).map(|t| Why::new(format!("`{}` builds a `{t}`", path_text(&p.path)), &t))?,
                _ => return None,
            },
            Expr::Struct(s) => variant_of(&s.path).map(|t| Why::new(format!("`{}` builds a `{t}`", path_text(&s.path)), &t))?,
            _ => return None,
        };
        Some((text(e), why))
    }

    /// Bind the names of `pat` in the innermost scope.
    ///
    /// `ty` is the declared type, `answers` the places another pattern of the same `match`
    /// names an answer's variants, `whole` why the value bound is known, and `scrut` whether
    /// the function's scrutinees apply to a binding of the whole value.
    fn bind(&mut self, pat: &Pat, ty: Option<&Type>, answers: &[(Place, String)], whole: Option<Why>, scrut: bool) {
        if let (None, Pat::Type(t)) = (ty, pat) {
            return self.bind(&t.pat, Some(&t.ty), answers, whole, scrut);
        }
        let declared = ty.and_then(carries);
        let mut here = answers.to_vec();
        answers_in(pat, &Vec::new(), &mut here);
        let mut names = Vec::new();
        bindings(pat, &Vec::new(), &mut names);
        for (name, place) in names {
            let mut why = None;
            if place.is_empty() {
                why = declared
                    .as_ref()
                    .map(|t| Why::new(format!("is declared as `{t}`"), t))
                    .or_else(|| whole.as_ref().map(|w| Why::new(format!("is bound to the value matched, and {}", w.why), &w.ty)))
                    .or_else(|| {
                        if !scrut {
                            return None;
                        }
                        let t = self.scrutinees.last()?.get(&name)?;
                        Some(Why::new(format!("is read against `{t}`'s variants in fn `{}`", self.function_name()), t))
                    });
            }
            if why.is_none() {
                why = here
                    .iter()
                    .find(|(q, _)| q.starts_with(&place))
                    .map(|(_, t)| Why::new(format!("is bound where a pattern of the same match names `{t}`'s variants"), t));
            }
            if let Some(top) = self.scopes.last_mut() {
                top.insert(name, why);
            }
        }
    }

    fn function(&mut self, sig: &syn::Signature, block: &Block) {
        let mut s = Scrutinees::default();
        s.visit_block(block);
        let outer = std::mem::replace(&mut self.scopes, vec![HashMap::new()]);
        self.scrutinees.push(s.found);
        self.fns.push(sig.ident.to_string());
        for input in &sig.inputs {
            match input {
                FnArg::Receiver(_) => {
                    let why = self.impls.last().cloned().flatten().map(|t| Why::new(format!("is the `{t}` its impl is for"), &t));
                    if let Some(top) = self.scopes.last_mut() {
                        top.insert("self".to_string(), why);
                    }
                }
                FnArg::Typed(t) => self.bind(&t.pat, Some(&t.ty), &[], None, true),
            }
        }
        self.visit_block(block);
        self.fns.pop();
        self.scrutinees.pop();
        self.scopes = outer;
    }

    fn condition(&mut self, e: &Expr) {
        match e {
            Expr::Let(l) => {
                self.visit_expr(&l.expr);
                let whole = self.known(&l.expr).map(|(_, w)| w);
                self.bind(&l.pat, None, &[], whole, false);
            }
            Expr::Binary(b) if matches!(b.op, syn::BinOp::And(_)) => {
                self.condition(&b.left);
                self.condition(&b.right);
            }
            other => self.visit_expr(other),
        }
    }

    fn decl(&self, m: &ItemMod) -> ModDecl {
        let path = m.attrs.iter().find(|a| a.path().is_ident("path")).and_then(|a| match &a.meta {
            Meta::NameValue(nv) => match &nv.value {
                Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        });
        ModDecl { inline: self.inline.clone(), name: m.ident.to_string(), path }
    }

    fn found(&mut self, mac: &str, line: Option<usize>, form: String, (expression, why): (String, Why)) {
        self.findings.push(Finding {
            file: self.file.clone(),
            line,
            function: self.function_name(),
            mac: mac.to_string(),
            form,
            expression,
            why: why.why,
            ty: why.ty,
        });
    }

    fn format_string(&mut self, mac: &str, line: Option<usize>, fmt: &Fmt, exprs: &[Expr]) {
        let mut next = 0;
        for ph in placeholders(&fmt.lit) {
            if ph.star {
                next += 1;
            }
            let at = match &ph.arg {
                Arg::Next => {
                    next += 1;
                    fmt.positional.get(next - 1).map(|&i| Ok(i))
                }
                Arg::Index(n) => fmt.positional.get(*n).map(|&i| Ok(i)),
                Arg::Name(n) => Some(fmt.named.iter().find(|(k, _)| k == n).map(|(_, i)| *i).ok_or(n.clone())),
            };
            if !ph.debug {
                continue;
            }
            let known = match at {
                Some(Ok(i)) => self.known(&exprs[i]),
                Some(Err(name)) => self.lookup(&name).map(|w| (name.clone(), Why::new(format!("`{name}` {}", w.why), &w.ty))),
                None => None,
            };
            if let Some(k) = known {
                self.found(mac, line, ph.text, k);
            }
        }
    }

    fn mac(&mut self, m: &Macro) {
        let Some((name, line)) = named(m) else { return };
        let (body, unread) = parse_body(&name, m);
        if unread {
            let at = line.map_or_else(|| format!("{} (line not placed)", self.file), |l| format!("{}:{l}", self.file));
            self.unread.push(format!(
                "{at}: the arguments of `{name}!` in fn `{}` do not parse, so whether it prints an answer by \
                 Debug cannot be told: write them as the macro's own syntax gives them",
                self.function_name()
            ));
        }
        match &body {
            Body::Format { exprs, fmt: Some(f) } => self.format_string(&name, line, f, exprs),
            Body::Tracing { exprs, debug, fmt } => {
                for (key, i) in debug {
                    if let Some(k) = self.known(&exprs[*i]) {
                        let form = match key {
                            Some(key) => format!("{key} = ?{}", k.0),
                            None => format!("?{}", k.0),
                        };
                        self.found(&name, line, form, k);
                    }
                }
                if let Some(f) = fmt {
                    self.format_string(&name, line, f, exprs);
                }
            }
            Body::Dbg { exprs } => {
                for e in exprs {
                    if let Some(k) = self.known(e) {
                        self.found(&name, line, format!("dbg!({})", k.0), k);
                    }
                }
            }
            _ => {}
        }
        for e in body.exprs() {
            self.visit_expr(e);
        }
        for ss in body.stmts() {
            self.push();
            for s in ss {
                self.visit_stmt(s);
            }
            self.pop();
        }
    }
}

impl<'ast> Visit<'ast> for Walker {
    fn visit_item(&mut self, i: &'ast Item) {
        if test_only(item_attrs(i)) {
            if let Item::Mod(m) = i {
                if m.content.is_none() {
                    let d = self.decl(m);
                    self.test_mods.push(d);
                }
            }
            return;
        }
        visit::visit_item(self, i);
    }

    fn visit_item_mod(&mut self, m: &'ast ItemMod) {
        if m.content.is_none() {
            let d = self.decl(m);
            self.mods.push(d);
            return;
        }
        self.inline.push(m.ident.to_string());
        visit::visit_item_mod(self, m);
        self.inline.pop();
    }

    fn visit_impl_item(&mut self, i: &'ast ImplItem) {
        if !test_only(impl_item_attrs(i)) {
            visit::visit_impl_item(self, i);
        }
    }

    fn visit_trait_item(&mut self, i: &'ast TraitItem) {
        if !test_only(trait_item_attrs(i)) {
            visit::visit_trait_item(self, i);
        }
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let ty = match &*i.self_ty {
            Type::Path(p) => p
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .filter(|n| ANSWERS.contains(&n.as_str())),
            _ => None,
        };
        self.impls.push(ty);
        visit::visit_item_impl(self, i);
        self.impls.pop();
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.function(&f.sig, &f.block);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.function(&f.sig, &f.block);
    }

    fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
        if let Some(b) = &f.default {
            self.function(&f.sig, b);
        }
    }

    fn visit_block(&mut self, b: &'ast Block) {
        self.push();
        visit::visit_block(self, b);
        self.pop();
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        match s {
            Stmt::Local(l) if test_only(&l.attrs) => {}
            Stmt::Macro(m) if test_only(&m.attrs) => {}
            s => visit::visit_stmt(self, s),
        }
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        let mut whole = None;
        if let Some(init) = &l.init {
            self.visit_expr(&init.expr);
            if let Some((_, d)) = &init.diverge {
                self.visit_expr(d);
            }
            whole = self.known(&init.expr).map(|(_, w)| w);
        }
        self.bind(&l.pat, None, &[], whole, true);
    }

    fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
        self.visit_expr(&m.expr);
        let whole = self.known(&m.expr).map(|(_, w)| w);
        let mut answers = Vec::new();
        for arm in &m.arms {
            answers_in(&arm.pat, &Vec::new(), &mut answers);
        }
        for arm in &m.arms {
            self.push();
            self.bind(&arm.pat, None, &answers, whole.clone(), false);
            if let Some((_, g)) = &arm.guard {
                self.visit_expr(g);
            }
            self.visit_expr(&arm.body);
            self.pop();
        }
    }

    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        self.push();
        self.condition(&e.cond);
        self.visit_block(&e.then_branch);
        self.pop();
        if let Some((_, els)) = &e.else_branch {
            self.visit_expr(els);
        }
    }

    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        self.push();
        self.condition(&e.cond);
        self.visit_block(&e.body);
        self.pop();
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        self.visit_expr(&e.expr);
        let whole = self.known(&e.expr).map(|(_, w)| w);
        self.push();
        self.bind(&e.pat, None, &[], whole, false);
        self.visit_block(&e.body);
        self.pop();
    }

    fn visit_expr_closure(&mut self, c: &'ast syn::ExprClosure) {
        self.push();
        for p in &c.inputs {
            self.bind(p, None, &[], None, true);
        }
        self.visit_expr(&c.body);
        self.pop();
    }

    fn visit_macro(&mut self, m: &'ast Macro) {
        self.mac(m);
    }
}

// ---------------------------------------------------------------------------------------------
// The tree

/// What one file's walk found.
struct Walked {
    findings: Vec<Finding>,
    unread: Vec<String>,
    test_targets: Vec<String>,
    targets: Vec<String>,
    whole_test: bool,
}

fn walk_file(path: &str, src: &str) -> Result<Walked, String> {
    let file = syn::parse_file(&mark(src)).map_err(|e| {
        format!("{path}: does not parse ({e}), so debug-check cannot read it: every source outside tests is read")
    })?;
    let mut fields = Fields::default();
    fields.visit_file(&file);
    let mut w = Walker::new(path, fields.map);
    let whole_test = test_only(&file.attrs);
    if !whole_test {
        w.visit_file(&file);
    }
    Ok(Walked {
        findings: w.findings,
        unread: w.unread,
        test_targets: w.test_mods.iter().flat_map(|d| targets(path, d)).collect(),
        targets: w.mods.iter().flat_map(|d| targets(path, d)).collect(),
        whole_test,
    })
}

/// What [`read`] found over a set of files.
#[derive(Debug, Default)]
pub(crate) struct Read {
    pub(crate) files: usize,
    pub(crate) test_files: usize,
    pub(crate) findings: Vec<Finding>,
    pub(crate) refused: Vec<String>,
}

/// Every finding over `files`, as (repo-relative path, contents), test code aside.
pub(crate) fn read(files: &[(String, String)]) -> Read {
    let mut read = Read::default();
    let mut walked = BTreeMap::new();
    let mut unparsed = Vec::new();
    for (path, src) in files {
        if is_test_file(path) {
            read.test_files += 1;
            continue;
        }
        match walk_file(path, src) {
            Ok(w) => {
                walked.insert(path.clone(), w);
            }
            Err(e) => unparsed.push((path.clone(), e)),
        }
    }
    let mut test: BTreeSet<String> = walked
        .iter()
        .filter(|(_, w)| w.whole_test)
        .map(|(p, _)| p.clone())
        .chain(walked.values().flat_map(|w| w.test_targets.iter().cloned()))
        .collect();
    loop {
        let more: Vec<String> = test
            .iter()
            .filter_map(|f| walked.get(f))
            .flat_map(|w| w.targets.iter().cloned())
            .filter(|t| !test.contains(t))
            .collect();
        if more.is_empty() {
            break;
        }
        test.extend(more);
    }
    for (path, e) in unparsed {
        if test.contains(&path) {
            read.test_files += 1;
        } else {
            read.refused.push(e);
        }
    }
    for (path, w) in walked {
        if test.contains(&path) {
            read.test_files += 1;
            continue;
        }
        read.files += 1;
        read.findings.extend(w.findings);
        read.refused.extend(w.unread);
    }
    read
}

/// Every `.rs` file git tracks under the code roots, with its contents.
fn tracked_sources(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut args = vec!["ls-files", "-z", "--cached", "--"];
    args.extend(crate::tree::CODE_ROOTS);
    let listed = git(root, &args)?;
    let mut out = Vec::new();
    for path in listed.split('\0').filter(|p| p.ends_with(".rs")) {
        let src = std::fs::read_to_string(root.join(path)).map_err(|e| format!("{path}: {e}"))?;
        out.push((path.to_string(), src));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// The owed list

/// One owed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Owe {
    pub(crate) file: String,
    pub(crate) function: String,
    pub(crate) expression: String,
    pub(crate) sites: usize,
    pub(crate) row: String,
}

impl Owe {
    fn key(&self) -> Key {
        (self.file.clone(), self.function.clone(), self.expression.clone())
    }

    fn named(&self) -> String {
        format!("{} fn `{}` `{}`", self.file, self.function, self.expression)
    }
}

/// Parse [`OWED_FILE`]: `[[owed]]` tables, each with `file`, `function`, `expression`,
/// `sites` and `row`, no key twice.
pub(crate) fn parse_owed(text: &str) -> Result<Vec<Owe>, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("{OWED_FILE} is not TOML: {e}"))?;
    if let Some(k) = table.keys().find(|k| *k != "owed") {
        return Err(format!("{OWED_FILE}: `{k}` is not `owed`, the one list it holds"));
    }
    let Some(list) = table.get("owed") else { return Ok(Vec::new()) };
    let Value::Array(list) = list else {
        return Err(format!("{OWED_FILE}: `owed` is not a list of [[owed]] tables"));
    };
    let mut out: Vec<Owe> = Vec::new();
    for (n, e) in list.iter().enumerate() {
        let n = n + 1;
        let Value::Table(t) = e else {
            return Err(format!("{OWED_FILE}: entry {n} is not a table"));
        };
        if let Some(k) = t.keys().find(|k| !["file", "function", "expression", "sites", "row"].contains(&k.as_str())) {
            return Err(format!("{OWED_FILE}: entry {n} holds `{k}`, which no entry holds"));
        }
        let s = |k: &str| match t.get(k) {
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
            _ => Err(format!("{OWED_FILE}: entry {n} has no `{k}` string")),
        };
        let (file, function, expression) = (s("file")?, s("function")?, s("expression")?);
        let sites = match t.get("sites") {
            Some(Value::Integer(i)) if *i >= 1 => *i as usize,
            _ => return Err(format!("{OWED_FILE}: entry {n} has no `sites` count of one or more")),
        };
        let owe = Owe { file, function, expression, sites, row: s("row")? };
        if out.iter().any(|o| o.key() == owe.key()) {
            return Err(format!("{OWED_FILE}: {} is listed twice", owe.named()));
        }
        out.push(owe);
    }
    Ok(out)
}

/// The owed list at the merge base with `origin/main`.
#[derive(Debug, PartialEq)]
pub(crate) enum Base {
    At { commit: String, owed: Vec<Owe> },
    /// Neither the merge base nor `origin/main` holds [`OWED_FILE`]: the file is arriving, and
    /// [`check`] compares it with what the check finds on the merge base's tree.
    Arriving { commit: String },
    /// Whether the list grew cannot be judged, and why.
    Unknown(String),
}

/// The list the sites `findings` would need: one entry per key, with its count.
pub(crate) fn owed_of(findings: &[Finding]) -> Vec<Owe> {
    let mut counts: BTreeMap<Key, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.key()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((file, function, expression), sites)| Owe {
            file,
            function,
            expression,
            sites,
            row: "found on the merge base's tree".to_string(),
        })
        .collect()
}

/// Every `.rs` file under the code roots at `commit`, with its contents, read from git objects.
fn sources_at(root: &Path, commit: &str) -> Result<Vec<(String, String)>, String> {
    use std::io::{BufRead, Read as _, Write as _};
    let mut args = vec!["ls-tree", "-r", "-z", "--name-only", commit, "--"];
    args.extend(crate::tree::CODE_ROOTS);
    let listed = git(root, &args)?;
    let paths: Vec<&str> = listed.split('\0').filter(|p| p.ends_with(".rs")).collect();
    let mut child = std::process::Command::new("git")
        .current_dir(root)
        .args(["cat-file", "--batch"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("git cat-file --batch: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("git cat-file --batch: no stdin")?;
    let request: String = paths.iter().map(|p| format!("{commit}:{p}\n")).collect();
    let writer = std::thread::spawn(move || stdin.write_all(request.as_bytes()));
    let mut out = std::io::BufReader::new(child.stdout.take().ok_or("git cat-file --batch: no stdout")?);
    let mut files = Vec::new();
    for p in &paths {
        let mut header = String::new();
        out.read_line(&mut header).map_err(|e| format!("git cat-file --batch: {e}"))?;
        let size: usize = header
            .split_whitespace()
            .nth(2)
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| format!("git cat-file --batch: {p}: {}", header.trim()))?;
        let mut body = vec![0; size + 1];
        out.read_exact(&mut body).map_err(|e| format!("git cat-file --batch: {e}"))?;
        body.pop();
        files.push((p.to_string(), String::from_utf8_lossy(&body).into_owned()));
    }
    writer.join().map_err(|_| "git cat-file --batch: the writer failed")?.map_err(|e| format!("git cat-file --batch: {e}"))?;
    child.wait().map_err(|e| format!("git cat-file --batch: {e}"))?;
    Ok(files)
}

/// The owed list at the merge base of `HEAD` with `origin/main`, read from git objects.
pub(crate) fn base_owed(root: &Path) -> Base {
    let commit = match merge_base(root) {
        Ok(c) => c,
        Err(e) => return Base::Unknown(e),
    };
    match file_at(root, &commit, OWED_FILE) {
        Err(e) => Base::Unknown(e),
        Ok(Some(t)) => match parse_owed(&t) {
            Ok(owed) => Base::At { commit, owed },
            Err(e) => Base::Unknown(format!("at {}: {e}", short(&commit))),
        },
        Ok(None) => match file_at(root, MAIN_REF, OWED_FILE) {
            Err(e) => Base::Unknown(e),
            Ok(None) => Base::Arriving { commit },
            Ok(Some(_)) => Base::Unknown(format!("{} has no {OWED_FILE}, and {MAIN_REF} has one", short(&commit))),
        },
    }
}

/// What is refused of `findings` against `owed` and the merge base's list.
pub(crate) fn judge(findings: &[Finding], owed: &[Owe], base: &Base) -> Vec<String> {
    let mut refused = Vec::new();
    let mut by_key: BTreeMap<Key, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_key.entry(f.key()).or_default().push(f);
    }
    for (key, fs) in &by_key {
        if !owed.iter().any(|o| o.key() == *key) {
            refused.extend(fs.iter().map(|f| f.said()));
        }
    }
    for o in owed {
        let fs = by_key.get(&o.key()).map(Vec::as_slice).unwrap_or(&[]);
        let n = fs.len();
        if n == 0 {
            refused.push(format!(
                "the owed entry {} covers no site: nothing there prints `{}` by Debug now, so delete the \
                 entry from {OWED_FILE}",
                o.named(),
                o.expression
            ));
        } else if n < o.sites {
            refused.push(format!(
                "the owed entry {} owes {} sites and {n} print it by Debug now: set `sites = {n}` in {OWED_FILE}",
                o.named(),
                o.sites
            ));
        } else if n > o.sites {
            let at: Vec<String> = fs.iter().map(|f| f.at()).collect();
            refused.push(format!(
                "the owed entry {} owes {} sites, and {n} print it by Debug ({}): a site is new, and no entry \
                 owes it. {}",
                o.named(),
                o.sites,
                at.join(", "),
                remedy(&fs[0].ty)
            ));
        }
    }
    match base {
        Base::Unknown(why) => refused.push(format!(
            "{OWED_FILE} cannot be compared with the merge base with {MAIN_REF}, so whether it grew cannot \
             be judged: {why}. Fetch, and merge {MAIN_REF} into the branch, so the merge base is main's tip"
        )),
        Base::Arriving { commit } => refused.push(format!(
            "{OWED_FILE} is arriving at {}, and what the check finds on that tree was not read, so \
             whether the list grew cannot be judged",
            short(commit)
        )),
        Base::At { commit, owed: there } => {
            for o in owed {
                match there.iter().find(|b| b.key() == o.key()) {
                    None => refused.push(format!(
                        "the owed entry {} is not owed at the merge base {}: the list only shrinks, so say \
                         the answer as the rule says and delete the entry. {REMEDY}",
                        o.named(),
                        short(commit)
                    )),
                    Some(b) if o.sites > b.sites => refused.push(format!(
                        "the owed entry {} owes {} sites, and the merge base {} owes {}: the list only \
                         shrinks. {REMEDY}",
                        o.named(),
                        o.sites,
                        short(commit),
                        b.sites
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    refused
}

/// What a run found.
#[derive(Debug, Default)]
pub(crate) struct Report {
    pub(crate) read: Read,
    pub(crate) owed: Vec<Owe>,
    pub(crate) arriving: bool,
    pub(crate) refused: Vec<String>,
}

/// The tree at `root`, read and judged.
pub(crate) fn check(root: &Path) -> Report {
    let mut report = Report::default();
    let files = match tracked_sources(root) {
        Ok(f) => f,
        Err(e) => {
            report.refused.push(format!("{e}: debug-check cannot tell which sources the tree holds"));
            return report;
        }
    };
    if files.is_empty() {
        report.refused.push(
            "found no .rs file under the code roots: a check that reads nothing does not pass. Run it from \
             the repository's root"
                .to_string(),
        );
        return report;
    }
    report.read = read(&files);
    report.refused.extend(report.read.refused.iter().cloned());
    let owed = match std::fs::read_to_string(root.join(OWED_FILE))
        .map_err(|e| format!("{OWED_FILE}: {e}"))
        .and_then(|t| parse_owed(&t))
    {
        Ok(o) => o,
        Err(e) => {
            report.refused.push(e);
            return report;
        }
    };
    let base = match base_owed(root) {
        Base::Arriving { commit } => {
            report.arriving = true;
            match sources_at(root, &commit) {
                Ok(files) => Base::At { owed: owed_of(&read(&files).findings), commit },
                Err(e) => Base::Unknown(format!("the sources at {} cannot be read: {e}", short(&commit))),
            }
        }
        b => b,
    };
    report.refused.extend(judge(&report.read.findings, &owed, &base));
    report.owed = owed;
    report
}

pub fn run(root: &Path) {
    let report = check(root);
    println!(
        "debug-check: {} source(s) read, {} test source(s) set aside; owed ({}):",
        report.read.files,
        report.read.test_files,
        report.owed.iter().map(|o| o.sites).sum::<usize>()
    );
    for o in &report.owed {
        println!("  {} ({} site(s)): {}", o.named(), o.sites, o.row);
    }
    if report.arriving {
        println!(
            "  {OWED_FILE} is arriving: neither the merge base nor {MAIN_REF} holds it, so it is held to \
             what the check finds on the merge base's tree"
        );
    }
    if report.refused.is_empty() {
        println!(
            "debug-check: OK: no `Debug` of a value the check knows to be one of the {} listed answer \
             types, outside tests and the owed list.",
            ANSWERS.len()
        );
        return;
    }
    eprintln!("debug-check: {} refused:\n", report.refused.len());
    for r in &report.refused {
        eprintln!("  {r}\n");
    }
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_fixture::Repo;

    const AT: &str = "core/x/src/lib.rs";

    fn found(src: &str) -> Vec<Finding> {
        let r = read(&[(AT.to_string(), src.to_string())]);
        assert!(r.refused.is_empty(), "{:?}", r.refused);
        r.findings
    }

    /// The one finding over `src`, its words holding `file:line` and the remedy.
    fn one(src: &str, line: usize) -> Finding {
        let f = found(src);
        assert_eq!(f.len(), 1, "{f:?}");
        let said = f[0].said();
        assert!(said.starts_with(&format!("{AT}:{line}: ")), "{said}");
        assert!(said.ends_with(&remedy(&f[0].ty)), "{said}");
        assert!(said.contains("kotton_wire::note::quoted_cut"), "{said}");
        f[0].clone()
    }

    #[test]
    fn a_positional_debug_of_a_declared_answer_is_refused() {
        let f = one("fn f(r: &UserResponse) -> String {\n    format!(\"got {:?}\", r)\n}\n", 2);
        assert_eq!((f.mac.as_str(), f.form.as_str(), f.expression.as_str(), f.function.as_str()), ("format", "{:?}", "r", "f"));
        assert!(f.why.contains("`r` is declared as `UserResponse`"), "{}", f.why);
    }

    #[test]
    fn an_inline_captured_debug_of_a_catch_all_is_refused() {
        let src = "fn g(a: u8) -> String {\n    match ask(a) {\n        UserResponse::Ok => String::new(),\n        \
                   other => format!(\"answered {other:?}\"),\n    }\n}\n";
        let f = one(src, 4);
        assert_eq!((f.form.as_str(), f.expression.as_str()), ("{other:?}", "other"));
        assert!(f.why.contains("names `UserResponse`'s variants"), "{}", f.why);
    }

    #[test]
    fn a_named_and_a_pretty_debug_are_refused() {
        let f = one("fn f(answer: Option<DeviceResponse>) {\n    println!(\"{a:?}\", a = answer);\n}\n", 2);
        assert_eq!((f.form.as_str(), f.expression.as_str()), ("{a:?}", "answer"));
        let f = one("fn f(k: Arc<KuidResponse>) {\n    let s = format!(\"{} {:#?}\", 1, k);\n}\n", 2);
        assert_eq!((f.form.as_str(), f.expression.as_str()), ("{:#?}", "k"));
        let f = one("fn f(k: KuidResponse, w: usize) {\n    let s = format!(\"{:.*} {1:?}\", 2, k);\n}\n", 2);
        assert_eq!(f.expression, "k");
        let f = one("fn f(k: KuidResponse) {\n    let s = format!(\"{:.*} {:?}\", 2, 1.5, k);\n}\n", 2);
        assert_eq!(f.expression, "k");
    }

    #[test]
    fn a_tracing_field_by_debug_is_refused() {
        let src = "fn f(r: RunnerOutput) {\n    tracing::warn!(relay = %x, answer = ?r, \"gone\");\n}\n";
        let f = one(src, 2);
        assert_eq!((f.mac.as_str(), f.form.as_str()), ("warn", "answer = ?r"));
        let f = one("fn f(r: RunnerHostCall) {\n    info!(?r);\n}\n", 2);
        assert_eq!(f.form, "?r");
        let f = one("fn f(r: PairingPayload) {\n    event!(target: \"x\", Level::WARN, ?r);\n}\n", 2);
        assert_eq!(f.form, "?r");
        let f = one("fn f(r: RendezvousError) {\n    debug!(target: \"t\", \"saw {:?}\", r);\n}\n", 2);
        assert_eq!(f.form, "{:?}");
        let f = one("fn f(r: UserResponse) {\n    let s = info_span!(\"s\", r = ?r);\n}\n", 2);
        assert_eq!(f.form, "r = ?r");
    }

    #[test]
    fn the_rest_of_the_format_family_is_read() {
        for (body, mac) in [
            ("write!(w, \"{r:?}\")", "write"),
            ("writeln!(w, \"{:?}\", r)", "writeln"),
            ("panic!(\"{r:?}\")", "panic"),
            ("anyhow::bail!(\"{r:?}\")", "bail"),
            ("ensure!(ok, \"{r:?}\")", "ensure"),
            ("anyhow!(\"{r:?}\")", "anyhow"),
            ("eprintln!(\"{r:?}\")", "eprintln"),
            ("format_args!(\"{r:?}\")", "format_args"),
            ("dbg!(r)", "dbg"),
        ] {
            let f = one(&format!("fn f(r: UserResponse) {{\n    {body};\n}}\n"), 2);
            assert_eq!(f.mac, mac, "{body}");
        }
    }

    #[test]
    fn each_way_an_answer_is_known_is_read() {
        // A field of a struct in the same file.
        let f = one("struct S { answer: UserResponse }\nfn f(s: S) {\n    warn!(?s.answer);\n}\n", 3);
        assert_eq!(f.expression, "s.answer");
        // A name `matches!` reads against an answer's variants.
        let src = "fn f() {\n    let answer = set();\n    if matches!(answer, UserResponse::Ok) {\n    } else {\n        \
                   warn!(answer = ?answer, \"not set\");\n    }\n}\n";
        let f = one(src, 5);
        assert!(f.why.contains("is read against `UserResponse`'s variants in fn `f`"), "{}", f.why);
        // `@`, and a catch-all inside a wrapper.
        one("fn f() {\n    if let a @ UserResponse::Ok = go() {\n        println!(\"{a:?}\");\n    }\n}\n", 3);
        let src = "fn f() {\n    match go() {\n        Ok(UserResponse::Ok) => {}\n        Ok(other) => panic!(\"{other:?}\"),\n        \
                   Err(e) => panic!(\"{e:?}\"),\n    }\n}\n";
        assert_eq!(one(src, 4).expression, "other");
        // A closure parameter, through a reference and a method.
        one("fn f() {\n    let p = |r: &UserResponse| format!(\"{:?}\", r.clone());\n}\n", 2);
        // `self` in an answer's impl, and a built answer.
        one("impl UserResponse {\n    fn said(&self) -> String {\n        format!(\"{self:?}\")\n    }\n}\n", 3);
        one("fn f() {\n    let s = format!(\"{:?}\", UserResponse::Ok);\n}\n", 2);
        // Nested in another macro's arguments.
        one("fn f(r: UserResponse) {\n    let v = vec![format!(\"{r:?}\")];\n}\n", 2);
    }

    #[test]
    fn what_is_not_an_answer_or_not_by_debug_passes() {
        let src = "fn f(e: std::io::Error, rule: Rule, r: UserResponse) {\n    \
                   tracing::info!(name, rule = ?rule, error = ?e, \"set\");\n    \
                   let s = format!(\"{e:?} {} {}\", r.name(), kotton_wire::ipc::unasked(&r));\n    \
                   tracing::warn!(answer = %r.name(), %r, \"{}\", r);\n    \
                   match ask() {\n        UserResponse::Error { message } => println!(\"{message:?}\"),\n        \
                   other => println!(\"{}\", unasked(&other)),\n    }\n    \
                   match other_thing() {\n        Thing::A => {}\n        other => println!(\"{other:?}\"),\n    }\n    \
                   let r = 5;\n    println!(\"{r:?}\");\n}\n";
        assert_eq!(found(src), Vec::new());
    }

    #[test]
    fn a_debug_in_test_code_passes() {
        let src = "fn real() {}\n\n#[cfg(test)]\nmod tests {\n    fn t(r: UserResponse) { panic!(\"{r:?}\") }\n}\n\n\
                   #[test]\nfn alone(r: UserResponse) { panic!(\"{r:?}\") }\n\n\
                   #[cfg(all(test, unix))]\nfn unix(r: UserResponse) { panic!(\"{r:?}\") }\n";
        assert_eq!(found(src), Vec::new());
        // `any(test, ..)` is compiled outside tests too.
        one("#[cfg(any(test, feature = \"x\"))]\nfn f(r: UserResponse) {\n    panic!(\"{r:?}\")\n}\n", 3);
        // A file brought in by a `#[cfg(test)] mod`, one it declares, and one under `tests/`.
        let printing = "fn t(r: UserResponse) { panic!(\"{r:?}\") }\nmod deeper;\n";
        let r = read(&[
            ("core/x/src/lib.rs".into(), "#[cfg(test)]\nmod a_tests;\n#[cfg(test)]\n#[path = \"b.rs\"]\nmod b;\nmod c;\n".into()),
            ("core/x/src/a_tests.rs".into(), printing.into()),
            ("core/x/src/a_tests/deeper.rs".into(), printing.into()),
            ("core/x/src/b.rs".into(), printing.into()),
            ("core/x/tests/it.rs".into(), printing.into()),
            ("core/x/src/c.rs".into(), "fn t(r: UserResponse) { panic!(\"{r:?}\") }\n".into()),
        ]);
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        assert!(r.findings[0].said().starts_with("core/x/src/c.rs:1: "), "{}", r.findings[0].said());
        assert_eq!((r.files, r.test_files), (2, 4));
    }

    #[test]
    fn lines_are_placed_past_strings_and_comments() {
        let src = "// foo!(x) in a comment\nconst S: &str = \"bar!(y)\n\";\n/* baz!{\n} */\nfn f(r: UserResponse) {\n    \
                   let s = r#\"q!(\"#;\n    println!(\"{r:?}\");\n}\n";
        one(src, 8);
    }

    #[test]
    fn a_format_macro_that_does_not_parse_is_refused() {
        let r = read(&[(AT.into(), "fn f() {\n    println!(\"{}\" x);\n}\n".into())]);
        assert_eq!(r.refused.len(), 1, "{:?}", r.refused);
        assert!(r.refused[0].starts_with(&format!("{AT}:2: the arguments of `println!` in fn `f` do not parse")), "{}", r.refused[0]);
    }

    #[test]
    fn placeholders_are_read_as_the_compiler_reads_them() {
        let p = placeholders("{{a}} {} {0:?} {name:#?} {:x?} {:>5} }}");
        let got: Vec<(&str, bool)> = p.iter().map(|p| (p.text.as_str(), p.debug)).collect();
        assert_eq!(got, [("{}", false), ("{0:?}", true), ("{name:#?}", true), ("{:x?}", true), ("{:>5}", false)]);
        assert_eq!(p[2].arg, Arg::Name("name".into()));
    }

    // The owed list.

    const SITE: &str = "fn speak(r: UserResponse) {\n    warn!(answer = ?r);\n}\n";

    fn finding() -> Vec<Finding> {
        found(SITE)
    }

    fn entry(sites: usize) -> String {
        format!(
            "[[owed]]\nfile = \"{AT}\"\nfunction = \"speak\"\nexpression = \"r\"\nsites = {sites}\nrow = \"an answer not \
             asked for is said by its name\"\n"
        )
    }

    fn at(text: &str) -> Base {
        Base::At { commit: "0123456789abcdef".into(), owed: parse_owed(text).unwrap() }
    }

    #[test]
    fn a_finding_an_entry_covers_passes() {
        assert_eq!(judge(&finding(), &parse_owed(&entry(1)).unwrap(), &at(&entry(1))), Vec::<String>::new());
        // A shrunk list passes.
        assert_eq!(judge(&[], &[], &at(&entry(1))), Vec::<String>::new());
    }

    #[test]
    fn a_finding_no_entry_covers_is_refused() {
        let r = judge(&finding(), &[], &at(""));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with(&format!("{AT}:2: `warn!` in fn `speak` prints `r` by Debug (`answer = ?r`)")), "{}", r[0]);
        assert!(r[0].ends_with(&remedy("UserResponse")), "{}", r[0]);
    }

    #[test]
    fn an_entry_that_covers_nothing_is_refused() {
        let r = judge(&[], &parse_owed(&entry(1)).unwrap(), &at(&entry(1)));
        assert_eq!(
            r,
            [format!(
                "the owed entry {AT} fn `speak` `r` covers no site: nothing there prints `r` by Debug now, so \
                 delete the entry from {OWED_FILE}"
            )]
        );
        let r = judge(&finding(), &parse_owed(&entry(2)).unwrap(), &at(&entry(2)));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].ends_with(&format!("owes 2 sites and 1 print it by Debug now: set `sites = 1` in {OWED_FILE}")), "{}", r[0]);
    }

    #[test]
    fn a_grown_list_is_refused() {
        // An entry the merge base does not hold.
        let r = judge(&finding(), &parse_owed(&entry(1)).unwrap(), &at(""));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with(&format!("the owed entry {AT} fn `speak` `r` is not owed at the merge base 0123456789ab")), "{}", r[0]);
        // A count above the merge base's.
        let two = [finding(), finding()].concat();
        let r = judge(&two, &parse_owed(&entry(2)).unwrap(), &at(&entry(1)));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains("owes 2 sites, and the merge base 0123456789ab owes 1: the list only shrinks"), "{}", r[0]);
        // A site more than the entry owes.
        let r = judge(&two, &parse_owed(&entry(1)).unwrap(), &at(&entry(1)));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains(&format!("owes 1 sites, and 2 print it by Debug ({AT}:2, {AT}:2): a site is new")), "{}", r[0]);
    }

    #[test]
    fn the_list_arriving_is_accepted_and_an_unknown_base_is_refused() {
        // Arriving, the list is held to what the check finds on the merge base's tree.
        let main = Base::At { commit: "0123456789abcdef".into(), owed: owed_of(&finding()) };
        assert_eq!(judge(&finding(), &parse_owed(&entry(1)).unwrap(), &main), Vec::<String>::new());
        let r = judge(&finding(), &parse_owed(&entry(1)).unwrap(), &Base::At { commit: "0123456789abcdef".into(), owed: owed_of(&[]) });
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains("is not owed at the merge base 0123456789ab"), "{}", r[0]);
        let r = judge(&finding(), &parse_owed(&entry(1)).unwrap(), &Base::Arriving { commit: "0123456789abcdef".into() });
        assert_eq!(r.len(), 1, "{r:?}");
        let r = judge(&finding(), &parse_owed(&entry(1)).unwrap(), &Base::Unknown("why".into()));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].ends_with("why. Fetch, and merge origin/main into the branch, so the merge base is main's tip"), "{}", r[0]);
    }

    #[test]
    fn the_merge_base_is_read_from_git() {
        let r = Repo::new();
        r.write("README", "x\n");
        let first = r.commit("first");
        r.git(&["update-ref", "refs/remotes/origin/main", &first]);
        r.write(OWED_FILE, &entry(1));
        r.commit("the list arrives on a branch");
        assert_eq!(base_owed(r.path()), Base::Arriving { commit: first.clone() });
        // The merge base's own tree is read from git objects, as the check reads it on disk.
        r.git(&["checkout", "-q", &first]);
        r.write(AT, SITE);
        let printing = r.commit("a site");
        r.git(&["update-ref", "refs/remotes/origin/main", &printing]);
        r.git(&["checkout", "-q", "-B", "arriving", &printing]);
        r.write(OWED_FILE, &entry(1));
        r.commit("the list arrives");
        let report = check(r.path());
        assert!(report.arriving && report.refused.is_empty(), "{:?}", report.refused);
        r.write(AT, &format!("{SITE}fn more(r: UserResponse) {{\n    warn!(answer = ?r);\n}}\n"));
        r.write(OWED_FILE, &format!("{}{}", entry(1), entry(1).replace("speak", "more")));
        r.commit("an entry added while the list arrives");
        let report = check(r.path());
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert!(report.refused[0].starts_with(&format!("the owed entry {AT} fn `more` `r` is not owed at the merge base {}", short(&printing))), "{}", report.refused[0]);
        r.git(&["checkout", "-q", "main"]);
        r.git(&["update-ref", "refs/remotes/origin/main", &first]);

        r.git(&["checkout", "-q", "-b", "main-later", &first]);
        r.write(OWED_FILE, &entry(2));
        let main = r.commit("main holds the list");
        r.git(&["update-ref", "refs/remotes/origin/main", &main]);
        r.git(&["checkout", "-q", "-"]);
        assert_eq!(
            base_owed(r.path()),
            Base::Unknown(format!("{} has no {OWED_FILE}, and origin/main has one", short(&first)))
        );

        r.git(&["checkout", "-q", "main-later"]);
        r.write(OWED_FILE, &entry(1));
        r.commit("shrink");
        assert_eq!(base_owed(r.path()), Base::At { commit: main, owed: parse_owed(&entry(2)).unwrap() });
    }

    #[test]
    fn the_owed_file_is_read_strictly() {
        assert_eq!(parse_owed("").unwrap(), Vec::new());
        assert!(parse_owed(&format!("{}{}", entry(1), entry(1))).unwrap_err().contains("listed twice"));
        assert!(parse_owed(&entry(0)).unwrap_err().contains("no `sites` count"));
        assert!(parse_owed("[[owed]]\nfile = \"a\"\n").unwrap_err().contains("no `function` string"));
        assert!(parse_owed("[other]\n").unwrap_err().contains("is not `owed`"));
    }

    #[test]
    fn an_owed_entry_with_a_key_no_entry_holds_is_refused() {
        let e = parse_owed(&format!("{}colour = \"red\"\n", entry(1)));
        assert!(matches!(&e, Err(m) if *m == format!("{OWED_FILE}: entry 1 holds `colour`, which no entry holds")), "{e:?}");
    }

    #[test]
    fn a_file_that_does_not_parse_is_refused_unless_it_is_test_code() {
        let r = read(&[(AT.into(), "fn f( {\n".into())]);
        assert_eq!(r.refused.len(), 1, "{:?}", r.refused);
        assert!(r.refused[0].starts_with(&format!("{AT}: does not parse (")), "{}", r.refused[0]);
        assert!(r.refused[0].ends_with("so debug-check cannot read it: every source outside tests is read"), "{}", r.refused[0]);
        // One a `#[cfg(test)] mod` brings in is set aside.
        let r = read(&[(AT.into(), "#[cfg(test)]\nmod t;\n".into()), ("core/x/src/t.rs".into(), "fn f( {\n".into())]);
        assert!(r.refused.is_empty(), "{:?}", r.refused);
        assert_eq!((r.files, r.test_files), (1, 1));
    }

    #[test]
    fn a_file_under_an_inner_cfg_test_is_set_aside() {
        let src = "#![cfg(test)]\nfn t(r: UserResponse) { panic!(\"{r:?}\") }\n";
        let r = read(&[(AT.into(), src.into())]);
        assert_eq!((r.findings.len(), r.files, r.test_files), (0, 0, 1), "{:?}", r.findings);
        // One whose condition holds outside tests too is read.
        let r = read(&[(AT.into(), src.replace("#![cfg(test)]", "#![cfg(any(test, unix))]"))]);
        assert_eq!((r.findings.len(), r.files, r.test_files), (1, 1, 0), "{:?}", r.findings);
    }

    #[test]
    fn a_statement_under_a_test_attribute_is_set_aside() {
        let src = "fn f(r: UserResponse) {\n    #[cfg(test)]\n    let s = format!(\"{r:?}\");\n    #[cfg(test)]\n    \
                   println!(\"{r:?}\");\n    eprintln!(\"{r:?}\");\n}\n";
        assert_eq!(one(src, 6).mac, "eprintln");
    }

    #[test]
    fn a_tree_with_no_source_is_refused() {
        let r = Repo::new();
        r.write("README", "x\n");
        r.commit("first");
        assert_eq!(
            check(r.path()).refused,
            ["found no .rs file under the code roots: a check that reads nothing does not pass. Run it from the \
              repository's root"]
        );
    }

    #[test]
    fn the_remedy_names_what_the_type_has() {
        for ty in ANSWERS {
            let said = one(&format!("fn f(r: {ty}) {{\n    panic!(\"{{r:?}}\")\n}}\n"), 2).said();
            if NAMED.contains(ty) {
                assert!(said.contains("`kotton_wire::ipc::unasked(&answer)` or `answer.name()`"), "{said}");
            } else {
                assert!(!said.contains("name()") && !said.contains("unasked"), "{said}");
                let sayer = if *ty == RELAY_ERROR { "by its `Display`" } else { "by a name of its own" };
                assert!(said.contains(sayer), "{said}");
            }
        }
    }

    // The answers, held to the wire crate.

    /// The wire's enums [`wire_enums`] names that are not another party's answer, each with why.
    /// None today: every one it names is an answer.
    const NOT_ANSWERS: &[(&str, &str)] = &[];

    /// What [`wire_enums`] finds.
    #[derive(Debug, Default)]
    struct WireEnums {
        /// Each enum a `variant_names!` names.
        named: BTreeSet<String>,
        /// Each `pub enum` whose name ends in `Response`, `Answer` or `Reply`.
        suffixed: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for WireEnums {
        fn visit_item(&mut self, i: &'ast Item) {
            if !test_only(item_attrs(i)) {
                visit::visit_item(self, i);
            }
        }

        fn visit_item_enum(&mut self, e: &'ast syn::ItemEnum) {
            let name = e.ident.to_string();
            if matches!(e.vis, syn::Visibility::Public(_)) && ["Response", "Answer", "Reply"].iter().any(|s| name.ends_with(s)) {
                self.suffixed.insert(name);
            }
        }

        fn visit_item_macro(&mut self, m: &'ast syn::ItemMacro) {
            if !m.mac.path.is_ident("variant_names") {
                return;
            }
            let ty = m
                .mac
                .parse_body_with(|input: ParseStream| {
                    let ty: Ident = input.parse()?;
                    input.step(|c| {
                        let mut rest = *c;
                        while let Some((_, next)) = rest.token_tree() {
                            rest = next;
                        }
                        Ok(((), rest))
                    })?;
                    Ok(ty)
                })
                .expect("a `variant_names!` begins with its type's name");
            self.named.insert(ty.to_string());
        }
    }

    /// The wire crate's enums an answer may be, read from every `.rs` file under `dir` outside
    /// test code: each enum a `variant_names!(Type { .. })` names (the crate's one way of
    /// giving a type a name, which a type has so a reader can say it), and each `pub enum`
    /// whose name ends in `Response`, `Answer` or `Reply`. Structs are not read.
    fn wire_enums(dir: &Path) -> WireEnums {
        let mut found = WireEnums::default();
        let mut dirs = vec![dir.to_path_buf()];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let src = std::fs::read_to_string(&path).unwrap();
                    let file = syn::parse_file(&src).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                    if !test_only(&file.attrs) {
                        found.visit_file(&file);
                    }
                }
            }
        }
        found
    }

    #[test]
    fn the_answers_are_held_to_the_wire_crate() {
        let wire = wire_enums(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/wire/src"));
        assert!(wire.named.contains("UserResponse") && wire.suffixed.contains("UserResponse"), "{wire:?}");
        let not: Vec<&str> = NOT_ANSWERS.iter().map(|(t, _)| *t).collect();
        let unplaced: Vec<&String> =
            wire.named.union(&wire.suffixed).filter(|t| !ANSWERS.contains(&t.as_str()) && !not.contains(&t.as_str())).collect();
        assert!(
            unplaced.is_empty(),
            "the wire crate's {unplaced:?} is in neither ANSWERS nor NOT_ANSWERS: add each to ANSWERS, or to \
             NOT_ANSWERS with why it is not another party's answer"
        );
        for t in &not {
            assert!(!ANSWERS.contains(t), "{t} is in both ANSWERS and NOT_ANSWERS");
            assert!(wire.named.contains(*t) || wire.suffixed.contains(*t), "NOT_ANSWERS names {t}, which the wire crate's rule does not");
        }
        let named: BTreeSet<&str> = wire.named.iter().map(String::as_str).filter(|t| ANSWERS.contains(t)).collect();
        assert_eq!(named, NAMED.iter().copied().collect::<BTreeSet<_>>(), "NAMED is the answers `variant_names!` names");
    }
}
