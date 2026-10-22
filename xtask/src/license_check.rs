// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask license-check` and `cargo xtask third-party-notices` — every dependency
//! has a license Kotton may ship under, and every archive says which.
//!
//! `TASK-a-release-carries-its-third-party-notices-and-every-dependency-has-a-known-license`,
//! Article XI. One verb holds four things, because they are one question asked of four
//! surfaces — *is the license of what we hand a person known?*:
//!
//! 1. **Every package every shipped workspace resolves** has a license expression that
//!    [`ALLOWED`] satisfies — permissive licenses and MPL-2.0 — read from `cargo metadata
//!    --locked`, so from the lockfile. A package with no expression is refused unless
//!    [`CLARIFIED`] names it, its version, and the sha256 of the license file its expression
//!    was read from; a copyleft id is refused unless an `OR` offers a permissive branch.
//! 2. **Every archive's notices can be made**: the same walk the release verbs do
//!    ([`notices`]), over each archive's [`Shipped`] parts, for its own target and features.
//! 3. **Every crate's `Cargo.toml` carries `license`** — `license.workspace = true`, or an
//!    id spelled out where a crate is a workspace of its own — it is one of
//!    [`FIRST_PARTY`], the licenses `LICENSE` carries the text of, and it is **the one its
//!    directory carries** under [`BOUNDARY`]: the licence is drawn by directory, so a crate
//!    moves licence by moving, never by editing a line.
//! 4. **Every source file under [`HEADER_TREES`] opens with an `SPDX-License-Identifier:`
//!    line** (the second line, after a `#!`) naming its own crate's license — its
//!    directory's, for a file in no crate.
//! 5. **`LICENSE` states the same boundary**: the text of every [`FIRST_PARTY`] id is in it,
//!    and so is every directory [`BOUNDARY`] names — so the table a reader sees and the one
//!    this gate applies cannot drift apart.
//!
//! (3), (4) and (5) are the gate `TASK-the-licence-headers-still-say-apache-while-the-ruling-says-agpl`
//! asks for. `DEC-0078` rules the trust path AGPL-3.0-or-later and the guest SDK, its WIT
//! and the examples built on it Apache-2.0; [`BOUNDARY`] is that ruling as a table, and
//! `LICENSE` is the same table as prose with both texts beneath it. Nothing here chooses a
//! license: moving the boundary is an edit to `DEC-0078` first, then to [`BOUNDARY`] and
//! `LICENSE` in one commit, and the check then names every manifest and header to follow.
//!
//! ## Why a verb and not `cargo deny`
//!
//! `cargo deny check licenses` with a `deny.toml` does (1) and nothing else: it cannot see
//! a `Cargo.toml` without a `license` line (it reports our own crates as unlicensed and
//! stops there), cannot read a source header, and does not write the notices file the
//! archives need — which is the same walk over the same metadata. So it would add a tool
//! every machine running `just lint` must install, a config file, and still leave three of
//! the four halves and the generator to write here. `cargo metadata` is already what every
//! other gate in this crate reads, and `serde_json` is already its one parser.
//!
//! ## What it cannot see
//!
//! A license is what a package's *metadata* declares, and `CLARIFIED` what a person read in
//! its license file. Neither is a legal review of every source file inside a crate: a crate
//! that says `MIT` and vendors a GPL file is `MIT` here. SQL migrations carry no SPDX
//! header on purpose — `sqlx` checksums an applied migration, and a comment added to one
//! is a database that refuses to open.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The licenses a dependency may carry: permissive ones, and MPL-2.0 (file-level
/// copyleft, which reaches only the MPL'd files themselves and never Kotton's).
///
/// Each is one commonly read as compatible with AGPL-3.0, which `DEC-0078` rules for the
/// trust path, so this list should not need to change when that ruling is put in force —
/// a reading, not counsel's opinion. `OpenSSL` is not here for that reason — its
/// advertising clause is GPL-incompatible — and enters only as a [`Clarified`] package
/// that is held out of every archive.
pub const ALLOWED: &[&str] = &[
    "0BSD",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "CDLA-Permissive-2.0",
    "ISC",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "Zlib",
];

/// Ids whose terms reach the work that links them. Refused like any id not in
/// [`ALLOWED`]; named separately only so the refusal says *copyleft*, not *unknown*.
const COPYLEFT: &[&str] = &["GPL", "LGPL", "AGPL", "EUPL", "EPL", "CDDL", "OSL", "SSPL", "CC-BY-SA"];

/// A package whose metadata carries no license expression, and the one a person read out
/// of its license file. Pinned to the version and to the file's sha256, so a new release
/// of the crate, or an edited file, is unclarified until someone reads it again.
pub struct Clarified {
    pub name: &'static str,
    pub version: &'static str,
    pub expression: &'static str,
    /// The file the expression was read from, relative to the package's directory.
    pub file: &'static str,
    pub sha256: &'static str,
    /// Where it was read, and what it says, for the next person.
    pub found: &'static str,
    /// `Some(why)` when the expression is not one [`ALLOWED`] satisfies and the package is
    /// tolerated in a workspace's lockfile only: [`notices`] refuses an archive whose build
    /// reaches it, so it can never ship.
    pub workspace_only: Option<&'static str>,
}

pub const CLARIFIED: &[Clarified] = &[Clarified {
    name: "ring",
    version: "0.16.20",
    expression: "ISC AND MIT AND OpenSSL",
    file: "LICENSE",
    sha256: "76b39f9b371688eac9d8323f96ee80b3aef5ecbc2217f25377bd4e4a615296a9",
    found: "https://github.com/briansmith/ring/blob/0.16.20/LICENSE — ring's own code is \
            ISC-style, third_party/fiat is MIT, and the BoringSSL-derived code is under the \
            OpenSSL and original SSLeay licenses, which SPDX's `OpenSSL` id names together. \
            Resolved in the workspace through libp2p-tls 0.5 -> rcgen 0.11, and held out of \
            every archive: one whose build reaches it is refused. ring 0.17 declares its own.",
    workspace_only: Some(
        "the OpenSSL license's advertising clause is incompatible with the AGPL-3.0 LICENSE \
         puts the trust path under, so this stays out of every archive",
    ),
}];

/// Crates that compile C sources they carry, whose own license file sits below the
/// crate's top: the crate's metadata licenses the build glue, and this is the license of
/// what the binary is made of. [`notices`] writes each out beside the crate's own, and
/// refuses when the file is gone — a new version that moved it is read again.
pub const VENDORED: &[(&str, &str, &str)] = &[
    ("libsqlite3-sys", "sqlcipher/LICENSE", "BSD-3-Clause (SQLCipher, Zetetic LLC), built with bundled-sqlcipher"),
    ("openssl-src", "openssl/LICENSE.txt", "Apache-2.0 (OpenSSL 3), built on musl for the vault"),
];

/// The workspaces whose packages reach something a person is handed, each with its own
/// lockfile. Every package each resolves is held to [`ALLOWED`], dev-dependencies too:
/// a test dependency is one `[dependencies]` line from a shipped one.
pub const WORKSPACES: &[&str] = &[
    ".",
    "infra/relay",
    "guest/apps/kotton-shell/logic",
    "guest/apps/kotton-editor/logic",
    "guest/apps/kotton-records/logic",
];

/// The source trees whose files carry an SPDX header, and what counts as a source file.
/// Every tree `LICENSE` lists, `docs/design/` aside: it is prose, and holds no source.
pub const HEADER_TREES: &[&str] = &[
    "core/", "infra/", "client/", "guest/", "tests/", "tools/", "xtask/", "scenarios/", "ui/",
];
const SOURCE_EXTENSIONS: &[&str] = &["rs", "sh", "js", "mjs", "css", "wit"];

/// The licenses Kotton's own crates may declare: the ones whose text `LICENSE` carries,
/// each with a line of that text the check looks for, so an id cannot be listed here
/// before `LICENSE` carries it.
pub const FIRST_PARTY: &[&str] = &["AGPL-3.0-or-later", "Apache-2.0"];
const TEXT_OF: &[(&str, &str)] = &[
    ("AGPL-3.0-or-later", "GNU AFFERO GENERAL PUBLIC LICENSE"),
    ("Apache-2.0", "Version 2.0, January 2004"),
];

/// The licence a path carries, by directory: the longest listed prefix wins, and a path
/// under none of them carries [`DEFAULT`]. This is `DEC-0078` as a table — the trust
/// path and everything Kotton ships on it copyleft; the seam other people build on
/// (the guest SDK and its WIT, the worked examples, the extensions) permissive — and
/// `LICENSE` is the same table as prose, held to this one by `run`.
pub const BOUNDARY: &[(&str, &str)] = &[
    ("guest/sdk/", "Apache-2.0"),
    ("guest/examples/", "Apache-2.0"),
    ("guest/extensions/", "Apache-2.0"),
];
pub const DEFAULT: &str = "AGPL-3.0-or-later";

/// The licence [`BOUNDARY`] gives `path`.
pub fn boundary_license(path: &str) -> &'static str {
    let mut best: Option<(&str, &str)> = None;
    for (dir, l) in BOUNDARY {
        if path.starts_with(dir) && best.is_none_or(|(d, _)| dir.len() > d.len()) {
            best = Some((dir, l));
        }
    }
    best.map(|(_, l)| l).unwrap_or(DEFAULT)
}

/// Trees the header rule does not reach yet, each with the record that holds it. Printed
/// on a green run, and a failure once nothing under it lacks a header — so an entry
/// cannot outlive its reason.
pub const HEADERS_NOT_YET: &[(&str, &str)] = &[];

/// One part of an archive: a workspace, the roots in it whose closure ships (a package
/// name or a `[[bin]]` name), the target it is built for, and the features it is built with.
#[derive(Clone, Copy, Debug)]
pub struct Part {
    pub workspace: &'static str,
    pub roots: &'static [&'static str],
    /// `None` is the host, as `cargo build` without `--target` builds.
    pub target: Option<&'static str>,
    pub features: Option<&'static str>,
}

/// Everything one archive carries code from.
#[derive(Clone, Copy, Debug)]
pub struct Shipped {
    pub name: &'static str,
    pub verb: &'static str,
    pub parts: &'static [Part],
}

/// The system: the binaries `cargo xtask release` packs, from the workspace, with their
/// packages' default features. It carries no guest app.
pub const SYSTEM: Shipped = Shipped {
    name: "system",
    verb: "cargo xtask release",
    parts: &[Part {
        workspace: ".",
        roots: crate::release::BINS,
        target: None,
        features: None,
    }],
};

pub const RELAY: Shipped = Shipped {
    name: "relay",
    verb: "cargo xtask release-server relay",
    parts: &[Part {
        workspace: "infra/relay",
        roots: &["kotton-relay"],
        target: Some(crate::release_server::TARGET),
        features: None,
    }],
};

pub const VAULT: Shipped = Shipped {
    name: "vault",
    verb: "cargo xtask release-server vault",
    parts: &[Part {
        workspace: ".",
        roots: &["kvaultd"],
        target: Some(crate::release_server::TARGET),
        features: None,
    }],
};

pub const ARCHIVES: [Shipped; 3] = [SYSTEM, RELAY, VAULT];

/// The file every archive carries at its top.
pub const FILE: &str = "THIRD-PARTY-NOTICES";

/// Where material written by others and carried as files rather than crates sits — the
/// faces the shell is set in (`TASK-the-desktop-is-set-in-geist-and-layered-as-the-mock-up`).
/// `DEC-0089`: it keeps its own terms, stated beside it.
pub const FONT_DIR: &str = "ui/fonts/";

/// A font carried in [`FONT_DIR`], pinned: the file, what it is, its licence and the file
/// beside it that states it, the sha256 the build embeds, and the crate that embeds it —
/// so an archive names it exactly when that crate is in what the archive ships.
pub struct Font {
    pub file: &'static str,
    pub family: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub license_file: &'static str,
    pub source: &'static str,
    pub sha256: &'static str,
    pub carried_by: &'static str,
}

/// The licences a carried font may be under. A font is not a crate, so [`ALLOWED`] does not
/// speak for it: the OFL's terms reach the font and its derivatives, never a document set
/// in it or a program that embeds it.
pub const FONT_LICENSES: &[(&str, &str)] = &[("OFL-1.1", "SIL OPEN FONT LICENSE Version 1.1")];

/// Every file in [`FONT_DIR`] that is a font. Taken from the `geist` package on npm at 1.7.2
/// (its integrity sha512 checked on download), whose `LICENSE.txt` is `OFL.txt` here.
pub const FONTS: &[Font] = &[
    Font {
        file: "ui/fonts/Geist-Variable.ttf",
        family: "Geist",
        version: "1.800",
        license: "OFL-1.1",
        license_file: "ui/fonts/OFL.txt",
        source: "https://github.com/vercel/geist-font",
        sha256: "cdcc4815cbf5f9882fa74e48f8ab410a0495781a58ff7316570f664e7e987753",
        carried_by: "kuid",
    },
    Font {
        file: "ui/fonts/GeistMono-Variable.ttf",
        family: "Geist Mono",
        version: "1.700",
        license: "OFL-1.1",
        license_file: "ui/fonts/OFL.txt",
        source: "https://github.com/vercel/geist-font",
        sha256: "0e1af3f507a1c8dfbb03d13ffad585834cd45ed7ccb78c756c7ce7873d180d30",
        carried_by: "kuid",
    },
];

/// What is wrong with [`FONT_DIR`] as it stands: a file no [`FONTS`] row names, a font whose
/// bytes are not its pin, a licence [`FONT_LICENSES`] does not list or whose file does not
/// say it. `files` is the directory's listing, repository-relative.
fn font_findings(repo: &Path, files: &[String]) -> Vec<String> {
    let mut findings = Vec::new();
    for f in files {
        if !FONTS.iter().any(|t| t.file == f || t.license_file == f) {
            findings.push(format!(
                "{f}: in {FONT_DIR} and not in FONTS — a font the build could embed with no licence or pin recorded"
            ));
        }
    }
    for t in FONTS {
        match file_sha256(&repo.join(t.file)) {
            Ok(h) if h == t.sha256 => {}
            Ok(h) => findings.push(format!("{}: sha256 {h}, and FONTS pins {}", t.file, t.sha256)),
            Err(e) => findings.push(e),
        }
        match FONT_LICENSES.iter().find(|(id, _)| *id == t.license) {
            None => findings.push(format!("{}: `{}` is not a licence FONT_LICENSES allows", t.file, t.license)),
            Some((_, says)) => match std::fs::read_to_string(repo.join(t.license_file)) {
                Ok(text) if text.contains(says) => {}
                Ok(_) => findings.push(format!("{}: does not say `{says}`, which {} is under", t.license_file, t.file)),
                Err(e) => findings.push(format!("{}: {e}", t.license_file)),
            },
        }
    }
    findings
}

// ---------------------------------------------------------------------------------------
// SPDX expressions

#[derive(Debug, PartialEq)]
enum Expr {
    Id(String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' | '/' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse an SPDX expression. `/` is read as `OR`, the way crates.io's older metadata
/// (`MIT/Apache-2.0`) means it; `WITH` binds tightest, then `AND`, then `OR`.
fn parse(s: &str) -> Result<Expr, String> {
    let toks = tokens(s);
    let mut pos = 0;
    let e = parse_or(&toks, &mut pos)?;
    if pos != toks.len() {
        return Err(format!("`{s}`: unexpected `{}`", toks[pos]));
    }
    Ok(e)
}

fn parse_or(t: &[String], p: &mut usize) -> Result<Expr, String> {
    let mut l = parse_and(t, p)?;
    while *p < t.len() && (t[*p] == "OR" || t[*p] == "/") {
        *p += 1;
        l = Expr::Or(Box::new(l), Box::new(parse_and(t, p)?));
    }
    Ok(l)
}

fn parse_and(t: &[String], p: &mut usize) -> Result<Expr, String> {
    let mut l = parse_atom(t, p)?;
    while *p < t.len() && t[*p] == "AND" {
        *p += 1;
        l = Expr::And(Box::new(l), Box::new(parse_atom(t, p)?));
    }
    Ok(l)
}

fn parse_atom(t: &[String], p: &mut usize) -> Result<Expr, String> {
    let tok = t.get(*p).ok_or("an expression ends where a license id should be")?;
    if tok == "(" {
        *p += 1;
        let e = parse_or(t, p)?;
        if t.get(*p).map(String::as_str) != Some(")") {
            return Err("an unclosed `(`".into());
        }
        *p += 1;
        return Ok(e);
    }
    if matches!(tok.as_str(), ")" | "AND" | "OR" | "WITH" | "/") {
        return Err(format!("`{tok}` where a license id should be"));
    }
    *p += 1;
    let mut id = tok.clone();
    if t.get(*p).map(String::as_str) == Some("WITH") {
        let ex = t.get(*p + 1).ok_or("`WITH` names no exception")?;
        id = format!("{id} WITH {ex}");
        *p += 2;
    }
    Ok(Expr::Id(id))
}

/// Whether `expr` can be satisfied from [`ALLOWED`]; on refusal, the ids that stood in
/// the way, each marked copyleft or unknown.
fn satisfied(expr: &Expr) -> Result<(), Vec<String>> {
    match expr {
        Expr::Id(id) if ALLOWED.contains(&id.as_str()) => Ok(()),
        Expr::Id(id) => {
            let kind = if COPYLEFT.iter().any(|c| id.starts_with(c)) {
                "copyleft"
            } else {
                "not allowed"
            };
            Err(vec![format!("{id} ({kind})")])
        }
        Expr::And(a, b) => match (satisfied(a), satisfied(b)) {
            (Ok(()), Ok(())) => Ok(()),
            (a, b) => Err([a.err(), b.err()].into_iter().flatten().flatten().collect()),
        },
        Expr::Or(a, b) => match (satisfied(a), satisfied(b)) {
            (Err(x), Err(y)) => Err(x.into_iter().chain(y).collect()),
            _ => Ok(()),
        },
    }
}

/// Whether `expression` is one Kotton may ship a dependency under, and if not, why.
pub fn judge(expression: &str) -> Result<(), String> {
    let e = parse(expression)?;
    satisfied(&e).map_err(|ids| format!("`{expression}`: no allowed choice — {}", ids.join(", ")))
}

// ---------------------------------------------------------------------------------------
// Metadata

/// One package as `cargo metadata` resolved it.
#[derive(Clone, Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub repository: Option<String>,
    /// The directory holding its `Cargo.toml` — for a registry crate, the unpacked source.
    pub dir: PathBuf,
    /// Kotton's own: a path package inside this repository.
    pub ours: bool,
}

struct Resolved {
    packages: BTreeMap<String, Package>,
    /// Package id -> its name and its `[[bin]]` names, for finding roots.
    names: BTreeMap<String, Vec<String>>,
}

/// The host triple, as `rustc -vV` reports it: what `cargo build` builds for when it is
/// given no `--target`.
fn host() -> Result<String, String> {
    let o = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|e| format!("cannot run rustc -vV: {e}"))?;
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_string))
        .ok_or_else(|| "rustc -vV names no host".into())
}

fn metadata(repo: &Path, workspace: &str, target: Option<&str>, features: Option<&str>) -> Result<Resolved, String> {
    let manifest = repo.join(workspace).join("Cargo.toml");
    let mut c = Command::new("cargo");
    c.args(["metadata", "--format-version", "1", "--locked", "--manifest-path"])
        .arg(&manifest)
        .current_dir(repo);
    if let Some(t) = target {
        c.args(["--filter-platform", t]);
    }
    if let Some(f) = features {
        c.args(["--features", f]);
    }
    let o = c.output().map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "cargo metadata --locked for {workspace} failed:\n{}",
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    let v: Value = serde_json::from_slice(&o.stdout).map_err(|e| format!("cargo metadata for {workspace}: {e}"))?;
    let mut packages = BTreeMap::new();
    let mut names = BTreeMap::new();
    for p in v["packages"].as_array().into_iter().flatten() {
        let s = |k: &str| p[k].as_str().map(str::to_string);
        let id = s("id").unwrap_or_default();
        let manifest = PathBuf::from(s("manifest_path").unwrap_or_default());
        let dir = manifest.parent().map(Path::to_path_buf).unwrap_or_default();
        let ours = p["source"].is_null() && dir.starts_with(repo);
        let mut n = vec![s("name").unwrap_or_default()];
        for t in p["targets"].as_array().into_iter().flatten() {
            if t["kind"].as_array().is_some_and(|k| k.iter().any(|k| k == "bin")) {
                n.extend(t["name"].as_str().map(str::to_string));
            }
        }
        names.insert(id.clone(), n);
        packages.insert(
            id,
            Package {
                name: s("name").unwrap_or_default(),
                version: s("version").unwrap_or_default(),
                license: s("license").filter(|l| !l.trim().is_empty()),
                license_file: s("license_file"),
                repository: s("repository"),
                dir,
                ours,
            },
        );
    }
    Ok(Resolved { packages, names })
}

/// The sha256 of a file, or why there is none.
fn file_sha256(path: &Path) -> Result<String, String> {
    if !path.is_file() {
        return Err(format!("{} does not exist", path.display()));
    }
    crate::release::sha256(path).ok_or_else(|| "no sha256sum or shasum on this machine".into())
}

/// The license expression Kotton holds `p` to: its metadata's, or its clarification's
/// when the license file still hashes to what was read.
pub fn expression_of(p: &Package) -> Result<String, String> {
    if let Some(l) = &p.license {
        return Ok(l.clone());
    }
    let Some(c) = CLARIFIED.iter().find(|c| c.name == p.name && c.version == p.version) else {
        return Err(format!(
            "{} {} declares no license{} — read it in the crate's repository and add it to CLARIFIED in xtask/src/license_check.rs, or replace the crate",
            p.name,
            p.version,
            p.license_file
                .as_deref()
                .map(|f| format!(", only a license file ({f})"))
                .unwrap_or_default()
        ));
    };
    let got = file_sha256(&p.dir.join(c.file))?;
    if got != c.sha256 {
        return Err(format!(
            "{} {}: {} hashes to {got}, not the {} it was clarified from — read it again",
            p.name, p.version, c.file, c.sha256
        ));
    }
    Ok(c.expression.to_string())
}

/// Every package the build of `roots` compiles, as `cargo tree` resolves that build — the
/// same package selection, features and target — over normal and build edges, never a
/// dev-dependency. Read from `cargo tree` rather than walked out of `cargo metadata`'s
/// graph because metadata unifies features over the whole workspace: the vault's
/// musl-only vendored OpenSSL appeared in the desktop's walk, which never builds it.
fn closure(repo: &Path, r: &Resolved, part: &Part, target: &str) -> Result<BTreeSet<String>, String> {
    let mut packages = Vec::new();
    for root in part.roots {
        let id = r
            .names
            .iter()
            .find(|(id, n)| n.iter().any(|n| n == root) && r.packages[*id].ours)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| format!("{} has no package or binary named {root}", part.workspace))?;
        let name = r.packages[&id].name.clone();
        if !packages.contains(&name) {
            packages.push(name);
        }
    }
    let mut c = Command::new("cargo");
    c.args(["tree", "--locked", "--manifest-path"])
        .arg(repo.join(part.workspace).join("Cargo.toml"))
        .args(["-e", "normal,build", "--target", target, "--prefix", "none", "-f", "{p}"])
        .current_dir(repo);
    for p in &packages {
        c.args(["-p", p]);
    }
    if let Some(f) = part.features {
        c.args(["--features", f]);
    }
    let o = c.output().map_err(|e| format!("cannot run cargo tree: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "cargo tree for {} failed:\n{}",
            part.workspace,
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    let mut seen = BTreeSet::new();
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let mut w = line.split_whitespace();
        let (Some(name), Some(v)) = (w.next(), w.next()) else { continue };
        let version = v.trim_start_matches('v');
        let path_dep = line.contains(" (/");
        let id = r
            .packages
            .iter()
            .find(|(_, p)| p.name == name && p.version == version && p.ours == path_dep)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| format!("cargo tree names {name} {version}, which cargo metadata for {} does not", part.workspace))?;
        seen.insert(id);
    }
    Ok(seen)
}

// ---------------------------------------------------------------------------------------
// The notices file

/// The license files a package carries at its top, and its declared `license-file`.
fn license_texts(p: &Package) -> Vec<(String, String)> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(&p.dir) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            let up = n.to_ascii_uppercase();
            let is = ["LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT", "UNLICENSE"]
                .iter()
                .any(|k| up.starts_with(k));
            if is && e.path().is_file() {
                names.insert(n);
            }
        }
    }
    if let Some(f) = &p.license_file {
        names.insert(f.clone());
    }
    for (crate_name, file, _) in VENDORED {
        if *crate_name == p.name {
            names.insert(file.to_string());
        }
    }
    names
        .into_iter()
        .filter_map(|n| {
            let bytes = std::fs::read(p.dir.join(&n)).ok()?;
            Some((n, String::from_utf8_lossy(&bytes).replace("\r\n", "\n")))
        })
        .collect()
}

/// `THIRD-PARTY-NOTICES` for one archive, from its parts' lockfiles.
///
/// Every third-party package each part's roots reach, once, sorted by name and version,
/// with the license expression it is held to, where it came from, and the license files it
/// carries — each distinct text written out once and numbered. Refuses, rather than
/// writes, when a package's license is unknown or not allowed: an archive never carries a
/// notice for a license the check would fail.
/// `target`, when given, is the one the archive is built for in place of each part's
/// own — `release-server --target`.
pub fn notices(repo: &Path, shipped: &Shipped, revision: &str, target: Option<&str>) -> Result<String, String> {
    let mut lockfiles = Vec::new();
    let mut third: BTreeMap<(String, String), (Package, String)> = BTreeMap::new();
    let mut ours: BTreeMap<String, String> = BTreeMap::new();
    let mut refused = Vec::new();
    let host = host()?;
    for part in shipped.parts {
        let built_for = target.or(part.target).map(str::to_string).unwrap_or_else(|| host.clone());
        let r = metadata(repo, part.workspace, Some(&built_for), part.features)?;
        let lock = repo.join(part.workspace).join("Cargo.lock");
        let rel = Path::new(part.workspace).join("Cargo.lock");
        lockfiles.push(format!(
            "  {}  sha256 {}  target {built_for}{}",
            rel.display().to_string().trim_start_matches("./"),
            file_sha256(&lock)?,
            part.features.map(|f| format!("  features {f}")).unwrap_or_default()
        ));
        for id in closure(repo, &r, part, &built_for)? {
            let p = &r.packages[&id];
            if p.ours {
                ours.insert(p.name.clone(), p.license.clone().unwrap_or_else(|| "(no license)".into()));
                continue;
            }
            match expression_of(p).and_then(|e| judge(&e).map(|()| e)) {
                Ok(e) => {
                    third
                        .entry((p.name.clone(), p.version.clone()))
                        .or_insert_with(|| (p.clone(), e));
                }
                Err(why) => {
                    let held = CLARIFIED
                        .iter()
                        .find(|c| c.name == p.name && c.version == p.version)
                        .and_then(|c| c.workspace_only)
                        .map(|w| format!(" — it is clarified for a lockfile only: {w}"))
                        .unwrap_or_default();
                    refused.push(format!("{} {}: {why}{held}", p.name, p.version))
                }
            }
        }
    }
    if !refused.is_empty() {
        refused.sort();
        refused.dedup();
        return Err(format!(
            "the {} archive would carry packages whose license is not allowed:\n  {}",
            shipped.name,
            refused.join("\n  ")
        ));
    }

    // Each distinct text once, numbered in first-use order over the sorted packages.
    let mut texts: Vec<(String, Vec<String>)> = Vec::new();
    let mut rows = Vec::new();
    for ((name, version), (p, expr)) in &third {
        for (crate_name, file, what) in VENDORED {
            if *crate_name == p.name && !p.dir.join(file).is_file() {
                return Err(format!(
                    "{name} {version} carries no {file}, the license of the {what} it compiles — read where it moved, and update VENDORED in xtask/src/license_check.rs"
                ));
            }
        }
        let mut refs = Vec::new();
        for (file, text) in license_texts(p) {
            let who = format!("{name} {version} ({file})");
            let n = match texts.iter().position(|(t, _)| *t == text) {
                Some(i) => {
                    texts[i].1.push(who);
                    i
                }
                None => {
                    texts.push((text, vec![who]));
                    texts.len() - 1
                }
            };
            refs.push(format!("[{}]", n + 1));
        }
        let source = p.repository.clone().unwrap_or_else(|| format!("https://crates.io/crates/{name}"));
        let refs = if refs.is_empty() {
            "(no license file in the package; the SPDX id is the notice)".to_string()
        } else {
            refs.join(" ")
        };
        rows.push(format!("{name}\t{version}\t{expr}\t{source}\t{refs}"));
    }

    let mut out = String::new();
    out.push_str(&format!("{FILE} — the Kotton {} archive, {revision}\n\n", shipped.name));
    out.push_str(&format!(
        "Generated by `{}` from the lockfiles below, never written by hand. NOTICES, at the\n\
         root of Kotton's repository, says how this file is made; `cargo xtask license-check`\n\
         holds every license here to the list it allows.\n\n",
        shipped.verb
    ));
    out.push_str("Lockfiles:\n");
    for l in &lockfiles {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(&format!("\nKotton's own crates, under Kotton's LICENSE: {}\n", ours.len()));
    for id in FIRST_PARTY {
        let named: Vec<&str> = ours.iter().filter(|(_, l)| l == id).map(|(n, _)| n.as_str()).collect();
        if !named.is_empty() {
            out.push_str(&format!("  {id}: {}\n", named.join(", ")));
        }
    }
    let stray: Vec<String> = ours.iter().filter(|(_, l)| !FIRST_PARTY.contains(&l.as_str())).map(|(n, l)| format!("{n} {l}")).collect();
    if !stray.is_empty() {
        return Err(format!("Kotton's own crates declare a license LICENSE does not carry: {}", stray.join(", ")));
    }
    out.push('\n');
    out.push_str(&format!("Third-party packages: {}\n", rows.len()));
    out.push_str("name\tversion\tlicense\tsource\tlicense texts\n");
    for r in &rows {
        out.push_str(r);
        out.push('\n');
    }
    let carried: Vec<&Font> = FONTS.iter().filter(|f| ours.contains_key(f.carried_by)).collect();
    if !carried.is_empty() {
        out.push_str(&format!("\nFonts, carried from {FONT_DIR}: {}\n", carried.len()));
        out.push_str("family\tversion\tlicense\tsource\tlicense texts\n");
        for f in &carried {
            let text = std::fs::read_to_string(repo.join(f.license_file))
                .map_err(|e| format!("{}: {e}", f.license_file))?
                .replace("\r\n", "\n");
            let who = format!("{} {} ({})", f.family, f.version, f.license_file);
            let n = match texts.iter().position(|(t, _)| *t == text) {
                Some(i) => {
                    texts[i].1.push(who);
                    i
                }
                None => {
                    texts.push((text, vec![who]));
                    texts.len() - 1
                }
            };
            out.push_str(&format!("{}\t{}\t{}\t{}\t[{}]\n", f.family, f.version, f.license, f.source, n + 1));
        }
    }
    out.push_str(&format!("\nLicense texts: {}\n", texts.len()));
    for (i, (text, who)) in texts.iter().enumerate() {
        out.push_str(&format!("\n======== [{}] {}\n\n", i + 1, who.join(", ")));
        out.push_str(text.trim_end());
        out.push('\n');
    }
    Ok(out)
}

/// Hold a notices file to its own shape: the header, a package count that matches its
/// rows, a license on every row, and every text a row cites written out. The release tests
/// read the archive's copy with this, so an archive whose notices are missing, empty or
/// truncated is refused as surely as one missing a binary.
pub fn check_notices(text: &str) -> Result<usize, String> {
    if !text.starts_with(FILE) {
        return Err(format!("{FILE} does not open with its own name"));
    }
    if !text.contains("never written by hand") {
        return Err(format!("{FILE} does not say how it was made"));
    }
    let mut lines = text.lines();
    let count: usize = lines
        .by_ref()
        .find_map(|l| l.strip_prefix("Third-party packages: "))
        .ok_or_else(|| format!("{FILE} has no package count"))?
        .trim()
        .parse()
        .map_err(|e| format!("{FILE}'s package count: {e}"))?;
    let _heading = lines.next();
    let rows: Vec<&str> = lines.by_ref().take_while(|l| !l.is_empty()).collect();
    if rows.len() != count {
        return Err(format!("{FILE} says {count} packages and lists {}", rows.len()));
    }
    if count == 0 {
        return Err(format!("{FILE} lists no packages"));
    }
    let texts: usize = lines
        .find_map(|l| l.strip_prefix("License texts: "))
        .ok_or_else(|| format!("{FILE} has no license texts"))?
        .trim()
        .parse()
        .map_err(|e| format!("{FILE}'s text count: {e}"))?;
    let cited = |who: &str, refs: &str| -> Result<(), String> {
        for r in refs.split_whitespace().filter(|r| r.starts_with('[')) {
            let n: usize = r.trim_matches(|c| c == '[' || c == ']').parse().unwrap_or(0);
            if n == 0 || n > texts || !text.contains(&format!("\n======== {r} ")) {
                return Err(format!("{FILE}: {who} cites license text {r}, which is not written out"));
            }
        }
        Ok(())
    };
    for row in &rows {
        let f: Vec<&str> = row.split('\t').collect();
        if f.len() != 5 || f[0].is_empty() || f[1].is_empty() || f[2].is_empty() {
            return Err(format!("{FILE} row is not name, version, license, source, texts: {row:?}"));
        }
        judge(f[2]).map_err(|e| format!("{FILE}: {} {}: {e}", f[0], f[1]))?;
        cited(f[0], f[4])?;
    }
    for (family, version, license) in fonts_in(text)? {
        if !FONT_LICENSES.iter().any(|(id, _)| *id == license) {
            return Err(format!("{FILE}: the font {family} {version} is under `{license}`, which FONT_LICENSES does not allow"));
        }
    }
    let font_rows = text.lines().skip_while(|l| !l.starts_with("Fonts, carried from ")).skip(2).take_while(|l| !l.is_empty());
    for row in font_rows {
        let f: Vec<&str> = row.split('\t').collect();
        cited(f[0], f.get(4).copied().unwrap_or(""))?;
        if f.get(4).is_none_or(|r| !r.contains('[')) {
            return Err(format!("{FILE}: the font {} cites no license text — a font's notice is its licence's text", f[0]));
        }
    }
    Ok(count)
}

/// The fonts a notices file names — family, version and licence — from its `Fonts, carried
/// from` section, or none when it has no such section. Refuses a section whose count is not
/// its rows, or a row that is not family, version, licence, source, texts.
pub fn fonts_in(text: &str) -> Result<Vec<(String, String, String)>, String> {
    let mut lines = text.lines().skip_while(|l| !l.starts_with("Fonts, carried from "));
    let Some(head) = lines.next() else { return Ok(Vec::new()) };
    let count: usize = head
        .rsplit_once(": ")
        .and_then(|(_, n)| n.trim().parse().ok())
        .ok_or_else(|| format!("{FILE}'s font count: {head:?}"))?;
    let _heading = lines.next();
    let rows: Vec<&str> = lines.take_while(|l| !l.is_empty()).collect();
    if rows.len() != count {
        return Err(format!("{FILE} says {count} fonts and lists {}", rows.len()));
    }
    rows.iter()
        .map(|row| {
            let f: Vec<&str> = row.split('\t').collect();
            if f.len() != 5 || f[..4].iter().any(|x| x.is_empty()) {
                return Err(format!("{FILE} font row is not family, version, license, source, texts: {row:?}"));
            }
            Ok((f[0].to_string(), f[1].to_string(), f[2].to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// The verb

/// `[workspace.package] license` of the root manifest: the one place Kotton's own crates'
/// license is stated.
fn workspace_license(repo: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(repo.join("Cargo.toml")).map_err(|e| format!("Cargo.toml: {e}"))?;
    let mut inside = false;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            inside = t == "[workspace.package]";
        } else if inside {
            if let Some(v) = t.strip_prefix("license").map(str::trim_start).and_then(|r| r.strip_prefix('=')) {
                return Ok(v.trim().trim_matches('"').to_string());
            }
        }
    }
    Err("the root Cargo.toml's [workspace.package] names no license".into())
}

/// A manifest's `[package]` license, as written: `Some("workspace")` for inheritance.
fn manifest_license(text: &str) -> Option<Option<String>> {
    let text = text.trim_start_matches('\u{feff}');
    let mut inside = false;
    let mut has_package = false;
    let mut found = None;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            inside = t == "[package]";
            has_package |= inside;
            continue;
        }
        if !inside {
            continue;
        }
        let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        if compact == "license.workspace=true" || compact == "license={workspace=true}" {
            found = Some("workspace".to_string());
        } else if let Some(v) = compact.strip_prefix("license=") {
            found = Some(t.split_once('=').map(|x| x.1).unwrap_or(v).trim().trim_matches('"').to_string());
        }
    }
    has_package.then_some(found)
}

fn git_files(repo: &Path, pathspecs: &[&str]) -> Vec<String> {
    Command::new("git")
        .arg("ls-files")
        .arg("--")
        .args(pathspecs)
        .current_dir(repo)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// The license of the crate `file` sits in — the deepest crate directory holding it —
/// from `crates`, sorted deepest first. `None` for a file in no crate (a script, a web
/// asset), which takes the workspace's.
fn crate_license<'a>(crates: &'a [(String, String)], file: &str) -> Option<&'a str> {
    crates
        .iter()
        .find(|(dir, _)| !dir.is_empty() && file.starts_with(dir.as_str()))
        .map(|(_, l)| l.as_str())
}

/// Each crate's directory and its license, workspace inheritance resolved, sorted deepest
/// first so a file takes the license of the crate nearest it. A manifest with no `license`,
/// or one `LICENSE` does not carry, is left out and pushed onto `failures`.
fn crate_licenses(repo: &Path, license: &str, failures: &mut Vec<String>) -> Vec<(String, String)> {
    let mut crates: Vec<(String, String)> = Vec::new();
    for m in git_files(repo, &["Cargo.toml", "*/Cargo.toml"]) {
        let Ok(text) = std::fs::read_to_string(repo.join(&m)) else { continue };
        let dir = m.strip_suffix("Cargo.toml").unwrap_or("").to_string();
        match manifest_license(&text) {
            None => {}
            Some(None) => failures.push(format!("{m}: [package] has no `license` — add `license.workspace = true`, or `license = \"{license}\"` in a workspace of its own")),
            Some(Some(l)) => {
                let l = if l == "workspace" { license.to_string() } else { l };
                match manifest_finding(&m, &dir, &l) {
                    Some(why) => failures.push(why),
                    None => crates.push((dir, l)),
                }
            }
        }
    }
    crates.sort_by_key(|(d, _)| std::cmp::Reverse(d.len()));
    crates
}

/// Why a manifest at `m`, in directory `dir`, may not declare `declared`: an id `LICENSE`
/// does not carry, or one its directory does not — `None` when it may.
fn manifest_finding(m: &str, dir: &str, declared: &str) -> Option<String> {
    if !FIRST_PARTY.contains(&declared) {
        return Some(format!(
            "{m}: license `{declared}` is not one LICENSE carries ({}) — which license a crate is under is LICENSE's table to say, and LICENSE gains the text first",
            FIRST_PARTY.join(", ")
        ));
    }
    let carried = boundary_license(dir);
    if declared != carried {
        return Some(format!(
            "{m}: declares `{declared}`, and its directory carries `{carried}` (LICENSE, BOUNDARY) — a crate's licence is its directory's; move the crate, or amend LICENSE's table first"
        ));
    }
    None
}

/// What `LICENSE`'s text fails to say that [`BOUNDARY`], [`HEADER_TREES`] and
/// [`FIRST_PARTY`] say: a missing text, or a directory the tables name and it does not.
fn license_text_findings(text: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for id in FIRST_PARTY {
        match TEXT_OF.iter().find(|(i, _)| i == id).map(|(_, m)| *m) {
            Some(m) if text.contains(m) => {}
            Some(m) => findings.push(format!("LICENSE does not carry the text of {id} (no line reads `{m}`)")),
            None => findings.push(format!("FIRST_PARTY names {id}, and TEXT_OF gives no line of its text to look for")),
        }
    }
    for (dir, _) in BOUNDARY {
        if !text.contains(dir) {
            findings.push(format!("LICENSE does not name `{dir}`, which BOUNDARY draws — the two tables must agree"));
        }
    }
    for tree in HEADER_TREES {
        if !text.contains(tree) {
            findings.push(format!("LICENSE does not name `{tree}`, which HEADER_TREES holds to a header"));
        }
    }
    findings
}

/// The license `license-check` holds `file`'s SPDX header to — its own crate's, or its
/// directory's for a file in no crate — read by the same code the check reads it with, so
/// a generator writing under [`HEADER_TREES`] writes the header the check will require
/// rather than keeping a second copy of the id. A manifest the check would refuse is the
/// check's to report; it is not repeated here.
pub fn file_license(repo: &Path, file: &str) -> Result<String, String> {
    let license = workspace_license(repo)?;
    let crates = crate_licenses(repo, &license, &mut Vec::new());
    Ok(crate_license(&crates, file).unwrap_or(boundary_license(file)).to_string())
}

/// Whether a path under [`HEADER_TREES`] is source the header rule reads.
fn is_source(path: &str, first_line: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    match file.rsplit_once('.') {
        Some((_, ext)) => SOURCE_EXTENSIONS.contains(&ext),
        None => first_line.starts_with("#!"),
    }
}

/// The SPDX line a source file opens with, if it does: the first line, or the second
/// after a `#!`.
pub fn spdx_header(text: &str) -> Option<&str> {
    let mut lines = text.trim_start_matches('\u{feff}').lines();
    let first = lines.next()?;
    let line = if first.starts_with("#!") { lines.next()? } else { first };
    line.split_once("SPDX-License-Identifier:").map(|(_, id)| id.trim().trim_end_matches("*/").trim())
}

pub fn run(repo: &Path) {
    let mut failures: Vec<String> = Vec::new();

    // 1. Every package every shipped workspace resolves.
    let mut judged = 0usize;
    let mut clarified_used = BTreeSet::new();
    for ws in WORKSPACES {
        match metadata(repo, ws, None, None) {
            Ok(r) => {
                for p in r.packages.values().filter(|p| !p.ours) {
                    judged += 1;
                    let workspace_only = p.license.is_none()
                        && CLARIFIED
                            .iter()
                            .any(|c| c.name == p.name && c.version == p.version && c.workspace_only.is_some());
                    let judged_ok = expression_of(p).and_then(|e| if workspace_only { Ok(()) } else { judge(&e) });
                    match judged_ok {
                        Ok(()) => {
                            if p.license.is_none() {
                                clarified_used.insert(format!("{} {}", p.name, p.version));
                            }
                        }
                        Err(why) => failures.push(format!("{ws}: {} {}: {why}", p.name, p.version)),
                    }
                }
            }
            Err(e) => failures.push(e),
        }
    }
    for c in CLARIFIED {
        let key = format!("{} {}", c.name, c.version);
        if !clarified_used.contains(&key) {
            failures.push(format!(
                "CLARIFIED names {key}, which no shipped workspace resolves any more — delete the entry"
            ));
        }
    }

    // 2. Every archive's notices can be made.
    let mut made = Vec::new();
    for a in &ARCHIVES {
        match notices(repo, a, "license-check", None).and_then(|t| check_notices(&t)) {
            Ok(n) => made.push(format!("{} {n}", a.name)),
            Err(e) => failures.push(e),
        }
    }

    // 2b. Every file carried from ui/fonts/ is pinned, and its licence is beside it.
    // Read from disk rather than the index, so a file dropped in is seen before it is added.
    let mut font_files: Vec<String> = std::fs::read_dir(repo.join(FONT_DIR))
        .map(|d| d.flatten().map(|e| format!("{FONT_DIR}{}", e.file_name().to_string_lossy())).collect())
        .unwrap_or_default();
    font_files.sort();
    failures.extend(font_findings(repo, &font_files));

    // 3. Every crate's license field: present, and one LICENSE carries.
    let license = match workspace_license(repo) {
        Ok(l) => l,
        Err(e) => {
            failures.push(e);
            String::new()
        }
    };
    if !license.is_empty() && license != DEFAULT {
        failures.push(format!(
            "Cargo.toml: [workspace.package] license is `{license}`, and the workspace's directories carry `{DEFAULT}` (BOUNDARY)"
        ));
    }
    let crates = crate_licenses(repo, &license, &mut failures);

    // 5. LICENSE carries every first-party text and names every directory the boundary draws.
    match std::fs::read_to_string(repo.join("LICENSE")) {
        Ok(text) => failures.extend(license_text_findings(&text)),
        Err(e) => failures.push(format!("LICENSE: {e}")),
    }

    // 4. Every source file's SPDX header, naming its own crate's license.
    let mut headed = 0usize;
    let mut not_yet: BTreeMap<&str, usize> = BTreeMap::new();
    for f in git_files(repo, HEADER_TREES) {
        let Ok(bytes) = std::fs::read(repo.join(&f)) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        if !is_source(&f, text.lines().next().unwrap_or("")) {
            continue;
        }
        let expected = crate_license(&crates, &f).unwrap_or(boundary_license(&f));
        match spdx_header(&text) {
            Some(id) if id == expected => headed += 1,
            Some(id) => failures.push(format!("{f}: SPDX-License-Identifier `{id}` is not its crate's license, `{expected}`")),
            None => match HEADERS_NOT_YET.iter().find(|(tree, _)| f.starts_with(tree)) {
                Some((tree, _)) => *not_yet.entry(tree).or_default() += 1,
                None => failures.push(format!("{f}: opens with no `SPDX-License-Identifier: {expected}` line")),
            },
        }
    }
    for (tree, record) in HEADERS_NOT_YET {
        match not_yet.get(tree) {
            Some(n) => println!("license-check: not yet — {n} files under {tree} carry no header ({record})"),
            None => failures.push(format!(
                "HEADERS_NOT_YET names {tree}, and every source file there carries its header — delete the entry and close {record}"
            )),
        }
    }
    let crates = crates.len();

    if failures.is_empty() {
        for c in CLARIFIED {
            println!(
                "license-check: clarified — {} {} is `{}`, read from {}: {}",
                c.name, c.version, c.expression, c.file, c.found
            );
        }
        println!(
            "license-check: OK — {judged} package entries across {} workspaces' lockfiles allowed ({} clarified), notices made for {}, {crates} crates declare a license LICENSE carries, {headed} source files carry their crate's SPDX header, {} fonts in {FONT_DIR} match their pins",
            WORKSPACES.len(),
            clarified_used.len(),
            made.join(", "),
            FONTS.len()
        );
    } else {
        for f in &failures {
            eprintln!("license-check: {f}");
        }
        eprintln!("license-check: FAILED — {} findings", failures.len());
        std::process::exit(1);
    }
}

/// `cargo xtask third-party-notices system|relay|vault`: print what that archive's
/// `THIRD-PARTY-NOTICES` would be, without building it.
pub fn print(repo: &Path, args: &[String]) {
    let Some(a) = args.first().and_then(|n| ARCHIVES.iter().find(|a| a.name == n.as_str())) else {
        eprintln!("usage: cargo xtask third-party-notices system|relay|vault");
        std::process::exit(2);
    };
    let rev = crate::release::revision(repo);
    match notices(repo, a, &rev.sha, None) {
        Ok(t) => print!("{t}"),
        Err(e) => {
            eprintln!("third-party-notices: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    #[test]
    fn a_permissive_or_mpl_expression_passes_and_the_crates_io_slash_is_or() {
        for ok in [
            "MIT OR Apache-2.0",
            "MIT/Apache-2.0",
            "Apache-2.0 / MIT",
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
            "ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)",
            "MPL-2.0",
            "(MIT OR Apache-2.0) AND Unicode-3.0",
        ] {
            assert_eq!(judge(ok), Ok(()), "{ok}");
        }
    }

    #[test]
    fn copyleft_passes_only_where_an_or_offers_a_permissive_branch() {
        assert_eq!(judge("GPL-2.0-only OR BSD-3-Clause"), Ok(()));
        assert_eq!(judge("MIT OR Apache-2.0 OR LGPL-2.1-or-later"), Ok(()));
        let e = judge("GPL-3.0-only").unwrap_err();
        assert!(e.contains("copyleft"), "{e}");
        let e = judge("MIT AND GPL-2.0-only").unwrap_err();
        assert!(e.contains("GPL-2.0-only (copyleft)"), "{e}");
        let e = judge("AGPL-3.0-or-later OR SSPL-1.0").unwrap_err();
        assert!(e.contains("AGPL") && e.contains("SSPL"), "{e}");
        // An exception only helps where the id it modifies is allowed with it.
        assert!(judge("GPL-2.0-only WITH Classpath-exception-2.0").is_err());
        assert!(judge("Some-Unknown-1.0").unwrap_err().contains("not allowed"));
    }

    #[test]
    fn a_malformed_expression_is_refused_not_guessed() {
        for bad in ["", "MIT OR", "(MIT", "AND MIT", "MIT WITH"] {
            assert!(judge(bad).is_err(), "{bad:?}");
        }
    }

    fn pkg(name: &str, version: &str, license: Option<&str>, dir: &Path) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
            license: license.map(str::to_string),
            license_file: Some("LICENSE".into()),
            repository: None,
            dir: dir.to_path_buf(),
            ours: false,
        }
    }

    /// A package with no expression is unknown unless CLARIFIED names it at that version
    /// and its license file still hashes to what was read.
    #[test]
    fn an_unlicensed_package_is_refused_unless_clarified_against_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let e = expression_of(&pkg("mystery", "1.0.0", None, dir.path())).unwrap_err();
        assert!(e.contains("declares no license"), "{e}");
        // ring 0.16.20 is clarified, but not against a file that says something else.
        std::fs::write(dir.path().join("LICENSE"), "GPL, surprise\n").unwrap();
        let e = expression_of(&pkg("ring", "0.16.20", None, dir.path())).unwrap_err();
        assert!(e.contains("read it again"), "{e}");
        // And not at another version.
        assert!(expression_of(&pkg("ring", "0.16.19", None, dir.path())).is_err());
        assert_eq!(
            expression_of(&pkg("x", "1.0.0", Some("MIT"), dir.path())).as_deref(),
            Ok("MIT")
        );
    }

    #[test]
    fn a_manifest_license_is_read_inherited_spelled_or_missing() {
        assert_eq!(manifest_license("[package]\nname = \"a\"\nlicense.workspace = true\n"), Some(Some("workspace".into())));
        assert_eq!(manifest_license("\u{feff}[package]\nname = \"a\"\nlicense = \"Apache-2.0\"\n"), Some(Some("Apache-2.0".into())));
        assert_eq!(manifest_license("[package]\nname = \"a\"\n[dependencies]\nlicense = \"x\"\n"), Some(None));
        assert_eq!(manifest_license("[workspace]\nmembers = []\n"), None);
    }

    #[test]
    fn a_header_is_the_first_line_or_the_one_after_a_shebang() {
        assert_eq!(spdx_header("// SPDX-License-Identifier: Apache-2.0\n//! doc\n"), Some("Apache-2.0"));
        assert_eq!(spdx_header("#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\nset -eu\n"), Some("Apache-2.0"));
        assert_eq!(spdx_header("/* SPDX-License-Identifier: Apache-2.0 */\n"), Some("Apache-2.0"));
        assert_eq!(spdx_header("//! doc\n// SPDX-License-Identifier: Apache-2.0\n"), None);
        assert!(is_source("infra/release/kotton-start", "#!/bin/sh"));
        assert!(!is_source("core/device/migrations/0001_create_events.sql", "CREATE"));
        assert!(!is_source("infra/relay/relay.env", "# x"));
    }

    /// The boundary is drawn by directory: the longest listed prefix wins, and everything
    /// else is the default.
    #[test]
    fn the_boundary_is_by_directory_and_the_rest_is_the_default() {
        assert_eq!(boundary_license("core/kuserd/src/main.rs"), "AGPL-3.0-or-later");
        assert_eq!(boundary_license("guest/apps/kotton-shell/logic/src/lib.rs"), "AGPL-3.0-or-later");
        assert_eq!(boundary_license("guest/sdk/kotton-app/wit/kotton-app.wit"), "Apache-2.0");
        assert_eq!(boundary_license("guest/examples/notes/src/lib.rs"), "Apache-2.0");
        assert_eq!(boundary_license("guest/extensions/feed-reader/Cargo.toml"), "Apache-2.0");
        assert_eq!(boundary_license("xtask/src/main.rs"), "AGPL-3.0-or-later");
        for (id, _) in TEXT_OF {
            assert!(FIRST_PARTY.contains(id));
        }
        for id in FIRST_PARTY {
            assert!(TEXT_OF.iter().any(|(i, _)| i == id), "{id} has no text mark");
        }
        for (_, l) in BOUNDARY {
            assert!(FIRST_PARTY.contains(l));
        }
        assert!(FIRST_PARTY.contains(&DEFAULT));
    }

    /// The two refusals the boundary adds, driven: a manifest declaring an id LICENSE does
    /// not carry, and one declaring the wrong side of the boundary for its directory; and a
    /// LICENSE that carries a text but not the other, or forgets a directory the tables name.
    #[test]
    fn a_manifest_off_its_directorys_side_of_the_boundary_is_refused() {
        assert_eq!(manifest_finding("core/kuserd/Cargo.toml", "core/kuserd/", "AGPL-3.0-or-later"), None);
        assert_eq!(manifest_finding("guest/sdk/kotton-app/Cargo.toml", "guest/sdk/kotton-app/", "Apache-2.0"), None);
        let wrong_side = manifest_finding("guest/sdk/kotton-app/Cargo.toml", "guest/sdk/kotton-app/", "AGPL-3.0-or-later").unwrap();
        assert!(wrong_side.contains("its directory carries `Apache-2.0`"), "{wrong_side}");
        let wrong_side = manifest_finding("core/kuserd/Cargo.toml", "core/kuserd/", "Apache-2.0").unwrap();
        assert!(wrong_side.contains("its directory carries `AGPL-3.0-or-later`"), "{wrong_side}");
        let unknown = manifest_finding("core/x/Cargo.toml", "core/x/", "MIT").unwrap();
        assert!(unknown.contains("not one LICENSE carries"), "{unknown}");
    }

    #[test]
    fn a_license_file_that_forgets_a_text_or_a_directory_is_refused() {
        let whole = std::fs::read_to_string(repo().join("LICENSE")).unwrap();
        assert!(license_text_findings(&whole).is_empty());
        let no_agpl = whole.replace("GNU AFFERO GENERAL PUBLIC LICENSE", "GNU AFFERO");
        assert!(license_text_findings(&no_agpl).iter().any(|f| f.contains("text of AGPL-3.0-or-later")));
        let no_sdk = whole.replace("guest/sdk/", "guest/sdk");
        assert!(license_text_findings(&no_sdk).iter().any(|f| f.contains("`guest/sdk/`")));
        let no_tests = whole.replace("tests/", "tests");
        assert!(license_text_findings(&no_tests).iter().any(|f| f.contains("`tests/`")));
    }

    /// A file takes the license of the deepest crate holding it, so when a trust-path
    /// crate moves licence (DEC-0078) its files' headers are held to the new id and the
    /// SDK's to the old, with no second table to keep in step.
    #[test]
    fn a_files_header_is_held_to_its_own_crates_license() {
        let mut crates = vec![
            ("core/".to_string(), "X".to_string()),
            ("core/kuserd/".to_string(), "AGPL-3.0-or-later".to_string()),
            ("guest/sdk/kotton-app/".to_string(), "Apache-2.0".to_string()),
        ];
        crates.sort_by_key(|(d, _)| std::cmp::Reverse(d.len()));
        assert_eq!(crate_license(&crates, "core/kuserd/src/main.rs"), Some("AGPL-3.0-or-later"));
        assert_eq!(crate_license(&crates, "core/kuserdx/src/main.rs"), Some("X"));
        assert_eq!(crate_license(&crates, "guest/sdk/kotton-app/src/lib.rs"), Some("Apache-2.0"));
        assert_eq!(crate_license(&crates, "infra/release/install.sh"), None);
    }

    /// ring 0.16.20's OpenSSL terms are tolerated in a lockfile and never in an archive:
    /// its expression is one ALLOWED does not satisfy, so `notices` refuses it.
    #[test]
    fn ring_0_16_is_clarified_for_a_lockfile_and_never_ships() {
        let c = CLARIFIED.iter().find(|c| c.name == "ring").unwrap();
        assert!(c.workspace_only.is_some());
        assert!(judge(c.expression).unwrap_err().contains("OpenSSL (not allowed)"));
        assert!(!ALLOWED.contains(&"OpenSSL"));
    }

    fn sample() -> String {
        "THIRD-PARTY-NOTICES — the Kotton relay archive, abc\n\nGenerated by `x` from the lockfiles below, never written by hand.\n\nThird-party packages: 2\nname\tversion\tlicense\tsource\tlicense texts\na\t1.0.0\tMIT\thttps://x\t[1]\nb\t2.0.0\tMIT OR Apache-2.0\thttps://y\t(no license file in the package; the SPDX id is the notice)\n\nLicense texts: 1\n\n======== [1] a 1.0.0 (LICENSE)\n\nMIT text\n".to_string()
    }

    #[test]
    fn a_notices_file_is_held_to_its_own_shape() {
        assert_eq!(check_notices(&sample()), Ok(2));
        let truncated = sample().replace("b\t2.0.0\tMIT OR Apache-2.0\thttps://y\t(no license file in the package; the SPDX id is the notice)\n", "");
        assert!(check_notices(&truncated).unwrap_err().contains("says 2 packages and lists 1"));
        let uncited = sample().replace("======== [1] ", "======== [9] ");
        assert!(check_notices(&uncited).unwrap_err().contains("not written out"));
        let gpl = sample().replace("\tMIT\t", "\tGPL-3.0-only\t");
        assert!(check_notices(&gpl).is_err());
        assert!(check_notices("").is_err());
        assert!(check_notices("THIRD-PARTY-NOTICES\nThird-party packages: 0\nname\n\nLicense texts: 0\n").is_err());
    }

    /// The relay's notices, generated from its lockfile: every row is a package the
    /// lockfile holds at that version, and a package it holds only as a dev-dependency
    /// is not there.
    #[test]
    fn the_relays_notices_are_its_lockfiles_shipped_closure() {
        let t = notices(&repo(), &RELAY, "test", None).unwrap();
        let n = check_notices(&t).unwrap();
        assert!(n > 50, "{n}");
        let lock = std::fs::read_to_string(repo().join("infra/relay/Cargo.lock")).unwrap();
        let rows = t.lines().skip_while(|l| !l.starts_with("name\t")).skip(1).take_while(|l| !l.is_empty());
        for row in rows {
            let f: Vec<&str> = row.split('\t').collect();
            assert!(
                lock.contains(&format!("name = \"{}\"\nversion = \"{}\"", f[0], f[1])),
                "{} {} is not in infra/relay/Cargo.lock",
                f[0],
                f[1]
            );
        }
        // The relay's integration test dev-depends on tokio-tungstenite 0.21, which the
        // lockfile holds and nothing the relay ships reaches (it ships 0.24).
        assert!(lock.contains("name = \"tokio-tungstenite\"\nversion = \"0.21.0\""));
        assert!(!t.contains("\ntokio-tungstenite\t0.21.0\t"), "a dev-dependency reached the notices");
        assert!(t.contains("infra/relay/Cargo.lock  sha256 "));
        assert!(t.contains("kotton-relay"), "Kotton's own crates are named");
    }

    /// `ui/fonts/` as it stands: every file a font [`FONTS`] pins or the licence beside
    /// one, every font's bytes its pin. And the walk argues back — a file dropped in beside
    /// them, or a font whose bytes moved, is a finding.
    #[test]
    fn the_carried_fonts_are_pinned_and_licensed_beside_them() {
        let listing: Vec<String> = std::fs::read_dir(repo().join(FONT_DIR))
            .unwrap()
            .flatten()
            .map(|e| format!("{FONT_DIR}{}", e.file_name().to_string_lossy()))
            .collect();
        assert_eq!(font_findings(&repo(), &listing), Vec::<String>::new());
        assert!(listing.iter().any(|f| f == "ui/fonts/OFL.txt"), "{listing:?}");

        let mut planted = listing.clone();
        planted.push("ui/fonts/Inter.ttf".into());
        let found = font_findings(&repo(), &planted);
        assert!(found.len() == 1 && found[0].contains("Inter.ttf"), "{found:?}");

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(FONT_DIR)).unwrap();
        for f in &listing {
            std::fs::copy(repo().join(f), dir.path().join(f)).unwrap();
        }
        std::fs::write(dir.path().join("ui/fonts/Geist-Variable.ttf"), b"not the pinned bytes").unwrap();
        let found = font_findings(dir.path(), &listing);
        assert!(found.len() == 1 && found[0].contains("Geist-Variable.ttf: sha256"), "{found:?}");
    }

    /// No archive ships a crate that carries a font — `kuid`, the one that embedded them, is
    /// not built here — so no archive's notices name one, and each is held to its shape.
    #[test]
    fn no_archives_notices_name_a_font_while_none_ships_the_crate_that_carries_one() {
        for shipped in [SYSTEM, RELAY] {
            let t = notices(&repo(), &shipped, "test", None).unwrap();
            check_notices(&t).unwrap();
            assert!(fonts_in(&t).unwrap().is_empty(), "{} names a font", shipped.name);
        }
    }

    /// A fonts section is held to its own shape, as the package table is: its count is its
    /// rows, and a row cites a licence text that is written out.
    #[test]
    fn a_notices_fonts_section_is_held_to_its_own_shape() {
        let fonts = "\nFonts, carried from ui/fonts/: 1\nfamily\tversion\tlicense\tsource\tlicense texts\nGeist\t1.800\tOFL-1.1\thttps://z\t[2]\n";
        let base = sample();
        let (head, tail) = base.split_at(base.find("\nLicense texts: ").unwrap());
        let two = tail.replace("License texts: 1", "License texts: 2")
            + "\n======== [2] Geist 1.800 (ui/fonts/OFL.txt)\n\nSIL OPEN FONT LICENSE Version 1.1\n";
        let good = format!("{head}{fonts}{two}");
        check_notices(&good).unwrap();
        assert_eq!(fonts_in(&good).unwrap().len(), 1);

        let uncited = format!("{head}{}{tail}", fonts.replace("[2]", "[3]"));
        assert!(check_notices(&uncited).unwrap_err().contains("Geist cites license text [3]"));
        let miscounted = format!("{head}{}{two}", fonts.replace(": 1\n", ": 2\n"));
        assert!(check_notices(&miscounted).unwrap_err().contains("says 2 fonts and lists 1"));
        let unlicensed = format!("{head}{}{two}", fonts.replace("OFL-1.1", "GPL-3.0-only"));
        assert!(check_notices(&unlicensed).unwrap_err().contains("FONT_LICENSES"));
    }
}
