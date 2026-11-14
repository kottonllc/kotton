// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ed25519-check`: every Ed25519 check in the tree is strict, and goes through one seam.
//!
//! ## What holds it
//!
//! Two things, one typed and one textual.
//!
//! - **The workspace's `clippy.toml`** refuses `ed25519_dalek::Verifier::verify` and the
//!   inherent `ed25519_dalek::SigningKey::verify`: the two ways to make the unstrict check. Clippy
//!   resolves the call, so a trait brought in under any name, a generic bound or a fully
//!   qualified call is refused as surely as `key.verify(..)`. `just lint` runs clippy over the
//!   workspace and over the relay's own workspace, `--all-targets`, so tests are held too, and
//!   with `-D warnings`, so a refusal fails the gate.
//! - **This check** holds what clippy cannot hold of itself: that the file is there and names
//!   both methods; that no other `clippy.toml` shadows it for a crate below it; that nothing
//!   turns the lint off but the one exemption named here ([`EXEMPTION`]); and the seam: in a
//!   crate that depends on `kotton-crypto` a check is `kotton_crypto::ed25519::verify`, so
//!   `verify_strict` is called in [`SEAM`] and, outside it, only in a crate that does not link
//!   `kotton-crypto` (`kotton-pair`, below it, and the relay).
//!
//! ## What it reads
//!
//! Every `.rs` file and `Cargo.toml` under the code roots (`tree::CODE_ROOTS`), tests
//! included, and the root manifest, `Justfile`, `just/*.just`, `.cargo/config.toml` and the
//! workflows for anything that would turn the lint off. It skips comment lines (starting with
//! `//`), and its own source, whose tests spell what it refuses. It reads text: an `allow` built by a macro, or a lint level set in an environment
//! variable at run time, is outside it; `just lint` and the workflows set none.

use std::path::{Path, PathBuf};

use crate::user_database_check::{rel, walk};

/// The file that holds the refusal, at the root of the tree.
const CLIPPY_TOML: &str = "clippy.toml";

/// The methods it refuses: every way to make the unstrict check.
const REFUSED: &[&str] = &["ed25519_dalek::Verifier::verify", "ed25519_dalek::SigningKey::verify"];

/// The one function every crate that depends on `kotton-crypto` calls for an Ed25519 check.
const SEAM: &str = "core/crypto/src/provider/ed25519.rs";

/// The one place the lint is allowed: (file, the test it is allowed on). The test holds the
/// difference between the strict check and the other one, so it makes the other one.
const EXEMPTION: (&str, &str) = (
    "core/crypto/src/schema_signature.rs",
    "fn a_small_order_publisher_key_with_a_forged_signature_is_refused",
);

/// This check's own source, whose tests spell what it refuses.
const THIS: &str = "xtask/src/ed25519_check.rs";

/// What turns the lint off when written in an attribute or a manifest.
const OFF: &[&str] = &["disallowed_methods", "disallowed-methods"];

pub fn run(root: &Path) {
    let mut files = Vec::new();
    for r in crate::tree::CODE_ROOTS {
        walk(&root.join(r), &mut files);
    }
    files.sort();
    let mut sources = Vec::new();
    let mut manifests = Vec::new();
    let mut shadows = Vec::new();
    for path in &files {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if name == CLIPPY_TOML || name == ".clippy.toml" {
            shadows.push(rel(root, path));
            continue;
        }
        let rs = path.extension().is_some_and(|e| e == "rs");
        if !rs && name != "Cargo.toml" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!("ed25519-check: could not read {}", path.display());
            std::process::exit(1);
        };
        if rs {
            sources.push((rel(root, path), text));
        } else {
            manifests.push((rel(root, path), text));
        }
    }
    if sources.is_empty() {
        eprintln!("ed25519-check: found no .rs file under the code roots. Run from the workspace root.");
        std::process::exit(1);
    }
    let mut elsewhere = Vec::new();
    for extra in [Path::new("Cargo.toml"), Path::new("Justfile"), Path::new(".cargo/config.toml")] {
        elsewhere.push(root.join(extra));
    }
    walk(&root.join("just"), &mut elsewhere);
    walk(&root.join(".github/workflows"), &mut elsewhere);
    let mut others = Vec::new();
    for path in &elsewhere {
        if let Ok(text) = std::fs::read_to_string(path) {
            others.push((rel(root, path), text));
        }
    }

    let config = std::fs::read_to_string(root.join(CLIPPY_TOML)).ok();
    let mut found = config_findings(config.as_deref(), &shadows);
    found.extend(allowance_findings(&sources, &manifests, &others));
    found.extend(seam_findings(&sources, &crates_linking_crypto(root, &files)));
    if found.is_empty() {
        println!(
            "ed25519-check: OK: {} source file(s); clippy.toml refuses the unstrict check, one named \
             exemption, and verify_strict only in the seam and in crates that do not link kotton-crypto.",
            sources.len()
        );
        return;
    }
    for f in &found {
        eprintln!("ed25519-check: {f}");
    }
    eprintln!(
        "\nEvery Ed25519 check in the tree is strict: kotton_crypto::ed25519::verify ({SEAM}) in a \
         crate that depends on kotton-crypto, verify_strict in one that does not."
    );
    std::process::exit(1);
}

/// `clippy.toml` is at the root, names every refused method, and no other shadows it.
fn config_findings(config: Option<&str>, shadows: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    match config {
        None => out.push(format!("{CLIPPY_TOML} is not at the root of the tree")),
        Some(text) => {
            let code: String = text.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n");
            for m in REFUSED {
                if !code.contains(&format!("path = \"{m}\"")) {
                    out.push(format!("{CLIPPY_TOML} does not refuse `{m}` (disallowed-methods)"));
                }
            }
        }
    }
    for s in shadows {
        out.push(format!("{s}: a clippy configuration below the root's, which the crates under it would read instead"));
    }
    out
}

/// Nothing turns the lint off but [`EXEMPTION`], and that is there, once, on its test.
fn allowance_findings(sources: &[(String, String)], manifests: &[(String, String)], others: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut exempt = 0;
    for (file, src) in sources {
        let lines: Vec<&str> = src.lines().collect();
        for (i, text) in lines.iter().enumerate() {
            if text.trim_start().starts_with("//") {
                continue;
            }
            let lowers = text.contains("allow(") || text.contains("expect(");
            let names = OFF.iter().any(|w| text.contains(w))
                || text.contains("clippy::all")
                || text.contains("clippy::style");
            if file == THIS || !lowers || !names {
                continue;
            }
            let on_exempt_test = file == EXEMPTION.0
                && text.trim() == "#[allow(clippy::disallowed_methods)]"
                && lines[i + 1..]
                    .iter()
                    .find(|l| !l.trim_start().starts_with("#["))
                    .is_some_and(|l| l.contains(EXEMPTION.1));
            if on_exempt_test {
                exempt += 1;
                continue;
            }
            out.push(format!("{file}:{}: turns off the refusal of the unstrict check: {}", i + 1, text.trim()));
        }
    }
    if exempt != 1 {
        out.push(format!(
            "{}: the one exemption is `#[allow(clippy::disallowed_methods)]` on `{}`, once; found {exempt}",
            EXEMPTION.0, EXEMPTION.1
        ));
    }
    for (file, text) in manifests.iter().chain(others) {
        let mut in_clippy_lints = false;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.starts_with('#') {
                continue;
            }
            if t.starts_with('[') {
                in_clippy_lints = t.ends_with("lints.clippy]");
                continue;
            }
            let key = t.split('=').next().unwrap_or("").trim();
            let group = in_clippy_lints && (key == "all" || key == "style") && t.contains("allow");
            if OFF.iter().any(|w| t.contains(w)) || group {
                out.push(format!("{file}:{}: turns off the refusal of the unstrict check: {t}", i + 1));
            }
        }
    }
    out
}

/// `verify_strict` is called in [`SEAM`], and elsewhere only in a crate that does not link
/// `kotton-crypto`. `crypto_crates` holds the directories of the crates that do, and
/// `kotton-crypto`'s own.
fn seam_findings(sources: &[(String, String)], crypto_crates: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seam_calls = 0;
    for (file, src) in sources {
        let linked = crypto_crates.iter().any(|dir| file.starts_with(&format!("{dir}/")));
        for (i, text) in src.lines().enumerate() {
            if text.trim_start().starts_with("//") || !text.contains("verify_strict") {
                continue;
            }
            if file == SEAM {
                seam_calls += 1;
                continue;
            }
            if linked {
                out.push(format!(
                    "{file}:{}: calls verify_strict in a crate that links kotton-crypto; call kotton_crypto::ed25519::verify",
                    i + 1
                ));
            }
        }
    }
    if seam_calls == 0 {
        out.push(format!("{SEAM}: the seam calls no verify_strict"));
    }
    out
}

/// The directories (relative, `/`-separated) of `kotton-crypto` and every crate whose manifest
/// names it.
fn crates_linking_crypto(root: &Path, files: &[PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    for path in files.iter().filter(|p| p.file_name().is_some_and(|n| n == "Cargo.toml")) {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        if manifest_links_crypto(&text) {
            out.push(rel(root, path.parent().unwrap_or(root)));
        }
    }
    out
}

/// Whether a manifest is `kotton-crypto`'s or names it as a dependency of any kind.
fn manifest_links_crypto(text: &str) -> bool {
    text.lines().map(str::trim).filter(|l| !l.starts_with('#')).any(|l| {
        l.starts_with("kotton-crypto ") || l.starts_with("kotton-crypto=") || l.replace(' ', "") == "name=\"kotton-crypto\""
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(file: &str, src: &str) -> Vec<(String, String)> {
        vec![(file.to_string(), src.to_string())]
    }

    const EXEMPT_SRC: &str = "#[cfg(test)]\nmod tests {\n    /// Why.\n    #[test]\n    #[allow(clippy::disallowed_methods)]\n    fn a_small_order_publisher_key_with_a_forged_signature_is_refused() {}\n}\n";

    #[test]
    fn the_config_names_both_methods_and_is_not_shadowed() {
        let good = "disallowed-methods = [\n  { path = \"ed25519_dalek::Verifier::verify\", reason = \"r\" },\n  { path = \"ed25519_dalek::SigningKey::verify\", reason = \"r\" },\n]\n";
        assert!(config_findings(Some(good), &[]).is_empty());
        let one_only = "disallowed-methods = [\n  { path = \"ed25519_dalek::Verifier::verify\", reason = \"r\" },\n  # { path = \"ed25519_dalek::SigningKey::verify\" },\n]\n";
        assert_eq!(config_findings(Some(one_only), &[]).len(), 1);
        assert_eq!(config_findings(None, &[]).len(), 1);
        assert_eq!(config_findings(Some(good), &["infra/relay/clippy.toml".into()]).len(), 1);
    }

    #[test]
    fn the_one_exemption_passes_and_any_other_allow_is_a_finding() {
        assert!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &[], &[]).is_empty());

        // The same allow anywhere else, or on another test, is a finding.
        let elsewhere = EXEMPT_SRC.replace("fn a_small_order", "fn another_small_order");
        assert_eq!(allowance_findings(&one(EXEMPTION.0, &elsewhere), &[], &[]).len(), 2);
        let mut two = one(EXEMPTION.0, EXEMPT_SRC);
        two.push(("core/msg/src/x.rs".into(), "#![allow(clippy::disallowed_methods)]\n".into()));
        assert_eq!(allowance_findings(&two, &[], &[]).len(), 1);

        // A lint group that holds it, allowed, is a finding.
        let mut group = one(EXEMPTION.0, EXEMPT_SRC);
        group.push(("core/msg/src/x.rs".into(), "#[allow(clippy::style)]\nfn f() {}\n".into()));
        assert_eq!(allowance_findings(&group, &[], &[]).len(), 1);

        // So is turning it off in a manifest or on the command line.
        let manifest = vec![("Cargo.toml".to_string(), "[workspace.lints.clippy]\ndisallowed_methods = \"allow\"\n".to_string())];
        assert_eq!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &manifest, &[]).len(), 1);
        let style = vec![("core/msg/Cargo.toml".to_string(), "[lints.clippy]\nstyle = \"allow\"\n".to_string())];
        assert_eq!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &style, &[]).len(), 1);
        let just = vec![("Justfile".to_string(), "lint:\n    cargo clippy -- -A clippy::disallowed_methods\n".to_string())];
        assert_eq!(allowance_findings(&one(EXEMPTION.0, EXEMPT_SRC), &[], &just).len(), 1);

        // And the exemption gone is a finding: the allowance does not outlive its test.
        assert_eq!(allowance_findings(&one(EXEMPTION.0, "fn f() {}\n"), &[], &[]).len(), 1);
    }

    #[test]
    fn verify_strict_outside_the_seam_in_a_crate_linking_crypto_is_a_finding() {
        let crypto = vec!["core/crypto".to_string(), "core/msg".to_string()];
        let seam = (SEAM.to_string(), "pub fn verify() { key.verify_strict(m, s) }\n".to_string());
        let pair = ("core/pair/src/browser.rs".to_string(), "vk.verify_strict(msg, &sig)\n".to_string());
        let relay = ("infra/relay/src/auth.rs".to_string(), "key.verify_strict(m, s)\n".to_string());
        let comment = ("core/msg/src/a.rs".to_string(), "// verify_strict, in prose\n".to_string());
        assert!(seam_findings(&[seam.clone(), pair, relay, comment], &crypto).is_empty());

        let in_msg = ("core/msg/src/envelope.rs".to_string(), "fn f() {\n    key.verify_strict(m, s)\n}\n".to_string());
        let found = seam_findings(&[seam.clone(), in_msg], &crypto);
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("core/msg/src/envelope.rs:2:"), "{found:?}");

        let in_crypto = ("core/crypto/src/warm_key.rs".to_string(), "key.verify_strict(m, s)\n".to_string());
        assert_eq!(seam_findings(&[seam, in_crypto], &crypto).len(), 1);

        // A seam that no longer calls verify_strict is a finding.
        assert_eq!(seam_findings(&[(SEAM.to_string(), "pub fn verify() {}\n".to_string())], &crypto).len(), 1);
    }

    #[test]
    fn a_manifest_links_crypto_by_name_or_by_dependency() {
        assert!(manifest_links_crypto("[package]\nname = \"kotton-crypto\"\n"));
        assert!(manifest_links_crypto("[dependencies]\nkotton-crypto = { path = \"../crypto\" }\n"));
        assert!(manifest_links_crypto("[dev-dependencies]\nkotton-crypto = { path = \"../crypto\", features = [\"test-utils\"] }\n"));
        assert!(!manifest_links_crypto("[dependencies]\nkotton-pair = { path = \"../pair\" }\n# kotton-crypto = {}\n"));
    }

    /// The tree as it is: the config, the one exemption and the seam hold.
    #[test]
    fn the_tree_holds() {
        let root = crate::out::root();
        let config = std::fs::read_to_string(root.join(CLIPPY_TOML)).ok();
        assert!(config_findings(config.as_deref(), &[]).is_empty());
        let mut files = Vec::new();
        for r in crate::tree::CODE_ROOTS {
            walk(&root.join(r), &mut files);
        }
        let sources: Vec<(String, String)> = files
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .filter_map(|p| Some((rel(&root, p), std::fs::read_to_string(p).ok()?)))
            .collect();
        let found = seam_findings(&sources, &crates_linking_crypto(&root, &files));
        assert!(found.is_empty(), "{found:#?}");
        let found = allowance_findings(&sources, &[], &[]);
        assert!(found.is_empty(), "{found:#?}");
    }
}
