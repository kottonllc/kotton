// SPDX-License-Identifier: AGPL-3.0-or-later
//! What the tree is made of, in one place.
//!
//! ## Why this exists
//!
//! Measured 2026-08-25: **eleven hardcoded top-level path lists across eight files**, in four
//! different spellings (with and without a trailing slash, with and without `tests/`), plus
//! **four hand-copied `DOMAINS` lists**. Every gate that walks the tree carried its own idea
//! of what the tree is.
//!
//! The cost is not untidiness, it is silent under-coverage. When `DEC-0041` moved `apps/` and
//! `sdk/` under new parents, four gates degraded **without failing**: `rsx-check` went to
//! *0 files scanned* and reported OK, `channel-check` scanned 361 of 497, `measure-check` lost
//! `rg` and printed *"could not search; treating as resolved"*. The one that failed loudly —
//! `seam-check` — did so only because somebody had written a test asserting its roots still
//! matched something.
//!
//! ## The rule
//!
//! **A hardcoded list is fine. An unchecked one is not.** These stay explicit rather than
//! globbed, because a gate's scope should be a decision somebody made, not whatever happened
//! to be on disk. What changes is that the tree now argues back: [`tests`] asserts every entry
//! resolves, and — the rule that would have caught the whole 2026-08-25 class — that **no
//! top-level directory containing Rust is missing from [`CODE_ROOTS`]**.
//!
//! One list, not eleven. Each gate that walks the tree names it.

/// Every top-level root that holds compilable code.
///
/// `core/` (the system, the vault and the protocol's crates) and `client/` (the CLI, the client
/// library and the device-owner tool), plus `infra/` (the relay, which is not a node),
/// `tools/` (test instruments), `xtask/` (the gates themselves) and `tests/` (the integration
/// harness). A gate asking *"where is the code"* means this.
pub const CODE_ROOTS: &[&str] = &["core", "client", "infra", "tools", "xtask", "tests"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn repo() -> std::path::PathBuf {
        crate::out::root()
    }

    /// Every name here is a real directory. A gate pointed at a path that does not exist does
    /// not fail — `rg` exits 2, the caller treats it as "cannot tell", and the check reports
    /// OK over nothing.
    #[test]
    fn every_named_root_exists() {
        for r in CODE_ROOTS {
            assert!(
                repo().join(r).is_dir(),
                "`{r}` is named here and is not a directory"
            );
        }
    }

    /// **The rule that would have caught 2026-08-25.** If a top-level directory holds Rust and
    /// is not in `CODE_ROOTS`, some gate is walking past it in silence.
    #[test]
    fn no_root_holding_rust_is_missing() {
        let mut missing = Vec::new();
        for entry in std::fs::read_dir(repo())
            .expect("repo root readable")
            .flatten()
        {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.')
                || is_build_output(&name)
                || CODE_ROOTS.contains(&name.as_str())
            {
                continue;
            }
            if holds_rust(&path) {
                missing.push(name);
            }
        }
        assert!(
            missing.is_empty(),
            "top-level dir(s) hold Rust and are in no gate's scope: {missing:?}"
        );
    }

    /// `tier-check`'s rows are held to the roots: every root a row lies in is a code root, and
    /// every code root is a row's or named as no row. A root in neither is
    /// code `tier-check` walks past.
    #[test]
    fn the_rows_lie_in_the_code_roots() {
        let rowed = crate::tier_check::row_roots();
        for r in &rowed {
            assert!(CODE_ROOTS.contains(r), "a row lies in `{r}`, which is not in CODE_ROOTS");
        }
        for r in CODE_ROOTS {
            let not = crate::tier_check::NOT_ROWS.contains(r);
            assert!(
                rowed.contains(r) != not,
                "code root `{r}` must be a row's or named as no row, and not both"
            );
        }
        for row in crate::tier_check::ROWS {
            for p in row.paths {
                assert!(repo().join(p).is_dir(), "row `{}` names `{p}`, which is not a directory", row.name);
            }
        }
    }

    /// Whether a directory is build output rather than source.
    ///
    /// **`target-*`, not just `target`.** The `cargo xtask` aliases in
    /// `.cargo/config.toml` build into `target-xtask`, and build scripts write
    /// generated `.rs` into it (`.../out/private.rs`, from `serde` and
    /// `thiserror`). This test skipped a directory named exactly `target`, so
    /// `target-xtask` read as *a top-level directory holding Rust that no gate
    /// walks* — and it fails on any checkout where `cargo xtask` has run, which
    /// is every checkout, because `just lint` and `just test` both run it.
    ///
    /// `.gitignore` generalised its own rule to `target-*/` on 2026-09-18, for
    /// the same directory and after 123 MB of it reached `main`. This is the
    /// half of that correction that was missed. Found by an executive on
    /// RFC-0087 stage 2, whose `just test` went red on it.
    ///
    /// **And `out`**, where every build output has lived since 2026-09-26 — the
    /// workspace's, xtask's, the guest apps' and the relay's, each holding the same
    /// generated `.rs` (`crate::out`). `target` and `target-*` stay, for a checkout that
    /// still carries the trees from before.
    fn is_build_output(name: &str) -> bool {
        name == crate::out::OUT || name == "target" || name.starts_with("target-")
    }

    fn holds_rust(dir: &Path) -> bool {
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    if p.file_name()
                        .is_some_and(|n| is_build_output(&n.to_string_lossy()))
                    {
                        continue;
                    }
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    return true;
                }
            }
        }
        false
    }
}
