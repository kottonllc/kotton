// SPDX-License-Identifier: AGPL-3.0-or-later
//! The lines the guides under `docs/use/` type, held to the lines the shell prints.
//!
//! `kotton mint`, `mint host` and `vault invite --me` print or take the lines a person types
//! at a host or a desktop, and the guides type the same lines. The pages are this tree's and
//! not the shell's: a release of the shell ships without them, so the shell's tests read none
//! of them. The shell says what it prints, [`kotton_shell::typed_lines`], and holds that to
//! its verbs in its own test; this holds each page to it. `docs-check` runs it, beside the two
//! generated references, so a page and a verb cannot drift apart without `just lint` failing.

/// How a page types a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Typed {
    /// On a line of its own, as a command block types it.
    OnALineOfItsOwn,
    /// Inside backticks, in the page's prose.
    InBackticks,
}

/// One line a page must type, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wanted {
    /// The page, from the root of the tree.
    pub(crate) page: &'static str,
    pub(crate) typed: Typed,
    pub(crate) line: String,
}

/// Every line in `wanted` that its page does not type as it says, one finding each; a page
/// `read` cannot read is a finding too. Nothing is a pass.
pub(crate) fn findings(wanted: &[Wanted], read: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut found = Vec::new();
    for w in wanted {
        let Some(page) = read(w.page) else {
            found.push(format!("{}: not readable", w.page));
            continue;
        };
        let typed = match w.typed {
            Typed::OnALineOfItsOwn => page.lines().any(|l| l.trim_end_matches('\r') == w.line),
            Typed::InBackticks => page.contains(&format!("`{}`", w.line)),
        };
        if !typed {
            let how = match w.typed {
                Typed::OnALineOfItsOwn => "on a line of its own",
                Typed::InBackticks => "in backticks",
            };
            found.push(format!("{}: does not type `{}` {how}", w.page, w.line));
        }
    }
    found
}

/// What each guide types of what the shell prints, for the placeholders the guides write for
/// a key.
#[cfg(feature = "cli-docs")]
pub(crate) fn wanted() -> Vec<Wanted> {
    const HOST: &str = "docs/use/run-a-host.md";
    const FIRST_HOUR: &str = "docs/use/first-hour.md";
    const VAULT: &str = "docs/use/run-a-vault.md";
    const RELAY: &str = "docs/use/run-a-relay.md";
    let lines = kotton_shell::typed_lines("<key>", "<relay key>", "<vault key>");
    let want = |page, typed, line: &String| Wanted { page, typed, line: line.clone() };
    use Typed::{InBackticks, OnALineOfItsOwn};
    vec![
        // The host's guide types the two lines `mint host` prints, and the verbs either side.
        want(HOST, OnALineOfItsOwn, &lines.host_clone),
        want(HOST, OnALineOfItsOwn, &lines.host_install),
        want(HOST, OnALineOfItsOwn, &lines.mint_host),
        want(HOST, OnALineOfItsOwn, &lines.enrol_the_hosts_line),
        // And the first hour runs `mint host` and enrols the line the host printed.
        want(FIRST_HOUR, OnALineOfItsOwn, &lines.mint_host),
        want(FIRST_HOUR, OnALineOfItsOwn, &lines.enrol_the_hosts_line),
        // Each service's guide types the install a mint prints for a new one, and the line a
        // running one takes for a second operator.
        want(VAULT, OnALineOfItsOwn, &lines.create_vault),
        want(VAULT, InBackticks, &lines.at_the_vault),
        want(VAULT, InBackticks, &lines.vault_invite_me),
        want(RELAY, OnALineOfItsOwn, &lines.create_relay),
        want(RELAY, OnALineOfItsOwn, &lines.at_the_relay),
    ]
}

/// [`findings`] for [`wanted`], each page read from `root`.
#[cfg(feature = "cli-docs")]
pub(crate) fn check(root: &std::path::Path) -> (usize, Vec<String>) {
    let wanted = wanted();
    let found = findings(&wanted, |page| std::fs::read_to_string(root.join(page)).ok());
    (wanted.len(), found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(page: &'static str, typed: Typed, line: &str) -> Vec<Wanted> {
        vec![Wanted { page, typed, line: line.to_string() }]
    }

    fn reading(text: &'static str) -> impl Fn(&str) -> Option<String> {
        move |_| Some(text.to_string())
    }

    #[test]
    fn a_line_typed_on_its_own_passes_and_one_inside_a_sentence_does_not() {
        let wanted = one("p.md", Typed::OnALineOfItsOwn, "kotton mint host");
        assert!(findings(&wanted, reading("Run it:\n\nkotton mint host\n")).is_empty());
        assert!(findings(&wanted, reading("Run it:\r\nkotton mint host\r\n")).is_empty(), "CRLF");
        let found = findings(&wanted, reading("Run `kotton mint host` at your desktop.\n"));
        assert_eq!(found, ["p.md: does not type `kotton mint host` on a line of its own"]);
        assert_eq!(findings(&wanted, reading("kotton mint host --key\n")).len(), 1, "a longer line is another line");
    }

    #[test]
    fn a_line_in_backticks_passes_and_bare_does_not() {
        let wanted = one("p.md", Typed::InBackticks, "kotton vault invite --me");
        assert!(findings(&wanted, reading("then `kotton vault invite --me` takes it\n")).is_empty());
        assert_eq!(findings(&wanted, reading("kotton vault invite --me\n")).len(), 1);
    }

    #[test]
    fn a_page_that_cannot_be_read_is_a_finding_not_a_pass() {
        let wanted = one("gone.md", Typed::InBackticks, "x");
        assert_eq!(findings(&wanted, |_| None), ["gone.md: not readable"]);
    }

    /// The real guides type what the real shell prints: the check `docs-check` runs, as a
    /// test, so `cargo test -p xtask --features cli-docs` says the same thing `just lint` does.
    #[cfg(feature = "cli-docs")]
    #[test]
    fn the_guides_type_what_the_shell_prints() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent");
        let (wanted, found) = check(root);
        assert_eq!(wanted, 11);
        assert!(found.is_empty(), "{found:#?}");
    }
}
