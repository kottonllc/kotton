// SPDX-License-Identifier: AGPL-3.0-or-later
//! `claim-check`: a page may not tell a reader to run a `kotton` command the binary lacks.
//!
//! The commands a person is told to type are the one part of a page that is mechanically
//! checkable, and `docs/cli/reference.md` is generated from the real command tree and held to
//! it by `docs-check` — so every page this reads is held to the reference, and through it to
//! the binary. A page that teaches a command the binary does not have is worse than no page.
//!
//! **What it reads:** `README.md`, always — it is the page of commands this repository
//! gives — and every page named on its command line, so a page added later is gated by naming
//! it in the `just lint` line that runs this. A page that cannot be read is refused, not
//! skipped: a gate over a page it never opened is a gate over nothing.
//!
//! It reads the commands, not the sentence beside them: whether a page's prose is true stays
//! a reviewer's job.
//!
//! **And the line that installs.** A person installs from the distribution,
//! `kottonllc/kotton-dist`, which holds the release tags and the assets a person installs and
//! fetches this repository's archives by its own lock. So the README's first line is
//! [`INSTALL`], byte for byte the line the distribution's README carries, and the README is
//! refused without it as a line of a fenced block: a page that clones this repository to
//! install gets a tag the distribution does not have, or an installer that is not the one that
//! runs. `kotton-dist/` is the distribution's tree, which this gate cannot read; the line is
//! held here, and the distribution holds its own README to it.
//!
//! **And the scripts a page runs from a checkout of this tree.** Every `sh kotton/<path>` in a
//! fenced block, `kotton/` being the directory a clone of this repository makes, must name a
//! file this tree has: a page that runs a script the checkout lacks fails at the reader's first
//! line, exactly as a missing command does.

/// The page every run reads, whatever else it is given.
const README: &str = "README.md";

/// The line that installs a release, as the distribution's README gives it and the README
/// here must carry: clone the distribution at a release's tag, and run its `install.sh`.
/// `kotton mint host` prints its first half and the same script, held to the README by the
/// shell's own test.
pub(crate) const INSTALL: &str =
    "git clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton-dist && sh kotton-dist/install.sh";
const CLI_REF: &str = "docs/cli/reference.md";

/// Every `kotton …` invocation inside a fenced block, longest-first against the real tree.
///
/// The commands a user is told to type are the one part of a page that is mechanically
/// checkable, and `docs/cli/reference.md` is already generated from the command tree and
/// gated by `docs-check` — so a page can be held to it for free. A flag or an argument is
/// not a subcommand, so the longest known prefix wins and the rest is the user's input.
fn unknown_commands(text: &str, known: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            continue;
        }
        let t = line.trim().trim_start_matches("$ ").trim();
        if !t.starts_with("kotton ") {
            continue;
        }
        let words: Vec<&str> = t.split_whitespace().collect();
        // Longest known prefix wins; what follows is the user's own argument.
        let mut depth = 0usize;
        for n in (1..=words.len().min(4)).rev() {
            let cand = words[..n].join(" ").to_ascii_lowercase();
            if known.contains(&cand) {
                depth = n;
                break;
            }
        }
        // The bare root is in the command tree, so matching at depth 1 would accept
        // `kotton anything-at-all` and make this rule vacuous — which is exactly what it did
        // on its first run, and why it is tested against an invented subcommand rather than
        // trusted. A depth-1 match is only real when what follows is a flag or nothing.
        let real = depth >= 2 || (depth == 1 && words[1..].iter().all(|w| w.starts_with('-')));
        if !real && !out.contains(&t.to_string()) {
            out.push(t.to_string());
        }
    }
    out
}

/// Every `sh kotton/<path>` inside a fenced block whose `<path>` `exists` does not hold, as
/// the `kotton/<path>` the page typed.
///
/// `kotton/` is the directory `git clone https://github.com/kottonllc/kotton` makes, so the
/// rest is a path in this tree. `kotton-dist/` is the distribution's, and is not read. An archive's directory (`kotton-relay-<rev>-…/install.sh`) is
/// not the checkout and is not read.
fn missing_scripts(text: &str, exists: impl Fn(&str) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        for pair in words.windows(2) {
            let Some(path) = pair[1].strip_prefix("kotton/") else { continue };
            if pair[0] == "sh" && !exists(path) && !out.contains(&pair[1].to_string()) {
                out.push(pair[1].to_string());
            }
        }
    }
    out
}

/// Whether `text` gives [`INSTALL`] as a whole line of a fenced block.
fn carries_install(text: &str) -> bool {
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced && line.trim() == INSTALL {
            return true;
        }
    }
    false
}

/// The command tree, as the generated reference lists it.
fn known_commands(cli_ref: &str) -> Vec<String> {
    cli_ref
        .lines()
        .filter_map(|l| l.trim().strip_prefix("* [`"))
        .filter_map(|l| l.split('`').next())
        .map(|c| c.trim_end_matches('↴').trim().to_ascii_lowercase())
        .filter(|c| c.starts_with("kotton"))
        .collect()
}

/// The pages a run reads: [`README`], then each page `args` names, in order and once each.
///
/// Repo-relative, as typed; `--` is not a page. A page named twice is read once.
pub(crate) fn gated_pages(args: &[String]) -> Vec<String> {
    let mut pages = vec![README.to_string()];
    for a in args {
        let a = a.replace('\\', "/");
        if a != "--" && !pages.contains(&a) {
            pages.push(a);
        }
    }
    pages
}

/// Every finding over `pages`, as the line the gate prints, given each page's text (or `None`
/// for one that could not be read), the known command tree and what the tree holds.
fn findings(
    pages: &[(String, Option<String>)],
    known: &[String],
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut bad: Vec<String> = Vec::new();
    for (rel, doc) in pages {
        let Some(doc) = doc else {
            bad.push(format!(
                "{rel} could not be read. A page this gate is given and cannot open is refused, \
                 not skipped."
            ));
            continue;
        };
        for cmd in unknown_commands(doc, known) {
            bad.push(format!(
                "{rel} tells a reader to run `{cmd}`, which is not in the generated command \
                 tree. A page that teaches a command the binary does not have is worse than \
                 no page."
            ));
        }
        if rel == README && !carries_install(doc) {
            bad.push(format!(
                "{rel} does not give `{INSTALL}` as a line of a fenced block. A person \
                 installs from the distribution, whose README gives that line: a page that \
                 installs otherwise names a tag or an installer the distribution does not have."
            ));
        }
        for script in missing_scripts(doc, &exists) {
            bad.push(format!(
                "{rel} tells a reader to run `sh {script}`, and a checkout has no such file: \
                 `kotton/` is the clone, so the rest is a path in this tree."
            ));
        }
    }
    bad
}

pub fn run(args: &[String]) {
    let root = crate::out::root();
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).ok();
    let Some(cli) = read(CLI_REF) else {
        eprintln!(
            "claim-check: could not read {CLI_REF}. Run from the workspace root; \
             `cargo xtask-docs gen-docs` writes it."
        );
        std::process::exit(1);
    };
    let known = known_commands(&cli);
    let pages: Vec<(String, Option<String>)> =
        gated_pages(args).into_iter().map(|rel| { let doc = read(&rel); (rel, doc) }).collect();
    let bad = findings(&pages, &known, |p| root.join(p).is_file());
    if bad.is_empty() {
        let names: Vec<&str> = pages.iter().map(|(rel, _)| rel.as_str()).collect();
        println!(
            "claim-check: OK — {README} installs from the distribution, every `kotton` command {} gives is one the binary has, and every script it runs from a checkout of this tree is in it.",
            names.join(", ")
        );
        return;
    }
    eprintln!("claim-check: {} finding(s):\n", bad.len());
    for b in &bad {
        eprintln!("  {b}");
    }
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The README is always read, and a page named on the command line is read beside it**,
    /// once, however often it is named; `--` is not a page.
    #[test]
    fn the_readme_and_every_named_page_are_gated() {
        assert_eq!(gated_pages(&[]), vec!["README.md"]);
        let args: Vec<String> =
            ["--", "docs/a.md", "README.md", "docs/a.md"].iter().map(|s| s.to_string()).collect();
        assert_eq!(gated_pages(&args), vec!["README.md", "docs/a.md"]);
    }

    /// **A page that names a verb the binary lacks is refused, and a page that cannot be read
    /// is refused rather than skipped.**
    #[test]
    fn an_invented_verb_and_an_unread_page_are_both_findings() {
        let known: Vec<String> =
            ["kotton", "kotton id create"].iter().map(|s| s.to_string()).collect();
        let pages = vec![
            ("README.md".to_string(), Some(format!("```sh\n{INSTALL}\nkotton id create alice\nkotton frobnicate\n```\n"))),
            ("docs/gone.md".to_string(), None),
        ];
        let bad = findings(&pages, &known, |_| true);
        assert_eq!(bad.len(), 2, "{bad:?}");
        assert!(bad[0].starts_with("README.md tells a reader to run `kotton frobnicate`"), "{bad:?}");
        assert!(bad[1].starts_with("docs/gone.md could not be read"), "{bad:?}");
    }

    /// **This tree's README passes against this tree's generated reference.** The gate's own
    /// run says the same; this holds it in `cargo test` too, so a verb renamed in the CLI with
    /// the README left behind fails here as well as in `just lint`.
    #[test]
    fn this_readme_names_only_commands_the_reference_has() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let cli = std::fs::read_to_string(root.join(CLI_REF)).expect("the generated reference");
        let readme = std::fs::read_to_string(root.join(README)).expect("README.md");
        let known = known_commands(&cli);
        assert!(known.len() > 10, "the reference parsed to {known:?}");
        let pages = vec![(README.to_string(), Some(readme))];
        let bad = findings(&pages, &known, |p| root.join(p).is_file());
        assert!(bad.is_empty(), "{bad:?}");
    }

    #[test]
    fn the_bare_root_does_not_accept_an_invented_subcommand() {
        let known: Vec<String> = ["kotton", "kotton id create", "kotton sync"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let doc = "```bash\nkotton identity summon\n```\n";
        assert_eq!(
            unknown_commands(doc, &known),
            vec!["kotton identity summon"]
        );
    }

    #[test]
    fn a_real_command_with_arguments_and_flags_passes() {
        let known: Vec<String> = ["kotton", "kotton id create", "kotton sync"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let doc = "```bash\nkotton id create alice\nkotton sync\nkotton --help\n```\n";
        assert!(unknown_commands(doc, &known).is_empty());
    }

    /// **A script a page runs from a clone of this tree is one the tree has.** The
    /// distribution's `kotton-dist/install.sh` and an archive's own `install.sh` are not this
    /// checkout's and are not read.
    #[test]
    fn a_script_run_from_the_checkout_is_one_the_tree_has() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let exists = |p: &str| root.join(p).is_file();
        let doc = format!(
            "```sh\n{INSTALL}\n\
             KOTTON_OPERATOR_KEY_RELAY=<relay key> KOTTON_OPERATOR_KEY_VAULT=<vault key> sh kotton-dist/install.sh --kind host\n\
             sh kotton-relay-<rev>-linux-x86_64/install.sh\n\
             sh kotton/infra/release/clean-machine.sh\n```\n"
        );
        assert!(missing_scripts(&doc, exists).is_empty(), "{:?}", missing_scripts(&doc, exists));
        let planted = "```sh\ngit clone https://github.com/kottonllc/kotton && sh kotton/get-kotton.sh\n```\n";
        assert_eq!(missing_scripts(planted, exists), vec!["kotton/get-kotton.sh"]);
        assert!(missing_scripts("Then sh kotton/get-kotton.sh, in prose.\n", exists).is_empty());
    }

    /// **The README installs from the distribution**: a README without [`INSTALL`] as a line of
    /// a fenced block is refused, whether it gives this repository's old line, gives
    /// the distribution's line in prose only, or gives a near miss; and only the README is held
    /// to it, since another page gated beside it need not install anything.
    #[test]
    fn the_readme_installs_from_the_distribution() {
        let known: Vec<String> = vec!["kotton".to_string()];
        let readme = |text: String| vec![(README.to_string(), Some(text))];
        assert!(findings(&readme(format!("```sh\n{INSTALL}\n```\n")), &known, |_| true).is_empty());
        for wrong in [
            "```sh\ngit clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton && sh kotton/install.sh\n```\n".to_string(),
            format!("Run {INSTALL} at a terminal.\n"),
            format!("```sh\n{}\n```\n", INSTALL.replace("--depth 1 ", "")),
        ] {
            let bad = findings(&readme(wrong.clone()), &known, |_| true);
            assert_eq!(bad.len(), 1, "{wrong}: {bad:?}");
            assert!(bad[0].starts_with("README.md does not give `git clone"), "{bad:?}");
        }
        let other = vec![
            (README.to_string(), Some(format!("```sh\n{INSTALL}\n```\n"))),
            ("docs/a.md".to_string(), Some("```sh\nkotton --help\n```\n".to_string())),
        ];
        assert!(findings(&other, &known, |_| true).is_empty());
    }

    #[test]
    fn prose_outside_a_fence_is_not_a_command() {
        let known: Vec<String> = vec!["kotton".to_string()];
        assert!(unknown_commands("Run kotton frobnicate to do it.\n", &known).is_empty());
    }
}
