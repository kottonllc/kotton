// SPDX-License-Identifier: AGPL-3.0-or-later
//! `claim-check`: a guide may not tell a reader to run a `kotton` command the binary lacks.
//!
//! The commands a person is told to type are the one part of a guide that is mechanically
//! checkable, and `docs/cli/reference.md` is generated from the real command tree and held to
//! it by `docs-check` — so every guide under `docs/use/` is held to the reference, and through
//! it to the binary. A guide that teaches a command the binary does not have is worse than no
//! guide.
//!
//! It reads the commands, not the sentence beside them: whether a guide's prose is true stays
//! a reviewer's job.
//!
//! **And the scripts a guide runs from a checkout.** A guide installs a release with
//! `git clone … https://github.com/kottonllc/kotton && sh kotton/install.sh`, so every
//! `sh kotton/<path>` in a fenced block must name a file this tree has: a guide that runs a
//! script the checkout lacks fails at the reader's first line, exactly as a missing command
//! does. A release tag is a commit on `main`, so a tree this gate passed is the tree the tag
//! holds.

/// The user layer. Every Markdown file directly in it is a guide this gate reads.
const USE_DIR: &str = "docs/use";
const CLI_REF: &str = "docs/cli/reference.md";

/// Every `kotton …` invocation inside a fenced block, longest-first against the real tree.
///
/// The commands a user is told to type are the one part of a guide that is mechanically
/// checkable, and `docs/cli/reference.md` is already generated from the command tree and
/// gated by `docs-check` — so a guide can be held to it for free. A flag or an argument is
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
/// the `kotton/<path>` the guide typed.
///
/// `kotton/` is the directory `git clone https://github.com/kottonllc/kotton` makes, so the
/// rest is a path in this tree. An archive's directory (`kotton-relay-<rev>-…/install.sh`) is
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

/// Every guide under [`USE_DIR`], as repo-relative paths, sorted.
///
/// The directory rather than a list of names: a page in `docs/use/` is gated because of
/// where it is, so a new guide cannot be added and left ungated.
pub(crate) fn gated_pages(root: &std::path::Path) -> Vec<String> {
    let mut pages: Vec<String> = std::fs::read_dir(root.join(USE_DIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            (name.ends_with(".md") && e.path().is_file()).then(|| format!("{USE_DIR}/{name}"))
        })
        .collect();
    pages.sort();
    pages
}

pub fn run(_args: &[String]) {
    let root = crate::out::root();
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).ok();
    let Some(cli) = read(CLI_REF) else {
        eprintln!("claim-check: could not read {CLI_REF}. Run from the workspace root.");
        std::process::exit(1);
    };
    let known = known_commands(&cli);
    let pages = gated_pages(&root);
    let mut bad: Vec<String> = Vec::new();
    for rel in &pages {
        let Some(doc) = read(rel) else { continue };
        for cmd in unknown_commands(&doc, &known) {
            bad.push(format!(
                "{rel} tells a reader to run `{cmd}`, which is not in the generated command \
                 tree. A guide that teaches a command the binary does not have is worse than \
                 no guide."
            ));
        }
        for script in missing_scripts(&doc, |p| root.join(p).is_file()) {
            bad.push(format!(
                "{rel} tells a reader to run `sh {script}`, and a checkout has no such file: \
                 `kotton/` is the clone, so the rest is a path in this tree."
            ));
        }
    }
    if bad.is_empty() {
        println!(
            "claim-check: OK — every `kotton` command the {} guides under {USE_DIR}/ give is one the binary has, and every script they run from a checkout is in this tree.",
            pages.len()
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

    /// **Every page in `docs/use/` is gated, by being there** — the platform pages, the relay
    /// and vault guides and the index alike, with no list a new page has to be added to.
    #[test]
    fn every_page_in_docs_use_is_gated() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let pages = gated_pages(root);
        for page in [
            "README.md", "first-hour.md", "linux.md", "wsl2.md", "the-window.md",
            "build-a-release.md", "run-a-relay.md",
            "run-a-vault.md", "recover-and-start-over.md",
        ] {
            assert!(pages.contains(&format!("{USE_DIR}/{page}")), "{page} is not gated: {pages:?}");
        }
        assert!(pages.iter().all(|p| p.ends_with(".md") && !p["docs/use/".len()..].contains('/')));
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

    /// **A script a guide runs from the clone is one the tree has**, and the install the guides
    /// give, the root `install.sh`, is one of them; an archive's own `install.sh` is not the
    /// checkout's and is not read.
    #[test]
    fn a_script_run_from_the_checkout_is_one_the_tree_has() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let exists = |p: &str| root.join(p).is_file();
        let doc = "```sh\ngit clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton && sh kotton/install.sh\n\
                   KOTTON_OPERATOR_KEY=<key> sh kotton/install.sh --kind relay\n\
                   sh kotton-relay-<rev>-linux-x86_64/install.sh\n```\n";
        assert!(missing_scripts(doc, exists).is_empty(), "{:?}", missing_scripts(doc, exists));
        let planted = "```sh\ngit clone https://github.com/kottonllc/kotton && sh kotton/get-kotton.sh\n```\n";
        assert_eq!(missing_scripts(planted, exists), vec!["kotton/get-kotton.sh"]);
        assert!(missing_scripts("Then sh kotton/get-kotton.sh, in prose.\n", exists).is_empty());
    }

    #[test]
    fn prose_outside_a_fence_is_not_a_command() {
        let known: Vec<String> = vec!["kotton".to_string()];
        assert!(unknown_commands("Run kotton frobnicate to do it.\n", &known).is_empty());
    }
}
