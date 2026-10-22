// SPDX-License-Identifier: AGPL-3.0-or-later
//! `runbook-check` — every fix `doctor` prints is a command the platform's page gives.
//!
//! `doctor`'s `NEEDS` table and the pages under `docs/use/` are two copies of one fact: how
//! a requirement is installed on this machine. On 2026-09-17 the clang row said `winget
//! install LLVM.LLVM` in the same commit that added `llvm` to `docs/use/windows.md`'s scoop
//! line — one dependency, one commit, two package managers — and nothing read both
//! (`TASK-the-doctor-s-fix-lines-are-not-held-to-the-runbooks`).
//!
//! It reads in the cheap direction. For each `target_os` with a page, every `Fix` the table
//! would print there is rendered as its installer and its package, and the page must give
//! that installer and that package **as one command in a fenced code block**: a `\`
//! continuation joins lines, `&&`, `||`, `|` and `;` separate commands, a `#` starts a comment,
//! and the installer must lead its command (after a `sudo`). Prose does not count — a sentence
//! that mentions `winget install` beside `LLVM.LLVM` is saying the opposite — and neither does a
//! word in a comment. A package the page installs with a different installer is a finding,
//! which is the case that happened: `llvm` was in the page, `LLVM.LLVM` and `winget install
//! llvm` were not. The reverse is not checked, since a page may name more than the table does —
//! `windows.md` lists MSVC and OpenSSL, which `doctor` has no rows for and says so.
//!
//! **It fails closed on platforms.** A row limited to a `target_os` with no page, or a fix
//! entry for one, is a finding: a fix nothing is held to is exactly what this gate exists to
//! refuse, and skipping it would let a misspelt `Linux` pass as quietly as a real `freebsd`.
//!
//! `wsl2.md` defers to `linux.md` and is not its own platform. The server tier is not the
//! desktop's: it is set up from `build-a-release.md`, so its rows are held to that page. The
//! build tier is both: the desktop's archive is built on a PC set up from
//! `build-a-release.md`, and the window's contributor installs the same libraries from
//! `linux.md` (the desktop tier lists them), so a row the build tier reads, in its own tier
//! or by `also`, is held to both pages on Linux — a package either page leaves out is a finding.
//!
//! **What it cannot see:** that a command on the page works. It holds that the two copies say
//! the same thing, not that either is right about the package manager.

use crate::doctor::{fixes_for, Fix, Need, Tier, NEEDS};

/// The platforms with a page of their own, and the page.
const PAGES: &[(&str, &str)] = &[
    ("linux", "docs/use/linux.md"),
    ("macos", "docs/use/macos.md"),
    ("windows", "docs/use/windows.md"),
];

/// The release guide: the server tier's page whatever platform it is read on, and the second
/// page of a row the build tier reads, on Linux, where the desktop's archive is built.
const RELEASE_PAGE: &str = "docs/use/build-a-release.md";

/// The table's own source, so a finding names the line the fix is written on.
const SOURCE: &str = include_str!("doctor.rs");

/// A fix the page for its platform does not give — or, with `page` empty, a platform the
/// row names that has no page at all.
#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub what: &'static str,
    pub os: &'static str,
    pub page: &'static str,
    /// The fix as `doctor` prints it; for a platform with no page, the entry that names it.
    pub command: String,
    /// 1-based line in `xtask/src/doctor.rs`.
    pub line: usize,
}

/// The pages a row's fixes are held to on `os`, which is always one of [`PAGES`].
fn pages_for(need: &Need, os: &'static str) -> Vec<&'static str> {
    if need.tier == Tier::Server {
        return vec![RELEASE_PAGE];
    }
    let mut pages = vec![PAGES
        .iter()
        .find(|(o, _)| *o == os)
        .map(|(_, p)| *p)
        .expect("findings only asks for a platform in PAGES")];
    if os == "linux" && (need.tier == Tier::Build || need.also.contains(&Tier::Build)) {
        pages.push(RELEASE_PAGE);
    }
    pages
}

/// One line of a fenced code block, `\`-continuations joined and its comment cut off.
#[derive(Debug)]
struct CodeLine {
    /// The whole line, for a `Shell` fix, which is matched as written.
    whole: String,
    /// The commands on it, split at `&&`, `||`, `|` and `;`, each as its words.
    commands: Vec<Vec<String>>,
}

/// A line that can open or close a fence: its character, its run length, and what follows.
fn fence_of(line: &str) -> Option<(char, usize, &str)> {
    let line = line.trim_start();
    let c = line.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let run = line.chars().take_while(|&x| x == c).count();
    (run >= 3).then(|| (c, run, &line[run..]))
}

/// The commands a page gives: the lines of its fenced code blocks, and nothing outside them.
/// Fences pair as CommonMark pairs them — a closer is the opener's character, at least as long,
/// with nothing after it — and a backtick fence whose info string holds a backtick is inline
/// code (` ```x``` `), not an opener. A fence never closed is an error naming `page` and its line.
fn command_lines(page: &str, text: &str) -> Result<Vec<CodeLine>, String> {
    let mut raw: Vec<String> = Vec::new();
    let mut open: Option<(char, usize, usize)> = None;
    let mut cur = String::new();
    for (i, line) in text.lines().enumerate() {
        let fence = fence_of(line);
        match (open, fence) {
            (None, Some((c, run, info))) if !(c == '`' && info.contains('`')) => {
                open = Some((c, run, i + 1));
                cur.clear();
                continue;
            }
            (Some((oc, orun, _)), Some((c, run, info)))
                if c == oc && run >= orun && info.trim().is_empty() =>
            {
                open = None;
                cur.clear();
                continue;
            }
            (None, _) => continue,
            _ => {}
        }
        let trimmed = line.trim_end();
        if let Some(head) = trimmed.strip_suffix('\\') {
            cur.push_str(head);
            cur.push(' ');
        } else {
            cur.push_str(trimmed);
            raw.push(std::mem::take(&mut cur));
        }
    }
    if let Some((c, run, at)) = open {
        let fence: String = std::iter::repeat_n(c, run).collect();
        return Err(format!("{page}:{at}: the `{fence}` fence opened here is never closed"));
    }
    Ok(raw
        .into_iter()
        .map(|line| {
            // A `#` at the start of a word begins a comment, in sh and in PowerShell alike.
            let code = match line.find(" #") {
                _ if line.trim_start().starts_with('#') => "",
                Some(at) => &line[..at],
                None => line.as_str(),
            };
            let commands = code
                .replace("&&", ";")
                .replace("||", ";")
                .replace('|', ";")
                .split(';')
                .map(|c| c.split_whitespace().map(str::to_owned).collect())
                .collect();
            CodeLine {
                whole: code.trim().to_owned(),
                commands,
            }
        })
        .collect())
}

/// The installer a fix is run with and the words it installs. `None` for a fix that is a
/// whole line of its own.
fn installer(fix: &Fix) -> Option<(&'static str, &'static str)> {
    match *fix {
        Fix::Cargo(c) => Some(("cargo install", c)),
        Fix::Rustup(t) => Some(("rustup target add", t)),
        Fix::Apt(p) => Some(("apt-get install", p)),
        Fix::Brew(p) => Some(("brew install", p)),
        Fix::Scoop(p) => Some(("scoop install", p)),
        Fix::Winget(p) => Some(("winget install", p)),
        Fix::Xcode | Fix::Shell(_) => None,
    }
}

/// The fix as `doctor` prints it, for the finding.
fn command(fix: &Fix) -> String {
    match *fix {
        Fix::Xcode => "xcode-select --install".to_owned(),
        Fix::Shell(line) => line.to_owned(),
        _ => {
            let (by, what) = installer(fix).expect("an installer fix");
            format!("{by} {what}")
        }
    }
}

/// Whether some command on the page gives this fix: a command that begins with the
/// installer (after a `sudo`) and names every word it installs. A `Shell` fix must be a
/// code line as written.
fn said(fix: &Fix, lines: &[CodeLine]) -> bool {
    if let Fix::Shell(whole) = *fix {
        return lines.iter().any(|l| l.whole.contains(whole));
    }
    let (by, what): (Vec<&str>, Vec<&str>) = match installer(fix) {
        Some((by, what)) => (by.split(' ').collect(), what.split_whitespace().collect()),
        None => (vec!["xcode-select", "--install"], Vec::new()),
    };
    lines.iter().flat_map(|l| &l.commands).any(|words| {
        let words = match words.first().map(String::as_str) {
            Some("sudo") => &words[1..],
            _ => &words[..],
        };
        words.len() >= by.len()
            && words.iter().zip(&by).all(|(w, b)| w == b)
            && what.iter().all(|p| words[by.len()..].iter().any(|w| w == p))
    })
}

/// The line in `source` a row's fix is written on: the first line of the row's `fix:` that
/// carries the fix's payload. The row's own line when the payload is not found.
fn line_of(source: &str, what: &str, fix: &Fix) -> usize {
    let payload = match *fix {
        Fix::Xcode => "Fix::Xcode".to_owned(),
        Fix::Shell(s)
        | Fix::Cargo(s)
        | Fix::Rustup(s)
        | Fix::Apt(s)
        | Fix::Brew(s)
        | Fix::Scoop(s)
        | Fix::Winget(s) => format!("\"{s}\""),
    };
    line_in_row(source, what, &payload, true)
}

/// The first line of `what`'s row carrying `needle` — from its `fix:` on when `in_fix`, so
/// a payload that is also the probe's name (`just`, `git`) is found where it is installed
/// rather than where it is looked for. The line after the row's `what:` when not found.
fn line_in_row(source: &str, what: &str, needle: &str, in_fix: bool) -> usize {
    let lines: Vec<&str> = source.lines().collect();
    let row = format!("what: \"{what}\",");
    let Some(start) = lines.iter().position(|l| l.trim() == row) else {
        return 0;
    };
    let row: Vec<&str> = lines[start + 1..]
        .iter()
        .copied()
        .take_while(|l| !l.trim_start().starts_with("what: "))
        .collect();
    let from = if in_fix {
        row.iter()
            .position(|l| l.trim_start().starts_with("fix: "))
            .unwrap_or(0)
    } else {
        0
    };
    row[from..]
        .iter()
        .position(|l| l.contains(needle))
        .map_or(start + 1, |i| start + 2 + from + i)
}

/// Every fix in `needs` that the page for its platform does not give. `read` returns a
/// page's text, or `None` when it cannot be read — which is itself a finding, never a pass.
pub fn findings(
    needs: &[Need],
    read: &dyn Fn(&str) -> Option<String>,
    source: &str,
) -> Result<Vec<Finding>, String> {
    let mut out = Vec::new();
    let paged = |os: &str| PAGES.iter().any(|(o, _)| *o == os);
    for need in needs {
        // A platform the row names and no page covers is refused before anything is matched.
        let named = need
            .only
            .iter()
            .map(|os| (*os, format!("only: {os:?}")))
            .chain(
                need.fix
                    .iter()
                    .filter(|(os, _)| !os.is_empty())
                    .map(|(os, fix)| (*os, format!("({os:?}, {})", command(fix)))),
            );
        for (os, entry) in named {
            if !paged(os) {
                out.push(Finding {
                    what: need.what,
                    os,
                    page: "",
                    command: entry,
                    line: line_in_row(source, need.what, &format!("\"{os}\""), false),
                });
            }
        }
        for (os, _) in PAGES {
            if !need.only.is_empty() && !need.only.contains(os) {
                continue;
            }
            let fixes = fixes_for(need, os);
            if fixes.is_empty() {
                continue;
            }
            for page in pages_for(need, os) {
                let text = read(page).ok_or_else(|| format!("cannot read {page}"))?;
                let lines = command_lines(page, &text)?;
                for fix in &fixes {
                    if !said(fix, &lines) {
                        out.push(Finding {
                            what: need.what,
                            os,
                            page,
                            command: command(fix),
                            line: line_of(source, need.what, fix),
                        });
                    }
                }
            }
        }
    }
    Ok(out)
}

pub fn run() {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let found = match findings(NEEDS, &read, SOURCE) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("runbook-check: {e}; refusing rather than reporting OK");
            std::process::exit(1);
        }
    };
    if found.is_empty() {
        let rows = NEEDS.iter().filter(|n| !n.fix.is_empty()).count();
        println!(
            "runbook-check: OK — every fix in doctor's {rows} rows with one is a command its \
             platform's page under docs/use/ gives."
        );
        return;
    }
    eprintln!(
        "runbook-check: {} fix(es) doctor prints that the platform's page does not give:",
        found.len()
    );
    for f in &found {
        if f.page.is_empty() {
            eprintln!(
                "  xtask/src/doctor.rs:{}: `{}` names {:?} ({}), which has no page under \
                 docs/use/ — nothing holds what it prints there",
                f.line, f.what, f.os, f.command
            );
        } else {
            eprintln!(
                "  xtask/src/doctor.rs:{}: `{}` on {}: `{}` — {} never gives it as a command",
                f.line, f.what, f.os, f.command, f.page
            );
        }
    }
    eprintln!(
        "One of the two is wrong. Change whichever the person was set up from is not: the page \
         if it omits a step, the table if it names an installer the page never uses."
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::{findings, said, CodeLine, Fix, SOURCE};
    use crate::doctor::{Need, NEEDS};

    fn command_lines(text: &str) -> Vec<CodeLine> {
        super::command_lines("test.md", text).unwrap()
    }

    fn page(p: &str) -> Option<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        std::fs::read_to_string(root.join(p)).ok()
    }

    /// **The table and the pages agree, today.** This is the gate itself, run over the tree.
    #[test]
    fn every_fix_doctor_prints_is_on_its_platforms_page() {
        let found = findings(NEEDS, &page, SOURCE).expect("every page reads");
        assert!(found.is_empty(), "{found:#?}");
    }

    /// **The disagreement that opened the record, by name and line.** The clang row as
    /// `f0c7ddb` first wrote it, against the Windows page as it stands: `llvm` is on the
    /// page, under scoop, and `winget install LLVM.LLVM` is not.
    #[test]
    fn the_2026_09_17_clang_row_is_refused() {
        let source = "    Need {\n        what: \"clang\",\n        fix: &[\n            \
                      (\"windows\", Fix::Winget(\"LLVM.LLVM\")),\n        ],\n    },\n";
        let rows = [Need::for_test("clang", &[("windows", Fix::Winget("LLVM.LLVM"))])];
        let found = findings(&rows, &page, source).unwrap();
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].what, "clang");
        assert_eq!(found[0].os, "windows");
        assert_eq!(found[0].page, "docs/use/windows.md");
        assert_eq!(found[0].command, "winget install LLVM.LLVM");
        assert_eq!(found[0].line, 4);
    }

    /// **The package is not enough; the installer must be the page's.** `llvm` is on the
    /// Windows page and so is `winget install` — on different lines, for different things.
    #[test]
    fn a_package_the_page_installs_another_way_is_refused() {
        let windows = command_lines(&page("docs/use/windows.md").unwrap());
        assert!(said(&Fix::Scoop("llvm"), &windows));
        assert!(!said(&Fix::Winget("llvm"), &windows));
        assert!(said(&Fix::Winget("Git.Git"), &windows));
        assert!(!said(&Fix::Cargo("llvm"), &windows));
    }

    /// A command wrapped with `\` is one command, and every word of a multi-word fix must
    /// be on it.
    #[test]
    fn a_continued_line_is_one_command() {
        let lines = command_lines("```\nsudo apt-get install -y a b \\\n    c d\napt-get install -y e\n```\n");
        assert!(said(&Fix::Apt("d"), &lines));
        assert!(said(&Fix::Apt("a c"), &lines));
        assert!(!said(&Fix::Apt("a e"), &lines));
        assert!(!said(&Fix::Brew("a"), &lines));
        assert!(said(&Fix::Shell("install -y e"), &lines));
        assert!(!said(&Fix::Xcode, &lines));
    }

    /// A row limited to one platform is held to that platform's page only: its fallback fix
    /// is never printed on the others, so their pages owe it nothing.
    #[test]
    fn a_row_is_held_only_where_it_applies() {
        let rows = [Need::for_test("gtk", &[("", Fix::Apt("libgtk-3-dev"))]).only(&["linux"])];
        assert_eq!(findings(&rows, &page, "").unwrap(), vec![]);
        let everywhere = [Need::for_test("gtk", &[("", Fix::Apt("libgtk-3-dev"))])];
        assert_eq!(findings(&everywhere, &page, "").unwrap().len(), 2);
    }

    /// **A platform with no page is a refusal, not a skip.** A row limited to a `target_os`
    /// nothing reads, a fix entry for one, and a misspelt one (`Linux`) each print a fix no
    /// page is held to, so each is a finding naming the row. Planted by the assessor on
    /// 2026-09-29: the first two came back exit 0.
    #[test]
    fn a_platform_with_no_page_is_refused() {
        let planted = [
            Need::for_test("perl", &[("", Fix::Apt("no-such-package"))]).only(&["freebsd"]),
            Need::for_test("just", &[("freebsd", Fix::Shell("pkg install no-such-thing"))]),
            Need::for_test("gtk", &[("linux", Fix::Apt("libgtk-3-dev"))]).only(&["Linux"]),
        ];
        for row in &planted {
            let found = findings(std::slice::from_ref(row), &page, "").unwrap();
            assert_eq!(found.len(), 1, "`{}`: {found:#?}", row.what);
            assert_eq!(found[0].what, row.what);
            assert_eq!(found[0].page, "");
        }
    }

    /// **Only a command counts, not a sentence about one.** A prose line that mentions
    /// `winget install` and `LLVM.LLVM` together says the opposite of installing it, and a
    /// word in a shell comment after the brew line is not a formula. Both passed the first
    /// form of this gate (the assessor, 2026-09-29).
    #[test]
    fn prose_and_comments_are_not_commands() {
        let mut windows = page("docs/use/windows.md").unwrap();
        windows.push_str(
            "\nWe do not use `winget install` here; the LLVM.LLVM package it offers is not \
             the one scoop names.\n",
        );
        assert!(!said(&Fix::Winget("LLVM.LLVM"), &command_lines(&windows)));
        let macos = command_lines(&page("docs/use/macos.md").unwrap());
        assert!(said(&Fix::Brew("openssl"), &macos));
        assert!(!said(&Fix::Brew("encrypted"), &macos));
        // A command that only mentions the installer, or runs it after another, is not it.
        let lines = command_lines("```\necho scoop install x\nscoop update && scoop install y\n```\n");
        assert!(!said(&Fix::Scoop("x"), &lines));
        assert!(said(&Fix::Scoop("y"), &lines));
        let lines = command_lines("```\nbrew install a; echo b\nbrew install c | tee d\n```\n");
        assert!(!said(&Fix::Brew("b"), &lines));
        assert!(!said(&Fix::Brew("d"), &lines));
        // Outside a fence nothing is a command, even a line that reads exactly like one —
        // and a `Shell` fix is held to the same rule.
        let prose = "scoop install x\nmatchbox-window-manager -use_titlebar no &\n";
        assert!(!said(&Fix::Scoop("x"), &command_lines(prose)));
        let shell = Fix::Shell("matchbox-window-manager -use_titlebar no &");
        assert!(!said(&shell, &command_lines(prose)));
        assert!(said(&shell, &command_lines(&format!("```\n{prose}```\n"))));
    }

    /// **Fences pair by character and length, not by toggling.** Three shapes read prose as
    /// commands under a toggle (the assessor, 2026-09-29): a one-line ` ```x``` `, a
    /// four-backtick block holding a three-backtick line, and a fence never closed. The
    /// first two put a prose line after them "inside" a fence; the third is refused by name.
    #[test]
    fn fences_pair_as_commonmark_pairs_them() {
        let none = |text: &str| {
            let lines = command_lines(text);
            assert!(!said(&Fix::Scoop("x"), &lines), "read as a command: {text:?}");
            assert!(lines.iter().all(|l| !l.whole.contains("scoop install x")), "{text:?}");
        };
        none("Run ```x``` first.\n```x```\nscoop install x\n");
        none("````md\n```\nnot a command\n```\n````\nscoop install x\n");
        none("~~~\n```\n~~~\nscoop install x\n");
        // The pairing still finds what is really fenced, longer closers included.
        let lines = command_lines("````\n```\nscoop install y\n`````\nscoop install x\n");
        assert!(said(&Fix::Scoop("y"), &lines) && !said(&Fix::Scoop("x"), &lines));
        // A fence never closed names the page and the line it opened on.
        let err = super::command_lines("p.md", "a\n```\nscoop install x\n").unwrap_err();
        assert!(err.starts_with("p.md:2:"), "{err}");
        let err = super::command_lines("p.md", "```\nok\n```\n````md\n```\n").unwrap_err();
        assert!(err.starts_with("p.md:4:"), "{err}");
    }

    /// **A row the build tier reads is held to the release guide as well as the platform's
    /// page, on Linux.** A package the window's page gives and the release guide leaves out
    /// is a finding naming the guide; the same package on a row the build tier does not read
    /// is not.
    #[test]
    fn a_build_row_is_held_to_the_release_guide_too() {
        use crate::doctor::Tier;
        // `libxkbcommon-x11-0` is on linux.md and, being the window's own, not on the guide.
        let fix: &'static [(&'static str, Fix)] = &[("linux", Fix::Apt("libxkbcommon-x11-0"))];
        let window = Need::for_test("x", fix).only(&["linux"]);
        assert_eq!(findings(std::slice::from_ref(&window), &page, "").unwrap(), vec![]);
        let build = Need::for_test("x", fix).only(&["linux"]).also(&[Tier::Build]);
        let found = findings(std::slice::from_ref(&build), &page, "").unwrap();
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].page, "docs/use/build-a-release.md");
        assert_eq!(found[0].command, "apt-get install libxkbcommon-x11-0");
    }

    /// A page that cannot be read is a refusal, not a pass.
    #[test]
    fn an_unreadable_page_is_not_a_pass() {
        let rows = [Need::for_test("clang", &[("windows", Fix::Scoop("llvm"))])];
        assert!(findings(&rows, &|_| None, "").is_err());
    }
}
