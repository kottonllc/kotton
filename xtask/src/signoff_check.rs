// SPDX-License-Identifier: AGPL-3.0-or-later
//! `signoff-check`: every commit on this branch is certified by a person, and none is made
//! as an agent.
//!
//! `DEC-0091`, as amended 2026-09-30 and 2026-10-02;
//! `TASK-every-commit-carries-a-sign-off-and-nothing-checks-it`,
//! `TASK-an-agent-commit-may-carry-a-session-url-and-an-agent-co-author-and-nothing-refuses-them`.
//!
//! ## Why this exists
//!
//! A contribution to Kotton is certified, not granted: a commit carries the Developer
//! Certificate of Origin as a `Signed-off-by: Name <email>` trailer, and the project receives
//! nothing a recipient does not. A certificate nothing reads is a decision nothing enforces —
//! the CLA it replaced was named in two documents and checked by nothing
//! (`TASK-cla-assistant-is-named-in-two-documents-and-installed-nowhere`). This is the check.
//!
//! ## The rules, as DEC-0091's amendments write them
//!
//! - **(a)** No commit is authored or committed as an agent identity: any name at an address on
//!   [`AGENT_ADDRESSES`], one of [`AGENT_IDENTITIES`], or a forge bot ([`BOT_SUFFIX`]).
//!   A commit an agent makes is authored as the person who directed it.
//! - **(b)** There is no exemption: a commit carrying an `Assisted-by:` trailer is held to (c)
//!   like any other, whoever authored it, the owner included. An agent cannot certify, so the
//!   person it was made for does, with their own `Signed-off-by:` (CONTRIBUTING.md, "Every
//!   commit is signed off"). [`PEOPLE`] no longer excuses anyone; it names the owner for the
//!   commits `cargo xtask merge` makes.
//! - **(c)** Every other commit carries a `Signed-off-by:` whose name and address are exactly
//!   its author's, and, when the committer differs, a second that is exactly the committer's.
//! - **(d)** No `Signed-off-by:` names an agent identity, on any commit: *"AI agents MUST NOT
//!   add Signed-off-by tags"*, the kernel's rule the amendment keeps. The record writes this
//!   inside (b); it is held on every commit because the reason for it is not specific to (b).
//! - **(e)** A commit carrying `Assisted-by:` carries no `Claude-Session:` trailer and no
//!   `Co-Authored-By:` naming an agent identity (DEC-0091, amended 2026-10-02: the loop's agent
//!   commit ends with `Gates:` then `Assisted-by: Claude Code`, and nothing else).
//!
//! Every finding carries the [`Rule`] it breaks, so a test can say which rule a commit fails
//! and not only that it fails: a commit refused by two rules stays refused when one of them is
//! deleted, and a test that reads only pass or fail cannot see the deletion.
//!
//! ## What it reads
//!
//! Every commit reachable from `HEAD` and from neither `origin/main` nor [`FLOOR`], merges
//! included; for each, its author and committer as git stores them and the trailers git's own
//! parser finds (`%(trailers:key=…)`), so a `Signed-off-by:` in the body above the trailer
//! block is not a sign-off. Commits on `main` are never read and nothing on `main` is rewritten;
//! there is no exemption by date. `origin/main` is not fetched here: a stale one only puts more
//! commits in range, and [`FLOOR`] bounds how many.
//!
//! ## What it is not
//!
//! It is not identity, and it proves no one agreed to anything. A trailer is a written claim
//! anyone can type, and so is the author field it is compared with; that is the DCO's ordinary
//! trust level everywhere it is used, and this gate does not raise it. It holds that every
//! commit on the branch *carries* the claim in the form DEC-0091 asks for, so a missing
//! certificate is found at `just lint` and not by nobody. `.github/workflows/signoff.yml` holds
//! the same rule on every pull request; this holds it at `just lint`, before one is opened.
//!
//! Usage: `cargo xtask signoff-check`

use std::path::Path;
use std::process::Command;

/// The identities a commit may not be authored or committed as, and a sign-off may not name
/// (DEC-0091, amended 2026-09-30). `Claude` at exactly its address, so a person who happens to
/// be called Claude signs for themselves; `fable-design` by name at any address, because the
/// loop identity committed at two (`None`). Compared ignoring ASCII case, which is broader than
/// the record's "exactly" in the one direction that refuses and never passes: `claude
/// <NoReply@anthropic.com>` is the same mailbox and not a person.
/// The `Claude` entry is now also covered by [`AGENT_ADDRESSES`]; it stays, as the record names it.
pub(crate) const AGENT_IDENTITIES: &[(&str, Option<&str>)] = &[
    ("Claude", Some("noreply@anthropic.com")),
    ("fable-design", None),
];

/// Addresses at which every identity is an agent, whatever its name (the driver's ruling of
/// 2026-09-30 under DEC-0091's amendment): the assistant names itself with its model —
/// `main` carries a commit as `Claude Fable 5.1 <noreply@anthropic.com>` — and a name list
/// cannot keep up with the models. No person receives mail there. Compared ignoring ASCII case.
pub(crate) const AGENT_ADDRESSES: &[&str] = &["noreply@anthropic.com"];

/// A forge bot names itself `<app>[bot]`, and GitHub gives it the no-reply address
/// `<id>+<app>[bot]@users.noreply.github.com` — `claude[bot]` is
/// `209825114+claude[bot]@users.noreply.github.com`. Either half makes it an agent, whatever the
/// app; a bot certifies nothing and authors nothing. Compared ignoring ASCII case. Proposed by
/// the driver, 2026-10-02, in DEC-0091; awaiting the owner in
/// `TASK-a-forge-bot-identity-is-held-to-be-an-agent-on-the-drivers-word`.
pub(crate) const BOT_SUFFIX: &str = "[bot]";
pub(crate) const BOT_DOMAIN: &str = "@users.noreply.github.com";

/// The people `cargo xtask merge` commits as: the owner, at their GitHub no-reply address.
/// No `Assisted-by:` commit is excused from a sign-off for being theirs. Matched exactly, name and
/// address. A change of address, or a second person, is an edit to this list and nothing else.
pub(crate) const PEOPLE: &[(&str, &str)] =
    &[("Austin Herman", "13291882+austinjherman@users.noreply.github.com")];

/// A commit already on `main` below which nothing is read, whatever `origin/main` says: the
/// `main` this check was built on, 2026-09-30. Every later `origin/main` contains it, so with a
/// current fetch it removes nothing from the range; it holds the 5,544 commits `main` carried
/// before DEC-0091's amendment out of range in a clone whose `origin/main` is stale. Skipped when
/// the clone does not have it, since then it has none of what lies under it either.
pub(crate) const FLOOR: &str = "5ea215acfaa9d06f205c60678b89efab16ff0be2";

const MAIN_REF: &str = "origin/main";

/// A name and an address, as git stores them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ident {
    pub name: String,
    pub email: String,
}

impl Ident {
    /// Exactly this name and address.
    fn is(&self, name: &str, email: &str) -> bool {
        self.name == name && self.email == email
    }

    fn same(&self, other: &Ident) -> bool {
        self.is(&other.name, &other.email)
    }

    /// At one of [`AGENT_ADDRESSES`], one of [`AGENT_IDENTITIES`], or a forge bot: a name
    /// ending in [`BOT_SUFFIX`], or an address at [`BOT_DOMAIN`] whose local part does.
    fn is_agent(&self) -> bool {
        let bot_name = self.name.to_ascii_lowercase().ends_with(BOT_SUFFIX);
        let bot_address = self
            .email
            .to_ascii_lowercase()
            .strip_suffix(BOT_DOMAIN)
            .is_some_and(|local| local.ends_with(BOT_SUFFIX));
        bot_name
            || bot_address
            || AGENT_ADDRESSES.iter().any(|a| self.email.eq_ignore_ascii_case(a))
            || AGENT_IDENTITIES.iter().any(|(n, e)| {
                self.name.eq_ignore_ascii_case(n)
                    && e.is_none_or(|e| self.email.eq_ignore_ascii_case(e))
            })
    }

    /// `Name <email>`, the form a trailer takes.
    fn parse(value: &str) -> Option<Ident> {
        let value = value.trim();
        let open = value.rfind('<')?;
        let close = value[open..].find('>')? + open;
        let name = value[..open].trim();
        let email = value[open + 1..close].trim();
        (!name.is_empty() && !email.is_empty()).then(|| Ident {
            name: name.to_string(),
            email: email.to_string(),
        })
    }
}

impl std::fmt::Display for Ident {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <{}>", self.name, self.email)
    }
}

/// One commit, as far as this gate reads it.
pub(crate) struct Commit {
    pub sha: String,
    pub subject: String,
    pub author: Ident,
    pub committer: Ident,
    pub signoffs: Vec<Ident>,
    /// Carries an `Assisted-by:` trailer, whatever it names.
    pub assisted: bool,
    /// Carries a `Claude-Session:` trailer, whatever it holds.
    pub session: bool,
    /// The identities its `Co-Authored-By:` trailers name.
    pub co_authors: Vec<Ident>,
}

/// Which of DEC-0091's rules a finding breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    /// (a), the author.
    AgentAuthor,
    /// (a), the committer.
    AgentCommitter,
    /// (d): a sign-off naming an agent.
    AgentSignoff,
    /// (c), the author's own sign-off.
    NoAuthorSignoff,
    /// (c), the committer's, when the committer is not the author.
    NoCommitterSignoff,
    /// (e): an `Assisted-by:` commit carrying a `Claude-Session:` trailer.
    SessionTrailer,
    /// (e): an `Assisted-by:` commit naming an agent in `Co-Authored-By:`.
    AgentCoAuthor,
}

/// Every rule `c` breaks, with why; empty when it passes.
pub(crate) fn verdict(c: &Commit) -> Vec<(Rule, String)> {
    let mut why = Vec::new();
    let signed = |who: &Ident| c.signoffs.iter().any(|s| s.same(who));
    let differs = !c.committer.same(&c.author);

    // (a) — an agent is refused as author or committer, and no sign-off answers for it; so (c)
    // does not ask one of it too, which would be a second finding for the same fact.
    if c.author.is_agent() {
        why.push((Rule::AgentAuthor, format!("is authored as the agent identity `{}`; an agent's commit is authored as the person who directed it", c.author)));
    }
    if differs && c.committer.is_agent() {
        why.push((Rule::AgentCommitter, format!("is committed as the agent identity `{}`; commit it as the person who directed it", c.committer)));
    }
    // (d)
    for s in c.signoffs.iter().filter(|s| s.is_agent()) {
        why.push((Rule::AgentSignoff, format!("carries `Signed-off-by: {s}`, which names an agent; only a person can certify the DCO")));
    }
    // (e) — an agent's commit ends with `Gates:` then `Assisted-by:`; no session URL stands
    // in for a person's statement, and the agent is never an author, so never a co-author.
    if c.assisted {
        if c.session {
            why.push((Rule::SessionTrailer, "carries `Assisted-by:` and a `Claude-Session:` trailer; a session URL is not a person's statement, and an agent's commit ends with `Gates:` then `Assisted-by:` only".to_string()));
        }
        for a in c.co_authors.iter().filter(|a| a.is_agent()) {
            why.push((Rule::AgentCoAuthor, format!("carries `Assisted-by:` and `Co-Authored-By: {a}`, which names an agent; the agent is never an author")));
        }
    }
    // (b) — there is no exemption: an assisted commit is held to (c) like any other.
    // (c)
    if !c.author.is_agent() && !signed(&c.author) {
        why.push((Rule::NoAuthorSignoff, format!("carries no `Signed-off-by: {}` for its author", c.author)));
    }
    if differs && !c.committer.is_agent() && !signed(&c.committer) {
        why.push((Rule::NoCommitterSignoff, format!("carries no `Signed-off-by: {}` for its committer, who is not its author", c.committer)));
    }
    why
}

fn git_in(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").current_dir(dir).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn resolves(dir: &Path, rev: &str) -> bool {
    git_in(dir, &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")]).is_some()
}

/// The commits on `HEAD` that none of `bases` has, oldest first. A base the clone cannot
/// resolve is skipped; the caller decides which of them must resolve.
pub(crate) fn branch_commits(dir: &Path, bases: &[&str]) -> Result<Vec<Commit>, String> {
    // Fields split by \x1f, commits by \x1e; trailer values split by \x1d, as git's trailer
    // parser reads them (`valueonly`, so a sign-off's value is `Name <email>`).
    let format = "--format=%H%x1f%s%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f\
                  %(trailers:key=Signed-off-by,valueonly,separator=%x1d)%x1f\
                  %(trailers:key=Assisted-by,valueonly,separator=%x1d)%x1f\
                  %(trailers:key=Claude-Session,valueonly,separator=%x1d)%x1f\
                  %(trailers:key=Co-Authored-By,valueonly,separator=%x1d)%x1e";
    let mut args = vec!["log".to_string(), "--reverse".to_string(), format.to_string(), "HEAD".to_string()];
    for b in bases.iter().filter(|b| resolves(dir, b)) {
        args.push(format!("^{b}"));
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = git_in(dir, &args).ok_or_else(|| format!("`git {}` failed", args.join(" ")))?;
    let mut commits = Vec::new();
    for rec in out.split('\x1e') {
        let rec = rec.trim_start_matches('\n');
        if rec.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = rec.split('\x1f').collect();
        if f.len() < 10 {
            return Err(format!("unreadable `git log` record: {rec:?}"));
        }
        commits.push(Commit {
            sha: f[0].to_string(),
            subject: f[1].chars().take(60).collect(),
            author: Ident { name: f[2].to_string(), email: f[3].to_string() },
            committer: Ident { name: f[4].to_string(), email: f[5].to_string() },
            signoffs: f[6].split('\x1d').filter_map(Ident::parse).collect(),
            assisted: !f[7].trim().is_empty(),
            session: !f[8].trim().is_empty(),
            co_authors: f[9].split('\x1d').filter_map(Ident::parse).collect(),
        });
    }
    Ok(commits)
}

/// The findings for the branch in `dir`, or why it could not be read.
pub(crate) fn check(dir: &Path, bases: &[&str]) -> Result<(usize, Vec<String>), String> {
    let commits = branch_commits(dir, bases)?;
    let mut found = Vec::new();
    for c in &commits {
        for (_, why) in verdict(c) {
            found.push(format!("{} {} — {why}", &c.sha[..c.sha.len().min(8)], c.subject));
        }
    }
    Ok((commits.len(), found))
}

pub fn run(root: &Path) {
    if !resolves(root, MAIN_REF) {
        eprintln!(
            "signoff-check: FAILED — no `{MAIN_REF}` in this clone, so there is no branch to \
             read. `git fetch origin main` and run it again."
        );
        std::process::exit(1);
    }
    match check(root, &[MAIN_REF, FLOOR]) {
        Err(e) => {
            eprintln!("signoff-check: FAILED — {e}");
            std::process::exit(1);
        }
        Ok((n, found)) if found.is_empty() => {
            println!(
                "signoff-check: OK — {n} commit(s) since {MAIN_REF}: none made as an agent, and \
                 each signed off by its author and committer \
                 (CONTRIBUTING.md, \"Every commit is signed off\")"
            );
        }
        Ok((n, found)) => {
            eprintln!(
                "signoff-check: FAILED — {} finding(s) in {n} commit(s) since {MAIN_REF} \
                 (CONTRIBUTING.md, \"Every commit is signed off\"):",
                found.len()
            );
            for f in &found {
                eprintln!("  {f}");
            }
            eprintln!(
                "\n  Sign off with `git commit -s`; commits already made on your own branch, \
                 `git rebase --signoff {MAIN_REF}`. A commit an agent made is authored as the \
                 person who directed it and carries `Assisted-by: <tool>` — and that person's \
                 own sign-off, with no exemption. An agent never signs off, never \
                 co-authors, and leaves no `Claude-Session:`."
            );
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_fixture::Repo;

    const OWNER: (&str, &str) = ("Austin Herman", "13291882+austinjherman@users.noreply.github.com");
    const ANN: (&str, &str) = ("Ann Example", "ann@example.invalid");
    const BOB: (&str, &str) = ("Bob Example", "bob@example.invalid");
    const CLAUDE: (&str, &str) = ("Claude", "noreply@anthropic.com");

    fn sob(who: (&str, &str)) -> String {
        format!("Signed-off-by: {} <{}>", who.0, who.1)
    }

    const ASSISTED: &str = "Assisted-by: Claude Code";

    /// Commit as `author`, committed by `committer`, with `trailers` at the foot of the message.
    fn commit_as(r: &Repo, file: &str, author: (&str, &str), committer: (&str, &str), trailers: &[&str]) {
        r.write(file, file);
        let mut msg = format!("add {file}\n\nbody.\n");
        if !trailers.is_empty() {
            msg.push('\n');
            for t in trailers {
                msg.push_str(t);
                msg.push('\n');
            }
        }
        r.git(&["add", "-A"]);
        let out = std::process::Command::new("git")
            .current_dir(r.path())
            .args(["commit", "-q", "-m", &msg])
            .env("GIT_AUTHOR_NAME", author.0)
            .env("GIT_AUTHOR_EMAIL", author.1)
            .env("GIT_COMMITTER_NAME", committer.0)
            .env("GIT_COMMITTER_EMAIL", committer.1)
            .output()
            .expect("git commit runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    /// A repository with one base commit, and the base's sha.
    fn repo() -> (Repo, String) {
        let r = Repo::new();
        r.commit("base");
        let base = r.git(&["rev-parse", "HEAD"]);
        (r, base)
    }

    /// The rules the one commit on top of `base` breaks, sorted.
    fn rules(r: &Repo, base: &str) -> Vec<Rule> {
        let commits = branch_commits(r.path(), &[base]).expect("the branch reads");
        assert_eq!(commits.len(), 1);
        let mut v: Vec<Rule> = verdict(&commits[0]).into_iter().map(|(r, _)| r).collect();
        v.sort();
        v
    }

    /// Commit once on a fresh repository and read which rules it breaks.
    fn judge(author: (&str, &str), committer: (&str, &str), trailers: &[&str]) -> Vec<Rule> {
        let (r, base) = repo();
        commit_as(&r, "f", author, committer, trailers);
        rules(&r, &base)
    }

    // The twelve verdicts of the record's Done-when, in its order. Each asserts the exact set
    // of rules broken, so deleting any one rule turns at least one of them red.

    #[test]
    fn v01_signed_by_its_author_passes() {
        assert_eq!(judge(ANN, ANN, &[&sob(ANN)]), vec![]);
    }

    #[test]
    fn v02_unsigned_fails() {
        assert_eq!(judge(ANN, ANN, &[]), vec![Rule::NoAuthorSignoff]);
    }

    #[test]
    fn v03_signed_by_someone_else_fails() {
        assert_eq!(judge(ANN, ANN, &[&sob(BOB)]), vec![Rule::NoAuthorSignoff]);
    }

    #[test]
    fn v04_a_differing_committer_who_did_not_sign_fails() {
        assert_eq!(judge(ANN, BOB, &[&sob(ANN)]), vec![Rule::NoCommitterSignoff]);
    }

    #[test]
    fn v05_the_owners_assisted_commit_with_no_sign_off_fails() {
        assert_eq!(judge(OWNER, OWNER, &[ASSISTED]), vec![Rule::NoAuthorSignoff]);
    }

    #[test]
    fn v06_the_owners_assisted_commit_signed_off_by_claude_fails() {
        assert_eq!(judge(OWNER, OWNER, &[ASSISTED, &sob(OWNER), &sob(CLAUDE)]), vec![Rule::AgentSignoff]);
    }

    #[test]
    fn v07_an_unlisted_persons_assisted_commit_with_their_own_sign_off_passes() {
        assert_eq!(judge(ANN, ANN, &[ASSISTED, &sob(ANN)]), vec![]);
    }

    #[test]
    fn v08_an_unlisted_persons_assisted_commit_without_it_fails() {
        assert_eq!(judge(ANN, ANN, &[ASSISTED]), vec![Rule::NoAuthorSignoff]);
    }

    #[test]
    fn v09_the_owners_assisted_commit_with_the_owners_own_sign_off_passes() {
        assert_eq!(judge(OWNER, OWNER, &[ASSISTED, &sob(OWNER)]), vec![]);
    }

    /// Committed by a person who signed, so authorship is the only thing wrong with it.
    #[test]
    fn v10_authored_as_claude_fails() {
        assert_eq!(judge(CLAUDE, ANN, &[&sob(ANN)]), vec![Rule::AgentAuthor]);
    }

    #[test]
    fn v11_authored_by_a_person_and_committed_as_claude_fails() {
        assert_eq!(judge(ANN, CLAUDE, &[&sob(ANN)]), vec![Rule::AgentCommitter]);
    }

    #[test]
    fn v12_authored_as_fable_design_at_any_address_fails() {
        for email in ["fable-design@kotton.invalid", "someone@example.invalid"] {
            assert_eq!(
                judge(("fable-design", email), ANN, &[&sob(ANN)]),
                vec![Rule::AgentAuthor],
                "fable-design <{email}>"
            );
        }
    }

    // Beyond the twelve: the halves of (b) and (d) none of them isolates.

    /// (b) excuses no one: the owner's commit, with or without `Assisted-by:`, signs off.
    #[test]
    fn the_owners_commit_without_assisted_by_needs_a_sign_off() {
        assert_eq!(judge(OWNER, OWNER, &[]), vec![Rule::NoAuthorSignoff]);
    }

    /// (d) holds on every commit, not only the owner's assisted ones.
    #[test]
    fn an_agents_sign_off_fails_beside_a_persons() {
        assert_eq!(judge(ANN, ANN, &[&sob(ANN), &sob(CLAUDE)]), vec![Rule::AgentSignoff]);
    }

    /// The owner is matched exactly: the owner's name at another address is not the owner.
    #[test]
    fn the_owner_is_matched_exactly() {
        let elsewhere = ("Austin Herman", "13291882+AustinJHerman@users.noreply.github.com");
        assert_eq!(judge(elsewhere, elsewhere, &[ASSISTED]), vec![Rule::NoAuthorSignoff]);
    }

    /// `Claude` is an agent at its own address only; a person called Claude signs for
    /// themselves. The agent's address in another case is still the agent.
    #[test]
    fn claude_is_known_by_name_and_address() {
        let person = ("Claude Example", "claude@example.invalid");
        assert_eq!(judge(person, person, &[&sob(person)]), vec![]);
        let named = ("Claude", "claude@example.invalid");
        assert_eq!(judge(named, named, &[&sob(named)]), vec![]);
        let shouted = ("claude", "NoReply@Anthropic.com");
        assert_eq!(judge(shouted, ANN, &[&sob(ANN)]), vec![Rule::AgentAuthor]);
    }

    /// A `Signed-off-by:` in the body, above other prose, is not a trailer.
    #[test]
    fn a_sign_off_in_the_body_is_not_a_trailer() {
        let (r, base) = repo();
        r.write("f", "f");
        r.commit("add f\n\nSigned-off-by: fixture <fixture@example.invalid>\n\nThat was prose.");
        assert_eq!(rules(&r, &base), vec![Rule::NoAuthorSignoff]);
    }

    /// Nothing reachable from a base is read, and a base the clone lacks is skipped rather
    /// than failing the walk — the two halves of [`FLOOR`].
    #[test]
    fn nothing_under_a_base_is_read() {
        let (r, main) = repo();
        commit_as(&r, "old", CLAUDE, CLAUDE, &[]);
        let floor = r.git(&["rev-parse", "HEAD"]);
        commit_as(&r, "new", OWNER, OWNER, &[ASSISTED, &sob(OWNER)]);
        let (n, found) = check(r.path(), &[&main, &floor]).expect("the branch reads");
        assert_eq!((n, found.len()), (1, 0), "{found:#?}");
        let (n, found) = check(r.path(), &[&main]).expect("the branch reads");
        assert_eq!((n, found.len()), (2, 1), "{found:#?}");
        let (n, _) = check(r.path(), &[&main, "0000000000000000000000000000000000000001"])
            .expect("an absent base is skipped");
        assert_eq!(n, 2);
    }

    /// Any name at the assistant's address is an agent — as author, as committer, and in a
    /// sign-off — so a model-named identity cannot pass as a person signing for itself.
    #[test]
    fn any_name_at_the_agent_address_is_an_agent() {
        let model = ("Claude Opus 5.5", "noreply@anthropic.com");
        assert_eq!(judge(model, ANN, &[&sob(ANN)]), vec![Rule::AgentAuthor]);
        assert_eq!(judge(ANN, model, &[&sob(ANN)]), vec![Rule::AgentCommitter]);
        assert_eq!(judge(ANN, ANN, &[&sob(ANN), &sob(model)]), vec![Rule::AgentSignoff]);
        assert_eq!(judge(model, model, &[&sob(model)]), vec![Rule::AgentAuthor, Rule::AgentSignoff]);
    }

    // (e), DEC-0091 amended 2026-10-02: the loop's agent commit ends with `Gates:` then
    // `Assisted-by: Claude Code`, and nothing else.

    const GATES: &str = "Gates: cargo test -p xtask 0";

    /// The owner's commit shape as the amendment writes it passes.
    #[test]
    fn the_owners_gates_and_assisted_by_commit_without_a_sign_off_fails() {
        assert_eq!(judge(OWNER, OWNER, &[GATES, ASSISTED]), vec![Rule::NoAuthorSignoff]);
    }

    #[test]
    fn the_owners_gates_and_assisted_by_commit_passes() {
        assert_eq!(judge(OWNER, OWNER, &[GATES, ASSISTED, &sob(OWNER)]), vec![]);
    }

    #[test]
    fn an_assisted_commit_carrying_claude_session_fails() {
        let session = "Claude-Session: https://claude.ai/code/session_0000";
        assert_eq!(judge(OWNER, OWNER, &[GATES, ASSISTED, &sob(OWNER), session]), vec![Rule::SessionTrailer]);
        // A contributor's assisted commit, signed off as the kernel asks, is held to it too.
        assert_eq!(
            judge(ANN, ANN, &[ASSISTED, &sob(ANN), session]),
            vec![Rule::SessionTrailer]
        );
    }

    #[test]
    fn an_assisted_commit_naming_an_agent_as_co_author_fails() {
        for agent in [CLAUDE, ("Claude Opus 5.5", "noreply@anthropic.com"), ("fable-design", "x@example.invalid")] {
            let co = format!("Co-Authored-By: {} <{}>", agent.0, agent.1);
            assert_eq!(
                judge(OWNER, OWNER, &[GATES, ASSISTED, &sob(OWNER), &co]),
                vec![Rule::AgentCoAuthor],
                "{co}"
            );
        }
    }

    /// `Co-Authored-By:` stays for another person who co-wrote it.
    #[test]
    fn an_assisted_commit_naming_a_person_as_co_author_passes() {
        let co = format!("Co-Authored-By: {} <{}>", ANN.0, ANN.1);
        assert_eq!(judge(OWNER, OWNER, &[GATES, ASSISTED, &sob(OWNER), &co]), vec![]);
    }

    /// A forge bot is an agent: a name ending in `[bot]`, or a GitHub no-reply address whose
    /// local part ends in `[bot]` — as author, as a sign-off (d), and as a co-author (e).
    #[test]
    fn a_bot_identity_is_an_agent() {
        let bot = ("claude[bot]", "209825114+claude[bot]@users.noreply.github.com");
        assert_eq!(judge(bot, ANN, &[&sob(ANN)]), vec![Rule::AgentAuthor]);
        assert_eq!(judge(ANN, ANN, &[&sob(ANN), &sob(bot)]), vec![Rule::AgentSignoff]);
        let co = format!("Co-Authored-By: {} <{}>", bot.0, bot.1);
        assert_eq!(judge(OWNER, OWNER, &[GATES, ASSISTED, &sob(OWNER), &co]), vec![Rule::AgentCoAuthor]);
        // Either half alone is enough.
        let named = ("dependabot[bot]", "bot@example.invalid");
        assert_eq!(judge(named, ANN, &[&sob(ANN)]), vec![Rule::AgentAuthor]);
        let addressed = ("Some Name", "49699333+Dependabot[Bot]@users.noreply.github.com");
        assert_eq!(judge(addressed, ANN, &[&sob(ANN)]), vec![Rule::AgentAuthor]);
        // A person whose name merely contains `bot` is a person.
        let person = ("Abbott Example", "abbott@example.invalid");
        assert_eq!(judge(person, person, &[&sob(person)]), vec![]);
    }

    /// The lists and the floor are exactly the ones the record names; a change to any is a
    /// change to the ruling's record, not a quiet edit here.
    #[test]
    fn the_lists_are_the_rulings() {
        assert_eq!(
            AGENT_IDENTITIES,
            &[("Claude", Some("noreply@anthropic.com")), ("fable-design", None)]
        );
        assert_eq!(AGENT_ADDRESSES, &["noreply@anthropic.com"]);
        assert_eq!((BOT_SUFFIX, BOT_DOMAIN), ("[bot]", "@users.noreply.github.com"));
        assert_eq!(PEOPLE, &[OWNER]);
        assert_eq!(FLOOR, "5ea215acfaa9d06f205c60678b89efab16ff0be2");
    }
}
