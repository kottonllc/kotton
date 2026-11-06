# Contributing to Kotton

Kotton is pre-alpha, built by one owner and the agents working at the owner's direction, and
open to anyone who wants to read it whole and send a change back. This page is how that works.

## Reach green

```sh
git clone https://github.com/kottonllc/kotton && cd kotton
cargo check --workspace --all-targets --locked
cargo check --manifest-path infra/relay/Cargo.toml --all-targets --locked
```

`cargo` is all it needs: `rustup` fetches the toolchain `rust-toolchain.toml` names on first
use. On Linux the workspace links the system OpenSSL, so install `libssl-dev` and `pkg-config`
first.

## The loop

- **An issue is the brief.** It says what is wrong or missing, where, and what done looks like.
  Open one before anything larger than a fix, so the shape is agreed before the work.
- **A pull request is the change.** One logical change, on a branch named for it, against
  `main`. Its description says what changed and every check that ran, each with its real exit.
  A claim a reviewer cannot reproduce is a reason to send it back.
- **An assessor, then a reviewer.** The assessor holds the change to the issue: does it do what
  was asked, at the cause rather than the site, and nothing else. The reviewer holds it to the
  design: does it keep the ownership bar and confinement, and does it say what it changed.
  Either may send it back, with the reason in writing.
- **The gate.** The merged tree is built again before it lands; a change that breaks it does
  not merge.

## What goes next

The sprint is the queue. Its milestone holds the sprint's scope items (label `scope`), in the
milestone's order, and a finish line; a found defect joins it only as a `blocker`. Whoever
drives the loop takes the top scope item; a maintainer ([`GOVERNANCE.md`](GOVERNANCE.md)) may
reorder it at any time, and nothing waits for one to.

- **A blocker goes next; nothing else interrupts.** A blocker is a defect on a path the sprint's
  finish line exercises or a released tag ships (none yet), and it does one of these: loses, or
  leaves unopenable, data the system acknowledged writing; lets one identity reach another's
  data or keys; carries a key across a process boundary; writes a durable identifier that joins
  observations across devices, vaults or time; lets a grant reach past what was granted; or
  breaks, on such a path, what a named pull request landed in this sprint or the last held with
  a green test. A red check on `main`, and a check that should hold `main` but does not run or
  cannot fail, are blockers on any path: the loop stands on them. A blocker issue names its
  clause, its path and its reproduction in its first lines; without all three it is a `defect`.
  A blocker that is a vulnerability is reported privately per [`SECURITY.md`](SECURITY.md),
  never as a public issue; it still goes next, and its public record, after the fix lands,
  names only its clause. A blocker goes next after the pull request in hand lands or is parked,
  not inside that pull request.
- **Severity is the finder's to propose and a maintainer's or the next reviewer's to settle.**
  `blocker`, `defect` or `hygiene` is set at filing by whoever found it, with the clause it
  meets. When the driver is the finder, a `blocker` it files is confirmed by the next reviewer
  before it goes next, and a `hygiene` it files is not closed as not taken without a
  maintainer's look. Otherwise the driver records severity and neither raises nor lowers it.
- **A choice an issue leaves open is a `decision`, not a wait.** The issue states the choice and
  a default, and mentions the person who directed the work and the maintainers. If no
  maintainer objects within 72 hours of the last change to the choice or its default, the
  default stands and is built through the loop, unless it is one
  [`GOVERNANCE.md`](GOVERNANCE.md) says is not decided this way. A design decision is then
  recorded where the design is (kotton-protocol's documents, or the module docs). A reversal
  after that is a new proposal, not a quiet change.
- **Defects are budgeted when a sprint opens.** One or two `defect` issues are taken into the
  sprint and named in its milestone; no others are taken mid-sprint. A `hygiene` issue that no
  sprint takes by the end of the next sprint is closed as not taken, with a comment citing this
  rule.
- **A pull request is the size of its issue's done-when.** A finding outside it is filed, not
  fixed there, unless the diff itself introduces it. At most one follow-up issue per review;
  wording and test-shape notes are review comments, not issues.
- **When a pull request lands, its issue closes**, once its assessor has confirmed the
  done-when was met, naming the pull request; or it says what is left and under which issue.
- **Report, do not ask, within the queue.** Before a blocker, name its clause and go. Work off
  the queue is a `decision` under the rule above, not something a driver starts on its own
  word. A driver does not close, relabel or delete what another person opened, delete a branch
  it did not make, or reorder the milestone; it asks for these, as it asks for what
  [`GOVERNANCE.md`](GOVERNANCE.md) reserves to a maintainer.

## Every commit is signed off

Every commit carries a `Signed-off-by: Your Name <email>` line, which `git commit -s` adds.
By it you certify the [Developer Certificate of Origin 1.1](DCO.md): that you have the right
to submit the change under the licence [`LICENSE`](LICENSE) gives the directory it lands in,
and that the record of it is public and kept.

There is no exemption. A commit an agent made at your direction is authored as you, carries
an `Assisted-by: <tool>` trailer, and carries your own sign-off: an agent cannot certify, and
a commit authored as an agent is refused. A merge commit is a commit: `git merge --signoff`
signs it.

The check that holds this is [`.github/workflows/signoff.yml`](.github/workflows/signoff.yml),
and it runs on every pull request. `cargo xtask signoff-check` holds the same rule, plus the
shape of an agent's commit (`Gates:`, `Assisted-by:`, then your sign-off), under `just lint`,
and a test keeps the two in agreement.

## What does not bend

- **Ownership is the bar.** Ask of any surface you touch: does this compose into an asset, and
  whose?
- **Never make a test pass by silencing it.** A red test is a finding.
- **Never `--no-verify`, never force-push a shared branch, never rewrite published history.**
- **Never delete code on suspicion.** Remove what you can show is dead, in its own commit.

## Security

Report a vulnerability privately, per [`SECURITY.md`](SECURITY.md), and never in a public issue.
