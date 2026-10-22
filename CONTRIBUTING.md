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

## Sign off

Every commit carries a `Signed-off-by: Your Name <email>` line, which `git commit -s` adds. By
it you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you have the right to submit the change under the licence [`LICENSE`](LICENSE) gives the
directory it lands in, and that the record of it is public and kept.

A merge commit is a commit: `git merge --signoff origin/main` signs it, and git's default merge
message without that flag is refused.

A commit is never authored as an agent. If an agent made it at your direction, it is authored as
you, carries an `Assisted-by: <tool>` trailer, and carries your own sign-off as well: an agent
cannot certify. The owner's own agent commits carry no per-commit sign-off, because the owner
certifies that work by signing each release; `signoff-check` holds both rules.

## Every commit is signed off

Every commit carries a `Signed-off-by: Your Name <email>` line, which `git commit -s` adds.
By it you certify the [Developer Certificate of Origin 1.1](DCO.md): that you have the right
to submit the change under [Apache-2.0](LICENSE) for code and [CC BY-SA 4.0](papers/LICENSE)
for prose, and that the record of it is public and kept.

There is no exemption. A commit an agent made at your direction is authored as you, carries
an `Assisted-by: <tool>` trailer, and carries your own sign-off: an agent cannot certify, and
a commit authored as an agent is refused. A merge commit is a commit: `git merge --signoff`
signs it.

The check that holds this is [`.github/workflows/signoff.yml`](.github/workflows/signoff.yml),
and it runs on every pull request.


## What does not bend

- **Ownership is the bar.** Ask of any surface you touch: does this compose into an asset, and
  whose?
- **Never make a test pass by silencing it.** A red test is a finding.
- **Never `--no-verify`, never force-push a shared branch, never rewrite published history.**
- **Never delete code on suspicion.** Remove what you can show is dead, in its own commit.

## Security

Report a vulnerability privately, per [`SECURITY.md`](SECURITY.md), and never in a public issue.
