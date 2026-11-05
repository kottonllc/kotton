# Governance

How decisions about this project are made, by role. This page names roles and how they are
held; it names no person, because a project whose data belongs to the people who make it should
not rest on one person either.

## Roles

- **Contributor.** Anyone who opens an issue or sends a pull request under
  [`CONTRIBUTING.md`](CONTRIBUTING.md). A contributor may propose anything, including a change
  to this page.
- **Maintainer.** Anyone the repository grants the right to merge into `main`. The list of
  maintainers is the repository's own list of who holds that right; it is not copied here, so it
  cannot drift. A maintainer is added or removed by a pull request to this page that the other
  maintainers do not object to within the 72 hours below, and the repository's settings follow it.
- **Driver.** Whoever moves an issue through the loop: a contributor, or an agent working at a
  contributor's direction. A driver holds no authority of its own; it follows
  [`CONTRIBUTING.md`](CONTRIBUTING.md) and reports.

## How a decision is made

- **Lazy consensus.** A proposal (an issue labelled `decision`, a pull request, or a change to
  kotton-protocol) states what will happen and its default. If no maintainer objects within
  72 hours, it stands. An objection says why, in writing, on the proposal.
- **When maintainers disagree,** the proposal stays open and its default is not built until they
  agree. If they cannot, the change that keeps the ownership bar ([`CLAUDE.md`](CLAUDE.md)) at
  least as strong is taken.
- **Where a decision is kept.** A design decision is recorded where the design is: the
  protocol documents in kotton-protocol, or the module docs it governs. Code cites it by name,
  never by number.
- **What does not bend** ([`CONTRIBUTING.md`](CONTRIBUTING.md)) is not decided this way. No
  decision may weaken the ownership bar, capability confinement, or the sign-off.

## Reserved to a maintainer

Only a maintainer may: tag or publish a release; change a repository setting, a required check
or a branch rule; hold or rotate a signing or release key; add or remove a maintainer. A driver
asks for these and does not do them.

## Changing this page

By a pull request, under the rule above. This page is meant to grow when there are more
maintainers: elected roles, areas with their own leads, or votes for what consensus cannot
settle. It does not have them yet, because there is no one yet to hold them.
