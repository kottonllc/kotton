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
  cannot drift. A maintainer is added or removed by a pull request to this page that a
  maintainer other than the one added or removed approves in writing; while there is one
  maintainer, that maintainer's own written approval is required, and the last maintainer is
  removed only by their own act. The repository's settings follow the merged page.
- **Driver.** Whoever moves an issue through the loop: a contributor, or an agent working at a
  contributor's direction. A driver holds no authority of its own; it follows
  [`CONTRIBUTING.md`](CONTRIBUTING.md) and reports to the person who directed it.

## How a decision is made

- **Lazy consensus.** A `decision` issue, or a proposed change to kotton-protocol's documents
  made from this repository's work, states the choice and its default, and mentions the person
  who directed the work and the maintainers. If no maintainer objects within 72 hours of the
  last change to the choice or its default, the default may be built. Building it is an ordinary
  pull request, landed only through the loop. Silence never merges anything. An objection says
  why, in writing, on the proposal.
- **When maintainers disagree,** the proposal stays open and its default is not built. It is
  settled by a maintainer's written answer that the others accept; no maintainer merges over
  another's open objection, and a choice that would keep the ownership bar
  ([`CLAUDE.md`](CLAUDE.md)) less strong than the other is never the one taken.
- **Where a decision is kept.** A design decision is recorded where the design is: the
  protocol documents in kotton-protocol, or the module docs it governs. Code cites it by name,
  never by number.
- **What is not decided this way.** What does not bend ([`CONTRIBUTING.md`](CONTRIBUTING.md)),
  and everything [`CLAUDE.md`](CLAUDE.md) says never to do. No decision may weaken the ownership
  bar or capability confinement, carry a key across a process boundary, trust infrastructure the
  design does not, add an identity authority, or weaken the sign-off. If anyone says in writing
  that a default might, that default is not built on silence: it waits for a maintainer's
  written answer.

## Merging into `main`

A pull request lands only after its assessor, its reviewer and the gate have passed it; no one,
maintainer or driver, merges around them. It is merged by a maintainer, or by a driver acting
under a maintainer's standing direction, given in writing and withdrawn the same way, once all
three have passed. A change to [`CLAUDE.md`](CLAUDE.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) or
this page also needs a maintainer's written approval on the pull request; its own rules do not
ratify it.

## Reserved to a maintainer

Only a maintainer may: give or withdraw a driver's standing direction to merge; approve in
writing a change to [`CLAUDE.md`](CLAUDE.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) or this page;
tag or publish a release; change a repository setting, a required check, a branch rule or a
milestone's order; hold or rotate a signing or release key; add or remove a maintainer. A driver
asks for these and does not do them.

## Changing this page

By a pull request with a maintainer's written approval. This page is meant to grow when there
are more maintainers: elected roles, areas with their own leads, or votes for what consensus
cannot settle. It does not have them yet, because there is no one yet to hold them.
