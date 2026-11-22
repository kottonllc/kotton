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
  contributor's direction. A driver holds no authority of its own: it decides and merges only as
  this page says, follows [`CONTRIBUTING.md`](CONTRIBUTING.md) and reports to the person who
  directed it.

## How a decision is made

- **The driver decides what touches no principle.** A `decision` issue, or a proposed change to
  kotton-protocol's documents made from this repository's work, states the choice and its
  default. The driver takes the default the issue argues for, or the one a reviewer argues for
  in its place, records it on the `decision` issue, or in the pull request's description when
  the choice came up in the work, and builds it. It does not wait for a maintainer, queue the
  choice for one or ask one to confirm the default. Building it is an ordinary pull request,
  landed only through the loop. A maintainer may answer any choice in writing at any time, and
  that answer stands.
- **What touches a principle is a maintainer's.** The driver brings it to a maintainer with the
  default it recommends, and nothing is built until a maintainer answers in writing. The answer
  settles whether the choice touches a principle and what is built; it cannot allow what the
  last paragraph of this section says no decision may do.
- **When maintainers disagree,** the proposal stays open and its default is not built. It is
  settled by a maintainer's written answer that the others accept; no maintainer merges over
  another's open objection, and a choice that would keep the ownership bar
  ([`CLAUDE.md`](CLAUDE.md)) less strong than the other is never the one taken.
- **Where a decision is kept.** A design decision is recorded where the design is: the protocol
  documents in kotton-protocol, or the module docs it governs. Everything in the tree (code,
  comments, docs, test names) cites it by name, the words of what it settles, never by a
  tracker's number: not an issue's, nor a choice's or an addendum's within one. A tracker's
  number means nothing to a reader of the tree, and goes stale. A protocol document is cited as
  it names itself. Where a commit message or a pull request's description cites a decision, it
  names it the same way, and may give the `decision` issue's number beside the name, as its
  address; the `decision` issue itself numbers its choices as it needs. The reviewer holds the
  lines a pull request changes, and its description, to this.
- **What is not decided this way.** What does not bend ([`CONTRIBUTING.md`](CONTRIBUTING.md)),
  and everything [`CLAUDE.md`](CLAUDE.md) says never to do. No decision may weaken the ownership
  bar or capability confinement, carry a key across a process boundary, trust infrastructure the
  design does not, add an identity authority, or weaken the sign-off. These, what does not bend,
  and kotton-protocol's
  [Principles](https://github.com/kottonllc/kotton-protocol/blob/main/design/principles.md), are
  the principles. A choice touches one when it would change what one says, weaken one or a check
  that holds it, or make an exception to one. A change to this paragraph, to what a pull request
  must pass before it lands, to what is reserved to a maintainer, to how a maintainer is added or
  removed, or to how these three documents are changed touches one too, unless it only binds a
  driver more tightly. Whoever makes or reads a choice and doubts it says so in writing. If
  anyone says in writing that a choice might touch one, the driver neither takes it nor merges
  it: it waits for a maintainer's written answer.

## Merging into `main`

A pull request lands only after its assessor, its reviewer and the gate have passed it, on a
head that contains `main`; no one, maintainer or driver, merges around them. It is merged by a
maintainer, or by a driver acting under a maintainer's standing direction, given in writing and
withdrawn the same way, once all three have passed. That direction reaches a change to
[`CLAUDE.md`](CLAUDE.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) or this page. It does not reach a
pull request, to these documents or anywhere in the tree, that touches a principle: that one
also needs a maintainer's written approval on the pull request, and its own rules do not ratify
it. A change to kotton-protocol's principles is a maintainer's to merge.

The reading is kept in proportion. A fix round that changes only prose or comments, and only as
its reader asked in writing, is not read a second time, and a `hygiene` change needs one reader,
not two. Neither holds for a change to [`CLAUDE.md`](CLAUDE.md),
[`CONTRIBUTING.md`](CONTRIBUTING.md) or this page: there the prose is the rule.

A standing direction is in force: a maintainer gave it in writing on the pull request that added
this sentence.

## Reserved to a maintainer

Only a maintainer may: give or withdraw a driver's standing direction to merge; answer what
touches a principle; shorten this list; tag or publish a release; change a repository setting, a
required check, a branch rule or a milestone's order; hold or rotate a signing or release key;
add or remove a maintainer. A driver asks for these and does not do them.

## Changing this page

By a pull request, landed as any other; one that touches a principle needs a maintainer's
written approval on the pull request. This page is meant to grow when
there are more maintainers: elected roles, areas with their own leads, or votes for what
consensus cannot settle. It does not have them yet, because there is no one yet to hold them.
