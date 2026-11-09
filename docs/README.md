# docs

What a person who builds or runs the tree reads. The system's design is in each crate's
`README.md` beside its code, and the protocol is in
[kottonllc/kotton-protocol](https://github.com/kottonllc/kotton-protocol).

- [`cli/reference.md`](cli/reference.md): every verb of the `kotton` command line and the
  REPL, generated from the tree by `cargo xtask-docs gen-docs`; a change to a verb's help
  regenerates it.
- [`windows.md`](windows.md): building the tree on Windows x86_64, what every pull request
  builds and tests there, and what it does not hold yet.
