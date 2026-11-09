# Kotton on Windows

What a person running Kotton on Windows x86_64 gets, what the gate holds of it on every
pull request, and what it does not. The protocol names Windows on x86_64 as a device at
`v0.1.0` and says each device platform is built and tested in the gate, so that what a
person runs is what the release was held to; this page says how far that is true today.
Windows on arm64 is not built and not promised.

## Building it

`cargo` builds the workspace on Windows as on Linux, through PowerShell. The
[`Justfile`](../Justfile) names what to install first:

- **OpenSSL**, which the encrypted record database links against: `scoop install openssl`.
  `.cargo/config.toml` points the build at it and forbids a vendored copy, so the build works
  in any shell without sourcing `.env`.
- **MSVC Build Tools**, from the Visual Studio Installer ("Desktop development with C++").
- **Python 3**, for the desktop build only (`just desktop::build`): the CSS engine under the
  window runs a code-generation step at compile time. A headless or server build needs none.

The toolchain is the one `rust-toolchain.toml` names; `rustup` installs it on the first
`cargo`. Kotton's data lives under `%LOCALAPPDATA%\Kotton`, and the daemon's socket is a named
pipe where Linux has a Unix domain socket (`core/ipc`).

## What every pull request holds on Windows

One job on a `windows-latest` runner, [`.github/workflows/windows.yml`](../.github/workflows/windows.yml),
runs on every pull request and is a required check on `main`. It is a build, not a check: a
check stops before codegen and the link, and the link is where a Windows-only symbol, an
import library or the linker fails. The job:

- builds the workspace with warnings refused;
- compiles every test target in the workspace, the integration suite's, xtask's and the
  daemons' included, so each one is held to compile on Windows whether or not it runs there;
- runs every test of the library crates it names, which is the greater part of the tree;
- runs the daemons' own unit tests in-process, with no daemon started.

The run is declared same-machine, so every socket binds loopback and nothing advertises on
the network; no test raises the Windows firewall dialog. The workflow's header says what it
holds and why, by test rather than by crate; it is the authority, and this page does not
restate its list.

## What it does not hold

- **The integration suite** (`tests/`), which starts the daemons and the relay as processes,
  is compiled on Windows and run on Linux only. The relay itself is a workspace of its own,
  released for Linux alone, and is not built on Windows; `cargo xtask windows-check`, a grep
  for Unix-only calls that runs in `just lint`, is what still reads it, and says so in its
  module doc.
- **xtask's tests**, the gate's own tooling, written for the Linux the gate runs on.
- **kvaultd's integration tests**, which install the built vault and drive it with a shell
  and Linux tools.
- **A release archive.** The release workflow produces no Windows archive today; the
  PowerShell installer kotton-dist will ship has nothing to install until it does
  (kotton #59). A Windows build of the tree has been run by hand and is not a release.
- **Confinement reaching a guest.** The Windows sandbox, an AppContainer with no
  capabilities, an access entry per grant and a job object attached at process creation, is
  written, compiled and measured by `core/proc`'s own probes on every pull request. It is not
  reached by `confine`, which still refuses on Windows: stable Rust gives a `Command` no way to
  carry the attribute list the container rides on. `core/proc/src/provider/sandbox/mod.rs`'s
  platform table and `windows.rs`'s module doc say exactly what is measured and what is not.
  A guest launched on Windows today runs unconfined, and the daemon says so rather than
  pretending otherwise.
- **The desktop.** The window builds on Windows with Python present; it is not exercised by
  any gate on any platform yet.

A thing not held here is a thing a pull request can break without a check going red. When
one of these moves into the gate, this page and the workflow's header move with it.
