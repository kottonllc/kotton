# kotton-proc

**The `proc` domain — spawning a process, and confining one.**

Two things live here, and the second is why the crate matters:

- **`OsProcess`** — the `Process` platform trait over `tokio::process`, so callers can be
  tested against a mock.
- **`sandbox`** — the operating-system confinement every guest process is spawned under
 .

## The sandbox

`DEC-0074` rules that a process running a stranger's file is a guest and is confined like
one. Two callers, and neither shaped the profile:

| Caller | Runs | Granted |
|---|---|---|
| `kinferd` | a weights file a stranger wrote | its own program. Nothing else — the weights arrive as frames on the pipe it was handed |
| `kotton-runner` | third-party WASM, on every launch of every app | its own program, the component, the app's data directory, the user's VFS mount, and — for the occupant — read on each root tree it is handed |

`Profile` is built by addition from `Profile::nothing`, so a spawn's reach is the list of
lines at its call site. **There is no way to ask for the network** — not a default that is
off, but a grant the type cannot express, because `Article VIII` says no app reaches the
network directly and both confined processes are reached over a descriptor handed to them at
spawn.

```rust
let profile = Profile::nothing("kinferd").executing(&binary);
kotton_proc::confine(&mut command, &profile)?;   // then spawn
```

Prepared in the parent, applied in the child between `fork` and `execve`: the child never
runs an instruction unconfined, and the confined binaries contain no sandbox code of their
own.

**A sandbox is per-platform, and `confine` refuses where there is none.** Linux is
implemented — Landlock for the filesystem, and a seccomp-BPF filter that returns `EPERM` to
`socket(2)`, to `connect`, `bind`, `listen` and `accept`, and to the three `io_uring` calls,
allowing only `socketpair(AF_UNIX, …)`. `io_uring` is on that list because a ring makes and
connects sockets inside the kernel without calling `socket(2)`, and until 2026-09-23 it was not:
a confined probe sent a datagram through it (`DEC-0074`, "io_uring was a second door"). The list
is the routes known to make an endpoint, each measured in `tests/sandbox.rs`, not a proof that
there is no other. Everywhere else returns `SandboxError::Unsupported`, and `kinferd`'s caller
does not spawn, which is `DEC-0074` §1: *where Kotton cannot confine, it does not run a
stranger's weights.* The runner's caller refuses too on Linux (an architecture the filter is
not compiled for); on every other platform it does spawn, with wasmtime as the only layer, which is what every
platform had before this crate had a sandbox: whether §1 reaches every guest app — and so
the desktop itself, since the shell is a guest — is escalated to the owner on the Windows
record below, and that is its default. The gaps are
macOS
and
Windows.

What it does **not** do: isolate GPU memory (`DEC-0074` §3 says so, and says it is a second
mechanism), or close a descriptor the parent leaked.

**Does not:** manage the `kdeviced` or `kuserd` daemon lifecycle, nor the WASM sandbox, which
is `kotton-wasm` and confines by construction where this confines by interception.

**Depends on:** `kotton-sys`.
