# kotton

The user-facing CLI for Kotton. `kotton repl <user>` (via `just terminal <user>`) is the headless shell entry point — it reads a cached session token and drops you into an interactive REPL where commands are short and VFS-scoped.

`kctl` (also in this crate) is the operator/device plumbing tool. It is not user-facing and is not documented here.

## The model

```
# Terminal 1
just kuserd::start           # start kuserd (user daemon)

# Terminal 2
just user::create alice         # create identity
just user::auth alice        # cache session token
just terminal alice          # enter headless REPL
```

Inside the REPL:

```
kotton> ls
kotton> cat /notes/hello.txt
kotton> edit /notes/hello.txt
kotton> app list
kotton> app add ./apps/kotton-shell
kotton> exit
```

For the GUI, register an app first, then start the display server:

```
just app::sideload ./apps/kotton-shell alice
just kuid::start
```

Or combined: `just desktop::run alice` after `just user::auth alice` and `just app::sideload ./apps/kotton-shell alice`.

## REPL commands

| Command                   | Description                                |
| ------------------------- | ------------------------------------------ |
| `ls [path]`               | List VFS directory                         |
| `cat <path>`              | Print file contents                        |
| `edit <path>`             | Open file in `$EDITOR`, write back on save |
| `mkdir <path>`            | Create directory                           |
| `rm <path>`               | Remove file or directory                   |
| `cp <src> <dst>`          | Copy                                       |
| `mv <src> <dst>`          | Move / rename                              |
| `app list`                | List registered app bundles                |
| `app dev <path>`          | Register a web app bundle (dev/HMR mode)   |
| `app install <path>`      | Register a web app bundle (production)     |
| `msg <did\|alias> <text>` | Send a direct message                      |
| `exit`                    | Exit REPL                                  |

## Developer tooling (`kctl`)

`kctl` commands are for device operators, not end users. Examples:

```bash
kctl daemon status
kctl ipc inspect
kctl node pair <token>
```

## Installation

```bash
cargo install --path .     # installs both `kotton` and `kctl`
```

## Testing

```bash
cargo test -p kotton
```

## Documentation

- Run `kotton --help` for full command reference
- [docs/cli/reference.md](../../docs/cli/reference.md) — generated CLI reference
- [README.md](../../README.md#building-it) — build and first run
- [SECURITY.md](../../SECURITY.md) — security architecture
