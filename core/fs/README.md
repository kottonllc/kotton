# kotton-fs

**The `fs` domain** — laid out by tier within the domain (RFC-0059).
Today it holds `provider/`; `runtime/` and `daemon/` arrive as `05_runtime`
and `06_daemon` dissolve.

Concrete implementation of the `Filesystem` platform trait using `tokio::fs`.
Provides `OsFilesystem`, the standard local-disk backend used by the daemon,
the runtime, and integration tests.

**Key public types:**

- `OsFilesystem` — implements `Filesystem` via `tokio::fs`. Supports async
  `read`, `write`, `delete`, `list_dir`, `metadata`, and `create_dir_all`.

**Does not:** implement any virtualization, encryption, caching, or remote
access. For encrypted or virtual storage see `kotton-runtime` (VFS layer); for
generic object key/value storage see `kotton-providers-object-storage`.

**Depends on:** `kotton-platform`.
