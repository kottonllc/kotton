# kotton-providers-ipc

**Layer 3 — IPC Transport**

Cross-platform IPC transport for daemon ↔ client communication.
On Linux/macOS this is a Unix domain socket; on Windows it is a named pipe.
All messages are length-prefixed (4-byte little-endian), JSON-encoded typed Rust structs.

**Key public types:**

- `IpcClient<Req, Resp>` — typed request/response client. Used by `kotton`
  to send `UserRequest` and receive `UserResponse`.
- `IpcServer` — accepts incoming connections and drives per-connection handlers.
- `OsIpcListener` / `OsIpcConnection` / `AcceptedConnection` — OS-level
  socket/pipe primitives implementing the `IpcListener` and `IpcConnection`
  traits from `kotton-platform`.
- `OsUserId` — the OS-reported PID/UID of the connecting process. Recorded as
  diagnostic metadata; the auth gate is the session token, not peer credentials.

The length-prefix framing is identical on both sides so the daemon and SDK
always agree on message boundaries without a handshake.

**Does not:** implement any serialization format other than JSON, any message
authentication beyond session tokens (enforced by `kotton-daemon`), or TLS
(managed by `kotton-providers-network` for remote connections).

**Depends on:** `kotton-platform`.
