# kotton-protocol

IPC wire protocol types shared across the kotton daemon, SDK, and all crates above this layer.

## Purpose

This crate contains **only** the shared protocol contract:

1. **IPC wire types** — `UserRequest`/`UserResponse` (kuserd, user daemon) and `DeviceRequest`/`DeviceResponse` (kdeviced, device daemon) — the request/response vocabularies for each IPC socket
2. **Peer and session types** — `PairedNode`, `EphemeralSession`, `SessionPermissions`, `SyncRule`, `MountConfig`
3. **Remote backend types** — `RemoteBackend`, `RemoteConfig`
4. **Coord types** — `CoordPushPayload`, `CoordLookupResponse`, `CoordStatusInfo`
5. **DID types** — `Did`, `DidDocument`, `VerificationMethod`

**Not** user record schemas. Those live in `crates/01_schemas`.

## Current Modules

### `did/` - W3C DID Standard

- Core identity types: `Did`, `DidDocument`, `VerificationMethod`
- Used by: `providers/crypto/did`
- Status: ✅ Actively used

### `sync/` - Sync Protocol

- Sync messages: `SyncMessage`, `SyncOperation`
- File state: `FileState`, `SyncState`
- Used by: `services/sync`
- Status: ✅ Actively used

## What DOES belong here

✅ **Protocol definitions** - Network handshakes, message envelopes
✅ **Persisted types** - User records, device info (stable schemas)
✅ **Cross-boundary types** - Shared between processes/services
✅ **Wire format types** - Serialized over network

## What DOES NOT belong here

❌ **Runtime logic** - Business logic, state machines
❌ **API responses** - Use `runtime/types.rs` instead
❌ **Premature features** - Add when implementing, not before
❌ **Single-crate types** - If only one crate uses it, define it there
❌ **Complex logic** - Schemas are pure data structures only

## Guidelines

### When to add a new type

1. **Is it actively used?** - Don't add speculative types
2. **Does it cross boundaries?** - Network, IPC, persistence
3. **Is it serializable?** - Must implement `Serialize + Deserialize`
4. **Is it stable?** - Persisted types need stable schemas

### Type organization

- **One domain per subdirectory** - `did/`, `sync/`, `user/`
- **No complex logic** - Pure data structures only
- **Re-export at module level** - `pub use` in mod.rs
- **Document purpose** - Clear docstrings on each type

## Anti-patterns to avoid

**Dumping ground** - Don't add types "just in case"
**Premature design** - Don't design features before implementing
**Runtime responses** - API responses go in `runtime/types.rs`

## Maintenance

- **Regular audits** - Check for unused types every milestone
- **Zero-tolerance for dead code** - Delete if unused
- **Document why** - Every module needs clear usage documentation

## See Also

- [Processes and crates](../../docs/design/processes.md) — what runs, what each process may hold, and how they talk
