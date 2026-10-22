# kotton-providers-peer-storage

**Layer 3 — Peer-to-Peer Object Storage**

Implements `ObjectStorage` by forwarding each operation to a paired Kotton peer
over a QUIC connection. This is the replication channel that lets two Kotton nodes
synchronise user data directly without a central cloud backend.

**Key public types:**

- `KottonPeerObjectStorage` — implements `ObjectStorage`. Each call serialises a
  `UserRequest` and sends it to the peer; the peer's daemon handles it and
  returns a `UserResponse`. The wire format is identical to the local IPC
  channel so the same daemon dispatch code handles both paths.
- `QuicPeerChannel` — the QUIC connection wrapper that implements `PeerChannel`.
  A new QUIC stream is opened per request; no persistent stream is held between
  calls.
- `PeerChannel` — the transport abstraction trait (allows test doubles).

**Relationship to `kotton-providers-object-storage`:**
`kotton-providers-object-storage` handles cloud/local blob stores (S3, disk, etc.).
This crate is the _inter-node transport_. The runtime's storage router decides
which backend to write to; this crate is just the QUIC delivery mechanism.

**Does not:** implement any discovery, NAT traversal, or authentication. It
requires a `QuicConnection` that is already established and mutually authenticated
by `kotton-runtime`'s pairing and NAT traversal layer.

**Depends on:** `kotton-platform`, `kotton-protocol`.
