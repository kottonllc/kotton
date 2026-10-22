# kotton-providers-object-storage

**Layer 3 — Generic Object Storage Providers**

Three storage-backend-agnostic implementations of the `ObjectStorage` trait from
`kotton-platform`. Each works with any key/value blob store; vendor-specific
backends (S3, Azure Blob, IPFS) live in `crates/04_integrations/`.

**Key public types:**

- `LocalObjectStorage` — filesystem-backed object store. Each object is a file
  under a root directory. Used as the default "local remote" for every user.
- `MemoryObjectStorage` — in-memory store for unit tests and ephemeral operations.
- `CachedObjectStorage` — wraps any remote `ObjectStorage` with a local
  `LocalObjectStorage` cache. Reads are served from cache when available;
  writes go to the remote first and then update the cache. Used to reduce
  latency and bandwidth for S3/IPFS backends.

**Relationship to `kotton-providers-peer-storage`:**
This crate handles cloud-style blob stores (local disk, S3, Azure, IPFS).
`kotton-providers-peer-storage` is a separate transport that synchronises blobs
_between two Kotton nodes_ over QUIC — it is the replication channel, not a
general blob store.

**Does not:** implement S3, Azure Blob, or IPFS directly. For those see
`kotton-integrations-aws`, `kotton-integrations-azure`, or
`kotton-integrations-ipfs`.

**Depends on:** `kotton-platform`, `kotton-protocol`.
