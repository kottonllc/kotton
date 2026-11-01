// SPDX-License-Identifier: AGPL-3.0-or-later
//! Superblock — the pack store's root pointer, committed
//! crash-atomically.
//!
//! Packs are opaque and manifests live *inside* packs, so opening the store
//! needs an entry point: one small sealed object holding the current manifest's
//! chunk ref. This module is that object and its commit protocol.
//!
//! # The commit protocol
//!
//! This is how a superblock commit is atomic. A superblock
//! is never rewritten in place — each commit writes a **new object** under a
//! generation-numbered key:
//!
//! ```text
//! _superblock/00000000000000000001
//! _superblock/00000000000000000002        ← current = highest that opens
//! ```
//!
//! Opening the store reads the highest generation that unseals and parses; a
//! crash *during* a commit leaves either no new object or a torn one, and both
//! resolve to the previous generation — the store always opens on the last
//! committed state (a generation counter, and the previous superblock
//! retained). Old generations are retired only after the commit's pack
//! retirement completes, and the immediately-previous generation is always
//! kept and adoptable, so there is no moment with a single copy in flight.
//! "Adoptable" is the caller's to judge: with nothing passed over, the two
//! newest generations are kept ([`retirable_superblocks`]); the pack layer
//! keeps two generations it does not hold *beside* every held one, since a
//! held generation is kept but cannot be adopted (`crate::packed`'s
//! `retire_superseded`, kotton #316). Neither yet discounts a superblock
//! that does not open: a torn one counts toward the two.
//!
//! A generation whose superblock opens but whose **state does not decode** is
//! passed over the same way ([`load_adopted_superblock`]): the pack layer's
//! manifest naming a pack outside the reserved grammar (kotton #273) is
//! authentic bytes a device of the person's wrote wrongly, and the generation
//! before it is the last state anyone can read. Both cases are reported on the
//! same channel, a `warn` naming the superblock's key and why. A failure to
//! *fetch* that state is not passed over: it is not a property of the
//! generation, and adopting an older one on a transient error would build on
//! a stale base.
//!
//! A commit made past a passed-over generation is numbered above the
//! highest generation passed over (kotton #308, `crate::packed`'s
//! `Committed::base_generation`), so it sorts above it by generation, not by
//! the key tie-break. Which states a caller passes over, and what it keeps for
//! them, is the caller's: the pack layer passes over only a refused pack id,
//! and holds that generation (`crate::packed`'s module doc).
//!
//! The `_superblock/` prefix cannot collide with a blinded object key: blinded
//! components are base32, an alphabet with no `_`.
//!
//! # Sealing
//!
//! Sealed under `K_pack` with the **storage key as AAD**, so a replica cannot
//! serve generation N's blob under generation M's key — the same
//! anti-relocation discipline as `path_aad`. The sealed plaintext is
//! padded to a fixed size, so every superblock is byte-identical in length and
//! a commit discloses only *that* the store changed (a timing channel accepted
//! by name), never how much.

use crate::manifest::PackChunkRef;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use kotton_sys::store::{
    ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Storage-key prefix for superblock generations. Reserved: base32 blinded
/// components can never start with `_`.
pub const SUPERBLOCK_PREFIX: &str = "_superblock";

/// Fixed sealed-plaintext size — every superblock is byte-identical in length.
const PLAINTEXT_SIZE: usize = 1024;
/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;
/// Length prefix for the serialized body inside the padded plaintext.
const BODY_LEN_BYTES: usize = 4;

/// The store's root pointer: which manifest is current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Superblock {
    /// Format version, for forward migration. Currently 1.
    pub version: u32,
    /// Monotonic commit counter. The highest generation that opens is current.
    pub generation: u64,
    /// Where the current manifest chunk lives across the pack set.
    pub manifest: PackChunkRef,
}

/// The storage key for generation `gen` — zero-padded so lexicographic and
/// numeric order agree, plus a per-commit random suffix.
///
/// The suffix is a collision guard, not decoration: two devices that each
/// commit "generation 2" must never write the **same storage key** with
/// different content, or a naive object-level sync would have one silently
/// clobber the other and strand the loser's packed files. With distinct keys
/// the worst a pre-pack-level sync can do is leave both present, and the
/// loader picks one deterministically while the other's packs remain intact
/// and scan-recoverable. (True manifest *merge* is pack-level sync's job, not
/// this layer's.)
fn superblock_key(gen: u64, nonce: &str) -> String {
    format!("{SUPERBLOCK_PREFIX}/{gen:020}-{nonce}")
}

/// Parse a generation back out of a superblock storage key.
fn parse_generation(key: &str) -> Option<u64> {
    let name = key.strip_prefix(SUPERBLOCK_PREFIX)?.strip_prefix('/')?;
    name.split('-').next()?.parse().ok()
}

/// Seal and write `sb` under its generation key. Returns the key written.
///
/// This is the *write* half of a commit only — the caller orders it after the
/// packs it references are durably written and verified, and retires old
/// generations (and old packs) only afterwards. A crash at any point between
/// leaves the previous generation intact and current.
pub async fn commit_superblock<S>(
    store: &S,
    k_pack: &[u8; 32],
    sb: &Superblock,
) -> ObjectStorageResult<String>
where
    S: SealedObjectAccess + ?Sized,
{
    let mut nonce_id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce_id);
    let key = superblock_key(sb.generation, &hex_lower(&nonce_id));
    let body = serde_json::to_vec(sb).map_err(|e| {
        ObjectStorageError::BackendError(format!("superblock serialize: {e}"))
    })?;
    if BODY_LEN_BYTES + body.len() > PLAINTEXT_SIZE {
        return Err(ObjectStorageError::BackendError(format!(
            "superblock body {} bytes exceeds fixed plaintext size {PLAINTEXT_SIZE}",
            body.len()
        )));
    }

    let mut plaintext = Vec::with_capacity(PLAINTEXT_SIZE);
    plaintext.extend_from_slice(&(body.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(&body);
    plaintext.resize(PLAINTEXT_SIZE, 0);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(k_pack.into());
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: key.as_bytes(),
            },
        )
        .map_err(|_| ObjectStorageError::BackendError("superblock seal failed".into()))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    store.put_sealed(Path::new(&key), &blob).await?;
    Ok(key)
}

/// Open one superblock blob stored at `key`.
fn open_superblock(k_pack: &[u8; 32], key: &str, blob: &[u8]) -> ObjectStorageResult<Superblock> {
    if blob.len() < NONCE_LEN {
        return Err(ObjectStorageError::BackendError(
            "superblock blob too short".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(k_pack.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: key.as_bytes(),
            },
        )
        .map_err(|_| {
            ObjectStorageError::BackendError(
                "superblock open failed (wrong key, corrupt, or relocated)".into(),
            )
        })?;
    if plaintext.len() < BODY_LEN_BYTES {
        return Err(ObjectStorageError::BackendError(
            "superblock plaintext too short".into(),
        ));
    }
    let body_len = u32::from_be_bytes(plaintext[..BODY_LEN_BYTES].try_into().unwrap()) as usize;
    let end = BODY_LEN_BYTES + body_len;
    if end > plaintext.len() {
        return Err(ObjectStorageError::BackendError(
            "superblock body length past end of plaintext".into(),
        ));
    }
    let sb: Superblock = serde_json::from_slice(&plaintext[BODY_LEN_BYTES..end])
        .map_err(|e| ObjectStorageError::BackendError(format!("superblock parse: {e}")))?;
    if sb.version != 1 {
        return Err(ObjectStorageError::BackendError(format!(
            "unsupported superblock version {}",
            sb.version
        )));
    }
    // The AAD already binds the key (and thus the generation); this is defence
    // in depth, worth failing loudly on because a mismatch means the binding
    // stopped holding.
    if parse_generation(key) != Some(sb.generation) {
        return Err(ObjectStorageError::BackendError(format!(
            "superblock at {key} claims generation {}",
            sb.generation
        )));
    }
    Ok(sb)
}

/// What [`load_adopted_superblock`] found: the newest generation whose
/// superblock opens and whose state was adopted, and the keys of the newer
/// generations whose superblock opened but whose state was refused.
#[derive(Debug)]
pub struct Adopted<T> {
    /// The superblock adopted.
    pub superblock: Superblock,
    /// What `adopt` made of it.
    pub state: T,
    /// Each generation passed over because its state was refused, newest
    /// first. Empty in a store no device wrote wrongly.
    pub passed_over: Vec<PassedOver>,
}

/// A generation [`load_adopted_superblock`] passed over: its superblock
/// opened, and the state it names was refused.
#[derive(Debug, Clone)]
pub struct PassedOver {
    /// Its generation.
    pub generation: u64,
    /// Its superblock's storage key.
    pub key: String,
    /// Why its state was refused.
    pub why: String,
}

/// Every superblock key on `store`, with its generation, highest first; the
/// key string breaks a same-generation tie deterministically (two devices can
/// commit the same generation under a naive object sync — see
/// `superblock_key`).
pub async fn superblock_keys<S>(store: &S) -> ObjectStorageResult<Vec<(u64, String)>>
where
    S: SealedObjectAccess + ?Sized,
{
    let entries = store.list_sealed(Path::new(SUPERBLOCK_PREFIX)).await?;
    let mut keys: Vec<(u64, String)> = entries
        .iter()
        .filter(|m| !m.is_dir)
        .filter_map(|m| parse_generation(&m.key).map(|g| (g, m.key.clone())))
        .collect();
    keys.sort_unstable_by(|a, b| b.cmp(a));
    Ok(keys)
}

/// The superblock stored under `key`: `Ok(None)` when it does not open (torn,
/// corrupt or relocated), `Err` when it could not be read.
pub async fn read_superblock<S>(
    store: &S,
    k_pack: &[u8; 32],
    key: &str,
) -> ObjectStorageResult<Option<Superblock>>
where
    S: SealedObjectAccess + ?Sized,
{
    let blob = store.get_sealed(Path::new(key)).await?;
    Ok(open_superblock(k_pack, key, &blob).ok())
}

/// Load the **highest generation that opens and whose state is adopted**.
///
/// [`load_current_superblock`] with one more reason to pass a generation
/// over: `adopt` reads the state the superblock names and returns `Ok(Ok(t))`
/// to adopt it, `Ok(Err(why))` when that state does not decode (the generation
/// is passed over, as a superblock that does not open is, and reported the
/// same way), or `Err` when it could not be read at all, which ends the walk:
/// a read that failed says nothing about the generation.
pub async fn load_adopted_superblock<S, T, F, Fut>(
    store: &S,
    k_pack: &[u8; 32],
    mut adopt: F,
) -> ObjectStorageResult<Option<Adopted<T>>>
where
    S: SealedObjectAccess + ?Sized,
    F: FnMut(Superblock) -> Fut,
    Fut: std::future::Future<Output = ObjectStorageResult<Result<T, ObjectStorageError>>>,
{
    let candidates = superblock_keys(store).await?;
    if candidates.is_empty() {
        return Ok(None);
    }

    let mut last_err = None;
    let mut passed_over = Vec::new();
    for (generation, key) in candidates {
        let blob = match store.get_sealed(Path::new(&key)).await {
            Ok(b) => b,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let sb = match open_superblock(k_pack, &key, &blob) {
            Ok(sb) => sb,
            Err(e) => {
                tracing::warn!(%key, error = %e, "skipping unreadable superblock generation");
                last_err = Some(e);
                continue;
            }
        };
        match adopt(sb.clone()).await? {
            Ok(state) => {
                return Ok(Some(Adopted {
                    superblock: sb,
                    state,
                    passed_over,
                }))
            }
            Err(e) => {
                tracing::warn!(%key, error = %e, "skipping superblock generation whose state does not decode");
                passed_over.push(PassedOver {
                    generation,
                    key,
                    why: e.to_string(),
                });
                last_err = Some(e);
            }
        }
    }
    Err(ObjectStorageError::BackendError(format!(
        "superblocks exist but none open — store is damaged, scan recovery required: {}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    )))
}

/// Load the current superblock: the **highest generation that opens**.
///
/// A generation that fails to open — torn by a crash mid-write, corrupted at
/// rest, or relocated — is skipped and the next-highest tried, which is exactly
/// what makes the commit protocol crash-atomic: an interrupted commit resolves
/// to the previous committed state. `Ok(None)` means a store with no superblock
/// at all (never packed). Present-but-none-open is an error, not `None` — the
/// caller should surface it and fall back to scan recovery, not silently
/// treat a damaged store as empty.
pub async fn load_current_superblock<S>(
    store: &S,
    k_pack: &[u8; 32],
) -> ObjectStorageResult<Option<Superblock>>
where
    S: SealedObjectAccess + ?Sized,
{
    Ok(load_adopted_superblock(store, k_pack, |_| async { Ok(Ok(())) })
        .await?
        .map(|adopted| adopted.superblock))
}

/// The superblocks older than the previous generation: what retirement may
/// delete when no generation is passed over. The two highest generations
/// present — current plus one fallback — are never among them, so no state
/// exists in which a single copy is in flight.
///
/// This counts every superblock as a fallback. The pack layer does not use
/// it: a generation it holds is kept but is no fallback, so it keeps two
/// generations beside the held ones (`crate::packed`'s `retire_superseded`).
pub async fn retirable_superblocks<S>(store: &S) -> ObjectStorageResult<Vec<String>>
where
    S: SealedObjectAccess + ?Sized,
{
    Ok(superblock_keys(store)
        .await?
        .into_iter()
        .skip(2)
        .map(|(_, key)| key)
        .collect())
}

/// Retire every [`retirable_superblocks`] key, returning how many were
/// deleted.
///
/// The pack layer does not call this: it retires through
/// `crate::packed`'s own pass, which also keeps a generation whose manifest
/// was refused, since that superblock is what holds the data only it names,
/// and does not count it toward the two it keeps.
pub async fn retire_old_superblocks<S>(store: &S) -> ObjectStorageResult<usize>
where
    S: SealedObjectAccess + ?Sized,
{
    let mut deleted = 0usize;
    for key in retirable_superblocks(store).await? {
        store.delete_sealed(Path::new(&key)).await?;
        deleted += 1;
    }
    Ok(deleted)
}

/// Lowercase hex, no dependency on the `hex` crate in this tier.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryObjectStorage;

    const K_PACK: [u8; 32] = [0x7c; 32];

    fn sb(gen: u64) -> Superblock {
        Superblock {
            version: 1,
            generation: gen,
            manifest: PackChunkRef {
                pack_id: crate::packed::PackId::parse(&format!("_pack/{gen:032x}")).unwrap(),
                offset: 0,
                length: 42,
                digest: "ab".repeat(32),
            },
        }
    }

    #[tokio::test]
    async fn a_superblock_round_trips() {
        let store = MemoryObjectStorage::new();
        commit_superblock(&store, &K_PACK, &sb(1)).await.unwrap();
        let loaded = load_current_superblock(&store, &K_PACK).await.unwrap();
        assert_eq!(loaded, Some(sb(1)));
    }

    #[tokio::test]
    async fn an_unpacked_store_has_no_superblock() {
        let store = MemoryObjectStorage::new();
        assert_eq!(
            load_current_superblock(&store, &K_PACK).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn the_highest_generation_wins() {
        let store = MemoryObjectStorage::new();
        for gen in [1, 3, 2] {
            commit_superblock(&store, &K_PACK, &sb(gen)).await.unwrap();
        }
        let loaded = load_current_superblock(&store, &K_PACK).await.unwrap();
        assert_eq!(loaded.unwrap().generation, 3);
    }

    /// The crash-atomicity property: a commit torn mid-write resolves to the
    /// previous committed generation, not to an error and not to garbage.
    #[tokio::test]
    async fn a_torn_commit_falls_back_to_the_previous_generation() {
        let store = MemoryObjectStorage::new();
        commit_superblock(&store, &K_PACK, &sb(1)).await.unwrap();

        // Generation 2 crashed partway through its write.
        let torn = vec![0u8; 100];
        store
            .put_sealed(Path::new(&superblock_key(2, "deadbeefdeadbeef")), &torn)
            .await
            .unwrap();

        let loaded = load_current_superblock(&store, &K_PACK).await.unwrap();
        assert_eq!(loaded.unwrap().generation, 1);
    }

    /// Anti-relocation: a replica serving generation 1's blob under generation
    /// 2's key must be refused — the storage key is bound as AAD.
    #[tokio::test]
    async fn a_relocated_superblock_is_refused() {
        let store = MemoryObjectStorage::new();
        let key = commit_superblock(&store, &K_PACK, &sb(1)).await.unwrap();

        let blob = store.get_sealed(Path::new(&key)).await.unwrap();
        store
            .put_sealed(Path::new(&superblock_key(2, "aaaaaaaaaaaaaaaa")), &blob)
            .await
            .unwrap();

        // The forged generation 2 is skipped; the honest generation 1 serves.
        let loaded = load_current_superblock(&store, &K_PACK).await.unwrap();
        assert_eq!(loaded.unwrap().generation, 1);
    }

    /// Two devices each committing "generation 2" under a naive object sync
    /// leave *both* superblocks present under distinct keys. The loader must
    /// pick one deterministically — never error, never clobber.
    #[tokio::test]
    async fn same_generation_twins_resolve_deterministically() {
        let store = MemoryObjectStorage::new();
        let mut a = sb(2);
        a.manifest.length = 1;
        let mut b = sb(2);
        b.manifest.length = 2;
        commit_superblock(&store, &K_PACK, &a).await.unwrap();
        commit_superblock(&store, &K_PACK, &b).await.unwrap();

        let first = load_current_superblock(&store, &K_PACK).await.unwrap();
        let second = load_current_superblock(&store, &K_PACK).await.unwrap();
        assert_eq!(first, second, "twin resolution must be deterministic");
        assert_eq!(first.unwrap().generation, 2);

        // Both twins are still present — nothing was clobbered.
        let entries = store.list_sealed(Path::new(SUPERBLOCK_PREFIX)).await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    /// Damaged is not empty: superblocks that exist but none of which open must
    /// surface as an error so the caller reaches for scan recovery, never as a
    /// silently fresh store.
    #[tokio::test]
    async fn all_generations_unreadable_is_an_error_not_none() {
        let store = MemoryObjectStorage::new();
        commit_superblock(&store, &K_PACK, &sb(1)).await.unwrap();

        // The pack key rotated out from under the store (or the blob corrupted).
        let wrong = [0x11; 32];
        assert!(load_current_superblock(&store, &wrong).await.is_err());
    }

    #[tokio::test]
    async fn a_wrong_key_cannot_open_a_superblock() {
        let store = MemoryObjectStorage::new();
        let key = commit_superblock(&store, &K_PACK, &sb(1)).await.unwrap();
        let blob = store.get_sealed(Path::new(&key)).await.unwrap();
        assert!(open_superblock(&[0x11; 32], &key, &blob).is_err());
    }

    /// Every superblock is byte-identical in length — a commit discloses that
    /// the store changed, never how much its index grew.
    #[tokio::test]
    async fn superblocks_are_constant_size() {
        let store = MemoryObjectStorage::new();
        let small = sb(1);
        let mut big = sb(2);
        // A pack id has one length (`crate::packed::PackId`), so the body is
        // grown by its digest.
        big.manifest.digest = "f".repeat(200);
        let key_small = commit_superblock(&store, &K_PACK, &small).await.unwrap();
        let key_big = commit_superblock(&store, &K_PACK, &big).await.unwrap();

        let a = store.get_sealed(Path::new(&key_small)).await.unwrap();
        let b = store.get_sealed(Path::new(&key_big)).await.unwrap();
        assert_eq!(a.len(), b.len(), "size must not track content");
    }

    #[tokio::test]
    async fn retirement_keeps_current_and_previous() {
        let store = MemoryObjectStorage::new();
        for gen in 1..=5 {
            commit_superblock(&store, &K_PACK, &sb(gen)).await.unwrap();
        }
        assert_eq!(retire_old_superblocks(&store).await.unwrap(), 3);

        let entries = store.list_sealed(Path::new(SUPERBLOCK_PREFIX)).await.unwrap();
        let mut gens: Vec<u64> = entries
            .iter()
            .filter_map(|m| parse_generation(&m.key))
            .collect();
        gens.sort_unstable();
        assert_eq!(gens, vec![4, 5]);
        // And the store still opens on the current generation.
        let loaded = load_current_superblock(&store, &K_PACK).await.unwrap();
        assert_eq!(loaded.unwrap().generation, 5);
    }

    #[tokio::test]
    async fn retirement_on_a_small_store_deletes_nothing() {
        let store = MemoryObjectStorage::new();
        commit_superblock(&store, &K_PACK, &sb(1)).await.unwrap();
        assert_eq!(retire_old_superblocks(&store).await.unwrap(), 0);
    }
}
