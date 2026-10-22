// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one meter a keeper has (RFC-0084 V3): sealed bytes held per pool, and
//! the quota each pool may fill.
//!
//! What a vault can see about what it holds is a byte count and when it
//! changes. That is the whole of what it may charge for, so it is the whole of
//! what is measured here. There is no meter for files and none for records,
//! because the vault cannot tell them apart.
//!
//! `held` is a cached count: measured by walking the pool's shelf when the
//! pool is loaded, raised by each completed sealed write, and re-measured
//! before any refusal — so a write is never refused on a stale number, and the
//! walk is paid only at the boundary rather than on every write. It is not
//! stored anywhere: the shelf *is* the record of what is held.
//!
//! The quota is the landlord's number for one tenant — the space set aside for
//! them at `kvaultd invite <user> --quota <bytes>` and changed since with
//! `kvaultd capacity <user> --set <bytes>`. A pool with no number of its own is
//! held to the vault's default, `KVAULTD_QUOTA_BYTES`. The number is a fact the
//! landlord states about a tenant, not one the shelf can be asked for, so it
//! is kept where the vault keeps the rest of what it knows per tenant — the
//! machine db, beside the doors it holds for them (`pool_quotas`, [`init`]) —
//! and read back when the vault starts. It is a byte count keyed by the pool's
//! user id and nothing else: the vault learns a number, not what the bytes are
//! (Article VII).
//!
//! A quota lowered below what a pool already holds truncates nothing. The
//! bytes stay; the pool's next write is refused, as any write past the number
//! is, until the number is raised or the tenant's devices drop enough.
//!
//! The walk goes through the shelf's own listing rather than a directory,
//! because a shelf need not be a directory (RFC-0084 V5): a bucket answers the
//! same listing, and the meter is the same meter.

use kotton_sys::store::SyncableStore;
use sqlx::{Row as _, SqlitePool};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Why a write was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full {
    pub held: u64,
    pub quota: u64,
}

pub struct Meter {
    held: RwLock<HashMap<String, u64>>,
    /// The number a pool with none of its own is held to — the keeper's
    /// `KVAULTD_QUOTA_BYTES`; `0` is no default, so such a pool has no quota.
    default: AtomicU64,
    /// Each pool's own number, by user id: what the landlord set at the invite
    /// or since. Persisted in `pool_quotas` before it is written here, so what
    /// this map says is what a restart reads back.
    quotas: RwLock<HashMap<String, u64>>,
    /// One landlord's set at a time, so the row and the map cannot be left
    /// saying different numbers by two sets racing for one pool.
    setting: tokio::sync::Mutex<()>,
}

/// Make the table the per-pool quotas persist in, in the vault's machine db —
/// the same file and the same idiom as the doors it holds (`doors::init`).
pub async fn init(db: &SqlitePool) -> io::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pool_quotas (
            user_id TEXT PRIMARY KEY NOT NULL,
            quota INTEGER NOT NULL
        )",
    )
    .execute(db)
    .await
    .map_err(io::Error::other)?;
    Ok(())
}

impl Meter {
    /// A meter whose pools start with `default` — `None` meaning a pool with
    /// no number of its own has no quota.
    pub fn new(default: Option<u64>) -> Self {
        Self {
            held: RwLock::new(HashMap::new()),
            default: AtomicU64::new(default.unwrap_or(0)),
            quotas: RwLock::new(HashMap::new()),
            setting: tokio::sync::Mutex::new(()),
        }
    }

    /// The default read from the keeper's environment: `KVAULTD_QUOTA_BYTES`,
    /// absent or `0` meaning none.
    pub fn from_env() -> Self {
        let quota = std::env::var("KVAULTD_QUOTA_BYTES")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|q| *q > 0);
        Self::new(quota)
    }

    /// Read back every pool's own number from `pool_quotas`. Called once when
    /// the vault starts, after [`init`]; what was set before a restart is what
    /// holds after it.
    pub async fn load(&self, db: &SqlitePool) -> io::Result<()> {
        let rows = sqlx::query("SELECT user_id, quota FROM pool_quotas")
            .fetch_all(db)
            .await
            .map_err(io::Error::other)?;
        let mut quotas = self.quotas.write().unwrap();
        for row in rows {
            let user_id: String = row.get("user_id");
            let quota: i64 = row.get("quota");
            // Only a positive number is ever written; anything else in the
            // file is not a number this vault set, and it is not honoured.
            if let Ok(q) = u64::try_from(quota) {
                if q > 0 {
                    quotas.insert(user_id, q);
                }
            }
        }
        Ok(())
    }

    /// The number a pool with none of its own is held to.
    pub fn default_quota(&self) -> Option<u64> {
        Some(self.default.load(Ordering::Relaxed)).filter(|q| *q > 0)
    }

    /// Change the default while serving — what a restart with a new
    /// `KVAULTD_QUOTA_BYTES` would do, without the restart. Pools with a
    /// number of their own are not moved by it.
    pub fn set_default_quota(&self, quota: Option<u64>) {
        self.default.store(quota.unwrap_or(0), Ordering::Relaxed);
    }

    /// The number this pool is held to: its own, else the default.
    pub fn quota(&self, user_id: &str) -> Option<u64> {
        self.quotas
            .read()
            .unwrap()
            .get(user_id)
            .copied()
            .or_else(|| self.default_quota())
    }

    /// Set this pool's own number, while serving: persisted first, then
    /// held, so a number the landlord was told was set survives a restart.
    ///
    /// A quota is a positive number of bytes. `0` is refused rather than read
    /// as "none" (what it means for the default) or as "nothing more" — a
    /// landlord typing it could mean either, and the two are opposites.
    /// Lowering a number below what the pool holds is allowed and truncates
    /// nothing; the pool's next write is refused.
    pub async fn set_pool_quota(&self, db: &SqlitePool, user_id: &str, quota: u64) -> io::Result<()> {
        if quota == 0 {
            return Err(io::Error::other(
                "a quota is a positive number of bytes; 0 is not one",
            ));
        }
        let _one_at_a_time = self.setting.lock().await;
        let stored = i64::try_from(quota)
            .map_err(|_| io::Error::other(format!("a quota of {quota} bytes is past what this vault can record")))?;
        sqlx::query(
            "INSERT INTO pool_quotas (user_id, quota) VALUES (?, ?)
             ON CONFLICT(user_id) DO UPDATE SET quota = excluded.quota",
        )
        .bind(user_id)
        .bind(stored)
        .execute(db)
        .await
        .map_err(io::Error::other)?;
        self.quotas.write().unwrap().insert(user_id.to_string(), quota);
        Ok(())
    }

    /// Forget a pool: its cached count and its own number, so a name invited
    /// again starts on the default rather than a number set for someone else.
    /// Memory only — the `pool_quotas` row is deleted by the drop's sweep of
    /// every row keyed by the tenant (`tenancy::sweep`), in the same act.
    pub async fn forget(&self, user_id: &str) {
        let _one_at_a_time = self.setting.lock().await;
        self.held.write().unwrap().remove(user_id);
        self.quotas.write().unwrap().remove(user_id);
    }

    /// Sum of object sizes on a shelf, walked through its sealed listing. A
    /// shelf that cannot be listed holds nothing it can be charged for.
    pub async fn measure(shelf: &dyn SyncableStore) -> u64 {
        let mut total = 0u64;
        let mut pending = vec![std::path::PathBuf::new()];
        while let Some(prefix) = pending.pop() {
            let Ok(entries) = shelf.list_sealed(&prefix).await else {
                continue;
            };
            for e in entries {
                if e.is_dir {
                    pending.push(Path::new(&e.key).to_path_buf());
                } else {
                    total = total.saturating_add(e.size);
                }
            }
        }
        total
    }

    /// Record a freshly measured count for a pool.
    pub fn set(&self, user_id: &str, held: u64) {
        self.held.write().unwrap().insert(user_id.to_string(), held);
    }

    /// Bytes this vault believes it holds for a pool, `None` for a pool it has
    /// not measured.
    pub fn held(&self, user_id: &str) -> Option<u64> {
        self.held.read().unwrap().get(user_id).copied()
    }

    /// A completed sealed write of `bytes`.
    pub fn add(&self, user_id: &str, bytes: u64) {
        let mut map = self.held.write().unwrap();
        let entry = map.entry(user_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(bytes);
    }

    /// May a write of `incoming` bytes land in this pool, under this pool's
    /// own number? A write that brings the pool to exactly its quota lands;
    /// one byte past it is refused — `held + incoming <= quota`, the rule the
    /// single quota had. The shelf is walked only when the cached count says
    /// no, so the answer at the boundary is exact and the walk is not paid on
    /// every write.
    pub async fn admits(
        &self,
        user_id: &str,
        shelf: &dyn SyncableStore,
        incoming: u64,
    ) -> Result<(), Full> {
        let Some(quota) = self.quota(user_id) else {
            return Ok(());
        };
        let cached = self.held(user_id).unwrap_or(0);
        if cached.saturating_add(incoming) <= quota {
            return Ok(());
        }
        let measured = Self::measure(shelf).await;
        self.set(user_id, measured);
        if measured.saturating_add(incoming) <= quota {
            Ok(())
        } else {
            Err(Full {
                held: measured,
                quota,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kotton_store::MemoryObjectStorage;
    use kotton_sys::store::ObjectStorage as _;

    #[tokio::test]
    async fn a_pool_fills_to_its_quota_and_no_further() {
        let shelf = MemoryObjectStorage::new();
        let m = Meter::new(Some(100));
        assert_eq!(m.admits("a", &shelf, 60).await, Ok(()));
        m.add("a", 60);
        assert_eq!(m.admits("a", &shelf, 40).await, Ok(()));
        m.add("a", 40);
        // The cache says full; the walk says the shelf is empty, so the
        // refusal is re-measured and the write lands. The number is honest.
        assert_eq!(m.admits("a", &shelf, 1).await, Ok(()));
        assert_eq!(m.held("a"), Some(0), "the re-measure corrected the cache");
        // Now the bytes are really there, counted as a completed write counts
        // them: the cache says full, the walk agrees, and the refusal carries
        // the measured number.
        shelf.put(Path::new("packs/pack"), &[0u8; 100]).await.unwrap();
        m.add("a", 100);
        assert_eq!(
            m.admits("a", &shelf, 1).await,
            Err(Full {
                held: 100,
                quota: 100
            })
        );
    }

    /// Two pools, two numbers, one meter: each is held to its own at the
    /// boundary. Exactly at the quota lands; one byte past it is refused —
    /// `held + incoming <= quota`, the rule the single quota had.
    #[tokio::test]
    async fn each_pool_is_held_to_its_own_number_at_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let db = kotton_device::db::open_machine_db(dir.path().join("agent.db"))
            .await
            .unwrap();
        init(&db).await.unwrap();
        let (small, large) = (MemoryObjectStorage::new(), MemoryObjectStorage::new());
        // The default is smaller than either pool's own number, so a meter
        // that read it instead would refuse both.
        let m = Meter::new(Some(10));
        m.set_pool_quota(&db, "small", 100).await.unwrap();
        m.set_pool_quota(&db, "large", 1000).await.unwrap();
        assert_eq!(m.quota("small"), Some(100));
        assert_eq!(m.quota("large"), Some(1000));

        small.put(Path::new("packs/a"), &[0u8; 60]).await.unwrap();
        m.add("small", 60);
        assert_eq!(m.admits("small", &small, 40).await, Ok(()), "exactly at the quota lands");
        assert_eq!(
            m.admits("small", &small, 41).await,
            Err(Full { held: 60, quota: 100 }),
            "one byte past it is refused, and the refusal names the pool's own number"
        );

        // The small pool is full; the large one takes what the small one
        // could not, up to its own number and no further.
        small.put(Path::new("packs/b"), &[0u8; 40]).await.unwrap();
        m.add("small", 40);
        assert_eq!(m.admits("small", &small, 1).await, Err(Full { held: 100, quota: 100 }));
        assert_eq!(m.admits("large", &large, 1000).await, Ok(()));
        assert_eq!(m.admits("large", &large, 1001).await, Err(Full { held: 0, quota: 1000 }));
    }

    #[tokio::test]
    async fn a_pool_with_no_number_of_its_own_is_held_to_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let db = kotton_device::db::open_machine_db(dir.path().join("agent.db"))
            .await
            .unwrap();
        init(&db).await.unwrap();
        let shelf = MemoryObjectStorage::new();
        let m = Meter::new(Some(50));
        m.set_pool_quota(&db, "own", 500).await.unwrap();
        assert_eq!(m.quota("other"), Some(50));
        assert_eq!(m.admits("other", &shelf, 51).await, Err(Full { held: 0, quota: 50 }));
        // Moving the default moves every pool without a number, and none with one.
        m.set_default_quota(Some(80));
        assert_eq!(m.quota("other"), Some(80));
        assert_eq!(m.quota("own"), Some(500));
        m.set_default_quota(None);
        assert_eq!(m.quota("other"), None);
        assert_eq!(m.admits("other", &shelf, u64::MAX).await, Ok(()));
    }

    /// Lowered below what the pool holds: nothing is removed, and the next
    /// write is refused with both numbers.
    #[tokio::test]
    async fn a_quota_lowered_below_held_refuses_the_next_write_and_truncates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = kotton_device::db::open_machine_db(dir.path().join("agent.db"))
            .await
            .unwrap();
        init(&db).await.unwrap();
        let shelf = MemoryObjectStorage::new();
        let m = Meter::new(None);
        m.set_pool_quota(&db, "a", 1000).await.unwrap();
        shelf.put(Path::new("packs/a"), &[0u8; 300]).await.unwrap();
        m.add("a", 300);
        m.set_pool_quota(&db, "a", 100).await.unwrap();
        assert_eq!(m.admits("a", &shelf, 1).await, Err(Full { held: 300, quota: 100 }));
        assert_eq!(Meter::measure(&shelf).await, 300, "the shelf still holds every byte");
        assert_eq!(m.held("a"), Some(300));
    }

    #[tokio::test]
    async fn zero_is_not_a_quota() {
        let dir = tempfile::tempdir().unwrap();
        let db = kotton_device::db::open_machine_db(dir.path().join("agent.db"))
            .await
            .unwrap();
        init(&db).await.unwrap();
        let m = Meter::new(Some(50));
        m.set_pool_quota(&db, "a", 0).await.expect_err("0 is refused");
        assert_eq!(m.quota("a"), Some(50), "and nothing was set");
    }

    /// The number survives the vault: set, close the machine db, open it again
    /// under a fresh meter whose default differs, and the pool's own number is
    /// what it reads back.
    #[tokio::test]
    async fn a_pools_quota_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system").join("agent.db");
        {
            let db = kotton_device::db::open_machine_db(&path).await.unwrap();
            init(&db).await.unwrap();
            let m = Meter::new(Some(10));
            m.set_pool_quota(&db, "alice", 4096).await.unwrap();
            m.set_pool_quota(&db, "bob", 1 << 20).await.unwrap();
            m.set_pool_quota(&db, "bob", 1 << 21).await.unwrap();
            db.close().await;
        }
        let db = kotton_device::db::open_machine_db(&path).await.unwrap();
        init(&db).await.unwrap();
        let m = Meter::new(Some(99));
        assert_eq!(m.quota("alice"), Some(99), "nothing is known before the load");
        m.load(&db).await.unwrap();
        assert_eq!(m.quota("alice"), Some(4096));
        assert_eq!(m.quota("bob"), Some(1 << 21), "the last number set is the one kept");
        assert_eq!(m.quota("carol"), Some(99), "a pool with no number reads this start's default");
    }

    #[tokio::test]
    async fn no_quota_admits_everything() {
        let shelf = MemoryObjectStorage::new();
        let m = Meter::new(None);
        assert_eq!(m.admits("a", &shelf, u64::MAX).await, Ok(()));
    }
}
