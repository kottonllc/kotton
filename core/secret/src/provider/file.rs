// SPDX-License-Identifier: AGPL-3.0-or-later
//! A secrets store that is a file — for a machine with no keychain.
//!
//! A rented vault, a gateway on a host, a node in a container: none of them has
//! a keychain, a Secret Service, or a kernel keyring a sandbox lets them reach.
//! What they keep here is the node's own operational key and the mount-domain
//! pins — the node's identity, not a person's data — and the honest place for
//! that on a server is a `0600` file beside the rest of the install, the same
//! way a host key is kept. It is chosen explicitly (`KOTTON_SECRETS=file`),
//! never by falling back: a device that has a keychain and lands here by
//! accident has lost a protection, and that must be a decision someone made.

use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A store over one file, which several processes may hold at once.
///
/// **The file is the store; this holds only its path.** Under
/// `KOTTON_SECRETS=file` one `system/secrets.json` is opened by `kuserd` for
/// its lifetime, by `kctl` to mint the operator key, by `device reset`, and by
/// `kdeviced` per child request
/// (`TASK-several-processes-each-hold-a-whole-map-of-one-secrets-file-and-the-last-write-drops-the-others-keys`).
/// A store that kept the map it read at open and renamed the whole of it over
/// the file on every write dropped whatever any other process had written in
/// between. So nothing is kept: a read reads the file, and a write is one
/// change applied to the file as it is now — under an exclusive lock on
/// [`Self::lock_path`], re-read, changed, written beside and renamed over.
///
/// Reads take no lock. Every write lands by a rename, so a read sees one whole
/// file, before or after any write; and a reader — `kdeviced`, which only
/// reads — never needs to create or open the lock file, so the lock asks
/// nothing of it that reading the file did not.
///
/// The lock is advisory (`flock(2)` through `std::fs::File::lock`, as
/// `kvaultd`'s `StateLock` takes it). It serialises the writers this crate
/// opens, which are all of them; it is not a guard against a process that
/// writes the file some other way, and nothing here pretends it is.
pub struct FileSecrets {
    path: PathBuf,
}

impl FileSecrets {
    /// The store at `base_dir/system/secrets.json`: see [`Self::at`].
    pub fn for_base_dir(base_dir: &Path) -> SecretsResult<Self> {
        Self::at(base_dir.join("system").join("secrets.json"))
    }

    /// The store at `path`. Only a file that does not exist opens empty.
    ///
    /// **Absent and unreadable are two states, and this is where they are told
    /// apart** (`TASK-an-unreadable-secrets-store-is-read-as-empty-and-the-nodes-key-is-replaced`).
    /// A file that exists and cannot be read, or does not parse, is an error
    /// naming it — never an empty store. Read as empty, its node finds no key,
    /// mints one, and the first write renames a new store over the only copy of
    /// the old one: the node's identity, and every pin beside it, replaced by a
    /// parse error. Refusing here means no `FileSecrets` exists over a file it
    /// could not read when it was opened; and since every read and every write
    /// reads the file again by the same rule ([`read_store`]), a file that
    /// becomes unreadable later is refused there too, and never written over.
    pub fn at(path: PathBuf) -> SecretsResult<Self> {
        read_store(&path)?;
        Ok(Self { path })
    }

    /// The lock every write takes: `secrets.json.lock`, beside the file, `0600`
    /// and empty — only its lock means anything. Beside the file rather than on
    /// it, because the file is replaced by a rename on every write, and a lock
    /// on the replaced inode would hold nothing.
    ///
    /// One function, so that where the lock sits moves with where the file is
    /// written: if writes come to go through a symlink to its target
    /// (`TASK-a-symlinked-secrets-file-is-severed-by-the-first-write-and-a-dangling-one-reads-as-absent`),
    /// the lock belongs beside the target too, or two links to one file would
    /// take two locks.
    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("json.lock")
    }

    /// Apply `change` to the file as it is now, under the exclusive lock, and
    /// write the result: the whole of a write, for [`SecretsStore::set_secret`]
    /// and [`SecretsStore::delete_secret`] alike.
    fn update(&self, change: impl FnOnce(&mut BTreeMap<String, String>)) -> SecretsResult<()> {
        let io = |e: std::io::Error| SecretsError::Storage(format!("{}: {e}", self.path.display()));
        // `system/`, and the base dir above it, owner-only when this first
        // write is what makes them (`kotton_common::fs::create_dir_all_owner_only`).
        // Only a write with something to keep gets here: a delete of a label
        // the file does not hold returns before it ([`SecretsStore::delete_secret`]).
        if let Some(parent) = self.path.parent() {
            kotton_common::fs::create_dir_all_owner_only(parent).map_err(io)?;
        }
        let lock = self.open_lock()?;
        // Waited for, not refused: another writer holds it for one read, one
        // small write and one rename. Released when `lock` drops, after the
        // rename, so the next writer's read is of this one's file.
        lock.lock().map_err(io)?;
        let mut entries = read_store(&self.path)?;
        change(&mut entries);
        self.persist(&entries)
    }

    /// Open the lock file, making it `0600` if it is not there.
    ///
    /// A writer needs write access to the lock file's inode, which is what it
    /// already needs of `secrets.json`'s directory to rename into it: a file
    /// another user left — `sudo kctl device reset` run once, say — stops
    /// writes until it is given back, and the refusal says which of the two it
    /// is: a lock file that is there and cannot be opened, or a directory the
    /// lock file cannot be made in.
    ///
    /// Other users are kept out of the lock file as they are kept out of
    /// `secrets.json` and its `.tmp`: by its `0600` creation mode. Its mode is
    /// not checked after the open — a check would refuse every write on file
    /// systems that keep no unix modes, where every file reads as `0777` or
    /// `0755`, and on those `secrets.json` is as exposed as the lock.
    fn open_lock(&self) -> SecretsResult<std::fs::File> {
        let lock_path = self.lock_path();
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        opts.open(&lock_path).map_err(|e| {
            let fix = if e.kind() != std::io::ErrorKind::PermissionDenied {
                String::new()
            } else if std::fs::symlink_metadata(&lock_path).is_ok() {
                format!(
                    ": the lock file is there and this process may not open it to write, which every writer of {} \
                     does — `chown` it to the user that runs Kotton, or remove it while no Kotton process is running",
                    self.path.display()
                )
            } else {
                format!(
                    ": the lock file is not there and this process may not create it, because it may not write the \
                     directory {} — which a writer of {} needs anyway, to rename into it; give the directory to the \
                     user that runs Kotton",
                    lock_path.parent().map(|d| d.display().to_string()).unwrap_or_default(),
                    self.path.display()
                )
            };
            SecretsError::Storage(format!(
                "the lock file {} could not be opened ({e}), so nothing was written{fix}",
                lock_path.display()
            ))
        })
    }

    fn persist(&self, entries: &BTreeMap<String, String>) -> SecretsResult<()> {
        let io = |e: std::io::Error| SecretsError::Storage(format!("{}: {e}", self.path.display()));
        let bytes = serde_json::to_vec_pretty(entries)
            // The kind only: an encoder's message may quote what it was given.
            .map_err(|e| SecretsError::Storage(format!("encode secrets: {:?} error", e.classify())))?;
        // Write beside, then rename: a crash mid-write leaves the old file whole.
        // One name is enough, because only the holder of the lock writes it.
        let tmp = self.path.with_extension("json.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp).map_err(io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(io)?;
            }
            f.write_all(&bytes).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(io)?;
        // The rename is a change to the directory, and until the directory is
        // synced a power cut can bring back the old entry — the file from
        // before `kctl` minted the operator key, say. So the write is not
        // done until the directory says so too.
        //
        // Some file systems (FUSE ones, 9p) answer `fsync` on a directory with
        // EINVAL or ENOTSUP: they cannot do it, and the rename has landed. Those
        // two are taken as "nothing more can be done here", not as a failed
        // write, because a write reported failed after it landed is one a
        // caller may retry or mint again over. Any other error is the write's.
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            match std::fs::File::open(parent).and_then(|d| d.sync_all()) {
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP)) => {}
                other => other.map_err(io)?,
            }
        }
        Ok(())
    }
}

/// The store's map as the file at `path` holds it now. Only a file that does
/// not exist reads as empty: see [`FileSecrets::at`].
fn read_store(path: &Path) -> SecretsResult<BTreeMap<String, String>> {
    match std::fs::read(path) {
        // Never serde's own message: it quotes the value it could not take,
        // and a file holding a key where the map should be would print the
        // key. Where it broke and what kind of break, nothing of what is there.
        Ok(bytes) => serde_json::from_slice::<BTreeMap<String, String>>(&bytes).map_err(|e| {
            SecretsError::Storage(format!(
                "{} does not parse as a secrets store ({:?} error at line {}, column {}), so nothing was taken \
                 from it and nothing was written over it",
                path.display(),
                e.classify(),
                e.line(),
                e.column()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(SecretsError::Storage(format!(
            "{} could not be read ({e}), so nothing was taken from it and nothing was written over it",
            path.display()
        ))),
    }
}

impl SecretsStore for FileSecrets {
    fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
        Ok(read_store(&self.path)?.remove(key))
    }

    fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        self.update(|entries| {
            entries.insert(key.to_string(), value.to_string());
        })
    }

    /// Remove `key`, writing only when the file holds it.
    ///
    /// **A delete brings nothing into being.** A write makes `system/`, the
    /// base directory above it, the file and its lock when they are not
    /// there ([`Self::update`]) — right for a set, which has something to
    /// keep, and wrong for a delete, which has nothing to keep. `device reset`
    /// removes the base directory and then deletes every label it names, and a
    /// delete that wrote would put back the directory it had just removed,
    /// holding an empty store and a lock. So a label the file does not hold —
    /// and every label, when there is no file — is deleted by writing nothing.
    ///
    /// The read that finds the label absent takes no lock, as no read does: a
    /// writer adding the label after it is ordered after this delete, which is
    /// where taking the lock first would have put it too.
    fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        if !read_store(&self.path)?.contains_key(key) {
            return Ok(());
        }
        self.update(|entries| {
            entries.remove(key);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_survives_a_restart_and_the_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = FileSecrets::for_base_dir(dir.path()).unwrap();
            s.set_secret("kotton:device_operational_key", "hex").unwrap();
            s.set_secret("gone", "x").unwrap();
            s.delete_secret("gone").unwrap();
        }
        let s = FileSecrets::for_base_dir(dir.path()).unwrap();
        assert_eq!(s.get_secret("kotton:device_operational_key").unwrap().as_deref(), Some("hex"));
        assert_eq!(s.get_secret("gone").unwrap(), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for file in ["system/secrets.json", "system/secrets.json.lock"] {
                let mode = std::fs::metadata(dir.path().join(file)).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{file}");
            }
        }
    }

    /// A store whose file holds `bytes`, at `dir/system/secrets.json`.
    fn a_file_holding(dir: &Path, bytes: &[u8]) -> PathBuf {
        let path = dir.join("system").join("secrets.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Open `path`, which must be refused naming it, then confirm its bytes are
    /// exactly `original`.
    fn refused_and_untouched(path: &Path, original: &[u8]) {
        let e = match FileSecrets::at(path.to_path_buf()) {
            Ok(_) => panic!("{} opened as a store", path.display()),
            Err(e) => e.to_string(),
        };
        assert!(e.contains(&path.display().to_string()), "the refusal names the file: {e}");
        assert_eq!(std::fs::read(path).unwrap(), original, "the file was written over");
    }

    /// Red on 726d1e2d1, where the open read garbage as empty and the first
    /// write renamed a new store over the file.
    #[test]
    fn a_secrets_file_that_does_not_parse_is_an_error_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let original = b"not json at all".to_vec();
        let path = a_file_holding(dir.path(), &original);
        refused_and_untouched(&path, &original);
    }

    /// A store cut off part-way — the key's first half and no closing brace.
    #[test]
    fn a_truncated_secrets_file_is_an_error_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let original = br#"{"kotton:device_operational_key": "9f86d081884c7d65"#.to_vec();
        let path = a_file_holding(dir.path(), &original);
        refused_and_untouched(&path, &original);
    }

    /// A path that exists and cannot be read. A directory stands in for a file
    /// the process may not read: the suite runs as root in its container, where
    /// a `0o000` file still reads, and the directory reaches the same arm — any
    /// read error but `NotFound`.
    #[test]
    fn a_secrets_file_that_cannot_be_read_is_an_error_and_is_left_where_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system").join("secrets.json");
        std::fs::create_dir_all(path.join("held")).unwrap();
        let e = match FileSecrets::at(path.clone()) {
            Ok(_) => panic!("an unreadable path opened as a store"),
            Err(e) => e.to_string(),
        };
        assert!(e.contains(&path.display().to_string()) && e.contains("could not be read"), "{e}");
        assert!(path.join("held").is_dir(), "what was at the path was replaced");
    }

    /// A delete from a store whose directory is not there writes nothing and
    /// makes nothing: no `system/`, no file, no lock, and no base directory.
    /// Red on e99e03317, where the delete was a write and made all four.
    #[test]
    fn a_delete_from_a_store_that_is_not_there_makes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        let s = FileSecrets::for_base_dir(&base).unwrap();
        s.delete_secret("kotton:device_operational_key").unwrap();
        assert!(!base.exists(), "the delete made {}", base.display());
    }

    /// A delete of a label the file does not hold writes nothing: the file is
    /// the same inode afterwards, and no lock appears beside it. Bytes alone
    /// cannot say so — a write of the same map renames a new file holding the
    /// same bytes over the old one — but every write lands by a rename
    /// ([`FileSecrets::persist`]), so a write is a new inode. A delete of a
    /// label the file holds still removes it, and that one is a write.
    #[cfg(unix)]
    #[test]
    fn a_delete_writes_only_what_it_removes() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        // Made by hand, not by a set, so no lock is there before the delete.
        let path = a_file_holding(dir.path(), br#"{"kotton:device_operational_key": "hex"}"#);
        let lock = path.with_extension("json.lock");
        let inode = |p: &Path| std::fs::metadata(p).unwrap().ino();
        let s = FileSecrets::at(path.clone()).unwrap();
        let before = inode(&path);

        s.delete_secret("kotton:device_operator_key").unwrap();
        assert_eq!(inode(&path), before, "a delete of a label the file does not hold wrote the file");
        assert!(!lock.exists(), "a delete of a label the file does not hold took the lock");

        s.delete_secret("kotton:device_operational_key").unwrap();
        assert_eq!(s.get_secret("kotton:device_operational_key").unwrap(), None);
        assert_ne!(inode(&path), before, "a delete of a label the file holds did not write");
    }

    /// The one state that opens empty: no file. Its first write creates it.
    #[test]
    fn an_absent_secrets_file_opens_empty_and_its_first_write_creates_it() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileSecrets::for_base_dir(dir.path()).unwrap();
        assert_eq!(s.get_secret("kotton:device_operational_key").unwrap(), None);
        s.set_secret("kotton:device_operational_key", "hex").unwrap();
        assert!(dir.path().join("system/secrets.json").is_file());
    }

    /// Two stores over one file, the second opened before the first writes —
    /// kuserd's store held for its lifetime, and `kctl` minting the operator
    /// key beside it. Red on d75005d8d, where each store held the map it read at
    /// open and renamed the whole of it over the file on every write.
    #[test]
    fn a_key_one_store_writes_survives_a_write_by_another_store_over_the_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let earlier = FileSecrets::for_base_dir(dir.path()).unwrap();
        let later = FileSecrets::for_base_dir(dir.path()).unwrap();
        later.set_secret("kotton:operator_signing_key", "minted").unwrap();
        earlier.set_secret("kotton:device_operational_key", "hex").unwrap();
        let fresh = FileSecrets::for_base_dir(dir.path()).unwrap();
        for s in [&fresh, &earlier, &later] {
            assert_eq!(s.get_secret("kotton:operator_signing_key").unwrap().as_deref(), Some("minted"));
            assert_eq!(s.get_secret("kotton:device_operational_key").unwrap().as_deref(), Some("hex"));
        }
        // A delete by the stale store removes its one label and nothing else.
        earlier.delete_secret("kotton:device_operational_key").unwrap();
        assert_eq!(fresh.get_secret("kotton:operator_signing_key").unwrap().as_deref(), Some("minted"));
        assert_eq!(fresh.get_secret("kotton:device_operational_key").unwrap(), None);
    }

    /// The process [`writes_from_two_processes_over_one_file_all_survive`]
    /// spawns: this test binary again, running only this test, with the file
    /// in the environment. Run by the suite with no such variable, it does
    /// nothing.
    const CHILD_FILE: &str = "KOTTON_FILE_SECRETS_TEST_CHILD";
    const WRITES_EACH: usize = 200;

    /// A barrier between the two processes: say `me` is ready by making a
    /// file beside the store, then wait for `other`'s.
    fn ready_then_wait(store: &Path, me: &str, other: &str) {
        let dir = store.parent().unwrap().parent().unwrap();
        std::fs::write(dir.join(format!("ready-{me}")), b"").unwrap();
        let started = std::time::Instant::now();
        while !dir.join(format!("ready-{other}")).exists() {
            assert!(started.elapsed() < std::time::Duration::from_secs(60), "{other} was never ready");
            std::thread::yield_now();
        }
    }

    #[test]
    fn the_other_process_writing_over_one_file() {
        let Some(path) = std::env::var_os(CHILD_FILE) else { return };
        let path = PathBuf::from(path);
        let s = FileSecrets::at(path.clone()).unwrap();
        ready_then_wait(&path, "child", "parent");
        for i in 0..WRITES_EACH {
            s.set_secret(&format!("child-{i}"), "c").unwrap();
        }
    }

    /// Two processes, each with its own store over one file, writing at once:
    /// every label either wrote is there at the end. The named test above is
    /// what the re-read answers for; this is what the lock answers for — two
    /// writers that each re-read and rename, with nothing to order them, still
    /// lose each other's labels between one's read and the other's rename.
    #[test]
    fn writes_from_two_processes_over_one_file_all_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system").join("secrets.json");
        let parent = FileSecrets::at(path.clone()).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "provider::file::tests::the_other_process_writing_over_one_file", "--test-threads=1"])
            .env(CHILD_FILE, &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Neither writes until both are ready, so the two loops overlap
        // whichever process starts first.
        ready_then_wait(&path, "parent", "child");
        for i in 0..WRITES_EACH {
            parent.set_secret(&format!("parent-{i}"), "p").unwrap();
        }
        assert!(child.wait().unwrap().success(), "the child process failed");
        let all = read_store(&path).unwrap();
        let lost: Vec<_> = (0..WRITES_EACH)
            .flat_map(|i| [format!("child-{i}"), format!("parent-{i}")])
            .filter(|k| !all.contains_key(k))
            .collect();
        assert!(lost.is_empty(), "{} of {} labels lost: {:?}", lost.len(), 2 * WRITES_EACH, &lost[..lost.len().min(8)]);
    }

    /// A file that is a bare JSON string — a key written where the store's map
    /// should be — is refused, and the refusal does not carry the key: serde's
    /// own message quotes the value it could not take.
    #[test]
    fn a_secrets_file_holding_a_bare_string_is_refused_without_echoing_it() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let original = format!("\"{secret}\"").into_bytes();
        let path = a_file_holding(dir.path(), &original);
        let e = match FileSecrets::at(path.clone()) {
            Ok(_) => panic!("a bare string opened as a store"),
            Err(e) => e,
        };
        assert!(!e.to_string().contains(secret), "the refusal echoes the file: {e}");
        assert!(!format!("{e:?}").contains(secret), "the refusal echoes the file: {e:?}");
        assert!(e.to_string().contains(&path.display().to_string()), "the refusal names the file: {e}");
        assert_eq!(std::fs::read(&path).unwrap(), original, "the file was written over");
    }
}
