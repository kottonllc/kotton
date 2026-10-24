// SPDX-License-Identifier: AGPL-3.0-or-later
//! A vault is created for its operator's key, and does not start without one
//! (RFC-0084, the amendment of 2026-10-01: V18, V19, V20).
//!
//! **Creation is the one way into an empty operator set.** `kvaultd create
//! --state-dir <dir> --operator <key>` runs once, offline, before any process
//! serves: it makes the vault's state and its own key, records the key it was
//! given as the first operator — the row `OperatorAdmit` writes — and prints
//! the vault's line as its last output. Over state that has an operator it
//! refuses and changes nothing; over state that has none — a vault from before
//! creation existed — it adopts it, keeping its key and its tenants, and it
//! never mints a key over existing state. The vault gets no offline `operator
//! enrol`: an operator added later is added at the running vault's door.
//!
//! **What existing state is, is read from the state.** The vault's machine db
//! (`system/agent.db`) is the file a vault opens; whether a key file exists is
//! not the test, because where the vault's key lives depends on its secrets
//! provider, and a test that looked for a file would read a vault under another
//! provider as absent and mint a new key over it.
//!
//! **A vault with no operator does not start.** [`refuse_unless_operated`] runs
//! before the vault binds any port or door, and ends the start with one
//! sentence naming the state directory and `create --operator <key>`.
//!
//! **`create` and a serving vault exclude each other** by [`StateLock`]: an
//! exclusive advisory lock on [`LOCK_FILE`] in the state directory, held by
//! `create` for its whole run and by a serving vault for its whole life, and
//! refused — never waited for — by whichever comes second. The machine db is a
//! pooled SQLite whose writer waits for SQLite's own lock, which serialises
//! writes and does not keep a second process out; this does.

use kotton_secret::SecretsProvider;
use kotton_sys::secret::SecretsStore;
use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;
use std::io;
use std::path::{Path, PathBuf};

/// The file in the state directory whose exclusive lock says an instance —
/// serving, or being created — holds the state. Empty; only its lock means
/// anything.
pub const LOCK_FILE: &str = "instance.lock";

/// The vault's machine db under its state directory: what says a vault is
/// there.
pub fn machine_db(state_dir: &Path) -> PathBuf {
    state_dir.join("system").join("agent.db")
}

/// The state directory's exclusive lock, held for as long as this value is.
#[derive(Debug)]
pub struct StateLock {
    _file: std::fs::File,
}

impl StateLock {
    /// Take the lock on `state_dir`, or refuse at once when anything holds it.
    /// The directory must exist; the lock file is made in it, `0600`.
    pub fn take(state_dir: &Path) -> io::Result<Self> {
        let path = state_dir.join(LOCK_FILE);
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "{} is held by another kvaultd — a vault serving from it, or `kvaultd create` making it; \
                     nothing was changed",
                    state_dir.display()
                ),
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }
}

/// The one sentence a vault with no operator ends its start with.
pub fn no_operator(state_dir: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "this vault has no operator, so it does not start: create it for its operator's key — \
             `kvaultd create --state-dir {} --operator <key>`, which keeps any state already there",
            state_dir.display()
        ),
    )
}

/// Whether the vault at `state_dir` may start: its machine db is there and
/// names at least one operator. Reads, and makes nothing: a vault started
/// before it was created leaves no state behind for `create` to mistake for an
/// older vault's.
pub async fn refuse_unless_operated(state_dir: &Path) -> io::Result<()> {
    let db_path = machine_db(state_dir);
    if !db_path.exists() {
        return Err(no_operator(state_dir));
    }
    let db = kotton_device::db::open_machine_db(&db_path)
        .await
        .map_err(|e| io::Error::other(format!("failed to open machine db: {e}")))?;
    let operated = !kotton_peer::daemon::db::operator_keys(&db).await?.is_empty();
    db.close().await;
    if operated {
        Ok(())
    } else {
        Err(no_operator(state_dir))
    }
}

/// Whether the secrets provider a vault is started with holds its key: a start
/// never makes a key over existing state, as `create` never does. A vault
/// that was created always has one, so none here — or one that does not read
/// as a key — is a start under settings other than the ones it was created
/// under (another `KOTTON_SECRETS`), and minting would make it a vault nobody
/// knows, printing a line with a key no desktop expects. Refused, naming that.
///
/// A provider that could not be read, or holds a value that is not a key, is
/// refused with that error rather than as one that holds no key: the remedy
/// differs (unlock the keychain, not change the settings), and the key may well
/// be there.
pub fn refuse_unless_keyed(state_dir: &Path, secrets: &(dyn SecretsStore + Send + Sync)) -> io::Result<()> {
    match kotton_device::runtime::stored_device_signing_key(secrets) {
        Ok(Some(_)) => Ok(()),
        Err(e) => Err(io::Error::other(format!(
            "the vault at {} could not read its key from the secrets provider it was started with, so it \
             does not start: {e}",
            state_dir.display()
        ))),
        Ok(None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "the vault at {} has no key in the secrets provider it was started with, so it does not start: \
                 a start never makes a new key over a vault's state — start it with the settings it was created \
                 under (KOTTON_SECRETS)",
                state_dir.display()
            ),
        )),
    }
}

/// Where a vault says it is reached: the host's one address and the peer port,
/// or nothing when either is missing. One rule, read by creation from the
/// settings and by every start from what the runtime was told, so the line
/// creation prints names the address the start announces.
pub fn hint(public_ip: Option<std::net::IpAddr>, peer_port: Option<u16>) -> String {
    match (public_ip, peer_port) {
        (Some(ip), Some(port)) => std::net::SocketAddr::new(ip, port).to_string(),
        _ => String::new(),
    }
}

/// The vault's line: its kind, where it is reached, its key.
pub fn line(hint: String, key: [u8; 32]) -> InstanceLine {
    InstanceLine {
        kind: OperatedService::Vault,
        hint,
        key,
    }
}

/// The file under the state's `system/` that records which secrets provider
/// `kvaultd create` kept the vault's key in — `file`, `keychain` — so a start
/// compares its own provider against the one the key is in, rather than each
/// re-deriving it from the path's spelling at its own moment
/// ([`refuse_unless_started_as_created`]).
pub const PROVIDER_FILE: &str = "secrets-provider";

fn provider_file(state_dir: &Path) -> PathBuf {
    state_dir.join("system").join(PROVIDER_FILE)
}

/// The provider `create` recorded for the vault at `state_dir`, if it recorded
/// one — a vault created in process, by a caller that holds its store, has none.
pub fn recorded_provider(state_dir: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(provider_file(state_dir)) {
        Ok(text) => Ok(Some(text.trim().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write `provider` as the record of which provider holds the vault's key,
/// `0600`. Written by `create`, and by the first start of a vault created
/// before the record existed, once that start has found the key there.
///
/// **The record is never authority.** It grants nothing and chooses nothing:
/// the provider is still chosen by the settings, and the key is still read from
/// it. A record that disagrees with the start only refuses the start
/// ([`refuse_unless_started_as_created`]); one that is missing only means the
/// next start that finds the key writes it.
pub fn record_provider(state_dir: &Path, provider: SecretsProvider) -> io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    use std::io::Write as _;
    opts.open(provider_file(state_dir))?.write_all(format!("{}\n", provider.name()).as_bytes())
}

/// A start under another secrets provider than the vault was created under is
/// refused, naming both: the key is in the one `create` recorded, and the start
/// would look for it in the other.
pub fn refuse_unless_started_as_created(state_dir: &Path, provider: SecretsProvider) -> io::Result<()> {
    match recorded_provider(state_dir)? {
        Some(created) if created != provider.name() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the vault at {} was created under the `{created}` secrets provider and is started under \
                 `{}`, so it does not start: its key is where `{created}` keeps it — start it with the settings \
                 it was created under (KOTTON_SECRETS)",
                state_dir.display(),
                provider.name()
            ),
        )),
        _ => Ok(()),
    }
}

/// [`create`], as `kvaultd create` runs it: the key kept by `provider`, and
/// `provider` recorded in the state for every start to compare against.
pub async fn create_recorded(
    state_dir: &Path,
    provider: SecretsProvider,
    operator: &str,
    hint: String,
) -> io::Result<InstanceLine> {
    // The check before the provider is opened: under `KOTTON_SECRETS=file`
    // the open reads `system/secrets.json`, and its error would otherwise be
    // what a refused directory prints.
    own_state_dir(state_dir)?;
    let secrets = provider.open(state_dir).map_err(io::Error::other)?;
    create_with(state_dir, secrets.as_ref(), Some(provider), operator, hint).await
}

/// Create the vault at `state_dir` for `operator` (64 hex), or adopt the state
/// there when it names no operator, and return the vault's line (RFC-0084
/// V18). `secrets` is the provider the vault's own key is kept in — the one
/// the serving vault reads; held by an in-process caller, which records none.
pub async fn create(
    state_dir: &Path,
    secrets: &(dyn SecretsStore + Send + Sync),
    operator: &str,
    hint: String,
) -> io::Result<InstanceLine> {
    create_with(state_dir, secrets, None, operator, hint).await
}

/// What the state directory is checked for: the sentence a refusal ends with
/// says what did not happen and what to run instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Create,
    Start,
}

impl Act {
    fn refused(self) -> &'static str {
        match self {
            Act::Create => "so nothing was created and nothing changed",
            Act::Start => "so the vault does not start and nothing changed",
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn verb(self) -> &'static str {
        match self {
            Act::Create => "run create",
            Act::Start => "start the vault",
        }
    }

    fn flag(self) -> &'static str {
        match self {
            Act::Create => "--state-dir",
            Act::Start => "KOTTON_BASE_DIR",
        }
    }
}

/// **The state directory's one maker and its one check**, for `create`
/// (`TASK-kvaultd-create-chmods-any-existing-directory-it-is-pointed-at`).
///
/// An absent `state_dir` is made `0700` by the mode `mkdir` is given, with any
/// missing parent made the same way (`kotton_common::fs::create_dir_all_owner_only`,
/// the one `DirBuilder` site for a node's base dir, its `system/` and this).
/// A present one is used only as [`check_state_dir`] says: a directory, not a
/// symlink, owned by the uid this runs as, granting group and other nothing.
/// Anything else is refused in one sentence naming the path and the fix, and
/// nothing is written and no mode is changed — `create` tightens no directory
/// it did not make. Nothing under the state directory is checked.
///
/// It runs before anything under the state directory is opened: `kvaultd
/// create` calls it on the path as given, before it canonicalizes;
/// [`create_recorded`] before its secrets provider is opened; and `create`
/// before its [`StateLock`]. So the order is the check, then
/// `SecretsProvider::open`, then the lock, and an in-process caller is held to
/// it as the binary is.
pub fn own_state_dir(state_dir: &Path) -> io::Result<()> {
    if kotton_common::fs::create_dir_all_owner_only(state_dir)? {
        return Ok(());
    }
    check(state_dir, Act::Create)
}

/// The check half of [`own_state_dir`], for a start: it never makes the state
/// directory, and an absent one is refused as a vault never created, naming
/// `kvaultd create` (`TASK-the-base-dir-and-system-are-said-to-be-0700-and-nothing-makes-them-so`).
/// Run by `Vault::new` before its secrets provider is opened and by
/// `Vault::open` before its lock.
pub fn check_state_dir(state_dir: &Path) -> io::Result<()> {
    check(state_dir, Act::Start)
}

fn check(state_dir: &Path, act: Act) -> io::Result<()> {
    let path = state_dir.display();
    // Its own entry, a symlink there not followed — however the leaf is
    // spelled: `link/` is read as `link` (`kotton_common::fs::own_entry`).
    let own = kotton_common::fs::own_entry(state_dir);
    let entry = match std::fs::symlink_metadata(&own) {
        Ok(entry) => entry,
        Err(e) if e.kind() == io::ErrorKind::NotFound && act == Act::Start => return Err(no_operator(state_dir)),
        Err(e) => return Err(io::Error::new(e.kind(), format!("{path}: {e}"))),
    };
    if entry.file_type().is_symlink() {
        let to = std::fs::read_link(&own).map(|t| format!(" (to {})", t.display())).unwrap_or_default();
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{path} is a symlink{to}, {}: give the directory it points to as {}",
                act.refused(),
                act.flag()
            ),
        ));
    }
    if !entry.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{path} is not a directory, {}: give a directory as {}", act.refused(), act.flag()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let me = rustix::process::geteuid().as_raw();
        if entry.uid() != me {
            let owner = user_name(entry.uid());
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{path} is owned by {owner}, not by {}, the user this runs as, {}: {} as {owner}",
                    user_name(me),
                    act.refused(),
                    act.verb()
                ),
            ));
        }
        let mode = entry.mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{path} is open to other users (mode {mode:04o}), {}: `chmod 700 {path}`, then {} again",
                    act.refused(),
                    act.verb()
                ),
            ));
        }
    }
    Ok(())
}

/// `uid`'s name in the local user database, or the number when it has none —
/// a sentence names the owner a person would type.
#[cfg(unix)]
fn user_name(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|users| {
            users.lines().find_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                (fields.nth(1)? == uid.to_string()).then(|| name.to_string())
            })
        })
        .unwrap_or_else(|| uid.to_string())
}

/// `create`'s refusal when the provider could not answer whether it holds the
/// vault's key: nothing was created, and nothing was made over a key it may hold.
fn unreadable_key(state_dir: &Path, e: anyhow::Error) -> io::Error {
    io::Error::other(format!(
        "{}: the secrets provider could not be read, so nothing was created and no key was made over one \
         it may hold: {e}",
        state_dir.display()
    ))
}

async fn create_with(
    state_dir: &Path,
    secrets: &(dyn SecretsStore + Send + Sync),
    provider: Option<SecretsProvider>,
    operator: &str,
    hint: String,
) -> io::Result<InstanceLine> {
    let operator = crate::operator::parse_key(operator)?;
    // The directory the lock lives in: made `0700` when it is not there — the
    // one write before the lock — and otherwise used only if it is this user's
    // and closed, refused unchanged if not (`own_state_dir`).
    own_state_dir(state_dir)?;
    // 1. The state's exclusive lock, held to the end of this function, before
    // anything in the state is read or changed.
    let _held = StateLock::take(state_dir)?;
    // 2. Whether a vault is here, read from the state.
    let db_path = machine_db(state_dir);
    let existing = db_path.exists();
    let key = if existing {
        let db = kotton_device::db::open_machine_db(&db_path)
            .await
            .map_err(|e| io::Error::other(format!("failed to open machine db: {e}")))?;
        let operators = kotton_peer::daemon::db::operator_keys(&db).await;
        db.close().await;
        // 3. A vault with an operator is not created again.
        if !operators?.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} holds a vault that has an operator, so nothing was created and nothing changed: \
                     an operator is added at the running vault — `kvaultd operator enrol <key>`",
                    state_dir.display()
                ),
            ));
        }
        // 4. Adopted: its own key, from its own provider, or nothing at all.
        kotton_device::runtime::stored_device_signing_key(secrets)
            .map_err(|e| unreadable_key(state_dir, e))?
            .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{} holds a vault, and its secrets provider holds no key for it, so nothing was created: \
                     create never makes a new key over a vault's state — run it with the settings the vault \
                     runs under (KOTTON_SECRETS)",
                    state_dir.display()
                ),
            )
        })?
    } else {
        // 6. A new vault's own key — one the provider already keeps is kept, and
        // one is made only when the provider answered that it holds none: a
        // provider it could not read may hold one, and is refused.
        match kotton_device::runtime::stored_device_signing_key(secrets).map_err(|e| unreadable_key(state_dir, e))? {
            Some(key) => key,
            None => kotton_device::runtime::make_device_signing_key(secrets).map_err(|e| io::Error::other(e.to_string()))?,
        }
    };
    // 5 and 7. The state, and the operator as its first row.
    let db = kotton_device::db::open_machine_db(&db_path)
        .await
        .map_err(|e| io::Error::other(format!("failed to open machine db: {e}")))?;
    let enrolled = kotton_peer::daemon::db::enrol_operator_key(&db, &operator).await;
    db.close().await;
    enrolled?;
    // Which provider holds the key, recorded once, for every start to compare.
    if let Some(provider) = provider {
        record_provider(state_dir, provider)?;
    }
    tracing::info!(
        adopted = existing,
        operator = %hex::encode(operator),
        "a vault is created for its operator's key"
    );
    // 8. The line.
    Ok(line(hint, key.verifying_key().to_bytes()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use kotton_secret::MemorySecrets;
    use std::sync::Arc;

    /// An operator key with a public half on the curve, 64 hex.
    fn a_key() -> (ed25519_dalek::SigningKey, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        let hex = hex::encode(key.verifying_key().to_bytes());
        (key, hex)
    }

    /// A state directory of the test's own, `0700` as `create` makes one and
    /// an installer leaves one. `tempfile` makes its directories by the umask
    /// — `0755` under `022` — and `create` and a start use an existing state
    /// directory only when it is closed
    /// (`TASK-kvaultd-create-chmods-any-existing-directory-it-is-pointed-at`).
    pub(crate) fn a_state_dir() -> tempfile::TempDir {
        #[cfg(unix)]
        let dir = {
            use std::os::unix::fs::PermissionsExt as _;
            let mut dir = tempfile::Builder::new();
            dir.permissions(std::fs::Permissions::from_mode(0o700));
            dir
        };
        #[cfg(not(unix))]
        let dir = tempfile::Builder::new();
        dir.tempdir().unwrap()
    }

    /// A vault created at `base` for a key this returns — what every test that
    /// starts a vault in this crate does first.
    pub(crate) async fn created(base: &Path, secrets: &(dyn SecretsStore + Send + Sync)) -> String {
        let (_, operator) = a_key();
        create(base, secrets, &operator, String::new()).await.expect("the vault is created");
        operator
    }

    async fn operators(base: &Path) -> Vec<[u8; 32]> {
        let db = kotton_device::db::open_machine_db(machine_db(base)).await.unwrap();
        let keys = kotton_peer::daemon::db::operator_keys(&db).await.unwrap();
        db.close().await;
        keys
    }

    /// A vault from before creation existed: its operator set emptied in place.
    async fn with_no_operator(base: &Path) {
        let db = kotton_device::db::open_machine_db(machine_db(base)).await.unwrap();
        sqlx::query("DELETE FROM operator_key").execute(&db).await.unwrap();
        db.close().await;
    }

    fn unhex(hex_text: &str) -> [u8; 32] {
        hex::decode(hex_text).unwrap().try_into().unwrap()
    }

    /// **`create` makes the state, the vault's own key and its first operator,
    /// and returns the vault's line naming that key** — the line `kvaultd
    /// create` prints as its last output.
    #[tokio::test]
    async fn an_instance_is_created_for_its_operators_key_and_creation_prints_its_line() {
        let base = a_state_dir();
        let secrets = MemorySecrets::new();
        let (_, operator) = a_key();
        let line = create(base.path(), &secrets, &operator, "vault.example:7710".into()).await.unwrap();
        let key = kotton_device::runtime::stored_device_signing_key(&secrets).unwrap().expect("its own key is made");
        assert_eq!(
            line,
            InstanceLine { kind: OperatedService::Vault, hint: "vault.example:7710".into(), key: key.verifying_key().to_bytes() }
        );
        assert_eq!(operators(base.path()).await, [unhex(&operator)], "the key it was created for is its first operator");
        assert!(machine_db(base.path()).exists());
    }

    /// **A second `create`, with another key, over a vault that has an
    /// operator, refuses and changes nothing.**
    #[tokio::test]
    async fn creating_over_an_existing_instance_refuses_and_changes_nothing() {
        let base = a_state_dir();
        let secrets = MemorySecrets::new();
        let (_, first) = a_key();
        let line = create(base.path(), &secrets, &first, String::new()).await.unwrap();
        // At `0700`, the state directory passes the check, so the refusal here
        // is the operator's. Its `0750` case — where the mode refusal now comes
        // first — is
        // `creating_over_an_existing_instance_at_0750_is_refused_for_its_mode_and_changes_nothing`.
        let (_, second) = a_key();
        let e = create(base.path(), &secrets, &second, String::new()).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists, "{e}");
        #[cfg(unix)]
        assert_eq!(mode_of(base.path()), 0o700, "the directory's mode is as it was");
        assert!(e.to_string().contains("kvaultd operator enrol"), "{e}");
        assert_eq!(operators(base.path()).await, [unhex(&first)], "the operator set is as it was");
        let key = kotton_device::runtime::stored_device_signing_key(&secrets).unwrap().unwrap();
        assert_eq!(line.key, key.verifying_key().to_bytes(), "the key is as it was");
    }

    /// **State that names no operator is adopted** (fork 4, the owner's ruling):
    /// `create --operator K` records K, keeps the key the vault already had —
    /// the line names it — and keeps its tenants.
    #[tokio::test]
    async fn create_adopts_state_with_no_operator_keeping_its_key() {
        let base = a_state_dir();
        let secrets = MemorySecrets::new();
        let first = create(base.path(), &secrets, &a_key().1, String::new()).await.unwrap();
        let db = Arc::new(kotton_device::db::open_machine_db(machine_db(base.path())).await.unwrap());
        kotton_peer::daemon::db::insert_paired_node(&db, "sams-laptop", "sam", "did:key:zSam", &[7u8; 32], "[]", 0, Some("full"))
            .await
            .unwrap();
        db.close().await;
        with_no_operator(base.path()).await;

        let (_, adopter) = a_key();
        let line = create(base.path(), &secrets, &adopter, String::new()).await.unwrap();
        assert_eq!(line.key, first.key, "the key the state already had");
        assert_eq!(operators(base.path()).await, [unhex(&adopter)]);
        let db = Arc::new(kotton_device::db::open_machine_db(machine_db(base.path())).await.unwrap());
        assert!(
            kotton_peer::daemon::db::is_pubkey_paired_to_user(&db, &[7u8; 32], "sam").await.unwrap(),
            "its tenant is kept"
        );
        db.close().await;
    }

    /// **`create` never mints a key over existing state**: under a secrets
    /// provider that holds no key for it, it refuses, and the state is as it
    /// was — no operator, and the provider still holds nothing.
    #[tokio::test]
    async fn create_never_mints_a_key_over_existing_state() {
        let base = a_state_dir();
        create(base.path(), &MemorySecrets::new(), &a_key().1, String::new()).await.unwrap();
        with_no_operator(base.path()).await;
        let elsewhere = MemorySecrets::new();
        let e = create(base.path(), &elsewhere, &a_key().1, String::new()).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
        assert!(e.to_string().contains("never makes a new key"), "{e}");
        assert!(kotton_device::runtime::stored_device_signing_key(&elsewhere).unwrap().is_none(), "a key was minted");
        assert!(operators(base.path()).await.is_empty(), "the refusal recorded an operator");
    }

    /// A provider whose every read fails — a locked or unreachable keychain —
    /// and which counts the writes it is asked for, refusing none, so a `create`
    /// that minted over it would be seen doing it
    /// (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
    #[derive(Default)]
    struct UnreadableProvider {
        writes: std::sync::atomic::AtomicUsize,
    }

    impl SecretsStore for UnreadableProvider {
        fn get_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<Option<String>> {
            Err(kotton_sys::secret::SecretsError::Storage("the keychain did not answer".into()))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> kotton_sys::secret::SecretsResult<()> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<()> {
            Ok(())
        }
    }

    /// **`create` over a provider it cannot read refuses and mints nothing** —
    /// the new-vault arm too, where "the provider keeps one" and "the provider
    /// holds none" were the only two answers it knew. An unreadable keychain
    /// may hold a key; minting would write over it.
    #[tokio::test]
    async fn create_over_a_provider_it_cannot_read_refuses_and_mints_nothing() {
        let base = a_state_dir();
        let unreadable = UnreadableProvider::default();
        let e = create(base.path(), &unreadable, &a_key().1, String::new()).await.unwrap_err();
        assert!(e.to_string().contains("the keychain did not answer"), "the read's error is named: {e}");
        assert_eq!(
            unreadable.writes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "set_secret was called: a key was minted over one the provider could not read"
        );
        assert!(!machine_db(base.path()).exists(), "no vault state was made");
    }

    /// **Adopting existing state over a provider it cannot read refuses with the
    /// read's error, records no operator and mints nothing** — step 4, where the
    /// state names no operator and its key must come from the provider.
    #[tokio::test]
    async fn adopting_state_over_a_provider_it_cannot_read_refuses_and_mints_nothing() {
        let base = a_state_dir();
        create(base.path(), &MemorySecrets::new(), &a_key().1, String::new()).await.unwrap();
        with_no_operator(base.path()).await;
        let unreadable = UnreadableProvider::default();
        let e = create(base.path(), &unreadable, &a_key().1, String::new()).await.unwrap_err();
        assert!(e.to_string().contains("the keychain did not answer"), "the read's error is named: {e}");
        assert!(e.to_string().contains("nothing was created"), "{e}");
        assert_eq!(unreadable.writes.load(std::sync::atomic::Ordering::SeqCst), 0, "a key was minted");
        assert!(operators(base.path()).await.is_empty(), "the refusal recorded an operator");
    }

    /// **A start over a provider it cannot read is refused with the read's own
    /// error**, not as a provider that holds no key — the refusal names what
    /// went wrong, and nothing is written.
    #[test]
    fn a_start_over_a_provider_it_cannot_read_is_refused_naming_the_read() {
        let base = a_state_dir();
        let unreadable = UnreadableProvider::default();
        let e = refuse_unless_keyed(base.path(), &unreadable).unwrap_err();
        assert!(e.to_string().contains("the keychain did not answer"), "the read's error is named: {e}");
        assert_eq!(unreadable.writes.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// **A vault whose state names no operator does not start**, with one
    /// sentence naming the state directory and `create --operator` — a state
    /// never created, and one whose set is empty — and nothing is made for the
    /// first.
    #[tokio::test]
    async fn an_instance_with_no_operator_refuses_to_start_and_names_create() {
        let (_door_dir, door) = crate::control::tests::a_door();
        let base = a_state_dir();
        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        let refused = |e: io::Error| {
            let said = e.to_string();
            assert_eq!(said, no_operator(base.path()).to_string());
            assert!(said.contains(&base.path().display().to_string()) && said.contains("create --state-dir"), "{said}");
            assert!(said.contains("--operator <key>"), "{said}");
        };
        let e = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door.clone(), Arc::clone(&secrets))
            .await
            .err()
            .expect("a vault never created started");
        refused(e);
        let made: Vec<_> = std::fs::read_dir(base.path()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(made, [LOCK_FILE], "the refusal made something but its lock");

        created(base.path(), secrets.as_ref()).await;
        with_no_operator(base.path()).await;
        let e = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, secrets)
            .await
            .err()
            .expect("a vault with no operator started");
        refused(e);
    }

    /// **`create` and a serving vault exclude each other on one state**, each
    /// refusing rather than waiting: a vault holds the state for its life, so
    /// `create` is refused; and a state `create` holds is refused its start.
    #[tokio::test]
    async fn create_refuses_while_an_instance_runs_on_the_state() {
        let (_door_dir, door) = crate::control::tests::a_door();
        let base = a_state_dir();
        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        let first = created(base.path(), secrets.as_ref()).await;
        let vault = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, Arc::clone(&secrets))
            .await
            .expect("a created vault starts");
        // Refused by the lock, before the state is read: `WouldBlock`, not the
        // refusal of a vault that has an operator.
        let e = create(base.path(), secrets.as_ref(), &a_key().1, String::new()).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
        assert!(e.to_string().contains("held by another kvaultd"), "{e}");
        assert_eq!(operators(base.path()).await, [unhex(&first)], "create wrote under a serving vault");
        vault.shutdown().await;
        drop(vault);
        let e = create(base.path(), secrets.as_ref(), &a_key().1, String::new()).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists, "once the vault is gone, the state is read: {e}");
    }

    /// **A vault does not start on a state `create` holds**, and starts once it
    /// lets go.
    #[tokio::test]
    async fn an_instance_does_not_start_while_create_holds_its_state() {
        let (_door_dir, door) = crate::control::tests::a_door();
        let base = a_state_dir();
        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        created(base.path(), secrets.as_ref()).await;
        // What `create` takes for its whole run.
        let held = StateLock::take(base.path()).unwrap();
        let e = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door.clone(), Arc::clone(&secrets))
            .await
            .err()
            .expect("a vault started on a state create holds");
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
        drop(held);
        crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, secrets)
            .await
            .expect("it starts once create lets go");
    }

    /// **The last operator cannot be revoked** (fork 3, the owner's ruling):
    /// naming it is refused, *every one but* a key not enrolled is refused, and
    /// with two, one goes and `--all --keep` leaves exactly the one named.
    #[tokio::test]
    async fn the_last_operator_cannot_be_revoked() {
        let (_door_dir, door) = crate::control::tests::a_door();
        let base = a_state_dir();
        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        let first = created(base.path(), secrets.as_ref()).await;
        let vault = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, secrets).await.unwrap();
        let ctx = &vault.control.peer;
        let e = crate::operator::revoke(ctx, &first).await.unwrap_err();
        assert_eq!(e.to_string(), crate::operator::LAST_OPERATOR);
        let (_, other) = a_key();
        let e = crate::operator::revoke_all_but(ctx, &other).await.unwrap_err();
        assert!(e.to_string().contains("never left with none"), "{e}");
        assert_eq!(operators(base.path()).await, [unhex(&first)], "a refused revoke changed the set");

        crate::operator::admit(ctx, &other).await.unwrap();
        crate::operator::revoke(ctx, &first).await.unwrap();
        assert_eq!(operators(base.path()).await, [unhex(&other)]);
        crate::operator::admit(ctx, &first).await.unwrap();
        assert_eq!(crate::operator::revoke_all_but(ctx, &first).await.unwrap(), 1);
        assert_eq!(operators(base.path()).await, [unhex(&first)]);
        vault.shutdown().await;
    }

    /// **A start never makes a key over existing state**: a created vault
    /// started with a secrets provider that holds no key for it — another
    /// `KOTTON_SECRETS` — is refused, naming that, and the provider is left
    /// with no key, where the runtime would have minted a stranger.
    #[tokio::test]
    async fn a_start_never_mints_a_key_over_existing_state() {
        let (_door_dir, door) = crate::control::tests::a_door();
        let base = a_state_dir();
        created(base.path(), &MemorySecrets::new()).await;
        let elsewhere = Arc::new(MemorySecrets::new());
        let e = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, elsewhere.clone())
            .await
            .err()
            .expect("a vault started with a provider holding no key for it");
        assert!(e.to_string().contains("KOTTON_SECRETS") && e.to_string().contains("never makes a new key"), "{e}");
        assert!(kotton_device::runtime::stored_device_signing_key(elsewhere.as_ref()).unwrap().is_none(), "a key was minted");
    }

    /// The permission bits of `path`'s own entry, a symlink's not followed.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Every file under `dir` with its bytes, and every directory, sorted: what
    /// a refusal that "writes nothing" must leave exactly as it found. Read only by
    /// the unix-only refusals above.
    #[cfg(unix)]
    fn snapshot(dir: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        let mut all = Vec::new();
        let mut dirs = vec![dir.to_path_buf()];
        while let Some(d) = dirs.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if e.file_type().unwrap().is_dir() {
                    all.push((p.clone(), None));
                    dirs.push(p);
                } else {
                    all.push((p.clone(), std::fs::read(&p).ok()));
                }
            }
        }
        all.sort();
        all
    }

    /// **(1) `create` refuses an existing directory at `0755` and leaves its
    /// mode** (`TASK-kvaultd-create-chmods-any-existing-directory-it-is-pointed-at`):
    /// it names the directory and `chmod 700`, the directory is still `0755`,
    /// and it is still empty. `create` changes the mode of no directory it did
    /// not make.
    #[cfg(unix)]
    #[tokio::test]
    async fn create_refuses_a_0755_directory_and_leaves_its_mode() {
        let base = a_state_dir();
        set_mode(base.path(), 0o755);
        let e = create(base.path(), &MemorySecrets::new(), &a_key().1, String::new()).await.unwrap_err();
        let said = e.to_string();
        assert!(said.contains(&format!("chmod 700 {}", base.path().display())), "{said}");
        assert_eq!(mode_of(base.path()), 0o755, "create changed the mode of a directory it did not make");
        assert!(snapshot(base.path()).is_empty(), "the refusal wrote into it: {:?}", snapshot(base.path()));
    }

    /// **`create_recorded` checks before it opens its provider**, in process as
    /// `kvaultd create` does through the binary (test (6)): over a `0755`
    /// directory holding a `system/secrets.json` that does not parse, under the
    /// `file` provider, the refusal is the `chmod 700` sentence, not the
    /// store's parse error. (`main.rs` checks first on the binary's path, so
    /// only an in-process call reaches this one.)
    #[cfg(unix)]
    #[tokio::test]
    async fn create_recorded_refuses_a_0755_directory_before_it_opens_its_provider() {
        let base = a_state_dir();
        std::fs::create_dir(base.path().join("system")).unwrap();
        std::fs::write(base.path().join("system/secrets.json"), b"this is not a secrets store").unwrap();
        set_mode(base.path(), 0o755);
        let before = snapshot(base.path());
        let e = create_recorded(base.path(), SecretsProvider::File, &a_key().1, String::new()).await.unwrap_err();
        assert!(e.to_string().contains(&format!("chmod 700 {}", base.path().display())), "{e}");
        assert_eq!(snapshot(base.path()), before, "the refusal wrote into it");
        assert_eq!(mode_of(base.path()), 0o755);
    }

    /// **(1)'s family: a created vault whose state directory is then `0750` is
    /// refused for its mode before its operator is read**, and nothing changes —
    /// not the mode, not the operator set, not the key.
    #[cfg(unix)]
    #[tokio::test]
    async fn creating_over_an_existing_instance_at_0750_is_refused_for_its_mode_and_changes_nothing() {
        let base = a_state_dir();
        let secrets = MemorySecrets::new();
        let (_, first) = a_key();
        let line = create(base.path(), &secrets, &first, String::new()).await.unwrap();
        set_mode(base.path(), 0o750);
        let before = snapshot(base.path());
        let e = create(base.path(), &secrets, &a_key().1, String::new()).await.unwrap_err();
        assert!(e.to_string().contains(&format!("chmod 700 {}", base.path().display())), "{e}");
        assert_eq!(mode_of(base.path()), 0o750, "the directory's mode is as it was");
        assert_eq!(snapshot(base.path()), before, "the refusal wrote into the state");
        assert_eq!(operators(base.path()).await, [unhex(&first)], "the operator set is as it was");
        let key = kotton_device::runtime::stored_device_signing_key(&secrets).unwrap().unwrap();
        assert_eq!(line.key, key.verifying_key().to_bytes(), "the key is as it was");
    }

    /// **(2) `create` refuses a directory another uid owns, naming that owner,
    /// and leaves it as it was** — mode, owner and contents. Arranging another
    /// owner needs `CAP_CHOWN`, so this runs only as root and otherwise says it
    /// was skipped and why; where it is skipped, the owner check is held by
    /// reading `own_state_dir` alone.
    #[cfg(unix)]
    #[tokio::test]
    async fn create_refuses_a_directory_another_uid_owns() {
        use std::os::unix::fs::MetadataExt as _;
        let base = a_state_dir();
        // The uid this test runs as: the owner of the directory it just made.
        if std::fs::metadata(base.path()).unwrap().uid() != 0 {
            eprintln!("skipped: not root — giving a directory to another uid needs CAP_CHOWN");
            return;
        }
        let theirs = base.path().join("theirs");
        std::fs::create_dir(&theirs).unwrap();
        set_mode(&theirs, 0o700);
        std::os::unix::fs::chown(&theirs, Some(65534), Some(65534)).unwrap();
        let e = create(&theirs, &MemorySecrets::new(), &a_key().1, String::new()).await.unwrap_err();
        let said = e.to_string();
        assert!(said.contains(&theirs.display().to_string()), "{said}");
        // Its owner by name where this machine has one for 65534, else by number.
        let owner = std::fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .find_map(|l| {
                let f: Vec<_> = l.split(':').collect();
                (f.get(2) == Some(&"65534")).then(|| f[0].to_string())
            })
            .unwrap_or_else(|| "65534".into());
        assert!(said.contains(&format!("run create as {owner}")), "{said}");
        let meta = std::fs::symlink_metadata(&theirs).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (65534, 65534), "the owner changed");
        assert_eq!(mode_of(&theirs), 0o700, "the mode changed");
        assert!(snapshot(&theirs).is_empty(), "root's files were written into it: {:?}", snapshot(&theirs));
    }

    /// **The library refuses a symlinked state directory too** — not only the
    /// CLI, which canonicalizes: `instance::create` handed a symlink to a
    /// `0700` directory of the caller's own refuses it, naming the link, and
    /// writes nothing through it.
    #[cfg(unix)]
    #[tokio::test]
    async fn instance_create_refuses_a_symlinked_state_directory() {
        let base = a_state_dir();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o700);
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // `link/` too: a trailing separator makes the kernel resolve the last
        // component (the Fable reviewer's refusal of `80b8458da`).
        let slashed = PathBuf::from(format!("{}/", link.display()));
        for spelled in [link.clone(), slashed] {
            let e = create(&spelled, &MemorySecrets::new(), &a_key().1, String::new()).await.unwrap_err();
            let said = e.to_string();
            assert!(said.contains(&link.display().to_string()) && said.contains("give the directory it points to"), "{}: {said}", spelled.display());
            assert!(snapshot(&real).is_empty(), "create wrote through {}: {:?}", spelled.display(), snapshot(&real));
            assert_eq!(mode_of(&real), 0o700);
        }
    }

    /// **(5) A started vault's state, `run/` and all, is adopted by a second
    /// `create`** once its operators are gone: created into an absent
    /// directory, served at the door `runtime_dir_in` resolves for an
    /// environment naming only `KOTTON_BASE_DIR` — tier 3, `<state>/run/`, as a
    /// hand-started vault with neither `XDG_RUNTIME_DIR` nor `TMPDIR` gets it —
    /// stopped with `run/` present, and left with no operator. The second
    /// `create` succeeds, keeps the key and leaves the state directory `0700`:
    /// nothing under it is read for who wrote it.
    #[cfg(unix)]
    #[tokio::test]
    async fn create_adopts_a_started_vault_in_its_own_0700_directory() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        let first = create(&state, secrets.as_ref(), &a_key().1, String::new()).await.unwrap();
        let only_base = |k: &str| (k == "KOTTON_BASE_DIR").then(|| state.display().to_string());
        let door = kotton_common::paths::daemon_socket_path_in(&only_base, "vault").unwrap();
        assert!(door.starts_with(state.join("run")), "{} is not tier 3", door.display());
        let endpoint = kotton_sys::ipc::IpcEndpoint::UnixSocket(door);
        let vault = crate::Vault::new_with_base_and_secrets(state.clone(), endpoint.clone(), Arc::clone(&secrets))
            .await
            .expect("a created vault starts");
        let serving = tokio::spawn(crate::control::serve(endpoint.clone(), Arc::clone(&vault.control)));
        let mut bound = false;
        for _ in 0..100 {
            if kotton_ipc::IpcClient::<kotton_wire::ipc::VaultRequest, kotton_wire::ipc::UserResponse>::connect(endpoint.clone())
                .await
                .is_ok()
            {
                bound = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(bound, "the door never listened");
        serving.abort();
        vault.shutdown().await;
        drop(vault);
        assert!(state.join("run").is_dir(), "the start left no run/");
        with_no_operator(&state).await;

        let (_, adopter) = a_key();
        let line = create(&state, secrets.as_ref(), &adopter, String::new()).await.expect("its own state is adopted");
        assert_eq!(line.key, first.key, "the key the state already had");
        assert_eq!(operators(&state).await, [unhex(&adopter)]);
        assert_eq!(mode_of(&state), 0o700);
    }

    /// **A start refuses a state directory wider than `0700`, and leaves it**
    /// (`TASK-the-base-dir-and-system-are-said-to-be-0700-and-nothing-makes-them-so`,
    /// (i)): a created vault whose state directory is then `0755` is refused at
    /// its next start, which writes nothing, names the state directory and
    /// `chmod 700 <state>`, and leaves it `0755`.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_vault_start_refuses_a_state_directory_wider_than_0700_and_leaves_it() {
        let (_door_dir, door) = crate::control::tests::a_door();
        let base = a_state_dir();
        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        created(base.path(), secrets.as_ref()).await;
        set_mode(base.path(), 0o755);
        let before = snapshot(base.path());
        let e = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, secrets)
            .await
            .err()
            .expect("a vault started over a state directory open to others");
        assert!(e.to_string().contains(&format!("chmod 700 {}", base.path().display())), "{e}");
        assert_eq!(mode_of(base.path()), 0o755, "the start changed the mode");
        assert_eq!(snapshot(base.path()), before, "the refused start wrote into the state");
    }

    /// **A vault whose `system/` is `0755` inside its `0700` state directory
    /// starts, and is created again** (the base-dir record's (ii)): nothing
    /// checks a subdirectory and nothing chmods it — beneath a closed state
    /// directory its mode grants nobody anything.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_vault_whose_system_is_0755_inside_its_0700_state_directory_starts_and_is_created_again() {
        let (_door_dir, door) = crate::control::tests::a_door();
        let base = a_state_dir();
        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());
        let first = create(base.path(), secrets.as_ref(), &a_key().1, String::new()).await.unwrap();
        let system = base.path().join("system");
        set_mode(&system, 0o755);
        let vault = crate::Vault::new_with_base_and_secrets(base.path().to_owned(), door, Arc::clone(&secrets))
            .await
            .expect("a vault whose system/ is 0755 starts");
        vault.shutdown().await;
        drop(vault);
        with_no_operator(base.path()).await;
        let line = create(base.path(), secrets.as_ref(), &a_key().1, String::new()).await.expect("it is created again");
        assert_eq!(line.key, first.key);
        assert_eq!(mode_of(&system), 0o755, "system/ was chmodded");
        assert_eq!(mode_of(base.path()), 0o700);
    }
}
