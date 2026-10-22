// SPDX-License-Identifier: AGPL-3.0-or-later
//! A relay is created for its operator's key, and does not start without one
//! (RFC-0084, the amendment of 2026-10-01: V18, V19, V20).
//!
//! **Creation is the one way into an empty operator set.** `kotton-relay
//! create --state-dir <dir> --operator <key>` runs once, offline, before any
//! process serves: it makes the relay's state and its own key
//! (`identity.key`), writes the key it was given as the first line of
//! `operators`, and prints the relay's line as its last output. Over state that
//! has an operator it refuses and changes nothing; over state that has none — a
//! relay from before creation existed — it adopts it, keeping its key, and it
//! never makes a key over existing state. The offline `operator enrol` adds to
//! a set that has an operator and refuses an empty one, naming this.
//!
//! **What existing state is, is read from the state**: any of the files a relay
//! keeps there — `rule.json`, `operators`, `identity.key`. The lock file is not
//! one; it says only who holds the directory.
//!
//! **A relay with no operator does not start** ([`refuse_unless_operated`]),
//! before it binds any port. A relay with no state directory is created and
//! started in one act: `--operator <key>` records the key and makes the relay's
//! own key in memory, both for the life of the process, and without it the relay
//! refuses to start like any other.
//!
//! **`create` and a serving relay exclude each other** by [`StateLock`], an
//! exclusive advisory lock on [`LOCK_FILE`] in the state directory, held by
//! `create` for its whole run and by a serving relay for its whole life, and
//! refused — never waited for — by whichever comes second. The offline operator
//! verbs do not take it: a serving relay holds it for its whole life, and each
//! verb writes `operators` whole through a temporary file and a rename, leaving
//! the set non-empty whatever it interleaves with.

use std::path::Path;

use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

use crate::admission::{is_key_hex, read_operators, OPERATORS_FILE, RULE_FILE};
use crate::identity::{RelayKey, KEY_FILE};

/// The file in the state directory whose exclusive lock says an instance —
/// serving, or being created — holds the state.
pub const LOCK_FILE: &str = "instance.lock";

/// The state directory's exclusive lock, held for as long as this value is.
pub struct StateLock {
    _file: std::fs::File,
}

impl StateLock {
    /// Take the lock on `dir`, or refuse at once when anything holds it.
    pub fn take(dir: &Path) -> anyhow::Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts.open(dir.join(LOCK_FILE))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
                "{} is held by another kotton-relay — a relay serving from it, or `kotton-relay create` \
                 making it; nothing was changed",
                dir.display()
            ),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

/// The file the deleted claim kept in the state directory: an open one-time
/// secret, the hashes of spent ones, the announced address. Nothing reads it
/// now, and a secret that no longer confers anything is still a secret on
/// disk, so adoption and every start delete it ([`remove_leftover_secret`]).
pub const LEFTOVER_SECRET_FILE: &str = "claim";

/// Delete the claim's leftover file from `dir`, if one is there; whether one
/// was. A link is removed, never followed. Anything that cannot be removed is
/// an error: a start or an adoption that left the secret behind would say it
/// had not.
pub fn remove_leftover_secret(dir: &Path) -> anyhow::Result<bool> {
    let path = dir.join(LEFTOVER_SECRET_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            tracing::info!(file = %path.display(), "removed the deleted claim's leftover file and the secret in it");
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow::anyhow!(
            "{} is the deleted claim's leftover file, which holds a secret, and it could not be removed ({e}); \
             remove it by hand",
            path.display()
        )),
    }
}

/// The one sentence a relay with a state directory and no operator ends its
/// start with.
pub fn no_operator(dir: &Path) -> String {
    format!(
        "this relay has no operator, so it does not start: create it for its operator's key — \
         `kotton-relay create --state-dir {} --operator <key>`, which keeps any state already there",
        dir.display()
    )
}

/// The sentence a relay with no state directory and no `--operator` ends its
/// start with.
pub const NO_OPERATOR_IN_MEMORY: &str =
    "this relay was given no operator, so it does not start: a relay with no state directory is created \
     as it starts — `kotton-relay --operator <key>` — and one with a state directory by \
     `kotton-relay create --state-dir <dir> --operator <key>`";

/// Whether the relay at `dir` may start: its operators' file names at least
/// one key. Reads, and makes nothing.
pub fn refuse_unless_operated(dir: &Path) -> anyhow::Result<()> {
    if !dir.is_dir() {
        anyhow::bail!("{}", no_operator(dir));
    }
    if read_operators(dir)?.is_empty() {
        anyhow::bail!("{}", no_operator(dir));
    }
    Ok(())
}

/// The key a relay with a state directory starts with: the one in it, never a
/// new one. A relay that was created always has one, so none here is a start
/// over state that lost it, and making one would make it a relay nobody knows,
/// printing a line with a key no desktop expects. Refused, naming that.
pub fn existing_key(dir: &Path) -> anyhow::Result<RelayKey> {
    RelayKey::open_existing(dir)?.ok_or_else(|| {
        anyhow::anyhow!(
            "the relay at {} has no key of its own ({KEY_FILE}), so it does not start: a start never makes a \
             new key over a relay's state — restore {KEY_FILE} from where the state was backed up",
            dir.display()
        )
    })
}

/// Whether `dir` holds a relay's state: any file a relay keeps there.
pub fn holds_state(dir: &Path) -> bool {
    [RULE_FILE, OPERATORS_FILE, KEY_FILE]
        .iter()
        .any(|f| dir.join(f).symlink_metadata().is_ok())
}

/// The relay's line: its kind, the address it announces, its key.
pub fn line(key: &RelayKey, advertise: &str) -> InstanceLine {
    InstanceLine {
        kind: OperatedService::Relay,
        hint: advertise.to_owned(),
        key: key.public(),
    }
}

/// `create`, as the state directory's owner: make the relay at `dir` for
/// `operator_hex`, or adopt the state there when it names no operator, and
/// return the relay's line (RFC-0084 V18).
pub fn create(dir: &Path, operator_hex: &str, advertise: &str) -> anyhow::Result<InstanceLine> {
    anyhow::ensure!(
        is_key_hex(operator_hex),
        "an operator key is 64 hex characters, the public key the desktop's `mint relay` printed"
    );
    // 1. The state's exclusive lock, held to the end of this function.
    let _held = StateLock::take(dir)?;
    // 2. Whether a relay is here, read from the state.
    let key = if holds_state(dir) {
        // 3. A relay with an operator is not created again.
        if !read_operators(dir)?.is_empty() {
            anyhow::bail!(
                "{} holds a relay that has an operator, so nothing was created and nothing changed: \
                 an operator is added there — `kotton-relay --state-dir {} operator enrol <key>`",
                dir.display(),
                dir.display()
            );
        }
        // 4. Adopted: its own key, or nothing at all.
        RelayKey::open_existing(dir)?.ok_or_else(|| {
            anyhow::anyhow!(
                "{} holds a relay's state and no key of its own, so nothing was created: create never \
                 makes a new key over a relay's state",
                dir.display()
            )
        })?
    } else {
        // 5 and 6. The state, and the relay's own key.
        RelayKey::open(dir)?
    };
    // The deleted claim's file, with the secret it kept, goes with adoption.
    remove_leftover_secret(dir)?;
    // 7. The operator, as the first line of `operators`.
    crate::admission::write_operators(dir, &[operator_hex.to_owned()])?;
    tracing::info!(operator = %operator_hex, "a relay is created for its operator's key");
    // 8. The line.
    Ok(line(&key, advertise))
}
