// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's one rule, who may use it, and the operator who sets it
//! (`TASK-a-relays-admission-rule-is-set-by-its-operator-over-the-wire`).
//!
//! **What the rule is checked against.** Not a list of who is allowed. A relay is
//! keyed by handles that rotate and name nobody (RFC-0083 R4), and an allowlist of
//! device keys would have every device present its durable key at the door — so
//! every circuit it opened would be joined to one key, which is the history the
//! handles were built to prevent. The relay checks membership and never which
//! member: a device presents a MAC under an **admission key** over its handle and
//! the timestamp its handle signed, and the relay learns that the caller holds the
//! key and nothing else.
//!
//! **Two keys, and the rule is which of them it reads.** *Mine* is held by the
//! operators' own devices; *invited* by the people an operator invites (their
//! contacts, and the tenants of their vault). *Only my devices* reads *mine*;
//! *the people I invite* reads either; *anyone* reads no tag. Narrowing the rule is
//! therefore immediate — the invited key stops being read, at the door and for
//! every reservation already held, which a set asks again and drops if the new
//! rule refuses it — and removing one
//! person is rotating the key they held, with the one before it accepted until the
//! next rotation.
//!
//! **Who sets it.** An operator: the key the relay was created for
//! (`kotton-relay create`, RFC-0084 V18), and any added at the relay's own
//! terminal (`kotton-relay operator enrol`), read from its file on every
//! request so a revocation takes effect at the next one. The set is never
//! emptied: `operator enrol` refuses a state with none, naming `create`, and
//! `operator revoke` refuses the last (RFC-0084 V19, fork 3). An operator's standing reaches the two
//! requests of `POST /operator` and nothing else: its header scheme is read on
//! that route only, so it admits no one as a device on any other.
//!
//! **What it keeps.** The rule, the keys, how many times each rotated, and the
//! timestamp of the last set — `rule.json` — and the operators' public keys —
//! `operators`. No handle, no device key, no person's identity, no tenant's name.
//! A relay that cannot reach its operator keeps the last rule it was given, across
//! a restart.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use kotton_wire::rendezvous::{
    admission_tag_input, AdmissionRule, RelayOperatorRequest, RelayOperatorResponse,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The rule's file, beside the operators' in the state directory.
pub(crate) const RULE_FILE: &str = "rule.json";
/// One operator key per line, 64 hex characters.
pub(crate) const OPERATORS_FILE: &str = "operators";

/// One admission key and the one before it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tier {
    /// How many times this key has been set. A count, not a key.
    pub epoch: u64,
    #[serde(default, with = "opt_key")]
    pub current: Option<[u8; 32]>,
    /// Still accepted for one epoch, so a device that has not learned the new
    /// key yet is not refused in between.
    #[serde(default, with = "opt_key")]
    pub previous: Option<[u8; 32]>,
}

impl Tier {
    fn rotate(&mut self, key: [u8; 32]) {
        if self.current == Some(key) {
            return;
        }
        self.previous = self.current.replace(key);
        self.epoch += 1;
    }

    fn admits(&self, input: &[u8], tag: &[u8]) -> bool {
        [self.current, self.previous]
            .into_iter()
            .flatten()
            .any(|key| verify_tag(&key, input, tag))
    }
}

/// Everything the rule is, and everything the relay keeps of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleState {
    pub rule: AdmissionRule,
    pub mine: Tier,
    pub invited: Tier,
    /// The timestamp of the last set an operator made. A set must be newer, so a
    /// set captured on the wire cannot be replayed to roll a rotation back.
    pub last_set: i64,
}

impl Default for RuleState {
    /// A relay its operator has set no rule on admits **nobody** — *only my
    /// devices*, with no key any device holds (RFC-0084, fork 2, the owner's
    /// ruling of 2026-10-01). A relay is created with an operator and no rule,
    /// because the rule's keys are minted at the desktop and handed over the
    /// operator wire; until that first set, nothing reserves, opens a circuit or
    /// stores an address here. The operator's first set replaces it; nothing
    /// else does.
    fn default() -> Self {
        Self {
            rule: AdmissionRule::OnlyMyDevices,
            mine: Tier::default(),
            invited: Tier::default(),
            last_set: 0,
        }
    }
}

impl RuleState {
    /// Whether this rule admits a handle whose `fingerprint` signed `ts` and
    /// which carried `tag` (base64url). The door, as a function of the rule: the
    /// same answer at an upgrade and, for what is already held, when the rule
    /// changes.
    pub fn admits(&self, fingerprint: &str, ts: i64, tag: Option<&str>) -> bool {
        if self.rule == AdmissionRule::Anyone {
            return true;
        }
        let Some(tag) = tag.and_then(|t| URL_SAFE_NO_PAD.decode(t).ok()) else {
            return false;
        };
        let input = admission_tag_input(fingerprint, ts);
        match self.rule {
            AdmissionRule::OnlyMyDevices => self.mine.admits(&input, &tag),
            AdmissionRule::PeopleIInvite => {
                self.mine.admits(&input, &tag) || self.invited.admits(&input, &tag)
            }
            AdmissionRule::Anyone => true,
        }
    }
}

/// Why a request was not admitted — for the log and the status code, and never a
/// hint about which key the caller would have needed.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No tag, or one no accepted key made.
    NotAdmitted,
}

/// The rule, held in memory and — with a state directory — on disk.
pub struct Admission {
    state: RwLock<RuleState>,
    dir: Option<PathBuf>,
    /// The operator a relay with no state directory was created for, held for
    /// as long as the process; `None` for a relay that keeps its operators in
    /// its state directory.
    operator: Option<String>,
}

impl Admission {
    /// A rule held only in memory, for as long as the process, set by the one
    /// operator the relay was created for (`kotton-relay --operator <key>`,
    /// RFC-0084 V19).
    pub fn in_memory(operator: &str, state: RuleState) -> Self {
        Self {
            state: RwLock::new(state),
            dir: None,
            operator: Some(operator.to_owned()),
        }
    }

    /// Load the rule from `dir`, or start at [`RuleState::default`] if the relay
    /// has never been given one. A file that is there and does not parse is an
    /// error: falling back to *anyone* would widen a narrowed relay because a
    /// byte went bad, and failing to start says so instead.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(RULE_FILE);
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                anyhow::anyhow!(
                    "{} does not parse ({e}); refusing to start rather than admit anyone",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RuleState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            state: RwLock::new(state),
            dir: Some(dir.to_path_buf()),
            operator: None,
        })
    }

    pub fn rule(&self) -> AdmissionRule {
        self.state.read().unwrap().rule
    }

    /// A copy of everything held, for a test that reads it all.
    #[cfg(test)]
    pub fn snapshot(&self) -> RuleState {
        self.state.read().unwrap().clone()
    }

    /// **The door.** Whether a request whose handle `fingerprint` signed `ts`, and
    /// which carried `tag` (base64url), is admitted under the rule held now.
    ///
    /// Called after the handle's signature is verified and before the relay
    /// answers anything; never after.
    pub fn admit(&self, fingerprint: &str, ts: i64, tag: Option<&str>) -> Result<(), Refusal> {
        self.admit_then(fingerprint, ts, tag, || ())
    }

    /// The door, and `then` run behind it while the rule it read is still the
    /// rule: a set waits for `then` to finish, and `then` never runs under a
    /// rule that has already been replaced. `reserve_handler` holds a
    /// reservation this way, so no reservation can be taken under the old rule
    /// after the set's sweep has passed it by.
    pub fn admit_then<R>(
        &self,
        fingerprint: &str,
        ts: i64,
        tag: Option<&str>,
        then: impl FnOnce() -> R,
    ) -> Result<R, Refusal> {
        let state = self.state.read().unwrap();
        if state.admits(fingerprint, ts, tag) {
            Ok(then())
        } else {
            Err(Refusal::NotAdmitted)
        }
    }

    /// Whether `key_hex` is an operator of this relay — read from the file on
    /// every call, so a key revoked at the terminal is refused at its next
    /// request. With no state directory, the one key it was created for.
    pub fn is_operator(&self, key_hex: &str) -> bool {
        match &self.dir {
            Some(dir) => match read_operators(dir) {
                Ok(keys) => keys.iter().any(|k| k == key_hex),
                // Refused, as a key not enrolled is — and said, because every
                // operator is refused the same way until the file can be read.
                Err(e) => {
                    tracing::warn!(
                        file = %dir.join(OPERATORS_FILE).display(),
                        error = %e,
                        "the operators' file cannot be read; every operator is refused until it can"
                    );
                    false
                }
            },
            None => self.operator.as_deref() == Some(key_hex),
        }
    }

    /// Answer a request an operator signed at `ts`. The caller has verified the
    /// signature and [`Self::is_operator`]; this is what the standing reaches.
    ///
    /// `on_set` runs once a set has been kept and held, with the rule as it now
    /// stands and before any door reads it: it is where what the relay already
    /// holds is asked the new rule.
    pub fn answer(
        &self,
        request: &RelayOperatorRequest,
        ts: i64,
        on_set: impl FnOnce(&RuleState),
    ) -> RelayOperatorResponse {
        match request {
            RelayOperatorRequest::ReadRule => self.read_rule(),
            RelayOperatorRequest::SetRule {
                rule,
                mine,
                invited,
            } => match self.set_rule(*rule, mine.as_deref(), invited.as_deref(), ts, on_set) {
                Ok(r) => r,
                Err(reason) => RelayOperatorResponse::Refused { reason },
            },
        }
    }

    fn read_rule(&self) -> RelayOperatorResponse {
        let s = self.state.read().unwrap();
        RelayOperatorResponse::Rule {
            rule: s.rule,
            mine_epoch: s.mine.epoch,
            invited_epoch: s.invited.epoch,
        }
    }

    fn set_rule(
        &self,
        rule: AdmissionRule,
        mine: Option<&str>,
        invited: Option<&str>,
        ts: i64,
        on_set: impl FnOnce(&RuleState),
    ) -> Result<RelayOperatorResponse, String> {
        let mine = mine.map(parse_key).transpose()?;
        let invited = invited.map(parse_key).transpose()?;

        let mut guard = self.state.write().unwrap();
        if ts <= guard.last_set {
            return Err("a set no newer than the last one is refused".into());
        }
        let mut next = guard.clone();
        if let Some(k) = mine {
            next.mine.rotate(k);
        }
        if let Some(k) = invited {
            next.invited.rotate(k);
        }
        next.rule = rule;
        next.last_set = ts;

        // A rule whose key nobody was given admits nobody — the operator's own
        // devices included — so it is refused rather than set.
        let needs_mine = matches!(
            rule,
            AdmissionRule::OnlyMyDevices | AdmissionRule::PeopleIInvite
        );
        if needs_mine && next.mine.current.is_none() {
            return Err("this rule reads the key your devices hold, and none has been set".into());
        }
        if rule == AdmissionRule::PeopleIInvite && next.invited.current.is_none() {
            return Err(
                "this rule reads the key the people you invite hold, and none has been set".into(),
            );
        }

        // Kept before it is held: a set the disk did not take is refused, so the
        // rule a restart comes back with is the rule the operator was told.
        if let Some(dir) = &self.dir {
            write_private(
                &dir.join(RULE_FILE),
                &serde_json::to_vec_pretty(&next).unwrap(),
            )
            .map_err(|e| format!("the rule could not be kept: {e}"))?;
        }
        *guard = next;
        on_set(&guard);
        Ok(RelayOperatorResponse::Rule {
            rule: guard.rule,
            mine_epoch: guard.mine.epoch,
            invited_epoch: guard.invited.epoch,
        })
    }
}

// ---------------------------------------------------------------------------
// The operators, set only at the terminal
// ---------------------------------------------------------------------------

/// The operators' keys, from `operators` in `dir`; none when there is no file.
///
/// **Only a regular file is read**
/// (`TASK-a-relay-operator-verb-typed-at-a-fifo-named-operators-waits-forever`). The
/// directory's owner can make `operators` anything, and reading by path reads what
/// the path names: a FIFO waits for a writer, holding the landlord's terminal and
/// the relay's operator requests with it, and a device may never end. So it is
/// opened without waiting — `O_NONBLOCK`, which a FIFO opened to read with no
/// writer does not block on — and the descriptor is `fstat`ed before one byte is
/// read. Anything but a regular file is refused naming the kind found, and a verb
/// that meets the refusal writes nothing either, since it reads first.
pub(crate) fn read_operators(dir: &Path) -> std::io::Result<Vec<String>> {
    use std::io::Read as _;
    let path = dir.join(OPERATORS_FILE);
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let mut f = match opts.open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        // What `open` says of a socket, and of a device with nothing behind it.
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
            return Err(not_a_regular_file(&path, "a socket or a device"))
        }
        Err(e) => return Err(e),
    };
    let kind = f.metadata()?.file_type();
    if !kind.is_file() {
        return Err(not_a_regular_file(&path, kind_of(kind)));
    }
    let mut text = String::new();
    f.read_to_string(&mut text)?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| is_key_hex(l))
        .map(str::to_owned)
        .collect())
}

/// The refusal [`read_operators`] gives what is not a regular file.
fn not_a_regular_file(path: &Path, found: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{} is {found}, not a regular file; the operators' keys are read only from a \
             regular file",
            path.display()
        ),
    )
}

/// What a file that is not a regular one is, in a sentence.
fn kind_of(kind: std::fs::FileType) -> &'static str {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;
        if kind.is_fifo() {
            return "a FIFO";
        }
        if kind.is_socket() {
            return "a socket";
        }
        if kind.is_char_device() {
            return "a character device";
        }
        if kind.is_block_device() {
            return "a block device";
        }
    }
    if kind.is_dir() {
        "a directory"
    } else {
        "neither a file nor a directory"
    }
}

/// A verb typed at the terminal against the state directory.
#[derive(Debug, Clone, Copy)]
pub enum Verb<'a> {
    /// `create --operator <key>`: create the relay for its operator's key, or
    /// adopt state that names none, and print its line with the address it
    /// announces (`--advertise`) (RFC-0084 V18).
    Create { operator: &'a str, advertise: &'a str },
    /// `operator enrol <key>`: add one operator to a set that has one, and
    /// leave the others.
    Enrol(&'a str),
    /// `operator revoke <key>`: end one operator's standing, never the last.
    Revoke(&'a str),
    /// `operator revoke --all --keep <key>`: end every one but the one named.
    RevokeAllBut(&'a str),
}

impl Verb<'_> {
    /// The arguments that type this verb, after `--state-dir <dir>`.
    pub fn args(&self) -> Vec<&str> {
        match *self {
            Verb::Create { operator, advertise } => vec!["--advertise", advertise, "create", "--operator", operator],
            Verb::Enrol(k) => vec!["operator", "enrol", k],
            Verb::Revoke(k) => vec!["operator", "revoke", k],
            Verb::RevokeAllBut(k) => vec!["operator", "revoke", "--all", "--keep", k],
        }
    }
}

/// Who types a verb at a state directory.
enum Typist {
    /// This process: it is the directory's owner.
    This,
    /// This process is root and the directory is someone else's: the verb is typed
    /// again as them.
    #[cfg(unix)]
    TheOwner { uid: u32, gid: u32 },
}

/// Type `verb` at `dir` as whoever the terminal is, and return the line it says.
///
/// **Only the directory's owner opens anything in it**
/// (`TASK-a-relay-operator-verb-typed-as-root-reads-operators-by-a-path-the-relays-user-controls`).
/// The relay runs as its own user because it reads bytes a stranger wrote, and that
/// user owns the state directory, so a relay taken over to it can make `operators`
/// a symlink to any path. Root that opened `operators` would open whatever it names.
/// So root does not: it types the verb again as the owner — `again` is the command
/// that does, this binary with the same verb — and what the owner can follow is
/// only what the owner could already read. Nothing root reaches is in the
/// directory but the file root itself left there ([`give_back_what_root_left`]).
///
/// The owner types it here. Anyone else is refused by name ([`not_the_owner`]), and
/// nothing is read or written.
pub fn type_verb(
    dir: &Path,
    verb: Verb<'_>,
    again: impl FnOnce() -> std::io::Result<std::process::Command>,
) -> anyhow::Result<String> {
    let (Verb::Create { operator: k, .. } | Verb::Enrol(k) | Verb::Revoke(k) | Verb::RevokeAllBut(k)) = verb;
    anyhow::ensure!(
        is_key_hex(k),
        "an operator key is 64 hex characters, the public key the desktop's `mint relay` printed"
    );
    match who_types(dir)? {
        Typist::This => Ok(match verb {
            Verb::Create { operator, advertise } => {
                crate::instance::create(dir, operator, advertise)?.to_text()
            }
            Verb::Enrol(k) => {
                if enrol_operator(dir, k)? {
                    "enrolled".to_owned()
                } else {
                    "already an operator".to_owned()
                }
            }
            Verb::Revoke(k) => format!("revoked {}", revoke_operator(dir, Revoke::One(k))?),
            Verb::RevokeAllBut(k) => format!("revoked {}", revoke_operator(dir, Revoke::AllBut(k))?),
        }),
        #[cfg(unix)]
        Typist::TheOwner { uid, gid } => as_the_owner(dir, uid, gid, again()?),
    }
}

/// Run `child` — the same verb — as `uid`/`gid`, after giving back a file root
/// left, and return what it said. `Command::uid` drops the supplementary groups
/// too when root sets it.
#[cfg(unix)]
fn as_the_owner(
    dir: &Path,
    uid: u32,
    gid: u32,
    mut child: std::process::Command,
) -> anyhow::Result<String> {
    use std::os::unix::process::CommandExt as _;
    give_back_what_root_left(dir, uid, gid)?;
    let out = child
        .uid(uid)
        .gid(gid)
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "{} belongs to uid {uid}, and a verb typed as root runs as that user; it could \
                 not start ({e}) — is the binary somewhere that user can run it?",
                dir.display()
            )
        })?;
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr);
        let said = said.trim();
        anyhow::bail!("{}", said.strip_prefix("Error: ").unwrap_or(said));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Who may type a verb at `dir`: its owner here, root as its owner, nobody else.
///
/// **Neither verb makes the directory.** The relay makes it, as the user it runs
/// as — systemd's `StateDirectory=` on a host, [`Admission::open`] anywhere else — so
/// a directory that is not there yet is refused, naming the start. A verb that made
/// it made it the typist's: root's `enrol` on a fresh host left `/var/lib/kotton-relay`
/// root's, with a file in it the relay's user could not read until systemd handed
/// the directory back
/// (`TASK-a-relay-state-directory-an-older-release-left-roots-is-handed-back-only-by-systemd-and-nobody-ran-it`).
///
/// One this user cannot look up gets its own sentence, which names no owner because
/// it cannot see one, and says to run as root. Where the effective uid cannot be
/// read (no `/proc`, see [`effective_uid`]) the verb is refused: not knowing whether
/// it is root, it cannot know whether opening the directory's files is safe.
fn who_types(dir: &Path) -> std::io::Result<Typist> {
    let owner = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(std::io::Error::new(
                e.kind(),
                format!(
                    "{} does not exist. The relay makes its state directory, as the user it runs \
                     as, when it starts — `systemctl start kotton-relay` on a host — and the verbs \
                     write into it; start the relay once, then run this again",
                    dir.display()
                ),
            ))
        }
        Err(e) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!(
                    "{} could not be looked up as this user ({e}); run this as root",
                    dir.display()
                ),
            ))
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let me = effective_uid().ok_or_else(|| {
            std::io::Error::other(
                "this process's user could not be read from /proc/self/status, and a verb must \
                 know whether it is root before it opens anything in the state directory",
            )
        })?;
        if me == owner.uid() {
            Ok(Typist::This)
        } else if me == 0 {
            Ok(Typist::TheOwner {
                uid: owner.uid(),
                gid: owner.gid(),
            })
        } else {
            Err(not_the_owner(dir, &owner))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = owner;
        Ok(Typist::This)
    }
}

/// The owner's verb, refused to anyone else — root included, whose verb is
/// [`type_verb`] and runs this as the owner.
fn the_owner_types(dir: &Path) -> anyhow::Result<()> {
    match who_types(dir)? {
        Typist::This => Ok(()),
        #[cfg(unix)]
        Typist::TheOwner { uid, .. } => anyhow::bail!(
            "{} belongs to uid {uid}; root's verb runs as that user and opens nothing there as root",
            dir.display()
        ),
    }
}

/// `operator enrol <key>` as the directory's owner: add one operator and leave the
/// others. A state with no operator is refused and nothing is written: creation
/// is the one way into an empty operator set (RFC-0084 V18, V19).
pub fn enrol_operator(dir: &Path, key_hex: &str) -> anyhow::Result<bool> {
    anyhow::ensure!(
        is_key_hex(key_hex),
        "an operator key is 64 hex characters, the public key the desktop's `mint relay` printed"
    );
    the_owner_types(dir)?;
    let mut keys = read_operators_as_the_owner(dir)?;
    if keys.is_empty() {
        anyhow::bail!(
            "this relay has no operator, so none is added here and nothing was written: a relay is \
             created for its first operator — `kotton-relay create --state-dir {} --operator <key>`",
            dir.display()
        );
    }
    if keys.iter().any(|k| k == key_hex) {
        return Ok(false);
    }
    keys.push(key_hex.to_owned());
    write_operators(dir, &keys)?;
    Ok(true)
}

/// Which operators a revocation ends.
#[derive(Debug, Clone, Copy)]
pub enum Revoke<'a> {
    /// This one, never the last.
    One(&'a str),
    /// Every one but this one, which must be enrolled.
    AllBut(&'a str),
}

/// `operator revoke <key>` or `operator revoke --all --keep <key>` as the
/// directory's owner. The set is never emptied (RFC-0084 V19, fork 3): the last
/// operator is not revoked, and *every one but* a key that is not enrolled
/// revokes nothing. Either refusal writes nothing.
pub fn revoke_operator(dir: &Path, which: Revoke<'_>) -> anyhow::Result<usize> {
    the_owner_types(dir)?;
    let keys = read_operators_as_the_owner(dir)?;
    // A key that is not enrolled is refused, as the vault refuses it, so a
    // typo never reads as a revocation.
    if let Revoke::One(k) = which {
        anyhow::ensure!(
            keys.iter().any(|x| x == k),
            "{k} is not one of this relay's operators, so nothing was revoked"
        );
    }
    let kept: Vec<String> = match which {
        Revoke::One(k) => keys.iter().filter(|x| *x != k).cloned().collect(),
        Revoke::AllBut(k) => keys.iter().filter(|x| *x == k).cloned().collect(),
    };
    if kept.is_empty() {
        anyhow::bail!(match which {
            Revoke::One(_) => "that is this relay's last operator, and a relay is never left \
                 with none: enrol the key that replaces it (`operator enrol <key>`), then revoke this one"
                .to_owned(),
            Revoke::AllBut(_) => "the key to keep is not one of this relay's operators, so nothing is \
                 revoked: a relay is never left with none"
                .to_owned(),
        });
    }
    let removed = keys.len() - kept.len();
    write_operators(dir, &kept)?;
    Ok(removed)
}

/// [`read_operators`], saying which file and as whom when it cannot: under root's
/// verb the reader is the owner, and a symlink the owner planted to a file only
/// root reads is refused here, by the kernel, as it would be to the owner anywhere.
fn read_operators_as_the_owner(dir: &Path) -> anyhow::Result<Vec<String>> {
    use anyhow::Context as _;
    read_operators(dir).with_context(|| {
        format!(
            "{} could not be read as the state directory's owner",
            dir.join(OPERATORS_FILE).display()
        )
    })
}

pub(crate) fn write_operators(dir: &Path, keys: &[String]) -> std::io::Result<()> {
    let mut text = String::new();
    for k in keys {
        text.push_str(k);
        text.push('\n');
    }
    write_private(&dir.join(OPERATORS_FILE), text.as_bytes())
}

/// Write `bytes` to `path` whole or not at all: a temporary file born `0600`, then
/// a rename. Only the directory's owner reaches here ([`the_owner_types`]), so the
/// file is theirs as it is made and the relay, which runs as them, reads it.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Give `operators` back to the directory's owner when it is a file root left
/// there — a verb typed as root by a build from before verbs ran as the owner —
/// so the owner's verb, and the relay, can read it again.
///
/// The one thing root opens in the owner's directory, and it opens it the way that
/// cannot be steered: `O_NOFOLLOW`, so a symlink is refused by the kernel rather
/// than followed; then `fstat` on that descriptor, and `fchown` on the same one,
/// so the file looked at is the file given. It gives only a regular file root owns
/// with one link — a second link would be a root file elsewhere that the owner
/// hard-linked in, and giving it would give that file away. Anything else is not
/// root's to touch and is left for the owner's verb to meet.
#[cfg(unix)]
fn give_back_what_root_left(dir: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(OPERATORS_FILE))
    {
        Ok(f) => f,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENXIO)) =>
        {
            return Ok(())
        }
        Err(e) => return Err(e),
    };
    let m = f.metadata()?;
    if m.file_type().is_file() && m.uid() == 0 && m.nlink() == 1 {
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// The refusal a verb typed as the wrong user gets: the directory's owner, and
/// the command that runs the verb as them.
#[cfg(unix)]
fn not_the_owner(dir: &Path, owner: &std::fs::Metadata) -> std::io::Error {
    use std::os::unix::fs::MetadataExt as _;
    let (uid, gid) = (owner.uid(), owner.gid());
    let (who, run_as) = match user_name(uid) {
        Some(n) => (
            format!("{n} (uid {uid})"),
            format!("runuser -u {n} -- kotton-relay …"),
        ),
        None => (
            format!("uid {uid}"),
            format!("setpriv --reuid={uid} --regid={gid} --clear-groups kotton-relay …"),
        ),
    };
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} belongs to {who}, and a verb typed as this user could not leave an operators' \
             file its owner can read; run this as that user — `{run_as}` — or as root",
            dir.display()
        ),
    )
}

/// This process's effective uid, from the `Uid:` line of `/proc/self/status`
/// (real, effective, saved, filesystem). The relay is released for Linux only,
/// and the one crate it has that could ask the kernel directly, `libc`, would
/// need `unsafe`, which this crate denies. `None` where there is no `/proc`.
#[cfg(unix)]
fn effective_uid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The login name of `uid`, from `/etc/passwd`, if it has one.
#[cfg(unix)]
fn user_name(uid: u32) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            (f.nth(1)?.parse::<u32>().ok()? == uid).then(|| name.to_owned())
        })
}

pub(crate) fn is_key_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_key(b64: &str) -> Result<[u8; 32], String> {
    URL_SAFE_NO_PAD
        .decode(b64)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| "an admission key is 32 bytes, base64url without padding".to_string())
}

/// HMAC-SHA256 of `input` under `key`, as a device computes it.
#[cfg(test)]
pub fn tag(key: &[u8; 32], input: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(input);
    mac.finalize().into_bytes().to_vec()
}

fn verify_tag(key: &[u8; 32], input: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(input);
    // Constant time: a tag that is close is told nothing about how close.
    mac.verify_slice(tag).is_ok()
}

mod opt_key {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(k: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match k {
            Some(k) => s.serialize_some(&URL_SAFE_NO_PAD.encode(k)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let Some(text) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Some)
            .map_err(|_| serde::de::Error::custom("an admission key is 32 bytes"))
    }
}
