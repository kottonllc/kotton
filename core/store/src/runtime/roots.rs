// SPDX-License-Identifier: AGPL-3.0-or-later
//! Roots: what a person's data is divided into.
//!
//! A person does not have *a* store; they have several **roots**. Each is a tree
//! with a name they gave it, a membership, zero or more targets it is kept at,
//! and this device's residency of it. Replication is a function of the
//! containing root and nothing else; this module is the person's half of that
//! sentence — the thing replication is a function *of*.
//!
//! ## What this half does and does not do
//!
//! This is the **store half** of roots: a root is named, and a vault is its
//! target. Nothing here puts a byte on a wire. A root records where it is meant to be
//! kept; the pass that carries it there — replicating a root to its targets
//! under a blinded id — is the wire half, which is not built, and until it
//! exists every root but the migrated one answers [`Kept::NotYetKeptAnywhereButHere`]
//! rather than claiming a copy it does not have. Saying so is the point: a
//! target set that reads as a backup and is not one is the failure this module
//! is built to avoid.
//!
//! ## Why the index is derived rather than stored twice
//!
//! [`Root::CORE`] is the core root, and it is special **by rule, not by
//! record**: its id, its name, its tree, its residency and its target set are
//! all computed. In particular its targets are the union of every other root's,
//! which is *replicated to every target the person has* expressed as an
//! invariant instead of a copy that could disagree with the roots it summarises.
//! So the index holds the other roots and nothing about core, and a new root
//! kept at a new vault marks core for that vault by construction.
//!
//! ## The index is two files, split along the boot boundary
//!
//! It is not one plaintext file. One file would be the one join a provider
//! would most want — every root's name, its members' AIDs and its vaults'
//! handles — sitting in the clear inside the tree the wire half replicates,
//! which Article I forbids a target to hold in a readable form. The index is
//! sealed before it travels, as two halves:
//!
//! - **[`RoutingIndex`]** — `core/roots.routing.json`, plaintext as
//!   `config.toml` is: per root, its id and its targets' handles, and nothing
//!   else. A device that has booted and has never been unlocked reads this, and
//!   can do what a vault does — move sealed bytes to and from known addresses —
//!   while naming nothing.
//! - **The meaning half** — `core/roots.sealed`, sealed under the person's own
//!   keys through [`crate::provider::seal_envelope`], the same envelope every
//!   object in their store is sealed with: per root, the name they gave it, its
//!   members' AIDs, its residency and its tree. [`RootSet::open`] needs the keys
//!   and there is no way to ask it for a name without them.
//!
//! **This is Android's device-encrypted/credential-encrypted split, and iOS's
//! *Protected Until First User Authentication*.** A screen lock is a shell state
//! and evicts nothing: the daemon holds the person's [`UserStore`] — and with it
//! their keys — from the first unlock until logout or shutdown, so delivery
//! continues across a lock. The state this split is for is the third one: booted,
//! never unlocked, where the daemon holds ciphertext, can route it, and can name
//! no root and no member.
//!
//! **The routing half is sealed to the machine where the machine can hold a
//! key, and says on its face where it is not.** The file opens with one ASCII line naming its form —
//! `kotton-roots-routing/1 device-sealed` or `kotton-roots-routing/1 plaintext`
//! — so the concession is legible on the disk that carries it rather than in a
//! comment somewhere else. On a device whose [`CustodyBackend`] binds
//! (`WindowsTpm`, `AppleSecureEnclave`) the body is
//! [`crate::provider::seal_envelope`] under a key derived from a
//! **no-auth-policy** binding's `binding_secret(None)`: the chip reproduces it
//! for this OS user at boot with no credential, so the daemon reads the file
//! cold and a copy of it opens nowhere else. On
//! [`CustodyBackend::None`] — every Linux machine today — the body is the same JSON
//! in the clear, under the `0o700` directory `config.toml` already sits in.
//!
//! **Why this key may be on by default where the vault's is opt-in.** Binding
//! the *vault* changes the recovery story: a cleared TPM leaves the person
//! behind their recovery phrase, so it is theirs to choose. The
//! routing half has no such bargain, because it is a **cache**: the roots it
//! routes are named by the meaning half and the handles it carries are in the
//! person's own `config.toml`. A binding that stops reproducing costs one
//! rebuild at the next unlock, which [`RootSet::open`] performs rather than
//! failing — see [`RoutingHalf`].
//!
//! [`UserStore`]: crate::runtime::user::UserStore
//! [`CustodyBackend`]: kotton_sys::secret::CustodyBackend
//! [`CustodyBackend::None`]: kotton_sys::secret::CustodyBackend::None
//!
//! ## Nothing is re-encrypted, and nothing moves
//!
//! Migration is a marker, not a copy. The existing VFS tree — `data/` under the
//! user's directory, which is what every path the sandbox resolves already lands
//! in — *becomes* the *Personal* root's tree in place, and the vaults the device
//! has already enrolled become that root's targets. No object is read, rewritten
//! or re-sealed. The same rule governs the core root: the identity material, the
//! device set and the settings it carries stay at the paths that hold them today
//! and are **named** by [`Carried`] rather than relocated, because moving them
//! would rewrite the recovery path (a person's own recovery kit reads
//! `users/<id>/recovery.json` by that name) for no protocol gain in a unit
//! that replicates nothing.

use anyhow::{Context, Result};
use hkdf::Hkdf;
use kotton_sys::secret::DeviceBinding;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};

/// The directory, relative to the user's directory, that today's VFS addresses.
///
/// `base/users/<uid>/data` is what `apps.rs` hands the sandbox as
/// `user_vfs_path`, so it is the one tree a guest can name a path in and the one
/// tree the sync pass moves. The migration makes it *Personal*'s, in place.
pub const VFS_TREE: &str = "data";

/// The core root's tree. Holds both halves of the index —
/// [`RootSet::SEALED_FILE`] and [`RoutingIndex::FILE`].
pub const CORE_TREE: &str = "core";

/// Where a root other than the migrated one keeps its tree: `roots/<id>`.
const ROOTS_DIR: &str = "roots";

// ── Targets ───────────────────────────────────────────────────────────────────

/// A vault a root is kept at.
///
/// The `handle` is the one the device's own enrolment already gave it: the vault's `did:key`, as it stands in the membership set with
/// `Role::OwnDevice` and `Posture::BlindStorage`, and as `RemoteBackend::Kotton`
/// records it in `config.toml`. Nothing new is minted here, because a second
/// name for one vault is a second thing that can disagree.
///
/// **This is not the identifier the vault will see.** The id a root
/// presents to any infrastructure is per-target and blinded, and what it is
/// derived from is the wire half's open question. A handle here is local, so it
/// joins nothing at a provider — nothing here sends it off this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// The enrolled vault's DID.
    pub handle: String,
    /// The label the enrolment recorded, for a surface to show. Never an id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Target {
    pub fn new(handle: impl Into<String>, label: Option<String>) -> Self {
        Self {
            handle: handle.into(),
            label,
        }
    }
}

// ── Residency ─────────────────────────────────────────────────────────────────

/// How much of a root this device holds.
///
/// **Never topology**, restated per root: which of these a device chose
/// says nothing about where the root authoritatively lives, and nothing about
/// what any other device sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Residency {
    /// Every byte is here.
    #[default]
    Full,
    /// Bytes are fetched from a target when opened.
    OnDemand,
}

// ── Kept ──────────────────────────────────────────────────────────────────────

/// What the store can honestly say about where a root is kept.
///
/// Three states and not two, because "no copy anywhere else" has two very
/// different causes and a person is owed the difference: they chose it, or the
/// software has not caught up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kept {
    /// No targets. The person chose this device and nothing else.
    ThisDeviceOnly,
    /// Targets recorded, and the pass that runs today carries the root to them.
    Replicated,
    /// Targets recorded and nothing carries the root to them yet.
    ///
    /// The wire half is what changes this. Until then the store says
    /// *not yet kept anywhere but here* rather than letting a recorded target
    /// read as a copy.
    NotYetKeptAnywhereButHere,
}

// ── What the core root carries ────────────────────────────────────────────────

/// One thing the core root holds.
///
/// Enumerated rather than relocated. Each variant already exists on this device
/// at a path something else owns; naming it here is what makes the core root a
/// real set rather than an empty directory, and it is the list the wire half
/// packs. Only [`Carried::RootIndex`] has its bytes inside the core tree today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Carried {
    /// The KEL and the keys that open data, at `users/<id>/`.
    IdentityMaterial,
    /// The device set — who this person's devices are.
    DeviceSet,
    /// The index of the other roots: `core/roots.sealed` and
    /// `core/roots.routing.json`, both written by this module.
    RootIndex,
    /// Settings — `config.toml`.
    Settings,
}

impl Carried {
    /// Everything the core root holds, in its own order.
    pub const ALL: [Carried; 4] = [
        Carried::IdentityMaterial,
        Carried::DeviceSet,
        Carried::RootIndex,
        Carried::Settings,
    ];

    /// Whether this item's bytes are inside the core root's tree today.
    ///
    /// `false` is not a gap in the model — it is where the byte is, stated. The
    /// item is the core root's either way; what has not happened is the move,
    /// and a move is what the wire half needs rather than what this one does.
    pub fn is_in_the_core_tree(&self) -> bool {
        matches!(self, Carried::RootIndex)
    }
}

// ── A root ────────────────────────────────────────────────────────────────────

/// One of a person's roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// A local id. Never presented to infrastructure — see [`Target`].
    pub id: String,
    /// The person's own word for this root.
    pub name: String,
    /// Who may read or write it, their own AID first.
    ///
    /// **A property of the root and of nothing inside it**. There is no
    /// per-path member list here and there is deliberately nowhere to put one;
    /// see [`RootSet::meaning_of_vfs_grant`].
    pub members: Vec<String>,
    /// Where this root is kept off this device. Empty is *This PC*.
    pub targets: Vec<Target>,
    /// How much of it this device holds.
    pub residency: Residency,
    /// The root's tree, relative to the user's directory.
    pub tree: String,
    /// The identity the root belongs to, where that is not the person whose set holds it.
    ///
    /// `None` is **the person** — every root a person makes for themselves, Personal and the
    /// core root included, and every root recorded without an owner. `Some` is another
    /// identity, and the one case today is an org: the project root is
    /// created under the org's identity so that its truth lives with the project and no
    /// member's leaving takes it. The person is in it the way anyone is, by being in
    /// [`members`](Self::members). Ownership is whose signature can delegate authority over
    /// the root — admitting a member takes `org.invite` from this identity; membership is who
    /// may read it. They are two facts, and neither is derived from the other.
    ///
    /// **What an owner changes today, and what it does not.** It changes who may admit people.
    /// It does not change reads, writes, or where the root is kept: the person's copy is sealed
    /// under the person's keys like any root in their set, and its targets are whatever this
    /// set records — none, at creation. An org's root is meant to have the targets the org
    /// rents; who may retarget, rename or remove a root an org owns is not decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// Whose a new root is, for [`RootSet::add`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// The person whose set this is.
    ThePerson,
    /// Another identity — for a project, the org's (`did:key:…`) — which the person holds
    /// the root on behalf of.
    Identity(String),
}

impl Root {
    /// The core root's id. Well-known by rule, because the index that names
    /// every other root lives inside the core root and cannot name it.
    pub const CORE: &'static str = "core";

    /// The name an older migration gave the root it laid over the existing
    /// tree. A device that already carries it keeps it: the store does not
    /// rename a root the person has seen — names are the person's, and a rename by migration is the store naming for them. What
    /// identifies that root is its tree ([`Root::adopts_the_mount`]), never
    /// this word.
    pub const PERSONAL: &'static str = "Personal";

    /// The one root everyone starts with: the person's files on this machine.
    ///
    /// *This computer is the one root everyone starts with.* First run lays
    /// this root over the existing tree ([`RootSet::open`]), and **no open of
    /// the index ever removes it**: retiring a root by this name on every open
    /// would make a root that is there one day and gone the next. It is
    /// not a reserved word: a person may rename this root, or name another
    /// one *This PC*, and both are their choice.
    pub const THIS_PC: &'static str = "This PC";

    /// The identity this root belongs to: [`owner`](Self::owner) where it names one, and
    /// otherwise `own_aid`, the person whose set holds it.
    pub fn owner_or<'a>(&'a self, own_aid: &'a str) -> &'a str {
        self.owner.as_deref().unwrap_or(own_aid)
    }

    /// Whether this is the core root.
    pub fn is_core(&self) -> bool {
        self.id == Self::CORE
    }

    /// Whether this root's tree is the person's own files on this machine —
    /// [`VFS_TREE`], adopted in place on first run.
    ///
    /// The one root a shell reaches through its `files` grant rather than
    /// through `roots.tree`, and the fact a surface draws it by: **found by its
    /// tree, never by its name** (see [`RootSet::personal`]). It is *This PC*,
    /// or *Personal* on a device whose first run named it so, or whatever the
    /// person renamed it to since.
    pub fn adopts_the_mount(&self) -> bool {
        self.tree == VFS_TREE
    }

    /// What the core root holds. Empty for every other root.
    pub fn carries(&self) -> &'static [Carried] {
        if self.is_core() {
            &Carried::ALL
        } else {
            &[]
        }
    }

    /// Where this root is kept, as the store can honestly state it.
    ///
    /// **One tree is replicated today** — [`VFS_TREE`], which `sync_mount` moves
    /// against a configured remote, and which the migration made *Personal*'s.
    /// Every other root, the core root included, has its targets recorded and
    /// nothing that carries it to them. When the wire half lands, this function
    /// is the one place that changes.
    pub fn kept(&self) -> Kept {
        if self.targets.is_empty() {
            Kept::ThisDeviceOnly
        } else if self.tree == VFS_TREE {
            Kept::Replicated
        } else {
            Kept::NotYetKeptAnywhereButHere
        }
    }

    /// This root's tree under `user_dir`.
    pub fn tree_path(&self, user_dir: &Path) -> PathBuf {
        user_dir.join(&self.tree)
    }

    /// This root's tree **when it is a tree of its own** — `roots/<id>`, beside
    /// the VFS mount — and `None` for every other shape a stored `tree` string
    /// can take.
    ///
    /// This is what a person's shell may be handed a directory on through
    /// `roots.tree`, which reads, and writes where the host hands the root
    /// writable (no root, until the owner rules). Three things are excluded, and
    /// each is excluded by not matching rather than by being checked for:
    ///
    /// - **the VFS mount** ([`VFS_TREE`], *Personal*'s tree). What may be done
    ///   in it is decided by the app's `files` grant, through the handle the
    ///   sandbox mints from that grant. A second door onto the same tree that
    ///   did not consult the grant would let an occupant approved to *read* its
    ///   files write them. So there is one door;
    /// - **the core tree** ([`CORE_TREE`]), the index's home, whatever
    ///   root claims it;
    /// - **anything else** an index entry could carry — `.`, `..`, an absolute
    ///   path, a tree not named for its own root. The index is the person's own
    ///   and sealed, so none of these is written by anything today; the join in
    ///   [`tree_path`](Self::tree_path) does not refuse them: a root's tree
    ///   string is joined without being checked.
    ///
    /// The id must be one plain segment of the characters [`new_root_id`]
    /// mints, so `roots/<id>` cannot name anything but a directory of `roots/`.
    pub fn tree_of_its_own(&self, user_dir: &Path) -> Option<PathBuf> {
        let plain = !self.id.is_empty()
            && self.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        (plain && !self.is_core() && self.tree == format!("{ROOTS_DIR}/{}", self.id))
            .then(|| user_dir.join(ROOTS_DIR).join(&self.id))
    }
}

// ── What a VFS grant means against the root set ───────────────────────────────

/// What a capability grant to a path means, read against the roots.
///
/// There is no third answer, and that is the invariant: a grant names software,
/// a membership names a person, and no path inside a root can carry one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantMeaning {
    /// An app's authority over a path inside this root. Adds no member.
    AppCapabilityInside(String),
    /// A path that falls in no root this device knows.
    OutsideEveryRoot,
}

// ── The routing half ──────────────────────────────────────────────────────────

/// One root's addresses: what to call it on the wire, and where it is kept.
///
/// **This is the whole of what a device that has never been unlocked knows
/// about a root**, and the fields are chosen by subtraction rather than by
/// convenience — a name or a member here would be the join denied a
/// provider, sitting in the clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingEntry {
    /// The root's local id — random, never derived from its name, and not the
    /// identifier it presents to a vault.
    ///
    /// **The per-target blinded id is the wire half's and is not here yet.**
    /// This file is where it lands when it exists, because this file is the
    /// addresses; what stands in for it today is a 16-byte random local id,
    /// which joins nothing at a provider because no provider has ever seen it.
    pub id: String,
    /// The handles of the vaults this root is kept at, as `config.toml` already
    /// records them. A handle and nothing else: the label the person gave the
    /// vault is a word of theirs, and it is read back from their config rather
    /// than copied into the index.
    pub targets: Vec<String>,
}

/// The file the routing half deserialises to.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutingIndexFile {
    version: u32,
    roots: Vec<RoutingEntry>,
}

/// The routing half of the index: readable from boot, and naming nothing.
///
/// A device that has booted and has never been unlocked can construct this, and
/// that is all it can construct. With it the daemon can do exactly what a vault
/// does — receive sealed bytes for a root and hold them, and move sealed bytes
/// to and from that root's targets — and it can answer no question about what
/// any root is called or whose it is.
///
/// **The stash is part of the same answer.** Bytes that arrive before the first
/// unlock have to wait somewhere, and "somewhere" must be addressable by an id
/// this half holds. [`RoutingIndex::stash`] writes them under
/// `core/stash/<root id>/`, refuses a root the index does not route, and refuses
/// an envelope name that is not a plain one — a daemon that cannot read the
/// index must not be talked into writing outside it either.
#[derive(Debug, Clone)]
pub struct RoutingIndex {
    entries: Vec<RoutingEntry>,
}

/// What asking for the routing half answered.
///
/// Three states rather than an index-or-error, because the two failures mean
/// opposite things and only one of them is recoverable by reading harder.
///
/// A device that has never been unlocked reads this directly; an unlocked one
/// gets it through [`RootSet::open`], which joins it to the meaning half.
#[derive(Debug)]
pub enum RoutingHalf {
    /// The file was there and this device opened it.
    Open(RoutingIndex),
    /// Nothing has ever written one. A device on its very first boot, and a
    /// true answer rather than an error.
    Absent,
    /// The file is there and this device cannot open it — the binding was
    /// cleared, the disk was moved, or the bytes are not a routing half at all.
    ///
    /// **Not an error.** It is a cache of what the meaning half knows, so the
    /// answer is to rebuild it at the next unlock, which is what
    /// [`RootSet::open`] does.
    Unopenable,
}

impl RoutingHalf {
    /// The index, for the one state that has one.
    ///
    /// A cold daemon that gets `None` here can route nothing — which is the
    /// honest answer, and the reason this is an `Option` rather than an empty
    /// index: an empty index and *the file would not open* are different facts,
    /// and conflating them is how a rebuild becomes a silent forgetting.
    pub fn routes(&self) -> Option<&RoutingIndex> {
        match self {
            Self::Open(index) => Some(index),
            Self::Absent | Self::Unopenable => None,
        }
    }
}

/// The HKDF info string the routing half's key is derived under.
///
/// **Stable forever**: changing it makes every bound device's routing half
/// unopenable, which costs a rebuild on each of them. Separate from every other
/// use of the binding secret so that the vault's binding and this cache's key
/// are not the same 32 bytes wearing two hats.
const ROUTING_KEY_INFO: &str = "kotton:roots-routing:v1";

/// The first line of every routing half this code writes.
const ROUTING_MAGIC: &str = "kotton-roots-routing/1";
/// The word that line ends in when the body is in the clear.
const AT_REST_PLAINTEXT: &str = "plaintext";
/// The word that line ends in when the body is sealed to this machine.
const AT_REST_SEALED: &str = "device-sealed";

/// The key the routing half seals under on a device that binds, or `None`.
///
/// `None` for three different devices, and the difference does not matter to
/// the caller: one with no binding at all, one whose [`CustodyBackend`] does
/// not bind ([`CustodyBackend::None`], every Linux machine today), and one whose
/// hardware refused. All three write and read the half in the clear, and the
/// file's first line says so.
///
/// **`binding_secret(None)` and no credential**, which is the whole of why this
/// can be on by default: the record's binding carries no auth policy, so the
/// chip reproduces the secret for this OS user at boot without anybody typing.
/// A binding that wanted a credential would make this file unreadable exactly
/// when it is needed, which is before the first unlock.
///
/// [`CustodyBackend`]: kotton_sys::secret::CustodyBackend
/// [`CustodyBackend::None`]: kotton_sys::secret::CustodyBackend::None
fn routing_key(binding: Option<&dyn DeviceBinding>) -> Option<[u8; 32]> {
    let binding = binding?;
    if !binding.backend().binds_device() {
        return None;
    }
    let secret = match binding.binding_secret(None) {
        Ok(secret) => secret,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "store: this device binds, and its hardware would not reproduce the \
                 binding secret — the routing half of the roots index will be written \
                 in the clear until the binding is repaired, and its first line says so"
            );
            return None;
        }
    };
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &secret)
        .expand(ROUTING_KEY_INFO.as_bytes(), &mut key)
        .expect("HKDF expand is infallible for 32B output");
    Some(key)
}

impl RoutingIndex {
    /// The routing half's file name, inside the core root's tree.
    ///
    /// The name is unchanged from when the body was always JSON, and it is a
    /// name rather than a promise: a migration that renamed it would leave
    /// every existing device with a file nothing reads. What the body is, is
    /// the file's own first line.
    pub const FILE: &'static str = "roots.routing.json";

    /// The directory sealed envelopes wait in, inside the core root's tree.
    const STASH_DIR: &'static str = "stash";

    const VERSION: u32 = 1;

    /// Where the routing half lives under `user_dir`.
    pub fn path(user_dir: &Path) -> PathBuf {
        user_dir.join(CORE_TREE).join(Self::FILE)
    }

    /// The AAD the routing half's body is sealed under, where it is sealed.
    ///
    /// The path relative to the user's directory, exactly as
    /// [`RootSet::sealed_aad`] takes it and for the same reason: a blob that
    /// authenticates where it sits rather than which machine it sits on.
    fn routing_aad() -> Vec<u8> {
        crate::provider::path_aad(Path::new(CORE_TREE).join(Self::FILE).as_path())
    }

    /// Read the routing half. **No person's keys, and no way to ask for a
    /// name.**
    ///
    /// `binding` is this device's no-auth-policy binding where it has one; a
    /// device with none passes `None` and reads the clear form. Passing the
    /// wrong binding, or none where the file is sealed, answers
    /// [`RoutingHalf::Unopenable`] rather than an error — telling a caller
    /// which of those it was is telling them something only the right key
    /// should be able to learn.
    ///
    /// **A file with no first line is read as the clear form.** That is the
    /// shape the split wrote before this one, and refusing it would make every
    /// device that had already been unlocked rebuild once for nothing. The next
    /// save gives it a first line.
    pub fn read(user_dir: &Path, binding: Option<&dyn DeviceBinding>) -> Result<RoutingHalf> {
        Self::read_under(user_dir, routing_key(binding).as_ref())
    }

    /// [`read`](Self::read) with the key already derived, which is how
    /// [`RootSet`] reads it: the derivation is a call into hardware and the set
    /// makes it once, at open.
    fn read_under(user_dir: &Path, key: Option<&[u8; 32]>) -> Result<RoutingHalf> {
        let path = Self::path(user_dir);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RoutingHalf::Absent),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let body = match split_at_rest_header(&raw) {
            Some((AT_REST_PLAINTEXT, body)) => body.to_vec(),
            Some((AT_REST_SEALED, body)) => {
                let Some(key) = key else {
                    tracing::warn!(
                        path = %path.display(),
                        "store: the routing half of the roots index is sealed to a device \
                         binding this daemon has not got"
                    );
                    return Ok(RoutingHalf::Unopenable);
                };
                match crate::provider::open_envelope(key, &Self::routing_aad(), body) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        tracing::warn!(
                            path = %path.display(),
                            "store: the routing half of the roots index did not open under \
                             this device's binding"
                        );
                        return Ok(RoutingHalf::Unopenable);
                    }
                }
            }
            Some((other, _)) => {
                tracing::warn!(
                    path = %path.display(),
                    form = %other,
                    "store: the routing half of the roots index names a form this build \
                     does not know"
                );
                return Ok(RoutingHalf::Unopenable);
            }
            // The headerless shape the split wrote first. Read, then re-written
            // with a first line by the next save.
            None => raw,
        };
        match serde_json::from_slice::<RoutingIndexFile>(&body) {
            Ok(file) => Ok(RoutingHalf::Open(Self {
                entries: file.roots,
            })),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "store: the routing half of the roots index is not one"
                );
                Ok(RoutingHalf::Unopenable)
            }
        }
    }

    /// Every root this device can route, by id, with its targets' handles.
    pub fn entries(&self) -> &[RoutingEntry] {
        &self.entries
    }

    /// Where one root's bytes are kept off this device, or `None` for a root
    /// this index does not route.
    pub fn targets_of(&self, root_id: &str) -> Option<&[String]> {
        self.entries
            .iter()
            .find(|e| e.id == root_id)
            .map(|e| e.targets.as_slice())
    }

    /// Hold a sealed envelope for a root until somebody can open it.
    ///
    /// The bytes are written exactly as they arrived. Nothing here opens them,
    /// and nothing here can: the daemon that calls this before the first unlock
    /// holds no key, which is the property the split exists to make true rather
    /// than to promise.
    ///
    /// Refuses a root this index does not route, and an `envelope` that is
    /// anything but a plain name — the two ways a caller with no key could
    /// otherwise choose where the daemon writes.
    pub fn stash(&self, user_dir: &Path, root_id: &str, envelope: &str, sealed: &[u8]) -> Result<PathBuf> {
        let dir = self.stash_dir(user_dir, root_id)?;
        let name = plain_name(envelope)?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(name);
        std::fs::write(&path, sealed)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    /// The envelopes waiting for one root, oldest name first. Empty for a root
    /// nothing has arrived for.
    pub fn stashed(&self, user_dir: &Path, root_id: &str) -> Result<Vec<String>> {
        let dir = self.stash_dir(user_dir, root_id)?;
        let mut names: Vec<String> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        names.sort();
        Ok(names)
    }

    /// One waiting envelope's bytes, still sealed.
    pub fn stashed_bytes(&self, user_dir: &Path, root_id: &str, envelope: &str) -> Result<Vec<u8>> {
        let path = self.stash_dir(user_dir, root_id)?.join(plain_name(envelope)?);
        std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    /// Where one root's envelopes wait, for a root this index routes.
    fn stash_dir(&self, user_dir: &Path, root_id: &str) -> Result<PathBuf> {
        if self.targets_of(root_id).is_none() {
            anyhow::bail!("this device does not route a root with that id");
        }
        Ok(user_dir
            .join(CORE_TREE)
            .join(Self::STASH_DIR)
            .join(plain_name(root_id)?))
    }

    /// Write the routing half, derived from the roots the meaning half names.
    ///
    /// `key` is [`routing_key`]'s answer for this device: `Some` seals the body
    /// to the machine, `None` writes it in the clear. Either way the file opens
    /// with one ASCII line saying which, so a person holding the disk can read
    /// off what protects it without running anything.
    ///
    /// Private because the two halves are written together by
    /// [`RootSet::save`]: a routing entry for a root nothing can name is a place
    /// bytes could arrive and never be opened, and two writers is how the halves
    /// would come to disagree.
    fn write(user_dir: &Path, roots: &[Root], key: Option<&[u8; 32]>) -> Result<()> {
        let file = RoutingIndexFile {
            version: Self::VERSION,
            roots: roots
                .iter()
                .map(|r| RoutingEntry {
                    id: r.id.clone(),
                    targets: r.targets.iter().map(|t| t.handle.clone()).collect(),
                })
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .context("serialising the routing half of the root index")?;
        let mut bytes = Vec::new();
        match key {
            Some(key) => {
                bytes.extend_from_slice(format!("{ROUTING_MAGIC} {AT_REST_SEALED}\n").as_bytes());
                let sealed = crate::provider::seal_envelope(key, &Self::routing_aad(), &json)
                    .map_err(|e| anyhow::anyhow!("sealing the routing half: {e}"))?;
                bytes.extend_from_slice(&sealed);
            }
            None => {
                bytes
                    .extend_from_slice(format!("{ROUTING_MAGIC} {AT_REST_PLAINTEXT}\n").as_bytes());
                bytes.extend_from_slice(&json);
            }
        }
        write_durably(&Self::path(user_dir), &bytes)
    }
}

/// The form word off a routing half's first line, and the body after it.
///
/// `None` for bytes with no such line — the headerless shape the split wrote
/// before the form was stated, which [`RoutingIndex::read_under`] reads as the
/// clear form.
fn split_at_rest_header(raw: &[u8]) -> Option<(&str, &[u8])> {
    let end = raw.iter().position(|b| *b == b'\n')?;
    let line = std::str::from_utf8(&raw[..end]).ok()?;
    let form = line.strip_prefix(ROUTING_MAGIC)?.trim();
    Some((form, &raw[end + 1..]))
}

/// Write `bytes` to `path` so that a crash leaves either the old file or the
/// new one, and never half of either.
///
/// A temporary name beside it, fsynced, then renamed over the target, then the
/// directory fsynced so the rename itself is on the disk. Both halves of the
/// roots index go through here; `std::fs::write` could truncate a file and then
/// fail, leaving the person with neither the old index nor a new one.
///
/// **The directory fsync is Unix-only** because Windows has no handle on a
/// directory to sync; `MoveFileEx` with replace semantics, which
/// [`std::fs::rename`] uses there, is the durability this gets on that
/// platform.
pub(crate) fn write_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no directory to write in", path.display()))?;
    let temp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        new_root_id()
    ));
    let mut file = std::fs::File::create(&temp)
        .with_context(|| format!("creating {}", temp.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", temp.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temp.display()))?;
    drop(file);
    if let Err(e) = std::fs::rename(&temp, path) {
        // The temporary is this function's litter, so it is this function's to
        // sweep: left behind it would sit in the core root's tree forever,
        // holding a copy of what the file was supposed to become.
        let _ = std::fs::remove_file(&temp);
        return Err(e).with_context(|| format!("renaming {} into place", temp.display()));
    }
    #[cfg(unix)]
    {
        if let Ok(handle) = std::fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
}

/// A single path segment with nothing clever in it.
///
/// The caller of [`RoutingIndex::stash`] before the first unlock is handling
/// bytes from the network, and the name attached to them is as much the
/// network's as the bytes are. `..`, a separator, or an empty string is refused
/// rather than sanitised, because a sanitised name is a name that still landed
/// somewhere nobody chose.
pub(crate) fn plain_name(segment: &str) -> Result<&str> {
    let ok = !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        anyhow::bail!("`{segment}` is not a name this may be written under");
    }
    Ok(segment)
}

// ── The set ───────────────────────────────────────────────────────────────────

/// The meaning half's file, sealed under the person's own keys.
///
/// Every field here is something a provider would want and may not have: what a
/// root is called, and whose it is — and where each root is kept.
///
/// **The targets are here, and this is the copy that decides.** A second copy
/// is a second thing that can disagree; but without it the per-root assignment
/// would live only in the routing half — which is a cache, and may be bound to
/// a chip that gets cleared — so a rebuild would have to guess it, and the
/// guess would be *every root at every vault*. The disagreement is answered by precedence rather than avoided: this half is
/// written first and is the authority, and the routing half is rewritten from
/// it whenever the two differ. Sealed under the person's keys, the handles here
/// are no more visible at rest than the names beside them.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeaningIndexFile {
    /// Bumped when the shape changes in a way an older reader cannot handle.
    version: u32,
    /// Every root except core, which is computed. See the module note.
    roots: Vec<RootMeaning>,
}

/// What one root is, as opposed to where it is.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RootMeaning {
    id: String,
    name: String,
    members: Vec<String>,
    residency: Residency,
    tree: String,
    /// The handles of the vaults this root is kept at. `None` only in an older
    /// meaning half, which did not carry them; the next save
    /// writes them. `Some(vec![])` is a root the person keeps nowhere but here,
    /// and is a different fact from `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    targets: Option<Vec<String>>,
    /// See [`Root::owner`]. Absent is the person, which is every meaning half written
    /// before an owner could be anyone else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
}

/// The file `roots.json` deserialised to, before the index was split.
///
/// Read once, by [`RootSet::open`], to move a device's index onto the two
/// halves; nothing writes this shape any more. Its `version` is not read: there
/// was one version, and a reader that refused an unknown one would refuse the
/// very file it exists to get rid of.
#[derive(Debug, Clone, Deserialize)]
struct LegacyRootIndexFile {
    roots: Vec<Root>,
}

/// A person's roots, as this device knows them **once it has been unlocked**.
///
/// Holding one is holding the meaning half open: every method here can name a
/// root or a member, so constructing one takes the person's keys and there is
/// no constructor that does not. A device that has never been unlocked gets
/// [`RoutingIndex`] instead, which can route and cannot name.
///
/// *The set of roots is known only inside the person's own encrypted state,
/// never as a provider's index* is, in this half, two facts: no code
/// path writes it outward, and the bytes it writes at rest are sealed under the
/// person's own keys.
#[derive(Clone)]
pub struct RootSet {
    user_dir: PathBuf,
    roots: Vec<Root>,
    own_aid: String,
    /// The key this person's own objects seal under, copied out of
    /// [`kotton_context::SealingKeys`] at open so a `RootSet` can re-seal the
    /// meaning half on every save without borrowing the context for its
    /// lifetime. It is the CEK and not the pair: this file is one blob at a
    /// known path, so there is no key to blind.
    cek: [u8; 32],
    /// The key the **routing** half seals under, or `None` on a device that
    /// does not bind. Derived once at [`open`](Self::open), for the same reason
    /// `cek` is copied: [`routing_key`] is a call into a TPM or a secure
    /// enclave, and a save is not the place to make one.
    routing_key: Option<[u8; 32]>,
}

/// Printed without either key.
///
/// The derived form put `cek` — the key every object in this person's store
/// seals under — into anything that formatted a `RootSet`, which is a log line,
/// a panic message, or an `anyhow` chain away from being written down. This
/// struct holds two keys, and the right number of keys in a `Debug` output is
/// none.
impl std::fmt::Debug for RootSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootSet")
            .field("user_dir", &self.user_dir)
            .field("roots", &self.roots)
            .field("own_aid", &self.own_aid)
            .field("cek", &"<redacted>")
            .field("routing_key", &self.routing_key.map(|_| "<redacted>"))
            .finish()
    }
}

impl RootSet {
    /// The meaning half, inside the core root's tree.
    pub const SEALED_FILE: &'static str = "roots.sealed";

    /// The plaintext index this one replaced, read once and removed.
    const LEGACY_INDEX_FILE: &'static str = "roots.json";

    const VERSION: u32 = 1;

    /// Where the meaning half lives under `user_dir`.
    pub fn sealed_path(user_dir: &Path) -> PathBuf {
        user_dir.join(CORE_TREE).join(Self::SEALED_FILE)
    }

    /// The AAD the meaning half is sealed under.
    ///
    /// The path **relative to the user's directory**, so the blob authenticates
    /// where it sits inside the core root rather than where this device happens
    /// to keep that person — the same blob has to open after it has travelled to
    /// a target and back, and an absolute path would differ on every machine.
    fn sealed_aad() -> Vec<u8> {
        crate::provider::path_aad(Path::new(CORE_TREE).join(Self::SEALED_FILE).as_path())
    }

    /// Open this person's roots, migrating on first run.
    ///
    /// `own_aid` is the person's AID, supplied by the caller: the
    /// store does not derive identity, and the AID is replayed from the KEL by
    /// the domain that owns it. `enrolled_targets` are the vaults this device
    /// has already enrolled; on first run they become the adopting root's. After first run
    /// they only label targets: which root is kept where is read from the
    /// meaning half, and a rebuilt routing half takes no target from here (see
    /// `read_halves`).
    ///
    /// **First run lays down the core root and one root named *This PC* over
    /// the existing tree, and nothing else.** *This computer is the one root
    /// everyone starts with.* That root is
    /// the person's files on this machine — the tree adopted in place, today's
    /// `data/` — with the vaults this device has enrolled as its targets, and
    /// no targets at all on a device that has enrolled none.
    ///
    /// **And no open ever removes a root called *This PC*.** The product does
    /// name one root for everyone, and it is this computer; and a migration
    /// that removes a row on the strength of its name is the one shape a store
    /// that holds the person's roots must not have. What holds is *one tree,
    /// one row*: *This PC* is the name of
    /// the adopting root, never a second root beside it, so the file browser
    /// lists this computer once.
    ///
    /// A device whose index already carries a root named *Personal* keeps that
    /// name. The store does not rename a root the person has seen; what
    /// makes it the adopting root is its tree ([`Root::adopts_the_mount`]), and
    /// a person who wants it called *This PC* renames it.
    ///
    /// Nothing is read out of `data/` and nothing is re-encrypted.
    ///
    /// **`keys` is the person's own sealing material, and it is not optional.**
    /// Every root this returns carries a name and a membership, so a caller that
    /// could construct one without the keys would be a caller that reads the
    /// meaning half without them. A device that has booted and has never been
    /// unlocked has no keys to pass and wants [`RoutingIndex::read`] instead.
    ///
    /// **A `core/roots.json` left by an earlier version is moved onto the two
    /// halves and deleted.** Deleting it is the unit: the whole point is that
    /// those bytes stop being readable at rest, and a plaintext copy left beside
    /// the sealed one would keep every property this change exists to get.
    pub fn open(
        user_dir: &Path,
        own_aid: &str,
        enrolled_targets: &[Target],
        keys: kotton_context::SealingKeys<'_>,
        binding: Option<&dyn DeviceBinding>,
    ) -> Result<Self> {
        let cek = *keys.cek;
        let routing_key = routing_key(binding);
        let legacy = user_dir.join(CORE_TREE).join(Self::LEGACY_INDEX_FILE);
        if legacy.exists() {
            let text = std::fs::read_to_string(&legacy)
                .with_context(|| format!("reading {}", legacy.display()))?;
            let file: LegacyRootIndexFile = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", legacy.display()))?;
            let set = Self {
                user_dir: user_dir.to_path_buf(),
                roots: file.roots,
                own_aid: own_aid.to_string(),
                cek,
                routing_key,
            };
            set.save()?;
            std::fs::remove_file(&legacy)
                .with_context(|| format!("removing {}", legacy.display()))?;
            tracing::info!(
                path = %legacy.display(),
                "store: the roots index was plaintext and is now sealed — the meaning \
                 half is under this person's keys and the routing half carries \
                 addresses only (RFC-0071 R11)"
            );
            return Ok(set);
        }

        if Self::sealed_path(user_dir).exists() {
            let (roots, rebuilt) =
                Self::read_halves(user_dir, &cek, enrolled_targets, routing_key.as_ref())?;
            let set = Self {
                user_dir: user_dir.to_path_buf(),
                roots,
                own_aid: own_aid.to_string(),
                cek,
                routing_key,
            };
            // A rebuilt routing half is written back here rather than at the
            // next change, because the thing that reads it is a daemon that has
            // not been unlocked — and this is the unlock.
            if rebuilt {
                set.save()?;
            }
            return Ok(set);
        }

        let this_pc = Root {
            id: new_root_id(),
            name: Root::THIS_PC.to_string(),
            members: vec![own_aid.to_string()],
            targets: enrolled_targets.to_vec(),
            residency: Residency::Full,
            // In place. The marker is this string; no byte moves.
            tree: VFS_TREE.to_string(),
            owner: None,
        };

        let set = Self {
            user_dir: user_dir.to_path_buf(),
            roots: vec![this_pc],
            own_aid: own_aid.to_string(),
            cek,
            routing_key,
        };
        set.save()?;
        Ok(set)
    }

    /// Read both halves and join them back into whole roots.
    ///
    /// **The meaning half decides which roots exist.** A routing entry with no
    /// meaning is a leftover — bytes could arrive for it and nobody could ever
    /// open them — so it is logged and dropped rather than silently kept, and
    /// the next [`save`](Self::save) writes the routing half from the roots that
    /// do exist.
    ///
    /// A target's label is **read back from the person's enrolled vaults**
    /// rather than stored: it is a word of theirs about a vault, `config.toml`
    /// already holds it beside the handle, and a copy in the index would be a
    /// second one that could disagree — which is the same argument
    /// [`enrolled_targets`] already makes about the handle itself.
    ///
    /// **Which root is kept where is read from the meaning half.** It carries
    /// each root's targets and is the authority; the routing half is the copy a
    /// cold daemon reads, and when the two differ — a save interrupted between
    /// the two files — the roots come back as the meaning half says and are
    /// reported as rebuilt, so the routing half is rewritten from them.
    ///
    /// **A routing half that will not open is rebuilt, not an error.** Which is
    /// the whole reason the routing half may be bound to a machine at all: it
    /// is a cache, and everything in it is in the half that just opened — so a
    /// cleared TPM or a moved disk costs a rebuild here and nothing anywhere
    /// else. The same answer covers a routing half that is *absent*, which is
    /// what a save interrupted between the two files used to leave behind: the
    /// targets come back rather than as the empty list the next save would have
    /// written down.
    ///
    /// **A rebuild never widens.** It takes targets from the meaning half, not
    /// from `enrolled` — which would give every root every vault, so a root the
    /// person had kept on this device only would come back marked for their
    /// vaults. `enrolled` is used for labels and nothing else. An older meaning
    /// half, which carries no targets, beside a routing half that will not open, has
    /// no record of the assignment anywhere: its roots come back **kept on this
    /// device only**, which the *Kept* column shows and the warning names, and
    /// the person targets them again. Forgetting a target is visible and theirs
    /// to undo; inventing one would send their bytes somewhere they did not
    /// choose.
    ///
    /// Returns the roots and whether they were rebuilt, because a rebuild has to
    /// be written back before the daemon that reads the routing half next boots.
    fn read_halves(
        user_dir: &Path,
        cek: &[u8; 32],
        enrolled: &[Target],
        routing_key: Option<&[u8; 32]>,
    ) -> Result<(Vec<Root>, bool)> {
        let path = Self::sealed_path(user_dir);
        let blob = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let plaintext = crate::provider::open_envelope(cek, &Self::sealed_aad(), &blob)
            .map_err(|e| anyhow::anyhow!("opening {}: {e}", path.display()))?;
        let meaning: MeaningIndexFile = serde_json::from_slice(&plaintext)
            .with_context(|| format!("parsing the meaning half of {}", path.display()))?;
        let half = RoutingIndex::read_under(user_dir, routing_key)?;

        let routing = half.routes();
        let label_of = |handle: &str| {
            enrolled
                .iter()
                .find(|t| t.handle == handle)
                .and_then(|t| t.label.clone())
        };

        if let Some(routing) = routing {
            for entry in routing.entries() {
                if !meaning.roots.iter().any(|r| r.id == entry.id) {
                    tracing::warn!(
                        root = %entry.id,
                        "store: the routing half routes a root the meaning half does not \
                         name; dropping the route, since bytes arriving for it could never \
                         be opened"
                    );
                }
            }
        } else {
            let unrecorded = meaning.roots.iter().filter(|m| m.targets.is_none()).count();
            tracing::warn!(
                roots = meaning.roots.len(),
                unrecorded,
                "store: the routing half of the roots index could not be read, so it is \
                 being rebuilt from the meaning half. A root whose meaning half predates \
                 the targets being recorded there comes back kept on this device only \
                 rather than at every vault — check where you meant to keep any root \
                 shown that way (RFC-0071 R13)"
            );
        }

        // Rebuilt means the routing half on the disk is not what these roots
        // say: it could not be read, or it disagrees with the authority, or the
        // authority is an older meaning half that the next save should complete.
        let mut rebuilt = routing.is_none();
        let roots = meaning
            .roots
            .into_iter()
            .map(|m| {
                let routed = routing.and_then(|r| r.targets_of(&m.id));
                let handles: Vec<String> = match (&m.targets, routed) {
                    (Some(recorded), routed) => {
                        if routed != Some(recorded.as_slice()) {
                            rebuilt = true;
                        }
                        recorded.clone()
                    }
                    // An older meaning half: the routing half is the only record
                    // of the assignment, and the next save copies it across.
                    (None, Some(routed)) => {
                        rebuilt = true;
                        routed.to_vec()
                    }
                    // Nowhere records it. Kept on this device only, never widened.
                    (None, None) => {
                        rebuilt = true;
                        Vec::new()
                    }
                };
                Root {
                    targets: handles
                        .iter()
                        .map(|handle| Target::new(handle, label_of(handle)))
                        .collect(),
                    id: m.id,
                    name: m.name,
                    members: m.members,
                    residency: m.residency,
                    tree: m.tree,
                    owner: m.owner,
                }
            })
            .collect();
        Ok((roots, rebuilt))
    }

    /// Persist **both halves** of the index, creating the core root's tree and
    /// each root's tree.
    ///
    /// The meaning half is sealed under this person's CEK through the same
    /// envelope every object in their store uses; the routing half is derived
    /// from the same roots and sealed under this device's binding where it has
    /// one, in the clear where it has not, saying which on its first line. They
    /// are written by one function because a device that holds one without the
    /// other is a device that either routes bytes nobody can open or holds roots
    /// it cannot reach.
    ///
    /// **Each half is written to a temporary name and renamed into place**, with
    /// the file and its directory fsynced, so an interrupted save leaves whole
    /// files rather than a truncated one.
    /// The window *between* the two renames is not closed by this and cannot be
    /// by any number of renames — that is two files, and closing it is one file
    /// or a journal. What makes the window survivable is the other half of the
    /// same repair: a routing half that is missing when the meaning half is
    /// there is rebuilt when the halves are joined back up, rather than read as
    /// *routes nothing*.
    ///
    /// `data/` is created by `UserStore::create` and is not re-created here —
    /// the migration must not be able to lay a fresh tree over the one it is
    /// supposed to be adopting.
    pub fn save(&self) -> Result<()> {
        let core_dir = self.user_dir.join(CORE_TREE);
        std::fs::create_dir_all(&core_dir)
            .with_context(|| format!("creating {}", core_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&core_dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("permissions on {}", core_dir.display()))?;
        }
        for root in &self.roots {
            if root.tree == VFS_TREE {
                continue;
            }
            let dir = root.tree_path(&self.user_dir);
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let meaning = MeaningIndexFile {
            version: Self::VERSION,
            roots: self
                .roots
                .iter()
                .map(|r| RootMeaning {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    members: r.members.clone(),
                    residency: r.residency,
                    tree: r.tree.clone(),
                    targets: Some(r.targets.iter().map(|t| t.handle.clone()).collect()),
                    owner: r.owner.clone(),
                })
                .collect(),
        };
        let plaintext =
            serde_json::to_vec(&meaning).context("serialising the meaning half of the root index")?;
        let sealed = crate::provider::seal_envelope(&self.cek, &Self::sealed_aad(), &plaintext)
            .map_err(|e| anyhow::anyhow!("sealing the root index: {e}"))?;
        write_durably(&Self::sealed_path(&self.user_dir), &sealed)?;

        // Both halves, one write, in this order: a routing entry with no
        // meaning beside it is a place bytes can arrive and never be opened, so
        // the half that can name a root lands first.
        RoutingIndex::write(&self.user_dir, &self.roots, self.routing_key.as_ref())?;
        Ok(())
    }

    /// The core root, computed rather than stored.
    ///
    /// Held in full on this device — [`Residency::Full`] and not a choice — and
    /// marked for every target the person has, which is the union of the other
    /// roots' target sets rather than a second list that could fall out of step
    /// with them.
    pub fn core(&self) -> Root {
        let mut targets: Vec<Target> = Vec::new();
        for root in &self.roots {
            for target in &root.targets {
                if !targets.iter().any(|t| t.handle == target.handle) {
                    targets.push(target.clone());
                }
            }
        }
        Root {
            id: Root::CORE.to_string(),
            name: "Core".to_string(),
            members: vec![self.own_aid.clone()],
            targets,
            residency: Residency::Full,
            tree: CORE_TREE.to_string(),
            owner: None,
        }
    }

    /// Every root, **core first** (it exists first, and a reader of this
    /// list should meet it before anything it indexes).
    pub fn all(&self) -> Vec<Root> {
        let mut out = vec![self.core()];
        out.extend(self.roots.iter().cloned());
        out
    }

    /// One root by id, core included.
    pub fn get(&self, id: &str) -> Option<Root> {
        self.all().into_iter().find(|r| r.id == id)
    }

    /// Who may read or write a root.
    pub fn members_of(&self, id: &str) -> Option<Vec<String>> {
        self.get(id).map(|r| r.members)
    }

    /// The root today's records belong to: the one that adopted [`VFS_TREE`]
    /// in place — *This PC*, or *Personal* on a device whose first run named it
    /// so ([`Root::PERSONAL`]).
    ///
    /// **Found by its tree, never by its name.** A person may rename it, and a
    /// root they name *Personal* or *This PC* later is not it. The adopted tree
    /// is the one fact about this root that no rename moves, and it is the same
    /// marker its records are adopted by: an unmarked record is this root's, as
    /// an unprefixed path is. The name of the accessor is the record
    /// vocabulary's (its *personal* selection), not the root's label.
    pub fn personal(&self) -> Option<Root> {
        self.roots.iter().find(|r| r.adopts_the_mount()).cloned()
    }

    /// Every root `aid` is a member of, by id — which is every root `aid` may
    /// read. Never the core root: it holds the index and identity
    /// material, and no records.
    pub fn member_roots(&self, aid: &str) -> Vec<String> {
        self.roots
            .iter()
            .filter(|r| r.members.iter().any(|m| m == aid))
            .map(|r| r.id.clone())
            .collect()
    }

    /// Record a root the person has named, whose it is, and its members and targets.
    ///
    /// **The one door to a second root.** Its first production caller is the project root
    /// (the project's records, imported into a root), which is owned by an org's
    /// identity: [`Owner::Identity`]. Every root a person makes for themselves is
    /// [`Owner::ThePerson`], and is recorded with no owner at all, as every root was before.
    ///
    /// Nothing in this module replicates it, and [`Root::kept`] says so
    /// rather than pretending. Returns the new root's id.
    pub fn add(
        &mut self,
        name: impl Into<String>,
        owner: Owner,
        members: Vec<String>,
        targets: Vec<Target>,
        residency: Residency,
    ) -> Result<String> {
        let id = new_root_id();
        let root = Root {
            tree: format!("{ROOTS_DIR}/{id}"),
            id: id.clone(),
            name: name.into(),
            members,
            targets,
            residency,
            owner: match owner {
                Owner::ThePerson => None,
                Owner::Identity(identity) => Some(identity),
            },
        };
        self.roots.push(root);
        self.save()?;
        Ok(id)
    }

    /// Add `member` to a root's membership, and save. `Ok(false)` when they were
    /// already in it.
    ///
    /// Refused for the core root, whose one member is the person by rule, and for an
    /// id this set does not hold. **Who may call this is not this function's question**: the
    /// caller holds the authority to admit someone — for a root an org owns, the org's
    /// `org.invite` delegated to the person — and this records the result.
    pub fn add_member(&mut self, root_id: &str, member: &str) -> Result<bool> {
        let root = self
            .roots
            .iter_mut()
            .find(|r| r.id == root_id)
            .ok_or_else(|| anyhow::anyhow!("no root with that id to add a member to"))?;
        if root.members.iter().any(|m| m == member) {
            return Ok(false);
        }
        root.members.push(member.to_owned());
        self.save()?;
        Ok(true)
    }

    /// Which root a VFS path falls inside.
    ///
    /// Today the VFS addresses exactly one tree — [`VFS_TREE`], the one the
    /// migration made *Personal*'s — so every path a guest can name is inside
    /// that root. The other roots have trees of their own and no VFS prefix yet;
    /// when the browser can address them this is the one function that changes.
    ///
    /// **It discards `path`, and that is the whole of the mapping.** Naming the
    /// parameter is the honest form: the signature is the one the browser half
    /// needs, and the body is the truth while there is one addressable tree.
    /// The consequence is that this function cannot return `None` on a tree that
    /// has been migrated, so [`GrantMeaning::OutsideEveryRoot`] is reachable
    /// only through a grant that is not a VFS grant at all — which is what
    /// `meaning_of_vfs_grant`'s test exercises, and what it says it exercises.
    /// Giving the other roots a VFS prefix is a design choice not made, so
    /// this does not guess at one.
    pub fn root_of_vfs_path(&self, _path: &str) -> Option<Root> {
        self.roots.iter().find(|r| r.tree == VFS_TREE).cloned()
    }

    /// What a grant to a VFS path means against the roots — never a membership.
    ///
    /// *An app's capability may still be scoped to a path inside a root,
    /// because a grant to software is not membership.* Both halves are here:
    /// the grant is placed in a root, and the answer has no arm that could add
    /// anybody to [`Root::members`].
    pub fn meaning_of_vfs_grant(&self, grant: &kotton_schemas::CapabilityGrant) -> GrantMeaning {
        let kotton_schemas::CapabilityTarget::Vfs { path } = &grant.target else {
            return GrantMeaning::OutsideEveryRoot;
        };
        match self.root_of_vfs_path(path) {
            Some(root) => GrantMeaning::AppCapabilityInside(root.id),
            None => GrantMeaning::OutsideEveryRoot,
        }
    }

    /// Where each root is to be replicated: its own targets and nothing else.
    ///
    /// **Replication is per root.** The plan is a function of the root set alone. No path,
    /// no mount, no grant and no per-path rule appears in it or can change it —
    /// which is what `a_root_s_targets_are_the_only_thing_that_decides_where_it_goes`
    /// pins. The wire half executes this; this half states it.
    pub fn replication_plan(&self) -> Vec<(String, Vec<Target>)> {
        self.all()
            .into_iter()
            .map(|r| (r.id, r.targets))
            .collect()
    }
}

/// The vaults a device has already enrolled, read out of its remote set.
///
/// **Two uses, and neither is the Settings readout.** First run makes these
/// *Personal*'s targets, on the reading that a Kotton remote is where this tree
/// has been synced — which is what `sync_mount` usually leaves behind; it is
/// not always so (a remote is saved before the pass, `RemoteAdd` and the sync
/// engine's `__sync_bg__` entry write one too, and a paired full device is a
/// remote), so first run reads every Kotton remote as a place the tree is kept,
/// which is a known gap. And a target's
/// label is read back from it. A rebuilt routing half does **not** take its
/// targets from here (see [`RootSet::open`]). The person's list of vaults is
/// the membership set's, read by the readout in `kuserd`: a vault admitted and
/// never synced to is in that list and is nobody's target until a root names
/// it.
///
/// Not minted here: `RemoteBackend::Kotton`'s `peer_did` **is** the handle
/// enrolment gave the vault, and its `label` is the word the person
/// saw when they enrolled it. A second name for one vault is a second thing that
/// can disagree, so there is not one.
pub fn enrolled_targets(config: &crate::runtime::UserConfig) -> Vec<Target> {
    use kotton_wire::remote::RemoteBackend;
    let mut targets: Vec<Target> = config
        .remotes
        .values()
        .filter_map(|r| match &r.backend {
            RemoteBackend::Kotton { peer_did, label } => {
                Some(Target::new(peer_did, Some(label.clone())))
            }
            _ => None,
        })
        .collect();
    // `remotes` is a `HashMap`, so its iteration order is not one a person or a
    // test should have to think about.
    targets.sort_by(|a, b| (&a.handle, &a.label).cmp(&(&b.handle, &b.label)));
    // One vault is one target, however many remotes reach it: the person's own
    // and a `__sync_bg__` entry a crash left behind carry the same DID, because
    // the engine's entry carries no node id.
    targets.dedup_by(|a, b| a.handle == b.handle);
    targets
}

/// A local, per-root id.
///
/// Random rather than derived from the name, so that renaming a root is a rename
/// and not a new root — and so that nothing about the person is recoverable from
/// it if it ever does escape. It is not the id a target sees; the blinded
/// per-target id is the wire half's open question.
fn new_root_id() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::{CapabilityGrant, CapabilityKind};

    const AID: &str = "did:kel:z6MkPersonsOwnAid";
    const VAULT: &str = "did:key:z6MkDropletVault";
    const OTHER_VAULT: &str = "did:key:z6MkAtticVault";

    /// Two remotes reaching one vault — the person's own and the engine's
    /// `__sync_bg__` entry a crash left behind, which carries the vault's DID
    /// — are one target, not two.
    #[test]
    fn one_vault_reached_by_two_remotes_is_one_target() {
        use kotton_wire::remote::{KeyFormat, RemoteBackend, RemoteConfig};
        let kotton = |did: &str, label: &str| RemoteConfig {
            backend: RemoteBackend::Kotton { peer_did: did.to_string(), label: label.to_string() },
            cache_dir: None,
            key_format: KeyFormat::default(),
        };
        let mut config = crate::runtime::UserConfig::default();
        config.remotes.insert("vault".into(), kotton("did:key:zVault", "vault"));
        config.remotes.insert("__sync_bg__vault".into(), kotton("did:key:zVault", "vault"));
        config.remotes.insert("other".into(), kotton("did:key:zOther", "other"));
        let handles: Vec<String> = enrolled_targets(&config).into_iter().map(|t| t.handle).collect();
        assert_eq!(handles, ["did:key:zOther", "did:key:zVault"]);
    }

    /// This person's keys, as a test holds them.
    ///
    /// Fixed bytes rather than random ones so that a test can state what the
    /// sealed half must *not* contain and still be able to open it.
    const CEK: [u8; 32] = [7u8; 32];
    const PATH_KEY: [u8; 32] = [9u8; 32];

    fn keys() -> kotton_context::SealingKeys<'static> {
        kotton_context::SealingKeys {
            cek: &CEK,
            path_key: &PATH_KEY,
        }
    }

    /// Open this person's roots the way an unlocked device with no hardware
    /// binding does — every Linux machine today.
    fn open(user_dir: &Path, targets: &[Target]) -> RootSet {
        RootSet::open(user_dir, AID, targets, keys(), None).unwrap()
    }

    /// **A root can belong to an identity that is not the person's**, and that survives the
    /// meaning half being sealed and opened again — while the person stays in it as a
    /// member, which is what reading it takes. Every root recorded without an owner, and
    /// every root a person makes for themselves, is the person's.
    #[test]
    fn a_root_owned_by_an_org_is_held_by_the_person_and_is_not_theirs() {
        const ORG: &str = "did:key:z6MkTheProjectsOrg";
        let dir = tempfile::tempdir().unwrap();
        let mut set = open(dir.path(), &[]);
        let project = set
            .add("kotton", Owner::Identity(ORG.into()), vec![AID.into()], Vec::new(), Residency::Full)
            .unwrap();
        let family = set
            .add("Family", Owner::ThePerson, vec![AID.into()], Vec::new(), Residency::Full)
            .unwrap();

        let again = open(dir.path(), &[]);
        let project = again.get(&project).unwrap();
        assert_eq!(project.owner.as_deref(), Some(ORG));
        assert_eq!(project.owner_or(AID), ORG);
        assert_ne!(project.owner_or(AID), AID, "the person is not the project root's owner");
        assert!(again.member_roots(AID).contains(&project.id), "and is in it");
        for mine in [again.get(&family).unwrap(), again.personal().unwrap(), again.core()] {
            assert_eq!(mine.owner, None, "{} is the person's", mine.name);
            assert_eq!(mine.owner_or(AID), AID);
        }
    }

    /// Admitting a member is recorded once, survives a reopen, and has no door into the core
    /// root or into a root this set does not hold.
    #[test]
    fn a_member_is_admitted_once_and_only_to_a_root_the_set_holds() {
        const BOB: &str = "did:kel:z6MkBob";
        let dir = tempfile::tempdir().unwrap();
        let mut set = open(dir.path(), &[]);
        let project = set
            .add("kotton", Owner::Identity("did:key:z6MkOrg".into()), vec![AID.into()], Vec::new(), Residency::Full)
            .unwrap();
        assert!(set.add_member(&project, BOB).unwrap());
        assert!(!set.add_member(&project, BOB).unwrap(), "admitted twice");
        assert_eq!(open(dir.path(), &[]).members_of(&project).unwrap(), vec![AID, BOB]);
        assert!(set.add_member(Root::CORE, BOB).is_err(), "the core root's member is the person");
        assert!(set.add_member("no-such-root", BOB).is_err());
    }

    /// Open them the way a device whose `CustodyBackend` binds does, with
    /// `binding` standing where the chip would.
    fn open_bound(user_dir: &Path, targets: &[Target], binding: &dyn DeviceBinding) -> RootSet {
        RootSet::open(user_dir, AID, targets, keys(), Some(binding)).unwrap()
    }

    /// The routing half as a daemon that has never been unlocked reads it.
    fn routing(user_dir: &Path, binding: Option<&dyn DeviceBinding>) -> RoutingHalf {
        RoutingIndex::read(user_dir, binding).unwrap()
    }

    /// The first line of the routing half at rest — the line that says what
    /// protects the rest of it.
    fn at_rest_form(user_dir: &Path) -> String {
        let raw = std::fs::read(RoutingIndex::path(user_dir)).unwrap();
        let end = raw.iter().position(|b| *b == b'\n').expect("a first line");
        String::from_utf8(raw[..end].to_vec()).unwrap()
    }

    /// A device binding a test can hold.
    ///
    /// **No auth policy, which is the property under test**: `binding_secret`
    /// answers for `None`, as `TpmBinding::create`'s key does, because the file
    /// it protects is read before anybody has typed anything. Two of these with
    /// different seeds are two machines; the secret is fixed rather than random
    /// so a test can state what the sealed bytes must not contain and still
    /// open them.
    struct FakeBinding {
        secret: [u8; 32],
        backend: kotton_sys::secret::CustodyBackend,
    }

    impl FakeBinding {
        /// A machine whose chip binds, identified by `seed`.
        fn chip(seed: u8) -> Self {
            Self {
                secret: [seed; 32],
                backend: kotton_sys::secret::CustodyBackend::WindowsTpm,
            }
        }

        /// A machine that has a binding type and no hardware behind it — what
        /// `CustodyBackend::None` means, and what every Linux machine answers.
        fn unbacked() -> Self {
            Self {
                secret: [0u8; 32],
                backend: kotton_sys::secret::CustodyBackend::None,
            }
        }
    }

    impl DeviceBinding for FakeBinding {
        fn backend(&self) -> kotton_sys::secret::CustodyBackend {
            self.backend
        }

        fn binding_secret(
            &self,
            _credential: Option<&str>,
        ) -> kotton_sys::secret::SecretsResult<[u8; 32]> {
            Ok(self.secret)
        }

        fn counts_attempts(&self) -> bool {
            false
        }

        fn requires_credential(&self) -> bool {
            false
        }
    }

    /// The meaning half, opened — what a reader with the keys sees.
    fn meaning(user_dir: &Path) -> MeaningIndexFile {
        let blob = std::fs::read(RootSet::sealed_path(user_dir)).unwrap();
        let plaintext =
            crate::provider::open_envelope(&CEK, &RootSet::sealed_aad(), &blob).unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }

    /// A user directory with the tree today's VFS already addresses, holding one
    /// file, so a migration that rewrote anything would be visible.
    fn a_user_with_one_tree() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        std::fs::create_dir_all(user_dir.join(VFS_TREE)).unwrap();
        std::fs::write(user_dir.join(VFS_TREE).join("note.txt"), b"before").unwrap();
        (temp, user_dir)
    }

    fn droplet() -> Target {
        Target::new(VAULT, Some("droplet".to_string()))
    }

    #[test]
    fn first_run_adopts_the_existing_tree_as_this_pc_with_nothing_re_encrypted() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let before = std::fs::read(user_dir.join(VFS_TREE).join("note.txt")).unwrap();

        let set = open(&user_dir, &[]);

        let this_pc = set.personal().expect("first run lays a root over the tree");
        assert_eq!(this_pc.name, Root::THIS_PC);
        // The marker, not a copy: This PC's tree *is* the directory that was
        // already there, and the bytes in it are the bytes that were in it.
        assert_eq!(this_pc.tree, VFS_TREE);
        assert!(this_pc.adopts_the_mount());
        assert_eq!(this_pc.tree_path(&user_dir), user_dir.join(VFS_TREE));
        let after = std::fs::read(user_dir.join(VFS_TREE).join("note.txt")).unwrap();
        assert_eq!(before, after, "the migration must not rewrite a single byte");
        assert_eq!(this_pc.members, vec![AID.to_string()]);
    }

    /// A first run on a device that has already enrolled a vault keeps today's
    /// answer: the adopting root carries it, so no vault is silently dropped
    /// from a root — and the root is still called *This PC*, because the name
    /// says where the person's files *start* and the *On this PC* column says
    /// where they are held.
    #[test]
    fn an_enrolled_vault_becomes_this_pcs_target_on_first_run() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let set = open(&user_dir, &[droplet()]);

        let this_pc = set.personal().unwrap();
        assert_eq!(this_pc.name, Root::THIS_PC);
        assert_eq!(this_pc.targets, vec![droplet()]);
        // And it is the one root a pass that exists today actually carries.
        assert_eq!(this_pc.kept(), Kept::Replicated);
    }

    #[test]
    fn the_core_root_exists_first_and_is_marked_for_every_target() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let mut set = open(&user_dir, &[droplet()]);
        set.add(
            "Family",
            Owner::ThePerson,
            vec![AID.to_string()],
            vec![Target::new(OTHER_VAULT, None)],
            Residency::Full,
        )
        .unwrap();

        let all = set.all();
        assert!(all[0].is_core(), "the core root is first in the list");

        let core = set.core();
        assert_eq!(core.residency, Residency::Full, "R16: held in full, always");
        let handles: Vec<&str> = core.targets.iter().map(|t| t.handle.as_str()).collect();
        assert_eq!(
            handles,
            vec![VAULT, OTHER_VAULT],
            "R16: marked for every target the person has"
        );
        // And what it holds is the core root's list, with the index the only part whose
        // bytes are inside the core tree in this half.
        assert_eq!(core.carries(), &Carried::ALL);
        assert!(Carried::RootIndex.is_in_the_core_tree());
        assert!(!Carried::IdentityMaterial.is_in_the_core_tree());
        assert!(RootSet::sealed_path(&user_dir).exists());
        assert!(RoutingIndex::path(&user_dir).exists());
    }

    #[test]
    fn the_core_root_is_computed_and_never_stored_in_the_index_it_holds() {
        let (_temp, user_dir) = a_user_with_one_tree();
        open(&user_dir, &[droplet()]);

        assert!(
            !meaning(&user_dir).roots.iter().any(|r| r.id == Root::CORE),
            "core is special by rule, not by record — a stored copy could disagree"
        );
        assert!(
            !routing(&user_dir, None)
                .routes()
                .expect("the routing half is there and in the clear")
                .entries()
                .iter()
                .any(|e| e.id == Root::CORE),
            "and the routing half does not route it either — its targets are the \
             union of the others', computed, never stored"
        );

        // Reopening finds the same roots and the same computed core.
        let again = open(&user_dir, &[droplet()]);
        assert_eq!(again.core().targets, vec![droplet()]);
        assert_eq!(again.all().len(), 2, "the core root and This PC");

        // **The handle is the index's; the label is the enrolment's.** The
        // routing half carries handles and no words, so reopening on a device
        // that no longer enrols that vault still routes the root there and can
        // no longer say what the person called it — which is the truth, because
        // the word came from an enrolment that is gone.
        let unenrolled = open(&user_dir, &[]);
        assert_eq!(
            unenrolled.core().targets,
            vec![Target::new(VAULT, None)],
            "the address survives the enrolment; the person's word for it does not"
        );
    }

    /// **First run on a device with no enrolled vaults lays down the core root
    /// and exactly one person's root, named *This PC*, with no targets — and a
    /// second open of the same directory keeps it.**
    ///
    /// *This computer is the one root everyone starts with.* The second open is
    /// the half that matters: a retirement on every open that dropped an empty,
    /// untargeted root by this name would read as the person's roots
    /// disappearing.
    #[test]
    fn first_run_lays_down_the_core_root_and_this_pc_and_nothing_else() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let set = open(&user_dir, &[]);

        let names: Vec<String> = set.all().into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["Core".to_string(), Root::THIS_PC.to_string()]);
        let this_pc = set.personal().expect("This PC adopts the tree");
        assert_eq!(this_pc.name, Root::THIS_PC);
        assert!(this_pc.targets.is_empty(), "no vault is enrolled, so no target");
        assert_eq!(this_pc.kept(), Kept::ThisDeviceOnly);
        assert!(this_pc.adopts_the_mount(), "This PC is the person's files on this machine");
        // One tree, one row: the root is laid over `data/`, and nothing was laid
        // down under `roots/` for a second one.
        assert!(
            !user_dir.join(ROOTS_DIR).exists(),
            "first run created a tree for a second root"
        );

        // A second open of the same directory keeps it, untouched: same row,
        // same name, still no targets, still the only person's root.
        let again = open(&user_dir, &[]);
        let kept = again.get(&this_pc.id).expect("an open of the index removed This PC");
        assert_eq!(kept.name, Root::THIS_PC);
        assert!(kept.targets.is_empty());
        assert!(kept.adopts_the_mount());
        let names: Vec<String> = again.all().into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["Core".to_string(), Root::THIS_PC.to_string()]);
        // And a third, because a retirement would run on *every* open, not the
        // first.
        assert!(open(&user_dir, &[]).get(&this_pc.id).is_some());
    }

    /// **A device whose index already carries *Personal* keeps that name.**
    ///
    /// A device whose first run named the adopting root *Personal*. The store
    /// does not rename a root the person has seen — names are the person's, and
    /// a rename by migration is the
    /// store naming for them. What makes it the adopting root is its tree, so a
    /// surface that routes by [`Root::adopts_the_mount`] finds it under either
    /// name, and a person who wants it called *This PC* renames it.
    #[test]
    fn an_index_that_already_carries_personal_keeps_that_name() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let mut set = open(&user_dir, &[droplet()]);
        let id = set.personal().unwrap().id;
        for root in set.roots.iter_mut() {
            if root.id == id {
                root.name = Root::PERSONAL.to_string();
            }
        }
        set.save().unwrap();

        let reopened = open(&user_dir, &[droplet()]);
        let personal = reopened.personal().expect("the adopting root is found by its tree");
        assert_eq!(personal.id, id);
        assert_eq!(personal.name, Root::PERSONAL, "a migration renamed a root the person has seen");
        assert!(personal.adopts_the_mount());
        assert_eq!(personal.targets, vec![droplet()]);
        assert!(
            !reopened.all().iter().any(|r| r.name == Root::THIS_PC),
            "a second root was minted beside Personal, which is what listed the device twice"
        );
    }

    /// **Only a root's own tree is one a shell may be handed.** A root the person made has
    /// one; *This PC*'s is the VFS mount, reached through the app's `files`
    /// grant and never through `roots.tree`; and a stored tree string that
    /// names the core tree, the user directory or somewhere else answers
    /// nothing rather than being joined.
    #[test]
    fn only_a_roots_own_tree_is_one_a_shell_may_be_handed() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let mut set = open(&user_dir, &[]);
        let id = set.add("Family", Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full).unwrap();
        let family = set.get(&id).unwrap();
        assert_eq!(family.tree_of_its_own(&user_dir), Some(user_dir.join("roots").join(&id)));

        let this_pc = set.personal().expect("This PC");
        assert_eq!(this_pc.tree_of_its_own(&user_dir), None, "This PC's tree is the grants' door");
        assert_eq!(set.core().tree_of_its_own(&user_dir), None, "the core tree is nobody's place");

        for tree in [CORE_TREE, ".", "..", "", "/etc", "roots", "roots/other", "roots/../core"] {
            let odd = Root { tree: tree.to_string(), ..family.clone() };
            assert_eq!(odd.tree_of_its_own(&user_dir), None, "a tree of {tree:?} was handed over");
        }
        let climbing = Root { id: "../core".to_string(), tree: "roots/../core".to_string(), ..family };
        assert_eq!(climbing.tree_of_its_own(&user_dir), None);
    }

    /// A root with no targets is a choice a person makes too, and the store says
    /// so in their own words — [`Kept::ThisDeviceOnly`], *this device and
    /// nowhere else*. *This PC* on a device with no vault answers the same.
    #[test]
    fn a_root_the_person_makes_with_no_targets_is_kept_on_this_device_only() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let mut set = open(&user_dir, &[droplet()]);

        let id = set
            .add("Scratch", Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();

        let scratch = set.get(&id).unwrap();
        assert!(scratch.targets.is_empty());
        assert_eq!(scratch.kept(), Kept::ThisDeviceOnly);
        assert!(scratch.tree_path(&user_dir).is_dir());
        // And it survives a reopen.
        let again = open(&user_dir, &[]);
        assert!(again.get(&id).is_some(), "a root the person made was removed");
    }

    #[test]
    fn a_root_other_than_personal_records_its_targets_and_is_not_yet_replicated() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let mut set = open(&user_dir, &[droplet()]);
        let id = set
            .add(
                "Family",
                Owner::ThePerson,
                vec![AID.to_string(), "did:kel:z6MkSomeoneElse".to_string()],
                vec![Target::new(OTHER_VAULT, Some("attic".to_string()))],
                Residency::OnDemand,
            )
            .unwrap();

        let family = set.get(&id).unwrap();
        assert_eq!(family.targets.len(), 1, "the target is recorded");
        assert_eq!(
            family.kept(),
            Kept::NotYetKeptAnywhereButHere,
            "the wire does not change in this unit, and the store must say so \
             rather than let a recorded target read as a copy"
        );
        // Residency is the person's and is not topology: it did not move the
        // root anywhere, and it did not change who holds it.
        assert_eq!(family.residency, Residency::OnDemand);
        assert_eq!(family.members.len(), 2);
        // The core root is marked for the new vault too, without anyone saying so.
        assert_eq!(set.core().targets.len(), 2);
        assert_eq!(set.core().kept(), Kept::NotYetKeptAnywhereButHere);
    }

    // ── The index at rest: sealed before it travels ──────────────────────────

    /// The name a person gives a root, and the AID of somebody they share it
    /// with. Both are what a provider may never hold, and both are
    /// long enough that finding them in a file is finding them and not a
    /// coincidence.
    const ROOT_NAME: &str = "Wedding photos";
    const THEIR_AID: &str = "did:kel:z6MkTheAidOfSomebodyElse";

    /// Whether `haystack` contains `needle` anywhere in it, as bytes.
    ///
    /// A byte search and not a `!=` against the plaintext: *the file differs
    /// from what it would have been* is satisfied by base64, by compression, and
    /// by a field order that happened to change, none of which conceal anything.
    /// What matters is whether the word is **in there**, so that is what is
    /// asked.
    fn contains(haystack: &[u8], needle: &str) -> bool {
        let needle = needle.as_bytes();
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// A person with one root of their own, shared with somebody, kept at a
    /// vault — every field the two halves have to divide between them.
    fn a_person_with_a_shared_root() -> (tempfile::TempDir, PathBuf, String) {
        let (temp, user_dir) = a_user_with_one_tree();
        let mut set = open(&user_dir, &[droplet()]);
        let id = set
            .add(
                ROOT_NAME,
                Owner::ThePerson,
                vec![AID.to_string(), THEIR_AID.to_string()],
                vec![Target::new(OTHER_VAULT, Some("attic".to_string()))],
                Residency::OnDemand,
            )
            .unwrap();
        (temp, user_dir, id)
    }

    /// **The meaning half at rest carries no name, no member and no handle.**
    ///
    /// Searched for, one at a time, in the bytes as they sit on the disk. This
    /// is the property the whole record is about: the index is the one join a
    /// provider would most want, the wire half is about to carry the core root
    /// to a vault, and Article I says a target holds bytes it cannot read.
    #[test]
    fn the_sealed_half_carries_no_root_name_no_member_aid_and_no_vault_handle() {
        let (_temp, user_dir, _id) = a_person_with_a_shared_root();

        let at_rest = std::fs::read(RootSet::sealed_path(&user_dir)).unwrap();

        assert!(!contains(&at_rest, ROOT_NAME), "the root's name is in the sealed half");
        assert!(!contains(&at_rest, Root::THIS_PC), "a root's name is in the sealed half");
        assert!(!contains(&at_rest, AID), "the person's own AID is in the sealed half");
        assert!(!contains(&at_rest, THEIR_AID), "a member's AID is in the sealed half");
        assert!(!contains(&at_rest, VAULT), "a vault handle is in the sealed half");
        assert!(!contains(&at_rest, OTHER_VAULT), "a vault handle is in the sealed half");

        // And it is the index rather than an empty file that says none of them:
        // the same bytes, opened under this person's keys, are every one.
        let opened = meaning(&user_dir);
        assert!(opened.roots.iter().any(|r| r.name == ROOT_NAME));
        assert!(opened
            .roots
            .iter()
            .any(|r| r.members.contains(&THEIR_AID.to_string())));
    }

    /// **The routing half at rest carries no name and no member.**
    ///
    /// It is plaintext by design — addresses a device must read before anybody
    /// has unlocked it — so what it may hold is the whole question. A handle is
    /// already in `config.toml` beside it and a local root id is random; a name
    /// or an AID would be the join.
    #[test]
    fn the_routing_half_carries_no_root_name_and_no_member_aid() {
        let (_temp, user_dir, id) = a_person_with_a_shared_root();

        let at_rest = std::fs::read(RoutingIndex::path(&user_dir)).unwrap();

        assert!(!contains(&at_rest, ROOT_NAME), "the root's name is in the routing half");
        assert!(!contains(&at_rest, Root::THIS_PC), "a root's name is in the routing half");
        assert!(!contains(&at_rest, AID), "the person's own AID is in the routing half");
        assert!(!contains(&at_rest, THEIR_AID), "a member's AID is in the routing half");

        // And it is the addresses rather than an empty file that says so.
        assert!(contains(&at_rest, &id), "the routing half must route the root");
        assert!(contains(&at_rest, OTHER_VAULT), "the routing half must carry the address");
    }

    /// **A device that has booted and has never been unlocked can route every
    /// root, hold what arrives for it, and name nothing.**
    ///
    /// Of the three states — unlocked, locked, booted and never unlocked — this
    /// is the third. It
    /// asks for the index with no keys at all: [`RootSet::open`] cannot be
    /// reached without them, and what can be reached answers addresses.
    #[test]
    fn a_device_that_has_never_been_unlocked_routes_every_root_and_names_none() {
        let (_temp, user_dir, id) = a_person_with_a_shared_root();

        let half = routing(&user_dir, None);
        let cold = half.routes().expect("a device with no binding reads the clear form");

        // Every root the person has, by address.
        assert_eq!(cold.entries().len(), 2, "Personal and the shared root");
        assert_eq!(cold.targets_of(&id), Some([OTHER_VAULT.to_string()].as_slice()));
        // And nothing it holds is a word: a serialisation of the whole thing
        // carries neither a name nor an AID.
        let all = serde_json::to_string(&cold.entries().to_vec()).unwrap();
        assert!(!all.contains(ROOT_NAME));
        assert!(!all.contains(THEIR_AID));

        // Bytes arrive for a root before anybody has unlocked the device, and
        // they wait — sealed, unopened, addressed by an id that names nothing.
        let envelope = b"\x00sealed-bytes-this-device-cannot-open".to_vec();
        cold.stash(&user_dir, &id, "0001.env", &envelope).unwrap();
        assert_eq!(cold.stashed(&user_dir, &id).unwrap(), vec!["0001.env".to_string()]);
        assert_eq!(
            cold.stashed_bytes(&user_dir, &id, "0001.env").unwrap(),
            envelope,
            "what was stashed is what arrived, byte for byte"
        );

        // A root this device does not route is not a place it will write, and
        // neither is a name with a path in it.
        assert!(cold.stash(&user_dir, "not-a-root", "0001.env", b"x").is_err());
        assert!(cold.stash(&user_dir, &id, "../../escape", b"x").is_err());
        assert!(cold.stash(&user_dir, &id, "", b"x").is_err());
        assert!(!user_dir.join("escape").exists());
    }

    // ── The routing half, bound to the device ────────────────────────────────

    /// A person with one shared root on a device whose chip binds.
    fn a_person_on_a_bound_device(
        binding: &dyn DeviceBinding,
    ) -> (tempfile::TempDir, PathBuf, String) {
        let (temp, user_dir) = a_user_with_one_tree();
        let mut set = open_bound(&user_dir, &[droplet()], binding);
        let id = set
            .add(
                ROOT_NAME,
                Owner::ThePerson,
                vec![AID.to_string(), THEIR_AID.to_string()],
                vec![Target::new(OTHER_VAULT, Some("attic".to_string()))],
                Residency::OnDemand,
            )
            .unwrap();
        (temp, user_dir, id)
    }

    /// **On a device that binds, the routing half at rest carries neither the
    /// id a root is routed by nor a vault handle.**
    ///
    /// Searched for in the bytes as they sit on the disk, one at a time — the
    /// same shape the meaning half's test uses. Those two fields are the whole of what the routing half
    /// holds, so a file that has neither has nothing; the second half of the
    /// test is that it is a routing half and not an empty file, opened under
    /// the same binding that wrote it.
    #[test]
    fn the_routing_half_on_a_device_that_binds_carries_no_root_id_and_no_target_handle() {
        let chip = FakeBinding::chip(1);
        let (_temp, user_dir, id) = a_person_on_a_bound_device(&chip);

        let at_rest = std::fs::read(RoutingIndex::path(&user_dir)).unwrap();

        assert!(!contains(&at_rest, &id), "a root's routing id is in the routing half");
        assert!(!contains(&at_rest, VAULT), "a vault handle is in the routing half");
        assert!(!contains(&at_rest, OTHER_VAULT), "a vault handle is in the routing half");
        assert!(!contains(&at_rest, ROOT_NAME), "a root's name is in the routing half");
        assert!(!contains(&at_rest, AID), "the person's own AID is in the routing half");
        assert!(!contains(&at_rest, THEIR_AID), "a member's AID is in the routing half");

        // And it is the addresses rather than an empty file that say none of
        // them: the same bytes, under the same binding, are both.
        let half = routing(&user_dir, Some(&chip));
        let cold = half.routes().expect("the chip that wrote it opens it");
        assert_eq!(cold.entries().len(), 2, "Personal and the shared root");
        assert_eq!(cold.targets_of(&id), Some([OTHER_VAULT.to_string()].as_slice()));
    }

    /// **The file's first line says what protects the rest of it.**
    ///
    /// Both ways round, because the point of stating it is that the concession
    /// is legible on the disk that carries it and not only where it is made.
    #[test]
    fn the_routing_halfs_first_line_says_whether_it_is_sealed_to_this_device() {
        let chip = FakeBinding::chip(1);
        let (_bound_temp, bound_dir, _) = a_person_on_a_bound_device(&chip);
        assert_eq!(at_rest_form(&bound_dir), "kotton-roots-routing/1 device-sealed");

        let (_plain_temp, plain_dir, id) = a_person_with_a_shared_root();
        assert_eq!(at_rest_form(&plain_dir), "kotton-roots-routing/1 plaintext");
        // And the clear form is still the clear form — a device with no chip
        // reads its addresses, which is the whole reason the half exists.
        let at_rest = std::fs::read(RoutingIndex::path(&plain_dir)).unwrap();
        assert!(contains(&at_rest, &id), "the clear form must carry the routing id");
        assert!(contains(&at_rest, OTHER_VAULT), "the clear form must carry the address");
    }

    /// **A copy of the file opens nowhere else.**
    ///
    /// One machine's chip wrote it; another machine's chip, and a machine with
    /// no chip at all, get [`RoutingHalf::Unopenable`] rather than an index —
    /// which is the property the seal is for, and it is asserted by reading the
    /// same bytes twice rather than by trusting the key.
    #[test]
    fn a_routing_half_sealed_to_one_device_does_not_open_on_another() {
        let chip = FakeBinding::chip(1);
        let (_temp, user_dir, _id) = a_person_on_a_bound_device(&chip);

        let another = FakeBinding::chip(2);
        assert!(
            routing(&user_dir, Some(&another)).routes().is_none(),
            "a different device's binding opened this machine's routing half"
        );
        assert!(
            routing(&user_dir, None).routes().is_none(),
            "the routing half opened with no binding at all"
        );
        assert!(
            routing(&user_dir, Some(&FakeBinding::unbacked())).routes().is_none(),
            "a backend that does not bind opened a half sealed to hardware"
        );
        // And the one that wrote it still does, so this is a statement about
        // the key rather than about the file being broken.
        assert!(routing(&user_dir, Some(&chip)).routes().is_some());
    }

    /// **A routing half this device cannot open is rebuilt at the next unlock,
    /// not an error.**
    ///
    /// The cleared TPM and the moved disk: the meaning half still names every
    /// root and records where each is kept, so the whole cost is one rebuild.
    /// Asserted end to end — the open succeeds, the roots come back named and
    /// kept where they were, and the file on the disk afterwards opens under
    /// the binding the device has *now*.
    #[test]
    fn a_routing_half_that_will_not_open_is_rebuilt_from_the_meaning_half() {
        let chip = FakeBinding::chip(1);
        let (_temp, user_dir, id) = a_person_on_a_bound_device(&chip);
        let sealed_before = std::fs::read(RoutingIndex::path(&user_dir)).unwrap();

        // The chip is cleared and a new binding is minted in its place.
        let replaced = FakeBinding::chip(2);
        let reopened = open_bound(&user_dir, &[droplet()], &replaced);

        let root = reopened.get(&id).expect("the root is still named");
        assert_eq!(root.name, ROOT_NAME, "the meaning half was never in doubt");
        assert_eq!(
            root.targets.iter().map(|t| t.handle.as_str()).collect::<Vec<_>>(),
            vec![OTHER_VAULT],
            "the root comes back kept where the meaning half says, and not at the \
             vaults this device has enrolled"
        );
        // Written through, so the daemon that reads this half next boot can.
        let at_rest = std::fs::read(RoutingIndex::path(&user_dir)).unwrap();
        assert_ne!(at_rest, sealed_before, "the unopenable half was left on the disk");
        assert!(
            routing(&user_dir, Some(&replaced)).routes().is_some(),
            "the rebuilt half does not open under the binding that rebuilt it"
        );
    }

    /// **A routing half that is not there is rebuilt too, and the next save
    /// never writes the empty list.**
    ///
    /// This is the crash between the two writes, staged by deleting the file
    /// that lands second. Read as *routes nothing*, a missing routing half would
    /// bring every root's targets back `unwrap_or(&[])`, and the next save would
    /// write that down — so the person's vaults would be gone and the forgetting
    /// permanent.
    #[test]
    fn a_missing_routing_half_is_rebuilt_rather_than_read_as_no_targets() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let before = open(&user_dir, &[droplet()]);
        let personal = before.personal().expect("first run lays down This PC");
        assert_eq!(personal.targets, vec![droplet()]);

        std::fs::remove_file(RoutingIndex::path(&user_dir)).unwrap();

        let mut reopened = open(&user_dir, &[droplet()]);
        assert_eq!(
            reopened
                .get(&personal.id)
                .expect("Personal is still named")
                .targets,
            vec![droplet()],
            "the vault that keeps this root was forgotten"
        );

        // And the save that follows persists the handle rather than the empty
        // list — which is the half of the defect that made it permanent.
        reopened
            .add(ROOT_NAME, Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();
        let half = routing(&user_dir, None);
        let cold = half.routes().expect("the routing half is back");
        assert_eq!(
            cold.targets_of(&personal.id),
            Some([VAULT.to_string()].as_slice()),
            "the next save wrote down the forgetting"
        );
    }

    /// **A rebuilt routing half keeps each root where it was kept, and widens
    /// none of them.**
    ///
    /// Three roots: *Personal* kept at the droplet by first run, one the person
    /// kept at the attic, and one they kept nowhere but here. The routing half
    /// is removed and the index reopened with **both** vaults enrolled — which
    /// is what a rebuild that widened would give every root. Each comes back as it was, and the one kept nowhere is still kept
    /// nowhere. Make the rebuild take `enrolled` again and every root comes
    /// back at both vaults, so the first assertion already fails, with
    /// `a_routing_half_that_will_not_open_is_rebuilt_from_the_meaning_half`
    /// failing beside it.
    #[test]
    fn a_rebuilt_routing_half_keeps_each_root_where_it_was_and_widens_none() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let attic = Target::new(OTHER_VAULT, Some("attic".to_string()));
        let mut set = open(&user_dir, &[droplet()]);
        let personal = set.personal().expect("first run lays down This PC").id;
        let kept_at_attic = set
            .add("Photos", Owner::ThePerson, vec![AID.to_string()], vec![attic.clone()], Residency::Full)
            .unwrap();
        let kept_here = set
            .add("Drafts", Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();

        std::fs::remove_file(RoutingIndex::path(&user_dir)).unwrap();
        let reopened = open(&user_dir, &[droplet(), attic.clone()]);

        assert_eq!(reopened.get(&personal).unwrap().targets, vec![droplet()]);
        assert_eq!(reopened.get(&kept_at_attic).unwrap().targets, vec![attic]);
        assert_eq!(
            reopened.get(&kept_here).unwrap().targets,
            Vec::<Target>::new(),
            "a root kept on this device only was re-targeted at a vault by the rebuild"
        );
        assert_eq!(reopened.get(&kept_here).unwrap().kept(), Kept::ThisDeviceOnly);
        // And the rebuilt half on the disk says the same, for the cold daemon.
        let half = routing(&user_dir, None);
        let cold = half.routes().expect("the routing half is back");
        assert_eq!(cold.targets_of(&kept_here), Some([].as_slice()));
    }

    /// **An older meaning half with no routing half beside it comes back kept
    /// on this device only — never at every vault.**
    ///
    /// An older meaning half does not record targets, so if its routing half is
    /// also gone there is no record of the assignment anywhere. The rebuild does
    /// not fill the gap with every enrolled vault; it leaves each root
    /// untargeted, which the *Kept* column shows and
    /// the person can undo, and the save that follows records that in both
    /// halves rather than inventing a target.
    #[test]
    fn an_older_meaning_half_without_its_routing_half_is_kept_here_and_not_widened() {
        let (_temp, user_dir, id) = a_person_with_a_shared_root();

        // Write the meaning half back as an earlier version wrote it: no
        // targets field on any root.
        let mut older = meaning(&user_dir);
        for root in &mut older.roots {
            root.targets = None;
        }
        let plaintext = serde_json::to_vec(&older).unwrap();
        assert!(
            !contains(&plaintext, "\"targets\""),
            "the staged meaning half still records targets"
        );
        let sealed =
            crate::provider::seal_envelope(&CEK, &RootSet::sealed_aad(), &plaintext).unwrap();
        std::fs::write(RootSet::sealed_path(&user_dir), sealed).unwrap();
        std::fs::remove_file(RoutingIndex::path(&user_dir)).unwrap();

        let reopened = open(&user_dir, &[droplet()]);
        for root in reopened.all().into_iter().filter(|r| !r.is_core()) {
            assert_eq!(
                root.targets,
                Vec::<Target>::new(),
                "{} was given a target nothing recorded",
                root.name
            );
        }
        assert_eq!(reopened.get(&id).unwrap().kept(), Kept::ThisDeviceOnly);
        // Written through: the meaning half now records the empty assignment,
        // so the next open has a record rather than a gap.
        assert!(meaning(&user_dir)
            .roots
            .iter()
            .all(|r| r.targets.as_deref() == Some(&[][..])));
    }

    /// **The headerless shape the split wrote first is read, not rebuilt.**
    ///
    /// A device unlocked before the routing half carried its first line has
    /// one. Refusing it would cost each of them a rebuild for nothing, and
    /// a rebuild is the one thing that cannot tell which root was kept where.
    #[test]
    fn a_routing_half_written_before_the_first_line_existed_is_still_read() {
        let (_temp, user_dir, id) = a_person_with_a_shared_root();

        // Strip the first line, leaving exactly what the split wrote.
        let raw = std::fs::read(RoutingIndex::path(&user_dir)).unwrap();
        let body = raw[raw.iter().position(|b| *b == b'\n').unwrap() + 1..].to_vec();
        std::fs::write(RoutingIndex::path(&user_dir), &body).unwrap();

        let half = routing(&user_dir, None);
        let cold = half.routes().expect("the headerless form is the clear form");
        assert_eq!(cold.targets_of(&id), Some([OTHER_VAULT.to_string()].as_slice()));

        // And the next save gives it a first line.
        open(&user_dir, &[droplet()]).save().unwrap();
        assert_eq!(at_rest_form(&user_dir), "kotton-roots-routing/1 plaintext");
    }

    /// **Each half is renamed into place and leaves no temporary behind.**
    ///
    /// The durability half of the same write path: a `std::fs::write` can
    /// truncate a file and then fail, and the person is left with neither the
    /// old index nor a new one. What a test in one process can hold is the two
    /// visible consequences — the replacement is whole, and the temporary the
    /// replacement went through is gone whether it succeeded or not.
    #[test]
    fn a_durable_write_replaces_the_file_whole_and_leaves_no_temporary() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("half.json");

        write_durably(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_durably(&path, b"second, and longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second, and longer");
        assert_eq!(
            std::fs::read_dir(temp.path()).unwrap().count(),
            1,
            "a temporary was left beside the file it was renamed from"
        );

        // A rename that cannot happen takes its temporary with it, and leaves
        // what was there alone.
        let blocked = temp.path().join("occupied");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("inside"), b"x").unwrap();
        assert!(write_durably(&blocked, b"over a directory").is_err());
        assert_eq!(
            std::fs::read_dir(temp.path()).unwrap().count(),
            2,
            "a failed rename left its temporary behind"
        );
        assert!(blocked.join("inside").exists(), "the failed write took something with it");
    }

    /// **Both halves of a saved index survive the save, under the seal each
    /// one gets.**
    ///
    /// The join the whole split rests on: the meaning half under the person's
    /// keys, the routing half under this device's binding, and nothing in the
    /// core tree in the clear that names either.
    #[test]
    fn a_bound_device_writes_both_halves_and_reads_them_back() {
        let chip = FakeBinding::chip(3);
        let (_temp, user_dir, id) = a_person_on_a_bound_device(&chip);

        let reopened = open_bound(&user_dir, &[droplet()], &chip);
        let root = reopened.get(&id).expect("the root is named");
        assert_eq!(root.name, ROOT_NAME);
        assert_eq!(
            root.targets,
            vec![Target::new(OTHER_VAULT, None)],
            "the handle comes back from the routing half, the label from the enrolment"
        );
    }

    /// **A plaintext `roots.json` left by an earlier version is sealed and
    /// removed.**
    ///
    /// Removed, not kept beside the sealed one: the unit is that those bytes
    /// stop being readable at rest, and a copy left behind keeps every property
    /// the change exists to get rid of.
    #[test]
    fn a_plaintext_index_left_by_an_earlier_version_is_sealed_and_removed() {
        let (_temp, user_dir) = a_user_with_one_tree();
        let legacy = user_dir.join(CORE_TREE).join("roots.json");
        std::fs::create_dir_all(user_dir.join(CORE_TREE)).unwrap();
        std::fs::write(
            &legacy,
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "roots": [{
                    "id": "0123456789abcdef",
                    "name": ROOT_NAME,
                    "members": [AID, THEIR_AID],
                    "targets": [{ "handle": OTHER_VAULT, "label": "attic" }],
                    "residency": "full",
                    "tree": "roots/0123456789abcdef",
                }],
            }))
            .unwrap(),
        )
        .unwrap();

        let set = open(&user_dir, &[Target::new(OTHER_VAULT, Some("attic".to_string()))]);

        assert!(!legacy.exists(), "the plaintext index is still on the disk");
        let root = set.get("0123456789abcdef").expect("the root survived the move");
        assert_eq!(root.name, ROOT_NAME);
        assert_eq!(root.members, vec![AID.to_string(), THEIR_AID.to_string()]);
        assert_eq!(root.targets, vec![Target::new(OTHER_VAULT, Some("attic".to_string()))]);
        assert_eq!(root.residency, Residency::Full);
        let at_rest = std::fs::read(RootSet::sealed_path(&user_dir)).unwrap();
        assert!(!contains(&at_rest, ROOT_NAME));
        assert!(!contains(&at_rest, THEIR_AID));
    }

    /// **The meaning half opens under this person's key and nothing else**, and
    /// not at another path either: the envelope binds the path it sits at, so a
    /// blob moved to another name in the core tree does not open there (H5).
    #[test]
    fn the_meaning_half_opens_under_this_persons_key_and_at_this_path_only() {
        let (_temp, user_dir, _id) = a_person_with_a_shared_root();
        let at_rest = std::fs::read(RootSet::sealed_path(&user_dir)).unwrap();

        let someone_else = [8u8; 32];
        assert!(
            crate::provider::open_envelope(&someone_else, &RootSet::sealed_aad(), &at_rest)
                .is_err(),
            "another person's key opened this person's index"
        );
        let elsewhere = crate::provider::path_aad(Path::new("core/devices.json"));
        assert!(
            crate::provider::open_envelope(&CEK, &elsewhere, &at_rest).is_err(),
            "the index opened under a path it was not sealed at"
        );
        assert!(
            crate::provider::open_envelope(&CEK, &RootSet::sealed_aad(), &at_rest).is_ok()
        );
    }

    #[test]
    fn a_grant_to_a_path_inside_a_root_is_an_app_capability_and_not_a_membership() {
        // The root's boundary is its sharing boundary; a path inside it
        // carries no membership, and there is nowhere in the model to put one.
        let (_temp, user_dir) = a_user_with_one_tree();
        let set = open(&user_dir, &[droplet()]);
        let personal = set.personal().unwrap();
        let members_before = set.members_of(&personal.id).unwrap();

        let grant = CapabilityGrant::vfs(CapabilityKind::Read, "/notes");
        let meaning = set.meaning_of_vfs_grant(&grant);

        assert_eq!(
            meaning,
            GrantMeaning::AppCapabilityInside(personal.id.clone()),
            "the grant lands inside Personal — Article IV is not narrowed"
        );
        assert_eq!(
            set.members_of(&personal.id).unwrap(),
            members_before,
            "reading a grant must not add anybody to a root"
        );
        assert_eq!(
            set.members_of(&personal.id).unwrap(),
            vec![AID.to_string()],
            "membership is the person's AID and nothing a grant named"
        );
        // A write grant to a deeper path is the same kind of thing: still a
        // capability, still not a member, and it does not partition the root.
        let deeper = CapabilityGrant::vfs(CapabilityKind::Write, "/notes/2026/trip.md");
        assert_eq!(
            set.meaning_of_vfs_grant(&deeper),
            GrantMeaning::AppCapabilityInside(personal.id.clone())
        );
        assert_eq!(set.members_of(&personal.id).unwrap(), members_before);

        // What this test does NOT falsify, said plainly so the next reader does
        // not mistake a green run for more than it is: `root_of_vfs_path`
        // discards its path (see its doc), so no VFS path can land outside a
        // migrated tree and the `None` arm below is unreachable from here. The
        // arm that *is* reachable is the one for a grant that names no VFS path
        // at all, and it is the one exercised. The path-to-root mapping stays
        // untestable until a second tree is addressable — the browser half.
        let not_a_path = CapabilityGrant::schema(
            CapabilityKind::Read,
            kotton_schemas::Nsid::new("sh.kotton.notes").unwrap(),
        );
        assert_eq!(
            set.meaning_of_vfs_grant(&not_a_path),
            GrantMeaning::OutsideEveryRoot,
            "a grant that names no path is in no root — the only way to reach \
             this arm while one tree is addressable"
        );
        assert_eq!(
            set.members_of(&personal.id).unwrap(),
            members_before,
            "and it still adds nobody"
        );
    }

    #[test]
    fn a_roots_targets_are_the_only_thing_that_decides_where_it_goes() {
        // Replication is per root. Two roots with different target sets go to different
        // targets, and nothing else in the model moves the answer.
        let (_temp, user_dir) = a_user_with_one_tree();
        let mut set = open(&user_dir, &[droplet()]);
        let family = set
            .add(
                "Family",
                Owner::ThePerson,
                vec![AID.to_string()],
                vec![Target::new(OTHER_VAULT, None)],
                Residency::Full,
            )
            .unwrap();
        let personal = set.personal().unwrap();

        let plan = set.replication_plan();
        let of = |id: &str| -> Vec<String> {
            plan.iter()
                .find(|(r, _)| r == id)
                .map(|(_, t)| t.iter().map(|t| t.handle.clone()).collect())
                .unwrap_or_default()
        };
        assert_eq!(of(&personal.id), vec![VAULT.to_string()]);
        assert_eq!(of(&family), vec![OTHER_VAULT.to_string()]);
        assert_eq!(
            of(Root::CORE),
            vec![VAULT.to_string(), OTHER_VAULT.to_string()],
            "the core root goes to every target and is the only root that does"
        );

        // Nothing else decides it. A grant over a path inside a root, a rename,
        // and a residency change are each applied and the plan is unchanged —
        // there is no per-path rule in the model for any of them to reach.
        let before = set.replication_plan();
        let _ = set.meaning_of_vfs_grant(&CapabilityGrant::vfs(CapabilityKind::Write, "/notes"));
        for root in set.roots.iter_mut() {
            root.name = format!("{} (renamed)", root.name);
            root.residency = Residency::OnDemand;
        }
        assert_eq!(
            set.replication_plan(),
            before,
            "R15: residency is never topology, and a name is not a target"
        );

        // Changing a target set is the one thing that moves it.
        set.roots
            .iter_mut()
            .find(|r| r.id == family)
            .unwrap()
            .targets
            .push(droplet());
        let after = set.replication_plan();
        assert_ne!(after, before);
        assert_eq!(
            after
                .iter()
                .find(|(r, _)| r == &personal.id)
                .map(|(_, t)| t.len()),
            Some(1),
            "and it moves only the root whose targets changed"
        );
    }

    /// **Membership is who may read, and Personal is found by its tree.** The
    /// two facts the record verbs are handed: which root an
    /// unmarked record belongs to, and which roots a person is in. A root the
    /// person is not a member of is not among them, the core root never is, and
    /// renaming Personal does not lose it.
    #[test]
    fn personal_is_found_by_its_tree_and_member_roots_are_the_ones_the_person_is_in() {
        let temp = tempfile::tempdir().unwrap();
        let mut set = open(temp.path(), &[]);
        let personal = set.personal().expect("first run lays down Personal");
        assert_eq!(personal.tree, VFS_TREE);

        let family = set
            .add("Family", Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();
        let theirs = set
            .add("Theirs", Owner::ThePerson, vec!["did:kel:z6MkSomeoneElse".to_string()], Vec::new(), Residency::Full)
            .unwrap();

        let mut member_of = set.member_roots(AID);
        member_of.sort();
        let mut want = vec![personal.id.clone(), family.clone()];
        want.sort();
        assert_eq!(member_of, want);
        assert!(!member_of.contains(&theirs), "a root the person is not in was readable");
        assert!(!member_of.iter().any(|r| r == Root::CORE), "the core root holds no records");

        // A rename is a rename: Personal is still the root that adopted `data/`.
        set.roots.iter_mut().find(|r| r.id == personal.id).unwrap().name = "Mine".into();
        assert_eq!(set.personal().unwrap().id, personal.id);
    }
}
