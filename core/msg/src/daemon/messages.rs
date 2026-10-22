// SPDX-License-Identifier: AGPL-3.0-or-later
//! Peer messaging IPC handlers — `peer_messaging` sprint.
//!
//! ## Security model
//!
//! * **DMs** are encrypted with an ephemeral X25519 ECDH key derived from the
//!   recipient's `did:key:` (Ed25519 verifying key).  The daemon never stores
//!   the plaintext — only the ChaCha20-Poly1305 ciphertext, the 12-byte nonce,
//!   and the 32-byte ephemeral public key are written to the `sh.kotton.message.v1`
//!   record.
//!
//! * **Channel messages** reuse a 32-byte symmetric channel key distributed to
//!   members via `sh.kotton.channel.key-grant` records (each grant is a DM-
//!   encrypted copy of the channel key — see `channel_key_wrap`/`channel_key_unwrap`
//!   in `kotton_crypto::x25519`).
//!
//! * **Inbox reads** are returned still encrypted; the calling client holds the
//!   decryption key and must decrypt locally.
//!
//! ## Dependency on the OS keychain
//!
//! The sender's/recipient's Ed25519 signing key seed (32 bytes hex) is stored at
//! `kotton:identity_key:{user_id}` and read via `OsSecrets`.  If the key is not
//! in the keychain (session not unlocked, different device), the handler returns
//! an `Error` response — **no silent failure**.

use kotton_wire::ipc::{
    ContactRequest, ContactResponse, Delivery, DeliveryAck, MemberDelivery, SealedDm,
    UserResponse,
};
use crate::daemon::outbox::{self, OutboxEntry, Path, SignedFor};
use crate::envelope::{self, ChannelCopy, ChannelGrant, DmInner, SealedRoster};
use kotton_crypto::reach_note::{Kept, ReachNote};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use kotton_sys::secret::SecretsStore;
use kotton_wire::did::Did;
use kotton_crypto::x25519::{
    channel_decrypt, channel_encrypt, channel_key_generate, channel_key_unwrap, channel_key_wrap,
};
use kotton_common::{
    crypto::kdf_labels,
    namespace::{NSID_CHANNEL_KEY_GRANT, NSID_MESSAGE_V1},
};
use serde_json::json;
use std::io;
use uuid::Uuid;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// `u64` because message timestamps are serialised unsigned on the wire.
///
/// Clamped at zero rather than cast blindly: the shared helper returns `i64`, and
/// a negative there could only come from a pre-1970 clock, which must not wrap
/// into an enormous timestamp on a message record.
fn now_secs() -> u64 {
    kotton_common::time::now_secs().max(0) as u64
}

// ── What this domain needs from its host ──────────────────────────────────────

/// The whole of what messaging asks of the machine it runs on.
///
/// Enumerated rather than assumed: every `runtime.*` and registry call in this
/// file was counted, and it is these six and nothing else — no event bus, no
/// mount locks, no peer client, no transport. The file had been taking
/// `&DeviceRuntime`, which is the machine entire, to reach a keychain, a
/// directory, two key look-ups and a record store.
///
/// This is the [`kotton_peer::membership::MemberStore`] inversion (RFC-0080
/// step 6): **domain logic names what it needs, not who provides it.** With
/// this trait in place `messages.rs` names nothing from the runtime crate, and
/// `core/msg` becomes a move rather than a refactor.
///
/// Two details decided the shape, and both are load-bearing:
///
/// - **Record access is per-user, not pre-resolved.** The obvious design hands
///   in one already-resolved store, and it is wrong: `deliver_locally` writes a
///   copy into *each other member's* store, so the domain must be able to ask
///   for a user it did not start with.
/// - **`record_query` keeps its full signature.** Two of the four call sites
///   pass `limit` and `before_id`; a simplified method would have quietly
///   dropped paging on the history and inbox verbs.
///
/// The last two methods are other domains' vocabulary reached through the host:
/// `user_current_key` is a KEL replay (identity's) and `member_public_key` is
/// [`kotton_peer::membership::Membership`]'s. They are listed here because
/// messaging *uses* them, not because it owns them — which is what a host trait
/// is for.
#[async_trait::async_trait]
pub trait MessageHost: Send + Sync {
    /// The keychain holding this user's signing key and channel-key material.
    fn secrets(&self) -> &(dyn SecretsStore + Send + Sync);

    /// A local user's canonical `did:kel` AID.
    fn user_aid(&self, user_id: &str) -> Option<String>;

    /// Which local user, if any, a DID names — the inverse of [`Self::user_aid`].
    fn local_user_for_did(&self, did: &str) -> Option<String>;

    /// A local user's current authoritative key, by replaying their KEL, so a
    /// rotation is observed immediately rather than after a cache expires.
    fn user_current_key(&self, user_id: &str) -> Option<[u8; 32]>;

    /// A known member's stored key, captured at admission (RFC-0024).
    async fn member_public_key(&self, user_id: &str, did: &str) -> Option<[u8; 32]>;

    /// Every way to reach `contact_did`'s door right now, each once, most
    /// preferred first — or why there is none to try (not a contact, this
    /// identity's key not here).
    ///
    /// *Where the other copy goes* is the machine's question — which relays,
    /// which of the recipient's nodes is awake, whether any is — so the domain
    /// owns no transport and never reads a [`Path`]: it asks for them all and
    /// dials them at once ([`crate::daemon::outbox::dial`]). Nothing that
    /// names one is handed back to a surface.
    ///
    /// **A co-member is reached as a contact is** — somebody this person holds
    /// no card for and shares a channel with ([`co_member`]): the paths their
    /// roster entry's reach note lists, and this node's own, and at the door
    /// the pair derives from the roster's key ([`Self::deliver_on`] alike). A
    /// card, where there is one, is what is read.
    async fn contact_paths(&self, user_id: &str, contact_did: &str) -> Result<Vec<Path>, String>;

    /// Say `request` — a sealed record, handed over or carried — at
    /// `contact_did`'s door along `path` (`DEC-0055`), and return what the door
    /// answered, or why nothing answered. What the answer *means* — whether a
    /// device signed for it — is the domain's, so it comes back whole
    /// ([`crate::daemon::outbox::dial`] reads it).
    async fn deliver_on(
        &self,
        user_id: &str,
        contact_did: &str,
        path: &Path,
        request: &ContactRequest,
    ) -> Result<ContactResponse, String>;

    /// This device signs for `message_id`, which `from_did` (a person on this
    /// device) received from `to_did`
    /// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
    ///
    /// The host signs and the domain never holds the device key: what it gets
    /// is an acknowledgement, under the acknowledgement's own domain tag, and
    /// nothing else can be signed through this.
    fn sign_delivery_ack(&self, message_id: &str, from_did: &str, to_did: &str) -> DeliveryAck;

    /// The reach note `user_id`'s card holds for `contact_did` — the note that
    /// person signed, believed under the key pairing authenticated. Its device
    /// list is the whole of who may sign for a message sent them.
    async fn contact_reach_note(&self, user_id: &str, contact_did: &str) -> Option<ReachNote>;

    /// `user_id`'s own reach note, as their node holds it — what a rotation
    /// they mint seals beside their key in the epoch's roster, so a member
    /// who never paired with them can dial them ([`RosterMember`]). Read, never
    /// signed here: keeping it current is the reach keeper's. `None` when none
    /// is held.
    async fn own_reach_note(&self, _user_id: &str) -> Option<ReachNote> {
        None
    }

    /// The rosters `user_id` holds have changed — a grant filed, an epoch
    /// minted, a channel left — so the people they share a channel with and
    /// hold no card for may have too ([`co_members`]): the host opens and
    /// closes their doors as it does a contact's when the cards change.
    fn rosters_changed(&self, _user_id: &str) {}

    /// Every message waiting in `user_id`'s outbox. An error when the outbox
    /// cannot be listed, never an empty one.
    async fn outbox_entries(&self, user_id: &str) -> anyhow::Result<Vec<OutboxEntry>>;

    /// Keep `entry` in `user_id`'s outbox, replacing the one under its id.
    async fn keep_outbox_entry(&self, user_id: &str, entry: &OutboxEntry) -> anyhow::Result<()>;

    /// Take `id` out of `user_id`'s outbox.
    async fn drop_outbox_entry(&self, user_id: &str, id: &str) -> anyhow::Result<()>;

    /// Keep that a message of `user_id`'s was signed for — and not by which
    /// device, or when.
    async fn keep_signed_for(&self, user_id: &str, signed: &SignedFor) -> anyhow::Result<()>;

    /// Every message of `user_id`'s that was signed for.
    async fn all_signed_for(&self, user_id: &str) -> anyhow::Result<Vec<SignedFor>>;

    /// How long a message waiting in the outbox waits between tries.
    fn outbox_retry(&self) -> outbox::Retry {
        outbox::Retry::DEFAULT
    }

    /// Hold `note`, which arrived sealed from `contact_did`, on `user_id`'s card
    /// for them — if it is theirs, unexpired and newer than the one held
    /// (`kotton_crypto::reach_note::accept`, under the key the card holds).
    async fn keep_reach_note(
        &self,
        user_id: &str,
        contact_did: &str,
        note: ReachNote,
    ) -> Result<Kept, NotKept>;

    /// `user_id`'s own key log, as their node holds it — what travels beside
    /// their reach note so a contact can learn a rotated key from it. Empty when
    /// there is none (a `did:key` identity) or it cannot be read.
    fn own_key_log(&self, user_id: &str) -> Vec<kotton_wire::kel::KelEvent>;

    /// The key log `user_id`'s card keeps for `contact_did` — kept at pairing
    /// and replaced only by [`Self::adopt_contact_key`]. Empty when none is kept.
    fn contact_key_log(&self, user_id: &str, contact_did: &str) -> Vec<kotton_wire::kel::KelEvent>;

    /// Hold `key` as `contact_did`'s on `user_id`'s card, and `log` as the key
    /// log that proved it — the one write that changes a contact's stored key
    /// after admission (`TASK-a-rotated-persons-contacts-keep-the-key-it-retired`).
    /// The caller has already resolved `key` from `log` with
    /// `kotton_crypto::kel_verify::contact_key_from_log` and held a signature to
    /// it; nothing else is written, and nothing says when.
    async fn adopt_contact_key(
        &self,
        user_id: &str,
        contact_did: &str,
        log: &[kotton_wire::kel::KelEvent],
        key: [u8; 32],
    ) -> Result<(), NotKept>;

    /// The identity keys `current` replaced on this node, newest first — kept,
    /// sealed to `current`, so that what was sealed to them still opens for the
    /// person after a rotation
    /// (`TASK-a-rotated-identity-key-leaves-every-older-message-sealed-to-a-key-the-node-no-longer-holds`).
    /// For **opening** only: nothing signs with them and nothing sends them.
    /// Empty when there are none, or when they cannot be read.
    fn retired_identity_keys(&self, user_id: &str, current: &SigningKey) -> Vec<SigningKey>;

    /// The name `user_id`'s card shows for `contact_did` — the one the pair
    /// chose at the ceremony — or `None` for a card with no name. What a share
    /// from them is filed under (RFC-0090, *Filing*).
    async fn contact_name(&self, user_id: &str, contact_did: &str) -> Option<String>;

    /// The names directly in the folder `dir` of `user_id`'s Personal tree —
    /// files and folders alike — or none when there is no such folder yet.
    /// `dir` is relative to the tree's root, as [`Self::personal_write`]'s path is.
    async fn personal_names(&self, user_id: &str, dir: &str) -> Result<Vec<String>, String>;

    /// Write `bytes` at `path` in `user_id`'s Personal tree, through the store's
    /// ordinary file write, missing folders appearing with it: a record of
    /// theirs, as anything they wrote is (RFC-0090 SH1). The one write a share
    /// makes, and the domain composes `path` ([`crate::share::landing`]).
    async fn personal_write(&self, user_id: &str, path: &str, bytes: &[u8]) -> Result<(), String>;

    /// Keep `bytes` under `key` on `user_id`'s **stream shelf**, replacing what
    /// is there: where a share's bytes wait while they stream in, until the
    /// share is filed whole (RFC-0090, *Above the frame cap*;
    /// [`crate::daemon::stream`]). A daemon object in the person's own store,
    /// out of every app's reach and out of their tree, so nothing of a share is
    /// anywhere a person or an app can see until it is filed. The domain
    /// composes `key` from hex, digits and dots only.
    async fn stream_keep(&self, user_id: &str, key: &str, bytes: &[u8]) -> Result<(), String>;

    /// Every key on `user_id`'s stream shelf — an error, never an empty list,
    /// when it cannot be listed, since read as empty a stream would never be
    /// whole and a share never filed.
    async fn stream_keys(&self, user_id: &str) -> Result<Vec<String>, String>;

    /// What [`Self::stream_keep`] kept under `key`.
    async fn stream_read(&self, user_id: &str, key: &str) -> Result<Vec<u8>, String>;

    /// Let go of `key` on `user_id`'s stream shelf.
    async fn stream_drop(&self, user_id: &str, key: &str) -> Result<(), String>;

    /// Write a record into `user_id`'s store.
    async fn record_insert(
        &self,
        user_id: &str,
        nsid: &str,
        record: serde_json::Value,
    ) -> anyhow::Result<String>;

    /// Read records from `user_id`'s store.
    async fn record_query(
        &self,
        user_id: &str,
        nsid: &str,
        field_eq: Vec<(String, serde_json::Value)>,
        limit: Option<usize>,
        offset: Option<usize>,
        before_id: Option<String>,
    ) -> anyhow::Result<Vec<serde_json::Value>>;

    /// Delete the record `record_id` (its `_id`) from `user_id`'s store. The one
    /// delete messaging makes: a person leaving a channel lets go of its
    /// key-grants ([`message_channel_leave`]).
    async fn record_delete(&self, user_id: &str, nsid: &str, record_id: &str) -> anyhow::Result<()>;
}

/// Why a reach note was not kept — and the difference matters to whoever holds
/// it. A **refusal** is the card's verdict on the note (not theirs, older than
/// the one held, expired) and only becomes more true with time, so a vault
/// holding it should let it go and its sender hand it over no more. A
/// **failure** is anything about this node rather than the note: the card
/// could not be read or written, is no contact's card, or this node's clock
/// trails the sender's by no more than a clock explains (a week past the
/// longest life a note may claim) — it may clear, the note may be good, so it
/// stays where it is and is handed again ([`judge_reach_note`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotKept {
    Refused(String),
    Failed(String),
}

impl NotKept {
    /// The reason, whichever it is.
    pub fn reason(&self) -> &str {
        match self {
            NotKept::Refused(r) | NotKept::Failed(r) => r,
        }
    }
}

/// What a card for a contact holds that a reach note from them is judged by:
/// the note it already holds for them, if any, and the identity key pairing
/// authenticated — never one the note or its envelope brought with it.
#[derive(Debug, Clone, Copy)]
pub struct NoteCard<'a> {
    pub held: Option<&'a ReachNote>,
    pub key: &'a [u8; 32],
}

/// The card's rule for a reach note that arrived from `contact_did`, at `now`
/// by this node's clock: `card` is the card this user keeps for them as a
/// contact, `None` when there is none.
///
/// A note the card would judge the same however often it were handed is a
/// [`NotKept::Refused`] — not theirs, ill-formed, expired, or older than the
/// one held — and its sender settles that version on it. A refusal that says
/// something about this node instead is a [`NotKept::Failed`], and the note
/// is handed again
/// (`TASK-a-door-refusal-that-can-clear-settles-a-reach-note-version-until-the-next`):
///
/// - **No card for them** — a fact about this node's cards, which change, and
///   not about the note: a door opened for a card that has since gone or
///   changed, or a card not written yet wherever a note can reach a card
///   before it is.
/// - **A longer life than any note is given, by no more than a clock behind
///   explains** — at most
///   [`CLOCK_BEHIND_SLACK_SECS`](kotton_crypto::reach_note::CLOCK_BEHIND_SLACK_SECS)
///   (seven days) past the longest life
///   ([`kotton_crypto::reach_note::clock_may_explain`]). As this node's clock
///   runs on, the excess shrinks, and within that week the same note is
///   believed. Past the slack it is a verdict: no clock explains it, and the
///   sender's next note will claim as much. Whatever else a note fails while
///   it claims a life within the slack is said the same way, and its verdict
///   reaches the sender once the life fits: a note retried more than it needed
///   costs hand-overs for at most a week, and one settled that would have been
///   kept costs the contact a renewal period.
///
/// An expired note stays a verdict although a clock running ahead can say it
/// too: a note is renewed at half its life, so to read a current one as
/// expired a clock must run at least fifteen days fast, and no amount of
/// waiting clears it.
pub fn judge_reach_note(
    card: Option<NoteCard<'_>>,
    note: &ReachNote,
    contact_did: &str,
    now: u64,
) -> Result<Kept, NotKept> {
    let Some(card) = card else {
        return Err(NotKept::Failed(format!("{contact_did} is not a contact")));
    };
    kotton_crypto::reach_note::accept(card.held, note, card.key, contact_did, now).map_err(|reason| {
        if kotton_crypto::reach_note::clock_may_explain(note, now) {
            NotKept::Failed(reason)
        } else {
            NotKept::Refused(reason)
        }
    })
}

/// Load a user's Ed25519 signing key from the OS keychain.
///
/// Returns `None` when the key is absent (session not unlocked or different
/// device).  Callers must return an `Error` response in that case.
pub(crate) fn load_user_signing_key(user_id: &str, secrets: &dyn SecretsStore) -> Option<SigningKey> {
    let hex = secrets
        .get_secret(&kdf_labels::identity_signing_key(user_id))
        .ok()??;
    let bytes: [u8; 32] = hex::decode(&hex).ok()?.try_into().ok()?;
    Some(SigningKey::from_bytes(&bytes))
}

/// The user's canonical DID — the `did:kel` AID the rest of the system issues.
///
/// This previously derived a `did:key` from the keychain identity key, which
/// made messaging internally consistent and disagreed with everything else:
/// `create_user` returns an AID, contacts are stored under AIDs, and an AID is
/// what a person shares. The mismatch broke channel key grants silently — they
/// were written against the member's AID and looked up under a derived
/// `did:key`, so they never matched.
fn user_did(host: &dyn MessageHost, user_id: &str) -> Option<String> {
    host.user_aid(user_id)
}

/// Resolve a DID to the 32-byte Ed25519 key to encrypt for.
///
/// A `did:kel` AID carries no key in the identifier, so it must be resolved.
/// Two sources, in order:
///
/// 1. **Your own AID** — replay your local key event log, which is what grant
///    verification does too, so a rotation is picked up immediately.
/// 2. **A known member** — `Member::public_key`, stored at admission precisely
///    so this needs no re-derivation, and replaced since only by a key their
///    own key log proved (`delivery`'s `sender_key`).
///
/// A DID that is neither is refused by name rather than guessed at: encrypting
/// to the wrong key would produce a message nobody can open.
///
/// **Not a co-member's roster key.** A person this one shares a channel with
/// and never paired with is named with a key in that channel's roster, and
/// that key seals and verifies the channel's copies only ([`key_in_channel`]).
/// A direct message — the one thing this resolves for besides a rotation's
/// own key — is sealed only to a card's: what a person may say outside a
/// channel waits on their pairing.
async fn pubkey_for_did(
    host: &dyn MessageHost,
    user_id: &str,
    did_str: &str,
) -> Result<[u8; 32], String> {
    // Reject junk here, so a malformed DID fails as itself rather than as a
    // confusing lookup miss further down.
    Did::parse(did_str).map_err(|e| format!("invalid DID: {e}"))?;

    if host.user_aid(user_id).as_deref() == Some(did_str) {
        return host.user_current_key(user_id)
            .ok_or_else(|| "could not resolve your own key from your KEL".to_string());
    }

    host.member_public_key(user_id, did_str)
        .await
        .ok_or_else(|| {
            format!("no key known for {did_str} — pair with them first so their key is stored")
        })
}

// ── Channel key epochs ────────────────────────────────────────────────────────

/// The epoch a key-grant or channel message belongs to.
///
/// Absent means **epoch 0**: every grant and message written before epochs
/// existed belongs to the channel's first key. Reading them that way is what
/// keeps a conversation that already exists readable by the people already in
/// it — the identity-continuity invariant outranks anything this tightens.
fn epoch_of(record: &serde_json::Value) -> u64 {
    record.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0)
}

/// Every key-grant `user_id` can actually open for `channel_did`, newest epoch
/// first.
///
/// Filtered to `to_did == self_did` because the store also holds grants
/// addressed to *other* members — the granter keeps a copy of each, which is
/// how membership was counted before the roster travelled in the grant
/// ([`current_members`]) — and those are wrapped to keys this user does not
/// hold.
///
/// The epoch is selected here rather than in the query on purpose.
/// `record_query` binds every filter value as text while `json_extract` yields
/// an integer for a JSON number, and SQLite never compares those equal, so an
/// `("epoch", json!(n))` filter would silently match nothing.
pub(crate) async fn own_grants(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    self_did: &str,
) -> Vec<serde_json::Value> {
    let mut grants = host.record_query(
        user_id,
        NSID_CHANNEL_KEY_GRANT,
        vec![
            ("channel_did".to_string(), json!(channel_did)),
            ("to_did".to_string(), json!(self_did)),
        ],
        None,
        None,
        None,
    )
    .await
    .unwrap_or_default();
    grants.sort_by_key(|g| std::cmp::Reverse(epoch_of(g)));
    grants
}

/// One member as an epoch's roster names them, `{did, key, reach, kel}`: their
/// DID and, in a roster minted since 2026-10-09, the identity key, the reach
/// note and the key log the person who minted the epoch held for them
/// (`TASK-a-channel-member-who-is-not-the-senders-contact-never-receives-the-senders-copies`;
/// RFC-0064, the note of 2026-10-09 on co-members).
///
/// The key and the note are what a member's **card** holds for a contact, and
/// they are here for the members who hold no card for each other: two people
/// in a household who never paired. Holding the epoch's key is what makes
/// someone a member (RFC-0090 SH4), so what the minting member knew of each
/// member from their card is shared with the members — under the epoch's key,
/// and with nobody else. With it, a member seals a copy to another they never
/// paired with, dials them, and holds what they say to that key — **for that
/// channel's copies only** (`delivery::co_member_may_say`).
///
/// **A card wins.** Where a node holds a card for somebody, the card's key and
/// note are used and the roster's are not; the roster speaks only for people
/// this node never paired with.
///
/// **The key is the member's own log's, not the minting member's word**
/// (`TASK-a-roster-key-is-the-minting-members-word-and-not-the-members-own-log`;
/// the orchestrator's ruling of 2026-10-09). Beside each key the roster carries
/// the member's key log as the minting member holds it — the chain a pairing
/// keeps on the card, or the one a roster handed them — and a node opening the
/// roster believes the key only when that log, replayed from the member's
/// `did:kel` DID, yields it ([`log_yields`]: the check a card already holds a
/// contact's carried log to, `kotton_crypto::kel_verify::contact_key_from_log`).
/// An entry whose log does not yield its key, or names somebody else, or that
/// carries none, keeps its DID — it is a member for the roster's count — and
/// loses its key and its note: unreachable and unverifiable, as an entry from
/// before keys travelled is. So a member who mints an epoch cannot name a key
/// of their own for somebody else and speak as them: the DID is the digest of
/// its own inception, and nobody but its holder extends its log. A member's
/// reach note is believed only when it is signed under the key so proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterMember {
    pub did: String,
    /// Their identity key — `None` in a roster from before keys travelled,
    /// where the minting member knew none, or where the log beside it does not
    /// yield it.
    pub key: Option<[u8; 32]>,
    /// The reach note they signed, as the minting member's card held it.
    pub reach: Option<ReachNote>,
    /// Their key log, as the minting member held it: what proves `key` is
    /// theirs. Empty where none was held.
    pub kel: Vec<kotton_wire::kel::KelEvent>,
}

/// Whether `log` — a member's key log, as a roster carries it — replays from
/// `did` and yields `key` as the key it installs now: its inception's digest is
/// `did`, every event after it is the identity's own, and the last key it
/// installs is `key`. Nothing else is believed of a roster's key.
pub(crate) fn log_yields(did: &str, key: &[u8; 32], log: &[kotton_wire::kel::KelEvent]) -> bool {
    !log.is_empty() && kotton_crypto::kel_verify::contact_key_from_log(&[], key, did, log).as_ref() == Ok(key)
}

impl RosterMember {
    /// A member named by their DID alone, as every roster before 2026-10-09
    /// named them.
    pub fn bare(did: &str) -> Self {
        Self { did: did.to_string(), key: None, reach: None, kel: Vec::new() }
    }

    /// As it is sealed: `{"did", "key", "reach", "kel"}`, the key hex, and each
    /// of the three left out when it is not known.
    fn to_json(&self) -> serde_json::Value {
        let mut entry = json!({ "did": self.did });
        if let Some(key) = &self.key {
            entry["key"] = json!(hex::encode(key));
        }
        if let Some(note) = &self.reach {
            entry["reach"] = json!(note);
        }
        if !self.kel.is_empty() {
            entry["kel"] = json!(self.kel);
        }
        entry
    }

    /// One entry of an opened roster, in any of its shapes: a DID alone, as a
    /// roster from before 2026-10-09 lists its members; `{"did", "key"?,
    /// "reach"?}`, as one minted between keys travelling and their logs doing
    /// so; or `{"did", "key", "reach", "kel"}`.
    ///
    /// The key is kept only when the log beside it yields it for `did`
    /// ([`log_yields`]). A key with no log — the middle shape — or with one
    /// that does not yield it is dropped, and the member is named by their DID
    /// alone. A reach note is kept only beside a key so kept, when it is the
    /// member's, signed under that key and unexpired at `now`
    /// (`kotton_crypto::reach_note::verify`); otherwise the member is dialled at
    /// the sender's own relay, as a card with no note is. A key that is not 32
    /// bytes of hex is a malformed roster; a log that does not parse is none.
    fn from_json(entry: &serde_json::Value, now: u64) -> Result<Self, String> {
        if let Some(did) = entry.as_str() {
            return Ok(Self::bare(did));
        }
        let did = entry
            .get("did")
            .and_then(|d| d.as_str())
            .ok_or_else(|| "roster: a member that is not a DID".to_string())?
            .to_string();
        let claimed = match entry.get("key").and_then(|k| k.as_str()) {
            None => None,
            Some(hex_key) => Some(
                hex::decode(hex_key)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or_else(|| format!("roster: {did}'s key is not 32 bytes of hex"))?,
            ),
        };
        let kel: Vec<kotton_wire::kel::KelEvent> = entry
            .get("kel")
            .and_then(|k| serde_json::from_value(k.clone()).ok())
            .unwrap_or_default();
        let key = claimed.filter(|key| {
            let proved = log_yields(&did, key, &kel);
            if !proved {
                tracing::debug!(member = %did, "a roster names a key its member's own log does not yield; it is not believed");
            }
            proved
        });
        let reach = match (entry.get("reach"), &key) {
            (Some(note), Some(key)) => serde_json::from_value::<ReachNote>(note.clone())
                .ok()
                .filter(|note| kotton_crypto::reach_note::verify(note, key, &did, now).is_ok()),
            _ => None,
        };
        Ok(Self { did, key, reach, kel })
    }
}

/// An epoch's roster, sealed under its channel key for the grants of that
/// epoch ([`SealedRoster`]).
///
/// The plaintext is `{"members": [{did, key, reach, kel}, …]}` ([`RosterMember`]):
/// an object rather than a bare list so that a channel's name can sit beside
/// the members if the owner rules for it (the naming idea's Shape 1), without
/// a second shape to read.
pub fn seal_roster(channel_key: &[u8; 32], members: &[RosterMember]) -> Result<SealedRoster, String> {
    seal_roster_admitting(channel_key, members, None)
}

/// [`seal_roster`], naming beside the members the one DID the rotation that
/// minted this epoch **admitted**, when it admitted somebody: `{"members":
/// [...], "admitted": did}`. It is how a node that left the channel tells an
/// invitation back — an epoch minted to admit it — from a grant minted before
/// its leave reached anybody, which only names it among the members
/// ([`roster_admits`]; `delivery::file_grant`). Sealed with the roster, so
/// nothing outside the epoch's key sees who was admitted.
pub(crate) fn seal_roster_admitting(
    channel_key: &[u8; 32],
    members: &[RosterMember],
    admitted: Option<&str>,
) -> Result<SealedRoster, String> {
    let entries: Vec<serde_json::Value> = members.iter().map(RosterMember::to_json).collect();
    let mut roster = json!({ "members": entries });
    if let Some(did) = admitted {
        roster["admitted"] = json!(did);
    }
    let plaintext = serde_json::to_vec(&roster)
        .map_err(|e| format!("could not write the channel's roster: {e}"))?;
    let (body, nonce) = channel_encrypt(&plaintext, channel_key)
        .map_err(|e| format!("could not seal the channel's roster: {e}"))?;
    Ok(SealedRoster { body: B64.encode(body), nonce: B64.encode(nonce) })
}

/// The roster a grant record carries, still sealed — `None` for a grant minted
/// before rosters existed.
fn sealed_roster_of(grant: &serde_json::Value) -> Option<SealedRoster> {
    let field = |k: &str| grant.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    Some(SealedRoster { body: field("roster")?, nonce: field("roster_nonce")? })
}

/// Open a grant's roster with the channel key the same grant unwrapped to,
/// each member in either shape ([`RosterMember::from_json`]): a roster from
/// before 2026-10-09 lists DIDs alone, and reads as members with no key.
///
/// `None` when the grant carries no roster (minted before rosters existed);
/// `Some(Err)` when it carries one that does not open under its own key, which
/// only a malformed grant does.
fn open_roster(grant: &serde_json::Value, channel_key: &[u8; 32]) -> Option<Result<Vec<RosterMember>, String>> {
    let opened = match open_roster_object(grant, channel_key)? {
        Ok(opened) => opened,
        Err(e) => return Some(Err(e)),
    };
    let now = now_secs();
    Some((|| {
        opened
            .get("members")
            .and_then(|m| m.as_array())
            .ok_or_else(|| "roster: no member list".to_string())?
            .iter()
            .map(|entry| RosterMember::from_json(entry, now))
            .collect()
    })())
}

/// A grant's roster opened, as the object it was sealed as — `None` for a grant
/// minted before rosters.
fn open_roster_object(grant: &serde_json::Value, channel_key: &[u8; 32]) -> Option<Result<serde_json::Value, String>> {
    let sealed = sealed_roster_of(grant)?;
    Some((|| {
        let body = B64.decode(&sealed.body).map_err(|e| format!("roster: base64 of the body: {e}"))?;
        let nonce: [u8; 12] = B64
            .decode(&sealed.nonce)
            .map_err(|e| format!("roster: base64 of the nonce: {e}"))?
            .try_into()
            .map_err(|_| "roster: the nonce must be 12 bytes".to_string())?;
        let plaintext = channel_decrypt(&body, &nonce, channel_key)
            .map_err(|e| format!("roster: does not open under its own epoch's key: {e}"))?;
        serde_json::from_slice(&plaintext).map_err(|e| format!("roster: not JSON: {e}"))
    })())
}

/// The DID the rotation that minted `grant`'s epoch admitted, read from its
/// roster opened under `channel_key` ([`seal_roster_admitting`]) — `None` when
/// it admitted nobody, carries no roster, or its roster does not open.
pub(crate) fn roster_admits(grant: &serde_json::Value, channel_key: &[u8; 32]) -> Option<String> {
    open_roster_object(grant, channel_key)?
        .ok()?
        .get("admitted")
        .and_then(|d| d.as_str())
        .map(str::to_owned)
}

/// Who holds a channel's current key, as one member's node knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Members {
    /// The epoch of the grant this was read from — the newest the member can
    /// open.
    pub epoch: u64,
    /// Every DID that epoch's key was granted to, each once.
    pub dids: Vec<String>,
    /// Read from the roster sealed in that grant (`true`), or counted from the
    /// grant records in the member's own store because the grant was minted
    /// before rosters existed (`false`). Only a sealed roster is the whole
    /// membership; a count is whatever the store happens to hold.
    pub sealed: bool,
}

/// The DIDs holding the channel's **current** key, and which epoch that is —
/// read from the roster sealed in `user_id`'s **newest grant they can open**
/// (RFC-0064, *Encryption model for channels*, the note of 2026-10-08).
///
/// The roster travels inside every grant of an epoch, under that epoch's key,
/// written by whoever minted it. So any member reads the whole membership from
/// their own grant, and not only the person who wrote the grants: until
/// 2026-10-08 this counted the grant records in the caller's store, where only
/// the granter holds everyone's, and to every other member the channel was a
/// channel of one
/// (`TASK-a-channel-member-who-admitted-nobody-sees-a-channel-of-one`).
///
/// Only current-epoch holders count as members: a rotation that leaves someone
/// out is how a member stops being one, so reading membership at the latest
/// epoch is what makes removal expressible at all.
///
/// **A grant minted before rosters existed** carries none, and for it this
/// falls back to the counting it replaced: every grant in the caller's store at
/// that grant's epoch. That is the whole membership for the person who wrote
/// the grants and only their own entry for anyone else, as it always was. No
/// migration: the next rotation mints an epoch that carries a roster.
///
/// `None` when the caller holds no grant for the channel that they can open.
/// A grant whose roster will not open under its own key is malformed and is
/// passed over for the next one, said in the log.
pub(crate) async fn current_members(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    self_did: &str,
    sk: &SigningKey,
    retired: &mut Option<Vec<SigningKey>>,
) -> Option<Members> {
    for grant in own_grants(host, user_id, channel_did, self_did).await {
        let Ok(key) = unwrap_own_grant(host, user_id, &grant, sk, retired) else {
            continue;
        };
        let epoch = epoch_of(&grant);
        match open_roster(&grant, &key) {
            Some(Ok(roster)) => {
                let mut dids: Vec<String> = Vec::with_capacity(roster.len());
                for member in roster {
                    if !dids.contains(&member.did) {
                        dids.push(member.did);
                    }
                }
                return Some(Members { epoch, dids, sealed: true });
            }
            Some(Err(e)) => {
                tracing::warn!(epoch, error = %e, "a key-grant's roster does not open; passing over it");
                continue;
            }
            None => {
                return Some(Members {
                    epoch,
                    dids: counted_members(host, user_id, channel_did, epoch).await,
                    sealed: false,
                })
            }
        }
    }
    None
}

/// The membership as it was read before the roster travelled in the grant:
/// the `to_did` of every grant record in `user_id`'s store for the channel at
/// `epoch`. Kept only for a grant minted before rosters ([`current_members`]).
///
/// Deduplicated because a member who has been present across several epochs
/// holds one grant per epoch. No query limit: this is bounded by members ×
/// epochs for a single channel, and a cap here would silently drop members
/// from both delivery and rotation.
async fn counted_members(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    epoch: u64,
) -> Vec<String> {
    let grants = host.record_query(
        user_id,
        NSID_CHANNEL_KEY_GRANT,
        vec![("channel_did".to_string(), json!(channel_did))],
        None,
        None,
        None,
    )
    .await
    .unwrap_or_default();

    let mut dids: Vec<String> = Vec::new();
    for did in grants
        .iter()
        .filter(|g| epoch_of(g) == epoch)
        .filter_map(|g| g.get("to_did").and_then(|d| d.as_str()))
    {
        if !dids.iter().any(|d| d == did) {
            dids.push(did.to_string());
        }
    }
    dids
}

/// Wrap `channel_key` for `member_did` at `epoch` and store the resulting grant,
/// carrying `roster` — the epoch's membership sealed under `channel_key`
/// ([`seal_roster`]) — when there is one.
///
/// Two copies, deliberately. One goes to the member — into their own store when
/// they have an identity on this device, over their door when they do not —
/// and that is delivery; the roster inside it is how they learn who else holds
/// this key. One always goes to the granter's store, carrying the same roster:
/// it is the granter's record of the grant, and for a channel whose newest
/// grant predates rosters it is still the count membership is read from
/// ([`current_members`]).
#[allow(clippy::too_many_arguments)]
async fn write_grant(
    host: &dyn MessageHost,
    granter_user_id: &str,
    channel_did: &str,
    member_did: &str,
    member_pub: &[u8; 32],
    channel_key: &[u8; 32],
    epoch: u64,
    roster: Option<&SealedRoster>,
) -> Result<serde_json::Value, String> {
    let (enc_key, nonce, eph_pub) = channel_key_wrap(channel_key, member_pub)
        .map_err(|e| format!("channel key wrap for {member_did} failed: {e}"))?;

    let mut grant = json!({
        "channel_did": channel_did,
        "to_did": member_did,
        "enc_key": B64.encode(enc_key),
        "nonce": B64.encode(nonce),
        "ephemeral_pub": B64.encode(eph_pub),
        "epoch": epoch,
        "granted_at": now_secs(),
    });
    if let Some(roster) = roster {
        grant["roster"] = json!(roster.body);
        grant["roster_nonce"] = json!(roster.nonce);
    }

    // The granter's copy is their record of the grant, so its failure is fatal
    // to the grant: a rotation the granter cannot account for is not one to
    // half-finish.
    host.record_insert(granter_user_id, NSID_CHANNEL_KEY_GRANT, grant.clone())
        .await
        .map_err(|e| format!("could not record the grant for {member_did}: {e}"))?;

    // Skipped when the member *is* the granter — the copy above already served
    // both purposes, and inserting again would duplicate it in one store, and
    // there is no door of their own to hand it over. Asked of the DID as well
    // as of the machine's directory: until 2026-10-09 a granter with no card
    // for themselves was skipped by the card miss in `hand_grant_over`, and a
    // grant sealed to a key the rotation resolved has no such miss.
    if user_did(host, granter_user_id).as_deref() == Some(member_did) {
        return Ok(grant);
    }
    match host.local_user_for_did(member_did) {
        Some(member_user_id) if member_user_id == granter_user_id => {}
        Some(member_user_id) => {
            if let Err(e) = host.record_insert(&member_user_id,
                NSID_CHANNEL_KEY_GRANT,
                grant.clone(),
            )
            .await
            {
                tracing::warn!(
                    member_user_id = %member_user_id,
                    error = %e,
                    "grant: could not write into the member's local store"
                );
            }
        }
        // A member on another daemon. Their copy goes over the door the granter
        // already has to them — the same route a message takes, because a channel
        // has no node of its own and there is no other route to build.
        //
        // Until 2026-09-09 this branch did not exist and the doc above said their
        // copy *"travels by sync"*. Between two people who have only paired there
        // is no sync to travel by, so a channel spanning two daemons could be
        // created and could never be opened by anyone but its creator. That was
        // invisible because every channel test had all its members on one daemon.
        //
        // Best-effort, and deliberately not fatal: the granter's own copy above is
        // the membership record and is already written, so a member who could not
        // be reached now is still in the channel and is re-granted by the next
        // rotation. A failure here would otherwise abandon a rotation half done.
        None => {
            if let Err(e) =
                hand_grant_over(host, granter_user_id, member_did, member_pub, channel_did, &grant).await
            {
                tracing::warn!(
                    member_did = %member_did,
                    error = %e,
                    "grant: could not hand a member's key-grant to their node; they are in \
                     the channel and cannot open it until they are granted again"
                );
            }
        }
    }

    Ok(grant)
}

/// Seal one member's key-grant to them, under `member_pub` — the key the
/// rotation resolved for them: a card's, or for a co-member the roster's
/// ([`member_in_rotation`]) — and hand it over their door, which for a
/// co-member is the pair's door the roster's key derives ([`co_member`]).
async fn hand_grant_over(
    host: &dyn MessageHost,
    granter_user_id: &str,
    member_did: &str,
    member_pub: &[u8; 32],
    channel_did: &str,
    grant: &serde_json::Value,
) -> Result<(), String> {
    let Some(sender_key) = load_user_signing_key(granter_user_id, host.secrets()) else {
        return Err("identity key unavailable — unlock your session first".to_string());
    };
    let Some(from_did) = user_did(host, granter_user_id) else {
        return Err("identity unavailable".to_string());
    };
    let str_field = |k: &str| grant.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let inner = DmInner {
        from_did,
        to_did: member_did.to_string(),
        thread_id: Uuid::new_v4().to_string(),
        sent_at: now_secs(),
        kind: "text".to_string(),
        text: String::new(),
        channel: None,
        grant: Some(ChannelGrant {
            channel_did: channel_did.to_string(),
            epoch: grant.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0),
            enc_key: str_field("enc_key"),
            nonce: str_field("nonce"),
            ephemeral_pub: str_field("ephemeral_pub"),
            granted_at: grant.get("granted_at").and_then(|v| v.as_u64()).unwrap_or_else(now_secs),
            roster: sealed_roster_of(grant),
        }),
        reach: None,
        ack: None,
        kel: Vec::new(),
        share: None,
        range: None,
    };
    let sealed = envelope::seal(&inner, &sender_key, member_pub)?;
    match outbox::hand_over(host, granter_user_id, member_did, &sealed).await {
        Delivery::Delivered | Delivery::Sent | Delivery::AlreadyHeld | Delivery::Local => Ok(()),
        Delivery::Unreachable { reason } => Err(reason),
    }
}

/// Seal `user_id`'s reach note to one contact and hand it over their door —
/// the same door and the same path a message takes, so the note reaches exactly
/// the people a message could and nobody else
/// (`TASK-a-persons-reach-note-is-signed-by-them-and-replaces-relay-url`).
///
/// A contact who is another account on this machine is not sent one: nothing
/// travels between them, so there is nowhere a note would route.
///
/// Read whole ([`outbox::Handed`]): their card refusing this note is said apart
/// from not reaching them, because only the second changes on a retry.
pub async fn hand_reach_note_over(
    host: &dyn MessageHost,
    user_id: &str,
    contact_did: &str,
    note: &ReachNote,
) -> outbox::Handed {
    use outbox::Handed;
    if host.local_user_for_did(contact_did).is_some() {
        return Handed::Delivery(Delivery::Local);
    }
    let Some(sender_key) = load_user_signing_key(user_id, host.secrets()) else {
        return Handed::Delivery(Delivery::Unreachable {
            reason: "identity key unavailable — unlock your session first".to_string(),
        });
    };
    let Some(contact_pub) = host.member_public_key(user_id, contact_did).await else {
        return Handed::Delivery(Delivery::Unreachable {
            reason: format!("{contact_did} is not a contact, so there is no door to hand a note to"),
        });
    };
    let inner = DmInner {
        from_did: note.did.clone(),
        to_did: contact_did.to_string(),
        thread_id: String::new(),
        sent_at: now_secs(),
        kind: "reach".to_string(),
        text: String::new(),
        channel: None,
        grant: None,
        reach: Some(note.clone()),
        ack: None,
        // The proof a card needs to follow this person through a rotation: the
        // note below is signed with their current key, and a card still holding
        // a retired one learns the current one from this and from nothing else.
        kel: host.own_key_log(user_id),
        share: None,
        range: None,
    };
    match envelope::seal(&inner, &sender_key, &contact_pub) {
        Ok(sealed) => outbox::hand_over_answered(host, user_id, contact_did, &sealed).await,
        Err(reason) => Handed::Delivery(Delivery::Unreachable { reason }),
    }
}

/// `(person, contact)` → the version of the person's reach note that contact
/// has settled: something of theirs took it, or their card refused that very
/// version. Kept by whoever hands notes out (`kuserd`'s reach keeper), in
/// memory; empty after a restart, which sends each contact the current note
/// once more and settles it again.
pub type NotesSettled = std::collections::HashMap<(String, String), u64>;

/// Hand `user_id`'s `note` to each of `contacts` that has not settled its
/// version, and keep in `settled` each that settles it now
/// (`TASK-a-reach-note-a-contact-refused-is-sent-to-them-again-every-hour`).
///
/// A contact settles a version by taking it — *delivered*, *sent*, already
/// held, or another account here — or by their card declining it: not theirs,
/// expired, or older than the one the card holds. Handed again, the card would
/// say the same, so that version is not handed to them again; a newer one is.
/// A contact nothing of whose answered, or whose door refused for a reason
/// that may clear — a vault holding as much as it will, a card that could not
/// be written or is no contact's card, a clock behind this person's within
/// the slack a clock explains
/// ([`judge_reach_note`]) — has settled nothing, and is handed the note again
/// on the next call. One device of theirs refusing it so while another is
/// silent settles nothing either: a refusal that may clear outranks no
/// silence (`outbox::race`).
///
/// What *taken* means stays the door's: holding a note until one of the
/// contact's devices signs for it is the outbox's work
/// (`TASK-a-persons-reach-travels-with-their-identity-and-a-message-reaches-them-by-whatever-path-works`,
/// its second unit).
pub async fn hand_reach_note_to(
    host: &dyn MessageHost,
    user_id: &str,
    contacts: &[String],
    note: &ReachNote,
    settled: &mut NotesSettled,
) {
    use outbox::Handed;
    for contact in contacts {
        let slot = (user_id.to_string(), contact.clone());
        if settled.get(&slot) == Some(&note.version) {
            continue;
        }
        match hand_reach_note_over(host, user_id, contact, note).await {
            Handed::Delivery(Delivery::Unreachable { reason }) => {
                tracing::info!(
                    user_id,
                    contact = %contact,
                    version = note.version,
                    reason = %reason,
                    "a contact could not be handed the current reach note; the next pass tries again"
                );
            }
            Handed::Delivery(_) => {
                tracing::debug!(user_id, contact = %contact, version = note.version, "reach note delivered");
                settled.insert(slot, note.version);
            }
            Handed::Declined { reason } => {
                tracing::info!(
                    user_id,
                    contact = %contact,
                    version = note.version,
                    reason = %reason,
                    "a contact's card refused the current reach note; it is not handed to them again"
                );
                settled.insert(slot, note.version);
            }
        }
    }
}

/// Mint a fresh channel key at `epoch` and grant it to exactly `members`.
///
/// This is what makes membership structural rather than incidental. The channel
/// key is symmetric and long-lived, so re-wrapping the *existing* key for a new
/// member hands them every message the channel has ever carried — the only thing
/// between them and yesterday's conversation would be which rows happened to be
/// copied, which is a delivery policy wearing a confidentiality property's
/// clothes. A fresh key per membership change makes the boundary real: a member
/// holds grants for the epochs they were part of and cannot open the others.
///
/// Whoever is absent from `members` is not granted the new key, which is also
/// how a member is removed ([`message_channel_remove_member`]) — no second
/// mechanism.
///
/// `admitted` is the DID this rotation admits, when it admits somebody: it is
/// sealed beside the roster ([`seal_roster_admitting`]).
///
/// Returns each `(did, grant)` written, so the caller can relay a member's grant
/// out-of-band.
async fn rotate_channel_key(
    host: &dyn MessageHost,
    granter_user_id: &str,
    channel_did: &str,
    epoch: u64,
    members: &[String],
    admitted: Option<&str>,
) -> Result<Vec<(String, serde_json::Value)>, String> {
    // Every key is resolved before anything is written. A rotation that grants
    // half the members a new key and abandons the rest leaves a channel nobody
    // can fully read, and the likeliest failure — a member whose key no longer
    // resolves — is knowable up front.
    //
    // Each member's key, reach note and key log are what this node knows of
    // them: its own, a card's — a card wins — or, for a member it never paired
    // with, what the rosters it holds for this channel carry
    // ([`member_in_rotation`]). So the next epoch names everybody with what
    // its minting member knew of them, and a member who holds no card for
    // another reaches them all the same (RFC-0064, the note of 2026-10-09).
    let rosters = Rosters::held(host, granter_user_id, channel_did).await;
    let mut targets: Vec<RosterMember> = Vec::with_capacity(members.len());
    for did in members {
        targets.push(member_in_rotation(host, granter_user_id, &rosters, did).await?);
    }

    let channel_key = channel_key_generate();
    // The epoch's roster, sealed once under its key and carried in every grant
    // of it — so each member learns who else holds the key from the grant that
    // hands it to them, and from nothing else (RFC-0064, the note of 2026-10-08).
    let roster = seal_roster_admitting(&channel_key, &targets, admitted)?;
    let mut written = Vec::with_capacity(targets.len());
    for member in &targets {
        // A member carried as a DID alone is one whose logs diverge here
        // ([`member_in_rotation`]): named in the roster, wrapped no grant.
        let Some(member_pub) = member.key else { continue };
        let grant = write_grant(
            host,
            granter_user_id,
            channel_did,
            &member.did,
            &member_pub,
            &channel_key,
            epoch,
            Some(&roster),
        )
        .await?;
        written.push((member.did.clone(), grant));
    }
    // The members this node holds no card for may have changed with the
    // roster, and a copy waiting for somebody it omits is nobody's now.
    roster_changed(host, granter_user_id, channel_did).await;
    Ok(written)
}

/// `did` as the epoch a rotation by `user_id` mints names them in its roster:
/// their identity key, their reach note and the key log that proves the key,
/// as this node knows them ([`RosterMember`]). `rosters` are the ones this node
/// holds for the channel.
///
/// - **This person** — the key their own log resolves to, the reach note their
///   node holds ([`MessageHost::own_reach_note`]), and their own log
///   ([`MessageHost::own_key_log`]).
/// - **A contact** — the card's key and note, and the log the card keeps
///   ([`MessageHost::contact_key_log`]). A card wins. A card that keeps no log
///   — a contact paired before logs were kept — names a key every other
///   member drops ([`log_yields`]); the rotation still wraps their grant to it.
/// - **A co-member** — never paired with, so no card: what the newest roster
///   this node holds that names them with a key carries ([`Rosters::member`]),
///   the log beside it copied as it came — the log that proved the key here.
///   So what they were known by when this node was handed its epoch is passed
///   on, and a key or a note they have changed since reaches the members who
///   hold no card for them only when somebody who does holds a card mints the
///   next epoch.
///
/// **Never refused for a member none of the three gives a key for** — one
/// whose logs diverge here ([`Rosters::disputed`]), one a roster names bare, or
/// one named only by a roster from before keys travelled: they are carried as
/// a DID alone and wrapped no grant, and the rotation completes. The one key a
/// rotation cannot do without is the rotating person's own, read from their
/// own log; and the person a rotation **admits** must have a key believed here,
/// which [`rotate_membership`] asks before anything is minted.
async fn member_in_rotation(
    host: &dyn MessageHost,
    user_id: &str,
    rosters: &Rosters,
    did: &str,
) -> Result<RosterMember, String> {
    if host.user_aid(user_id).as_deref() == Some(did) {
        let key = pubkey_for_did(host, user_id, did).await?;
        return Ok(RosterMember {
            did: did.to_string(),
            key: Some(key),
            reach: host.own_reach_note(user_id).await,
            kel: host.own_key_log(user_id),
        });
    }
    if let Some(key) = host.member_public_key(user_id, did).await {
        return Ok(RosterMember {
            did: did.to_string(),
            key: Some(key),
            reach: host.contact_reach_note(user_id, did).await,
            kel: host.contact_key_log(user_id, did),
        });
    }
    match rosters.resolve(did) {
        Named::Believed(named) => Ok(named.clone()),
        // **A rotation proceeds on a fork** (the orchestrator's ruling on the
        // assessor's last ground at `ff3fd1422`). Refusing would let whoever
        // holds a retired key of any member's stop this node minting any epoch
        // — a removal of the forger, the elector's rotation after a leave. So
        // the disputed member is carried as a DID alone — no key, no note, and
        // no log, from neither side, so the fork does not travel on — and is
        // wrapped no grant at this epoch: denied on this node's epochs until a
        // node holding their card rotates and names them again from it.
        // **A rotation never refuses for a member's missing key** (the
        // orchestrator's rulings on the assessor's grounds at `ff3fd1422` and
        // `cc7652b47`). Whatever the reason this node believes no key for a
        // member — their logs diverge here, a roster names them bare, a roster
        // from before keys travelled, no card — refusing would let any of them
        // stall the channel on this node: no admission, no removal of a
        // forger, no elector's rotation after a leave. So the member is carried
        // as a DID alone — no key, no note, and no log, so neither side of a
        // fork travels on — wrapped no grant at this epoch, and named in a
        // warning. They are denied on this node's epochs, never evicted: their
        // DID stays in every roster, and the next rotation by a node that holds
        // their card or a believed entry names them in full again.
        Named::Disputed | Named::Unknown => {
            tracing::warn!(
                channel = %rosters.channel_did,
                member = %did,
                "a rotation carries a member this node believes no key for as a DID alone, and wraps them no grant"
            );
            Ok(RosterMember::bare(did))
        }
    }
}

// ── MessageSend ───────────────────────────────────────────────────────────────

/// Encrypt `body` as a DM to `recipient_did` and store it as a
/// `sh.kotton.message.v1` record owned by `user_id`.
///
/// The record stored in the DB contains only ciphertext; the daemon never
/// writes the plaintext to any persistent store.
pub async fn message_send(
    host: &dyn MessageHost,
    user_id: String,
    recipient_did: String,
    body: String,
    thread_id: Option<String>,
) -> io::Result<UserResponse> {
    send_direct(host, user_id, recipient_did, thread_id, Said::Text(body)).await
}

// ── MessageShare ──────────────────────────────────────────────────────────────

/// Share a file called `name`, holding `data`, with `recipient_did`: a direct
/// message whose `type` is `share` and whose body is the file's
/// [`Manifest`](crate::share::Manifest) (RFC-0090, *Delivery › To one person*;
/// `TASK-a-file-shared-with-a-contact-is-a-copy-of-theirs-under-shared-with-you`).
///
/// **The message protocol's own path, and nothing added.** [`message_send`]
/// and this are one function past the manifest: sealed to the recipient with a
/// fresh key, handed over their contact door, kept in the outbox until a device
/// of theirs signs for it, waiting at their vault otherwise; and the sender's
/// own copy sealed to the sender. The two copies differ in one field —
/// `origin`, which names the sender's file and is on the sender's copy only
/// (SH5).
///
/// A file above [`INLINE_MAX`](crate::share::INLINE_MAX) is sent as its
/// manifest first, with `stream` set and `inline` absent, and its bytes follow
/// as sealed ranges over the same door, each kept in the outbox until a device
/// of theirs signs for it (RFC-0090, *Delivery › Above the frame cap*;
/// [`outbox::send_share`]). A file above
/// [`STREAM_MAX`](crate::share::STREAM_MAX) — more than their node files in
/// one piece — is refused here, with a sentence that says why.
pub async fn message_share(
    host: &dyn MessageHost,
    user_id: String,
    recipient_did: String,
    name: String,
    data: Vec<u8>,
    origin: Option<String>,
    thread_id: Option<String>,
) -> io::Result<UserResponse> {
    match crate::share::Manifest::of_file(&name, &data, origin) {
        Ok(manifest) => {
            send_direct(host, user_id, recipient_did, thread_id, Said::Share(manifest, data)).await
        }
        Err(message) => Ok(UserResponse::Error { message }),
    }
}

/// What a direct message says: a line of text, or a share.
enum Said {
    Text(String),
    /// The sender's manifest, `origin` and all — the recipient's is
    /// [`for_recipient`](crate::share::Manifest::for_recipient) — and the
    /// file's bytes, which follow it as ranges when it streams.
    Share(crate::share::Manifest, Vec<u8>),
}

/// The ranges `bytes` — the plaintext of the share `manifest`, whose message
/// is `inner`, sealed as the envelope whose id is `share` — follow it as: one
/// envelope each, sealed to `recipient_pub` with a fresh key and signed by
/// `sender_key`, exactly as the manifest is. Inside each is the range and
/// nothing of the message but who it is from and to: no name, no thread, no
/// type the conversation would show.
fn seal_ranges(
    inner: &DmInner,
    manifest: &crate::share::Manifest,
    share: &str,
    bytes: &[u8],
    sender_key: &SigningKey,
    recipient_pub: &[u8; 32],
) -> Result<Vec<SealedDm>, String> {
    crate::share::ranges(&manifest.digest, share, bytes)
        .into_iter()
        .map(|range| {
            let part = DmInner {
                from_did: inner.from_did.clone(),
                to_did: inner.to_did.clone(),
                thread_id: String::new(),
                sent_at: inner.sent_at,
                kind: "range".to_string(),
                text: String::new(),
                channel: None,
                grant: None,
                reach: None,
                ack: None,
                kel: Vec::new(),
                share: None,
                range: Some(range),
            };
            envelope::seal(&part, sender_key, recipient_pub)
        })
        .collect()
}

/// Seal what is `said` to `recipient_did` and to `user_id` themselves, keep the
/// sender's copy, and hand the recipient's over — [`message_send`] and
/// [`message_share`] alike.
async fn send_direct(
    host: &dyn MessageHost,
    user_id: String,
    recipient_did: String,
    thread_id: Option<String>,
    said: Said,
) -> io::Result<UserResponse> {
    // 1. Derive sender DID.
    let from_did = match user_did(host, &user_id) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity unavailable — unlock your session first".to_string(),
            });
        }
    };

    // 2. Resolve the recipient's Ed25519 public key from their DID.
    let recipient_pub = match pubkey_for_did(host, &user_id, &recipient_did).await {
        Ok(k) => k,
        Err(e) => return Ok(UserResponse::Error { message: e }),
    };

    // 3. Seal. The sender, the recipient, the thread and the time go inside,
    //    signed by the sender's identity key; outside there is an ephemeral
    //    key, a nonce and ciphertext (RFC-0064 MS1, MS7; `DEC-0056`).
    let Some(sender_key) = load_user_signing_key(&user_id, host.secrets()) else {
        return Ok(UserResponse::Error {
            message: "identity key unavailable — session not unlocked".to_string(),
        });
    };
    let thread_id = thread_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let (kind, text, share, streamed) = match said {
        Said::Text(body) => ("text".to_string(), body, None, None),
        // The conversation shows a share by its file's name; the manifest is
        // what the recipient's node files.
        Said::Share(manifest, bytes) => {
            let streamed = manifest.is_streamed().then_some(bytes);
            (crate::share::MESSAGE_TYPE.to_string(), manifest.name.clone(), Some(manifest), streamed)
        }
    };
    let own_inner = DmInner {
        from_did: from_did.clone(),
        to_did: recipient_did.clone(),
        thread_id,
        sent_at: now_secs(),
        kind,
        text,
        channel: None,
        grant: None,
        reach: None,
        ack: None,
        kel: Vec::new(),
        share,
        range: None,
    };
    // The recipient's copy: the sender's, less anything that names where the
    // sender keeps the thing they shared (SH5). For a text message the two are
    // the same claims.
    let inner = DmInner {
        share: own_inner.share.as_ref().map(crate::share::Manifest::for_recipient),
        ..own_inner.clone()
    };
    let sealed = match envelope::seal(&inner, &sender_key, &recipient_pub) {
        Ok(s) => s,
        Err(e) => return Ok(UserResponse::Error { message: e }),
    };
    // A share above the inline cap: its bytes follow the manifest as ranges,
    // each sealed exactly as the manifest is — to the recipient, with a fresh
    // key, signed by the sender — so nothing that carries them can tell one
    // from a message (RFC-0090 SH5, SH7; RFC-0048 ST2).
    let ranges = match (&inner.share, &streamed) {
        (Some(manifest), Some(bytes)) => {
            match seal_ranges(&inner, manifest, &sealed.ephemeral_pub, bytes, &sender_key, &recipient_pub) {
                Ok(r) => r,
                Err(e) => return Ok(UserResponse::Error { message: e }),
            }
        }
        _ => Vec::new(),
    };

    // 4. Build the sender's own sh.kotton.message.v1 record: the claims in the
    //    clear, because this store is theirs, and the message sealed again —
    //    to the sender's own key. `sealed` opens only for the recipient, so
    //    filing it here left the sender holding a copy of their own words they
    //    could not read (`TASK-a-sender-cannot-reopen-what-they-sent`). The
    //    envelope that travels is still `sealed`, and only the outbox keeps it,
    //    until one of their devices signs for it; the store keeps the copy that
    //    is the sender's. So the record's shape is unchanged, it still holds
    //    exactly one seal, and the transport's `ephemeral_pub` — the one value
    //    the relay, a vault and the recipient also saw — is not in it.
    let own_pub = sender_key.verifying_key().to_bytes();
    let own_copy = match envelope::seal(&own_inner, &sender_key, &own_pub) {
        Ok(s) => s,
        Err(e) => return Ok(UserResponse::Error { message: e }),
    };
    let record = filed_record(&own_inner, &own_copy);

    // 5. Insert. The sender's copy is written first and unconditionally: it is
    //    theirs whatever happens next (Article V), and a send that could not be
    //    handed over is a message waiting at home, not a message lost.
    let message_id = match host.record_insert(&user_id, NSID_MESSAGE_V1, record.clone()).await {
        Ok(id) => id,
        Err(e) => {
            return Ok(UserResponse::Error {
                message: format!("record insert failed: {e}"),
            })
        }
    };

    // 6. Hand over the recipient's copy (`DEC-0055`). Another account on this
    //    machine is filed directly — there is no carrier to involve — and goes
    //    through the same acceptance path a remote delivery meets, so the
    //    checks and the deduplication are one implementation rather than two.
    let delivery = match host.local_user_for_did(&recipient_did) {
        // Addressed to yourself — a note, and a shape the messaging tests use.
        // The copy just written *is* the recipient's copy; there is no second
        // one to make and nobody to hand it to.
        Some(local_user) if local_user == user_id => Delivery::Local,
        Some(local_user) => {
            // The sender's key is the door here: on a wire delivery the
            // mailbox's verifier proves it, and on this machine it is read
            // from the sender's own log.
            let Some(sender_pub) = host.user_current_key(&user_id) else {
                return Ok(UserResponse::Error {
                    message: "could not resolve your own key from your KEL".to_string(),
                });
            };
            hand_here(host, &local_user, &from_did, &sender_pub, sealed, ranges).await
        }
        // Someone elsewhere: into the outbox, and tried now. It stays there
        // until one of their devices signs for it, and is tried again until
        // then (`outbox`).
        None if !ranges.is_empty() => {
            outbox::send_share(
                host,
                &user_id,
                &recipient_did,
                &message_id,
                &sealed,
                &ranges,
                None,
                host.outbox_retry(),
            )
            .await
        }
        None => {
            outbox::send(host, &user_id, &recipient_did, &message_id, &sealed, None, host.outbox_retry())
                .await
        }
    };

    Ok(UserResponse::MessageSent {
        message_id,
        delivery: Some(delivery),
    })
}

/// Hand `sealed` — and, for a share whose bytes stream, its `ranges` — to
/// another account on this machine, `local_user`, through the acceptance path a
/// remote delivery meets ([`delivery::accept`](crate::daemon::delivery::accept)),
/// as from `from_did`, whose key is `sender_pub`: the one way [`send_direct`]
/// and a channel's [`deliver_copy`] hand anything here, so the checks and the
/// deduplication are one implementation rather than three.
///
/// A share whose bytes stream goes as it goes to anyone: its manifest first,
/// kept waiting for its bytes; then its ranges, the last of which files it;
/// then the manifest again, which finds it filed and is signed for.
async fn hand_here(
    host: &dyn MessageHost,
    local_user: &str,
    from_did: &str,
    sender_pub: &[u8; 32],
    sealed: SealedDm,
    ranges: Vec<SealedDm>,
) -> Delivery {
    let streamed = !ranges.is_empty();
    let hand = |sealed: SealedDm| {
        crate::daemon::delivery::accept(host, local_user, from_did, sender_pub, ContactRequest::DeliverMessage { sealed })
    };
    if streamed {
        hand(sealed.clone()).await;
        for range in ranges {
            if let ContactResponse::Refused { reason } | ContactResponse::Declined { reason } = hand(range).await {
                tracing::info!(local_user, %reason, "a range of a share to another account here was not taken");
            }
        }
    }
    match hand(sealed).await {
        ContactResponse::Delivered { stored: true, .. } | ContactResponse::SignedSealed { stored: true, .. } => {
            Delivery::Local
        }
        // Filed by its last range a moment ago, not by an earlier send.
        ContactResponse::Delivered { ack: Some(_), .. } if streamed => Delivery::Local,
        // Still waiting for its bytes: nothing was filed.
        ContactResponse::Delivered { ack: None, .. } if streamed => Delivery::Unreachable {
            reason: "its bytes did not all arrive, and nothing was filed".to_string(),
        },
        ContactResponse::Delivered { stored: false, .. } | ContactResponse::SignedSealed { stored: false, .. } => {
            Delivery::AlreadyHeld
        }
        ContactResponse::Refused { reason } | ContactResponse::Declined { reason } => Delivery::Unreachable { reason },
    }
}

/// The `sh.kotton.message.v1` record a node files for a direct message it
/// holds: the opened claims in the clear — this is the holder's own store —
/// and the sealed form beside them.
///
/// `sealed` must be sealed to the **holder**, because `message_decrypt_dm`
/// opens a record with the caller's own key and nobody else's. For a copy that
/// arrived, that is the envelope the door verified, so reading it later opens
/// the same bytes. For the sender's own copy it is a second seal to the sender
/// (`message_send`), not the envelope that travelled — which opens only for the
/// recipient (`TASK-a-sender-cannot-reopen-what-they-sent`).
pub fn filed_record(inner: &DmInner, sealed: &SealedDm) -> serde_json::Value {
    // A **channel** copy files the channel's own ciphertext, not the envelope's.
    // The envelope was transport to this member's door and is finished with; what
    // is kept is the same bytes every other member kept, so
    // `message_decrypt_channel` opens it with this member's key-grant exactly as
    // it opens a copy filed locally, and the conversation reads the same on every
    // device in it.
    //
    // `ephemeral_pub` stays the envelope's either way, because it is what
    // deduplicates a retried delivery — fresh per envelope, and the channel
    // ciphertext is identical across members, so it could not tell two copies
    // apart.
    if let Some(channel) = &inner.channel {
        return json!({
            "from_did": inner.from_did,
            "to_did": null,
            "channel_did": channel.channel_did,
            "thread_id": inner.thread_id,
            // The one place a channel copy's ciphertext becomes base64 text on
            // this side of the door: the stored record keeps it as every
            // channel message is kept, sender's own included, and nothing
            // stored crosses a frame.
            "body": B64.encode(&channel.body),
            "nonce": channel.nonce,
            "ephemeral_pub": sealed.ephemeral_pub,
            "epoch": channel.epoch,
            "sent_at": inner.sent_at,
            "type": inner.kind,
        });
    }
    json!({
        "from_did": inner.from_did,
        "to_did": inner.to_did,
        "channel_did": null,
        "thread_id": inner.thread_id,
        "body": sealed.body,
        "nonce": sealed.nonce,
        "ephemeral_pub": sealed.ephemeral_pub,
        "sent_at": inner.sent_at,
        "type": inner.kind,
    })
}

// ── MessageDeliveries ─────────────────────────────────────────────────────────

/// What each direct message `user_id` sent `peer_did` reads as: *delivered*
/// once one of their devices signed for it, *sent* while something of theirs
/// holds it, *waiting at home* while nothing does
/// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
pub async fn message_deliveries(
    host: &dyn MessageHost,
    user_id: String,
    peer_did: String,
) -> io::Result<UserResponse> {
    Ok(match outbox::readings(host, &user_id, &peer_did).await {
        Ok(readings) => UserResponse::MessageDeliveries { readings },
        Err(message) => UserResponse::Error { message },
    })
}

// ── MessageChannelSend ────────────────────────────────────────────────────────

/// Encrypt `body` with the channel's symmetric key and store it as a
/// `sh.kotton.message.v1` record.
///
/// The channel key is read from a `sh.kotton.channel.key-grant` record stored
/// for this user, then unwrapped with the user's Ed25519 identity key — or, for
/// a grant wrapped before a `RotateIdentity`, the key it retired, which only
/// opens.
pub async fn message_channel_send(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
    body: String,
) -> io::Result<UserResponse> {
    let sealer = match ChannelSealer::newest(host, &user_id, &channel_did).await {
        Ok(s) => s,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    // Encrypt body with the channel key. The sender's copy and every member's
    // are the same ciphertext: a line of text names nothing of the sender's.
    let sealed = match sealer.seal(body.as_bytes()) {
        Ok(v) => v,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    sealer.file_and_fan_out(host, &user_id, &channel_did, "text", &sealed, &sealed, &[]).await
}

// ── MessageChannelShare ───────────────────────────────────────────────────────

/// Share a file called `name`, holding `data`, with the group that holds
/// `channel_did`'s key: a channel message whose `type` is `share` and whose
/// opened body is the file's [`Manifest`](crate::share::Manifest)
/// (RFC-0090, *Delivery › To a group*, SH2, SH3;
/// `TASK-a-file-shared-with-a-group-is-a-copy-of-each-members-under-shared-with-you`).
///
/// **The channel's own path, and nothing added.** Sealed under the newest
/// epoch the sender holds, exactly as [`message_channel_send`] seals a line,
/// and handed once to each current member by [`fan_out`] — the same
/// ciphertext to every one of them, each in an envelope of its own. Each
/// member's node files it under *Shared with you* as it files a direct share
/// (`delivery::file_message`).
///
/// **One ciphertext, and it carries no `origin` — not even on the sender's own
/// copy.** A record sealed under a key other people hold carries nothing that
/// is the sender's alone (the orchestrator's ruling of 2026-10-08). A direct
/// share's own copy is sealed to the sender's key and nobody else's, so its
/// `origin` is theirs; a channel copy is sealed under the epoch's key, which
/// every member holds, so a path in the sender's tree under it would be a path
/// every member could open — that it never travels would be the sender's
/// restraint, not the seal's. So `origin` is taken, as `messages.share` takes
/// it, and not kept: the sender files the very ciphertext the members are
/// handed, the manifest less `origin` ([`Manifest::for_recipient`](crate::share::Manifest::for_recipient)),
/// as a line of text is one ciphertext for everybody. Nothing reads a channel
/// share's `origin` today; if something comes to, it is a field sealed to the
/// sender alone beside the channel record, never one under the channel key.
///
/// **Above [`GROUP_INLINE_MAX`](crate::share::GROUP_INLINE_MAX) its bytes
/// stream, under the same key** (the ruling of 2026-10-09 on RFC-0090,
/// *Delivery › To a group*;
/// `TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`).
/// The manifest carries `stream`, as a direct share's does above
/// [`INLINE_MAX`](crate::share::INLINE_MAX), and the file's ranges follow it,
/// each sealed **once** under the epoch the manifest is and handed to every
/// current member as a channel copy of their own — one ciphertext per range,
/// by the same [`fan_out`] the manifest rides. Not a stream per member sealed
/// to each pair: that would seal the same bytes once per member, carry a thing
/// that is the channel's on the direct-message path, and hand ranges to
/// whoever the sender's pairs say rather than whoever holds the key. Each range
/// names the share by its manifest's channel nonce, which every member's copy
/// holds ([`crate::share::Range::share`]). Each member's manifest and ranges
/// go into the outbox as a direct share's do ([`outbox::send_share`]): the
/// manifest first, each range `part_of` it, kept until a device of theirs
/// signs for it and carried by the sender's vault while none of the sender's
/// is awake. A file above [`STREAM_MAX`](crate::share::STREAM_MAX) is refused
/// here, before anything is sealed, as a share to a person is.
pub async fn message_channel_share(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
    name: String,
    data: Vec<u8>,
    origin: Option<String>,
) -> io::Result<UserResponse> {
    let manifest = match crate::share::Manifest::of_file_for_a_group(&name, &data, origin) {
        Ok(m) => m,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let sealer = match ChannelSealer::newest(host, &user_id, &channel_did).await {
        Ok(s) => s,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    // Under the channel key, so without `origin`, for the members and the
    // sender alike (above).
    let sealed = match sealer.seal(&manifest.for_recipient().channel_body()) {
        Ok(v) => v,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let ranges = if manifest.is_streamed() {
        match sealer.seal_ranges(&channel_did, &manifest, &sealed.nonce, &data) {
            Ok(r) => r,
            Err(message) => return Ok(UserResponse::Error { message }),
        }
    } else {
        Vec::new()
    };
    drop(data);
    sealer
        .file_and_fan_out(host, &user_id, &channel_did, crate::share::MESSAGE_TYPE, &sealed, &sealed, &ranges)
        .await
}

/// One range of a share to a group: its place in the stream, with no bytes
/// ([`crate::share::places`]), and its plaintext sealed once under the
/// channel's key — the channel copy every member is handed it as.
type GroupRange = (crate::share::Range, ChannelCopy);

/// The newest key-grant `user_id` holds for a channel, opened: who they are,
/// the key they sign with, and the epoch and channel key a message is sealed
/// under. One reading for every channel message a person sends, so a line and
/// a share are sealed at the same epoch by the same rule.
struct ChannelSealer {
    sk: SigningKey,
    from_did: String,
    epoch: u64,
    channel_key: [u8; 32],
}

/// A channel ciphertext, as its bytes, and its nonce, base64.
struct ChannelSealed {
    body: Vec<u8>,
    nonce: String,
}

impl ChannelSealer {
    async fn newest(host: &dyn MessageHost, user_id: &str, channel_did: &str) -> Result<Self, String> {
        // 1. Derive sender DID and signing key.
        let sk = load_user_signing_key(user_id, host.secrets())
            .ok_or_else(|| "identity key unavailable — unlock your session first".to_string())?;
        // The AID, not a key-derived DID: grants and records are addressed by
        // the identity the rest of the system issues.
        let from_did = user_did(host, user_id)
            .ok_or_else(|| "identity unavailable — unlock your session first".to_string())?;

        // 2. Take the newest key-grant this user holds for the channel. Sealing
        //    under the latest epoch is what keeps a message readable by the
        //    current membership: anyone still in the channel was granted this
        //    epoch, and anyone removed at the last rotation was not.
        let grant = own_grants(host, user_id, channel_did, &from_did)
            .await
            .into_iter()
            .next()
            .ok_or_else(|| {
                format!(
                    "no channel key grant found for channel {channel_did} — \
                     you may not be a member of this channel"
                )
            })?;
        let epoch = epoch_of(&grant);

        // 3. Unwrap the channel key — with a key a rotation retired, when the
        //    grant was wrapped before it. That key only opens: the channel key
        //    it yields seals, and the current key signs.
        let channel_key = unwrap_own_grant(host, user_id, &grant, &sk, &mut None)?;
        Ok(Self { sk, from_did, epoch, channel_key })
    }

    /// `plaintext`, sealed under this epoch's channel key.
    fn seal(&self, plaintext: &[u8]) -> Result<ChannelSealed, String> {
        let (ciphertext, nonce) = channel_encrypt(plaintext, &self.channel_key)
            .map_err(|e| format!("channel encryption failed: {e}"))?;
        Ok(ChannelSealed { body: ciphertext, nonce: B64.encode(nonce) })
    }

    /// `bytes` — the plaintext of the streamed share `manifest`, whose channel
    /// ciphertext's nonce is `share` — as the ranges that follow it to every
    /// member of `channel_did`: each range's plaintext sealed under this epoch's
    /// channel key, once, beside its place in the stream.
    fn seal_ranges(
        &self,
        channel_did: &str,
        manifest: &crate::share::Manifest,
        share: &str,
        bytes: &[u8],
    ) -> Result<Vec<GroupRange>, String> {
        crate::share::places(&manifest.digest, share, bytes)
            .into_iter()
            .map(|(range, part)| {
                let sealed = self.seal(part)?;
                let copy = ChannelCopy {
                    channel_did: channel_did.to_string(),
                    epoch: self.epoch,
                    body: sealed.body,
                    nonce: sealed.nonce,
                };
                Ok((range, copy))
            })
            .collect()
    }

    /// File the sender's own copy, `own`, as a message of type `kind`, and
    /// hand every current member `theirs` and, for a share whose bytes stream,
    /// its `ranges` ([`fan_out`]).
    #[allow(clippy::too_many_arguments)]
    async fn file_and_fan_out(
        &self,
        host: &dyn MessageHost,
        user_id: &str,
        channel_did: &str,
        kind: &str,
        own: &ChannelSealed,
        theirs: &ChannelSealed,
        ranges: &[GroupRange],
    ) -> io::Result<UserResponse> {
        let message_id = match self.file_own(host, user_id, channel_did, kind, own).await {
            Ok(id) => id,
            Err(message) => return Ok(UserResponse::Error { message }),
        };

        // 5. Hand a copy to every current member (`DEC-0055`). The sender's copy
        //    is already written and is theirs whatever happens next (Article V),
        //    so no member's answer can fail this send — each is reported on its
        //    own.
        let copy = self.copy(channel_did, theirs);
        let fanout =
            fan_out(host, user_id, &self.from_did, &self.sk, channel_did, &copy, kind, ranges, &message_id).await;

        Ok(UserResponse::ChannelSent { message_id, fanout })
    }

    /// `sealed`, as the channel copy every member is handed at this epoch.
    fn copy(&self, channel_did: &str, sealed: &ChannelSealed) -> ChannelCopy {
        ChannelCopy {
            channel_did: channel_did.to_string(),
            epoch: self.epoch,
            body: sealed.body.clone(),
            nonce: sealed.nonce.clone(),
        }
    }

    /// File the sender's own copy, `own`, as a message of type `kind`, and
    /// answer its record id.
    async fn file_own(
        &self,
        host: &dyn MessageHost,
        user_id: &str,
        channel_did: &str,
        kind: &str,
        own: &ChannelSealed,
    ) -> Result<String, String> {
        // 4. Build and insert the record. The epoch is stamped so history can
        //    say which stretch of the conversation a message belongs to;
        //    decryption does not depend on it, and trusts the AEAD instead (see
        //    `message_decrypt_channel`).
        let record = json!({
            "from_did": self.from_did,
            "to_did": null,
            "channel_did": channel_did,
            "thread_id": Uuid::new_v4().to_string(),
            "body": B64.encode(&own.body),
            "nonce": own.nonce,
            "ephemeral_pub": null,
            "epoch": self.epoch,
            "sent_at": now_secs(),
            "type": kind,
        });

        host.record_insert(user_id, NSID_MESSAGE_V1, record)
            .await
            .map_err(|e| format!("record insert failed: {e}"))
    }
}

// ── The groups a person holds a key for ──────────────────────────────────────

/// A channel this person holds a key for, as the share sheet offers it: its
/// DID and how many people hold its current key (RFC-0090, *The surface*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub channel_did: String,
    /// How many people hold the epoch this person's newest grant opens, them
    /// included — read from the roster sealed in that grant
    /// ([`current_members`]).
    pub members: usize,
}

/// Every channel `user_id` holds a key for: those for which a grant addressed
/// to them opens under their own key, each with its member count — read from
/// their own grants and nothing else (RFC-0090 SH4: membership is a key).
///
/// A channel has no name yet
/// (`IDEA-a-channel-has-no-name-and-nothing-lists-the-channels-a-person-is-in`),
/// so this answers its DID and its count, which is what the sheet draws until
/// one does. A person removed from a channel still holds the epoch before
/// their removal and still reads it here: nothing tells a removed member, and a
/// share they send to it is refused at every remaining member's door
/// (`delivery::in_current_epoch`).
pub async fn message_groups(host: &dyn MessageHost, user_id: &str) -> Result<Vec<Group>, String> {
    let sk = load_user_signing_key(user_id, host.secrets())
        .ok_or_else(|| "identity key unavailable — unlock your session first".to_string())?;
    let own = user_did(host, user_id).ok_or_else(|| "identity unavailable — unlock your session first".to_string())?;
    let grants = host
        .record_query(
            user_id,
            NSID_CHANNEL_KEY_GRANT,
            vec![("to_did".to_string(), json!(own))],
            None,
            None,
            None,
        )
        .await
        .map_err(|e| format!("could not read your channel keys: {e}"))?;
    let mut channels: Vec<String> = grants
        .iter()
        .filter_map(|g| g.get("channel_did").and_then(|d| d.as_str()).map(str::to_owned))
        .collect();
    channels.sort();
    channels.dedup();
    let mut retired = None;
    let mut groups = Vec::new();
    for channel_did in channels {
        if let Some(members) = current_members(host, user_id, &channel_did, &own, &sk, &mut retired).await {
            groups.push(Group { channel_did, members: members.dids.len() });
        }
    }
    Ok(groups)
}

/// What a channel copy that arrived at `user_id` opens to under the keys they
/// hold ([`open_channel_copy`]).
pub(crate) enum Opened {
    /// The plaintext.
    Plain(Vec<u8>),
    /// No key this identity holds opens it, and it was sealed at an epoch newer
    /// than any they hold: the grant may still be on its way.
    NotYet(String),
    /// No key this identity holds opens it, and it was sealed at an epoch they
    /// have reached: a key they were never granted, or a copy that is not one.
    NotHeld(String),
}

/// Open the channel ciphertext `copy` with every key-grant `user_id` holds for
/// its channel, newest first, and let the AEAD decide — as
/// [`message_decrypt_channel`] does. A member removed before it was sealed, or
/// admitted after it without backfill, holds no grant whose key opens it.
pub(crate) async fn open_channel_copy(host: &dyn MessageHost, user_id: &str, copy: &ChannelCopy) -> Opened {
    let (Some(sk), Some(own)) = (load_user_signing_key(user_id, host.secrets()), user_did(host, user_id)) else {
        return Opened::NotYet("this identity's key is not available on this node".to_string());
    };
    let grants = own_grants(host, user_id, &copy.channel_did, &own).await;
    let nonce: Option<[u8; 12]> = B64.decode(&copy.nonce).ok().and_then(|n| n.try_into().ok());
    let Some(nonce) = nonce else {
        return Opened::NotHeld("its channel nonce is not base64 of 12 bytes".to_string());
    };
    let body = &copy.body;
    let mut retired = None;
    for grant in &grants {
        if let Ok(key) = unwrap_own_grant(host, user_id, grant, &sk, &mut retired) {
            if let Ok(plaintext) = channel_decrypt(body, &nonce, &key) {
                return Opened::Plain(plaintext);
            }
        }
    }
    let newest = grants.first().map(epoch_of);
    let reason = format!(
        "it was sealed at epoch {} of channel {}, and no key this identity holds for it opens it",
        copy.epoch, copy.channel_did
    );
    match newest {
        Some(newest) if copy.epoch <= newest => Opened::NotHeld(reason),
        _ => Opened::NotYet(reason),
    }
}

// ── MessageChannelHistory ─────────────────────────────────────────────────────

/// Return up to `limit` raw (still-encrypted) `sh.kotton.message.v1` records
/// for `channel_did`, newest-filed first — by `filed_at`, the person's own
/// devices' filing stamps (`Record::filed_at`), never a sender's clock.
///
/// Records are returned to the client still-encrypted; the client SDK must
/// unwrap and decrypt using the channel key grant.
pub async fn message_channel_history(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
    before_id: Option<String>,
    limit: u32,
) -> io::Result<UserResponse> {
    let limit = (limit.min(100)) as usize;
    let records = host.record_query(
        &user_id,
        NSID_MESSAGE_V1,
        vec![("channel_did".to_string(), json!(channel_did))],
        Some(limit),
        None,
        before_id,
    )
    .await
    .map_err(io::Error::other)?
    .into_iter()
    .map(expose_row_id)
    .collect();

    Ok(UserResponse::MessageHistory { messages: records })
}

// ── MessagePollInbox ──────────────────────────────────────────────────────────

/// Return the 50 most recent `sh.kotton.message.v1` records addressed to
/// `user_id`'s DID (where `to_did` equals the user's `did:key:…`).
///
/// Records are returned still-encrypted; the caller decrypts using their
/// identity key.
pub async fn message_poll_inbox(
    host: &dyn MessageHost,
    user_id: String,
) -> io::Result<UserResponse> {
    let to_did = match user_did(host, &user_id) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity unavailable — unlock your session first".to_string(),
            });
        }
    };

    let records = host.record_query(
        &user_id,
        NSID_MESSAGE_V1,
        vec![("to_did".to_string(), json!(to_did))],
        Some(50),
        None,
        None,
    )
    .await
    .map_err(io::Error::other)?
    .into_iter()
    .map(expose_row_id)
    .collect();

    Ok(UserResponse::MessageHistory { messages: records })
}

// ── One conversation ─────────────────────────────────────────────────────────

/// How many of a conversation's newest messages [`message_conversation`]
/// answers with: the inbox's 50, doubled, because a conversation is two
/// directions of it.
pub const CONVERSATION_LIMIT: usize = 100;

/// Both directions of `user_id`'s direct conversation with `peer_did`, from
/// `user_id`'s own store: what `peer_did` sent them and what they sent
/// `peer_did`, newest-filed first, each still sealed and each carrying
/// `filed_at` (`TASK-messages-is-the-drawn-one`).
///
/// **Why the sender's half is here at all.** Their copy of what they sent is
/// sealed to their own key since 2026-09-25
/// (`TASK-a-sender-cannot-reopen-what-they-sent`), so it opens through the same
/// `MessageDecryptDm` a received one does; a window that could read only the
/// inbox would draw half a conversation. Nothing here is anyone else's: both
/// queries are against the caller's own store, filtered to records naming the
/// caller, and nothing is opened — the answer is ciphertext, as the inbox's is.
///
/// Ordered by `(filed_at, id)`, newest first — where this person's store filed
/// each copy, the one key both directions share
/// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
pub async fn message_conversation(
    host: &dyn MessageHost,
    user_id: String,
    peer_did: String,
) -> io::Result<UserResponse> {
    let Some(me) = user_did(host, &user_id) else {
        return Ok(UserResponse::Error {
            message: "identity unavailable — unlock your session first".to_string(),
        });
    };
    let mut messages = Vec::new();
    for (from, to) in [(&peer_did, &me), (&me, &peer_did)] {
        let half = host
            .record_query(
                &user_id,
                NSID_MESSAGE_V1,
                vec![
                    ("from_did".to_string(), json!(from)),
                    ("to_did".to_string(), json!(to)),
                ],
                Some(CONVERSATION_LIMIT),
                None,
                None,
            )
            .await
            .map_err(io::Error::other)?;
        messages.extend(half.into_iter().map(expose_row_id));
    }
    let position = |v: &serde_json::Value| {
        (
            v.get("filed_at").and_then(|x| x.as_u64()).unwrap_or(0),
            v.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        )
    };
    messages.sort_by_key(|v| std::cmp::Reverse(position(v)));
    messages.truncate(CONVERSATION_LIMIT);
    Ok(UserResponse::MessageHistory { messages })
}

/// Rename the store's internal row id to the one the wire calls `id`.
///
/// `record_cmds::query` writes the row id to `_id` on every row it returns. The
/// IPC layer must not leak an internal column name, and a caller needs *some*
/// stable handle on a message — for a history cursor, and for saying which
/// message a person has read up to — so it is renamed rather than dropped.
///
/// **One function because two call sites disagreed.** `message_channel_history`
/// did this inline and `message_poll_inbox` did not, so a record reaching the
/// occupant's parser through the inbox had `_id`, no `id`, and was dropped by a
/// `filter_map` that reported nothing: the shell's inbox was unconditionally
/// empty and looked exactly like a real one
/// (`kuserd::agent::occupant_host::message_tests::a_record_as_the_store_answers_it_is_not_dropped`,
/// which is red without this).
///
/// **And `_filed_at` to `filed_at`, for the same reason.** It is when this
/// person's device filed the message, on that device's clock
/// (`Record::filed_at`), and it is the only
/// key both halves of a conversation share: `sent_at` on what they sent is their
/// clock and on what you sent is yours. A conversation is ordered by it and a
/// read mark is written with it
/// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
pub fn expose_row_id(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(id) = v.get("_id").and_then(|x| x.as_str()).map(str::to_owned) {
        v["id"] = json!(id);
    }
    if let Some(filed_at) = v.get("_filed_at").and_then(|x| x.as_i64()) {
        v["filed_at"] = json!(filed_at);
    }
    if let Some(o) = v.as_object_mut() {
        o.remove("_id");
        o.remove("_filed_at");
    }
    v
}

// ── Internal: channel key unwrap ─────────────────────────────────────────────

/// Decode the base64 fields from a `sh.kotton.channel.key-grant` record and
/// unwrap the channel symmetric key using `sk`.
fn unwrap_channel_key(grant: &serde_json::Value, sk: &SigningKey) -> Result<[u8; 32], String> {
    let enc_key = b64_field(grant, "enc_key")?;
    let nonce_vec = b64_field(grant, "nonce")?;
    let eph_pub_vec = b64_field(grant, "ephemeral_pub")?;

    let nonce: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| "channel key grant: nonce must be 12 bytes".to_string())?;
    let eph_pub: [u8; 32] = eph_pub_vec
        .try_into()
        .map_err(|_| "channel key grant: ephemeral_pub must be 32 bytes".to_string())?;

    channel_key_unwrap(&enc_key, &nonce, &eph_pub, sk)
        .map_err(|e| format!("channel key unwrap failed: {e}"))
}

/// Unwrap one of `user_id`'s own grants: with the current key `sk`, or — for a
/// grant wrapped before a `RotateIdentity` — with a key that rotation retired
/// (`TASK-a-person-who-rotated-cannot-post-to-or-admit-into-a-channel-they-were-in`).
///
/// For `own_grants` only, whose `to_did` is this person, so a retired key is
/// tried only against a grant already addressed to its holder. The retired keys
/// are fetched into `retired` at most once per request, and only when the current
/// key fails. They only open: nothing here seals, signs or wraps with one, and
/// nothing records which key opened the grant. The current key's error stands if
/// none of them opens it.
pub(crate) fn unwrap_own_grant(
    host: &dyn MessageHost,
    user_id: &str,
    grant: &serde_json::Value,
    sk: &SigningKey,
    retired: &mut Option<Vec<SigningKey>>,
) -> Result<[u8; 32], String> {
    unwrap_channel_key(grant, sk).or_else(|e| {
        retired
            .get_or_insert_with(|| host.retired_identity_keys(user_id, sk))
            .iter()
            .find_map(|old| unwrap_channel_key(grant, old).ok())
            .ok_or(e)
    })
}

fn b64_field(record: &serde_json::Value, field: &str) -> Result<Vec<u8>, String> {
    let s = record[field]
        .as_str()
        .ok_or_else(|| format!("channel key grant: missing field '{field}'"))?;
    B64.decode(s)
        .map_err(|e| format!("channel key grant: base64 decode of '{field}' failed: {e}"))
}

// ── MessageDecryptDm ─────────────────────────────────────────────────────────

/// Decrypt an encrypted DM `body` in-process using `user_id`'s identity key.
///
/// The full crypto chain: Ed25519 signing key → X25519 private key → ECDH with
/// `ephemeral_pub` → HKDF-SHA-256 session key → ChaCha20-Poly1305 decrypt.
pub async fn message_decrypt_dm(
    host: &dyn MessageHost,
    user_id: String,
    body: String,
    nonce: String,
    ephemeral_pub: String,
) -> io::Result<UserResponse> {
    let record = serde_json::json!({
        "body": body,
        "nonce": nonce,
        "ephemeral_pub": ephemeral_pub,
    });
    match dm_decrypt_record(&user_id, &record, host.secrets(), |current| {
        host.retired_identity_keys(&user_id, current)
    }) {
        Ok(plaintext) => Ok(UserResponse::Decrypted { plaintext }),
        Err(e) => Ok(UserResponse::Error { message: e }),
    }
}

// ── MessageDecryptChannel ─────────────────────────────────────────────────────

/// Decrypt a channel message `body` using the channel key grant stored for `user_id`.
pub async fn message_decrypt_channel(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
    body: String,
    nonce: String,
) -> io::Result<UserResponse> {
    let sk = match load_user_signing_key(&user_id, host.secrets()) {
        Some(k) => k,
        None => {
            return Ok(UserResponse::Error {
                message: "identity key unavailable — unlock your session first".to_string(),
            });
        }
    };
    // The AID, not a key-derived DID: grants and records are addressed by the
    // identity the rest of the system issues.
    let from_did = match user_did(host, &user_id) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity unavailable — unlock your session first".to_string(),
            });
        }
    };

    let grants = own_grants(host, &user_id, &channel_did, &from_did).await;
    if grants.is_empty() {
        return Ok(UserResponse::Error {
            message: format!(
                "no channel key grant for channel {channel_did} — \
                 not yet a member or key not delivered"
            ),
        });
    }

    // Try each epoch this user holds, newest first, and let the AEAD decide.
    // ChaCha20-Poly1305 authenticates, so a key from the wrong epoch fails
    // rather than yielding plausible garbage — which makes trial decryption
    // exact, and means a client need not tell us which epoch it is asking about.
    //
    // The confidentiality boundary is not enforced here but *above* here: a
    // member holds no grant for the epochs they were not part of, so those
    // messages have no key in this list to succeed with.
    //
    // A grant wrapped before a `RotateIdentity` was wrapped to the key the
    // rotation retired, so a grant the current key does not open is tried
    // against those — the same fallback, and the same keys, `dm_decrypt_record`
    // uses for a direct message
    // (`TASK-a-channel-key-grant-wrapped-to-a-retired-identity-key-does-not-open`).
    // They are asked for once, only when needed, and only unwrap: nothing here
    // signs or wraps with them, and nothing records which key opened the grant.
    let record = serde_json::json!({ "body": body, "nonce": nonce });
    let mut retired = None;
    let mut usable_keys = 0usize;
    let mut last_unwrap_error = None;
    for grant in &grants {
        match unwrap_own_grant(host, &user_id, grant, &sk, &mut retired) {
            Ok(channel_key) => {
                usable_keys += 1;
                if let Ok(plaintext) = channel_decrypt_record(&record, &channel_key) {
                    // A share opens to its file's name, as a direct share does;
                    // its bytes are reached under *Shared with you*.
                    return Ok(UserResponse::Decrypted { plaintext: crate::share::channel_text(plaintext) });
                }
            }
            Err(e) => last_unwrap_error = Some(e),
        }
    }

    // A held key that simply does not open this message is the *expected* answer
    // when reading back past a rotation, so it is reported as that — naming the
    // epochs held — rather than as a crypto failure. The unwrap error is only
    // the better explanation when no grant could be opened at all; otherwise a
    // single malformed grant would mask the ordinary case.
    if usable_keys == 0 {
        if let Some(e) = last_unwrap_error {
            return Ok(UserResponse::Error { message: e });
        }
    }
    let held: Vec<String> = grants.iter().map(|g| epoch_of(g).to_string()).collect();
    Ok(UserResponse::Error {
        message: format!(
            "this message belongs to a channel key epoch you do not hold \
             (you hold epoch(s) {}) — it was sent to a different membership of {channel_did}",
            held.join(", ")
        ),
    })
}

// ── Opening a filed message ───────────────────────────────────────────────────

/// What [`message_open`] reads off a filed message, each field by its name.
///
/// `channel_did` and `ephemeral_pub` are both `Option<String>`, and which of
/// the two is asked first is the whole of the opener's decision. Handed over as
/// two positional arguments they could be swapped at a call site and still
/// compile, which reintroduces the defect this opener ended with nothing
/// failing to build. So they travel named, and a guest's message record becomes
/// one in exactly one place (the `From` below).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenableMessage {
    /// The channel the record names, if any: it decides which key opens it.
    pub channel_did: Option<String>,
    /// The ephemeral key the record carries, if any — the one a direct message
    /// is sealed against, or the envelope's on a channel copy from a door.
    pub ephemeral_pub: Option<String>,
    /// The ciphertext, base64.
    pub body: String,
    /// The nonce, base64.
    pub nonce: String,
}

impl From<kotton_wire::runner::RunnerSealedMessage> for OpenableMessage {
    fn from(m: kotton_wire::runner::RunnerSealedMessage) -> Self {
        Self { channel_did: m.channel_did, ephemeral_pub: m.ephemeral_pub, body: m.body, nonce: m.nonce }
    }
}

/// Open a message this person's store filed, to what it shows: its text, or a
/// share's file name. The one opener for every shape [`filed_record`] and the
/// two send paths file — a direct message, the sender's own channel copy, and
/// a channel copy that arrived over a member's door. The guest's
/// `messages.open` reaches it through the occupant host.
///
/// **Which key opens it is the record's `channel_did`, asked first.** A record
/// naming a channel holds the channel's own ciphertext, whichever way it came,
/// and opens under this person's grants for that channel
/// ([`message_decrypt_channel`]); a record naming none is a direct message,
/// sealed to this person's identity key against its `ephemeral_pub`
/// ([`message_decrypt_dm`]).
///
/// `ephemeral_pub` does not say which. On a direct message it is the key the
/// body is sealed against. On a channel copy that came over a door it is the
/// key of the **envelope** it came in, kept only to deduplicate a retried
/// delivery ([`filed_record`]) — the body is not sealed to it. Until
/// 2026-10-08 the occupant host asked `ephemeral_pub` first, so every channel
/// copy from another member was opened as a direct message and failed; only the
/// sender's own copy, filed without one, opened
/// (`TASK-an-app-cannot-open-a-channel-message-that-arrived-from-another-member`).
///
/// Every record that names a channel holds channel ciphertext: the door has
/// filed the channel's `body` and `nonce` since channel copies first crossed one
/// (2026-09-09), and before that a channel message never left the sender's
/// node. So asking the channel first opens every record ever filed.
pub async fn message_open(host: &dyn MessageHost, user_id: String, message: OpenableMessage) -> io::Result<UserResponse> {
    let OpenableMessage { channel_did, ephemeral_pub, body, nonce } = message;
    match (channel_did, ephemeral_pub) {
        (Some(channel_did), _) => message_decrypt_channel(host, user_id, channel_did, body, nonce).await,
        (None, Some(ephemeral_pub)) => message_decrypt_dm(host, user_id, body, nonce, ephemeral_pub).await,
        (None, None) => Ok(UserResponse::Error {
            message: "this record names neither a channel nor an ephemeral key, so there is nothing \
                      that opens it"
                .to_string(),
        }),
    }
}

// ── Decrypt helper (for SDK use, also called from WIT host bridge) ────────────

/// Decrypt a single DM record using this user's identity key — or, for a record
/// sealed before a rotation, the key it was sealed to, which `retired` hands
/// over from the person's own node. `retired` is asked only when the current key
/// does not open the record.
pub fn dm_decrypt_record(
    user_id: &str,
    record: &serde_json::Value,
    secrets: &dyn SecretsStore,
    retired: impl FnOnce(&SigningKey) -> Vec<SigningKey>,
) -> Result<String, String> {
    let sk = load_user_signing_key(user_id, secrets)
        .ok_or_else(|| "identity key unavailable — session not unlocked".to_string())?;
    let sealed = SealedDm {
        body: str_field(record, "body")?,
        nonce: str_field(record, "nonce")?,
        ephemeral_pub: str_field(record, "ephemeral_pub")?,
    };
    // A record in this store was verified at its door when it was filed;
    // reading it opens the same bytes and takes the text.
    match envelope::open_filed(&sealed, &sk) {
        Ok(inner) => Ok(inner.text),
        // Not sealed to the current key: sealed, perhaps, to one a rotation
        // retired. The record's own error stands if none of those opens it.
        Err(e) => retired(&sk)
            .iter()
            .find_map(|old| envelope::open_filed(&sealed, old).ok())
            .map(|inner| inner.text)
            .ok_or(e),
    }
}

fn str_field(record: &serde_json::Value, field: &str) -> Result<String, String> {
    record
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("DM record: missing `{field}`"))
}

/// Decrypt a channel message record using a pre-unwrapped `channel_key`.
pub fn channel_decrypt_record(
    record: &serde_json::Value,
    channel_key: &[u8; 32],
) -> Result<String, String> {
    let ciphertext = b64_field(record, "body")?;
    let nonce_vec = b64_field(record, "nonce")?;
    let nonce: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| "channel message record: nonce must be 12 bytes")?;
    let plaintext = channel_decrypt(&ciphertext, &nonce, channel_key)
        .map_err(|e| format!("channel decryption failed: {e}"))?;
    String::from_utf8(plaintext)
        .map_err(|e| format!("decrypted channel message is not valid UTF-8: {e}"))
}

// ── MessageChannelCreate ───────────────────────────────────────────────────────

/// Generate a fresh channel symmetric key, wrap it for the creator's own DID,
/// and store a `sh.kotton.channel.key-grant` record in the creator's store.
///
/// After this call the creator can immediately call `message_channel_send` and
/// then grant access to members via `message_channel_grant_key`.
pub async fn message_channel_create(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
) -> io::Result<UserResponse> {
    let sk = match load_user_signing_key(&user_id, host.secrets()) {
        Some(k) => k,
        None => {
            return Ok(UserResponse::Error {
                message: "identity key unavailable — unlock your session first".to_string(),
            });
        }
    };
    // The AID, not a key-derived DID — see `user_did`.
    let creator_did = match user_did(host, &user_id) {
        Some(d) => d,
        None => {
            return Ok(UserResponse::Error {
                message: "identity unavailable — unlock your session first".to_string(),
            });
        }
    };
    let creator_pub: [u8; 32] = sk.verifying_key().to_bytes();

    // A new channel starts at epoch 0 with one member. Every later membership
    // change mints the next epoch (see `rotate_channel_key`).
    let channel_key = channel_key_generate();
    let creator = RosterMember {
        did: creator_did.clone(),
        key: Some(creator_pub),
        reach: host.own_reach_note(&user_id).await,
        kel: host.own_key_log(&user_id),
    };
    let roster = match seal_roster(&channel_key, std::slice::from_ref(&creator)) {
        Ok(r) => r,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    match write_grant(
        host,
        &user_id,
        &channel_did,
        &creator_did,
        &creator_pub,
        &channel_key,
        0,
        Some(&roster),
    )
    .await
    {
        // Echo the channel id, not the grant's record id: callers want the
        // handle they will pass to send/history, and returning the record id
        // invited using it as the channel — which fails later, and misleadingly.
        Ok(_grant) => Ok(UserResponse::ChannelCreated { channel_did }),
        Err(e) => Ok(UserResponse::Error {
            message: format!("key-grant insert failed: {e}"),
        }),
    }
}

// ── Membership changes: MessageChannelGrantKey, MessageChannelRemoveMember ────

/// What a rotation does to a channel's membership — the one thing admitting
/// and removing do differently.
///
/// RFC-0064, *Encryption model for channels*: "a rotation that omits someone is
/// how a member stops being one; there is no second protocol." So there is one
/// rotation, [`rotate_membership`], and this is its argument: who the next epoch
/// goes to besides the current members, or who it leaves out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delta<'a> {
    /// Grant the next epoch to this DID as well as to everyone holding the
    /// current one.
    Admit(&'a str),
    /// Grant the next epoch to everyone holding the current one but this DID.
    Remove(&'a str),
}

/// Who the next epoch goes to: `members`, the holders of the current key as
/// the rotating person's node knows them, changed by `delta` — with the
/// rotating person (`self_did`) always among them, since they mint the key.
///
/// The two refusals are both removals:
///
/// - **Not a member.** Removing someone who holds no grant at the current
///   epoch would mint a key for nothing: they are already outside it, or were
///   never in. Said rather than done, so a mistyped DID is not a silent rotation.
/// - **Yourself.** The person rotating generates the next key, so a rotation
///   they mint cannot leave them out of it — they hold the key whether or not
///   they wrap a grant of it to themselves. Leaving is therefore a different
///   verb from removing, and it is not this one.
fn next_members(
    mut members: Vec<String>,
    self_did: &str,
    channel_did: &str,
    delta: Delta<'_>,
) -> Result<Vec<String>, String> {
    match delta {
        Delta::Admit(member_did) => {
            for did in [member_did, self_did] {
                if !members.iter().any(|m| m == did) {
                    members.push(did.to_string());
                }
            }
        }
        Delta::Remove(member_did) => {
            if member_did == self_did {
                return Err(format!(
                    "you cannot remove yourself from channel {channel_did}: the next key is \
                     minted by whoever removes, so it cannot omit them — leaving is a \
                     different verb, and this is not it"
                ));
            }
            if !members.iter().any(|m| m == member_did) {
                return Err(format!(
                    "{member_did} is not a member of channel {channel_did} at its current \
                     epoch, so there is nobody to remove"
                ));
            }
            members.retain(|m| m != member_did);
            if !members.iter().any(|m| m == self_did) {
                members.push(self_did.to_string());
            }
        }
    }
    Ok(members)
}

/// Every roster `user_id`'s node can read for `channel_did`, by epoch: each
/// grant they hold that unwraps under their keys and carries a roster that
/// opens. An epoch they hold no such grant for is absent — not an error. `Err`
/// only when the store cannot answer.
async fn rosters_held(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    own: &str,
    sk: &SigningKey,
    retired: &mut Option<Vec<SigningKey>>,
) -> Result<Vec<(u64, Vec<RosterMember>)>, String> {
    let filter = vec![
        ("channel_did".to_string(), json!(channel_did)),
        ("to_did".to_string(), json!(own)),
    ];
    let grants = match host.record_query(user_id, NSID_CHANNEL_KEY_GRANT, filter, None, None, None).await {
        Ok(grants) => grants,
        Err(e) if e.to_string().contains("no such table") => Vec::new(),
        Err(e) => return Err(format!("could not read this identity's keys for channel {channel_did}: {e}")),
    };
    let mut rosters = Vec::new();
    for grant in &grants {
        let Ok(key) = unwrap_own_grant(host, user_id, grant, sk, retired) else { continue };
        if let Some(Ok(roster)) = open_roster(grant, &key) {
            rosters.push((epoch_of(grant), roster));
        }
    }
    Ok(rosters)
}

// ── Co-members: the people a channel's roster names and no card does ─────────

/// What the rosters a node holds say of one member ([`Rosters::resolve`]).
enum Named<'a> {
    /// No roster names them with a key its log yields.
    Unknown,
    /// The entry whose log every other held log for them extends.
    Believed(&'a RosterMember),
    /// Two held logs for them diverge: neither is believed.
    Disputed,
}

/// Every roster `user_id`'s node holds for one channel, newest epoch first —
/// read once, so a fan-out or a rotation that asks after every member reads
/// the store and unwraps each grant once and not once per member.
///
/// Empty when this identity's key is not here, it holds no grant it can open
/// for the channel, or the store cannot answer: then nobody is named in it,
/// and a member with no card is not reached, as before rosters carried keys.
pub(crate) struct Rosters {
    channel_did: String,
    held: Vec<(u64, Vec<RosterMember>)>,
}

impl Rosters {
    pub(crate) async fn held(host: &dyn MessageHost, user_id: &str, channel_did: &str) -> Self {
        match Self::read(host, user_id, channel_did).await {
            Ok(rosters) => rosters,
            Err(e) => {
                tracing::info!(user_id, error = %e, "the rosters of a channel could not be read; nobody is named in them");
                Self { channel_did: channel_did.to_string(), held: Vec::new() }
            }
        }
    }

    /// [`Self::held`], with a store that cannot answer said as an error rather
    /// than as a channel that names nobody — for a caller that keeps what it
    /// had when a read fails ([`co_members_read`]). A key that is not here is
    /// still nobody named, as in `held`: that is a fact about this node, not a
    /// failed read.
    pub(crate) async fn read(host: &dyn MessageHost, user_id: &str, channel_did: &str) -> Result<Self, String> {
        let none = || Self { channel_did: channel_did.to_string(), held: Vec::new() };
        let (Some(sk), Some(own)) = (load_user_signing_key(user_id, host.secrets()), user_did(host, user_id)) else {
            return Ok(none());
        };
        let mut rosters = rosters_held(host, user_id, channel_did, &own, &sk, &mut None).await?;
        rosters.sort_by_key(|(epoch, _)| std::cmp::Reverse(*epoch));
        Ok(Self { channel_did: channel_did.to_string(), held: rosters })
    }

    /// What the rosters this node holds say of `did`: the entry **whose key log
    /// every other log held for them is a prefix of** — of those that name them
    /// with a key their log yields — the newest roster's where several carry
    /// that same log. **None when two held logs diverge**, neither a prefix of
    /// the other: then no key and no note are believed for them, and it is said
    /// as a warning naming the channel and the DID.
    ///
    /// This is the rule a card holds a contact's carried log to
    /// (`kotton_crypto::kel_verify::contact_key_from_log` with a log held: the
    /// offered log must *continue* the held one), carried across every roster
    /// this node holds. Each entry's key is already one its own log yields
    /// ([`RosterMember::from_json`]), replayed from nothing held, so a prefix of
    /// a member's real log passes with the key they had before a rotation —
    /// and whoever holds that retired key can extend the prefix with events of
    /// their own (a recovery-set growth, a cooperative rotation, each signed by
    /// it), making a log longer than the real one that still yields the retired
    /// key. Neither newest nor longest can tell those apart; only extension
    /// can. So a log is believed over another only when it extends it:
    ///
    /// - a prefix never overrides the log it is a prefix of — an older epoch's
    ///   longer log wins over a newer epoch's prefix (the assessor's ground 1
    ///   at `9b1eca245`);
    /// - a fork against the real log believes neither (the assessor at
    ///   `c81cf0672`): a minter holding the retired key cannot override the
    ///   member's key on a node that holds the real log, only deny it.
    ///
    /// **What remains:** a minter holding a member's retired private key can
    /// keep that key believed on a node that holds no longer log for the
    /// member and no card for them. A card, where one exists, wins over all of
    /// this ([`key_in_channel`]).
    ///
    /// An epoch minted by somebody who held neither a card nor a roster entry
    /// for them names them bare and is passed over. Being a member *now* is
    /// not decided here — that is the current roster's ([`current_members`]),
    /// which every door holds an author to.
    pub(crate) fn member(&self, did: &str) -> Option<&RosterMember> {
        match self.resolve(did) {
            Named::Believed(entry) => Some(entry),
            Named::Unknown | Named::Disputed => None,
        }
    }

    /// Whether the logs the rosters this node holds carry for `did` diverge
    /// ([`Self::member`] believes neither): somebody holding a retired key of
    /// theirs has grown a fork of their log. A rotation carries them as a DID
    /// alone and wraps them no grant ([`member_in_rotation`]); a copy to them
    /// says so ([`no_key_for`]).
    pub(crate) fn disputed(&self, did: &str) -> bool {
        matches!(self.resolve(did), Named::Disputed)
    }

    fn resolve(&self, did: &str) -> Named<'_> {
        let named: Vec<&RosterMember> = self
            .held
            .iter()
            .flat_map(|(_, roster)| roster.iter())
            .filter(|m| m.did == did && m.key.is_some())
            .collect();
        let extends = |longer: &RosterMember, shorter: &RosterMember| {
            shorter.kel.len() <= longer.kel.len() && longer.kel[..shorter.kel.len()] == shorter.kel[..]
        };
        // Newest roster first, so of several carrying the one log that extends
        // every other, the newest's entry is believed.
        if named.is_empty() {
            return Named::Unknown;
        }
        match named.iter().copied().find(|candidate| named.iter().all(|other| extends(candidate, other))) {
            Some(entry) => Named::Believed(entry),
            None => {
                tracing::warn!(
                    channel = %self.channel_did,
                    member = %did,
                    "the rosters held for this channel carry key logs for this member that diverge; neither is \
                     believed, and the member is unreachable here unless this node holds a card for them"
                );
                Named::Disputed
            }
        }
    }

    /// The newest roster this node holds, as its members.
    fn current(&self) -> &[RosterMember] {
        self.held.first().map(|(_, roster)| roster.as_slice()).unwrap_or_default()
    }
}

/// The identity key `did` is sealed to, and held to, for **`channel_did`'s**
/// copies, whose rosters `user_id` holds as `rosters`: their card's key when
/// `user_id` holds a card for them — a card wins — or else the key the newest
/// roster naming them with one carries ([`Rosters::member`]). `None` when
/// neither knows one: a member named only by a roster from before keys
/// travelled, until the next rotation re-seals it.
///
/// Scoped to the channel on purpose. A key from a channel's roster seals and
/// verifies that channel's copies and nothing else — not a direct message,
/// which is sealed only to a card's key ([`pubkey_for_did`]) and refused at a
/// door that holds no card (`delivery::co_member_may_say`).
pub(crate) async fn key_in_channel(
    host: &dyn MessageHost,
    user_id: &str,
    rosters: &Rosters,
    did: &str,
) -> Option<[u8; 32]> {
    if let Some(key) = host.member_public_key(user_id, did).await {
        return Some(key);
    }
    rosters.member(did).and_then(|m| m.key)
}

/// Someone `user_id` shares a channel with and holds no card for, as the
/// roster of that channel names them: a **co-member**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoMember {
    pub did: String,
    /// Their identity key, as the roster carries it — what the pair's door is
    /// derived from and what their copies are held to.
    pub key: [u8; 32],
    /// The reach note the roster carries for them: where they are dialled,
    /// and which devices may sign for a copy sent them.
    pub reach: Option<ReachNote>,
    /// The channel whose roster names them.
    pub channel_did: String,
}

/// Every co-member of `user_id`'s ([`CoMember`]): for each channel they hold a
/// key for, each member of its **current** roster who is not them, holds no
/// card on their node, and is named with a key by a roster of the channel they
/// hold ([`Rosters::member`]). One entry per person and key: a person in two
/// channels under one key is one door, and under two keys — one roster
/// staler than the other — two, each held to its own channel's copies.
///
/// What a node opens a door for besides its contacts (`kuserd`'s mailbox), what
/// its vault is handed doors for, and where a copy to a co-member is dialled.
/// Somebody removed at the last rotation is in no current roster and has no
/// door. An error only when the store cannot list this person's channels; a
/// channel whose rosters cannot be read names nobody here, and
/// [`co_members_read`] says which those were.
pub async fn co_members(host: &dyn MessageHost, user_id: &str) -> Result<Vec<CoMember>, String> {
    co_members_read(host, user_id).await.map(|read| read.members)
}

/// What one reading of a person's co-members found ([`co_members_read`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoMembersRead {
    /// Every co-member the readable channels name, as [`co_members`] answers.
    pub members: Vec<CoMember>,
    /// The channels this person holds a key for whose rosters could not be
    /// read this time: they name nobody in `members`, and that is a failed
    /// read, not a channel that is empty.
    pub unreadable: Vec<String>,
}

/// [`co_members`], and which channels' rosters could not be read.
///
/// For a caller that keeps what it had when a read fails: `kuserd`'s mailbox,
/// whose rebuild would otherwise take a roster it could not read for a channel
/// that names nobody and drop every door that channel opened
/// (`TASK-a-mailbox-rebuild-that-cannot-list-the-set-drops-every-door-and-is-not-tried-again`).
pub async fn co_members_read(host: &dyn MessageHost, user_id: &str) -> Result<CoMembersRead, String> {
    let Some(own) = user_did(host, user_id) else {
        return Ok(CoMembersRead::default());
    };
    let grants = match host
        .record_query(user_id, NSID_CHANNEL_KEY_GRANT, vec![("to_did".to_string(), json!(own))], None, None, None)
        .await
    {
        Ok(grants) => grants,
        Err(e) if e.to_string().contains("no such table") => Vec::new(),
        Err(e) => return Err(format!("could not read this identity's channel keys: {e}")),
    };
    let mut channels: Vec<String> = grants
        .iter()
        .filter_map(|g| g.get("channel_did").and_then(|d| d.as_str()).map(str::to_owned))
        .collect();
    channels.sort();
    channels.dedup();
    let mut out: Vec<CoMember> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    for channel_did in channels {
        let rosters = match Rosters::read(host, user_id, &channel_did).await {
            Ok(rosters) => rosters,
            Err(e) => {
                tracing::info!(user_id, channel_did, error = %e, "the rosters of a channel could not be read; nobody is named in them");
                unreadable.push(channel_did);
                continue;
            }
        };
        for member in rosters.current() {
            if member.did == own {
                continue;
            }
            let Some(named) = rosters.member(&member.did) else { continue };
            let Some(key) = named.key else { continue };
            if out.iter().any(|c| c.did == member.did && c.key == key) {
                continue;
            }
            if host.member_public_key(user_id, &member.did).await.is_some() {
                continue;
            }
            out.push(CoMember { did: member.did.clone(), key, reach: named.reach.clone(), channel_did: channel_did.clone() });
        }
    }
    Ok(CoMembersRead { members: out, unreadable })
}

/// `did` as a co-member of `user_id`'s, in whichever channel names them first
/// ([`co_members`]) — `None` for a contact, a stranger, or when nothing can be
/// read. For what names no channel: where a hand-over to them is dialled, and
/// an acknowledgement they send back ([`far_key`], [`far_note`]).
pub async fn co_member(host: &dyn MessageHost, user_id: &str, did: &str) -> Option<CoMember> {
    co_members(host, user_id).await.ok()?.into_iter().find(|c| c.did == did)
}

/// The key `did` speaks to `user_id` under where no channel is named — an
/// acknowledgement sealed back: their card's, or a co-member's from a roster.
pub(crate) async fn far_key(host: &dyn MessageHost, user_id: &str, did: &str) -> Option<[u8; 32]> {
    match host.member_public_key(user_id, did).await {
        Some(key) => Some(key),
        None => co_member(host, user_id, did).await.map(|c| c.key),
    }
}

/// The reach note an acknowledgement from `did` is believed under: the one
/// their card holds, or — with no card — the one a roster carries for them.
pub(crate) async fn far_note(host: &dyn MessageHost, user_id: &str, did: &str) -> Option<ReachNote> {
    if host.member_public_key(user_id, did).await.is_some() {
        return host.contact_reach_note(user_id, did).await;
    }
    co_member(host, user_id, did).await.and_then(|c| c.reach)
}

/// Whether `author` has been in the channel **without a break this node can
/// see** since `from`, the epoch their leave notice was sealed at, to `current`,
/// the epoch this node holds: in the roster of every epoch after `from` up to
/// `current` that this node holds ([`rosters_held`]).
///
/// That is what tells two notices that look alike apart (the coordinator's
/// ruling of 2026-10-09). A notice sealed before the leaver's node had
/// received the newest epoch has its author in every roster since — it is
/// this membership's leave, and counts. A notice from before the author was
/// taken out and admitted again has a roster since without them — it is an
/// earlier membership's, and does not.
///
/// **An epoch this node holds no roster for is skipped, never refused** (the
/// ruling of 2026-10-09 on the assessor's ground 1). Refusing stalled the
/// channel: an elector with a gap could neither rotate for the leave nor admit
/// nor remove anybody, and nothing ran the leave again when the epoch arrived.
/// The cost is stated, not hidden: a re-admission in an epoch this node does
/// not hold is invisible to it, so it may remove a person who was admitted
/// again — which admitting them again undoes. A stall that ends only by hand is
/// not undone by anything.
fn present_since(rosters: &[(u64, Vec<RosterMember>)], author: &str, from: u64, current: u64) -> bool {
    rosters
        .iter()
        .filter(|(epoch, _)| *epoch > from && *epoch <= current)
        .all(|(_, roster)| roster.iter().any(|m| m.did == author))
}

/// The members of `channel_did`'s current epoch (`current`, whose roster is
/// `members`) who have said they left: the author of a leave notice
/// `user_id`'s store holds, still in `members`, and in the channel without a
/// break since the epoch the notice was sealed at ([`present_since`]) — the
/// members whose leave a rotation from this node must not undo
/// ([`rotate_membership`] omits them). A notice from before its author was
/// admitted again says nothing about the membership they hold now.
///
/// A store that cannot answer — for the notices or for the keys — refuses the
/// rotation rather than reading as nobody having left. An epoch this node holds
/// no roster for is skipped ([`present_since`]), never refused.
#[allow(clippy::too_many_arguments)]
async fn left_at_or_after(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    own: &str,
    sk: &SigningKey,
    retired: &mut Option<Vec<SigningKey>>,
    members: &[String],
    current: u64,
) -> Result<Vec<String>, String> {
    let filter = vec![
        ("channel_did".to_string(), json!(channel_did)),
        ("type".to_string(), json!(LEAVE_TYPE)),
    ];
    let notices = match host.record_query(user_id, NSID_MESSAGE_V1, filter, None, None, None).await {
        Ok(notices) => notices,
        // The message table is made on a person's first message: a store that
        // has none holds no notice either (as `records::record_query` reads it).
        Err(e) if e.to_string().contains("no such table") => Vec::new(),
        Err(e) => return Err(format!("could not read who has left channel {channel_did}: {e}")),
    };
    let mut rosters = None;
    let mut left = Vec::new();
    for notice in &notices {
        let Some(author) = notice.get("from_did").and_then(|d| d.as_str()) else { continue };
        if !members.iter().any(|m| m == author) || left.iter().any(|l| l == author) {
            continue;
        }
        if rosters.is_none() {
            rosters = Some(rosters_held(host, user_id, channel_did, own, sk, retired).await?);
        }
        if present_since(rosters.as_deref().unwrap_or_default(), author, epoch_of(notice), current) {
            left.push(author.to_string());
        }
    }
    Ok(left)
}

/// The rosters `user_id` holds for `channel_did` have changed — an epoch this
/// node minted ([`rotate_channel_key`]), or a grant its door or vault pickup
/// filed (`delivery::file_grant`): the host opens and closes co-members' doors
/// ([`MessageHost::rosters_changed`]), and every copy waiting in the outbox
/// for somebody the channel no longer holds is taken out
/// ([`drop_copies_for_the_gone`]).
pub(crate) async fn roster_changed(host: &dyn MessageHost, user_id: &str, channel_did: &str) {
    host.rosters_changed(user_id);
    drop_copies_for_the_gone(host, user_id, channel_did).await;
}

/// Take out of `user_id`'s outbox every copy of `channel_did` waiting for
/// somebody the channel's **current roster, as this node holds it**, does not
/// name — removed at a rotation this node holds — or names but who has said
/// they left, in a notice this node has filed ([`left_at_or_after`]). Returns
/// how many entries went (`outbox::drop_channel_copies`, which also takes a
/// share's ranges with its manifest;
/// `TASK-a-channel-copy-to-a-member-who-left-is-retried-from-the-outbox-for-ever`).
///
/// Until then such a copy had no exit but a signature, and was tried at the
/// retry's cap, and carried by the sender's vault, for as long as the sender's
/// node ran. A copy is for a member, so the question is the one the fan-out
/// asks ([`fan_out`]): whom the newest roster this node can open names.
///
/// **Nothing is taken out on a roster this node cannot read as the whole
/// membership**: no key here, no grant it can open, or a newest grant from
/// before rosters, whose count names only the grants this store happens to
/// hold. A store that cannot say who left takes out only whom the roster
/// omits. Both fail towards keeping a copy, which costs a retry; the other way
/// costs a message.
async fn drop_copies_for_the_gone(host: &dyn MessageHost, user_id: &str, channel_did: &str) -> usize {
    let (Some(sk), Some(own)) = (load_user_signing_key(user_id, host.secrets()), user_did(host, user_id)) else {
        return 0;
    };
    let mut retired = None;
    let Some(members) = current_members(host, user_id, channel_did, &own, &sk, &mut retired).await else {
        return 0;
    };
    if !members.sealed {
        return 0;
    }
    let left = match left_at_or_after(host, user_id, channel_did, &own, &sk, &mut retired, &members.dids, members.epoch)
        .await
    {
        Ok(left) => left,
        Err(e) => {
            tracing::info!(user_id, error = %e, "who has left could not be read; only copies for people the roster omits are taken out");
            Vec::new()
        }
    };
    let still_in = |did: &str| members.dids.iter().any(|m| m == did) && !left.iter().any(|l| l == did);
    outbox::drop_channel_copies(host, user_id, channel_did, &still_in).await
}

/// What a membership rotation leaves its caller: the key it proved with, the
/// grants it held before the rotation (newest epoch first), the retired keys
/// it fetched on the way if any, and each `(did, grant)` the rotation wrote.
struct Rotation {
    sk: SigningKey,
    held: Vec<serde_json::Value>,
    retired: Option<Vec<SigningKey>>,
    written: Vec<(String, serde_json::Value)>,
}

/// Change a channel's membership by `delta`, rotating the channel key as it
/// does — admitting and removing are this one function.
///
/// The requesting `user_id` must already hold — and be able to open — a
/// `sh.kotton.channel.key-grant` for `channel_did`. That is the whole of the
/// authority to change the membership: whoever may admit may remove
/// (`TASK-a-member-is-removed-from-a-channel-by-a-rotation-that-omits-them`,
/// which takes it as the default while who may remove whom stays the
/// membership model's open question).
///
/// Every change **mints a new epoch** — a fresh key granted to exactly the
/// next membership, never the existing key re-wrapped. Admitted, a member
/// holds no key for what came before; removed, a member holds none for what
/// comes after. Both are properties of which keys a person holds, not of which
/// rows were copied to them.
async fn rotate_membership(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    delta: Delta<'_>,
) -> Result<Rotation, String> {
    let sk = load_user_signing_key(user_id, host.secrets())
        .ok_or_else(|| "identity key unavailable — unlock your session first".to_string())?;
    // The AID, not a key-derived DID: grants and records are addressed by the
    // identity the rest of the system issues.
    let self_did = user_did(host, user_id)
        .ok_or_else(|| "identity unavailable — unlock your session first".to_string())?;

    // 1. The caller's own grants, newest epoch first.
    let held = own_grants(host, user_id, channel_did, &self_did).await;
    if held.is_empty() {
        return Err(format!(
            "no channel key grant found for channel {channel_did} — \
             you must be the channel creator or a key-holder"
        ));
    }
    let current_epoch = epoch_of(&held[0]);

    // 2. Proof of membership. Rotating does not *need* the old key — a fresh one
    //    is minted — but being able to open it is what separates a key-holder
    //    from someone merely holding a grant record addressed to them that they
    //    cannot use. Changing a channel's membership should require being in it.
    //    A grant wrapped before a `RotateIdentity` is opened with the key it
    //    retired, as in `message_decrypt_channel`: the person is no less a
    //    key-holder for having rotated.
    let mut retired = None;
    unwrap_own_grant(host, user_id, &held[0], &sk, &mut retired)?;

    // 3. Who the new epoch goes to: everyone holding the current key, changed by
    //    `delta`. Existing members have to be carried across or the rotation
    //    would quietly evict them — the sender moves to the new epoch on their
    //    very next message, and anyone left behind would stop being able to read
    //    a channel they are still in. Leaving one of them behind on purpose is
    //    what a removal is.
    //    Read from the roster in the caller's own grant, so a member who wrote
    //    none of the grants sees the whole channel and does not fork it.
    //    Less everyone whose leave notice this node has filed and who has been
    //    in the channel without a break since the epoch it was sealed at
    //    ([`left_at_or_after`]): until the elector's epoch
    //    reaches this node its roster still lists a leaver, and a rotation of
    //    any kind made from it would hand them the next key — and their node,
    //    holding no grant, would take it. The elector decides *who rotates on a
    //    leave*; this is *what any rotation omits*. The delta's own DID is kept
    //    so `delta` says what happens to them: the elector's removal of the
    //    leaver removes them, and an admission of somebody who left admits them
    //    again, on purpose.
    let (members, epoch) = current_members(host, user_id, channel_did, &self_did, &sk, &mut retired)
        .await
        .map(|m| (m.dids, m.epoch))
        .unwrap_or_default();
    let named = match delta {
        Delta::Admit(did) | Delta::Remove(did) => did,
    };
    let left = left_at_or_after(host, user_id, channel_did, &self_did, &sk, &mut retired, &members, epoch).await?;
    let members: Vec<String> = members.into_iter().filter(|m| m == named || !left.contains(m)).collect();
    let members = next_members(members, &self_did, channel_did, delta)?;

    // 4. Mint the next epoch and distribute it — but not to admit somebody it
    //    could wrap no key to. A member already in is carried bare when this
    //    node believes no key for them ([`member_in_rotation`]); the person
    //    being admitted is not a member yet, and an epoch minted for them that
    //    they are granted nothing of would admit nobody.
    let admitted = match delta {
        Delta::Admit(did) => Some(did),
        Delta::Remove(_) => None,
    };
    if let Some(did) = admitted.filter(|did| *did != self_did) {
        let rosters = Rosters::held(host, user_id, channel_did).await;
        if key_in_channel(host, user_id, &rosters, did).await.is_none() {
            Did::parse(did).map_err(|e| format!("invalid DID: {e}"))?;
            return Err(format!(
                "no key known for {did} — they are not a contact of yours, and no roster you hold for this \
                 channel names a key for them; pair with them first"
            ));
        }
    }
    let written = rotate_channel_key(host, user_id, channel_did, current_epoch + 1, &members, admitted).await?;
    Ok(Rotation { sk, held, retired, written })
}

/// Admit `member_did` to a channel, rotating the channel key as it does
/// ([`rotate_membership`] with [`Delta::Admit`]).
///
/// Admission **mints a new epoch**: a fresh channel key is generated and granted
/// to the existing membership *and* the new member, rather than the existing key
/// being re-wrapped. That is what makes "joining does not show you yesterday's
/// conversation" a property of the cryptography instead of a property of which
/// rows happened to be copied. The new member holds no key for the earlier
/// epochs, so that history stays closed to them wherever they meet it —
/// including on a hosting node that mirrors the channel's ciphertext to members.
///
/// `backfill` is the deliberate exception, and the reason the choice belongs
/// here: admitting someone to a household channel may very well mean showing
/// them the history, and with epochs that becomes something the admitter grants
/// for this admission rather than something the system settles once for
/// everybody. When set, the member also receives a grant for every earlier epoch
/// the granter can open.
///
/// The new member's grant is returned as `ChannelKeyGrantCreated { grant }` so
/// callers can relay it out-of-band (e.g. as an encrypted DM) when the member
/// has no identity on this daemon.
pub async fn message_channel_grant_key(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
    member_did: String,
    backfill: bool,
) -> io::Result<UserResponse> {
    let Rotation { sk, held, mut retired, written } =
        match rotate_membership(host, &user_id, &channel_did, Delta::Admit(&member_did)).await {
            Ok(r) => r,
            Err(message) => return Ok(UserResponse::Error { message }),
        };

    // Backfill, when it was asked for: hand the member every earlier epoch the
    // granter can open. Deliberately after the rotation, so that a failure here
    // cannot leave the channel without a current key — a member short some
    // history is recoverable, a channel nobody can write is not.
    if backfill {
        match pubkey_for_did(host, &user_id, &member_did).await {
            Ok(member_pub) => {
                for past in &held {
                    let past_epoch = epoch_of(past);
                    let Ok(key) = unwrap_own_grant(host, &user_id, past, &sk, &mut retired) else {
                        // An epoch the granter cannot open is one they cannot
                        // pass on. Skipped rather than fatal: the admission
                        // itself has already succeeded.
                        tracing::warn!(
                            epoch = past_epoch,
                            "backfill: skipping an epoch the granter cannot open"
                        );
                        continue;
                    };
                    // That epoch's roster as its minter sealed it, carried
                    // through unopened: it says who that epoch was granted to,
                    // and a backfill adds a reader of the past, not a member
                    // of it. The member reads the current membership from
                    // their grant at the new epoch, which is never this one.
                    if let Err(e) = write_grant(
                        host,
                        &user_id,
                        &channel_did,
                        &member_did,
                        &member_pub,
                        &key,
                        past_epoch,
                        sealed_roster_of(past).as_ref(),
                    )
                    .await
                    {
                        tracing::warn!(
                            epoch = past_epoch,
                            error = %e,
                            "backfill: could not grant an earlier epoch"
                        );
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "backfill: member key unresolvable"),
        }
    }

    match written
        .into_iter()
        .find(|(did, _)| did == &member_did)
        .map(|(_, g)| g)
    {
        Some(grant) => Ok(UserResponse::ChannelKeyGrantCreated { grant }),
        None => Ok(UserResponse::Error {
            message: format!("internal: the rotation produced no grant for {member_did}"),
        }),
    }
}

/// Remove `member_did` from a channel: the rotation that admits, with the
/// member omitted instead of added ([`rotate_membership`] with
/// [`Delta::Remove`]).
///
/// A fresh key is minted at the next epoch and granted to every current member
/// but them. They keep every grant they already hold, so what was said while
/// they were in stays open to them — it was theirs to read, and nothing can
/// take back a key already handed over. What is sealed after the rotation is
/// under a key they were never given, so it does not open for them even with
/// the ciphertext in hand, and the next message's fan-out does not reach them,
/// since membership is read at the newest epoch.
///
/// Who may remove is who may admit: anyone holding the channel's current key.
/// Removing yourself is refused — leaving is another verb ([`next_members`]).
///
/// Answers `Ok`: there is no grant to hand back, because the point is that the
/// removed member is given none.
pub async fn message_channel_remove_member(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
    member_did: String,
) -> io::Result<UserResponse> {
    match rotate_membership(host, &user_id, &channel_did, Delta::Remove(&member_did)).await {
        Ok(_) => Ok(UserResponse::Ok),
        Err(message) => Ok(UserResponse::Error { message }),
    }
}

// ── Leaving: MessageChannelLeave ──────────────────────────────────────────────

/// The `type` a leave notice carries: a channel message saying its author has
/// left, with an empty body. Kept in the channel like any message, so the
/// conversation shows who left and when (RFC-0064, *The `message-type` field*,
/// the note of 2026-10-09).
pub const LEAVE_TYPE: &str = "leave";

/// Who rotates the channel when `leaver` leaves it: the member whose DID sorts
/// first in `roster` — the current epoch's, as any member's node reads it from
/// its own grant ([`current_members`]) — once the leaver is taken out.
///
/// Deterministic on purpose. Every member's node holds the same sealed roster
/// for an epoch, so every node names the same elector with no message, no
/// clock and no vote; and since a rotation mints a fresh key, two members
/// each rotating for one leave would mint two keys for one epoch and fork the
/// channel. `None` when the leaver is not in the roster — the epoch that
/// omits them is already here, or they were never in it — or was alone in it.
pub(crate) fn elector<'a>(roster: &'a [String], leaver: &str) -> Option<&'a str> {
    if !roster.iter().any(|d| d == leaver) {
        return None;
    }
    roster.iter().map(String::as_str).filter(|d| *d != leaver).min()
}

/// What filing a leave notice did on a remaining member's node
/// ([`rotate_for_leave`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AfterLeave {
    /// This node is the elector, and minted this epoch for every current
    /// member but the leaver.
    Rotated(u64),
    /// Another member is the elector; this node waits for the epoch they mint.
    Waits { elector: String },
    /// Nothing to rotate, and why — the leaver is not in this node's current
    /// roster (a notice at an epoch already left behind), the channel's newest
    /// grant here is from before rosters, or this is the leaver's own node.
    Nothing(String),
    /// This node is the elector and the rotation did not happen, and why.
    Failed(String),
}

/// A leave notice from `leaver_did` for `channel_did` has just been filed in
/// `user_id`'s store: rotate the channel to an epoch that omits them **only if
/// this node is the [`elector`]**, and otherwise wait.
///
/// The rotation is [`rotate_membership`] with [`Delta::Remove`] — removal's,
/// unchanged — run by the one member the roster names, so nothing new signs
/// anything and nobody else mints a key. It rotates for a notice sealed at
/// `epoch` whose author is in this node's current roster **and has been in the
/// channel without a break since `epoch`** ([`present_since`]; the
/// coordinator's ruling of 2026-10-09): a notice sealed before the leaver's
/// node had received the newest epoch is this membership's leave, and rotates
/// now, at the current epoch; a notice from before its author was taken out and
/// admitted again rotates nothing; a second notice finds the leaver out of the
/// roster. An epoch in the range this node holds no roster for is skipped; a
/// store that cannot answer refuses the rotation.
/// A notice newer than the node's epoch is held back before filing
/// ([`leave_not_yet`]).
///
/// Called by the one filing a channel copy takes, the door's and the vault
/// pickup's alike (`delivery::file_message`), and only for a notice filed now
/// — a copy already held is the same notice again.
pub(crate) async fn rotate_for_leave(
    host: &dyn MessageHost,
    user_id: &str,
    channel_did: &str,
    leaver_did: &str,
    epoch: u64,
) -> AfterLeave {
    let (Some(sk), Some(own)) = (load_user_signing_key(user_id, host.secrets()), user_did(host, user_id)) else {
        return AfterLeave::Nothing("this identity's key is not available on this node".to_string());
    };
    if leaver_did == own {
        return AfterLeave::Nothing("it is this identity's own notice".to_string());
    }
    let Some(members) = current_members(host, user_id, channel_did, &own, &sk, &mut None).await else {
        return AfterLeave::Nothing(format!("this identity holds no key-grant it can open for channel {channel_did}"));
    };
    if !members.sealed {
        // Every node of a channel from before rosters reads a different count,
        // so they would name different electors and fork it: nobody rotates.
        return AfterLeave::Nothing(format!(
            "this identity's newest grant for channel {channel_did} (epoch {}) was filed before rosters, so it \
             names no elector — a channel from before rosters takes no new epoch over the door",
            members.epoch
        ));
    }
    if epoch > members.epoch {
        return AfterLeave::Nothing(format!(
            "the notice was sealed at epoch {epoch} of channel {channel_did}, newer than epoch {}, the newest \
             this identity holds",
            members.epoch
        ));
    }
    match elector(&members.dids, leaver_did) {
        None => AfterLeave::Nothing(format!(
            "{leaver_did} is not in channel {channel_did} at epoch {}, the newest this identity holds — the \
             epoch that omits them is already here",
            members.epoch
        )),
        Some(elector) if elector != own => AfterLeave::Waits { elector: elector.to_string() },
        Some(_) => {
            let rosters = match rosters_held(host, user_id, channel_did, &own, &sk, &mut None).await {
                Ok(rosters) => rosters,
                Err(reason) => return AfterLeave::Failed(reason),
            };
            if !present_since(&rosters, leaver_did, epoch, members.epoch) {
                return AfterLeave::Nothing(format!(
                    "{leaver_did} was out of channel {channel_did} at an epoch after {epoch}, the one the notice \
                     was sealed at, and has been admitted again since — a notice from an earlier membership \
                     rotates nothing"
                ));
            }
            match rotate_membership(host, user_id, channel_did, Delta::Remove(leaver_did)).await {
                Ok(rotation) => AfterLeave::Rotated(
                    rotation.written.first().map(|(_, g)| epoch_of(g)).unwrap_or(members.epoch + 1),
                ),
                Err(reason) => AfterLeave::Failed(reason),
            }
        }
    }
}

/// Why a leave notice sealed at `epoch` cannot be filed by `user_id`'s node
/// yet: it is newer than any epoch this node holds, whose grant may still be on
/// its way. Filed now, it would be judged against a membership this node has
/// not reached, and it would not be filed again. Refused for now instead, it waits in
/// the leaver's outbox, or at this node's vault, and is filed once the epoch it
/// was sealed at is here. `None` when it may be filed.
pub(crate) async fn leave_not_yet(host: &dyn MessageHost, user_id: &str, channel_did: &str, epoch: u64) -> Option<String> {
    let (sk, own) = (load_user_signing_key(user_id, host.secrets())?, user_did(host, user_id)?);
    let members = current_members(host, user_id, channel_did, &own, &sk, &mut None).await?;
    (epoch > members.epoch).then(|| {
        format!(
            "that leave notice was sealed at epoch {epoch} of channel {channel_did}, newer than epoch {}, the \
             newest this identity holds — it is filed once that epoch is here",
            members.epoch
        )
    })
}

/// Leave `channel_did`: post a [`LEAVE_TYPE`] notice into it, then drop every
/// key-grant `user_id` holds for it.
///
/// **The notice is a channel message**, sealed under the newest epoch the
/// leaver holds and signed by them, filed as their own copy and handed to every
/// current member by [`fan_out`] — the path any post takes, the door's, the
/// vault's and the carry's — and filed on each member's node by the filing any
/// channel copy takes, behind the author check. There, the [`elector`] rotates
/// ([`rotate_for_leave`]) and everyone else waits for the epoch it mints. The
/// elector is handed the notice **last**: the epoch it mints no longer holds
/// the leaver, so a member who took that epoch first would refuse the notice
/// as from somebody outside the channel. A member reached only later — asleep,
/// their vault holding both — may still meet the epoch first, and keeps no
/// notice; they read the leave in the roster.
///
/// **Then the keys go.** Every grant for the channel in the leaver's store —
/// their own, at every epoch, and the copies they kept of grants they wrote to
/// others — is deleted, so the channel is no longer among their groups
/// ([`message_groups`]) and nothing sealed after opens for them on this node,
/// even given the ciphertext — including a post sealed at the epoch they held,
/// before the elector's rotation reaches the sender. Nothing else is touched:
/// the conversation's records stay in their store, and every file shared with
/// them stays under *Shared with you*, a copy of theirs (RFC-0090 SH1).
/// Without the keys, the conversation's own text no longer opens for them —
/// the cost of the record's *drops every grant*, escalated in
/// `TASK-a-person-who-leaves-a-channel-can-no-longer-read-what-was-said-while-they-were-in`.
///
/// **Leaving is unconditional** (the coordinator's ruling of 2026-10-09). Each
/// member's copy of the notice goes into the leaver's outbox, as a message to
/// a contact does ([`hand_leave`]): tried now, tried again until a device of
/// theirs signs for it, and carried by the leaver's vault while none of the
/// leaver's devices is awake. The leave is done on the leaver's node the
/// moment the notice is filed and in the outbox, and the keys go then; the
/// others learn when it reaches them, and the elector rotates when it files
/// it. Nothing waits on any member taking it now — a member asleep, the elector
/// included, is a notice waiting in the outbox. What leaves the person in is a
/// notice never posted: their own copy could not be sealed or written, or a
/// member's copy could not be kept in the outbox — then nothing was handed to
/// anybody, their own copy is taken out again, and they are told so from their
/// own store.
///
/// Answers `ChannelSent` with each member's delivery, as a post does.
pub async fn message_channel_leave(
    host: &dyn MessageHost,
    user_id: String,
    channel_did: String,
) -> io::Result<UserResponse> {
    let sealer = match ChannelSealer::newest(host, &user_id, &channel_did).await {
        Ok(s) => s,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    // Who rotates, from the roster the notice is sealed at — the same roster
    // every remaining member reads, so the same answer theirs gives.
    let roster = current_members(host, &user_id, &channel_did, &sealer.from_did, &sealer.sk, &mut None).await;
    let elector = roster
        .as_ref()
        .filter(|m| m.sealed)
        .and_then(|m| elector(&m.dids, &sealer.from_did).map(str::to_owned));
    let members = roster.map(|m| m.dids).unwrap_or_default();
    let sealed = match sealer.seal(b"") {
        Ok(v) => v,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let message_id = match sealer.file_own(host, &user_id, &channel_did, LEAVE_TYPE, &sealed).await {
        Ok(id) => id,
        Err(message) => return Ok(UserResponse::Error { message }),
    };
    let copy = sealer.copy(&channel_did, &sealed);
    let fanout = match hand_leave(host, &user_id, &sealer, &members, elector.as_deref(), &copy, &message_id).await {
        Ok(fanout) => fanout,
        Err(why) => {
            // Nothing was handed to anybody: the person is still in, so their
            // own conversation does not say they left.
            if let Err(e) = host.record_delete(&user_id, NSID_MESSAGE_V1, &message_id).await {
                tracing::warn!(error = %e, "leave: the notice could not be kept to send, and its own copy stays");
            }
            return Ok(UserResponse::Error {
                message: format!(
                    "you have not left channel {channel_did}: your leave notice could not be kept to send ({why}), \
                     so it went to nobody, and you are still in the channel holding its keys"
                ),
            });
        }
    };
    let dropped = drop_grants(host, &user_id, &channel_did).await;
    // Without the keys there are no rosters, and nobody this channel alone
    // made a co-member of is one any more: their doors close.
    host.rosters_changed(&user_id);
    match dropped {
        Ok(()) => Ok(UserResponse::ChannelSent { message_id, fanout }),
        Err(e) => Ok(UserResponse::Error {
            message: format!(
                "your leave notice was posted, and {e} — a key you still hold for channel {channel_did} opens \
                 what is sealed under it until you leave again"
            ),
        }),
    }
}

/// Hand each member but the leaver their copy of the leave notice `copy`,
/// whose leaver's own record is `record_id`, and answer each one's delivery.
///
/// **Kept before anything is handed**, as a streamed share's pieces are: every
/// member's sealed copy goes into the leaver's outbox first, where it waits until
/// a device of theirs signs for it and the leaver's vault carries it while none
/// of the leaver's devices is awake. If any cannot be kept, those that were are
/// taken out again and nothing is handed to anybody — `Err`, and the leave does
/// not happen: the keys drop only once the notice is sure to be said
/// (the assessor's ground 4 of 2026-10-09). A member on this machine is handed
/// theirs at once. A member who is no contact of the leaver's is sealed to and
/// dialled by what the channel's roster carries for them, and their copy waits
/// in the outbox like any other
/// (`TASK-a-channel-member-who-is-not-the-senders-contact-never-receives-the-senders-copies`);
/// only one named by a roster from before keys travelled, whom the leaver never
/// paired with, has no key to be sealed to, and is said so in their own line.
///
/// **The elector last** (`elector`). Its node rotates on filing the notice, and
/// the epoch it mints no longer holds the leaver, so a member handed the notice
/// after that epoch reached them would refuse it as from somebody outside the
/// channel. Handed last, it reaches every member reachable now after they have
/// filed it.
async fn hand_leave(
    host: &dyn MessageHost,
    user_id: &str,
    sealer: &ChannelSealer,
    members: &[String],
    elector: Option<&str>,
    copy: &ChannelCopy,
    record_id: &str,
) -> Result<Vec<MemberDelivery>, String> {
    let mut order: Vec<&String> = members.iter().filter(|m| **m != sealer.from_did).collect();
    order.sort_by_key(|m| Some(m.as_str()) == elector);

    enum Way {
        Door(outbox::OutboxEntry),
        Here(String, SealedDm),
        Said(Delivery),
    }
    // A member this person never paired with is sealed to and dialled by what
    // the channel's roster carries for them, as a post is ([`deliver_copy`]).
    let rosters = Rosters::held(host, user_id, &copy.channel_did).await;
    let mut ways: Vec<(String, Way)> = Vec::with_capacity(order.len());
    for member_did in order {
        let way = match key_in_channel(host, user_id, &rosters, member_did).await {
            None => Way::Said(no_key_for(member_did, rosters.disputed(member_did))),
            Some(member_pub) => {
                let inner = copy_inner(&sealer.from_did, member_did, copy, LEAVE_TYPE);
                match envelope::seal(&inner, &sealer.sk, &member_pub) {
                    Err(reason) => Way::Said(Delivery::Unreachable { reason }),
                    Ok(sealed) => match host.local_user_for_did(member_did) {
                        Some(local) if local == user_id => Way::Said(Delivery::Local),
                        Some(local) => Way::Here(local, sealed),
                        None => Way::Door(outbox::new_entry(member_did, record_id, &sealed, Some(&copy.channel_did))),
                    },
                }
            }
        };
        ways.push((member_did.clone(), way));
    }

    // Every member's copy kept, or none.
    let mut kept: Vec<&str> = Vec::new();
    for (_, way) in &ways {
        if let Way::Door(entry) = way {
            if let Err(e) = host.keep_outbox_entry(user_id, entry).await {
                for id in kept {
                    if let Err(e) = host.drop_outbox_entry(user_id, id).await {
                        tracing::warn!(error = %e, "leave: a notice kept for a member could not be taken out again");
                    }
                }
                return Err(format!("your outbox could not keep it: {e}"));
            }
            kept.push(&entry.id);
        }
    }

    let mut out = Vec::with_capacity(ways.len());
    for (member_did, way) in ways {
        let delivery = match way {
            Way::Door(entry) => outbox::attempt(host, user_id, entry, host.outbox_retry()).await,
            Way::Here(local, sealed) => match host.user_current_key(user_id) {
                Some(sender_pub) => hand_here(host, &local, &sealer.from_did, &sender_pub, sealed, Vec::new()).await,
                None => Delivery::Unreachable { reason: "could not resolve your own key from your KEL".to_string() },
            },
            Way::Said(delivery) => delivery,
        };
        out.push(MemberDelivery { member_did, delivery });
    }
    Ok(out)
}

/// Delete every key-grant for `channel_did` in `user_id`'s store — their own
/// at every epoch, and the copies they kept of grants they wrote to others.
/// Every one is tried; the failures are said together.
async fn drop_grants(host: &dyn MessageHost, user_id: &str, channel_did: &str) -> Result<(), String> {
    let grants = host
        .record_query(
            user_id,
            NSID_CHANNEL_KEY_GRANT,
            vec![("channel_did".to_string(), json!(channel_did))],
            None,
            None,
            None,
        )
        .await
        .map_err(|e| format!("its keys could not be read to let go of them: {e}"))?;
    let mut failed = Vec::new();
    for grant in &grants {
        let Some(id) = grant.get("_id").and_then(|v| v.as_str()) else {
            failed.push("a key-grant with no id".to_string());
            continue;
        };
        if let Err(e) = host.record_delete(user_id, NSID_CHANNEL_KEY_GRANT, id).await {
            failed.push(e.to_string());
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("{} of its {} keys could not be let go: {}", failed.len(), grants.len(), failed.join("; ")))
    }
}

/// Hand a copy of a channel message to every current member but the sender.
///
/// **The unit of delivery is a member, not the channel.** A channel has no node
/// and no door of its own; what exists is a set of people the sender has paired
/// with, and this is one hand-off to each, over the same contact door and the
/// same verb a direct message uses. That is `DEC-0055`'s sentence — *a group
/// message is the same verb to each current member* — and it is why there is no
/// group transport to build.
///
/// **Current, in the RFC-0064 sense.** The set is the roster sealed in the
/// sender's newest grant ([`current_members`]), so it is the whole membership
/// from any member's node — not only from the node of whoever wrote the grants —
/// and somebody removed at the last rotation is not in it. They also
/// could not read a copy if they were given one, since it is sealed under the key
/// they were not re-granted — the epoch filter is what stops the copy being sent
/// at all, and the seal is what makes that failure safe rather than merely tidy.
///
/// **A member is never a failed send.** The sender's own copy was written before
/// this runs. Each member's answer is reported beside their DID, so one person
/// with nothing awake and no vault leaves their copy waiting at home while every
/// other copy is handed over.
///
/// **A member is a member whether or not the sender ever paired with them**
/// (`TASK-a-channel-member-who-is-not-the-senders-contact-never-receives-the-senders-copies`).
/// The roster that says who holds the key also carries each member's key and
/// reach note ([`RosterMember`]), so a member who is no contact of the sender's
/// is sealed to and dialled by what it says of them — the door the pair's keys
/// derive, at the relays their note lists — and their copy waits in the outbox
/// until a device of theirs signs for it, as every other member's does.
#[allow(clippy::too_many_arguments)]
async fn fan_out(
    host: &dyn MessageHost,
    sender_user_id: &str,
    sender_did: &str,
    sender_key: &SigningKey,
    channel_did: &str,
    copy: &ChannelCopy,
    kind: &str,
    ranges: &[GroupRange],
    record_id: &str,
) -> Vec<MemberDelivery> {
    let members = current_members(host, sender_user_id, channel_did, sender_did, sender_key, &mut None)
        .await
        .map(|m| m.dids)
        .unwrap_or_default();
    let rosters = Rosters::held(host, sender_user_id, channel_did).await;
    let mut out = Vec::new();
    for member_did in members {
        if member_did == sender_did {
            continue;
        }
        let delivery = deliver_copy(
            host,
            sender_user_id,
            sender_did,
            sender_key,
            &rosters,
            &member_did,
            copy,
            kind,
            ranges,
            record_id,
        )
        .await;
        out.push(MemberDelivery {
            member_did,
            delivery,
        });
    }
    out
}

/// The envelope's inside for one member's copy of a channel message of type
/// `kind`: who it is from and to, and the channel ciphertext — nothing else.
fn copy_inner(sender_did: &str, member_did: &str, copy: &ChannelCopy, kind: &str) -> DmInner {
    DmInner {
        from_did: sender_did.to_string(),
        to_did: member_did.to_string(),
        thread_id: Uuid::new_v4().to_string(),
        sent_at: now_secs(),
        // `text`, `share` or `leave`: the signed claim a member's node files
        // the copy by. A share's manifest is not here but in the channel
        // ciphertext, under the channel key, the same bytes every member is
        // handed.
        kind: kind.to_string(),
        // The readable body is the channel ciphertext; there is no second
        // plaintext to carry, and a copy of it here would be one the channel key
        // did not protect.
        text: String::new(),
        channel: Some(copy.clone()),
        grant: None,
        reach: None,
        ack: None,
        kel: Vec::new(),
        share: None,
        range: None,
    }
}

/// One member's copy: seal it to them, then take the same route a direct
/// message takes — the acceptance path for an account on this machine, the
/// contact door for anyone else.
///
/// Local and remote go through **one** acceptance implementation on purpose. A
/// second one filing straight into a member's store is what this replaced, and it
/// skipped every check the door applies — including, once channel copies exist,
/// the one that refuses a message for a channel the recipient is not in.
#[allow(clippy::too_many_arguments)]
async fn deliver_copy(
    host: &dyn MessageHost,
    sender_user_id: &str,
    sender_did: &str,
    sender_key: &SigningKey,
    rosters: &Rosters,
    member_did: &str,
    copy: &ChannelCopy,
    kind: &str,
    ranges: &[GroupRange],
    record_id: &str,
) -> Delivery {
    // Their identity key: their card's, as this user recorded it when they
    // paired, or — for a member this user never paired with — the one the
    // channel's roster carries for them ([`key_in_channel`]). Until 2026-10-09
    // a member with no card was answered *not a contact* here and their copy
    // dropped, so every post and every leave reached only the sender's
    // contacts. Only a member named by a roster from before keys travelled,
    // with no card, has no key to seal to: said in their own line, and every
    // other copy goes.
    let Some(member_pub) = key_in_channel(host, sender_user_id, rosters, member_did).await else {
        return no_key_for(member_did, rosters.disputed(member_did));
    };

    let inner = copy_inner(sender_did, member_did, copy, kind);
    let sealed = match envelope::seal(&inner, sender_key, &member_pub) {
        Ok(s) => s,
        Err(e) => return Delivery::Unreachable { reason: e },
    };
    // A share whose bytes stream: each range in an envelope of this member's,
    // its place beside it and its bytes the one channel ciphertext every
    // member is handed — nothing of the message but who it is from and to, as
    // a direct share's range carries.
    let ranges: Result<Vec<SealedDm>, String> = ranges
        .iter()
        .map(|(range, copy)| {
            let part = DmInner {
                from_did: sender_did.to_string(),
                to_did: member_did.to_string(),
                thread_id: String::new(),
                sent_at: inner.sent_at,
                kind: "range".to_string(),
                text: String::new(),
                channel: Some(copy.clone()),
                grant: None,
                reach: None,
                ack: None,
                kel: Vec::new(),
                share: None,
                range: Some(range.clone()),
            };
            envelope::seal(&part, sender_key, &member_pub)
        })
        .collect();
    let ranges = match ranges {
        Ok(r) => r,
        Err(e) => return Delivery::Unreachable { reason: e },
    };

    match host.local_user_for_did(member_did) {
        Some(local_user) if local_user == sender_user_id => Delivery::Local,
        Some(local_user) => {
            let Some(sender_pub) = host.user_current_key(sender_user_id) else {
                return Delivery::Unreachable {
                    reason: "could not resolve your own key from your KEL".to_string(),
                };
            };
            hand_here(host, &local_user, sender_did, &sender_pub, sealed, ranges).await
        }
        // A share whose bytes stream waits in the outbox as a direct one does,
        // its manifest and each range `part_of` it, until a device of this
        // member's signs for it — so its ranges are tried again, and carried
        // by the sender's vault, as any share's are.
        None if !ranges.is_empty() => {
            outbox::send_share(
                host,
                sender_user_id,
                member_did,
                record_id,
                &sealed,
                &ranges,
                Some(&copy.channel_did),
                host.outbox_retry(),
            )
            .await
        }
        // Any other copy waits in the outbox too, as a direct message does:
        // tried now, tried again until a device of theirs signs for it, and
        // carried by the sender's vault while none of the sender's devices is
        // awake. Until 2026-10-09 it was handed once and not kept, so a member
        // with nothing awake and no vault never received it.
        None => {
            outbox::send(host, sender_user_id, member_did, record_id, &sealed, Some(&copy.channel_did), host.outbox_retry())
                .await
        }
    }
}

/// What a member's line says when this node believes no key for them: it
/// holds no card for them, and no roster it holds for the channel names a key
/// their log yields — a bare entry, a roster from before keys travelled — or,
/// `disputed`, the logs those rosters carry for them diverge
/// ([`Rosters::disputed`]). One text for all of them, the divergence named only
/// when it is the reason: nothing can be sealed to them here until a rotation
/// by somebody holding their card names them again.
fn no_key_for(member_did: &str, disputed: bool) -> Delivery {
    let why = if disputed {
        " — the rosters you hold for this channel carry key logs for them that diverge"
    } else {
        ""
    };
    Delivery::Unreachable {
        reason: format!(
            "{member_did} is in this channel, but their key is not known on this node: you hold no card for them{why}; \
             a rotation by somebody who holds their card names them again"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::expose_row_id;

    /// The rename the wire's `id` depends on, and the removal the IPC layer
    /// depends on: a caller must get a stable handle on a message and must not
    /// get the store's own column name.
    #[test]
    fn a_row_id_is_renamed_and_the_internal_name_is_gone() {
        let out = expose_row_id(serde_json::json!({ "_id": "row-1", "body": "x" }));
        assert_eq!(out["id"], "row-1");
        assert!(out.get("_id").is_none(), "the internal column name must not leave the daemon");
        assert_eq!(out["body"], "x");
    }

    /// The filing position crosses under the wire's name, beside the sender's
    /// claim rather than instead of it.
    #[test]
    fn a_filing_position_is_renamed_beside_the_senders_claim() {
        let out = expose_row_id(serde_json::json!({ "_id": "row-1", "_filed_at": 1_757_000_000_123i64, "sent_at": 5 }));
        assert_eq!(out["filed_at"], 1_757_000_000_123i64);
        assert!(out.get("_filed_at").is_none(), "the internal name must not leave the daemon");
        assert_eq!(out["sent_at"], 5, "the sender's claim is still there, and still only a claim");
    }

    /// A row with no id at all is passed through rather than refused — the
    /// caller decides what an unidentifiable row is worth, and this function's
    /// job is one rename.
    #[test]
    fn a_row_without_an_id_is_left_as_it_is() {
        let out = expose_row_id(serde_json::json!({ "body": "x" }));
        assert!(out.get("id").is_none());
        assert_eq!(out["body"], "x");
    }
}

#[cfg(test)]
mod tests_epoch {
    use super::*;

    /// Continuity: a grant or message written before epochs existed reads as
    /// epoch 0, so an existing conversation stays open to the people already in
    /// it. Pinned here rather than left to the `unwrap_or` because getting it
    /// wrong would lock users out of their own history on upgrade, which no
    /// tightening this change makes is allowed to do.
    #[test]
    fn a_record_without_an_epoch_is_epoch_zero() {
        assert_eq!(epoch_of(&json!({ "to_did": "did:kel:x" })), 0);
        assert_eq!(epoch_of(&json!({ "epoch": 0 })), 0);
        assert_eq!(epoch_of(&json!({ "epoch": 7 })), 7);
    }

    /// A malformed epoch reads as 0 rather than panicking or being skipped: it
    /// is the same answer as absence, and the conservative one — the grant stays
    /// usable for the oldest epoch instead of becoming unreadable.
    #[test]
    fn a_malformed_epoch_reads_as_zero() {
        assert_eq!(epoch_of(&json!({ "epoch": "3" })), 0);
        assert_eq!(epoch_of(&json!({ "epoch": null })), 0);
        assert_eq!(epoch_of(&json!({ "epoch": -1 })), 0);
    }
}

#[cfg(test)]
mod tests_membership {
    use super::*;

    const AVERY: &str = "did:kel:avery";
    const SAM: &str = "did:kel:sam";
    const JORDAN: &str = "did:kel:jordan";
    const CHANNEL: &str = "did:key:zHousehold";

    fn current() -> Vec<String> {
        vec![AVERY.to_string(), SAM.to_string(), JORDAN.to_string()]
    }

    /// A removal is the admission's rotation with the member left out: the
    /// next epoch goes to everyone else who holds the current one, the remover
    /// among them.
    #[test]
    fn a_removal_grants_the_next_epoch_to_everyone_but_the_member() {
        let next = next_members(current(), AVERY, CHANNEL, Delta::Remove(SAM)).expect("sam is removed");
        assert_eq!(next, vec![AVERY.to_string(), JORDAN.to_string()]);
    }

    /// Admission and removal are one function: the same current members, the
    /// delta reversed.
    #[test]
    fn an_admission_grants_the_next_epoch_to_everyone_and_the_member() {
        let next = next_members(vec![AVERY.to_string(), JORDAN.to_string()], AVERY, CHANNEL, Delta::Admit(SAM))
            .expect("sam is admitted");
        assert_eq!(next, vec![AVERY.to_string(), JORDAN.to_string(), SAM.to_string()]);
    }

    /// Somebody who holds no grant at the current epoch is not removed by a
    /// rotation that would change nothing for them; it is refused, by name.
    #[test]
    fn removing_someone_who_is_not_a_member_is_refused() {
        let err = next_members(vec![AVERY.to_string(), JORDAN.to_string()], AVERY, CHANNEL, Delta::Remove(SAM))
            .expect_err("sam is not in the channel");
        assert!(err.contains(SAM) && err.contains("not a member"), "{err}");
    }

    /// The remover mints the next key, so a rotation cannot omit them: removing
    /// yourself is refused, and the refusal says leaving is another verb.
    #[test]
    fn removing_yourself_is_refused() {
        let err = next_members(current(), AVERY, CHANNEL, Delta::Remove(AVERY))
            .expect_err("avery cannot remove avery");
        assert!(err.contains("yourself") && err.contains("leaving"), "{err}");
    }
}

/// One person's node, for the tests of who is in a channel: their identity
/// key, the contacts they have paired with, and a record store that answers a
/// query by matching every named field exactly. Nothing travels: a test hands
/// one node's grant or message to another's door itself.
#[cfg(test)]
pub(crate) mod test_node {
    use super::*;
    use kotton_sys::secret::SecretsResult;
    use std::sync::Mutex;

    pub(crate) struct Keychain(String);
    impl SecretsStore for Keychain {
        fn get_secret(&self, _key: &str) -> SecretsResult<Option<String>> {
            Ok(Some(self.0.clone()))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    pub(crate) struct Node {
        pub did: String,
        pub key: SigningKey,
        keychain: Keychain,
        contacts: Vec<(String, [u8; 32])>,
        records: Mutex<Vec<(String, serde_json::Value)>>,
        /// The next `_id` a kept record is given.
        rows: std::sync::atomic::AtomicU64,
        /// The names this person's cards show, by DID.
        pub card_names: Mutex<Vec<(String, String)>>,
        /// This person's Personal tree: every file, by its path from the root.
        pub tree: Mutex<Vec<(String, Vec<u8>)>>,
        /// Every envelope this node handed to a contact's door, and whose:
        /// nothing travels, so a test hands each to the node it was for.
        pub handed: Mutex<Vec<(String, SealedDm)>>,
        /// This person's outbox: what waits for a device of its recipient's
        /// to sign for it — a streamed share's manifest and its ranges.
        pub outbox: Mutex<Vec<OutboxEntry>>,
        /// This person's stream shelf, by key.
        pub shelf: Mutex<Vec<(String, Vec<u8>)>>,
        /// Whether a door this node dials takes what it is handed, as a vault
        /// does — held, and signed for by nothing — rather than answering
        /// nothing. Off by default: nothing travels.
        pub takes: std::sync::atomic::AtomicBool,
        /// Whether reading `sh.kotton.message.v1` records fails, as a store
        /// that cannot be read does.
        pub fails_message_reads: std::sync::atomic::AtomicBool,
        /// Whether reading one channel's grants — its rosters — fails, as a
        /// store that cannot answer does; listing which channels this person
        /// holds a key for still answers.
        pub fails_roster_reads: std::sync::atomic::AtomicBool,
        /// Whether keeping an outbox entry fails, as an outbox that cannot be
        /// written does.
        pub fails_outbox_keep: std::sync::atomic::AtomicBool,
        /// How many more outbox entries may be kept before keeping fails, when
        /// set: an outbox that fails part-way.
        pub outbox_keeps_left: Mutex<Option<usize>>,
        /// Reach notes by whose they are: this person's own, and each one a
        /// card of theirs holds — read only for a DID that is a contact.
        pub notes: Mutex<Vec<ReachNote>>,
        /// Key logs by whose they are (their inception's AID): this person's
        /// own, and each one a card of theirs keeps — read only for a contact.
        pub logs: Mutex<Vec<Vec<kotton_wire::kel::KelEvent>>>,
    }

    /// A `did:kel` identity whose key is seeded `seed`: its AID — the digest
    /// of its inception — and its log, the inception alone.
    pub(crate) fn identity(seed: u8) -> (String, Vec<kotton_wire::kel::KelEvent>) {
        let inception = kotton_crypto::kel_verify::build_fresh_inception(&SigningKey::from_bytes(&[seed; 32]));
        (inception.aid.0.clone(), vec![inception])
    }

    impl Node {
        pub(crate) fn new(did: &str, seed: u8, contacts: &[(&str, u8)]) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            Self {
                did: did.to_string(),
                keychain: Keychain(hex::encode(key.to_bytes())),
                key,
                contacts: contacts
                    .iter()
                    .map(|(d, s)| (d.to_string(), SigningKey::from_bytes(&[*s; 32]).verifying_key().to_bytes()))
                    .collect(),
                records: Mutex::new(Vec::new()),
                rows: std::sync::atomic::AtomicU64::new(0),
                card_names: Mutex::new(Vec::new()),
                tree: Mutex::new(Vec::new()),
                handed: Mutex::new(Vec::new()),
                outbox: Mutex::new(Vec::new()),
                shelf: Mutex::new(Vec::new()),
                takes: std::sync::atomic::AtomicBool::new(false),
                fails_message_reads: std::sync::atomic::AtomicBool::new(false),
                fails_roster_reads: std::sync::atomic::AtomicBool::new(false),
                fails_outbox_keep: std::sync::atomic::AtomicBool::new(false),
                outbox_keeps_left: Mutex::new(None),
                notes: Mutex::new(Vec::new()),
                logs: Mutex::new(Vec::new()),
            }
        }
        fn log_of(&self, did: &str) -> Vec<kotton_wire::kel::KelEvent> {
            self.logs.lock().unwrap().iter().find(|l| l.first().map(|e| e.aid.0.as_str()) == Some(did)).cloned().unwrap_or_default()
        }
        pub(crate) fn public(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }
        /// Keep `record`, giving it an `_id` as the store does, unless it has one.
        pub(crate) fn keep(&self, nsid: &str, mut record: serde_json::Value) -> String {
            let mut records = self.records.lock().unwrap();
            let id = match record.get("_id").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => {
                    let id = format!("row{}", self.rows.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
                    record["_id"] = json!(id);
                    id
                }
            };
            records.push((nsid.to_string(), record));
            id
        }
        pub(crate) fn all(&self, nsid: &str) -> Vec<serde_json::Value> {
            self.records.lock().unwrap().iter().filter(|(n, _)| n == nsid).map(|(_, r)| r.clone()).collect()
        }
    }

    /// `channel_key` granted to `to` (whose identity key is seeded `seed`) at
    /// `epoch`, carrying `roster` sealed under it when there is one — the
    /// record a grant becomes in its holder's store.
    pub(crate) fn grant(
        channel_did: &str,
        to: &str,
        seed: u8,
        channel_key: &[u8; 32],
        epoch: u64,
        roster: Option<&[&str]>,
    ) -> serde_json::Value {
        let to_pub = SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        let (enc_key, nonce, eph_pub) = channel_key_wrap(channel_key, &to_pub).unwrap();
        let grant = json!({
            "channel_did": channel_did,
            "to_did": to,
            "enc_key": B64.encode(enc_key),
            "nonce": B64.encode(nonce),
            "ephemeral_pub": B64.encode(eph_pub),
            "epoch": epoch,
            "granted_at": 1,
        });
        if let Some(members) = roster {
            let members: Vec<RosterMember> = members.iter().map(|m| RosterMember::bare(m)).collect();
            return with_roster(grant, channel_key, &members);
        }
        grant
    }

    /// [`grant`], carrying `members` — each with whatever key and note the
    /// test gives them — sealed under `channel_key`.
    pub(crate) fn grant_naming(
        channel_did: &str,
        to: &str,
        seed: u8,
        channel_key: &[u8; 32],
        epoch: u64,
        members: &[RosterMember],
    ) -> serde_json::Value {
        with_roster(grant(channel_did, to, seed, channel_key, epoch, None), channel_key, members)
    }

    fn with_roster(mut grant: serde_json::Value, channel_key: &[u8; 32], members: &[RosterMember]) -> serde_json::Value {
        let sealed = seal_roster(channel_key, members).unwrap();
        grant["roster"] = json!(sealed.body);
        grant["roster_nonce"] = json!(sealed.nonce);
        grant
    }

    #[async_trait::async_trait]
    impl MessageHost for Node {
        fn secrets(&self) -> &(dyn SecretsStore + Send + Sync) {
            &self.keychain
        }
        fn user_aid(&self, _: &str) -> Option<String> {
            Some(self.did.clone())
        }
        fn local_user_for_did(&self, _: &str) -> Option<String> {
            None
        }
        fn user_current_key(&self, _: &str) -> Option<[u8; 32]> {
            Some(self.public())
        }
        async fn member_public_key(&self, _: &str, did: &str) -> Option<[u8; 32]> {
            self.contacts.iter().find(|(d, _)| d == did).map(|(_, k)| *k)
        }
        async fn contact_paths(&self, _: &str, _: &str) -> Result<Vec<Path>, String> {
            Ok(vec![Path::new(())])
        }
        /// Kept, and not carried: what reaches a door is the test's to hand.
        async fn deliver_on(&self, _: &str, contact_did: &str, _: &Path, request: &ContactRequest) -> Result<ContactResponse, String> {
            self.handed.lock().unwrap().push((contact_did.to_string(), request.sealed().clone()));
            if self.takes.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(ContactResponse::Delivered { stored: true, ack: None });
            }
            Err("nothing travels in these tests".to_string())
        }
        fn sign_delivery_ack(&self, message_id: &str, from_did: &str, to_did: &str) -> DeliveryAck {
            kotton_crypto::delivery_ack::sign(message_id, from_did, to_did, &self.key)
        }
        async fn contact_reach_note(&self, _: &str, did: &str) -> Option<ReachNote> {
            if !self.contacts.iter().any(|(d, _)| d == did) {
                return None;
            }
            self.notes.lock().unwrap().iter().find(|n| n.did == did).cloned()
        }
        async fn own_reach_note(&self, _: &str) -> Option<ReachNote> {
            self.notes.lock().unwrap().iter().find(|n| n.did == self.did).cloned()
        }
        async fn outbox_entries(&self, _: &str) -> anyhow::Result<Vec<OutboxEntry>> {
            Ok(self.outbox.lock().unwrap().clone())
        }
        async fn keep_outbox_entry(&self, _: &str, entry: &OutboxEntry) -> anyhow::Result<()> {
            if self.fails_outbox_keep.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("the outbox cannot be written");
            }
            if let Some(left) = self.outbox_keeps_left.lock().unwrap().as_mut() {
                if *left == 0 {
                    anyhow::bail!("the outbox stopped taking writes");
                }
                *left -= 1;
            }
            let mut outbox = self.outbox.lock().unwrap();
            outbox.retain(|e| e.id != entry.id);
            outbox.push(entry.clone());
            Ok(())
        }
        async fn drop_outbox_entry(&self, _: &str, id: &str) -> anyhow::Result<()> {
            self.outbox.lock().unwrap().retain(|e| e.id != id);
            Ok(())
        }
        async fn keep_signed_for(&self, _: &str, _: &SignedFor) -> anyhow::Result<()> {
            Ok(())
        }
        async fn all_signed_for(&self, _: &str) -> anyhow::Result<Vec<SignedFor>> {
            Ok(vec![])
        }
        async fn keep_reach_note(&self, _: &str, _: &str, _: ReachNote) -> Result<Kept, NotKept> {
            unreachable!("nobody in these tests sends a note")
        }
        fn own_key_log(&self, _: &str) -> Vec<kotton_wire::kel::KelEvent> {
            self.log_of(&self.did)
        }
        fn contact_key_log(&self, _: &str, did: &str) -> Vec<kotton_wire::kel::KelEvent> {
            if !self.contacts.iter().any(|(d, _)| d == did) {
                return Vec::new();
            }
            self.log_of(did)
        }
        async fn adopt_contact_key(&self, _: &str, _: &str, _: &[kotton_wire::kel::KelEvent], _: [u8; 32]) -> Result<(), NotKept> {
            unreachable!("nobody in these tests carries a key log")
        }
        fn retired_identity_keys(&self, _: &str, _: &SigningKey) -> Vec<SigningKey> {
            Vec::new()
        }
        async fn contact_name(&self, _: &str, contact_did: &str) -> Option<String> {
            self.card_names.lock().unwrap().iter().find(|(d, _)| d == contact_did).map(|(_, n)| n.clone())
        }
        async fn personal_names(&self, _: &str, dir: &str) -> Result<Vec<String>, String> {
            let prefix = format!("{dir}/");
            Ok(self
                .tree
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(path, _)| path.strip_prefix(&prefix))
                .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
                .collect())
        }
        async fn personal_write(&self, _: &str, path: &str, bytes: &[u8]) -> Result<(), String> {
            let mut tree = self.tree.lock().unwrap();
            tree.retain(|(p, _)| p != path);
            tree.push((path.to_string(), bytes.to_vec()));
            Ok(())
        }
        async fn stream_keep(&self, _: &str, key: &str, bytes: &[u8]) -> Result<(), String> {
            let mut shelf = self.shelf.lock().unwrap();
            shelf.retain(|(k, _)| k != key);
            shelf.push((key.to_string(), bytes.to_vec()));
            Ok(())
        }
        async fn stream_keys(&self, _: &str) -> Result<Vec<String>, String> {
            Ok(self.shelf.lock().unwrap().iter().map(|(k, _)| k.clone()).collect())
        }
        async fn stream_read(&self, _: &str, key: &str) -> Result<Vec<u8>, String> {
            self.shelf.lock().unwrap().iter().find(|(k, _)| k == key).map(|(_, b)| b.clone()).ok_or_else(|| format!("no {key}"))
        }
        async fn stream_drop(&self, _: &str, key: &str) -> Result<(), String> {
            self.shelf.lock().unwrap().retain(|(k, _)| k != key);
            Ok(())
        }
        async fn record_insert(&self, _: &str, nsid: &str, record: serde_json::Value) -> anyhow::Result<String> {
            Ok(self.keep(nsid, record))
        }
        async fn record_delete(&self, _: &str, nsid: &str, record_id: &str) -> anyhow::Result<()> {
            self.records
                .lock()
                .unwrap()
                .retain(|(n, r)| !(n == nsid && r.get("_id").and_then(|v| v.as_str()) == Some(record_id)));
            Ok(())
        }
        async fn record_query(
            &self,
            _: &str,
            nsid: &str,
            field_eq: Vec<(String, serde_json::Value)>,
            limit: Option<usize>,
            _: Option<usize>,
            _: Option<String>,
        ) -> anyhow::Result<Vec<serde_json::Value>> {
            if nsid == NSID_MESSAGE_V1 && self.fails_message_reads.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("the message store cannot be read");
            }
            if nsid == NSID_CHANNEL_KEY_GRANT
                && field_eq.iter().any(|(k, _)| k == "channel_did")
                && self.fails_roster_reads.load(std::sync::atomic::Ordering::SeqCst)
            {
                anyhow::bail!("the channel's grants cannot be read");
            }
            let mut out: Vec<serde_json::Value> = self
                .all(nsid)
                .into_iter()
                .filter(|r| field_eq.iter().all(|(k, v)| r.get(k) == Some(v)))
                .collect();
            if let Some(limit) = limit {
                out.truncate(limit);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests_roster {
    use super::test_node::{grant, identity, Node};
    use super::*;

    const AVERY: &str = "did:kel:avery";
    const SAM: &str = "did:kel:sam";
    const JORDAN: &str = "did:kel:jordan";
    const CHANNEL: &str = "did:key:zHousehold";

    /// The roster a grant carries opens under the key the same grant unwraps
    /// to, and under no other; a grant minted before rosters carries none.
    #[test]
    fn a_roster_sealed_in_a_grant_opens_under_its_own_epochs_key_and_no_other() {
        let key = channel_key_generate();
        let g = grant(CHANNEL, SAM, 2, &key, 2, Some(&[AVERY, SAM, JORDAN]));
        assert!(g.get("roster").is_some() && g.get("roster_nonce").is_some(), "{g}");
        let opened = open_roster(&g, &key).expect("the grant carries a roster").expect("it opens");
        let dids: Vec<&str> = opened.iter().map(|m| m.did.as_str()).collect();
        assert_eq!(dids, [AVERY, SAM, JORDAN]);

        let other_epoch = channel_key_generate();
        let err = open_roster(&g, &other_epoch).expect("the grant carries a roster").expect_err("another epoch's key");
        assert!(err.contains("does not open"), "{err}");

        let before = grant(CHANNEL, SAM, 2, &key, 2, None);
        assert_eq!(open_roster(&before, &key), None, "a grant from before rosters carries none");

        // Nothing outside the seal names a member: the roster's ciphertext
        // does not hold a DID in the clear.
        let outside = g.to_string();
        assert!(!outside.contains(AVERY) && !outside.contains(JORDAN), "{outside}");
    }

    /// A member who wrote none of the grants holds only their own — and reads
    /// the whole membership from it. Counting the grant records in their store,
    /// as `current_members` did until this test, reads a channel of one.
    #[tokio::test]
    async fn a_member_who_wrote_no_grant_reads_the_whole_membership_from_their_own() {
        let sam = Node::new(SAM, 2, &[]);
        let older = channel_key_generate();
        let current = channel_key_generate();
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, SAM, 2, &older, 1, Some(&[AVERY, SAM])));
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, SAM, 2, &current, 2, Some(&[AVERY, SAM, JORDAN])));

        let members = current_members(&sam, "u", CHANNEL, SAM, &sam.key, &mut None)
            .await
            .expect("sam holds grants they can open");
        assert_eq!(
            members,
            Members { epoch: 2, dids: vec![AVERY.to_string(), SAM.to_string(), JORDAN.to_string()], sealed: true },
            "the roster of sam's newest grant, not the count of sam's store"
        );
    }

    /// The newest grant a member *can open* is the one read: a grant addressed
    /// to them that their key does not unwrap is passed over.
    #[tokio::test]
    async fn a_grant_the_member_cannot_open_is_passed_over_for_the_newest_they_can() {
        let sam = Node::new(SAM, 2, &[]);
        let key = channel_key_generate();
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, SAM, 2, &key, 2, Some(&[AVERY, SAM, JORDAN])));
        // Epoch 3, filed under Sam's name, wrapped to somebody else's key.
        sam.keep(NSID_CHANNEL_KEY_GRANT, {
            let mut g = grant(CHANNEL, JORDAN, 3, &channel_key_generate(), 3, Some(&[JORDAN]));
            g["to_did"] = json!(SAM);
            g
        });
        let members = current_members(&sam, "u", CHANNEL, SAM, &sam.key, &mut None).await.expect("sam can open epoch 2");
        assert_eq!(members.epoch, 2);
        assert_eq!(members.dids, vec![AVERY.to_string(), SAM.to_string(), JORDAN.to_string()]);
    }

    /// A channel whose newest grant was minted before rosters is read as it
    /// always was — counted from the store — and says so, so the door does not
    /// hold anybody to a count.
    #[tokio::test]
    async fn a_grant_from_before_rosters_falls_back_to_the_count() {
        let avery = Node::new(AVERY, 1, &[]);
        let key = channel_key_generate();
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, 1, &key, 1, None));
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, SAM, 2, &key, 1, None));
        let members = current_members(&avery, "u", CHANNEL, AVERY, &avery.key, &mut None).await.expect("avery holds epoch 1");
        assert_eq!(members, Members { epoch: 1, dids: vec![AVERY.to_string(), SAM.to_string()], sealed: false });
    }

    /// A rotation seals the next epoch's membership into every grant of it,
    /// the granter's own copy included, and each opens under that epoch's key
    /// — naming each member with the key Avery holds for them and the log that
    /// proves it: Avery's own, and each card's.
    #[tokio::test]
    async fn a_rotation_seals_its_roster_into_every_grant_it_writes() {
        let ((avery, avery_log), (sam, sam_log), (jordan, jordan_log)) = (identity(1), identity(2), identity(3));
        let node = Node::new(&avery, 1, &[(&sam, 2), (&jordan, 3)]);
        *node.logs.lock().unwrap() = vec![avery_log.clone(), sam_log.clone(), jordan_log.clone()];
        let members = vec![avery.clone(), sam.clone(), jordan.clone()];
        let written = rotate_channel_key(&node, "u", CHANNEL, 4, &members, None).await.expect("rotate");
        assert_eq!(written.len(), 3);
        let filed = node.all(NSID_CHANNEL_KEY_GRANT);
        assert_eq!(filed.len(), 3, "avery's store keeps a copy of each grant");
        for g in &filed {
            assert!(g.get("roster").is_some(), "every grant carries the roster: {g}");
        }
        let averys = filed.iter().find(|g| g["to_did"] == json!(avery)).unwrap();
        let key = unwrap_channel_key(averys, &node.key).unwrap();
        let roster = open_roster(averys, &key).unwrap().unwrap();
        let named: Vec<(&str, Option<[u8; 32]>, usize)> =
            roster.iter().map(|m| (m.did.as_str(), m.key, m.kel.len())).collect();
        let public = |seed: u8| Some(SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes());
        assert_eq!(
            named,
            [(avery.as_str(), public(1), 1), (sam.as_str(), public(2), 1), (jordan.as_str(), public(3), 1)],
            "each member is named with the key avery holds for them and the log that yields it"
        );
    }

    /// **Every shape a roster has been sealed in opens**, and a key is believed
    /// only through the log beside it
    /// (`TASK-a-roster-key-is-the-minting-members-word-and-not-the-members-own-log`):
    ///
    /// - DIDs alone, as every roster before 2026-10-09 was sealed — members with
    ///   no key;
    /// - a key and a note with **no log**, as rosters were sealed between keys
    ///   travelling and their logs doing so — **treated as no key**, and so no
    ///   note: the minting member's word alone is not believed;
    /// - a key with the member's own log, which yields it — kept, with the note
    ///   signed under it;
    /// - a key that is not the one the member's own log yields — the minting
    ///   member's own, under the member's DID and log — dropped;
    /// - a key with somebody else's log, which yields that key for another DID
    ///   — dropped.
    ///
    /// Every such member keeps their DID: they are a member for the count.
    #[test]
    fn every_roster_shape_opens_and_a_key_is_believed_only_through_its_members_own_log() {
        let ((avery, avery_log), (sam, sam_log), (pat, pat_log), (jordan, _)) =
            (identity(1), identity(2), identity(4), identity(3));
        let key = channel_key_generate();
        let legacy = {
            let plaintext = serde_json::to_vec(&json!({ "members": [avery.clone(), sam.clone()] })).unwrap();
            let (body, nonce) = channel_encrypt(&plaintext, &key).unwrap();
            let mut g = grant(CHANNEL, &sam, 2, &key, 1, None);
            g["roster"] = json!(B64.encode(body));
            g["roster_nonce"] = json!(B64.encode(nonce));
            g
        };
        let opened = open_roster(&legacy, &key).unwrap().unwrap();
        assert_eq!(opened, vec![RosterMember::bare(&avery), RosterMember::bare(&sam)]);

        let signer = |seed: u8| SigningKey::from_bytes(&[seed; 32]);
        let public = |seed: u8| signer(seed).verifying_key().to_bytes();
        let now = now_secs();
        let relays = [kotton_crypto::reach_note::RelayRef { key: None, addr: "https://relay.sam".into(), admit: None }];
        let note_of = |did: &str, seed: u8| kotton_crypto::reach_note::next(None, did, &relays, &[], &signer(seed), now).unwrap();
        let members = [
            // Sam: a key, a note and Sam's own log.
            RosterMember { did: sam.clone(), key: Some(public(2)), reach: Some(note_of(&sam, 2)), kel: sam_log.clone() },
            // Pat: a key and a note, and no log.
            RosterMember { did: pat.clone(), key: Some(public(4)), reach: Some(note_of(&pat, 4)), kel: Vec::new() },
            // Jordan: Avery's own key, with a note Avery signed, under Jordan's
            // DID — beside Avery's log, which yields Avery's key for Avery.
            RosterMember { did: jordan.clone(), key: Some(public(1)), reach: Some(note_of(&jordan, 1)), kel: avery_log.clone() },
            // Avery: Avery's key under Avery's DID, beside Pat's log.
            RosterMember { did: avery.clone(), key: Some(public(1)), reach: None, kel: pat_log.clone() },
        ];
        let g = super::test_node::grant_naming(CHANNEL, &sam, 2, &key, 2, &members);
        let opened = open_roster(&g, &key).unwrap().unwrap();
        assert_eq!(opened[0], members[0], "a key its member's own log yields travels whole, note and log");
        let keyless = |m: &RosterMember| (m.did.clone(), m.key, m.reach.clone());
        assert_eq!(keyless(&opened[1]), (pat.clone(), None, None), "a key with no log beside it is not believed");
        assert_eq!(keyless(&opened[2]), (jordan.clone(), None, None), "nor a key the member's log does not yield");
        assert_eq!(keyless(&opened[3]), (avery.clone(), None, None), "nor a key beside somebody else's log");
    }
}

/// A file shared with a group: one channel ciphertext, handed to each current
/// member, filed under *Shared with you* on each of their nodes — and nothing
/// for anybody who holds no key for the epoch it was sealed at
/// (`TASK-a-file-shared-with-a-group-is-a-copy-of-each-members-under-shared-with-you`).
#[cfg(test)]
mod tests_channel_share {
    use super::test_node::{grant, Node};
    use super::*;
    use crate::daemon::delivery;
    use crate::share::{Manifest, FRAME_CAP, GROUP_INLINE_MAX, INLINE_MAX, RANGE_LEN, STREAM_MAX};
    use kotton_wire::ipc::PendingDelivery;

    const AVERY: &str = "did:kel:avery";
    const SAM: &str = "did:kel:sam";
    const JORDAN: &str = "did:kel:jordan";
    const PAT: &str = "did:kel:pat";
    const LEE: &str = "did:kel:lee";
    const CHANNEL: &str = "did:key:zHousehold";

    fn seed(did: &str) -> u8 {
        match did {
            AVERY => 1,
            SAM => 2,
            JORDAN => 3,
            PAT => 4,
            LEE => 5,
            _ => unreachable!(),
        }
    }

    /// The household's keys: epoch 3 was Avery, Sam, Jordan and Pat's; epoch
    /// 4, which removing Pat minted, is Avery, Sam and Jordan's; epoch 5,
    /// which admitting Lee without backfill minted, is theirs and Lee's.
    struct Household {
        e3: [u8; 32],
        e4: [u8; 32],
        e5: [u8; 32],
    }

    impl Household {
        fn new() -> Self {
            Self { e3: channel_key_generate(), e4: channel_key_generate(), e5: channel_key_generate() }
        }

        /// `did`'s node as it stands before Lee is admitted, holding the
        /// grants of the epochs they were in, every other member as a contact,
        /// and a card naming each by their first name.
        fn node(&self, did: &str) -> Node {
            let others: Vec<(&str, u8)> =
                [AVERY, SAM, JORDAN, PAT, LEE].into_iter().filter(|d| *d != did).map(|d| (d, seed(d))).collect();
            let node = Node::new(did, seed(did), &others);
            node.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, did, seed(did), &self.e3, 3, Some(&[AVERY, SAM, JORDAN, PAT])));
            if did != PAT {
                node.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, did, seed(did), &self.e4, 4, Some(&[AVERY, SAM, JORDAN])));
            }
            for (other, _) in &others {
                let name = other.rsplit(':').next().unwrap().to_string();
                node.card_names.lock().unwrap().push((other.to_string(), name));
            }
            node
        }

        /// Lee's node: admitted at epoch 5 without backfill, so holding that
        /// epoch's grant and no earlier one.
        fn lee(&self) -> Node {
            let node = Node::new(LEE, seed(LEE), &[(SAM, seed(SAM))]);
            node.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, LEE, seed(LEE), &self.e5, 5, Some(&[AVERY, SAM, JORDAN, LEE])));
            node.card_names.lock().unwrap().push((SAM.to_string(), "sam".to_string()));
            node
        }
    }

    /// Bytes that are not text, so a transfer that re-encoded them fails.
    fn a_photo(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect()
    }

    async fn sam_shares(sam: &Node, bytes: &[u8]) -> UserResponse {
        message_channel_share(
            sam,
            "u".into(),
            CHANNEL.into(),
            "beach.jpg".into(),
            bytes.to_vec(),
            Some("/Photos/beach.jpg".into()),
        )
        .await
        .unwrap()
    }

    /// What `sealed`, handed to `to`, says once opened with their key.
    fn opened(sealed: &SealedDm, to: &str) -> DmInner {
        envelope::open_filed(sealed, &SigningKey::from_bytes(&[seed(to); 32])).unwrap()
    }

    /// `copy`, in an envelope from Sam to `to` — what a fan-out that reached
    /// them would have handed them.
    fn resealed_to(copy: &ChannelCopy, to: &str) -> SealedDm {
        let inner = DmInner {
            from_did: SAM.into(),
            to_did: to.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: crate::share::MESSAGE_TYPE.into(),
            text: String::new(),
            channel: Some(copy.clone()),
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let to_pub = SigningKey::from_bytes(&[seed(to); 32]).verifying_key().to_bytes();
        envelope::seal(&inner, &SigningKey::from_bytes(&[seed(SAM); 32]), &to_pub).unwrap()
    }

    async fn at_the_door(node: &Node, sealed: SealedDm) -> ContactResponse {
        let sam_pub = SigningKey::from_bytes(&[seed(SAM); 32]).verifying_key().to_bytes();
        delivery::accept(node, "u", SAM, &sam_pub, ContactRequest::DeliverMessage { sealed }).await
    }

    fn channel_body(record: &serde_json::Value, key: &[u8; 32]) -> Manifest {
        let body = B64.decode(record["body"].as_str().unwrap()).unwrap();
        let nonce: [u8; 12] = B64.decode(record["nonce"].as_str().unwrap()).unwrap().try_into().unwrap();
        Manifest::of_channel_body(&channel_decrypt(&body, &nonce, key).unwrap()).unwrap()
    }

    /// **Clauses (1) and (2).** Sam — who wrote none of the grants — shares a
    /// photo with the group. It is sealed under epoch 4, the newest Sam holds,
    /// and handed once to Avery and once to Jordan, the current members, and
    /// to nobody else: not to Pat, removed at epoch 4. Both are handed the
    /// **same ciphertext**, each in an envelope of their own, typed `share`;
    /// it opens to the manifest less `origin`, and Sam's own copy, under the
    /// same key, keeps it. Each member's node files it under
    /// *Shared with you/sam/beach.jpg*, byte-identical, and keeps the message in
    /// the channel, where it opens to the file's name.
    #[tokio::test]
    async fn a_share_to_a_group_is_one_ciphertext_handed_to_each_current_member_and_filed_under_shared_with_you() {
        let household = Household::new();
        let (sam, avery, jordan) = (household.node(SAM), household.node(AVERY), household.node(JORDAN));
        let photo = a_photo(180_000);

        let UserResponse::ChannelSent { fanout, .. } = sam_shares(&sam, &photo).await else { panic!("not sent") };
        let mut to: Vec<&str> = fanout.iter().map(|m| m.member_did.as_str()).collect();
        to.sort();
        assert_eq!(to, [AVERY, JORDAN], "every current member, once, and not Pat");
        let handed = sam.handed.lock().unwrap().clone();
        let mut handed_to: Vec<&str> = handed.iter().map(|(d, _)| d.as_str()).collect();
        handed_to.sort();
        assert_eq!(handed_to, [AVERY, JORDAN], "one hand-off per current member");

        let copies: Vec<DmInner> = handed.iter().map(|(d, sealed)| opened(sealed, d)).collect();
        for inner in &copies {
            assert_eq!(inner.kind, "share");
            assert!(inner.share.is_none() && inner.text.is_empty(), "the manifest rides under the channel key only");
            assert_eq!(inner.channel.as_ref().unwrap().epoch, 4, "sealed under the newest epoch Sam holds");
        }
        assert_eq!(copies[0].channel, copies[1].channel, "each member is handed the same bytes");
        assert_ne!(handed[0].1, handed[1].1, "in an envelope of their own");
        let theirs = copies[0].channel.as_ref().unwrap();
        let manifest = channel_body(&json!({"body": B64.encode(&theirs.body), "nonce": theirs.nonce}), &household.e4);
        assert_eq!((manifest.name.as_str(), manifest.origin.as_deref()), ("beach.jpg", None));
        assert!(!serde_json::to_string(theirs).unwrap().contains("Photos"));

        // Sam's own copy is filed in the channel at the same epoch.
        let own = sam.all(NSID_MESSAGE_V1);
        assert_eq!(own.len(), 1);
        assert_eq!((own[0]["type"].as_str(), own[0]["epoch"].as_u64()), (Some("share"), Some(4)));

        for (node, did) in [(&avery, AVERY), (&jordan, JORDAN)] {
            let sealed = handed.iter().find(|(d, _)| d == did).unwrap().1.clone();
            let answer = at_the_door(node, sealed).await;
            assert!(matches!(answer, ContactResponse::Delivered { stored: true, ack: Some(_) }), "{did}: {answer:?}");
            let tree = node.tree.lock().unwrap().clone();
            assert_eq!(tree, vec![("Shared with you/sam/beach.jpg".to_string(), photo.clone())], "{did}");
            let kept = node.all(NSID_MESSAGE_V1);
            assert_eq!(kept.len(), 1, "{did}: the message stays in the channel");
            assert_eq!((kept[0]["channel_did"].as_str(), kept[0]["type"].as_str()), (Some(CHANNEL), Some("share")));
            let read = message_decrypt_channel(
                node,
                "u".into(),
                CHANNEL.into(),
                kept[0]["body"].as_str().unwrap().into(),
                kept[0]["nonce"].as_str().unwrap().into(),
            )
            .await
            .unwrap();
            let UserResponse::Decrypted { plaintext } = read else { panic!("{did}: {read:?}") };
            assert_eq!(plaintext, "beach.jpg", "{did}: opens to its name");
        }
    }

    /// **The sender's own copy of a share to a group carries no `origin`.** It is
    /// sealed under the channel key, which every member holds, so a path in
    /// Sam's tree under it would be one every member could open: opened under
    /// that key, Sam's own record is the manifest without it — the very
    /// ciphertext the members were handed — though Sam's surface passed one.
    #[tokio::test]
    async fn the_senders_own_copy_of_a_share_to_a_group_carries_no_origin_under_the_shared_key() {
        let household = Household::new();
        let sam = household.node(SAM);
        sam_shares(&sam, &a_photo(4_000)).await;
        let own = sam.all(NSID_MESSAGE_V1);
        assert_eq!(own.len(), 1);
        let opened = channel_body(&own[0], &household.e4);
        assert_eq!((opened.name.as_str(), opened.origin.as_deref()), ("beach.jpg", None));
        assert!(!own[0].to_string().contains("Photos"));
        let (to, sealed) = sam.handed.lock().unwrap()[0].clone();
        let theirs = opened_copy(&sealed, &to);
        assert_eq!(
            (own[0]["body"].as_str(), own[0]["nonce"].as_str()),
            (Some(B64.encode(&theirs.body).as_str()), Some(theirs.nonce.as_str())),
            "the one ciphertext the members were handed"
        );
    }

    fn opened_copy(sealed: &SealedDm, to: &str) -> ChannelCopy {
        opened(sealed, to).channel.unwrap()
    }

    /// **Clause (3).** Pat, removed at epoch 4, holds no key for it: handed
    /// the very ciphertext Avery was handed, Pat's node opens nothing, files
    /// nothing, and keeps no message — at the door and from the vault. Lee,
    /// admitted at epoch 5 without backfill, holds no key for epoch 4 either,
    /// and the same copy is declined at Lee's door.
    #[tokio::test]
    async fn a_member_removed_before_a_share_or_admitted_after_it_files_nothing_even_given_its_ciphertext() {
        let household = Household::new();
        let (sam, pat, lee) = (household.node(SAM), household.node(PAT), household.lee());
        sam_shares(&sam, &a_photo(4_000)).await;
        let (to, sealed) = sam.handed.lock().unwrap()[0].clone();
        let copy = opened(&sealed, &to).channel.unwrap();

        let answer = at_the_door(&pat, resealed_to(&copy, PAT)).await;
        let ContactResponse::Refused { reason } = answer else { panic!("pat: {answer:?}") };
        assert!(reason.contains("epoch 4") && reason.contains("no key this identity holds"), "{reason}");
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: resealed_to(&copy, PAT) };
        assert!(delivery::file_from_vault(&pat, "u", &held).await.is_err(), "nothing filed from the vault");
        assert!(pat.tree.lock().unwrap().is_empty(), "pat's tree holds no copy");
        assert!(pat.all(NSID_MESSAGE_V1).is_empty(), "pat keeps no message");

        let answer = at_the_door(&lee, resealed_to(&copy, LEE)).await;
        let ContactResponse::Declined { reason } = answer else { panic!("lee: {answer:?}") };
        assert!(reason.contains("a share from sam was refused") && reason.contains("epoch 4"), "{reason}");
        assert!(lee.tree.lock().unwrap().is_empty(), "lee's tree holds no copy");
        assert!(lee.all(NSID_MESSAGE_V1).is_empty(), "lee keeps no message");
    }

    /// A share to a group carries its bytes inside its manifest, and the frame
    /// each member is handed holds that up to [`GROUP_INLINE_MAX`] — which is
    /// [`INLINE_MAX`], a direct share's, now that a channel copy's ciphertext
    /// rides as its own bytes inside the envelope rather than base64 inside its
    /// JSON (`TASK-a-channel-copy-carries-its-sealed-bytes-base64-twice`). At
    /// the cap each member's request fits the frame, and comes to no more than
    /// a direct share of the same file sealed to the same person, give or take
    /// the envelope's own fields: the channel layer adds its seal and nothing
    /// else, so the bytes are encoded once on the way. Above the cap a share
    /// streams; above `STREAM_MAX` it is refused with a person's sentence,
    /// before anything is sealed, filed or handed to anyone.
    #[tokio::test]
    async fn a_group_share_at_its_cap_fits_each_members_frame_and_one_above_what_a_store_holds_is_refused() {
        assert_eq!(GROUP_INLINE_MAX, INLINE_MAX, "a group carries what a person is carried inline");
        let household = Household::new();
        let sam = household.node(SAM);
        let file = a_photo(GROUP_INLINE_MAX);
        sam_shares(&sam, &file).await;

        // The same file, shared with Avery alone: what a direct share's frame is.
        let to_avery = SigningKey::from_bytes(&[seed(AVERY); 32]).verifying_key().to_bytes();
        let manifest = Manifest::of_file("beach.jpg", &file, None).unwrap().for_recipient();
        let direct = DmInner {
            from_did: SAM.into(),
            to_did: AVERY.into(),
            thread_id: Uuid::new_v4().to_string(),
            sent_at: now_secs(),
            kind: crate::share::MESSAGE_TYPE.into(),
            text: manifest.name.clone(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: Some(manifest),
            range: None,
        };
        let sealed = envelope::seal(&direct, &SigningKey::from_bytes(&[seed(SAM); 32]), &to_avery).unwrap();
        let direct = serde_json::to_vec(&ContactRequest::CarryMessage { sealed }).unwrap().len();
        assert!(direct < FRAME_CAP, "a direct share at INLINE_MAX: {direct} bytes in a {FRAME_CAP} byte frame");

        let handed: Vec<(String, SealedDm)> = sam.handed.lock().unwrap().drain(..).collect();
        assert_eq!(handed.len(), 2, "Avery and Jordan");
        for (to, sealed) in handed {
            let frame = serde_json::to_vec(&ContactRequest::CarryMessage { sealed }).unwrap().len();
            assert!(frame < FRAME_CAP, "{to}: {frame} bytes in a {FRAME_CAP} byte frame");
            assert!(
                frame <= direct + 1024,
                "{to}: a group's copy is {frame} bytes where a direct share of the same file is {direct} — \
                 the channel ciphertext is encoded more than once on the way"
            );
        }

        // Above it a group share streams (below); above what a store files in
        // one piece it is refused with a person's sentence. Zeroed, so the
        // allocation is never touched: the refusal reads the length.
        let before = sam.all(NSID_MESSAGE_V1).len();
        let huge = vec![0u8; STREAM_MAX + 1];
        let refused = sam_shares(&sam, &huge).await;
        let UserResponse::Error { message } = refused else { panic!("{refused:?}") };
        assert_eq!(message, crate::share::too_large(huge.len() as u64));
        assert_eq!(sam.all(NSID_MESSAGE_V1).len(), before, "nothing filed");
        assert!(sam.handed.lock().unwrap().is_empty(), "nothing handed to anyone");
    }

    /// **Clause (4)'s host verb** answers the channels this person holds a key
    /// for, each with how many hold its current epoch — from their own grants
    /// and nothing else. A grant in their store addressed to someone else (the
    /// granter's copy) lists nothing, and neither does one their key does not
    /// open.
    #[tokio::test]
    async fn the_groups_a_person_holds_a_key_for_are_listed_by_their_own_grants_and_no_others() {
        let household = Household::new();
        let sam = household.node(SAM);
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant("did:key:zTheirs", JORDAN, seed(JORDAN), &channel_key_generate(), 1, Some(&[JORDAN, PAT])));
        sam.keep(NSID_CHANNEL_KEY_GRANT, {
            let mut g = grant("did:key:zNotMine", JORDAN, seed(JORDAN), &channel_key_generate(), 1, Some(&[SAM, JORDAN]));
            g["to_did"] = json!(SAM);
            g
        });
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant("did:key:zPair", SAM, seed(SAM), &channel_key_generate(), 1, Some(&[SAM, AVERY])));
        assert_eq!(
            message_groups(&sam, "u").await.unwrap(),
            vec![
                Group { channel_did: CHANNEL.into(), members: 3 },
                Group { channel_did: "did:key:zPair".into(), members: 2 },
            ]
        );
        // Pat, removed, still holds epoch 3 and reads it: nothing tells them.
        assert_eq!(message_groups(&household.node(PAT), "u").await.unwrap(), vec![Group { channel_did: CHANNEL.into(), members: 4 }]);
    }

    /// What `record`, as this person's store filed it, opens to through the
    /// opener the guest's `messages.open` reaches — handed exactly the fields
    /// the occupant host reads off the record (`sealed_from_record`).
    async fn opens_to(node: &Node, record: &serde_json::Value) -> Result<String, String> {
        let field = |k: &str| record[k].as_str().map(str::to_owned);
        let message = OpenableMessage {
            channel_did: field("channel_did"),
            ephemeral_pub: field("ephemeral_pub"),
            body: field("body").unwrap(),
            nonce: field("nonce").unwrap(),
        };
        match message_open(node, "u".into(), message).await.unwrap() {
            UserResponse::Decrypted { plaintext } => Ok(plaintext),
            UserResponse::Error { message } => Err(message),
            other => panic!("{other:?}"),
        }
    }

    /// **An app opens a channel message that arrived from another member**
    /// (`TASK-an-app-cannot-open-a-channel-message-that-arrived-from-another-member`).
    /// Sam posts to the household and shares a photo with it; each copy is
    /// handed to Avery's door and filed there by the door's own filing, which
    /// keeps the envelope's `ephemeral_pub` beside the channel's ciphertext.
    /// Opened as the guest's `messages.open` opens it, the post reads as its
    /// text and the share as its file's name. Sam's own copies, filed with no
    /// `ephemeral_pub`, open the same way, and a direct message from Sam still
    /// opens as one. Asking `ephemeral_pub` before `channel_did` turns this red
    /// at Avery's copies.
    #[tokio::test]
    async fn a_channel_message_from_another_member_opens_to_its_text_and_a_share_to_its_name() {
        let household = Household::new();
        let (sam, avery) = (household.node(SAM), household.node(AVERY));
        let posted =
            message_channel_send(&sam, "u".into(), CHANNEL.into(), "the ferry leaves at 6:40, not 7".into()).await.unwrap();
        assert!(matches!(posted, UserResponse::ChannelSent { .. }), "{posted:?}");
        sam_shares(&sam, &a_photo(4_000)).await;

        let to_avery: Vec<SealedDm> =
            sam.handed.lock().unwrap().iter().filter(|(d, _)| d == AVERY).map(|(_, s)| s.clone()).collect();
        assert_eq!(to_avery.len(), 2, "the post and the share");
        for sealed in to_avery {
            let answer = at_the_door(&avery, sealed).await;
            assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        }
        let kept = avery.all(NSID_MESSAGE_V1);
        assert_eq!(kept.len(), 2);
        let mut read = Vec::new();
        for record in &kept {
            assert_eq!(record["channel_did"].as_str(), Some(CHANNEL));
            assert!(record["ephemeral_pub"].is_string(), "filed with the envelope's key, as the door files it: {record}");
            read.push(opens_to(&avery, record).await.unwrap_or_else(|e| panic!("avery cannot open it: {e}")));
        }
        read.sort();
        assert_eq!(read, ["beach.jpg", "the ferry leaves at 6:40, not 7"]);

        let mut own = Vec::new();
        for record in &sam.all(NSID_MESSAGE_V1) {
            assert!(record["ephemeral_pub"].is_null(), "{record}");
            own.push(opens_to(&sam, record).await.unwrap());
        }
        own.sort();
        assert_eq!(own, ["beach.jpg", "the ferry leaves at 6:40, not 7"], "the sender's own copies open too");

        let direct = DmInner {
            from_did: SAM.into(),
            to_did: AVERY.into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: "text".into(),
            text: "and bring the cooler".into(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let avery_pub = SigningKey::from_bytes(&[seed(AVERY); 32]).verifying_key().to_bytes();
        let sealed = envelope::seal(&direct, &SigningKey::from_bytes(&[seed(SAM); 32]), &avery_pub).unwrap();
        assert!(matches!(at_the_door(&avery, sealed).await, ContactResponse::Delivered { stored: true, .. }));
        let dm = avery.all(NSID_MESSAGE_V1).into_iter().find(|r| r["channel_did"].is_null()).expect("the direct message");
        assert_eq!(opens_to(&avery, &dm).await.as_deref(), Ok("and bring the cooler"));
    }

    // ── Above the inline cap (`TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`)

    /// Six MiB: above the group's inline cap, so a manifest and two ranges.
    const SIX_MIB: usize = 6 * 1024 * 1024;

    /// What `from` handed `to` through its outbox, as `to` would be handed it:
    /// the manifest first, then each range in order — the manifest being the
    /// entry no other is `part_of`.
    fn outbox_to(from: &Node, to: &str) -> (SealedDm, Vec<SealedDm>) {
        let outbox = from.outbox.lock().unwrap().clone();
        let mine: Vec<&OutboxEntry> = outbox.iter().filter(|e| e.to_did == to).collect();
        let manifest = mine.iter().find(|e| e.part_of.is_none()).expect("a manifest for them");
        let mut ranges: Vec<(u64, SealedDm)> = mine
            .iter()
            .filter(|e| e.part_of.as_deref() == Some(manifest.id.as_str()))
            .map(|e| (opened(&e.sealed, to).range.unwrap().offset, e.sealed.clone()))
            .collect();
        ranges.sort_by_key(|(offset, _)| *offset);
        assert_eq!(mine.len(), ranges.len() + 1, "every other entry of theirs is part of the share");
        (manifest.sealed.clone(), ranges.into_iter().map(|(_, s)| s).collect())
    }

    async fn at_the_door_from(node: &Node, from: &str, sealed: SealedDm) -> ContactResponse {
        let from_pub = SigningKey::from_bytes(&[seed(from); 32]).verifying_key().to_bytes();
        delivery::accept(node, "u", from, &from_pub, ContactRequest::DeliverMessage { sealed }).await
    }

    /// **A group share above the inline cap streams, each range sealed once
    /// under the channel's key.** Sam shares six MiB with the household. Its
    /// manifest carries `stream`, sealed under epoch 4 as an inline share's
    /// is. Its two ranges follow it to Avery and to Jordan, each **the same
    /// channel ciphertext for both**, sealed under epoch 4's key and opening
    /// there to exactly its place's bytes — carried as each member's envelope's
    /// channel copy, with the range's place beside it and **no bytes beside
    /// it**, each naming the share by the manifest's channel nonce. Each
    /// member's manifest and ranges wait in Sam's outbox, every range
    /// `part_of` that member's manifest. Handed to each member's door in that
    /// order, the manifest waits, the ranges are kept and signed for, and the
    /// last one files the photo whole under *Shared with you/sam* — one message
    /// in the channel, nothing left on the shelf; the manifest handed again is
    /// signed for.
    ///
    /// Red when the ranges are sealed to each pair instead of under the
    /// channel's key: they carry no channel copy, and each member's are
    /// different bytes.
    #[tokio::test]
    async fn a_group_share_above_the_inline_cap_streams_each_range_once_under_the_channel_key_and_each_member_files_it_whole() {
        let household = Household::new();
        let (sam, avery, jordan) = (household.node(SAM), household.node(AVERY), household.node(JORDAN));
        let photo = a_photo(SIX_MIB);

        let UserResponse::ChannelSent { fanout, .. } = sam_shares(&sam, &photo).await else { panic!("not sent") };
        let mut to: Vec<&str> = fanout.iter().map(|m| m.member_did.as_str()).collect();
        to.sort();
        assert_eq!(to, [AVERY, JORDAN], "every current member, once, and not Pat");
        assert_eq!(sam.outbox.lock().unwrap().len(), 2 * 3, "a manifest and two ranges for each member");

        let mut each: Vec<Vec<ChannelCopy>> = Vec::new();
        for member in [AVERY, JORDAN] {
            let (manifest, ranges) = outbox_to(&sam, member);
            let held = opened(&manifest, member).channel.unwrap();
            assert_eq!(held.epoch, 4);
            let declared = channel_body(&json!({"body": B64.encode(&held.body), "nonce": held.nonce}), &household.e4);
            assert!(declared.is_streamed() && declared.inline.is_none(), "{member}: the manifest streams");
            assert_eq!(ranges.len(), 2, "{member}");
            let mut copies = Vec::new();
            for sealed in &ranges {
                let inner = opened(sealed, member);
                assert_eq!(inner.kind, "range");
                let range = inner.range.expect("its place");
                let copy = inner.channel.expect("a range of a group's share is a channel copy");
                assert!(range.bytes.is_empty(), "{member}: bytes beside the channel ciphertext");
                assert_eq!(range.share, held.nonce, "{member}: named by what every member's manifest holds");
                assert_eq!((copy.channel_did.as_str(), copy.epoch), (CHANNEL, 4));
                let nonce: [u8; 12] = B64.decode(&copy.nonce).unwrap().try_into().unwrap();
                let plain = channel_decrypt(&copy.body, &nonce, &household.e4).expect("opens under epoch 4's key");
                let at = range.offset as usize;
                assert_eq!(plain, photo[at..(at + RANGE_LEN).min(photo.len())], "{member}: its place's bytes");
                copies.push(copy);
            }
            each.push(copies);
        }
        assert_eq!(each[0], each[1], "one ciphertext per range, the same for every member");
        assert_ne!(outbox_to(&sam, AVERY).1, outbox_to(&sam, JORDAN).1, "each in an envelope of their own");

        for (node, did) in [(&avery, AVERY), (&jordan, JORDAN)] {
            let (manifest, ranges) = outbox_to(&sam, did);
            let waiting = at_the_door(node, manifest.clone()).await;
            assert!(matches!(waiting, ContactResponse::Delivered { stored: false, ack: None }), "{did}: {waiting:?}");
            assert!(node.tree.lock().unwrap().is_empty(), "{did}: filed before its bytes");
            for sealed in ranges {
                let kept = at_the_door(node, sealed).await;
                assert!(matches!(kept, ContactResponse::Delivered { stored: true, ack: Some(_) }), "{did}: {kept:?}");
            }
            assert_eq!(node.tree.lock().unwrap().clone(), vec![("Shared with you/sam/beach.jpg".to_string(), photo.clone())], "{did}");
            let signed = at_the_door(node, manifest).await;
            assert!(matches!(signed, ContactResponse::Delivered { stored: false, ack: Some(_) }), "{did}: {signed:?}");
            let kept = node.all(NSID_MESSAGE_V1);
            assert_eq!(kept.len(), 1, "{did}: one message, and no range filed as one");
            assert_eq!((kept[0]["channel_did"].as_str(), kept[0]["type"].as_str()), (Some(CHANNEL), Some("share")));
            assert!(node.shelf.lock().unwrap().is_empty(), "{did}: the stream was left on the shelf");
        }
    }

    /// **A range of a group's share opens only for a holder of its epoch, and
    /// one from a member removed at the last rotation is refused at the door.**
    ///
    /// Sam's ranges, sealed under epoch 4, handed to Pat — removed at epoch 4,
    /// holding epoch 3 — open to nothing: refused as not yet, at the door and
    /// from the vault, and nothing is kept on Pat's shelf. Handed to Lee —
    /// admitted at epoch 5 without backfill — they are declined, a key Lee was
    /// never granted. And Pat, who still holds epoch 3 and reads Sam, Avery and
    /// Jordan in its roster, shares six MiB with the household: Avery's door
    /// declines the manifest *and each range* by the author check every
    /// channel copy takes — Pat is not in epoch 4's roster — though Avery holds
    /// epoch 3's key and could open them; nothing is kept or filed.
    ///
    /// A range carrying bytes beside its channel ciphertext is declined.
    ///
    /// Red when the range's channel copy skips the author check: Avery opens
    /// Pat's range under epoch 3 and it is refused only as a range whose share
    /// has not arrived, which may clear.
    #[tokio::test]
    async fn a_groups_range_opens_only_for_a_holder_of_its_epoch_and_one_from_a_removed_member_is_refused() {
        let household = Household::new();
        let (sam, pat, lee, avery) = (household.node(SAM), household.node(PAT), household.lee(), household.node(AVERY));
        sam_shares(&sam, &a_photo(SIX_MIB)).await;
        let (manifest, ranges) = outbox_to(&sam, AVERY);
        let copy_to = |sealed: &SealedDm, to: &str| {
            let inner = opened(sealed, AVERY);
            let to_pub = SigningKey::from_bytes(&[seed(to); 32]).verifying_key().to_bytes();
            envelope::seal(&DmInner { to_did: to.into(), ..inner }, &SigningKey::from_bytes(&[seed(SAM); 32]), &to_pub).unwrap()
        };

        for sealed in std::iter::once(&manifest).chain(&ranges) {
            let answer = at_the_door(&pat, copy_to(sealed, PAT)).await;
            let ContactResponse::Refused { reason } = answer else { panic!("pat: {answer:?}") };
            assert!(reason.contains("epoch 4") && reason.contains("no key this identity holds"), "{reason}");
            let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: copy_to(sealed, PAT) };
            let _ = delivery::file_from_vault(&pat, "u", &held).await;
        }
        assert!(pat.shelf.lock().unwrap().is_empty(), "pat kept a range it holds no key for");
        assert!(pat.tree.lock().unwrap().is_empty() && pat.all(NSID_MESSAGE_V1).is_empty());

        for sealed in &ranges {
            let answer = at_the_door(&lee, copy_to(sealed, LEE)).await;
            let ContactResponse::Declined { reason } = answer else { panic!("lee: {answer:?}") };
            assert!(reason.contains("epoch 4") && reason.contains("no key this identity holds"), "{reason}");
        }
        assert!(lee.shelf.lock().unwrap().is_empty());

        // A range of a group's share with bytes beside its ciphertext is
        // declined at a member's door: bytes the channel key did not protect.
        let mut beside = opened(&ranges[0], AVERY);
        beside.range.as_mut().unwrap().bytes = B64.encode(b"not under the channel key");
        let sealed = envelope::seal(&beside, &SigningKey::from_bytes(&[seed(SAM); 32]), &avery.public()).unwrap();
        let answer = at_the_door(&avery, sealed).await;
        let ContactResponse::Declined { reason } = answer else { panic!("bytes beside: {answer:?}") };
        assert!(reason.contains("carried them beside it"), "{reason}");

        // Pat, removed, shares under the epoch Pat still holds.
        let UserResponse::ChannelSent { .. } = sam_shares_as(&pat, &a_photo(SIX_MIB)).await else { panic!("pat's send") };
        let (theirs, their_ranges) = outbox_to(&pat, AVERY);
        assert_eq!(opened(&theirs, AVERY).channel.unwrap().epoch, 3);
        let answer = at_the_door_from(&avery, PAT, theirs).await;
        assert!(matches!(answer, ContactResponse::Declined { .. }), "the manifest: {answer:?}");
        for sealed in their_ranges {
            let answer = at_the_door_from(&avery, PAT, sealed).await;
            let ContactResponse::Declined { reason } = answer else { panic!("a range from pat: {answer:?}") };
            assert!(reason.contains("who is not in channel") && reason.contains("at epoch 4"), "{reason}");
        }
        assert!(avery.shelf.lock().unwrap().is_empty(), "avery kept a removed member's range");
        assert!(avery.tree.lock().unwrap().is_empty() && avery.all(NSID_MESSAGE_V1).is_empty());
    }

    /// **A group's range that waited at a member's vault is taken as at the
    /// door** (`delivery::take_range`, the vault-pickup arm). Every device of
    /// Jordan's slept, so Sam's manifest and both ranges waited at Jordan's
    /// vault; Jordan's pickup takes them in the order they were handed: the
    /// manifest waits for its bytes (taken off the vault, nothing filed), each
    /// range is opened under epoch 4 and kept, and the last files the photo
    /// whole under *Shared with you/sam* — one message in the channel, nothing
    /// left on the shelf. Pat's range, sealed at epoch 3 after Pat's removal,
    /// is declined at Avery's pickup as at Avery's door — taken off the vault
    /// (`Ok(false)`), nothing kept or filed.
    ///
    /// Red when the pickup takes a person's path for a group's range: its bytes
    /// are under the channel key and not in the range, so nothing is kept and
    /// the share is never filed.
    #[tokio::test]
    async fn a_groups_range_that_waited_at_a_members_vault_is_taken_under_the_channel_key_as_at_the_door() {
        let household = Household::new();
        let (sam, jordan, pat, avery) = (household.node(SAM), household.node(JORDAN), household.node(PAT), household.node(AVERY));
        let photo = a_photo(SIX_MIB);
        sam_shares(&sam, &photo).await;
        let held = |sealed: SealedDm| PendingDelivery { handle_did: "did:key:door".into(), sealed };

        let (manifest, ranges) = outbox_to(&sam, JORDAN);
        assert_eq!(delivery::file_from_vault(&jordan, "u", &held(manifest)).await, Ok(false), "waiting for its bytes");
        assert!(jordan.tree.lock().unwrap().is_empty(), "filed before its bytes");
        for sealed in ranges {
            assert_eq!(delivery::file_from_vault(&jordan, "u", &held(sealed)).await, Ok(true), "a range kept from the vault");
        }
        assert_eq!(jordan.tree.lock().unwrap().clone(), vec![("Shared with you/sam/beach.jpg".to_string(), photo.clone())]);
        let kept = jordan.all(NSID_MESSAGE_V1);
        assert_eq!(kept.len(), 1, "one message, and no range filed as one");
        assert_eq!((kept[0]["channel_did"].as_str(), kept[0]["type"].as_str()), (Some(CHANNEL), Some("share")));
        assert!(jordan.shelf.lock().unwrap().is_empty(), "the stream was left on the shelf");

        let UserResponse::ChannelSent { .. } = sam_shares_as(&pat, &a_photo(SIX_MIB)).await else { panic!("pat's send") };
        let (theirs, their_ranges) = outbox_to(&pat, AVERY);
        assert_eq!(delivery::file_from_vault(&avery, "u", &held(theirs)).await, Ok(false), "pat's manifest is refused");
        for sealed in their_ranges {
            assert_eq!(
                delivery::file_from_vault(&avery, "u", &held(sealed)).await,
                Ok(false),
                "a removed member's range is taken off the vault and kept nowhere"
            );
        }
        assert!(avery.shelf.lock().unwrap().is_empty(), "avery kept a removed member's range");
        assert!(avery.tree.lock().unwrap().is_empty() && avery.all(NSID_MESSAGE_V1).is_empty());
    }

    async fn sam_shares_as(node: &Node, bytes: &[u8]) -> UserResponse {
        message_channel_share(node, "u".into(), CHANNEL.into(), "beach.jpg".into(), bytes.to_vec(), None).await.unwrap()
    }

    /// **Each range's channel copy fits the frame, encoded once.** A whole
    /// `RANGE_LEN` range of a group's share, in the envelope each member is
    /// handed, is said at the door as `CarryMessage`: it fits [`FRAME_CAP`],
    /// and comes to its ciphertext base64 once plus the envelope's fields —
    /// less than a person's range of the same bytes, whose plaintext is
    /// base64 inside the JSON before the seal base64s it again.
    #[tokio::test]
    async fn each_range_of_a_group_share_fits_the_frame_its_ciphertext_encoded_once() {
        let household = Household::new();
        let sam = household.node(SAM);
        let photo = a_photo(SIX_MIB);
        sam_shares(&sam, &photo).await;

        // A person's range of the same bytes, sealed to Avery.
        let to_avery = SigningKey::from_bytes(&[seed(AVERY); 32]).verifying_key().to_bytes();
        let range = crate::share::ranges(&crate::share::digest_of(&photo), "the share", &photo).remove(0);
        let part = DmInner {
            from_did: SAM.into(),
            to_did: AVERY.into(),
            thread_id: String::new(),
            sent_at: now_secs(),
            kind: "range".into(),
            text: String::new(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: Some(range),
        };
        let sealed = envelope::seal(&part, &SigningKey::from_bytes(&[seed(SAM); 32]), &to_avery).unwrap();
        let direct = serde_json::to_vec(&ContactRequest::CarryMessage { sealed }).unwrap().len();

        for member in [AVERY, JORDAN] {
            let (_, ranges) = outbox_to(&sam, member);
            let whole = &ranges[0];
            assert_eq!(opened(whole, member).range.unwrap().offset, 0, "a whole RANGE_LEN range");
            let frame = serde_json::to_vec(&ContactRequest::CarryMessage { sealed: whole.clone() }).unwrap().len();
            eprintln!("{member}: a group's range is {frame} bytes on the wire; a person's is {direct}");
            assert!(frame < FRAME_CAP, "{member}: {frame} bytes in a {FRAME_CAP} byte frame");
            assert!(frame <= (RANGE_LEN + 16) * 4 / 3 + 2048, "{member}: {frame} bytes — encoded more than once");
            assert!(frame < direct, "{member}: {frame} bytes against a person's {direct}");
        }
    }

    /// A record naming neither a channel nor an ephemeral key is refused, not
    /// guessed at.
    #[tokio::test]
    async fn a_record_naming_no_channel_and_no_key_is_refused() {
        let avery = Household::new().node(AVERY);
        let record = json!({ "body": "Y2lwaGVy", "nonce": "bm9uY2U=" });
        let refused = opens_to(&avery, &record).await.unwrap_err();
        assert!(refused.contains("nothing that opens it"), "{refused}");
    }
}

#[cfg(test)]
mod tests_leave {
    //! `TASK-a-member-leaves-a-channel-by-saying-so-and-one-remaining-member-rotates`:
    //! the elector rule, each refusal, and what the leaver holds after.
    use super::test_node::{grant, Node};
    use super::*;
    use crate::daemon::delivery;
    use kotton_wire::ipc::PendingDelivery;
    use std::sync::atomic::Ordering;

    // Sorted: avery < jordan < sam. With Sam leaving, Avery is the elector.
    const AVERY: &str = "did:kel:avery";
    const JORDAN: &str = "did:kel:jordan";
    const SAM: &str = "did:kel:sam";
    const PAT: &str = "did:kel:pat";
    const CHANNEL: &str = "did:key:zHousehold";

    fn seed(did: &str) -> u8 {
        match did {
            AVERY => 1,
            SAM => 2,
            JORDAN => 3,
            PAT => 4,
            _ => unreachable!(),
        }
    }

    fn public(did: &str) -> [u8; 32] {
        SigningKey::from_bytes(&[seed(did); 32]).verifying_key().to_bytes()
    }

    /// `did`'s node holding the household at epoch 4 — Avery, Sam and Jordan,
    /// sealed in the grant — and epoch 3 before it, with every other member as
    /// a contact, and Pat, who is in none of it, as well. Its doors take what
    /// they are handed.
    fn node(did: &str, e3: &[u8; 32], e4: &[u8; 32]) -> Node {
        let others: Vec<(&str, u8)> = [AVERY, SAM, JORDAN, PAT].into_iter().filter(|d| *d != did).map(|d| (d, seed(d))).collect();
        let node = Node::new(did, seed(did), &others);
        node.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, did, seed(did), e3, 3, Some(&[AVERY, SAM, JORDAN])));
        node.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, did, seed(did), e4, 4, Some(&[AVERY, SAM, JORDAN])));
        node.takes.store(true, Ordering::SeqCst);
        node
    }

    /// Sam leaves, and answers with what Sam's node handed each member.
    async fn sam_leaves(sam: &Node) -> Vec<(String, SealedDm)> {
        let answer = message_channel_leave(sam, "u".into(), CHANNEL.into()).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelSent { .. }), "{answer:?}");
        sam.handed.lock().unwrap().clone()
    }

    fn to(handed: &[(String, SealedDm)], did: &str) -> SealedDm {
        handed.iter().find(|(d, _)| d == did).unwrap_or_else(|| panic!("nothing handed to {did}")).1.clone()
    }

    async fn at_door(node: &Node, from: &str, sealed: SealedDm) -> ContactResponse {
        delivery::accept(node, "u", from, &public(from), ContactRequest::DeliverMessage { sealed }).await
    }

    /// The epochs of the grants addressed to the node's own DID, sorted.
    fn own_epochs(node: &Node) -> Vec<u64> {
        let mut epochs: Vec<u64> = node
            .all(NSID_CHANNEL_KEY_GRANT)
            .iter()
            .filter(|g| g["to_did"] == node.did.as_str())
            .map(epoch_of)
            .collect();
        epochs.sort();
        epochs
    }

    async fn roster(node: &Node) -> Members {
        current_members(node, "u", CHANNEL, &node.did, &node.key, &mut None).await.expect("a grant it can open")
    }

    fn sealed_under(key: &[u8; 32], text: &str) -> (String, String) {
        let (body, nonce) = channel_encrypt(text.as_bytes(), key).unwrap();
        (B64.encode(body), B64.encode(nonce))
    }

    async fn opens(node: &Node, (body, nonce): &(String, String)) -> Result<String, String> {
        match message_decrypt_channel(node, "u".into(), CHANNEL.into(), body.clone(), nonce.clone()).await.unwrap() {
            UserResponse::Decrypted { plaintext } => Ok(plaintext),
            UserResponse::Error { message } => Err(message),
            other => panic!("{other:?}"),
        }
    }

    /// **The elector rule.** The member whose DID sorts first once the leaver
    /// is taken out, whatever order the roster lists them in; nobody for a
    /// leaver not in the roster, or alone in it.
    #[test]
    fn the_elector_is_the_did_that_sorts_first_without_the_leaver() {
        let roster: Vec<String> = [SAM, JORDAN, AVERY].iter().map(|d| d.to_string()).collect();
        assert_eq!(elector(&roster, SAM), Some(AVERY));
        assert_eq!(elector(&roster, AVERY), Some(JORDAN), "the leaver is never their own elector");
        assert_eq!(elector(&roster, "did:kel:lee"), None, "not in it: the epoch that omits them is here");
        assert_eq!(elector(&[SAM.to_string()], SAM), None, "alone: nobody is left to rotate");
    }

    /// **Clause (1).** Sam's node posts a `leave` notice — a channel message
    /// sealed under epoch 4, the newest Sam holds, filed as Sam's own copy and
    /// handed to Avery and Jordan — and then drops every grant it holds for
    /// the channel. The channel is not among Sam's groups, and what is sealed
    /// under epoch 4 after the notice does not open for Sam even given the
    /// ciphertext. What Sam holds is untouched: their messages, and the file
    /// shared with them under *Shared with you*.
    ///
    /// Red when the leaver keeps a grant.
    #[tokio::test]
    async fn a_leaver_posts_the_notice_and_then_drops_every_key_and_keeps_what_they_hold() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let sam = node(SAM, &e3, &e4);
        // A grant Sam wrote for someone else, as a granter keeps one.
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, JORDAN, seed(JORDAN), &e3, 3, Some(&[AVERY, SAM, JORDAN])));
        let UserResponse::ChannelSent { .. } =
            message_channel_send(&sam, "u".into(), CHANNEL.into(), "before i go".into()).await.unwrap()
        else {
            panic!("sam's post")
        };
        sam.tree.lock().unwrap().push(("Shared with you/avery/beach.jpg".into(), vec![7; 16]));
        assert_eq!(message_groups(&sam, "u").await.unwrap().len(), 1);
        sam.handed.lock().unwrap().clear();

        let handed = sam_leaves(&sam).await;

        let handed_to: Vec<&str> = handed.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(handed_to, [JORDAN, AVERY], "every other current member, the elector last");
        for (did, sealed) in &handed {
            let inner = envelope::open_filed(sealed, &SigningKey::from_bytes(&[seed(did); 32])).unwrap();
            assert_eq!(inner.kind, LEAVE_TYPE, "{did}");
            assert_eq!(inner.from_did, SAM, "{did}: signed by the leaver");
            assert_eq!(inner.channel.as_ref().map(|c| c.epoch), Some(4), "{did}: sealed under the newest epoch");
        }

        assert!(sam.all(NSID_CHANNEL_KEY_GRANT).is_empty(), "sam's node still holds a grant: {:?}", sam.all(NSID_CHANNEL_KEY_GRANT));
        assert!(message_groups(&sam, "u").await.unwrap().is_empty(), "the sheet would still offer the channel");
        let after = sealed_under(&e4, "after sam left");
        let refused = opens(&sam, &after).await.expect_err("sealed after the notice, and it opened for the leaver");
        assert!(refused.contains("no channel key grant"), "{refused}");

        let messages = sam.all(NSID_MESSAGE_V1);
        let types: Vec<Option<&str>> = messages.iter().map(|m| m["type"].as_str()).collect();
        assert_eq!(types, [Some("text"), Some(LEAVE_TYPE)], "sam's messages stay, the notice among them");
        assert_eq!(sam.tree.lock().unwrap().len(), 1, "the file shared with sam stays theirs");
    }

    /// **Clause (2).** Filing Sam's notice, Avery's node — the elector, Avery
    /// sorting first of Avery and Jordan — rotates once, to epoch 5 for Avery
    /// and Jordan with Sam omitted, and hands Jordan the grant. Jordan's node
    /// files the notice and rotates nothing: it waits, and takes Avery's epoch.
    /// Both keep the notice in the channel.
    ///
    /// Red when the elector rule is removed: Jordan's node mints an epoch 5 of
    /// its own, and takes Avery's as a second.
    #[tokio::test]
    async fn the_elector_rotates_on_filing_a_leave_notice_and_every_other_member_waits() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let (sam, avery, jordan) = (node(SAM, &e3, &e4), node(AVERY, &e3, &e4), node(JORDAN, &e3, &e4));
        let handed = sam_leaves(&sam).await;

        let answer = at_door(&jordan, SAM, to(&handed, JORDAN)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&jordan), [3, 4], "jordan is not the elector, and minted an epoch");
        assert!(jordan.handed.lock().unwrap().is_empty(), "jordan handed a grant to somebody");

        let answer = at_door(&avery, SAM, to(&handed, AVERY)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&avery), [3, 4, 5], "avery, the elector, rotates once");
        let now = roster(&avery).await;
        assert_eq!((now.epoch, now.dids.clone()), (5, vec![AVERY.to_string(), JORDAN.to_string()]));
        let grants_out: Vec<String> = avery.handed.lock().unwrap().iter().map(|(d, _)| d.clone()).collect();
        assert_eq!(grants_out, [JORDAN], "the new epoch is handed to jordan, and not to sam");

        let grant_to_jordan = to(&avery.handed.lock().unwrap(), JORDAN);
        let answer = at_door(&jordan, AVERY, grant_to_jordan).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&jordan), [3, 4, 5], "jordan takes the elector's epoch, and only it");
        assert_eq!(roster(&jordan).await.dids, vec![AVERY.to_string(), JORDAN.to_string()]);

        for node in [&avery, &jordan] {
            let notices: Vec<serde_json::Value> =
                node.all(NSID_MESSAGE_V1).into_iter().filter(|m| m["type"] == LEAVE_TYPE).collect();
            assert_eq!(notices.len(), 1, "{}: the notice is kept in the channel", node.did);
            assert_eq!((notices[0]["from_did"].as_str(), notices[0]["channel_did"].as_str()), (Some(SAM), Some(CHANNEL)));
        }
    }

    /// **Clause (3).** A notice that waited at the vault is filed by the same
    /// path as at the door: the elector rotates on its pickup; the same notice
    /// at the door after it is the same notice, and rotates nothing more.
    #[tokio::test]
    async fn a_leave_notice_picked_up_from_the_vault_rotates_as_at_the_door_and_once() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let (sam, avery) = (node(SAM, &e3, &e4), node(AVERY, &e3, &e4));
        let handed = sam_leaves(&sam).await;
        let notice = to(&handed, AVERY);

        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: notice.clone() };
        assert_eq!(delivery::file_from_vault(&avery, "u", &held).await, Ok(true));
        assert_eq!(own_epochs(&avery), [3, 4, 5], "the elector rotates on the pickup");

        // Its author is out of the roster now, so the door declines it before
        // asking whether it is held — either way, nothing is filed twice.
        let answer = at_door(&avery, SAM, notice).await;
        assert!(matches!(answer, ContactResponse::Declined { .. }), "{answer:?}");
        assert_eq!(own_epochs(&avery), [3, 4, 5], "the same notice again rotates nothing");
        let notices = avery.all(NSID_MESSAGE_V1).into_iter().filter(|m| m["type"] == LEAVE_TYPE).count();
        assert_eq!(notices, 1, "the notice is kept once");
        assert_eq!(delivery::file_from_vault(&avery, "u", &held).await, Ok(false));
        assert_eq!(own_epochs(&avery), [3, 4, 5]);
    }

    /// **The refusals.** A notice filed twice rotates nothing the second time.
    /// A notice from a leaver the elector's roster no longer holds — at an
    /// epoch the node has left behind — is not filed and rotates nothing. A
    /// channel whose newest grant here is from before rosters names no
    /// elector, and nobody rotates it. And the leaver, once omitted, cannot
    /// open the epoch that omits them, given its ciphertext or handed a copy.
    #[tokio::test]
    async fn a_second_notice_or_one_from_an_epoch_left_behind_rotates_nothing_and_the_leaver_cannot_open_the_next() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let (sam, avery) = (node(SAM, &e3, &e4), node(AVERY, &e3, &e4));
        let handed = sam_leaves(&sam).await;
        let notice = to(&handed, AVERY);

        assert!(matches!(at_door(&avery, SAM, notice.clone()).await, ContactResponse::Delivered { stored: true, .. }));
        let again = at_door(&avery, SAM, notice).await;
        assert!(!matches!(again, ContactResponse::Delivered { stored: true, .. }), "filed twice: {again:?}");
        assert_eq!(own_epochs(&avery), [3, 4, 5], "handed twice, rotated once");

        // A second notice of Sam's at epoch 4, which Avery's node has left behind.
        let second = DmInner {
            from_did: SAM.into(),
            to_did: AVERY.into(),
            thread_id: "t".into(),
            sent_at: 2,
            kind: LEAVE_TYPE.into(),
            text: String::new(),
            channel: Some({
                let (body, nonce) = channel_encrypt(b"", &e4).unwrap();
                ChannelCopy { channel_did: CHANNEL.into(), epoch: 4, body, nonce: B64.encode(nonce) }
            }),
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let second = envelope::seal(&second, &SigningKey::from_bytes(&[seed(SAM); 32]), &public(AVERY)).unwrap();
        let answer = at_door(&avery, SAM, second).await;
        assert!(matches!(answer, ContactResponse::Declined { .. }), "{answer:?}");
        assert_eq!(own_epochs(&avery), [3, 4, 5], "a notice at an epoch left behind rotated");
        let AfterLeave::Nothing(why) = rotate_for_leave(&avery, "u", CHANNEL, SAM, 5).await else { panic!("rotated again") };
        assert!(why.contains("not in channel"), "{why}");

        // What Avery says at epoch 5 does not open for Sam: no key, given the
        // ciphertext, and nothing filed at Sam's door.
        let UserResponse::ChannelSent { .. } =
            message_channel_send(&avery, "u".into(), CHANNEL.into(), "after sam left".into()).await.unwrap()
        else {
            panic!("avery's post")
        };
        let post = avery.all(NSID_MESSAGE_V1).into_iter().find(|m| m["epoch"] == 5).expect("a post at epoch 5");
        let given = (post["body"].as_str().unwrap().to_string(), post["nonce"].as_str().unwrap().to_string());
        assert!(opens(&sam, &given).await.is_err(), "the leaver opened the epoch that omits them");
        let to_sam = avery.handed.lock().unwrap().iter().filter(|(d, _)| d == SAM).count();
        assert_eq!(to_sam, 0, "the post was handed to the leaver");

        // A channel from before rosters: nobody is the elector.
        let old = Node::new(AVERY, seed(AVERY), &[(SAM, seed(SAM)), (JORDAN, seed(JORDAN))]);
        old.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, seed(AVERY), &e4, 4, None));
        old.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, SAM, seed(SAM), &e4, 4, None));
        let AfterLeave::Nothing(why) = rotate_for_leave(&old, "u", CHANNEL, SAM, 4).await else { panic!("rotated") };
        assert!(why.contains("before rosters"), "{why}");
        assert_eq!(own_epochs(&old), [4]);
    }

    /// **No rotation hands a leaver the next epoch**
    /// (`TASK-a-member-who-rotates-before-the-elector-hands-the-leaver-the-next-epoch`).
    /// Jordan leaves; Avery, sorting first without them, is the elector and is
    /// asleep. Sam, who is not, files the notice and waits — and then admits
    /// Pat. Sam's roster still lists Jordan, since the elector's epoch has not
    /// reached Sam, and the epoch the admission mints omits Jordan all the
    /// same: no grant of it to Jordan, none handed to Jordan's door, and its
    /// roster is Avery, Sam and Pat. Jordan's node, given its ciphertext, opens
    /// nothing. Removing somebody else omits Jordan the same way.
    ///
    /// Red when a rotation does not read the leave notices its node has filed.
    #[tokio::test]
    async fn a_member_who_admits_before_the_elector_rotates_omits_the_leaver_from_the_new_epoch() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let (sam, jordan) = (node(SAM, &e3, &e4), node(JORDAN, &e3, &e4));
        let answer = message_channel_leave(&jordan, "u".into(), CHANNEL.into()).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelSent { .. }), "{answer:?}");
        let notice = to(&jordan.handed.lock().unwrap(), SAM);

        let answer = at_door(&sam, JORDAN, notice).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&sam), [3, 4], "sam is not the elector, and rotated on the notice");
        assert_eq!(roster(&sam).await.dids, vec![AVERY.to_string(), SAM.to_string(), JORDAN.to_string()]);

        let admitted = message_channel_grant_key(&sam, "u".into(), CHANNEL.into(), PAT.into(), false).await.unwrap();
        assert!(matches!(admitted, UserResponse::ChannelKeyGrantCreated { .. }), "{admitted:?}");
        let now = roster(&sam).await;
        assert_eq!(now.epoch, 5);
        assert_eq!(now.dids, vec![AVERY.to_string(), SAM.to_string(), PAT.to_string()], "the new epoch's roster holds the leaver");
        let mut granted: Vec<String> = sam
            .all(NSID_CHANNEL_KEY_GRANT)
            .iter()
            .filter(|g| epoch_of(g) == 5)
            .map(|g| g["to_did"].as_str().unwrap().to_string())
            .collect();
        granted.sort();
        assert_eq!(granted, [AVERY, PAT, SAM], "epoch 5 was granted to the leaver");
        assert!(
            !sam.handed.lock().unwrap().iter().any(|(d, _)| d == JORDAN),
            "a grant of the new epoch was handed to the leaver's door"
        );
        let (body, nonce) = channel_encrypt(b"after pat joined", &{
            let grant = sam.all(NSID_CHANNEL_KEY_GRANT).into_iter().find(|g| epoch_of(g) == 5 && g["to_did"] == SAM).unwrap();
            unwrap_channel_key(&grant, &sam.key).unwrap()
        })
        .unwrap();
        assert!(opens(&jordan, &(B64.encode(body), B64.encode(nonce))).await.is_err(), "the leaver opened the new epoch");

        // Removing somebody else omits the leaver as well: epoch 6 is Sam's
        // and Avery's.
        message_channel_remove_member(&sam, "u".into(), CHANNEL.into(), PAT.into()).await.unwrap();
        let now = roster(&sam).await;
        assert_eq!((now.epoch, now.dids), (6, vec![AVERY.to_string(), SAM.to_string()]));
    }

    /// **Leaving is unconditional.** With no path to anybody — nothing of
    /// Avery's or Jordan's takes anything — Sam still leaves: Sam's node drops
    /// every key, the channel leaves Sam's groups, Sam's own copy of the notice
    /// stays, and each member's copy waits in Sam's outbox. Later the elector's
    /// vault hands Avery's copy over and Avery's node, filing it at the pickup,
    /// rotates to epoch 5 without Sam; Sam's next pass hands Jordan theirs.
    #[tokio::test]
    async fn a_leave_with_no_path_to_anyone_drops_the_keys_and_the_notice_reaches_the_elector_later() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let (sam, avery, jordan) = (node(SAM, &e3, &e4), node(AVERY, &e3, &e4), node(JORDAN, &e3, &e4));
        sam.takes.store(false, Ordering::SeqCst);

        let answer = message_channel_leave(&sam, "u".into(), CHANNEL.into()).await.unwrap();
        let UserResponse::ChannelSent { fanout, .. } = answer else { panic!("{answer:?}") };
        assert!(fanout.iter().all(|m| matches!(m.delivery, Delivery::Unreachable { .. })), "{fanout:?}");
        assert!(sam.all(NSID_CHANNEL_KEY_GRANT).is_empty(), "sam kept a key while the notice waits");
        assert!(message_groups(&sam, "u").await.unwrap().is_empty());
        let own: Vec<serde_json::Value> = sam.all(NSID_MESSAGE_V1);
        assert_eq!(own.len(), 1, "sam's own copy of the notice stays");
        assert_eq!(own[0]["type"], LEAVE_TYPE);
        let waiting = sam.outbox.lock().unwrap().clone();
        let mut to: Vec<&str> = waiting.iter().map(|e| e.to_did.as_str()).collect();
        to.sort();
        assert_eq!(to, [AVERY, JORDAN], "each member's copy waits in the outbox");

        // The elector's vault hands it over later.
        let averys = waiting.iter().find(|e| e.to_did == AVERY).unwrap().sealed.clone();
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: averys };
        assert_eq!(delivery::file_from_vault(&avery, "u", &held).await, Ok(true));
        assert_eq!(own_epochs(&avery), [3, 4, 5], "the elector rotates on the later arrival");
        assert_eq!(roster(&avery).await.dids, vec![AVERY.to_string(), JORDAN.to_string()]);

        // Sam's next pass, with a door that answers now, hands Jordan theirs.
        sam.takes.store(true, Ordering::SeqCst);
        sam.handed.lock().unwrap().clear();
        assert_eq!(outbox::retry_due(&sam, "u", u64::MAX, outbox::Retry::DEFAULT).await, 2);
        let answer = at_door(&jordan, SAM, to_member(&sam, JORDAN)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&jordan), [3, 4], "jordan is not the elector");
    }

    fn to_member(node: &Node, did: &str) -> SealedDm {
        to(&node.handed.lock().unwrap(), did)
    }

    /// **A notice from before its author was admitted again rotates nothing.**
    /// Sam sealed a notice at epoch 4; Avery's node has since rotated Sam out
    /// (epoch 5, Avery and Jordan) and admitted Sam again (epoch 6). Filed at
    /// epoch 6 — Sam is in its roster — the old notice mints nothing: epoch 5
    /// lacks Sam, so it is an earlier membership's leave. And a notice sealed
    /// at an epoch newer than any Avery holds is not filed yet: refused for
    /// now, it waits for that epoch.
    ///
    /// Red when the continuity check is removed.
    #[tokio::test]
    async fn a_notice_from_before_a_readmission_rotates_nothing_and_a_newer_one_waits() {
        let (e3, e4, e5, e6) = (channel_key_generate(), channel_key_generate(), channel_key_generate(), channel_key_generate());
        let (sam, avery) = (node(SAM, &e3, &e4), node(AVERY, &e3, &e4));
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, seed(AVERY), &e5, 5, Some(&[AVERY, JORDAN])));
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, seed(AVERY), &e6, 6, Some(&[AVERY, SAM, JORDAN])));
        let notice = to(&sam_leaves(&sam).await, AVERY);

        let answer = at_door(&avery, SAM, notice).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&avery), [3, 4, 5, 6], "a notice from before sam's re-admission rotated");
        let AfterLeave::Nothing(why) = rotate_for_leave(&avery, "u", CHANNEL, SAM, 4).await else { panic!("rotated") };
        assert!(why.contains("admitted again"), "{why}");
        // Nor does any other rotation read it as a leave: Avery admitting Pat
        // keeps Sam, admitted again, in the epoch it mints.
        message_channel_grant_key(&avery, "u".into(), CHANNEL.into(), PAT.into(), false).await.unwrap();
        let now = roster(&avery).await;
        assert_eq!(now.epoch, 7);
        assert!(now.dids.iter().any(|d| d == SAM), "an old notice took sam out of an admission: {:?}", now.dids);

        // Newer than Avery's: Jordan's node holds epoch 5, Avery's only 4.
        let (avery_behind, jordan_ahead) = (node(AVERY, &e3, &e4), node(JORDAN, &e3, &e4));
        jordan_ahead.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, JORDAN, seed(JORDAN), &e5, 5, Some(&[AVERY, SAM, JORDAN])));
        message_channel_leave(&jordan_ahead, "u".into(), CHANNEL.into()).await.unwrap();
        let answer = at_door(&avery_behind, JORDAN, to_member(&jordan_ahead, AVERY)).await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "{answer:?}");
        assert!(avery_behind.all(NSID_MESSAGE_V1).is_empty(), "a notice from an epoch not yet held was filed");
    }

    /// **A leave sealed before the leaver's node held the newest epoch does
    /// not lapse**
    /// (`TASK-a-leave-sealed-before-the-leavers-node-held-the-newest-epoch-lapses`).
    /// Avery admits Pat: epoch 5, Sam among its members, and Sam's grant of it
    /// still on its way. Sam leaves at epoch 4, the newest Sam's node holds.
    /// Avery, the elector, files the notice at epoch 5 — Sam has been in every
    /// roster since 4 — and rotates to 6 without Sam. Then the epoch-5 grant
    /// lands at Sam's door: it is declined, since it only names Sam among the
    /// members, and Sam's node holds no key and lists no group. Avery admitting
    /// Sam by name later is an invitation back, and Sam's node takes it.
    ///
    /// Red when the continuity check is replaced by the epoch rule it
    /// replaced, and when the leaver's node takes any grant.
    #[tokio::test]
    async fn a_leave_sealed_before_the_newest_epoch_reached_the_leaver_rotates_and_the_grant_in_flight_is_refused() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let (sam, avery) = (node(SAM, &e3, &e4), node(AVERY, &e3, &e4));
        let admitted = message_channel_grant_key(&avery, "u".into(), CHANNEL.into(), PAT.into(), false).await.unwrap();
        assert!(matches!(admitted, UserResponse::ChannelKeyGrantCreated { .. }), "{admitted:?}");
        let in_flight = to_member(&avery, SAM);
        avery.handed.lock().unwrap().clear();

        let notice = to(&sam_leaves(&sam).await, AVERY);
        let answer = at_door(&avery, SAM, notice).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&avery), [3, 4, 5, 6], "the elector did not rotate on a leave sealed at epoch 4");
        let now = roster(&avery).await;
        assert_eq!((now.epoch, now.dids), (6, vec![AVERY.to_string(), JORDAN.to_string(), PAT.to_string()]));

        let answer = at_door(&sam, AVERY, in_flight).await;
        assert!(matches!(answer, ContactResponse::Declined { .. }), "the grant in flight put sam back: {answer:?}");
        assert!(sam.all(NSID_CHANNEL_KEY_GRANT).is_empty(), "sam's node holds a key again");
        assert!(message_groups(&sam, "u").await.unwrap().is_empty(), "sam's sheet offers the channel again");

        // Invited back, by name: taken.
        avery.handed.lock().unwrap().clear();
        message_channel_grant_key(&avery, "u".into(), CHANNEL.into(), SAM.into(), false).await.unwrap();
        let answer = at_door(&sam, AVERY, to_member(&avery, SAM)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "an invitation back was refused: {answer:?}");
        assert_eq!(own_epochs(&sam), [7]);
        assert_eq!(message_groups(&sam, "u").await.unwrap().len(), 1);
    }

    /// **An epoch the node holds no roster for is skipped, never refused** (the
    /// assessor's probe of 2026-10-09). Avery, the elector, holds epochs 4 and 6
    /// and nothing for 5. Filing Sam's epoch-4 notice, Avery's node rotates —
    /// Sam is in every roster it holds since — to epoch 7 without Sam; then it
    /// admits Pat and removes Pat. Jordan, holding the same gap, removes Sam by
    /// name: a removal names its DID and never asks continuity.
    ///
    /// Red when an epoch not held refuses: the leave, the admission and the
    /// removal all stall, and nothing runs them again when epoch 5 arrives.
    #[tokio::test]
    async fn an_elector_with_a_roster_gap_rotates_on_a_leave_and_can_admit_and_remove() {
        let (e3, e4, e6) = (channel_key_generate(), channel_key_generate(), channel_key_generate());
        let (sam, avery, jordan) = (node(SAM, &e3, &e4), node(AVERY, &e3, &e4), node(JORDAN, &e3, &e4));
        for (n, did) in [(&avery, AVERY), (&jordan, JORDAN)] {
            n.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, did, seed(did), &e6, 6, Some(&[AVERY, SAM, JORDAN])));
        }
        let handed = sam_leaves(&sam).await;

        let answer = at_door(&avery, SAM, to(&handed, AVERY)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        let now = roster(&avery).await;
        assert_eq!((now.epoch, now.dids), (7, vec![AVERY.to_string(), JORDAN.to_string()]), "the gap stalled the leave");
        let admitted = message_channel_grant_key(&avery, "u".into(), CHANNEL.into(), PAT.into(), false).await.unwrap();
        assert!(matches!(admitted, UserResponse::ChannelKeyGrantCreated { .. }), "{admitted:?}");
        let removed = message_channel_remove_member(&avery, "u".into(), CHANNEL.into(), PAT.into()).await.unwrap();
        assert!(matches!(removed, UserResponse::Ok), "{removed:?}");
        assert_eq!(roster(&avery).await.epoch, 9);

        let answer = at_door(&jordan, SAM, to(&handed, JORDAN)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        let removed = message_channel_remove_member(&jordan, "u".into(), CHANNEL.into(), SAM.into()).await.unwrap();
        assert!(matches!(removed, UserResponse::Ok), "{removed:?}");
        assert_eq!(roster(&jordan).await.dids, vec![AVERY.to_string(), JORDAN.to_string()]);
    }

    /// **The grant that first admitted a person, handed to them again after
    /// they left, is not an invitation back** (the lapse record's Done-when
    /// (4), its `epoch > left_at` half). Sam joins at epoch 5, admitted by name,
    /// and leaves at 5. The same grant, redelivered, is declined: it does admit
    /// Sam by name, but at the epoch Sam left at, not above it. Taken, it would
    /// make Sam a member again, and every grant after it would pass.
    #[tokio::test]
    async fn the_grant_that_admitted_a_leaver_redelivered_after_they_left_is_declined() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let avery = Node::new(AVERY, seed(AVERY), &[(SAM, seed(SAM)), (JORDAN, seed(JORDAN)), (PAT, seed(PAT))]);
        avery.takes.store(true, Ordering::SeqCst);
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, seed(AVERY), &e3, 3, Some(&[AVERY, JORDAN])));
        avery.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, AVERY, seed(AVERY), &e4, 4, Some(&[AVERY, JORDAN])));
        let sam = Node::new(SAM, seed(SAM), &[(AVERY, seed(AVERY)), (JORDAN, seed(JORDAN)), (PAT, seed(PAT))]);
        sam.takes.store(true, Ordering::SeqCst);

        message_channel_grant_key(&avery, "u".into(), CHANNEL.into(), SAM.into(), false).await.unwrap();
        let admission = to_member(&avery, SAM);
        let answer = at_door(&sam, AVERY, admission.clone()).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&sam), [5]);

        let answer = message_channel_leave(&sam, "u".into(), CHANNEL.into()).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelSent { .. }), "{answer:?}");
        assert!(sam.all(NSID_CHANNEL_KEY_GRANT).is_empty());

        let answer = at_door(&sam, AVERY, admission).await;
        assert!(matches!(answer, ContactResponse::Declined { .. }), "the grant that first admitted sam put sam back: {answer:?}");
        assert!(sam.all(NSID_CHANNEL_KEY_GRANT).is_empty() && message_groups(&sam, "u").await.unwrap().is_empty());
    }

    /// **An outbox that fails part-way keeps nothing of the leave.** Sam's
    /// outbox keeps Jordan's copy — the first in order, the elector Avery being
    /// last — and then refuses Avery's. The copy it kept is taken out again,
    /// nothing is handed to anybody, and Sam keeps every key.
    ///
    /// Red when the take-back is removed: Jordan's entry is left in the outbox,
    /// and the next pass would hand Jordan a notice of a leave that did not
    /// happen.
    #[tokio::test]
    async fn a_leave_whose_outbox_fails_part_way_takes_back_what_it_kept_and_hands_nothing() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let sam = node(SAM, &e3, &e4);
        *sam.outbox_keeps_left.lock().unwrap() = Some(1);

        let answer = message_channel_leave(&sam, "u".into(), CHANNEL.into()).await.unwrap();
        let UserResponse::Error { message } = answer else { panic!("left on a half-kept notice: {answer:?}") };
        assert!(message.contains("you have not left"), "{message}");
        assert!(sam.outbox.lock().unwrap().is_empty(), "a kept copy was left in the outbox: {:?}", sam.outbox.lock().unwrap());
        assert!(sam.handed.lock().unwrap().is_empty(), "a copy was handed to somebody");
        assert_eq!(own_epochs(&sam), [3, 4], "a key was dropped");
        assert!(sam.all(NSID_MESSAGE_V1).is_empty());
    }

    /// **A leave whose notice the outbox cannot keep does not happen**
    /// (the assessor's ground 4 of 2026-10-09). Sam's outbox refuses to keep
    /// anything: nothing is handed to anybody, Sam's node keeps every key and
    /// still lists the group, Sam's own copy of the notice is taken out again,
    /// and Sam is told so in Sam's own words — no member's door answered.
    #[tokio::test]
    async fn a_leave_whose_notice_the_outbox_cannot_keep_leaves_the_person_in_holding_every_key() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let sam = node(SAM, &e3, &e4);
        sam.fails_outbox_keep.store(true, Ordering::SeqCst);

        let answer = message_channel_leave(&sam, "u".into(), CHANNEL.into()).await.unwrap();
        let UserResponse::Error { message } = answer else { panic!("left without a kept notice: {answer:?}") };
        assert!(message.contains("you have not left") && message.contains("outbox"), "{message}");
        assert_eq!(own_epochs(&sam), [3, 4], "a key was dropped");
        assert_eq!(message_groups(&sam, "u").await.unwrap().len(), 1);
        assert!(sam.handed.lock().unwrap().is_empty(), "a copy was handed to somebody");
        assert!(sam.all(NSID_MESSAGE_V1).is_empty(), "sam's conversation says sam left");
        assert!(sam.outbox.lock().unwrap().is_empty());
    }

    /// **A store whose leave notices cannot be read refuses the rotation**
    /// (`TASK-a-member-who-rotates-before-the-elector-hands-the-leaver-the-next-epoch`):
    /// read as nobody having left, it would hand a leaver the next epoch.
    #[tokio::test]
    async fn a_rotation_whose_node_cannot_read_its_leave_notices_is_refused() {
        let (e3, e4) = (channel_key_generate(), channel_key_generate());
        let sam = node(SAM, &e3, &e4);
        sam.fails_message_reads.store(true, Ordering::SeqCst);
        let answer = message_channel_grant_key(&sam, "u".into(), CHANNEL.into(), PAT.into(), false).await.unwrap();
        let UserResponse::Error { message } = answer else { panic!("admitted blind: {answer:?}") };
        assert!(message.contains("could not read who has left"), "{message}");
        assert_eq!(own_epochs(&sam), [3, 4], "an epoch was minted");
    }
}

/// `TASK-a-channel-member-who-is-not-the-senders-contact-never-receives-the-senders-copies`:
/// Sam and Pat are both members of Avery's household channel, and each is a
/// contact of Avery's and of nobody else's. The roster Avery seals carries
/// each member's key, reach note and key log, so Pat's post and Pat's leave
/// reach Sam, and Sam holds them to the key the roster carries for Pat — for that
/// channel's copies, and nothing else.
#[cfg(test)]
mod tests_co_member {
    use super::test_node::{identity, Node};
    use super::*;
    use crate::daemon::delivery;
    use kotton_crypto::reach_note::RelayRef;
    use kotton_wire::ipc::PendingDelivery;
    use std::sync::LazyLock;

    /// Avery, Sam, Pat and Lee, as `did:kel` identities: each one's AID — the
    /// digest of their inception — and their log. Seeds 1, 2, 4 and 5.
    static PEOPLE: LazyLock<Vec<(u8, String, Vec<kotton_wire::kel::KelEvent>)>> = LazyLock::new(|| {
        [1u8, 2, 4, 5]
            .into_iter()
            .map(|seed| {
                let (aid, log) = identity(seed);
                (seed, aid, log)
            })
            .collect()
    });
    #[allow(non_snake_case)]
    fn AVERY() -> &'static str {
        &PEOPLE[0].1
    }
    #[allow(non_snake_case)]
    fn SAM() -> &'static str {
        &PEOPLE[1].1
    }
    #[allow(non_snake_case)]
    fn PAT() -> &'static str {
        &PEOPLE[2].1
    }
    #[allow(non_snake_case)]
    fn LEE() -> &'static str {
        &PEOPLE[3].1
    }
    const CHANNEL: &str = "did:key:zHousehold";
    const OTHER: &str = "did:key:zAveryAndSam";

    fn seed(did: &str) -> u8 {
        PEOPLE.iter().find(|(_, aid, _)| aid == did).map(|(s, _, _)| *s).expect("one of the four")
    }

    /// `did`'s own key log.
    fn log(did: &str) -> Vec<kotton_wire::kel::KelEvent> {
        PEOPLE.iter().find(|(_, aid, _)| aid == did).map(|(_, _, l)| l.clone()).expect("one of the four")
    }

    fn name(did: &str) -> &'static str {
        ["avery", "sam", "pat", "lee"][PEOPLE.iter().position(|(_, aid, _)| aid == did).expect("one of the four")]
    }

    fn key(did: &str) -> SigningKey {
        SigningKey::from_bytes(&[seed(did); 32])
    }

    fn public(did: &str) -> [u8; 32] {
        key(did).verifying_key().to_bytes()
    }

    /// `did`'s reach note: their relay, and their identity key as the one
    /// device that signs for what reaches them — as the test node signs.
    ///
    /// Signed **once** per person, the first time any test asks, and the same
    /// note every time after: a note carries its signing time, so one minted
    /// afresh for a comparison differs from the stored one across a second.
    fn note(did: &str) -> ReachNote {
        static NOTES: LazyLock<Vec<ReachNote>> = LazyLock::new(|| {
            let now = now_secs();
            PEOPLE
                .iter()
                .map(|(_, did, _)| {
                    let relay = RelayRef { key: None, addr: format!("https://relay.{}", name(did)), admit: None };
                    let device = hex::encode(public(did));
                    kotton_crypto::reach_note::next(None, did, &[relay], &[device], &key(did), now).unwrap()
                })
                .collect()
        });
        NOTES.iter().find(|n| n.did == did).cloned().expect("one of the four")
    }

    /// `did`'s node, a contact of each of `contacts` and holding each one's
    /// note on their card, and their own.
    fn node(did: &str, contacts: &[&str]) -> Node {
        let cards: Vec<(&str, u8)> = contacts.iter().map(|c| (*c, seed(c))).collect();
        let node = Node::new(did, seed(did), &cards);
        let mut notes = vec![note(did)];
        notes.extend(contacts.iter().map(|c| note(c)));
        *node.notes.lock().unwrap() = notes;
        let mut logs = vec![log(did)];
        logs.extend(contacts.iter().map(|c| log(c)));
        *node.logs.lock().unwrap() = logs;
        node
    }

    /// The last envelope `from` handed `to`, taken off what it handed.
    fn take_handed(from: &Node, to: &str) -> SealedDm {
        let mut handed = from.handed.lock().unwrap();
        let i = handed.iter().rposition(|(d, _)| d == to).unwrap_or_else(|| panic!("nothing handed to {to}"));
        handed.remove(i).1
    }

    async fn at_door(node: &Node, from: &str, from_key: &[u8; 32], sealed: SealedDm) -> ContactResponse {
        delivery::accept(node, "u", from, from_key, ContactRequest::DeliverMessage { sealed }).await
    }

    fn own_epochs(node: &Node) -> Vec<u64> {
        let mut epochs: Vec<u64> =
            node.all(NSID_CHANNEL_KEY_GRANT).iter().filter(|g| g["to_did"] == node.did.as_str()).map(epoch_of).collect();
        epochs.sort();
        epochs
    }

    /// Avery creates the household and admits Sam, then Pat, handing each
    /// grant over its door: epoch 1 is Avery and Sam's, epoch 2 the three of
    /// them. Sam and Pat each hold a card for Avery and for nobody else.
    async fn household() -> (Node, Node, Node) {
        let (avery, sam, pat) = (node(AVERY(), &[SAM(), PAT()]), node(SAM(), &[AVERY()]), node(PAT(), &[AVERY()]));
        message_channel_create(&avery, "u".into(), CHANNEL.into()).await.unwrap();
        for (member, at) in [(SAM(), vec![SAM()]), (PAT(), vec![SAM(), PAT()])] {
            let answer = message_channel_grant_key(&avery, "u".into(), CHANNEL.into(), member.into(), false).await.unwrap();
            assert!(matches!(answer, UserResponse::ChannelKeyGrantCreated { .. }), "admit {member}: {answer:?}");
            for to in at {
                let to_node = if to == SAM() { &sam } else { &pat };
                let answer = at_door(to_node, AVERY(), &public(AVERY()), take_handed(&avery, to)).await;
                assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{to}: {answer:?}");
            }
        }
        assert_eq!((own_epochs(&sam), own_epochs(&pat)), (vec![1, 2], vec![2]));
        (avery, sam, pat)
    }

    /// What `node`'s roster at its newest epoch names `did` with.
    async fn named(node: &Node, did: &str) -> RosterMember {
        Rosters::held(node, "u", CHANNEL).await.member(did).cloned().unwrap_or_else(|| RosterMember::bare(did))
    }

    /// **The record's test.** Sam and Pat are both members, and Sam is not
    /// Pat's contact. Avery's roster names each of them with the key and the
    /// note Avery's cards hold, so Pat's node holds Sam as a co-member and
    /// Sam's holds Pat. Pat's post is sealed to the roster's key for Sam,
    /// handed at Sam's door, and kept in Pat's outbox until Sam's device signs
    /// for it — which Pat believes under the device the roster's note for Sam
    /// lists. Sam's node holds Pat's signature to the key the roster carries
    /// for Pat, at the door and at a vault pickup alike, and reads the post.
    /// Pat's leave notice reaches Sam the same way — and Sam, whom Pat never
    /// paired with, is the elector: Avery files the notice and waits, Sam files
    /// it and rotates to an epoch without Pat, and Avery takes it.
    ///
    /// Red when the roster carries no key, or a key without the member's own
    /// log: Pat's copy to Sam is answered with no key and never handed or kept. Red when the vault pickup does not
    /// fall back from the card to the roster: Sam's node answers that Pat is
    /// not a contact.
    #[tokio::test]
    async fn a_members_post_and_leave_reach_a_member_who_is_not_their_contact() {
        let (avery, sam, pat) = household().await;

        // The roster carries what Avery's cards hold of each member.
        assert_eq!(
            named(&pat, SAM()).await,
            RosterMember { did: SAM().into(), key: Some(public(SAM())), reach: Some(note(SAM())), kel: log(SAM()) },
            "pat's roster names sam with the key and the note avery's card holds"
        );
        let pats = co_members(&pat, "u").await.unwrap();
        assert_eq!(pats.iter().map(|c| (c.did.as_str(), c.key)).collect::<Vec<_>>(), [(SAM(), public(SAM()))]);
        let sams = co_members(&sam, "u").await.unwrap();
        assert_eq!(sams.iter().map(|c| (c.did.as_str(), c.key)).collect::<Vec<_>>(), [(PAT(), public(PAT()))]);
        assert!(co_members(&avery, "u").await.unwrap().is_empty(), "avery holds a card for both: no co-member");

        // Pat posts.
        let UserResponse::ChannelSent { fanout, .. } =
            message_channel_send(&pat, "u".into(), CHANNEL.into(), "the ferry leaves at 6:40".into()).await.unwrap()
        else {
            panic!("pat's post")
        };
        let mut to: Vec<&str> = fanout.iter().map(|m| m.member_did.as_str()).collect();
        to.sort();
        let mut want = [AVERY(), SAM()];
        want.sort();
        assert_eq!(to, want, "{fanout:?}");
        let waiting: Vec<OutboxEntry> = pat.outbox.lock().unwrap().iter().filter(|e| e.to_did == SAM()).cloned().collect();
        assert_eq!(waiting.len(), 1, "pat's copy for sam waits in pat's outbox until a device of sam's signs for it");
        let copy = take_handed(&pat, SAM());
        assert_eq!(copy, waiting[0].sealed, "the copy handed is the copy kept");

        // At Sam's door — the door Sam's node opened for Pat from the roster.
        let answer = at_door(&sam, PAT(), &sams[0].key, copy).await;
        let ContactResponse::Delivered { stored: true, ack: Some(ack) } = answer else {
            panic!("sam's door: {answer:?}")
        };
        assert_eq!(
            outbox::take_ack(&pat, "u", SAM(), &waiting[0].id, &ack).await,
            Ok(true),
            "pat believes sam's device under the note the roster carries for sam"
        );
        assert!(pat.outbox.lock().unwrap().iter().all(|e| e.to_did != SAM()), "signed for, and out of the outbox");
        let filed: Vec<serde_json::Value> = sam.all(NSID_MESSAGE_V1);
        assert_eq!(filed.len(), 1);
        let read = message_decrypt_channel(
            &sam,
            "u".into(),
            CHANNEL.into(),
            filed[0]["body"].as_str().unwrap().into(),
            filed[0]["nonce"].as_str().unwrap().into(),
        )
        .await
        .unwrap();
        assert!(matches!(read, UserResponse::Decrypted { ref plaintext } if plaintext == "the ferry leaves at 6:40"), "{read:?}");

        // A second post, picked up from Sam's vault: no door proved Pat, so
        // Sam's node holds the signature to the key the roster carries.
        message_channel_send(&pat, "u".into(), CHANNEL.into(), "bring a coat".into()).await.unwrap();
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: take_handed(&pat, SAM()) };
        assert_eq!(delivery::file_from_vault(&sam, "u", &held).await, Ok(true), "sam files pat's post from the vault");
        assert_eq!(sam.all(NSID_MESSAGE_V1).len(), 2);

        // Pat leaves. With these identities the elector — the first DID in the
        // roster without Pat — is Sam, the member Pat never paired with: the
        // case this record's `Security:` is about. The notice reaches Avery
        // first, who files it and waits, and Sam last, who files it and rotates.
        assert!(SAM() < AVERY(), "the seeds make sam the elector");
        let UserResponse::ChannelSent { fanout, .. } =
            message_channel_leave(&pat, "u".into(), CHANNEL.into()).await.unwrap()
        else {
            panic!("pat leaves")
        };
        assert!(
            fanout.iter().all(|m| !matches!(&m.delivery, Delivery::Unreachable { reason } if reason.contains("card"))),
            "no member is answered as one pat holds no card for: {fanout:?}"
        );
        assert!(
            pat.outbox.lock().unwrap().iter().any(|e| e.to_did == SAM()),
            "the notice for sam waits in pat's outbox, as one for a contact does"
        );
        let answer = at_door(&avery, PAT(), &public(PAT()), take_handed(&pat, AVERY())).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        assert_eq!(own_epochs(&avery), [0, 1, 2], "avery is not the elector, and waits");

        let answer = at_door(&sam, PAT(), &public(PAT()), take_handed(&pat, SAM())).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "{answer:?}");
        let notices: Vec<serde_json::Value> =
            sam.all(NSID_MESSAGE_V1).into_iter().filter(|m| m["type"] == LEAVE_TYPE).collect();
        assert_eq!(notices.len(), 1, "sam keeps pat's notice");
        let now = current_members(&sam, "u", CHANNEL, SAM(), &sam.key, &mut None).await.unwrap();
        let mut two = vec![AVERY().to_string(), SAM().to_string()];
        two.sort();
        let mut dids = now.dids.clone();
        dids.sort();
        assert_eq!((now.epoch, dids), (3, two), "sam, the elector pat never paired with, rotates pat out");
        let answer = at_door(&avery, SAM(), &public(SAM()), take_handed(&sam, AVERY())).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "avery takes sam's epoch: {answer:?}");
        assert_eq!(own_epochs(&avery), [0, 1, 2, 3]);
    }

    /// **A channel whose rosters cannot be read is named as such, not taken
    /// for one that names nobody** — what lets `kuserd`'s mailbox keep the
    /// doors that channel opened
    /// (`TASK-a-mailbox-rebuild-that-cannot-list-the-set-drops-every-door-and-is-not-tried-again`).
    /// `co_members` answers as it did: nobody from that channel.
    ///
    /// Red when `co_members_read` reads a channel through `Rosters::held`,
    /// which takes a failed read for an empty roster.
    #[tokio::test]
    async fn a_channel_whose_rosters_cannot_be_read_is_named_unreadable() {
        let (_avery, _sam, pat) = household().await;
        let read = co_members_read(&pat, "u").await.expect("pat's channels are listed");
        assert_eq!(read.members.iter().map(|c| c.did.as_str()).collect::<Vec<_>>(), [SAM()], "sam, from the roster");
        assert!(read.unreadable.is_empty());

        pat.fails_roster_reads.store(true, std::sync::atomic::Ordering::SeqCst);
        let read = co_members_read(&pat, "u").await.expect("pat's channels are still listed");
        assert!(read.members.is_empty(), "a roster that cannot be read names nobody");
        assert_eq!(read.unreadable, [CHANNEL], "and the channel is named as unreadable");
        assert!(co_members(&pat, "u").await.expect("co_members answers as before").is_empty());
    }

    /// **A rotation by a member who never paired with another** names them
    /// with what the roster it holds carries: Sam admits Lee — a contact of
    /// Sam's — and the epoch Sam mints names Pat, whom Sam never paired with,
    /// with Pat's key and note as Avery's roster carried them; its grant to
    /// Pat is sealed to that key and handed at Pat's door, where Pat's node
    /// files it from a co-member. Before rosters carried keys, Sam's rotation
    /// was refused outright: no key known for Pat.
    #[tokio::test]
    async fn a_member_who_never_paired_with_another_rotates_and_names_them_from_the_roster() {
        let (_avery, sam, pat) = household().await;
        let sam = {
            // Sam pairs with Lee, to admit them.
            let lee = (LEE(), seed(LEE()));
            let again = Node::new(SAM(), seed(SAM()), &[(AVERY(), seed(AVERY())), lee]);
            *again.notes.lock().unwrap() = vec![note(SAM()), note(AVERY()), note(LEE())];
            *again.logs.lock().unwrap() = vec![log(SAM()), log(AVERY()), log(LEE())];
            for g in sam.all(NSID_CHANNEL_KEY_GRANT) {
                again.keep(NSID_CHANNEL_KEY_GRANT, g);
            }
            again
        };
        let answer = message_channel_grant_key(&sam, "u".into(), CHANNEL.into(), LEE().into(), false).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelKeyGrantCreated { .. }), "sam admits lee: {answer:?}");

        let at3 = Rosters::held(&sam, "u", CHANNEL).await;
        assert_eq!(at3.current().len(), 4);
        assert_eq!(
            at3.current().iter().find(|m| m.did == PAT()),
            Some(&RosterMember { did: PAT().into(), key: Some(public(PAT())), reach: Some(note(PAT())), kel: log(PAT()) }),
            "pat is named with what avery's roster carried for them"
        );
        let answer = at_door(&pat, SAM(), &public(SAM()), take_handed(&sam, PAT())).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "pat files the grant from sam: {answer:?}");
        assert_eq!(own_epochs(&pat), [2, 3]);
    }

    /// **A member who mints an epoch cannot speak as another**
    /// (`TASK-a-roster-key-is-the-minting-members-word-and-not-the-members-own-log`).
    /// Avery — who holds the channel's key and mints its epochs — seals an
    /// epoch 3 whose roster names Pat under **Avery's own key**: once beside
    /// Pat's own log, which does not yield it, and once beside no log. Sam,
    /// who holds no card for Pat, believes neither: the key is not taken from
    /// either roster, no door opens for it (`co_members`), and a post Avery
    /// seals as Pat, under Avery's key, is refused at a door opened for that
    /// key and not filed from Sam's vault — Sam's node holds Pat's copies to
    /// the key Pat's own log yields, which Avery does not hold.
    ///
    /// Red when a roster's key is believed without its member's log yielding
    /// it: the forged key is Pat's on Sam's node, its door opens, and Avery's
    /// post as Pat is filed.
    #[tokio::test]
    async fn a_member_who_mints_an_epoch_cannot_name_their_own_key_for_another_and_speak_as_them() {
        for forged_log in [log(PAT()), Vec::new()] {
            let (avery, sam, _pat) = household().await;
            let e3 = channel_key_generate();
            let members = [
                RosterMember { did: AVERY().into(), key: Some(public(AVERY())), reach: None, kel: log(AVERY()) },
                RosterMember { did: SAM().into(), key: Some(public(SAM())), reach: None, kel: log(SAM()) },
                RosterMember { did: PAT().into(), key: Some(public(AVERY())), reach: None, kel: forged_log.clone() },
            ];
            sam.keep(NSID_CHANNEL_KEY_GRANT, super::test_node::grant_naming(CHANNEL, SAM(), seed(SAM()), &e3, 3, &members));
            let with = if forged_log.is_empty() { "no log" } else { "pat's log" };

            let at3 = Rosters::held(&sam, "u", CHANNEL).await;
            let named = at3.current().iter().find(|m| m.did == PAT()).expect("pat is a member at epoch 3");
            assert_eq!(named.key, None, "{with}: avery's key under pat's DID is not believed");
            let co = co_members(&sam, "u").await.unwrap();
            assert!(
                co.iter().all(|c| c.key != public(AVERY())),
                "{with}: no door opens for avery's key as pat's: {co:?}"
            );

            // Avery's post, sealed as Pat's under the epoch's key and Avery's
            // own identity key.
            let (body, nonce) = channel_encrypt(b"pat says: give avery the car", &e3).unwrap();
            let copy = ChannelCopy { channel_did: CHANNEL.into(), epoch: 3, body, nonce: B64.encode(nonce) };
            let forged = envelope::seal(&copy_inner(PAT(), SAM(), &copy, "text"), &key(AVERY()), &public(SAM())).unwrap();
            let answer = at_door(&sam, PAT(), &public(AVERY()), forged.clone()).await;
            assert!(
                !matches!(answer, ContactResponse::Delivered { .. }),
                "{with}: a door for avery's key took a post as pat's: {answer:?}"
            );
            let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: forged };
            assert!(
                !matches!(delivery::file_from_vault(&sam, "u", &held).await, Ok(true)),
                "{with}: sam's vault pickup filed avery's post as pat's"
            );
            let filed = sam.all(NSID_MESSAGE_V1);
            assert!(filed.iter().all(|m| m["from_did"] != PAT()), "{with}: nothing is filed as pat's: {filed:?}");
            drop(avery);
        }
    }

    /// **An older prefix of a member's log does not put their retired key
    /// back** (the assessor's ground 1 of 2026-10-09). Pat2 rotates once: their
    /// log is an inception and a rotation, and their key is the rotated one.
    /// Avery mints epoch 4 naming Pat2 with that log and that key, then epoch
    /// 5 naming Pat2 with the **one-event prefix** of the same log and the key
    /// it installs — the retired one. Each entry alone is a key its log yields.
    /// Sam, who holds no card for Pat2, believes the epoch-4 key — the longest
    /// log he holds for them — opens no door for the retired key, and a post
    /// as Pat2 signed with the retired key is refused at a door opened for it
    /// and not filed from the vault; one signed with the current key is filed.
    ///
    /// Red when the longest-log rule is removed (the newest roster with a key
    /// is believed): the retired key is Pat2's on Sam's node, and the post it
    /// signs is filed.
    #[tokio::test]
    async fn an_older_prefix_of_a_members_log_does_not_put_their_retired_key_back() {
        use kotton_crypto::kel_verify::{build_inception, build_mnemonic_rotation, kel_recovery_pubkey};
        let phrase = [42u8; 32];
        let rung = |i: u64| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&phrase, i));
        let (retired, current) = (SigningKey::from_bytes(&[6; 32]), SigningKey::from_bytes(&[7; 32]));
        let inception = build_inception(&retired, &[rung(0)]);
        let rotation = build_mnemonic_rotation(&inception, &phrase, 0, &current, 0, &[rung(0)]);
        let pat2 = inception.aid.0.clone();
        let (full, prefix) = (vec![inception.clone(), rotation], vec![inception]);
        let (retired_pub, current_pub) = (retired.verifying_key().to_bytes(), current.verifying_key().to_bytes());
        assert!(log_yields(&pat2, &current_pub, &full), "the full log yields the current key");
        assert!(log_yields(&pat2, &retired_pub, &prefix), "and its prefix, alone, the retired one");

        let sam = node(SAM(), &[AVERY()]);
        let base = |pat2_key: [u8; 32], pat2_log: &Vec<kotton_wire::kel::KelEvent>| {
            [
                RosterMember { did: AVERY().into(), key: Some(public(AVERY())), reach: None, kel: log(AVERY()) },
                RosterMember { did: SAM().into(), key: Some(public(SAM())), reach: None, kel: log(SAM()) },
                RosterMember { did: pat2.clone(), key: Some(pat2_key), reach: None, kel: pat2_log.clone() },
            ]
        };
        let (e4, e5) = (channel_key_generate(), channel_key_generate());
        sam.keep(NSID_CHANNEL_KEY_GRANT, super::test_node::grant_naming(CHANNEL, SAM(), seed(SAM()), &e4, 4, &base(current_pub, &full)));
        sam.keep(NSID_CHANNEL_KEY_GRANT, super::test_node::grant_naming(CHANNEL, SAM(), seed(SAM()), &e5, 5, &base(retired_pub, &prefix)));

        let rosters = Rosters::held(&sam, "u", CHANNEL).await;
        assert_eq!(rosters.member(&pat2).and_then(|m| m.key), Some(current_pub), "the longest log sam holds is believed");
        let co = co_members(&sam, "u").await.unwrap();
        assert_eq!(co.iter().map(|c| (c.did.as_str(), c.key)).collect::<Vec<_>>(), [(pat2.as_str(), current_pub)]);

        let post = |text: &[u8], by: &SigningKey| {
            let (body, nonce) = channel_encrypt(text, &e5).unwrap();
            let copy = ChannelCopy { channel_did: CHANNEL.into(), epoch: 5, body, nonce: B64.encode(nonce) };
            envelope::seal(&copy_inner(&pat2, SAM(), &copy, "text"), by, &public(SAM())).unwrap()
        };
        let stale = post(b"under the key pat2 retired", &retired);
        let answer = at_door(&sam, &pat2, &retired_pub, stale.clone()).await;
        assert!(!matches!(answer, ContactResponse::Delivered { .. }), "a door for the retired key took a post: {answer:?}");
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: stale };
        assert!(!matches!(delivery::file_from_vault(&sam, "u", &held).await, Ok(true)), "the vault pickup filed it");
        assert!(sam.all(NSID_MESSAGE_V1).is_empty(), "nothing under the retired key is filed");

        let answer = at_door(&sam, &pat2, &current_pub, post(b"under pat2's own key", &current)).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "the current key's post: {answer:?}");
    }

    /// **A fork of a member's log grown with their retired key believes
    /// neither** (the assessor at `c81cf0672`). Pat2's real log is an
    /// inception and a rotation to their current key. Whoever holds the
    /// retired key can grow the one-event prefix with events of their own —
    /// two recovery-set growths, each signed by it — into a three-event log
    /// that still yields the retired key and is longer than the real one.
    ///
    /// - **Both held** (the real log in epoch 4, the fork in epoch 5): neither
    ///   extends the other, so Sam's node believes no key for Pat2, opens no
    ///   door for either, and refuses a post signed with the retired key —
    ///   the forger denies, and cannot override.
    /// - **Only the fork held**: the retired key is believed. That is the
    ///   residual both records state — a node holding no longer log for the
    ///   member and no card.
    /// - **The same log in two rosters** is one entry: equality is an
    ///   extension, and the newest roster's is believed.
    ///
    /// Red when extension is replaced by length: the fork, longer, is believed
    /// over the real log, and the retired key's post is filed.
    #[tokio::test]
    async fn a_fork_of_a_members_log_grown_with_their_retired_key_believes_neither() {
        use kotton_crypto::kel_verify::{build_add_recovery, build_inception, build_mnemonic_rotation, kel_recovery_pubkey};
        let phrase = [42u8; 32];
        let rung = |i: u64| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&phrase, i));
        let (retired, current) = (SigningKey::from_bytes(&[6; 32]), SigningKey::from_bytes(&[7; 32]));
        let inception = build_inception(&retired, &[rung(0)]);
        let rotation = build_mnemonic_rotation(&inception, &phrase, 0, &current, 0, &[rung(0)]);
        let grown = build_add_recovery(&inception, &[rung(0), [8; 32]], &retired);
        let grown_again = build_add_recovery(&grown, &[rung(0), [8; 32], [9; 32]], &retired);
        let pat2 = inception.aid.0.clone();
        let real = vec![inception.clone(), rotation];
        let fork = vec![inception, grown, grown_again];
        let (retired_pub, current_pub) = (retired.verifying_key().to_bytes(), current.verifying_key().to_bytes());
        assert!(log_yields(&pat2, &current_pub, &real), "the real log yields the current key");
        assert!(log_yields(&pat2, &retired_pub, &fork), "the fork, alone, yields the retired key");
        assert!(fork.len() > real.len(), "and is the longer of the two");

        let roster = |pat2_key: [u8; 32], pat2_log: &Vec<kotton_wire::kel::KelEvent>| {
            [
                RosterMember { did: AVERY().into(), key: Some(public(AVERY())), reach: None, kel: log(AVERY()) },
                RosterMember { did: SAM().into(), key: Some(public(SAM())), reach: None, kel: log(SAM()) },
                RosterMember { did: pat2.clone(), key: Some(pat2_key), reach: None, kel: pat2_log.clone() },
            ]
        };
        let grant_at = |epoch: u64, key: &[u8; 32], members: &[RosterMember]| {
            super::test_node::grant_naming(CHANNEL, SAM(), seed(SAM()), key, epoch, members)
        };
        let (e4, e5) = (channel_key_generate(), channel_key_generate());

        // Both held: neither is believed.
        let sam = node(SAM(), &[AVERY()]);
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant_at(4, &e4, &roster(current_pub, &real)));
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant_at(5, &e5, &roster(retired_pub, &fork)));
        assert_eq!(Rosters::held(&sam, "u", CHANNEL).await.member(&pat2), None, "a fork against the real log: neither");
        assert!(co_members(&sam, "u").await.unwrap().iter().all(|c| c.did != pat2), "no door for either key");
        let post = |text: &[u8], by: &SigningKey| {
            let (body, nonce) = channel_encrypt(text, &e5).unwrap();
            let copy = ChannelCopy { channel_did: CHANNEL.into(), epoch: 5, body, nonce: B64.encode(nonce) };
            envelope::seal(&copy_inner(&pat2, SAM(), &copy, "text"), by, &public(SAM())).unwrap()
        };
        let stale = post(b"under the key pat2 retired", &retired);
        let answer = at_door(&sam, &pat2, &retired_pub, stale.clone()).await;
        assert!(!matches!(answer, ContactResponse::Delivered { .. }), "a door for the retired key took a post: {answer:?}");
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed: stale };
        assert!(!matches!(delivery::file_from_vault(&sam, "u", &held).await, Ok(true)), "the vault pickup filed it");
        assert!(sam.all(NSID_MESSAGE_V1).is_empty(), "nothing under the retired key is filed");

        // Only the fork held: the retired key is believed — the residual.
        let alone = node(SAM(), &[AVERY()]);
        alone.keep(NSID_CHANNEL_KEY_GRANT, grant_at(5, &e5, &roster(retired_pub, &fork)));
        assert_eq!(
            Rosters::held(&alone, "u", CHANNEL).await.member(&pat2).and_then(|m| m.key),
            Some(retired_pub),
            "with no longer log and no card held, the fork's key is believed: the residual the records state"
        );

        // The same log in two rosters: one entry, the newest's.
        let twice = node(SAM(), &[AVERY()]);
        twice.keep(NSID_CHANNEL_KEY_GRANT, grant_at(4, &e4, &roster(current_pub, &real)));
        twice.keep(NSID_CHANNEL_KEY_GRANT, grant_at(5, &e5, &roster(current_pub, &real)));
        let believed = Rosters::held(&twice, "u", CHANNEL).await.member(&pat2).cloned();
        assert_eq!(believed.map(|m| (m.key, m.kel.len())), Some((Some(current_pub), 2)), "equality is an extension");
    }

    /// **A rotation proceeds on a fork** (the orchestrator's ruling on the
    /// assessor's last ground at `ff3fd1422`). Sam holds no card for Pat2 and
    /// two rosters whose logs for Pat2 diverge — the real one in epoch 4, a
    /// fork grown with Pat2's retired key in epoch 5. Sam admits Lee: epoch 6
    /// is minted, Avery, Sam and Lee are wrapped grants, and Pat2 is carried as
    /// a DID alone — no key, no note, no log from either side — and wrapped
    /// none. Sam then removes Avery: epoch 7 completes the same way. A copy to
    /// Pat2 says their logs diverge, not that the roster is old.
    ///
    /// Red when a fork refuses the rotation: whoever holds a retired key of
    /// any member's could stop this node minting any epoch at all.
    #[tokio::test]
    async fn a_rotation_proceeds_on_a_fork_and_carries_the_disputed_member_as_a_did_alone() {
        use kotton_crypto::kel_verify::{build_add_recovery, build_inception, build_mnemonic_rotation, kel_recovery_pubkey};
        let phrase = [42u8; 32];
        let rung = |i: u64| kel_recovery_pubkey(&kotton_crypto::kdf::derive_kel_recovery_key(&phrase, i));
        let (retired, current) = (SigningKey::from_bytes(&[6; 32]), SigningKey::from_bytes(&[7; 32]));
        let inception = build_inception(&retired, &[rung(0)]);
        let rotation = build_mnemonic_rotation(&inception, &phrase, 0, &current, 0, &[rung(0)]);
        let grown = build_add_recovery(&inception, &[rung(0), [8; 32]], &retired);
        let pat2 = inception.aid.0.clone();
        let (real, fork) = (vec![inception.clone(), rotation], vec![inception, grown]);
        let roster = |pat2_key: [u8; 32], pat2_log: &Vec<kotton_wire::kel::KelEvent>| {
            [
                RosterMember { did: AVERY().into(), key: Some(public(AVERY())), reach: None, kel: log(AVERY()) },
                RosterMember { did: SAM().into(), key: Some(public(SAM())), reach: None, kel: log(SAM()) },
                RosterMember { did: pat2.clone(), key: Some(pat2_key), reach: None, kel: pat2_log.clone() },
            ]
        };
        let sam = node(SAM(), &[AVERY(), LEE()]);
        let (e4, e5) = (channel_key_generate(), channel_key_generate());
        let grant_at = |epoch: u64, key: &[u8; 32], members: &[RosterMember]| {
            super::test_node::grant_naming(CHANNEL, SAM(), seed(SAM()), key, epoch, members)
        };
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant_at(4, &e4, &roster(current.verifying_key().to_bytes(), &real)));
        sam.keep(NSID_CHANNEL_KEY_GRANT, grant_at(5, &e5, &roster(retired.verifying_key().to_bytes(), &fork)));
        assert!(Rosters::held(&sam, "u", CHANNEL).await.disputed(&pat2), "the two logs diverge on sam's node");

        let granted_at = |epoch: u64| {
            let mut to: Vec<String> = sam
                .all(NSID_CHANNEL_KEY_GRANT)
                .iter()
                .filter(|g| epoch_of(g) == epoch)
                .map(|g| g["to_did"].as_str().unwrap().to_string())
                .collect();
            to.sort();
            to
        };
        let sorted = |dids: &[&str]| {
            let mut v: Vec<String> = dids.iter().map(|d| d.to_string()).collect();
            v.sort();
            v
        };

        let answer = message_channel_grant_key(&sam, "u".into(), CHANNEL.into(), LEE().into(), false).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelKeyGrantCreated { .. }), "sam admits lee on a fork: {answer:?}");
        assert_eq!(granted_at(6), sorted(&[AVERY(), SAM(), LEE()]), "every member but the disputed one is granted epoch 6");
        let at6 = Rosters::held(&sam, "u", CHANNEL).await;
        assert_eq!(
            at6.current().iter().find(|m| m.did == pat2),
            Some(&RosterMember::bare(&pat2)),
            "pat2 is carried as a DID alone: no key, no note, no log from either side"
        );

        let answer = message_channel_remove_member(&sam, "u".into(), CHANNEL.into(), AVERY().into()).await.unwrap();
        assert!(matches!(answer, UserResponse::Ok), "sam removes avery on a fork: {answer:?}");
        assert_eq!(granted_at(7), sorted(&[SAM(), LEE()]), "the removal completes, and pat2 is granted nothing");
        let now = current_members(&sam, "u", CHANNEL, SAM(), &sam.key, &mut None).await.unwrap();
        let mut dids = now.dids.clone();
        dids.sort();
        assert_eq!((now.epoch, dids), (7, sorted(&[SAM(), &pat2, LEE()])), "pat2 is still a member, denied here");

        let UserResponse::ChannelSent { fanout, .. } =
            message_channel_send(&sam, "u".into(), CHANNEL.into(), "after the fork".into()).await.unwrap()
        else {
            panic!("sam's post")
        };
        let pats = fanout.iter().find(|m| m.member_did == pat2).expect("pat2's line");
        assert!(matches!(&pats.delivery, Delivery::Unreachable { reason } if reason.contains("diverge")), "{pats:?}");
    }

    /// **A rotation never refuses for a member's missing key** (the
    /// orchestrator's ruling on the assessor's ground at `cc7652b47`). Lee was
    /// admitted at epoch 6, minted on a fork, whose roster names Pat2 as a DID
    /// alone; Lee holds no card for Pat2 and no older roster, so Pat2 is
    /// simply unknown on Lee's node. Lee admits Pat — a contact of Lee's —
    /// and epoch 7 completes, every member granted but Pat2, who is carried
    /// bare; Lee removes Avery and epoch 8 completes the same way. Pat2 stays
    /// a member throughout: denied on Lee's epochs, never evicted.
    ///
    /// Red when an unknown member refuses the rotation: the channel stalls on
    /// Lee's node, for an admission and a removal alike.
    #[tokio::test]
    async fn a_member_admitted_after_a_fork_rotates_and_carries_the_member_it_knows_no_key_for_bare() {
        const PAT2: &str = "did:kel:pat2-carried-bare-since-a-fork";
        let lee = node(LEE(), &[SAM(), PAT()]);
        let e6 = channel_key_generate();
        let at6 = [
            RosterMember { did: AVERY().into(), key: Some(public(AVERY())), reach: None, kel: log(AVERY()) },
            RosterMember { did: SAM().into(), key: Some(public(SAM())), reach: None, kel: log(SAM()) },
            RosterMember::bare(PAT2),
            RosterMember { did: LEE().into(), key: Some(public(LEE())), reach: None, kel: log(LEE()) },
        ];
        lee.keep(NSID_CHANNEL_KEY_GRANT, super::test_node::grant_naming(CHANNEL, LEE(), seed(LEE()), &e6, 6, &at6));
        let held = Rosters::held(&lee, "u", CHANNEL).await;
        assert!(held.member(PAT2).is_none() && !held.disputed(PAT2), "pat2 is unknown here, not disputed");

        let granted_at = |epoch: u64| {
            let mut to: Vec<String> = lee
                .all(NSID_CHANNEL_KEY_GRANT)
                .iter()
                .filter(|g| epoch_of(g) == epoch)
                .map(|g| g["to_did"].as_str().unwrap().to_string())
                .collect();
            to.sort();
            to
        };
        let sorted = |dids: &[&str]| {
            let mut v: Vec<String> = dids.iter().map(|d| d.to_string()).collect();
            v.sort();
            v
        };
        let bare_at_current = || async {
            Rosters::held(&lee, "u", CHANNEL).await.current().iter().find(|m| m.did == PAT2).cloned()
        };

        let answer = message_channel_grant_key(&lee, "u".into(), CHANNEL.into(), PAT().into(), false).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelKeyGrantCreated { .. }), "lee admits pat: {answer:?}");
        assert_eq!(granted_at(7), sorted(&[AVERY(), SAM(), LEE(), PAT()]), "every member granted epoch 7 but pat2");
        assert_eq!(bare_at_current().await, Some(RosterMember::bare(PAT2)), "pat2 carried as a DID alone");

        let answer = message_channel_remove_member(&lee, "u".into(), CHANNEL.into(), AVERY().into()).await.unwrap();
        assert!(matches!(answer, UserResponse::Ok), "lee removes avery: {answer:?}");
        assert_eq!(granted_at(8), sorted(&[SAM(), LEE(), PAT()]), "the removal completes, pat2 granted nothing");
        assert_eq!(bare_at_current().await, Some(RosterMember::bare(PAT2)), "pat2 is still a member, never evicted");

        // Admitting somebody this node knows no key for is still refused, by
        // name, before any epoch is minted: they are not a member yet.
        let refused = message_channel_grant_key(&lee, "u".into(), CHANNEL.into(), "did:kel:a-stranger".into(), false)
            .await
            .unwrap();
        assert!(
            matches!(refused, UserResponse::Error { ref message } if message.contains("no key known")),
            "{refused:?}"
        );
        assert!(granted_at(9).is_empty(), "no epoch was minted for the refused admission");
    }

    /// **A roster's key opens that channel's copies and nothing else.** At
    /// Sam's door for Pat — opened from the household's roster — a direct
    /// message from Pat is declined, and Pat cannot seal one: Pat holds no
    /// card for Sam. A copy from Pat naming another channel Sam is in, which
    /// Pat is not, is not filed. A copy from Lee, whom no roster names, is not
    /// filed either; nor is one from Pat under a key the roster does not carry.
    #[tokio::test]
    async fn a_co_members_key_from_a_roster_verifies_only_that_channels_copies() {
        let (avery, sam, pat) = household().await;

        // Pat's node will not seal a direct message to Sam at all.
        let refused = message_send(&pat, "u".into(), SAM().into(), "hi".into(), None).await.unwrap();
        assert!(matches!(refused, UserResponse::Error { ref message } if message.contains("pair with them")), "{refused:?}");

        // One sealed by hand is declined at Sam's door all the same.
        let dm = DmInner {
            from_did: PAT().into(),
            to_did: SAM().into(),
            thread_id: "t".into(),
            sent_at: 1,
            kind: "text".into(),
            text: "hi".into(),
            channel: None,
            grant: None,
            reach: None,
            ack: None,
            kel: Vec::new(),
            share: None,
            range: None,
        };
        let sealed = envelope::seal(&dm, &key(PAT()), &public(SAM())).unwrap();
        let answer = at_door(&sam, PAT(), &public(PAT()), sealed.clone()).await;
        assert!(matches!(answer, ContactResponse::Declined { .. }), "a direct message from a co-member: {answer:?}");
        let held = PendingDelivery { handle_did: "did:key:door".into(), sealed };
        assert!(delivery::file_from_vault(&sam, "u", &held).await.is_err(), "nor is one picked up from the vault");
        assert!(sam.all(NSID_MESSAGE_V1).is_empty(), "nothing of it is filed");

        // Sam and Avery share a second channel, which Pat is not in.
        let other_key = channel_key_generate();
        sam.keep(
            NSID_CHANNEL_KEY_GRANT,
            super::test_node::grant_naming(
                OTHER,
                SAM(),
                seed(SAM()),
                &other_key,
                0,
                &[
                    RosterMember { did: AVERY().into(), key: Some(public(AVERY())), reach: None, kel: log(AVERY()) },
                    RosterMember { did: SAM().into(), key: Some(public(SAM())), reach: None, kel: log(SAM()) },
                ],
            ),
        );
        let (body, nonce) = channel_encrypt(b"not pat's to say", &other_key).unwrap();
        let elsewhere = ChannelCopy { channel_did: OTHER.into(), epoch: 0, body, nonce: B64.encode(nonce) };
        let sealed = envelope::seal(&copy_inner(PAT(), SAM(), &elsewhere, "text"), &key(PAT()), &public(SAM())).unwrap();
        let answer = at_door(&sam, PAT(), &public(PAT()), sealed).await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "a copy for a channel pat is not in: {answer:?}");

        // A household copy from Lee, whom no roster names.
        let sealer = ChannelSealer::newest(&avery, "u", CHANNEL).await.unwrap();
        let copy = sealer.copy(CHANNEL, &sealer.seal(b"from a stranger").unwrap());
        let sealed = envelope::seal(&copy_inner(LEE(), SAM(), &copy, "text"), &key(LEE()), &public(SAM())).unwrap();
        let answer = at_door(&sam, LEE(), &public(LEE()), sealed).await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "a non-member's copy: {answer:?}");

        // A household copy from Pat, signed under a key the roster does not
        // carry for Pat, at a door opened for that key.
        let stranger = SigningKey::from_bytes(&[9; 32]);
        let sealed = envelope::seal(&copy_inner(PAT(), SAM(), &copy, "text"), &stranger, &public(SAM())).unwrap();
        let answer = at_door(&sam, PAT(), &stranger.verifying_key().to_bytes(), sealed).await;
        assert!(matches!(answer, ContactResponse::Refused { .. }), "pat under another key: {answer:?}");
        assert!(sam.all(NSID_MESSAGE_V1).is_empty(), "nothing was filed");

        // And the household's own copy from Pat, under the roster's key, is.
        let sealed = envelope::seal(&copy_inner(PAT(), SAM(), &copy, "text"), &key(PAT()), &public(SAM())).unwrap();
        let answer = at_door(&sam, PAT(), &public(PAT()), sealed).await;
        assert!(matches!(answer, ContactResponse::Delivered { stored: true, .. }), "a co-member's copy: {answer:?}");
    }

    /// **A roster from before keys travelled** names Pat by DID alone, and a
    /// member who holds no card for Pat still has no key to seal to: Pat's
    /// line says their key is not known on this node, and nothing is handed or
    /// kept for them. The next rotation
    /// by somebody who holds Pat's card names the key.
    #[tokio::test]
    async fn a_member_named_by_a_roster_from_before_keys_is_still_unreachable_and_says_why() {
        let sam = node(SAM(), &[AVERY()]);
        let e = channel_key_generate();
        sam.keep(NSID_CHANNEL_KEY_GRANT, super::test_node::grant(CHANNEL, SAM(), seed(SAM()), &e, 2, Some(&[AVERY(), SAM(), PAT()])));
        let UserResponse::ChannelSent { fanout, .. } =
            message_channel_send(&sam, "u".into(), CHANNEL.into(), "hello".into()).await.unwrap()
        else {
            panic!("sam's post")
        };
        let pats = fanout.iter().find(|m| m.member_did == PAT()).expect("pat's line");
        assert!(
            matches!(&pats.delivery, Delivery::Unreachable { reason } if reason.contains("not known on this node") && !reason.contains("diverge")),
            "{pats:?}"
        );
        assert!(sam.handed.lock().unwrap().iter().all(|(d, _)| d != PAT()), "nothing is handed to pat");
        assert!(sam.outbox.lock().unwrap().iter().all(|e| e.to_did != PAT()), "nor kept for them");
    }
}

#[cfg(test)]
mod tests_outbox_prune {
    //! `TASK-a-channel-copy-to-a-member-who-left-is-retried-from-the-outbox-for-ever`:
    //! a copy waiting for somebody the roster this node holds no longer names
    //! — removed, or said they left — is taken out of the outbox when the
    //! roster changes, and nothing else is.
    use super::test_node::{grant, Node};
    use super::*;
    use crate::daemon::delivery;

    const AVERY: &str = "did:kel:avery";
    const PAT: &str = "did:kel:pat";
    const SAM: &str = "did:kel:sam";
    const JORDAN: &str = "did:kel:jordan";
    const CHANNEL: &str = "did:key:zHousehold";
    const OTHER: &str = "did:key:zBookClub";

    fn seed(did: &str) -> u8 {
        match did {
            AVERY => 1,
            SAM => 2,
            JORDAN => 3,
            PAT => 4,
            _ => unreachable!(),
        }
    }

    /// `did`'s node holding the household at epoch 4 — Avery, Pat and Sam,
    /// sealed in the grant — with every other person as a contact. Nothing
    /// travels: a copy handed to a door waits in the outbox.
    fn node(did: &str, e4: &[u8; 32]) -> Node {
        let others: Vec<(&str, u8)> =
            [AVERY, PAT, SAM, JORDAN].into_iter().filter(|d| *d != did).map(|d| (d, seed(d))).collect();
        let node = Node::new(did, seed(did), &others);
        node.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, did, seed(did), e4, 4, Some(&[AVERY, PAT, SAM])));
        node
    }

    /// Whom `node`'s outbox holds an entry for, one per entry, sorted.
    fn waiting_for(node: &Node) -> Vec<String> {
        let mut to: Vec<String> = node.outbox.lock().unwrap().iter().map(|e| e.to_did.clone()).collect();
        to.sort();
        to
    }

    /// An entry for `to` that is not one of the household's copies: a direct
    /// message (`channel` none), or a copy for another channel.
    fn entry(id: &str, to: &str, channel: Option<&str>) -> OutboxEntry {
        let sealed = SealedDm { ephemeral_pub: id.into(), nonce: "n".into(), body: "b".into() };
        outbox::new_entry(to, "r", &sealed, channel)
    }

    async fn at_door(node: &Node, from: &str, sealed: SealedDm) -> ContactResponse {
        let from_pub = SigningKey::from_bytes(&[seed(from); 32]).verifying_key().to_bytes();
        delivery::accept(node, "u", from, &from_pub, ContactRequest::DeliverMessage { sealed }).await
    }

    /// **The record's condition.** Pat posts while Sam is offline, so Sam's
    /// copy waits in Pat's outbox beside Avery's. Avery removes Sam: epoch 5
    /// is Avery's and Pat's. Until Pat's node holds it, Sam's copy waits — Pat
    /// has no way to know. Once Pat's door files Avery's grant, Pat's outbox
    /// holds no copy for Sam; Avery's copy, a direct message to Sam and a copy
    /// to Sam for another channel are untouched. Sam's node, never told it was
    /// removed, would have filed the copy: what pruning costs a removed member.
    ///
    /// Red when nothing prunes: Sam's copy is still there, tried every hour.
    #[tokio::test]
    async fn a_copy_waiting_for_a_member_removed_at_the_next_epoch_leaves_the_outbox_once_the_senders_node_holds_it() {
        let e4 = channel_key_generate();
        let (pat, avery) = (node(PAT, &e4), node(AVERY, &e4));
        let UserResponse::ChannelSent { .. } =
            message_channel_send(&pat, "u".into(), CHANNEL.into(), "dinner at six".into()).await.unwrap()
        else {
            panic!("pat's post")
        };
        assert_eq!(waiting_for(&pat), [AVERY, SAM], "a copy for each member, waiting");
        assert!(
            pat.outbox.lock().unwrap().iter().all(|e| e.channel_did.as_deref() == Some(CHANNEL)),
            "each copy names its channel"
        );
        pat.outbox.lock().unwrap().push(entry("direct", SAM, None));
        pat.outbox.lock().unwrap().push(entry("elsewhere", SAM, Some(OTHER)));

        let answer = message_channel_remove_member(&avery, "u".into(), CHANNEL.into(), SAM.into()).await.unwrap();
        assert!(matches!(answer, UserResponse::Ok), "{answer:?}");
        let to_pat = avery
            .handed
            .lock()
            .unwrap()
            .iter()
            .find(|(d, _)| d == PAT)
            .map(|(_, s)| s.clone())
            .expect("epoch 5 handed to pat");
        assert_eq!(waiting_for(&pat).iter().filter(|d| *d == SAM).count(), 3, "pat's node does not hold epoch 5 yet");
        // What it costs Sam: their node is never told, still holds epoch 4,
        // and would have filed the copy had it woken (the record's finding 1).
        let for_sam = pat
            .outbox
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.to_did == SAM && e.channel_did.as_deref() == Some(CHANNEL))
            .map(|e| e.sealed.clone())
            .unwrap();
        let sam = node(SAM, &e4);
        let filed = at_door(&sam, PAT, for_sam).await;
        assert!(matches!(filed, ContactResponse::Delivered { stored: true, .. }), "{filed:?}");

        let filed = at_door(&pat, AVERY, to_pat).await;
        assert!(matches!(filed, ContactResponse::Delivered { stored: true, .. }), "{filed:?}");
        let now = current_members(&pat, "u", CHANNEL, PAT, &pat.key, &mut None).await.unwrap();
        assert_eq!((now.epoch, now.dids), (5, vec![AVERY.to_string(), PAT.to_string()]));

        let left: Vec<(String, Option<String>)> =
            pat.outbox.lock().unwrap().iter().map(|e| (e.to_did.clone(), e.channel_did.clone())).collect();
        assert!(!left.contains(&(SAM.to_string(), Some(CHANNEL.to_string()))), "a copy for sam still waits: {left:?}");
        assert_eq!(waiting_for(&pat), [AVERY, SAM, SAM], "avery's copy, the direct message and the other channel's");
        let mut ids: Vec<String> = pat.outbox.lock().unwrap().iter().filter(|e| e.to_did == SAM).map(|e| e.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, ["direct", "elsewhere"]);
    }

    /// **A share goes whole.** Pat shares a photo large enough to stream with
    /// the household: Avery's and Sam's copies each wait as a manifest and two
    /// ranges. Pat removes Sam — the rotation Pat's own node mints — and every
    /// piece of Sam's share leaves the outbox with its manifest; all of Avery's
    /// stay.
    ///
    /// Red when the rotation's roster change prunes nothing, or prunes the
    /// manifest and leaves its ranges.
    #[tokio::test]
    async fn a_member_who_removes_another_takes_every_piece_of_their_waiting_share_out_with_its_manifest() {
        let e4 = channel_key_generate();
        let pat = node(PAT, &e4);
        let photo: Vec<u8> = (0..6 * 1024 * 1024).map(|i: usize| (i as u8).wrapping_mul(31)).collect();
        let answer =
            message_channel_share(&pat, "u".into(), CHANNEL.into(), "beach.jpg".into(), photo, None).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelSent { .. }), "{answer:?}");
        let pieces = |to: &str| -> (usize, usize) {
            let outbox = pat.outbox.lock().unwrap();
            let mine: Vec<&OutboxEntry> = outbox.iter().filter(|e| e.to_did == to).collect();
            (mine.iter().filter(|e| e.part_of.is_none()).count(), mine.iter().filter(|e| e.part_of.is_some()).count())
        };
        assert_eq!((pieces(AVERY), pieces(SAM)), ((1, 2), (1, 2)), "a manifest and two ranges each");

        let answer = message_channel_remove_member(&pat, "u".into(), CHANNEL.into(), SAM.into()).await.unwrap();
        assert!(matches!(answer, UserResponse::Ok), "{answer:?}");

        assert_eq!(pieces(SAM), (0, 0), "a piece of sam's share still waits");
        assert_eq!(pieces(AVERY), (1, 2), "avery's share went with sam's");
    }

    /// **Somebody who said they left goes too, though a roster still names
    /// them.** Pat's copy for Sam waits. Sam leaves — Sam's node keeps a notice
    /// for each member in its own outbox, each naming the channel — and Pat's
    /// door files Sam's notice; Avery is the elector, so Pat waits. Then an
    /// epoch reaches Pat from a member who had not filed the notice, still
    /// naming Sam: Sam's copy leaves Pat's outbox, for Sam's node holds no key
    /// to file it with. Avery's stays.
    ///
    /// Red when only the roster is read: the epoch names Sam, and the copy
    /// stays.
    #[tokio::test]
    async fn a_copy_for_somebody_whose_leave_notice_this_node_filed_goes_at_the_next_roster_though_it_names_them() {
        let e4 = channel_key_generate();
        let (pat, sam) = (node(PAT, &e4), node(SAM, &e4));
        let UserResponse::ChannelSent { .. } =
            message_channel_send(&pat, "u".into(), CHANNEL.into(), "dinner at six".into()).await.unwrap()
        else {
            panic!("pat's post")
        };
        let answer = message_channel_leave(&sam, "u".into(), CHANNEL.into()).await.unwrap();
        assert!(matches!(answer, UserResponse::ChannelSent { .. }), "{answer:?}");
        let notices = sam.outbox.lock().unwrap().clone();
        assert_eq!(notices.len(), 2, "a notice for avery and one for pat, waiting");
        assert!(notices.iter().all(|e| e.channel_did.as_deref() == Some(CHANNEL)), "a leave notice names its channel");
        let to_pat = sam.handed.lock().unwrap().iter().find(|(d, _)| d == PAT).map(|(_, s)| s.clone()).unwrap();
        let filed = at_door(&pat, SAM, to_pat).await;
        assert!(matches!(filed, ContactResponse::Delivered { stored: true, .. }), "{filed:?}");
        assert_eq!(waiting_for(&pat), [AVERY, SAM], "filing a notice is not a roster change");

        let e5 = channel_key_generate();
        pat.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, PAT, seed(PAT), &e5, 5, Some(&[AVERY, PAT, SAM, JORDAN])));
        roster_changed(&pat, "u", CHANNEL).await;

        assert_eq!(waiting_for(&pat), [AVERY], "sam said they left, and their copy waits");
    }

    /// **A roster that is not the whole membership takes nothing out.** Pat's
    /// newest grant is from before rosters, so the count of the grants Pat's
    /// store holds names Pat alone — and every copy waiting for a member stays.
    /// So does every copy when Pat's node holds no grant it can open.
    ///
    /// Red when a count is read as a roster: Avery's and Sam's copies go.
    #[tokio::test]
    async fn a_channel_whose_roster_this_node_cannot_read_whole_takes_no_copy_out() {
        let e4 = channel_key_generate();
        let pat = Node::new(PAT, seed(PAT), &[(AVERY, seed(AVERY)), (SAM, seed(SAM))]);
        pat.keep(NSID_CHANNEL_KEY_GRANT, grant(CHANNEL, PAT, seed(PAT), &e4, 4, None));
        pat.outbox.lock().unwrap().push(entry("a", AVERY, Some(CHANNEL)));
        pat.outbox.lock().unwrap().push(entry("s", SAM, Some(CHANNEL)));
        roster_changed(&pat, "u", CHANNEL).await;
        assert_eq!(waiting_for(&pat), [AVERY, SAM], "a count from before rosters took a member's copy out");

        let nobody = Node::new(PAT, seed(PAT), &[(SAM, seed(SAM))]);
        nobody.outbox.lock().unwrap().push(entry("s", SAM, Some(CHANNEL)));
        roster_changed(&nobody, "u", CHANNEL).await;
        assert_eq!(waiting_for(&nobody), [SAM], "no roster here, and a copy went");
    }

    /// **A try does not put back a copy the roster took out meanwhile.** A
    /// channel copy that is no longer in the outbox when its try comes back
    /// — taken out while the try was out — is not written back; a direct
    /// message is, as before.
    ///
    /// Red when the write-back does not ask: the copy is back, and tried again
    /// for ever.
    #[tokio::test]
    async fn a_try_does_not_write_back_a_channel_copy_taken_out_while_it_was_out() {
        let pat = Node::new(PAT, seed(PAT), &[(SAM, seed(SAM))]);
        let retry = outbox::Retry::DEFAULT;
        let said = outbox::attempt(&pat, "u", entry("copy", SAM, Some(CHANNEL)), retry).await;
        assert!(matches!(said, Delivery::Unreachable { .. }), "{said:?}");
        assert!(pat.outbox.lock().unwrap().is_empty(), "a copy taken out was written back");

        outbox::attempt(&pat, "u", entry("direct", SAM, None), retry).await;
        assert_eq!(waiting_for(&pat), [SAM], "a direct message is written back as before");
    }
}
