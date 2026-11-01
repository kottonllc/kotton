// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{
    AppGrantEnvelope, ConfigItem, EventEntry, HandlerEntry, InstalledApp, InstalledExtension,
    KeyHealth, LockMode,
    OrgEntry,
    OrgGrantEntry, OrgRootDelegation, SchemaGrantEntry, SyncDirection, SyncOutcome,
    WindowStateDto,
};
use crate::peer::{EphemeralSession, MountConfig, PairedNode, SyncRule};
use kotton_schemas::CapabilityGrant;
use serde::{Deserialize, Serialize};

/// One entry in a [`UserResponse::SealedList`]: an opaque stored key and its size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedListEntry {
    /// The stored (blinded, on a blinding store) key — never a logical path.
    pub key: String,
    /// Object size in bytes.
    pub size: u64,
    /// Last-modified Unix seconds, if the backend records it.
    pub modified: Option<u64>,
}

/// Responses from the system daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserResponse {
    // -- Peer messaging --------------------------------------------------------
    /// A DM or channel message was stored; contains the new record identifier.
    MessageSent {
        message_id: String,
        /// Where the recipient's copy went, for a direct message
        /// (`DEC-0055`). `None` where the question does not arise — a channel
        /// key grant reuses this variant, and grants are not delivered.
        #[serde(default)]
        delivery: Option<crate::ipc::Delivery>,
    },
    /// A channel message was sealed, kept, and handed to each current member
    /// (`DEC-0055`).
    ///
    /// Its own variant rather than a reuse of [`Self::MessageSent`], for the
    /// reason `ChannelCreated` is its own: the obvious reading of a shared shape
    /// is the wrong one, and the wrong one is only found later. A direct message
    /// has one recipient and one word; a channel message has a copy per member
    /// and an answer per copy.
    ChannelSent {
        message_id: String,
        /// One entry per current member other than the sender. Empty when the
        /// sender is the only member.
        fanout: Vec<crate::ipc::MemberDelivery>,
    },
    /// Answer to `MessageChannelGrantKey`: a channel key-grant was created (and
    /// optionally stored for the member).
    ///
    /// `grant` is the wrapped key-grant JSON blob.  The caller may relay it
    /// to the member out-of-band (e.g. as an encrypted DM) if the member is
    /// not on this daemon.
    ChannelKeyGrantCreated {
        grant: serde_json::Value,
    },

    /// Encrypted message records returned from a history or inbox query.
    ///
    /// Each value is a JSON object with the full `sh.kotton.message.v1` fields
    /// (body, nonce, ephemeral_pub, etc. still base64-encoded).  The caller
    /// decrypts using the appropriate key.
    MessageHistory {
        messages: Vec<serde_json::Value>,
    },
    /// Answer to `MessageDecryptDm` and `MessageDecryptChannel`: the decrypted plaintext.
    Decrypted {
        plaintext: String,
    },
    /// Answer to `MessageDeliveries`: one reading per direct message the
    /// outbox has held for that person.
    MessageDeliveries {
        readings: Vec<crate::ipc::DeliveryReading>,
    },
    /// How many messages this person has not read.
    ///
    /// A number and not a breakdown: a per-conversation count would say which
    /// conversations are busy and which are quiet, and the caller that asked is
    /// drawing one badge.
    MessageUnread {
        count: u64,
    },
    /// A read mark was recorded, or was already at or past the position given.
    ///
    /// `moved` is false for the second case rather than an error, because a
    /// caller re-marking a conversation it has already read is doing the normal
    /// thing and there is nothing for it to handle.
    MessageRead {
        moved: bool,
    },

    // -- Window registry (M44a) -----------------------------------------------
    /// Snapshot of all open WASM app windows.
    WindowList {
        windows: Vec<WindowStateDto>,
    },
    /// Acknowledgement that a window-opened or window-closed notification was recorded.
    WindowAck,

    // -- User lifecycle --------------------------------------------------------
    /// A newly minted identity.
    ///
    /// Carries no recovery phrase, because creation no longer mints one: an
    /// identity is born with a random key and an empty recovery set, and a person
    /// sets recovery up afterwards. A response that returned a phrase here would be
    /// the wire insisting on a ceremony the product deliberately moved.
    UserCreated {
        did: String,
        device_fingerprint: String,
        /// Session token to pass to `Authenticate` on subsequent requests.
        session_token: crate::ipc::SecretText,
    },
    /// Creation was refused because the credential is too weak, with the reason.
    ///
    /// Its own variant rather than an `Error`, because the caller's next move
    /// differs: this one is retryable by the person at the keyboard, and an
    /// `Error` is not. `create_user` refuses deep in `core/device`, so the type
    /// travels as a `Weakness` inside `anyhow` and is recovered by `downcast_ref`
    /// here — the alternative was reading the message, which is a contract
    /// nobody can see.
    WeakCredential {
        message: String,
    },
    /// A recovery phrase was added. Shown once, never stored — the daemon keeps no
    /// copy, which is the whole point of it.
    RecoveryPhraseAdded {
        recovery_key: crate::ipc::vault_request::SecretText,
        /// The paired nodes that hold nothing and now keep the sealed copy —
        /// delivered right after sealing, so a node enrolled before the phrase
        /// existed can serve recovery too (RFC-0081). Best effort: a node that
        /// was asleep is missing here and gets the copy at its next enrolment
        /// or when the phrase is set again.
        ///
        /// **Whole nodes, not labels.** Recovery from a phrase needs an
        /// authority and a **locator**, and the phrase is only the first. A
        /// wiped device has no peers at all, so before `id recover` can ask a
        /// node for the sealed copy it has to be told the node exists —
        /// `peer add <label> <did> <pubkey-hex> <addr>`, four values it can get
        /// from nowhere else. This carried `Vec<String>` until 2026-09-12 and
        /// the client dropped even that at a `..`, so the one call that knew
        /// where the copies went printed the phrase and discarded the address
        /// (`TASK-add-recovery-prints-the-card`).
        ///
        /// A locator is not a secret. It is a coordinate, it composes into no
        /// asset — the pair is the resolver (RFC-0083 R5) and nothing here is
        /// keyed by the identity — and withholding it does not protect the
        /// person, it strands them.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        copies_delivered_to: Vec<PairedNode>,
    },
    UserLoggedOut,
    LoginSuccessful {
        user_id: String,
        device_fingerprint: String,
        /// Session token to pass to `Authenticate` on subsequent requests.
        session_token: crate::ipc::SecretText,
    },
    /// The user's identity was rotated via a mnemonic recovery rotation
    /// (RFC-0038). The `did:kel` AID is unchanged; `new_key_hex` is the new
    /// operational verifying key.
    IdentityRotated {
        new_key_hex: String,
    },
    /// Answer to `Recover`: the identity is back on this device, its data roots
    /// are installed, and every paired node that served the recovery has admitted
    /// this device under the rotated key.
    Recovered {
        /// The `did:kel` AID, unchanged by recovery.
        did: String,
        /// The identity's new operational key — this device's own.
        new_key_hex: String,
        /// This device kept a copy of the identity key sealed under the person's
        /// old passphrase, and it was replaced: it sealed the key the recovery
        /// replaced. Either way the roots are sealed under the passphrase the
        /// request carried.
        #[serde(default)]
        sealed_copy_removed: bool,
        /// Why the vault the request's line names was not recorded as the
        /// person's drive, when the phrase proved and the record could not be
        /// written; absent when it is recorded. The identity is recovered
        /// either way, so this is said beside the success and not as a refusal:
        /// recovering again would rotate again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        drive_not_recorded: Option<String>,
    },
    /// Answer to `RecoveryFetch`: the identity's public chain and, when this node
    /// holds one, its phrase-sealed recovery copy as the JSON it was written in.
    RecoveryMaterial {
        kel: Vec<crate::kel::KelEvent>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bundle: Option<String>,
    },
    /// Answer to `HoldDoors`: how many doors this vault now holds for the person, and
    /// the last epoch they reach.
    DoorsHeld { held: u32, through_epoch: u64 },
    /// Answer to `TakeDeliveries`: what is still waiting after the acknowledgement.
    Deliveries {
        items: Vec<crate::ipc::PendingDelivery>,
    },
    /// Answer to `CarryFrame`: how many messages this vault now carries for the
    /// person, and which — by `ephemeral_pub`, the id the device itself sealed
    /// each under, with the last epoch its doors reach — so the device hands
    /// only the difference next, and a message again only as its window closes.
    /// `room` is how many more it would carry for them: its cap less what it
    /// carries, so the device hands no more new messages than fit, rather than
    /// frames the vault refuses whole (the cap is the vault's to know).
    /// Required, added 2026-10-08: a vault from before it answers in a shape a
    /// device from after cannot read, and is handed nothing.
    FrameCarried {
        carried: u32,
        carrying: Vec<crate::ipc::Carrying>,
        room: u32,
    },
    UserList {
        users: Vec<String>,
    },

    // -- Session auth ---------------------------------------------------------
    /// Answer to `Authenticate`: the request succeeded, and `user_id` is now bound
    /// to this connection for the lifetime of the session.
    ActiveSession {
        user_id: String,
    },
    /// There is no active authenticated session on this connection.
    NoActiveSession,
    /// Diagnostic information about the calling process.
    CallerInfoResponse {
        os_user: String,
        has_active_session: bool,
        session_user_id: Option<String>,
        transport: String,
    },
    /// The session was invalidated; the client must re-authenticate.
    SessionLocked,
    /// Custody for the named user is closed: the vault is sealed until the
    /// daily credential opens it. The session that asked is untouched.
    CustodyLocked,
    /// The request variant is not in the scope declared when the session
    /// authenticated (see `Authenticate`).
    /// The connection remains open; the client may retry with an in-scope request.
    NotInScope,
    /// The connection's **trust-origin** is below the operation's `required_trust`
    /// (RFC-0035): a `Remote` (gateway) connection tried to invoke a `Local`-tier
    /// operation. Distinct from [`NotInScope`] (a least-privilege scope miss) — this
    /// is the structural local/remote floor, which no scope can re-open. The origin
    /// is bound at authentication (see `Authenticate`) from the credential and is
    /// not caller-assertable.
    NotAllowed,
    /// The PIN unlock succeeded; a fresh session token is ready.
    UnlockOk {
        session_token: crate::ipc::SecretText,
        /// What a repair did: `Some` with the root labels an unlock with
        /// `repair` wrote from the vault — empty when every root read and
        /// matched — and `None` when no repair ran: a plain unlock, or a daemon
        /// that predates `repair` and ignored it. Labels only, never a value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repaired: Option<Vec<String>>,
    },
    /// The PIN was wrong.  `attempts_remaining` counts down from `MAX_ATTEMPTS`
    /// and is always at least 1 — the failure that spends the budget answers
    /// [`UserResponse::UnlockRateLimited`] instead.
    UnlockFailed {
        attempts_remaining: u8,
    },
    /// The attempt budget is spent; the PIN was **not checked**. A correct PIN
    /// receives this too, which is what makes it a brake rather than a counter.
    ///
    /// Distinct from [`UserResponse::UnlockFailed`] on purpose: a client that
    /// conflated them would tell the user to try again at the one moment trying
    /// again cannot work.
    UnlockRateLimited {
        retry_after_secs: u64,
    },
    /// Answer to `GetUnlockMethods`: which credentials this device accepts for the
    /// user it names.
    ///
    /// Carries no credential material and no attempt state — only which door to
    /// knock on. `pin` is false for an unknown user, so this does not confirm
    /// whether an identity exists on the device (see `ListUsers`, which answers
    /// that and is likewise pre-auth).
    UnlockMethods {
        /// A PIN is configured and will be accepted.
        pin: bool,
        /// The recovery phrase is accepted. Always true — it is the root
        /// credential and the floor beneath every other method, which is why it
        /// is reported rather than assumed: a client should not hardcode the
        /// fallback that RFC-0053 step 9 is scheduled to demote.
        recovery_key: bool,
    },
    /// The answer to `GetUnlockState`: session and custody, each with its end.
    UnlockState {
        /// This connection holds a live session for the asked-for user.
        session_live: bool,
        /// When that session expires, unix seconds. `None` while `session_live`
        /// means the token is process-scoped — it lives as long as the daemon.
        session_until: Option<i64>,
        /// Whether the user's operational roots are held, and until when.
        custody: crate::ipc::CustodyState,
    },
    /// The user's vault is now bound to this device's hardware.
    DeviceBound {
        /// Which backend holds the binding, for the confirmation message.
        backend: String,
    },
    /// A contact was admitted.
    ContactAdded {
        did: String,
    },
    /// The terminal frame of a contact pairing (RFC-0022): the other person is
    /// now a contact, with the key the ceremony authenticated.
    ContactPaired {
        /// Their identity (`did:kel:…` or `did:key:…`).
        did: String,
        /// What they asked to be called.
        label: String,
    },
    /// The contacts this user has admitted, as `(did, label)`.
    ContactListing {
        contacts: Vec<(String, Option<String>)>,
    },
    /// The lock policy for this user.
    LockPolicy {
        mode: LockMode,
        auto_lock_minutes: u32,
    },
    /// The lock policy was updated.
    LockPolicySet,

    // -- Recovery status (M25b) -----------------------------------------------
    /// The mnemonic-confirmed flag was written successfully.
    MnemonicConfirmed,
    /// The recovery layer coverage for a user.
    RecoveryStatus {
        mnemonic_confirmed: bool,
        pin_set: bool,
        escrow_set: bool,
        guardian_count: u8,
    },

    // -- Key health (M26h) ----------------------------------------------------
    /// Cryptographic health summary for a user.
    KeyHealthInfo(KeyHealth),

    // -- File operations -------------------------------------------------------
    FileData {
        /// The requested byte range of the file (base64 on the wire — a raw
        /// Vec<u8> in JSON is a ~4x number array).
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
        /// Total size of the whole file, so a ranged reader knows when it has
        /// all of it (RFC-0048).
        total_size: u64,
    },
    FileList {
        files: Vec<String>,
    },
    /// A model was installed, or its kind's choice moved to it (RFC-0085).
    ModelInstalled {
        /// The weights hash, which is the model's identity and its record id.
        id: String,
        /// Whether this is now the model of its kind that answers.
        active: bool,
    },
    /// Every model this user has installed.
    ModelList {
        models: Vec<crate::ipc::InstalledModel>,
    },
    /// Paths holding retained losing versions, each with the content ids of the
    /// versions kept for it (RFC-0071 R3).
    ConflictList {
        conflicts: Vec<(String, Vec<String>)>,
    },

    /// A session minted for a third party (RFC-0043). The gateway authenticates
    /// with this token when acting for that principal, and never with its own.
    PrincipalSession {
        token: crate::ipc::SecretText,
    },
    /// Answer to `WebShellPair`: the desk is open and waiting for a browser
    /// (RFC-0078). The first frame of that stream, so the operator's screen can say "ready" and a
    /// caller knows the desk is registered before a browser could reach it.
    WebShellPairReady,
    /// Answer to `BrowserDeviceList`: the browsers admitted for a user, oldest first.
    BrowserDevices {
        browsers: Vec<super::types::BrowserDevice>,
    },
    /// Answer to `BrowserDeviceRevoke`: a browser was revoked, and its row, its
    /// session and its live channels are gone. `channels_closed` counts the channels that
    /// were open when it was revoked — zero for a browser not connected then.
    BrowserDeviceRevoked {
        channels_closed: u32,
    },
    /// Answer to `UserRequest::BrowserFrame`: one frame back to a browser's sealed
    /// channel. Handshake frames in the clear, then
    /// ciphertext; `khttpd` forwards it to the WebSocket unread.
    BrowserFrame {
        /// The frame, base64 on the wire.
        #[serde(with = "crate::base64_bytes")]
        bytes: Vec<u8>,
    },

    // -- Sealed replication (RFC-0041) -----------------------------------------
    /// An object as it rests, tagged with the key domain it belongs to.
    ///
    /// `blob` is opaque — the protocol layer never interprets it, and a node
    /// without the CEK cannot open it. `domain_id` is the hex-encoded one-way
    /// fingerprint of the CEK that sealed it.
    SealedObject {
        /// The requested byte range of the sealed object (base64 on the wire —
        /// a raw `Vec<u8>` would be a 4x JSON number array).
        #[serde(with = "crate::base64_bytes")]
        blob: Vec<u8>,
        domain_id: String,
        /// Total size of the whole sealed object, so a ranged reader knows when
        /// it has assembled all of it.
        total_size: u64,
    },
    /// A sealed transfer was refused because the peer's key domain is not the one
    /// this node can open (or, on a blind mount, not the one it already holds).
    ///
    /// Refusing is the point: accepting would leave blobs nobody can attribute to
    /// a key. Verbatim transfer removes the accidental re-encryption that used to
    /// paper over this, so the condition becomes visible instead of silently
    /// migrating the key domain.
    ///
    /// The check is on the domain fingerprint rather than a rotation counter,
    /// because a counter cannot see the case that matters: two nodes that were
    /// never in the same fleet both start at epoch 0 and compare equal while
    /// holding entirely different keys.
    SealedDomainMismatch {
        expected: String,
        got: String,
    },
    /// Answer to `ListSealed`: the storage-space listing, the opaque stored keys and their
    /// sizes, with no logical path recovered.
    SealedList {
        entries: Vec<SealedListEntry>,
    },

    // -- Remote storage --------------------------------------------------------
    RemoteAdded {
        name: String,
    },
    RemoteList {
        remotes: Vec<String>,
    },

    // -- Generic ---------------------------------------------------------------
    Ok,
    Error {
        message: String,
    },

    // -- Sync (legacy remote-backend) ----------------------------------------
    SyncComplete {
        pushed: u32,
        pulled: u32,
        skipped: u32,
        /// (direction, key, bytes_transferred)
        transfers: Vec<(SyncDirection, String, u64)>,
    },

    // -- Peer pairing ---------------------------------------------------------
    /// The pairing ceremony completed successfully.
    NodePaired {
        node: PairedNode,
    },
    /// List of paired nodes.
    NodeList {
        nodes: Vec<PairedNode>,
    },
    /// Answer to [`crate::UserRequest::NodeRelay`]: the relay this node reserves
    /// at, `None` when it has none.
    NodeRelayResult {
        relay_url: Option<String>,
        /// The key the relay at `relay_url` proved, 64 hex — what the relay
        /// *is* (RFC-0084 V9); `relay_url` is where it was last found. An asker
        /// holds `admission` under this key, never under the address. `None`
        /// when the answering node recorded none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_key: Option<String>,
        /// The key to present at `relay_url`, when the answering node holds one
        /// it may hand this asker: a vault to its tenant (the *invited* key), a
        /// relay operator's device to another of theirs (*mine*, and the invited
        /// key to offer on). `None` from anyone else, and from a relay whose rule
        /// nobody narrowed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        admission: Option<crate::rendezvous::RelayAdmission>,
    },
    /// Answer to [`crate::UserRequest::OperatorMint`]: the public half of the
    /// key just minted, 64 hex characters, for the vault's or the relay's
    /// terminal to enrol. Never the secret.
    OperatorMinted {
        name: String,
        key: String,
    },
    /// Answer to [`crate::UserRequest::OperatorMints`]: each key minted here
    /// and not yet completed, oldest first. Public halves only.
    OperatorMints {
        mints: Vec<crate::ipc::vault_request::MintWaiting>,
    },
    /// Answer to [`crate::UserRequest::OperatorHeld`]: the name of each
    /// instance of the kind asked for that this person operates, in the order
    /// kept. Empty when they operate none.
    OperatorHeld {
        names: Vec<String>,
    },
    /// Answer to [`crate::UserRequest::OperatorForget`]: the credential
    /// forgotten, by its name and service; its key's public half, 64 hex, for
    /// the revoke at an instance that may still run; and whether the instance
    /// answered at all when it was asked. `false` is a host that is gone, or
    /// one not reached within the bound — the key stays enrolled at it, if it
    /// runs, until it is revoked there. `true` is an instance that answered
    /// and does not stand the key.
    OperatorForgotten {
        name: String,
        service: crate::ipc::vault_request::OperatedService,
        key: String,
        answered: bool,
    },
    /// Answer to [`crate::UserRequest::OperatorEnrol`], and the door's one
    /// line: the credential kept,
    /// by the name and service it is kept under.
    OperatorEnrolled {
        name: String,
        service: crate::ipc::vault_request::OperatedService,
        /// Why an enrolled vault is not yet standing at a relay, the
        /// credential being kept all the same. `None` when it was told, and
        /// for a relay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unstood: Option<crate::ipc::vault_request::Unstood>,
    },
    /// Answer to [`crate::UserRequest::OperatorEnrolLines`]: what each line
    /// came to, in the order the lines were given.
    OperatorEnrolledLines {
        lines: Vec<crate::ipc::vault_request::LineEnrolled>,
    },
    /// Answer to `OperatorVerb::ReadRule` and `OperatorVerb::SetRule`: the rule
    /// the relay reports it holds now. Never a key.
    RelayRule {
        rule: crate::rendezvous::AdmissionRule,
    },
    /// Answer to `OperatorVerb::RelayInvite`: an invite to the relay, in the
    /// one code grammar (`crate::line::InviteCode::Relay`) — its key, its
    /// address and the *invited* admission key its rule reads — for the
    /// operator to hand a person. A bearer at member level, so it is carried
    /// as [`crate::ipc::SecretText`] and prints `<redacted>`.
    RelayInvite {
        invite: crate::ipc::vault_request::SecretText,
    },
    /// Answer to [`crate::UserRequest::Introduce`]: where the listener opened for
    /// the introduced device is, `ip:port`.
    Introduced {
        addr: String,
    },
    /// Answer to [`crate::UserRequest::VaultCapacity`], `SetQuota` and
    /// `VaultRequest::SetQuota`: sealed bytes held for the user and the quota
    /// they may fill, `None` when the keeper sets none.
    VaultCapacityResult {
        held: u64,
        quota: Option<u64>,
    },
    /// Answer to [`crate::UserRequest::TenantDrives`]: every drive the vault
    /// keeps for the tenant, the tenancy's own tree first.
    TenantDrivesResult {
        drives: Vec<crate::ipc::TenantDrive>,
    },
    /// Answer to `DriveCreate`, `DriveList` and `DriveShow`: the drives the
    /// verb is about, each as its descriptor.
    Drives {
        drives: Vec<crate::ipc::DriveDescriptor>,
    },
    /// Answer to `DriveMove` (kotton #314): the drive where it now lives, as its
    /// descriptor, and what the move refused. Its own answer, as `SyncComplete`
    /// is the sync verb's, so no other verb's answer carries a count it never
    /// fills.
    DriveMoved {
        drives: Vec<crate::ipc::DriveDescriptor>,
        /// How many keys the vault the drive left listed that are not storage
        /// keys (`kotton_store::StorageKey`), each refused before anything was
        /// read or written under it and not carried (kotton #274), as a sync
        /// pass counts the keys it refuses. Required on the wire: a move
        /// answer that does not say how many it refused has not said none.
        keys_refused: u32,
    },
    /// Answer to `PinSet` and `PinList`: what this device keeps, and the
    /// notices.
    Pins {
        pins: crate::ipc::PinReadout,
    },
    /// Answer to `Status`.
    Status {
        status: crate::ipc::DeviceStatus,
    },
    /// A sealed write refused because it would exceed the quota (RFC-0084 V3).
    /// Typed rather than an `Error` string so a device can show the person the
    /// two numbers instead of a failure.
    VaultFull {
        held: u64,
        quota: u64,
    },
    /// An invite refused because this vault already keeps a pool named
    /// `user_id`: an invite admits someone new, under a name nobody holds
    /// here, and the tenant's own devices need none (`kvaultd::control::mint_invite`).
    /// Typed rather than an `Error` string because one caller reads it as done,
    /// not refused: `vault invite --me` asks the vault to keep this person's
    /// things, and a vault that keeps them already has (#108). Every other
    /// reader of an invite's answer says it as a refusal, in
    /// [`vault_keeps_already_said`] through [`answer_said`], as each says any
    /// answer but the invite: `kvaultd invite` at the vault's own door, a
    /// guest's `landlord.invite`, and on the operator's desktop
    /// `vault invite <v> <name>`. No reader but `--me` names it, and no reader
    /// names it to decide what to send
    /// next: the operator's desktop sends a number after an invite only on
    /// the invite itself (`kuserd::agent::operator::in_order`, #114).
    VaultKeepsAlready {
        user_id: String,
    },
    /// Answer to the door's `VaultRequest::Tenants` and
    /// `UserRequest::Tenants`: every tenant the vault
    /// keeps anything for, by name, with bytes held, quota and a device count.
    VaultTenants {
        tenants: Vec<super::VaultTenant>,
    },
    /// Answer to `UserRequest::InviteDigits`: the six digits of each
    /// ceremony an invite for the pool, minted under the asking operator key,
    /// is waiting in — one per such invite a device has dialled and not
    /// finished, since an invite admits one dial. Empty while none has.
    InviteDigits {
        digits: Vec<u32>,
    },
    /// Answer to the door's `VaultRequest::DropTenant` and
    /// `UserRequest::DropTenant`: the tenant is gone
    /// from this vault, and this is their readout as it stood before.
    TenantDropped {
        tenant: super::VaultTenant,
    },
    /// The node was removed from the allowlist.
    NodeRevoked,

    /// The pairing ceremony completed successfully (terminal frame of the RFC-0040
    /// pairing stream; see `DeviceAdd` and `DeviceJoin`). On the admitting side it is sent only
    /// after the joining device answered that it kept what it was handed, and
    /// the device was then recorded and introduced at the person's drives —
    /// and, for a vault admitted by code, after the vault answered that it
    /// keeps for this device, before it was recorded; on the joining side, only once the admitting device replied, sealed in the
    /// ceremony's channel, that it heard that answer.
    PairingComplete {
        node: PairedNode,
        /// A session token for the newly-joined device (the joiner side of
        /// `DeviceJoin`): completing the FROST join cryptographically authenticates
        /// the device, so it is issued a session immediately (the device holds no
        /// mnemonic to log in with afterward). `None` for the issuer side, which
        /// keeps its existing session. (TERMINAL-RUNTIME-PIVOT.)
        #[serde(default)]
        session_token: Option<crate::ipc::SecretText>,
        /// The relay a vault's invite met at, **offered** to a device that
        /// stands at no relay — as that relay's line
        /// (`crate::line::InstanceLine`: its key, and its address as a hint).
        /// Never taken by the admit: the device stands there only when the
        /// person says yes — at the door its offer, at the terminal `relay set
        /// <line>` (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`,
        /// Done-when (3)). `None` for every other ceremony, and for a device
        /// that has a relay already.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_offer: Option<String>,
    },

    // -- RFC-0040 streamed pairing ceremony -----------------------------------
    // Frames streamed by `DeviceAdd` (issuer) / `DeviceJoin` (joiner). The stream
    // ends with `PairingComplete` (success) or `PairFailed` (any abort). The
    // six-digit SAS is confirmed out-of-band via a separate `PairConfirmCode`
    // request carrying the `token` from `PairShowCode`.
    /// Issuer: advertising and waiting for a device to connect. `code` is what
    /// the person hands the other side, and it is a secret on every ceremony
    /// that streams it: an admit's interim connection code (address and
    /// session id; see `DeviceAdd`) until mDNS discovery (P1) removes it; a contact pairing's
    /// spoken words, the PAKE's password; and a vault's invite
    /// (`kotton-invite:vault:…`), whose words are that password and which
    /// carries its meeting relay's *invited* admission key when the vault holds
    /// one (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`).
    /// So it is [`crate::ipc::SecretText`]: the same bytes on the wire, `<redacted>` in a
    /// `{:?}`, read by the one reader that hands it on. Answer to `DeviceAdd`,
    /// `DeviceInvite`, `ContactPairStart` and `OperatorVerb::Invite`: the first
    /// frame each of the three ceremonies streams, and the vault's invite the
    /// operator verb mints.
    PairAdvertising {
        code: crate::ipc::vault_request::SecretText,
        /// Unix seconds when the offer expires.
        expires_at: u64,
    },
    /// Joiner: dialing the issuer's bootstrap listener.
    PairConnecting,
    /// The bootstrap connection is up; the committed handshake is running.
    PairConnected,
    /// Both devices derived the six-digit SAS. Show it (zero-padded, grouped
    /// `"NNN NNN"`) and return the human's verdict (see
    /// `PairConfirmCode { token, matches }`).
    PairShowCode {
        /// Correlates the human's verdict back to this parked ceremony.
        token: crate::ipc::SecretText,
        /// The six-digit SAS (0..1_000_000).
        sas: u32,
        /// The peer's label, when known (the joiner learns the issuer's). `None`
        /// on the issuer side.
        peer_label: Option<String>,
    },
    /// The local human confirmed; waiting for the peer's confirmation.
    PairAwaitingPeer,
    /// Both sides confirmed; key material is transferring / installing.
    PairTransferring,
    /// The ceremony aborted (mismatch, cancel, timeout, or peer vanished), or
    /// the joining device did not keep what it was handed — it refused it, or
    /// did not say it kept it in time — in which case the admitting device kept
    /// nothing of the join either: no row, and no drive told of it. On an
    /// admit by code it is also the frame for a vault whose rule refuses this
    /// device, which is read before the vault is recorded: no row either. On the
    /// joining side it is also the frame for a join it kept whose admitting
    /// device never replied that it heard: that device may or may not have
    /// kept it, and `reason` says to check there.
    /// `reason` is calm, specific §7 copy suitable to show verbatim.
    PairFailed {
        reason: String,
    },
    /// Answer to `PairConfirmCode`: the verdict was delivered to the parked
    /// ceremony.
    PairConfirmAck,
    /// Answer to `DeviceName`: this device's current human name.
    DeviceNameInfo {
        name: String,
    },

    // -- Sync engine (RFC-0019) -----------------------------------------------
    /// A sync pass was enqueued. Answer to `SyncDrives`, at once.
    SyncStarted {
        /// Opaque job identifier — pass to `SyncAwait` to block for the result.
        job_id: String,
        /// How many drives the pass syncs.
        targets: u32,
    },
    /// A sync pass completed successfully. Answer to `SyncAwait`.
    SyncOutcomeMsg {
        job_id: String,
        outcome: SyncOutcome,
    },
    /// A sync pass failed. Answer to `SyncAwait`.
    SyncJobFailed {
        job_id: String,
        message: String,
    },
    /// Answer to `SyncAwait`: it timed out before the pass completed.
    SyncJobTimeout {
        job_id: String,
    },

    // -- Peer sync rules ------------------------------------------------------
    /// A sync rule was created or updated.
    SyncConfigured {
        rule: SyncRule,
    },
    /// List of configured sync rules.
    SyncRuleList {
        rules: Vec<SyncRule>,
    },
    /// The sync rule was removed.
    SyncRuleRemoved,

    // -- Peer mounts ----------------------------------------------------------
    /// The mount was added to the VFS router.
    Mounted {
        config: MountConfig,
    },
    /// List of configured peer mounts.
    MountList {
        mounts: Vec<MountConfig>,
    },
    /// The cache for the mount was evicted.
    MountEvicted {
        /// Number of bytes freed from the local cache.
        freed_bytes: u64,
    },

    // -- Ephemeral sessions ---------------------------------------------------
    /// List of active ephemeral sessions.
    SessionList {
        sessions: Vec<EphemeralSession>,
    },
    /// The session was revoked.
    SessionEnded,

    // -- NAT / rendezvous -----------------------------------------------------
    /// The rendezvous URL was saved.
    RendezvousSet,
    /// Current rendezvous configuration and activity.
    RendezvousStatus(crate::rendezvous::RendezvousStatusInfo),
    /// The TURN URL was saved.
    TurnSet,
    /// Where the local-network door stands. Answer to `LocalDoor`.
    LocalDoorResult {
        /// `closed`, `10m` or `always` — the one lit answer on this network.
        answer: String,
        /// Seconds left on *10 minutes*, when it is running here.
        #[serde(default)]
        remaining_secs: Option<u64>,
        /// Where the door's listener is bound, when one exists.
        #[serde(default)]
        listening: Option<String>,
        /// Whether this machine can tell which network it is on — whether *Always*
        /// can be chosen here.
        network_known: bool,
    },
    /// QUIC gateway configuration and live status. Answer to `QuicGatewayStatus`.
    QuicGatewayStatusResult {
        enabled: bool,
        port: u16,
        /// Which local addresses `kquicd` binds — see `QuicGatewaySet`.
        bind: String,
        /// Which source addresses it admits. Empty admits every source.
        #[serde(default)]
        allow: Option<String>,
        /// Whether `kquicd` is expected to be running based on the enabled flag.
        running: bool,
    },
    /// List of authorised-client public keys (hex) for a node. Answer to
    /// `GetAuthorizedClients`.
    AuthorizedClients {
        /// Paired DID strings (for logging / display).
        dids: Vec<String>,
        /// Raw 32-byte Ed25519 public key bytes, hex-encoded, one per DID.
        pubkey_hexes: Vec<String>,
    },
    /// Ed25519 signing key material for `kquicd`'s QUIC mTLS listener.
    /// Answer to `GetDeviceCert`. `Local`-tier.
    DeviceCert {
        /// Raw 32-byte Ed25519 signing key bytes (little-endian scalar).
        signing_key_bytes: crate::ipc::SecretBytes,
    },

    /// This daemon's stable device DID and ephemeral signing public key.
    /// Answer to `GetNodeIdentity`.
    NodeIdentity {
        /// `did:key:z6Mk…` stable device DID.
        device_did: String,
        /// 32-byte raw Ed25519 signing public key, lowercase hex (64 chars).
        signing_pubkey_hex: String,
    },

    // -- HTTP gateway (RFC-0016) -----------------------------------------------
    /// Configuration and runtime state of the HTTP gateway. Answer to `WebShellStatus`.
    WebShellStatusResult {
        enabled: bool,
        port: u16,
        bind: String,
        /// Which source addresses it admits. Empty admits every source.
        #[serde(default)]
        allow: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        static_dir: Option<String>,
        /// `true` when `khttpd` is actively running.
        running: bool,
    },
    /// Device configuration summary table. Answer to `ConfigStatus`.
    ConfigStatus {
        items: Vec<ConfigItem>,
    },

    // -- Record operations ----------------------------------------------------
    /// A record was inserted; contains the stable record identifier.
    RecordInserted {
        record_id: String,
    },
    /// Query results Ã¢â‚¬â€ one JSON value per matching record.
    RecordQueryResult {
        records: Vec<serde_json::Value>,
    },
    /// A record was soft-deleted (tombstone written).
    RecordDeleted,

    /// The opened record and its NSID.
    RecordOpenResult {
        /// The record body as a JSON object.
        record: serde_json::Value,
        /// The NSID of the schema the record belongs to.
        nsid: String,
    },
    /// No record was found at the given `kotton://` URL.
    RecordOpenNotFound {
        /// The URL that was requested.
        url: String,
    },

    // -- Import ---------------------------------------------------------------
    /// An export was read into the person's records.
    ///
    /// Both counts are reported because only their sum matches the file. An
    /// import that says "412" over an export holding 415 events is a confident
    /// wrong answer, and the person is the only one who can tell whether the
    /// three that did not make it mattered.
    Imported {
        /// The shape the items were written under.
        schema_nsid: String,
        /// Items written as records.
        imported: u32,
        /// Items the reader could not make a record of.
        skipped: u32,
    },

    // -- Schema management ----------------------------------------------------
    /// List of registered schema NSIDs.
    SchemaList {
        /// All known NSIDs, core + app, in unspecified order.
        schemas: Vec<String>,
    },
    /// An app schema was validated and registered.
    SchemaRegistered,

    /// Full JSON definition of the requested schema.
    SchemaGetResult {
        definition_json: String,
    },

    /// Requested schema NSID is not registered on this device.
    SchemaNotFound {
        nsid: String,
    },

    // -- Schema grant management (RFC-0003) -----------------------------------
    /// List of schema access grants for an app.
    SchemaGrantListResult {
        grants: Vec<SchemaGrantEntry>,
    },
    /// A schema access grant was created or updated.
    SchemaGrantUpdated,
    /// A schema access grant was removed.
    SchemaGrantRevoked,
    /// Quota limits were updated for an (app_id, nsid) pair.
    SchemaQuotaUpdated,

    // -- Handler registry (v0.5) ----------------------------------------------
    /// The handler was registered successfully.
    HandlerRegistered,
    /// The handler was unregistered.
    HandlerUnregistered,
    /// The default handler for the requested NSID.
    HandlerInfo {
        entry: HandlerEntry,
    },
    /// No handler is registered for the requested NSID.
    HandlerNotFound {
        nsid: String,
    },
    /// All registered handlers.
    HandlerList {
        entries: Vec<HandlerEntry>,
    },
    /// The default handler was updated.
    DefaultHandlerSet,

    // -- App lifecycle (v0.6) -------------------------------------------------
    /// The app was installed successfully.
    ///
    /// The client should present `capabilities` to the user before the app
    /// runs for the first time.
    AppInstalled {
        app_id: String,
        name: String,
        /// Human-readable capability list, e.g. `"schema.read:sh.kotton.notes"`.
        capabilities: Vec<String>,
    },
    /// What an app package is asking for, before anything is minted or written.
    ///
    /// The answer to [`UserRequest::AppInstallPreview`]. `requested` is rendered
    /// with [`CapabilityGrant::display_string`] alongside the structured grants,
    /// so what the user is shown and what the client echoes back (see
    /// `AppInstall { approved }`) are the same values, not two renderings that
    /// could disagree.
    AppInstallPreview {
        app_id: String,
        name: String,
        version: String,
        /// BLAKE3 of the WASM bytes, hex — the binary this preview describes.
        wasm_hash: String,
        /// Every capability the manifest declares.
        requested: Vec<CapabilityGrant>,
        /// `requested`, rendered for display, in the same order.
        requested_display: Vec<String>,
        /// The VFS resources the app declared, each bindable to a path the user
        /// chooses. Pass the ones they changed back as `AppInstall { bindings }`.
        shapes: Vec<kotton_schemas::CapabilityShape>,
        /// True when the publisher DID signature verified. `false` means the
        /// binary is unsigned or self-published — worth saying out loud in a
        /// consent prompt, since a signature is what ties it to a publisher.
        publisher_verified: bool,
    },
    /// Answer to `AppGrants`: what an installed app asked for, and what it
    /// actually holds.
    ///
    /// The two lists are deliberately both here. An app's manifest is a request,
    /// and reading it as the grant is the defect
    /// `TASK-the-approval-is-signed-but-not-enforced` was filed for; showing them
    /// side by side is how a reader — a person or a test — sees the difference
    /// rather than having to know it.
    AppGrants {
        app_id: String,
        name: String,
        /// Everything the manifest declares. What it asked for.
        requested: Vec<CapabilityGrant>,
        /// `requested`, rendered, in the same order.
        requested_display: Vec<String>,
        /// What the user approved, or `None` if no approval was ever recorded.
        ///
        /// `None` is not the same as `Some(vec![])`: the first means nobody was
        /// asked (an install predating the consent gate), the second means they
        /// were asked and said no to everything. Both grant nothing at runtime,
        /// but only the first is a reason to run the ceremony again.
        approved: Option<Vec<CapabilityGrant>>,
        /// `approved`, rendered. Empty when `approved` is `None`.
        approved_display: Vec<String>,
        /// The signed envelopes backing this app's grants, if any.
        ///
        /// Separate from `approved` because they answer different questions: the
        /// approval is the user's decision, an envelope is the attestation that
        /// their key endorsed it. A bundled app has the first and not the second.
        envelopes: Vec<AppGrantEnvelope>,
    },
    /// The app was uninstalled and all its data removed.
    AppUninstalled,

    /// Answer to `MessageChannelCreate`: a channel was created and its key granted
    /// to the creator.
    ///
    /// Echoes the channel id back rather than returning the key-grant record id.
    /// The previous shape reused `MessageSent { message_id }`, so the obvious
    /// reading — "this is the channel" — was wrong, and using it as one failed
    /// later with a misleading *"you may not be a member of this channel."*
    ChannelCreated {
        channel_did: String,
    },

    // ── Confined extensions (RFC-0049 / RFC-0050) ─────────────────────────────
    /// An extension was installed and its grants minted.
    ExtensionInstalled {
        extension_id: String,
        name: String,
        /// `"fetcher"` | `"storage-backend"` — the WIT world it runs against.
        class: String,
        /// BLAKE3 hex, computed by the daemon from the bytes.
        content_hash: String,
        /// `false` when the package carried no publisher signature. A fact to
        /// surface, not an error (RFC-0013: provenance is shown, not gated).
        signed: bool,
        /// The exact lines shown to the user before consent, so a caller cannot
        /// render a softer version than the one the daemon enforced.
        consent_summary: Vec<String>,
    },
    /// Installed extensions on this device.
    ExtensionList {
        extensions: Vec<InstalledExtension>,
    },
    /// The extension was removed and its grants revoked.
    ExtensionRemoved {
        extension_id: String,
    },
    /// Answer to `AppVerify`: the re-hashed binary compared against the stored hash.
    AppVerifyResult {
        app_id: String,
        /// Stored BLAKE3 hash (64 hex chars).
        stored_hash: String,
        /// Freshly computed BLAKE3 hash of the on-disk binary (64 hex chars).
        computed_hash: String,
        /// `true` if `stored_hash == computed_hash`.
        matches: bool,
    },

    // -- Trust registry + grant management (Step 8) -------------------------
    /// An org DID was added to the trusted-issuer registry.
    TrustAdded,
    /// An org DID was removed from the trusted-issuer registry.
    TrustRemoved,
    /// The list of trusted-issuer DIDs for this user.
    TrustedIssuers {
        dids: Vec<String>,
    },
    /// An envelope ID was added to the local revocation list.
    GrantRevoked,
    /// A cross-DID `GrantEnvelope` was verified and stored.
    GrantImported {
        /// The `GrantEnvelope.id` that was stored.
        envelope_id: String,
    },

    // -- Org identity Ã¢â‚¬â€ single-key (Step 9) ---------------------------------
    /// A new org identity was created.
    OrgCreated {
        /// The `did:key:Ã¢â‚¬Â¦` of the new org.
        org_did: String,
    },
    /// Metadata for a single org identity.
    OrgInfo {
        org_did: String,
        name: String,
        owner_did: String,
        created_at: i64,
    },
    /// The list of org identities owned by this user.
    OrgList {
        orgs: Vec<OrgEntry>,
    },
    /// A `GrantEnvelope` was issued by the org. The full JSON is returned so
    /// the caller can deliver it to the member out-of-band.
    OrgGrantIssued {
        envelope_id: String,
        /// Full JSON serialisation of the signed `GrantEnvelope`.
        envelope_json: String,
    },
    /// The list of grants issued by an org.
    OrgGrantList {
        grants: Vec<OrgGrantEntry>,
    },
    /// All outstanding envelopes for the member were revoked.
    OrgMemberRemoved {
        /// Number of envelopes that were revoked.
        revoked_count: u32,
    },
    /// A root owned by an org was created. Answer to `OrgRootCreate`.
    OrgRootCreated {
        /// The new root's id — what `OrgRootInvite` and the record verbs' `root` name.
        root: String,
        /// The identity that owns it: the org, and never the person who asked.
        owner: String,
        /// How `org.invite` on the root reached the person.
        delegation: OrgRootDelegation,
    },
    /// A member was admitted to a root an org owns. Answer to `OrgRootInvite`.
    OrgRootInvited {
        /// The identity admitted.
        member: String,
        /// `true` when they were not already a member.
        added: bool,
        /// The membership grant, as JSON: a `MembershipGrant` — the envelope that admits
        /// them, and the `org.invite` it was issued under.
        grant_json: String,
    },

    // -- Org identity Ã¢â‚¬â€ FROST multi-sig (Step 10) ----------------------------
    /// A FROST org was created. Answer to `OrgFrostNew`.
    ///
    /// The initiator must securely deliver `shares[i].1` to participant `i+2`
    /// (1-based index). Share at index 0 is for participant 2, etc.
    OrgFrostCreated {
        /// The `did:key:Ã¢â‚¬Â¦` of the new org.
        org_did: String,
        /// Key share blobs for non-initiator participants.
        /// Each entry is `(participant_idx, key_package_hex)`.  Index starts at 2.
        /// The initiator's share (index 1) is already stored in the daemon.
        shares: Vec<(u16, crate::ipc::vault_request::SecretText)>,
    },
    /// A participant successfully joined a FROST org. Answer to `OrgFrostJoin`.
    OrgFrostJoined {
        /// The `did:key:Ã¢â‚¬Â¦` of the joined org.
        org_did: String,
    },
    /// A FROST signing session was initiated. Answer to `OrgFrostSignBegin`.
    ///
    /// The coordinator prints `session_id`, `message_hex`, `my_id_hex`, and
    /// `my_commitment_hex` and shares them with a co-signer so they can
    /// contribute (see `OrgFrostSignContribute`).
    OrgFrostSignSession {
        /// Opaque session identifier.
        session_id: String,
        /// Raw bytes to be signed (hex-encoded).  Needed by the co-signer.
        message_hex: String,
        /// Coordinator's FROST `Identifier` (hex).  Needed by the co-signer.
        coordinator_id_hex: String,
        /// Coordinator's round-1 commitment (hex).  Needed by the co-signer.
        coordinator_commitment_hex: String,
    },
    /// A co-signer completed their contribution. Answer to `OrgFrostSignContribute`.
    ///
    /// Return `cosigner_id_hex`, `cosigner_commitment_hex`, and
    /// `cosigner_share_hex` to the coordinator so they can finalise (see
    /// `OrgFrostSignFinalize`).
    OrgFrostContributed {
        /// Co-signer's FROST `Identifier` (hex).
        cosigner_id_hex: String,
        /// Co-signer's round-1 commitment (hex).
        cosigner_commitment_hex: String,
        /// Co-signer's round-2 signature share (hex).
        cosigner_share_hex: crate::ipc::vault_request::SecretText,
    },
    /// The FROST signing ceremony completed and the grant was issued.
    /// Answer to `OrgFrostSignFinalize`.
    OrgFrostSigned {
        /// The `GrantEnvelope.id` of the newly issued grant.
        envelope_id: String,
        /// Full JSON serialisation of the signed `GrantEnvelope`.
        envelope_json: String,
    },

    AppList {
        apps: Vec<InstalledApp>,
    },
    /// Answer to `AppGetRole`: the app ID registered for a named system role.
    AppRole {
        role: String,
        app_id: String,
    },
    /// A role assignment was written successfully.
    AppRoleSet {
        role: String,
        app_id: String,
    },
    /// The app was launched successfully.
    AppLaunched {
        app_id: String,
        /// Element tree patches committed via `surface::commit` during `on_launch`.
        /// Each patch is a versioned binary blob; format version 0x00 = raw JSON message.
        #[serde(default)]
        patches: Vec<Vec<u8>>,
    },
    /// No app with the given `app_id` is installed on this device. Answer to
    /// `AppGetRole` when no app holds the role, among other app verbs.
    AppNotFound {
        app_id: String,
    },
    /// The bundle path for an installed app.
    ///
    /// `bundle_path` is `None` if the app has no web bundle (WASM-only).
    AppBundlePath {
        app_id: String,
        bundle_path: Option<String>,
    },
    /// The app bundle was registered successfully.
    AppBundleRegistered {
        app_id: String,
    },
    /// The `on-message` export was called; contains any surface patches
    /// committed by the app during the handler.
    AppMessageDelivered {
        /// Element tree patches committed via `surface::commit` during the handler.
        #[serde(default)]
        patches: Vec<Vec<u8>>,
    },

    // -- Event log (v0.7) -------------------------------------------------
    /// Query results from the event log.
    EventList {
        events: Vec<EventEntry>,
    },
    /// Answer to `SubscribeEvents`: a single live event of its stream. The
    /// connection receives one frame per matching event.
    EventStream {
        event: EventEntry,
    },
    /// The server is closing the subscription stream (daemon shutdown, etc.).
    /// After receiving this the client should drop the connection.
    EventStreamEnd,
    /// HMAC integrity chain verification result.
    EventLogIntegrity {
        /// `true` if every chained row's stored HMAC matches the recomputed value.
        ok: bool,
        /// Unix timestamp of the first row where the chain broke, if any.
        first_broken_at: Option<u64>,
    },

    // -- Daemon health (M22b) -------------------------------------------------
    /// Answer to `DaemonStatus`: a live snapshot of daemon state.
    DaemonStatusInfo {
        /// Daemon binary version.
        version: String,
        /// Seconds since the daemon process started.
        uptime_secs: u64,
        /// Number of active user sessions.
        user_count: u32,
        /// Number of installed apps.
        app_count: u32,
        /// Total events persisted in `events.db`.
        event_count: u64,
        /// Events with `level = 'error'` in the last 24 hours.
        error_count: u64,
        /// Seconds since the most recent event (0 if no events).
        last_event_secs_ago: u64,
    },

    // -- Device sync responses (RFC-0008) -------------------------------------
    /// Answer to `SyncAvailable` or `RecordSyncAvailable`: the daemon has
    /// acknowledged the notification and has woken its sync engine.
    SyncAck,

    /// Answer to [`crate::UserRequest::FrostSignRound`]: one round of a
    /// distributed FROST signing ceremony. `payload` is the JSON-serialised
    /// runtime `FrostRoundReply` (a commitment for round 1, a signature share for
    /// round 2).
    FrostSignReply {
        payload: String,
    },

    /// Answer to [`crate::UserRequest::ThresholdSign`]: the aggregate
    /// threshold signature as lowercase hex (64 bytes), verifiable as a standard
    /// Ed25519 signature under the group (identity) DID.
    ThresholdSigned {
        signature_hex: String,
    },

    // -- VFS watch subscription (RFC-0017) ------------------------------------
    /// Answer to [`crate::UserRequest::VfsWatch`], the first frame of its stream:
    /// the watch is **established**, and a change made from here on is delivered.
    ///
    /// Without it a subscriber cannot tell "nothing has changed yet" from "the
    /// watch is not up yet", so a write made straight after subscribing can
    /// vanish with no error and no way to detect the loss. That is every
    /// client's race, not only a test's — `ksyncd` subscribes and then trusts
    /// the stream for the life of the daemon.
    VfsWatchReady,
    /// The watch could **not** be established, and no change will ever arrive on
    /// this stream.
    ///
    /// Distinct from [`Self::VfsWatchEnd`] on purpose. `VfsWatchEnd` means *the
    /// daemon is going away*, and a client's correct answer to it is to stop. A
    /// watcher that never registered — inotify instance exhaustion is the
    /// observed case — is a different fact with a different answer: the daemon is
    /// fine and the client should keep doing whatever it does without a watch. A
    /// sidecar told only `VfsWatchEnd` exits and takes its fallback poll with it,
    /// and restarting lands it in the same immediate end.
    VfsWatchFailed {
        /// Why registration failed, as the watcher reported it. The same text its
        /// `error!` line carries, sent to the one party that cannot read the log.
        reason: String,
    },
    /// Answer to [`crate::UserRequest::VfsWatch`]: a filesystem change its stream delivers.
    VfsChanged {
        /// Absolute VFS path of the changed file or directory.
        path: String,
        /// The kind of change that occurred.
        kind: VfsChangeKind,
        /// Unix timestamp (seconds) when the change was observed.
        timestamp_secs: u64,
    },
    /// Answer to [`crate::UserRequest::VfsWatch`], its last frame: the daemon is
    /// closing the subscription (daemon shutdown or internal error). After
    /// receiving this the client should drop the connection.
    VfsWatchEnd,

    // -- Runtime inspection (runtime_inspection sprint) -----------------------
    /// Snapshot of all sidecar processes. Answer to `DaemonSidecars`.
    DaemonSidecarsResult {
        sidecars: Vec<crate::ipc::types::SidecarInfo>,
    },
    /// Snapshot of all authenticated IPC sessions. Answer to `IpcSessions`.
    IpcSessionsResult {
        sessions: Vec<crate::ipc::types::IpcSessionInfo>,
    },

    // -- Network status (net_status sprint) -----------------------------------
    /// Answer to [`crate::UserRequest::SyncStatus`]: the sync state summary.
    SyncStatusResult(crate::ipc::types::SyncStatusResult),
    /// Answer to [`crate::UserRequest::NetworkStatus`]: the aggregated network status.
    NetworkStatusResult {
        peers: Vec<crate::ipc::types::PeerStatus>,
        quic_gateway: crate::ipc::types::GatewaySummary,
        http_gateway: crate::ipc::types::GatewaySummary,
        rendezvous_url: Option<String>,
        /// Whether this node is reachable through that relay now (RFC-0083 R6).
        relay: crate::ipc::types::RelayReadout,
        sync: crate::ipc::types::SyncStatusResult,
    },
    /// Answer to [`crate::UserRequest::ReachStatus`]: the relay readout alone.
    ReachStatusResult {
        relay: crate::ipc::types::RelayReadout,
    },

    // -- Display server / kuid sidecar (RFC-0018) -----------------------------
    /// Acknowledgement that a `SurfaceOpen`, `SurfaceCommit`, `SurfaceClose`,
    /// or `SurfaceResize` was processed successfully.
    SurfaceOk,
    /// Input event from the compositor to be routed to a WASM component.
    /// Sent by `kuid` back to `kuserd` after a keyboard or pointer event.
    SurfaceInputEvent {
        app_id: String,
        event: crate::ipc::types::InputEventPayload,
    },
    /// The user closed a surface window (e.g. clicked the close button).
    /// Sent by `kuid` back to `kuserd` to trigger app teardown.
    SurfaceClosed {
        app_id: String,
    },
}

/// The vault's refusal of an invite naming `user_id`, a pool it keeps
/// ([`UserResponse::VaultKeepsAlready`]), in the one sentence every reader
/// that refuses on it says.
pub fn vault_keeps_already_said(user_id: &str) -> String {
    format!(
        "this vault already keeps for '{user_id}' — an invite admits someone new, so it takes a name nobody holds \
         here; their own devices need none"
    )
}

/// What a reader of an operated vault's or relay's answer says of an answer
/// it does not act on: anything but the one its verb asked for (and, for an
/// invite or a join at the vault's door, the ceremony's own frames). The
/// vault's own words where the answer carries them — an `Error`'s message,
/// [`vault_keeps_already_said`] — and otherwise the answer's name, never its
/// fields. The name is said without naming who answered: the same words
/// serve a relay's answer and a vault's, and the reader's own word (`relay:`,
/// `vault:`) says which.
///
/// **This says; it does not decide** (#114, #121). Each reader acts only on
/// the answer it asked for and stops on anything else, so an answer a release
/// adds is never misread as leave to go on: it is said here by its name
/// until it is given a sentence, and then said in it by every reader at once.
/// The readers that say through this: `kvaultd invite` and `kvaultd join` at
/// the vault's door; six of a guest's landlord verbs, through `kuserd`'s
/// `occupant_host::answered!` — `landlord.invite`, `landlord.people`,
/// `landlord.drop-pool`, `landlord.rule`, `landlord.set-rule` and
/// `landlord.move-vault` (not `landlord.enrol`, which reads through
/// `door::enrolled`, #139; `landlord.resolve` reads no answer); and the shell's
/// verbs said to an operated vault or relay (`operated::spoken`).
pub fn answer_said(answer: &UserResponse) -> String {
    match answer {
        UserResponse::Error { message } => message.clone(),
        UserResponse::VaultKeepsAlready { user_id } => vault_keeps_already_said(user_id),
        unsaid => format!(
            "the answer was `{}`, which this release has no sentence for; nothing more was asked of it",
            unsaid.name()
        ),
    }
}

impl UserResponse {
    /// The variant's name and nothing of its fields: the leading word of its
    /// derived `Debug`, which is the variant's identifier. Nothing past that
    /// word is kept, and a secret field prints redacted in `Debug` anyway.
    fn name(&self) -> String {
        let printed = format!("{self:?}");
        printed
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default()
            .to_string()
    }
}

/// A handler's error, as the frame a door answers it with
/// (`kotton_ipc::ChannelAcceptor` requires this of every `Resp` it serves).
/// The text is the error's own; the door closes the connection after it.
impl From<std::io::Error> for UserResponse {
    fn from(e: std::io::Error) -> Self {
        UserResponse::Error {
            message: e.to_string(),
        }
    }
}

/// The kind of filesystem change delivered by a [`crate::UserRequest::VfsWatch`] stream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VfsChangeKind {
    Created,
    Modified,
    Deleted,
}

#[cfg(test)]
mod answer_said_tests {
    use super::{answer_said, vault_keeps_already_said, UserResponse};
    use crate::ipc::SecretText;

    /// **An answer a reader does not act on is said in the vault's words where
    /// it carries them, and otherwise by its name alone** (#114): never a
    /// debug print of its fields, which for an answer a release adds may hold
    /// what is not to be printed.
    #[test]
    fn an_answer_is_said_in_the_vaults_words_or_by_its_name_alone() {
        assert_eq!(answer_said(&UserResponse::Error { message: "no relay".into() }), "no relay");
        assert_eq!(
            answer_said(&UserResponse::VaultKeepsAlready { user_id: "sam".into() }),
            vault_keeps_already_said("sam")
        );
        let full = answer_said(&UserResponse::VaultFull { held: 17, quota: 9 });
        assert!(full.starts_with("the answer was `VaultFull`,"), "{full}");
        assert!(!full.contains("17") && !full.contains('{'), "fields were printed: {full}");
        let unit = answer_said(&UserResponse::NoActiveSession);
        assert!(unit.starts_with("the answer was `NoActiveSession`,"), "{unit}");
        let secret = answer_said(&UserResponse::PairAdvertising {
            code: SecretText::new("kotton-invite:vault:the-words"),
            expires_at: 1,
        });
        assert!(secret.starts_with("the answer was `PairAdvertising`,") && !secret.contains("the-words"), "{secret}");
    }
}

#[cfg(test)]
mod unlock_ok_tests {
    use super::UserResponse;

    /// **An `UnlockOk` from a daemon that predates `repair` reads as "no repair
    /// ran", not as "a repair wrote nothing".** The two must stay apart: the
    /// second tells the owner every key matched their vault, which an old
    /// daemon never checked
    /// (`TASK-a-keychain-entry-that-fails-permanently-has-no-repair-verb-and-lockedby-says-it-is-recoverable`).
    #[test]
    fn an_unlock_ok_without_repaired_is_no_repair_and_an_empty_one_is_nothing_written() {
        let old: UserResponse = serde_json::from_str(r#"{"UnlockOk":{"session_token":"t"}}"#).unwrap();
        assert!(matches!(old, UserResponse::UnlockOk { repaired: None, .. }), "{old:?}");
        let none_written: UserResponse =
            serde_json::from_str(r#"{"UnlockOk":{"session_token":"t","repaired":[]}}"#).unwrap();
        assert!(
            matches!(&none_written, UserResponse::UnlockOk { repaired: Some(v), .. } if v.is_empty()),
            "{none_written:?}"
        );
        let plain = serde_json::to_string(&UserResponse::UnlockOk { session_token: crate::ipc::SecretText::new("t"), repaired: None }).unwrap();
        assert_eq!(plain, r#"{"UnlockOk":{"session_token":"t"}}"#, "a plain unlock serialises as before");
    }
}

#[cfg(test)]
mod pair_advertising_tests {
    use super::UserResponse;
    use crate::ipc::SecretText;

    /// **What a ceremony hands the person never prints**
    /// (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`):
    /// a vault's invite carries its words and its relay's *invited* admission
    /// key, so `PairAdvertising`'s derived `Debug` shows the code as
    /// `<redacted>`, and the wire carries the plain string it carried before.
    #[test]
    fn an_advertised_code_is_redacted_in_debug_and_plain_on_the_wire() {
        let invite = format!(
            "kotton-invite:vault:{}:fame-cheap-unfold:{}:{}@http://relay.example:7700",
            "cd".repeat(32),
            "ab".repeat(32),
            "01".repeat(32)
        );
        let frame = UserResponse::PairAdvertising { code: SecretText::new(invite.clone()), expires_at: 7 };
        let printed = format!("{frame:?}");
        assert!(!printed.contains("fame-cheap-unfold") && !printed.contains(&"01".repeat(32)), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
        let wire = serde_json::to_string(&frame).unwrap();
        assert_eq!(wire, format!(r#"{{"PairAdvertising":{{"code":"{invite}","expires_at":7}}}}"#));
        let back: UserResponse = serde_json::from_str(&wire).unwrap();
        assert!(matches!(back, UserResponse::PairAdvertising { ref code, expires_at: 7 } if code.expose() == invite));
    }
}

#[cfg(test)]
mod secret_debug_tests {
    //! **No secret an answer hands back prints through `Debug`**: the
    //! recovery phrase `AddRecoveryPhrase` returns, the FROST key shares and
    //! signature share the org ceremony returns, every session token and the
    //! ceremony token are `SecretText`, and the device's signing seed is
    //! `SecretBytes` — what it was on the wire, `<redacted>` in a `{:?}`.

    use super::UserResponse;
    use crate::ipc::{SecretBytes, SecretText};
    use crate::peer::PairedNode;
    use crate::did::Did;

    /// `value` prints `<redacted>` and none of `secrets`, and its JSON still
    /// carries every one of them as it was written.
    fn hides(value: &UserResponse, secrets: &[&str]) {
        let printed = format!("{value:?}");
        let wire = serde_json::to_string(value).unwrap();
        for secret in secrets {
            assert!(!printed.contains(secret), "{secret:?} prints in {printed}");
            let on_wire = serde_json::to_string(secret).unwrap();
            assert!(wire.contains(&on_wire), "{secret:?} is not on the wire as written: {wire}");
        }
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    #[test]
    fn no_response_prints_a_secret_it_hands_back() {
        let phrase = "quartz mango trumpet velvet orbit lunar cactus whisper";
        hides(
            &UserResponse::RecoveryPhraseAdded { recovery_key: SecretText::new(phrase), copies_delivered_to: vec![] },
            &[phrase],
        );
        let (two, three) = ("5ec2e75a".repeat(8), "7a3e5ec2".repeat(8));
        hides(
            &UserResponse::OrgFrostCreated {
                org_did: "did:key:z6Mk".into(),
                shares: vec![(2, SecretText::new(two.clone())), (3, SecretText::new(three.clone()))],
            },
            &[&two, &three],
        );
        let signature_share = "c05e1a7e".repeat(8);
        hides(
            &UserResponse::OrgFrostContributed {
                cosigner_id_hex: "02".into(),
                cosigner_commitment_hex: "ab".into(),
                cosigner_share_hex: SecretText::new(signature_share.clone()),
            },
            &[&signature_share],
        );
    }

    #[test]
    fn no_response_prints_a_session_or_ceremony_token_it_hands_back() {
        let token = "5e55104d7c3b9a01e2f4";
        let t = || SecretText::new(token);
        hides(
            &UserResponse::UserCreated { did: "did:key:z6Mk".into(), device_fingerprint: "fp".into(), session_token: t() },
            &[token],
        );
        hides(
            &UserResponse::LoginSuccessful { user_id: "alice".into(), device_fingerprint: "fp".into(), session_token: t() },
            &[token],
        );
        hides(&UserResponse::UnlockOk { session_token: t(), repaired: None }, &[token]);
        hides(&UserResponse::PrincipalSession { token: t() }, &[token]);
        hides(&UserResponse::PairShowCode { token: t(), sas: 123_456, peer_label: None }, &[token]);
        let node = PairedNode {
            id: "laptop".into(),
            device_did: Did::new("key", "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            public_key: [1u8; 32],
            paired_at: 1_700_000_000,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };
        hides(&UserResponse::PairingComplete { node, session_token: Some(t()), relay_offer: None }, &[token]);
    }

    /// The seed `GetDeviceCert` returns prints `<redacted>`, and crosses as the
    /// JSON array of bytes it was.
    #[test]
    fn a_device_signing_seed_is_redacted_in_debug_and_plain_on_the_wire() {
        let seed: Vec<u8> = (0xa0..0xc0).collect();
        let cert = UserResponse::DeviceCert { signing_key_bytes: SecretBytes::new(seed.clone()) };
        let printed = format!("{cert:?}");
        assert!(!printed.contains("160") && printed.contains("<redacted>"), "{printed}");
        let wire = serde_json::to_value(&cert).unwrap();
        assert_eq!(wire["DeviceCert"]["signing_key_bytes"], serde_json::json!(seed));
        let back: UserResponse = serde_json::from_value(wire).unwrap();
        assert!(matches!(back, UserResponse::DeviceCert { ref signing_key_bytes } if signing_key_bytes.expose() == seed));
    }
}


#[cfg(test)]
mod drive_answer_tests {
    use super::UserResponse;

    /// **Only the move answers a refused-key count** (kotton #314): create,
    /// list and show answer `Drives`, which carries the descriptors and
    /// nothing a move fills, and a `Drives` written without `keys_refused`,
    /// as every daemon before kotton #274 wrote it, decodes (kotton #313).
    #[test]
    fn a_drives_answer_carries_no_refused_count_and_decodes_without_one() {
        let wire = serde_json::to_string(&UserResponse::Drives { drives: vec![] }).unwrap();
        assert_eq!(wire, r#"{"Drives":{"drives":[]}}"#);
        let recorded: UserResponse = serde_json::from_str(r#"{"Drives":{"drives":[]}}"#).unwrap();
        assert!(matches!(recorded, UserResponse::Drives { ref drives } if drives.is_empty()), "{recorded:?}");
    }

    /// **A move's answer says how many keys it refused, or it is not a move's
    /// answer.** `keys_refused` has no default: a `DriveMoved` without it does
    /// not decode as "none refused", which would tell the person every listed
    /// key was carried when the daemon never said so.
    #[test]
    fn a_drive_moved_answer_carries_its_count_and_does_not_decode_without_it() {
        let wire = serde_json::to_string(&UserResponse::DriveMoved { drives: vec![], keys_refused: 2 }).unwrap();
        assert_eq!(wire, r#"{"DriveMoved":{"drives":[],"keys_refused":2}}"#);
        let back: UserResponse = serde_json::from_str(&wire).unwrap();
        assert!(matches!(back, UserResponse::DriveMoved { keys_refused: 2, .. }), "{back:?}");
        assert!(serde_json::from_str::<UserResponse>(r#"{"DriveMoved":{"drives":[]}}"#).is_err());
    }
}
