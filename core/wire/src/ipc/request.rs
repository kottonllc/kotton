// SPDX-License-Identifier: AGPL-3.0-or-later
//! User-facing IPC request types.
//!
//! **Adding a variant?** Put it under the section comment for its *domain* rather than at
//! the end of the enum, and keep its `required_trust()` arm and `REMOTE_ELIGIBLE`
//! membership accurate. Device-scoped verbs belong in
//! [`crate::sys_ipc::DeviceRequest`], not here — different principal, different
//! enforcement.
//!
//! See `ADVISORY.md` in the repo root for why, and for the rest of the list.
//!
//! ## Authentication — who may speak on this channel
//!
//! Stated here per RFC-0082 rule 6, because a channel whose mechanism is only
//! inferable is one nobody can review.
//!
//! `UserRequest` is the wire type for the **`kuserd-{did_short}` socket**. A
//! connection begins unauthenticated and may send only `Authenticate` and
//! `CallerInfo`; `Authenticate` exchanges a session token for a connection
//! session carrying three things, and everything else is decided from them:
//!
//! | | what it decides | where it comes from |
//! |---|---|---|
//! | `origin` | the trust floor — a `Remote` connection cannot reach a `Local`-tier verb | bound from the credential at `Authenticate` |
//! | `scope` | an allow-list of variant names | **supplied by the caller**; `None` means no restriction |
//! | `principal` | whether this is a disarmed deputy (RFC-0043 P1), which may only mint | the token's registration |
//!
//! **Two properties of `scope` are worth knowing before relying on it.** It is
//! *client-declared* — a caller narrowing itself, which is worth having and is
//! not authority the system withheld. And it is *not monotonic*: `UnlockWithPin`
//! replaces the connection's session with `scope: None` while preserving `origin`
//! and `principal`, so a narrowed connection can widen again.
//!
//! **What is not checked:** who the connecting process is. The socket takes the
//! caller's word, and any process that can open it and present a token is
//! indistinguishable from any other. `TASK-sockets-take-the-callers-word-for-who-it-is`
//! carries the peer-credential work (`SO_PEERCRED` / `getpeereid`) that would
//! change that.
//!
//! Remote callers do not arrive here directly. `khttpd` and `kquicd` decode
//! [`crate::ipc::remote_request::RemoteRequest`] — the remote-eligible half — and
//! forward, so a `Local`-tier variant is not something they can construct.

use super::{ImportFormat, LockMode, SyncChangesetRow, SyncDirection};
use kotton_schemas::CapabilityGrant;
use crate::peer::SessionPermissions;
use crate::remote::RemoteBackend;
use serde::{Deserialize, Serialize};

/// Requests sent to the system daemon over IPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRequest {
    // -- User lifecycle --------------------------------------------------------
    CreateUser {
        user_id: String,
        /// The daily unlock credential, assessed and sealed by `create_user`.
        ///
        /// Not optional. It rode on `SetLockPolicy` as a second, later call
        /// until 2026-08-29, which meant the two CLI paths never made it and
        /// minted identities protected by nothing. A credential that arrives
        /// with the request cannot be the step somebody skipped.
        passphrase: crate::ipc::vault_request::SecretText,
    },
    /// Give this identity a recovery phrase — the "set up recovery" action.
    ///
    /// Separate from `CreateUser` because creation mints no phrase: an identity is
    /// born with a random key and no recovery authority, so first run asks for
    /// nothing. This is what a person does afterwards, when they want a way back
    /// in. It **grows** the committed recovery set and can never shrink it, which
    /// is why it is safe to authorize with the key already on the device.
    AddRecoveryPhrase {
        user_id: String,
    },
    LogoutUser {
        user_id: String,
    },
    LoginWithRecoveryKey {
        recovery_key: crate::ipc::vault_request::SecretText,
        device_name: Option<String>,
        /// Required when the user isn't already registered on this device.
        /// Ignored if the DID is already in the local registry.
        user_id: Option<String>,
    },
    /// Rotate the user's operational identity key via a **mnemonic recovery
    /// rotation** (RFC-0038 — survive key compromise). Reveals the pre-committed
    /// reserve key, installs a fresh key, and appends the rotation to the KEL; the
    /// `did:kel` AID is unchanged. Local operator action only (`Local` trust tier).
    ///
    /// Carries the daily credential for the reason [`UserRequest::BindDeviceHardware`]
    /// does: the vault is the durable copy of the person's roots, a rotation changes
    /// one of them, and re-sealing it under the credential cannot be done without
    /// the credential — custody holds the roots, never the credential or the key
    /// derived from it. A person with a vault who sends `None` is refused before
    /// anything changes (`TASK-a-rotation-leaves-the-pin-vault-holding-the-key-it-retired`).
    RotateIdentity {
        user_id: String,
        recovery_key: crate::ipc::vault_request::SecretText,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential: Option<crate::ipc::vault_request::SecretText>,
    },
    /// Take the account back on a device that holds nothing but the phrase
    /// (`RFC-0081`, the ruling on `IDEA-what-a-phrase-login-should-rotate`).
    ///
    /// `LoginWithRecoveryKey` is non-destructive and stays that way: on a device
    /// that has never held the identity it only *claims* a locked slot. This is
    /// the verb that makes the claim good. It asks the user's paired nodes for
    /// the identity's public chain and phrase-sealed recovery copy, proves the
    /// phrase against the chain, installs the data roots, and rotates the
    /// identity onto **this device's key** — the rotation is what every node then
    /// admits the device on. Local operator only, with the phrase in hand.
    ///
    /// `passphrase` is the one the person chose for this device, read at the
    /// terminal before the recovery began: the recovered roots are sealed under
    /// it, and the lock policy set to it, before the answer, so a recovered
    /// device is never held without a sealed copy.
    Recover {
        user_id: String,
        recovery_key: crate::ipc::vault_request::SecretText,
        passphrase: crate::ipc::vault_request::SecretText,
    },
    ListUsers,

    // -- Session auth ---------------------------------------------------------
    /// Authenticate this connection with a session token returned by
    /// `CreateUser` or `LoginWithRecoveryKey`.
    ///
    /// `scope` is an optional allow-list of `UserRequest` variant names
    /// (e.g. `["ReadFile", "WriteFile"]`). When present and non-empty,
    /// `kuserd` will reject any request whose variant is not in this list
    /// with `UserResponse::NotInScope`. A `None` or empty scope means full
    /// access: what `kotton-client` asks for, and the CLI through it, and what
    /// `kquicd` asks for when it mints a session for a peer it authenticated
    /// and when it forwards a remote request. `kquicd`'s own administrative
    /// connection and its refresh of the authorized keys ask for a scope.
    /// This is a backwards-compatible addition, callers that omit `scope`
    /// continue to work unchanged.
    Authenticate {
        token: crate::ipc::SecretText,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Vec<String>>,
    },
    /// Return diagnostic information about the calling process and the
    /// current connection's session state.
    CallerInfo,
    /// Return the `user_id` bound to the current session, if any.
    GetActiveSession,
    /// Invalidate the current session token for this connection.
    LockSession,

    // -- Fs: VFS operations, placed by path -----------------------------------
    // The caller names a path; the node decides which store it lands in, via
    // `UserStorageRouter` and the user's `storage-mounts.toml` (RFC-0058).
    // Naming a store is an operator act, not something every file call carries.
    ReadFile {
        user_id: String,
        path: String,
        /// Byte offset to start reading from. A large file exceeds the IPC frame
        /// cap, so it is read as a sequence of ranges (RFC-0048).
        offset: u64,
        /// Maximum bytes to return; the response carries `total_size`.
        length: u32,
    },
    WriteFile {
        user_id: String,
        path: String,
        /// One chunk of the file (base64 on the wire), starting at `offset`.
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
        /// Byte offset this chunk begins at; `0` starts (or restarts) the write.
        offset: u64,
        /// Total size of the whole file; the receiver commits when its buffer
        /// reaches this.
        total_size: u64,
        /// BLAKE3 of the whole file, hex — keys the reassembly buffer and is
        /// verified before the file is written (RFC-0048).
        content_hash: String,
    },
    ListFiles {
        user_id: String,
        prefix: String,
    },
    DeleteFile {
        user_id: String,
        path: String,
    },
    /// Paths holding a version that lost a concurrent write, with each retained
    /// version's content id (RFC-0071 R3).
    ///
    /// Replication keeps the losing write rather than destroying it. Without
    /// this the retention is real and invisible: the bytes survive and nobody
    /// can be told they exist.
    ListConflicts {
        user_id: String,
    },
    /// Settle the conflict on `path`, releasing what was retained for it.
    ///
    /// `keep` names a retained version to promote — its bytes are written at
    /// `path` as an ordinary new version, so the resolution enters the history
    /// as a write naming what it superseded. `None` keeps the current version.
    ///
    /// Remote-eligible for the same reason `DeleteFile` is: everything it does
    /// is recorded and recoverable. It chooses between versions the user wrote;
    /// it erases neither.
    ResolveConflict {
        user_id: String,
        path: String,
        /// Content id of the retained version to promote, or `None` to keep the
        /// current one.
        keep: Option<String>,
    },
    /// Erase a path **and its entire history** (RFC-0047 `purge`).
    ///
    /// **Local-origin only, and deliberately unlike `DeleteFile`.** A delete is
    /// recorded as a fact and the content stays recoverable; purge removes the
    /// record, which is precisely what makes a generous retention default safe
    /// to offer. It is the one file operation with no way back, so it is not
    /// reachable from a browser gateway or a peer — the same reasoning that
    /// keeps `UnlockWithPin` local.
    PurgeFile {
        user_id: String,
        path: String,
    },

    /// Exchange evidence about a third party for a session **minted for that
    /// party** (RFC-0043).
    ///
    /// The only operation a gateway's bootstrap token may invoke. A gateway holds
    /// no authority of its own beyond the right to ask for one on someone's
    /// behalf, so a compromised gateway inherits the principals currently
    /// connected rather than the whole account.
    MintPrincipalSession {
        user_id: String,
        evidence: PrincipalEvidence,
    },

    /// One frame of a browser's sealed channel (RFC-0078 GW3), relayed by
    /// `khttpd` byte-for-byte. The daemon runs the RFC-0040 ceremony on the far
    /// end (`kotton_pair::browser::Issuer`): four cleartext handshake frames, then
    /// ciphertext the gateway cannot open. Once established, each frame carries
    /// one `UserRequest` the daemon dispatches **as the browser** — the principal
    /// bound to the channel — and the reply comes back sealed in
    /// `UserResponse::BrowserFrame`.
    ///
    /// The only verb `khttpd` speaks. It carries no `user_id`: the gateway's
    /// bootstrap token — or, for a gateway reached through the relay, its paired
    /// key's posture (`Posture::Gateway`) — names the user it serves.
    BrowserFrame {
        /// The frame, base64 on the wire.
        #[serde(with = "crate::base64_bytes")]
        bytes: Vec<u8>,
        /// Which browser this frame belongs to, for a gateway that carries
        /// several over one peer identity. Absent on the local IPC path, where
        /// the connection is the channel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
    },
    /// Enrol a gateway on another machine by the six-digit ceremony (RFC-0078,
    /// RFC-0076). **Streams** like `DeviceAdd`, with the transport reversed: the
    /// gateway printed `code` (its address and the session id) and is listening;
    /// this node dials it, runs the issuer half, and admits it under
    /// `Posture::Gateway` — a device that holds nothing and speaks one verb. The
    /// gateway generates its own key and never gives it up; nothing secret
    /// travels on any path but the ceremony's.
    GatewayEnroll {
        user_id: String,
        /// The code the gateway printed (`khttpd enroll`).
        code: crate::ipc::SecretText,
        /// How long to wait for the ceremony, in seconds.
        ttl_seconds: u64,
    },
    /// Admit a node by the invite it minted (`kvaultd invite`, or a
    /// connection code a node that still listens printed), under `posture`
    /// (RFC-0084 V8). **Streams** like `DeviceAdd`, with the issuer half on
    /// this side: a vault's invite (`kotton-invite:vault:…`, the one code
    /// grammar) is met at its relay once that relay has proved the key the
    /// invite names, and the vault is held to the key it names; a code is
    /// dialled. Only the blind posture is admitted this way — a vault holds no
    /// key. Admitting never sets this device's relay: the last frame offers it
    /// (`PairingComplete.relay_offer`).
    DeviceAdmit {
        user_id: String,
        code: crate::ipc::SecretText,
        ttl_seconds: u64,
        posture: kotton_schemas::membership::Posture,
        /// The vault whose operator credential this person keeps, by the
        /// credential's name, when the invite is one that credential minted
        /// (`vault invite <v> --me`, DEC-0086): the vault that answers must
        /// prove the key the credential pins, and the six digits are confirmed
        /// by that key and never shown.
        /// `None` is every other admit, and asks the person for the digits.
        #[serde(default)]
        operator_of: Option<String>,
    },
    /// Mint an invite and wait to be admitted through the relay
    /// (`DEC-0068`): reserve
    /// under the invite's handle at this node's relay for `ttl_seconds`,
    /// stream the invite (`PairAdvertising { code }` — `kotton-invite:vault:…`), and run
    /// the joiner half when a device dials the relay. Nothing listens on a
    /// public port. The vault's door speaks this (`kvaultd invite`); a device
    /// admits it with `device admit <invite> --blind`.
    DeviceInvite {
        user_id: String,
        ttl_seconds: u64,
        #[serde(default)]
        as_name: Option<String>,
    },

    // -- The landlord's verbs, over the wire (RFC-0084; the operator credential) --
    // `SetQuota`, `Tenants` and `DropTenant` mirror `VaultRequest`'s variants of
    // the same name byte for byte, and with `DeviceInvite` above they are the
    // four verbs a vault answers on its peer transport for **one** connection:
    // one whose key is the vault's operator credential (`PeerStanding::Operator`).
    // A tenant's device can build every one of them and is refused by standing,
    // not by an arm (`kvaultd::peer::reaches`). A device answers none of them.
    /// Set one pool's quota, in bytes, at a vault: the space its landlord sets
    /// aside for one tenant. Answered with the pool's `VaultCapacityResult`.
    SetQuota { user_id: String, quota: u64 },
    /// Every tenant a vault keeps anything for, with the landlord's readout of
    /// each: answered with `VaultTenants`.
    Tenants,
    /// Drop exactly one tenant at a vault — their sealed pool, chain, sealed
    /// recovery copy, pairing and quota. Answered with `TenantDropped`.
    DropTenant { user_id: String },
    /// Tell a vault the whole of its reach set (RFC-0084 V10): the relays it
    /// stands at, each by its key, with an address as a hint and the admission
    /// keys that relay's rule reads. The vault replaces the set it held with
    /// this one, keeps it in its own state so a restart needs no desktop, and
    /// reserves where it says; an empty set is standing nowhere. The first relay
    /// is the one it answers `NodeRelay` with. Said by the desktop that holds
    /// the vault's operator key, on its `enrol` and whenever the set changes —
    /// a relay's rule, a rotated key — and by nobody else: the operator's alone,
    /// like the four above, and a device answers it with a refusal. The keys are
    /// redacted in `Debug`. Answered `Ok`.
    StandAt {
        relays: Vec<crate::rendezvous::Stand>,
    },
    /// The six digits each ceremony an invite for `user_id` is waiting in has
    /// derived, at a vault: what `kvaultd invite` prints on its `sas=` line at
    /// the host, for an invite minted from the desktop under the asking
    /// operator key — never another key's — where
    /// nothing else shows them. The person admitting the invite types them on
    /// their own device, read to them by whoever invited them; the vault keeps
    /// them while the ceremony waits and forgets them when it ends. Said by
    /// the desktop that holds the vault's operator key (`vault digits`), like
    /// the verbs above, and by nobody else. Answered with `InviteDigits`.
    InviteDigits { user_id: String },

    // -- The operator credential, on the desktop's own side --------------------
    /// Mint an operator credential for one service — a vault or a relay —
    /// in this person's own store (DEC-0083, DEC-0087): a new key of its own,
    /// kept sealed (a relay's with its first rule beside it), and waiting for
    /// the service to be said. Answered with `OperatorMinted`, which carries
    /// the public half and nothing else — the service enrols that half at its
    /// terminal, and the secret is never anywhere but this store. Refused for
    /// a name whose credential for that service is already kept; minting again
    /// for one not yet enrolled replaces the key it waited with.
    OperatorMint {
        user_id: String,
        service: crate::ipc::vault_request::OperatedService,
        /// The name the person gives the vault or the relay here; `None`
        /// labels it by its kind's word (`relay`, `vault`), and is refused
        /// while a mint of that kind waits or is kept under that word
        /// (`TASK-mint-prints-the-hosts-install-command-and-is-verb-first`).
        #[serde(default)]
        name: Option<String>,
        /// Who may use the relay, set there when the credential is enrolled.
        /// `None` is *only my devices*. A vault's mint carries none, and is
        /// refused with one: the rule is the relay's.
        #[serde(default)]
        rule: Option<crate::rendezvous::AdmissionRule>,
    },
    /// The keys `OperatorMint` kept and nothing has completed yet, each by
    /// its name, its service and its public half — what a bare `mint` lists.
    /// Answered `OperatorMints`; never a secret.
    OperatorMints { user_id: String },
    /// The names of the instances of `service` this person operates — the
    /// credentials kept for that kind, in the order kept. Read once by an
    /// operating verb typed with no name (`vault people`, `relay rule
    /// only_my_devices`), which is said to the one there is and refused,
    /// listing them, where there are several. Names only: no key, no address.
    /// Answered `OperatorHeld`.
    OperatorHeld {
        user_id: String,
        service: crate::ipc::vault_request::OperatedService,
    },
    /// Forget the operator credential this person keeps for the `service`
    /// called `name`, once its instance no longer stands that key: the
    /// credential, any key minted under that name and not yet completed, a
    /// vault's record of where it was told to stand, and a relay's two
    /// admission keys, which this device stops holding at once. The desktop
    /// first asks the instance as its operator, within the bound every operator
    /// dial has; one that answers as this key's instance is not forgotten, and
    /// the refusal says to destroy it or revoke the key there. One that does
    /// not answer — a host started over — is forgotten, and the answer says so.
    /// A local act: nothing is said to the instance but the asking. Answered
    /// `OperatorForgotten`.
    OperatorForget {
        user_id: String,
        service: crate::ipc::vault_request::OperatedService,
        name: String,
    },
    /// Keep a whole operator credential — the `kotton-operator 2` form, secret
    /// included — as a sealed object in this person's own store. A key minted
    /// here is completed from its instance's line by `OperatorEnrolLines`, not
    /// here. Enrolling a vault's tells it where to stand, and a relay's tells
    /// every vault told nothing yet
    /// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`). Answered
    /// `OperatorEnrolled` — carrying why, when a vault was not told where to
    /// stand, the credential being kept all the same; enrolling a credential
    /// again replaces it.
    OperatorEnrol {
        user_id: String,
        /// Redacted in `Debug`: the file's `operator=` line is a secret key.
        credential: crate::ipc::vault_request::SecretText,
    },
    /// Complete, each on its own, the keys `OperatorMint` kept from the lines
    /// their instances printed when they were created (RFC-0084 V21, V23;
    /// `enrol <line> [<line>…]`,
    /// `TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`).
    /// A line names the instance's kind, where it is reached and its key, and
    /// confers nothing, so it is no secret; it names no mint, so the daemon
    /// finds the one key waiting for its kind, and when several wait it asks
    /// which (`LineCame::Which`) and completes nothing until it is told — the
    /// `mint` on [`LineToEnrol`] is that answer and nothing else. Each instance
    /// is held to its line's key before anything is kept — a relay at its
    /// proof, a vault at the operator dial pinned to it under the minted key,
    /// which it admits only if it was created for it — and a vault is told
    /// where to stand only after. Relays
    /// are completed before vaults, whatever order the lines came in, so a
    /// vault's readout says where it stands. Refused for an instance this
    /// desktop already operates, and for a second instance under a key it
    /// already keeps (V22). Answered `OperatorEnrolledLines`, one readout per
    /// line, in the order given.
    OperatorEnrolLines {
        user_id: String,
        lines: Vec<crate::ipc::vault_request::LineToEnrol>,
    },
    /// Speak one of the landlord's verbs to the vault or the relay named
    /// `name`, under the operator credential this person enrolled for it — the
    /// verb says which service (`OperatorVerb::service`). A vault's verbs go
    /// over the sealed channel a device already uses, a relay's to its
    /// `POST /operator`. `verb` can name nothing else, so this daemon has no
    /// way to send any other request under that key. Answered with what the
    /// service answered.
    AsOperator {
        user_id: String,
        name: String,
        verb: crate::ipc::vault_request::OperatorVerb,
    },

    // -- Sealed replication (RFC-0041) -----------------------------------------
    // Replication primitives, **not** file operations. They bind to the store's
    // sealed view (`SealedObjectAccess`), never to the VFS: `ReadSealed` returns
    // the object exactly as it rests, and `WriteSealed` stores bytes verbatim
    // without sealing them. This is what lets a sync pass move ciphertext
    // between nodes without either side materialising plaintext (B1/B2), so a
    // node whose posture withholds the data keys receives bytes it cannot open.
    //
    // Both are `Remote`-eligible of necessity: a peer link is bound to
    // `ConnTrustOrigin::Remote`, the floor's bottom step, so any higher tier here
    // would block peer sync outright. That costs nothing — they grant no privilege
    // beyond the VFS verbs beside them. `ReadSealed` returns strictly less than
    // `ReadFile` (ciphertext, not plaintext), and a `WriteSealed` caller without
    // the CEK can only write bytes that fail to open: forging an openable blob
    // needs a DEK wrapped under the CEK, and `path_aad` binds each ciphertext to
    // its key so a blob cannot be relocated and still decrypt.
    //
    // Restricting them to own-device members is therefore a *membership* check in
    // the handler, not a trust-origin tier.
    /// Read an object as a sealed blob, with the CEK epoch it is sealed under.
    ReadSealed {
        user_id: String,
        mount: String,
        path: String,
        /// Byte offset into the sealed object to start from. A sealed object can
        /// be a whole `PACK_SIZE` (16 MiB) pack, larger than the peer channel's
        /// per-response cap, so it is fetched as a sequence of ranges rather than
        /// one oversized response.
        offset: u64,
        /// Maximum bytes to return from `offset`. The response carries `total_size`
        /// so the caller knows when it has the whole object.
        length: u32,
    },
    /// What a device that holds only the phrase needs before it can prove
    /// anything: the identity's public key event log, and the phrase-sealed
    /// recovery copy of its data roots (`RFC-0081`, the cold fetch).
    ///
    /// Served **only over a peer connection**, and only to a device the handshake
    /// admitted on a recovery claim for this identity or that is already one of
    /// its paired devices; the IPC path refuses it outright. Neither half opens
    /// anything: the chain is public by construction, and the copy opens under
    /// the phrase alone, which never crosses.
    RecoveryFetch {
        user_id: String,
    },
    /// Hand a node the user's phrase-sealed recovery copy to keep (RFC-0081).
    ///
    /// The copy travels with the chain at enrolment; a phrase set up *after* a
    /// blind node was enrolled has to reach it some other way, and this is it —
    /// sent by the device that just sealed the copy, to every paired node that
    /// holds nothing (`Posture::BlindStorage`). Served **only over a peer
    /// connection** from a paired device; the node keeps the bytes verbatim and
    /// can open none of them.
    RecoveryStore {
        user_id: String,
        /// The recovery bundle exactly as written on the sending device.
        bundle: String,
        /// The identity's key events, as the sending device has them.
        ///
        /// **The copy is useless to the node without them.** Setting up a phrase
        /// appends a key event committing the new recovery authority, and a
        /// blind node admits a phrase-only device by finding that authority in
        /// the chain it holds. A node enrolled before the phrase existed holds a
        /// chain that stops short of the commitment, so it would keep the sealed
        /// copy and refuse the one device that will ever ask for it. Delivering
        /// the copy and the events that authorize it in one request is what
        /// makes them impossible to deliver apart
        /// (`TASK-a-node-keeps-a-recovery-copy-it-will-refuse-to-serve`).
        ///
        /// The receiver takes only events past its own tip and replays the whole
        /// chain before keeping it, so this widens nothing: a peer cannot insert
        /// an authority the identity did not sign for. Empty from a pre-2026-09-12
        /// sender, which the receiver treats as "nothing new offered".
        #[serde(default)]
        kel: Vec<crate::kel::KelEvent>,
    },
    /// The other direction of a browser's sealed channel (`DEC-0059`).
    ///
    /// A gateway opens a second connection and issues this once, naming the
    /// channel it also relays `BrowserFrame`s for. The response is a stream:
    /// every frame the node has for that browser that no call is waiting on —
    /// a ceremony's, chiefly, since the person's six digits arrive while
    /// nothing is being asked for.
    ///
    /// The gateway reads none of it. Each frame is sealed under the channel's
    /// key exactly as a reply is, so this widens what a gateway *carries* and
    /// not what it can see. Held for as long as the gateway holds the browser's
    /// socket; when the stream ends the node drops the channel.
    BrowserOutbound {
        channel: String,
    },
    /// Hand this vault the doors to hold for `user_id` (`DEC-0056`): the pair
    /// handle for each contact and each epoch of a window ahead, so the vault
    /// can reserve them and take delivery while every device is asleep.
    /// Replaces the window; doors for epochs already past are dropped.
    ///
    /// Peer-only, from a paired device of the person's. A vault verb.
    HoldDoors {
        user_id: String,
        doors: Vec<crate::ipc::HeldDoor>,
    },
    /// Take what this vault has held for `user_id`, and acknowledge — by
    /// ephemeral key — what the device has already filed, so the vault drops
    /// it. Returns whatever is still pending after the acknowledgement.
    ///
    /// Peer-only, from a paired device of the person's. A vault verb.
    TakeDeliveries {
        user_id: String,
        ack: Vec<String>,
    },
    /// Hand this vault what `user_id`'s outbox holds, for it to carry while no
    /// device of theirs is awake
    /// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`,
    /// clause 3). The vault tries each message's own sealed bytes at the
    /// recipient's door until a device signs for it, and keeps the
    /// acknowledgement — sealed to the sender — to be taken with
    /// `TakeDeliveries`.
    ///
    /// **It carries what it is handed and drops what it is told; a set is
    /// built across passes, one frame at a time.** `messages` are added — one
    /// already carried keeps its schedule, and its doors are the ones handed
    /// now — and `drop` names, by `ephemeral_pub`, what the vault stops
    /// carrying: a message the outbox no longer holds. The answer lists every
    /// message the vault then carries for the person, so a device hands only
    /// the difference and never more than one frame holds
    /// (`TASK-an-outbox-holding-two-shares-is-handed-to-its-vault-in-one-frame-that-cannot-hold-them`).
    /// Empty both ways, it is the readout of what is carried.
    ///
    /// **Named for what it now means.** Until 2026-10-08 this verb was
    /// `CarryMessages` and replaced the set with the one handed. The name
    /// changed with the meaning so that a vault from before refuses this
    /// request as a verb it does not know, rather than reading a readout — no
    /// messages — as *carry nothing* and emptying what it carries every pass;
    /// and a device from before is refused by a vault from after the same way.
    ///
    /// Peer-only, from a paired device of the person's. A vault verb.
    CarryFrame {
        user_id: String,
        messages: Vec<crate::ipc::CarriedMessage>,
        drop: Vec<String>,
    },
    /// Admit another device of `user_id`'s at this drive, or withdraw one:
    /// `change` signed under the person's identity (`signature`, Ed25519 over
    /// [`crate::ipc::TenantDeviceChange::signed_bytes`]).
    ///
    /// A vault holds no data keys and cannot read the member list, so the
    /// device that enrolled it is the one it admits; this is how it learns the
    /// rest. The device that admitted a new device sends it to every drive the
    /// person has at the ceremony's end, and the withdrawal at `device revoke`.
    /// The drive takes it only from a device it already admits for the tenant,
    /// only under the identity's current key in the key log it keeps, and only
    /// newer than the last change it took for that key.
    ///
    /// Peer-only, from a paired device of the person's. A vault verb.
    TenantDevice {
        user_id: String,
        change: crate::ipc::TenantDeviceChange,
        signature: Vec<u8>,
    },
    /// List a mount in **storage-key space** — the keys `ReadSealed`/`WriteSealed`
    /// address, not the caller's logical paths (RFC-0044).
    ///
    /// Replication lists here rather than via `ListFiles` so it sees the opaque
    /// stored keys on both sides — a blinding peer would otherwise un-blind them
    /// to plaintext, which both breaks key comparison and would put the paths on
    /// the wire.
    ListSealed {
        user_id: String,
        mount: String,
        prefix: String,
    },
    /// Store `blob` verbatim, declaring which key domain it belongs to.
    ///
    /// `domain_id` is the hex-encoded, one-way fingerprint of the sender's CEK.
    /// The receiver refuses a domain it cannot open rather than keeping a blob
    /// nobody can attribute to a key (see `SealedDomainMismatch`).
    WriteSealed {
        user_id: String,
        mount: String,
        path: String,
        /// One chunk of the sealed object (base64 on the wire), starting at
        /// `offset`. A whole 16 MiB pack exceeds the frame cap, so it is written
        /// as a sequence of sub-cap chunks the receiver reassembles.
        #[serde(with = "crate::base64_bytes")]
        blob: Vec<u8>,
        domain_id: String,
        /// Byte offset this chunk begins at. `offset == 0` starts (or restarts)
        /// the transfer.
        offset: u64,
        /// Total size of the whole sealed object; the receiver commits once its
        /// reassembly buffer reaches this.
        total_size: u64,
        /// BLAKE3 of the whole sealed object, hex. Keys the receiver's reassembly
        /// buffer — so two writers of different content to one path never
        /// interleave — and is verified before the object is committed.
        content_hash: String,
    },

    // -- Remote storage management ---------------------------------------------
    RemoteAdd {
        user_id: String,
        name: String,
        backend: RemoteBackend,
        /// Serialized backend credentials; daemon writes to OS keychain.
        /// `None` means no credentials needed (e.g., local backend).
        credentials: Option<crate::ipc::SecretValue>,
    },
    RemoteRemove {
        user_id: String,
        name: String,
    },
    RemoteList {
        user_id: String,
    },
    RemoteCacheClear {
        user_id: String,
        name: String,
    },
    RemoteCredentialsSet {
        user_id: String,
        name: String,
        /// Replaces the existing keychain entry for this remote.
        credentials: crate::ipc::SecretValue,
    },
    /// Signal kuserd to re-read `storage-mounts.toml` and rebuild the mount router
    /// without restarting. Triggered by `kotton config storage add/remove`.
    StorageReload {
        user_id: String,
    },

    // -- Sync (legacy remote-backend) ----------------------------------------
    /// Synchronise a local mount against a named remote.
    ///
    /// `direction`:
    ///   - `None`            -> bidirectional, last-write-wins
    ///   - `Some(Push)`      -> local -> remote only
    ///   - `Some(Pull)`      -> remote -> local only
    SyncMount {
        user_id: String,
        /// Local storage mount to sync (typically `"local"`).
        mount: String,
        /// Named remote to sync against (as registered with `remote add`).
        remote: String,
        direction: Option<SyncDirection>,
    },

    // -- Peer pairing ---------------------------------------------------------
    /// Issue a short-lived ephemeral session ticket to a guest device.
    PairNodeEphemeral {
        user_id: String,
        /// Label for the guest session.
        label: String,
        /// Paths the guest may access.
        paths: Vec<String>,
        /// Permissions granted to the guest.
        permissions: SessionPermissions,
        /// Session lifetime in seconds from now.
        ttl_seconds: u64,
        /// Guest device's X25519 ephemeral public key (32 bytes), generated
        /// fresh by the guest for this session.  When provided, the returned
        /// `GuestAccessToken.wrapped_deks` is populated with per-path DEKs
        /// re-wrapped to the derived guest session key.  When absent,
        /// `wrapped_deks` is empty (backwards-compatible).
        #[serde(default)]
        guest_ephemeral_pubkey: Option<[u8; 32]>,
    },

    /// RFC-0040 **streamed** device-add (issuer side; user-facing `device add`).
    ///
    /// Opens a bootstrap QUIC listener and runs the committed-handshake ceremony,
    /// streaming ceremony state as a sequence of frames: `PairAdvertising` (with
    /// the interim connection code) → `PairConnected` → `PairShowCode` →
    /// `PairAwaitingPeer` → `PairTransferring` → `PairingComplete` | `PairFailed`.
    /// The six-digit SAS is confirmed via a separate `PairConfirmCode` carrying
    /// the token from `PairShowCode`.
    DeviceAdd {
        user_id: String,
        /// Override this device's announced name for this ceremony only (`--as`).
        /// `None` uses the persisted device name (see `DeviceName`), defaulting to
        /// the OS hostname. The joiner adopts whatever name this device announces;
        /// this device never labels the joiner — the joiner announces its own.
        #[serde(default)]
        as_name: Option<String>,
        /// Session TTL in seconds before the ceremony times out.
        ttl_seconds: u64,
        /// UDP port to bind on (`0` = OS-assigned).
        port: u16,
        /// Posture (RFC-0036) the issuer admits the joiner under.
        #[serde(default)]
        posture: kotton_schemas::membership::Posture,
    },
    /// RFC-0040 **streamed** device-join (new-device side; user-facing `device join`).
    ///
    /// Dials the issuer using the interim connection `code` (address + session id,
    /// no key material) or discovers it on the LAN via mDNS, and runs the committed
    /// handshake, streaming the same ceremony frames as `DeviceAdd`. Session-less —
    /// the join *bootstraps* this user on the device, so it cannot presuppose a
    /// session; its security is the SAS + the ceremony.
    DeviceJoin {
        user_id: String,
        /// The interim connection code shown by the issuer (address + session id).
        code: crate::ipc::SecretText,
        /// Override this device's announced name for this ceremony only (`--as`).
        /// `None` uses the persisted device name (see `DeviceName`), defaulting to
        /// the OS hostname. The issuer adopts whatever name this device announces;
        /// this device labels the issuer with the name the issuer announced.
        #[serde(default)]
        as_name: Option<String>,
    },
    /// The human's verdict on the six-digit SAS for a parked ceremony.
    ///
    /// `token` is the value from the `PairShowCode` frame; `matches = true` means
    /// the codes matched (proceed), `false` cancels (nothing is transferred). Sent
    /// on a second connection while the ceremony stream is still open. Session-less
    /// because the joiner has no session yet during a bootstrap join — **the token
    /// is the authorization**: a fresh id surfaced only to the stream that issued
    /// it, so a confirm carrying someone else's token fails on the token.
    ///
    /// One verb serves device pairing and contact pairing, so its tier is the
    /// lower of the two streams it confirms — `Paired` since DEC-0057. The tier is
    /// not what protects it, and adding a second check beside the token would add
    /// a guard without removing anything's reach.
    PairConfirmCode {
        user_id: String,
        /// The ceremony token from `PairShowCode`.
        token: crate::ipc::SecretText,
        /// `true` if the human confirmed the codes match.
        matches: bool,
    },

    /// Get or set this device's human name — the label it announces to peers when
    /// pairing (RFC-0040 §1). Device-level (shared across users on this machine),
    /// so no `user_id`. `new_name = None` returns the current name, defaulting to
    /// the OS hostname if never set; `Some(name)` sets it. Local-only.
    DeviceName {
        #[serde(default)]
        new_name: Option<String>,
    },

    /// List all paired nodes for a user.
    NodeList {
        user_id: String,
    },
    /// Where this node holds its relay reservations — the answer a paired
    /// device records so its next dial lands even after this node changes relay
    /// (RFC-0083 R5: the pair is the resolver; a relay change is a forwarding
    /// address). One URL of this node's own configuration, no address of a
    /// peer's, nothing of the user's.
    NodeRelay {
        user_id: String,
    },
    /// A relay both devices are on introduces them: the dialling device hands
    /// the other its local address and a token over the sealed channel the relay
    /// carries and cannot read, and asks for a listener that hears that address
    /// and that token and nothing else. The answer is where that listener is.
    /// The pair then dials direct, and the relay carries only what cannot
    /// (`TASK-a-relay-introduces-your-devices`).
    ///
    /// Peer-only, from a paired device of the same person — never a contact, a
    /// guest or a gateway. `addr` is the dialler's `ip:port`; `token` is 16
    /// bytes, hex; `router` is the key of the network the dialler is on (hex,
    /// the door's `RouterKey`), and a device on another network — or one that
    /// cannot name its own — declines, so no dial is ever aimed at an address
    /// that belongs to a stranger where the dialler sits.
    Introduce {
        user_id: String,
        addr: String,
        token: crate::ipc::SecretText,
        #[serde(default)]
        router: Option<String>,
    },
    /// How much a vault keeps for this user and how much it may (RFC-0084 V3):
    /// bytes held and the quota, the one meter a keyless keeper has. Answered
    /// like `NodeRelay` — a fact of the node's own configuration, nothing read
    /// from what it holds.
    VaultCapacity {
        user_id: String,
    },
    /// Revoke a paired node, removing it from the allowlist.
    NodeRevoke {
        user_id: String,
        node_id: String,
    },

    /// One round of a distributed FROST threshold-signing ceremony, sent by a
    /// coordinator node to a co-signer over the authenticated peer connection
    /// (RFC-0036). `payload` is the JSON-serialised round message (round 1 opens a
    /// nonce session keyed by an id the coordinator chose; round 2 carries the
    /// signing package). The co-signer's FROST share and its round-1 nonces never
    /// leave its process — only a commitment and a signature share are returned.
    ///
    /// This is a **peer-only** request (served via the QUIC peer listener, like
    /// file/record sync); it is intentionally `Remote`-eligible.
    FrostSignRound {
        user_id: String,
        /// JSON of the runtime `FrostRound` message.
        payload: String,
    },

    /// Coordinate a distributed FROST threshold signature over `message_hex`
    /// across this node's own network (RFC-0036): this node signs with its share
    /// and co-signs with every Full own-device member over the peer channel.
    ///
    /// Local-IPC only — it signs with this node's share, so a remote peer must
    /// never trigger it (it is `Local`-tier); peers contribute via
    /// `FrostSignRound` instead.
    ThresholdSign {
        user_id: String,
        /// Lowercase-hex of the message bytes to threshold-sign.
        message_hex: String,
    },

    /// Add a peer node by explicit DID, public key, and address — bypassing the
    /// pairing ceremony.  Used by the demo recipe, the `two_node_transfer`
    /// integration test, and any future tooling that exchanges identity out-of-band.
    ///
    /// `peer_pubkey_hex` is the 32-byte raw Ed25519 public key in lowercase hex.
    /// It must match the key the peer daemon was started with; it is inserted into
    /// the local `paired_nodes` table and live `paired_keys` allowlist so the peer
    /// can authenticate its mTLS connection immediately.
    PeerAdd {
        user_id: String,
        /// Human label for this node, e.g. `"node-b"`.
        label: String,
        /// `did:key:z6Mk…` stable device DID.
        peer_did: String,
        /// 32-byte Ed25519 public key, lowercase hex (64 chars).
        peer_pubkey_hex: String,
        /// QUIC listener address of the peer.
        peer_addr: std::net::SocketAddr,
        /// The node is a vault the person keeps a drive on: record the drive
        /// (`kotton_peer::daemon::drives`), and the row's posture
        /// `blind-storage`. `kotton id recover` says it of the vault its line
        /// names; absent, nothing but the row is recorded.
        #[serde(default)]
        drive: bool,
    },

    /// Return this daemon's stable device DID and ephemeral signing public key.
    ///
    /// The signing key is the 32-byte raw Ed25519 public key of the ephemeral key
    /// generated at daemon startup — the same value a remote peer must store via
    /// `PeerAdd` to allow mTLS connections from this node.  Not in
    /// `Remote`-eligible (public identity, not private key material).
    GetNodeIdentity,
    /// Add or update a background sync rule between a local path and a node.
    SyncConfigure {
        user_id: String,
        node_id: String,
        path: String,
        /// Enable filesystem-watch based continuous sync.
        watch: bool,
    },
    /// List all sync rules for a user.
    SyncRuleList {
        user_id: String,
    },
    /// Remove a sync rule.
    SyncRuleRemove {
        user_id: String,
        node_id: String,
        path: String,
    },
    /// Enqueue a sync pass for all matching rules (or a single node).
    ///
    /// Returns immediately with a `SyncStarted { job_id }`. Pass `job_id` to
    /// `SyncAwait` to block until the pass completes (RFC-0019).
    ///
    /// `node_id = None` enqueues all configured sync rules for the user.
    SyncTrigger {
        user_id: String,
        /// Restrict to a single paired node. `None` = all nodes.
        node_id: Option<String>,
    },
    /// Block until a previously enqueued sync job completes or times out.
    ///
    /// Returns `SyncOutcomeMsg`, `SyncFailed`, or `SyncTimeout`.
    SyncAwait {
        user_id: String,
        /// Job id returned by `SyncTrigger`.
        job_id: String,
        /// Maximum seconds to wait before returning `SyncTimeout`.
        timeout_secs: u64,
    },

    // -- Peer mounts ----------------------------------------------------------
    /// Mount a path from a paired node into the local VFS.
    MountPath {
        user_id: String,
        node_id: String,
        /// Path exported by the remote node.
        remote_path: String,
        /// Local path at which the remote tree should appear.
        local_path: String,
        /// Maximum local cache size in bytes. `None` = unlimited.
        cache_budget_bytes: Option<u64>,
        /// Subpaths to keep pinned (pre-fetched, never evicted).
        pins: Vec<String>,
    },
    /// List all peer mounts for a user.
    MountList {
        user_id: String,
    },
    /// Evict the local cache for a mount (frees disk space).
    MountEvict {
        user_id: String,
        node_id: String,
        local_path: String,
    },

    // -- Ephemeral sessions ---------------------------------------------------
    /// List all active ephemeral sessions for a user.
    SessionList {
        user_id: String,
    },
    /// Revoke an ephemeral session before it expires.
    SessionEnd {
        user_id: String,
        session_id: String,
    },

    // -- NAT / rendezvous -----------------------------------------------------
    /// Set (or clear) the rendezvous server URL for this device.
    ///
    /// `url = None` removes the configured rendezvous server; the device will fall
    /// back to direct QUIC only and TURN relay if configured.
    RendezvousSet {
        url: Option<String>,
    },
    /// Stand this device at the relay a code names, held to the key the code
    /// names (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`):
    /// a relay's line — what an invite's admit offers — or a relay's invite,
    /// whose *invited* admission key is kept sealed in `user_id`'s store and
    /// presented at that relay. Nothing is written unless the relay at the
    /// code's address proves the code's key. `relay set <code>` at the terminal.
    RelayStand {
        user_id: String,
        code: crate::ipc::vault_request::SecretText,
    },
    /// Return current rendezvous configuration and activity summary.
    RendezvousStatus,

    /// Return a human-readable table of all device-level config keys, their
    /// current values, and the command needed to configure each one.
    ConfigStatus,

    /// Set (or clear) the TURN relay URL for this device.
    ///
    /// Credentials are passed separately via the OS keychain; this call only
    /// stores the server endpoint.
    TurnSet {
        url: Option<String>,
    },

    // -- Models (RFC-0085 *The model as content*, `DEC-0073`) -----------------
    /// Write the manifest record for weights already sealed into this user's
    /// store, making the model installed.
    ///
    /// The weights arrive first, through [`UserRequest::ModelWeights`], which
    /// lands them at the daemon's own key for the manifest's hash and commits
    /// only when the stream hashes to it (`DEC-0073`'s verify-before-seal).
    /// This verb re-hashes the object at that key against the manifest, and
    /// only then does a model exist. No person-facing path names that key, so
    /// no `files` grant — not one on `/` — can put other bytes there
    /// (`TASK-a-models-weights-are-the-daemons-and-no-files-grant-reaches-them`).
    ///
    /// `Local`-tier. A model is gigabytes in the person's own store and it
    /// decides what answers their questions; a browser session or a peer must
    /// not be able to install one, and neither may an app — which names a model
    /// only through `models()` and only one the host showed it.
    ModelAdd {
        user_id: String,
        /// The manifest as the person obtained it, carried unchanged: it is what
        /// gets stored.
        manifest: kotton_schemas::ModelManifest,
    },
    /// One chunk of a model's weights, streamed into the daemon's own object
    /// for the hash they declare — the door `ModelAdd` reads from.
    ///
    /// The chunk shape `WriteFile` has, less the path: **the key is derived
    /// from `content_hash` by the daemon**, outside the person's tree, so the
    /// caller names bytes and never a place. The daemon streams the chunks into
    /// the store as they arrive (a multi-gigabyte model is never whole in
    /// memory, here or on the wire), hashes them on the way past, and commits
    /// only if the whole stream is the declared hash; until then nothing is at
    /// the key under any name.
    ///
    /// A sibling of `ModelAdd` rather than fields on it: a manifest per chunk
    /// is waste, and a manifest-less first chunk would be a second shape of one
    /// verb.
    ///
    /// `Local`-tier, as `ModelAdd` is: installing what runs over the person's
    /// data is the person's act at their machine. A guest never reaches it — an
    /// app speaks the runner's protocol, not this one, and its `files` door
    /// resolves every path inside the person's tree.
    ModelWeights {
        user_id: String,
        /// One chunk of the weights (base64 on the wire), starting at `offset`.
        #[serde(with = "crate::base64_bytes")]
        data: Vec<u8>,
        /// Byte offset this chunk begins at; `0` starts (or restarts) the stream.
        offset: u64,
        /// Total size of the weights; the daemon commits when it has them all.
        total_size: u64,
        /// BLAKE3 of the whole weights, hex — `ModelManifest::weights`. Names
        /// the object and is verified before it exists.
        content_hash: String,
    },
    /// Every model this user has installed, and which one of each kind answers.
    ///
    /// `Local`-tier for now. The phone asking a paired machine what it can run is
    /// RFC-0085's *phone* step, and widening this is that step's decision to make.
    ModelList {
        user_id: String,
    },
    /// Remove a model: its manifest record and the sealed weights it names.
    ///
    /// `Local`-tier — for the reason `PurgeFile` is: it deletes the person's
    /// bytes, and a remote party must not.
    ModelRemove {
        user_id: String,
        /// The model's hash, a hash prefix, or its name.
        model: String,
    },
    /// Choose which model of its kind answers (`DEC-0073`).
    ///
    /// `Local`-tier. Which model answers is the person's choice at the machine,
    /// like `InferenceSet` beside it.
    ModelUse {
        user_id: String,
        /// The model's hash, a hash prefix, or its name.
        model: String,
        /// The person saying yes to invalidating the index, which changing the
        /// active `embed` model does. Ignored for every other kind: a chat model
        /// can be swapped between two questions and an embedding model cannot,
        /// and the surface must not make the two look identical (RFC-0085, *The
        /// index*).
        rebuild_index: bool,
    },

    /// Turn this machine's inference runtime on or off (RFC-0085).
    ///
    /// Takes effect when `kuserd` next starts: the daemon reads
    /// `inference.enabled` at boot and supervises `kinferd` only when it says
    /// yes, which is the bargain `QuicGatewaySet` already makes.
    ///
    /// `Local`-tier. Deciding that this machine runs a model is an operator
    /// action at the machine — a browser session or a peer must not be able to
    /// start a process here, and a model runs only where the keys are (IN2).
    InferenceSet {
        enabled: bool,
    },

    /// Read, or answer, the row *Open to your devices here*: whether this machine
    /// listens and announces on the local network it is on
    /// (`TASK-the-local-network-is-a-door-opened-on-purpose-for-ten-minutes-and-a-relay-introduces-your-devices`).
    ///
    /// `answer` is `closed`, `10m` or `always`; `None` reads without changing. The
    /// door is closed by default, *10 minutes* shuts itself, and *Always* is kept
    /// for the one network whose router this machine is on now.
    ///
    /// `Local`-tier. Opening a port on the network this machine sits on is an act at
    /// the machine; a browser session or a peer must not be able to open a door that
    /// exists precisely because it is reachable by strangers.
    LocalDoor {
        #[serde(default)]
        answer: Option<String>,
    },

    // -- QUIC gateway (RFC-0015) ----------------------------------------------
    /// Enable or reconfigure the QUIC gateway sidecar (`kquicd`).
    ///
    /// Fields set to `None` leave the current value unchanged.
    /// Defaults: `enabled = false`, `port = 7443`, `bind = "lan"`.
    ///
    /// `Local`-tier — gateway lifecycle is a local operator action.
    QuicGatewaySet {
        enabled: Option<bool>,
        port: Option<u16>,
        /// Which local addresses to bind: `"loopback"` (default), `"all"`, or a
        /// literal IP. See `kotton_common::listen::BindScope`.
        ///
        /// `"lan"` and `"public"` are accepted as deprecated spellings of
        /// `all`+`allow=private` and `all` respectively — the pair they always
        /// meant, and could not express as one value.
        bind: Option<String>,
        /// Which source addresses to admit, as comma-separated CIDRs, or `"private"`
        /// for the RFC 1918 / ULA / link-local set. Empty admits every source.
        ///
        /// Separate from `bind` because they answer different questions: `bind` is
        /// which doors are open, this is who may walk through one.
        #[serde(default)]
        allow: Option<String>,
    },
    /// Return current QUIC gateway configuration and whether `kquicd` is running.
    ///
    /// `Local`-tier.
    QuicGatewayStatus,
    /// Return the raw Ed25519 public-key bytes (hex) for every DID in `paired_nodes`
    /// for `user_id`.
    ///
    /// Used by `kquicd` to build its in-memory authorised-client allowlist.
    GetAuthorizedClients {
        user_id: String,
    },
    /// Return the Ed25519 signing key bytes (32 bytes, raw) for `user_id`.
    ///
    /// Used by `kquicd` to construct the QUIC mTLS server certificate that
    /// remote clients verify against the node DID.  `Local`-tier —
    /// never callable from a remote gateway connection.
    GetDeviceCert {
        user_id: String,
    },

    // -- HTTP gateway (RFC-0016) ----------------------------------------------
    /// Enable or reconfigure the HTTP gateway sidecar (`khttpd`).
    ///
    /// Fields set to `None` leave the current value unchanged.
    /// Defaults: `enabled = false`, `port = 8443`, `bind = "loopback"`.
    ///
    /// `Local`-tier — gateway lifecycle is a local operator action.
    WebShellSet {
        enabled: Option<bool>,
        port: Option<u16>,
        /// Which local addresses to bind — see [`Self::QuicGatewaySet`]'s `bind`.
        bind: Option<String>,
        /// Absolute path to static bundle directory. `None` leaves unchanged.
        static_dir: Option<String>,
        /// Which source addresses to admit — see [`Self::QuicGatewaySet`]'s `allow`.
        #[serde(default)]
        allow: Option<String>,
    },
    /// Return current HTTP gateway configuration and whether `khttpd` is running.
    ///
    /// `Local`-tier.
    WebShellStatus,
    /// Wait for a browser to pair, and show its six digits here (RFC-0078).
    ///
    /// Streams the ceremony like `DeviceAdd`: `PairShowCode { token, sas, .. }`
    /// when a browser with an unregistered device key arrives on the sealed
    /// channel, then `PairAwaitingPeer` / `PairTransferring` / `PairFailed`. The
    /// human compares the digits with the phone and answers with
    /// `PairConfirmCode { token, matches }`; on yes the browser's key is
    /// registered under the name it proposed.
    ///
    /// `Local`-tier — admission is decided on a trusted screen, never over the
    /// network. Without a parked `WebShellPair`, an unknown browser is refused.
    WebShellPair {
        user_id: String,
        /// How long to wait for a browser, in seconds.
        ttl_seconds: u64,
    },
    /// Every browser admitted for `user_id` by the six-digit ceremony, oldest
    /// first (DEC-0053) — the other half of `WebShellPair`, so what a person
    /// admitted they can also see.
    ///
    /// `Local`-tier, like the desk that admits one: the list is the person's own
    /// roster of what acts as them, read on a trusted screen. A browser does not
    /// see it through its own channel, and no app is handed it.
    BrowserDeviceList {
        user_id: String,
    },
    /// Revoke the browser admitted for `user_id` as `name` (Article IV).
    ///
    /// Decided here, by the daemon that holds the admission, and never by asking
    /// the browser to leave: the row goes, the session its admission minted
    /// goes, and the channel it established is dropped from the registry, so a
    /// call on that **live** channel is refused rather than only its next
    /// handshake. Answered with `BrowserDeviceRevoked`, or an error naming no
    /// such browser.
    ///
    /// `Local`-tier: revoking a device is decided on a trusted screen, and a
    /// browser must not be able to revoke its siblings.
    BrowserDeviceRevoke {
        user_id: String,
        name: String,
    },

    // -- Record operations ----------------------------------------------------
    /// Insert a JSON record into the schema table for `schema_nsid`.
    ///
    /// The `record` value should be a JSON object whose keys match the fields
    /// declared in the schema.  An `id` field is generated if not supplied.
    RecordInsert {
        user_id: String,
        /// NSID of the target schema, e.g. `"sh.kotton.notes"`.
        schema_nsid: String,
        /// JSON-encoded record body.
        record: serde_json::Value,
        /// The root the record belongs to, by its local id (RFC-0071 R17).
        /// `None` is *Personal*, so every caller that predates roots writes
        /// where it always did. A root the person is not a member of is
        /// refused (R12).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root: Option<String>,
        /// Calling app identifier, `None` for trusted shell/CLI callers.
        /// When `Some`, the daemon enforces `schema_grants` before inserting.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app_id: Option<String>,
    },

    /// Query records from a schema table.
    ///
    /// Returns only non-deleted records matching all `field_eq` predicates.
    RecordQuery {
        user_id: String,
        /// NSID of the target schema.
        schema_nsid: String,
        /// Exact field-equality predicates `[(field_name, expected_value)]`.
        field_eq: Vec<(String, serde_json::Value)>,
        /// Maximum number of results.
        limit: Option<usize>,
        /// Number of results to skip (pagination).
        offset: Option<usize>,
        /// Read one root only, by its local id (RFC-0071 R17). `None` reads
        /// every root the person is a member of — their own view across their
        /// roots — and never a root they are not in (R12).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root: Option<String>,
        /// Calling app identifier, `None` for trusted shell/CLI callers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app_id: Option<String>,
    },

    /// Cross-schema search for the hub feed and search bar.
    ///
    /// Returns enriched records `{id, schema_nsid, updated_at, body}` sorted by
    /// `updated_at` descending.  Optionally filtered to a single `nsid` and/or
    /// by a case-insensitive substring match over the JSON body.
    RecordSearch {
        user_id: String,
        /// Restrict to a single schema NSID; `None` queries all schemas.
        nsid: Option<String>,
        /// Case-insensitive substring to match in the record body.
        text: Option<String>,
        /// Maximum number of records to return.
        limit: Option<u32>,
        /// Calling app identifier, `None` for trusted shell/CLI callers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app_id: Option<String>,
    },

    /// Soft-delete a record by writing a tombstone.
    RecordDelete {
        user_id: String,
        schema_nsid: String,
        record_id: String,
        /// Delete only from this root, by its local id (RFC-0071 R17). `None`
        /// reaches every root the person is a member of and no other (R12).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root: Option<String>,
        /// Calling app identifier, `None` for trusted shell/CLI callers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app_id: Option<String>,
    },

    /// Open a single record by its `kotton://records/<nsid>/<id>` URL.
    RecordOpen {
        user_id: String,
        /// The full `kotton://records/<nsid>/<id>` URL.
        url: String,
    },

    // -- Import ---------------------------------------------------------------
    /// Read an export the person brought with them and write its items as
    /// ordinary records in their own store
    /// (`TASK-a-person-brings-their-history-with-them`).
    ///
    /// **The bytes travel; the path does not.** The client reads the file and
    /// sends what it read, the way `AppInstall` sends the wasm rather than a
    /// path to it. A verb that took a path would make the daemon open whatever
    /// the caller named, with the daemon's reach rather than the caller's, and
    /// `kuserd` serves every user on the machine — that is a confused deputy,
    /// bought for nothing, since the client can already read its own file.
    ///
    /// `Local`-tier: see the `required_trust` arm.
    Import {
        user_id: String,
        /// Which reader to use. Named by the caller and never sniffed — an
        /// importer that guesses the format guesses what the records mean.
        format: ImportFormat,
        /// The export's **file name**, kept as provenance on every record it
        /// produces. The daemon takes the last path component and nothing else.
        source_name: String,
        /// The export's bytes, exactly as they were on disk. Decoding is the
        /// reader's job, so a file that is not what it claims is refused where
        /// the error can say so.
        content: Vec<u8>,
    },

    // -- Schema management ----------------------------------------------------
    /// List the schema NSIDs visible to `user_id`: core plus their own
    /// registrations.
    SchemaList {
        user_id: String,
    },

    /// Register a new app-supplied schema.
    ///
    /// `definition_json` must be a JSON-encoded [`kotton_schemas::definition::SchemaDefinition`].
    /// When `app_id` is `Some`, the daemon checks `can_register` before proceeding.
    /// A version upgrade migrates only `user_id`'s record store.
    SchemaRegister {
        user_id: String,
        definition_json: String,
        /// Calling app identifier, `None` for trusted shell/CLI callers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app_id: Option<String>,
    },

    /// Retrieve the full JSON definition of a schema visible to `user_id`.
    SchemaGet {
        user_id: String,
        nsid: String,
    },

    // -- Schema grant management (RFC-0003) -----------------------------------
    /// List all schema access grants for `app_id`.
    SchemaGrantList {
        app_id: String,
    },

    /// Create or update a schema access grant for `(app_id, nsid)`.
    SchemaGrantSet {
        app_id: String,
        nsid: String,
        can_read: bool,
        can_write: bool,
        can_register: bool,
    },

    /// Remove all schema access grants for `(app_id, nsid)`.
    SchemaGrantRevoke {
        app_id: String,
        nsid: String,
    },

    /// Override the write quota limits for `(app_id, nsid)`.
    ///
    /// `record_quota = 0` removes the record count limit.
    /// `byte_quota = 0` removes the byte limit.
    SchemaQuotaSet {
        app_id: String,
        nsid: String,
        /// Maximum live records (0 = unlimited).
        record_quota: i64,
        /// Maximum total body bytes (0 = unlimited).
        byte_quota: i64,
    },

    // -- Handler registry (v0.5) ----------------------------------------------
    /// Register `app_id` as a handler for schema `nsid`.
    ///
    /// The first handler for an NSID becomes the default automatically.
    RegisterHandler {
        app_id: String,
        nsid: String,
    },
    /// Remove `app_id` as a handler for schema `nsid`.
    ///
    /// If the removed entry was the default, the next-oldest handler is
    /// promoted automatically.
    UnregisterHandler {
        app_id: String,
        nsid: String,
    },
    /// Return the default handler for a schema NSID.
    GetHandlerFor {
        nsid: String,
    },
    /// Return all registered handlers, ordered by NSID then app_id.
    ListHandlers,
    /// Override the default handler for a schema NSID.
    ///
    /// `app_id` must already be registered for `nsid`.
    SetDefaultHandler {
        app_id: String,
        nsid: String,
    },

    // -- App lifecycle (v0.6) -------------------------------------------------
    /// Install a WASM app from its manifest TOML and compiled bytes.
    ///
    /// The daemon parses the manifest, writes the `.wasm` file to the app store
    /// directory, stores metadata in the `app_registry` table, and registers
    /// the app as a handler for each NSID listed in `handler_for`.
    AppInstall {
        /// The user_id on whose behalf the app is being installed.
        ///
        /// The daemon uses this to look up the user's identity signing key and
        /// create a self-signed `GrantEnvelope` over `approved` — **not** over
        /// what the manifest declared.
        user_id: String,
        /// TOML-encoded app manifest (see [`kotton_wasm::AppManifest`]).
        manifest_toml: String,
        /// Compiled WASM module bytes.
        wasm_bytes: Vec<u8>,
        /// The capabilities a human approved, having been shown them.
        ///
        /// **Required, and required for a reason.** Until 2026-08-30 this field
        /// did not exist and the daemon signed `manifest.capabilities` with the
        /// user's identity key, unattended — security-audit finding H2. A prompt
        /// in one client would not have fixed it: the daemon signed whatever any
        /// caller handed it, so a script, another client, or the AI terminal
        /// calling `AppInstall` directly bypassed the courtesy entirely.
        /// Carrying the approved set on the wire is what makes the auto-mint
        /// unreachable rather than merely discouraged.
        ///
        /// Obtain the set to show the user with [`Self::AppInstallPreview`]. The
        /// daemon refuses any grant not also requested by the manifest, so this
        /// channel can narrow a request but never widen one. An empty vec is
        /// legal and means "install it, grant it nothing".
        ///
        /// For VFS capabilities prefer `bindings`, which lets the user choose
        /// *where* a declared shape points. Grants listed here are taken as-is
        /// and must still be a subset of what the manifest requested.
        approved: Vec<CapabilityGrant>,
        /// Where the user put each declared VFS shape: `(shape id, path)`.
        ///
        /// RFC-0021's ceremony — "the user can accept the default or type any
        /// path they like". The daemon builds the grant from **its own** reading
        /// of the manifest and substitutes only the target, so this channel
        /// cannot add a capability the app never declared: there would be no
        /// shape to name. Shape ids come from `AppInstallPreview`'s `shapes`.
        ///
        /// A shape left unbound keeps the manifest's suggestion. Empty means
        /// "accept every suggestion", which is what install did before binding
        /// existed — so an older client keeps working unchanged.
        #[serde(default)]
        bindings: Vec<(String, String)>,
    },
    /// Parse and validate an app package, and report what it is asking for.
    ///
    /// **Mints nothing and signs nothing.** This is the first half of the
    /// two-phase install ([`IDEA-install-consent-gate`], Option B): the client
    /// asks what the app wants, shows a human, and sends back the approved
    /// subset in [`Self::AppInstall`]. Nothing is written to the app store here,
    /// so a preview the user declines leaves no trace.
    ///
    /// Returns [`UserResponse::AppInstallPreview`].
    ///
    /// [`IDEA-install-consent-gate`]: https://kotton.sh/records/IDEA-install-consent-gate
    /// Report what an installed app **asked for** and what it **holds**.
    ///
    /// The read-only counterpart to the consent ceremony. Until this existed
    /// nothing could observe an app's grants after install: `app_list` showed a
    /// display string and no verb reported the structured decision, so the
    /// install tests could assert only that installing succeeded — one of them
    /// stayed green against a planted auto-mint for exactly that reason
    /// (`TASK-the-approval-is-signed-but-not-enforced`).
    ///
    /// It is also the surface a user is owed: "what does this app hold" should
    /// be answerable without reading a manifest off disk.
    ///
    /// Returns [`UserResponse::AppGrants`].
    AppGrants {
        app_id: String,
    },
    AppInstallPreview {
        /// The user_id the install would be for.
        user_id: String,
        /// TOML-encoded app manifest.
        manifest_toml: String,
        /// Compiled WASM module bytes — hashed, not stored.
        wasm_bytes: Vec<u8>,
    },
    /// Uninstall a previously installed app.
    ///
    /// Removes any `.wasm` file, the `app_registry` row, and all handler
    /// registry entries for this app.
    AppUninstall {
        app_id: String,
    },
    /// Re-hash the installed WASM binary and confirm it matches the stored hash.
    ///
    /// Returns [`UserResponse::AppVerifyResult`] with the stored hash, computed
    /// hash, and a boolean indicating whether they match.
    AppVerify {
        app_id: String,
    },

    // ── Confined extensions (RFC-0049 / RFC-0050) ─────────────────────────────
    /// Install a confined extension from an already-obtained package.
    ///
    /// Deliberately separate from [`Self::AppInstall`]: an app declares which of
    /// the user's data it wants; an extension declares which *class* it is, and
    /// the class selects the WIT world that decides what it can reach at all.
    /// The verbs stay apart so no handler can confuse the two consent stories.
    ///
    /// The daemon computes the content hash from `wasm_bytes` (never trusting a
    /// package's claim about its own identity), verifies the publisher
    /// signature if present, parses every declared endpoint pattern, and mints
    /// capabilities **derived from the class** rather than requested.
    ExtensionInstall {
        /// The user on whose behalf the extension is installed; the daemon signs
        /// the resulting `GrantEnvelope` with this user's identity key.
        user_id: String,
        /// TOML-encoded extension manifest (see `kotton_schemas::ExtensionManifest`).
        manifest_toml: String,
        /// The compiled WASM component.
        wasm_bytes: Vec<u8>,
    },
    /// List installed extensions.
    ExtensionList {
        user_id: String,
    },
    /// Uninstall an extension: remove the package, drop the registry row, and
    /// **revoke its grants** — the last of which is what actually removes its
    /// authority, since the signed envelope rather than the row is the
    /// capability.
    ExtensionRemove {
        user_id: String,
        extension_id: String,
    },
    /// List all installed apps on this device (WASM + bundle).
    AppList,
    /// Register a pre-built web bundle as an installed app.
    ///
    /// This is for web-bundle apps (no WASM). The bundle directory must
    /// already exist on disk, the daemon stores the path, not the files.
    /// Capabilities are a JSON-encoded `Vec<String>` array.
    AppRegisterBundle {
        app_id: String,
        name: String,
        version: String,
        capabilities_json: String,
        /// Absolute filesystem path to the `dist/` directory.
        bundle_path: String,
        /// If `true`, this is a dev registration (`app dev`), marked in the
        /// registry and shown with a `(dev)` badge in `app list`.
        dev: bool,
    },
    /// Return the bundle path for an installed app.
    ///
    /// Nothing in the workspace sends it: `kotton-client` wraps it as
    /// `app().bundle_path`, and nothing calls that.
    AppGetBundlePath {
        app_id: String,
    },
    /// Ask the daemon to launch an installed WASM app.
    ///
    /// The daemon starts a runner for the app, and the runner calls its
    /// `on-launch` export with a surface the daemon minted for this instance
    /// and with the launch arguments. An app with no WASM, a registered bundle,
    /// is not run: the daemon announces the launch with every `"path"` dropped
    /// from the arguments it announces, and calls nothing.
    ///
    /// `launch_args` is a list of key/value pairs, and it arrives as
    /// `on-launch`'s `args` with two changes the daemon makes on the way:
    ///
    /// - `"path"` names a file in the person's own tree. When it names one, the
    ///   daemon grants the app read and write on that file, a grant that ends
    ///   when the person closes the app's window, and the app receives the
    ///   file's name in its place. The daemon hands over the first `"path"`
    ///   pair in the list and drops every other; when the first names no file
    ///   of theirs, or the grant cannot be made, it is dropped too. The app
    ///   never receives the person's path.
    /// - The daemon adds the keys it authors from the session, each only when
    ///   the list does not already carry it: `"display_name"` and `"did"` for
    ///   the person the launch is for, and `"notice"` when that person's keys
    ///   are not loaded.
    /// - The screen keys are the shell's. Into the launch of the app the
    ///   person designated their shell, and into no other app's, the daemon
    ///   adds `"mode"` for the screen the session is on, when the list does not
    ///   already carry it, and with it on the lock screen `"users"` and
    ///   `"names"`, the people registered on this device and what they are
    ///   called.
    ///
    /// Every other key, `"record_url"` (a `kotton://records/<nsid>/<id>` deep
    /// link) among them, reaches the app unchanged. An empty list opens the
    /// app's default view.
    AppLaunch {
        app_id: String,
        /// Key/value launch arguments, delivered to `on-launch` as its `args`.
        #[serde(default)]
        launch_args: Vec<(String, String)>,
    },
    /// Deliver one string to an installed app's `on-message` export.
    ///
    /// A client on the person's session, local or through a gateway, sends it,
    /// naming the app. The daemon calls `on-message` with `msg` unchanged, sends
    /// the surface patches the app committed while handling it to the
    /// compositor, and answers with the same patches. A long-lived app that is
    /// not running is spawned by the message and kept; a one-shot app is
    /// started fresh for each message, and its patch list is always empty. The
    /// daemon's own pushes to an app (the ceremony frames and the window-list
    /// nudge) do not travel as this request, and nothing here refuses a `msg`
    /// shaped like one.
    AppMessage {
        app_id: String,
        /// The string handed to `on-message`: JSON whose schema the app defines.
        msg: String,
    },
    /// Query which app is registered for a named system role.
    ///
    /// Returns [`DeviceResponse::AppRole`] with the `app_id`, or
    /// [`DeviceResponse::AppNotFound`] if no app is registered for the role.
    AppGetRole {
        /// Named role to look up, e.g. `"shell"` or `"dock"`.
        role: String,
    },
    /// Assign an installed app to a named system role.
    ///
    /// The daemon validates that the target app satisfies the role's
    /// capability contract before writing the assignment.  Returns
    /// [`DeviceResponse::AppRoleSet`] on success or an error string on
    /// validation failure.
    AppSetRole {
        /// Named role to assign, e.g. `"shell"`.
        role: String,
        /// `app_id` of the installed app to assign to this role.
        app_id: String,
    },

    // -- Trust registry + grant management (Step 8 / identity_model) ----------
    /// Add an org DID to the trusted-issuer registry for this user.
    ///
    /// Once added, the user's daemon will accept `GrantEnvelope`s whose
    /// `issuer_did` matches this DID (subject to signature verification).
    TrustAdd {
        user_id: String,
        /// The fully-qualified `did:key:...` of the org to trust.
        org_did: String,
    },
    /// Remove an org DID from the trusted-issuer registry.
    ///
    /// Existing imported envelopes signed by this DID are not deleted, but
    /// will no longer pass the trusted-issuer check for new imports and will
    /// be rejected by the enforcement checker.
    TrustRemove {
        user_id: String,
        /// The fully-qualified `did:key:...` of the org to remove.
        org_did: String,
    },
    /// List all trusted-issuer DIDs for this user.
    TrustList {
        user_id: String,
    },
    /// Add an envelope ID to the local revocation list.
    ///
    /// Any IPC calls from apps whose `GrantEnvelope` matches this ID will be
    /// rejected after this point. Revocation is irreversible on this device.
    GrantRevoke {
        user_id: String,
        /// The UUID from `GrantEnvelope.id`.
        envelope_id: String,
    },
    /// Import a cross-DID `GrantEnvelope` issued by an org.
    ///
    /// The daemon:
    /// 1. Deserialises the JSON.
    /// 2. Rejects self-signed envelopes (`issuer_did == subject_did`).
    /// 3. Verifies the issuer's DID is in the trusted-issuer registry.
    /// 4. Verifies the Ed25519 signature.
    /// 5. Stores the envelope in `imported_grant_envelopes`.
    GrantImport {
        user_id: String,
        /// Full JSON serialisation of the `GrantEnvelope`.
        envelope_json: String,
    },

    // -- Org identity - single-key (Step 9 / identity_model) ----------------
    /// Create a new org identity.
    ///
    /// Generates a fresh Ed25519 keypair, stores the private scalar in the OS
    /// keychain (`kotton:org_key:{org_did}`), inserts a row in `org_identities`,
    /// and returns the new org DID.
    OrgNew {
        user_id: String,
        /// Human-readable org name, e.g. `"kotton-core"`.
        name: String,
    },
    /// Return metadata for an org DID owned by this user.
    OrgShow {
        user_id: String,
        /// Fully-qualified `did:key:...` of the org.
        org_did: String,
    },
    /// List all org identities owned by this user.
    OrgList {
        user_id: String,
    },
    /// Issue a `GrantEnvelope` from an org to a member DID.
    ///
    /// Signs with the org's Ed25519 key from the OS keychain. Records the
    /// issued envelope in `org_members` for later revocation. The caller
    /// is responsible for delivering the envelope JSON to the member
    /// (out-of-band, e.g. via `kotton msg` or a shared file).
    OrgGrantIssue {
        user_id: String,
        /// DID of the org issuing the grant.
        org_did: String,
        /// DID of the member receiving the grant.
        member_did: String,
        /// Capability strings in display form, e.g. `["schema.read:sh.kotton.notes"]`.
        caps: Vec<String>,
        /// Optional TTL in seconds. `None` means no expiry (not recommended
        /// for cross-DID grants).
        ttl_secs: Option<i64>,
        /// Optional node DID to scope the envelope to a specific device.
        node_did: Option<String>,
    },
    /// List all grants issued by an org.
    OrgGrantList {
        user_id: String,
        /// DID of the org to query.
        org_did: String,
    },
    /// Revoke all outstanding `GrantEnvelope`s issued by an org to a member.
    ///
    /// Adds every tracked envelope ID for `member_did` to the local revocation
    /// list and deletes the corresponding `org_members` rows.
    OrgMemberRemove {
        user_id: String,
        /// DID of the org.
        org_did: String,
        /// DID of the member whose envelopes should be revoked.
        member_did: String,
    },
    /// Create a root **owned by an org** this person holds, with the person as its first
    /// member, and delegate `org.invite` on it to them (RFC-0088, "Ownership and membership").
    ///
    /// The one production path to a second root (`RootSet::add`). Refused when `org_did` is
    /// not an org this person holds on this device, or names the person themselves: the
    /// project root's owner is an identity that is not any person's (RFC-0088 rule 5).
    /// Answered with `OrgRootCreated`.
    OrgRootCreate {
        user_id: String,
        /// The org identity (`did:key:…`) the root is created under.
        org_did: String,
        /// The person's word for the root, e.g. the project's name.
        name: String,
    },
    /// Admit `member` to a root an org owns, and issue their membership grant — **under the
    /// caller's `org.invite` on that root**, issued by the root's owner, and refused without
    /// it. The capability is checked, never a role name (DEC-0080). Answered with
    /// `OrgRootInvited`.
    OrgRootInvite {
        user_id: String,
        /// The root's id, as `OrgRootCreated` gave it.
        root: String,
        /// The identity being let in — their AID (`did:kel:…`), as a root's members are.
        member: String,
    },

    // -- Org identity - FROST multi-sig (Step 10 / identity_model) ----------
    /// Create a new FROST-keyed org identity using the trusted-dealer path.
    ///
    /// The daemon calls `frost::generate_key_shares`, derives the org DID from
    /// the group verifying key, stores the initiator's `KeyPackage` +
    /// `PublicKeyPackage` in SQLite, and returns the share blobs for all other
    /// participants. Each share blob must be delivered to its participant over a
    /// confidential channel; the participant imports it with `OrgFrostJoin`.
    OrgFrostNew {
        user_id: String,
        /// Human-readable org name.
        name: String,
        /// Minimum number of co-signers required to produce a valid signature.
        threshold: u16,
        /// Total number of participants.
        total: u16,
    },
    /// A non-initiator participant imports their FROST key share for an org.
    ///
    /// The `share_hex` blob was printed by the initiator's `OrgFrostNew`
    /// response and delivered out-of-band.  The daemon validates the share,
    /// converts it to a `KeyPackage`, stores it in `frost_key_packages`, and
    /// also inserts a row in `org_identities` (so the org is visible in
    /// `OrgList`).
    OrgFrostJoin {
        user_id: String,
        /// Human-readable name for the org (used in `org_identities`).
        name: String,
        /// The org DID (`did:key:...`), as printed by the initiator.
        org_did: String,
        /// The hex-encoded `KeyPackage` blob assigned to this participant.
        share_hex: crate::ipc::vault_request::SecretText,
        /// 1-based participant index that was assigned to this share.
        participant_idx: u16,
    },
    /// Initiate a FROST signing ceremony for a grant, round 1.
    ///
    /// The daemon generates a `GrantEnvelope` with all fields populated except
    /// the signature, serialises it as the message, runs FROST round-1
    /// (`signing_commit`), persists the session, and returns the session ID +
    /// round-1 commitment to be shared with co-signers.
    ///
    /// Called internally from `OrgGrantIssue` when `is_frost_org` returns true;
    /// also callable directly.
    OrgFrostSignBegin {
        user_id: String,
        /// DID of the FROST org issuing the grant.
        org_did: String,
        /// DID of the member receiving the grant.
        member_did: String,
        /// Capability strings in display form.
        caps: Vec<String>,
        /// Optional TTL in seconds.
        ttl_secs: Option<i64>,
        /// Optional node DID to scope the envelope to a specific device.
        node_did: Option<String>,
    },
    /// A co-signer contributes their round-1 commitment and round-2 share.
    ///
    /// The co-signer runs both FROST rounds atomically:
    /// 1. `signing_commit` -> their commitment.
    /// 2. `create_signing_package(message, [coordinator_commitment, my_commitment])`.
    /// 3. `signing_sign` -> their share.
    ///
    /// The result (commitment + share) is sent back to the coordinator, who
    /// calls `OrgFrostSignFinalize`.
    OrgFrostSignContribute {
        user_id: String,
        /// Session ID printed by `OrgFrostSignBegin`.
        session_id: String,
        /// Org DID, so the daemon can look up this device's `KeyPackage`.
        org_did: String,
        /// The raw message bytes (hex) to be signed, as printed by `OrgFrostSignBegin`.
        message_hex: String,
        /// The coordinator's FROST `Identifier` (hex), as printed by `OrgFrostSignBegin`.
        coordinator_id_hex: String,
        /// The coordinator's round-1 commitment (hex), as printed by `OrgFrostSignBegin`.
        coordinator_commitment_hex: String,
    },
    /// Coordinator finalises the FROST signing ceremony.
    ///
    /// Called after receiving one co-signer's contribution. The daemon:
    /// 1. Builds the `SigningPackage` from both commitments.
    /// 2. Signs with its own key share -> own `SignatureShare`.
    /// 3. Calls `frost::aggregate` with both shares.
    /// 4. Embeds the resulting Ed25519 signature into the `GrantEnvelope`.
    /// 5. Stores the envelope in `org_members` (same as single-key path).
    OrgFrostSignFinalize {
        user_id: String,
        /// Session ID from `OrgFrostSignBegin`.
        session_id: String,
        /// Co-signer's FROST `Identifier` (hex), as returned by `OrgFrostSignContribute`.
        cosigner_id_hex: String,
        /// Co-signer's round-1 commitment (hex), as returned by `OrgFrostSignContribute`.
        cosigner_commitment_hex: String,
        /// Co-signer's round-2 signature share (hex), as returned by `OrgFrostSignContribute`.
        cosigner_share_hex: crate::ipc::vault_request::SecretText,
    },

    // -- Event log (v0.7) -------------------------------------------------
    /// Query persisted daemon events.
    ///
    /// All filters are optional. `since` is a Unix-seconds cursor, only
    /// events with `timestamp > since` are returned. Pass `0` (or omit) to
    /// retrieve from the beginning.
    QueryEvents {
        /// Filter by category (e.g. "auth", "wasm", "ipc"). `None` = all.
        category: Option<String>,
        /// Minimum level ("trace" | "debug" | "info" | "warn" | "error"). `None` = all.
        level: Option<String>,
        /// Unix-seconds cursor. Only events after this timestamp are returned.
        since: Option<i64>,
        /// Maximum number of events to return. Defaults to 200, capped at 500.
        limit: Option<u32>,
    },
    /// Verify the HMAC integrity chain of the event log for the authenticated user.
    ///
    /// Re-derives `hmac_key = HKDF(master_secret, "kotton:hmac:events:v1")` from the
    /// user's keychain-stored seed and walks every event row in insertion order,
    /// re-computing the rolling HMAC-SHA256 chain. Returns whether the chain is intact
    /// and, if not, the Unix timestamp of the first broken row.
    ///
    /// Requires an authenticated session (master_secret must be available in the OS
    /// keychain). Cold-start events written before any unlock have an empty hmac and
    /// are skipped (sentinel value, not a chain break).
    VerifyEventLog {
        user_id: String,
    },

    /// Subscribe to the live event stream.
    ///
    /// After sending this request the connection switches to streaming mode:
    /// the server writes a sequence of [`DeviceResponse::EventStream`] frames
    /// until the connection is dropped (client disconnect) or the daemon shuts
    /// down (server sends [`DeviceResponse::EventStreamEnd`]).
    ///
    /// Filtering mirrors [`QueryEvents`]: omit either field to receive all
    /// categories / levels.
    SubscribeEvents {
        /// Filter by category (e.g. `"wasm"`, `"auth"`). `None` = all.
        category: Option<String>,
        /// Minimum level (`"trace"` ... `"error"`). `None` = all.
        level: Option<String>,
    },

    // -- VFS watch subscription (RFC-0017) -------------------------------------
    /// Subscribe to filesystem change notifications for `user_id`'s VFS.
    ///
    /// Streaming: opens with [`crate::UserResponse::VfsWatchReady`] — the watch
    /// is established, and a change made from here on is delivered — then
    /// [`crate::UserResponse::VfsChanged`] frames, then
    /// [`crate::UserResponse::VfsWatchEnd`] when the subscription closes.
    ///
    /// **Wait for the first frame before acting.** Sending this request does not
    /// establish the watch; a write made before `VfsWatchReady` arrives can be
    /// missed with no error and no way to detect the loss.
    ///
    /// `paths` is a list of VFS path prefixes to watch; empty = watch all.
    VfsWatch {
        user_id: String,
        /// VFS path prefixes to filter on.  Empty = all paths.
        paths: Vec<String>,
    },

    // -- Runtime inspection (runtime_inspection sprint) -----------------------
    /// Return a snapshot of all sidecar processes managed by this kuserd instance.
    ///
    /// The first row is always kuserd itself (self-reported). Subsequent rows
    /// are ksyncd, kquicd, and khttpd in that order.
    ///
    /// `Local`-tier — internal runtime state must not be
    /// readable from a remote gateway connection.
    DaemonSidecars,
    /// Return a list of all currently authenticated IPC sessions.
    ///
    /// Each entry corresponds to a connection that has successfully called
    /// `Authenticate`. Sessions are removed when the connection drops or
    /// `LockSession` is called.
    ///
    /// `Local`-tier — session metadata is internal runtime state.
    IpcSessions,

    // -- Network status (net_status sprint) -----------------------------------
    /// Report current connected-peer state from ksyncd to kuserd.
    ///
    /// Sent by `ksyncd` after each QUIC connection-state change.
    /// `kuserd` stores the set in `DeviceDaemon::connected_peers`.
    ///
    /// `Local`-tier — daemon-internal reporting only.
    VfsReport {
        connected_peers: Vec<String>,
    },
    /// Return sync state for the given user: last sync time, pending items,
    /// connected peer count, and whether ksyncd is running.
    SyncStatus {
        user_id: String,
    },
    /// Return a complete network-status snapshot for the given user:
    /// configured peers with live connection state, gateway summaries,
    /// rendezvous URL, and sync state.
    ///
    /// `Local`-tier — network topology is local-only operator data.
    NetworkStatus {
        user_id: String,
    },

    /// Whether this node can be reached through its relay right now — the one
    /// fact of [`Self::NetworkStatus`] a person's own phone draws (RFC-0083 R6:
    /// reachability is a readout beside the devices that hold a copy).
    ///
    /// `Remote`-eligible, unlike `NetworkStatus`: it answers a state and two
    /// counts, no address, no port, no bind. A paired browser learning that its
    /// node is reachable is the readout's whole purpose.
    ReachStatus {
        user_id: String,
    },

    // -- Display server / kuid sidecar (RFC-0018) -----------------------------
    // Nothing. Both directions of the compositor conversation are
    // `crate::kuid_ipc` now, on the socketpair kuserd hands kuid at spawn:
    // `KuidRequest` down, `CompositorEvent` up.
    //
    // The kuserd → kuid half moved first (RFC-0082, different acceptor). The
    // kuid → kuserd half — `SurfaceInputEvent`, `SurfaceError`, `SurfaceClosed`
    // — stayed here until 2026-08-27 because it genuinely did arrive on this
    // channel, from kuid holding a bearer token like any other client.
    //
    // What it cost to leave it: a session token names a *user*, so a compositor
    // could not report a keystroke on a machine where nobody had logged in yet.
    // That is every machine on its first boot, and it is why first run had no
    // display server (`TASK-a-new-machine-has-no-display-server`). Moving the
    // three verbs to a channel authorised by possession removed the need for a
    // principal rather than inventing one.

    // -- Daemon health (M22b) -------------------------------------------------
    /// Return a live snapshot of daemon state: uptime, users, apps, events.
    ///
    /// Polled every 5s from the hub health panel. No persistent state required,
    /// all fields are derived from existing tables.
    DaemonStatus,

    // -- session: credentials, locks, and device binding -----------------------
    /// Set the lock policy for a user.  `pin` carries the daily credential and
    /// must be present for any mode other than `LockMode::None`; it is hashed
    /// with Argon2id before storage, and must clear the device's required
    /// strength (RFC-0053 step 3) or the request is refused.
    ///
    /// A credential-bearing mode also seals the device's copy of the person's
    /// keys under the credential, and the policy is written only once that copy
    /// is: a seal that fails refuses the request and leaves the passphrase on
    /// record as it was, or none if there was none.
    SetLockPolicy {
        user_id: String,
        mode: LockMode,
        auto_lock_minutes: u32,
        /// Required when `mode == Pin`; ignored otherwise.
        pin: Option<crate::ipc::vault_request::SecretText>,
    },
    /// Return the current lock policy for a user (mode + auto_lock_minutes;
    /// pin hash is never returned).
    GetLockPolicy {
        user_id: String,
    },
    /// Unlock a user's session with a PIN after `LockSession` was called.
    UnlockWithPin {
        user_id: String,
        pin: crate::ipc::vault_request::SecretText,
        /// The owner asks, with the same credential, for the operational roots
        /// to be **repaired** from the vault: a root the store could not read or
        /// does not hold is written from it, a root that read is compared with
        /// it, and a mismatch refuses naming the label
        /// (`TASK-a-keychain-entry-that-fails-permanently-has-no-repair-verb-and-lockedby-says-it-is-recoverable`).
        ///
        /// A field and not a verb of its own, on purpose: a repair is reachable
        /// exactly where an unlock is and answers to exactly its guards — Local
        /// origin, the counted credential — because it *is* this request. A
        /// second session-less variant would be a second door to keep in step.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        repair: bool,
    },
    /// Which credentials this device will accept to open a session for
    /// `user_id` — asked **before** any session exists (RFC-0053 step 2).
    ///
    /// A client cannot use `GetRecoveryStatus` to discover whether a PIN is set,
    /// because that requires the session it is trying to obtain. So the login
    /// path either prompts for a credential that may not exist, or asks.
    ///
    /// Asking is safe because **the credential type is not a secret**: every
    /// lock screen announces that it wants a PIN before the user proves
    /// anything, SSH advertises `publickey,password` to an unauthenticated
    /// caller, and a password manager publishes its KDF parameters in an
    /// unopened vault header. What must stay secret is the credential, and this
    /// discloses none of it.
    ///
    /// Local-origin only, like [`UserRequest::UnlockWithPin`]. It is a small
    /// enumeration surface — it tells a caller which door to knock on — and a
    /// remote caller has no business asking, since it cannot use either answer.
    GetUnlockMethods {
        user_id: String,
    },
    /// The three lifetimes behind "am I logged in", for `user_id`, in one
    /// answer: whether this connection holds a live session for them and
    /// until when, and whether their vault is open and until when. The
    /// verb `whoami` reads on both surfaces
    /// (`TASK-unlock-never-ends-and-nothing-reports-it`, `Done when` 2).
    ///
    /// Session-less, necessarily: "do I have a session" cannot require one.
    /// Local-origin only, with `GetUnlockMethods` and for its reason — it
    /// says who is unlocked at this machine, which is nobody's business
    /// over a gateway. It discloses no key material and no credential, and
    /// an unknown user reads as `Locked` with no session, the same as a
    /// real one who never unlocked.
    GetUnlockState {
        user_id: String,
    },
    /// Close custody for `user_id` now — drop the operational roots from this
    /// daemon's memory and rebuild their resident store without a key — so the
    /// vault is sealed until the daily credential opens it again
    /// (`TASK-nothing-closes-custody-on-request`).
    ///
    /// Not `LockSession`: that ends the *authorisation*, this ends *possession
    /// of keys*, and the two are separately callable on purpose. A person
    /// stepping away from a shared machine closes the vault and keeps their
    /// CLI logged in; a script ending its session must not close the vault
    /// under another process. Requires the user's own session, so nobody
    /// locks another person's vault out from under them. Local-origin, with
    /// `UnlockWithPin`: what opens and closes the vault is decided at the
    /// machine that holds it.
    LockCustody {
        user_id: String,
    },
    /// Bind this user's at-rest vault to this device's hardware (RFC-0053
    /// step 8, RFC-0056 `HardwareCustody`).
    ///
    /// Opt-in and irreversible-by-hardware: after this the vault opens only on
    /// this machine, and clearing the TPM leaves the recovery phrase as the only
    /// way back in. Carries the credential because the vault must be re-sealed
    /// under a key that mixes in the binding, which cannot be done without
    /// opening it.
    BindDeviceHardware {
        user_id: String,
        credential: crate::ipc::vault_request::SecretText,
    },

    // -- peer: contacts ---------------------------------------------------------
    /// Admit another identity on this device as a contact.
    ///
    /// The first domino in "contacts -> admission -> channel key grant":
    /// granting a channel key resolves the member's public key from the
    /// membership registry, and until this verb the only writer of that registry
    /// was device pairing — so it could hold your own devices and no one else.
    ContactAdd {
        user_id: String,
        /// The contact's AID (`did:kel:...`).
        contact_did: String,
    },
    /// Start pairing with another person (RFC-0022, DEC-0055): print a spoken
    /// code, wait at this node's relay for whoever types it, and run the
    /// ceremony. **Streams** like `DeviceAdd`: `PairAdvertising` (the code) →
    /// `PairConnected` → `PairShowCode` → `ContactPaired` | `PairFailed`. The
    /// six digits are confirmed by `PairConfirmCode`. Needs a session and a
    /// screen of the person's own — `Paired`, so this machine or a browser it
    /// admitted by ceremony, and not a gateway or an mTLS peer (DEC-0057).
    ContactPairStart {
        user_id: String,
        /// The name the other person's screen will call this one. Defaults to
        /// `user_id`.
        as_name: Option<String>,
        /// How long to wait for the other person, in seconds.
        ttl_seconds: u64,
    },
    /// Join another person's pairing by the code they read out. **Streams** the
    /// same frames as `ContactPairStart` from `PairConnecting` on. Needs a
    /// session, and `Paired` like its sibling above.
    ContactPairJoin {
        user_id: String,
        /// The code as heard: case and separators do not matter.
        code: crate::ipc::SecretText,
        as_name: Option<String>,
    },
    /// List the contacts `user_id` has admitted.
    ContactList {
        user_id: String,
    },

    // -- Recovery status (M25b) -----------------------------------------------
    /// Mark that the user has confirmed their BIP-39 recovery mnemonic.
    ///
    /// Writes `users/{user_id}/onboarding.json` with `mnemonic_confirmed: true`.
    /// Call this once the onboarding flow has verified word re-entry.
    ConfirmMnemonic {
        user_id: String,
    },
    /// Return the recovery layer coverage for a user.
    ///
    /// Checks: mnemonic confirmed, PIN set, escrow blob, guardian count.
    GetRecoveryStatus {
        user_id: String,
    },

    // -- Key health (M26h) ----------------------------------------------------
    /// Return the cryptographic health summary for a user.
    ///
    /// Reports the active signing algorithm, key version, rotation status, and
    /// the status of every recovery layer.  Safe to call at any time, reads
    /// only on-disk files, no keychain access required.
    GetKeyHealth {
        user_id: String,
    },

    // -- Post-quantum migration (M25c) -----------------------------------------

    // -- Peer messaging (peer_messaging sprint) --------------------------------
    /// Encrypt and store an encrypted DM as `sh.kotton.message.v1`.
    ///
    /// The daemon looks up `recipient_did`'s Ed25519 public key from the
    /// contacts/identity registry, performs X25519 ECDH with an ephemeral
    /// keypair, derives a ChaCha20-Poly1305 session key via HKDF-SHA-256, and
    /// inserts the resulting record.  The plaintext body never leaves the
    /// daemon process unencrypted.
    MessageSend {
        user_id: String,
        /// `did:key:...` of the message recipient.
        recipient_did: String,
        /// UTF-8 plaintext body (the daemon encrypts it).
        body: String,
        /// Optional thread identifier, callers may pass the `id` of the first
        /// message in a thread to group related messages.
        thread_id: Option<String>,
    },

    /// Encrypt and store a channel message as `sh.kotton.message.v1`.
    ///
    /// `channel_did` identifies the channel (typically the org DID). The daemon
    /// looks up the channel's symmetric key from a `sh.kotton.channel.key-grant`
    /// record stored for this user and encrypts the plaintext with it.
    MessageChannelSend {
        user_id: String,
        /// `did:key:...` of the channel identity.
        channel_did: String,
        /// UTF-8 plaintext body.
        body: String,
    },

    /// Create a new channel and generate + store its symmetric key for the creator.
    ///
    /// The daemon generates a 32-byte random channel key via
    /// `channel_key_generate()`, wraps it with X25519 ECDH to the creator's
    /// own `did:…` public key, and stores it as a
    /// `sh.kotton.channel.key-grant` record at **epoch 0** in the creator's
    /// record store. Every later membership change mints the next epoch.
    ///
    /// Returns `MessageSent { message_id }` with the key-grant record ID.
    MessageChannelCreate {
        user_id: String,
        /// `did:…` of the channel identity.
        channel_did: String,
    },

    /// Admit a member to a channel, rotating the channel key as it does.
    ///
    /// The daemon mints a **new channel key epoch** and grants it to the current
    /// membership plus the new member — it does not re-wrap the existing key.
    /// That is what makes the new member's reach begin at their admission
    /// rather than at the channel's creation: they hold no key for the earlier
    /// epochs, so that history stays closed to them wherever they meet it.
    ///
    /// A member with a local account on this daemon gets the grant written
    /// directly into their record store; a member elsewhere receives theirs by
    /// sync. The grant is always returned as `ChannelKeyGrantCreated { grant }`
    /// for out-of-band delivery if needed.
    MessageChannelGrantKey {
        user_id: String,
        channel_did: String,
        /// `did:…` of the member to admit.
        member_did: String,
        /// Also grant every earlier epoch, so the member can read the history.
        ///
        /// The default is `false`: joining shows you the conversation from the
        /// point you joined. Setting it is the admitter's deliberate choice to
        /// share what came before — per admission, rather than as a property
        /// fixed once for everyone.
        backfill: bool,
    },

    /// Remove a member from a channel: the rotation [`Self::MessageChannelGrantKey`]
    /// makes, with the member omitted instead of added.
    ///
    /// The daemon mints a **new channel key epoch** and grants it to every
    /// current member but `member_did`. They keep the grants they hold, so what
    /// was said while they were in stays open to them; what is sealed after the
    /// rotation is under a key they were never given. RFC-0064: "a rotation that
    /// omits someone is how a member stops being one; there is no second
    /// protocol."
    ///
    /// Whoever may admit may remove: the caller must hold, and be able to open,
    /// the channel's current key. Removing yourself is refused — the remover
    /// mints the next key, so it cannot omit them. Answers `Ok`.
    MessageChannelRemoveMember {
        user_id: String,
        channel_did: String,
        /// `did:…` of the member to remove.
        member_did: String,
    },

    /// Leave a channel: say so in it, then let go of its keys.
    ///
    /// The daemon posts a `leave` notice into the channel — a channel message,
    /// sealed under the newest epoch the caller holds and signed by them, handed
    /// to every current member as any post is — and then **drops every
    /// key-grant the caller holds for the channel**. From then on the channel
    /// is not among the groups the caller holds a key for, and nothing sealed
    /// after opens for them on this node, even given the ciphertext. The
    /// records they hold — the conversation's ciphertext, and every file shared
    /// with them, which is a copy of theirs — are not touched.
    ///
    /// Leaving is not removing yourself: the remover mints the next key, so a
    /// rotation cannot omit the person who makes it. One remaining member does
    /// instead — whichever member's DID sorts first in the roster without the
    /// leaver rotates to the next epoch on filing the notice, and every other
    /// member waits for that epoch.
    ///
    /// **Leaving is unconditional.** Each member's copy of the notice waits in
    /// the caller's outbox until a device of theirs signs for it, carried by
    /// the caller's vault meanwhile, and the keys are dropped as soon as it is
    /// posted: the leave is done on the caller's node then, and the others
    /// learn of it as it reaches them. Only a notice never posted — the
    /// caller's own copy could not be written — leaves the caller in. Answers
    /// `ChannelSent` with each member's delivery, as a post does.
    MessageChannelLeave {
        user_id: String,
        channel_did: String,
    },

    /// Return up to `limit` raw (encrypted) `sh.kotton.message.v1` records for
    /// a channel, newest-filed first — by `filed_at`, the stamp the person's
    /// own device filed each with — each carrying `filed_at`.
    ///
    /// Records are returned to the client still encrypted; the client SDK is
    /// responsible for decryption using the channel key grant.
    MessageChannelHistory {
        user_id: String,
        channel_did: String,
        /// Pagination cursor, only messages with a `record_id` lexicographically
        /// less than this value are returned.  Pass `None` to start from the
        /// newest message.
        before_id: Option<String>,
        /// Maximum number of messages to return (capped at 100 by the daemon).
        limit: u32,
    },

    /// Return all `sh.kotton.message.v1` records addressed to `user_id`
    /// (i.e. where `to_did` equals the user's DID), newest-filed first and
    /// capped at 50. Each carries `filed_at` — when this person's device filed
    /// it, on that device's clock — which is the key a conversation is ordered by;
    /// its `sent_at` is the sender's claim.
    ///
    /// Records are returned still encrypted.  The caller decrypts using their
    /// own identity key.
    MessagePollInbox {
        user_id: String,
    },

    /// What each direct message this person sent `peer_did` reads as: *sent*,
    /// *delivered*, or *waiting at home* with when it is next tried
    /// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
    ///
    /// The same one word `MessageSend` answers with, read again later, so a
    /// message that was waiting when it was sent reads *delivered* once one of
    /// the recipient's devices signs for it. Only messages the outbox has held
    /// are listed; which device signed, and when, is not in the answer and is
    /// not kept (`DEC-0056`).
    MessageDeliveries {
        user_id: String,
        peer_did: String,
    },

    /// How many messages this person has not read.
    ///
    /// A count rather than a list, because the thing that needs it is a badge.
    /// Computed from the inbox and the person's own read marks — a message is
    /// unread when it sits above the mark for the conversation it is in.
    MessageUnreadCount {
        user_id: String,
    },

    /// Record that this person has read `peer_did`'s conversation as far as
    /// `(filed_at, message_id)`.
    ///
    /// The position is taken **from the messages that were shown** — the
    /// `filed_at` the message verbs report, which is where this person's own
    /// store filed each one, strictly increasing in the order a device files
    /// them (a row synced from another of the person's devices keeps the stamp
    /// it was filed with there). It
    /// was the sender's `sent_at` until 2026-09-25: whole seconds on a clock the
    /// sender controls, under which a message arriving after the mark could
    /// fall below it and never be counted
    /// (`TASK-a-conversation-is-ordered-by-a-clock-it-does-not-hold`).
    ///
    /// Only ever advances. A caller that has drawn an older stretch of a
    /// conversation is telling the truth about what it drew and would still be
    /// wrong to unread what came after.
    ///
    /// Read state never travels to the sender. It is stronger than `delivered`,
    /// and `DEC-0056` gives the sender four words on purpose.
    MessageMarkRead {
        user_id: String,
        /// The other person in the conversation.
        peer_did: String,
        /// `filed_at` of the newest message that was shown.
        filed_at: u64,
        /// That message's id, as the message verbs report it.
        message_id: String,
    },

    /// Decrypt an encrypted DM on behalf of `user_id`.
    ///
    /// The daemon derives the X25519 private key from the user's Ed25519 identity
    /// key, performs ECDH with `ephemeral_pub`, derives the ChaCha20-Poly1305
    /// session key via HKDF-SHA-256, and decrypts in-process.  Returns
    /// `Decrypted { plaintext }` on success.
    MessageDecryptDm {
        user_id: String,
        /// Base64-encoded ChaCha20-Poly1305 ciphertext.
        body: String,
        /// Base64-encoded 12-byte nonce.
        nonce: String,
        /// Base64-encoded 32-byte ephemeral X25519 public key.
        ephemeral_pub: String,
    },

    /// Decrypt a channel message on behalf of `user_id`.
    ///
    /// The daemon looks up the `sh.kotton.channel.key-grant` record for
    /// `user_id` + `channel_did`, unwraps the channel key, then decrypts
    /// `body` with it.  Returns `Decrypted { plaintext }` on success.
    MessageDecryptChannel {
        user_id: String,
        /// `did:key:...` of the channel.
        channel_did: String,
        /// Base64-encoded ChaCha20-Poly1305 ciphertext.
        body: String,
        /// Base64-encoded 12-byte nonce.
        nonce: String,
    },

    // -- Window registry (M44a) -----------------------------------------------
    /// Notify the daemon that a WASM app window was opened.
    ///
    /// A client on the person's session sends it when it opens a window for an
    /// app, through `KottonClient::window_opened`; no client in the tree does.
    WindowOpened {
        /// Reverse-domain app identifier, e.g. `"sh.kotton.notes"`.
        app_id: String,
        /// UUID that uniquely identifies this open instance.
        instance_id: String,
        /// Window title (initially the app name).
        title: String,
    },
    /// Notify the daemon that a WASM app window was closed.
    WindowClosed {
        /// UUID of the instance being closed.
        instance_id: String,
    },
    /// Return a snapshot of all currently open WASM app windows.
    WindowList,

    // -- Device sync notifications (RFC-0008) ---------------------------------
    /// Sent by a peer after a successful file-sync push.
    ///
    /// On receipt the daemon wakes its local sync engine so it can pull the
    /// pushed objects without waiting for the next poll tick.
    SyncAvailable {
        /// User whose VFS was updated on the sender.
        user_id: String,
        /// Object paths that were written (informational; may be empty).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        paths: Vec<String>,
    },

    /// Sent by a peer after a successful record-sync push.
    ///
    /// Wakes the local record sync pass for the listed NSIDs.
    RecordSyncAvailable {
        /// User whose records were updated on the sender.
        user_id: String,
        /// NSIDs that have new or updated records (informational; may be empty).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nsids: Vec<String>,
    },

    /// Push a record changeset from a peer.
    ///
    /// The daemon applies the changeset via `merge_changeset` with LWW
    /// semantics.  Only paired devices may send this request.
    ApplyRecordChangeset {
        /// Owner of the records.
        user_id: String,
        /// NSID of the schema all rows belong to.
        nsid: String,
        /// Rows to merge.
        rows: Vec<SyncChangesetRow>,
    },
}

impl UserRequest {
    /// Returns the `user_id` for requests that operate on behalf of a specific
    /// user, or `None` for device-level and public operations.
    ///
    /// Used by the daemon's central auth guard to enforce session ownership
    /// before dispatching to a handler.
    pub fn target_user_id(&self) -> Option<&str> {
        match self {
            Self::LogoutUser { user_id } => Some(user_id),
            Self::ReadFile { user_id, .. } => Some(user_id),
            Self::WriteFile { user_id, .. } => Some(user_id),
            Self::ListFiles { user_id, .. } => Some(user_id),
            Self::DeleteFile { user_id, .. } => Some(user_id),
            Self::ListConflicts { user_id, .. } => Some(user_id),
            Self::ResolveConflict { user_id, .. } => Some(user_id),
            Self::PurgeFile { user_id, .. } => Some(user_id),
            Self::MintPrincipalSession { user_id, .. } => Some(user_id),
            Self::ReadSealed { user_id, .. } => Some(user_id),
            Self::ListSealed { user_id, .. } => Some(user_id),
            Self::WriteSealed { user_id, .. } => Some(user_id),
            Self::RemoteAdd { user_id, .. } => Some(user_id),
            Self::RemoteRemove { user_id, .. } => Some(user_id),
            Self::RemoteList { user_id } => Some(user_id),
            Self::RemoteCacheClear { user_id, .. } => Some(user_id),
            Self::RemoteCredentialsSet { user_id, .. } => Some(user_id),
            Self::SyncMount { user_id, .. } => Some(user_id),
            Self::PairNodeEphemeral { user_id, .. } => Some(user_id),
            Self::DeviceAdd { user_id, .. } => Some(user_id),
            // DeviceJoin is the bootstrap that *establishes* this user on a new
            // device — the joiner has no session for the user yet (it is creating one
            // from the ceremony), so it cannot require a pre-existing authenticated
            // session. Its security is the cryptographic ceremony (committed
            // handshake + six-digit SAS), like CreateUser/login which are likewise
            // session-less.
            Self::DeviceJoin { .. } => None,
            Self::PairConfirmCode { user_id, .. } => Some(user_id),
            // DeviceName is device-level (no user).
            Self::DeviceName { .. } => None,
            // RotateIdentity is authorized by the mnemonic (revealing K_rec) AND
            // gated to an authenticated local session — a sensitive identity op.
            Self::RotateIdentity { user_id, .. } => Some(user_id),
            Self::Recover { user_id, .. } => Some(user_id),
            Self::RecoveryFetch { user_id } => Some(user_id),
            Self::RecoveryStore { user_id, .. } => Some(user_id),
            Self::BrowserOutbound { .. } => None,
            Self::HoldDoors { user_id, .. } => Some(user_id),
            Self::CarryFrame { user_id, .. } => Some(user_id),
            Self::TenantDevice { user_id, .. } => Some(user_id),
            Self::TakeDeliveries { user_id, .. } => Some(user_id),
            Self::NodeList { user_id } => Some(user_id),
            Self::NodeRelay { user_id } => Some(user_id),
            Self::Introduce { user_id, .. } => Some(user_id),
            Self::VaultCapacity { user_id } => Some(user_id),
            Self::NodeRevoke { user_id, .. } => Some(user_id),
            Self::FrostSignRound { user_id, .. } => Some(user_id),
            Self::ThresholdSign { user_id, .. } => Some(user_id),
            Self::PeerAdd { user_id, .. } => Some(user_id),
            Self::SyncConfigure { user_id, .. } => Some(user_id),
            Self::SyncRuleList { user_id } => Some(user_id),
            Self::SyncRuleRemove { user_id, .. } => Some(user_id),
            Self::SyncTrigger { user_id, .. } => Some(user_id),
            Self::SyncAwait { user_id, .. } => Some(user_id),
            Self::MountPath { user_id, .. } => Some(user_id),
            Self::MountList { user_id } => Some(user_id),
            Self::MountEvict { user_id, .. } => Some(user_id),
            Self::SessionList { user_id } => Some(user_id),
            Self::SessionEnd { user_id, .. } => Some(user_id),
            Self::RecordInsert { user_id, .. } => Some(user_id),
            Self::RecordQuery { user_id, .. } => Some(user_id),
            Self::RecordSearch { user_id, .. } => Some(user_id),
            Self::RecordDelete { user_id, .. } => Some(user_id),
            Self::RecordOpen { user_id, .. } => Some(user_id),
            Self::Import { user_id, .. } => Some(user_id),
            // A model is installed into one person's store, listed out of it
            // and removed from it: the session must own the named user, the
            // same as every other verb over their records.
            Self::ModelAdd { user_id, .. } => Some(user_id),
            Self::ModelWeights { user_id, .. } => Some(user_id),
            Self::ModelList { user_id } => Some(user_id),
            Self::ModelRemove { user_id, .. } => Some(user_id),
            Self::ModelUse { user_id, .. } => Some(user_id),
            // Schema verbs — principal-scoped since the SCHEMA-REGISTRY-IS-
            // MACHINE-WIDE narrowing; the session must own the named user.
            Self::SchemaList { user_id } => Some(user_id),
            Self::SchemaRegister { user_id, .. } => Some(user_id),
            Self::SchemaGet { user_id, .. } => Some(user_id),
            // M23c PIN/lock - all require an authenticated session.
            Self::SetLockPolicy { user_id, .. } => Some(user_id),
            Self::GetLockPolicy { user_id } => Some(user_id),
            // UnlockWithPin is the *re-authentication* path after a lock;
            // it carries the user_id but intentionally bypasses the session
            // guard so unauthenticated connections can unlock.
            Self::UnlockWithPin { .. } => None,
            // GetUnlockMethods is asked *before* a session exists, by definition.
            Self::GetUnlockMethods { .. } => None,
            // GetUnlockState answers whether one exists, so it cannot require one.
            Self::GetUnlockState { .. } => None,
            // Closing the vault is the owner's act: the session must be theirs.
            Self::LockCustody { user_id } => Some(user_id),
            Self::BindDeviceHardware { user_id, .. } => Some(user_id),
            // Recovery status (M25b) - require authenticated session.
            Self::ContactAdd { user_id, .. } => Some(user_id),
            Self::ContactList { user_id } => Some(user_id),
            Self::ConfirmMnemonic { user_id } => Some(user_id),
            Self::GetRecoveryStatus { user_id } => Some(user_id),
            // Key health (M26h) - requires authenticated session.
            Self::GetKeyHealth { user_id } => Some(user_id),
            // Event log verification (M26i) - requires authenticated session.
            Self::VerifyEventLog { user_id } => Some(user_id),
            // Post-quantum migration (M25c) - requires authenticated session.
            // App install - scoped to a specific user.
            // An empty user_id means a system/bundled install; no session required.
            // `AppInstallPreview` is scoped identically. It mints nothing, but
            // it reads a package on a named user's behalf, and asking questions
            // about one user's install from another user's session is not a
            // thing to leave reachable. (Written after the preview's own test
            // passed *because* this arm was missing — the request fell to the
            // catch-all and needed no session at all.)
            Self::AppInstall { user_id, .. } | Self::AppInstallPreview { user_id, .. } => {
                if user_id.is_empty() {
                    None
                } else {
                    Some(user_id)
                }
            }
            // Trust registry + grant management - all require an authenticated session.
            Self::TrustAdd { user_id, .. } => Some(user_id),
            Self::TrustRemove { user_id, .. } => Some(user_id),
            Self::TrustList { user_id } => Some(user_id),
            Self::GrantRevoke { user_id, .. } => Some(user_id),
            Self::GrantImport { user_id, .. } => Some(user_id),
            // Org identity - all require an authenticated session.
            Self::OrgNew { user_id, .. } => Some(user_id),
            Self::OrgShow { user_id, .. } => Some(user_id),
            Self::OrgList { user_id } => Some(user_id),
            Self::OrgGrantIssue { user_id, .. } => Some(user_id),
            Self::OrgGrantList { user_id, .. } => Some(user_id),
            Self::OrgMemberRemove { user_id, .. } => Some(user_id),
            Self::OrgRootCreate { user_id, .. } => Some(user_id),
            Self::OrgRootInvite { user_id, .. } => Some(user_id),
            // FROST multi-sig - all require an authenticated session.
            Self::OrgFrostNew { user_id, .. } => Some(user_id),
            Self::OrgFrostJoin { user_id, .. } => Some(user_id),
            Self::OrgFrostSignBegin { user_id, .. } => Some(user_id),
            Self::OrgFrostSignContribute { user_id, .. } => Some(user_id),
            Self::OrgFrostSignFinalize { user_id, .. } => Some(user_id),
            // Peer messaging - all require an authenticated session.
            Self::MessageChannelCreate { user_id, .. } => Some(user_id),
            Self::MessageChannelGrantKey { user_id, .. } => Some(user_id),
            Self::MessageChannelRemoveMember { user_id, .. } => Some(user_id),
            Self::MessageChannelLeave { user_id, .. } => Some(user_id),
            Self::MessageSend { user_id, .. } => Some(user_id),
            Self::MessageChannelSend { user_id, .. } => Some(user_id),
            Self::MessageChannelHistory { user_id, .. } => Some(user_id),
            Self::MessagePollInbox { user_id } => Some(user_id),
            Self::MessageUnreadCount { user_id } => Some(user_id),
            Self::MessageDeliveries { user_id, .. } => Some(user_id),
            Self::MessageMarkRead { user_id, .. } => Some(user_id),
            Self::MessageDecryptDm { user_id, .. } => Some(user_id),
            Self::MessageDecryptChannel { user_id, .. } => Some(user_id),
            // VFS watch (RFC-0017)
            Self::VfsWatch { user_id, .. } => Some(user_id),
            // QUIC gateway (RFC-0015) — user-scoped operations
            Self::GetAuthorizedClients { user_id } => Some(user_id),
            Self::GetDeviceCert { user_id } => Some(user_id),
            // HTTP gateway (RFC-0016) u{2014} user-scoped operations
            Self::WebShellPair { user_id, .. } => Some(user_id),
            Self::BrowserDeviceList { user_id } => Some(user_id),
            Self::BrowserDeviceRevoke { user_id, .. } => Some(user_id),
            Self::GatewayEnroll { user_id, .. } => Some(user_id),
            Self::DeviceAdmit { user_id, .. } => Some(user_id),
            Self::RelayStand { user_id, .. } => Some(user_id),
            Self::DeviceInvite { user_id, .. } => Some(user_id),
            // The person whose store holds the credential.
            Self::OperatorMint { user_id, .. } => Some(user_id),
            Self::OperatorEnrol { user_id, .. } => Some(user_id),
            Self::OperatorEnrolLines { user_id, .. } => Some(user_id),
            Self::OperatorMints { user_id } => Some(user_id),
            Self::OperatorHeld { user_id, .. } => Some(user_id),
            Self::OperatorForget { user_id, .. } => Some(user_id),
            Self::AsOperator { user_id, .. } => Some(user_id),
            // Network status (net_status sprint)
            Self::SyncStatus { user_id } => Some(user_id),
            Self::NetworkStatus { user_id } => Some(user_id),
            Self::ReachStatus { user_id } => Some(user_id),
            // Device-level and public operations - no session required.
            _ => None,
        }
    }

    /// Whether this request may only be dispatched on a connection that already
    /// holds an authenticated session.
    ///
    /// **Default-deny.** Every variant requires a session *except* the explicit
    /// pre-authentication set enumerated below. This is the positive inverse of
    /// gating on [`Self::target_user_id`]`().is_some()`, which required a session
    /// only as a *side effect* of a variant carrying a `user_id` field — leaving
    /// the entire control plane (`SchemaGrantSet`, `AppSetRole`, `RendezvousSet`,
    /// `RegisterHandler`, …) reachable over local IPC with **no session at all**,
    /// even while the screen is locked (security audit finding C2). Because the
    /// default is "session required", a variant added later is gated by default;
    /// opting out is a deliberate edit to this list, reviewed as a security change.
    ///
    /// The session *ownership* check (the session must belong to the `user_id` a
    /// request names) still rides on [`Self::target_user_id`]; this method only
    /// decides whether a session must exist at all.
    pub fn requires_session(&self) -> bool {
        // `AppInstall` mirrors `target_user_id`: a user-scoped install requires
        // that user's session, but an empty `user_id` is a system/bundled install
        // (session-less by existing design — the daemon installs bundled apps at
        // setup; H2 tracks its separate consent gap).
        if let Self::AppInstall { user_id, .. } | Self::AppInstallPreview { user_id, .. } = self {
            return !user_id.is_empty();
        }
        !matches!(
            self,
            // ── Bootstrap ────────────────────────────────────────────────────
            // These *establish* an identity or session, so they cannot presuppose
            // one. Each carries its own cryptographic guard (mnemonic, PIN vault,
            // or the enrollment ceremony) rather than a session token.
            Self::CreateUser { .. }             // mints the identity + first session
                | Self::LoginWithRecoveryKey { .. } // mnemonic → session
                | Self::Authenticate { .. }         // sets the connection's session token
                | Self::UnlockWithPin { .. }        // re-authentication after a lock
                | Self::DeviceJoin { .. }           // RFC-0040 fresh-device join (bootstrap)
                // RFC-0084 V8's other half: a fresh vault mints an invite and
                // waits at its relay to be admitted, before it is anyone's. The
                // same bootstrap shape as `DeviceJoin`, and said here because it
                // is now read — the streaming path used to skip this question
                // for the listening transport this replaced, and answer it by
                // having no check at all.
                | Self::DeviceInvite { .. }
                // PairConfirmCode carries the human's SAS verdict. The joiner side
                // runs during a session-less bootstrap join, so it cannot require a
                // session; the fresh ceremony token (surfaced only to the local
                // stream) is the authorization, and it is local-only.
                | Self::PairConfirmCode { .. }
                // Device-level machine name; readable/settable before login (e.g.
                // naming a fresh device before it joins). Local-only.
                | Self::DeviceName { .. }
                // ── Pre-auth introspection ───────────────────────────────────
                // Read-only, expose no user data, and are needed before a session
                // exists (onboarding / login / pairing bootstrap).
                | Self::CallerInfo                  // calling process + connection state
                | Self::ListUsers                   // enumerate user ids to log in as
                | Self::GetActiveSession            // returns the session user, or None
                | Self::GetNodeIdentity             // this node's public DID (pairing)
                | Self::GetUnlockMethods { .. }     // which credential to prompt for
                | Self::GetUnlockState { .. }       // is there a session; is the vault open
                | Self::LockSession // session lifecycle; a no-op without one
        )
    }

    /// Returns the serde variant name of this request (e.g. `"ReadFile"`).
    ///
    /// Used by the daemon's scope guard to check whether a request is permitted
    /// on a connection that authenticated with a non-empty scope allow-list.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::CreateUser { .. } => "CreateUser",
            Self::AddRecoveryPhrase { .. } => "AddRecoveryPhrase",
            Self::LogoutUser { .. } => "LogoutUser",
            Self::LoginWithRecoveryKey { .. } => "LoginWithRecoveryKey",
            Self::RotateIdentity { .. } => "RotateIdentity",
            Self::Recover { .. } => "Recover",
            Self::RecoveryFetch { .. } => "RecoveryFetch",
            Self::RecoveryStore { .. } => "RecoveryStore",
            Self::BrowserOutbound { .. } => "BrowserOutbound",
            Self::HoldDoors { .. } => "HoldDoors",
            Self::CarryFrame { .. } => "CarryFrame",
            Self::TenantDevice { .. } => "TenantDevice",
            Self::TakeDeliveries { .. } => "TakeDeliveries",
            Self::ListUsers => "ListUsers",
            Self::Authenticate { .. } => "Authenticate",
            Self::CallerInfo => "CallerInfo",
            Self::GetActiveSession => "GetActiveSession",
            Self::LockSession => "LockSession",
            Self::ReadFile { .. } => "ReadFile",
            Self::WriteFile { .. } => "WriteFile",
            Self::ListFiles { .. } => "ListFiles",
            Self::DeleteFile { .. } => "DeleteFile",
            Self::ListConflicts { .. } => "ListConflicts",
            Self::ResolveConflict { .. } => "ResolveConflict",
            Self::PurgeFile { .. } => "PurgeFile",
            Self::MintPrincipalSession { .. } => "MintPrincipalSession",
            Self::BrowserFrame { .. } => "BrowserFrame",
            Self::ReadSealed { .. } => "ReadSealed",
            Self::ListSealed { .. } => "ListSealed",
            Self::WriteSealed { .. } => "WriteSealed",
            Self::StorageReload { .. } => "StorageReload",
            Self::RemoteAdd { .. } => "RemoteAdd",
            Self::RemoteRemove { .. } => "RemoteRemove",
            Self::RemoteList { .. } => "RemoteList",
            Self::RemoteCacheClear { .. } => "RemoteCacheClear",
            Self::RemoteCredentialsSet { .. } => "RemoteCredentialsSet",
            Self::SyncMount { .. } => "SyncMount",
            Self::DeviceAdd { .. } => "DeviceAdd",
            Self::DeviceJoin { .. } => "DeviceJoin",
            Self::PairConfirmCode { .. } => "PairConfirmCode",
            Self::ContactPairStart { .. } => "ContactPairStart",
            Self::ContactPairJoin { .. } => "ContactPairJoin",
            Self::DeviceName { .. } => "DeviceName",
            Self::PairNodeEphemeral { .. } => "PairNodeEphemeral",
            Self::NodeList { .. } => "NodeList",
            Self::NodeRelay { .. } => "NodeRelay",
            Self::Introduce { .. } => "Introduce",
            Self::VaultCapacity { .. } => "VaultCapacity",
            Self::NodeRevoke { .. } => "NodeRevoke",
            Self::FrostSignRound { .. } => "FrostSignRound",
            Self::ThresholdSign { .. } => "ThresholdSign",
            Self::PeerAdd { .. } => "PeerAdd",
            Self::GetNodeIdentity => "GetNodeIdentity",
            Self::SyncConfigure { .. } => "SyncConfigure",
            Self::SyncRuleList { .. } => "SyncRuleList",
            Self::SyncRuleRemove { .. } => "SyncRuleRemove",
            Self::SyncTrigger { .. } => "SyncTrigger",
            Self::SyncAwait { .. } => "SyncAwait",
            Self::MountPath { .. } => "MountPath",
            Self::MountList { .. } => "MountList",
            Self::MountEvict { .. } => "MountEvict",
            Self::SessionList { .. } => "SessionList",
            Self::SessionEnd { .. } => "SessionEnd",
            Self::RendezvousSet { .. } => "RendezvousSet",
            Self::RendezvousStatus => "RendezvousStatus",
            Self::TurnSet { .. } => "TurnSet",
            Self::InferenceSet { .. } => "InferenceSet",
            Self::LocalDoor { .. } => "LocalDoor",
            Self::ModelAdd { .. } => "ModelAdd",
            Self::ModelWeights { .. } => "ModelWeights",
            Self::ModelList { .. } => "ModelList",
            Self::ModelRemove { .. } => "ModelRemove",
            Self::ModelUse { .. } => "ModelUse",
            Self::ConfigStatus => "ConfigStatus",
            Self::QuicGatewaySet { .. } => "QuicGatewaySet",
            Self::QuicGatewayStatus => "QuicGatewayStatus",
            Self::GetAuthorizedClients { .. } => "GetAuthorizedClients",
            Self::GetDeviceCert { .. } => "GetDeviceCert",
            Self::WebShellSet { .. } => "WebShellSet",
            Self::WebShellStatus => "WebShellStatus",
            Self::WebShellPair { .. } => "WebShellPair",
            Self::BrowserDeviceList { .. } => "BrowserDeviceList",
            Self::BrowserDeviceRevoke { .. } => "BrowserDeviceRevoke",
            Self::GatewayEnroll { .. } => "GatewayEnroll",
            Self::DeviceAdmit { .. } => "DeviceAdmit",
            Self::RelayStand { .. } => "RelayStand",
            Self::DeviceInvite { .. } => "DeviceInvite",
            Self::SetQuota { .. } => "SetQuota",
            Self::Tenants => "Tenants",
            Self::DropTenant { .. } => "DropTenant",
            Self::StandAt { .. } => "StandAt",
            Self::InviteDigits { .. } => "InviteDigits",
            Self::OperatorMint { .. } => "OperatorMint",
            Self::OperatorEnrol { .. } => "OperatorEnrol",
            Self::OperatorEnrolLines { .. } => "OperatorEnrolLines",
            Self::OperatorMints { .. } => "OperatorMints",
            Self::OperatorHeld { .. } => "OperatorHeld",
            Self::OperatorForget { .. } => "OperatorForget",
            Self::AsOperator { .. } => "AsOperator",
            Self::RecordInsert { .. } => "RecordInsert",
            Self::RecordQuery { .. } => "RecordQuery",
            Self::RecordSearch { .. } => "RecordSearch",
            Self::RecordDelete { .. } => "RecordDelete",
            Self::RecordOpen { .. } => "RecordOpen",
            Self::Import { .. } => "Import",
            Self::SchemaList { .. } => "SchemaList",
            Self::SchemaRegister { .. } => "SchemaRegister",
            Self::SchemaGet { .. } => "SchemaGet",
            Self::SchemaGrantList { .. } => "SchemaGrantList",
            Self::SchemaGrantSet { .. } => "SchemaGrantSet",
            Self::SchemaGrantRevoke { .. } => "SchemaGrantRevoke",
            Self::SchemaQuotaSet { .. } => "SchemaQuotaSet",
            Self::RegisterHandler { .. } => "RegisterHandler",
            Self::UnregisterHandler { .. } => "UnregisterHandler",
            Self::GetHandlerFor { .. } => "GetHandlerFor",
            Self::ListHandlers => "ListHandlers",
            Self::SetDefaultHandler { .. } => "SetDefaultHandler",
            Self::AppInstall { .. } => "AppInstall",
            Self::AppInstallPreview { .. } => "AppInstallPreview",
            Self::AppGrants { .. } => "AppGrants",
            Self::AppUninstall { .. } => "AppUninstall",
            Self::AppVerify { .. } => "AppVerify",
            Self::ExtensionInstall { .. } => "ExtensionInstall",
            Self::ExtensionList { .. } => "ExtensionList",
            Self::ExtensionRemove { .. } => "ExtensionRemove",
            Self::AppList => "AppList",
            Self::AppRegisterBundle { .. } => "AppRegisterBundle",
            Self::AppGetBundlePath { .. } => "AppGetBundlePath",
            Self::AppGetRole { .. } => "AppGetRole",
            Self::AppSetRole { .. } => "AppSetRole",
            Self::AppLaunch { .. } => "AppLaunch",
            Self::AppMessage { .. } => "AppMessage",
            Self::SubscribeEvents { .. } => "SubscribeEvents",
            Self::QueryEvents { .. } => "QueryEvents",
            Self::GetKeyHealth { .. } => "GetKeyHealth",
            Self::DaemonStatus => "DaemonStatus",
            Self::SetLockPolicy { .. } => "SetLockPolicy",
            Self::GetLockPolicy { .. } => "GetLockPolicy",
            Self::UnlockWithPin { .. } => "UnlockWithPin",
            Self::GetUnlockMethods { .. } => "GetUnlockMethods",
            Self::GetUnlockState { .. } => "GetUnlockState",
            Self::LockCustody { .. } => "LockCustody",
            Self::BindDeviceHardware { .. } => "BindDeviceHardware",
            Self::ContactAdd { .. } => "ContactAdd",
            Self::ContactList { .. } => "ContactList",
            Self::ConfirmMnemonic { .. } => "ConfirmMnemonic",
            Self::GetRecoveryStatus { .. } => "GetRecoveryStatus",
            Self::VerifyEventLog { .. } => "VerifyEventLog",
            Self::TrustAdd { .. } => "TrustAdd",
            Self::TrustRemove { .. } => "TrustRemove",
            Self::TrustList { .. } => "TrustList",
            Self::GrantRevoke { .. } => "GrantRevoke",
            Self::GrantImport { .. } => "GrantImport",
            Self::OrgNew { .. } => "OrgNew",
            Self::OrgShow { .. } => "OrgShow",
            Self::OrgList { .. } => "OrgList",
            Self::OrgGrantIssue { .. } => "OrgGrantIssue",
            Self::OrgGrantList { .. } => "OrgGrantList",
            Self::OrgMemberRemove { .. } => "OrgMemberRemove",
            Self::OrgRootCreate { .. } => "OrgRootCreate",
            Self::OrgRootInvite { .. } => "OrgRootInvite",
            Self::OrgFrostNew { .. } => "OrgFrostNew",
            Self::OrgFrostJoin { .. } => "OrgFrostJoin",
            Self::OrgFrostSignBegin { .. } => "OrgFrostSignBegin",
            Self::OrgFrostSignContribute { .. } => "OrgFrostSignContribute",
            Self::OrgFrostSignFinalize { .. } => "OrgFrostSignFinalize",
            Self::MessageChannelCreate { .. } => "MessageChannelCreate",
            Self::MessageChannelGrantKey { .. } => "MessageChannelGrantKey",
            Self::MessageChannelRemoveMember { .. } => "MessageChannelRemoveMember",
            Self::MessageChannelLeave { .. } => "MessageChannelLeave",
            Self::MessageSend { .. } => "MessageSend",
            Self::MessageChannelSend { .. } => "MessageChannelSend",
            Self::MessageChannelHistory { .. } => "MessageChannelHistory",
            Self::MessagePollInbox { .. } => "MessagePollInbox",
            Self::MessageUnreadCount { .. } => "MessageUnreadCount",
            Self::MessageDeliveries { .. } => "MessageDeliveries",
            Self::MessageMarkRead { .. } => "MessageMarkRead",
            Self::MessageDecryptDm { .. } => "MessageDecryptDm",
            Self::MessageDecryptChannel { .. } => "MessageDecryptChannel",
            Self::WindowOpened { .. } => "WindowOpened",
            Self::WindowClosed { .. } => "WindowClosed",
            Self::WindowList => "WindowList",
            Self::SyncAvailable { .. } => "SyncAvailable",
            Self::RecordSyncAvailable { .. } => "RecordSyncAvailable",
            Self::ApplyRecordChangeset { .. } => "ApplyRecordChangeset",
            Self::VfsWatch { .. } => "VfsWatch",
            Self::DaemonSidecars => "DaemonSidecars",
            Self::IpcSessions => "IpcSessions",
            Self::VfsReport { .. } => "VfsReport",
            Self::SyncStatus { .. } => "SyncStatus",
            Self::NetworkStatus { .. } => "NetworkStatus",
            Self::ReachStatus { .. } => "ReachStatus",
        }
    }
}

/// The exact set of `UserRequest` variants a **`Remote`** caller — a browser
/// session or a network peer — may invoke.
///
/// **This is a pinned mirror, not the authority.** [`UserRequest::required_trust`]
/// decides the tier, exhaustively and per-variant, so the compiler refuses a new
/// request until someone assigns it one.
/// `trust_origin_tests::remote_eligible_set_is_pinned` asserts this list equals the
/// `Remote` arm of that match, so the two cannot drift.
///
/// It exists so callers holding only a variant *name* (integration tests asserting
/// that a particular operation stays local) can check the tier without constructing
/// an instance of every variant.
///
/// It replaces the former `REMOTE_EXCLUDES` denylist, and the inversion is the
/// point: a denylist is **default-allow**, so a variant nobody remembered to list
/// was silently reachable from the network. An allow-list is default-deny —
/// omission removes reach rather than granting it, and the pin test makes any
/// widening a deliberate diff.
pub const REMOTE_ELIGIBLE: &[&str] = &[
    "AppGetBundlePath",
    "AppGetRole",
    "AppLaunch",
    "AppList",
    "AppMessage",
    "AppUninstall",
    "AppVerify",
    "ApplyRecordChangeset",
    "Authenticate",
    "BrowserFrame",
    "BrowserOutbound",
    "CallerInfo",
    "ConfigStatus",
    "ConfirmMnemonic",
    "DaemonStatus",
    "DeleteFile",
    "FrostSignRound",
    "GetActiveSession",
    "GetAuthorizedClients",
    "GetHandlerFor",
    "GetKeyHealth",
    "GetLockPolicy",
    "GetNodeIdentity",
    "GetRecoveryStatus",
    "GrantImport",
    "GrantRevoke",
    "ListConflicts",
    "ListFiles",
    "ListHandlers",
    "ListSealed",
    "ListUsers",
    "LockSession",
    "LoginWithRecoveryKey",
    "LogoutUser",
    "MessageChannelCreate",
    "MessageChannelGrantKey",
    "MessageChannelHistory",
    "MessageChannelLeave",
    "MessageChannelRemoveMember",
    "MessageChannelSend",
    "MessageDecryptChannel",
    "MessageDecryptDm",
    "MessageDeliveries",
    "MessagePollInbox",
    "MessageSend",
    "MintPrincipalSession",
    "MountEvict",
    "MountList",
    "MountPath",
    "NodeList",
    "NodeRelay",
    "NodeRevoke",
    "OrgFrostJoin",
    "OrgFrostNew",
    "OrgFrostSignBegin",
    "OrgFrostSignContribute",
    "OrgFrostSignFinalize",
    "OrgGrantIssue",
    "OrgGrantList",
    "OrgList",
    "OrgMemberRemove",
    "OrgNew",
    "OrgShow",
    "PairNodeEphemeral",
    "QueryEvents",
    "ReachStatus",
    "ReadFile",
    "ReadSealed",
    "RecordDelete",
    "RecordInsert",
    "RecordOpen",
    "RecordQuery",
    "RecordSearch",
    "RecordSyncAvailable",
    "RemoteAdd",
    "RemoteCacheClear",
    "RemoteCredentialsSet",
    "RemoteList",
    "RemoteRemove",
    "RendezvousSet",
    "RendezvousStatus",
    "ResolveConflict",
    "SchemaGet",
    "SchemaGrantList",
    "SchemaGrantRevoke",
    "SchemaGrantSet",
    "SchemaList",
    "SchemaQuotaSet",
    "SchemaRegister",
    "SessionEnd",
    "SessionList",
    "SetLockPolicy",
    "SubscribeEvents",
    "SyncAvailable",
    "SyncAwait",
    "SyncConfigure",
    "SyncMount",
    "SyncRuleList",
    "SyncRuleRemove",
    "SyncStatus",
    "SyncTrigger",
    "TrustAdd",
    "TrustList",
    "TrustRemove",
    "TurnSet",
    "VaultCapacity",
    "VerifyEventLog",
    "VfsWatch",
    "WindowClosed",
    "WindowList",
    "WindowOpened",
    "WriteFile",
    "WriteSealed",
];

/// Where a session's requests originate, for the RFC-0035 trust floor. Bound once
/// at `Authenticate` from the credential kuserd issued the client — **never
/// settable by the caller**. Ordered by privilege: `Remote` < `Paired` < `Local`.
///
/// The middle step is DEC-0057. The floor had two values because there were two
/// kinds of caller: the human at this machine, and a credential from over the
/// wire. DEC-0053 made a third — a device that is over the wire *and* is the
/// person's own screen, admitted by the same six-digit ceremony devices use — and
/// the contact ceremony was marked `Local` for a reason ("a human comparing six
/// digits on a screen of their own") that fits a phone exactly and that `Local`
/// cannot express.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize,
)]
pub enum ConnTrustOrigin {
    /// A network peer, via a gateway session kuserd minted (`kquicd` / `khttpd`),
    /// or a gateway acting as itself. Least privileged: may invoke only
    /// `Remote`-tier operations.
    Remote,
    /// A session minted from a sealed channel to a device the person admitted by
    /// ceremony — today, a browser DEC-0053 paired (`Principal::Browser`).
    ///
    /// It is the person's screen, so it may do what needs a person: admit a
    /// contact on their word. It is not the machine, so everything that presumes
    /// the machine — daemon lifecycle, socket and IPC configuration, spawn and
    /// exec, adding a *device* — stays above it (DEC-0057, RFC-0065).
    Paired,
    /// A direct local client on the OS-protected IPC socket (CLI, desktop host,
    /// WASM sandbox, `kuid`, `ksyncd`). May invoke any operation.
    Local,
}

/// **Whose** authority a connection carries (RFC-0043).
///
/// Orthogonal to [`ConnTrustOrigin`], which says *how much*. The trust floor
/// applies first and is unchanged; this answers the question it cannot express —
/// which party a request is being made *for*.
///
/// Bound once at `Authenticate` from the credential kuserd issued, exactly as
/// origin is, and **never settable by the caller**. A caller-assertable principal
/// would let anything holding a gateway token name any principal it liked, which
/// is the mistake RFC-0035 already avoided for origin.
///
/// Before this existed, a gateway proxied every request on its own blanket
/// bootstrap token, so kuserd saw the *sidecar* and never the browser tab or
/// remote client behind it — a confused deputy with the run of the account.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Principal {
    /// A direct local client on the OS-protected IPC socket (CLI, shell, desktop
    /// host, WASM sandbox) or a non-gateway sidecar acting for the node itself.
    LocalOperator,
    /// A gateway sidecar acting **as itself**, holding only its bootstrap token.
    ///
    /// Its sole authority is to exchange evidence about a third party for a
    /// session minted for that party (P1). It is a distinct variant rather than
    /// an absent principal so the restriction is something the type system can
    /// carry: a handler asking "who is calling?" gets an answer that is checkable,
    /// not a `None` that every call site must remember to interpret.
    Gateway,
    /// A browser session, identified by the browser *device* the sealed channel
    /// admitted (DEC-0053): the row `add_browser_device` wrote, keyed by the key
    /// the browser proved in the ceremony. kuserd minted it; no gateway's claim
    /// is involved.
    Browser {
        /// Opaque, non-secret handle for the credential — enough to attribute and
        /// revoke, never the credential itself.
        credential_id: String,
    },
    /// A remote client authenticated by mutual TLS, identified by its verified DID.
    ///
    /// The DID is **asserted by `kquicd`**: kuserd did not observe the handshake
    /// and cannot re-derive it. kuserd validates what it can — the DID must be a
    /// currently authorised client. This is a named trust boundary, not an
    /// oversight; closing it requires kuserd to terminate TLS itself (RFC-0043
    /// Alternatives).
    RemoteClient {
        /// The peer's `did:key:…` DID as verified during the TLS handshake.
        did: String,
    },
}

impl Principal {
    /// Whether this principal is one of the user's own enrolled devices.
    ///
    /// Sealed replication (RFC-0041) and other own-device operations gate on this.
    /// A `Browser` is never an own device: it holds a credential, not a device
    /// identity, however privileged its session.
    pub fn own_device_did(&self) -> Option<&str> {
        match self {
            Self::RemoteClient { did } => Some(did),
            Self::LocalOperator | Self::Gateway | Self::Browser { .. } => None,
        }
    }

    /// Whether this principal may do nothing but mint a session for someone else
    /// (RFC-0043 P1).
    pub fn is_mint_only(&self) -> bool {
        matches!(self, Self::Gateway)
    }

    /// The RFC-0035 trust origin a session for this principal is bound to.
    ///
    /// Only a direct local client on the OS-protected socket is `Local`. A
    /// gateway acting as itself and a peer authenticated by mutual TLS are
    /// `Remote`: nothing about either says a person is watching. A browser is
    /// `Paired` (DEC-0057) — it reaches kuserd through a gateway like the other
    /// two, and unlike them it proved a human by the six-digit ceremony, holds a
    /// device key of its own, and speaks inside a channel the gateway cannot
    /// open. Deriving origin here, from *who* the credential says is calling,
    /// leaves no parallel bookkeeping a mint site can forget to update: a
    /// session's floor is a property of its principal, not of which map its
    /// token landed in.
    pub fn trust_origin(&self) -> ConnTrustOrigin {
        match self {
            Self::LocalOperator => ConnTrustOrigin::Local,
            Self::Browser { .. } => ConnTrustOrigin::Paired,
            Self::Gateway | Self::RemoteClient { .. } => ConnTrustOrigin::Remote,
        }
    }
}

/// Evidence a gateway presents to mint a session for the party behind it.
///
/// The gateway does not name a principal; it hands over what it received and
/// kuserd decides. That inversion is the point — see [`Principal`].
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum PrincipalEvidence {
    /// The raw Ed25519 public key `kquicd` read from the peer certificate the
    /// TLS handshake verified, hex-encoded.
    ///
    /// The gateway reports **what it saw**, not a conclusion drawn from it —
    /// kuserd checks the key against the authorised set and derives the DID
    /// itself. Keeping the transformation on the kuserd side means a bug in the
    /// network-facing sidecar cannot express a peer identity that its certificate
    /// does not actually carry. See [`Principal::RemoteClient`] for the boundary
    /// that remains.
    VerifiedPeerKey { pubkey_hex: String },
}

impl UserRequest {
    /// Minimum connection trust-origin required to invoke this variant (RFC-0035).
    ///
    /// The dispatch floor enforces `origin(conn) >= required_trust(req)`: a
    /// `Remote` connection may reach only `Remote`-tier operations; a `Local`
    /// connection clears the floor for everything. This makes the local/remote
    /// boundary unforgeable (origin is not caller-assertable) — closing #22, where
    /// a scoped connection re-enabled an excluded variant by naming it in its scope.
    ///
    /// **Exhaustive by construction.** Every variant states its tier here, with no
    /// wildcard arm, so adding a request to the enum does not compile until someone
    /// decides how much trust it needs. This replaces the former `REMOTE_EXCLUDES`
    /// string denylist, which was *default-allow*: a new variant was silently
    /// `Remote`-reachable unless its name was remembered and added to a list far
    /// from the definition. Forgetting is now a build failure rather than an
    /// exposure.
    ///
    /// The compiler forces a *decision*, not a correct one — `Remote` is still
    /// typeable for something sensitive. `trust_origin_tests::remote_eligible_set_is_pinned`
    /// pins the exact `Remote` set, so widening it is a deliberate diff a reviewer
    /// must approve rather than one word buried in a 139-arm match.
    ///
    /// The stronger form — parsing remote input into a type that *cannot express*
    /// `Local`-only variants, so there is no check to forget — is recorded as the
    /// eventual shape in RFC-0035 and not built here.
    pub fn required_trust(&self) -> ConnTrustOrigin {
        use ConnTrustOrigin::{Local, Paired, Remote};
        match self {
            // ── Local-only ───────────────────────────────────────────────────
            // RFC-0040 device pairing splits the user's identity and moves key
            // material on both sides; a remote party must never make this device
            // issue a share or join another identity, and the ceremony assumes a
            // local human comparing the SAS. Admitting a *device* is a larger
            // grant than admitting a contact, so it stays here while contact
            // pairing moves down a step (DEC-0057, "Not decided here").
            Self::DeviceAdd { .. }
            | Self::DeviceJoin { .. }
            | Self::DeviceName { .. } => Local,

            // Identity lifecycle: minting a user, and rotating the authoritative
            // key (local operator with the mnemonic only).
            Self::CreateUser { .. }
            | Self::AddRecoveryPhrase { .. }
            | Self::RotateIdentity { .. }
            | Self::Recover { .. } => Local,

            // Peer-only: the recovery fetch never arrives over IPC at all — the
            // dispatcher refuses it there — so no gateway session can reach it.
            Self::RecoveryFetch { .. } | Self::RecoveryStore { .. } => Local,
            // The vault's doors (`DEC-0056`): served only over a peer connection
            // to a paired device; no gateway session has a use for them.
            Self::HoldDoors { .. } | Self::TakeDeliveries { .. } | Self::CarryFrame { .. } => Local,
            // A person's other devices, introduced to their drive: served only
            // over a peer connection, to a vault, from a device it admits.
            Self::TenantDevice { .. } => Local,
            // An introduction opens a listener on the network this machine is on.
            // It is served only over a peer connection to one of the person's own
            // devices; no session, and no peer's `Remote` origin, reaches it.
            Self::Introduce { .. } => Local,
            // The landlord's three (the fourth is `DeviceInvite`, below): a vault
            // answers them on its peer transport to its operator's key alone,
            // and no session on a device has a use for them.
            Self::SetQuota { .. } | Self::Tenants | Self::DropTenant { .. } => Local,
            // A vault's reach set, told by its operator.
            Self::StandAt { .. } => Local,
            // The digits an operator's invite is waiting on, read by that
            // operator's desktop.
            Self::InviteDigits { .. } => Local,
            // An operator credential is a key that governs a vault or a relay: taken in and
            // spoken with at the machine, never from a browser or a peer.
            Self::OperatorMint { .. }
            | Self::OperatorEnrol { .. }
            | Self::OperatorEnrolLines { .. }
            | Self::OperatorMints { .. }
            | Self::OperatorHeld { .. }
            | Self::OperatorForget { .. }
            | Self::AsOperator { .. } => Local,

            // Privilege assignment for guest apps.
            Self::AppSetRole { .. } | Self::AppRegisterBundle { .. } => Local,

            // Reconfiguration of this node's storage / crypto algorithm.
            Self::StorageReload { .. } => Local,

            // Purge erases a path's history, not just its current version. A
            // delete is recoverable because the log keeps it as a fact; purge is
            // what removes that fact, and it is the only file operation with no
            // way back. `DeleteFile` beside it is remote-eligible for exactly the
            // reason this is not.
            Self::PurgeFile { .. } => Local,

            // PeerAdd grants mTLS trust to a node; only callable locally.
            Self::PeerAdd { .. } => Local,

            // A root an org owns, and who is in it (RFC-0088). Creating one and admitting a
            // member change the person's sealed root index and sign with keys on this
            // device; nothing remote needs either yet, and the browser phase is what would
            // widen them, if it does.
            Self::OrgRootCreate { .. } | Self::OrgRootInvite { .. } => Local,

            // ThresholdSign coordinates a signature with this node's FROST share.
            // A remote party must never trigger it; peers contribute their share
            // via FrostSignRound, which is Remote-eligible.
            Self::ThresholdSign { .. } => Local,

            // Gateway configuration and this node's certificate/auth material.
            // A gateway must not be able to reconfigure or re-authorise itself.
            Self::QuicGatewaySet { .. }
            // Starting a model runtime on this machine is the same kind of act:
            // a remote party must not be able to make this device run a process,
            // and a model runs only where the keys are (RFC-0085 IN2).
            | Self::InferenceSet { .. }
            // Opening this machine's door on the network it sits on is the same
            // kind of act: nothing remote may make this device listen for strangers.
            | Self::LocalDoor { .. }
            // Installing a model, removing one, and choosing which one answers
            // are the same kind of act one level up: they decide what runs over
            // the person's own data, on this machine, and they move gigabytes
            // into their store. `ModelList` is here with them because nothing
            // remote needs it yet — RFC-0085's phone step is what widens it, if
            // it does.
            | Self::ModelAdd { .. }
            | Self::ModelWeights { .. }
            | Self::ModelList { .. }
            | Self::ModelRemove { .. }
            | Self::ModelUse { .. }
            | Self::QuicGatewayStatus { .. }
            | Self::GetDeviceCert { .. }
            | Self::WebShellSet { .. }
            | Self::WebShellStatus { .. }
            | Self::WebShellPair { .. }
            // The roster of admitted browsers and the revoke beside it: the
            // desk admits on a trusted screen, so the list and the revoke are
            // read and decided there too. A browser at `Paired` is floored out
            // of both — it neither sees its siblings nor revokes them.
            | Self::BrowserDeviceList { .. }
            | Self::BrowserDeviceRevoke { .. }
            | Self::GatewayEnroll { .. }
            | Self::DeviceAdmit { .. }
            | Self::RelayStand { .. }
            | Self::DeviceInvite { .. } => Local,

            // Node-local introspection — sidecar processes, IPC sessions, VFS and
            // network reports. Operational detail a remote party has no business
            // enumerating.
            Self::DaemonSidecars { .. }
            | Self::IpcSessions { .. }
            | Self::VfsReport { .. }
            | Self::NetworkStatus { .. } => Local,

            // The compositor protocol used to need three `Local` arms here,
            // because kuid spoke this wire and an external client must never
            // inject a keystroke or forge a surface error. There is no arm now:
            // the verbs are `CompositorEvent`, and a type a client cannot send
            // needs no tier to keep it out. A trust tier is a check, and this is
            // what removing the reachability instead looks like at the far end.

            // Confined extensions (RFC-0049 / RFC-0050) — **Local only**.
            //
            // Installing an extension mints capabilities and writes code that
            // will subsequently execute. A peer link or a browser session must
            // never be able to do either, however well authenticated: the
            // consent that authorises an extension is a decision made at the
            // machine, not a request arriving over the network.
            //
            // `ExtensionList` is Local too, though it is only a read. It
            // enumerates what runs on this device and where each extension may
            // connect — a reconnaissance surface with no legitimate remote
            // caller. `AppInstall` used to sit in the Remote-eligible block for
            // historical reasons; it no longer does — see the arm below.
            Self::ExtensionInstall { .. }
            | Self::ExtensionList { .. }
            | Self::ExtensionRemove { .. } => Local,

            // `AppInstall` — **Local only**, for the reason immediately above.
            //
            // It sat in the Remote-eligible block until 2026-08-23, and the comment
            // above named that as history rather than precedent. Reading what it
            // does settles it: `install_app` writes a `.wasm` file to the app store,
            // registers the app as a handler for every NSID in `handler_for`, and
            // **builds and signs a `GrantEnvelope` binding the app's declared
            // capabilities to the user's DID** (`core/app/src/daemon/apps.rs`). That
            // is both halves of the extension rule — code that will subsequently
            // execute, and minted capability — so the same answer follows.
            //
            // Nothing legitimate is lost. The only caller is the shell's
            // `app install <path>`, which runs at the machine; there is no browser
            // or peer path, and the capability grant is a decision made in front of
            // the person it binds.
            //
            // `AppUninstall`, `AppLaunch` and the handler-registration verbs remain
            // Remote-eligible and are *not* settled by this: removing an app is
            // tamper rather than execution, and redirecting an NSID to a different
            // installed app is its own question — see
            // TASK-remote-callers-can-redirect-a-users-handlers.
            Self::AppInstall { .. } => Local,
            // `AppInstallPreview` — **Local only**, for the same reason as
            // `AppInstall` immediately above: it takes the WASM bytes, and a
            // remote caller shipping a binary to be parsed here is the shape
            // that block exists to refuse. It mints nothing, but "harmless to
            // run" is not the test — reachability is.
            Self::AppInstallPreview { .. } => Local,
            // `Import` — **Local only**, and for the same reason as
            // `AppInstallPreview` above: a caller shipping a file here to be
            // parsed is exactly the shape that block refuses. The reader is new
            // code walking attacker-shaped text, and it runs inside the daemon
            // that holds every user's content key.
            //
            // Nothing legitimate is lost today — the only caller is
            // `kotton import <path>` at the machine. The verb that a browser or
            // a phone would eventually want is *upload this to my node*, which
            // is a different question with its own consent, not this one widened.
            Self::Import { .. } => Local,

            // `AppGrants` — Local only. It reads no bytes from the caller and
            // mints nothing, but it reports exactly which of the user's data an
            // app can reach, which is a map worth having before an attack and
            // not a thing to answer over a remote connection.
            Self::AppGrants { .. } => Local,
            // The handler registry's **mutating** verbs — Local only.
            //
            // Which app opens a user's records is a decision about their data.
            // `SetDefaultHandler` points an NSID at a different already-installed
            // app; `RegisterHandler` adds one as a handler for a schema it never
            // declared; `UnregisterHandler` removes a handler and the registry
            // promotes the next automatically — so removing the current default
            // is enough to select its successor without naming it. None installs
            // anything, so none tripped the rule that made `AppInstall` Local,
            // and all three sat in the Remote-eligible block beside it until
            // 2026-09-06 (TASK-remote-callers-can-redirect-a-users-handlers).
            //
            // The reading that settles them: redirection *within* an
            // already-consented set is still redirection — "app A opens what the
            // user meant for app B" is the case grants exist to prevent, and a
            // signed `GrantEnvelope` bounding each app's capabilities does not
            // bound which app the user's own records route to. The only callers
            // are the shell's `kotton handler` subcommands over local IPC;
            // `install_app` registers a new app's handlers directly against the
            // user db, not through these verbs, so install is untouched. Nothing
            // legitimate reaches them remotely, so nothing is lost — and being
            // `Local` deletes them from `RemoteRequest`, the type a browser or
            // peer decodes into, so a remote caller cannot name them at all.
            //
            // The **reads** stay Remote-eligible: `GetHandlerFor` and
            // `ListHandlers` redirect nothing, and a remote shell view showing
            // which app opens a schema is a legitimate reader — the same
            // disposition `AppList` has. If those enumerations later prove to be
            // reconnaissance worth closing, that is its own call.
            Self::RegisterHandler { .. }
            | Self::UnregisterHandler { .. }
            | Self::SetDefaultHandler { .. } => Local,

            // PIN unlock is a **local-presence ceremony** (RFC-0053).
            //
            // It sat in the Remote-eligible block below until RFC-0053 step 2,
            // which is a defect and not a design: the PIN is a 4–16 digit secret
            // that both mints a full-authority session *and* unseals the at-rest
            // vault holding the operational roots. Reachable from a gateway
            // session, that is a four-digit password on the open network — and
            // the attempt budget that would have bounded it was, until the
            // preceding commit, purely decorative.
            //
            // Nothing legitimate is lost. The only callers are the CLI and the
            // shell, both over local IPC. Remote unlock is meant to be device-key
            // challenge–response (RFC-0053 step 6), where what crosses the wire
            // is a signature over a fresh challenge rather than a reusable
            // secret; a PIN over a gateway is not a smaller version of that
            // design, it is the thing the design exists to replace.
            //
            // An earlier design and the project's status log both asserted this was
            // already Local. It was not — the RFC's stated precedent for
            // `GetUnlockMethods`'s scoping was a scoping that did not exist.
            //
            // `GetUnlockMethods` joins it: it is only a read, and the credential
            // *type* is not a secret, but it enumerates who can log in at this
            // machine and how — reconnaissance with no remote caller who could
            // act on either answer, since the unlock verb itself is Local.
            Self::UnlockWithPin { .. }
            | Self::GetUnlockMethods { .. }
            // The same enumeration surface — who is unlocked here, and for how
            // long — and no remote caller who could act on the answer.
            | Self::GetUnlockState { .. }
            | Self::LockCustody { .. }
            // Binding touches this machine's hardware and re-seals the vault; a
            // remote caller has no business doing either.
            | Self::BindDeviceHardware { .. }
            // Admission writes the registry every trust gate is projected from.
            // Pairing and enrolment are Local for this reason; so is this.
            | Self::ContactAdd { .. } => Local,

            // ── Paired ───────────────────────────────────────────────────────
            // Needs a person at a screen of their own, and nothing more (DEC-0057).
            //
            // Contact pairing shows three words and six digits to a human and
            // admits a stranger's key on their word. That is what `Local` was
            // standing in for here until 2026-09-07 — and the demonstration's
            // screen is a phone, where "read me three words" actually happens.
            // A browser DEC-0053 admitted proved a human by the same digits, holds
            // a device key of its own, and speaks inside a channel the gateway
            // cannot open, so it is such a screen. A gateway acting as itself and
            // an mTLS peer are not, and they stay below this line.
            //
            // What a wrong pairing from a phone costs is bounded by what a contact
            // gets: RFC-0022 CP5 yields the contact role and nothing else. A wrong
            // pairing is one wrong contact, revocable — not a wrong device, which
            // is why `DeviceAdd` / `DeviceJoin` stay `Local` above.
            Self::ContactPairStart { .. }
            | Self::ContactPairJoin { .. }
            // `PairConfirmCode` is one verb shared by device and contact pairing:
            // it carries a token the stream issued and the human's verdict. Its
            // authority is that token, which only the session that opened the
            // stream was handed — a confirm presented with someone else's token
            // fails on the token, as it does today, and the tier is not what
            // protects it. So it follows the lower of the two streams rather than
            // acquiring a second check beside the one that works.
            | Self::PairConfirmCode { .. }
            // Read-only, and it enumerates who this person knows, which is why it
            // sat at `Local` with *"widen it deliberately if the phone view needs
            // it"* written beside it. `DEC-0060` is that widening, and its
            // argument is the three verbs above: a browser may *add* to this
            // list — it runs the ceremony that admits a stranger's key — so
            // refusing it the read holds the weaker power back while granting the
            // stronger one, which is a rule nobody can state. `MessagePollInbox`
            // is `Remote` and every message carries `from_did` in the clear, so
            // the fact was reachable a tier lower anyway.
            | Self::ContactList { .. }
            // Read state is an **attention** signal, and a stronger one than
            // anything the sender is owed: when you looked, and therefore when
            // you were awake. `MessagePollInbox` is `Remote` and gives a caller
            // the messages; neither of these is derivable from that, because
            // neither is about the messages. So they sit above the tier a
            // gateway or a peer link carries, and a browser — which runs the
            // ceremony that earns `Paired` — reaches both.
            //
            // The write matters more than the read. A caller that could mark
            // your conversations read would empty your badge, and a message
            // nobody is told about is a message nobody answers.
            | Self::MessageUnreadCount { .. }
            | Self::MessageMarkRead { .. } => Paired,

            // ── Remote-eligible ──────────────────────────────────────────────
            // Reachable over a gateway session or a peer link. Sealed replication
            // (RFC-0041) sits here of necessity: a peer link is `Remote` origin —
            // the floor's bottom step — so marking ReadSealed / WriteSealed above
            // it would break peer sync outright. They grant no
            // privilege beyond the VFS verbs beside them — ReadSealed returns
            // strictly less than ReadFile (ciphertext, not plaintext), and a
            // WriteSealed caller without the CEK can only write bytes that fail to
            // open. Restricting them to own-device members is a membership check
            // in the handler, not a trust-origin tier.
            Self::LogoutUser { .. }
            | Self::LoginWithRecoveryKey { .. }
            | Self::ListUsers { .. }
            | Self::Authenticate { .. }
            | Self::CallerInfo { .. }
            | Self::GetActiveSession { .. }
            | Self::LockSession { .. }
            | Self::ReadFile { .. }
            | Self::WriteFile { .. }
            | Self::ListFiles { .. }
            | Self::DeleteFile { .. }
            | Self::ListConflicts { .. }
            | Self::ResolveConflict { .. }
            | Self::MintPrincipalSession { .. }
            | Self::BrowserFrame { .. }
            | Self::BrowserOutbound { .. }
            | Self::ReadSealed { .. }
            | Self::ListSealed { .. }
            | Self::WriteSealed { .. }
            | Self::RemoteAdd { .. }
            | Self::RemoteRemove { .. }
            | Self::RemoteList { .. }
            | Self::RemoteCacheClear { .. }
            | Self::RemoteCredentialsSet { .. }
            | Self::SyncMount { .. }
            | Self::PairNodeEphemeral { .. }
            | Self::NodeList { .. }
            // Asked by a paired peer after every connect, and by a gateway before
            // it serves, so a relay change follows the pair (RFC-0083 R5).
            | Self::NodeRelay { .. }
            // A paired device asks its vault how much it keeps and may keep
            // (RFC-0084 V3); the answer names nothing the vault cannot see.
            | Self::VaultCapacity { .. }
            | Self::NodeRevoke { .. }
            | Self::FrostSignRound { .. }
            | Self::GetNodeIdentity { .. }
            | Self::SyncConfigure { .. }
            | Self::SyncRuleList { .. }
            | Self::SyncRuleRemove { .. }
            | Self::SyncTrigger { .. }
            | Self::SyncAwait { .. }
            | Self::MountPath { .. }
            | Self::MountList { .. }
            | Self::MountEvict { .. }
            | Self::SessionList { .. }
            | Self::SessionEnd { .. }
            | Self::RendezvousSet { .. }
            | Self::RendezvousStatus { .. }
            // The relay readout (RFC-0083 R6): a state and two counts, drawn on
            // the phone home. `NetworkStatus` beside it stays Local — it carries
            // ports and binds — and this is the one fact split out of it.
            | Self::ReachStatus { .. }
            | Self::TurnSet { .. }
            | Self::ConfigStatus { .. }
            | Self::GetAuthorizedClients { .. }
            | Self::RecordInsert { .. }
            | Self::RecordQuery { .. }
            | Self::RecordSearch { .. }
            | Self::RecordDelete { .. }
            | Self::RecordOpen { .. }
            | Self::SchemaList { .. }
            | Self::SchemaRegister { .. }
            | Self::SchemaGet { .. }
            | Self::SchemaGrantList { .. }
            | Self::SchemaGrantSet { .. }
            | Self::SchemaGrantRevoke { .. }
            | Self::SchemaQuotaSet { .. }
            | Self::GetHandlerFor { .. }
            | Self::ListHandlers { .. }
            | Self::AppUninstall { .. }
            | Self::AppVerify { .. }
            | Self::AppList { .. }
            | Self::AppGetBundlePath { .. }
            | Self::AppGetRole { .. }
            | Self::AppLaunch { .. }
            | Self::AppMessage { .. }
            | Self::SubscribeEvents { .. }
            | Self::QueryEvents { .. }
            | Self::GetKeyHealth { .. }
            | Self::DaemonStatus { .. }
            | Self::SetLockPolicy { .. }
            | Self::GetLockPolicy { .. }
            | Self::ConfirmMnemonic { .. }
            | Self::GetRecoveryStatus { .. }
            | Self::VerifyEventLog { .. }
            | Self::TrustAdd { .. }
            | Self::TrustRemove { .. }
            | Self::TrustList { .. }
            | Self::GrantRevoke { .. }
            | Self::GrantImport { .. }
            | Self::OrgNew { .. }
            | Self::OrgShow { .. }
            | Self::OrgList { .. }
            | Self::OrgGrantIssue { .. }
            | Self::OrgGrantList { .. }
            | Self::OrgMemberRemove { .. }
            | Self::OrgFrostNew { .. }
            | Self::OrgFrostJoin { .. }
            | Self::OrgFrostSignBegin { .. }
            | Self::OrgFrostSignContribute { .. }
            | Self::OrgFrostSignFinalize { .. }
            | Self::MessageChannelCreate { .. }
            | Self::MessageChannelGrantKey { .. }
            | Self::MessageChannelRemoveMember { .. }
            | Self::MessageChannelLeave { .. }
            | Self::MessageSend { .. }
            // The word `MessageSend` already answered with, read again: a
            // caller that may send may read what became of what it sent.
            | Self::MessageDeliveries { .. }
            | Self::MessageChannelSend { .. }
            | Self::MessageChannelHistory { .. }
            | Self::MessagePollInbox { .. }
            | Self::MessageDecryptDm { .. }
            | Self::MessageDecryptChannel { .. }
            | Self::WindowOpened { .. }
            | Self::WindowClosed { .. }
            | Self::WindowList { .. }
            | Self::SyncAvailable { .. }
            | Self::RecordSyncAvailable { .. }
            | Self::ApplyRecordChangeset { .. }
            | Self::VfsWatch { .. }
            | Self::SyncStatus { .. } => Remote,
        }
    }
}

#[cfg(test)]
mod trust_origin_tests {
    use super::*;

    #[test]
    fn origin_ordered_by_privilege() {
        assert!(ConnTrustOrigin::Remote < ConnTrustOrigin::Paired);
        assert!(ConnTrustOrigin::Paired < ConnTrustOrigin::Local);
        // Stated transitively too, because the floor is written as one `<` and a
        // reader checking it should not have to compose two facts to see that a
        // gateway acting as itself still cannot reach a `Local` verb.
        assert!(ConnTrustOrigin::Remote < ConnTrustOrigin::Local);
    }

    /// A browser is the one principal at `Paired`; the other two gateway-reachable
    /// principals are not, and the local operator is above it.
    ///
    /// Origin is derived from the principal rather than stored beside it, so this
    /// is the whole of what binds the new step to a caller — there is no second
    /// place a mint site could set it differently.
    #[test]
    fn only_a_browser_is_paired() {
        use crate::ipc::Principal;

        assert_eq!(
            Principal::Browser { credential_id: "b".into() }.trust_origin(),
            ConnTrustOrigin::Paired,
        );
        assert_eq!(Principal::Gateway.trust_origin(), ConnTrustOrigin::Remote);
        assert_eq!(
            Principal::RemoteClient { did: "did:key:z".into() }.trust_origin(),
            ConnTrustOrigin::Remote,
        );
        assert_eq!(Principal::LocalOperator.trust_origin(), ConnTrustOrigin::Local);
    }

    /// Pins the `Paired` set at the three verbs DEC-0057 moved, plus the one
    /// DEC-0060 added: `ContactList`, the read of the list those three write.
    ///
    /// The sibling of `remote_eligible_set_is_pinned`, and for the same reason: a
    /// tier is one word in a 200-arm match, and the diff that widens it should be
    /// a diff someone reads. `Paired` is the tier a *phone* clears, so a verb that
    /// lands here becomes something a screen the person is holding — over a relay,
    /// away from the machine — can invoke.
    ///
    /// If this fails, do not paste the new name in. Ask whether a browser session
    /// should be able to invoke that operation, and if the answer is yes, say so
    /// in a record first.
    #[test]
    fn paired_set_is_pinned() {
        let src = include_str!("request.rs");
        let group = src
            .split_once("── Paired ─")
            .expect("marker comment present in required_trust")
            .1
            .split_once("=> Paired,")
            .expect("the Paired arm group is terminated")
            .0;

        let mut found: Vec<&str> = group
            .match_indices("Self::")
            .map(|(i, _)| {
                let rest = &group[i + "Self::".len()..];
                let end = rest
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();
        found.sort_unstable();
        found.dedup();

        assert_eq!(
            found,
            vec![
                "ContactList",
                "ContactPairJoin",
                "ContactPairStart",
                "MessageMarkRead",
                "MessageUnreadCount",
                "PairConfirmCode"
            ],
            "the Paired set changed — a browser session can now reach a different \
             set of operations than DEC-0057, DEC-0060 and DEC-0061 ruled on"
        );
        for name in &found {
            assert!(
                !REMOTE_ELIGIBLE.contains(name),
                "{name} is Paired-tier; it must not also sit in the Remote allow-list"
            );
        }
    }

    #[test]
    fn required_trust_separates_local_from_remote() {
        // Identity-bearing ceremony → Local-only.
        let pair = UserRequest::DeviceAdd {
            user_id: "u".into(),
            as_name: None,
            ttl_seconds: 1,
            port: 0,
            posture: Default::default(),
        };
        assert_eq!(pair.required_trust(), ConnTrustOrigin::Local);

        // Ordinary operation → Remote-eligible (Local callers still clear the floor).
        let auth = UserRequest::Authenticate {
            token: crate::ipc::SecretText::new("t"),
            scope: None,
        };
        assert_eq!(auth.required_trust(), ConnTrustOrigin::Remote);

        // Sealed replication is Remote-eligible by necessity: a peer link carries
        // the same `Remote` origin as a browser session, so a Local-only tier here
        // would break peer sync (RFC-0041).
        let sealed = UserRequest::WriteSealed {
            user_id: "u".into(),
            mount: "local".into(),
            path: "notes/x".into(),
            blob: vec![1, 2, 3],
            domain_id: "0011223344556677".to_string(),
            offset: 0,
            total_size: 3,
            // `required_trust` is keyed on the variant, not the payload, so the
            // reassembly fields only have to be present.
            content_hash: "00".repeat(32),
        };
        assert_eq!(sealed.required_trust(), ConnTrustOrigin::Remote);
    }

    /// A PIN unlock must never be reachable from a gateway session or a peer.
    ///
    /// It was, until RFC-0053 step 2. The PIN both mints a full-authority
    /// session and unseals the vault holding the operational roots, so a remote
    /// caller could grind a 4-digit secret for the whole identity. Remote unlock
    /// is device-key challenge–response (RFC-0053 step 6); this variant is the
    /// local-presence path and stays local.
    /// Purge erases a path's history, and `DeleteFile` beside it is remote-
    /// eligible — so the asymmetry is the thing to pin, or someone will read it
    /// as an oversight and widen it.
    ///
    /// A delete is recoverable precisely because the log keeps it as a fact.
    /// Purge removes the fact, which is what makes a generous retention default
    /// safe to offer in the first place. It is the only file operation with no
    /// way back, so it is not reachable from a browser gateway or a peer.
    #[test]
    fn purge_is_local_only_though_delete_is_not() {
        let purge = UserRequest::PurgeFile {
            user_id: "avery".into(),
            path: "/notes/todo.md".into(),
        };
        let delete = UserRequest::DeleteFile {
            user_id: "avery".into(),
            path: "/notes/todo.md".into(),
        };
        assert_eq!(purge.required_trust(), ConnTrustOrigin::Local);
        assert_eq!(delete.required_trust(), ConnTrustOrigin::Remote);
        assert!(
            !REMOTE_ELIGIBLE.contains(&purge.variant_name()),
            "PurgeFile must not appear in the Remote allow-list"
        );
    }

    /// The handler registry's mutating verbs redirect which app opens a user's
    /// records — a decision about their data — so they are Local, while the
    /// registry's reads stay Remote-eligible. `UnregisterHandler` is the sharp
    /// one: it names no successor, yet removing the current default promotes the
    /// next, so the reach is there without an app id crossing the wire.
    ///
    /// Pinned against `GetHandlerFor`, which stays Remote, because the pair is
    /// what is easy to get wrong: reading which app opens a schema is not the
    /// same act as changing it.
    #[test]
    fn handler_mutation_is_local_only_though_reading_is_not() {
        let register = UserRequest::RegisterHandler {
            app_id: "sh.kotton.notes".into(),
            nsid: "sh.kotton.contacts".into(),
        };
        let unregister = UserRequest::UnregisterHandler {
            app_id: "sh.kotton.notes".into(),
            nsid: "sh.kotton.contacts".into(),
        };
        let set_default = UserRequest::SetDefaultHandler {
            app_id: "sh.kotton.notes".into(),
            nsid: "sh.kotton.contacts".into(),
        };
        let get_for = UserRequest::GetHandlerFor {
            nsid: "sh.kotton.contacts".into(),
        };
        for verb in [&register, &unregister, &set_default] {
            assert_eq!(
                verb.required_trust(),
                ConnTrustOrigin::Local,
                "{} redirects which app opens the user's records; it must be Local",
                verb.variant_name()
            );
            assert!(
                !REMOTE_ELIGIBLE.contains(&verb.variant_name()),
                "{} must not appear in the Remote allow-list",
                verb.variant_name()
            );
        }
        // The read redirects nothing and has a legitimate remote caller.
        assert_eq!(get_for.required_trust(), ConnTrustOrigin::Remote);
        assert!(REMOTE_ELIGIBLE.contains(&get_for.variant_name()));
    }

    /// Installing an app is a decision made at the machine, not a request that
    /// arrives over the network — the same rule as a confined extension, and for
    /// the same two reasons: it writes code that will subsequently execute, and it
    /// mints a signed capability grant bound to the user's DID.
    ///
    /// Pinned against `AppLaunch`, which stays Remote-eligible, because the pair is
    /// the thing that is easy to get wrong: running an app the user already chose to
    /// install is not the same act as choosing to install one.
    #[test]
    fn app_install_is_local_only_though_launching_is_not() {
        let install = UserRequest::AppInstall {
            user_id: "avery".into(),
            manifest_toml: String::new(),
            wasm_bytes: Vec::new(),
            approved: Vec::new(),
            bindings: Vec::new(),
        };
        let preview = UserRequest::AppInstallPreview {
            user_id: "avery".into(),
            manifest_toml: String::new(),
            wasm_bytes: Vec::new(),
        };
        let launch = UserRequest::AppLaunch {
            app_id: "sh.kotton.editor".into(),
            launch_args: Default::default(),
        };
        assert_eq!(install.required_trust(), ConnTrustOrigin::Local);
        assert_eq!(launch.required_trust(), ConnTrustOrigin::Remote);
        assert!(
            !REMOTE_ELIGIBLE.contains(&install.variant_name()),
            "AppInstall must not appear in the Remote allow-list"
        );
        // The preview mints nothing, which is not the test. It takes the WASM
        // bytes, and a remote caller shipping a binary here to be parsed is the
        // shape this block refuses — reachability, not harm.
        assert_eq!(preview.required_trust(), ConnTrustOrigin::Local);
        assert!(
            !REMOTE_ELIGIBLE.contains(&preview.variant_name()),
            "AppInstallPreview must not appear in the Remote allow-list"
        );
    }

    #[test]
    fn pin_unlock_is_local_only() {
        let unlock = UserRequest::UnlockWithPin {
            user_id: "avery".into(),
            pin: crate::ipc::SecretText::new("135790"),
            repair: false,
        };
        assert_eq!(unlock.required_trust(), ConnTrustOrigin::Local);
        assert!(
            !REMOTE_ELIGIBLE.contains(&unlock.variant_name()),
            "UnlockWithPin must not appear in the Remote allow-list"
        );
    }

    /// Pins the exact set of `Remote`-eligible requests.
    ///
    /// The exhaustive match in [`UserRequest::required_trust`] forces a *decision*
    /// for every new variant, but not a correct one — `Remote` is still typeable
    /// for something sensitive, and one word in a 139-arm match is easy to wave
    /// through. This test makes widening the remote surface a deliberate diff: a
    /// variant added to the `Remote` group fails here until its name is also added
    /// below (`REMOTE_ELIGIBLE`), which puts the change in front of a reviewer.
    ///
    /// A `Local`-tier operation is not something a remote caller can express.
    ///
    /// Since DEC-0057 the arms above the `Remote-eligible` marker are `Local` *and*
    /// `Paired`, and this reads both — which is what it should read. `Paired` is
    /// reached by being a browser inside its own sealed channel, never by naming a
    /// verb in a gateway or peer frame, so a `Paired` verb must be as unparseable
    /// here as a `Local` one. The two doors are different mechanisms and this is
    /// the one that closes the frame.
    ///
    /// This is the property the gateways used to enforce with
    /// `if request.required_trust() > ConnTrustOrigin::Remote { refuse }`. `khttpd`
    /// and `kquicd` now decode into [`crate::ipc::remote_request::RemoteRequest`],
    /// so the refusal is not a line of code that could be edited away — the frame
    /// does not parse.
    ///
    /// The `Local` names are read out of this file rather than listed, so a variant
    /// moved between tiers is covered the day it moves.
    #[test]
    fn a_local_tier_operation_is_not_expressible_as_a_remote_request() {
        use crate::ipc::remote_request::RemoteRequest;

        let src = include_str!("request.rs");
        let group = src
            .split_once("pub fn required_trust")
            .expect("required_trust present")
            .1
            .split_once("── Remote-eligible ─")
            .expect("the Local arms come first, then the marker")
            .0;

        let mut above_remote: Vec<&str> = group
            .match_indices("Self::")
            .map(|(i, _)| {
                let rest = &group[i + "Self::".len()..];
                let end = rest
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();
        above_remote.sort_unstable();
        above_remote.dedup();
        assert!(
            above_remote.len() > 20,
            "parsed {} Local/Paired variants, which cannot be right — this test would \
             pass vacuously",
            above_remote.len()
        );
        for pinned in ["ContactPairStart", "ContactPairJoin", "PairConfirmCode"] {
            assert!(
                above_remote.contains(&pinned),
                "{pinned} is Paired-tier and must be covered here too"
            );
        }

        for name in &above_remote {
            let wire = format!(r#"{{"{name}":{{}}}}"#);
            assert!(
                serde_json::from_str::<RemoteRequest>(&wire).is_err(),
                "{name} is above the Remote tier but deserializes as a RemoteRequest \
                 — a gateway or a peer can name it",
            );
        }

        // …and the remote half is genuinely reachable, so the assertion above is not
        // passing because nothing parses. This control caught a wrong fixture once
        // already; without it the loop above passes when *everything* fails to parse.
        let ok = r#"{"AppMessage":{"app_id":"a","msg":"m"}}"#;
        assert!(
            serde_json::from_str::<RemoteRequest>(ok).is_ok(),
            "a remote-eligible variant must still parse",
        );
    }

    /// If this test fails, do not "fix" it by pasting the new name in. Ask whether
    /// a network peer or a browser session should be able to invoke that operation.
    #[test]
    fn remote_eligible_set_is_pinned() {
        // Read the `Remote` arm group straight out of this file, so the pin tracks
        // the match itself rather than a hand-maintained mirror that can drift.
        let src = include_str!("request.rs");
        let after_marker = src
            .split_once("── Remote-eligible ─")
            .expect("marker comment present in required_trust")
            .1;
        let group = after_marker
            .split_once("=> Remote,")
            .expect("Remote arm group is terminated")
            .0;

        let mut found: Vec<&str> = group
            .match_indices("Self::")
            .map(|(i, _)| {
                let rest = &group[i + "Self::".len()..];
                let end = rest
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();
        found.sort_unstable();
        found.dedup();

        let expected: Vec<&str> = REMOTE_ELIGIBLE.to_vec();
        assert_eq!(
            found, expected,
            "the Remote-eligible set changed — a peer or gateway session can now \
             reach a different set of operations than this pin records"
        );
    }

    /// **A verb whose meaning changed has a new name, so neither side misreads
    /// the other.** The carry verb was `CarryMessages`, a whole-set
    /// replacement; read as one, `CarryFrame`'s readout — no messages — would
    /// tell a vault from before to carry nothing. Under its own tag it is a
    /// verb such a vault does not know, and refuses (`invalid peer request`,
    /// `kvaultd`'s peer handler); and the old verb from a device from before
    /// does not decode here, so a vault from after refuses it the same way
    /// (`TASK-an-outbox-holding-two-shares-is-handed-to-its-vault-in-one-frame-that-cannot-hold-them`).
    #[test]
    fn the_carry_verb_changed_its_name_with_its_meaning() {
        let readout = UserRequest::CarryFrame { user_id: "alice".into(), messages: vec![], drop: vec![] };
        let bytes = serde_json::to_value(&readout).unwrap();
        let tags: Vec<&String> = bytes.as_object().unwrap().keys().collect();
        assert_eq!(tags, ["CarryFrame"], "{bytes}");
        let old = serde_json::json!({ "CarryMessages": { "user_id": "alice", "messages": [] } });
        assert!(serde_json::from_value::<UserRequest>(old).is_err(), "the old verb still decodes");
    }
}

#[cfg(test)]
mod secret_debug_tests {
    //! **No secret a request carries prints through `Debug`.** `UserRequest`
    //! and `RemoteRequest` derive it, so every field that holds a passphrase,
    //! a PIN, a recovery phrase, a FROST share, a session or ceremony token or
    //! a code that admits is `SecretText`, and a backend's credentials are
    //! `SecretValue`: what it was on the wire, `<redacted>` in a `{:?}`.

    use super::*;
    use crate::ipc::{SecretText, SecretValue};
    use crate::remote::RemoteBackend;
    use crate::RemoteRequest;

    const PASSPHRASE: &str = "velvet-orchard-passphrase-4417";
    const NEW_PASSPHRASE: &str = "harbour-lantern-passphrase-9052";
    const PHRASE: &str = "quartz mango trumpet velvet orbit lunar cactus whisper";
    const PIN: &str = "86420975";
    const OPERATOR: &str = "kotton-operator 2\nname=kotton\noperator=0f0f0f0f\n";
    const RELAY_CODE: &str = "http://relay#ember-tundra-sapphire";
    const SESSION: &str = "5e55104d7c3b9a01e2f4";
    const CEREMONY: &str = "c3e3e301a7f2";
    const CONNECTION: &str = "192.0.2.7:7443#9f1c0a";
    const SPOKEN: &str = "amber-falcon-river";
    const INVITE: &str = "kotton-invite:vault:fame-cheap-unfold@http://relay.example:7700";
    const ENROL: &str = "gateway-enrol-4d2b";
    const SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI-K7MDENG-bPxRfiCY";

    fn credentials() -> SecretValue {
        SecretValue::new(serde_json::json!({ "access_key_id": "AKIA", "secret_access_key": SECRET_ACCESS_KEY }))
    }

    fn s3() -> RemoteBackend {
        RemoteBackend::S3 { bucket: "b".into(), region: "r".into(), endpoint: None }
    }

    fn s(text: impl Into<String>) -> SecretText {
        SecretText::new(text)
    }

    fn share() -> String {
        "5ec2e75a".repeat(8)
    }

    fn cosigner_share() -> String {
        "c05e1a7e".repeat(8)
    }

    /// `value` prints `<redacted>` and none of `secrets`, and its JSON still
    /// carries every one of them as it was written.
    fn hides<T: std::fmt::Debug + serde::Serialize>(value: &T, secrets: &[&str]) {
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
    fn no_user_request_prints_a_secret_it_carries() {
        let user = || "alice".to_string();
        hides(&UserRequest::CreateUser { user_id: user(), passphrase: s(PASSPHRASE) }, &[PASSPHRASE]);
        hides(
            &UserRequest::LoginWithRecoveryKey { recovery_key: s(PHRASE), device_name: None, user_id: Some(user()) },
            &[PHRASE],
        );
        hides(
            &UserRequest::RotateIdentity { user_id: user(), recovery_key: s(PHRASE), credential: Some(s(PASSPHRASE)) },
            &[PHRASE, PASSPHRASE],
        );
        hides(
            &UserRequest::Recover { user_id: user(), recovery_key: s(PHRASE), passphrase: s(NEW_PASSPHRASE) },
            &[PHRASE, NEW_PASSPHRASE],
        );
        hides(
            &UserRequest::OrgFrostJoin {
                user_id: user(),
                name: "org".into(),
                org_did: "did:key:z6Mk".into(),
                share_hex: s(share()),
                participant_idx: 2,
            },
            &[&share()],
        );
        hides(
            &UserRequest::OrgFrostSignFinalize {
                user_id: user(),
                session_id: "session".into(),
                cosigner_id_hex: "02".into(),
                cosigner_commitment_hex: "ab".into(),
                cosigner_share_hex: s(cosigner_share()),
            },
            &[&cosigner_share()],
        );
        hides(
            &UserRequest::SetLockPolicy {
                user_id: user(),
                mode: LockMode::Passphrase,
                auto_lock_minutes: 0,
                pin: Some(s(PASSPHRASE)),
            },
            &[PASSPHRASE],
        );
        hides(&UserRequest::UnlockWithPin { user_id: user(), pin: s(PIN), repair: false }, &[PIN]);
        hides(&UserRequest::BindDeviceHardware { user_id: user(), credential: s(PASSPHRASE) }, &[PASSPHRASE]);
        hides(&UserRequest::OperatorEnrol { user_id: user(), credential: s(OPERATOR) }, &[OPERATOR]);
        hides(&UserRequest::RelayStand { user_id: user(), code: s(RELAY_CODE) }, &[RELAY_CODE]);
        hides(&UserRequest::Authenticate { token: s(SESSION), scope: None }, &[SESSION]);
        hides(&UserRequest::PairConfirmCode { user_id: user(), token: s(CEREMONY), matches: true }, &[CEREMONY]);
        hides(
            &UserRequest::Introduce { user_id: user(), addr: "192.0.2.7:7443".into(), token: s(CEREMONY), router: None },
            &[CEREMONY],
        );
        hides(&UserRequest::ContactPairJoin { user_id: user(), code: s(SPOKEN), as_name: None }, &[SPOKEN]);
        hides(
            &UserRequest::DeviceAdmit {
                user_id: user(),
                code: s(INVITE),
                ttl_seconds: 60,
                posture: kotton_schemas::membership::Posture::Full,
                operator_of: None,
            },
            &[INVITE],
        );
        hides(&UserRequest::DeviceJoin { user_id: user(), code: s(CONNECTION), as_name: None }, &[CONNECTION]);
        hides(&UserRequest::GatewayEnroll { user_id: user(), code: s(ENROL), ttl_seconds: 60 }, &[ENROL]);
        hides(
            &UserRequest::RemoteAdd { user_id: user(), name: "s3".into(), backend: s3(), credentials: Some(credentials()) },
            &[SECRET_ACCESS_KEY],
        );
        hides(
            &UserRequest::RemoteCredentialsSet { user_id: user(), name: "s3".into(), credentials: credentials() },
            &[SECRET_ACCESS_KEY],
        );
    }

    #[test]
    fn no_remote_request_prints_a_secret_it_carries() {
        let user = || "alice".to_string();
        hides(
            &RemoteRequest::LoginWithRecoveryKey { recovery_key: s(PHRASE), device_name: None, user_id: Some(user()) },
            &[PHRASE],
        );
        hides(
            &RemoteRequest::OrgFrostJoin {
                user_id: user(),
                name: "org".into(),
                org_did: "did:key:z6Mk".into(),
                share_hex: s(share()),
                participant_idx: 2,
            },
            &[&share()],
        );
        hides(
            &RemoteRequest::OrgFrostSignFinalize {
                user_id: user(),
                session_id: "session".into(),
                cosigner_id_hex: "02".into(),
                cosigner_commitment_hex: "ab".into(),
                cosigner_share_hex: s(cosigner_share()),
            },
            &[&cosigner_share()],
        );
        hides(
            &RemoteRequest::SetLockPolicy {
                user_id: user(),
                mode: LockMode::Passphrase,
                auto_lock_minutes: 0,
                pin: Some(s(PASSPHRASE)),
            },
            &[PASSPHRASE],
        );
        hides(&RemoteRequest::Authenticate { token: s(SESSION), scope: None }, &[SESSION]);
        hides(
            &RemoteRequest::RemoteAdd { user_id: user(), name: "s3".into(), backend: s3(), credentials: Some(credentials()) },
            &[SECRET_ACCESS_KEY],
        );
        hides(
            &RemoteRequest::RemoteCredentialsSet { user_id: user(), name: "s3".into(), credentials: credentials() },
            &[SECRET_ACCESS_KEY],
        );
    }

    /// The recorded surfaces hold the rule for a field not written yet: one
    /// named for a secret, on a request or on an answer, is a secret wrapper
    /// (`SecretText`, `SecretValue`, `SecretBytes`) or a `bool` that says
    /// whether one is set, or the surface says otherwise and this names it.
    #[test]
    fn every_field_named_for_a_secret_is_secret_text_on_the_recorded_surface() {
        const SECRET_NAMES: [&str; 11] = [
            "passphrase",
            "pin",
            "recovery_key",
            "share_hex",
            "cosigner_share_hex",
            "credential",
            "token",
            "code",
            "session_token",
            "credentials",
            "signing_key_bytes",
        ];
        const SECRET_TYPES: [&str; 3] = ["SecretText", "SecretValue", "SecretBytes"];
        let surfaces = [
            ("request", include_str!("../../wire-surface.txt"), 22),
            ("response", include_str!("../../response-surface.txt"), 12),
        ];
        let mut plain = Vec::new();
        for (which, surface, at_least) in surfaces {
            let mut variant = "";
            let mut seen = 0;
            for line in surface.lines() {
                if !line.starts_with(' ') && !line.starts_with('#') {
                    variant = line.trim();
                    continue;
                }
                let Some((name, ty)) = line.trim().split_once(": ") else { continue };
                if SECRET_NAMES.contains(&name) {
                    seen += 1;
                    if ty != "bool" && !SECRET_TYPES.iter().any(|secret| ty.contains(secret)) {
                        plain.push(format!("{which} {variant}.{name}: {ty}"));
                    }
                }
            }
            assert!(seen >= at_least, "the {which} surface names {seen} secret fields; the parser no longer reads it");
        }
        assert!(plain.is_empty(), "secret fields that print through Debug: {plain:?}");
    }
}
