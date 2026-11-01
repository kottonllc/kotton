// SPDX-License-Identifier: AGPL-3.0-or-later
//! `VaultRequest` — what a vault's door accepts (RFC-0084 V1, RFC-0082 rule 2).
//!
//! A vault is the binary in which the plaintext verbs do not exist, and the
//! rule that one acceptor has one request type is how that is made true on the
//! wire rather than at runtime: the door decodes *this* enum, so `ReadFile`
//! arriving at a vault is not refused by an arm — it fails to deserialize.
//! Unconstructible, not rejected. The same distinction `RemoteRequest` draws
//! for a gateway.
//!
//! Every variant here mirrors the `UserRequest` variant of the same name byte
//! for byte — same name, same fields, same `serde` attributes — so a device's
//! client, which speaks `UserRequest`, drives the vault's door unchanged for
//! the verbs the door has. The mirror is small enough to hold by hand; the
//! test at the bottom holds it.
//!
//! **Three variants mirror nothing, on purpose: `OperatorAdmit`,
//! `OperatorRevoke` and `OperatorRevokeAllBut`.** They decide who holds the vault's operator credential —
//! the key a landlord's desktop speaks the landlord's verbs under — and
//! neither has a `UserRequest` twin, so nothing on the peer transport can name
//! them: not a tenant's device, and not the operator's own key, which cannot
//! enrol a second key or keep itself from being revoked. Who enrols the
//! operator is whoever reaches this socket, which is the landlord (RFC-0084).
//! The tests at the bottom hold that.
//!
//! **`SetQuota`, `Tenants` and `DropTenant` mirrored nothing until 2026-09-23.**
//! They were the landlord's acts over the tenants a vault keeps for, and the
//! only way to keep them from a tenant was to leave them off the device's wire.
//! They mirror `UserRequest` now, because the operator credential carries them
//! over the peer transport; a tenant's device can build them and is refused
//! there by *standing* — `PeerStanding::Operator` is the only standing that
//! reaches them, and it reaches nothing else (`kvaultd::peer::reaches`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultRequest {
    /// Mint an invite and wait to be admitted through the relay: nothing
    /// listens on a public port (`kvaultd invite`).
    DeviceInvite {
        user_id: String,
        ttl_seconds: u64,
        #[serde(default)]
        as_name: Option<String>,
    },
    /// Hand the vault a pairing code; it joins the ceremony blind.
    DeviceJoin {
        user_id: String,
        code: SecretText,
        #[serde(default)]
        as_name: Option<String>,
    },
    /// The landlord's verdict on the six digits.
    PairConfirmCode {
        user_id: String,
        token: SecretText,
        matches: bool,
    },
    /// Bind the token the join handed back. Nothing is unlocked by it; the
    /// answer is only whether it is live.
    Authenticate {
        token: SecretText,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Vec<String>>,
    },
    /// This vault's stable DID and signing key, for the device that pairs it.
    GetNodeIdentity,
    /// Which nodes a pool is paired with.
    NodeList { user_id: String },
    /// Where this vault reserves.
    NodeRelay { user_id: String },
    /// Bytes held and the quota, for one pool.
    VaultCapacity { user_id: String },
    /// Set one pool's quota, in bytes: the space the landlord sets aside for
    /// one tenant (`kvaultd invite <user> --quota`, `kvaultd capacity <user>
    /// --set`). Answered with the pool's `VaultCapacityResult` after the set.
    /// The operator's key says it over the wire too — see the module note.
    SetQuota { user_id: String, quota: u64 },
    /// Every tenant this vault keeps anything for, with the landlord's
    /// readout of each (`kvaultd tenants`): answered with `VaultTenants`. The
    /// operator's key says it over the wire too — see the module note.
    Tenants,
    /// Drop exactly one tenant — their sealed pool, identity chain, sealed
    /// recovery copy, pairing and quota, and nothing of anyone else's
    /// (`kvaultd drop <user>`). Answered with `TenantDropped`, carrying the
    /// readout as it stood before. The operator's key says it over the wire
    /// too — see the module note.
    DropTenant { user_id: String },
    /// Enrol an operator credential by its public half — 64 hex characters,
    /// the key a desktop's `mint vault` printed (`kvaultd operator enrol`). A
    /// vault keeps a set of operators, each holding their own credential, so
    /// this adds one and leaves the others
    /// (`TASK-a-device-has-operators-not-an-operator`). Answered `Ok`. The
    /// door's alone — see the module note.
    OperatorAdmit { key: String },
    /// Revoke one operator credential by its public half: its row goes, and
    /// its key leaves the handshake's allowlist in the same step (`kvaultd
    /// operator revoke <key>`). A key that is not enrolled is refused, and so
    /// is the last one: a vault's operator set is never emptied while it runs
    /// (RFC-0084 V19, fork 3). Answered `Ok`. The door's alone — see the
    /// module note.
    OperatorRevoke { key: String },
    /// Revoke every operator credential but `keep` (`kvaultd operator revoke
    /// --all --keep <key>`): replacing a lost key is enrolling the new one and
    /// then this. Refused when `keep` is not enrolled, so the set is never
    /// emptied (RFC-0084 V19, fork 3). Answered `Ok`. The door's alone.
    OperatorRevokeAllBut { keep: String },
}

/// The service an operator credential operates (DEC-0087): a vault, or a relay.
/// Each is its own credential under its own key — `mint vault` and `mint
/// relay` make different keys — and nothing on the server answers to both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatedService {
    Vault,
    Relay,
}

impl OperatedService {
    /// The word a credential, a verb and a sentence spell it with.
    pub fn word(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Relay => "relay",
        }
    }
}

/// A key this desktop minted and has not yet completed from its instance's
/// line — what a bare `mint` lists (`TASK-mint-prints-the-hosts-install-command-and-is-verb-first`).
/// The public half alone, as `OperatorMinted` carries it: the secret stays in
/// the person's store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintWaiting {
    /// The name it was minted under.
    pub name: String,
    pub service: OperatedService,
    /// The public half, 64 hex — the key its instance is created for.
    pub key: String,
}

/// One line `enrol` was given (`UserRequest::OperatorEnrolLines`). The line
/// names no mint: the daemon finds the key waiting for the line's kind. `mint`
/// is set only to answer [`LineCame::Which`] — the name of the key the person
/// chose among those it listed — and is held there to a key still waiting for
/// that kind, never trusted for more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineToEnrol {
    /// The instance's line, `kotton-instance:<kind>:<key>@<hint>`.
    pub line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<String>,
}

/// What one line `enrol` was given came to, with the three readouts the
/// person reads it by (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`,
/// Done-when (1)): what it names, whether it is reached from here, and whether
/// its key matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineEnrolled {
    /// The line, as it reads back; what was given when it is no line.
    pub line: String,
    /// What it names: a relay or a vault. `None` when it is no line.
    pub kind: Option<OperatedService>,
    /// Where it says the instance is reached. Empty when it is no line, or
    /// names no address.
    pub hint: String,
    /// Whether the line's address was dialled at all: not for a line that is
    /// no line, one asked about, or one refused before the dial.
    pub dialled: bool,
    /// Whether the instance answered at that address: `None` when nothing was
    /// dialled, or when the dial failed in a way that does not say.
    pub reached: Option<bool>,
    /// Whether the instance there proved the line's key and answered as its
    /// operator under the key this desktop minted for it — a relay at its
    /// operator door, a vault to the operator's read: `None` when nothing was
    /// dialled, or it could not be told.
    pub matched: Option<bool>,
    pub came_to: LineCame,
}

/// What a line came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineCame {
    /// Its key was completed and is kept, under the name it was minted under.
    Kept {
        name: String,
        /// Whether it is the one instance of its kind this desktop operates —
        /// what decides whether the person is shown its name.
        only: bool,
        /// Why a vault is not yet standing at a relay, the credential being
        /// kept all the same; `None` when it was told, and for a relay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unstood: Option<Unstood>,
        /// For a relay, the vaults this desktop operates that its enrol told
        /// to stand there, by name — each told nothing before — for `enrol` to
        /// keep this person's things at the ones that do not keep them yet
        /// (#102). Empty for a vault, and for a relay that told none.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        stood: Vec<String>,
    },
    /// Several keys of the line's kind wait here, and nothing tells which one
    /// its instance was created for: nothing was dialled, and these are the
    /// names to choose among. Asked only then.
    Which { names: Vec<String> },
    /// Nothing was kept; this is why.
    Refused { why: String },
}

/// Why a vault whose operator credential is kept stands at no relay yet — on
/// `OperatorEnrolled` and `vault stand`'s refusal. The
/// cause is data so the shell names the act that works for it, never by
/// reading the sentence (`TASK-a-kept-claim-is-answered-as-a-failure-and-its-unit-left-stale-lines`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unstood {
    pub why: UnstoodWhy,
    /// The sentence, for the person.
    pub reason: String,
    /// For [`UnstoodWhy::RelaysNotHeld`] and [`UnstoodWhy::Moved`], each
    /// relay the vault was told of — where it was last found, as told — and
    /// what stands between it and this desktop; for [`UnstoodWhy::Several`],
    /// each relay this desktop operates, to choose among; empty otherwise. The
    /// truth is per relay, so the act is too ([`Unstood::acts`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<UnstoodRelay>,
}

/// One relay a vault was told of and this desktop no longer operates by the
/// key it was told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnstoodRelay {
    /// Where it was last found, as the vault was told.
    pub hint: String,
    pub state: UnstoodRelayState,
    /// The name this desktop keeps a credential for it under, where it keeps
    /// one: what `vault move` names. `None` for a relay no longer held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Why a relay the vault was told of is not one this desktop tells it of now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnstoodRelayState {
    /// No relay credential here names its key: hold it again, then `vault
    /// stand`.
    NotHeld,
    /// A relay held here answers at its address under another key — a new
    /// relay there, which the vault would move to — by `vault move`, or
    /// *Move…* in Settings, and never by itself.
    Moved,
    /// This desktop operates the relay, and it is one of several the vault
    /// could be told to stand at: which is the person's to say (the Default
    /// ruled on `TASK-settings-has-one-door-and-it-takes-a-code`).
    Operated,
}

/// What stands between a kept vault and a relay, by what fixes it. With
/// relays named, it is the act that leads: `RelaysNotHeld` when any one can be
/// held again, since that works today, and `Moved` only when every one moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnstoodWhy {
    /// This desktop operates no relay: enrolling one tells every vault not
    /// yet told.
    NoRelay,
    /// No relay the vault was told to stand at is one this desktop operates
    /// now, and at least one of them can be held again — its credential gone,
    /// or its name re-enrolled under another key. Holding that relay again,
    /// then `vault stand`, tells it.
    RelaysNotHeld,
    /// There was a set to tell and the vault did not take it — unreachable,
    /// or it refused (another key at a relay's address). `vault stand` again.
    NotTold,
    /// Every relay the vault was told of has a relay this desktop holds
    /// answering at its address under another key. A relay is its key, so the
    /// relay there is not the one the vault stands at: standing there is a
    /// move, and holding "that relay again" would only record the key already
    /// held. The move is the person's: `vault move`, or *Move…* in Settings
    /// (`TASK-settings-has-one-door-and-it-takes-a-code`).
    ///
    /// A cause of its own, not a field on [`Self::RelaysNotHeld`]: its act is
    /// different in kind — none a command can do — and [`Unstood::remedy`]
    /// and every reader choose the act by matching the cause, so a new cause
    /// is one they are made to answer, where a field is one they may skip.
    Moved,
    /// The vault was told nothing yet and this desktop operates more than one
    /// relay, so it asks rather than tells: with exactly one it tells the vault
    /// to stand there, and with more the person chooses (the owner took this
    /// default on `TASK-settings-has-one-door-and-it-takes-a-code`, 2026-09-29).
    /// [`Unstood::relays`] lists them, each by the name `vault move` takes.
    Several,
}

impl Unstood {
    /// The act that stands the vault `vault` for this cause, as the person
    /// types it — the one place it is worded, read by the shell beside a kept
    /// credential and by `vault stand`'s own refusal.
    pub fn remedy(&self, vault: &str) -> String {
        match self.why {
            UnstoodWhy::NoRelay => {
                "`enrol <the relay's line>` — enrolling a relay tells every vault not yet told".to_string()
            }
            UnstoodWhy::NotTold => format!("`vault stand {vault}`"),
            UnstoodWhy::Several => format!(
                "choose where it stands — `vault move {vault} <relay>` with one of: {}",
                self.relays.iter().map(|r| r.name.as_deref().unwrap_or(&r.hint)).collect::<Vec<_>>().join(", ")
            ),
            UnstoodWhy::RelaysNotHeld | UnstoodWhy::Moved => {
                let again = self.hints(UnstoodRelayState::NotHeld);
                let mut acts = Vec::new();
                match again.as_slice() {
                    [] => {}
                    [at] => acts.push(hold_again(at, vault)),
                    several => acts.push(format!(
                        "hold one of these relays again — `mint relay <a new name>`, enrol the key it prints \
                         at that relay's terminal, `enrol <the line it prints>` at one of these: {} — then \
                         `vault stand {vault}`",
                        several.join(", ")
                    )),
                }
                for r in self.relays.iter().filter(|r| r.state == UnstoodRelayState::Moved) {
                    acts.push(offer_move(r, vault));
                }
                if acts.is_empty() {
                    acts.push(hold_again("<its address>", vault));
                }
                acts.join("; or ")
            }
        }
    }

    /// The act for each relay the vault was told of, the ones that can be held
    /// again first — each with the relay's hint — or, for a cause that names no
    /// relay, the one act with none. What the shell lists; [`Self::remedy`] is
    /// the same acts in one sentence.
    pub fn acts(&self, vault: &str) -> Vec<(Option<String>, String)> {
        if self.relays.is_empty() || !matches!(self.why, UnstoodWhy::RelaysNotHeld | UnstoodWhy::Moved | UnstoodWhy::Several) {
            return vec![(None, self.remedy(vault))];
        }
        let of = |state: UnstoodRelayState| self.relays.iter().filter(move |r| r.state == state);
        let again = of(UnstoodRelayState::NotHeld).map(|r| (Some(r.hint.clone()), hold_again(&r.hint, vault)));
        let moved = of(UnstoodRelayState::Moved).map(|r| (Some(r.hint.clone()), offer_move(r, vault)));
        let operated = of(UnstoodRelayState::Operated).map(|r| (Some(r.hint.clone()), stand_there(r, vault)));
        again.chain(moved).chain(operated).collect()
    }

    fn hints(&self, state: UnstoodRelayState) -> Vec<&str> {
        self.relays.iter().filter(|r| r.state == state).map(|r| r.hint.as_str()).collect()
    }
}

fn hold_again(at: &str, vault: &str) -> String {
    format!(
        "hold that relay again — `mint relay <a new name>`, enrol the key it prints at \
         that relay's terminal, `enrol <the line the relay at {at} prints>` — then `vault stand {vault}`"
    )
}

/// Whether the vault moves is the person's decision, so this names the act and
/// never takes it.
fn offer_move(r: &UnstoodRelay, vault: &str) -> String {
    let at = &r.hint;
    match &r.name {
        Some(name) => format!(
            "the relay at {at} is a new relay, under another key — to stand the vault '{vault}' there, \
             `vault move {vault} {name}`, or *Move…* on the vault in Settings"
        ),
        None => format!(
            "the relay at {at} is a new relay, under another key — to stand the vault '{vault}' there, \
             *Move…* on the vault in Settings, or `vault move {vault} <relay>`"
        ),
    }
}

/// One relay the person may choose for a vault told nothing yet.
fn stand_there(r: &UnstoodRelay, vault: &str) -> String {
    format!("`vault move {vault} {}`", r.name.as_deref().unwrap_or("<relay>"))
}

impl std::fmt::Display for Unstood {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// One of the landlord's verbs, as a person's desktop names it to its own
/// daemon under an operator credential (`UserRequest::AsOperator`). The daemon
/// turns each into the vault's request of the same meaning — `Invite` into
/// `SetQuota` then `DeviceInvite`, in that order so the pool is never admitted
/// under a number the landlord did not give it — and this type is what keeps
/// the daemon from sending anything else under that key: there is no variant
/// to carry a sealed read, a write or a recovery packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorVerb {
    /// Mint an invite for the pool `pool`, with its quota if given; answered
    /// with the invite (`PairAdvertising`). The vault admits the device that
    /// meets it blind, and confirms its side of the six digits on sight, as
    /// `kvaultd invite` does: the person's device is where they are compared,
    /// against the digits [`OperatorVerb::Digits`] reads here.
    Invite {
        pool: String,
        #[serde(default)]
        quota: Option<u64>,
        ttl_seconds: u64,
    },
    /// The six digits the ceremony an invite for `pool` is waiting in has
    /// derived (`InviteDigits`): what the person admitting it types, read to
    /// them from here. Said as `InviteDigits`; empty while no device has
    /// dialled the invite.
    Digits { pool: String },
    /// Every pool the vault keeps, with bytes held and quota (`VaultTenants`).
    Pools,
    /// One pool's quota (`VaultCapacityResult`).
    SetQuota { pool: String, quota: u64 },
    /// Tell the vault where to stand again (`Ok`): what this desktop told it
    /// before or, told nothing yet, every relay this desktop operates
    /// (RFC-0084 V10). Said by the desktop as `StandAt`, the set drawn from its
    /// own record — the verb carries no relay. The remedy an enrol
    /// names when it kept the credential and could not tell the vault.
    Stand,
    /// Tell the vault to stand at the relay this desktop operates as `relay`,
    /// and nowhere else (`Ok`): `StandAt` again, with that relay's set. The
    /// door's *Move…*, and the answer to [`UnstoodWhy::Several`] — where to
    /// stand is the person's to say, and this is the saying
    /// (`TASK-settings-has-one-door-and-it-takes-a-code`).
    Move { relay: String },
    /// Drop one pool (`TenantDropped`). The invited key rotates after it at
    /// each relay this person operates that their desktop told the vault to
    /// stand at, so the pool's devices are refused there from the rotation
    /// after this one; with no such relay, nothing rotates.
    Drop { pool: String },
    /// The rule the relay holds. Asked of the relay under its own
    /// credential's key. Answered with `RelayRule`.
    ReadRule,
    /// Set the relay's rule (answered with `RelayRule`): the desktop mints the relay's two
    /// admission keys if it holds none, tells every vault it told to stand at
    /// that relay its reach set again with them (to none when there is none),
    /// and then sets the rule with them at the relay, in that order, so no rule
    /// is narrowed before the operator's own machines hold a key it reads.
    SetRule {
        rule: crate::rendezvous::AdmissionRule,
    },
    /// Mint an invite to the relay (answered with `RelayInvite`): the relay's key, its
    /// address and the *invited* admission key this desktop keeps for it, in
    /// the one code grammar. Said to nothing — the desktop holds all three —
    /// and refused for a relay whose rule admits only its operator's devices,
    /// where an invite would admit nobody.
    RelayInvite,
}

impl OperatorVerb {
    /// The service this verb is said to (DEC-0087): the seven the vault's
    /// credential speaks under, and the relay's three — two the relay answers,
    /// and its invite, which the desktop mints from what it keeps. The name in
    /// `AsOperator` is looked up among the credentials for this service alone.
    pub fn service(&self) -> OperatedService {
        match self {
            Self::Invite { .. }
            | Self::Digits { .. }
            | Self::Pools
            | Self::SetQuota { .. }
            | Self::Stand
            | Self::Move { .. }
            | Self::Drop { .. } => {
                OperatedService::Vault
            }
            Self::ReadRule | Self::SetRule { .. } | Self::RelayInvite => OperatedService::Relay,
        }
    }
}

/// Text that carries a secret on a request or an answer that otherwise derives
/// `Debug`: an operator credential's file, whose `operator=` line is the key the
/// desktop speaks under; the daily credential, passphrase or PIN; a recovery
/// phrase; a FROST key share or signature share; a code that admits; a
/// session token or a ceremony's token, either of which is the authority. On the
/// wire it is the plain string (`serde(transparent)`, so the bytes are what they
/// were); in a `{:?}` log or error it is `<redacted>`, as `DataKeys` and
/// `PairingPayload` print (`crate::peer`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretText(String);

impl SecretText {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The text, for the one reader that parses it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A structured secret: a storage backend's credentials, which the daemon hands
/// to the keychain and which arrive as JSON rather than as one string. The same
/// shape as [`SecretText`], over [`serde_json::Value`]: on the wire the value it
/// was (`serde(transparent)`), in a `{:?}` `<redacted>`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(serde_json::Value);

impl SecretValue {
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// The value, for the one reader that stores it.
    pub fn expose(&self) -> &serde_json::Value {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Key material as bytes: an Ed25519 seed handed to the one process that signs
/// with it. The same shape as [`SecretText`], over `Vec<u8>`: on the wire the
/// bytes as they were (`serde(transparent)`), in a `{:?}` `<redacted>`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The bytes, for the one reader that builds a key from them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One tenant as the landlord's door reads it: the name the landlord gave at
/// the invite and the three numbers a landlord bills and plans by. Nothing
/// here names a device or a key — `devices` is a count — because the door is
/// a readout of what the landlord holds, not of who the tenant is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultTenant {
    pub user_id: String,
    /// Sealed bytes held in the tenant's pool.
    pub held: u64,
    /// The number the tenant is held to: their own, else the vault's default.
    pub quota: Option<u64>,
    /// How many of the tenant's devices are paired with this vault.
    pub devices: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::UserRequest;

    /// **An operator credential never prints**: `UserRequest`'s derived
    /// `Debug` shows `OperatorEnrol`'s credential as `<redacted>`, and the wire
    /// carries it as the plain string it was.
    #[test]
    fn an_operator_credential_is_redacted_in_debug_and_plain_on_the_wire() {
        let secret = "kotton-operator 2\nname=kotton\noperator=0f0f0f0f\n";
        let request = UserRequest::OperatorEnrol {
            user_id: "lee".into(),
            credential: SecretText::new(secret),
        };
        let printed = format!("{request:?}");
        assert!(!printed.contains("0f0f0f0f") && !printed.contains("operator="), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["OperatorEnrol"]["credential"], serde_json::json!(secret));
    }

    /// **The door's own secrets never print**: the code a device hands the
    /// vault to join a ceremony, the token the landlord's verdict names and the
    /// token a device binds all show as `<redacted>` and cross the wire as
    /// written, so the vault's door cannot print what the device's wire hides.
    #[test]
    fn no_vault_request_prints_a_secret_it_carries() {
        let hides = |request: &VaultRequest, secret: &str| {
            let printed = format!("{request:?}");
            assert!(!printed.contains(secret), "{secret:?} prints in {printed}");
            assert!(printed.contains("<redacted>"), "{printed}");
            let wire = serde_json::to_string(request).unwrap();
            let on_wire = serde_json::to_string(secret).unwrap();
            assert!(wire.contains(&on_wire), "{secret:?} is not on the wire as written: {wire}");
        };
        hides(
            &VaultRequest::DeviceJoin {
                user_id: "lee".into(),
                code: SecretText::new("CODE-ONLY-THE-VAULT-SEES"),
                as_name: None,
            },
            "CODE-ONLY-THE-VAULT-SEES",
        );
        hides(
            &VaultRequest::PairConfirmCode {
                user_id: "lee".into(),
                token: SecretText::new("TOKEN-OF-THE-VERDICT"),
                matches: true,
            },
            "TOKEN-OF-THE-VERDICT",
        );
        hides(
            &VaultRequest::Authenticate { token: SecretText::new("BEARER-AT-THE-DOOR"), scope: None },
            "BEARER-AT-THE-DOOR",
        );
    }

    /// The door's variants are `UserRequest`'s, byte for byte: what a device's
    /// client sends for these verbs decodes at the vault, and nothing else does.
    #[test]
    fn the_door_mirrors_the_device_wire_and_nothing_more() {
        let same: Vec<UserRequest> = vec![
            UserRequest::DeviceJoin {
                user_id: "alice".into(),
                code: SecretText::new("c"),
                as_name: None,
            },
            UserRequest::DeviceInvite {
                user_id: "alice".into(),
                ttl_seconds: 86_400,
                as_name: None,
            },
            UserRequest::PairConfirmCode {
                user_id: "alice".into(),
                token: SecretText::new("t"),
                matches: true,
            },
            UserRequest::Authenticate {
                token: SecretText::new("t"),
                scope: None,
            },
            UserRequest::GetNodeIdentity,
            UserRequest::NodeList {
                user_id: "alice".into(),
            },
            UserRequest::NodeRelay {
                user_id: "alice".into(),
            },
            UserRequest::VaultCapacity {
                user_id: "alice".into(),
            },
        ];
        for req in &same {
            let bytes = serde_json::to_vec(req).unwrap();
            let door: VaultRequest = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{} must decode at the door: {e}", req.variant_name()));
            assert_eq!(serde_json::to_vec(&door).unwrap(), bytes, "re-encodes byte for byte");
        }
        let not: UserRequest = UserRequest::ReadFile {
            user_id: "alice".into(),
            path: "notes.txt".into(),
            offset: 0,
            length: 0,
        };
        assert!(
            serde_json::from_slice::<VaultRequest>(&serde_json::to_vec(&not).unwrap()).is_err(),
            "a plaintext verb is unconstructible at the door"
        );
    }

    /// The landlord's three verbs over tenants mirror the device's wire byte
    /// for byte: what the door takes, the operator's key sends on the peer
    /// transport, where standing — not decoding — is what refuses a tenant.
    #[test]
    fn the_landlords_verbs_mirror_the_device_wire() {
        for verb in [
            UserRequest::SetQuota {
                user_id: "alice".into(),
                quota: 1 << 30,
            },
            UserRequest::Tenants,
            UserRequest::DropTenant {
                user_id: "alice".into(),
            },
        ] {
            let bytes = serde_json::to_vec(&verb).unwrap();
            let door: VaultRequest = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{} must decode at the door: {e}", verb.variant_name()));
            assert_eq!(serde_json::to_vec(&door).unwrap(), bytes, "re-encodes byte for byte");
        }
    }

    /// Who holds the operator credential is the door's alone: neither verb
    /// decodes as a `UserRequest`, so nothing on the peer transport — a
    /// tenant's device, or the operator's key itself — can enrol a key or
    /// revoke one.
    #[test]
    fn the_operators_key_is_set_only_at_the_door() {
        for verb in [
            VaultRequest::OperatorAdmit { key: "00".repeat(32) },
            VaultRequest::OperatorRevoke { key: "00".repeat(32) },
            VaultRequest::OperatorRevokeAllBut { keep: "00".repeat(32) },
        ] {
            let bytes = serde_json::to_vec(&verb).unwrap();
            assert!(
                serde_json::from_slice::<UserRequest>(&bytes).is_err(),
                "{verb:?} is unconstructible on a device's wire"
            );
            let door: VaultRequest = serde_json::from_slice(&bytes).expect("the door decodes it");
            assert_eq!(serde_json::to_vec(&door).unwrap(), bytes);
        }
    }

    /// Neither revocation can say *every operator*: each names a key, and a
    /// request that omits it does not decode (RFC-0084 V19, fork 3).
    #[test]
    fn revoking_every_operator_cannot_be_said() {
        for bare in [
            r#"{"OperatorRevoke":{}}"#,
            r#""OperatorRevoke""#,
            r#"{"OperatorRevoke":{"key":null}}"#,
            r#"{"OperatorRevokeAllBut":{}}"#,
            r#"{"OperatorRevokeAllBut":{"keep":null}}"#,
        ] {
            assert!(serde_json::from_str::<VaultRequest>(bare).is_err(), "{bare} decoded");
        }
    }
}
