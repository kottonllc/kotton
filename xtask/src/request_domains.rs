// SPDX-License-Identifier: AGPL-3.0-or-later
//! `request-domains`: every `UserRequest` variant is assigned to a domain.
//!
//! ## Why this exists before the split
//!
//! RFC-0080's last open criterion asks that `required_trust()` stop being an
//! exhaustive match over one enum, and that **per-domain request enums carry
//! trust in the type**. That is a large change — 151 variants, 466 call sites,
//! and a wire format that must stay compatible — and it cannot start until
//! every variant has an owner.
//!
//! Assigning them is not mechanical. **Only 91 of the 151 carry their domain in
//! their name.** The other 60 do not: `ReadFile` is `fs`, `Authenticate` is
//! `session`, `TrustAdd` and `ContactList` are `peer`, `ThresholdSign` is `org`.
//! A name that does not say where a variant belongs is exactly how 151 of them
//! ended up in one enum without anyone deciding to put them there.
//!
//! So the classification is a judgement, and a judgement left in a commit
//! message rots. This check makes it an artifact:
//!
//! - every variant of `UserRequest` appears in the table below, and
//! - every entry in the table names a variant that exists.
//!
//! Both directions, for the reason `layer-check` needs both: a table that has
//! drifted in either direction has stopped describing the enum, and a stale
//! entry reads as a decision when it is a leftover.
//!
//! **This is not the split.** It is the measurement the split proceeds from,
//! and it keeps the answer true while that happens one domain at a time.

use std::path::Path;

/// Where each `UserRequest` variant belongs.
///
/// The domain names are the crates in `core/`. Where a variant could plausibly
/// sit in two, the tiebreak is RFC-0080's question — *on whose authority does
/// this act?* — not which crate currently implements the handler.
const DOMAINS: &[(&str, &[&str])] = &[
    (
        "identity",
        &[
            "CreateUser",
            "AddRecoveryPhrase",
            "LogoutUser",
            "LoginWithRecoveryKey",
            "RotateIdentity",
            "Recover",
            "RecoveryFetch",
            "RecoveryStore",
            "ConfirmMnemonic",
            "GetRecoveryStatus",
            "GetKeyHealth",
            "UnlockWithPin",
            "GetUnlockMethods",
            "BindDeviceHardware",
        ],
    ),
    (
        "session",
        &[
            "Authenticate",
            "CallerInfo",
            "GetActiveSession",
            "LockSession",
            "MintPrincipalSession",
            "SessionList",
            "SessionEnd",
            "SetLockPolicy",
            "GetLockPolicy",
            "IpcSessions",
            "GetUnlockState",
            "LockCustody",
        ],
    ),
    (
        "fs",
        &[
            "ReadFile",
            "WriteFile",
            "ListFiles",
            "DeleteFile",
            "ListConflicts",
            "ResolveConflict",
            "PurgeFile",
            "ReadSealed",
            "ListSealed",
            "WriteSealed",
            "VfsWatch",
            "VfsReport",
        ],
    ),
    (
        "store",
        &[
            "RemoteAdd",
            "RemoteRemove",
            "RemoteList",
            "RemoteCacheClear",
            "RemoteCredentialsSet",
            "StorageReload",
            "MountPath",
            "MountList",
            "MountEvict",
        ],
    ),
    (
        "peer",
        &[
            "PairNodeEphemeral",
            "DeviceAdd",
            "DeviceJoin",
            "PairConfirmCode",
            "NodeList",
            "NodeRelay",
            "Introduce",
            "VaultCapacity",
            "NodeRevoke",
            "PeerAdd",
            "GetNodeIdentity",
            "TrustAdd",
            "TrustRemove",
            "TrustList",
            "ContactAdd",
            "ContactList",
            "ContactPairStart",
            "ContactPairJoin",
            // The landlord's verbs at a vault, and the operator credential a
            // desktop speaks them under (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`).
            "SetQuota",
            "Tenants",
            "DropTenant",
            "StandAt",
            "InviteDigits",
            "OperatorMint",
            "OperatorMints",
            "OperatorHeld",
            "OperatorForget",
            "OperatorEnrol",
            "OperatorEnrolLines",
            "AsOperator",
        ],
    ),
    (
        "sync",
        &[
            "SyncMount",
            "SyncConfigure",
            "SyncRuleList",
            "SyncRuleRemove",
            "SyncTrigger",
            "SyncAwait",
            "SyncStatus",
            "SyncAvailable",
        ],
    ),
    (
        "device",
        &[
            "DeviceName",
            "ListUsers",
            "RendezvousSet",
            "RendezvousStatus",
            "ConfigStatus",
            "TurnSet",
            "QuicGatewaySet",
            "QuicGatewayStatus",
            "GetAuthorizedClients",
            // Whether this machine runs a model is the machine's configuration,
            // like a gateway's (RFC-0085).
            "InferenceSet",
            // Whether this machine listens on the network it is on is the
            // machine's configuration too.
            "LocalDoor",
            "GetDeviceCert",
            "WebShellSet",
            "WebShellStatus",
            // The browser is paired like a device (DEC-0053): the door and the
            // frames through it act on the device's authority, not a session's.
            "WebShellPair",
            // What the desk admitted, seen and taken back on the same screen.
            "BrowserDeviceList",
            "BrowserDeviceRevoke",
            "BrowserFrame",
            "GatewayEnroll",
            "DeviceAdmit",
            "RelayStand",
            "DeviceInvite",
            // The reverse direction of `BrowserFrame`, and the same authority:
            // the gateway carries what the node hands it, sealed to the
            // browser's key, for as long as it holds the socket.
            "BrowserOutbound",
        ],
    ),
    ("net", &["NetworkStatus", "ReachStatus"]),
    (
        "record",
        &[
            "RecordInsert",
            "RecordQuery",
            "RecordSearch",
            "RecordDelete",
            "RecordOpen",
            "SchemaList",
            "SchemaRegister",
            "SchemaGet",
            "RecordSyncAvailable",
            "Import",
            "ApplyRecordChangeset",
            // A model is a manifest record and the sealed object it names
            // (RFC-0085). Not `device`, where `InferenceSet` sits: whether this
            // machine runs a model is the machine's configuration, and which
            // models the person owns is their content — it syncs to their other
            // devices and comes back from the phrase.
            "ModelAdd",
            "ModelWeights",
            "ModelList",
            "ModelRemove",
            "ModelUse",
        ],
    ),
    (
        "grant",
        &[
            "SchemaGrantList",
            "SchemaGrantSet",
            "SchemaGrantRevoke",
            "SchemaQuotaSet",
            "GrantRevoke",
            "GrantImport",
        ],
    ),
    (
        "app",
        &[
            "RegisterHandler",
            "UnregisterHandler",
            "GetHandlerFor",
            "ListHandlers",
            "SetDefaultHandler",
            "AppInstall",
            "AppInstallPreview",
            "AppGrants",
            "AppUninstall",
            "AppVerify",
            "ExtensionInstall",
            "ExtensionList",
            "ExtensionRemove",
            "AppList",
            "AppRegisterBundle",
            "AppGetBundlePath",
            "AppLaunch",
            "AppMessage",
            "AppGetRole",
            "AppSetRole",
        ],
    ),
    (
        "org",
        &[
            "OrgNew",
            "OrgShow",
            "OrgList",
            "OrgGrantIssue",
            "OrgGrantList",
            "OrgMemberRemove",
            "OrgRootCreate",
            "OrgRootInvite",
            "OrgFrostNew",
            "OrgFrostJoin",
            "OrgFrostSignBegin",
            "OrgFrostSignContribute",
            "OrgFrostSignFinalize",
            "FrostSignRound",
            "ThresholdSign",
        ],
    ),
    (
        "msg",
        &[
            "MessageSend",
            "MessageChannelSend",
            "MessageChannelCreate",
            "MessageChannelGrantKey",
            "MessageChannelRemoveMember",
            "MessageChannelLeave",
            "MessageChannelHistory",
            "MessagePollInbox",
            "MessageDecryptDm",
            "MessageDecryptChannel",
            // What a person has read, which is about messages and about nothing
            // else — the state a second device of theirs needs to agree with.
            "MessageMarkRead",
            "MessageUnreadCount",
            // What became of what a person sent: the outbox's reading.
            "MessageDeliveries",
            // The doors a vault holds and what arrives at them (`DEC-0056`).
            // They are `peer`-shaped in their transport and `msg` in their
            // subject: a door exists so a message reaches a person whose every
            // device is asleep, and the vault is told nothing else about it.
            "HoldDoors",
            "TakeDeliveries",
            // What a vault carries for its sender while no device of theirs is
            // awake: the outbox's own bytes, at the recipient's door.
            "CarryFrame",
        ],
    ),
    (
        "surface",
        // No compositor verb is left here, in either direction.
        //
        // `SurfaceOpen`/`Commit`/`Close`/`Resize` went to `KuidRequest` on
        // 2026-08-23 (kuserd → kuid, never requests *to* this daemon, RFC-0082).
        // `SurfaceInputEvent`/`SurfaceError`/`SurfaceClosed` followed on
        // 2026-08-27 as `CompositorEvent` — the same journey in the other
        // direction, and the one that let kuid stop being a client of this
        // daemon at all.
        //
        // What remains is the window queries a client genuinely asks. This
        // check's staleness rule caught both sets once they named nothing, which
        // is the whole reason it exists.
        &["WindowOpened", "WindowClosed", "WindowList"],
    ),
    (
        "diag",
        &[
            "QueryEvents",
            "VerifyEventLog",
            "SubscribeEvents",
            "DaemonStatus",
            "DaemonSidecars",
        ],
    ),
];

pub fn run() {
    let path = Path::new("core/wire/src/ipc/request.rs");
    let Ok(src) = std::fs::read_to_string(path) else {
        eprintln!(
            "request-domains: could not read {}. Run from workspace root.",
            path.display()
        );
        std::process::exit(1);
    };

    let variants = parse_variants(&src);
    if variants.is_empty() {
        eprintln!(
            "request-domains: parsed no variants out of UserRequest, which cannot be true. \
             The parser is broken and this check is silently vacuous."
        );
        std::process::exit(1);
    }

    let mut assigned: Vec<&str> = DOMAINS
        .iter()
        .flat_map(|(_, vs)| vs.iter().copied())
        .collect();
    assigned.sort_unstable();
    let dupes: Vec<&str> = assigned
        .windows(2)
        .filter(|w| w[0] == w[1])
        .map(|w| w[0])
        .collect();

    let unclassified: Vec<&String> = variants
        .iter()
        .filter(|v| !assigned.binary_search(&v.as_str()).is_ok())
        .collect();
    let phantom: Vec<&str> = assigned
        .iter()
        .copied()
        .filter(|a| !variants.iter().any(|v| v == a))
        .collect();

    if unclassified.is_empty() && phantom.is_empty() && dupes.is_empty() {
        println!(
            "request-domains: OK — all {} UserRequest variants are assigned across {} domains.",
            variants.len(),
            DOMAINS.len()
        );
        return;
    }

    if !unclassified.is_empty() {
        eprintln!(
            "request-domains: {} variant(s) belong to no domain:\n  {}\n\nAdd them to DOMAINS in \
             xtask. A variant nobody claimed is how this enum reached 151 of them.",
            unclassified.len(),
            unclassified
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !phantom.is_empty() {
        eprintln!(
            "request-domains: {} table entr{} name{} no variant:\n  {}\n\nThe assignment reads as \
             a decision but describes nothing.",
            phantom.len(),
            if phantom.len() == 1 { "y" } else { "ies" },
            if phantom.len() == 1 { "s" } else { "" },
            phantom.join(", ")
        );
    }
    if !dupes.is_empty() {
        eprintln!(
            "request-domains: {} variant(s) assigned to more than one domain:\n  {}",
            dupes.len(),
            dupes.join(", ")
        );
    }
    std::process::exit(1);
}

/// Pull the variant names out of `pub enum UserRequest { .. }`.
///
/// Brace-matched rather than line-counted: the enum spans 1,578 lines and its
/// variants carry struct bodies, so "the next `}`" is wrong in about a hundred
/// places.
fn parse_variants(src: &str) -> Vec<String> {
    let Some(start) = src.find("pub enum UserRequest {") else {
        return Vec::new();
    };
    let body_start = start + "pub enum UserRequest {".len();
    let mut depth = 1usize;
    let mut end = body_start;
    for (i, c) in src[body_start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    let mut depth = 0usize;
    for line in src[body_start..end].lines() {
        let trimmed = line.trim_start();
        // Only top-level lines inside the enum name a variant; anything deeper
        // is a field of one.
        if depth == 0 && !trimmed.starts_with("//") && !trimmed.starts_with('#') {
            let ident: String = trimmed
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() && ident.starts_with(|c: char| c.is_ascii_uppercase()) {
                out.push(ident);
            }
        }
        depth = depth
            .saturating_add(line.matches('{').count())
            .saturating_sub(line.matches('}').count());
    }
    out.sort_unstable();
    out.dedup();
    out
}
