// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic constants for Kotton

/// Argon2id parameters for PIN hashing.
///
/// Used by the daemon to hash the 6-digit device PIN stored in
/// `device/users/{user_id}/auth.json`.  These are the OWASP-recommended
/// interactive minimums.  **Never use `Argon2::default()`** — it uses 19 MB /
/// 2 iterations, which cracks a 6-digit PIN space (10⁶) in seconds on a
/// consumer GPU.  At 64 MB / 3 iterations, the full space takes ~83 GPU-hours.
///
/// When M24e lands, the same parameters wrap the per-user CEK
/// (`Argon2id(PIN) → wrap_key → decrypt(wrapped_master_secret)`).
pub mod pin {
    /// Memory cost — 64 MiB (OWASP interactive minimum).
    pub const ARGON2_M_COST: u32 = 65_536;
    /// Time cost — 3 iterations.
    pub const ARGON2_T_COST: u32 = 3;
    /// Parallelism — 1 lane (single-threaded; avoids NUMA surprises on servers).
    pub const ARGON2_P_COST: u32 = 1;
    /// Output length in bytes (256-bit).
    pub const ARGON2_OUTPUT_LEN: usize = 32;
    /// Consecutive failed unlock attempts before the daemon stops checking the
    /// PIN at all and imposes a cooldown.
    ///
    /// This is enforced in `kuserd`'s `lock_policy`, not merely displayed. It
    /// used to be neither: the counter was incremented and reported as
    /// "attempts remaining" while every attempt was still verified, so the
    /// daemon would accept guess number five thousand (RFC-0053 step 2).
    pub const MAX_ATTEMPTS: u8 = 5;
    /// Cooldown imposed by the failure that reaches [`MAX_ATTEMPTS`]. Each
    /// further failure doubles the wait, up to [`MAX_COOLDOWN_SECS`].
    ///
    /// The doubling is what makes the brake worth having. A flat 30s window
    /// grants an attacker ~14k guesses a day, which walks a 4-digit PIN space
    /// in under an hour of wall-clock patience; doubling puts the tenth failure
    /// past an hour and the space out of online reach.
    pub const COOLDOWN_SECS: u64 = 30;
    /// Ceiling on the doubling cooldown — one hour.
    ///
    /// A cap rather than unbounded growth because the legitimate user is the
    /// one most likely to hit this, and a locked-out honest user's remedy
    /// (the mnemonic) should not be *more* convenient than waiting.
    pub const MAX_COOLDOWN_SECS: u64 = 3_600;
}

/// The **daily unlock credential** — RFC-0053's tier 2 (`pin`, above, holds the
/// KDF parameters it is stretched with).
///
/// The whole design turns on one number: how much entropy the credential has
/// against an attacker who copies `vault.json` and guesses offline, where no
/// counter of ours is in the room. RFC-0053's rule follows the rate limiter
/// rather than the platform:
///
/// > A short PIN is permitted **only** where hardware sealing with
/// > attempt-limiting is present. Everywhere else, a real passphrase is required.
///
/// The limiter is a property of a user's hardware binding, not of the
/// platform: `kotton_sys::secret::attempt_limiting_for(binding)` answers for
/// the key at hand, and the bar for a user follows the binding they stored.
/// Where nothing is bound, or the binding's counting has not been verified on
/// real hardware (`TPM_LOCKOUT_VERIFIED`), it reports `None` and
/// [`MIN_ENTROPY_BITS`] is the bar. The two constants exist as a pair so that
/// verifying the counter flips a predicate rather than rewriting a policy
/// (DEC-0046, TASK-the-enclave-does-not-count-attempts).
pub mod daily_credential {
    /// Words in a passphrase Kotton generates.
    ///
    /// The BIP-39 list is 2048 words = [`BITS_PER_WORD`] bits per draw. Kotton
    /// draws **without replacement**, so five words is
    /// `log2(2048 × 2047 × … × 2044)` ≈ 54.997 bits — above
    /// [`MIN_ENTROPY_BITS`] with margin, and short enough to retype daily.
    /// This number is *known*, not estimated, which is the reason generation is
    /// the offered path.
    pub const GENERATED_WORDS: usize = 5;

    /// Bits contributed per word drawn uniformly from the 2048-word list.
    pub const BITS_PER_WORD: f64 = 11.0;

    /// Minimum entropy when nothing limits an attacker's guess rate.
    ///
    /// 50 bits sits just under RFC-0053's "4-word diceware ≈ 51 bits →
    /// infeasible" row and well above the "6-digit PIN ≈ 20 bits → hours on
    /// rented hardware" one. It is the line between the two rows of that table,
    /// which is the only place the number comes from — it is a judgement about
    /// offline cost, not a standard.
    pub const MIN_ENTROPY_BITS: f64 = 50.0;

    /// Minimum entropy where hardware counts failed attempts somewhere the
    /// attacker cannot reach, which is what makes a short PIN defensible.
    ///
    /// **Unreachable today**: no platform reports hardware attempt-limiting
    /// until RFC-0053 step 8 lands. It is written down now so the rule is
    /// expressed as a rule rather than as an accident of there being only one
    /// branch.
    ///
    /// 19.9 and not 20, because the case this exists to permit is a six-digit
    /// PIN and that is `log2(10^6)` = **19.93** bits, not 20. A round number
    /// here would have excluded the exact credential the constant is named
    /// for — which is what the tests caught when it was written as 20.0.
    pub const MIN_ENTROPY_BITS_HARDWARE_LIMITED: f64 = 19.9;

    /// Floor tests for a passphrase the user wrote themselves.
    ///
    /// These are a floor beneath the measurement, not the measurement — see
    /// `kotton_crypto::daily_credential`, which scores a user-chosen secret by
    /// the order an attacker searches (zxcvbn, since 2026-09-06). These two
    /// still reject the obviously weak with a message that names what is wrong
    /// ("too short", "too repetitive") before the estimate is consulted.
    pub const MIN_CHARS: usize = 12;
    /// Distinct characters required, so repetition cannot buy length.
    pub const MIN_UNIQUE_CHARS: usize = 8;
}

/// HKDF info-string labels for Kotton key derivation.
///
/// All labels are stable, versioned ASCII strings.  They must **never change**
/// once any database has been encrypted with a key derived from them.  To
/// rotate, introduce a new version suffix (e.g. `"v2"`) and run a re-key
/// migration — never silently change an existing label.
///
/// Labels follow the pattern `"kotton:<domain>:<scope>:v<N>"`.
pub mod kdf_labels {
    /// Info string for the top-level master secret derivation.
    ///
    /// Input: `seed32` (first 32 bytes of BIP-39 PBKDF2 seed)
    /// Output: `master_secret` — never stored.
    pub const MASTER: &str = "kotton:master:v1";

    /// Info string for the system events/config database (`system/events.db`).
    pub const SYSTEM_DB: &str = "kotton:db:system:v1";

    /// Info string for a per-user record store (`users/<user_id>/records.db`).
    pub fn user_records_db(user_id: &str) -> String {
        format!("kotton:db:user:{user_id}:v1")
    }

    /// Info string for a per-user agent database (`users/<user_id>/agent.db`).
    ///
    /// RFC-0063 stage 3b: the user-scoped tables of the machine-wide
    /// `system/agent.db` move into one encrypted database per principal,
    /// keyed like `records.db` from that user's master secret.
    pub fn user_agent_db(user_id: &str) -> String {
        format!("kotton:db:user-agent:{user_id}:v1")
    }

    /// Info string for a per-app data database (`app_data/<app_id>.db`).
    pub fn app_db(app_id: &str) -> String {
        format!("kotton:db:app:{app_id}:v1")
    }

    /// Info string for the event-log HMAC integrity chain key.
    ///
    /// This key is used by `SqliteEventLog` to sign each event row and by
    /// `verify_event_log` to re-verify the chain. It is derived from the
    /// user's `master_secret` and is never stored.
    pub const HMAC_EVENTS: &str = "kotton:hmac:events:v1";

    /// OS keychain entry name under which a user's `seed32` is stored.
    ///
    /// The value is a lowercase-hex 32-byte string.  Written at account creation
    /// or recovery login; deleted at logout.
    pub fn seed32_keychain_key(user_id: &str) -> String {
        format!("kotton:seed32:{user_id}")
    }

    /// HKDF info string for deriving the Ed25519 identity signing key scalar.
    ///
    /// Input:  `seed32` (first 32 bytes of BIP-39 PBKDF2 seed)
    /// Output: 32-byte Ed25519 scalar → clamped per RFC 8032 → identity keypair
    ///
    /// **Stable forever.**  Changing this string changes every user's DID.  To
    /// migrate, introduce `"kotton:identity:ed25519:v2"` as a new dispatch case.
    pub const IDENTITY_ED25519: &str = "kotton:identity:ed25519:v1";

    /// HKDF info string for deriving the Content Encryption Key (CEK).
    ///
    /// Input:  `seed32` (first 32 bytes of BIP-39 PBKDF2 seed)
    /// Output: 32-byte symmetric key — root of the per-file key hierarchy.
    ///
    /// **Stable forever.**  A change here invalidates all stored ciphertext for
    /// every user; requires a full re-encryption pass.  To migrate, introduce
    /// `"kotton:cek:v2"` and run the background re-encryption infrastructure.
    pub const CEK: &str = "kotton:cek:v1";

    /// HKDF info string for deriving the CEK *recovery* key-encryption key (KEK).
    ///
    /// Input:  `seed32` (first 32 bytes of BIP-39 PBKDF2 seed)
    /// Output: 32-byte KEK that wraps the random CEK so the mnemonic alone can
    ///         recover it (RFC-0033 Hybrid CEK — the continuity invariant).
    ///
    /// **Stable forever.**  A change here makes every user's CEK unrecoverable
    /// from their mnemonic — i.e. permanent data loss. To migrate, introduce
    /// `"kotton:cek-recovery:v2"` and re-wrap each user's recovery copy.
    pub const CEK_RECOVERY: &str = "kotton:cek-recovery:v1";

    /// HKDF info string for deriving a **key-domain identifier** from the CEK.
    ///
    /// A non-secret, one-way fingerprint of the content-encryption key. Sealed
    /// replication carries it so a receiver can decide the only question that
    /// matters — *can I open this blob?* — which is exactly *is this the same
    /// CEK?* (RFC-0041).
    ///
    /// It replaces the CEK **epoch** on the wire, which could not answer that: a
    /// rotation counter says which generation within one lineage, so two nodes
    /// that were never in the same fleet both start at 0 and compare equal while
    /// holding entirely different keys. A rotation changes the CEK and therefore
    /// this value too, so the domain id subsumes the epoch for the correctness
    /// check. The epoch remains a *local* concept, for diagnostics and for a
    /// future rotation ceremony.
    ///
    /// **Stability contract:** fixed forever. Changing it makes every node
    /// consider every peer a different domain, halting replication fleet-wide
    /// until all of them upgrade. A migration must introduce a `v2` label and
    /// accept both during the transition.
    pub const CEK_DOMAIN_ID: &str = "kotton:cek-domain-id:v1";

    /// HKDF info string for deriving the **path-blinding key** from
    /// `master_secret` (RFC-0044).
    ///
    /// Object keys are stored blinded so a replica holding the user's ciphertext
    /// cannot read their names: `family/legal/filing.pdf` becomes three opaque
    /// components. Without this key a blinded component is indistinguishable from
    /// random, and it cannot be brute-forced from a dictionary of likely names —
    /// computing *any* blinded value requires the key.
    ///
    /// Derived from the **CEK**, the object key domain — a path is object metadata,
    /// so RFC-0036's blast-radius isolation is best served by keeping this key in
    /// the domain of the data it protects. Deriving it from `master_secret` (the
    /// db-domain root) would instead leak every object path on a record-database
    /// compromise, a cross-domain leak; see RFC-0044 M1 for the full analysis.
    ///
    /// **Stability contract:** fixed forever. Changing it renames every object in
    /// every store — the data survives, but nothing can find it without a full
    /// re-blinding migration. A migration must introduce a `v2` label and rewrite
    /// each key.
    pub const PATH_BLIND: &str = "kotton:path-blind:v1";

    /// HKDF info string for deriving the **pack-sealing key** from the CEK
    /// (RFC-0045).
    ///
    /// A pack is the object-storage envelope, so its key is object-domain and
    /// CEK-derived — the same reasoning as [`PATH_BLIND`]: `master_secret`
    /// derivation would leak every pack on a record-database compromise and would
    /// leave a joined device (CEK but no `master_secret`) unable to open packs.
    /// Record segments inside a pack (RFC-0046) carry their own inner seal, so the
    /// db domain stays separate.
    ///
    /// **Stability contract:** fixed forever; a change re-seals every pack.
    pub const PACK: &str = "kotton:pack:v1";
    /// HKDF info string for deriving an **ephemeral session key** from the CEK,
    /// one per session id (RFC-0075).
    ///
    /// A session key scopes a guest device to a subset of the user's storage for
    /// a bounded time. It is object-domain — it opens the user's stored bytes —
    /// so it derives from the CEK, the same root the pack and path-blinding keys
    /// take, not from `master_secret`.
    ///
    /// Parameterised by the session id so each session gets an independent key,
    /// the same shape [`app_db`] uses to give each app one. Until 2026-09-06 this
    /// key was derived in `kotton_grant` with `blake3::derive_key` and an inline
    /// label — a second key hierarchy nobody reviewing this registry would learn
    /// existed (`TASK-session-key-derives-outside-the-hierarchy`). It is HKDF here
    /// now, one label among the rest, so "different labels produce independent,
    /// separated keys" stays a claim this file can be read to check.
    ///
    /// **Stability contract:** the session key is ephemeral and re-derived, never
    /// stored, so a change here invalidates only sessions still live at the
    /// moment of the change — not data. Bump to `v2` to rotate.
    pub fn session(session_id: &str) -> String {
        format!("kotton:session:{session_id}:v1")
    }

    /// HKDF info string for deriving the **history-log segment key** from
    /// `master_secret` (RFC-0046, widened by RFC-0047).
    ///
    /// The inverse of [`PACK`], and deliberately so. A segment is the *inner*
    /// seal on record and object history, so it is **db-domain** and derives
    /// from `master_secret`; the pack it sits in supplies the outer,
    /// object-domain seal. That separation is the point: a CEK compromise opens
    /// packs but not the history inside them (RFC-0036 blast-radius isolation),
    /// so a device holding only the CEK can carry segments without reading
    /// them.
    ///
    /// **Stability contract:** fixed forever; a change orphans every segment
    /// ever written. A migration needs a `v2` label and a rewrite of the log.
    pub const HISTORY_LOG: &str = "kotton:history-log:v1";

    /// HKDF info string for deriving the **identity-key recovery** KEK.
    ///
    /// Input:  `seed32` (first 32 bytes of BIP-39 PBKDF2 seed)
    /// Output: 32-byte KEK that wraps a recovery copy of the (random) operational
    ///         identity key so the mnemonic alone can re-establish a working
    ///         identity after total device loss (RFC-0039 generate-and-seal — the
    ///         identity half of the continuity invariant, parallel to
    ///         [`CEK_RECOVERY`]).
    ///
    /// **Stable forever.**  A change here makes every user's identity key
    /// unrecoverable from their mnemonic. To migrate, introduce
    /// `"kotton:identity-recovery:v2"` and re-wrap each user's recovery copy.
    pub const IDENTITY_RECOVERY: &str = "kotton:identity-recovery:v1";

    /// HKDF info string for deriving the **`master_secret` recovery** KEK.
    ///
    /// Input:  `seed32` (first 32 bytes of BIP-39 PBKDF2 seed)
    /// Output: 32-byte KEK that wraps a recovery copy of the (random) operational
    ///         `master_secret` — the DB-encryption root — so the mnemonic alone can
    ///         recover every database after total device loss (RFC-0039
    ///         generate-and-seal, parallel to [`CEK_RECOVERY`] / [`IDENTITY_RECOVERY`]).
    ///
    /// **Stable forever.**  A change here makes every user's databases unrecoverable
    /// from their mnemonic. To migrate, introduce `"kotton:master-recovery:v2"` and
    /// re-wrap each user's recovery copy.
    pub const MASTER_RECOVERY: &str = "kotton:master-recovery:v1";

    /// HKDF info-string **prefix** for the indexed **KEL pre-rotation recovery key**
    /// `K_rec[i]` (RFC-0038). Combined with the little-endian index:
    /// `HKDF(seed32, "kotton:kel:recovery:v1" || i)` → an Ed25519 seed. The
    /// mnemonic-rooted, zero-custody reserve whose public key each KEL event
    /// pre-commits (`recovery_commitment`) — so a full-quorum thief cannot roll the
    /// identity forward, only the mnemonic re-derives the reserve.
    ///
    /// **Stable forever.** A change here makes every user's KEL recovery lineage
    /// unrecoverable from their mnemonic.
    pub const KEL_RECOVERY: &str = "kotton:kel:recovery:v1";

    /// OS keychain entry name under which a user's Ed25519 identity signing key
    /// scalar is stored.
    ///
    /// The value is a lowercase-hex 32-byte scalar.  Written alongside `seed32`
    /// at account creation/login; deleted at logout.  Used by the daemon to sign
    /// `GrantEnvelope`s at app-install time without needing the mnemonic.
    pub fn identity_signing_key(user_id: &str) -> String {
        format!("kotton:identity_key:{user_id}")
    }

    /// OS keychain entry name under which a user's **random operational
    /// `master_secret`** is stored (lowercase-hex 32 bytes).
    ///
    /// RFC-0039: the `master_secret` (DB-encryption root) is random — *not*
    /// `HKDF(seed32)` — so `seed32` is never needed to open the databases. Written
    /// at account creation / unlock; the mnemonic-sealed recovery copy lives
    /// separately (see [`crate::kdf`] `MASTER_RECOVERY`). Distinct from the
    /// [`MASTER`] HKDF label, which is the legacy `seed32`-derived derivation.
    pub fn master_secret_keychain_key(user_id: &str) -> String {
        format!("kotton:master_secret:{user_id}")
    }
    /// OS keychain entry name under which this device's FROST key-package
    /// **share** for `user_id` is stored (RFC-0033 node enrollment).
    ///
    /// The value is the hex-serialised `frost_ed25519` `KeyPackage`. Present on
    /// every device that participates in the user's threshold: the issuer's
    /// retained 2-of-2 share, and each enrolled device's own share. Absence
    /// means this device is not a FROST party (1-of-1 bootstrap or blind relay).
    pub fn frost_share(user_id: &str) -> String {
        format!("kotton:frost_share:{user_id}")
    }

    /// OS keychain entry name under which the user's FROST group
    /// **`PublicKeyPackage`** (hex) is stored.
    ///
    /// The public half of the threshold — needed by a signing coordinator to
    /// aggregate signature shares (`frost::aggregate`). Persisted on every node
    /// that holds a share (RFC-0036, distributed-signing prerequisite). Public
    /// material, but identity-sensitive (reveals the participant verifying shares).
    pub fn frost_pubkey_package(user_id: &str) -> String {
        format!("kotton:frost_pubkey:{user_id}")
    }

    /// OS keychain entry name under which an enrolled device's **warm signing
    /// key** (private Ed25519 scalar, lowercase hex) is stored.
    ///
    /// The warm key performs routine operations under a root-signed
    /// [`warm_key_delegation`] so the FROST quorum is not touched per action
    /// (RFC-0031 / RFC-0033). Generated fresh on the enrolling device.
    pub fn warm_signing_key(user_id: &str) -> String {
        format!("kotton:warm_key:{user_id}")
    }

    /// OS keychain entry name under which an enrolled device stores the
    /// root-quorum-signed `WarmKeyDelegation` (JSON) authorising its warm key.
    pub fn warm_key_delegation(user_id: &str) -> String {
        format!("kotton:warm_delegation:{user_id}")
    }

    /// OS keychain entry name under which an enrolled device stores the
    /// operational Content Encryption Key (CEK) delivered at enrollment
    /// (lowercase-hex 32 bytes).
    ///
    /// Distinct from the `seed32`-derived [`CEK`]: an enrolled device that joins
    /// via FROST never receives `seed32`, so it holds the CEK directly. The VFS
    /// reading this stored CEK rather than deriving it is the CEK→VFS slice.
    pub fn operational_cek(user_id: &str) -> String {
        format!("kotton:cek_operational:{user_id}")
    }

    /// Whether `label` names one of the **operational roots** — key material
    /// that opens the user's data, as opposed to a fingerprint, epoch, or
    /// bookkeeping value.
    ///
    /// RFC-0053 step 4 turns on this distinction: the platform may *hold*
    /// Kotton's secrets but what it holds should be ciphertext, so a root must
    /// never sit in an OS keychain in the clear once the user has a daily
    /// credential to seal it under. Everything else may.
    ///
    /// It lives here, beside the functions that mint these labels, because the
    /// only safe place to decide "is this a root" is the module that names them
    /// — a classifier anywhere else drifts the first time a root is added.
    /// `every_root_label_is_classified` holds the two in step.
    pub fn is_operational_root(label: &str) -> bool {
        matches!(
            label.strip_prefix("kotton:").and_then(|l| l.split(':').next()),
            Some("seed32" | "identity_key" | "master_secret" | "cek_operational")
        )
    }

    /// Which identity a root label belongs to, if it is a root.
    ///
    /// RFC-0056 R4 requires that one identity's roots never share a compromise
    /// domain with another's, and enforcing that needs the owner of a label —
    /// which only the naming module can extract, since only it knows that the
    /// scope is the final segment.
    ///
    /// Returns `None` for anything that is not an operational root, so a caller
    /// cannot accidentally group non-root material by identity.
    pub fn root_owner(label: &str) -> Option<&str> {
        if !is_operational_root(label) {
            return None;
        }
        // `kotton:<kind>:<user_id>` — split twice, keep the remainder, so a
        // user_id containing a colon survives intact.
        let (_, owner) = label.strip_prefix("kotton:")?.split_once(':')?;
        (!owner.is_empty()).then_some(owner)
    }

    /// OS keychain entry name under which an enrolled device stores the CEK
    /// rotation **epoch** (decimal string) for [`operational_cek`].
    pub fn operational_cek_epoch(user_id: &str) -> String {
        format!("kotton:cek_epoch:{user_id}")
    }

    /// OS keychain entry name recording which **key domain** the sealed objects
    /// on a given replicated mount belong to (hex domain id).
    ///
    /// Only meaningful on a node that holds **no** CEK of its own (RFC-0036
    /// `BlindStorage`): it cannot compare an incoming blob against a key domain it
    /// does not have, so it records the domain of the first sealed write and
    /// refuses later writes from a different one. That keeps a blind mount
    /// single-domain, so every blob on it is attributable to one key — and it is
    /// why re-seeding, not silent mixing, is what a CEK rotation demands of a
    /// hosted replica (RFC-0041).
    pub fn sealed_mount_domain(user_id: &str, mount: &str) -> String {
        format!("kotton:sealed_mount_domain:{user_id}:{mount}")
    }

    /// OS keychain entry name for this **device's** operational signing key
    /// (lowercase-hex 32-byte Ed25519 seed) — the key that authenticates the
    /// device's operational peer connections (mTLS), presence, and dialing.
    ///
    /// Device-level (not per-user): one persistent operational identity per
    /// machine, loaded at daemon startup. Replaces the former per-process
    /// ephemeral key so the identity is stable across restarts; bound to a
    /// user's root via a per-`(user, device)` `WarmKeyDelegation` (RFC-0031).
    /// See `DEC-0001`.
    pub fn device_operational_key() -> String {
        "kotton:device_operational_key".to_string()
    }

    /// OS keychain entry name for this machine's **operator** signing key
    /// (lowercase-hex 32-byte Ed25519 seed) — the warm credential `kctl`
    /// authenticates to `kdeviced` with.
    ///
    /// Minted by the client on first contact with a fresh device and
    /// auto-enrolled as the first sudoer (trust on first use — the person at
    /// the machine on first boot is the owner/operator; see
    /// `DEC-0017`). Distinct from
    /// [`device_operational_key`](Self::device_operational_key), which is the
    /// *daemon's* network identity: this one belongs to the human
    /// administrating the device, holds device authority only, and reaches no
    /// user key material. The recovery mnemonic remains the break-glass path.
    pub fn device_operator_key() -> String {
        "kotton:device_operator_key".to_string()
    }

    /// OS keychain entry name under which an org's Ed25519 private key scalar
    /// is stored.
    ///
    /// The value is a lowercase-hex 32-byte scalar generated fresh at org
    /// creation (`kotton org new`).  Stored once; never rotated without an
    /// explicit key-rotation migration.  Absence means the org key is
    /// unavailable on this device (e.g. after a `kctl user remove`).
    pub fn org_signing_key(org_did: &str) -> String {
        format!("kotton:org_key:{org_did}")
    }
}

#[cfg(test)]
mod tests {
    use super::kdf_labels as L;

    /// Every label that names key material opening the user's data must be
    /// classified as a root, and everything beside it must not be.
    ///
    /// The classifier and the constructors are two lists that have to agree, so
    /// this is the thing that keeps them agreeing: a new root label added
    /// without a matching arm shows up here, not in a keychain full of
    /// plaintext.
    #[test]
    fn every_root_label_is_classified() {
        for label in [
            L::seed32_keychain_key("avery"),
            L::identity_signing_key("avery"),
            L::master_secret_keychain_key("avery"),
            L::operational_cek("avery"),
        ] {
            assert!(
                L::is_operational_root(&label),
                "{label} opens the user's data and must be treated as a root"
            );
        }
    }

    /// Bookkeeping beside the roots is not itself a root. Over-classifying is
    /// not the safe direction here: it would push values the daemon needs
    /// before unlock into memory-only storage and break cold start.
    #[test]
    fn bookkeeping_labels_are_not_roots() {
        for label in [
            L::operational_cek_epoch("avery"),
            L::org_signing_key("did:kel:org"),
        ] {
            assert!(
                !L::is_operational_root(&label),
                "{label} is not key material that opens data"
            );
        }
    }

    /// A malformed or foreign label must not be mistaken for a root — the
    /// classifier reads a fixed position, so anything not in Kotton's namespace
    /// answers no.
    #[test]
    fn foreign_labels_are_not_roots() {
        for label in ["", "master_secret:avery", "other:master_secret:avery"] {
            assert!(!L::is_operational_root(label), "{label:?} is not ours");
        }
    }

    /// Every root label reports the identity it belongs to — the fact RFC-0056
    /// R4 is enforced with. A root whose owner could not be determined would
    /// have to be grouped somewhere, and any answer would be wrong.
    #[test]
    fn every_root_label_reports_its_owner() {
        for label in [
            L::seed32_keychain_key("avery"),
            L::identity_signing_key("avery"),
            L::master_secret_keychain_key("avery"),
            L::operational_cek("avery"),
        ] {
            assert_eq!(L::root_owner(&label), Some("avery"), "for {label}");
        }
    }

    /// A user id containing a colon must survive intact, or two identities
    /// could be grouped under the same truncated owner — which is the one
    /// failure mode this function must not have.
    #[test]
    fn an_owner_containing_a_colon_is_not_truncated() {
        let did = "did:kel:EabcXYZ";
        assert_eq!(
            L::root_owner(&L::master_secret_keychain_key(did)),
            Some(did)
        );
    }

    /// Non-roots have no owner, so nothing that is not key material can be
    /// grouped into an identity's set by accident.
    #[test]
    fn non_roots_have_no_owner() {
        assert_eq!(L::root_owner(&L::operational_cek_epoch("avery")), None);
        assert_eq!(L::root_owner(&L::org_signing_key("did:kel:org")), None);
        assert_eq!(L::root_owner("kotton:master_secret:"), None);
    }
}
