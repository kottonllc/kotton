// SPDX-License-Identifier: AGPL-3.0-or-later
//! `device/users.json` — maps logical user-ids to their DID and registration metadata.
//!
//! Written atomically at [`register`] time. Each entry is a [`UserRecord`]
//! struct rather than a plain OS identity string, and a caller is authenticated
//! by session token, not by an OS-identity check (see `agent/mod.rs`).
//!
//! File layout  (`<base>/device/users.json`):
//! ```json
//! {
//!   "alice": { "did": "did:key:z6Mk…", "registered_at": "…" },
//!   "u3f9c…": { "did": "did:kel:E…", "registered_at": "…",
//!               "display_name": "Austin" }
//! }
//! ```
//!
//! **The key is an id, and the id is never shown.** The first entry above is
//! what the CLI makes — `kotton id create alice` names the id — and what an
//! older device holds, as `owner`. The
//! second is what the window makes: an id [`mint_user_id`] drew at random, and
//! beside it the name the person typed, which is what the desktop calls them.
//! A record with no `display_name` is an older one, or a CLI-made one; the
//! shell draws its fallbacks for it and Settings offers to set one. Nothing
//! reads the key to draw it.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

// ─── types ───────────────────────────────────────────────────────────────────

/// Per-user record stored in `device/users.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    /// Decentralised identifier created when the user was first registered.
    pub did: String,
    /// ISO 8601 timestamp of when this user was registered on the device.
    pub registered_at: String,
    /// What the desktop calls this person: the name they typed on the welcome,
    /// or set later in Settings. A display fact and nothing else — renaming
    /// changes this field and no directory, no key and no id.
    ///
    /// **A cache, not the source.**
    /// The name is the person's, so it is kept as a sealed record in their own
    /// store ([`crate::own_name`]) and travels to their other devices with it.
    /// This copy exists because the lock screen greets the person before
    /// anything of theirs is unlocked and so cannot read that record; it is
    /// written from the record — when a write reaches it, and when a sync pass
    /// lands one ([`cache_display_name`]) — and never read back into it.
    /// Absent on an older record, on one the CLI made, and
    /// until a name arrives; `serde(default)` is what lets those files still
    /// open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

// ─── path helper ─────────────────────────────────────────────────────────────

fn users_file(base: &Path) -> PathBuf {
    base.join("device").join("users.json")
}

// ─── load / save ─────────────────────────────────────────────────────────────

/// Read the current user-registry from disk, relative to `base` — the base
/// directory the daemon holding this registry was constructed with, never a
/// process-global answer.
/// Returns an empty map if the file does not yet exist.
pub fn load(base: &Path) -> io::Result<HashMap<String, UserRecord>> {
    let path = users_file(base);
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = std::fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Persist `map` to `<base>/device/users.json`, creating the parent directory if needed.
fn save(base: &Path, map: &HashMap<String, UserRecord>) -> io::Result<()> {
    let path = users_file(base);
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)?;
    }
    let json = serde_json::to_string_pretty(map)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(&path, json)
}

// ─── public API ──────────────────────────────────────────────────────────────

/// Validate a proposed user ID.
///
/// Rules:
/// - 1–64 characters
/// - Must start with a lowercase ASCII letter
/// - Remaining characters: lowercase ASCII letters, digits, `-`, `_`
/// - Must not be a Windows reserved device name (CON, PRN, AUX, NUL, COMn, LPTn)
///
/// Returns `Err` with a descriptive message if the ID is invalid.
pub fn validate_user_id(user_id: &str) -> io::Result<()> {
    if user_id.is_empty() || user_id.len() > 64 {
        return Err(io::Error::other(
            "user_id must be between 1 and 64 characters",
        ));
    }
    let mut chars = user_id.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(io::Error::other(
            "user_id must start with a lowercase ASCII letter",
        ));
    }
    for c in chars {
        if !matches!(c, 'a'..='z' | '0'..='9' | '-' | '_') {
            return Err(io::Error::other(format!(
                "user_id contains invalid character '{c}'; \
                 only lowercase letters, digits, '-' and '_' are allowed"
            )));
        }
    }
    // Reject Windows reserved device names to prevent path traversal on Windows.
    const RESERVED: &[&str] = &[
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    if RESERVED.contains(&user_id) {
        return Err(io::Error::other(
            "user_id is a reserved device name on Windows",
        ));
    }
    Ok(())
}

/// A user id that [`validate_user_id`] accepts, and nothing else: built only by
/// [`UserId::parse`], so a value of this type is one a path under `users/` or a
/// keychain label may be built from.
///
/// The peer path parses the `user_id` a request names into one before it does
/// anything with it — before a row is read, a chain is looked up or a database
/// is found — so a name that would climb out of `users/` (`..`, `/`), name
/// nobody (empty) or overrun the rule never reaches a path (kotton #262). The
/// request type itself still carries a `String` (`kotton_wire::ipc::PeerRequest`);
/// whether the wire should carry this type is kotton #283.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    /// `s`, if [`validate_user_id`] accepts it.
    pub fn parse(s: &str) -> io::Result<Self> {
        validate_user_id(s)?;
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The most characters a display name may hold. Generous for a name and short
/// enough that a menubar cannot be pushed off the screen by one.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;

/// Bring a typed display name to the form the registry stores.
///
/// Trimmed; `Ok(None)` when nothing is left, which is how a person clears
/// their name and how a caller with no name to give says so. Refused with a
/// reason when it holds a control character — the shell's own name field
/// already drops those, and the launch carries several names in one argument
/// separated by U+001F, which only holds while no name can contain one — or
/// when it runs past [`MAX_DISPLAY_NAME_CHARS`].
pub fn normalize_display_name(raw: &str) -> io::Result<Option<String>> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().any(char::is_control) {
        return Err(io::Error::other(
            "a display name cannot contain control characters",
        ));
    }
    if name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(io::Error::other(format!(
            "a display name is at most {MAX_DISPLAY_NAME_CHARS} characters"
        )));
    }
    Ok(Some(name.to_owned()))
}

/// Draw a fresh user id for an identity the window creates.
///
/// **Random, local to this device, and derived from nothing** — not from the
/// name the person typed, so a rename is a display change and never a move;
/// and not from their DID, because a directory name that is a function of the
/// identity would be a join key between this disk and everywhere that identity
/// appears (`CLAUDE.md`, the first design test).
/// A `u` and thirty-two hex digits, which is a value [`validate_user_id`]
/// accepts and a person is never shown.
pub fn mint_user_id() -> String {
    format!("u{}", uuid::Uuid::new_v4().simple())
}

/// Associate `user_id` with its DID in the on-disk registry, and the name the
/// desktop calls the person, if one was given — as [`normalize_display_name`]
/// reads it, like every write of that field (see [`set_display_name`]).
pub fn register(base: &Path, user_id: &str, did: &str, display_name: Option<&str>) -> io::Result<()> {
    let record = new_record(did, display_name)?;
    let mut map = load(base)?;
    map.insert(user_id.to_owned(), record);
    save(base, &map)
}

/// The record [`register`] writes, registered now. Apart from the file so the
/// rule it holds — the stored name is the normalised one — can be read without
/// one.
fn new_record(did: &str, display_name: Option<&str>) -> io::Result<UserRecord> {
    Ok(UserRecord {
        did: did.to_owned(),
        registered_at: chrono::Utc::now().to_rfc3339(),
        display_name: display_name.map(normalize_display_name).transpose()?.flatten(),
    })
}

/// Change what the desktop calls `user_id`, to `raw` as
/// [`normalize_display_name`] reads it; an empty name clears it, after which the
/// shell draws its no-name fallbacks again. Returns what was stored.
///
/// **Both writes of `display_name` normalise** — [`register`] through
/// [`new_record`], and this one — and not only their callers: the `names`
/// launch argument relies on no stored name holding U+001F, and a rule held by
/// whoever calls this is a rule the next caller forgets. The occupant host
/// normalises once more *before* creation, so a name that does not fit is
/// refused with nothing made rather than after the identity exists.
///
/// The one thing this touches is the record's `display_name`: the id stays,
/// the directory under `users/` stays, and the DID is not consulted. That is
/// the whole of what "a rename is a display change only" means in code.
pub fn set_display_name(base: &Path, user_id: &str, raw: &str) -> io::Result<Option<String>> {
    let display_name = normalize_display_name(raw)?;
    let mut map = load(base)?;
    let record = map.get_mut(user_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("'{user_id}' is not registered on this device"),
        )
    })?;
    record.display_name = display_name.clone();
    save(base, &map)?;
    Ok(display_name)
}

/// Make this device's copy of `user_id`'s name `name`, already normalised,
/// copied from the sealed record in the person's store
/// ([`crate::own_name::refresh_cache`]). Returns whether the registry changed.
///
/// **This is the one write of the copy that follows the record rather than a
/// person's edit**, and it makes an entry when there is none: a device joined
/// to the identity is not registered by the ceremony, and the name arriving is
/// the first fact of the person's it holds. The entry carries `did`, the
/// identity whose store the record was read from.
pub fn cache_display_name(
    base: &Path,
    user_id: &str,
    did: &str,
    name: Option<&str>,
) -> io::Result<bool> {
    let mut map = load(base)?;
    match map.get_mut(user_id) {
        Some(record) if record.display_name.as_deref() == name => return Ok(false),
        Some(record) => record.display_name = name.map(str::to_owned),
        None => {
            map.insert(user_id.to_owned(), new_record(did, name)?);
        }
    }
    save(base, &map)?;
    Ok(true)
}

/// Remove `user_id` from the registry (called at logout time).
pub fn unregister(base: &Path, user_id: &str) -> io::Result<()> {
    let mut map = load(base)?;
    if map.remove(user_id).is_some() {
        save(base, &map)?;
    }
    Ok(())
}

/// Returns `true` if `user_id` has an entry in the registry.
pub fn user_exists(base: &Path, user_id: &str) -> io::Result<bool> {
    let map = load(base)?;
    Ok(map.contains_key(user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the peer path refuses before a path or a label is built from it
    /// (kotton #262): a climb, a separator, nothing, too much, and anything
    /// that is not an identifier.
    #[test]
    fn user_id_parse_refuses_what_is_not_an_identifier() {
        let over_long = format!("a{}", "b".repeat(64));
        for bad in [
            "..",
            "../../x",
            "a/b",
            "/",
            "/tmp/abs",
            "",
            over_long.as_str(),
            "Alice",
            "1alice",
            "a.b",
            "a b",
            "a\\b",
            "con",
            "ali\u{0}ce",
        ] {
            assert!(UserId::parse(bad).is_err(), "{bad:?} is refused at the parse");
        }
        let longest = format!("a{}", "b".repeat(63));
        for good in ["alice", "a", "a-b_c9", longest.as_str()] {
            assert_eq!(UserId::parse(good).expect(good).as_str(), good);
        }
        let minted = mint_user_id();
        assert_eq!(UserId::parse(&minted).expect("a minted id parses").as_str(), minted);
    }

    /// The minted id is one the registry's own rule accepts, and two mints are
    /// two ids — a fixed value here would be `owner` under another name.
    #[test]
    fn a_minted_user_id_validates_and_is_never_the_same_twice() {
        let a = mint_user_id();
        let b = mint_user_id();
        validate_user_id(&a).expect("a minted id passes validate_user_id");
        validate_user_id(&b).expect("a minted id passes validate_user_id");
        assert_ne!(a, b, "two mints must differ");
        assert_ne!(a, "owner", "the literal is retired for new devices");
    }

    /// The minted id is drawn from nothing the person supplied: two identities
    /// made under the same name get unrelated ids, and the name is not in either.
    #[test]
    fn a_minted_user_id_is_not_derived_from_the_name() {
        let name = "austin";
        let a = mint_user_id();
        let b = mint_user_id();
        assert!(!a.contains(name) && !b.contains(name), "{a} {b}");
        assert_ne!(a, b);
    }

    /// A `users.json` written before the display name existed still opens, and
    /// reads as a record with no name — which is what an `owner` device is.
    #[test]
    fn a_record_written_before_the_display_name_still_loads_with_none() {
        let raw = r#"{ "owner": { "did": "did:kel:Eabc", "registered_at": "2026-09-01T00:00:00Z" } }"#;
        let map: HashMap<String, UserRecord> = serde_json::from_str(raw).expect("old shape loads");
        let owner = &map["owner"];
        assert_eq!(owner.did, "did:kel:Eabc");
        assert_eq!(owner.display_name, None);
        // And it is written back in the old shape, not with a `null` a reader
        // older than this field would have to learn to skip.
        let back = serde_json::to_string(&map).unwrap();
        assert!(!back.contains("display_name"), "{back}");
    }

    /// The registry's own write holds the rule, whatever its caller did: the
    /// stored name is the normalised one, an empty one is none, and one that
    /// does not fit is a refusal with no record made.
    #[test]
    fn registering_stores_the_normalised_name_or_refuses() {
        let did = "did:kel:Eabc";
        assert_eq!(new_record(did, None).unwrap().display_name, None);
        assert_eq!(new_record(did, Some("   ")).unwrap().display_name, None);
        assert_eq!(
            new_record(did, Some("  Austin ")).unwrap().display_name.as_deref(),
            Some("Austin")
        );
        assert!(new_record(did, Some("Aus\u{1f}tin")).is_err());
        assert!(new_record(did, Some(&"a".repeat(MAX_DISPLAY_NAME_CHARS + 1))).is_err());
    }

    #[test]
    fn a_display_name_is_trimmed_bounded_and_free_of_control_characters() {
        assert_eq!(normalize_display_name("  Austin ").unwrap(), Some("Austin".to_owned()));
        assert_eq!(normalize_display_name("   ").unwrap(), None);
        assert_eq!(normalize_display_name("").unwrap(), None);
        assert!(normalize_display_name("Aus\u{1f}tin").is_err(), "the launch's separator");
        assert!(normalize_display_name("Aus\ntin").is_err());
        let long = "a".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert!(normalize_display_name(&long).is_err());
        let exact = "é".repeat(MAX_DISPLAY_NAME_CHARS);
        assert!(normalize_display_name(&exact).is_ok(), "the bound counts characters, not bytes");
    }

    /// **Two daemons on different bases, in one process, see different
    /// registries.**
    ///
    /// Resolving `kotton_common::base_dir()`, a process-global answer read from
    /// the environment, two daemons in the same process — exactly what the
    /// integration suite runs — would share one file no matter which base each
    /// was constructed with. Nothing here touches the environment: each `base` is
    /// its own tempdir, and the two registries are read and written entirely
    /// through the functions this record's callers use.
    #[test]
    fn two_bases_in_one_process_see_different_registries() {
        let base_a = tempfile::tempdir().expect("tempdir a");
        let base_b = tempfile::tempdir().expect("tempdir b");

        register(base_a.path(), "alice", "did:key:z6MkAlice", Some("Alice")).expect("register on a");
        register(base_b.path(), "bob", "did:key:z6MkBob", Some("Bob")).expect("register on b");

        let on_a = load(base_a.path()).expect("load a");
        let on_b = load(base_b.path()).expect("load b");

        assert_eq!(on_a.keys().collect::<Vec<_>>(), vec!["alice"], "base a holds only what was registered on it");
        assert_eq!(on_b.keys().collect::<Vec<_>>(), vec!["bob"], "base b holds only what was registered on it");
        assert!(!on_a.contains_key("bob"), "base a must not see base b's registration");
        assert!(!on_b.contains_key("alice"), "base b must not see base a's registration");

        // And a write through one base cannot reach the other's file.
        unregister(base_a.path(), "alice").expect("unregister on a");
        assert!(load(base_a.path()).unwrap().is_empty(), "a is now empty");
        assert_eq!(
            load(base_b.path()).unwrap().keys().collect::<Vec<_>>(),
            vec!["bob"],
            "b is untouched by a's write"
        );
    }
}
