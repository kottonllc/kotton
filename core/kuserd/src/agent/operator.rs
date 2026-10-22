// SPDX-License-Identifier: AGPL-3.0-or-later
//! The operator credentials on the desktop's side, which is where an
//! operator's verbs reach over the wire: kept, and spoken under.
//!
//! **One credential per service, each under its own key.** A vault's and a
//! relay's are two credentials, named by the person at the mint (`mint vault
//! <v>`, `mint relay <r>`); nothing here answers to a name spanning both,
//! because nothing on the server does.
//!
//! **Kept** as a private sealed object in the person's own store
//! (`kotton_store::runtime::private`), under their keys, in no root — so it
//! reaches no vault (not even the one it governs), no other device, no browser
//! and no app. **Spoken under** by a dialer that authenticates as a vault's
//! credential rather than as this device, to the one vault it names, saying
//! only what an [`OperatorVerb`] can name — four verbs, turned here into the
//! vault's requests of the same meaning, and a fifth, `Stand`, said as the
//! `StandAt` this desktop's own record draws. There is no other request this
//! file can send under that key, because there is no variant to carry it.
//!
//! What the vault lets that connection say is the vault's table
//! (`kvaultd::peer::reaches`); this side holds nothing that would widen it.
//!
//! **The relay, spoken to under its own key.**
//! The relay's rule is read and set with two more verbs, over HTTP to the
//! relay's `POST /operator`, signed by the relay's credential. Setting it is
//! three steps, in this order, so no rule is narrowed before the operator's own
//! machines hold a key it reads: the relay's two admission keys — *mine* and
//! *invited* — are minted if this person keeps none for that relay and kept
//! sealed beside the credentials (a private object, as they are); every vault
//! **this desktop told to stand at that relay** is told its reach set again,
//! with the keys riding beside the relay they belong to (`StandAt`, the
//! operator's row alone) — none when there is none — and the keys are held in
//! this device's keyring; and only then is the rule set at the relay with them.
//! Dropping a pool at a vault rotates *invited* the same way at each relay this
//! person operates that the vault stands at.
//!
//! **The desktop introduces the two services, and nobody else does**: it tells
//! the vault which relays to stand at. A relay is its key: the key its credential recorded when it
//! proved it. A vault's `enrol` is followed by telling the vault the reach set
//! for the relays this desktop operates, and a relay's by telling every vault
//! this desktop has told nothing yet. What was told to which vault is a dated
//! record in the person's own store ([`STANDS`]) — the vault by its key, each
//! relay by its key with its address as a hint — and it is how the vaults at a
//! relay are found: by the relay's key, never by a URL. The relay is told
//! nothing; the vault's credential names no relay.
//!
//! The keys leave this device three ways and no other: to the operator's own
//! services (the relay, and the vaults that reserve at it), to another of this
//! person's own devices in its answer to `NodeRelay`, and — *invited* alone —
//! to their contacts, inside the reach note sealed to each. No guest is ever
//! handed one: the shell names a rule, and is answered with a rule.
//!
//! **A `kotton-operator 1` credential is dropped and said.** It
//! named a host, one credential over both services; the desktop no longer reads
//! it, and the first verb that finds one kept drops it — with the keys minted
//! in that form and the relay keys kept beside it — and answers with the
//! commands to re-make it and to revoke its key at each service
//! ([`first_form_dropped`]).
//!
//! **So is any other kept credential that stops reading**: said, not logged. The desktop
//! cannot speak under it, and its key is still enrolled at the service it
//! named; the first verb that finds one drops it and answers with which it
//! was, the re-make, and the revoke at that service with the key in it
//! ([`stopped_reading`]). Never only a log line: an enrolled key nobody is told
//! about is standing left behind.

use crate::residency::{RecordStores, UserRegistry};
use kotton_device::DeviceRuntime;
use kotton_peer::operator::{FirstForm, Operates, OperatorCredential, Unread};
use kotton_peer::relay_keys::{relay_id, RelayId};
use kotton_store::runtime::user::UserStore;
use kotton_net::rendezvous::AdmissionKey;
use kotton_wire::ipc::{
    OperatedService, OperatorVerb, UnstoodRelayState, SecretText, Unstood, UnstoodRelay, UnstoodWhy, UserRequest, UserResponse,
};
use kotton_wire::rendezvous::{AdmissionRule, RelayOperatorRequest, RelayOperatorResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// The private object's name.
const KEPT: &str = "operators";

/// The private object that keeps each key minted here and not yet enrolled:
/// the text `minted_text` writes, one per service and name. A key
/// moves out of it and into [`KEPT`] when `enrol` completes it.
const MINTED: &str = "operators-minted";

/// The private object that keeps each relay's two admission keys.
const KEYS: &str = "relay-admission";

/// The private object that keeps the *invited* key of each relay this person
/// stood this device at from a relay's invite, by the relay's key. Theirs, not an operator's: it is never offered on.
const INVITED: &str = "relay-invited";

/// The private object that keeps what this desktop told each vault it
/// operates about where to stand: the desktop's readout and its
/// *Move…*, and how the vaults at a relay are found. Read by nothing else.
const STANDS: &str = "stands-at";

/// One relay's keys, as this person keeps them — by the relay's key, 64 hex.
/// Keys kept by the relay's URL carry no key; they are not read, and the
/// relay's next `relay rule` mints its keys again.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RelayKeys {
    #[serde(default)]
    pub key: String,
    pub mine: String,
    pub invited: String,
}

impl std::fmt::Debug for RelayKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayKeys").field("key", &self.key).finish_non_exhaustive()
    }
}

impl RelayKeys {
    fn relay(&self) -> Option<RelayId> {
        relay_id(Some(&self.key))
    }
}

/// Every relay's keys this person keeps, by relay key. An entry that names no
/// relay by its key is not read.
pub(crate) fn kept_keys(store: &UserStore) -> anyhow::Result<Vec<RelayKeys>> {
    let all: Vec<RelayKeys> = match kotton_store::runtime::private::read(store, KEYS)? {
        Some(bytes) => serde_json::from_slice(&bytes)?,
        None => Vec::new(),
    };
    Ok(all.into_iter().filter(|k| k.relay().is_some()).collect())
}

/// One relay a vault was told to stand at, as the desktop recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Stood {
    /// The relay's key, 64 hex.
    pub key: String,
    /// Where it was found when the vault was told.
    pub hint: String,
}

/// What this desktop told one vault, and when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StandsAt {
    /// The vault's key, 64 hex — what the vault *is*.
    pub vault: String,
    /// The reach set, first relay first.
    pub relays: Vec<Stood>,
    /// Unix seconds.
    pub told_at: u64,
}

/// Every vault this desktop told where to stand.
pub(crate) fn stands(store: &UserStore) -> anyhow::Result<Vec<StandsAt>> {
    match kotton_store::runtime::private::read(store, STANDS)? {
        Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
        None => Ok(Vec::new()),
    }
}

fn keep_stands(store: &UserStore, all: &[StandsAt]) -> anyhow::Result<()> {
    kotton_store::runtime::private::write(store, STANDS, &serde_json::to_vec(all)?)
}

/// What this desktop last told the vault `vault`, if anything.
pub(crate) fn stands_of(store: &UserStore, vault: &[u8; 32]) -> Option<StandsAt> {
    let want = hex::encode(vault);
    stands(store).ok()?.into_iter().find(|s| s.vault == want)
}

/// The vault key of a vault's credential.
fn vault_key(c: &OperatorCredential) -> Option<[u8; 32]> {
    match c.operates {
        Operates::Vault { vault, .. } => Some(vault),
        Operates::Relay { .. } => None,
    }
}

/// The key of a relay's credential, when it recorded one.
fn relay_key(c: &OperatorCredential) -> Option<RelayId> {
    match c.operates {
        Operates::Relay { key, .. } => key,
        Operates::Vault { .. } => None,
    }
}

fn keep_keys(store: &UserStore, all: &[RelayKeys]) -> anyhow::Result<()> {
    kotton_store::runtime::private::write(store, KEYS, &serde_json::to_vec(all)?)
}

/// One relay invite's key this person stood this device at a relay with.
#[derive(Clone, Serialize, Deserialize)]
struct InvitedKey {
    /// The relay's key, 64 hex.
    key: String,
    /// The *invited* admission key, as [`AdmissionKey::to_text`] writes it.
    invited: String,
}

fn kept_invited(store: &UserStore) -> anyhow::Result<Vec<InvitedKey>> {
    Ok(match kotton_store::runtime::private::read(store, INVITED)? {
        Some(bytes) => serde_json::from_slice(&bytes)?,
        None => Vec::new(),
    })
}

/// Keep `invited` sealed in this person's store as the key they present at
/// `relay`, replacing any kept for it, and hold it in this device's keyring.
pub(crate) fn keep_invited(runtime: &DeviceRuntime, store: &UserStore, relay: &RelayId, invited: AdmissionKey) -> anyhow::Result<()> {
    let mut all = kept_invited(store)?;
    all.retain(|k| relay_id(Some(&k.key)).as_ref() != Some(relay));
    all.push(InvitedKey { key: hex::encode(relay), invited: invited.to_text() });
    kotton_store::runtime::private::write(store, INVITED, &serde_json::to_vec(&all)?)?;
    runtime.reachability().relay_keys().hold_invited(store.user_id(), relay, invited);
    Ok(())
}

/// Hold every relay key this person keeps in this device's keyring, so its
/// reservations and lookups at those relays present *mine*, and its reach note
/// offers *invited* — and, at a relay they were invited to, the *invited* key
/// that invite carried. Each relay's keys are held with the address its
/// operator credential names ([`operated_url`]), so this device presents
/// *mine* at that relay as its operator's own device whether or not it stands
/// there. Called when a person's store is there to read; the
/// keys are in memory only, and this is how they come back after a restart.
pub(crate) fn present_kept_keys(runtime: &DeviceRuntime, store: &UserStore) {
    match kept_keys(store) {
        Ok(all) => {
            let kept = held(store).unwrap_or_default();
            for k in all {
                if let (Some(r), Some(m), Some(i)) = (k.relay(), AdmissionKey::parse(&k.mine), AdmissionKey::parse(&k.invited)) {
                    let at = operated_url(&kept, &r);
                    runtime.reachability().relay_keys().hold_as_operator(store.user_id(), &r, at, m, i);
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "the relay keys kept here do not open"),
    }
    match kept_invited(store) {
        Ok(all) => {
            for k in all {
                if let (Some(r), Some(i)) = (relay_id(Some(&k.key)), AdmissionKey::parse(&k.invited)) {
                    runtime.reachability().relay_keys().hold_invited(store.user_id(), &r, i);
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "the relay invites kept here do not open"),
    }
}

/// The address the operator credential for the relay `relay` names, among
/// the credentials `kept` — this person's own record of where the relay they
/// operate is. `None` when no credential they hold names that relay's key.
fn operated_url<'a>(kept: &'a [OperatorCredential], relay: &RelayId) -> Option<&'a str> {
    kept.iter().find(|c| relay_key(c) == Some(*relay)).and_then(|c| match &c.operates {
        Operates::Relay { url, .. } => Some(url.as_str()),
        Operates::Vault { .. } => None,
    })
}

/// How long a verb may take end to end, dial included, before it is reported
/// as a service that did not answer rather than left hanging.
pub(crate) const WITHIN: Duration = Duration::from_secs(60);

fn refused(message: impl Into<String>) -> UserResponse {
    UserResponse::Error {
        message: message.into(),
    }
}

/// Every operator credential this person holds that reads, from their sealed
/// object. Empty when they hold none. One that does not read — the refused
/// first form, or any other — is not dropped here and hides none of the
/// others: it stays in the store for [`drop_unread`], which every verb runs
/// first and which drops it *and says so* to the person, with its key and the
/// revoke at its service. A readout passes it over, so nobody is dropped-on
/// without being told.
pub(crate) fn held(store: &UserStore) -> anyhow::Result<Vec<OperatorCredential>> {
    let Some(bytes) = kotton_store::runtime::private::read(store, KEPT)? else {
        return Ok(Vec::new());
    };
    let texts: Vec<String> = serde_json::from_slice(&bytes)?;
    Ok(texts.iter().filter_map(|t| OperatorCredential::parse(t).ok()).collect())
}

pub(crate) fn is(c: &OperatorCredential, service: OperatedService, name: &str) -> bool {
    c.service() == service && c.name == name
}

pub(crate) fn minted(store: &UserStore) -> anyhow::Result<Vec<String>> {
    match kotton_store::runtime::private::read(store, MINTED)? {
        Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
        None => Ok(Vec::new()),
    }
}

fn keep_minted(store: &UserStore, all: &[String]) -> anyhow::Result<()> {
    kotton_store::runtime::private::write(store, MINTED, &serde_json::to_vec(all)?)
}

fn minted_is(text: &str, service: OperatedService, name: &str) -> bool {
    let (waits, n, _) = kotton_peer::operator::service_name_and_secret(text);
    waits == service && n.as_deref() == Some(name) && kotton_peer::operator::first_form(text).is_none()
}

/// What `kvaultd operator revoke` and the relay's own revoke are typed as, at
/// each service's shell, for `key` — the forms `docs/use/` types the enrol in.
pub(crate) fn revoke_at_each_service(key: &str) -> [String; 2] {
    [
        format!("kvaultd operator revoke {key}"),
        format!("runuser -u kotton-relay -- kotton-relay --state-dir /var/lib/kotton-relay operator revoke {key}"),
    ]
}

/// The revoke at `service` alone, for `key` ([`revoke_at_each_service`]).
fn revoke_at(service: OperatedService, key: &str) -> String {
    let [vault, relay] = revoke_at_each_service(key);
    match service {
        OperatedService::Vault => vault,
        OperatedService::Relay => relay,
    }
}

/// The enrol of `key` as a further operator at `service`, typed at its shell
/// in the form its guide types it (`docs/use/run-a-vault.md`,
/// `docs/use/run-a-relay.md`).
fn enrol_at(service: OperatedService, key: &str) -> String {
    match service {
        OperatedService::Vault => format!("kvaultd operator enrol {key}"),
        OperatedService::Relay => {
            format!("runuser -u kotton-relay -- kotton-relay --state-dir /var/lib/kotton-relay operator enrol {key}")
        }
    }
}

/// How a sentence that drops credentials ends ([`first_form_dropped`],
/// [`stopped_reading`]): the verb it answered did nothing else.
const SAID_AGAIN: &str = "Nothing else was done — say it again once the new credential is made.";

/// What is said of each kept credential that stopped reading, without the
/// ending ([`stopped_reading`]).
fn stopped_lines(unread: &[Unread]) -> String {
    let mut out = String::new();
    for u in unread {
        let name = u.name.as_deref().unwrap_or("<name>");
        let which = match (u.service, &u.name) {
            (Some(s), Some(n)) => format!("an operator credential for the {} '{n}'", s.word()),
            (Some(s), None) => format!("an operator credential for a {} that names nothing", s.word()),
            (None, Some(n)) => format!("an operator credential named '{n}' that says no service"),
            (None, None) => "an operator credential that names nothing".to_string(),
        };
        out.push_str(&format!(
            "This desktop kept {which} that it can no longer read, so it is dropped here: nothing can be said \
             under it. "
        ));
        let key = u.key.as_deref();
        match u.service {
            Some(s) => {
                let word = s.word();
                let revoke = revoke_at(s, key.unwrap_or("<key>"));
                out.push_str(&format!(
                    "Its key is still enrolled at the {word} until you revoke it there. Re-make it under a new key \
                     first — `mint {word} {name}`, paste the command it prints at the {word}'s host (`{}`), and \
                     `enrol <the {word}'s line>`, which takes no name — and then revoke the old key at the {word}: \
                     `{revoke}`. The {word} never revokes its last operator, so the new key comes first. ",
                    enrol_at(s, "<the new key>")
                ));
            }
            None => {
                let [vault, relay] = revoke_at_each_service(key.unwrap_or("<key>"));
                out.push_str(&format!(
                    "Its key is still enrolled at the service it operated until you revoke it there — `{vault}` \
                     at a vault, or `{relay}` at a relay — once a new key, minted with `mint vault {name}` or \
                     `mint relay {name}`, is enrolled there: a service never revokes its last operator. "
                ));
            }
        }
        if key.is_none() {
            out.push_str("Its key could not be read back, so revoke it by the key you enrolled. ");
        }
    }
    out
}

/// The sentence a person is told when this desktop drops kept credentials
/// that no longer read — said, not logged: which one, by
/// its service and name; that its key is still enrolled at that service until
/// it is revoked there, with that service's revoke and the old key in it; and
/// how to re-make it first, since a service never revokes its last operator.
/// Said, never only logged: the key is standing the person still holds.
pub(crate) fn stopped_reading(unread: &[Unread]) -> String {
    format!("{}{SAID_AGAIN}", stopped_lines(unread))
}

/// The sentence a person is told when this desktop drops credentials of the
/// refused first form: what was dropped, how to re-make it as the
/// two credentials it now is, and that the old key stays enrolled at both
/// services until it is revoked there — with the two commands. Said, never
/// only logged: an enrolled key nobody is told about is standing left behind.
pub(crate) fn first_form_dropped(forms: &[FirstForm]) -> String {
    let mut out = String::new();
    for f in forms {
        let name = if f.name.is_empty() { "<name>" } else { f.name.as_str() };
        out.push_str(&format!(
            "This desktop kept an operator credential for the host '{name}' in the `{}` form, which named one \
             host's vault and relay together; it no longer reads that form, so it is dropped here, with \
             any key minted in that form and the relay keys kept beside it. Re-make it as two credentials, \
             each under its own key: `mint vault {name}` and `mint relay {name}`, each enrolled at its own \
             service. ",
            kotton_peer::operator::FIRST_FORM
        ));
        match &f.key {
            Some(key) => {
                let [vault, relay] = revoke_at_each_service(key);
                out.push_str(&format!(
                    "The old key is still enrolled at both services until you revoke it there: `{vault}` at \
                     the vault, and `{relay}` at the relay. "
                ));
            }
            None => out.push_str(
                "Its key could not be read back, so revoke it at each service by the key you enrolled: \
                 `kvaultd operator revoke <key>` at the vault, and `kotton-relay … operator revoke <key>` at \
                 the relay. ",
            ),
        }
    }
    out.push_str(SAID_AGAIN);
    out
}

/// Drop every kept credential this person's desktop can no longer read — one
/// that stopped reading ([`stopped_reading`]) and one of the refused first
/// form, with the keys minted in that form and the relay keys kept for the
/// relays it reached ([`first_form_dropped`]) — and answer with the one
/// sentence that says what each was and what to revoke where; `None` when
/// there was none. Run first by every verb that reads a credential, so the
/// person is told in that verb's answer.
///
/// **Everything is read and decided before anything is written.** A part of
/// the store that does not open fails the drop with nothing written, so a
/// credential is never dropped without the sentence that names it reaching
/// the person; the next verb finds it again. The kept credentials — the
/// standing the sentence is about — are written last, so a write that fails
/// before them leaves them to be said by the next verb.
pub(crate) fn drop_unread(store: &UserStore) -> anyhow::Result<Option<String>> {
    let kept: Vec<String> = match kotton_store::runtime::private::read(store, KEPT)? {
        Some(bytes) => serde_json::from_slice(&bytes)?,
        None => Vec::new(),
    };
    let waiting = minted(store)?;
    let (stopped, kept): (Vec<String>, Vec<String>) =
        kept.into_iter().partition(|t| kotton_peer::operator::unread(t).is_some());
    let (old_kept, rest_kept): (Vec<String>, Vec<String>) =
        kept.into_iter().partition(|t| kotton_peer::operator::first_form(t).is_some());
    let (old_minted, rest_minted): (Vec<String>, Vec<String>) =
        waiting.into_iter().partition(|t| kotton_peer::operator::first_form(t).is_some());
    if stopped.is_empty() && old_kept.is_empty() && old_minted.is_empty() {
        return Ok(None);
    }
    let unread: Vec<Unread> = stopped.iter().filter_map(|t| kotton_peer::operator::unread(t)).collect();
    let forms: Vec<FirstForm> = old_kept
        .iter()
        .chain(&old_minted)
        .filter_map(|t| kotton_peer::operator::first_form(t))
        .collect();
    // The relay keys kept beside a first-form credential were kept by its
    // relay's URL; nothing reads keys kept that way any more (`kept_keys`), so
    // writing back the ones that name a relay by its key drops them.
    let keys = if forms.is_empty() { None } else { Some(kept_keys(store)?) };
    let said = match (unread.is_empty(), forms.is_empty()) {
        (false, true) => stopped_reading(&unread),
        (true, false) => first_form_dropped(&forms),
        _ => format!("{}{}", stopped_lines(&unread), first_form_dropped(&forms)),
    };

    if let Some(keys) = keys {
        keep_keys(store, &keys)?;
    }
    if !old_minted.is_empty() {
        keep_minted(store, &rest_minted)?;
    }
    if !stopped.is_empty() || !old_kept.is_empty() {
        kotton_store::runtime::private::write(store, KEPT, &serde_json::to_vec(&rest_kept)?)?;
    }
    for u in &unread {
        tracing::info!(
            user_id = store.user_id(),
            service = u.service.map(|s| s.word()),
            name = u.name.as_deref(),
            "dropped a kept operator credential that no longer reads; the person is told what to revoke"
        );
    }
    Ok(Some(said))
}

/// [`drop_unread`], answered as a verb answers: the sentence as the refusal
/// when something was dropped, or the reason the store did not open.
pub(crate) fn unread_answer(store: &UserStore) -> Option<UserResponse> {
    match drop_unread(store) {
        Ok(None) => None,
        Ok(Some(said)) => Some(refused(said)),
        Err(e) => Some(refused(format!("the operator credentials kept here do not open: {e:#}"))),
    }
}

/// Mint an operator credential for the vault or the relay `name` in this
/// person's own store, and answer with its public half
/// alone. The secret is made here and kept here, sealed — a relay's with
/// `rule` (*only my devices* when `None`) beside it; the service enrols the
/// public half at its terminal, and [`enrol`] completes the credential with
/// what the service said. Each mint is a new key: a vault's and a relay's are
/// never the same. Refused for a name whose credential for that service this
/// person already keeps — a second key would be one the service never
/// enrolled; minting again for one still waiting replaces its key.
///
/// **With no name** the instance is labelled by its kind's word, and a mint
/// with no name is refused while one of that kind waits or is kept under that
/// word, in one line naming the spelling that works. The refusal is here and not in the shell: a re-mint under a
/// name still waiting replaces its key, so only the side that holds the keys
/// can tell a second nameless mint from a mint again.
pub(crate) fn mint(
    users: &UserRegistry,
    user_id: &str,
    service: OperatedService,
    name: Option<&str>,
    rule: Option<AdmissionRule>,
) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    let word = service.word();
    let named = name.is_some();
    let name = name.unwrap_or(word);
    // `relay rule <word>` reads the rule of the relay `<word>` or sets the
    // rule `<word>`; a relay named for a rule would be both.
    if service == OperatedService::Relay && is_a_rule(name) {
        return refused(relay_named_for_a_rule(name));
    }
    match held(&store) {
        Ok(kept) if kept.iter().any(|c| is(c, service, name)) => {
            return refused(name_kept(word, name))
        }
        Ok(_) => {}
        Err(e) => return refused(format!("the operator credentials kept here do not open: {e:#}")),
    }
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let text = match kotton_peer::operator::minted_text(service, name, &key, rule) {
        Ok(t) => t,
        Err(e) => return refused(format!("{e:#}")),
    };
    let mut all = match minted(&store) {
        Ok(all) => all,
        Err(e) => return refused(format!("the keys minted here do not open: {e:#}")),
    };
    if !named && all.iter().any(|t| minted_is(t, service, name)) {
        return refused(name_waiting(word, name));
    }
    all.retain(|t| !minted_is(t, service, name));
    all.push(text);
    if let Err(e) = keep_minted(&store, &all) {
        return refused(format!("could not keep the key: {e:#}"));
    }
    tracing::info!(user_id, service = word, name, "minted an operator credential; the service enrols its public half");
    UserResponse::OperatorMinted {
        name: name.to_string(),
        key: hex::encode(key.verifying_key().to_bytes()),
    }
}

/// The rules' words, as `relay rule` takes them.
const RULE_WORDS: &str = "only_my_devices, people_i_invite and anyone";

/// Whether `name` is a rule's word — as the credential and `relay rule` spell
/// it, or as the window prints it, with hyphens — which no relay is named.
fn is_a_rule(name: &str) -> bool {
    kotton_peer::operator::parse_rule(&name.replace('-', "_")).is_ok()
}

/// Each key minted here and not yet completed, by its name, its service and
/// its public half, in the order they were minted — what a bare `mint` lists. The
/// minted text holds the secret; only the `key=` line, the public half
/// [`kotton_peer::operator::minted_text`] writes beside it, is read out. A
/// text of the refused first form is not one waiting: [`drop_unread`] drops it.
pub(crate) fn mints(users: &UserRegistry, user_id: &str) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    match minted(&store) {
        Ok(all) => UserResponse::OperatorMints { mints: all.iter().filter_map(|t| waiting(t)).collect() },
        Err(e) => refused(format!("the keys minted here do not open: {e:#}")),
    }
}

/// The name of each instance of `service` this person operates, in the order
/// its credential was kept — what an operating verb typed with no name reads,
/// once, to be said to the one there is, and to be refused with the list where
/// there are several (`UserRequest::OperatorHeld`). Names only. A credential
/// that does not read is dropped and said first, as by every verb
/// ([`unread_answer`]).
pub(crate) fn held_of(users: &UserRegistry, user_id: &str, service: OperatedService) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    match held(&store) {
        Ok(kept) => UserResponse::OperatorHeld {
            names: kept.into_iter().filter(|c| c.service() == service).map(|c| c.name).collect(),
        },
        Err(e) => refused(format!("the operator credentials kept here do not open: {e:#}")),
    }
}

/// What an instance said when it was asked, as its operator, whether it stands
/// a key: before its credential is forgotten ([`ask_as_operator`]), and, for a
/// vault, before a line's credential is kept ([`held_by_the_vaults_answer`]).
#[derive(Debug, PartialEq, Eq)]
enum Asked {
    /// It answered as its operator under this key: it stands the key still.
    Stands,
    /// It answered under its own key, and did not say whether it stands this
    /// one: why.
    Unsure(String),
    /// It answered under its own key, and said in so many words that this key
    /// is not one of its operators — revoked there, or never enrolled there.
    Answered,
    /// Nothing answered as that instance within the bound: nothing at its
    /// address, or another key there. A host started over.
    Silent,
}

/// Ask the instance `credential` operates, as its operator, whether it still
/// stands the credential's key — what [`forget`] refuses on. A relay is held to
/// the key it recorded, when it recorded one, and then asked its rule under the
/// credential's key: the operator door answers only a key enrolled there. A
/// vault is dialled pinned to its own key, at its address or the relay this
/// desktop told it to stand at, and asked the operator's read. Each step is
/// bounded ([`WITHIN`]); a step that is not answered is not taken as an answer,
/// and what each answer is, is [`relay_said`]'s and [`vault_said`]'s to say.
async fn ask_as_operator(runtime: &DeviceRuntime, store: &UserStore, credential: &OperatorCredential) -> Asked {
    match &credential.operates {
        Operates::Relay { url, key, .. } => {
            // A relay that proves the key it recorded is that relay; another key
            // at its address, or none, is not it.
            let proved = match key {
                Some(k) => match kotton_peer::relay_key::prove_relay(url, Some(k)).await {
                    Ok(_) => true,
                    Err(_) => return Asked::Silent,
                },
                None => false,
            };
            let said = tokio::time::timeout(
                WITHIN,
                kotton_net::rendezvous::say_as_operator(url, &credential.key, &RelayOperatorRequest::ReadRule),
            )
            .await;
            relay_said(proved, said.ok())
        }
        Operates::Vault { vault, .. } => {
            let told = stands_of(store, vault);
            let reach = told.as_ref().and_then(|t| t.relays.first()).map(|r| r.hint.as_str());
            let Ok(node) = credential.vault_node(reach) else { return Asked::Silent };
            let dialer = credential.dialer(Arc::clone(runtime.reachability()), Arc::clone(runtime.event_bus()));
            // A failed dial does not say whether nothing answered or something
            // answered under another key; neither is the vault this key operates.
            let conn = match tokio::time::timeout(WITHIN, dialer.connect(node, "")).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(_)) | Err(_) => return Asked::Silent,
            };
            // The dial proved the vault's key. Whether it stands this one is its
            // answer to the operator's read.
            vault_said(tokio::time::timeout(WITHIN, conn.send(&UserRequest::Tenants)).await.ok())
        }
    }
}

/// What a relay's answer to its rule, asked under the credential's key, says
/// of that key — `said` is `None` when it gave none within the bound, and
/// `proved` is whether the relay at the address proved the key the credential
/// recorded. A rule, or a request it read and refused, is an answer only an
/// operator is given: the key stands.
///
/// **A refusal is never the relay's answer.** The relay's door refuses a key
/// it does not hold with a 403, but that answer is plain HTTP on a request of
/// its own: nothing binds it to the key the relay proved on another, and a
/// proxy in front of the relay — the guide puts one there — or anything on the
/// path of an `http://` address can answer 403 for its own reasons. So a 403
/// after the proof is read as the relay not having answered: the forget goes
/// ahead and says the revoke, for a key that may still be enrolled. Anything
/// else from a relay that proved its key — an unauthorised clock, a wire that
/// dropped, no answer — says nothing either way, and is unsure. From a relay
/// that proved no key, nothing answered as the instance.
fn relay_said(proved: bool, said: Option<Result<RelayOperatorResponse, kotton_net::rendezvous::RendezvousError>>) -> Asked {
    use kotton_net::rendezvous::RendezvousError;
    match said {
        Some(Ok(RelayOperatorResponse::Rule { .. } | RelayOperatorResponse::Refused { .. })) => Asked::Stands,
        Some(Err(RendezvousError::HttpError { status: 403, .. })) => Asked::Silent,
        Some(Err(e)) if proved => Asked::Unsure(format!("{e}")),
        None if proved => Asked::Unsure(format!("no answer as its operator within {}s", WITHIN.as_secs())),
        _ => Asked::Silent,
    }
}

/// What a vault's answer to the operator's read, on a connection pinned to its
/// key, says of the credential's key — `said` is `None` when it gave none
/// within the bound. The read answered is the key standing. The vault refusing
/// the key at the handshake (`RefusedAtHandshake`), under keys only it holds,
/// is the key not standing there: a vault admits no key it does not hold past
/// its handshake, so that refusal is its whole answer. A wire that dropped, a
/// connection cut by whatever stands between, an answer of any other kind or
/// none says nothing about the key.
fn vault_said(said: Option<anyhow::Result<UserResponse>>) -> Asked {
    match said {
        Some(Ok(UserResponse::VaultTenants { .. })) => Asked::Stands,
        Some(Err(e)) if kotton_peer::refused_at_handshake(&e).is_some() => Asked::Answered,
        Some(Err(e)) => Asked::Unsure(format!("{e:#}")),
        Some(Ok(UserResponse::Error { message })) => Asked::Unsure(message),
        Some(Ok(other)) => Asked::Unsure(format!("it answered {other:?}")),
        None => Asked::Unsure(format!("no answer as its operator within {}s", WITHIN.as_secs())),
    }
}

/// `relay forget [<r>]`, `vault forget [<v>]` (`UserRequest::OperatorForget`):
/// forget the credential this person keeps for the `service` called `name`,
/// once its instance no longer stands the key. The instance is asked first
/// ([`ask_as_operator`]); one that answers as this key's instance is not
/// forgotten, and the refusal says to destroy it or revoke the key there, with
/// the revoke. Otherwise everything kept for it is dropped ([`drop_credential`])
/// and the answer says whether the instance answered, with the key's public
/// half for the revoke at one that may still run. A name not held is refused.
pub(crate) async fn forget(runtime: &DeviceRuntime, users: &UserRegistry, user_id: &str, service: OperatedService, name: &str) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    let word = service.word();
    let credential = match held(&store) {
        Ok(kept) => match kept.into_iter().find(|c| is(c, service, name)) {
            Some(c) => c,
            None => {
                return refused(format!(
                    "this desktop holds no operator credential for the {word} '{name}', so there is nothing to forget"
                ))
            }
        },
        Err(e) => return refused(format!("the operator credentials kept here do not open: {e:#}")),
    };
    let key = hex::encode(credential.key.verifying_key().to_bytes());
    let revoke = revoke_at(service, &key);
    let answered = match ask_as_operator(runtime, &store, &credential).await {
        Asked::Stands => {
            return refused(forget_refused_running(word, name, &revoke))
        }
        Asked::Unsure(why) => {
            return refused(forget_refused_unsure(word, name, &why, &revoke))
        }
        Asked::Answered => true,
        Asked::Silent => false,
    };
    if let Err(e) = drop_credential(runtime, &store, &credential) {
        return refused(format!("the {word} '{name}' was not forgotten: {e:#}"));
    }
    tracing::info!(user_id, service = word, name, answered, "forgot an operator credential whose instance no longer stands its key");
    UserResponse::OperatorForgotten { name: name.to_string(), service, key, answered }
}

/// Drop everything this desktop keeps for `credential`, as if it had never
/// been enrolled: the credential; a key minted under its name and not yet
/// completed; a vault's record of where it was told to stand; and a relay's
/// two admission keys, which this device stops holding at once — what
/// [`present_kept_keys`] would hold after a restart, keeping a relay invite's
/// key the person stood here with. Nothing another record names is touched:
/// a vault told to stand at a relay forgotten keeps that record, which
/// `vault stand` then answers as a relay no longer held.
///
/// **Everything is read before anything is written**, and the credential is
/// written last, so a write that fails leaves the credential kept and the
/// forget can be said again.
fn drop_credential(runtime: &DeviceRuntime, store: &UserStore, credential: &OperatorCredential) -> anyhow::Result<()> {
    let service = credential.service();
    let name = credential.name.as_str();
    let relay = relay_key(credential);
    let vault = vault_key(credential);
    let kept: Vec<String> = match kotton_store::runtime::private::read(store, KEPT)? {
        Some(bytes) => serde_json::from_slice(&bytes)?,
        None => Vec::new(),
    };
    let waiting = minted(store)?;
    let keys = relay.map(|_| kept_keys(store)).transpose()?;
    let invited = relay.map(|_| kept_invited(store)).transpose()?;
    let told = vault.map(|_| stands(store)).transpose()?;

    if let (Some(id), Some(mut all)) = (relay, keys) {
        all.retain(|k| k.relay() != Some(id));
        keep_keys(store, &all)?;
    }
    if let (Some(v), Some(mut all)) = (vault, told) {
        all.retain(|s| s.vault != hex::encode(v));
        keep_stands(store, &all)?;
    }
    if waiting.iter().any(|t| minted_is(t, service, name)) {
        let rest: Vec<String> = waiting.into_iter().filter(|t| !minted_is(t, service, name)).collect();
        keep_minted(store, &rest)?;
    }
    let rest: Vec<&String> = kept
        .iter()
        .filter(|t| !OperatorCredential::parse(t).is_ok_and(|c| is(&c, service, name)))
        .collect();
    kotton_store::runtime::private::write(store, KEPT, &serde_json::to_vec(&rest)?)?;

    if let Some(id) = relay {
        let keyring = runtime.reachability().relay_keys();
        keyring.release(store.user_id(), &id);
        let theirs = invited
            .unwrap_or_default()
            .into_iter()
            .find(|k| relay_id(Some(&k.key)) == Some(id))
            .and_then(|k| AdmissionKey::parse(&k.invited));
        if let Some(i) = theirs {
            keyring.hold_invited(store.user_id(), &id, i);
        }
        // The reach note offered this relay's *invited* key; it no longer does.
        runtime.reach_changed().notify_one();
    }
    Ok(())
}

/// One minted text as [`mints`] lists it: `None` for one of the first form, or
/// one that names no name or no public half.
fn waiting(text: &str) -> Option<kotton_wire::ipc::MintWaiting> {
    if kotton_peer::operator::first_form(text).is_some() {
        return None;
    }
    let (service, name, _) = kotton_peer::operator::service_name_and_secret(text);
    let key = text.lines().map(str::trim).find_map(|l| l.strip_prefix("key="))?;
    Some(kotton_wire::ipc::MintWaiting { name: name?, service, key: key.to_string() })
}

/// Keep a whole `credential` for `user_id`, replacing one for the same service
/// and name — and, when it is a relay's carrying a rule nobody has set there,
/// set that rule at the relay now. A key minted here is not completed here: its
/// instance's line completes it ([`complete`]), and text that holds no secret
/// is refused with the verb that does. The enrol is answered `Ok` whether or
/// not the relay answered: a rule not yet taken stays on the credential and is
/// set the next time this desktop speaks to the relay.
pub(crate) async fn enrol(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    user_id: &str,
    credential: &str,
) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    let (_, _, whole) = kotton_peer::operator::service_name_and_secret(credential);
    if !whole {
        return refused(NOT_A_WHOLE_CREDENTIAL);
    }
    let mut parsed = match OperatorCredential::parse(credential) {
        Ok(c) => c,
        Err(e) => return refused(format!("{e:#}")),
    };
    // The relay's key, recorded beside its URL: a relay has a key of its own
    // and proves it. A credential that
    // already names one expects it: another key at the address is refused. One
    // that names none records what the relay proves now, or nothing if it keeps
    // no key or does not answer — the enrol is kept either way, as before.
    if let Operates::Relay { url, key, .. } = &mut parsed.operates {
        let proved = kotton_peer::relay_key::prove_relay(url, key.as_ref()).await;
        match kotton_peer::relay_key::key_to_keep(*key, proved) {
            Ok(k) => *key = k,
            Err(e) => return refused(format!("{e}")),
        }
    }
    keep(runtime, users, record_stores, &store, parsed, None).await
}

/// What a line completes, found before anything is dialled ([`completes`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Completes {
    /// The key minted under `name`, as its minted text.
    Key { name: String, text: String },
    /// Several keys of the line's kind wait, and nothing here tells which one
    /// its instance was created for: these are their names.
    Which(Vec<String>),
}

/// Which key this desktop minted a line completes, and under what name — read
/// before anything is dialled or written, from the credentials kept here
/// (`kept`) and the keys minted and waiting (`minted`, the texts [`MINTED`]
/// holds). `chosen` is set only when the person was asked which and answered
/// (`LineToEnrol::mint`); `enrol` takes no name, only the lines an instance
/// printed.
///
/// - **An instance this desktop already operates** — a kept credential pinning
///   the line's key — completes nothing: its line is said again at every
///   start, and pasting it again changes nothing.
/// - **The one key of the line's kind waiting** is the one it completes, and the
///   name is the mint's. Whether the instance was created for that key is the
///   instance's to say, and it says it at the dial ([`held_to_the_line`]): a
///   vault admits the key or refuses it, and so does a relay's operator door.
/// - **Several waiting, and none chosen**: [`Completes::Which`], naming each.
///   A line does not say which key its instance was created for, and trying
///   each at the instance would show it every key waiting here — a join of
///   keys to one operator — so the person is asked, and only then.
/// - **A key chosen** must be one still waiting for the line's kind. One whose
///   credential is already kept is a second instance under a key already
///   kept: one key at two instances joins them, for anyone who sees both, to
///   one operator. The refusal cannot undo that — the instance exists
///   — so it names the remedy: a key of its own for it, enrolled there, and the
///   reused one revoked there.
/// - **No key minted for its kind**: refused in words that name the mint, and,
///   when this desktop keeps a credential of that kind, the reuse it may be.
pub(crate) fn completes(
    kept: &[OperatorCredential],
    minted: &[String],
    chosen: Option<&str>,
    line: &kotton_wire::line::InstanceLine,
) -> Result<Completes, String> {
    let kind = line.kind;
    let word = kind.word();
    if let Some(c) = kept.iter().find(|c| c.service() == kind && instance_key(c) == Some(line.key)) {
        return Err(format!(
            "this desktop already operates the {word} at {} as '{}' — its line completes nothing more",
            line.hint, c.name
        ));
    }
    let waiting = |n: &str| minted.iter().find(|t| minted_is(t, kind, n)).cloned();
    let names: Vec<String> = minted
        .iter()
        .filter(|t| kotton_peer::operator::first_form(t).is_none())
        .filter_map(|t| match kotton_peer::operator::service_name_and_secret(t) {
            (s, Some(n), _) if s == kind => Some(n),
            _ => None,
        })
        .collect();
    if let Some(name) = chosen {
        if let Some(c) = kept.iter().find(|c| is(c, kind, name)) {
            return Err(reused(c, &line.hint));
        }
        return waiting(name).map(|text| Completes::Key { name: name.to_string(), text }).ok_or_else(|| {
            format!(
                "this desktop has no key waiting for a {word} called '{name}' — the keys waiting for a {word} are: {}",
                if names.is_empty() { "none".to_string() } else { names.join(", ") }
            )
        });
    }
    match names.as_slice() {
        [] => match kept.iter().filter(|c| c.service() == kind).collect::<Vec<_>>().as_slice() {
            [c] => Err(none_waiting_and_maybe_reused(c, &line.hint)),
            others => Err(format!(
                "this desktop minted no key waiting for a {word}, so this line completes nothing here. A {word} is \
                 created for a key you mint first: `mint {word}{}`, then paste the line its creation returns.",
                if others.is_empty() { "" } else { " <a new name>" }
            )),
        },
        [one] => Ok(Completes::Key { name: one.clone(), text: waiting(one).expect("listed as waiting") }),
        several => Ok(Completes::Which(several.to_vec())),
    }
}

/// The instance a kept credential pins: a vault's own key, or the key a relay
/// proved.
fn instance_key(c: &OperatorCredential) -> Option<[u8; 32]> {
    match &c.operates {
        Operates::Vault { vault, .. } => Some(*vault),
        Operates::Relay { key, .. } => *key,
    }
}

/// The refusal for a second instance under a key this desktop already keeps,
/// and its remedy at that instance, in the commands each
/// kind's guide types.
fn reused(kept: &OperatorCredential, hint: &str) -> String {
    let word = kept.service().word();
    let name = &kept.name;
    format!(
        "this desktop already keeps the key it minted for the {word} '{name}', and that key operates the {word} it \
         completed; the {word} at {hint} was created for the same key, so one key operates two instances, and anyone \
         who sees both can tell they are one operator's. It is not completed. {}",
        own_key(kept)
    )
}

/// The refusal of a line for which no key of its kind waits, while this
/// desktop operates one instance of that kind (`kept`): the likely cause is
/// that instance's command run again on a second host — one key at two
/// instances — which only the instance could confirm, and asking it
/// would show it the key. So it is said as what it may be, with its remedy.
fn none_waiting_and_maybe_reused(kept: &OperatorCredential, hint: &str) -> String {
    let word = kept.service().word();
    let name = &kept.name;
    format!(
        "this desktop minted no key waiting for a {word}, so this line completes nothing here. If the {word} at {hint} \
         was created with the command printed for the {word} '{name}' you operate, one key now operates two \
         instances, and anyone who sees both can tell they are one operator's — {} Otherwise a {word} is created for \
         a key you mint first: `mint {word} <a new name>`, then paste the line its creation returns.",
        own_key(kept)
    )
}

/// The remedy for an instance created for a key `kept` already completed, at
/// that instance, in the commands each kind's guide types.
fn own_key(kept: &OperatorCredential) -> String {
    let word = kept.service().word();
    let key = hex::encode(kept.key.verifying_key().to_bytes());
    let (enrol, revoke) = (enrol_at(kept.service(), "<the new key>"), revoke_at(kept.service(), &key));
    format!(
        "Give it a key of its own: `mint {word} <a new name>`, enrol the key it prints at that {word} (`{enrol}`), \
         revoke the reused key there (`{revoke}`), then `enrol <this line>`."
    )
}

/// `enrol <line> [<line>…]` (`UserRequest::OperatorEnrolLines`): complete each line on its own ([`enrol_one`]) and answer what each came
/// to, in the order given. **Relays first**, whatever order the lines came in:
/// a vault completed after the relay it will stand at is told to stand there
/// at once, so its readout says where it stands; a relay completed after a
/// vault tells every vault told nothing yet ([`after_kept`]), so the end is the
/// same either way, and only the readout would differ.
pub(crate) async fn enrol_lines(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    user_id: &str,
    lines: &[kotton_wire::ipc::LineToEnrol],
) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    let vault_last = |given: &kotton_wire::ipc::LineToEnrol| {
        kotton_wire::line::InstanceLine::parse(&given.line).is_ok_and(|l| l.kind == OperatedService::Vault)
    };
    let mut order: Vec<usize> = (0..lines.len()).collect();
    order.sort_by_key(|&i| vault_last(&lines[i]));
    let mut came: Vec<Option<kotton_wire::ipc::LineEnrolled>> = vec![None; lines.len()];
    for i in order {
        came[i] = Some(enrol_one(runtime, users, record_stores, &store, &lines[i].line, lines[i].mint.as_deref()).await);
    }
    UserResponse::OperatorEnrolledLines { lines: came.into_iter().flatten().collect() }
}

/// The door's *Enrol* (`landlord.enrol`): one line, told no name, completed
/// as `enrol` completes it ([`enrol_one`]) and answered as the door has always
/// read it — `OperatorEnrolled`, or a refusal. Several keys waiting for the
/// line's kind is a refusal here, naming the terminal's `enrol`, which asks
/// which: the door's sheet does not ask yet.
pub(crate) async fn complete(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    user_id: &str,
    line: &str,
) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    let one = enrol_one(runtime, users, record_stores, &store, line, None).await;
    match (one.came_to, one.kind) {
        (kotton_wire::ipc::LineCame::Kept { name, unstood, .. }, Some(service)) => {
            UserResponse::OperatorEnrolled { name, service, unstood }
        }
        (kotton_wire::ipc::LineCame::Which { names }, kind) => refused(which_at_the_door(kind, &names)),
        (kotton_wire::ipc::LineCame::Refused { why }, _) => refused(why),
        (kotton_wire::ipc::LineCame::Kept { .. }, None) => refused("a line of no kind was kept — this is a defect"),
    }
}

/// What the door says of a line whose kind has several keys waiting: it does
/// not ask, so it sends the person to the terminal's `enrol`, which does.
pub(crate) fn which_at_the_door(kind: Option<OperatedService>, names: &[String]) -> String {
    let word = kind.map_or("instance", OperatedService::word);
    format!(
        "This desktop has {} keys minted for a {word} and waiting — {} — and a line does not say which one its {word} \
         was created for. Paste it at the terminal's `enrol <line>`, which asks which.",
        names.len(),
        names.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(", ")
    )
}

/// Complete the key this desktop minted from the line its instance printed,
/// and say what it came to with the three readouts: what
/// the line names, whether the instance was reached, whether its key matched.
/// Find the key ([`completes`]) — asking which when several wait, and dialling
/// nothing then — make it a credential pinning the line's key, **hold the
/// instance to that key and to the minted one before anything is kept**
/// ([`held_to_the_line`]), and only then keep it and say what follows: a vault
/// is told where to stand ([`after_kept`]), which hands it the reach set with
/// the relay's *mine* key in it, so a stand-in at the address is never handed
/// it. Another key at the address, a key not admitted, or no answer keeps
/// nothing, and the minted key still waits. `chosen` is the person's answer
/// to which, and nothing else.
async fn enrol_one(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    store: &UserStore,
    given: &str,
    chosen: Option<&str>,
) -> kotton_wire::ipc::LineEnrolled {
    use kotton_wire::ipc::{LineCame, LineEnrolled};
    let line = match kotton_wire::line::InstanceLine::parse(given) {
        Ok(l) => l,
        Err(why) => {
            return LineEnrolled {
                line: given.trim().to_string(),
                kind: None,
                hint: String::new(),
                dialled: false,
                reached: None,
                matched: None,
                came_to: LineCame::Refused { why },
            }
        }
    };
    let readout = |dialled, reached, matched, came_to| LineEnrolled {
        line: line.to_text(),
        kind: Some(line.kind),
        hint: line.hint.clone(),
        dialled,
        reached,
        matched,
        came_to,
    };
    let refused_with = |why: String| readout(false, None, None, LineCame::Refused { why });
    let kept = match held(store) {
        Ok(k) => k,
        Err(e) => return refused_with(format!("the operator credentials kept here do not open: {e:#}")),
    };
    let minted = match minted(store) {
        Ok(m) => m,
        Err(e) => return refused_with(format!("the keys minted here do not open: {e:#}")),
    };
    let (name, key) = match completes(&kept, &minted, chosen, &line) {
        Ok(Completes::Key { name, text }) => (name, text),
        Ok(Completes::Which(names)) => return readout(false, None, None, LineCame::Which { names }),
        Err(why) => return refused_with(why),
    };
    let credential = match kotton_peer::operator::complete_from_line(&key, &line)
        .and_then(|text| OperatorCredential::parse(&text))
    {
        Ok(c) => c,
        Err(e) => return refused_with(format!("{e:#}")),
    };
    if let Err(not) = held_to_the_line(runtime, &credential, &line, chosen.is_some()).await {
        return readout(true, not.reached, not.matched_not.then_some(false), LineCame::Refused { why: not.why });
    }
    let service = credential.service();
    match keep(runtime, users, record_stores, store, credential, Some(&name)).await {
        UserResponse::OperatorEnrolled { name, unstood, .. } => {
            let only = held(store).map(|k| k.iter().filter(|c| c.service() == service).count() == 1).unwrap_or(false);
            readout(true, Some(true), Some(true), LineCame::Kept { name, only, unstood })
        }
        UserResponse::Error { message } => readout(true, Some(true), Some(true), LineCame::Refused { why: message }),
        other => readout(true, Some(true), Some(true), LineCame::Refused { why: format!("kept, and answered {other:?}") }),
    }
}

/// Why an instance was not held to its line, with what is known of the two
/// readouts: whether anything answered at the address (`None`: cannot be
/// told), and whether it answered under another key or refused the minted one.
#[derive(Debug)]
struct NotHeld {
    reached: Option<bool>,
    matched_not: bool,
    why: String,
}

/// Hold the instance at the line's address to the line's key and to the key [`completes`] found, before anything is kept. Each kind
/// proves its own key and then answers as its operator under the minted one:
/// a relay proves its key at `GET /identity` and answers its operator door
/// (`POST /operator`, a read of its rule); a vault answers the operator dial,
/// whose handshake is pinned to its key, and then the operator's read. Either
/// answer is the instance saying it was created for that key, or has it
/// enrolled at its terminal. It is shown no other key. So a line completed
/// under the wrong key — a wrong answer to *which* — keeps nothing and spends
/// no mint, and a relay's key enrolled at its terminal comes before the
/// desktop's `enrol`, as the guides order it. `Err` is why not; nothing has
/// been sent but the dial and that read.
async fn held_to_the_line(
    runtime: &DeviceRuntime,
    credential: &OperatorCredential,
    line: &kotton_wire::line::InstanceLine,
    chosen: bool,
) -> Result<(), NotHeld> {
    let kept_nothing = "nothing is kept, and nothing was told to it";
    let word = line.kind.word();
    let name = &credential.name;
    match &credential.operates {
        Operates::Relay { url, .. } => {
            use kotton_peer::relay_key::RelayKeyError;
            match kotton_peer::relay_key::prove_relay(url, Some(&line.key)).await {
                Ok(_) => {}
                Err(e @ RelayKeyError::Stranger { shown: None, .. }) => {
                    return Err(NotHeld { reached: Some(false), matched_not: false, why: format!("{e} — {kept_nothing}") })
                }
                Err(e) => return Err(NotHeld { reached: Some(true), matched_not: true, why: format!("{e} — {kept_nothing}") }),
            }
            // The relay proved its key. Whether it stands the minted one is its
            // operator door's answer, asked under that key: the same read
            // `relay rule` makes, and nothing set.
            let said = tokio::time::timeout(
                WITHIN,
                kotton_net::rendezvous::say_as_operator(url, &credential.key, &RelayOperatorRequest::ReadRule),
            )
            .await;
            held_at_the_relays_door(credential, line, chosen, said.ok())
        }
        Operates::Vault { .. } => {
            let dialer = credential.dialer(Arc::clone(runtime.reachability()), Arc::clone(runtime.event_bus()));
            let node = credential
                .vault_node(None)
                .map_err(|e| NotHeld { reached: None, matched_not: false, why: format!("{e:#}") })?;
            let conn = match tokio::time::timeout(WITHIN, dialer.connect(node, "")).await {
                Ok(Ok(conn)) => conn,
                // A failed dial does not say whether nothing answered or
                // something answered under another key.
                Ok(Err(e)) => return Err(NotHeld {
                    reached: None,
                    matched_not: false,
                    why: format!(
                        "the vault at {} did not answer under the key its line names, admitting the key minted for the \
                         {word} '{name}': {e:#} — {kept_nothing}",
                        line.hint
                    ),
                }),
                Err(_) => {
                    return Err(NotHeld {
                        reached: Some(false),
                        matched_not: false,
                        why: format!("the vault at {} did not answer within {}s — {kept_nothing}", line.hint, WITHIN.as_secs()),
                    })
                }
            };
            // The dial proved the vault's key; whether it admits the minted
            // one is not settled by the dial returning — the client's half of
            // the handshake ends before the vault has read this key, and a
            // vault that refuses it closes the connection after. So it is
            // asked the operator's own read, `vault people`, and what its
            // answer says of the key is [`held_by_the_vaults_answer`]'s to
            // say. Nothing is said to a vault that does not stand it.
            let said = tokio::time::timeout(WITHIN, conn.send(&UserRequest::Tenants)).await;
            held_by_the_vaults_answer(credential, line, said.ok())
        }
    }
}

/// What a relay that proved its line's key said at its operator door, asked
/// under the key minted for `credential` ([`held_to_the_line`]) — `chosen` is
/// whether the person named that key among several waiting, and `said` is
/// `None` when it gave no answer within the bound. A rule, or a request it
/// read and could not do, is an answer only an operator is given: the relay
/// stands the key, and it is held.
///
/// A `403` there is unsigned, and something in front of the relay could give
/// it too (decision 0006), so it is not the relay saying the key does not
/// stand: `matched` is not told, and nothing is kept, which is the side that
/// costs a second `enrol` and never a wrong credential. It is said as what was
/// presented and where, never as the relay's rule, with what most often
/// admits it — this key enrolled at its host first, and, when the key was
/// chosen, the line enrolled again under the one that relay was created for.
/// Anything else — a clock it would not take, a wire that dropped, no answer —
/// does not say whether it stands the key either, and keeps nothing.
fn held_at_the_relays_door(
    credential: &OperatorCredential,
    line: &kotton_wire::line::InstanceLine,
    chosen: bool,
    said: Option<Result<RelayOperatorResponse, kotton_net::rendezvous::RendezvousError>>,
) -> Result<(), NotHeld> {
    use kotton_net::rendezvous::RendezvousError;
    let (hint, name) = (&line.hint, &credential.name);
    let kept_nothing = KEPT_NOTHING;
    match said {
        Some(Ok(RelayOperatorResponse::Rule { .. } | RelayOperatorResponse::Refused { .. })) => Ok(()),
        Some(Err(RendezvousError::HttpError { status: 403, .. })) => {
            Err(NotHeld {
                reached: Some(true),
                matched_not: false,
                why: relay_refused_unsigned(hint, name, &hex::encode(credential.key.verifying_key().to_bytes()), chosen),
            })
        }
        Some(Err(e)) => Err(NotHeld {
            reached: Some(true),
            matched_not: false,
            why: format!(
                "the relay at {hint} proved the key its line names and did not answer as its operator under the key \
                 minted for the relay '{name}' ({e}) — {kept_nothing}"
            ),
        }),
        None => Err(NotHeld {
            reached: Some(true),
            matched_not: false,
            why: format!(
                "the relay at {hint} proved the key its line names and did not answer as its operator within {}s — \
                 {kept_nothing}",
                WITHIN.as_secs()
            ),
        }),
    }
}

/// What a vault that proved its line's key said to the operator's read, asked
/// under the key minted for `credential` ([`held_to_the_line`]) — `said` is
/// `None` when it gave no answer within the bound. What the answer says of the
/// key is [`vault_said`]'s, the reading `forget` makes of the same read, so
/// `matched` means for a vault what it means for a relay: the instance's own
/// words, and nothing else's.
///
/// The read answered is the vault standing the key as its operator: it is
/// held. The vault refusing the key at its handshake (`RefusedAtHandshake`),
/// under keys only it holds, is the vault saying it was not created for that
/// key: `matched` is `false`, and nothing is kept. A wire that dropped, a
/// connection cut by whatever stands between, an answer of any other kind, or
/// none does not say whether it stands the key: `matched` is not told, and
/// nothing is kept, which is the side that costs a second `enrol` and never a
/// wrong credential.
fn held_by_the_vaults_answer(
    credential: &OperatorCredential,
    line: &kotton_wire::line::InstanceLine,
    said: Option<anyhow::Result<UserResponse>>,
) -> Result<(), NotHeld> {
    let (hint, word, name) = (&line.hint, line.kind.word(), &credential.name);
    let kept_nothing = "nothing is kept, and nothing was told to it";
    let presented = match &said {
        Some(Err(e)) => format!("{e:#}"),
        _ => String::new(),
    };
    let not_told = |why: String| NotHeld {
        reached: Some(true),
        matched_not: false,
        why: format!(
            "the vault at {hint} proved the key its line names and did not answer as its operator under the key \
             minted for the {word} '{name}' ({why}) — {kept_nothing}, and the key still waits"
        ),
    };
    if said.is_none() {
        return Err(NotHeld {
            reached: Some(true),
            matched_not: false,
            why: format!(
                "the vault at {hint} proved its key and did not answer as its operator within {}s — {kept_nothing}",
                WITHIN.as_secs()
            ),
        });
    }
    match vault_said(said) {
        Asked::Stands => Ok(()),
        Asked::Answered => Err(NotHeld {
            reached: Some(true),
            matched_not: true,
            why: format!(
                "the vault at {hint} proved the key its line names and refused the key minted for the {word} '{name}': \
                 {presented} — it was not created for that key; {kept_nothing}, and the key still waits"
            ),
        }),
        Asked::Unsure(why) => Err(not_told(why)),
        Asked::Silent => Err(not_told("nothing answered".into())),
    }
}

/// Keep `parsed`, replacing a credential for the same service and name; drop
/// the minted key `completing` names, when it completed one; and do what
/// follows a credential kept ([`after_kept`]).
async fn keep(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    store: &UserStore,
    mut parsed: OperatorCredential,
    completing: Option<&str>,
) -> UserResponse {
    let mut kept = match held(store) {
        Ok(k) => k,
        Err(e) => return refused(format!("the operator credentials already kept do not open: {e:#}")),
    };
    let service = parsed.service();
    let name = parsed.name.clone();
    kept.retain(|c| !is(c, service, &name));
    tracing::info!(user_id = store.user_id(), service = service.word(), name, "kept an operator credential");
    // The mint's answer is the *first* rule, and only that: a relay this
    // person has set a rule on before keeps the rule they set there, and
    // enrolling it again does not undo it.
    if let Operates::Relay { key: Some(relay), rule, .. } = &mut parsed.operates {
        let set_before = kept_keys(store).map(|k| k.iter().any(|k| k.relay() == Some(*relay))).unwrap_or(false);
        if set_before {
            *rule = None;
        }
    }
    let pending = matches!(parsed.operates, Operates::Relay { rule: Some(_), .. });
    kept.push(parsed.clone());
    if let Err(e) = keep_credentials(store, &kept) {
        return refused(format!("could not keep the operator credential: {e:#}"));
    }
    if let Some(name) = completing {
        if let Err(e) = spend_minted(store, service, name) {
            tracing::warn!(error = %e, name, "the credential is kept, and its minted key is still listed as waiting");
        }
    }
    let told = after_kept(runtime, users, record_stores, store, &parsed, pending).await;
    kept_answer(name, service, told)
}

/// Drop the key minted for `service` and `name` from those waiting, once the
/// credential it completed is kept: it is no longer one a bare `mint` lists.
fn spend_minted(store: &UserStore, service: OperatedService, name: &str) -> anyhow::Result<()> {
    let mut all = minted(store)?;
    all.retain(|t| !minted_is(t, service, name));
    keep_minted(store, &all)
}

/// The answer once a credential is kept: kept, and, when [`after_kept`] could
/// not tell the vault where to stand, why not. Never a refusal: the service
/// enrolled this desktop's key and the credential is sealed here, so an error
/// would send the person to enrol a key already taken. The remedy is `vault stand <v>`
/// (`OperatorVerb::Stand`), which the shell names beside the reason.
fn kept_answer(name: String, service: OperatedService, told: Result<(), Unstood>) -> UserResponse {
    let unstood = told.err();
    if let Some(why) = &unstood {
        tracing::warn!(name, cause = ?why.why, %why, "the credential is kept, and the vault was not told where to stand");
    }
    UserResponse::OperatorEnrolled { name, service, unstood }
}

/// Every relay this desktop operates, by the key its credential recorded, in
/// the order the credentials were kept. A relay whose credential recorded no
/// key — one that showed none when it was enrolled — cannot be named, and is
/// not in it.
fn operated_relays(store: &UserStore) -> Vec<RelayId> {
    held(store).unwrap_or_default().iter().filter_map(relay_key).collect()
}

/// Tell every vault this desktop operates and has told nothing yet to stand at
/// the relay it operates, when it operates exactly one. With more than one,
/// where each stands is the person's to say ([`stand_as_told`] asks), so a
/// second relay operated tells nobody. A vault that does not answer is said in
/// the log and told by `vault stand <v>` ([`stand`]).
async fn tell_the_untold(runtime: &DeviceRuntime, store: &UserStore) {
    let relays = operated_relays(store);
    if relays.len() != 1 {
        return;
    }
    for vault in held(store).unwrap_or_default() {
        let Some(v) = vault_key(&vault) else { continue };
        if stands_of(store, &v).is_some() {
            continue;
        }
        if let Err(e) = tell(runtime, store, &vault, &relays).await {
            tracing::warn!(vault = %vault.name, error = %e, "a vault this desktop operates was not told where to stand");
        }
    }
}

/// A telling that did not happen for a cause `vault stand` answers.
fn not_told(reason: String) -> Unstood {
    Unstood { why: UnstoodWhy::NotTold, reason, relays: Vec::new() }
}

/// Tell the vault `vault` its whole reach set — `relays`, each by its key, as
/// this desktop operates it: the URL its credential holds as the hint, and the
/// admission keys kept for it — and record what was told, dated. A relay in
/// `relays` this desktop no longer operates is left out, and a set left with
/// none is not sent. Answers why not when nothing was sent or the vault did not
/// take it.
async fn tell(runtime: &DeviceRuntime, store: &UserStore, vault: &OperatorCredential, relays: &[RelayId]) -> Result<(), Unstood> {
    let v = vault_key(vault).ok_or_else(|| not_told(format!("'{}' is a relay's credential", vault.name)))?;
    let kept = held(store).map_err(|e| not_told(format!("the operator credentials kept here do not open: {e:#}")))?;
    let keys = kept_keys(store).map_err(|e| not_told(format!("the relay keys kept here do not open: {e:#}")))?;
    let mut set = Vec::new();
    let mut told = Vec::new();
    for relay in relays {
        let Some(Operates::Relay { url, .. }) =
            kept.iter().find(|c| relay_key(c) == Some(*relay)).map(|c| &c.operates)
        else {
            continue;
        };
        let held = keys.iter().find(|k| k.relay() == Some(*relay));
        set.push(kotton_wire::rendezvous::Stand {
            key: hex::encode(relay),
            hint: url.clone(),
            mine: held.map(|k| SecretText::new(k.mine.clone())),
            invited: held.map(|k| SecretText::new(k.invited.clone())),
        });
        told.push(Stood { key: hex::encode(relay), hint: url.clone() });
    }
    // A set with no relay in it is not a telling — a vault told it would stand
    // nowhere — so it is said, never answered `Ok`: the one check for both
    // causes, which differ in what the person can do, so the cause is data
    // (`UnstoodWhy`) the shell names the act by. Either this desktop operates
    // no relay, or every relay the vault was told of is one it no longer
    // operates (its credential gone, or its name re-enrolled under another
    // key). Within the second, each relay has its own state: a relay this
    // desktop holds may sit at an address the vault was told, under another
    // key. A relay is its key, so that is a relay rebuilt or replaced, and
    // standing the vault there would be a move — "hold that relay again" would
    // record the key it already holds and be refused here again. The cause is
    // the act the person can take today: `RelaysNotHeld` while any relay can be
    // held again, `Moved` only when every one moved. A move is `vault move` or
    // the door's *Move…*, not a verb yet, and this does not perform one:
    // moving a vault is an act the person takes, never a side effect of a
    // telling.
    if set.is_empty() {
        let name = &vault.name;
        return Err(if relays.is_empty() {
            Unstood {
                why: UnstoodWhy::NoRelay,
                reason: format!("this desktop operates no relay to tell the vault '{name}' of"),
                relays: Vec::new(),
            }
        } else {
            // Each relay the vault was told of, by what stands between it and
            // this desktop. Its address is compared as every relay address is
            // (`same_relay_address`), and only to ask *where*: the key says
            // whether the relay there is the one told.
            let recorded: Vec<Stood> = stands_of(store, &v).map(|t| t.relays).unwrap_or_default();
            let relays: Vec<UnstoodRelay> = recorded
                .into_iter()
                .map(|r| {
                    let there = kept.iter().find(|c| {
                        matches!(&c.operates, Operates::Relay { url, key: Some(k), .. }
                            if kotton_schemas::membership::same_relay_address(url, &r.hint) && hex::encode(k) != r.key)
                    });
                    match there {
                        Some(c) => UnstoodRelay { hint: r.hint, state: UnstoodRelayState::Moved, name: Some(c.name.clone()) },
                        None => UnstoodRelay { hint: r.hint, state: UnstoodRelayState::NotHeld, name: None },
                    }
                })
                .collect();
            let hints = |state: UnstoodRelayState| -> Vec<&str> {
                relays.iter().filter(|r| r.state == state).map(|r| r.hint.as_str()).collect()
            };
            let (again, moved) = (hints(UnstoodRelayState::NotHeld), hints(UnstoodRelayState::Moved));
            // Holding a relay again leads: it stands the vault where it was
            // told, and a move changes where that is, which is a larger act.
            let (why, reason) = if again.is_empty() {
                (
                    UnstoodWhy::Moved,
                    format!(
                        "the relay at {} answers under another key than the one the vault '{name}' was told to stand at",
                        moved.join(", ")
                    ),
                )
            } else {
                let mut reason = format!(
                    "none of the relays the vault '{name}' was told to stand at ({}) is one this desktop operates now",
                    relays.iter().map(|r| r.hint.as_str()).collect::<Vec<_>>().join(", ")
                );
                if !moved.is_empty() {
                    reason.push_str(&format!("; the relay at {} answers under another key", moved.join(", ")));
                }
                (UnstoodWhy::RelaysNotHeld, reason)
            };
            Unstood { why, reason, relays }
        });
    }
    let before = stands_of(store, &v);
    let reach = before.as_ref().and_then(|b| b.relays.first()).map(|r| r.hint.as_str());
    let request = vec![UserRequest::StandAt { relays: set }];
    match tokio::time::timeout(WITHIN, say(runtime, vault, reach, request)).await {
        Ok(Ok(UserResponse::Ok)) => {}
        Ok(Ok(UserResponse::Error { message })) => return Err(not_told(format!("the vault '{}' refused: {message}", vault.name))),
        Ok(Ok(_)) => return Err(not_told(format!("the vault '{}' answered something other than taking its reach set", vault.name))),
        Ok(Err(e)) => return Err(not_told(format!("the vault '{}' could not be reached: {e:#}", vault.name))),
        Err(_) => return Err(not_told(format!("the vault '{}' did not answer within {}s", vault.name, WITHIN.as_secs()))),
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut all = stands(store).map_err(|e| not_told(format!("the record of where vaults stand does not open: {e:#}")))?;
    all.retain(|s| s.vault != hex::encode(v));
    all.push(StandsAt { vault: hex::encode(v), relays: told, told_at: now });
    keep_stands(store, &all).map_err(|e| not_told(format!("the vault was told, and the record of it was not kept: {e:#}")))?;
    tracing::info!(vault = %vault.name, relays = relays.len(), "told a vault where to stand");
    Ok(())
}

/// What follows keeping a credential, by `enrol`: a vault is told where to stand, and a relay
/// newly operated is where every untold vault stands — then, if its
/// credential carries one, its first rule. `Err` is why a vault was not told
/// where to stand; the caller says what to do about it. It is handed the
/// credential its caller kept, and looks nothing up by name, so there is no
/// case in which the credential is not there; a store that does not open is
/// [`tell`]'s `Err`, never `Ok`.
pub(crate) async fn after_kept(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    store: &UserStore,
    credential: &OperatorCredential,
    pending: bool,
) -> Result<(), Unstood> {
    match credential.service() {
        OperatedService::Vault => stand_as_told(runtime, store, credential).await?,
        // A relay newly operated is where every vault this desktop has told
        // nothing yet stands; then its first rule, which tells them again with
        // the keys it mints.
        OperatedService::Relay => {
            tell_the_untold(runtime, store).await;
            if pending {
                let _ = set_pending_rule(runtime, users, record_stores, store, &credential.name).await;
            }
        }
    }
    Ok(())
}

/// Tell the vault `credential` operates where to stand: what this desktop told
/// it before, or, told nothing yet, every relay this desktop operates.
/// An empty set is [`tell`]'s to refuse: it is where the set is made.
///
/// **Told nothing yet, it tells only where there is one answer**: with
/// exactly one relay operated the vault is told to stand there (the person
/// moves it with *Move…*, or `vault move`); with none, [`tell`] says so; with
/// more than one it is told nothing, and the answer is [`UnstoodWhy::Several`]
/// naming each, for the person to choose with [`move_to`].
async fn stand_as_told(runtime: &DeviceRuntime, store: &UserStore, credential: &OperatorCredential) -> Result<(), Unstood> {
    let relays = relays_to_tell(store, credential)?;
    tell(runtime, store, credential, &relays).await
}

/// Which relays the vault `credential` operates is told to stand at, before
/// anything is dialled: the set this desktop told it last, when it told it
/// one; else the Default — the relay this desktop runs, when it runs exactly
/// one — and with more than one, the question ([`several`]).
fn relays_to_tell(store: &UserStore, credential: &OperatorCredential) -> Result<Vec<RelayId>, Unstood> {
    match vault_key(credential).and_then(|v| stands_of(store, &v)) {
        Some(told) => Ok(told.relays.iter().filter_map(|r| relay_id(Some(&r.key))).collect()),
        None => {
            let operated = operated_relays(store);
            if operated.len() > 1 {
                return Err(several(store, &credential.name));
            }
            Ok(operated)
        }
    }
}

/// Why a vault told nothing yet is not told: this desktop operates several
/// relays, each listed by its address and the name `vault move` takes.
fn several(store: &UserStore, vault: &str) -> Unstood {
    let relays: Vec<UnstoodRelay> = held(store)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| match c.operates {
            Operates::Relay { url, key: Some(_), .. } => {
                Some(UnstoodRelay { hint: url, state: UnstoodRelayState::Operated, name: Some(c.name) })
            }
            _ => None,
        })
        .collect();
    Unstood {
        why: UnstoodWhy::Several,
        reason: format!(
            "this desktop runs {} relays, and where the vault '{vault}' stands is yours to choose",
            relays.len()
        ),
        relays,
    }
}

/// `vault move <v> <relay>` and the door's *Move…*: tell the vault
/// `credential` operates to stand at the relay this desktop operates as
/// `relay`, and nowhere else — `StandAt` again, with that relay's set, recorded
/// and dated as every telling is. The relay is found by its credential's name
/// and told by its key; one whose credential recorded no key cannot be named
/// to a vault, and is refused.
async fn move_to(runtime: &DeviceRuntime, store: &UserStore, credential: &OperatorCredential, relay: &str) -> UserResponse {
    let name = &credential.name;
    let kept = match held(store) {
        Ok(k) => k,
        Err(e) => return refused(format!("the operator credentials kept here do not open: {e:#}")),
    };
    let Some(to) = kept.iter().find(|c| is(c, OperatedService::Relay, relay)) else {
        return refused(format!(
            "this desktop runs no relay called '{relay}' — the vault '{name}' stands where it did"
        ));
    };
    let Some(key) = relay_key(to) else {
        return refused(format!(
            "the relay '{relay}' showed no key when it was enrolled, so no vault can be told to stand at it — \
             the vault '{name}' stands where it did"
        ));
    };
    match tell(runtime, store, credential, &[key]).await {
        Ok(()) => UserResponse::Ok,
        Err(e) => refused(format!("the vault '{name}' was not moved: {e} — {}", e.remedy(name))),
    }
}

/// `vault stand <v>`: tell the vault `credential` operates where to stand
/// again, as a kept credential does ([`after_kept`]) — the remedy an enrol
/// names when it could not. It is handed the credential [`speak`] found,
/// and looks nothing up again, so `Ok` is only ever the vault having taken a
/// set with a relay in it: with none to tell it of, [`tell`] says so, and this
/// refuses.
async fn stand(runtime: &DeviceRuntime, store: &UserStore, credential: &OperatorCredential) -> UserResponse {
    let name = &credential.name;
    match stand_as_told(runtime, store, credential).await {
        Ok(()) => UserResponse::Ok,
        Err(e) => refused(format!("the vault '{name}' is still not standing at a relay: {e} — {}", e.remedy(name))),
    }
}

pub(crate) fn keep_credentials(store: &UserStore, kept: &[OperatorCredential]) -> anyhow::Result<()> {
    let texts: Vec<String> = kept.iter().map(OperatorCredential::to_text).collect();
    kotton_store::runtime::private::write(store, KEPT, &serde_json::to_vec(&texts)?)
}

/// Set the rule asked for at the mint, if the credential for the relay `name`
/// still carries one, and keep the credential without it once the relay has
/// taken it. A relay that does not answer leaves it carried, for the next time
/// this desktop speaks to it. Answers what the set answered, or `None` when
/// there was nothing to set.
pub(crate) async fn set_pending_rule(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    store: &UserStore,
    name: &str,
) -> Option<UserResponse> {
    let kept = held(store).ok()?;
    let credential = kept.iter().find(|c| is(c, OperatedService::Relay, name))?.clone();
    let Operates::Relay { rule: Some(rule), .. } = credential.operates else {
        return None;
    };
    let answer = set_rule(runtime, users, record_stores, store, &credential, rule, false).await;
    if matches!(answer, UserResponse::RelayRule { .. }) {
        if let Err(e) = set_pending_cleared(store, name) {
            tracing::warn!(error = %e, name, "the rule was set, and the credential still carries it");
        }
        tracing::info!(name, rule = ?rule, "set the relay's rule asked for at the mint");
    } else {
        tracing::warn!(name, answer = ?answer, "the relay's rule asked for at the mint is not set yet");
    }
    Some(answer)
}

/// The vault's requests an [`OperatorVerb`] is, in the order they are sent;
/// the first is the verb's own, and its answer is the verb's ([`in_order`]).
///
/// **An invite with a quota is the invite first, then the number.** The other
/// way round, an invite the vault refuses — a name it already keeps — would
/// already have reset that tenant's number to the sheet's. Asked this way, a refused invite
/// changes nothing. The pool is still never admitted under anything but the
/// landlord's number: the number is set on the same connection before the
/// invite's text is handed back, and nobody can take an invite they have not
/// been given.
pub(crate) fn requests_for(verb: OperatorVerb) -> Vec<UserRequest> {
    match verb {
        OperatorVerb::Invite {
            pool,
            quota,
            ttl_seconds,
        } => {
            let mut out = Vec::with_capacity(2);
            out.push(UserRequest::DeviceInvite {
                user_id: pool.clone(),
                ttl_seconds,
                as_name: None,
            });
            if let Some(quota) = quota {
                out.push(UserRequest::SetQuota { user_id: pool, quota });
            }
            out
        }
        OperatorVerb::Digits { pool } => vec![UserRequest::InviteDigits { user_id: pool }],
        OperatorVerb::Pools => vec![UserRequest::Tenants],
        OperatorVerb::SetQuota { pool, quota } => vec![UserRequest::SetQuota { user_id: pool, quota }],
        OperatorVerb::Drop { pool } => vec![UserRequest::DropTenant { user_id: pool }],
        // Said to the relay, not the vault; and `Stand` and `Move` are said as
        // `StandAt`, from this desktop's record and credentials: see [`speak`].
        OperatorVerb::ReadRule
        | OperatorVerb::SetRule { .. }
        | OperatorVerb::RelayInvite
        | OperatorVerb::Stand
        | OperatorVerb::Move { .. } => Vec::new(),
    }
}

/// The refusal for a relay named for a rule: `relay rule <word>` would read
/// the rule of a relay called `<word>` and set the rule `<word>` both.
fn relay_named_for_a_rule(name: &str) -> String {
    format!(
        "a relay is not named for a rule — {RULE_WORDS} are the rules `relay rule` sets, so `relay rule {name}` \
         would not read it; name it otherwise (`mint relay <name>`)"
    )
}

/// The refusal for a mint under a name whose credential this desktop keeps.
fn name_kept(word: &str, name: &str) -> String {
    format!(
        "you already hold a {word} called {name}; name this one (`mint {word} <name>`) — its credential \
         is enrolled, and a new key under that name would be one the {word} never enrolled"
    )
}

/// The refusal for a second nameless mint while one waits under the kind's word.
fn name_waiting(word: &str, name: &str) -> String {
    format!("you already hold a {word} called {name}; name this one (`mint {word} <name>`)")
}

/// What `forget` says of an instance still running under the key.
fn forget_refused_running(word: &str, name: &str, revoke: &str) -> String {
    format!(
        "the {word} '{name}' is still running and stands this key as its operator, so it is not forgotten — \
         destroy it first, or revoke the key there: `{revoke}`"
    )
}

/// What `forget` says of an instance that answered and did not say whether it
/// still stands the key.
fn forget_refused_unsure(word: &str, name: &str, why: &str, revoke: &str) -> String {
    format!(
        "the {word} '{name}' answers under its own key and did not say whether it still stands this one \
         ({why}), so it is not forgotten — say it again, or revoke the key there first: `{revoke}`"
    )
}

/// What `enrol` says of a credential that is not a whole one.
const NOT_A_WHOLE_CREDENTIAL: &str = "this is not a whole operator credential — a key minted here is completed by the \
     line its instance printed when it was created: `enrol <line>`";

/// How [`held_at_the_relays_door`] says nothing is kept.
const KEPT_NOTHING: &str = "nothing is kept, and the key still waits";

/// What is said of a relay that answered an unsigned refusal as the operator:
/// what was presented and where, and what most often admits it.
fn relay_refused_unsigned(hint: &str, name: &str, key: &str, chosen: bool) -> String {
    let another = if chosen {
        "If that relay was created for another key you minted, `enrol` its line again and choose that one; if \
         this key is to operate it too"
    } else {
        "If this key is to operate it"
    };
    format!(
        "the relay at {hint} proved the key its line names and, asked as its operator under the key minted \
         for the relay '{name}', answered a refusal nothing signed — {KEPT_NOTHING}. {another}, enrol the key \
         at its host first (`{}`), then `enrol` its line again.",
        enrol_at(OperatedService::Relay, key)
    )
}

/// The refusal of an admit as the operator of a vault this desktop keeps no
/// credential for.
fn no_vault_key_for_the_admit(name: &str) -> String {
    format!(
        "this desktop holds no operator credential for the vault '{name}', so it has no vault key to hold \
         the admit to — `mint vault {name}` and `enrol <the vault's line>` first"
    )
}

/// The refusal of an invite from a relay that showed no key when enrolled.
fn relay_showed_no_key_for_an_invite(name: &str) -> String {
    format!(
        "the relay '{name}' showed no key of its own when it was enrolled, so an invite could not name it — \
         hold it under a key of its own: `mint relay <a new name>`, then `enrol <its line>`"
    )
}

/// The refusal of an invite from a relay with no invite key kept yet.
fn relay_has_no_invite_key(name: &str) -> String {
    format!(
        "the relay '{name}' has no key for the people you invite yet — `relay rule {name} people_i_invite` \
         mints it and sets the rule that reads it"
    )
}

/// The refusal of an invite from a relay whose rule admits only the operator's devices.
fn relay_admits_only_the_operators(name: &str) -> String {
    format!(
        "the relay '{name}' admits only your own devices, so an invite would admit nobody — \
         `relay rule {name} people_i_invite` first"
    )
}

/// The refusal of a rule for a relay that showed no key when enrolled.
fn relay_showed_no_key_for_a_rule(name: &str, relay: &str) -> String {
    format!(
        "the relay '{name}' showed no key of its own when it was enrolled, so nothing can name it — a relay \
         from before 2026-09-29 at {relay}. Upgrade it; a relay of today prints its line at every start. Hold \
         it under a key of its own — `mint relay <a new name>`, enrol the key at the relay's terminal, then \
         `enrol <its line>`"
    )
}

/// What a verb said to the service's instance `name` is refused with when this
/// desktop keeps no credential for it: how one is made today.
fn no_credential_sentence(service: OperatedService, name: &str) -> String {
    let word = service.word();
    format!(
        "this desktop holds no operator credential for the {word} '{name}' — `mint {word} {name}`, \
         paste the command it prints at the {word}'s host, then `enrol <the line its creation printed>`"
    )
}

/// Every sentence of this file that tells a person to type a command,
/// rendered for the kind `line` is of and the name `name`, each with a label
/// for the failure message — the ones that are for a relay alone only for a
/// relay, and the one for a vault alone only for a vault. It exists for the
/// suite: the daemon's copy cannot depend on the shell, so `tests/` renders
/// these and holds every command in them to the verbs the shell has, and a
/// verb the shell retires cannot stay in the copy unseen. A sentence is
/// rendered by the builder the verb itself uses, called with the inputs that
/// bring it about, so a new sentence with a command in it is one more line
/// here.
///
/// It renders what it is handed and makes no credential: `kept` is the
/// credentials of `line`'s kind a desktop keeps — at least two, the first of
/// which is the one the sentences about a single credential name — and `line`
/// is the line an instance printed. With none kept it renders nothing.
pub fn commands_the_copy_tells_a_person_to_type(
    name: &str,
    kept: &[OperatorCredential],
    line: &kotton_wire::line::InstanceLine,
) -> Vec<(&'static str, String)> {
    use kotton_net::rendezvous::RendezvousError;
    let Some(first) = kept.first() else {
        return Vec::new();
    };
    let service = line.kind;
    let word = service.word();
    let public = hex::encode(first.key.verifying_key().to_bytes());
    let key = Some(public.clone());
    let revoke = revoke_at(service, &public);
    let stopped = |service, key| stopped_reading(&[Unread { service, name: Some(name.to_string()), key }]);
    let one = &kept[..1];
    let completing = |kept: &[OperatorCredential], chosen: Option<&str>| completes(kept, &[], chosen, line).err().unwrap_or_default();

    let mut out = vec![
        ("a stopped credential, its service known", stopped(Some(service), key.clone())),
        ("a stopped credential naming no service", stopped(None, None)),
        ("a first-form credential, key known", first_form_dropped(&[FirstForm { name: name.to_string(), key }])),
        ("a first-form credential, key unknown", first_form_dropped(&[FirstForm { name: name.to_string(), key: None }])),
        ("a mint under a name kept", name_kept(word, name)),
        ("a second nameless mint", name_waiting(word, name)),
        ("a verb said to a name with no credential", no_credential_sentence(service, name)),
        ("forget, the instance still running", forget_refused_running(word, name, &revoke)),
        ("forget, the instance unsure", forget_refused_unsure(word, name, "no answer in time", &revoke)),
        ("enrol, not a whole credential", NOT_A_WHOLE_CREDENTIAL.to_string()),
        ("enrol, no key waiting and none kept", completing(&[], None)),
        ("enrol, no key waiting and two kept", completing(kept, None)),
        ("enrol, no key waiting and one kept", completing(one, None)),
        ("enrol, a key chosen that is already kept", completing(one, Some(first.name.as_str()))),
        ("enrol at the door, several keys waiting", which_at_the_door(Some(service), &["home".to_string(), "cabin".to_string()])),
    ];
    match service {
        OperatedService::Vault => out.push(("an admit as the operator of a vault with no credential", no_vault_key_for_the_admit(name))),
        OperatedService::Relay => {
            let refused_unsigned = |chosen| {
                let said = Some(Err(RendezvousError::HttpError { status: 403, body: String::new() }));
                held_at_the_relays_door(first, line, chosen, said).err().map(|e| e.why).unwrap_or_default()
            };
            out.extend([
                ("a relay named for a rule", relay_named_for_a_rule(name)),
                ("a relay's unsigned refusal, its key chosen", refused_unsigned(true)),
                ("a relay's unsigned refusal, its key not chosen", refused_unsigned(false)),
                ("an invite from a relay that showed no key", relay_showed_no_key_for_an_invite(name)),
                ("an invite from a relay with no invite key", relay_has_no_invite_key(name)),
                ("an invite from a relay for its operator's devices only", relay_admits_only_the_operators(name)),
                ("a rule for a relay that showed no key", relay_showed_no_key_for_a_rule(name, &line.hint)),
            ]);
        }
    }
    out
}

/// Say `verb` to the vault or the relay `name` — the verb says which
/// (`OperatorVerb::service`) — under the credential `user_id` keeps for it,
/// and answer with what the service answered.
pub(crate) async fn speak(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    user_id: &str,
    name: &str,
    verb: OperatorVerb,
) -> UserResponse {
    let Some(store) = users.get(user_id) else {
        return refused(format!("user runtime '{user_id}' is not loaded"));
    };
    if let Some(said) = unread_answer(&store) {
        return said;
    }
    let service = verb.service();
    let kept = match held(&store) {
        Ok(kept) => kept,
        Err(e) => return refused(format!("the operator credentials kept here do not open: {e:#}")),
    };
    let Some(mut credential) = kept.iter().find(|c| is(c, service, name)).cloned() else {
        return refused(no_credential_sentence(service, name));
    };
    if service == OperatedService::Relay {
        // The rule asked for at the mint, if the relay has not taken it yet. A
        // set below is the person's newer word, and replaces it.
        let pending = matches!(credential.operates, Operates::Relay { rule: Some(_), .. });
        if pending && !matches!(verb, OperatorVerb::SetRule { .. }) {
            if let Some(UserResponse::RelayRule { .. }) = set_pending_rule(runtime, users, record_stores, &store, name).await {
                if let Operates::Relay { rule, .. } = &mut credential.operates {
                    *rule = None;
                }
            }
        }
        return match verb {
            OperatorVerb::SetRule { rule } => {
                let answer = set_rule(runtime, users, record_stores, &store, &credential, rule, false).await;
                if pending && matches!(answer, UserResponse::RelayRule { .. }) {
                    let _ = set_pending_cleared(&store, name);
                }
                answer
            }
            OperatorVerb::RelayInvite => relay_invite(&store, &credential).await,
            _ => read_rule(&credential).await,
        };
    }
    if verb == OperatorVerb::Stand {
        return stand(runtime, &store, &credential).await;
    }
    if let OperatorVerb::Move { relay } = &verb {
        return move_to(runtime, &store, &credential, relay).await;
    }
    let drop = matches!(verb, OperatorVerb::Drop { .. });
    let told = vault_key(&credential).and_then(|v| stands_of(&store, &v));
    let reach = told.as_ref().and_then(|t| t.relays.first()).map(|r| r.hint.as_str());
    let answer = match tokio::time::timeout(WITHIN, say(runtime, &credential, reach, requests_for(verb))).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(e)) => return refused(format!("the vault '{name}' could not be reached: {e:#}")),
        Err(_) => return refused(format!("the vault '{name}' did not answer within {}s", WITHIN.as_secs())),
    };
    // A pool dropped is a person no longer invited: *invited* rotates at each
    // relay this person operates that this desktop told the vault to stand at
    // — found by the relay's key in its record, never by a URL — so their
    // devices are refused there from the rotation after this one (the relay
    // still reads the key before the current one, for a device that has not
    // learned the new key yet). Only where keys are kept for it: a relay nobody
    // set a rule on reads no key, and one run by someone else is not this
    // person's to rotate. The rotation tells every vault standing there again.
    if drop && !matches!(answer, UserResponse::Error { .. }) {
        let keys = kept_keys(&store).unwrap_or_default();
        for stood in told.iter().flat_map(|t| &t.relays) {
            let Some(id) = relay_id(Some(&stood.key)) else { continue };
            let Some(relay) = kept.iter().find(|c| relay_key(c) == Some(id)) else { continue };
            if !keys.iter().any(|k| k.relay() == Some(id)) {
                continue;
            }
            match read_rule(relay).await {
                UserResponse::RelayRule { rule } => {
                    let rotated = set_rule(runtime, users, record_stores, &store, relay, rule, true).await;
                    if let UserResponse::Error { message } = rotated {
                        tracing::warn!(name, %message, "the pool is dropped and the invited key did not rotate");
                    }
                }
                other => tracing::warn!(name, answer = ?other, "the pool is dropped and the relay's rule could not be read to rotate its key"),
            }
        }
    }
    answer
}

/// The vault an admit is held to when this person admits an invite as the
/// operator of the vault `name` (`vault invite <v> --me`): the key
/// their credential for it pins. Read from the sealed object and handed to the
/// ceremony as a public key only — the operator's own key stays here, and the
/// tenant key the admit pairs is this device's, so the two standings stay two
/// credentials.
pub(crate) fn pinned_vault(
    users: &UserRegistry,
    user_id: &str,
    name: &str,
) -> Result<kotton_device::users::pairing::PinnedVault, String> {
    let store = users
        .get(user_id)
        .ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;
    if let Some(said) = drop_unread(&store).map_err(|e| format!("the operator credentials kept here do not open: {e:#}"))? {
        return Err(said);
    }
    let kept = held(&store).map_err(|e| format!("the operator credentials kept here do not open: {e:#}"))?;
    let credential = kept.into_iter().find(|c| is(c, OperatedService::Vault, name)).ok_or_else(|| {
        no_vault_key_for_the_admit(name)
    })?;
    let Operates::Vault { vault, .. } = credential.operates else {
        unreachable!("found as a vault's credential");
    };
    Ok(kotton_device::users::pairing::PinnedVault { vault: name.to_string(), key: vault })
}

fn set_pending_cleared(store: &UserStore, name: &str) -> anyhow::Result<()> {
    let cleared: Vec<OperatorCredential> = held(store)?
        .into_iter()
        .map(|mut c| {
            if c.name == name {
                if let Operates::Relay { rule, .. } = &mut c.operates {
                    *rule = None;
                }
            }
            c
        })
        .collect();
    keep_credentials(store, &cleared)
}

/// The relay's answer, in the desktop's words.
fn rule_answer(said: Result<RelayOperatorResponse, kotton_net::rendezvous::RendezvousError>, name: &str) -> UserResponse {
    match said {
        Ok(RelayOperatorResponse::Rule { rule, .. }) => UserResponse::RelayRule { rule },
        Ok(RelayOperatorResponse::Refused { reason }) => refused(format!("the relay '{name}' refused: {reason}")),
        Err(e) => refused(format!("the relay '{name}' could not be reached: {e}")),
    }
}

/// An invite to the relay a relay's `credential` names, in the one code
/// grammar (`InviteCode::Relay`): its key, its address, and the
/// *invited* admission key this desktop keeps for it — a bearer at member
/// level, the same key every person this operator invites holds. Refused, with the act that mends it, for a relay that showed
/// no key, one with no keys kept here yet, and one whose rule admits only its
/// operator's devices: under that rule an invite would admit nobody. The rule
/// is asked of the relay; nothing else is said to it.
async fn relay_invite(store: &UserStore, credential: &OperatorCredential) -> UserResponse {
    let name = credential.name.as_str();
    let Operates::Relay { url, key, .. } = &credential.operates else {
        return refused(format!("'{name}' is a vault's credential, and a relay's invite is the relay's"));
    };
    let Some(id) = *key else {
        return refused(relay_showed_no_key_for_an_invite(name));
    };
    let kept = match kept_keys(store) {
        Ok(k) => k,
        Err(e) => return refused(format!("the relay keys kept here do not open: {e:#}")),
    };
    let Some(invited) = kept.iter().find(|k| k.relay() == Some(id)).and_then(|k| AdmissionKey::parse(&k.invited)) else {
        return refused(relay_has_no_invite_key(name));
    };
    match read_rule(credential).await {
        UserResponse::RelayRule { rule: AdmissionRule::OnlyMyDevices } => refused(relay_admits_only_the_operators(name)),
        UserResponse::RelayRule { .. } => UserResponse::RelayInvite {
            invite: SecretText::new(
                kotton_wire::line::InviteCode::Relay { key: id, hint: url.clone(), invited: invited.to_bytes() }.to_text(),
            ),
        },
        other => other,
    }
}

/// Ask the relay a relay's credential names which rule it holds.
async fn read_rule(credential: &OperatorCredential) -> UserResponse {
    let Operates::Relay { url, .. } = &credential.operates else {
        return refused(format!("'{}' is a vault's credential, and a rule is the relay's", credential.name));
    };
    let said = tokio::time::timeout(
        WITHIN,
        kotton_net::rendezvous::say_as_operator(url, &credential.key, &RelayOperatorRequest::ReadRule),
    )
    .await
    .unwrap_or_else(|_| {
        Err(kotton_net::rendezvous::RendezvousError::Clock(format!(
            "no answer within {}s",
            WITHIN.as_secs()
        )))
    });
    rule_answer(said, &credential.name)
}

/// Set the relay's rule to `rule`, under the relay's `credential`: keys first
/// (minted if none are kept for the relay's key, or *invited* minted anew when
/// `rotate_invited`), kept sealed; then every vault this desktop told to stand
/// at that relay is told its reach set again with them — none when there is
/// none — and they go into this device's keyring; then the rule, at the relay.
/// Refused for a relay whose credential recorded no key: nothing could name it.
pub(crate) async fn set_rule(
    runtime: &DeviceRuntime,
    users: &UserRegistry,
    record_stores: &RecordStores,
    store: &UserStore,
    credential: &OperatorCredential,
    rule: AdmissionRule,
    rotate_invited: bool,
) -> UserResponse {
    let name = credential.name.as_str();
    let Operates::Relay { url: relay, key, .. } = &credential.operates else {
        return refused(format!("'{name}' is a vault's credential, and a rule is the relay's"));
    };
    let Some(id) = *key else {
        return refused(relay_showed_no_key_for_a_rule(name, relay));
    };
    let relay = relay.clone();
    // 1. The keys, kept before anything is sent anywhere.
    let mut all = match kept_keys(store) {
        Ok(a) => a,
        Err(e) => return refused(format!("the relay keys kept here do not open: {e:#}")),
    };
    let existing = all.iter().find(|k| k.relay() == Some(id)).cloned();
    let keys = match existing {
        Some(mut k) => {
            if rotate_invited {
                k.invited = AdmissionKey::generate().to_text();
            }
            k
        }
        None => RelayKeys {
            key: hex::encode(id),
            mine: AdmissionKey::generate().to_text(),
            invited: AdmissionKey::generate().to_text(),
        },
    };
    all.retain(|k| k.relay() != Some(id));
    all.push(keys.clone());
    if let Err(e) = keep_keys(store, &all) {
        return refused(format!("could not keep the relay's keys: {e:#}"));
    }
    // 2. To every vault this desktop told to stand at this relay — its whole
    // reach set again, the keys riding with the relay they belong to — and into
    // this device's keyring. A vault needs *mine* to go on reserving at its
    // relay under *only my devices*, and *invited* to hand its tenants. Found by
    // the relay's key in the desktop's own record: a relay no vault was told to
    // stand at tells none.
    let kept = match held(store) {
        Ok(k) => k,
        Err(e) => return refused(format!("the operator credentials kept here do not open: {e:#}")),
    };
    let told = stands(store).unwrap_or_default();
    for vault in &kept {
        let Some(v) = vault_key(vault) else { continue };
        let Some(at) = told.iter().find(|t| t.vault == hex::encode(v)) else { continue };
        let set: Vec<RelayId> = at.relays.iter().filter_map(|r| relay_id(Some(&r.key))).collect();
        if !set.contains(&id) {
            continue;
        }
        if let Err(e) = tell(runtime, store, vault, &set).await {
            return refused(format!("the vault '{}' did not take the relay's keys: {e}", vault.name));
        }
    }
    if let (Some(m), Some(i)) = (AdmissionKey::parse(&keys.mine), AdmissionKey::parse(&keys.invited)) {
        runtime.reachability().relay_keys().hold_as_operator(store.user_id(), &id, Some(relay.as_str()), m, i);
    }
    // A new invited key is a new note for every contact. Under *the people I
    // invite* — the one rule that admits a contact — handed over before the
    // relay is told: the set drops every
    // reservation it refuses, and a contact whose own reach is this relay and
    // who holds no key yet could be handed the note carrying it only while the
    // relay still admits them. A
    // contact not reached now is not waited for; the keeper tries again, and
    // reaches them only if their reach is somewhere this rule does not govern.
    runtime.reach_changed().notify_one();
    if rule == AdmissionRule::PeopleIInvite {
        super::reach_keeper::hand_to_contacts(runtime, users, record_stores, store.user_id()).await;
    }
    // 3. The rule, with the keys, at the relay. A key the relay already holds
    // is not a rotation there, so sending both every time changes nothing but
    // what did change.
    let set = RelayOperatorRequest::SetRule {
        rule,
        mine: Some(keys.mine),
        invited: Some(keys.invited),
    };
    let said = tokio::time::timeout(
        WITHIN,
        kotton_net::rendezvous::say_as_operator(&relay, &credential.key, &set),
    )
    .await
    .unwrap_or_else(|_| {
        Err(kotton_net::rendezvous::RendezvousError::Clock(format!(
            "no answer within {}s",
            WITHIN.as_secs()
        )))
    });
    rule_answer(said, name)
}

async fn say(
    runtime: &DeviceRuntime,
    credential: &OperatorCredential,
    stands_at: Option<&str>,
    requests: Vec<UserRequest>,
) -> anyhow::Result<UserResponse> {
    let dialer = credential.dialer(
        Arc::clone(runtime.reachability()),
        Arc::clone(runtime.event_bus()),
    );
    // No pool is named to the dialer: the operator stands to the vault, not to
    // anyone's pool, and the connection carries nothing but `requests`.
    // The vault is reached at its address, or at the relay this desktop told
    // it to stand at.
    let conn = dialer.connect(credential.vault_node(stands_at)?, "").await?;
    let conn = &conn;
    in_order(requests, |request| async move { conn.send(&request).await }).await
}

/// Send `requests` one after another, each only once the one before it was
/// answered and not refused. The answer is the first request's — the verb's
/// own, the invite's text for an invite — unless one is refused, and then it
/// is that refusal, and nothing after it is sent.
async fn in_order<F, Fut>(requests: Vec<UserRequest>, mut send: F) -> anyhow::Result<UserResponse>
where
    F: FnMut(UserRequest) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<UserResponse>>,
{
    let mut answer = None;
    for request in requests {
        let said = send(request).await?;
        if matches!(said, UserResponse::Error { .. }) {
            return Ok(said);
        }
        answer.get_or_insert(said);
    }
    Ok(answer.unwrap_or_else(|| refused("no request was sent")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A kept credential whose vault was not told where to stand is answered
    /// as kept, carrying why** — never a refusal, which would send the person
    /// to enrol a key already taken.
    #[test]
    fn a_vault_not_told_where_to_stand_is_answered_kept_with_why() {
        let why = || {
            Err::<(), _>(Unstood {
                why: UnstoodWhy::NotTold,
                reason: "the vault 'kotton' could not be reached".into(),
                relays: Vec::new(),
            })
        };
        match kept_answer("kotton".into(), OperatedService::Vault, why()) {
            UserResponse::OperatorEnrolled { name, service, unstood } => {
                assert_eq!((name.as_str(), service), ("kotton", OperatedService::Vault));
                assert_eq!(unstood.map(|u| (u.why, u.reason)), Some((UnstoodWhy::NotTold, "the vault 'kotton' could not be reached".into())));
            }
            other => panic!("a kept enrol was answered {other:?}"),
        }
        assert!(matches!(
            kept_answer("gate".into(), OperatedService::Relay, Ok(())),
            UserResponse::OperatorEnrolled { unstood: None, .. }
        ));
    }

    fn a_store(temp: &tempfile::TempDir) -> UserStore {
        UserStore::create(
            "lee",
            "did:key:z6MkLeeDesk",
            temp.path().to_path_buf(),
            kotton_store::runtime::UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .expect("a store")
    }

    async fn a_runtime(temp: &tempfile::TempDir) -> DeviceRuntime {
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> = Arc::new(kotton_secret::MemorySecrets::new());
        DeviceRuntime::new_with_secrets(temp.path().join("device"), kotton_device::config::RuntimeConfig::default(), secrets)
            .await
            .expect("a device runtime")
    }

    fn a_vault(name: &str) -> OperatorCredential {
        OperatorCredential {
            name: name.into(),
            key: ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            operates: Operates::Vault { vault: [2u8; 32], addr: None },
        }
    }

    fn a_relay(name: &str, url: &str, key: [u8; 32]) -> OperatorCredential {
        OperatorCredential {
            name: name.into(),
            key: ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            operates: Operates::Relay { url: url.into(), key: Some(key), rule: None },
        }
    }

    /// **Which minted key a line completes, decided before anything is
    /// dialled, with no name given.** The one key waiting for the
    /// line's kind is the one, and the name is the mint's — never a key of the
    /// other kind, so this is red when a line is matched to the wrong mint.
    /// Several of its kind waiting is a question, never a guess, and asked only
    /// then: a key of the other kind waiting beside one of this kind is not.
    /// The answer must name a key still waiting for the line's kind. A line for
    /// an instance already operated completes nothing; an answer naming a key
    /// already kept is a second instance under it, refused with the remedy; and
    /// a line for which nothing waits names the mint, and the reuse it may be.
    #[test]
    fn a_line_completes_the_one_key_waiting_for_its_kind_and_asks_only_between_several() {
        use kotton_wire::line::InstanceLine;
        let minted = |kind, name: &str, seed: u8| {
            kotton_peer::operator::minted_text(kind, name, &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]), None).unwrap()
        };
        let line = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: [9u8; 32] };
        let relay_line = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [8u8; 32] };
        let key = |name: &str, text: &str| Completes::Key { name: name.into(), text: text.into() };

        // One of each kind waiting: each line completes its own kind's key, under the mint's name.
        let waiting = vec![minted(OperatedService::Relay, "gate", 5), minted(OperatedService::Vault, "attic", 4)];
        assert_eq!(completes(&[], &waiting, None, &line), Ok(key("attic", &waiting[1])), "the vault's key, by the mint's name");
        assert_eq!(completes(&[], &waiting, None, &relay_line), Ok(key("gate", &waiting[0])), "the relay's key, by the mint's name");
        // A line never completes a key of the other kind, named or not.
        let relays_only = &waiting[..1];
        assert!(completes(&[], relays_only, None, &line).is_err(), "a vault's line completed the relay's key");
        assert!(completes(&[], relays_only, Some("gate"), &line).is_err(), "a vault's line completed the relay's key by its name");

        // Two of its kind: asked, never guessed — and the answer is held to a key still waiting.
        let several = [waiting.clone(), vec![minted(OperatedService::Vault, "home", 6)]].concat();
        assert_eq!(completes(&[], &several, None, &line), Ok(Completes::Which(vec!["attic".into(), "home".into()])));
        assert_eq!(completes(&[], &several, Some("home"), &line), Ok(key("home", &several[2])));
        assert_eq!(completes(&[], &several, Some("attic"), &line), Ok(key("attic", &several[1])));
        let nope = completes(&[], &several, Some("nope"), &line).unwrap_err();
        assert!(nope.contains("no key waiting for a vault called 'nope'") && nope.contains("attic, home"), "{nope}");
        assert_eq!(completes(&[], &several, None, &relay_line), Ok(key("gate", &several[0])), "a relay's line is not asked about vaults");

        let operated = OperatorCredential { operates: Operates::Vault { vault: [9u8; 32], addr: None }, ..a_vault("old") };
        let again = completes(&[operated], &waiting, None, &line).unwrap_err();
        assert!(again.contains("already operates the vault at 203.0.113.9:7710 as 'old'"), "{again}");

        let kept = a_vault("kotton");
        let revoke = format!("`kvaultd operator revoke {}`", hex::encode(kept.key.verifying_key().to_bytes()));
        let reused = completes(std::slice::from_ref(&kept), &[minted(OperatedService::Vault, "kotton", 7)], Some("kotton"), &line).unwrap_err();
        assert!(reused.contains("one key operates two instances") && reused.contains(&revoke), "{reused}");
        assert!(reused.contains("`mint vault <a new name>`") && reused.contains("then `enrol <this line>`"), "{reused}");

        let maybe = completes(&[kept], relays_only, None, &line).unwrap_err();
        assert!(maybe.contains("minted no key waiting for a vault") && maybe.contains("If the vault at 203.0.113.9:7710"), "{maybe}");
        assert!(maybe.contains("one key now operates two instances") && maybe.contains(&revoke), "{maybe}");
        let nothing = completes(&[], relays_only, None, &line).unwrap_err();
        assert!(nothing.contains("minted no key waiting for a vault") && nothing.contains("`mint vault`,"), "{nothing}");
        for said in [&nope, &again, &reused, &maybe, &nothing] {
            assert!(!said.contains("vault enrol") && !said.contains("relay enrol"), "a verb that is gone: {said}");
        }
    }

    /// **`enrol` answers each line, in the order given, and a question dials
    /// nothing.** Three things pasted at once — a vault's line with
    /// two vault keys waiting, a relay's line with no relay key waiting, and a
    /// word — come back as three readouts in that order: the vault's asks
    /// which, naming both and dialling nothing; the relay's is refused before
    /// any dial, naming the mint; the word is no line. An answer that names no
    /// key waiting is refused undialled too, and every key still waits.
    #[tokio::test]
    async fn the_lines_are_answered_in_the_order_given_and_a_question_dials_nothing() {
        use kotton_wire::ipc::{LineCame, LineToEnrol};
        use kotton_wire::line::InstanceLine;
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let runtime = a_runtime(&temp).await;
        let (users, stores) = (UserRegistry::new(), RecordStores::new());
        users.insert("lee".to_string(), store.clone());
        for name in ["home", "attic"] {
            assert!(matches!(mint(&users, "lee", OperatedService::Vault, Some(name), None), UserResponse::OperatorMinted { .. }));
        }
        let vault = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: [9u8; 32] }.to_text();
        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [8u8; 32] }.to_text();
        let given = |line: &str, mint: Option<&str>| LineToEnrol { line: line.into(), mint: mint.map(str::to_string) };
        let answer = enrol_lines(&runtime, &users, &stores, "lee", &[given(&vault, None), given(&relay, None), given("kotton", None)]).await;
        let UserResponse::OperatorEnrolledLines { lines } = answer else { panic!("{answer:?}") };
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!((lines[0].line.as_str(), lines[0].kind), (vault.as_str(), Some(OperatedService::Vault)));
        assert_eq!(lines[0].came_to, LineCame::Which { names: vec!["home".into(), "attic".into()] });
        assert_eq!((lines[1].line.as_str(), lines[1].kind), (relay.as_str(), Some(OperatedService::Relay)));
        assert!(matches!(&lines[1].came_to, LineCame::Refused { why } if why.contains("minted no key waiting for a relay")), "{lines:?}");
        assert_eq!((lines[2].line.as_str(), lines[2].kind), ("kotton", None));
        assert!(matches!(lines[2].came_to, LineCame::Refused { .. }), "{lines:?}");
        for l in &lines {
            assert_eq!((l.dialled, l.reached, l.matched), (false, None, None), "dialled: {l:?}");
        }
        let answer = enrol_lines(&runtime, &users, &stores, "lee", &[given(&vault, Some("nope"))]).await;
        let UserResponse::OperatorEnrolledLines { lines } = answer else { panic!("{answer:?}") };
        assert!(matches!(&lines[0].came_to, LineCame::Refused { why } if why.contains("home, attic")) && !lines[0].dialled, "{lines:?}");
        let UserResponse::OperatorMints { mints } = mints(&users, "lee") else { panic!() };
        assert_eq!(mints.len(), 2, "a key was spent: {mints:?}");
    }

    /// **A relay that proved its line's key is held to the minted key by its
    /// operator door, and a refusal there keeps nothing** (#53: a wrong answer
    /// to *which* was kept). A rule, or a request the relay
    /// read and could not do, is the relay standing the key. A `403` is unsigned
    /// and so not told as the key not matching; it is said as the key presented
    /// and where — never the relay's rule, never its body —
    /// with the enrol at the host for it, and, only when the key was chosen
    /// among several, the line enrolled again under another. Any other answer,
    /// or none, cannot say, and keeps nothing either.
    #[test]
    fn a_relay_is_held_to_the_minted_key_by_its_operator_door() {
        use kotton_net::rendezvous::RendezvousError;
        use kotton_wire::line::InstanceLine;
        let credential = a_relay("gate", "http://203.0.113.9:7700", [8u8; 32]);
        let line = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [8u8; 32] };
        let rule = RelayOperatorResponse::Rule { rule: AdmissionRule::OnlyMyDevices, mine_epoch: 0, invited_epoch: 0 };
        assert!(held_at_the_relays_door(&credential, &line, false, Some(Ok(rule))).is_ok());
        let could_not = RelayOperatorResponse::Refused { reason: "a reason".into() };
        assert!(held_at_the_relays_door(&credential, &line, false, Some(Ok(could_not))).is_ok());

        let door = || Some(Err(RendezvousError::HttpError { status: 403, body: "not an operator of this relay".into() }));
        let key = hex::encode(credential.key.verifying_key().to_bytes());
        let chosen = held_at_the_relays_door(&credential, &line, true, door()).unwrap_err();
        assert_eq!((chosen.reached, chosen.matched_not), (Some(true), false), "{chosen:?}");
        assert!(
            chosen.why.contains("the relay at http://203.0.113.9:7700 proved the key its line names and, asked as its operator under the key minted for the relay 'gate', answered a refusal nothing signed"),
            "{}",
            chosen.why
        );
        assert!(chosen.why.contains("nothing is kept, and the key still waits"), "{}", chosen.why);
        assert!(chosen.why.contains("choose that one") && chosen.why.contains(&format!("`{}`", enrol_at(OperatedService::Relay, &key))), "{}", chosen.why);
        let only = held_at_the_relays_door(&credential, &line, false, door()).unwrap_err();
        assert!(!only.why.contains("choose that one") && only.why.contains(&enrol_at(OperatedService::Relay, &key)), "{}", only.why);
        for said in [&chosen.why, &only.why] {
            for word in ["not an operator", "holds", "forget", "only my devices", "only_my_devices", "rule"] {
                assert!(!said.contains(word), "the refusal says {word:?}: {said}");
            }
        }

        let clock = held_at_the_relays_door(&credential, &line, true, Some(Err(RendezvousError::HttpError { status: 401, body: "stale".into() }))).unwrap_err();
        assert_eq!((clock.reached, clock.matched_not), (Some(true), false), "{clock:?}");
        assert!(clock.why.contains("did not answer as its operator") && clock.why.contains("nothing is kept"), "{}", clock.why);
        let silent = held_at_the_relays_door(&credential, &line, true, None).unwrap_err();
        assert_eq!((silent.reached, silent.matched_not), (Some(true), false), "{silent:?}");
        assert!(silent.why.contains(&format!("within {}s", WITHIN.as_secs())), "{}", silent.why);
    }

    /// **A vault that proved its line's key is held to the minted key by its
    /// own answer to the operator's read, and only its handshake refusal is
    /// told as the key not matching** (#114: every error after the dial was).
    /// The read answered is the vault standing the key. Its refusal at the
    /// handshake, under keys only the vault holds, is `matched: false`, said as
    /// the vault not created for that key. A wire cut after the dial — by the
    /// vault or by whatever stands between — an error answered, an answer of
    /// another kind, or none does not say: it is never told as the key not
    /// matching, is said as the vault not answering as its operator, and keeps
    /// nothing.
    #[test]
    fn a_vault_is_held_to_the_minted_key_by_its_own_refusal_alone() {
        use kotton_wire::line::InstanceLine;
        let credential = a_vault("home");
        let line = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.7:7444".into(), key: [2u8; 32] };
        let read = UserResponse::VaultTenants { tenants: Vec::new() };
        assert!(held_by_the_vaults_answer(&credential, &line, Some(Ok(read))).is_ok());

        let refused = anyhow::Error::new(kotton_peer::RefusedAtHandshake { alert: 42 }).context("read response length failed: aborted by peer");
        let not = held_by_the_vaults_answer(&credential, &line, Some(Err(refused))).unwrap_err();
        assert_eq!((not.reached, not.matched_not), (Some(true), true), "{not:?}");
        assert!(
            not.why.contains("the vault at 203.0.113.7:7444 proved the key its line names and refused the key minted for the vault 'home'"),
            "{}",
            not.why
        );
        assert!(not.why.contains("it was not created for that key") && not.why.contains("nothing is kept"), "{}", not.why);

        let unsaid: [(&str, Option<anyhow::Result<UserResponse>>); 4] = [
            ("a cut wire", Some(Err(anyhow::anyhow!("read response length failed: closed by peer: 0")))),
            ("an error answered", Some(Ok(UserResponse::Error { message: "no".into() }))),
            ("an answer of another kind", Some(Ok(UserResponse::Ok))),
            ("no answer", None),
        ];
        for (what, said) in unsaid {
            let unsure = held_by_the_vaults_answer(&credential, &line, said).unwrap_err();
            assert_eq!((unsure.reached, unsure.matched_not), (Some(true), false), "{what} was told as the key not matching: {unsure:?}");
            assert!(unsure.why.contains("the vault at 203.0.113.7:7444 proved"), "{what}: {}", unsure.why);
            assert!(unsure.why.contains("did not answer as its operator") && unsure.why.contains("nothing is kept"), "{what}: {}", unsure.why);
            assert!(!unsure.why.contains("not created for that key"), "{what} was said as the vault's refusal: {}", unsure.why);
        }
    }

    fn refusal(answer: UserResponse) -> String {
        match answer {
            UserResponse::Error { message } => message,
            other => panic!("`vault stand` answered {other:?} where it told nothing"),
        }
    }

    /// **`after_kept` answers why when the store does not open, never `Ok`.**
    /// It is handed the credential its caller kept, so a credential not
    /// there is no case it has; a kept list that does not open tells nothing,
    /// and [`tell`] answers why.
    #[tokio::test]
    async fn after_kept_answers_why_when_the_vaults_credential_does_not_read_back() {
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let (users, stores) = (UserRegistry::new(), RecordStores::new());
        kotton_store::runtime::private::write(&store, KEPT, b"not the kept list").unwrap();
        let unread = after_kept(&runtime, &users, &stores, &store, &a_vault("kotton"), false).await;
        let unread = unread.expect_err("a store that does not open was answered as told");
        assert_eq!(unread.why, UnstoodWhy::NotTold, "{unread}");
        assert!(unread.reason.contains("do not open"), "{unread}");
    }

    /// **`vault stand` tells the vault by the credential it is handed**, and
    /// answers *told* only when the vault took a set. `speak` found it; `stand` looks nothing up again, so a credential
    /// the store no longer returns cannot turn into *told where to stand*. Here
    /// the store holds nothing at all and the credential is handed in: the
    /// telling is made for it, finds no relay, and is refused for that cause.
    #[tokio::test]
    async fn vault_stand_tells_by_the_credential_it_is_handed() {
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let message = refusal(stand(&runtime, &store, &a_vault("kotton")).await);
        assert!(message.contains("operates no relay to tell the vault 'kotton' of"), "{message}");
        assert!(message.contains("`enrol <the relay's line>`"), "{message}");
    }

    /// **A held relay at the address the vault was told, under another key, is
    /// a move, said as one.** The vault was told to stand at the relay whose key is
    /// `[4; 32]`, found at `U`; the relay this desktop holds at `U` now is
    /// `[5; 32]` — rebuilt. "Hold that relay again" would record `[5; 32]` and
    /// be refused here again, so the cause is `Moved`, with the address, and
    /// the refusal names the move by the held relay's name. Nothing is sent:
    /// the vault's record is what it was.
    #[tokio::test]
    async fn a_relay_rebuilt_at_the_told_address_is_a_move_and_is_said_as_one() {
        const U: &str = "http://203.0.113.9:7700";
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let vault = a_vault("kotton");
        keep_credentials(&store, &[vault.clone(), a_relay("gate", U, [5u8; 32])]).unwrap();
        let before = StandsAt {
            vault: hex::encode([2u8; 32]),
            relays: vec![Stood { key: hex::encode([4u8; 32]), hint: format!("{U}/") }],
            told_at: 1,
        };
        keep_stands(&store, std::slice::from_ref(&before)).unwrap();

        let why = stand_as_told(&runtime, &store, &vault).await.expect_err("a rebuilt relay is not a telling");
        assert_eq!(why.why, UnstoodWhy::Moved, "{why}");
        assert_eq!(
            why.relays,
            vec![UnstoodRelay { hint: format!("{U}/"), state: UnstoodRelayState::Moved, name: Some("gate".into()) }]
        );
        let message = refusal(stand(&runtime, &store, &vault).await);
        assert!(message.contains("`vault move kotton gate`"), "the move, by the held relay's name: {message}");
        assert!(message.contains("to stand the vault 'kotton' there"), "{message}");
        assert!(message.contains("*Move…*"), "{message}");
        assert!(!message.contains("hold that relay again"), "the act that loops: {message}");
        assert_eq!(stands(&store).unwrap(), vec![before], "nothing was told");

        // The same relay somewhere else is not a move: it is a relay no longer
        // held, and holding it again is the act.
        keep_credentials(&store, &[vault.clone(), a_relay("gate", "http://198.51.100.4:7700", [5u8; 32])]).unwrap();
        let why = stand_as_told(&runtime, &store, &vault).await.expect_err("no relay the vault was told of is held");
        assert_eq!(why.why, UnstoodWhy::RelaysNotHeld, "{why}");
    }

    /// **A relay address is compared by `same_relay_address`, the one
    /// comparison of an address.** A hint recorded with space around it is the same address
    /// as the credential's: the relay rebuilt there is a move. A comparator of
    /// its own that trims only `/` said otherwise, and sent the person to hold
    /// again a relay they already hold.
    #[tokio::test]
    async fn a_told_address_is_compared_as_every_relay_address_is() {
        const U: &str = "http://203.0.113.9:7700";
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let vault = a_vault("kotton");
        keep_credentials(&store, &[vault.clone(), a_relay("gate", U, [5u8; 32])]).unwrap();
        let told = vec![Stood { key: hex::encode([4u8; 32]), hint: format!(" {U} ") }];
        keep_stands(&store, &[StandsAt { vault: hex::encode([2u8; 32]), relays: told, told_at: 1 }]).unwrap();
        let why = stand_as_told(&runtime, &store, &vault).await.expect_err("a rebuilt relay is not a telling");
        assert_eq!(why.why, UnstoodWhy::Moved, "{why}");
    }

    /// **One relay rebuilt and another no longer held: the one that can be
    /// held again leads** (the driver's ruling on `3f8911bf`). Holding that
    /// relay again and `vault stand` works today; a move does not exist yet,
    /// so the cause is the one the person can act on, and each relay keeps its
    /// own state.
    #[tokio::test]
    async fn a_relay_rebuilt_beside_one_no_longer_held_leads_with_holding_again() {
        const U: &str = "http://203.0.113.9:7700";
        const GONE: &str = "http://198.51.100.4:7700";
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let vault = a_vault("kotton");
        keep_credentials(&store, &[vault.clone(), a_relay("gate", U, [5u8; 32])]).unwrap();
        let told = vec![
            Stood { key: hex::encode([4u8; 32]), hint: U.into() },
            Stood { key: hex::encode([6u8; 32]), hint: GONE.into() },
        ];
        keep_stands(&store, &[StandsAt { vault: hex::encode([2u8; 32]), relays: told, told_at: 1 }]).unwrap();
        let why = stand_as_told(&runtime, &store, &vault).await.expect_err("no relay the vault was told of is held");
        assert_eq!(why.why, UnstoodWhy::RelaysNotHeld, "{why}");
        let act = why.remedy("kotton");
        assert!(act.starts_with("hold that relay again"), "the act that works now leads: {act}");
        assert!(act.contains(GONE), "{act}");
        assert_eq!(
            why.relays,
            vec![
                UnstoodRelay { hint: U.into(), state: UnstoodRelayState::Moved, name: Some("gate".into()) },
                UnstoodRelay { hint: GONE.into(), state: UnstoodRelayState::NotHeld, name: None },
            ],
            "each relay keeps its own state"
        );
        assert!(act.contains("*Move…*"), "the rebuilt relay's act is still named: {act}");
    }

    /// **A vault told nothing, by a desktop that runs exactly one relay, is
    /// told to stand at that relay without asking** — the Default's first arm,
    /// decided before anything is dialled. With none it is told no relay; with
    /// a second it is asked (the test below). Once told, the set it was told is
    /// told again whatever this desktop runs now.
    #[tokio::test]
    async fn a_vault_told_nothing_by_a_desktop_running_one_relay_is_told_to_stand_there() {
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let vault = a_vault("kotton");
        keep_credentials(&store, std::slice::from_ref(&vault)).unwrap();
        assert_eq!(relays_to_tell(&store, &vault).expect("no relay is no question"), Vec::<RelayId>::new());

        keep_credentials(&store, &[vault.clone(), a_relay("gate", "http://203.0.113.9:7700", [4u8; 32])]).unwrap();
        assert_eq!(
            relays_to_tell(&store, &vault).expect("one relay is a telling, not a question"),
            vec![[4u8; 32]],
            "the one relay run here"
        );

        keep_stands(
            &store,
            &[StandsAt { vault: hex::encode([2u8; 32]), relays: vec![Stood { key: hex::encode([4u8; 32]), hint: "x".into() }], told_at: 1 }],
        )
        .unwrap();
        keep_credentials(
            &store,
            &[vault.clone(), a_relay("gate", "http://203.0.113.9:7700", [4u8; 32]), a_relay("attic", "http://198.51.100.4:7700", [5u8; 32])],
        )
        .unwrap();
        assert_eq!(
            relays_to_tell(&store, &vault).expect("a vault told once is told again, not asked"),
            vec![[4u8; 32]]
        );
    }

    /// **A vault told nothing, by a desktop that runs two relays, is asked and
    /// told nothing**: with exactly one relay
    /// the vault is told to stand there, and with more the person chooses. The
    /// cause is `Several`, listing each relay by its address and the name
    /// `vault move` takes; nothing is recorded as told.
    #[tokio::test]
    async fn a_vault_told_nothing_by_a_desktop_running_two_relays_is_asked_where_to_stand() {
        const A: &str = "http://203.0.113.9:7700";
        const B: &str = "http://198.51.100.4:7700";
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let vault = a_vault("kotton");
        keep_credentials(&store, &[vault.clone(), a_relay("gate", A, [4u8; 32]), a_relay("attic", B, [5u8; 32])]).unwrap();
        let why = stand_as_told(&runtime, &store, &vault).await.expect_err("two relays is a question, not a telling");
        assert_eq!(why.why, UnstoodWhy::Several, "{why}");
        assert_eq!(
            why.relays,
            vec![
                UnstoodRelay { hint: A.into(), state: UnstoodRelayState::Operated, name: Some("gate".into()) },
                UnstoodRelay { hint: B.into(), state: UnstoodRelayState::Operated, name: Some("attic".into()) },
            ]
        );
        assert!(stands(&store).unwrap().is_empty(), "nothing was told");
        let message = refusal(stand(&runtime, &store, &vault).await);
        assert!(message.contains("`vault move kotton <relay>` with one of: gate, attic"), "{message}");
    }

    /// **`vault move` names a relay this desktop runs, by a key it recorded,
    /// or nothing is told.** A name it holds no relay credential under, and a
    /// relay whose credential recorded no key, are each refused in words, and
    /// the vault's record is what it was.
    #[tokio::test]
    async fn a_move_to_a_relay_not_run_here_or_with_no_key_is_refused_and_tells_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let vault = a_vault("kotton");
        let keyless = OperatorCredential {
            name: "old".into(),
            key: ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            operates: Operates::Relay { url: "http://192.0.2.1:7700".into(), key: None, rule: None },
        };
        keep_credentials(&store, &[vault.clone(), keyless]).unwrap();
        let message = refusal(move_to(&runtime, &store, &vault, "gate").await);
        assert!(message.contains("runs no relay called 'gate'"), "{message}");
        let message = refusal(move_to(&runtime, &store, &vault, "old").await);
        assert!(message.contains("showed no key"), "{message}");
        assert!(stands(&store).unwrap().is_empty(), "nothing was told");
    }

    /// **A kept `kotton-operator 1` credential is dropped, and the person is
    /// told the re-make and revoke commands.** The first verb that
    /// finds one — here the mint that would re-make it — answers with the
    /// sentence and does nothing else; the credential goes, with the key
    /// minted in that form and the relay keys kept for its relay, and what is
    /// of the current form stays. The sentence names both new mints and the
    /// revoke at each service with the old key in it; a second verb finds
    /// nothing to drop and does what it was asked.
    #[test]
    fn a_first_form_credential_is_dropped_and_the_person_is_told_what_to_type() {
        use kotton_peer::operator::{FIRST_FORM, FIRST_FORM_NAME};
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let users = UserRegistry::new();
        users.insert("lee".to_string(), std::sync::Arc::clone(&store));

        let old = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let old_public = hex::encode(old.verifying_key().to_bytes());
        let first = format!(
            "{FIRST_FORM}\n{FIRST_FORM_NAME}=kotton\noperator={}\nkey={old_public}\nvault={}\nrelay=http://203.0.113.9:7700\n",
            hex::encode(old.to_bytes()),
            hex::encode([9u8; 32])
        );
        let current = kotton_peer::operator::minted_text(OperatedService::Vault, "attic", &old, None).unwrap();
        let other_vault = format!(
            "{}vault={}\naddr=198.51.100.4:7710\n",
            current.replace("operates=vault\n", ""),
            hex::encode([8u8; 32])
        );
        let first_minted = format!("{FIRST_FORM}\n{FIRST_FORM_NAME}=kotton\noperator={}\nrule=anyone\n", hex::encode(old.to_bytes()));
        kotton_store::runtime::private::write(&store, KEPT, &serde_json::to_vec(&[first, other_vault]).unwrap()).unwrap();
        keep_minted(&store, &[first_minted, current.clone()]).unwrap();
        // Keys kept then, by the relay's URL, and keys kept now, by a
        // relay's key.
        let by_url = serde_json::json!({ "relay": "http://203.0.113.9:7700", "mine": "m", "invited": "i" });
        let by_key = serde_json::json!({ "key": hex::encode([4u8; 32]), "mine": "m", "invited": "i" });
        kotton_store::runtime::private::write(&store, KEYS, &serde_json::to_vec(&[by_url, by_key]).unwrap()).unwrap();

        let said = match mint(&users, "lee", OperatedService::Vault, Some("kotton"), None) {
            UserResponse::Error { message } => message,
            other => panic!("the mint went ahead over a first-form credential: {other:?}"),
        };
        let [at_vault, at_relay] = revoke_at_each_service(&old_public);
        for words in [
            "kotton-operator 1",
            "the host 'kotton'",
            "`mint vault kotton`",
            "`mint relay kotton`",
            &format!("`{at_vault}`"),
            &format!("`{at_relay}`"),
            "Nothing else was done",
        ] {
            assert!(said.contains(words), "the sentence does not say {words:?}: {said}");
        }
        assert_eq!(at_vault, format!("kvaultd operator revoke {old_public}"));
        assert!(at_relay.ends_with(&format!("kotton-relay --state-dir /var/lib/kotton-relay operator revoke {old_public}")));

        // Dropped: the first form's credential, minted key and relay keys; the
        // current form's stay.
        let kept = held(&store).unwrap();
        assert_eq!(kept.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["attic"]);
        assert_eq!(minted(&store).unwrap(), vec![current]);
        let relays: Vec<String> = kept_keys(&store).unwrap().into_iter().map(|k| k.key).collect();
        assert_eq!(relays, [hex::encode([4u8; 32])]);

        // Said once: the next verb does what it was asked.
        assert!(drop_unread(&store).unwrap().is_none());
        assert!(matches!(
            mint(&users, "lee", OperatedService::Vault, Some("kotton"), None),
            UserResponse::OperatorMinted { ref name, .. } if name == "kotton"
        ));
    }

    /// **A kept credential that stops reading is dropped and said, not logged.**
    /// A readout
    /// passes it over and drops nothing. The first verb that finds one — here a
    /// mint for another name — answers with the sentence and does nothing else:
    /// which credential, by its service and name; that its key is still
    /// enrolled there; the re-make, first, since a service never revokes its
    /// last operator; and that service's revoke with the old key in it — read
    /// from `key=`, or from the secret when the text has no `key=`. What reads
    /// stays, and a second verb finds nothing to drop. With a first-form
    /// credential beside it, one sentence says both and ends once.
    #[test]
    fn a_credential_that_stops_reading_is_dropped_and_the_person_is_told_its_revoke() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let users = UserRegistry::new();
        users.insert("lee".to_string(), std::sync::Arc::clone(&store));
        let kept_texts = |store: &UserStore| -> Vec<String> {
            serde_json::from_slice(&kotton_store::runtime::private::read(store, KEPT).unwrap().unwrap()).unwrap()
        };

        // A vault's credential with no address: a form this desktop no longer
        // reads. A relay's with a line the form does not have, and no `key=`.
        let vault = a_vault("kotton");
        let vault_public = hex::encode(vault.key.verifying_key().to_bytes());
        let stopped_vault = vault.to_text();
        assert!(OperatorCredential::parse(&stopped_vault).is_err(), "the fixture is a credential that does not read");
        let porch = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let porch_public = hex::encode(porch.verifying_key().to_bytes());
        let stopped_relay = format!(
            "{}\nname=porch\noperator={}\nrelay=http://203.0.113.9:7700\ncolour=blue\n",
            kotton_peer::operator::MAGIC,
            hex::encode(porch.to_bytes())
        );
        let readable = a_relay("gate", "http://198.51.100.7:7700", [4u8; 32]).to_text();
        kotton_store::runtime::private::write(
            &store,
            KEPT,
            &serde_json::to_vec(&[stopped_vault, readable.clone(), stopped_relay]).unwrap(),
        )
        .unwrap();

        // The readout passes them over, and drops nothing.
        assert_eq!(held(&store).unwrap().iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["gate"]);
        assert_eq!(kept_texts(&store).len(), 3);

        let said = match mint(&users, "lee", OperatedService::Vault, Some("cellar"), None) {
            UserResponse::Error { message } => message,
            other => panic!("the mint went ahead over a credential that stopped reading: {other:?}"),
        };
        let [vault_revoke, _] = revoke_at_each_service(&vault_public);
        let [_, relay_revoke] = revoke_at_each_service(&porch_public);
        for words in [
            "the vault 'kotton'",
            "still enrolled at the vault",
            &format!("`{vault_revoke}`"),
            "`mint vault kotton`",
            "`kvaultd operator enrol <the new key>`",
            "`enrol <the vault's line>`",
            "the relay 'porch'",
            "still enrolled at the relay",
            &format!("`{relay_revoke}`"),
            "`mint relay porch`",
            "`enrol <the relay's line>`",
            "never revokes its last operator",
            "Nothing else was done",
        ] {
            assert!(said.contains(words), "the sentence does not say {words:?}: {said}");
        }
        assert_eq!(vault_revoke, format!("kvaultd operator revoke {vault_public}"));
        assert!(relay_revoke.ends_with(&format!("operator revoke {porch_public}")));

        // Dropped: the two that stopped reading; what reads stays.
        assert_eq!(kept_texts(&store), vec![readable]);
        assert!(drop_unread(&store).unwrap().is_none());
        assert!(matches!(
            mint(&users, "lee", OperatedService::Vault, Some("cellar"), None),
            UserResponse::OperatorMinted { ref name, .. } if name == "cellar"
        ));

        // Beside a first-form credential: one sentence, ending once.
        let first = format!(
            "{}\n{}=attic\nkey={porch_public}\n",
            kotton_peer::operator::FIRST_FORM,
            kotton_peer::operator::FIRST_FORM_NAME
        );
        kotton_store::runtime::private::write(&store, KEPT, &serde_json::to_vec(&[first, a_vault("kotton").to_text()]).unwrap())
            .unwrap();
        let both = drop_unread(&store).unwrap().expect("both are said");
        assert!(both.contains("the vault 'kotton'") && both.contains("the host 'attic'"), "{both}");
        assert_eq!(both.matches(SAID_AGAIN).count(), 1, "{both}");
        assert_eq!(kept_texts(&store), Vec::<String>::new());
    }

    /// **A drop that cannot read everything it decides on writes nothing.**
    /// A credential that stopped reading
    /// sits beside a list of minted keys that will not open, then beside a
    /// first-form credential and relay keys that will not open: each time the
    /// drop fails, and the kept credentials are as they were, so the next verb
    /// can still say them. Once the store opens, the drop says the credential,
    /// with its key and its revoke.
    #[test]
    fn a_drop_that_cannot_read_everything_writes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let kept_texts = |store: &UserStore| -> Vec<String> {
            serde_json::from_slice(&kotton_store::runtime::private::read(store, KEPT).unwrap().unwrap()).unwrap()
        };
        let vault = a_vault("kotton");
        let stopped = vault.to_text();
        kotton_store::runtime::private::write(&store, KEPT, &serde_json::to_vec(std::slice::from_ref(&stopped)).unwrap()).unwrap();

        kotton_store::runtime::private::write(&store, MINTED, b"not the minted list").unwrap();
        assert!(drop_unread(&store).is_err(), "a minted list that does not open is a store that does not open");
        assert_eq!(kept_texts(&store), vec![stopped.clone()], "the credential went unsaid");
        keep_minted(&store, &[]).unwrap();

        let first = format!(
            "{}\n{}=attic\nkey={}\n",
            kotton_peer::operator::FIRST_FORM,
            kotton_peer::operator::FIRST_FORM_NAME,
            hex::encode([5u8; 32])
        );
        let both = vec![stopped.clone(), first];
        kotton_store::runtime::private::write(&store, KEPT, &serde_json::to_vec(&both).unwrap()).unwrap();
        kotton_store::runtime::private::write(&store, KEYS, b"not the relay keys").unwrap();
        assert!(drop_unread(&store).is_err(), "relay keys that do not open are a store that does not open");
        assert_eq!(kept_texts(&store), both, "a credential went unsaid");

        keep_keys(&store, &[]).unwrap();
        let said = drop_unread(&store).unwrap().expect("both are said once the store opens");
        let [revoke, _] = revoke_at_each_service(&hex::encode(vault.key.verifying_key().to_bytes()));
        assert!(said.contains(&format!("`{revoke}`")) && said.contains("the host 'attic'"), "{said}");
        assert_eq!(kept_texts(&store), Vec::<String>::new());
    }

    /// **`mint vault` and `mint relay` make different keys**, and a
    /// vault's mint takes no rule — the rule is the relay's.
    #[test]
    fn a_vault_and_a_relay_minted_under_one_name_are_two_keys() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let users = UserRegistry::new();
        users.insert("lee".to_string(), store);
        let key = |answer| match answer {
            UserResponse::OperatorMinted { key, .. } => key,
            other => panic!("{other:?}"),
        };
        let vault = key(mint(&users, "lee", OperatedService::Vault, Some("kotton"), None));
        let relay = key(mint(&users, "lee", OperatedService::Relay, Some("kotton"), Some(AdmissionRule::PeopleIInvite)));
        assert_ne!(vault, relay);
        assert!(matches!(
            mint(&users, "lee", OperatedService::Vault, Some("kotton"), Some(AdmissionRule::Anyone)),
            UserResponse::Error { .. }
        ));
    }

    /// **A bare `mint` lists each key minted and not yet enrolled, by name and
    /// kind, with its public half and never its secret.** Minting again under a name replaces the key it waited with, and a
    /// key whose credential is kept is no longer listed.
    #[test]
    fn the_keys_minted_and_not_yet_enrolled_are_listed_by_name_and_kind() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let users = UserRegistry::new();
        users.insert("lee".to_string(), store.clone());
        let key = |answer| match answer {
            UserResponse::OperatorMinted { key, .. } => key,
            other => panic!("{other:?}"),
        };
        let listed = |users: &UserRegistry| match mints(users, "lee") {
            UserResponse::OperatorMints { mints } => mints,
            other => panic!("{other:?}"),
        };
        assert_eq!(listed(&users), Vec::new(), "nothing minted, nothing waiting");

        let first = key(mint(&users, "lee", OperatedService::Vault, Some("kotton"), None));
        let gate = key(mint(&users, "lee", OperatedService::Relay, Some("gate"), None));
        let again = key(mint(&users, "lee", OperatedService::Vault, Some("kotton"), None));
        assert_ne!(first, again, "a mint again is a new key");
        let waiting = |name: &str, service, key: &str| kotton_wire::ipc::MintWaiting {
            name: name.into(),
            service,
            key: key.into(),
        };
        assert_eq!(
            listed(&users),
            vec![waiting("gate", OperatedService::Relay, &gate), waiting("kotton", OperatedService::Vault, &again)],
            "one per kind and name, the newest key for each"
        );
        let said = serde_json::to_string(&mints(&users, "lee")).unwrap();
        for text in minted(&store).unwrap() {
            let secret = text.lines().find_map(|l| l.strip_prefix("operator=")).unwrap().to_string();
            assert!(!said.contains(&secret), "a secret listed: {said}");
        }

        spend_minted(&store, OperatedService::Vault, "kotton").unwrap();
        // A kind's word is the name a nameless mint is held under; once one is
        // kept under it, a mint under it again is refused naming the spelling
        // that works.
        keep_credentials(&store, &[a_relay("relay", "http://203.0.113.9:7700", [5u8; 32])]).unwrap();
        match mint(&users, "lee", OperatedService::Relay, Some("relay"), None) {
            UserResponse::Error { message } => assert!(
                message.starts_with("you already hold a relay called relay; name this one (`mint relay <name>`)"),
                "{message}"
            ),
            other => panic!("a second relay under `relay`: {other:?}"),
        }
        assert_eq!(listed(&users), vec![waiting("gate", OperatedService::Relay, &gate)], "the completed key is not waiting");
        assert!(matches!(mints(&users, "sam"), UserResponse::Error { .. }), "no runtime, no list");
    }

    /// **A relay is not minted under a rule's word**, so `relay rule <word>`
    /// is never a relay held and a rule both: each rule's word, as the
    /// credential spells it and as the window prints it, is refused in one line
    /// naming the words, and nothing is minted. A vault may take one, since
    /// `vault` has no rule; a name that merely contains a rule's word is not
    /// refused.
    #[test]
    fn a_relay_is_not_minted_under_a_rules_word() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let users = UserRegistry::new();
        users.insert("lee".to_string(), store.clone());
        for name in ["only_my_devices", "people_i_invite", "anyone", "only-my-devices", "people-i-invite"] {
            match mint(&users, "lee", OperatedService::Relay, Some(name), None) {
                UserResponse::Error { message } => {
                    assert!(message.starts_with("a relay is not named for a rule"), "{message}");
                    assert!(message.contains(RULE_WORDS) && !message.contains('\n'), "{message}");
                }
                other => panic!("a relay minted as '{name}': {other:?}"),
            }
        }
        assert!(minted(&store).unwrap().is_empty(), "a refused mint kept a key");
        assert!(matches!(mint(&users, "lee", OperatedService::Relay, Some("anyone-home"), None), UserResponse::OperatorMinted { .. }));
        assert!(matches!(mint(&users, "lee", OperatedService::Vault, Some("anyone"), None), UserResponse::OperatorMinted { .. }));
    }

    /// **The instances of a kind this person operates are read by name, in
    /// the order kept, and the other kind's are not among them** — what an
    /// operating verb typed with no name reads once to be said to the one
    /// there is, or refused listing several. Names only: nothing of a key or
    /// an address is said.
    #[test]
    fn the_instances_of_a_kind_held_are_read_by_name_and_kind() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let users = UserRegistry::new();
        users.insert("lee".to_string(), store.clone());
        let names = |service| match held_of(&users, "lee", service) {
            UserResponse::OperatorHeld { names } => names,
            other => panic!("{other:?}"),
        };
        assert_eq!(names(OperatedService::Vault), Vec::<String>::new(), "none held, none read");
        // A vault's credential reads back only with the address it is reached at.
        let vault = |name: &str| OperatorCredential {
            operates: Operates::Vault { vault: [2u8; 32], addr: Some("203.0.113.9:7710".parse().unwrap()) },
            ..a_vault(name)
        };
        keep_credentials(&store, &[vault("home"), a_relay("gate", "http://203.0.113.9:7700", [5u8; 32]), vault("attic")]).unwrap();
        assert_eq!(names(OperatedService::Vault), vec!["home".to_string(), "attic".to_string()]);
        assert_eq!(names(OperatedService::Relay), vec!["gate".to_string()]);
        let said = serde_json::to_string(&held_of(&users, "lee", OperatedService::Relay)).unwrap();
        assert!(!said.contains("203.0.113.9") && !said.contains(&hex::encode([5u8; 32])), "more than a name: {said}");
        assert!(matches!(held_of(&users, "sam", OperatedService::Vault), UserResponse::Error { .. }), "no runtime, nothing read");
    }

    /// **A credential forgotten takes what was kept for it, and nothing else**
    /// (decision 0006). A vault's credential goes with its record of where it
    /// was told to stand and a key minted under its name; a relay's with its
    /// two admission keys, which this device stops presenting and offering at
    /// once — as a restart with the credential gone holds them — keeping the
    /// key a relay invite carried there. The other vault, the other relay, their
    /// keys, a vault's record that names the forgotten relay and a key minted
    /// under another name are untouched.
    #[tokio::test]
    async fn a_credential_forgotten_takes_what_was_kept_for_it_and_nothing_else() {
        let temp = tempfile::tempdir().unwrap();
        let store = a_store(&temp);
        let runtime = a_runtime(&temp).await;
        let (gate, yard) = ([5u8; 32], [6u8; 32]);
        let vault = |name: &str, key: u8| OperatorCredential {
            operates: Operates::Vault { vault: [key; 32], addr: Some("203.0.113.9:7710".parse().unwrap()) },
            ..a_vault(name)
        };
        let (home, attic) = (vault("home", 2), vault("attic", 4));
        let (g, y) = (a_relay("gate", "http://203.0.113.9:7700", gate), a_relay("yard", "http://203.0.113.9:7701", yard));
        keep_credentials(&store, &[home.clone(), g.clone(), attic.clone(), y.clone()]).unwrap();
        let keys = |relay: [u8; 32], b: u8| RelayKeys {
            key: hex::encode(relay),
            mine: AdmissionKey::from_bytes([b; 32]).to_text(),
            invited: AdmissionKey::from_bytes([b + 1; 32]).to_text(),
        };
        keep_keys(&store, &[keys(gate, 10), keys(yard, 20)]).unwrap();
        let stood = |vault: u8| StandsAt { vault: hex::encode([vault; 32]), relays: vec![Stood { key: hex::encode(gate), hint: "http://203.0.113.9:7700".into() }], told_at: 1 };
        keep_stands(&store, &[stood(2), stood(4)]).unwrap();
        let text = |name| kotton_peer::operator::minted_text(OperatedService::Vault, name, &ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]), None).unwrap();
        keep_minted(&store, &[text("home"), text("cellar")]).unwrap();
        let ring = runtime.reachability().relay_keys();
        keep_invited(&runtime, &store, &gate, AdmissionKey::from_bytes([30u8; 32])).unwrap();
        present_kept_keys(&runtime, &store);
        assert_eq!(ring.present_for("lee", &gate), Some(AdmissionKey::from_bytes([10u8; 32])), "the operator's own key, before");

        drop_credential(&runtime, &store, &home).unwrap();
        let names = |service| held(&store).unwrap().into_iter().filter(|c| c.service() == service).map(|c| c.name).collect::<Vec<_>>();
        assert_eq!(names(OperatedService::Vault), vec!["attic".to_string()]);
        assert_eq!(stands(&store).unwrap(), vec![stood(4)], "the forgotten vault's record went, and only it");
        let waiting: Vec<_> = minted(&store).unwrap().iter().map(|t| kotton_peer::operator::service_name_and_secret(t).1).collect();
        assert_eq!(waiting, vec![Some("cellar".to_string())], "the key minted under the forgotten name went, and only it");

        drop_credential(&runtime, &store, &g).unwrap();
        assert_eq!(names(OperatedService::Relay), vec!["yard".to_string()]);
        assert_eq!(kept_keys(&store).unwrap().iter().map(|k| k.key.clone()).collect::<Vec<_>>(), vec![hex::encode(yard)]);
        assert_eq!(stands(&store).unwrap(), vec![stood(4)], "a vault's record naming the forgotten relay is the vault's");
        assert_eq!(ring.present_for("lee", &gate), Some(AdmissionKey::from_bytes([30u8; 32])), "only the invite's key is presented there now");
        assert_eq!(ring.offer_for("lee", &gate), None, "the forgotten relay's invited key is still offered");
        assert!(ring.at("lee", &gate).operated_at.is_none(), "the forgotten relay's address is still read as own");
        assert_eq!(ring.present_for("lee", &yard), Some(AdmissionKey::from_bytes([20u8; 32])));
        let elsewhere = tempfile::tempdir().unwrap();
        let restarted = a_runtime(&elsewhere).await;
        present_kept_keys(&restarted, &store);
        let again = restarted.reachability().relay_keys();
        for relay in [gate, yard] {
            let (now, after) = (ring.at("lee", &relay), again.at("lee", &relay));
            assert_eq!(
                (now.present.map(|(k, t)| (k.to_text(), t)), now.offer.map(|k| k.to_text()), now.operated_at),
                (after.present.map(|(k, t)| (k.to_text(), t)), after.offer.map(|k| k.to_text()), after.operated_at),
                "what is held now is not what a restart holds"
            );
        }
    }

    /// **A verb said to a name this desktop keeps no credential for is refused
    /// with the verbs that make one today**: `mint <word> <name>`, the command
    /// it prints pasted at the host, then `enrol <the line its creation
    /// printed>` — which takes no name — and no verb the shell has retired.
    #[tokio::test]
    async fn a_name_with_no_credential_is_told_the_mint_and_the_enrol_that_exist() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let runtime = a_runtime(&temp).await;
        let users = UserRegistry::new();
        users.insert("lee".to_string(), store);
        let record_stores = RecordStores::new();
        for (word, verb) in [("vault", OperatorVerb::Pools), ("relay", OperatorVerb::ReadRule)] {
            let said = match speak(&runtime, &users, &record_stores, "lee", "attic", verb).await {
                UserResponse::Error { message } => message,
                other => panic!("a name with no credential was answered {other:?}"),
            };
            for words in [
                format!("no operator credential for the {word} 'attic'"),
                format!("`mint {word} attic`"),
                format!("paste the command it prints at the {word}'s host"),
                "`enrol <the line its creation printed>`".to_string(),
            ] {
                assert!(said.contains(&words), "the refusal does not say {words:?}: {said}");
            }
        }
    }

    /// **`forget` asks the instance first, and forgets one that does not
    /// answer, saying so; a name not held is refused** (decision 0006). Nothing
    /// listens where this vault and this relay were, as after a host started
    /// over: each is forgotten, answered as not having answered, with its key's
    /// public half for the revoke.
    #[tokio::test]
    async fn an_instance_that_does_not_answer_is_forgotten_and_a_name_not_held_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let runtime = a_runtime(&temp).await;
        let users = UserRegistry::new();
        users.insert("lee".to_string(), store.clone());
        let nobody = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let home = OperatorCredential { operates: Operates::Vault { vault: [2u8; 32], addr: Some(nobody) }, ..a_vault("home") };
        let gate = a_relay("gate", &format!("http://{nobody}"), [5u8; 32]);
        keep_credentials(&store, &[home.clone(), gate.clone()]).unwrap();

        match forget(&runtime, &users, "lee", OperatedService::Vault, "attic").await {
            UserResponse::Error { message } => assert!(message.contains("no operator credential for the vault 'attic'"), "{message}"),
            other => panic!("a name not held was forgotten: {other:?}"),
        }
        for (service, name, credential) in [(OperatedService::Vault, "home", &home), (OperatedService::Relay, "gate", &gate)] {
            match tokio::time::timeout(WITHIN * 2, forget(&runtime, &users, "lee", service, name)).await.expect("bounded") {
                UserResponse::OperatorForgotten { name: n, service: s, key, answered } => {
                    assert_eq!((n.as_str(), s, answered), (name, service, false));
                    assert_eq!(key, hex::encode(credential.key.verifying_key().to_bytes()));
                }
                other => panic!("{name} was not forgotten: {other:?}"),
            }
        }
        assert!(held(&store).unwrap().is_empty());
    }

    /// **What a relay's answer says of the key** (decision 0006). A rule, or
    /// a request it read and refused, is given only to an operator: the key
    /// stands. *Not an operator of this relay*, the 403 its door refuses a key
    /// it does not hold with, is an unsigned answer any proxy on the path can
    /// give, so it is never read as the relay having answered: it is the relay
    /// not answering, and the forget says the revoke. Any other error, an
    /// unauthorised clock among them, and no answer, say nothing about the key
    /// from a relay that proved its key, and are refused as unsure; from one
    /// that proved none, nothing answered as the instance.
    #[test]
    fn a_relays_answer_is_the_key_standing_revoked_or_unsaid() {
        use kotton_net::rendezvous::RendezvousError;
        let rule = || Ok(RelayOperatorResponse::Rule { rule: AdmissionRule::OnlyMyDevices, mine_epoch: 0, invited_epoch: 0 });
        let http = |status| Err(RendezvousError::HttpError { status, body: "not an operator of this relay".into() });
        assert_eq!(relay_said(true, Some(rule())), Asked::Stands);
        assert_eq!(relay_said(true, Some(Ok(RelayOperatorResponse::Refused { reason: "no".into() }))), Asked::Stands);
        assert_eq!(relay_said(true, Some(http(403))), Asked::Silent, "an unsigned 403 was read as the relay answering");
        for said in [Some(rule()), Some(http(403)), Some(http(401)), None] {
            assert_ne!(relay_said(true, said), Asked::Answered, "a relay is never said to have answered");
        }
        assert!(matches!(relay_said(true, Some(http(401))), Asked::Unsure(_)), "an unauthorised clock is not a revoked key");
        assert!(matches!(relay_said(true, Some(http(502))), Asked::Unsure(_)));
        assert!(matches!(relay_said(true, Some(Err(RendezvousError::Clock("x".into())))), Asked::Unsure(_)));
        assert!(matches!(relay_said(true, None), Asked::Unsure(_)), "no answer from a relay that proved its key");
        assert_eq!(relay_said(false, Some(http(403))), Asked::Silent, "a 403 from a relay that proved no key is not the instance's");
        assert_eq!(relay_said(false, None), Asked::Silent);
        assert_eq!(relay_said(false, Some(rule())), Asked::Stands);
    }

    /// **What a vault's answer says of the key** (decision 0006). The read
    /// answered is the key standing; the vault refusing the key at its
    /// handshake is the key revoked there. A connection cut after the
    /// handshake, an error answered, an answer of another kind and no answer
    /// say nothing about the key, and are refused as unsure — never said as the
    /// vault having answered, which would print no revoke for a key that may
    /// still be enrolled.
    #[test]
    fn a_vaults_answer_is_the_key_standing_revoked_or_unsaid() {
        assert_eq!(vault_said(Some(Ok(UserResponse::VaultTenants { tenants: Vec::new() }))), Asked::Stands);
        let refused = anyhow::Error::new(kotton_peer::RefusedAtHandshake { alert: 42 }).context("read response length failed: aborted by peer");
        assert_eq!(vault_said(Some(Err(refused))), Asked::Answered);
        let cut = anyhow::anyhow!("read response length failed: closed by peer: 0");
        assert!(matches!(vault_said(Some(Err(cut))), Asked::Unsure(_)), "a cut wire was said as the vault answering");
        assert!(matches!(vault_said(Some(Ok(UserResponse::Error { message: "no".into() }))), Asked::Unsure(_)));
        assert!(matches!(vault_said(Some(Ok(UserResponse::Ok))), Asked::Unsure(_)));
        assert!(matches!(vault_said(None), Asked::Unsure(_)));
    }

    /// **`mint relay` twice is refused the second time, naming the spelling
    /// that works; a named mint is not.** A nameless mint is labelled by its kind's word; a second
    /// one of that kind, waiting or kept, is refused here, where the keys are,
    /// and leaves the first key as it was. A named mint again under a waiting
    /// name still replaces its key, and the other kind is not refused.
    #[test]
    fn a_second_nameless_mint_of_a_kind_is_refused_and_a_named_one_is_not() {
        let temp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(a_store(&temp));
        let users = UserRegistry::new();
        users.insert("lee".to_string(), store.clone());
        let key = |answer| match answer {
            UserResponse::OperatorMinted { name, key } => (name, key),
            other => panic!("{other:?}"),
        };
        let line = "you already hold a relay called relay; name this one (`mint relay <name>`)";
        let (label, first) = key(mint(&users, "lee", OperatedService::Relay, None, None));
        assert_eq!(label, "relay", "a nameless mint is labelled by its kind's word");
        match mint(&users, "lee", OperatedService::Relay, None, None) {
            UserResponse::Error { message } => assert_eq!(message, line),
            other => panic!("a second `mint relay` was minted: {other:?}"),
        }
        let waiting = |users: &UserRegistry| match mints(users, "lee") {
            UserResponse::OperatorMints { mints } => mints.into_iter().map(|m| (m.name, m.key)).collect::<Vec<_>>(),
            other => panic!("{other:?}"),
        };
        assert_eq!(waiting(&users), vec![("relay".to_string(), first.clone())], "the refusal replaced nothing");

        let (named, _) = key(mint(&users, "lee", OperatedService::Relay, Some("gate"), None));
        assert_eq!(named, "gate", "`mint relay gate` names it and is not refused");
        let (_, vault) = key(mint(&users, "lee", OperatedService::Vault, None, None));
        assert!(!vault.is_empty(), "the other kind is not refused");
        let (_, again) = key(mint(&users, "lee", OperatedService::Relay, Some("relay"), None));
        assert_ne!(again, first, "a named mint again under a waiting name replaces its key, as before");

        // Kept under the kind's word, a nameless mint is refused in the same line.
        spend_minted(&store, OperatedService::Relay, "relay").unwrap();
        keep_credentials(&store, &[a_relay("relay", "http://203.0.113.9:7700", [5u8; 32])]).unwrap();
        match mint(&users, "lee", OperatedService::Relay, None, None) {
            UserResponse::Error { message } => assert!(message.starts_with(line), "{message}"),
            other => panic!("a nameless relay over a kept one: {other:?}"),
        }
    }

    /// An invite with a number is the invite, then the number, for the same
    /// pool; without one it is the invite alone. The other three are one
    /// request each, and no verb becomes anything a tenant says.
    #[test]
    fn each_verb_is_the_vaults_request_of_the_same_meaning() {
        let with = requests_for(OperatorVerb::Invite {
            pool: "sam".into(),
            quota: Some(5),
            ttl_seconds: 60,
        });
        assert!(matches!(
            with.as_slice(),
            [UserRequest::DeviceInvite { user_id: a, ttl_seconds: 60, as_name: None }, UserRequest::SetQuota { user_id: b, quota: 5 }]
                if a == "sam" && b == "sam"
        ));
        let without = requests_for(OperatorVerb::Invite {
            pool: "sam".into(),
            quota: None,
            ttl_seconds: 60,
        });
        assert!(matches!(without.as_slice(), [UserRequest::DeviceInvite { .. }]));
        assert!(matches!(requests_for(OperatorVerb::Pools).as_slice(), [UserRequest::Tenants]));
        assert!(
            matches!(
                requests_for(OperatorVerb::Digits { pool: "sam".into() }).as_slice(),
                [UserRequest::InviteDigits { user_id }] if user_id == "sam"
            ),
            "the digits are asked of the vault for the pool named, and nothing else is said"
        );
        assert!(matches!(
            requests_for(OperatorVerb::SetQuota { pool: "sam".into(), quota: 9 }).as_slice(),
            [UserRequest::SetQuota { quota: 9, .. }]
        ));
        assert!(matches!(
            requests_for(OperatorVerb::Drop { pool: "sam".into() }).as_slice(),
            [UserRequest::DropTenant { .. }]
        ));
    }

    /// Drive an invite with a number through [`in_order`] against a vault that
    /// answers `invite` to the invite and `quota` to the number, and say what
    /// was sent and what came back.
    async fn an_invite_answered(invite: UserResponse, quota: UserResponse) -> (Vec<&'static str>, UserResponse) {
        let sent = std::sync::Mutex::new(Vec::new());
        let requests = requests_for(OperatorVerb::Invite {
            pool: "sam".into(),
            quota: Some(25),
            ttl_seconds: 60,
        });
        let answer = in_order(requests, |request| {
            sent.lock().unwrap().push(request.variant_name());
            let said = match &request {
                UserRequest::DeviceInvite { .. } => invite.clone(),
                UserRequest::SetQuota { .. } => quota.clone(),
                other => panic!("an invite sent {}", other.variant_name()),
            };
            async move { Ok(said) }
        })
        .await
        .expect("the fake vault answers");
        (sent.into_inner().unwrap(), answer)
    }

    /// **A refused invite resets nobody's number.** The vault refuses an invite naming a pool it already keeps;
    /// the number is asked for only after the invite is answered, so a refusal
    /// is the whole answer and no `SetQuota` is sent. An invite the vault mints
    /// is answered with the invite's text — not the number's readout, which
    /// comes second — and a number refused after it is what the landlord reads.
    #[tokio::test]
    async fn a_refused_invite_sends_no_number_and_a_minted_one_answers_with_the_invite() {
        let refusal = UserResponse::Error {
            message: "this vault already keeps for 'sam'".into(),
        };
        let minted = UserResponse::PairAdvertising {
            code: SecretText::new("http://relay#three-words-here"),
            expires_at: 1,
        };
        let readout = UserResponse::VaultCapacityResult { held: 0, quota: Some(25) };

        let (sent, answer) = an_invite_answered(refusal.clone(), readout.clone()).await;
        assert_eq!(sent, ["DeviceInvite"], "a refused invite sent the number after it");
        assert!(matches!(answer, UserResponse::Error { ref message } if message.contains("already keeps")));

        let (sent, answer) = an_invite_answered(minted.clone(), readout).await;
        assert_eq!(sent, ["DeviceInvite", "SetQuota"]);
        assert!(
            matches!(answer, UserResponse::PairAdvertising { ref code, .. } if code.expose().ends_with("three-words-here")),
            "the answer is the invite: {answer:?}"
        );

        let (_, answer) = an_invite_answered(minted, refusal).await;
        assert!(matches!(answer, UserResponse::Error { .. }), "a refused number is not hidden behind the invite");
    }

    /// **A credential that names the relay's key refuses another key at the
    /// address.** A named key the relay does not show, with nothing else shown, is kept as
    /// named; a key proved where none was named is recorded; one it could not
    /// prove refuses either way.
    #[test]
    fn an_enrol_that_names_the_relays_key_refuses_another() {
        use kotton_peer::relay_key::RelayKeyError;
        let (named, other) = ([1u8; 32], [2u8; 32]);
        let stranger = |shown: Option<[u8; 32]>| RelayKeyError::Stranger {
            url: "http://relay".into(),
            expected: hex::encode(named),
            shown: shown.map(hex::encode),
        };
        assert!(
            matches!(kotton_peer::relay_key::key_to_keep(Some(named), Err(stranger(Some(other)))), Err(RelayKeyError::Stranger { .. })),
            "another key at the address refuses the enrol"
        );
        assert_eq!(kotton_peer::relay_key::key_to_keep(Some(named), Err(stranger(None))), Ok(Some(named)), "a silent relay keeps the named key");
        assert_eq!(kotton_peer::relay_key::key_to_keep(Some(named), Ok(Some(named))), Ok(Some(named)));
        assert_eq!(kotton_peer::relay_key::key_to_keep(None, Ok(Some(other))), Ok(Some(other)), "first sight records what it proved");
        assert_eq!(kotton_peer::relay_key::key_to_keep(None, Ok(None)), Ok(None));
        let unproven = || RelayKeyError::NotProven { url: "http://relay".into(), why: "x".into() };
        assert!(kotton_peer::relay_key::key_to_keep(None, Err(unproven())).is_err(), "an unproven key refuses at first sight");
        assert!(kotton_peer::relay_key::key_to_keep(Some(named), Err(unproven())).is_err());
    }
}
