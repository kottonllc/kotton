// SPDX-License-Identifier: AGPL-3.0-or-later
//! An operator credential, as the desktop holds it.
//!
//! **A credential names one service — a vault or a relay — and how to reach
//! it, under a key of its own.** The server has two releases, two units and two
//! operator enrolments (`kvaultd operator enrol`, `kotton-relay operator
//! enrol`), and nothing on it answers to a name that spans both; so neither
//! does a credential. `mint vault <v>` and `mint relay <r>` make two keys.
//!
//! A credential is one `key=value` a line under a first line naming the form.
//! It is born in the person's own store: the mint makes the key and
//! keeps it there ([`minted_text`]), the instance is created for the public
//! half, and the enrol adds what the instance's line says
//! ([`complete_from_line`]).
//!
//! ```text
//! kotton-operator 2
//! name=<what the person calls it on this desktop>
//! operator=<64 hex: the secret key>
//! key=<64 hex: its public half, which the service enrolled>
//! # a vault's credential — `vault=` names the vault it operates:
//! vault=<64 hex: the vault's own public key>
//! addr=<the vault's address and peer port>     (where it is reached)
//! # a relay's credential — `relay=`, with no `vault=`, names the relay:
//! relay=<the relay's URL>
//! relay_key=<64 hex: the key the relay proved at the enrol>   (when it showed one)
//! rule=<only_my_devices | people_i_invite | anyone>
//! ```
//!
//! `relay_key=` is what the relay *is*: the key it proved when the desktop enrolled the credential,
//! with `relay=` beside it as where that key was last found.
//!
//! **A vault's credential names no relay.**
//! Which relays a vault stands at is what this desktop *told* it, kept in the
//! person's own store as a dated record by each relay's key — never a line a
//! vault printed and a person pasted, so the two services never meet by a URL.
//! Which one a credential is, is `vault=`: present, a vault's; absent, a
//! relay's. An older vault's credential carries a `relay=` line; it is read and
//! dropped, never written, so what the desktop kept still opens.
//!
//! `rule=` is the answer asked for once, at a relay's mint: who may use it. It
//! is a rule not yet set — the desktop sets it at the relay when it enrols the
//! credential, and keeps the credential without it once the relay has taken it.
//!
//! A vault's credential names nothing of any tenant's: no pool key, no chain,
//! no recovery copy. What it lets its holder say is the vault's decision
//! (`PeerStanding::Operator`), not this file's. Lines starting `#` are the
//! file's own words to a person and are skipped.
//!
//! **`kotton-operator 1` is refused, not migrated.** It named a
//! *box* — one credential spanning a vault and its relay under one key — and
//! [`FirstForm`] reads just enough of one for the desktop to drop it and say
//! how to re-make it and revoke its key at each service.

use crate::dialer::Dialer;
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::SigningKey;
use kotton_crypto::DidKeyMethod;
use kotton_wire::ipc::OperatedService;
use kotton_wire::peer::PairedNode;
use kotton_wire::rendezvous::AdmissionRule;
use std::net::SocketAddr;

/// The first line of every credential: the form, and its version.
pub const MAGIC: &str = "kotton-operator 2";

/// The first line of the refused form.
pub const FIRST_FORM: &str = "kotton-operator 1";

/// The line the refused form named its host on — read only to say which
/// credential was dropped, and never written.
pub const FIRST_FORM_NAME: &str = "box";

/// The line a minted key carries until the service is said, and which a
/// whole credential never carries — so a minted key does not read as one.
const OPERATES: &str = "operates";

/// What a credential operates, and how that service is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operates {
    /// A vault: its own key, and the address it announces. Where else it is
    /// reached is the relay this desktop told it to stand at, which is not the
    /// credential's to say.
    Vault {
        vault: [u8; 32],
        addr: Option<SocketAddr>,
    },
    /// A relay, by its URL, the key it proved when the credential was
    /// enrolled (`None` when it showed none), and the rule asked for at the
    /// mint that nobody has set there yet.
    Relay { url: String, key: Option<[u8; 32]>, rule: Option<AdmissionRule> },
}

/// One operator credential, read.
#[derive(Clone)]
pub struct OperatorCredential {
    /// The name the person gave it on this desktop, at the mint.
    pub name: String,
    /// The key the desktop speaks under. The service holds only its public half.
    pub key: SigningKey,
    /// The service it operates.
    pub operates: Operates,
}

/// Printed without the secret.
impl std::fmt::Debug for OperatorCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorCredential")
            .field("name", &self.name)
            .field("key", &hex::encode(self.key.verifying_key().to_bytes()))
            .field("operates", &self.operates)
            .finish()
    }
}

fn key32(name: &str, value: &str) -> Result<[u8; 32]> {
    hex::decode(value.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("`{name}=` is 64 hex characters"))
}

/// The first meaningful line of a credential's text.
fn first_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))
}

impl OperatorCredential {
    /// Read a credential, refusing one that is not whole: the secret must
    /// match the public half the service enrolled, a vault's must say where
    /// the vault is reached, and a relay's must name the relay.
    pub fn parse(text: &str) -> Result<Self> {
        let first = first_line(text);
        if first == Some(FIRST_FORM) {
            bail!("this operator credential is the `{FIRST_FORM}` form, which named one host for a vault and a relay together; it is no longer read");
        }
        if first != Some(MAGIC) {
            bail!("this is not an operator credential — its first line is `{MAGIC}`");
        }
        let lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).skip(1);
        let (mut name, mut secret, mut public, mut vault, mut addr, mut relay, mut rule, mut relay_key) =
            (None, None, None, None, None, None, None, None);
        for line in lines {
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("`{line}` is not a `key=value` line"))?;
            let slot = match k {
                "name" => &mut name,
                "operator" => &mut secret,
                "key" => &mut public,
                "vault" => &mut vault,
                "addr" => &mut addr,
                "relay" => &mut relay,
                "rule" => &mut rule,
                "relay_key" => &mut relay_key,
                OPERATES => bail!(
                    "this is a key minted here and not yet enrolled — the service has not been said"
                ),
                other => bail!("an operator credential has no `{other}=` line"),
            };
            if slot.replace(v.to_string()).is_some() {
                bail!("`{k}=` appears twice");
            }
        }
        let name = name.ok_or_else(|| anyhow!("the credential names nothing (`name=`)"))?;
        check_name(&name)?;
        let key = SigningKey::from_bytes(&key32(
            "operator",
            &secret.ok_or_else(|| anyhow!("the credential holds no key (`operator=`)"))?,
        )?);
        if let Some(public) = public {
            if key32("key", &public)? != key.verifying_key().to_bytes() {
                bail!("`operator=` is not the secret half of `key=` — the file was edited");
            }
        }
        let relay = relay.filter(|r| !r.is_empty());
        let operates = match vault {
            Some(vault) => {
                if rule.is_some() {
                    bail!("a vault's credential carries no `rule=` — the rule is its relay's");
                }
                if relay_key.is_some() {
                    bail!("a vault's credential carries no `relay_key=` — that line names a relay operated");
                }
                let vault = key32("vault", &vault)?;
                let addr = addr
                    .map(|a| a.parse::<SocketAddr>().map_err(|_| anyhow!("`addr=` is not an address and port")))
                    .transpose()?;
                // `relay=` on a vault's credential is the line an older form
                // carried: read, and dropped here, so a credential kept in it
                // still opens and is written back without it. Nothing reads
                // it — a vault stands where its owner's desktop told it.
                let _ = relay;
                if addr.is_none() {
                    bail!(
                        "the credential names no address to reach the vault at — a vault with no public address \
                         needs a meeting place for first contact, which 0.1 does not do \
                         (TASK-a-vault-with-no-public-address-meets-its-owner-at-a-relay-named-once)"
                    );
                }
                Operates::Vault { vault, addr }
            }
            None => {
                if addr.is_some() {
                    bail!("a relay's credential has no `addr=` — a relay is reached by its URL");
                }
                let url = relay.ok_or_else(|| {
                    anyhow!("the credential does not say what it operates yet — a vault's `vault=` line, or a relay's `relay=`")
                })?;
                Operates::Relay {
                    url,
                    key: relay_key.map(|k| key32("relay_key", &k)).transpose()?,
                    rule: rule.map(|r| parse_rule(&r)).transpose()?,
                }
            }
        };
        Ok(Self { name, key, operates })
    }

    /// Which service this credential operates.
    pub fn service(&self) -> OperatedService {
        match self.operates {
            Operates::Vault { .. } => OperatedService::Vault,
            Operates::Relay { .. } => OperatedService::Relay,
        }
    }

    /// The text [`parse`](Self::parse) reads — what the desktop keeps, sealed.
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "{MAGIC}\nname={}\noperator={}\nkey={}\n",
            self.name,
            hex::encode(self.key.to_bytes()),
            hex::encode(self.key.verifying_key().to_bytes()),
        );
        match &self.operates {
            Operates::Vault { vault, addr } => {
                out.push_str(&format!("vault={}\n", hex::encode(vault)));
                if let Some(a) = addr {
                    out.push_str(&format!("addr={a}\n"));
                }
            }
            Operates::Relay { url, key, rule } => {
                out.push_str(&format!("relay={url}\n"));
                if let Some(k) = key {
                    out.push_str(&format!("relay_key={}\n", hex::encode(k)));
                }
                if let Some(r) = rule {
                    out.push_str(&format!("rule={}\n", rule_name(*r)));
                }
            }
        }
        out
    }

    /// The vault as the dialer takes a peer: its key, where it answers, and
    /// `stands_at` — the address of the relay this desktop told it to stand at,
    /// from its own record, when it told it one. Never written to
    /// `paired_nodes` — the vault is the landlord's, not one of this person's
    /// devices. Refused for a relay's credential.
    pub fn vault_node(&self, stands_at: Option<&str>) -> Result<PairedNode> {
        let Operates::Vault { vault, addr } = &self.operates else {
            bail!("'{}' is a relay's credential, and a relay is not dialled as a peer", self.name);
        };
        Ok(PairedNode {
            id: self.name.clone(),
            device_did: DidKeyMethod::from_public_key_bytes(vault).map_err(|e| anyhow!("the vault's key: {e}"))?,
            public_key: *vault,
            paired_at: 0,
            addresses: addr.iter().copied().collect(),
            relay_url: stands_at.map(str::to_string),
            // It holds nothing of the person's, so nothing it answers is learned
            // as one of their own devices' keys (`RelayKeyring::learn_proven`).
            posture: Some(kotton_schemas::membership::Posture::BlindStorage.as_str().to_string()),
        })
    }

    /// A dialer that authenticates as this credential rather than as the
    /// device — the one connection a vault stands as its operator.
    pub fn dialer(
        &self,
        reachability: std::sync::Arc<crate::Reachability>,
        events: std::sync::Arc<kotton_diag::EventBus>,
    ) -> Dialer {
        Dialer::new(self.key.clone(), reachability, events)
    }
}

/// A credential's name, as a person typed it: no line break, no `/` and no
/// `=` in it, and no space, so it is one line of the form and one word.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.chars().any(|c| c.is_control() || c == '/' || c == '=' || c.is_whitespace()) {
        bail!("'{name}' is not a name for a vault or a relay — one word, no `/` or `=`");
    }
    Ok(())
}

/// A key just minted for the vault or the relay `name`, as the person's store
/// keeps it until the service is said: the form's first line, the
/// name, the secret and its public half, the service it waits for, and — for
/// a relay — its first rule, *only my devices* when none is given. It does not
/// read as a credential yet; [`complete`] makes it one. A vault's mint takes
/// no rule: the rule is the relay's.
pub fn minted_text(service: OperatedService, name: &str, key: &SigningKey, rule: Option<AdmissionRule>) -> Result<String> {
    check_name(name)?;
    let mut out = format!(
        "{MAGIC}\nname={name}\noperator={}\nkey={}\n{OPERATES}={}\n",
        hex::encode(key.to_bytes()),
        hex::encode(key.verifying_key().to_bytes()),
        service.word(),
    );
    match service {
        OperatedService::Vault if rule.is_some() => {
            bail!("a vault's key takes no rule — the rule is its relay's: `mint relay <r> --rule …`")
        }
        OperatedService::Vault => {}
        OperatedService::Relay => {
            out.push_str(&format!("rule={}\n", rule_name(rule.unwrap_or(AdmissionRule::OnlyMyDevices))));
        }
    }
    Ok(out)
}

/// The service and the name a text is for, and whether it holds a secret —
/// read before anything is parsed, so a service's half can be told from a
/// whole credential and a minted key found by what it waits for. A minted key
/// says its service on its `operates=` line; anything else is a vault's when
/// it has a `vault=` line, and a relay's otherwise.
pub fn service_name_and_secret(text: &str) -> (OperatedService, Option<String>, bool) {
    let mut name = None;
    let mut secret = false;
    let mut waits = None;
    let mut vault = false;
    for line in text.lines().map(str::trim) {
        if let Some(v) = line.strip_prefix("name=") {
            name.get_or_insert_with(|| v.to_string());
        } else if line.starts_with("operator=") {
            secret = true;
        } else if line.starts_with("vault=") {
            vault = true;
        } else if let Some(v) = line.strip_prefix("operates=") {
            waits = Some(if v == "relay" { OperatedService::Relay } else { OperatedService::Vault });
        }
    }
    let service = waits.unwrap_or(if vault { OperatedService::Vault } else { OperatedService::Relay });
    (service, name, secret)
}

/// A minted key and the service's half, made one credential. The
/// half is what [`complete_from_line`] reads off an instance's line: `name=`
/// and, for a vault, `vault=` and `addr=`; for a relay, `relay=` and
/// `relay_key=`. A half naming another name, or for the other service, is
/// refused by name. Everything else is refused by reading the whole back with
/// [`OperatorCredential::parse`], which is the one guard: a secret, a public
/// key or a rule in the half would be a second copy of a line the store
/// minted, and parse refuses a line that appears twice or one the form does
/// not have — so nothing in the half can override what was minted.
fn complete(minted: &str, half: &str) -> Result<String> {
    let (waits, minted_name, _) = service_name_and_secret(minted);
    let minted_name = minted_name.ok_or_else(|| anyhow!("the minted key names nothing"))?;
    let mut out = String::new();
    for line in minted.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if !line.starts_with("operates=") {
            out.push_str(line);
            out.push('\n');
        }
    }
    for line in half.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && *l != MAGIC) {
        match line.split_once('=') {
            Some(("name", v)) if v == minted_name => {}
            Some(("name", v)) => bail!("these lines are for '{v}', and the key was minted for '{minted_name}'"),
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    let whole = OperatorCredential::parse(&out)
        .map_err(|e| anyhow!("the lines do not complete the key minted for '{minted_name}': {e:#}"))?;
    if whole.service() != waits {
        bail!(
            "the key for '{minted_name}' was minted for a {}, and these lines are a {}'s",
            waits.word(),
            whole.service().word()
        );
    }
    Ok(out)
}

/// A minted key completed from the line its instance printed when it was
/// created: the line says which kind of instance it is,
/// where it is reached and its key, and the credential pins that key — a
/// vault's as `vault=`, the key the operator dial holds it to; a relay's as
/// `relay_key=`, the key it must prove. The line confers nothing; the minted
/// key is what operates, and it was this store's before the instance existed.
///
/// Refused for a line of the other kind than the key was minted for, and for
/// a line that names no address: an instance announcing none cannot be
/// reached from here, and a credential that names nowhere is no credential.
pub fn complete_from_line(minted: &str, line: &kotton_wire::line::InstanceLine) -> Result<String> {
    let (waits, name, _) = service_name_and_secret(minted);
    let name = name.ok_or_else(|| anyhow!("the minted key names nothing"))?;
    if line.kind != waits {
        bail!(
            "the key '{name}' was minted for a {}, and this is a {}'s line",
            waits.word(),
            line.kind.word()
        );
    }
    if line.hint.is_empty() {
        bail!(
            "the {}'s line names no address to reach it at — it announces none; give it its address and paste \
             the line it prints then",
            line.kind.word()
        );
    }
    let key = hex::encode(line.key);
    let half = match line.kind {
        OperatedService::Vault => format!("name={name}\nvault={key}\naddr={}\n", line.hint),
        OperatedService::Relay => format!("name={name}\nrelay={}\nrelay_key={key}\n", line.hint),
    };
    complete(minted, &half)
}

/// What the desktop reads of a `kotton-operator 1` credential, or of a key
/// minted in that form: enough to drop it and to say what to type at each
/// service. Nothing here is spoken under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstForm {
    /// The host it named.
    pub name: String,
    /// Its public key, 64 hex — what each service enrolled, and what to revoke.
    pub key: Option<String>,
}

/// Read `text` as the refused first form, or `None` when it is not that form.
pub fn first_form(text: &str) -> Option<FirstForm> {
    if first_line(text) != Some(FIRST_FORM) {
        return None;
    }
    let (mut name, mut key, mut secret) = (None, None, None);
    for line in text.lines().map(str::trim) {
        let Some((k, v)) = line.split_once('=') else { continue };
        let slot = match k {
            k if k == FIRST_FORM_NAME => &mut name,
            "key" => &mut key,
            "operator" => &mut secret,
            _ => continue,
        };
        slot.get_or_insert_with(|| v.to_string());
    }
    let key = key.or_else(|| public_of(secret.as_deref()?));
    Some(FirstForm {
        name: name.unwrap_or_default(),
        key,
    })
}

/// The public half of a secret spelled as `operator=` spells it, 64 hex.
fn public_of(secret: &str) -> Option<String> {
    key32("operator", secret)
        .ok()
        .map(|s| hex::encode(SigningKey::from_bytes(&s).verifying_key().to_bytes()))
}

/// What the desktop reads of a kept credential that does not read — said,
/// not logged: enough to drop
/// it and to say which it was, and what to revoke at its service. Nothing here
/// is spoken under, and nothing of why it does not read is kept — a line of a
/// file that no longer parses may be any line of it, the secret's included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unread {
    /// The service it operated, when a line says: `vault=` a vault's,
    /// `relay=` with no `vault=` a relay's. `None` when neither line is there.
    pub service: Option<OperatedService>,
    /// The name it was kept under, when it has a `name=` line.
    pub name: Option<String>,
    /// Its public key, 64 hex — what its service enrolled, and what to revoke
    /// there: the public half of `operator=` when that is a secret, since the
    /// service enrolled the half of the key that was minted; `key=` only when
    /// there is no secret to derive it from, because a damaged `key=` can
    /// still be 64 hex and would name a key nobody enrolled.
    pub key: Option<String>,
}

/// Read `text` as a kept credential that does not read, or `None` when it
/// reads — or is the refused first form, which [`first_form`] reads.
pub fn unread(text: &str) -> Option<Unread> {
    if first_line(text) == Some(FIRST_FORM) || OperatorCredential::parse(text).is_ok() {
        return None;
    }
    let (mut name, mut key, mut secret, mut vault, mut relay) = (None, None, None, false, false);
    for line in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k {
            "name" => {
                name.get_or_insert_with(|| v.to_string());
            }
            "key" => {
                key.get_or_insert_with(|| v.to_string());
            }
            "operator" => {
                secret.get_or_insert_with(|| v.to_string());
            }
            "vault" => vault = true,
            "relay" => relay = true,
            _ => {}
        }
    }
    let service = match (vault, relay) {
        (true, _) => Some(OperatedService::Vault),
        (false, true) => Some(OperatedService::Relay),
        (false, false) => None,
    };
    let key = secret
        .as_deref()
        .and_then(public_of)
        .or_else(|| key.filter(|k| key32("key", k).is_ok()));
    Some(Unread {
        service,
        name: name.filter(|n| !n.is_empty()),
        key,
    })
}

/// A rule as the credential spells it — the wire's own name for it.
pub fn rule_name(rule: AdmissionRule) -> &'static str {
    use AdmissionRule::*;
    match rule {
        OnlyMyDevices => "only_my_devices",
        PeopleIInvite => "people_i_invite",
        Anyone => "anyone",
    }
}

/// The inverse of [`rule_name`].
pub fn parse_rule(text: &str) -> Result<AdmissionRule> {
    use AdmissionRule::*;
    match text.trim() {
        "only_my_devices" => Ok(OnlyMyDevices),
        "people_i_invite" => Ok(PeopleIInvite),
        "anyone" => Ok(Anyone),
        other => bail!("`rule={other}` is not a rule — only_my_devices, people_i_invite or anyone"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_text(key: &SigningKey) -> String {
        format!(
            "{MAGIC}\n# words for a person\nname=kotton\noperator={}\nkey={}\nvault={}\naddr=203.0.113.9:7710\nrelay=http://203.0.113.9:7700\n",
            hex::encode(key.to_bytes()),
            hex::encode(key.verifying_key().to_bytes()),
            hex::encode([7u8; 32]),
        )
    }

    fn relay_text(key: &SigningKey) -> String {
        format!(
            "{MAGIC}\nname=kotton\noperator={}\nkey={}\nrelay=http://203.0.113.9:7700\n",
            hex::encode(key.to_bytes()),
            hex::encode(key.verifying_key().to_bytes()),
        )
    }

    /// **The rule asked for at a relay's mint rides in its credential and
    /// reads back**: each of the three spellings, round-tripped; a line that names no rule is
    /// refused rather than read as one; a relay's credential without the line
    /// carries no rule to set; and a vault's credential carries none at all.
    #[test]
    fn the_rule_asked_for_at_the_mint_reads_back_from_a_relays_credential() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        for (line, rule) in [
            ("only_my_devices", AdmissionRule::OnlyMyDevices),
            ("people_i_invite", AdmissionRule::PeopleIInvite),
            ("anyone", AdmissionRule::Anyone),
        ] {
            let c = OperatorCredential::parse(&format!("{}rule={line}\n", relay_text(&key))).expect("reads");
            assert!(matches!(c.operates, Operates::Relay { rule: Some(r), .. } if r == rule));
            let again = OperatorCredential::parse(&c.to_text()).unwrap();
            assert!(matches!(again.operates, Operates::Relay { rule: Some(r), .. } if r == rule));
            assert_eq!(serde_json::to_value(rule).unwrap(), serde_json::json!(rule_name(rule)));
        }
        assert!(OperatorCredential::parse(&format!("{}rule=everyone\n", relay_text(&key))).is_err());
        assert!(matches!(
            OperatorCredential::parse(&relay_text(&key)).unwrap().operates,
            Operates::Relay { rule: None, .. }
        ));
        assert!(
            OperatorCredential::parse(&format!("{}rule=anyone\n", vault_text(&key))).is_err(),
            "a vault's credential carries no rule"
        );
    }

    /// **`vault=` says which service a credential operates**: with it, a
    /// vault's — its `relay=`, a line of an older form, read and dropped; without it, a relay's, and `relay=` is the relay operated. Each
    /// writes back as it read.
    #[test]
    fn a_whole_credential_reads_and_writes_back_as_the_service_it_names() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let c = OperatorCredential::parse(&vault_text(&key)).expect("reads");
        assert_eq!(c.name, "kotton");
        assert_eq!(c.service(), OperatedService::Vault);
        assert_eq!(
            c.operates,
            Operates::Vault {
                vault: [7u8; 32],
                addr: Some("203.0.113.9:7710".parse().unwrap()),
            }
        );
        let again = OperatorCredential::parse(&c.to_text()).expect("reads its own text");
        assert_eq!(again.key.to_bytes(), key.to_bytes());
        assert_eq!(again.operates, c.operates);
        assert!(!format!("{c:?}").contains(&hex::encode(key.to_bytes())), "Debug hides the secret");

        let r = OperatorCredential::parse(&relay_text(&key)).expect("reads");
        assert_eq!(r.service(), OperatedService::Relay);
        assert!(r.vault_node(None).is_err(), "a relay is not dialled as a peer");
        assert_eq!(OperatorCredential::parse(&r.to_text()).unwrap().operates, r.operates);
    }

    /// **A key minted in the person's store becomes a credential with its
    /// service's lines, and only with them.** A vault's
    /// minted text carries no rule, a relay's carries *only my devices* when
    /// none was given, and neither reads as a credential until the service is
    /// said. The half may not carry a secret, a public key, a rule, another
    /// name, or the other service's lines, and the whole is read back.
    #[test]
    fn a_minted_key_is_completed_by_its_services_lines_and_nothing_else() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let vault = hex::encode([7u8; 32]);

        let minted = minted_text(OperatedService::Vault, "kotton", &key, None).expect("mints");
        assert!(!minted.contains("rule="), "{minted}");
        assert!(OperatorCredential::parse(&minted).is_err(), "a minted key names no service yet");
        assert_eq!(service_name_and_secret(&minted), (OperatedService::Vault, Some("kotton".into()), true));
        assert!(minted_text(OperatedService::Vault, "kotton", &key, Some(AdmissionRule::Anyone)).is_err());

        let half = format!("name=kotton\nvault={vault}\naddr=203.0.113.9:7710\n");
        assert_eq!(service_name_and_secret(&half), (OperatedService::Vault, Some("kotton".into()), false));
        let whole = complete(&minted, &half).expect("completes");
        let c = OperatorCredential::parse(&whole).unwrap();
        assert_eq!(c.key.to_bytes(), key.to_bytes());
        assert_eq!(c.service(), OperatedService::Vault);
        // A relay line is not where a vault is reached, so it alone reaches
        // nothing: a vault stands where the desktop tells it.
        assert!(complete(&minted, &format!("name=kotton\nvault={vault}\nrelay=http://r:7700\n")).is_err());
        // A relay's lines do not complete a vault's key.
        assert!(complete(&minted, "name=kotton\nrelay=http://r:7700\n").is_err());

        let relay = minted_text(OperatedService::Relay, "kotton", &key, None).expect("mints");
        assert!(relay.contains("rule=only_my_devices\n"), "{relay}");
        assert_eq!(service_name_and_secret(&relay).0, OperatedService::Relay);
        for (given, rule) in [(AdmissionRule::PeopleIInvite, "people_i_invite"), (AdmissionRule::Anyone, "anyone")] {
            assert!(minted_text(OperatedService::Relay, "kotton", &key, Some(given)).unwrap().contains(&format!("rule={rule}\n")));
        }
        let r = OperatorCredential::parse(&complete(&relay, "name=kotton\nrelay=http://r:7700\n").expect("completes")).unwrap();
        assert!(matches!(r.operates, Operates::Relay { ref url, key: None, rule: Some(AdmissionRule::OnlyMyDevices) } if url == "http://r:7700"));
        // A vault's lines do not complete a relay's key.
        assert!(complete(&relay, &half).is_err());
        // The key the relay proved rides beside its URL and survives the text
        // the desktop keeps;
        // a vault's credential carries none, and a malformed one is refused.
        let mut proved = r.clone();
        if let Operates::Relay { key, .. } = &mut proved.operates {
            *key = Some([5u8; 32]);
        }
        let text = proved.to_text();
        assert!(text.contains(&format!("relay_key={}\n", hex::encode([5u8; 32]))), "{text}");
        assert!(matches!(OperatorCredential::parse(&text).unwrap().operates, Operates::Relay { key: Some(k), .. } if k == [5u8; 32]));
        assert!(OperatorCredential::parse(&text.replace(&hex::encode([5u8; 32]), "zz")).is_err());
        assert!(complete(&minted, &format!("{half}relay_key={}\n", hex::encode([5u8; 32]))).is_err());

        let other = hex::encode(SigningKey::from_bytes(&[4u8; 32]).to_bytes());
        for bad in [
            format!("{half}operator={other}\n"),
            format!("{half}key={}\n", hex::encode([9u8; 32])),
            format!("{half}rule=anyone\n"),
            half.replace("name=kotton", "name=elsewhere"),
            "name=kotton\naddr=203.0.113.9:7710\n".to_string(),
            format!("{half}shelf=s3\n"),
            format!("{half}operates=relay\n"),
        ] {
            assert!(complete(&minted, &bad).is_err(), "{bad}");
        }
        for name in ["", "a/b", "a=b", "two words", "line\nbreak"] {
            assert!(minted_text(OperatedService::Vault, name, &key, None).is_err(), "{name:?}");
        }
    }

    /// **A minted key is completed from its instance's line, and the
    /// credential pins the line's key**: a vault's as the key
    /// its dial is held to, a relay's as the key it must prove. A line of the
    /// other kind, or one that names no address, completes nothing.
    #[test]
    fn a_minted_key_is_completed_from_its_instances_line_and_pins_its_key() {
        use kotton_wire::line::InstanceLine;
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let vault = minted_text(OperatedService::Vault, "kotton", &key, None).unwrap();
        let relay = minted_text(OperatedService::Relay, "gate", &key, None).unwrap();
        let v_line = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: [7; 32] };
        let r_line = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [5; 32] };

        let v = OperatorCredential::parse(&complete_from_line(&vault, &v_line).unwrap()).unwrap();
        assert_eq!((v.name.as_str(), v.key.to_bytes()), ("kotton", key.to_bytes()));
        assert_eq!(v.operates, Operates::Vault { vault: [7; 32], addr: Some("203.0.113.9:7710".parse().unwrap()) });
        let r = OperatorCredential::parse(&complete_from_line(&relay, &r_line).unwrap()).unwrap();
        assert_eq!(
            r.operates,
            Operates::Relay { url: "http://203.0.113.9:7700".into(), key: Some([5; 32]), rule: Some(AdmissionRule::OnlyMyDevices) }
        );

        assert!(complete_from_line(&vault, &r_line).unwrap_err().to_string().contains("this is a relay's line"));
        assert!(complete_from_line(&relay, &v_line).unwrap_err().to_string().contains("this is a vault's line"));
        let nowhere = InstanceLine { hint: String::new(), ..r_line };
        assert!(complete_from_line(&relay, &nowhere).unwrap_err().to_string().contains("names no address"));
    }

    #[test]
    fn a_credential_that_is_not_whole_is_refused() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let whole = vault_text(&key);
        let other = hex::encode(SigningKey::from_bytes(&[4u8; 32]).verifying_key().to_bytes());
        let cases = [
            whole.replacen(MAGIC, "kotton-operator 3", 1),
            whole.replacen(MAGIC, FIRST_FORM, 1),
            whole.replace(&hex::encode(key.verifying_key().to_bytes()), &other),
            whole
                .lines()
                .filter(|l| !l.starts_with("addr=") && !l.starts_with("relay="))
                .collect::<Vec<_>>()
                .join("\n"),
            whole.lines().filter(|l| !l.starts_with("vault=") && !l.starts_with("relay=")).collect::<Vec<_>>().join("\n"),
            format!("{whole}name=twice\n"),
            format!("{whole}shelf=s3\n"),
            format!("{}addr=203.0.113.9:7710\n", relay_text(&key)),
        ];
        for bad in cases {
            assert!(OperatorCredential::parse(&bad).is_err(), "{bad}");
        }
    }

    /// **The refused form is read only far enough to drop it and say what to
    /// revoke**: its host's name and its public key — from `key=`, or
    /// from the secret when a minted key had only that. A
    /// credential of the current form is not the first form.
    #[test]
    fn the_first_form_is_read_for_its_name_and_key_and_nothing_else() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let old = format!(
            "{FIRST_FORM}\nbox=kotton\noperator={}\nkey={public}\nvault={}\nrelay=http://r:7700\n",
            hex::encode(key.to_bytes()),
            hex::encode([7u8; 32])
        );
        assert_eq!(
            first_form(&old),
            Some(FirstForm { name: "kotton".into(), key: Some(public.clone()) })
        );
        let minted_then = format!("{FIRST_FORM}\nbox=attic\noperator={}\nrule=anyone\n", hex::encode(key.to_bytes()));
        assert_eq!(first_form(&minted_then).unwrap().key, Some(public));
        assert!(OperatorCredential::parse(&old).unwrap_err().to_string().contains(FIRST_FORM));
        assert_eq!(first_form(&vault_text(&key)), None);
    }

    /// **A kept credential that does not read is read only far enough to say
    /// which it was and what to revoke**: its
    /// service by `vault=` or `relay=`, its name, and its public key — from
    /// the secret when there is one, even when `key=` is 64 hex naming another
    /// key, and from `key=` only when there is no secret. One that reads is not
    /// unread, nor is the first form; one naming no service says so.
    #[test]
    fn a_credential_that_does_not_read_is_read_for_its_service_name_and_key() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let no_addr = vault_text(&key).replace("addr=203.0.113.9:7710\n", "");
        assert_eq!(
            unread(&no_addr),
            Some(Unread { service: Some(OperatedService::Vault), name: Some("kotton".into()), key: Some(public.clone()) })
        );
        let edited_key = relay_text(&key).replace(&format!("key={public}"), "key=not-a-key") + "colour=blue\n";
        assert_eq!(
            unread(&edited_key),
            Some(Unread { service: Some(OperatedService::Relay), name: Some("kotton".into()), key: Some(public.clone()) })
        );
        let damaged = vault_text(&key).replace(&format!("key={public}"), &format!("key={}", hex::encode([9u8; 32])));
        assert_eq!(unread(&damaged).unwrap().key, Some(public.clone()), "the secret names the key, not a damaged `key=`");
        let neither = format!("{MAGIC}\nname=attic\nkey={public}\n");
        assert_eq!(unread(&neither).unwrap().service, None);
        assert_eq!(unread(&neither).unwrap().key, Some(public.clone()), "with no secret, `key=` names it");
        assert_eq!(unread(&vault_text(&key)), None);
        assert_eq!(unread(&relay_text(&key)), None);
        assert_eq!(unread(&format!("{FIRST_FORM}\nbox=kotton\nkey={public}\n")), None);
    }

    /// **A vault's credential names no relay**: written without one; one kept before carries a `relay=` line, which is
    /// read and dropped, so it still opens and is written back without it; and
    /// the vault is dialled at the relay this desktop told it, not one it named.
    #[test]
    fn a_vaults_credential_names_no_relay_and_one_kept_with_a_relay_line_still_opens_without_it() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let vault = hex::encode(SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes());
        let kept_then = vault_text(&key).replace(&hex::encode([7u8; 32]), &vault);
        assert!(kept_then.contains("relay="), "the fixture is the form kept before");
        let c = OperatorCredential::parse(&kept_then).expect("a credential kept then still opens");
        let text = c.to_text();
        assert!(!text.contains("relay="), "{text}");
        assert_eq!(c.vault_node(None).unwrap().relay_url, None, "no relay is read from the credential");
        assert_eq!(
            c.vault_node(Some("http://told:7700")).unwrap().relay_url.as_deref(),
            Some("http://told:7700"),
            "the vault is reached where it was told to stand"
        );
        let no_addr: String = kept_then.lines().filter(|l| !l.starts_with("addr=")).map(|l| format!("{l}\n")).collect();
        assert!(
            OperatorCredential::parse(&no_addr).is_err(),
            "a relay line is no longer where a vault is reached, so a vault with no address has none"
        );
    }
}
