// SPDX-License-Identifier: AGPL-3.0-or-later
//! `vault` — and the operator half of `relay` — be the landlord of your own
//! vault and relay from this desktop, each under its own operator credential
//! (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`, DEC-0087).
//!
//! **Mint and enrol make one; relay and vault operate one.** Mint is the one
//! act that precedes the instance, so it leads with the verb and names the
//! kind as a word — `mint relay <r>`, `mint vault <v>` — and a bare `mint`
//! lists the keys minted and not yet enrolled
//! (`TASK-mint-prints-the-hosts-install-command-and-is-verb-first`). The
//! operating verbs stay noun-first on an instance that exists (`relay rule`,
//! `vault invite`). `relay mint` and `vault mint` are gone, not aliased.
//!
//! **The verbs are named for the service they act on.** On the server there
//! are two releases, two units and two operator enrolments, and nothing
//! answers to a name spanning both; so a credential names one service, and
//! `mint vault <v>` and `mint relay <r>` make two keys. `mint host` is the two
//! mints at once for the one machine that runs both: two keys still, one each,
//! printed into the one command the host's install takes, which ends on one
//! line naming both instances — `enrol` takes it as the two lines it is.
//!
//! **Each credential is born here** (DEC-0083). `mint vault <v>` makes its key
//! in your own store and prints the command the host runs to create the vault
//! for it — its public half inside, and nothing else of it (RFC-0084 V18; the
//! install, or with `--key` the half alone, for a host's provisioner) — and
//! creation returns the vault's line; `enrol <line>` pastes it back, and the
//! credential is whole — sealed in your store, the secret never having been
//! anywhere else. `mint relay <r>` is the same for the relay, and one `enrol`
//! takes both lines, in either order. The line confers nothing: it names the
//! instance's kind, where it is reached and its key, and the desktop holds the
//! instance to that key — a vault to the key it minted, too — before it keeps
//! anything (V21). `enrol` takes no name: the name was given at the mint, and the line
//! completes the one key waiting for its kind, asking which only when several
//! wait (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`).
//! A vault is where things are kept, so a vault's completion asks nothing
//! more: it runs `vault invite --me` for that vault, and the vault is recorded
//! as this person's drive, as the admit of a vault records one. Nothing is
//! synced then: `sync` syncs this device's drives when the person asks
//! (RFC 0002, Consequences; #57). A vault enrolled while this desktop operates
//! no relay stands nowhere, so that keep cannot meet; the relay's `enrol`
//! later stands it there, and then keeps the person's things at it, as the
//! vault's own enrol would have (#102). A vault that keeps them already says
//! so in its own answer to the invite, and that is said as the keep done, not
//! failed (#108).
//!
//! From then on the vault's four acts — invite someone with the space set
//! aside for them, list who keeps there, change one person's space, drop one
//! person — and the relay's rule are said from here, over the same sealed
//! channel your devices use for the vault and to the relay's `/operator`.
//! Nothing else is: a credential reads no one's data, and an invite it mints
//! admits a device blind, exactly as `kvaultd invite` does. Settings ›
//! Networking lists the vault as *Yours* once it is enrolled.
//!
//! **The two meet where your desktop introduced them**
//! (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`). A vault's
//! `enrol` tells the vault to stand at the relays you operate, and a relay's
//! tells every vault told nothing yet; `relay rule [<r>] <rule>` tells every vault you
//! told to stand at that relay again, with its keys — found by the relay's key,
//! never a URL — and `vault drop` rotates the invited key at each relay you
//! operate that the vault stands at. When the ceremony a vault's enrol runs
//! offers this device the relay the same `enrol` kept, this device stands
//! there too, held to that relay's key: the line was the person's own, typed
//! into this `enrol` ([`relays_kept`]).
//!
//! A drop is confirmed as the terminal confirms it: the landlord types the
//! pool's name back (`vault drop [<v>] <name> --confirm <name>`), as `kvaultd
//! drop` asks for it. The two are one act with two doors, and a door that
//! asked less would make the desktop's drop a different act from the
//! terminal's.
//!
//! **A verb names its instance only when there are several of its kind**
//! (decision 0005). The instances held of the verb's kind are read once for
//! the line ([`held_for`]) and decide whether its first word is a name
//! ([`operate`]): with one held the line need not name it, with several it
//! must, and a line that names none is then refused listing them — never
//! said to a guess.

use anyhow::Result;
use kotton_wire::ipc::{OperatedService, OperatorVerb, UserResponse};
use kotton_wire::rendezvous::AdmissionRule;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// A day, as `kvaultd invite` waits by default.
const INVITE_TTL_SECS: u64 = 24 * 60 * 60;

/// How long `vault invite [<v>] --me` gives its own invite: this desktop admits
/// it the moment it is minted, so it need outlive only the ceremony.
const INVITE_ME_TTL_SECS: u64 = 120;

/// The one line the help says of the setup verbs and the operating verbs
/// (the ruling of 2026-10-12 on
/// `IDEA-an-instance-is-set-up-in-three-pastes-and-nothing-is-typed-by-hand`).
pub(super) const MAKE_AND_OPERATE: &str = "mint and enrol make one; relay and vault operate one";

const VAULT_USAGE: &str = "usage: vault stand [<v>] | vault move [<v>] <r> | vault people [<v>] | \
                           vault invite [<v>] <name> [--space <bytes>] | vault invite [<v>] --me | vault digits [<v>] <name> | \
                           vault space [<v>] <name> <bytes> | vault drop [<v>] <name> --confirm <name> | \
                           vault forget [<v>] — <v> only when this desktop operates more than one vault; \
                           mint and enrol make one; relay and vault operate one: `mint vault`, then `enrol <line>`, makes one";

pub(super) const RELAY_OPERATOR_USAGE: &str = "relay rule [<r>] [<rule>] | relay invite [<r>] | relay forget [<r>] \
                                               — <r> only when this desktop operates more than one relay; \
                                               mint and enrol make one; relay and vault operate one: `mint relay`, then `enrol <line>`, makes one";

const ENROL_USAGE: &str = "usage: enrol <line> [<line>…] — the line each relay or vault printed when it was created, \
                           `kotton-instance:<relay|vault>:<key>@<address>`, space-separated or one per row; \
                           mint and enrol make one; relay and vault operate one";

const MINT_USAGE: &str = "usage: mint relay [<r>] [--rule only_my_devices|people_i_invite|anyone] [--rev <rev> | --key] | \
                          mint vault [<v>] [--rev <rev> | --key] | \
                          mint host [<h>] [--rule only_my_devices|people_i_invite|anyone] [--rev <rev> | --key] | mint \
                          — mint and enrol make one; relay and vault operate one";

/// The revision of the newest release this desktop knows — the newest `v*`
/// tag reachable from the commit it was built from, 12 hex, as the release
/// names its archives (`.github/workflows/release.yml`) — or empty when it was
/// built where no such tag is known (`client/shell/build.rs`).
const RELEASE_REV: &str = env!("KOTTON_RELEASE_REV");

/// [`RELEASE_REV`], when there is one.
fn release_rev() -> Option<&'static str> {
    (!RELEASE_REV.is_empty()).then_some(RELEASE_REV)
}

/// Where a host clones the release from: the distribution, which holds the
/// release tags and the assets a person installs, and whose tag holds the key
/// the release is checked against. It fetches this repository's archives by
/// its own release lock, so its tags are not this repository's, and a desktop
/// built here knows none of them: `mint host` prints a visible `<tag>`.
const REPOSITORY: &str = "https://github.com/kottonllc/kotton-dist";

/// The distribution's own release page, where a release's tag is read.
const RELEASES: &str = "https://github.com/kottonllc/kotton-dist/releases";

/// The installer a host runs, from the distribution's checkout: the directory
/// `git clone` of [`REPOSITORY`] makes, then `install.sh`.
const CHECKOUT_INSTALLER: &str = "kotton-dist/install.sh";

pub struct VaultCommand;

fn bytes(v: &str) -> Option<u64> {
    v.parse::<u64>().ok().filter(|n| *n > 0)
}

fn rule(v: &str) -> Option<AdmissionRule> {
    match v {
        "only_my_devices" => Some(AdmissionRule::OnlyMyDevices),
        "people_i_invite" => Some(AdmissionRule::PeopleIInvite),
        "anyone" => Some(AdmissionRule::Anyone),
        _ => None,
    }
}

/// The inverse of [`rule`]: a rule in the words it is typed in.
fn rule_word(r: AdmissionRule) -> &'static str {
    match r {
        AdmissionRule::OnlyMyDevices => "only_my_devices",
        AdmissionRule::PeopleIInvite => "people_i_invite",
        AdmissionRule::Anyone => "anyone",
    }
}

/// What an operator line asks for, decided before anything is sent: only a
/// [`Parsed::Speak`] reaches a service.
#[derive(Debug, PartialEq, Eq)]
enum Parsed<'a> {
    /// Mint a key for this service in the person's store, under the name
    /// given or else the kind's own word — a relay's with its first rule,
    /// `None` being *only my devices* — and print what [`Prints`] says.
    Mint(OperatedService, Option<&'a str>, Option<AdmissionRule>, Prints<'a>),
    /// Mint a relay's key and a vault's, as `Mint` mints each, under the
    /// name given or else each kind's word, the relay's with its first rule;
    /// and print what [`Prints`] says for a host that runs both.
    MintHost(Option<&'a str>, Option<AdmissionRule>, Prints<'a>),
    /// List the keys minted here and not yet enrolled.
    Mints,
    /// Say this verb to this vault or relay under its credential.
    Speak(To<'a>, OperatorVerb),
    /// Make this desktop a tenant of this vault, in one act (DEC-0086).
    InviteMe(To<'a>),
    /// Forget the credential kept for this relay or vault, once its instance
    /// no longer stands its key (decision 0006).
    Forget(OperatedService, To<'a>),
    /// Nothing is sent; this is why.
    Refuse(String),
}

/// The instance an operating verb is said to: the one the line names, or —
/// the line naming none — the one instance of its kind this desktop operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum To<'a> {
    /// Named on the line: `vault people home`.
    Named(&'a str),
    /// Named by nothing, and the one of its kind held here: `vault people`.
    Only(&'a str),
}

impl<'a> To<'a> {
    fn name(self) -> &'a str {
        match self {
            To::Named(n) | To::Only(n) => n,
        }
    }

    /// The instance as a line typed next names it: as this one did — by its
    /// name, or not at all.
    fn said(self) -> String {
        match self {
            To::Named(n) => format!(" {n}"),
            To::Only(_) => String::new(),
        }
    }
}

/// What a mint prints: the command the host runs, its archive named by the
/// revision given (`--rev`) or else the newest release this desktop knows; or
/// the public half alone (`--key`), for a provider that takes a key and not a
/// command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prints<'a> {
    Command(Option<&'a str>),
    Key,
}

/// A revision `--rev` takes: the hex a release names its archives by (7 to
/// 40 characters), with the `-dirty` an archive built from uncommitted
/// changes carries. Nothing else, since it is printed into a line run as root.
fn a_rev(r: &str) -> bool {
    let hex = r.strip_suffix("-dirty").unwrap_or(r);
    (7..=40).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `mint relay [<r>] [--rule <rule>] [--rev <rev> | --key]`, `mint vault
/// [<v>] [--rev <rev> | --key]`, `mint host [<h>] [--rule <rule>] [--rev <rev>
/// | --key]`, or a bare `mint`. The name is optional (the owner's amendment of
/// 2026-10-12): with none, the instance is named by its kind's word. A host's
/// rule is its relay's.
fn parse_mint<'a>(args: &[&'a str]) -> Parsed<'a> {
    let usage = || Parsed::Refuse(MINT_USAGE.into());
    // `None` is the host: a relay and a vault.
    let (service, rest) = match args {
        [] => return Parsed::Mints,
        ["relay", rest @ ..] => (Some(OperatedService::Relay), rest),
        ["vault", rest @ ..] => (Some(OperatedService::Vault), rest),
        ["host", rest @ ..] => (None, rest),
        _ => return usage(),
    };
    let (name, flags) = match rest {
        [name, flags @ ..] if !name.starts_with("--") => (Some(*name), flags),
        flags => (None, flags),
    };
    let word = service.map_or("host", OperatedService::word);
    let (mut rule, mut rev, mut key) = (None, None, false);
    let mut rest = flags;
    while !rest.is_empty() {
        rest = match rest {
            ["--rule", w, more @ ..] if rule.is_none() => match (service, self::rule(w)) {
                (Some(OperatedService::Vault), _) => {
                    return Parsed::Refuse(format!(
                        "mint vault: a rule is the relay's, not the vault's — `mint relay <r> --rule {w}`"
                    ))
                }
                (_, Some(r)) => {
                    rule = Some(r);
                    more
                }
                (_, None) => {
                    return Parsed::Refuse(format!(
                        "mint {word}: '{w}' is not a rule — only_my_devices, people_i_invite or anyone"
                    ))
                }
            },
            ["--rev", r, more @ ..] if rev.is_none() => {
                if !a_rev(r) {
                    return Parsed::Refuse(format!(
                        "mint {word}: '{r}' is not a revision — the hex in your build's archive name, \
                         kotton-{word}-<rev>-linux-x86_64.tar.gz"
                    ));
                }
                rev = Some(*r);
                more
            }
            ["--key", more @ ..] if !key => {
                key = true;
                more
            }
            _ => return usage(),
        };
    }
    let prints = match (key, rev) {
        (true, Some(_)) => {
            return Parsed::Refuse(format!(
                "mint {word}: --key prints the key alone and --rev names an archive in the command — say one"
            ))
        }
        (true, None) => Prints::Key,
        (false, rev) => Prints::Command(rev),
    };
    match service {
        Some(service) => Parsed::Mint(service, name, rule, prints),
        None => Parsed::MintHost(name, rule, prints),
    }
}

/// What a bare `mint` lists for the keys `waiting`: each by its kind, and by
/// its name only where its kind has more than one waiting or the name is not
/// the kind's own word (the owner's amendment of 2026-10-12).
fn waiting_rows(waiting: &[kotton_wire::ipc::MintWaiting]) -> Vec<Vec<String>> {
    waiting
        .iter()
        .map(|m| {
            let word = m.service.word();
            let several = waiting.iter().filter(|o| o.service == m.service).count() > 1;
            let name = if several || m.name != word { m.name.clone() } else { String::new() };
            vec![word.to_string(), name]
        })
        .collect()
}

/// `relay mint` and `vault mint`, refused with the spelling that replaced
/// them: gone, not aliased.
fn gone(service: OperatedService) -> Parsed<'static> {
    let word = service.word();
    Parsed::Refuse(format!(
        "`{word} mint` is now `mint {word} [<name>]` — {MAKE_AND_OPERATE}. A bare `mint` lists the keys minted and not yet enrolled."
    ))
}

/// `relay enrol` and `vault enrol`, refused with the spelling that replaced
/// them: gone, not aliased. The line says its kind and the mint gave the name.
fn gone_enrol(service: OperatedService) -> Parsed<'static> {
    let word = service.word();
    Parsed::Refuse(format!(
        "`{word} enrol` is now `enrol <line>` — the line says it is a {word}'s, and the name was given at the mint. \
         {MAKE_AND_OPERATE}."
    ))
}

/// What an operating verb's own words ask, before the instance it is said to
/// is known: the words after the verb, less the instance's name where the line
/// gives one.
#[derive(Debug)]
enum Act {
    Say(OperatorVerb),
    /// `vault invite --me`.
    InviteMe,
    /// `relay forget`, `vault forget`.
    Forget,
    /// `vault drop <name>` with nothing typed back: answered with how to
    /// confirm it, at the instance.
    Confirm(String),
    Refuse(String),
}

/// A vault's verb `verb` with `words` after it, or `None` when they are not
/// that verb's words. Each verb takes a count of words no two of which are
/// one apart, so a line with the vault's name and the same line without it are
/// never both a verb's words: a vault's line is never read two ways.
fn vault_act(verb: &str, words: &[&str]) -> Option<Act> {
    let flag = |name: &str| name.starts_with("--");
    let invite = |name: &str, quota| {
        Act::Say(OperatorVerb::Invite {
            pool: name.to_string(),
            quota,
            ttl_seconds: INVITE_TTL_SECS,
        })
    };
    Some(match (verb, words) {
        ("stand", []) => Act::Say(OperatorVerb::Stand),
        ("forget", []) => Act::Forget,
        ("move", [r]) => Act::Say(OperatorVerb::Move { relay: (*r).to_string() }),
        ("people", []) => Act::Say(OperatorVerb::Pools),
        ("digits", [name]) => Act::Say(OperatorVerb::Digits { pool: (*name).to_string() }),
        ("invite", ["--me"]) => Act::InviteMe,
        ("invite", [name] | [name, "--space", _]) if flag(name) => Act::Refuse(format!(
            "vault invite: '{name}' is not a person's name — `vault invite [<v>] <name>` invites someone, \
             `vault invite [<v>] --me` makes this desktop a tenant of the vault"
        )),
        ("invite", [name]) => invite(name, None),
        ("invite", [name, "--space", n]) => match bytes(n) {
            Some(q) => invite(name, Some(q)),
            None => Act::Refuse("vault invite: --space takes a number of bytes".into()),
        },
        ("space", [name, n]) => match bytes(n) {
            Some(q) => Act::Say(OperatorVerb::SetQuota {
                pool: (*name).to_string(),
                quota: q,
            }),
            None => Act::Refuse("vault space: the space is a number of bytes".into()),
        },
        ("drop", [name, "--confirm", typed]) if typed == name => Act::Say(OperatorVerb::Drop { pool: (*name).to_string() }),
        ("drop", [name, "--confirm", typed]) => Act::Refuse(format!("vault drop: '{typed}' is not '{name}' — not dropped")),
        ("drop", [name]) if !flag(name) => Act::Confirm((*name).to_string()),
        _ => return None,
    })
}

/// A relay's verb `verb` with `words` after it, or `None` when they are not
/// that verb's words. `rule` takes none or one, so `relay rule <word>` reads
/// two ways — the rule of the relay `<word>`, or `<word>` set on the one relay
/// — and [`operate`] settles it by the relays held: no relay is named for a
/// rule, so the word is one or the other.
fn relay_act(verb: &str, words: &[&str]) -> Option<Act> {
    Some(match (verb, words) {
        ("rule", []) => Act::Say(OperatorVerb::ReadRule),
        ("rule", [w]) => match rule(w) {
            Some(r) => Act::Say(OperatorVerb::SetRule { rule: r }),
            None => Act::Refuse(format!("relay rule: '{w}' is not a rule — only_my_devices, people_i_invite or anyone")),
        },
        ("invite", []) => Act::Say(OperatorVerb::RelayInvite),
        ("forget", []) => Act::Forget,
        _ => return None,
    })
}

/// The line `<kind> <verb> <words…>` said to its instance, or `None` when its
/// words are no form of the verb. The line names the instance first or not at
/// all, and `held` — the instances of the kind this desktop operates, read
/// once for the line — decides which it did and, where it named none, which
/// instance it means:
///
/// - a line that is the verb's words only with a name first is said to the
///   instance it names (the daemon refuses one it does not hold);
/// - a line that is the verb's words without a name is said to the one
///   instance of the kind held; with none held it says how one is made, and
///   with several it is refused in one line listing them and saying the named
///   form, and never guessed;
/// - a line that is both (`relay rule <word>`) is the named form when its
///   first word names an instance held, and the nameless one otherwise. A
///   relay is never minted under a rule's word (`operator::mint`), so a word
///   is never a relay held and a rule both.
fn operate<'a>(
    service: OperatedService,
    verb: &str,
    rest: &[&'a str],
    held: &'a [String],
    act: fn(&str, &[&str]) -> Option<Act>,
) -> Option<Parsed<'a>> {
    let word = service.word();
    let nameless = act(verb, rest);
    let named = match rest {
        [v, words @ ..] if !v.starts_with("--") => act(verb, words).map(|a| (*v, a)),
        _ => None,
    };
    let holds = |v: &str| held.iter().any(|h| h == v);
    let (to, act) = match (nameless, named) {
        (None, None) => return None,
        (_, Some((v, a))) if holds(v) => (To::Named(v), a),
        (None, Some((v, a))) => (To::Named(v), a),
        (Some(Act::Refuse(why)), _) => return Some(Parsed::Refuse(why)),
        (Some(a), _) => match held {
            [one] => (To::Only(one.as_str()), a),
            [] => {
                return Some(Parsed::Refuse(format!(
                    "{word} {verb}: this desktop operates no {word} — {MAKE_AND_OPERATE}: `mint {word}`, then `enrol <line>`"
                )))
            }
            several => {
                let at = match service {
                    OperatedService::Vault => "<v>",
                    OperatedService::Relay => "<r>",
                };
                let form = [word, verb, at].into_iter().chain(rest.iter().copied()).collect::<Vec<_>>().join(" ");
                return Some(Parsed::Refuse(format!(
                    "{word} {verb}: this desktop operates {} {word}s — {} — so the line names one: `{form}`",
                    several.len(),
                    several.join(", ")
                )));
            }
        },
    };
    Some(match act {
        Act::Say(verb) => Parsed::Speak(to, verb),
        Act::InviteMe => Parsed::InviteMe(to),
        Act::Forget => Parsed::Forget(service, to),
        Act::Confirm(name) => Parsed::Refuse(format!(
            "vault drop: this deletes {name}'s sealed pool, identity chain and sealed recovery copy at \
             '{}', and unpairs their devices; their data stays theirs, on their own devices. Type \
             the name back to drop them: vault drop{} {name} --confirm {name}",
            to.name(),
            to.said()
        )),
        Act::Refuse(why) => Parsed::Refuse(why),
    })
}

/// A `vault` line. `held` is the vaults this desktop operates, read once for
/// a line that opens with an operating verb.
fn parse_vault<'a>(args: &[&'a str], held: &'a [String]) -> Parsed<'a> {
    match args {
        ["mint", ..] => gone(OperatedService::Vault),
        ["enrol", ..] => gone_enrol(OperatedService::Vault),
        [verb, rest @ ..] => operate(OperatedService::Vault, verb, rest, held, vault_act).unwrap_or_else(|| Parsed::Refuse(VAULT_USAGE.into())),
        [] => Parsed::Refuse(VAULT_USAGE.into()),
    }
}

/// The relay's operator lines, or `None` for a line that is not one — the
/// relay's own `set`, `clear` and `status` stay `relay`'s. `held` is the
/// relays this desktop operates, read once for a line that opens with an
/// operating verb.
fn parse_relay<'a>(args: &[&'a str], held: &'a [String]) -> Option<Parsed<'a>> {
    Some(match args {
        ["mint", ..] => gone(OperatedService::Relay),
        ["enrol", ..] => gone_enrol(OperatedService::Relay),
        [verb @ ("rule" | "invite" | "forget"), rest @ ..] => operate(OperatedService::Relay, verb, rest, held, relay_act)
            .unwrap_or_else(|| Parsed::Refuse(format!("usage: {RELAY_OPERATOR_USAGE}"))),
        _ => return None,
    })
}

#[async_trait::async_trait]
impl Command for VaultCommand {
    fn help_text(&self) -> &'static str {
        "vault [stand [<v>] | move [<v>] <r> | people [<v>] | invite [<v>] <name> [--space <bytes>] | invite [<v>] --me | digits [<v>] <name> | space [<v>] <name> <bytes> | drop [<v>] <name> --confirm <name> | forget [<v>]] — the landlord's verbs for a vault of your own, and forget [<v>] for one whose host is gone; <v> only when this desktop operates more than one vault. mint and enrol make one; relay and vault operate one: `mint vault`, then `enrol <its line>`, makes one"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let held = held_for(state, OperatedService::Vault, &args).await?;
        run(parse_vault(&args, &held), state).await
    }
}

/// `mint` — make the key an instance is created for, and print the command
/// its host runs; bare, list the keys minted and not yet enrolled.
pub struct MintCommand;

#[async_trait::async_trait]
impl Command for MintCommand {
    fn help_text(&self) -> &'static str {
        "mint [relay [<r>] [--rule <rule>] | vault [<v>] | host [<h>] [--rule <rule>]] [--rev <rev> | --key] — make the key a relay or a vault of your own is created for, and print the command its host runs; host makes one of each, for one machine that runs both, and prints the one command it runs; with no name each is named by its kind; bare, list the keys minted and not yet enrolled. mint and enrol make one; relay and vault operate one"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run(parse_mint(&args), state).await
    }
}

/// `enrol <line> [<line>…]` — complete the keys minted here from the lines
/// their instances printed when they were created, each on its own; a vault's
/// then keeps this person's things, asking nothing (#57), and a relay's keeps
/// them at each vault it stood that could not keep them yet (#102).
pub struct EnrolCommand;

#[async_trait::async_trait]
impl Command for EnrolCommand {
    fn help_text(&self) -> &'static str {
        "enrol <line> [<line>…] — paste the line each relay or vault of your own printed when it was created, space-separated or one per row, in any order, or the one line a host printed, which names both: each completes the key minted for it, and says what it names, whether it is reached from here and whether its key matched; a vault's then keeps your things, sealed, as one of your drives — `sync` syncs them there when you ask — and this device stands at the relay the same enrol kept; a relay's keeps them at each vault it stands that does not keep them yet. mint and enrol make one; relay and vault operate one"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        enrol(&args.join(" "), state).await
    }
}

/// What `enrol` was given, read by the one parser for lines
/// (`InstanceLine::block`): the lines to send, each as it reads back, and a
/// readout for each word that is no line — said beside the rest, which are
/// completed all the same. `None` when nothing was given.
fn parse_enrol(text: &str) -> Option<(Vec<String>, Vec<kotton_wire::ipc::LineEnrolled>)> {
    use kotton_wire::ipc::{LineCame, LineEnrolled};
    let given = kotton_wire::line::InstanceLine::block(text);
    if given.is_empty() {
        return None;
    }
    let lines = given.iter().filter_map(|(_, l)| l.as_ref().ok().map(kotton_wire::line::InstanceLine::to_text)).collect();
    let words = given
        .into_iter()
        .filter_map(|(word, l)| l.err().map(|why| (word, why)))
        .map(|(word, why)| {
            let why = if word.contains(':') {
                why
            } else {
                format!("'{word}' is not a line — `enrol` takes no name: the name was given at the mint, and the line says its kind")
            };
            LineEnrolled {
                line: word,
                kind: None,
                hint: String::new(),
                dialled: false,
                reached: None,
                matched: None,
                came_to: LineCame::Refused { why },
            }
        })
        .collect();
    Some((lines, words))
}

/// `enrol`: send the lines, ask which where several keys of a kind wait, say
/// what each came to, then keep this person's things at each vault kept, and
/// at each vault a relay kept stood that does not keep them yet. Every decision is the
/// daemon's (`operator::enrol_lines`); this asks the person what only they
/// can answer, and sends their answer back as the line's `mint`.
async fn enrol(text: &str, state: &mut ShellState) -> Result<CommandOutput> {
    use kotton_wire::ipc::{LineCame, LineToEnrol};
    let Some((lines, not_lines)) = parse_enrol(text) else {
        return Ok(CommandOutput::fail(ENROL_USAGE, None));
    };
    let user_id = state.user_id.clone();
    let client = std::sync::Arc::clone(&state.client);
    let send = |lines: Vec<LineToEnrol>| {
        let client = std::sync::Arc::clone(&client);
        let user_id = user_id.clone();
        async move {
            let mut client = client.lock().await;
            client.operator_enrol_lines(&user_id, lines).await.map_err(|e| anyhow::anyhow!("enrol: {e}"))
        }
    };
    let mut came = if lines.is_empty() {
        Vec::new()
    } else {
        send(lines.iter().map(|l| LineToEnrol { line: l.clone(), mint: None }).collect()).await?
    };
    let mut out = Vec::new();
    // Which, line by line, and only then. Once one is answered, a line asked
    // about is sent again as it was first: the answer may have left one key
    // of its kind waiting, and then nothing is asked.
    let mut answered = false;
    for c in &mut came {
        if !matches!(c.came_to, LineCame::Which { .. }) {
            continue;
        }
        if answered {
            if let Some(again) = send(vec![LineToEnrol { line: c.line.clone(), mint: None }]).await?.pop() {
                *c = again;
            }
        }
        let LineCame::Which { names } = &c.came_to else { continue };
        let word = c.kind.map_or("instance", OperatedService::word);
        let question =
            format!("the {word} at {} was created for which key you minted for a {word} — {}?", c.hint, names.join(", "));
        let Some(answer) = state.ask(&mut out, &question)? else { continue };
        let answer = answer.trim().to_string();
        if !names.contains(&answer) {
            out.push(Out::Fail {
                what: format!("'{answer}' is not one of {} — the {word} at {} is not enrolled", names.join(", "), c.hint),
                try_: Some("`enrol` its line again".into()),
            });
            continue;
        }
        if let Some(chosen) = send(vec![LineToEnrol { line: c.line.clone(), mint: Some(answer) }]).await?.pop() {
            *c = chosen;
        }
        answered = true;
    }
    let mut all_kept = not_lines.is_empty() && came.iter().all(|c| matches!(c.came_to, LineCame::Kept { .. }));
    for c in not_lines.iter().chain(came.iter()) {
        out.push(Out::Record(readout(c)));
    }
    let relays = relays_kept(&came);
    for c in &came {
        if let (Some(OperatedService::Vault), LineCame::Kept { name, only, .. }) = (c.kind, &c.came_to) {
            all_kept &= keep_at(state, &mut out, name, *only, &relays).await;
        }
    }
    // A relay's enrol takes up the keep at each vault it stood that could
    // not keep yet, as that vault's own enrol would have (#102).
    let stood = stood_by_relays(&came);
    if !stood.is_empty() {
        let only = {
            let mut client = state.client.lock().await;
            client.operator_held(&state.user_id, OperatedService::Vault).await.is_ok_and(|held| held.len() == 1)
        };
        for vault in &stood {
            all_kept &= keep_at(state, &mut out, vault, only, &relays).await;
        }
    }
    let mut answer = CommandOutput::shapes(out);
    if !all_kept {
        answer.exit_code = crate::ExitCode::Code(1);
    }
    Ok(answer)
}

/// The keys of the relays this `enrol` kept: the relays whose lines the
/// person typed into it, which this device may stand at on their word
/// ([`super::device::relay_offer_taken`]).
fn relays_kept(came: &[kotton_wire::ipc::LineEnrolled]) -> Vec<[u8; 32]> {
    came.iter()
        .filter(|c| c.kind == Some(OperatedService::Relay) && matches!(c.came_to, kotton_wire::ipc::LineCame::Kept { .. }))
        .filter_map(|c| kotton_wire::line::InstanceLine::parse(&c.line).ok())
        .filter(|l| l.kind == OperatedService::Relay)
        .map(|l| l.key)
        .collect()
}

/// The vaults the relays this `enrol` kept told to stand there, each once and
/// in the order told — less any whose own line this `enrol` kept, whose keep
/// its own completion runs. A relay's completion names them
/// (`LineCame::Kept::stood`); a vault told nothing before stood nowhere, so its
/// keep could not meet, and this is where it is taken up (#102).
fn stood_by_relays(came: &[kotton_wire::ipc::LineEnrolled]) -> Vec<String> {
    use kotton_wire::ipc::LineCame;
    let kept_as_vaults: Vec<&str> = came
        .iter()
        .filter_map(|c| match (c.kind, &c.came_to) {
            (Some(OperatedService::Vault), LineCame::Kept { name, .. }) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let mut stood: Vec<String> = Vec::new();
    for c in came {
        let (Some(OperatedService::Relay), LineCame::Kept { stood: told, .. }) = (c.kind, &c.came_to) else { continue };
        for vault in told {
            if !kept_as_vaults.contains(&vault.as_str()) && !stood.contains(vault) {
                stood.push(vault.clone());
            }
        }
    }
    stood
}

/// What one line came to, in the three readouts it is read by — what it
/// names, whether it is reached from here, whether its key matched — and then
/// what was kept, or why not, or what is asked.
fn readout(c: &kotton_wire::ipc::LineEnrolled) -> Vec<(String, String)> {
    use kotton_wire::ipc::LineCame;
    let names = match c.kind {
        Some(kind) => {
            let key = c.line.rsplit_once('@').map(|(head, _)| head).and_then(|h| h.rsplit(':').next()).unwrap_or("");
            let at = if c.hint.is_empty() { "no address".to_string() } else { c.hint.clone() };
            format!("a {} at {at}, key {}…", kind.word(), key.get(..8).unwrap_or(key))
        }
        None => format!("no line: {}", c.line),
    };
    let yes_no = |v: Option<bool>, yes: &str, no: &str, unasked: &str| match v {
        Some(true) => yes.to_string(),
        Some(false) => no.to_string(),
        None => unasked.to_string(),
    };
    let (unreached, unmatched) = if c.dialled { ("could not be told", "could not be told") } else { ("not dialled", "not checked") };
    let mut rows = vec![
        ("names".to_string(), names),
        ("reached from here".to_string(), yes_no(c.reached, "yes", "no — nothing answered there", unreached)),
        ("its key".to_string(), yes_no(c.matched, "matched", "did not match", unmatched)),
    ];
    match &c.came_to {
        LineCame::Kept { name, unstood, stood, .. } => {
            let word = c.kind.map_or("instance", OperatedService::word);
            let named = if name == word { String::new() } else { format!(" '{name}'") };
            rows.push(("enrolled".into(), format!("you operate the {word}{named}; its credential is sealed in your store")));
            rows.extend(self::unstood(&kotton::KeptCredential { name: name.clone(), unstood: unstood.clone() }));
            if !stood.is_empty() {
                let vaults: Vec<String> = stood.iter().map(|v| format!("the vault '{v}'")).collect();
                rows.push(("told to stand here".into(), vaults.join(", ")));
            }
        }
        LineCame::Which { names } => rows.push((
            "not enrolled".into(),
            format!(
                "several keys wait for a {} — {} — and the line does not say which it was created for; `enrol` at a terminal asks",
                c.kind.map_or("instance", OperatedService::word),
                names.join(", ")
            ),
        )),
        LineCame::Refused { why } => rows.push(("not enrolled".into(), why.clone())),
    }
    rows
}

/// A vault's completion keeps this person's things there, and asks nothing
/// (RFC 0002, Consequences: "a vault is where things are kept"; #57): this
/// desktop becomes a tenant of the vault `vault` — `vault invite --me`, whose
/// admit records the vault as the person's drive — and nothing is synced
/// now; `sync` syncs this device's drives when the person asks. When the
/// ceremony offers this device a relay among `relays` — the ones this `enrol`
/// kept — this device stands there, held to its key, rather than being told
/// the `relay set` that would. `false` when the vault does not keep them —
/// one that stands at no relay, so its invite has nowhere to meet, or an
/// invite or ceremony that failed — said as a failure naming why and the
/// `vault invite [<v>] --me` that takes it up. The enrol then exits non-zero:
/// a vault is where things are kept, and a vault's enrol that keeps nothing
/// has not done what enrol does, though its credential is kept. Nothing in a
/// keep aborts the enrol: its readouts are said whatever the keep came to. A
/// relay's enrol that stands such a vault takes the keep up there, by this
/// same act ([`stood_by_relays`]; #102). A vault that keeps this person's
/// things already answers the invite so, in its own typed word
/// ([`kotton::InvitedMe::KeptAlready`]), and mints nothing: that is the keep
/// done, said ([`kept_already`]) and `true` (#108). Whom a vault keeps for is
/// the vault's to say, so nothing here reads its people to guess it.
async fn keep_at(state: &mut ShellState, out: &mut Vec<Out>, vault: &str, only: bool, relays: &[[u8; 32]]) -> bool {
    let to = if only { To::Only(vault) } else { To::Named(vault) };
    let not_kept = |why: String| Out::Fail {
        what: format!("your things are not kept at the vault: {why}"),
        try_: Some(format!("`vault invite{} --me`", to.said())),
    };
    let user_id = state.user_id.clone();
    let invited = {
        let mut client = state.client.lock().await;
        client.vault_invite_me_stream(&user_id, vault, INVITE_ME_TTL_SECS).await
    };
    let mut rx = match invited {
        Ok(kotton::InvitedMe::Admitting(rx)) => rx,
        Ok(kotton::InvitedMe::KeptAlready) => {
            out.push(kept_already(vault));
            return true;
        }
        Err(e) => {
            out.push(not_kept(e.to_string()));
            return false;
        }
    };
    let ceremony = {
        let client = state.client.lock().await;
        super::device::run_ceremony_to(&client, &user_id, &mut rx, super::device::Role::OwnVault, None, relays).await
    };
    // A ceremony that errs — its confirm refused on the wire — is a keep
    // that did not happen, said beside the readouts, never an abort of them.
    let (said, node, stand) = match ceremony {
        Ok(done) => done,
        Err(e) => {
            out.push(not_kept(format!("{e:#}")));
            return false;
        }
    };
    out.extend(said.out);
    let kept = node.is_some();
    match said.stderr {
        Some(why) => out.push(not_kept(why)),
        None if !kept => out.push(not_kept("the admit ended before it completed".into())),
        None => {}
    }
    if let Some(line) = stand {
        let mut client = state.client.lock().await;
        out.push(stood_at(client.relay_stand(&user_id, &line).await, &line));
    }
    kept
}

/// What a keep at the vault `vault` says when the vault keeps this person's
/// things already: the act's done state, said, never a failure (#108).
fn kept_already(vault: &str) -> Out {
    Out::Note(format!("your things are kept at the vault '{vault}' already — it keeps for you, so nothing was invited"))
}

/// What standing this device at the relay `line` came to: stood there, held
/// to its key, or not, with the `relay set` that does it.
fn stood_at(stood: std::io::Result<()>, line: &str) -> Out {
    let at = kotton_wire::line::InstanceLine::parse(line).map(|l| l.hint).unwrap_or_default();
    match stood {
        Ok(()) => Out::Confirm {
            action: "this device stands at your relay too, held to its key — your other devices reach it away from this network".into(),
            subject: at,
        },
        Err(e) => Out::Fail {
            what: format!("this device does not stand at your relay at {at}: {e}"),
            try_: Some(format!("`relay set {line}`")),
        },
    }
}

/// The relay's operator verbs, for `relay` to hand a line to: `None` when the
/// line is not one of them.
pub(super) async fn relay_operator(args: &[&str], state: &mut ShellState) -> Option<Result<CommandOutput>> {
    let held = match held_for(state, OperatedService::Relay, args).await {
        Ok(held) => held,
        Err(e) => return Some(Err(e)),
    };
    let parsed = parse_relay(args, &held)?;
    Some(run(parsed, state).await)
}

/// The words that open a vault's operating verbs, and a relay's.
const VAULT_VERBS: &[&str] = &["stand", "move", "people", "digits", "invite", "space", "drop", "forget"];
const RELAY_VERBS: &[&str] = &["rule", "invite", "forget"];

/// The names of the instances of `service` this desktop operates, read from
/// the daemon once for a line that opens with one of that kind's operating
/// verbs, and not at all for any other line: how many there are decides
/// whether the line must name one ([`operate`]). The daemon still refuses a
/// name it does not hold, at the act.
async fn held_for(state: &ShellState, service: OperatedService, args: &[&str]) -> Result<Vec<String>> {
    let verbs = match service {
        OperatedService::Vault => VAULT_VERBS,
        OperatedService::Relay => RELAY_VERBS,
    };
    if !args.first().is_some_and(|w| verbs.contains(w)) {
        return Ok(Vec::new());
    }
    let mut client = state.client.lock().await;
    client
        .operator_held(&state.user_id, service)
        .await
        .map_err(|e| anyhow::anyhow!("{}: {e}", service.word()))
}

async fn run(parsed: Parsed<'_>, state: &mut ShellState) -> Result<CommandOutput> {
    let user_id = state.user_id.clone();
    let (to, verb) = match parsed {
        Parsed::Mint(service, n, rule, prints) => {
            let word = service.word();
            let mut client = state.client.lock().await;
            // A mint with no name is sent with none: the daemon labels it by
            // its kind's word, and refuses a second of the kind there.
            let key = client
                .operator_mint(&user_id, service, n, rule)
                .await
                .map_err(|e| anyhow::anyhow!("mint {word}: {e}"))?;
            return Ok(CommandOutput::shapes(minted(service, n, &key, prints, release_rev())));
        }
        Parsed::MintHost(n, rule, prints) => {
            let mut client = state.client.lock().await;
            // Two mints, the relay's first, each as its own `mint` would be
            // sent: a refusal is the daemon's, and a refused second leaves
            // the first waiting, which is said.
            let relay = client
                .operator_mint(&user_id, OperatedService::Relay, n, rule)
                .await
                .map_err(|e| anyhow::anyhow!("mint host: the relay's key: {e}"))?;
            let vault = match client.operator_mint(&user_id, OperatedService::Vault, n, None).await {
                Ok(key) => key,
                Err(e) => {
                    return Ok(CommandOutput::fail(
                        format!("mint host: the vault's key was refused: {e} — the relay's key is minted and waits"),
                        Some("a bare `mint` lists the keys waiting".into()),
                    ))
                }
            };
            return Ok(CommandOutput::shapes(minted_host(n, &relay, &vault, prints)));
        }
        Parsed::Mints => {
            let mut client = state.client.lock().await;
            let mints = client.operator_mints(&user_id).await.map_err(|e| anyhow::anyhow!("mint: {e}"))?;
            return Ok(CommandOutput::shapes(vec![Out::Table {
                columns: vec!["kind".into(), "name".into()],
                rows: waiting_rows(&mints),
            }]));
        }
        Parsed::InviteMe(to) => {
            // Minted over the operator channel for the user this shell acts
            // as — what `whoami` prints — and admitted here, held to the vault
            // key the credential pins. No words, no digits.
            let invited = {
                let mut client = state.client.lock().await;
                client
                    .vault_invite_me_stream(&user_id, to.name(), INVITE_ME_TTL_SECS)
                    .await
                    .map_err(|e| anyhow::anyhow!("vault invite --me: {e}"))?
            };
            // A vault that keeps this person's things already has done what
            // `--me` asks: said, not failed (#108).
            let mut rx = match invited {
                kotton::InvitedMe::Admitting(rx) => rx,
                kotton::InvitedMe::KeptAlready => return Ok(CommandOutput::shapes(vec![kept_already(to.name())])),
            };
            let client = state.client.lock().await;
            return super::device::run_ceremony(&client, &user_id, &mut rx, super::device::Role::OwnVault, None)
                .await;
        }
        Parsed::Forget(service, to) => {
            let word = service.word();
            let mut client = state.client.lock().await;
            // A refusal — the instance still stands the key, or none is held
            // under the name — is said as a failure, as a verb's is.
            return Ok(match client.operator_forget(&user_id, service, to.name()).await {
                Ok(gone) => CommandOutput::shapes(forgotten(&gone)),
                Err(e) => CommandOutput::fail(format!("{word} forget: {e}"), None),
            });
        }
        Parsed::Speak(to, verb) => (to, verb),
        Parsed::Refuse(why) => return Ok(CommandOutput::fail(why, None)),
    };
    let asked = verb.clone();
    let mut client = state.client.lock().await;
    let answer = client
        .as_operator(&user_id, to.name(), verb)
        .await
        .map_err(|e| anyhow::anyhow!("{}: {e}", asked.service().word()))?;
    Ok(spoken(&asked, to, answer))
}

/// What a verb said to the instance `to` comes to, read from the answer it
/// was given: each verb acts on the one answer it asked for, and on no other.
///
/// **No list of refusals, and no answer read as another verb's** (#121). Any
/// answer that is not the one `asked` asks for — the daemon's or the vault's
/// `Error`, a name the vault keeps (`VaultKeepsAlready`, refused here as
/// everywhere but `--me`, #108), an answer meant for another verb, or one a
/// later release adds — is a failure said in
/// [`kotton_wire::ipc::answer_said`]: the vault's words where the answer
/// carries them, its name where not, and never its fields.
fn spoken(asked: &OperatorVerb, to: To<'_>, answer: UserResponse) -> CommandOutput {
    let word = asked.service().word();
    match (asked, answer) {
        (OperatorVerb::Invite { pool, .. }, UserResponse::PairAdvertising { code, .. }) => {
            CommandOutput::shapes(vec![Out::Record(vec![
                ("invite".into(), code.expose().to_string()),
                ("on their device".into(), "drive enrol <invite>".into()),
                (
                    "the six digits".into(),
                    format!("`vault digits{} {pool}` once their device asks for them; read them out", to.said()),
                ),
            ])])
        }
        (OperatorVerb::Digits { pool }, UserResponse::InviteDigits { digits }) => {
            CommandOutput::shapes(vec![Out::Record(digits_said(pool, &digits))])
        }
        (OperatorVerb::Pools, UserResponse::VaultTenants { tenants }) => CommandOutput::shapes(vec![Out::Table {
            columns: vec!["name".into(), "held (bytes)".into(), "space (bytes)".into(), "devices".into()],
            rows: tenants
                .into_iter()
                .map(|t| {
                    vec![
                        t.user_id,
                        t.held.to_string(),
                        t.quota.map_or_else(|| "none".to_string(), |q| q.to_string()),
                        t.devices.to_string(),
                    ]
                })
                .collect(),
        }]),
        (OperatorVerb::SetQuota { .. }, UserResponse::VaultCapacityResult { held, quota }) => {
            CommandOutput::shapes(vec![Out::Record(vec![
                ("held (bytes)".into(), held.to_string()),
                ("space (bytes)".into(), quota.map_or_else(|| "none".to_string(), |q| q.to_string())),
            ])])
        }
        (OperatorVerb::Drop { .. }, UserResponse::TenantDropped { tenant }) => CommandOutput::shapes(vec![Out::Confirm {
            action: format!("dropped — {} bytes, {} device(s) unpaired", tenant.held, tenant.devices),
            subject: tenant.user_id,
        }]),
        (OperatorVerb::ReadRule | OperatorVerb::SetRule { .. }, UserResponse::RelayRule { rule }) => {
            CommandOutput::shapes(vec![Out::Record(vec![("rule".into(), rule_word(rule).to_string())])])
        }
        // The relay's invite, in the one code grammar: the person pastes it at
        // their Settings door, or names it to `relay set` at a terminal.
        (OperatorVerb::RelayInvite, UserResponse::RelayInvite { invite }) => CommandOutput::shapes(vec![Out::Record(vec![
            ("invite".into(), invite.expose().to_string()),
            ("on their device".into(), "paste it at Settings' door, or `relay set <invite>`".into()),
        ])]),
        (OperatorVerb::Stand | OperatorVerb::Move { .. }, UserResponse::Ok) => CommandOutput::shapes(vec![Out::Confirm {
            action: "told where to stand".into(),
            subject: to.name().to_string(),
        }]),
        (_, unread) => CommandOutput::fail(format!("{word}: {}", kotton_wire::ipc::answer_said(&unread)), None),
    }
}

/// What `vault digits [<v>] <name>` says: the six digits the ceremony `name`'s
/// device is in derived — the ones it asks them to type, read to them from
/// here — or that no device has dialled the invite yet. An invite admits one
/// dial, so there is one set per invite minted under the name that a device
/// has dialled, and more than one says so.
fn digits_said(pool: &str, digits: &[u32]) -> Vec<(String, String)> {
    match digits {
        [] => vec![(
            "digits".into(),
            format!("none yet: no device is waiting under an invite for {pool}"),
        )],
        [one] => vec![
            ("digits".into(), super::device::format_sas(*one)),
            ("read them to".into(), pool.to_string()),
        ],
        several => {
            let mut said: Vec<(String, String)> =
                several.iter().map(|d| ("digits".to_string(), super::device::format_sas(*d))).collect();
            said.push((
                "read them to".into(),
                format!(
                    "{pool} — one set per invite minted under this name that a device has dialled: {} \
                     invites for {pool} are waiting",
                    several.len()
                ),
            ));
            said
        }
    }
}

/// The lines a kept credential adds when its vault could not be told where to
/// stand: the credential is kept
/// (the line above these says so first), the vault stands at no relay yet and
/// why, and the act that stands it for that cause, read from the cause the
/// daemon sent (`Unstood::acts`), never from the sentence — one act per relay
/// the vault was told of, the ones that can be held again first, each under
/// its address. Nothing when it was told.
fn unstood(kept: &kotton::KeptCredential) -> Vec<(String, String)> {
    let Some(u) = &kept.unstood else { return Vec::new() };
    let acts = u.acts(&kept.name);
    let one = acts.len() == 1;
    let mut lines = vec![("not yet standing".into(), format!("the vault is not yet standing at a relay: {}", u.reason))];
    lines.extend(acts.into_iter().map(|(at, act)| match at {
        Some(at) if !one => (format!("at {at}"), act),
        _ => ("to stand it".into(), act),
    }));
    lines
}

/// What `relay forget` and `vault forget` say of a credential forgotten: that
/// it is, whether its instance answered when it was asked, and how to make one
/// again under the same name. An instance that did not answer may still run
/// somewhere, its key enrolled there until it is revoked there, so the revoke
/// is said with the key in it; one that answered no longer stands the key.
fn forgotten(gone: &kotton::ForgottenCredential) -> Vec<Out> {
    let word = gone.service.word();
    let answered = if gone.answered {
        format!("yes, and the {word} no longer stands this key as its operator")
    } else {
        format!(
            "no — if the {word} still runs somewhere, this key stays enrolled there until you revoke it: `{}`",
            revoke_at(gone.service, &gone.key)
        )
    };
    let again = if gone.name == word { format!("`mint {word}`") } else { format!("`mint {word} {}`", gone.name) };
    vec![
        Out::Confirm { action: "forgotten".into(), subject: gone.name.clone() },
        Out::Record(vec![("answered".into(), answered), ("to make it again".into(), again)]),
    ]
}

/// The revoke of `key` at a running instance's shell, in the form its guide
/// types the enrol ([`at_the_vault`], [`at_the_relay`]).
fn revoke_at(service: OperatedService, key: &str) -> String {
    match service {
        OperatedService::Vault => format!("kvaultd operator revoke {key}"),
        OperatedService::Relay => {
            format!("runuser -u kotton-relay -- kotton-relay --state-dir /var/lib/kotton-relay operator revoke {key}")
        }
    }
}

/// What a mint prints for the key `key` it minted for the `service` named
/// `name`, or by its kind's word when none was given. With [`Prints::Key`], the public half alone. Otherwise the whole
/// command the host runs ([`to_create`]), verbatim on a line of its own, its
/// archive named by the revision given or else `known`, the newest release this
/// desktop knows; with neither, a visible `<rev>` and one line saying to put
/// the release's revision there — never a revision nobody named. Then the
/// line for an instance of that kind that runs already, and the enrol that
/// completes it here.
fn minted(service: OperatedService, name: Option<&str>, key: &str, prints: Prints<'_>, known: Option<&str>) -> Vec<Out> {
    let word = service.word();
    let said = name.map(|n| format!(" {n}")).unwrap_or_default();
    let rev = match prints {
        Prints::Key => return vec![Out::Data(key.to_string())],
        Prints::Command(given) => given.or(known),
    };
    let mut out = vec![
        Out::Note(format!("On the host, as root, beside the unpacked kotton-{word}-{}-linux-x86_64.tar.gz:", rev.unwrap_or("<rev>"))),
        Out::Data(to_create(service, key, rev)),
    ];
    if rev.is_none() {
        out.push(Out::Hint(format!(
            "this desktop knows no release: put the release's revision where <rev> is, or `mint {word}{said} --rev <rev>` for your own build"
        )));
    }
    let at = match service {
        OperatedService::Vault => at_the_vault(key),
        OperatedService::Relay => at_the_relay(key),
    };
    out.push(Out::Record(vec![
        (format!("a {word} you run already"), at),
        ("then here".into(), "enrol <the line its creation printed>".to_string()),
    ]));
    out
}

/// What `mint host` prints for the relay's key `relay` and the vault's
/// `vault`. With [`Prints::Key`], the two keys alone, the relay's first. With
/// a revision given, the one command that installs one's own build of the
/// host's archive, unpacked. Otherwise the two lines the host runs, as root:
/// the clone of the distribution at a visible `<tag>`, with one line saying
/// where a release's tag is read — the distribution's tags are not this
/// repository's, so a desktop built here knows none ([`REPOSITORY`]) — and the
/// distribution's `install.sh --kind host` given a key each ([`host_install`]).
/// Then the `enrol` that takes the line it prints back.
fn minted_host(name: Option<&str>, relay: &str, vault: &str, prints: Prints<'_>) -> Vec<Out> {
    let said = name.map(|n| format!(" {n}")).unwrap_or_default();
    let mut out = match prints {
        Prints::Key => {
            return vec![
                Out::Note("the relay's key, then the vault's:".into()),
                Out::Data(relay.to_string()),
                Out::Data(vault.to_string()),
            ]
        }
        Prints::Command(Some(rev)) => vec![
            Out::Note(format!("On the host, as root, beside the unpacked kotton-host-{rev}-linux-x86_64.tar.gz:")),
            Out::Data(host_install(relay, vault, &format!("kotton-host-{rev}-linux-x86_64/install.sh"))),
        ],
        Prints::Command(None) => vec![
            Out::Note("On the host — an always-on machine with a public address — as root, both lines; it prints one line back:".into()),
            Out::Data(host_clone()),
            Out::Data(host_install(relay, vault, &format!("{CHECKOUT_INSTALLER} --kind host"))),
        ],
    };
    if matches!(prints, Prints::Command(None)) {
        out.push(Out::Hint(format!(
            "put a release's tag from {RELEASES} where <tag> is, or `mint host{said} --rev <rev>` for your own build"
        )));
    }
    out.push(Out::Record(vec![("then here".into(), ENROL_THE_HOSTS_LINE.to_string())]));
    out
}

/// The `enrol` that takes back the one line a host's install printed, as `mint host` says it.
const ENROL_THE_HOSTS_LINE: &str = "enrol <the line the host printed>";

/// The lines the operating verbs print or take, each as a person types it, with the
/// placeholders a guide writes for a key: `key` for a vault's or a relay's, `relay_key` and
/// `vault_key` for a host's two.
///
/// The guides under `docs/use/` type these lines, and the pages are not this crate's: a
/// release of the shell ships without them. So the shell says what it prints, here, and the
/// tree that holds the pages holds each page to it (`cargo xtask-docs docs-check`). This
/// crate's own test holds these to what the verbs print
/// (`the_lines_a_guide_is_held_to_are_the_lines_the_verbs_print`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedLines {
    /// `kotton mint host`, the one verb a host's two keys are minted by.
    pub mint_host: String,
    /// The `kotton enrol` that takes back the line a host's install printed.
    pub enrol_the_hosts_line: String,
    /// `kotton vault invite --me`: the operator keeps their own things at their vault.
    pub vault_invite_me: String,
    /// The clone of the distribution a host's install runs from, at a `<tag>`.
    pub host_clone: String,
    /// The host's install, given the relay's key and the vault's.
    pub host_install: String,
    /// What a vault's install is given to create the vault for `key`, from a release's archive.
    pub create_vault: String,
    /// What a relay's install is given to create the relay for `key`, from a release's archive.
    pub create_relay: String,
    /// What a second operator's `key` is enrolled by, typed at a running vault.
    pub at_the_vault: String,
    /// What a second operator's `key` is enrolled by, typed at a running relay.
    pub at_the_relay: String,
}

/// [`TypedLines`] for the placeholders a page writes for each key.
pub fn typed_lines(key: &str, relay_key: &str, vault_key: &str) -> TypedLines {
    TypedLines {
        mint_host: "kotton mint host".to_string(),
        enrol_the_hosts_line: format!("kotton {ENROL_THE_HOSTS_LINE}"),
        vault_invite_me: "kotton vault invite --me".to_string(),
        host_clone: host_clone(),
        host_install: host_install(relay_key, vault_key, &format!("{CHECKOUT_INSTALLER} --kind host")),
        create_vault: to_create(OperatedService::Vault, key, None),
        create_relay: to_create(OperatedService::Relay, key, None),
        at_the_vault: at_the_vault(key),
        at_the_relay: at_the_relay(key),
    }
}

/// The clone of the distribution at a release's `<tag>` that a host's install
/// runs from: the first half of the README's install line.
fn host_clone() -> String {
    format!("git clone --depth 1 --branch <tag> {REPOSITORY}")
}

/// The host's install of `script`, given the relay's key and the vault's, one
/// each: one key never operates two instances.
fn host_install(relay: &str, vault: &str, script: &str) -> String {
    format!("KOTTON_OPERATOR_KEY_RELAY={relay} KOTTON_OPERATOR_KEY_VAULT={vault} sh {script}")
}

/// What a mint tells the person to do with `key` for a new instance: give it to
/// the install, which creates the instance for it (RFC-0084 V18), in the
/// archive of the release `rev` names — `<rev>` when none is known. A vault or
/// a relay does not start without an operator, so the first operator is never
/// enrolled at a running one — the line [`at_the_vault`] and [`at_the_relay`]
/// print is for a second operator. The installer is the archive's
/// `install.sh`; by hand it is `create --operator <key>`, which the guides name.
fn to_create(service: OperatedService, key: &str, rev: Option<&str>) -> String {
    format!("KOTTON_OPERATOR_KEY={key} sh kotton-{}-{}-linux-x86_64/install.sh", service.word(), rev.unwrap_or("<rev>"))
}

/// What `mint vault` tells the landlord to type at a running vault's shell, as
/// root, to enrol `key` as a second operator. The line `docs/use/run-a-vault.md` types,
/// held there by `docs-check` ([`TypedLines`]). A vault's machine runs no Docker
/// (DEC-0085): `kvaultd` is on root's `PATH` and reads `/etc/kotton/vault.env` itself, so
/// it is typed bare.
fn at_the_vault(key: &str) -> String {
    format!("kvaultd operator enrol {key}")
}

/// What `mint relay` tells the landlord to type at a running relay's shell to
/// enrol `key` as a second operator: as the user the relay runs as, `kotton-relay`, against the state
/// directory the unit gives it, which is how `docs/use/run-a-relay.md` types
/// it. Typed as root it is as good — the relay's README types it bare, since
/// the verb hands its file to the directory's owner
/// (`TASK-a-relay-operator-verb-typed-as-root-locks-every-operator-out-until-the-relay-restarts`)
/// — so the guide's form is what this follows, not the only safe one.
fn at_the_relay(key: &str) -> String {
    format!("runuser -u kotton-relay -- kotton-relay --state-dir /var/lib/kotton-relay operator enrol {key}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The instances of a kind this desktop operates, by name, as
    /// `operator_held` answers them.
    fn held(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn refusal(parsed: Parsed<'_>) -> String {
        match parsed {
            Parsed::Refuse(why) => why,
            other => panic!("not refused: {other:?}"),
        }
    }

    /// Every operating verb in its nameless form, and what it says to the
    /// instance: the vault's verbs and the relay's.
    fn nameless() -> Vec<(OperatedService, Vec<&'static str>, OperatorVerb)> {
        use OperatedService::{Relay, Vault};
        let invite = |quota| OperatorVerb::Invite {
            pool: "sam".into(),
            quota,
            ttl_seconds: INVITE_TTL_SECS,
        };
        vec![
            (Relay, vec!["rule"], OperatorVerb::ReadRule),
            (Relay, vec!["rule", "only_my_devices"], OperatorVerb::SetRule { rule: AdmissionRule::OnlyMyDevices }),
            (Relay, vec!["invite"], OperatorVerb::RelayInvite),
            (Vault, vec!["stand"], OperatorVerb::Stand),
            (Vault, vec!["people"], OperatorVerb::Pools),
            (Vault, vec!["invite", "sam"], invite(None)),
            (Vault, vec!["invite", "sam", "--space", "10"], invite(Some(10))),
            (Vault, vec!["space", "sam", "10"], OperatorVerb::SetQuota { pool: "sam".into(), quota: 10 }),
            (Vault, vec!["drop", "sam", "--confirm", "sam"], OperatorVerb::Drop { pool: "sam".into() }),
            (Vault, vec!["digits", "sam"], OperatorVerb::Digits { pool: "sam".into() }),
            (Vault, vec!["move", "gate"], OperatorVerb::Move { relay: "gate".into() }),
        ]
    }

    fn parse<'a>(service: OperatedService, line: &[&'a str], held: &'a [String]) -> Parsed<'a> {
        match service {
            OperatedService::Vault => parse_vault(line, held),
            OperatedService::Relay => parse_relay(line, held).expect("an operator line"),
        }
    }

    /// **An operating verb names its instance only when there is more than
    /// one of its kind** (Done-when: `relay rule only_my_devices` and `vault
    /// invite sam` act on the one instance of their kind). With one held,
    /// every verb's nameless form is said to it, and `vault invite --me` is
    /// that vault's.
    #[test]
    fn with_one_of_its_kind_held_an_operating_verb_takes_no_name() {
        for (service, line, verb) in nameless() {
            let one = held(&[service.word()]);
            assert_eq!(parse(service, &line, &one), Parsed::Speak(To::Only(service.word()), verb), "{} {line:?}", service.word());
        }
        assert_eq!(parse_vault(&["invite", "--me"], &held(&["home"])), Parsed::InviteMe(To::Only("home")));
    }

    /// **The named forms stay**: each verb with its instance's name first is
    /// said to that instance, whether one of its kind is held or two.
    #[test]
    fn the_named_forms_stand_with_one_held_and_with_two() {
        for h in [held(&["home"]), held(&["home", "attic"])] {
            for (service, line, verb) in nameless() {
                let mut named = vec![line[0], "home"];
                named.extend(&line[1..]);
                assert_eq!(parse(service, &named, &h), Parsed::Speak(To::Named("home"), verb), "{named:?} with {h:?}");
            }
            assert_eq!(parse_vault(&["invite", "home", "--me"], &h), Parsed::InviteMe(To::Named("home")));
        }
    }

    /// **With two of a kind held, a nameless verb never guesses**: it is
    /// refused in one line that lists both and says the named form — the
    /// line as typed, with the instance's place in it — and nothing is sent.
    /// `vault invite sam` with two vaults, one of them `sam`, is the case the
    /// words alone cannot settle, and it is refused too.
    #[test]
    fn a_nameless_verb_with_two_held_is_refused_listing_both_and_the_named_form() {
        let two = held(&["home", "attic"]);
        for (service, line, _) in nameless() {
            let why = refusal(parse(service, &line, &two));
            let word = service.word();
            let at = if service == OperatedService::Vault { "<v>" } else { "<r>" };
            let mut form = vec![word, line[0], at];
            form.extend(&line[1..]);
            assert!(why.contains("home, attic"), "{why}");
            assert!(why.contains(&format!("`{}`", form.join(" "))), "{line:?}: {why}");
            assert!(!why.contains('\n'), "one line: {why}");
        }
        let why = refusal(parse_vault(&["invite", "--me"], &two));
        assert!(why.contains("home, attic") && why.contains("`vault invite <v> --me`"), "{why}");
        let why = refusal(parse_vault(&["invite", "sam"], &held(&["home", "sam"])));
        assert!(why.contains("home, sam") && why.contains("`vault invite <v> sam`"), "{why}");
        let why = refusal(parse_vault(&["drop", "sam"], &two));
        assert!(why.contains("home, attic") && why.contains("`vault drop <v> sam`"), "{why}");
    }

    /// **With none of its kind held, a nameless verb says how one is made**,
    /// and sends nothing; a named one is left to the daemon, which refuses a
    /// name it does not hold.
    #[test]
    fn a_nameless_verb_with_none_held_says_how_one_is_made() {
        for (service, line, _) in nameless() {
            let why = refusal(parse(service, &line, &[]));
            let word = service.word();
            assert!(why.contains(&format!("operates no {word}")) && why.contains(&format!("`mint {word}`, then `enrol <line>`")), "{why}");
        }
        assert_eq!(parse_vault(&["people", "home"], &[]), Parsed::Speak(To::Named("home"), OperatorVerb::Pools));
    }

    /// **`relay rule <word>` is the one line whose words read two ways** — the
    /// rule of the relay `<word>`, or `<word>` set as the rule of the one relay
    /// — and the relays held settle it: a relay held by that name is read, and
    /// a rule is set; a word that is neither is not a rule. No relay is minted
    /// under a rule's word (`kuserd::agent::operator::tests::a_relay_is_not_minted_under_a_rules_word`),
    /// so no word is both; one kept under such a word from before is read.
    #[test]
    fn relay_rule_reads_one_word_as_a_relay_held_or_as_a_rule() {
        let gate = held(&["gate"]);
        assert_eq!(parse_relay(&["rule", "gate"], &gate), Some(Parsed::Speak(To::Named("gate"), OperatorVerb::ReadRule)));
        assert_eq!(
            parse_relay(&["rule", "anyone"], &gate),
            Some(Parsed::Speak(To::Only("gate"), OperatorVerb::SetRule { rule: AdmissionRule::Anyone }))
        );
        let why = refusal(parse_relay(&["rule", "everyone"], &gate).unwrap());
        assert!(why.contains("'everyone' is not a rule"), "{why}");
        let two = held(&["gate", "attic"]);
        assert_eq!(parse_relay(&["rule", "attic"], &two), Some(Parsed::Speak(To::Named("attic"), OperatorVerb::ReadRule)));
        assert!(refusal(parse_relay(&["rule", "anyone"], &two).unwrap()).contains("gate, attic"));
        let old = held(&["anyone", "gate"]);
        assert_eq!(parse_relay(&["rule", "anyone"], &old), Some(Parsed::Speak(To::Named("anyone"), OperatorVerb::ReadRule)));
    }

    /// **A drop typed with no name back says how to confirm it, in the form
    /// it was typed in**: by the vault's name where the line named it, and
    /// without where it did not.
    #[test]
    fn a_drop_says_how_to_confirm_in_the_form_it_was_typed() {
        let one = held(&["vault"]);
        let why = refusal(parse_vault(&["drop", "sam"], &one));
        assert!(why.contains("Type the name back to drop them: vault drop sam --confirm sam"), "{why}");
        assert!(why.contains("at 'vault'"), "{why}");
        let why = refusal(parse_vault(&["drop", "vault", "sam"], &one));
        assert!(why.contains("vault drop vault sam --confirm sam"), "{why}");
        assert_eq!((To::Only("vault").said(), To::Named("home").said()), (String::new(), " home".to_string()));
    }

    /// **`relay forget` and `vault forget` name their instance as every
    /// operating verb does** (decision 0005): nameless with one of the kind
    /// held, named with two, refused listing both when a nameless line has two
    /// to choose from, and saying how one is made with none. A word after the
    /// name is no form of the verb.
    #[test]
    fn forget_names_its_instance_only_when_there_are_several() {
        for service in [OperatedService::Vault, OperatedService::Relay] {
            let word = service.word();
            assert_eq!(parse(service, &["forget"], &held(&["home"])), Parsed::Forget(service, To::Only("home")), "{word}");
            let two = held(&["home", "attic"]);
            assert_eq!(parse(service, &["forget", "attic"], &two), Parsed::Forget(service, To::Named("attic")), "{word}");
            let at = if service == OperatedService::Vault { "<v>" } else { "<r>" };
            let why = refusal(parse(service, &["forget"], &two));
            assert!(why.contains("home, attic") && why.contains(&format!("`{word} forget {at}`")), "{why}");
            let why = refusal(parse(service, &["forget"], &[]));
            assert!(why.contains(&format!("operates no {word}")), "{why}");
            assert!(matches!(parse(service, &["forget", "home", "now"], &two), Parsed::Refuse(_)), "{word}");
        }
    }

    /// **A credential forgotten says whether its instance answered**, and,
    /// where it did not, the revoke at the instance with the key in it — a
    /// host not reached may still run, its key enrolled — and the mint that
    /// makes one again under the same name: by the kind's word alone when that
    /// is its name.
    #[test]
    fn a_forget_says_whether_the_instance_answered_and_how_to_mint_again() {
        let gone = |service, name: &str, answered| kotton::ForgottenCredential {
            name: name.into(),
            service,
            key: "ab".repeat(32),
            answered,
        };
        let record = |out: Vec<Out>| match out.as_slice() {
            [Out::Confirm { action, .. }, Out::Record(rows)] if action == "forgotten" => rows.clone(),
            other => panic!("{other:?}"),
        };
        let rows = record(forgotten(&gone(OperatedService::Vault, "vault", false)));
        assert!(rows[0].1.starts_with("no") && rows[0].1.contains(&format!("`kvaultd operator revoke {}`", "ab".repeat(32))), "{rows:?}");
        assert_eq!(rows[1], ("to make it again".to_string(), "`mint vault`".to_string()));
        let rows = record(forgotten(&gone(OperatedService::Relay, "gate", false)));
        assert!(rows[0].1.contains(&format!("kotton-relay operator revoke {}`", "ab".repeat(32))), "{rows:?}");
        assert_eq!(rows[1].1, "`mint relay gate`");
        let rows = record(forgotten(&gone(OperatedService::Vault, "home", true)));
        assert!(rows[0].1.starts_with("yes") && !rows[0].1.contains("revoke"), "{rows:?}");
    }

    /// **The usage and the help show the name in brackets and say when it is
    /// needed.**
    #[test]
    fn the_usage_brackets_the_name_and_says_when_it_is_needed() {
        for (text, at) in [(VAULT_USAGE, "<v>"), (VaultCommand.help_text(), "<v>")] {
            for form in ["forget [<v>]", "stand [<v>]", "move [<v>] <r>", "people [<v>]", "invite [<v>] <name>", "invite [<v>] --me", "digits [<v>] <name>", "space [<v>] <name> <bytes>", "drop [<v>] <name> --confirm <name>"] {
                assert!(text.contains(form), "{form} in {text}");
            }
            assert!(text.contains(&format!("{at} only when this desktop operates more than one vault")), "{text}");
        }
        for text in [RELAY_OPERATOR_USAGE, super::super::RelayCommand.help_text()] {
            assert!(text.contains("rule [<r>] [<rule>]") && text.contains("invite [<r>]") && text.contains("forget [<r>]"), "{text}");
            assert!(text.contains("<r> only when this desktop operates more than one relay"), "{text}");
        }
    }

    /// Each relay in the state its cause names: moved for `Moved`, not held
    /// otherwise.
    fn kept_unstood(why: kotton_wire::ipc::UnstoodWhy, relays: &[&str]) -> Vec<(String, String)> {
        use kotton_wire::ipc::{UnstoodRelayState, UnstoodWhy};
        let state = if why == UnstoodWhy::Moved { UnstoodRelayState::Moved } else { UnstoodRelayState::NotHeld };
        kept_relays(why, &relays.iter().map(|r| (*r, state)).collect::<Vec<_>>())
    }

    fn kept_relays(why: kotton_wire::ipc::UnstoodWhy, relays: &[(&str, kotton_wire::ipc::UnstoodRelayState)]) -> Vec<(String, String)> {
        unstood(&kotton::KeptCredential {
            name: "kotton".into(),
            unstood: Some(kotton_wire::ipc::Unstood {
                why,
                reason: "the reason the daemon gave".into(),
                relays: relays
                    .iter()
                    .map(|(hint, state)| kotton_wire::ipc::UnstoodRelay { hint: hint.to_string(), state: *state, name: None })
                    .collect(),
            }),
        })
    }

    /// **A kept credential whose vault was not told where to stand says so,
    /// and names the act that stands it for the cause the daemon sent** — each
    /// cause its own act, read from the cause and never from the sentence
    /// (`TASK-a-kept-claim-is-answered-as-a-failure-and-its-unit-left-stale-lines`).
    /// Told, it adds nothing.
    #[test]
    fn a_vault_not_told_where_to_stand_is_answered_kept_with_the_act_for_its_cause() {
        use kotton_wire::ipc::UnstoodWhy;
        let not_told = kept_unstood(UnstoodWhy::NotTold, &[]);
        assert_eq!(not_told.len(), 2, "{not_told:?}");
        assert!(not_told[0].1.contains("not yet standing at a relay: the reason the daemon gave"), "{not_told:?}");
        assert_eq!(not_told[1].1, "`vault stand kotton`");
        assert_eq!(parse_vault(&["stand", "kotton"], &held(&["kotton"])), Parsed::Speak(To::Named("kotton"), OperatorVerb::Stand));
        assert!(unstood(&kotton::KeptCredential { name: "kotton".into(), unstood: None }).is_empty());
    }

    /// **With no relay operated, the act is enrolling a relay, not `vault
    /// stand`** — which would be refused for the same cause.
    #[test]
    fn a_vault_with_no_relay_to_stand_at_is_sent_to_enrol_one() {
        let lines = kept_unstood(kotton_wire::ipc::UnstoodWhy::NoRelay, &[]);
        assert!(lines[1].1.contains("`enrol <the relay's line>`"), "{lines:?}");
        assert!(!lines[1].1.contains("vault stand"), "`vault stand` is refused with no relay: {lines:?}");
    }

    /// **With the relays it was told of no longer held, the act is holding
    /// that relay again under a new name, at the address it was told, then
    /// `vault stand`** — `mint relay` under the old name refuses a relay
    /// already kept.
    #[test]
    fn a_vault_whose_relays_are_no_longer_held_is_sent_to_hold_one_again() {
        let lines = kept_unstood(kotton_wire::ipc::UnstoodWhy::RelaysNotHeld, &["http://203.0.113.9:7700"]);
        let act = &lines[1].1;
        assert!(act.contains("`mint relay <a new name>`"), "{act}");
        assert!(act.contains("`enrol <the line the relay at http://203.0.113.9:7700 prints>`"), "the address it was told: {act}");
        assert!(act.ends_with("then `vault stand kotton`"), "{act}");
    }

    /// **With several relays recorded, the act names each, not the first**
    /// (`TASK-vault-stand-answers-told-only-when-a-vault-took-a-set`, Done-when
    /// (3)): `vault stand`'s refusal says *one of these*, listed as the reason
    /// lists them, and the shell gives each relay its own line.
    #[test]
    fn a_vault_told_of_several_relays_is_sent_to_hold_one_of_them() {
        use kotton_wire::ipc::{UnstoodRelayState, Unstood, UnstoodRelay, UnstoodWhy};
        const A: &str = "http://203.0.113.9:7700";
        const B: &str = "http://198.51.100.4:7700";
        let u = Unstood {
            why: UnstoodWhy::RelaysNotHeld,
            reason: String::new(),
            relays: [A, B].iter().map(|h| UnstoodRelay { hint: h.to_string(), state: UnstoodRelayState::NotHeld, name: None }).collect(),
        };
        let act = u.remedy("kotton");
        assert!(act.contains("hold one of these relays again"), "{act}");
        assert!(act.contains(&format!("at one of these: {A}, {B}")), "{act}");
        assert!(!act.contains("hold that relay again"), "{act}");
        assert!(act.ends_with("then `vault stand kotton`"), "{act}");

        let lines = kept_unstood(UnstoodWhy::RelaysNotHeld, &[A, B]);
        assert_eq!(lines[1].0, format!("at {A}"), "{lines:?}");
        assert!(lines[1].1.contains(&format!("the relay at {A} prints")), "{lines:?}");
        assert_eq!(lines[2].0, format!("at {B}"), "{lines:?}");
        assert!(lines[2].1.contains(&format!("the relay at {B} prints")), "{lines:?}");
    }

    /// **One relay rebuilt and one no longer held: each gets its own act, and
    /// the one that works today comes first** (the driver's ruling on
    /// `3f8911bf`). Holding the gone relay again and `vault stand` stands the
    /// vault now; the rebuilt one is offered by the door, not typed.
    #[test]
    fn a_rebuilt_relay_beside_one_no_longer_held_gives_each_its_own_act() {
        use kotton_wire::ipc::{UnstoodRelayState, UnstoodWhy};
        const U: &str = "http://203.0.113.9:7700";
        const GONE: &str = "http://198.51.100.4:7700";
        let lines = kept_relays(UnstoodWhy::RelaysNotHeld, &[(U, UnstoodRelayState::Moved), (GONE, UnstoodRelayState::NotHeld)]);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(lines[1].0, format!("at {GONE}"), "the act that works today leads: {lines:?}");
        assert!(lines[1].1.contains("hold that relay again") && lines[1].1.ends_with("then `vault stand kotton`"), "{lines:?}");
        assert_eq!(lines[2].0, format!("at {U}"), "{lines:?}");
        assert!(lines[2].1.contains("*Move…*") && !lines[2].1.contains("vault stand"), "{lines:?}");
    }

    /// **A relay rebuilt at the address the vault was told is named a move,
    /// and the move is the act** (`TASK-vault-stand-answers-told-only-when-a-vault-took-a-set`,
    /// Done-when (2); `vault move` since `TASK-settings-has-one-door-and-it-takes-a-code`):
    /// holding it again would record the key already held, so neither `relay
    /// enrol` nor `vault stand` is offered. The relay held there is named by
    /// the name `vault move` takes.
    #[test]
    fn a_vault_whose_relay_answers_under_a_new_key_is_told_it_is_a_move() {
        use kotton_wire::ipc::{Unstood, UnstoodRelay, UnstoodRelayState, UnstoodWhy};
        let lines = kept_unstood(UnstoodWhy::Moved, &["http://203.0.113.9:7700"]);
        let act = &lines[1].1;
        assert!(act.contains("the relay at http://203.0.113.9:7700 is a new relay"), "{act}");
        assert!(act.contains("*Move…*") && act.contains("`vault move kotton <relay>`"), "{act}");
        assert!(!act.contains("relay enrol") && !act.contains("vault stand"), "holding again loops: {act}");
        let named = Unstood {
            why: UnstoodWhy::Moved,
            reason: String::new(),
            relays: vec![UnstoodRelay {
                hint: "http://203.0.113.9:7700".into(),
                state: UnstoodRelayState::Moved,
                name: Some("gate".into()),
            }],
        };
        assert!(named.remedy("kotton").contains("`vault move kotton gate`"), "{}", named.remedy("kotton"));
    }

    /// **A move is the person's to say, never stated as done** (the Fable review
    /// of `3f8911bf`): the act names the move and does not claim it happened.
    #[test]
    fn a_move_is_named_as_the_persons_act() {
        let lines = kept_unstood(kotton_wire::ipc::UnstoodWhy::Moved, &["http://203.0.113.9:7700"]);
        let act = &lines[1].1;
        assert!(!act.contains("moves to it"), "the person's decision stated as a fact: {act}");
        assert!(act.contains("to stand the vault 'kotton' there"), "{act}");
    }

    /// **A vault told nothing, by a desktop that runs several relays, is asked
    /// where to stand: one act per relay, each `vault move` by that relay's
    /// name** (the Default ruled on `TASK-settings-has-one-door-and-it-takes-a-code`).
    /// `vault move` parses to the verb it names.
    #[test]
    fn a_vault_asked_where_to_stand_is_given_a_move_per_relay() {
        use kotton_wire::ipc::{Unstood, UnstoodRelay, UnstoodRelayState, UnstoodWhy};
        const A: &str = "http://203.0.113.9:7700";
        const B: &str = "http://198.51.100.4:7700";
        let lines = unstood(&kotton::KeptCredential {
            name: "kotton".into(),
            unstood: Some(Unstood {
                why: UnstoodWhy::Several,
                reason: "this desktop runs 2 relays".into(),
                relays: [(A, "gate"), (B, "attic")]
                    .iter()
                    .map(|(h, n)| UnstoodRelay { hint: h.to_string(), state: UnstoodRelayState::Operated, name: Some(n.to_string()) })
                    .collect(),
            }),
        });
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!((lines[1].0.as_str(), lines[1].1.as_str()), (format!("at {A}").as_str(), "`vault move kotton gate`"));
        assert_eq!((lines[2].0.as_str(), lines[2].1.as_str()), (format!("at {B}").as_str(), "`vault move kotton attic`"));
        assert_eq!(
            parse_vault(&["move", "kotton", "gate"], &held(&["kotton"])),
            Parsed::Speak(To::Named("kotton"), OperatorVerb::Move { relay: "gate".into() })
        );
    }

    /// **A drop is confirmed as the terminal confirms it**: the pool's name,
    /// typed back. Missing, or typed wrong, nothing is sent — the line is
    /// refused before the vault is dialled — and typed right it is the one drop
    /// of that pool.
    #[test]
    fn vault_drop_sends_nothing_until_the_name_is_typed_back() {
        for line in [
            &["drop", "kotton", "sam"][..],
            &["drop", "kotton", "sam", "--confirm", "same"],
            &["drop", "kotton", "sam", "--confirm", "Sam"],
            &["drop", "kotton", "sam", "--confirm", ""],
            &["drop", "kotton", "sam", "--confirm"],
            &["drop", "kotton", "sam", "sam"],
            &["drop", "kotton", "sam", "--yes"],
        ] {
            assert!(
                matches!(parse_vault(line, &held(&["kotton"])), Parsed::Refuse(_)),
                "{line:?} would have dropped a pool: {:?}",
                parse_vault(line, &held(&["kotton"]))
            );
        }
        assert_eq!(
            parse_vault(&["drop", "kotton", "sam", "--confirm", "sam"], &held(&["kotton"])),
            Parsed::Speak(To::Named("kotton"), OperatorVerb::Drop { pool: "sam".into() })
        );
        // The refusal says how to confirm, so the landlord is not left guessing.
        match parse_vault(&["drop", "kotton", "sam"], &held(&["kotton"])) {
            Parsed::Refuse(why) => assert!(why.contains("vault drop kotton sam --confirm sam"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    /// **`mint relay` asks the rule once, and *only my devices* is the answer
    /// when none is given** (DEC-0083; DEC-0087 made the rule the relay's own
    /// mint's). `None` here is written `rule=only_my_devices`
    /// in the store (`a_minted_key_is_completed_by_its_services_lines_and_nothing_else`,
    /// core/peer). A word that names no rule sends nothing, and a vault's mint
    /// takes no rule at all.
    #[test]
    fn mint_relay_takes_one_rule_and_mint_vault_takes_none() {
        let cmd = Prints::Command(None);
        assert_eq!(parse_mint(&["relay", "gate"]), Parsed::Mint(OperatedService::Relay, Some("gate"), None, cmd));
        for (word, r) in [
            ("only_my_devices", AdmissionRule::OnlyMyDevices),
            ("people_i_invite", AdmissionRule::PeopleIInvite),
            ("anyone", AdmissionRule::Anyone),
        ] {
            assert_eq!(
                parse_mint(&["relay", "gate", "--rule", word]),
                Parsed::Mint(OperatedService::Relay, Some("gate"), Some(r), cmd)
            );
        }
        assert!(matches!(parse_mint(&["relay", "gate", "--rule", "everyone"]), Parsed::Refuse(_)));
        assert!(matches!(parse_mint(&["relay", "gate", "--rule"]), Parsed::Refuse(_)));
        assert!(matches!(parse_mint(&["relay", "gate", "--rule", "anyone", "--rule", "anyone"]), Parsed::Refuse(_)));
        assert_eq!(parse_mint(&["vault", "kotton"]), Parsed::Mint(OperatedService::Vault, Some("kotton"), None, cmd));
        assert!(matches!(parse_mint(&["vault", "kotton", "--rule", "anyone"]), Parsed::Refuse(_)));
        assert!(matches!(parse_mint(&["gateway", "kotton"]), Parsed::Refuse(_)), "the kind is a relay, a vault or a host");
    }

    /// **`mint host` is the two mints at once: a name for both, the relay's
    /// rule, and `--rev` or `--key` as each kind takes them.** A rule that is
    /// none, a revision that is none, and both `--rev` and `--key` are
    /// refused before a key is minted.
    #[test]
    fn mint_host_takes_a_name_the_relays_rule_and_a_revision_or_the_key_alone() {
        let cmd = Prints::Command(None);
        assert_eq!(parse_mint(&["host"]), Parsed::MintHost(None, None, cmd));
        assert_eq!(parse_mint(&["host", "attic"]), Parsed::MintHost(Some("attic"), None, cmd));
        assert_eq!(
            parse_mint(&["host", "--rule", "people_i_invite", "--rev", "0f35b823a1b2"]),
            Parsed::MintHost(None, Some(AdmissionRule::PeopleIInvite), Prints::Command(Some("0f35b823a1b2")))
        );
        assert_eq!(parse_mint(&["host", "--key"]), Parsed::MintHost(None, None, Prints::Key));
        for line in [
            &["host", "--rule", "everyone"][..],
            &["host", "--rev", "v0.1.0"],
            &["host", "--key", "--rev", "0f35b823a1b2"],
            &["host", "attic", "extra"],
        ] {
            assert!(matches!(parse_mint(line), Parsed::Refuse(_)), "{line:?}: {:?}", parse_mint(line));
        }
        assert!(MINT_USAGE.contains("mint host [<h>]"), "{MINT_USAGE}");
        assert!(MintCommand.help_text().contains("host [<h>]"), "{}", MintCommand.help_text());
    }

    /// The lines a mint prints to copy, its `Out::Data`, in order.
    fn data(out: &[Out]) -> Vec<&str> {
        out.iter()
            .filter_map(|o| match o {
                Out::Data(d) => Some(d.as_str()),
                _ => None,
            })
            .collect()
    }

    /// **`mint host` prints the two lines a host runs: the clone of the
    /// distribution at a release's tag, and its `install.sh --kind host` given
    /// a key each** — the relay's and the vault's, never one for both. The tag
    /// is a visible `<tag>` with one line saying where a release's is read,
    /// since the distribution's tags are not this repository's. With a
    /// revision given, the one command for one's own build of the host's
    /// archive; with `--key`, the two keys alone, the relay's first. Each ends
    /// on the `enrol` that takes the line back.
    #[test]
    fn mint_host_prints_the_clone_and_the_install_with_a_key_each() {
        const RELAY_KEY: &str = "7f3a0c9e4b1d2f6a8c5e7b9d1f3a5c7e9b2d4f6a8c0e2b4d6f8a1c3e5b7d9f1a";
        const VAULT_KEY: &str = "1a9f7d5b3e1c8a6f4d2b0e8c6a4f2d0b9e7c5a3f1d9b7e5c3a1f8d6b4e2c0a9f";
        let enrol = |out: &[Out]| {
            out.iter().any(|o| matches!(o, Out::Record(rows) if rows.iter().any(|(_, v)| v == "enrol <the line the host printed>")))
        };
        let out = minted_host(Some("attic"), RELAY_KEY, VAULT_KEY, Prints::Command(None));
        assert_eq!(
            data(&out),
            vec![
                "git clone --depth 1 --branch <tag> https://github.com/kottonllc/kotton-dist".to_string(),
                format!("KOTTON_OPERATOR_KEY_RELAY={RELAY_KEY} KOTTON_OPERATOR_KEY_VAULT={VAULT_KEY} sh kotton-dist/install.sh --kind host"),
            ]
        );
        let hints: Vec<&String> = out
            .iter()
            .filter_map(|o| match o {
                Out::Hint(h) => Some(h),
                _ => None,
            })
            .collect();
        assert_eq!(hints.len(), 1, "{out:?}");
        assert!(
            hints[0].contains("https://github.com/kottonllc/kotton-dist/releases where <tag> is")
                && hints[0].contains("`mint host attic --rev <rev>`"),
            "{hints:?}"
        );
        assert!(enrol(&out), "{out:?}");

        let own = minted_host(Some("attic"), RELAY_KEY, VAULT_KEY, Prints::Command(Some("c0ffee123456-dirty")));
        assert_eq!(
            data(&own),
            vec![format!(
                "KOTTON_OPERATOR_KEY_RELAY={RELAY_KEY} KOTTON_OPERATOR_KEY_VAULT={VAULT_KEY} sh kotton-host-c0ffee123456-dirty-linux-x86_64/install.sh"
            )]
        );
        assert!(enrol(&own), "{own:?}");
        assert!(!own.iter().any(|o| matches!(o, Out::Hint(_))), "one's own build needs no tag: {own:?}");

        assert_eq!(data(&minted_host(None, RELAY_KEY, VAULT_KEY, Prints::Key)), vec![RELAY_KEY, VAULT_KEY]);
    }

    /// **`mint host` clones what the README's first line clones and runs the
    /// same installer**: the README's install line, the one the distribution's
    /// README carries, is `mint host`'s clone line, then ` && sh `, then the
    /// installer its second line runs; and the README's host section shows
    /// both lines `mint host` prints, for the placeholders it writes. So the
    /// line a host runs and the line a desktop ran cannot name two
    /// repositories, and a README moved to another distribution fails here
    /// until `mint host` moves with it.
    #[test]
    fn mint_host_clones_and_installs_what_the_readme_does() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let readme = std::fs::read_to_string(root.join("README.md")).expect("the repository's README.md");
        let mut fenced = false;
        let fenced_lines: Vec<&str> = readme
            .lines()
            .filter(|l| {
                if l.trim_start().starts_with("```") {
                    fenced = !fenced;
                    return false;
                }
                fenced
            })
            .map(str::trim)
            .collect();
        let host = minted_host(None, "<relay key>", "<vault key>", Prints::Command(None));
        let printed = data(&host);
        let install = format!("{} && sh {CHECKOUT_INSTALLER}", printed[0]);
        assert_eq!(
            fenced_lines.iter().find(|l| l.starts_with("git clone ") && l.contains(" && sh ")),
            Some(&install.as_str()),
            "the README's install line is not `mint host`'s clone and installer"
        );
        for line in &printed[..2] {
            assert!(fenced_lines.contains(line), "the README's host section does not show `{line}`");
        }
    }

    /// **The lines a guide is held to are the lines the verbs print**: what
    /// [`typed_lines`] says, for the placeholders a page writes, is what `mint
    /// host` and each kind's `mint` print for those keys, and the verbs it names
    /// are verbs this shell parses. The pages are not this crate's; the tree that
    /// holds them holds each to [`TypedLines`] (`cargo xtask-docs docs-check`), so
    /// a page and a verb cannot drift apart without one of the two failing.
    #[test]
    fn the_lines_a_guide_is_held_to_are_the_lines_the_verbs_print() {
        let lines = typed_lines("<key>", "<relay key>", "<vault key>");

        let host = minted_host(None, "<relay key>", "<vault key>", Prints::Command(None));
        assert_eq!(data(&host)[..2], [lines.host_clone.as_str(), lines.host_install.as_str()]);
        let enrol = lines.enrol_the_hosts_line.strip_prefix("kotton ").expect("typed after `kotton`");
        assert!(
            host.iter().any(|o| matches!(o, Out::Record(rows) if rows.iter().any(|(_, v)| v == enrol))),
            "`mint host` ends on `{enrol}`: {host:?}"
        );

        for (service, create, at) in [
            (OperatedService::Vault, &lines.create_vault, &lines.at_the_vault),
            (OperatedService::Relay, &lines.create_relay, &lines.at_the_relay),
        ] {
            let out = minted(service, Some("kotton"), "<key>", Prints::Command(None), None);
            assert_eq!(command(&out), create.as_str());
            assert!(
                out.iter().any(|o| matches!(o, Out::Record(rows) if rows.iter().any(|(_, v)| v == at))),
                "`mint {}` names `{at}` for a second operator: {out:?}",
                service.word()
            );
        }

        fn words(line: &str) -> Vec<&str> {
            line.split(' ').skip(1).collect()
        }
        assert_eq!(words(&lines.mint_host), ["mint", "host"]);
        assert_eq!(parse_mint(&words(&lines.mint_host)[1..]), Parsed::MintHost(None, None, Prints::Command(None)));
        assert_eq!(words(&lines.vault_invite_me), ["vault", "invite", "--me"]);
        assert_eq!(
            parse_vault(&words(&lines.vault_invite_me)[1..], &held(&["vault"])),
            Parsed::InviteMe(To::Only("vault"))
        );
    }

    /// **`enrol` takes the one line a host printed as the relay's line and the
    /// vault's**: the host's install prints them on one row, one space
    /// between, and the one parser reads that row as it reads two lines given
    /// one after the other — the relay's first.
    #[test]
    fn enrol_reads_a_hosts_one_line_as_the_relays_line_and_the_vaults() {
        use kotton_wire::line::InstanceLine;
        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [5; 32] }.to_text();
        let vault = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: [7; 32] }.to_text();
        let host = format!("{relay} {vault}");
        let (sent, said) = parse_enrol(&host).expect("the host's line");
        assert_eq!(sent, vec![relay.clone(), vault.clone()]);
        assert!(said.is_empty(), "{said:?}");
        assert_eq!(parse_enrol(&format!("{relay}\n{vault}")).expect("two rows").0, sent, "one parser");
    }

    /// **When a vault's enrol keeps your things there, this device stands at
    /// the relay the same `enrol` kept, and is told of any other**: the relay a ceremony offers is
    /// taken only when its key is a relay whose line was typed into this
    /// `enrol` and kept there — not one refused, not a vault's line, not
    /// another relay's. What standing there came to is said either way.
    #[test]
    fn the_relay_a_host_enrol_kept_is_stood_at_and_any_other_is_offered() {
        use kotton_wire::ipc::{LineCame, LineEnrolled};
        use kotton_wire::line::InstanceLine;
        let line = |kind, key: u8, hint: &str| InstanceLine { kind, hint: hint.into(), key: [key; 32] }.to_text();
        let came = |text: String, kind, came_to| LineEnrolled {
            line: text,
            kind: Some(kind),
            hint: String::new(),
            dialled: true,
            reached: Some(true),
            matched: Some(true),
            came_to,
        };
        let kept = || LineCame::Kept { name: "relay".into(), only: true, unstood: None, stood: Vec::new() };
        let mine = line(OperatedService::Relay, 5, "http://203.0.113.9:7700");
        let refused = line(OperatedService::Relay, 6, "http://203.0.113.10:7700");
        let vault = line(OperatedService::Vault, 7, "203.0.113.9:7710");
        let relays = relays_kept(&[
            came(mine.clone(), OperatedService::Relay, kept()),
            came(refused.clone(), OperatedService::Relay, LineCame::Refused { why: "another key".into() }),
            came(vault.clone(), OperatedService::Vault, LineCame::Kept { name: "vault".into(), only: true, unstood: None, stood: Vec::new() }),
        ]);
        assert_eq!(relays, vec![[5; 32]]);
        assert!(super::super::device::relay_offer_taken(&mine, &relays));
        // The same relay at another address is still that relay: it is its key.
        assert!(super::super::device::relay_offer_taken(&line(OperatedService::Relay, 5, "http://198.51.100.2:7700"), &relays));
        for other in [&refused, &vault, &line(OperatedService::Relay, 9, "http://192.0.2.1:7700")] {
            assert!(!super::super::device::relay_offer_taken(other, &relays), "{other}");
        }
        assert!(!super::super::device::relay_offer_taken(&mine, &[]), "a vault's enrol alone stands this device nowhere");

        match stood_at(Ok(()), &mine) {
            Out::Confirm { subject, .. } => assert_eq!(subject, "http://203.0.113.9:7700"),
            other => panic!("{other:?}"),
        }
        match stood_at(Err(std::io::Error::other("refused")), &mine) {
            Out::Fail { what, try_ } => {
                assert!(what.contains("refused"), "{what}");
                assert_eq!(try_, Some(format!("`relay set {mine}`")));
            }
            other => panic!("{other:?}"),
        }
    }

    /// **A relay's enrol takes up the keep at each vault it stood, once, and
    /// not at one whose own line this enrol kept** (#102). The relay's
    /// completion names the vaults it told to stand there; a vault named by two
    /// relays is kept at once, a vault whose line is in the same enrol is kept
    /// by its own completion, and a refused relay names none. Its readout says
    /// which vaults it stood.
    #[test]
    fn a_relays_enrol_keeps_at_each_vault_it_stood_once() {
        use kotton_wire::ipc::{LineCame, LineEnrolled};
        let came = |kind, came_to| LineEnrolled {
            line: String::new(),
            kind: Some(kind),
            hint: String::new(),
            dialled: true,
            reached: Some(true),
            matched: Some(true),
            came_to,
        };
        let relay = |stood: &[&str]| {
            came(
                OperatedService::Relay,
                LineCame::Kept { name: "relay".into(), only: true, unstood: None, stood: stood.iter().map(|s| s.to_string()).collect() },
            )
        };
        let vault = |name: &str| came(OperatedService::Vault, LineCame::Kept { name: name.into(), only: false, unstood: None, stood: Vec::new() });
        assert_eq!(stood_by_relays(&[relay(&["attic", "home"])]), vec!["attic".to_string(), "home".into()]);
        assert_eq!(stood_by_relays(&[relay(&["attic"]), relay(&["attic", "home"])]), vec!["attic".to_string(), "home".into()], "once each");
        assert_eq!(stood_by_relays(&[vault("attic"), relay(&["attic", "home"])]), vec!["home".to_string()], "attic's own line keeps it");
        assert!(stood_by_relays(&[relay(&[]), vault("attic")]).is_empty(), "a relay that stood none takes up nothing");
        assert!(
            stood_by_relays(&[came(OperatedService::Relay, LineCame::Refused { why: "another key".into() })]).is_empty(),
            "a refused relay stood nothing"
        );

        let rows = readout(&relay(&["attic", "home"]));
        assert!(
            rows.contains(&("told to stand here".to_string(), "the vault 'attic', the vault 'home'".to_string())),
            "{rows:?}"
        );
        assert!(!readout(&relay(&[])).iter().any(|(k, _)| k == "told to stand here"));
    }

    /// **`mint <kind> <name>` takes `--rev <rev>` for one's own build and
    /// `--key` for the key alone, never both** (Done-when (1)). A revision is
    /// the hex an archive is named by, since it is printed into a line run as
    /// root; anything else is refused before a key is minted.
    #[test]
    fn mint_takes_a_revision_or_the_key_alone() {
        assert_eq!(
            parse_mint(&["vault", "kotton", "--rev", "0f35b823a1b2"]),
            Parsed::Mint(OperatedService::Vault, Some("kotton"), None, Prints::Command(Some("0f35b823a1b2")))
        );
        assert_eq!(
            parse_mint(&["relay", "gate", "--rev", "0f35b823a1b2-dirty", "--rule", "anyone"]),
            Parsed::Mint(OperatedService::Relay, Some("gate"), Some(AdmissionRule::Anyone), Prints::Command(Some("0f35b823a1b2-dirty")))
        );
        assert_eq!(parse_mint(&["relay", "gate", "--key"]), Parsed::Mint(OperatedService::Relay, Some("gate"), None, Prints::Key));
        for line in [
            &["vault", "kotton", "--key", "--rev", "0f35b823a1b2"][..],
            &["vault", "kotton", "--rev", "0f35b823a1b2", "--key"],
            &["vault", "kotton", "--rev"],
            &["vault", "kotton", "--rev", "v0.1.0"],
            &["vault", "kotton", "--rev", "0f35b823;reboot"],
            &["vault", "kotton", "--rev", "0F35B823A1B2"],
            &["vault", "kotton", "--key", "--key"],
            &["vault", "kotton", "extra"],
        ] {
            assert!(matches!(parse_mint(line), Parsed::Refuse(_)), "{line:?}: {:?}", parse_mint(line));
        }
    }

    /// **The name is optional: with none, the instance is named by its
    /// kind's word** (the owner's amendment of 2026-10-12, Done-when (1)), and
    /// every flag still reads after it. A word that is not a kind is refused.
    #[test]
    fn mint_with_no_name_names_the_instance_by_its_kind() {
        let cmd = Prints::Command(None);
        assert_eq!(parse_mint(&["relay"]), Parsed::Mint(OperatedService::Relay, None, None, cmd));
        assert_eq!(parse_mint(&["vault"]), Parsed::Mint(OperatedService::Vault, None, None, cmd));
        assert_eq!(parse_mint(&["relay", "--key"]), Parsed::Mint(OperatedService::Relay, None, None, Prints::Key));
        assert_eq!(
            parse_mint(&["relay", "--rule", "anyone", "--rev", "0f35b823a1b2"]),
            Parsed::Mint(OperatedService::Relay, None, Some(AdmissionRule::Anyone), Prints::Command(Some("0f35b823a1b2")))
        );
        assert!(matches!(parse_mint(&["vault", "--rule", "anyone"]), Parsed::Refuse(_)));
        // The instance is labelled by its kind's word, and the enrol it names says so.
        let out = minted(OperatedService::Relay, None, "07ab", Prints::Command(None), None);
        assert!(out.iter().any(|o| matches!(o, Out::Record(rows) if rows.iter().any(|(_, v)| v == "enrol <the line its creation printed>"))), "{out:?}");
        assert!(out.iter().any(|o| matches!(o, Out::Hint(h) if h.contains("`mint relay --rev <rev>`"))), "{out:?}");
    }

    /// **A nameless mint is sent with no name, so the daemon decides**
    /// (Done-when (1), (5) as amended 2026-10-12): the shell does not label it
    /// or check it, and the refusal of a second `mint relay` is the daemon's —
    /// `kuserd::agent::operator::tests::a_second_nameless_mint_of_a_kind_is_refused_and_a_named_one_is_not`,
    /// and through this REPL
    /// `a_second_nameless_mint_typed_at_the_repl_is_refused_by_the_daemon`.
    #[test]
    fn a_nameless_mint_is_sent_with_no_name_for_the_daemon_to_refuse_a_second() {
        assert_eq!(parse_mint(&["relay"]), Parsed::Mint(OperatedService::Relay, None, None, Prints::Command(None)));
        assert_eq!(parse_mint(&["relay", "gate"]), Parsed::Mint(OperatedService::Relay, Some("gate"), None, Prints::Command(None)));
    }

    /// **A bare `mint` lists the keys minted and not yet enrolled, by kind,
    /// and by name only where a kind has more than one or the name is not the
    /// kind's word** (Done-when (2), as amended 2026-10-12); what the daemon
    /// answers is
    /// `kuserd::agent::operator::tests::the_keys_minted_and_not_yet_enrolled_are_listed_by_name_and_kind`.
    #[test]
    fn a_bare_mint_lists_the_keys_waiting_by_kind() {
        use kotton_wire::ipc::MintWaiting;
        assert_eq!(parse_mint(&[]), Parsed::Mints);
        let w = |name: &str, service| MintWaiting { name: name.into(), service, key: "07".into() };
        let row = |kind: &str, name: &str| vec![kind.to_string(), name.to_string()];
        assert_eq!(
            waiting_rows(&[w("relay", OperatedService::Relay), w("vault", OperatedService::Vault)]),
            vec![row("relay", ""), row("vault", "")],
            "one of each, by its kind's word: the kind alone"
        );
        assert_eq!(waiting_rows(&[w("attic", OperatedService::Vault)]), vec![row("vault", "attic")], "a name not the kind's");
        assert_eq!(
            waiting_rows(&[w("relay", OperatedService::Relay), w("gate", OperatedService::Relay), w("vault", OperatedService::Vault)]),
            vec![row("relay", "relay"), row("relay", "gate"), row("vault", "")],
            "two relays: each by its name"
        );
        assert_eq!(waiting_rows(&[]), Vec::<Vec<String>>::new());
    }

    /// **`relay mint` and `vault mint` are gone, not aliased** (Done-when (3)):
    /// refused before anything is minted, with the spelling that replaced them
    /// and the one line that tells the two kinds of verb apart — which
    /// `relay`'s and `vault`'s usage and help say too.
    #[test]
    fn relay_mint_and_vault_mint_are_gone_and_the_usage_says_which_verbs_make_one() {
        for (parsed, word) in [
            (parse_relay(&["mint", "gate"], &[]).expect("an operator line"), "relay"),
            (parse_relay(&["mint", "gate", "--rule", "anyone"], &[]).expect("an operator line"), "relay"),
            (parse_relay(&["mint"], &[]).expect("an operator line"), "relay"),
            (parse_vault(&["mint", "kotton"], &[]), "vault"),
        ] {
            match parsed {
                Parsed::Refuse(why) => {
                    assert!(why.contains(&format!("`mint {word} [<name>]`")), "{why}");
                    assert!(why.contains(MAKE_AND_OPERATE), "{why}");
                }
                other => panic!("`{word} mint` is still a verb: {other:?}"),
            }
        }
        assert_eq!(MAKE_AND_OPERATE, "mint and enrol make one; relay and vault operate one");
        for usage in [VAULT_USAGE, RELAY_OPERATOR_USAGE, MINT_USAGE] {
            assert!(usage.contains(MAKE_AND_OPERATE), "{usage}");
            assert!(!usage.contains("relay mint") && !usage.contains("vault mint"), "{usage}");
        }
        match parse_vault(&[], &[]) {
            Parsed::Refuse(why) => assert!(why.contains(MAKE_AND_OPERATE) && why.contains("`mint vault`, then `enrol <line>`"), "{why}"),
            other => panic!("{other:?}"),
        }
        for help in [VaultCommand.help_text(), MintCommand.help_text(), super::super::RelayCommand.help_text()] {
            assert!(help.contains(MAKE_AND_OPERATE), "{help}");
            assert!(!help.contains("relay mint") && !help.contains("vault mint") && !help.contains("[mint"), "{help}");
        }
        match parse_relay(&["rule"], &[]) {
            Some(Parsed::Refuse(why)) => assert!(why.contains(MAKE_AND_OPERATE) && why.contains("`mint relay`, then `enrol <line>`"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    /// The command a mint prints, the one `Out::Data` line of its answer.
    fn command(out: &[Out]) -> &str {
        let data: Vec<&str> = out
            .iter()
            .filter_map(|o| match o {
                Out::Data(d) => Some(d.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(data.len(), 1, "one line to copy: {out:?}");
        data[0]
    }

    /// **Mint prints the whole command the host runs for that kind, with the
    /// key in it, and not a bare key** (Done-when (1), (5)). Held to the exact
    /// line for each kind, so it is red when the key is left out and when the
    /// other kind's archive is named; the revision is the one given, else the
    /// newest release the desktop knows, else a visible `<rev>` with one line
    /// saying to put the release's there; `--key` is the key alone.
    #[test]
    fn mint_prints_the_command_the_host_runs_with_the_key_in_it() {
        const KEY: &str = "7f3a0c9e4b1d2f6a8c5e7b9d1f3a5c7e9b2d4f6a8c0e2b4d6f8a1c3e5b7d9f1a";
        for (service, word, other) in [(OperatedService::Relay, "relay", "vault"), (OperatedService::Vault, "vault", "relay")] {
            let out = minted(service, Some("kotton"), KEY, Prints::Command(None), Some("0f35b823a1b2"));
            let line = command(&out);
            assert_eq!(line, format!("KOTTON_OPERATOR_KEY={KEY} sh kotton-{word}-0f35b823a1b2-linux-x86_64/install.sh"));
            assert!(!line.contains(&format!("kotton-{other}-")), "the other kind's archive: {line}");
            assert!(!out.iter().any(|o| matches!(o, Out::Hint(_))), "a known release needs no hint: {out:?}");
            assert!(
                !out.iter().any(|o| matches!(o, Out::Record(rows) if rows.iter().any(|(_, v)| v == KEY))),
                "a bare key beside the command: {out:?}"
            );

            let own = minted(service, Some("kotton"), KEY, Prints::Command(Some("c0ffee123456-dirty")), Some("0f35b823a1b2"));
            assert_eq!(command(&own), format!("KOTTON_OPERATOR_KEY={KEY} sh kotton-{word}-c0ffee123456-dirty-linux-x86_64/install.sh"));

            let unknown = minted(service, Some("kotton"), KEY, Prints::Command(None), None);
            assert_eq!(command(&unknown), format!("KOTTON_OPERATOR_KEY={KEY} sh kotton-{word}-<rev>-linux-x86_64/install.sh"));
            let hints: Vec<&String> = unknown
                .iter()
                .filter_map(|o| match o {
                    Out::Hint(h) => Some(h),
                    _ => None,
                })
                .collect();
            assert_eq!(hints.len(), 1, "{unknown:?}");
            assert!(hints[0].contains("where <rev> is") && hints[0].contains(&format!("`mint {word} kotton --rev <rev>`")), "{hints:?}");

            assert_eq!(minted(service, Some("kotton"), KEY, Prints::Key, Some("0f35b823a1b2")), vec![Out::Data(KEY.into())]);
        }
    }

    /// **The revision built in is a release's or nothing** — 12 hex, as
    /// `.github/workflows/release.yml` names its archives, or empty when this
    /// desktop was built where no `v*` tag is known.
    #[test]
    fn the_release_this_desktop_knows_is_twelve_hex_or_none() {
        match release_rev() {
            None => assert!(RELEASE_REV.is_empty()),
            Some(rev) => assert!(rev.len() == 12 && a_rev(rev) && !rev.ends_with("-dirty"), "{rev}"),
        }
    }

    /// **`relay enrol` and `vault enrol` are gone, not aliased, and the usage
    /// says `enrol <line>`**
    /// (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`,
    /// Done-when (4)). Every form of either — the line form, the old forms, a
    /// bare `enrol` under the noun — is refused before anything is sent, with
    /// the spelling that replaced it and the one line that tells the two kinds
    /// of verb apart; `relay`'s and `vault`'s usage and help keep that line and
    /// name `enrol <line>`, and no help offers the old spelling.
    #[test]
    fn relay_enrol_and_vault_enrol_are_gone_and_the_usage_says_enrol_a_line() {
        use kotton_wire::line::InstanceLine;
        let vault = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: [7; 32] }.to_text();
        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [5; 32] }.to_text();
        let gone = |parsed: Parsed<'_>, word: &str| match parsed {
            Parsed::Refuse(why) => {
                assert!(why.contains(&format!("`{word} enrol` is now `enrol <line>`")), "{why}");
                assert!(why.contains(MAKE_AND_OPERATE), "{why}");
            }
            other => panic!("`{word} enrol` is still a verb: {other:?}"),
        };
        for line in [&["enrol", "kotton", &vault][..], &["enrol", &vault], &["enrol"], &["enrol", "kotton", "vault=07", "addr=x:1"]] {
            gone(parse_vault(line, &[]), "vault");
        }
        for line in [&["enrol", "gate", &relay][..], &["enrol", &relay], &["enrol"], &["enrol", "gate", "http://203.0.113.9:7700"]] {
            gone(parse_relay(line, &[]).expect("an operator line"), "relay");
        }
        for usage in [VAULT_USAGE, RELAY_OPERATOR_USAGE, ENROL_USAGE] {
            assert!(usage.contains(MAKE_AND_OPERATE), "{usage}");
            assert!(usage.contains("enrol <line>"), "{usage}");
            assert!(!usage.contains("relay enrol") && !usage.contains("vault enrol"), "{usage}");
        }
        for help in [VaultCommand.help_text(), super::super::RelayCommand.help_text(), EnrolCommand.help_text()] {
            assert!(help.contains(MAKE_AND_OPERATE), "{help}");
            assert!(!help.contains("enrol <v>") && !help.contains("enrol <r>") && !help.contains("[enrol"), "{help}");
        }
        assert!(EnrolCommand.help_text().starts_with("enrol <line> [<line>…]"));
    }

    /// **`enrol` takes one line or several, space-separated or one per row,
    /// through the one parser** (Done-when (1)): both ways of giving two lines
    /// send the same two, in the same order; a word that is no line is said
    /// beside them — a name, with what `enrol` takes instead — and does not
    /// stop them; nothing at all is the usage.
    #[test]
    fn enrol_reads_lines_space_separated_or_one_per_row_with_one_parser() {
        use kotton_wire::ipc::LineCame;
        use kotton_wire::line::InstanceLine;
        let vault = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: [7; 32] }.to_text();
        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [5; 32] }.to_text();
        let (sent, said) = parse_enrol(&format!("{vault} {relay}")).expect("two lines");
        assert_eq!(sent, vec![vault.clone(), relay.clone()]);
        assert!(said.is_empty());
        assert_eq!(parse_enrol(&format!("{vault}\n{relay}\n")).expect("one per row").0, sent, "one parser");
        let (sent, said) = parse_enrol(&format!("kotton {vault}")).expect("a line and a word");
        assert_eq!(sent, vec![vault]);
        match said.as_slice() {
            [w] => match &w.came_to {
                LineCame::Refused { why } => assert!(why.contains("`enrol` takes no name"), "{why}"),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
        let cut = relay.replacen(&"05".repeat(32), &"05".repeat(31), 1);
        let (_, said) = parse_enrol(&cut).expect("a line cut short");
        assert!(matches!(&said[0].came_to, LineCame::Refused { why } if why.contains("64 hex")), "said as the parser says it: {said:?}");
        assert!(parse_enrol("  \n").is_none());
    }

    /// **What each line came to is said in its three readouts** (Done-when
    /// (1)): what it names, whether it is reached from here, whether its key
    /// matched — then kept, asked or refused. A line not dialled says so
    /// rather than *no*.
    #[test]
    fn each_line_is_said_by_what_it_names_whether_it_is_reached_and_whether_its_key_matched() {
        use kotton_wire::ipc::{LineCame, LineEnrolled};
        let line = |dialled, reached, matched, came_to| LineEnrolled {
            line: format!("kotton-instance:vault:{}@203.0.113.9:7710", "7c1e4a9f".repeat(8)),
            kind: Some(OperatedService::Vault),
            hint: "203.0.113.9:7710".into(),
            dialled,
            reached,
            matched,
            came_to,
        };
        let field = |rows: &[(String, String)], k: &str| rows.iter().find(|(f, _)| f == k).map(|(_, v)| v.clone()).unwrap();
        let kept = readout(&line(true, Some(true), Some(true), LineCame::Kept { name: "vault".into(), only: true, unstood: None, stood: Vec::new() }));
        assert_eq!(field(&kept, "names"), "a vault at 203.0.113.9:7710, key 7c1e4a9f…");
        assert_eq!(field(&kept, "reached from here"), "yes");
        assert_eq!(field(&kept, "its key"), "matched");
        assert_eq!(field(&kept, "enrolled"), "you operate the vault; its credential is sealed in your store", "the kind's word is no name");
        let named = readout(&line(true, Some(true), Some(true), LineCame::Kept { name: "attic".into(), only: false, unstood: None, stood: Vec::new() }));
        assert!(field(&named, "enrolled").contains("the vault 'attic'"), "{named:?}");
        let stand_in = readout(&line(true, Some(true), Some(false), LineCame::Refused { why: "another key".into() }));
        assert_eq!((field(&stand_in, "reached from here"), field(&stand_in, "its key")), ("yes".into(), "did not match".into()));
        let nobody = readout(&line(true, Some(false), None, LineCame::Refused { why: "no answer".into() }));
        assert_eq!(field(&nobody, "reached from here"), "no — nothing answered there");
        let asked = readout(&line(false, None, None, LineCame::Which { names: vec!["home".into(), "attic".into()] }));
        assert_eq!((field(&asked, "reached from here"), field(&asked, "its key")), ("not dialled".into(), "not checked".into()));
        assert!(field(&asked, "not enrolled").contains("home, attic"), "{asked:?}");
    }

    /// **`relay rule <r>` reads the relay's rule and `relay rule <r> <rule>`
    /// sets it, by the relay's own name**, with one relay held or two; the
    /// relay's `set`, `clear` and `status` are not operator lines and are left
    /// to `relay`, and read nothing.
    #[test]
    fn relay_rule_reads_and_sets_by_the_relays_name() {
        for h in [held(&["gate"]), held(&["gate", "attic"])] {
            assert_eq!(parse_relay(&["rule", "gate"], &h), Some(Parsed::Speak(To::Named("gate"), OperatorVerb::ReadRule)));
            assert_eq!(
                parse_relay(&["rule", "gate", "people_i_invite"], &h),
                Some(Parsed::Speak(To::Named("gate"), OperatorVerb::SetRule { rule: AdmissionRule::PeopleIInvite }))
            );
            assert!(matches!(parse_relay(&["rule", "gate", "everyone"], &h), Some(Parsed::Refuse(_))));
            assert_eq!(parse_relay(&["invite", "gate"], &h), Some(Parsed::Speak(To::Named("gate"), OperatorVerb::RelayInvite)));
            assert!(matches!(parse_relay(&["invite", "gate", "sam"], &h), Some(Parsed::Refuse(_))), "a relay's invite names nobody");
        }
        for line in [&["set", "http://x:1"][..], &["clear"], &["status"], &[]] {
            assert_eq!(parse_relay(line, &[]), None, "{line:?}");
            assert!(!line.first().is_some_and(|w| RELAY_VERBS.contains(w)), "`relay {line:?}` would read the relays held");
        }
    }

    /// The vault's other verbs parse as they did: one verb each, and nothing else.
    #[test]
    fn the_vaults_other_verbs_are_one_verb_each() {
        let one = held(&["kotton"]);
        assert_eq!(parse_vault(&["people", "kotton"], &one), Parsed::Speak(To::Named("kotton"), OperatorVerb::Pools));
        assert_eq!(
            parse_vault(&["space", "kotton", "sam", "10"], &one),
            Parsed::Speak(
                To::Named("kotton"),
                OperatorVerb::SetQuota {
                    pool: "sam".into(),
                    quota: 10
                }
            )
        );
        assert!(matches!(parse_vault(&["space", "kotton", "sam", "0"], &one), Parsed::Refuse(_)));
        assert!(matches!(parse_vault(&["invite", "kotton", "sam", "--space", "x"], &one), Parsed::Refuse(_)));
        assert!(matches!(parse_vault(&[], &one), Parsed::Refuse(_)));
        assert!(matches!(parse_vault(&["rule", "kotton"], &one), Parsed::Refuse(_)), "a rule is the relay's");
    }

    /// **`vault digits <v> <name>` asks the vault for the digits `name`'s
    /// device was asked for**, and says them grouped to be read out, or that
    /// nobody has dialled yet.
    #[test]
    fn vault_digits_asks_for_the_digits_and_says_them_to_be_read_out() {
        assert_eq!(
            parse_vault(&["digits", "kotton", "sam"], &held(&["kotton"])),
            Parsed::Speak(To::Named("kotton"), OperatorVerb::Digits { pool: "sam".into() })
        );
        assert!(matches!(parse_vault(&["digits"], &held(&["kotton"])), Parsed::Refuse(_)), "the digits are someone's");
        assert_eq!(
            digits_said("sam", &[4_729]),
            vec![("digits".to_string(), "004 729".to_string()), ("read them to".to_string(), "sam".to_string())]
        );
        let none = digits_said("sam", &[]);
        assert!(none.len() == 1 && none[0].1.starts_with("none yet"), "{none:?}");
        let two = digits_said("sam", &[1, 2]);
        assert_eq!(two.iter().filter(|(k, _)| k == "digits").count(), 2, "{two:?}");
        assert!(two.last().unwrap().1.contains("one set per invite"), "{two:?}");
    }

    /// **`vault invite --me` is the operator's own act, and never an invite
    /// for someone named `--me`** (DEC-0086). A flag in the name's place is
    /// refused before anything is sent. The vault is named only where this
    /// desktop operates more than one.
    #[test]
    fn vault_invite_me_is_one_act_and_a_flag_is_never_a_name() {
        let one = held(&["kotton"]);
        assert_eq!(parse_vault(&["invite", "kotton", "--me"], &one), Parsed::InviteMe(To::Named("kotton")));
        assert_eq!(parse_vault(&["invite", "--me"], &one), Parsed::InviteMe(To::Only("kotton")));
        // The line the guide types is this act, on the one vault a bare
        // `mint vault` names by its kind's word. The guide is a terminal page,
        // so it types the verb after `kotton`, which the shell takes bare; the
        // page is held to `TypedLines::vault_invite_me` by `docs-check`.
        assert_eq!(parse_vault(&["invite", "--me"], &held(&["vault"])), Parsed::InviteMe(To::Only("vault")));
        for line in [
            &["invite", "kotton", "--you"][..],
            &["invite", "--you"],
            &["invite", "kotton", "--me", "--space", "10"],
            &["invite", "--me", "--space", "10"],
            &["invite", "--space", "10"],
        ] {
            assert!(matches!(parse_vault(line, &one), Parsed::Refuse(_)), "{line:?}: {:?}", parse_vault(line, &one));
        }
        let invite = |pool: &str, quota| OperatorVerb::Invite {
            pool: pool.into(),
            quota,
            ttl_seconds: INVITE_TTL_SECS,
        };
        assert_eq!(parse_vault(&["invite", "kotton", "sam"], &one), Parsed::Speak(To::Named("kotton"), invite("sam", None)));
        // With one vault, a line whose one complete reading is a person and
        // their space is that: the vault `kotton` is the one held.
        assert_eq!(
            parse_vault(&["invite", "kotton", "--space", "10"], &one),
            Parsed::Speak(To::Only("kotton"), invite("kotton", Some(10)))
        );
    }

    /// **Each mint prints the line a running service takes** — no Docker,
    /// since a vault's or relay's machine runs none (DEC-0085), and the
    /// relay's verb as the relay's user, against its state directory. The
    /// guides type these lines, and `docs-check` holds them there through
    /// [`TypedLines`]. The first operator's key is the one each service is
    /// created for (RFC-0084 V18), so a mint prints the install given
    /// `KOTTON_OPERATOR_KEY` too; the line a mint prints for the service's
    /// shell is the way a second operator is added.
    #[test]
    fn each_mint_prints_the_line_a_running_service_takes() {
        let lines = typed_lines("<key>", "<relay key>", "<vault key>");
        assert_eq!(lines.at_the_vault, "kvaultd operator enrol <key>");
        for line in [&lines.at_the_vault, &lines.at_the_relay] {
            assert!(!line.contains("docker"), "{line}");
        }
        assert!(at_the_relay("07ab").ends_with(" operator enrol 07ab"));
        assert!(at_the_relay("07ab").starts_with("runuser -u kotton-relay -- kotton-relay --state-dir /var/lib/kotton-relay "));
        // A new instance is created for the key, by the install of the kind's own archive.
        for (service, create) in [(OperatedService::Vault, &lines.create_vault), (OperatedService::Relay, &lines.create_relay)] {
            assert!(create.starts_with("KOTTON_OPERATOR_KEY=<key> "), "{create}");
            assert!(create.ends_with(&format!(" sh kotton-{}-<rev>-linux-x86_64/install.sh", service.word())), "{create}");
        }
        assert!(to_create(OperatedService::Vault, "07ab", None).starts_with("KOTTON_OPERATOR_KEY=07ab "));
    }

    /// The one failure a verb's answer came to, and nothing else drawn.
    fn failed(out: CommandOutput) -> String {
        match out.out.as_slice() {
            [Out::Fail { what, try_: None }] => what.clone(),
            other => panic!("not one failure: {other:?}"),
        }
    }

    /// **A verb's answer it did not ask for is said by its name, never
    /// printed** (#121). `VaultFull` stands in for a typed refusal a later
    /// release adds, as #122's tests: every verb says it in `answer_said`'s
    /// words, with none of its fields, and draws nothing else.
    #[test]
    fn an_answer_no_verb_names_is_said_by_its_name_never_printed() {
        let unnamed = UserResponse::VaultFull { held: 3, quota: 2 };
        for (_, _, verb) in nameless() {
            let word = verb.service().word();
            let said = failed(spoken(&verb, To::Only("home"), unnamed.clone()));
            assert_eq!(said, format!("{word}: {}", kotton_wire::ipc::answer_said(&unnamed)), "{verb:?}");
            assert!(!said.contains('{') && !said.contains("does not read"), "{said}");
        }
    }

    /// **Each verb acts on the answer it asked for, and on no other** (#121):
    /// a drop answered to `vault people` is not drawn as a drop, and an `Ok`
    /// answered to `relay rule` is not drawn as a rule. The answer asked for
    /// is drawn; a refusal is said in the vault's words, and a name the vault
    /// keeps in its one sentence (#108), through `answer_said` and no arm of
    /// this reader's own.
    #[test]
    fn a_verb_acts_on_the_answer_it_asked_for_and_says_any_other() {
        let tenant = || kotton_wire::ipc::VaultTenant { user_id: "sam".into(), held: 7, quota: None, devices: 1 };
        let people = spoken(&OperatorVerb::Pools, To::Named("home"), UserResponse::VaultTenants { tenants: vec![tenant()] });
        assert!(matches!(people.out.as_slice(), [Out::Table { rows, .. }] if rows.len() == 1));
        let not_asked = failed(spoken(&OperatorVerb::Pools, To::Named("home"), UserResponse::TenantDropped { tenant: tenant() }));
        assert!(not_asked.starts_with("vault: the answer was `TenantDropped`"), "{not_asked}");
        let not_a_rule = failed(spoken(&OperatorVerb::ReadRule, To::Only("gate"), UserResponse::Ok));
        assert!(not_a_rule.starts_with("relay: the answer was `Ok`"), "{not_a_rule}");
        let stood = spoken(&OperatorVerb::Stand, To::Only("home"), UserResponse::Ok);
        assert!(matches!(stood.out.as_slice(), [Out::Confirm { subject, .. }] if subject == "home"));

        let invite = OperatorVerb::Invite { pool: "sam".into(), quota: None, ttl_seconds: 5 };
        let kept = failed(spoken(&invite, To::Only("home"), UserResponse::VaultKeepsAlready { user_id: "sam".into() }));
        assert_eq!(kept, format!("vault: {}", kotton_wire::ipc::vault_keeps_already_said("sam")));
        let refused = failed(spoken(&OperatorVerb::Pools, To::Only("home"), UserResponse::Error { message: "no relay".into() }));
        assert_eq!(refused, "vault: no relay");
    }
}
