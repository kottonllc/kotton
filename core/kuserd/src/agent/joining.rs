// SPDX-License-Identifier: AGPL-3.0-or-later
//! Joining a network for the shell, and telling it what happened: the desktop
//! pairs a relay and enrols a vault from *Settings → Network*.
//!
//! ## What this is, beside [`super::ceremony`]
//!
//! The same shape and for the same reason. Admitting an invite is the
//! six-digit ceremony; it is not answerable from state the daemon
//! already holds, so it needs something that outlives a single host call — and
//! that something already exists, so this module puts a second map on
//! [`Ceremonies`] rather than a second copy of its eighteen fields. Two maps,
//! because a join and a contact pairing are two ceremonies on two screens and
//! neither may cancel the other.
//!
//! ## Two requests, and they are the terminal's
//!
//! | verb | request | the CLI that sends it |
//! |---|---|---|
//! | `admit`, a vault's invite | `DeviceAdmit`'s handler, blind | `kotton drive enrol <invite> --blind` |
//! | `admit`, a relay's invite | `RelayStand`'s handler | `relay set <invite>` |
//! | `take_relay` | `RelayStand`'s, with the line the admit offered | `relay set <line>` |
//!
//! The handler is called directly rather than a request being dispatched at
//! this daemon's own socket, which is how [`super::ceremony`] calls
//! `handle_contact_pair_start`. What matters for *no verb the shell can say
//! that the CLI cannot* is which handler runs and with what arguments, and
//! those are the CLI's — narrowed. The guest names an invite; the posture is
//! fixed blind here because a vault holds no key, and the user id
//! is the session's rather than an argument.
//!
//! ## Which door reaches it
//!
//! Settings has one door, *Paste a code*: a vault's invite pasted there is
//! `admit`. **Admitting an invite never sets this device's relay**: a device
//! that has none is offered the relay the vault was met at, in the
//! joined frame's words, and stands there only when the person says yes —
//! `take_relay`, which names nothing. The offer is kept here, by the relay's
//! line, so the yes cannot be pointed anywhere else.
//!
//! There is no *Stand this PC here too* after a relay is claimed: with no
//! caller it would be a dial nobody needed. The desktop completes the key it
//! minted from the line the service prints, which adds what it needs.
//!
//! ## The token stays here, and so do the digits
//!
//! As in [`super::ceremony`]: the stream parks on a confirmation token, the
//! token is taken out of the frame and kept in this daemon, and `confirm` looks
//! up the join *this occupant* started. A guest that could name a token could
//! answer a ceremony it did not start.
//!
//! **The six digits stay here too, which is where this differs from the
//! contact ceremony.** Admitting a vault makes this device the *issuer*, and
//! the ceremony's confirm is asymmetric — the issuer does not display the code:
//! the person types what the vault printed on its `sas=` line, and this daemon
//! compares that with the SAS it holds — the comparison `kotton drive enrol`
//! makes in the terminal (`prompt_code_match`). A guest that was shown the
//! digits could offer a yes/no, and a yes/no is blindly approvable, so the
//! person types the six digits rather than being asked whether they match.

use std::sync::Arc;

use kotton_wire::runner::{RunnerJoiningState, JOINING_FRAME_KIND};
use kotton_wire::UserResponse;

use super::ceremony::Ceremonies;

/// How long a join waits for the other end of the invite.
///
/// The same minute `kotton drive enrol` defaults to. A person who has just
/// been handed an invite is looking at the screen; a window measured in
/// minutes would leave them looking at it long after the answer was *nobody
/// is there*.
const ADMIT_TTL_SECONDS: u64 = 60;

/// One join in flight, as the daemon tracks it.
///
/// The twin of `ceremony::Running`, and deliberately not shared with it: the
/// two are looked up by two verbs that must not find each other's.
pub(crate) struct RunningJoin {
    /// What the ceremony is parked on, once both ends have met. `None` before
    /// that: there is nothing to confirm until there are digits, and a
    /// `confirm` that arrived early says so rather than answering nothing.
    pub(super) parked: Option<Parked>,
    /// Cancels the driving task, which is what abandons the join.
    pub(super) task: tokio::task::AbortHandle,
}

/// A join parked at the compare step: the token that answers it and the SAS
/// the typed digits are compared with. One value, so neither can be present
/// without the other — a token with no SAS would have nothing to compare, and
/// the only thing it could then do is answer blind.
pub(crate) struct Parked {
    /// The bearer token `confirm_code` fires.
    pub(super) token: String,
    /// The six digits both ends derived, which the other end printed and this
    /// one never shows.
    pub(super) sas: u32,
}

impl Ceremonies {
    /// Admit a vault's invite (`kotton-invite:vault:…`) under the blind posture.
    pub async fn admit(&self, user_id: String, invite: String) -> Result<(), String> {
        let invite = invite.trim().to_string();
        if invite.is_empty() {
            return Err(NO_INVITE.to_string());
        }
        self.start_join(user_id, invite).await
    }

    /// Stand this device at the relay `user_id`'s last admit offered, on the
    /// person's yes: held to the key the invite named, as `relay set <line>`
    /// is at the terminal. Refused when nothing was offered; the offer is
    /// spent either way, so a second yes is a second admit's.
    pub async fn take_relay(&self, user_id: &str) -> Result<(), String> {
        let Some(line) = self.offered.lock().await.remove(user_id) else {
            return Err(NO_OFFER.to_string());
        };
        super::handlers::device_config::stand_here(&self.runtime, &self.device_db, &line.hint, line.key, |_| Ok(())).await
    }

    /// Answer the join this occupant is running with the six digits the
    /// person typed. Compared here, never in the guest.
    pub async fn join_confirm(&self, user_id: &str, typed: &str) -> Result<(), String> {
        confirm_for(&self.joining, &self.pending_confirms, user_id, typed).await
    }

    /// Abandon whatever join this user had running, and any relay it offered.
    /// Idempotent.
    pub async fn join_cancel(&self, user_id: &str) {
        if let Some(prev) = self.joining.lock().await.remove(user_id) {
            prev.task.abort();
        }
        self.offered.lock().await.remove(user_id);
    }

    /// Spawn the driving task and record it, replacing whatever was there.
    ///
    /// A second attempt replaces the first, for the reason a second
    /// `pair_start` does: two live joins on one screen have no meaning, and a
    /// person pressing the button twice means *start over*. Aborting before
    /// spawning means there is never a window with two.
    ///
    /// **The slot is written before the task runs, not from inside it.** The
    /// task's first act on reaching the digits is to put the ceremony's token
    /// in this slot; a slot written by a second spawned task would be a race
    /// that drops the token, and `confirm` would then refuse a ceremony whose
    /// digits are on the screen.
    async fn start_join(&self, user_id: String, invite: String) -> Result<(), String> {
        let mut running = self.joining.lock().await;
        if let Some(prev) = running.remove(&user_id) {
            prev.task.abort();
        }
        // A new admit is a new offer, or none.
        self.offered.lock().await.remove(&user_id);
        let driving = self.clone();
        let uid = user_id.clone();
        let task = tokio::spawn(async move { driving.drive_admit(uid, invite).await });
        running.insert(
            user_id,
            RunningJoin {
                parked: None,
                task: task.abort_handle(),
            },
        );
        Ok(())
    }

    /// Run the admit ceremony, pushing every frame that means something.
    ///
    /// A relay's invite runs no ceremony: it stands this device at that relay,
    /// held to the key it names and holding the invited key it carries —
    /// `RelayStand`'s handler, which `relay set <invite>`
    /// reaches at the terminal — and ends joined to that relay, with no vault.
    async fn drive_admit(self, user_id: String, invite: String) {
        if let Ok(kotton_wire::line::InviteCode::Relay { hint, .. }) = kotton_wire::line::InviteCode::parse(&invite) {
            let named = relay_display_name(&hint);
            self.push_join(&user_id, RunnerJoiningState::Reaching { relay: named.clone() }).await;
            let stood = super::handlers::device_config::relay_stand(
                &self.runtime,
                &self.device_db,
                &self.users,
                &user_id,
                &invite,
            )
            .await;
            let state = match stood {
                Ok(_) => RunnerJoiningState::Joined { relay: named, vault: None, offered: false },
                Err(e) => RunnerJoiningState::Failed { reason: in_the_persons_words(&e.to_string(), &named) },
            };
            self.finish_join(&user_id, state).await;
            return;
        }
        // The relay the invite names, for the states below. An invite that is
        // not one still goes to the handler — it also accepts a bare connection
        // code — and the handler's refusal is what says so.
        let named = kotton_wire::line::InviteCode::parse(&invite)
            .ok()
            .and_then(|code| kotton_peer::pairing::Invite::of(&code))
            .map(|i| relay_display_name(&i.relay_url))
            .unwrap_or_else(|| relay_display_name(&self.runtime.reachability().nat().relay_url));
        self.push_join(&user_id, RunnerJoiningState::Reaching { relay: named.clone() })
            .await;

        let out = kotton_device::users::pairing::handle_device_admit(
            Arc::clone(&self.runtime),
            Arc::new(self.users.clone()) as Arc<dyn kotton_device::users::residency::Residency>,
            Arc::clone(&self.db),
            Arc::clone(&self.device_db),
            Arc::clone(&self.paired_keys),
            self.pending_confirms.clone(),
            user_id.clone(),
            invite,
            ADMIT_TTL_SECONDS,
            // Fixed here, and not an argument the guest may name: only the
            // blind posture is admitted this way, because a vault holds no key
            // and this door cannot make one that does.
            kotton_schemas::membership::Posture::BlindStorage,
            // Never held to a vault's key from this door: a guest names an
            // invite and nothing else, so the person answers the six digits
            // here as they would at the shell (holding the admit to a vault's
            // key is the operator's own act, and a guest is not the operator).
            None,
        )
        .await;

        let mut rx = match out {
            Ok(rx) => rx,
            // A ceremony that refuses before it starts still owes the screen a
            // sentence, for the reason `ceremony::drive` says: an unopenable
            // one that says nothing looks exactly like one still thinking. The
            // handler's type is the stream, so its refusal is this `Err` or a
            // frame on the stream, never a lone frame (#120).
            Err(e) => {
                self.finish_join(
                    &user_id,
                    RunnerJoiningState::Failed {
                        reason: in_the_persons_words(&e.to_string(), &named),
                    },
                )
                .await;
                return;
            }
        };

        while let Some(frame) = rx.recv().await {
            // The token and the digits are taken out of the frame and kept
            // here rather than pushed: see the module doc.
            if let UserResponse::PairShowCode { token, sas, .. } = &frame {
                if let Some(r) = self.joining.lock().await.get_mut(&user_id) {
                    r.parked = Some(Parked {
                        token: token.expose().to_owned(),
                        sas: *sas,
                    });
                }
            }
            // The relay the admit offers is kept here, for the yes.
            if let UserResponse::PairingComplete { relay_offer: Some(line), .. } = &frame {
                if let Ok(line) = kotton_wire::line::InstanceLine::parse(line) {
                    self.offered.lock().await.insert(user_id.clone(), line);
                }
            }
            let Some(state) = as_join_state(frame, &named) else {
                continue;
            };
            let last = matches!(
                state,
                RunnerJoiningState::Joined { .. } | RunnerJoiningState::Failed { .. }
            );
            self.push_join(&user_id, state).await;
            if last {
                break;
            }
        }
        self.joining.lock().await.remove(&user_id);
    }

    /// Push one joining frame to the shell.
    async fn push_join(&self, user_id: &str, state: RunnerJoiningState) {
        self.push_frame(user_id, JOINING_FRAME_KIND, &state).await;
    }

    /// Push a terminal frame and forget the join. One call, because forgetting
    /// without pushing leaves a screen mid-flight and pushing without
    /// forgetting leaves a `confirm` able to answer a ceremony that is over.
    async fn finish_join(&self, user_id: &str, state: RunnerJoiningState) {
        self.push_join(user_id, state).await;
        self.joining.lock().await.remove(user_id);
    }
}

/// Answer `user_id`'s join with what they typed, and nobody else's.
///
/// **The whole of `join_confirm`, as a function the tests can reach, because
/// it is the one thing standing between the six digits and a stranger's key.**
/// The guest cannot name a token and is never shown the digits —
/// `interface joining`'s `confirm` takes the typed text — so what has to hold
/// is on this side: the slot is looked up by *this* user, the typed digits are
/// compared with *that* slot's SAS, the ceremony hears `true` only on
/// equality, and a `confirm` arriving before there are digits is refused
/// rather than silently doing nothing.
///
/// **A wrong six refuses the ceremony; it is not a retry.** The terminal does
/// the same (`prompt_code_match`): one transcription, and a mismatch ends it
/// with nothing handed over. A retry loop would turn the comparison into a
/// guess the person — or a guest — could repeat.
///
/// The lookup lives here and not in `join_confirm` because the review that
/// asked for this found it one line outside the function under test: with the
/// lookup there, `.get(user_id)` could become "whichever slot is first" and
/// every test still passed, since a test with one user cannot tell the
/// difference. `confirm_fires_this_users_parked_ceremony_and_nothing_else`
/// parks two users' ceremonies at once for exactly that reason.
async fn confirm_for(
    joining: &tokio::sync::Mutex<std::collections::HashMap<String, RunningJoin>>,
    pending: &kotton_peer::daemon::nodes::PendingConfirms,
    user_id: &str,
    typed: &str,
) -> Result<(), String> {
    let (token, sas) = parked_for(&*joining.lock().await, user_id)?;
    let matched = typed_matches_sas(typed, sas);
    kotton_peer::daemon::nodes::confirm_code(pending, token, matched)
        .await
        .map_err(|e| format!("answering the comparison: {e}"))?;
    Ok(())
}

/// Whether what a person typed is the SAS: the digits in it, and only those,
/// equal the six zero-padded digits.
///
/// **The terminal's normalisation, exactly** — `digits_only(typed) ==
/// format!("{sas:06}")` in `prompt_code_match` (`client/shell/src/commands/device.rs`)
/// — so a person who types `042 137` or `042-137` at either surface is
/// answered the same way. One ceremony at two strengths is a defect; one ceremony under two normalisations would be the same
/// defect, smaller. Spelled here rather than shared because the shell's copy
/// sits in a client-region crate this daemon may not depend on.
pub(crate) fn typed_matches_sas(typed: &str, sas: u32) -> bool {
    let digits: String = typed.chars().filter(|c| c.is_ascii_digit()).collect();
    digits == format!("{sas:06}")
}

/// The token and SAS `user_id`'s join is parked on, or the sentence that says
/// there are none — looked up by that user and by nothing else.
///
/// **What keeps the confirm per user is that the token never leaves the daemon.**
/// `PendingConfirms` is one map for every ceremony on this node, keyed by the
/// bearer token, so anyone holding a token could fire that ceremony; the guest
/// never holds one, because `as_join_state` puts neither the token nor the
/// digits in the frame, and the only path from a guest to `confirm_code` is
/// [`confirm_for`], which reads the token out of *their* slot. A change that let a token reach a
/// frame, a log line or another user's slot would undo this without touching a
/// line here — which is why the sentence is on this function and not in a test.
fn parked_for(
    running: &std::collections::HashMap<String, RunningJoin>,
    user_id: &str,
) -> Result<(String, u32), String> {
    running
        .get(user_id)
        .and_then(|r| r.parked.as_ref())
        .map(|p| (p.token.clone(), p.sas))
        .ok_or_else(|| NO_DIGITS.to_string())
}

// ── What a person is told ─────────────────────────────────────────────────────

/// What `confirm` says when there are no digits yet.
const NO_DIGITS: &str =
    "There are no digits to compare yet: nothing this window started is waiting on a \
     comparison.";

/// What `take_relay` says when no admit offered a relay.
const NO_OFFER: &str = "There is no relay to stand at: nothing this window admitted offered one.";

/// What `admit` says when handed nothing.
const NO_INVITE: &str = "That is empty. An invite is one line, and it begins `kotton-invite:`.";

/// The name a relay is shown under: its address without the scheme.
///
/// The same rule `network_readout::relay_name` applies to the readout, so the
/// row a flow ends with is named the same as the row the pane already draws —
/// which is what *the new network is in the list by name* means. Spelled here
/// rather than shared, because that module's whole property is that it cannot
/// write anything and importing it from a module that does would read as one
/// module.
pub(crate) fn relay_display_name(url: &str) -> String {
    super::network_readout::relay_name(url)
}

/// What a person is told when a relay would not answer.
pub(crate) fn dial_refused(shown: &str, detail: &str) -> String {
    format!(
        "{shown} did not answer, so nothing changed — this device is still on the relay it was \
         on. Check the name and that the relay is running. ({detail})"
    )
}

/// The three refusals a join can end in, in the person's words.
///
/// A wrong name, a refused dial and a lapsed invite are the three a person
/// meets, and each has to say what to *do* — the daemon's own sentence says
/// what happened to a program. Anything else is passed through rather than
/// flattened into "it failed": a refusal this function does not recognise is
/// still the truest thing anyone knows about it.
pub(crate) fn in_the_persons_words(reason: &str, relay: &str) -> String {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("no vault is waiting on that invite")
        || lower.contains("has not expired")
        || lower.contains("nobody admitted this invite")
    {
        return format!(
            "Nobody is waiting on that invite at {relay}. An invite is good for a while and then \
             it lapses — check the words, or ask for a fresh one. ({reason})"
        );
    }
    if lower.contains("relay reservation")
        || lower.contains("relay circuit")
        || lower.contains("connectionfailed")
        || lower.contains("connection failed")
    {
        return dial_refused(relay, reason);
    }
    // A rejected SAS, keyed on the sentence that actually arrives: the admit
    // handler rewrites `PairChannelError::SasRejected` with
    // `ceremony_failure_copy` before this sees it, so the raw "codes did not
    // match" never reaches here (an arm keyed on it was unreachable, and the
    // person read the interference sentence instead). On this door the
    // issuer typed the digits, so a typo is the likelier cause and is said
    // first; the copy it replaces is not appended, because its whole content
    // is the reading this one corrects.
    if lower.contains("codes don't match") {
        return "Those are not the six digits the vault printed on its sas= line, so nothing \
                was handed over and nothing was joined. Check them and start again with a \
                fresh invite; if they were typed exactly as shown, something was in the middle."
            .to_string();
    }
    reason.to_string()
}

/// The stream's frames, as the surface sees them.
///
/// Frames with no surface meaning map to `None` and are skipped rather than
/// shown as an error, for the reason `ceremony::as_state` skips them: the
/// stream carries machinery a person has no use for.
pub(crate) fn as_join_state(resp: UserResponse, relay: &str) -> Option<RunnerJoiningState> {
    match resp {
        // No digits: this device is the issuer, and the issuer does not
        // display the code. The person types what the other end
        // printed, and `confirm_for` compares it with the SAS kept in the slot.
        UserResponse::PairShowCode { .. } => Some(RunnerJoiningState::Compare),
        UserResponse::PairingComplete { node, relay_offer, .. } => Some(RunnerJoiningState::Joined {
            // The relay the vault was met at. Admitting never makes it this
            // device's relay: `offered` says whether it is offered.
            relay: relay.to_string(),
            // An empty label is no label: the surface draws a name or the words
            // it has for a vault without one, and `Some("")` would have it draw
            // neither.
            vault: Some(node.id).filter(|id| !id.is_empty()),
            offered: relay_offer.is_some(),
        }),
        UserResponse::PairFailed { reason } => Some(RunnerJoiningState::Failed {
            reason: in_the_persons_words(&reason, relay),
        }),
        UserResponse::Error { message } => Some(RunnerJoiningState::Failed {
            reason: in_the_persons_words(&message, relay),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_wire::peer::PairedNode;

    const RELAY: &str = "droplet.austin.dev:7700";

    /// **A refused dial says nothing changed, and names the relay.**
    ///
    /// The sentence a person reads has to answer *what do I still have* —
    /// pairing dials before it writes, so the honest answer is *the relay you
    /// were on*, and a Notice that left that out would read as a loss.
    #[test]
    fn a_refused_dial_says_the_old_relay_is_still_there() {
        let said = dial_refused(RELAY, "connection refused");
        assert!(said.contains(RELAY), "{said}");
        assert!(said.contains("did not answer"), "{said}");
        assert!(said.contains("nothing changed"), "{said}");
        // And the daemon's own words are kept, in brackets: a person who is
        // going to paste this into a message wants the detail in it.
        assert!(said.contains("connection refused"), "{said}");
    }

    /// **A lapsed invite says what a person can do about it.**
    ///
    /// The refusal the ceremony raises says *no vault is waiting on that
    /// invite*, which is true and tells a person nothing. What they can do is
    /// check the words or ask for a fresh invite, so that is what it says.
    #[test]
    fn a_lapsed_invite_says_to_ask_for_a_fresh_one() {
        let raw = "no vault is waiting on that invite at http://droplet.austin.dev:7700 \
                   (relay circuit: closed) — check the words, and that the invite has not expired";
        let said = in_the_persons_words(raw, RELAY);
        assert!(said.contains("lapses"), "{said}");
        assert!(said.contains("fresh one"), "{said}");
        assert!(said.contains(RELAY), "{said}");
    }

    /// **A refused dial mid-ceremony is the same sentence as a refused pair.**
    ///
    /// One wording for one fact, because a person meets it at two doors and
    /// two spellings of *the relay would not answer* would read as two
    /// different problems.
    #[test]
    fn a_refused_dial_reads_the_same_at_both_doors() {
        let said = in_the_persons_words("relay reservation for the invite: ConnectionFailed", RELAY);
        assert_eq!(said, dial_refused(RELAY, "relay reservation for the invite: ConnectionFailed"));
    }

    /// **Wrong digits say nothing was handed over — from the sentence the
    /// ceremony actually sends.**
    ///
    /// The input is *produced*, not written: a rejected SAS leaves the ceremony
    /// as `PairChannelError::SasRejected`, and `handle_device_admit` rewrites it
    /// with `ceremony_failure_copy` before this module ever sees it. A test fed
    /// a literal the daemon never sends would pass while the person still read
    /// the interference sentence.
    /// On the issuer's typed confirm a wrong six is most likely a typo, so the
    /// sentence says what happened, that nothing was handed over, and only
    /// then what else it could mean.
    #[test]
    fn wrong_digits_say_nothing_was_handed_over_from_what_the_ceremony_sends() {
        use kotton_peer::daemon::nodes::ceremony_failure_copy;
        use kotton_peer::pair_channel::PairChannelError;
        let sent = ceremony_failure_copy(&PairChannelError::SasRejected.to_string());
        let said = in_the_persons_words(&sent, RELAY);
        assert!(said.contains("nothing was handed over"), "{said}");
        assert!(said.contains("sas="), "{said}");
        assert!(!said.contains("interfered"), "the typo reads as an attack: {said}");
    }

    /// **A refusal nobody recognised is passed through whole.**
    ///
    /// Flattening it into "it failed" would delete the only thing anyone knows
    /// about it. This is the honest-absence rule applied to an error message.
    #[test]
    fn an_unrecognised_refusal_is_passed_through_rather_than_flattened() {
        let odd = "the vault answered with a posture this device does not admit";
        assert_eq!(in_the_persons_words(odd, RELAY), odd);
    }

    /// **The compare step reaches the surface with no digits, and the end
    /// names the vault.**
    ///
    /// Two frames the pane draws and one it does not: `PairConnecting` is
    /// machinery, and a state pushed for it would be a step a person has
    /// nothing to do about. And the compare frame is only its name — this
    /// device is the issuer, and a frame that carried the SAS would hand the
    /// guest what it needs to draw a yes/no.
    #[test]
    fn the_frames_a_person_sees_are_the_compare_step_and_the_end() {
        let compare = as_join_state(
            UserResponse::PairShowCode {
                token: kotton_wire::ipc::SecretText::new("tok"),
                sas: 42_137,
                peer_label: Some("vault".to_owned()),
            },
            RELAY,
        );
        assert_eq!(compare, Some(RunnerJoiningState::Compare));
        let pushed = serde_json::to_string(&compare).expect("a state serialises");
        assert!(!pushed.contains("42137"), "the SAS reached the frame: {pushed}");
        assert!(!pushed.contains("tok"), "the token reached the frame: {pushed}");
        let node = PairedNode {
            id: "Vault \u{00b7} droplet".to_owned(),
            device_did: kotton_wire::did::Did::parse("did:key:z6MkVaultDroplet")
                .expect("a did:key parses"),
            public_key: [0u8; 32],
            paired_at: 1_755_648_000,
            addresses: Vec::new(),
            relay_url: Some("http://droplet.austin.dev:7700".to_owned()),
            posture: None,
        };
        assert_eq!(
            as_join_state(
                UserResponse::PairingComplete {
                    node: node.clone(),
                    session_token: None,
                    relay_offer: None,
                },
                RELAY
            ),
            Some(RunnerJoiningState::Joined {
                relay: RELAY.to_owned(),
                vault: Some("Vault \u{00b7} droplet".to_owned()),
                offered: false,
            })
        );
        // A device that stands at no relay is offered the one the vault was
        // met at — said in the frame, never taken by it.
        assert_eq!(
            as_join_state(
                UserResponse::PairingComplete {
                    node,
                    session_token: None,
                    relay_offer: Some(format!("kotton-instance:relay:{}@http://{RELAY}", "ab".repeat(32))),
                },
                RELAY
            ),
            Some(RunnerJoiningState::Joined {
                relay: RELAY.to_owned(),
                vault: Some("Vault \u{00b7} droplet".to_owned()),
                offered: true,
            })
        );
        assert_eq!(as_join_state(UserResponse::PairConnecting, RELAY), None);
    }

    /// **The typed digits are compared the way the terminal compares them.**
    ///
    /// `digits_only(typed) == format!("{sas:06}")` — the zero pad kept, the
    /// grouping a person types forgiven, and nothing else. One ceremony under
    /// two normalisations would answer the same six digits differently at two
    /// surfaces.
    #[test]
    fn typed_digits_are_compared_as_the_terminal_compares_them() {
        for typed in ["042137", "042 137", " 042-137\n"] {
            assert!(typed_matches_sas(typed, 42_137), "{typed:?} is the SAS as typed");
        }
        // The zero is part of the number a person reads.
        assert!(!typed_matches_sas("42137", 42_137));
        // Wrong, short, long, and nothing at all.
        for typed in ["042138", "04213", "0421370", "", "yes", "match"] {
            assert!(!typed_matches_sas(typed, 42_137), "{typed:?} matched");
        }
    }

    /// **`confirm` fires this user's parked ceremony, and nothing else — with
    /// `true` only for the right six.**
    ///
    /// The one thing standing between the six digits and a stranger's key. A
    /// guest cannot name a token at all and is never shown the digits —
    /// `interface joining`'s `confirm` takes the typed text — so what has to
    /// hold on this side is that the token comes from *this user's* slot, that
    /// the typed digits are compared with *that slot's* SAS, and that a
    /// `confirm` arriving before there are digits is refused rather than
    /// quietly doing nothing.
    ///
    /// **Two users' ceremonies are parked at once**, because a test with one
    /// user cannot tell "this user's slot" from "whichever slot is first" — and
    /// that is the mutation the review ran, which passed every test that
    /// existed. Each user's verdict must reach their own parked ceremony and
    /// leave the other's untouched, and a third user with nothing running is
    /// refused while both are parked. A lookup that fired any slot fails at
    /// least one of those three whichever slot a map happens to yield first.
    ///
    /// What is driven is [`confirm_for`], the whole of `join_confirm`, down to
    /// the `oneshot` the ceremony is parked on — so "fired" means the verdict
    /// arrived where the ceremony is waiting, not that a string was returned.
    #[tokio::test]
    async fn confirm_fires_this_users_parked_ceremony_and_nothing_else() {
        use std::collections::HashMap;
        use tokio::sync::{oneshot, Mutex};

        let (alice_tx, mut alice_rx) = oneshot::channel::<bool>();
        let (bob_tx, mut bob_rx) = oneshot::channel::<bool>();
        let pending: kotton_peer::daemon::nodes::PendingConfirms = std::sync::Arc::new(Mutex::new(
            HashMap::from([
                ("alice-token".to_owned(), alice_tx),
                ("bob-token".to_owned(), bob_tx),
            ]),
        ));
        // Two different SASes, so a lookup that compared against the wrong
        // slot's digits answers wrongly for at least one of them.
        let joining = Mutex::new(HashMap::from([
            (
                "alice".to_owned(),
                RunningJoin {
                    parked: Some(Parked {
                        token: "alice-token".to_owned(),
                        sas: 42_137,
                    }),
                    task: aborted_handle(),
                },
            ),
            (
                "bob".to_owned(),
                RunningJoin {
                    parked: Some(Parked {
                        token: "bob-token".to_owned(),
                        sas: 819_004,
                    }),
                    task: aborted_handle(),
                },
            ),
            // A join that has started and not yet reached the digits.
            (
                "carol".to_owned(),
                RunningJoin {
                    parked: None,
                    task: aborted_handle(),
                },
            ),
        ]));

        // Someone with nothing running is refused — while two ceremonies are
        // parked and one is starting, any of which a careless lookup would fire.
        assert_eq!(
            confirm_for(&joining, &pending, "dave", "042137")
                .await
                .expect_err("dave has no join"),
            NO_DIGITS
        );
        // So is someone whose join has not reached the digits yet.
        assert_eq!(
            confirm_for(&joining, &pending, "carol", "042137")
                .await
                .expect_err("carol has no digits yet"),
            NO_DIGITS
        );
        assert_eq!(
            alice_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty),
            "a refused confirm fired alice's ceremony"
        );
        assert_eq!(
            bob_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty),
            "a refused confirm fired bob's ceremony"
        );

        // Alice types her own six, grouped as she read them: her ceremony
        // hears *yes*, Bob's hears nothing.
        confirm_for(&joining, &pending, "alice", "042 137")
            .await
            .expect("alice's join is at the compare step");
        assert_eq!(alice_rx.try_recv(), Ok(true), "alice's right digits did not reach her ceremony as yes");
        assert_eq!(
            bob_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty),
            "alice's confirm fired bob's ceremony"
        );

        // Bob types six digits that are not his — they are Alice's. His
        // ceremony hears *no*, which is the check working, and nothing is
        // handed over. A confirm that compared against the wrong slot's SAS
        // would have said *yes* here.
        confirm_for(&joining, &pending, "bob", "042137")
            .await
            .expect("bob's join is at the compare step");
        assert_eq!(bob_rx.try_recv(), Ok(false), "bob's wrong digits reached his ceremony as yes");
    }

    /// An abort handle for a task that does nothing.
    ///
    /// `RunningJoin` carries one so a second attempt can cancel the first; the
    /// test above is about the token beside it, so the handle is real and
    /// points at a task with nothing to abort. It spawns on the ambient runtime,
    /// so it can only be called from a `#[tokio::test]`; a synchronous `#[test]`
    /// that calls it panics with "no reactor running".
    fn aborted_handle() -> tokio::task::AbortHandle {
        tokio::spawn(std::future::ready(())).abort_handle()
    }

    /// **An empty invite is refused before anything is started.**
    ///
    /// A person who pressed Join with nothing in the field gets told what an
    /// invite looks like, not a spinner and then a timeout a minute later.
    #[test]
    fn an_empty_invite_is_refused_with_an_example() {
        assert!(NO_INVITE.contains("kotton-invite:"), "{NO_INVITE}");
        assert!(NO_DIGITS.contains("comparison"), "{NO_DIGITS}");
    }
}
