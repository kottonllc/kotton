// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `net` domain — how this node is reachable, and whether it currently is.
//!
//! Reached through [`KottonClient::net`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut net = client.net("did:key:…");
//! let status = net.status().await?;
//! # let _ = status;
//! # Ok(())
//! # }
//! ```
//!
//! Reachability only. Who may connect is `peer`, and what crosses the link once
//! open is `sync` — RFC-0054
//! keeps those apart deliberately, because a rendezvous URL is infrastructure
//! configuration while a paired device is an authority decision.

use std::io;

use kotton_wire::ipc::types::{GatewaySummary, PeerStatus, RelayReadout, SyncStatusResult};

use super::{KottonClient, RendezvousStatusInfo, UserRequest, UserResponse};

/// Aggregated network status returned by [`KottonClient::network_status`].
#[derive(Debug, Clone)]
pub struct NetworkStatusSummary {
    pub peers: Vec<PeerStatus>,
    pub quic_gateway: GatewaySummary,
    pub http_gateway: GatewaySummary,
    pub rendezvous_url: Option<String>,
    /// Whether the node is reachable through that relay now (RFC-0083 R6).
    pub relay: RelayReadout,
    pub sync: SyncStatusResult,
}

/// An operator credential kept by `relay claim` / `vault claim` or by an
/// enrol: the name it is kept under, and — for a vault this desktop could not
/// tell where to stand — why it stands at no relay yet. The credential is kept
/// either way; `vault stand <name>` tells it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptCredential {
    pub name: String,
    pub unstood: Option<kotton_wire::ipc::Unstood>,
}

/// An operator credential forgotten (`relay forget`, `vault forget`): the name
/// and service it was kept under, its key's public half, and whether its
/// instance answered when it was asked. An instance that did not answer may
/// still run, with the key enrolled until it is revoked there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgottenCredential {
    pub name: String,
    pub service: kotton_wire::ipc::OperatedService,
    pub key: String,
    pub answered: bool,
}

/// The `net` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Net<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `net` domain for a user.
    pub fn net(&mut self, user_id: &str) -> Net<'_> {
        Net {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Net<'_> {
    /// Where this node reaches the world. See [`KottonClient::network_status`].
    pub async fn status(&mut self) -> io::Result<NetworkStatusSummary> {
        let u = self.user_id.clone();
        self.client.network_status(&u).await
    }

    /// Point this node at a rendezvous server. See [`KottonClient::node_rendezvous_set`].
    pub async fn set_rendezvous(&mut self, url: Option<&str>) -> io::Result<()> {
        self.client.node_rendezvous_set(url).await
    }

    /// Whether the rendezvous server is answering.
    /// See [`KottonClient::node_rendezvous_status`].
    pub async fn rendezvous_status(&mut self) -> io::Result<RendezvousStatusInfo> {
        self.client.node_rendezvous_status().await
    }

    /// Point this node at a TURN relay. See [`KottonClient::node_turn_set`].
    pub async fn set_turn(&mut self, url: Option<&str>) -> io::Result<()> {
        self.client.node_turn_set(url).await
    }
}


impl KottonClient {
    /// Set or clear the rendezvous server URL for this device.
    ///
    /// Pass `None` to remove the configured rendezvous server; the device will fall
    /// back to direct QUIC only.
    pub async fn node_rendezvous_set(&mut self, url: Option<&str>) -> io::Result<()> {
        let request = UserRequest::RendezvousSet {
            url: url.map(str::to_owned),
        };
        match self.client.send(&request).await? {
            UserResponse::RendezvousSet => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Stand this device at the relay `code` names, held to the key it names —
    /// a relay's line (what an invite's admit offers) or a relay's invite, whose
    /// invited key `user_id` then keeps sealed and presents there
    /// (`UserRequest::RelayStand`). Nothing changes unless the relay proves the
    /// code's key.
    pub async fn relay_stand(&mut self, user_id: &str, code: &str) -> io::Result<()> {
        let request = UserRequest::RelayStand {
            user_id: user_id.to_owned(),
            code: kotton_wire::ipc::SecretText::new(code),
        };
        match self.client.send(&request).await? {
            UserResponse::RendezvousSet => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the current rendezvous configuration and recent activity summary.
    pub async fn node_rendezvous_status(&mut self) -> io::Result<RendezvousStatusInfo> {
        let request = UserRequest::RendezvousStatus;
        match self.client.send(&request).await? {
            UserResponse::RendezvousStatus(info) => Ok(info),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Turn this machine's inference runtime on or off (RFC-0085).
    ///
    /// Stored, not started: `kuserd` reads the key at boot. The answer to
    /// "is it running now?" is `kotton sidecars`.
    pub async fn inference_set(&mut self, enabled: bool) -> io::Result<()> {
        let request = UserRequest::InferenceSet { enabled };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Read, or answer, the local-network door: `closed`, `10m` or `always`, or `None`
    /// to read without changing it.
    pub async fn local_door(&mut self, answer: Option<String>) -> io::Result<LocalDoor> {
        match self.client.send(&UserRequest::LocalDoor { answer }).await? {
            UserResponse::LocalDoorResult { answer, remaining_secs, listening, network_known } => {
                Ok(LocalDoor { answer, remaining_secs, listening, network_known })
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Set or clear the TURN relay URL for this device.
    pub async fn node_turn_set(&mut self, url: Option<&str>) -> io::Result<()> {
        let request = UserRequest::TurnSet {
            url: url.map(str::to_owned),
        };
        match self.client.send(&request).await? {
            UserResponse::TurnSet => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// What a vault keeps for this user and how much it may (RFC-0084 V3):
    /// `(held, quota)` in bytes, quota `None` when the keeper sets none.
    pub async fn vault_capacity(&mut self, user_id: &str) -> io::Result<(u64, Option<u64>)> {
        let request = UserRequest::VaultCapacity {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::VaultCapacityResult { held, quota } => Ok((held, quota)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Mint an operator credential for the vault or the relay `name` — with
    /// none, labelled by its kind's word — in this person's own store
    /// (DEC-0083, DEC-0087) and return the public half, for that service's
    /// terminal to enrol. Each mint is its own key. `rule` is a
    /// relay's first rule, and a vault's mint is refused with one. The secret
    /// stays in the store; nothing here ever holds it.
    pub async fn operator_mint(
        &mut self,
        user_id: &str,
        service: kotton_wire::ipc::OperatedService,
        name: Option<&str>,
        rule: Option<kotton_wire::rendezvous::AdmissionRule>,
    ) -> io::Result<String> {
        let request = UserRequest::OperatorMint {
            user_id: user_id.to_string(),
            service,
            name: name.map(str::to_string),
            rule,
        };
        match self.client.send(&request).await? {
            UserResponse::OperatorMinted { key, .. } => Ok(key),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// The keys `operator_mint` kept and nothing has completed yet, each by
    /// its name, its service and its public half — what a bare `mint` lists.
    pub async fn operator_mints(&mut self, user_id: &str) -> io::Result<Vec<kotton_wire::ipc::MintWaiting>> {
        let request = UserRequest::OperatorMints { user_id: user_id.to_string() };
        match self.client.send(&request).await? {
            UserResponse::OperatorMints { mints } => Ok(mints),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// The names of the instances of `service` this person operates, in the
    /// order kept: what an operating verb typed with no name reads, once, to
    /// say itself to the one there is.
    pub async fn operator_held(&mut self, user_id: &str, service: kotton_wire::ipc::OperatedService) -> io::Result<Vec<String>> {
        let request = UserRequest::OperatorHeld { user_id: user_id.to_string(), service };
        match self.client.send(&request).await? {
            UserResponse::OperatorHeld { names } => Ok(names),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Forget the credential this person keeps for the `service` called
    /// `name`, once its instance no longer stands its key (`relay forget`,
    /// `vault forget`): answered with the key's public half and
    /// whether the instance answered when asked, or refused — the instance still
    /// standing the key among the reasons.
    pub async fn operator_forget(
        &mut self,
        user_id: &str,
        service: kotton_wire::ipc::OperatedService,
        name: &str,
    ) -> io::Result<ForgottenCredential> {
        let request = UserRequest::OperatorForget { user_id: user_id.to_string(), service, name: name.to_string() };
        match self.client.send(&request).await? {
            UserResponse::OperatorForgotten { name, service, key, answered } => {
                Ok(ForgottenCredential { name, service, key, answered })
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Keep a whole `kotton-operator 2` credential sealed in this person's own
    /// store. Returns what was kept, and why a vault is not yet standing at a
    /// relay when it could not be told. A key `operator_mint` kept is completed
    /// by [`Self::operator_complete`].
    pub async fn operator_enrol(&mut self, user_id: &str, credential: &str) -> io::Result<KeptCredential> {
        let request = UserRequest::OperatorEnrol {
            user_id: user_id.to_string(),
            credential: kotton_wire::ipc::SecretText::new(credential),
        };
        match self.client.send(&request).await? {
            UserResponse::OperatorEnrolled { name, unstood, .. } => Ok(KeptCredential { name, unstood }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// `enrol <line> [<line>…]`: complete, each on its own, the keys
    /// `operator_mint` kept from the lines their instances printed when they
    /// were created (RFC-0084 V21). The daemon finds the key waiting for each
    /// line's kind, holds the instance to the line's key before it keeps
    /// anything, and answers what each line came to, in the order
    /// given — `LineCame::Which` when several keys of a kind wait, which a
    /// `LineToEnrol::mint` answers.
    pub async fn operator_enrol_lines(
        &mut self,
        user_id: &str,
        lines: Vec<kotton_wire::ipc::LineToEnrol>,
    ) -> io::Result<Vec<kotton_wire::ipc::LineEnrolled>> {
        let request = UserRequest::OperatorEnrolLines { user_id: user_id.to_string(), lines };
        match self.client.send(&request).await? {
            UserResponse::OperatorEnrolledLines { lines } => Ok(lines),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// One line through [`Self::operator_enrol_lines`], completing the key
    /// waiting under `mint` — the answer to *which*, when several keys of the
    /// line's kind wait. Returns what was kept, as [`Self::operator_enrol`]
    /// does; a line that was not kept, or asked which, is an `Err` saying why.
    pub async fn operator_complete(&mut self, user_id: &str, mint: &str, line: &str) -> io::Result<KeptCredential> {
        let given = kotton_wire::ipc::LineToEnrol { line: line.to_string(), mint: Some(mint.to_string()) };
        let came = self.operator_enrol_lines(user_id, vec![given]).await?.into_iter().next();
        match came.map(|l| l.came_to) {
            Some(kotton_wire::ipc::LineCame::Kept { name, unstood, .. }) => Ok(KeptCredential { name, unstood }),
            Some(kotton_wire::ipc::LineCame::Refused { why }) => Err(io::Error::other(why)),
            Some(kotton_wire::ipc::LineCame::Which { names }) => {
                Err(io::Error::other(format!("several keys wait for this line's kind: {}", names.join(", "))))
            }
            None => Err(io::Error::other("the daemon answered no line")),
        }
    }

    /// Say one of the landlord's verbs to the vault or the relay `name` — the
    /// verb says which — under the operator credential this person keeps for
    /// it. The answer is returned whole, refusals included — the service's, or
    /// this daemon's when it holds no credential by that name or the service
    /// does not answer — so a caller can read which it was; `Err` is only the
    /// local connection failing.
    pub async fn as_operator(
        &mut self,
        user_id: &str,
        name: &str,
        verb: kotton_wire::ipc::OperatorVerb,
    ) -> io::Result<UserResponse> {
        let request = UserRequest::AsOperator {
            user_id: user_id.to_string(),
            name: name.to_string(),
            verb,
        };
        self.client.send(&request).await
    }

    /// Make this desktop a tenant of the vault it operates as `vault`, in one
    /// act (DEC-0086, `vault invite <v> --me`): mint an invite over the
    /// operator channel for a pool named `user_id` — the user this desktop acts
    /// as, so the pool and the name it syncs under cannot differ — and admit it
    /// here, held to the vault key the credential pins
    /// ([`Self::device_admit_as_operator_stream`]). No words are typed and no
    /// digits are asked. A vault that keeps for `user_id` already mints
    /// nothing and says so in its own answer (`VaultKeepsAlready`), which is
    /// [`InvitedMe::KeptAlready`]: what this act asks for is so already (#108).
    /// Any other refusal to mint (no credential is kept for `vault`, the vault
    /// stands at no relay) is the `Err`.
    pub async fn vault_invite_me_stream(
        &mut self,
        user_id: &str,
        vault: &str,
        ttl_seconds: u64,
    ) -> io::Result<InvitedMe> {
        let verb = kotton_wire::ipc::OperatorVerb::Invite {
            pool: user_id.to_string(),
            quota: None,
            ttl_seconds,
        };
        let code = match self.as_operator(user_id, vault, verb).await? {
            UserResponse::PairAdvertising { code, .. } => code.expose().to_string(),
            UserResponse::VaultKeepsAlready { .. } => return Ok(InvitedMe::KeptAlready),
            UserResponse::Error { message } => return Err(io::Error::other(message)),
            got => return Err(crate::protocol::unexpected(got)),
        };
        self.device_admit_as_operator_stream(user_id, &code, ttl_seconds, vault)
            .await
            .map(InvitedMe::Admitting)
    }

    /// Aggregated network status: peers, both gateways, rendezvous, and sync.
    pub async fn network_status(
        &mut self,
        user_id: &str,
    ) -> io::Result<NetworkStatusSummary> {
        let request = UserRequest::NetworkStatus {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::NetworkStatusResult {
                peers,
                quic_gateway,
                http_gateway,
                rendezvous_url,
                relay,
                sync,
            } => Ok(NetworkStatusSummary {
                peers,
                quic_gateway,
                http_gateway,
                rendezvous_url,
                relay,
                sync,
            }),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// What `vault invite --me` came to at the vault
/// ([`crate::KottonClient::vault_invite_me_stream`]).
#[derive(Debug)]
pub enum InvitedMe {
    /// The vault minted an invite for this person, and this device's admit is
    /// running: its frames, as a ceremony streams them.
    Admitting(tokio::sync::mpsc::Receiver<UserResponse>),
    /// The vault keeps for this person's name already, in its own word, and
    /// minted nothing: the keep the act asks for is done.
    KeptAlready,
}

/// Where the local-network door stands, as `LocalDoor` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDoor {
    /// `closed`, `10m` or `always`.
    pub answer: String,
    /// Seconds left on `10m`, when it is running here.
    pub remaining_secs: Option<u64>,
    /// Where the door's listener is bound, when one exists.
    pub listening: Option<String>,
    /// Whether this device can tell which network it is on.
    pub network_known: bool,
}
