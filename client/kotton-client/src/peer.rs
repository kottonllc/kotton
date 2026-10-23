// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `peer` domain — the other devices a user's data moves between, and the
//! ceremony that admits one.
//!
//! Reached through [`KottonClient::peer`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut peer = client.peer("did:key:…");
//! let nodes = peer.nodes().await?;
//! # let _ = nodes;
//! # Ok(())
//! # }
//! ```
//!
//! ## The pairing stream is still the protocol's enum
//!
//! [`Peer::add_device`] and [`Peer::join_device`] return a channel of raw
//! [`UserResponse`] frames rather than a typed progress value. That is the one
//! place this facade still hands a consumer the god-enum, and
//! RFC-0055's correction
//! identified those call sites — nine, all in `shell/commands/device.rs` — as the
//! entirety of its real remaining leak.
//!
//! It is left as it is deliberately. The fix is to hoist the nine `Pair*`
//! variants into a `PairingProgress` type **in the protocol crate**, so the
//! facade re-exports rather than defines it and RFC-0055's rule 3 holds. Measured,
//! that touches 197 sites across the protocol, runtime and daemon — which makes it
//! part of the protocol split rather than of this pass, and the split is now
//! unblocked by the wire-format decision.
//!
//! A progress stream is a real requirement, not an escape hatch. Pairing has
//! seven observable states and a consumer must render them.

use std::io;

use kotton_ipc::IpcClient;
use kotton_schemas::membership::Posture;
use tokio::sync::mpsc;

use super::{
    EphemeralSession, KottonClient, PairedNode, SessionPermissions, UserRequest, UserResponse,
};

/// Pass a join's frames through, keeping the session its `PairingComplete` carries
/// in the session cache before that frame reaches the caller, so a caller that sees
/// the join complete finds the session already there.
fn keeping_the_joined_session(
    user_id: String,
    mut frames: mpsc::Receiver<UserResponse>,
) -> mpsc::Receiver<UserResponse> {
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        while let Some(frame) = frames.recv().await {
            if let UserResponse::PairingComplete { session_token: Some(token), .. } = &frame {
                crate::session_cache::save(&user_id, token.expose());
            }
            if tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    rx
}

/// Authenticate a fresh connection with an existing session token.
async fn authenticate_raw(
    raw: &mut IpcClient<UserRequest, UserResponse>,
    token: &str,
) -> io::Result<()> {
    match raw
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: None,
        })
        .await?
    {
        // The daemon answers a successful auth with the bound session's user.
        UserResponse::ActiveSession { .. } | UserResponse::Ok => Ok(()),
        UserResponse::NoActiveSession => Err(io::Error::other(
            "session token is not valid on this daemon",
        )),
        UserResponse::Error { message } => Err(io::Error::other(message)),
        _ => Err(io::Error::other("unexpected authenticate response")),
    }
}

/// The `peer` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Peer<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `peer` domain for a user.
    pub fn peer(&mut self, user_id: &str) -> Peer<'_> {
        Peer {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Peer<'_> {
    /// Issue a short-lived ticket for a guest device.
    /// See [`KottonClient::pair_node_ephemeral`].
    pub async fn pair_guest(
        &mut self,
        label: &str,
        paths: Vec<String>,
        permissions: SessionPermissions,
        ttl_seconds: u64,
    ) -> io::Result<EphemeralSession> {
        let u = self.user_id.clone();
        self.client
            .pair_node_ephemeral(&u, label, paths, permissions, ttl_seconds)
            .await
    }

    /// Every paired device. See [`KottonClient::list_nodes`].
    pub async fn nodes(&mut self) -> io::Result<Vec<PairedNode>> {
        let u = self.user_id.clone();
        self.client.list_nodes(&u).await
    }

    /// Revoke a paired device. See [`KottonClient::revoke_node`].
    pub async fn revoke(&mut self, node_id: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.revoke_node(&u, node_id).await
    }

    /// Add a peer whose key and address are already known, skipping the
    /// ceremony. See [`KottonClient::peer_add`].
    pub async fn add(
        &mut self,
        label: &str,
        peer_did: &str,
        peer_pubkey_hex: &str,
        peer_addr: std::net::SocketAddr,
    ) -> io::Result<PairedNode> {
        let u = self.user_id.clone();
        self.client
            .peer_add(&u, label, peer_did, peer_pubkey_hex, peer_addr)
            .await
    }

    /// Start the streamed `device add` ceremony as issuer.
    ///
    /// Yields raw [`UserResponse`] frames — see the module doc for why this one
    /// verb still exposes the protocol enum. See [`KottonClient::device_add_stream`].
    pub async fn add_device(
        &self,
        user_id: &str,
        as_name: Option<&str>,
        ttl_seconds: u64,
        port: u16,
        posture: Posture,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        self.client
            .device_add_stream(user_id, as_name, ttl_seconds, port, posture)
            .await
    }

    /// Join another device's ceremony. See [`KottonClient::device_join_stream`].
    pub async fn join_device(
        &self,
        user_id: &str,
        code: &str,
        as_name: Option<&str>,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        self.client
            .device_join_stream(user_id, code, as_name)
            .await
    }

    /// Answer a `PairShowCode` frame: `matches` is whether the human confirmed
    /// the six digits agree on both devices. See [`KottonClient::pair_confirm_code`].
    pub async fn confirm_code(&self, token: &str, matches: bool) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.pair_confirm_code(&u, token, matches).await
    }

    /// Get or set this device's announced name. See [`KottonClient::device_name`].
    pub async fn device_name(&mut self, new_name: Option<&str>) -> io::Result<String> {
        self.client.device_name(new_name).await
    }

    /// This node's identity. See [`KottonClient::get_node_identity`].
    pub async fn node_identity(&mut self) -> io::Result<(String, String)> {
        self.client.get_node_identity().await
    }
}

impl KottonClient {
    /// Issue a short-lived ephemeral session ticket for a guest device.
    ///
    /// Returns the newly created [`EphemeralSession`].
    pub async fn pair_node_ephemeral(
        &mut self,
        user_id: &str,
        label: &str,
        paths: Vec<String>,
        permissions: SessionPermissions,
        ttl_seconds: u64,
    ) -> io::Result<EphemeralSession> {
        let request = UserRequest::PairNodeEphemeral {
            user_id: user_id.to_string(),
            label: label.to_string(),
            paths,
            permissions,
            ttl_seconds,
            guest_ephemeral_pubkey: None,
        };
        match self.client.send(&request).await? {
            // pair_node_ephemeral returns SessionList with exactly one entry
            UserResponse::SessionList { mut sessions } if !sessions.is_empty() => {
                Ok(sessions.remove(0))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List all paired nodes for `user_id`.
    pub async fn list_nodes(&mut self, user_id: &str) -> io::Result<Vec<PairedNode>> {
        let request = UserRequest::NodeList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::NodeList { nodes } => Ok(nodes),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Revoke a paired node, removing it from the allowlist.
    pub async fn revoke_node(&mut self, user_id: &str, node_id: &str) -> io::Result<()> {
        let request = UserRequest::NodeRevoke {
            user_id: user_id.to_string(),
            node_id: node_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::NodeRevoked => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// The browsers admitted for `user_id` by the six-digit ceremony, oldest
    /// first (`BrowserDeviceList`).
    pub async fn list_browsers(
        &mut self,
        user_id: &str,
    ) -> io::Result<Vec<kotton_wire::ipc::types::BrowserDevice>> {
        let request = UserRequest::BrowserDeviceList {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::BrowserDevices { browsers } => Ok(browsers),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Revoke the browser admitted as `name` (`BrowserDeviceRevoke`): its next
    /// handshake needs a human again, and a channel it holds open now is ended.
    /// Returns how many channels were open.
    pub async fn revoke_browser(&mut self, user_id: &str, name: &str) -> io::Result<u32> {
        let request = UserRequest::BrowserDeviceRevoke {
            user_id: user_id.to_string(),
            name: name.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::BrowserDeviceRevoked { channels_closed } => Ok(channels_closed),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Open an additional connection to the **same** daemon this client is bound
    /// to (a streamed ceremony needs its own connection, and the confirm goes on
    /// yet another). Uses the retained endpoint so it works against a test/dev
    /// daemon on a non-default socket, not just the default `kuserd`.
    async fn fresh_connection(&self) -> io::Result<IpcClient<UserRequest, UserResponse>> {
        IpcClient::connect(self.endpoint.clone()).await
    }

    /// Start the streamed `device add` ceremony (issuer). Returns a channel of
    /// ceremony frames (`UserResponse`): render them, and when a `PairShowCode`
    /// arrives, show the six digits and answer with [`pair_confirm_code`]. The
    /// stream ends on `PairingComplete` or `PairFailed`. Requires an authenticated
    /// session (a dedicated connection is opened for the stream).
    ///
    /// `as_name` overrides this device's announced name for the ceremony (`--as`);
    /// `None` uses the persisted device name. The joiner adopts whatever this device
    /// announces and announces its own name back — neither side types the other's.
    pub async fn device_add_stream(
        &self,
        user_id: &str,
        as_name: Option<&str>,
        ttl_seconds: u64,
        port: u16,
        posture: Posture,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();
        let mut raw = self.fresh_connection().await?;
        authenticate_raw(&mut raw, &token).await?;
        raw.send_streaming(&UserRequest::DeviceAdd {
            user_id: user_id.to_string(),
            as_name: as_name.map(str::to_string),
            ttl_seconds,
            port,
            posture,
        })
        .await
    }

    /// Start pairing with another person (RFC-0022): the first frame carries the
    /// spoken code; confirm the six digits with [`Self::pair_confirm_code`]; the
    /// terminal frame is `ContactPaired` or `PairFailed`.
    pub async fn contact_pair_start_stream(
        &self,
        user_id: &str,
        as_name: Option<&str>,
        ttl_seconds: u64,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();
        let mut raw = self.fresh_connection().await?;
        authenticate_raw(&mut raw, &token).await?;
        raw.send_streaming(&UserRequest::ContactPairStart {
            user_id: user_id.to_string(),
            as_name: as_name.map(str::to_string),
            ttl_seconds,
        })
        .await
    }

    /// Join another person's pairing by the code they read out (RFC-0022).
    pub async fn contact_pair_join_stream(
        &self,
        user_id: &str,
        code: &str,
        as_name: Option<&str>,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();
        let mut raw = self.fresh_connection().await?;
        authenticate_raw(&mut raw, &token).await?;
        raw.send_streaming(&UserRequest::ContactPairJoin {
            user_id: user_id.to_string(),
            code: kotton_wire::ipc::SecretText::new(code),
            as_name: as_name.map(str::to_string),
        })
        .await
    }

    /// Open a desk for a browser to pair at (`WebShellPair`, DEC-0053): the
    /// stream carries `WebShellPairReady`, then a `PairShowCode` when a phone
    /// commits to its six digits. Answered with [`Self::pair_confirm_code`].
    pub async fn web_shell_pair_stream(
        &self,
        user_id: &str,
        ttl_seconds: u64,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();
        let mut raw = self.fresh_connection().await?;
        authenticate_raw(&mut raw, &token).await?;
        raw.send_streaming(&UserRequest::WebShellPair {
            user_id: user_id.to_string(),
            ttl_seconds,
        })
        .await
    }

    /// Enrol a gateway on another machine by the ceremony (`GatewayEnroll`,
    /// RFC-0078): `code` is what `khttpd enroll` printed there. Streams like
    /// [`Self::device_add_stream`]; answered with [`Self::pair_confirm_code`].
    /// Admit a listening node by its code under `posture` (`DeviceAdmit`,
    /// RFC-0084 V8): the node printed the code and is listening; this node
    /// dials it. Frames as [`Self::device_add_stream`].
    pub async fn device_admit_stream(
        &self,
        user_id: &str,
        code: &str,
        ttl_seconds: u64,
        posture: Posture,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();
        let mut raw = self.fresh_connection().await?;
        authenticate_raw(&mut raw, &token).await?;
        raw.send_streaming(&UserRequest::DeviceAdmit {
            user_id: user_id.to_string(),
            code: kotton_wire::ipc::SecretText::new(code),
            ttl_seconds,
            posture,
            operator_of: None,
        })
        .await
    }

    /// Admit an invite blind as the operator of the vault `vault` (DEC-0086):
    /// the vault that answers must prove the key this person's operator
    /// credential for it pins, and the six digits are confirmed by that key —
    /// no `PairShowCode` frame is streamed, and a vault that proves any other
    /// key ends in `PairFailed` naming both. Frames otherwise as
    /// [`Self::device_admit_stream`]. What `vault invite <v> --me` runs on the
    /// invite it has just minted ([`Self::vault_invite_me_stream`]).
    pub async fn device_admit_as_operator_stream(
        &self,
        user_id: &str,
        code: &str,
        ttl_seconds: u64,
        vault: &str,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();
        let mut raw = self.fresh_connection().await?;
        authenticate_raw(&mut raw, &token).await?;
        raw.send_streaming(&UserRequest::DeviceAdmit {
            user_id: user_id.to_string(),
            code: kotton_wire::ipc::SecretText::new(code),
            ttl_seconds,
            posture: Posture::BlindStorage,
            operator_of: Some(vault.to_string()),
        })
        .await
    }

    /// Mint an invite and wait to be admitted through the relay
    /// (`DeviceInvite`): session-less, like a join. The first frame is
    /// `PairAdvertising { code }` where the code is the invite,
    /// `kotton-invite:vault:…`; then the ceremony.
    pub async fn device_invite_stream(
        &self,
        user_id: &str,
        ttl_seconds: u64,
        as_name: Option<&str>,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let raw = self.fresh_connection().await?;
        raw.send_streaming(&UserRequest::DeviceInvite {
            user_id: user_id.to_string(),
            ttl_seconds,
            as_name: as_name.map(str::to_string),
        })
        .await
    }

    pub async fn gateway_enroll_stream(
        &self,
        user_id: &str,
        code: &str,
        ttl_seconds: u64,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let token = self
            .session_token
            .as_deref()
            .ok_or_else(|| io::Error::other("not authenticated"))?
            .to_owned();
        let mut raw = self.fresh_connection().await?;
        authenticate_raw(&mut raw, &token).await?;
        raw.send_streaming(&UserRequest::GatewayEnroll {
            user_id: user_id.to_string(),
            code: kotton_wire::ipc::SecretText::new(code),
            ttl_seconds,
        })
        .await
    }

    /// Start the streamed `device join` ceremony (new device). Session-less
    /// bootstrap. Returns a channel of ceremony frames; on success the terminal
    /// `PairingComplete` carries a `session_token` for this newly-joined device.
    ///
    /// `as_name` overrides this device's announced name for the ceremony (`--as`);
    /// `None` uses the persisted device name. This device labels the issuer with the
    /// name the issuer announces, and announces its own name back.
    ///
    /// The session that last frame carries is kept where [`Self::connect_as`] looks,
    /// as [`Self::create_user`] and every login keep theirs, so the next command on
    /// this device acts as the identity it joined: the ceremony is what proved this
    /// device, and that session is what the daemon issued for it.
    pub async fn device_join_stream(
        &self,
        user_id: &str,
        code: &str,
        as_name: Option<&str>,
    ) -> io::Result<mpsc::Receiver<UserResponse>> {
        let raw = self.fresh_connection().await?;
        let frames = raw
            .send_streaming(&UserRequest::DeviceJoin {
                user_id: user_id.to_string(),
                code: kotton_wire::ipc::SecretText::new(code),
                as_name: as_name.map(str::to_string),
            })
            .await?;
        if !self.caches_sessions {
            return Ok(frames);
        }
        Ok(keeping_the_joined_session(user_id.to_string(), frames))
    }

    /// Get (`new_name = None`) or set (`Some`) this device's human name — the label
    /// peers see when pairing (device-level; defaults to the OS hostname). Returns
    /// the resulting name.
    pub async fn device_name(&mut self, new_name: Option<&str>) -> io::Result<String> {
        match self
            .client
            .send(&UserRequest::DeviceName {
                new_name: new_name.map(str::to_string),
            })
            .await?
        {
            UserResponse::DeviceNameInfo { name } => Ok(name),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Deliver the human's SAS verdict for a parked ceremony (`token` from the
    /// `PairShowCode` frame). Sent on a fresh single-shot connection while the
    /// ceremony stream is still open.
    pub async fn pair_confirm_code(
        &self,
        user_id: &str,
        token: &str,
        matches: bool,
    ) -> io::Result<()> {
        let mut raw = self.fresh_connection().await?;
        match raw
            .send(&UserRequest::PairConfirmCode {
                user_id: user_id.to_string(),
                token: kotton_wire::ipc::SecretText::new(token),
                matches,
            })
            .await?
        {
            UserResponse::PairConfirmAck => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::other("unexpected confirm response")),
        }
    }

    /// Add a peer node by explicit DID, public key (hex), and address.
    ///
    /// Inserts the peer directly into the `paired_nodes` table and live mTLS
    /// allowlist without running the pairing ceremony.  Used by the demo recipe
    /// and integration tests that exchange identity out-of-band.
    ///
    /// `peer_pubkey_hex` must be 64 lowercase hex characters (32-byte Ed25519 key).
    pub async fn peer_add(
        &mut self,
        user_id: &str,
        label: &str,
        peer_did: &str,
        peer_pubkey_hex: &str,
        peer_addr: std::net::SocketAddr,
    ) -> io::Result<PairedNode> {
        self.peer_add_as(user_id, label, peer_did, peer_pubkey_hex, peer_addr, false).await
    }

    /// [`Self::peer_add`] for a node that is a vault the person keeps a drive
    /// on: the device records the drive (vault key and tenancy) and the row's
    /// posture `blind-storage`, as enrolling the vault would
    /// (`kotton_peer::daemon::drives`). `kotton id recover` adds the vault its
    /// line names this way.
    pub async fn peer_add_drive(
        &mut self,
        user_id: &str,
        label: &str,
        vault_did: &str,
        vault_key_hex: &str,
        vault_addr: std::net::SocketAddr,
    ) -> io::Result<PairedNode> {
        self.peer_add_as(user_id, label, vault_did, vault_key_hex, vault_addr, true).await
    }

    async fn peer_add_as(
        &mut self,
        user_id: &str,
        label: &str,
        peer_did: &str,
        peer_pubkey_hex: &str,
        peer_addr: std::net::SocketAddr,
        drive: bool,
    ) -> io::Result<PairedNode> {
        let request = UserRequest::PeerAdd {
            user_id: user_id.to_string(),
            label: label.to_string(),
            peer_did: peer_did.to_string(),
            peer_pubkey_hex: peer_pubkey_hex.to_string(),
            peer_addr,
            drive,
        };
        match self.client.send(&request).await? {
            UserResponse::NodePaired { node } => Ok(node),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Drop a paired node from the user's set: its key leaves the allowlist and
    /// its row is gone. The node is not consulted — leaving needs nobody's
    /// cooperation but the user's.
    pub async fn node_revoke(&mut self, user_id: &str, node_id: &str) -> io::Result<()> {
        let request = UserRequest::NodeRevoke {
            user_id: user_id.to_string(),
            node_id: node_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::NodeRevoked => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return this daemon's stable device DID and ephemeral signing public key (hex).
    ///
    /// The `signing_pubkey_hex` value is what a remote peer must pass to `peer_add`
    /// to allow mTLS connections from this node.
    pub async fn get_node_identity(&mut self) -> io::Result<(String, String)> {
        match self.client.send(&UserRequest::GetNodeIdentity).await? {
            UserResponse::NodeIdentity {
                device_did,
                signing_pubkey_hex,
            } => Ok((device_did, signing_pubkey_hex)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
