// SPDX-License-Identifier: AGPL-3.0-or-later
//! Starting the peer listener — the device's half of being reachable.
//!
//! The reachability assembly itself lives in
//! [`kotton_peer::Reachability`](kotton_peer::reachability::Reachability): it
//! binds the QUIC socket, keeps the presence registration live, and holds the
//! relay reservation. What is left here is the device's part — driving the
//! accept loop and owning its task handle, because that loop ends when the
//! device shuts down.

use crate::config::NatNetworkConfig;
use crate::runtime::DeviceRuntime;
use anyhow::Result;
use kotton_peer::PeerHandler;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

impl DeviceRuntime {
    /// Bind the QUIC peer-listener on `port` and start the accept loop.
    ///
    /// # Arguments
    ///
    /// * `port` -- UDP port to bind on. The address comes from
    ///   [`kotton_peer::scope`]: all interfaces normally, loopback when the run
    ///   declared itself same-machine.
    /// * `handler` -- async callback invoked for each inbound peer request.
    ///   Receives raw request bytes, returns raw response bytes.
    ///
    /// Who may connect comes from [`paired_keys`](Self::paired_keys), which the
    /// daemon seeds and keeps current.
    pub async fn start_peer_listener(
        self: &Arc<Self>,
        port: u16,
        handler: PeerHandler,
    ) -> Result<()> {
        let listener = self.reachability.bind_peer_listener(port).await?;

        let handle = self.spawn_accept_loop(
            Arc::from(listener),
            format!("QUIC peer (port {port})"),
            handler,
        );
        self.accept_tasks.lock().await.push(handle);

        Ok(())
    }

    /// Hold this node's relay reservations and serve what arrives on them — the
    /// inbound path for when direct, punch and TURN all fail, and the only one
    /// for a node that binds no port at all.
    ///
    /// **Separate from [`Self::start_peer_listener`], and that is the point.**
    /// It used to be the last line of that function, so a node with no
    /// `peer_listen_port` held no reservations — which is exactly backwards: a
    /// machine that cannot be dialled is the one the relay exists for. A laptop
    /// behind NAT would have been unreachable by the path built for it, and a
    /// contact's message would have had no mailbox to arrive at.
    ///
    /// Started unconditionally: it idles until a relay is configured, which is
    /// what lets a device boot relay-less and become reachable from a
    /// `relay set` without a restart.
    pub fn start_relay_reservations(self: &Arc<Self>, handler: PeerHandler) {
        self.reachability.spawn_relay_listener(handler);
    }

    /// Where this device's peer listener bound, once it has — the address a
    /// peer must dial to reach this node's protocol.
    ///
    /// Read back off the socket
    /// ([`Reachability::peer_listen_addr`](kotton_peer::Reachability::peer_listen_addr)),
    /// never from the config that asked for it: a node whose listener was started
    /// by an explicit call has no configured port, and a bind on port 0 has none
    /// to have. A pairing ceremony announces this so the other side records where
    /// to dial rather than the bootstrap socket the ceremony ran over.
    pub fn peer_listen_addr(&self) -> Option<std::net::SocketAddr> {
        self.reachability.peer_listen_addr()
    }

    /// What a ceremony that observes no address should announce for this
    /// node's peer listener: the host's configured public address
    /// ([`RuntimeConfig::public_ip`](crate::config::RuntimeConfig::public_ip))
    /// with the port the listener actually bound, or the bound address itself
    /// when the host has none. A ceremony over QUIC does not need this — the
    /// other side completes an announced port with the address it reached this
    /// node on, which is known to work — but a ceremony met at a relay observes
    /// nothing, and a vault at a public address would otherwise be recorded
    /// with no address at all and reached only through the relay.
    pub fn announced_peer_addr(&self) -> Option<std::net::SocketAddr> {
        let bound = self.reachability.peer_listen_addr()?;
        Some(match self.config.public_ip {
            Some(ip) => std::net::SocketAddr::new(ip, bound.port()),
            None => bound,
        })
    }

    /// The live allowlist of paired device keys, for the daemon to seed from its
    /// records and keep current as devices are paired and revoked.
    ///
    /// The same set the TLS handshake admits from and the presence registrar
    /// announces to — see
    /// [`Reachability::paired_keys`](kotton_peer::Reachability::paired_keys).
    pub fn paired_keys(&self) -> Arc<RwLock<HashSet<[u8; 32]>>> {
        self.reachability.paired_keys()
    }

    /// Live-apply a reachability config change (e.g. a runtime `relay set`) — no
    /// restart. See [`Reachability::reconfigure`](kotton_peer::Reachability::reconfigure).
    ///
    /// The relays a person can be reached at are part of what changed, so each
    /// person's reach note is due too ([`Self::reach_changed`]).
    pub async fn reconfigure_network(&self, nat: NatNetworkConfig) -> Result<()> {
        let applied = self.reachability.reconfigure(nat).await;
        self.reach_changed.notify_one();
        applied
    }
}
