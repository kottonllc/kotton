// SPDX-License-Identifier: AGPL-3.0-or-later
//! Handing a sealed message to another person's node.
//!
//! The sender's half of the mailbox: derive where the contact answers, open a
//! circuit to it through the relay their identity resolves through, and hand
//! over one `ContactRequest`.
//!
//! **What the relay sees.** Two per-pair, per-epoch labels — the sender's own
//! mailbox handle as the dial's identity, the recipient's as its target — and
//! an opaque mTLS stream between them. Neither label is durable and neither
//! composes with anything (Article VII). What the relay carries
//! it cannot open, and it keeps nothing.
//!
//! **What the certificate proves.** The pair's key for the epoch, and nothing
//! durable: the sender presents its own mailbox handle for the pair, and the
//! far end must prove the recipient's — which the recipient's vault may hold as
//! well as their device. So the handshake proves *this pair*, and who wrote is
//! proved inside the seal, signed. That is also
//! why a sender may dial the same door at every relay a person is reached at:
//! each relay sees the same two rotating labels, and learns no identity it did
//! not hold. A message reaches them by every path at once, and they keep one
//! copy.

use crate::rendezvous;
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use kotton_net::transport::quic::tls::{Ed25519DeviceCert, PairedDeviceVerifier};
use kotton_net::transport::RelayClient;
use kotton_wire::ipc::{ContactRequest, ContactResponse};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Hand `request` to the node answering for `contact_pub` at `relay_url`,
/// presenting a tag under `admission` when the sender holds a key for that
/// relay — the invited key the contact's reach note handed them, or their own.
///
/// Tries the current epoch's mailbox, then the previous one — a recipient whose
/// clock sits either side of the boundary still answers. An error here means
/// nothing was handed over: the caller's own copy is already written, so a
/// failure is a message waiting at home rather than a message lost.
pub async fn deliver(
    relay_url: &str,
    own_identity: &SigningKey,
    contact_pub: &[u8; 32],
    request: &ContactRequest,
    admission: Option<kotton_net::rendezvous::AdmissionKey>,
) -> Result<ContactResponse> {
    if relay_url.trim().is_empty() {
        return Err(anyhow!(
            "no relay is known for this contact, so there is nowhere to hand the message to"
        ));
    }
    let attempts = rendezvous::dm_delivery_attempts(
        own_identity,
        contact_pub,
        rendezvous::unix_now(),
    )?;
    deliver_by(relay_url, attempts, request, admission).await
}

/// Hand `request` over at `relay_url` by `attempts` already derived — the
/// pair's handles for each epoch to try, in order.
///
/// What [`deliver`] does once it has derived them from the identity key, and
/// what a node holding the handles and no identity key does: the sender's
/// vault, carrying a message while no device of theirs is awake. The handles
/// label the dial and prove the pair inside the circuit;
/// they open nothing, so a carrier dialling with them can say nothing the
/// sender did not seal.
pub async fn deliver_by(
    relay_url: &str,
    attempts: Vec<rendezvous::DeliveryAttempt>,
    request: &ContactRequest,
    admission: Option<kotton_net::rendezvous::AdmissionKey>,
) -> Result<ContactResponse> {
    if relay_url.trim().is_empty() {
        return Err(anyhow!(
            "no relay is known for this contact, so there is nowhere to hand the message to"
        ));
    }
    if attempts.is_empty() {
        return Err(anyhow!("no door is known for this pair at this hour"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let body = serde_json::to_vec(request)?;
    let mut last: Option<anyhow::Error> = None;
    for attempt in attempts {
        // Both ends of the circuit prove the pair's key for this epoch, not an
        // identity: the far end may be the recipient's vault, which holds the
        // handle and nothing that opens. Who *wrote* is proved inside the seal,
        // never by this handshake.
        let mut admit = HashSet::new();
        admit.insert(attempt.target_pub);
        let verifier =
            PairedDeviceVerifier::new(Arc::new(RwLock::new(admit)), Arc::clone(&provider));
        let cert = Ed25519DeviceCert::from_signing_key(&attempt.auth_key)
            .map_err(|e| anyhow!("delivery certificate: {e}"))?;
        let client = RelayClient::new(
            relay_url,
            attempt.auth_did,
            attempt.auth_key,
            cert,
            verifier,
            Arc::clone(&provider),
        )
        .with_admission(admission.clone());
        tracing::debug!(
            target = %attempt.target,
            relay = %relay_url,
            "dialling a contact's door"
        );
        match client.dial(&attempt.target).await {
            Ok(conn) => match conn.request(&body).await {
                Ok(bytes) => {
                    return serde_json::from_slice(&bytes)
                        .map_err(|e| anyhow!("the recipient answered something unreadable: {e}"))
                }
                Err(e) => last = Some(anyhow!("handing the message over failed: {e}")),
            },
            Err(e) => last = Some(anyhow!("no mailbox answered: {e}")),
        }
    }
    Err(last.expect("attempts is never empty here"))
}

/// How long one dial to a door heard on the local network is given. A LAN
/// handshake is milliseconds; a door that is not this contact's never answers,
/// because its front drops a knock it does not hold, and this is what each costs.
pub const KNOCK_WITHIN: std::time::Duration = std::time::Duration::from_secs(2);

/// Hand `request` to `contact_pub`'s door on the local network, if one of `heard`
/// is theirs, while their door is open.
///
/// Every beacon heard is dialled at once, under the knock this pair derives from
/// its nonce on `network`, for each hour a relayed dial would try: a door that is
/// not theirs drops the dial before any parse and never answers, and theirs admits
/// the pair's handle for the hour and nothing else. The handshake proves the same
/// two rotating handles a relay would carry, and who wrote is proved
/// inside the seal. Each dial is from its own socket on `bind_ip`, so no two doors
/// see one port.
pub async fn deliver_here(
    heard: &[crate::local_network::Beacon],
    network: &[u8; 32],
    bind_ip: std::net::IpAddr,
    own_identity: &SigningKey,
    contact_pub: &[u8; 32],
    request: &ContactRequest,
) -> Result<ContactResponse> {
    use kotton_net::transport::quic::knocked::{dial_knocked, request_once};
    let body = serde_json::to_vec(request)?;
    let attempts = rendezvous::dm_delivery_attempts(own_identity, contact_pub, rendezvous::unix_now())?;
    let mut dials = tokio::task::JoinSet::new();
    for beacon in heard.iter().filter(|b| b.addr.is_ipv4() == bind_ip.is_ipv4()) {
        let Some(nonce) = crate::local_network::beacon_nonce(beacon) else {
            continue;
        };
        for attempt in &attempts {
            let knock = kotton_crypto::contact_knock_to_dial(
                own_identity,
                contact_pub,
                &nonce,
                attempt.epoch,
                network,
            )?;
            let socket = std::net::UdpSocket::bind((bind_ip, 0))?;
            let (auth_key, target_pub, front) = (attempt.auth_key.clone(), attempt.target_pub, beacon.addr);
            dials.spawn(async move {
                tokio::time::timeout(
                    KNOCK_WITHIN,
                    dial_knocked(&auth_key, target_pub, socket, front, knock),
                )
                .await
            });
        }
    }
    if dials.is_empty() {
        return Err(anyhow!("no open door is heard on this network"));
    }
    while let Some(dialled) = dials.join_next().await {
        let Ok(Ok(Ok(conn))) = dialled else { continue };
        dials.abort_all();
        let answer = request_once(&conn, &body)
            .await
            .map_err(|e| anyhow!("handing the message over failed: {e}"));
        conn.close(0u32.into(), b"delivered");
        return serde_json::from_slice(&answer?)
            .map_err(|e| anyhow!("the recipient answered something unreadable: {e}"));
    }
    Err(anyhow!("none of the doors open on this network is theirs"))
}
