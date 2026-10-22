// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for the pairing channel.
//!
//! They drive a real QUIC loopback through `open_pair_listener`, in this
//! crate's `pairing` module, and test the channel's API from outside it. They
//! follow `pairing`, not the channel.

use crate::pair_channel::*;
use async_trait::async_trait;
use crate::pairing::open_pair_listener;
use ed25519_dalek::SigningKey;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// A test confirmer with a fixed verdict that records the SAS it was shown.
struct FixedConfirmer {
    verdict: bool,
    seen_sas: Arc<AtomicU32>,
    seen_label: std::sync::Mutex<Option<String>>,
}
impl FixedConfirmer {
    fn new(verdict: bool) -> Self {
        Self {
            verdict,
            seen_sas: Arc::new(AtomicU32::new(u32::MAX)),
            seen_label: std::sync::Mutex::new(None),
        }
    }
}
#[async_trait]
impl SasConfirmer for FixedConfirmer {
    async fn confirm(&self, sas: u32, peer_label: Option<&str>) -> bool {
        self.seen_sas.store(sas, Ordering::SeqCst);
        *self.seen_label.lock().unwrap() = peer_label.map(str::to_string);
        self.verdict
    }
}

/// A live loopback bootstrap QUIC connection pair. The endpoints are returned
/// alongside the connections and must be kept alive for the duration of the
/// ceremony (dropping an `Endpoint` tears down its connections). The bi-stream
/// is opened/accepted *inside each test's task*: the joiner's `open_bi` +
/// first `hello` write is what makes the issuer's `accept_bi` return, so there
/// is no empty-write nudge to race on.
struct Loopback {
    _issuer_listener: crate::pairing::PairListener,
    _joiner_endpoint: quinn::Endpoint,
    issuer_conn: quinn::Connection,
    joiner_conn: quinn::Connection,
}

async fn loopback_conns() -> Loopback {
    let issuer_key = SigningKey::from_bytes(&[42u8; 32]);
    let joiner_key = SigningKey::from_bytes(&[24u8; 32]);
    let (_code, listen_addr, _expires, endpoint) =
        open_pair_listener(&issuer_key, 0, 30).await.unwrap();
    let dial = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_addr.port());

    let client_config = {
        use kotton_net::build_bootstrap_client_config;
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let cert =
            kotton_net::Ed25519DeviceCert::from_signing_key(&joiner_key).unwrap();
        build_bootstrap_client_config(&cert, provider).unwrap()
    };
    // Loopback: the dial target is 127.0.0.1, and a wildcard client socket
    // buys nothing here but a firewall dialog on every run.
    let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let connecting = client
        .connect_with(client_config, dial, "kotton-pairing")
        .unwrap();

    // Accept and connect concurrently. The server handshake only progresses
    // while the `Incoming` is being awaited, so drive `accept().await` *and*
    // `incoming.await` inside one future alongside the client's `connecting` —
    // otherwise the two sides deadlock until the idle timeout.
    let server_fut = async {
        let incoming = endpoint.accept().await.expect("incoming");
        incoming.await.expect("issuer conn")
    };
    let (issuer_conn, joiner_res) = tokio::join!(server_fut, connecting);
    let joiner_conn = joiner_res.expect("joiner conn");

    Loopback {
        _issuer_listener: endpoint,
        _joiner_endpoint: client,
        issuer_conn,
        joiner_conn,
    }
}

const SID: [u8; 16] = [7u8; 16];

#[tokio::test]
async fn channel_establishes_and_transfers_only_after_confirm() {
    let lb = loopback_conns().await;
    let (ic_conn, jc_conn) = (lb.issuer_conn.clone(), lb.joiner_conn.clone());
    let ic = Arc::new(FixedConfirmer::new(true));
    let jc = Arc::new(FixedConfirmer::new(true));
    let ic2 = ic.clone();
    let jc2 = jc.clone();

    let issuer = tokio::spawn(async move {
        let (is, ir) = ic_conn.accept_bi().await.unwrap();
        let mut ch = issuer_establish(is, ir, SID, "austin's PC", ic2.as_ref())
            .await
            .expect("issuer establishes");
        // Transfer a payload only reachable after both confirmations.
        ch.send_encrypted(b"the-secret-payload").await.unwrap();
        ch.finish().await.unwrap();
        ch.sas()
    });
    let joiner = tokio::spawn(async move {
        let (js, jr) = jc_conn.open_bi().await.unwrap();
        let mut ch = joiner_establish(js, jr, SID, jc2.as_ref())
            .await
            .expect("joiner establishes");
        let got = ch.recv_encrypted().await.unwrap();
        (ch.sas(), ch.peer_label().map(str::to_string), got)
    });

    let issuer_sas = issuer.await.unwrap();
    let (joiner_sas, label, payload) = joiner.await.unwrap();
    assert_eq!(issuer_sas, joiner_sas, "both sides derive the same SAS");
    assert_eq!(ic.seen_sas.load(Ordering::SeqCst), issuer_sas);
    assert_eq!(jc.seen_sas.load(Ordering::SeqCst), joiner_sas);
    assert_eq!(label.as_deref(), Some("austin's PC"), "joiner learns the label");
    assert_eq!(payload, b"the-secret-payload", "payload transfers post-confirm");
}

#[tokio::test]
async fn joiner_cancel_transfers_nothing() {
    let lb = loopback_conns().await;
    let (ic_conn, jc_conn) = (lb.issuer_conn.clone(), lb.joiner_conn.clone());
    let ic = Arc::new(FixedConfirmer::new(true));
    // Joiner's human says the codes do NOT match.
    let jc = Arc::new(FixedConfirmer::new(false));
    let ic2 = ic.clone();
    let jc2 = jc.clone();

    let issuer = tokio::spawn(async move {
        let (is, ir) = ic_conn.accept_bi().await.unwrap();
        let mut result = issuer_establish(is, ir, SID, "austin's PC", ic2.as_ref()).await;
        // If (improbably) the channel came up, the payload send is the thing that
        // must never be reached; fold it into the result.
        if let Ok(ch) = &mut result {
            ch.send_encrypted(b"leak").await.ok();
        }
        result.is_ok()
    });
    let joiner = tokio::spawn(async move {
        let (js, jr) = jc_conn.open_bi().await.unwrap();
        matches!(
            joiner_establish(js, jr, SID, jc2.as_ref()).await,
            Err(PairChannelError::SasRejected)
        )
    });

    let issuer_completed = issuer.await.unwrap();
    let joiner_rejected = joiner.await.unwrap();
    assert!(joiner_rejected, "joiner returns SasRejected");
    assert!(!issuer_completed, "issuer must not complete when the joiner cancels");
}

#[tokio::test]
async fn issuer_cancel_transfers_nothing() {
    let lb = loopback_conns().await;
    let (ic_conn, jc_conn) = (lb.issuer_conn.clone(), lb.joiner_conn.clone());
    let ic = Arc::new(FixedConfirmer::new(false));
    let jc = Arc::new(FixedConfirmer::new(true));
    let ic2 = ic.clone();
    let jc2 = jc.clone();

    let issuer = tokio::spawn(async move {
        let (is, ir) = ic_conn.accept_bi().await.unwrap();
        matches!(
            issuer_establish(is, ir, SID, "austin's PC", ic2.as_ref()).await,
            Err(PairChannelError::SasRejected)
        )
    });
    let joiner = tokio::spawn(async move {
        let (js, jr) = jc_conn.open_bi().await.unwrap();
        let mut result = joiner_establish(js, jr, SID, jc2.as_ref()).await;
        if let Ok(ch) = &mut result {
            // Would block forever if it tried to read a payload; just report.
            let _ = ch.sas();
        }
        result.is_ok()
    });

    assert!(issuer.await.unwrap(), "issuer returns SasRejected");
    assert!(!joiner.await.unwrap(), "joiner must not complete when the issuer cancels");
}

#[tokio::test]
async fn wrong_offer_sid_is_rejected() {
    let lb = loopback_conns().await;
    let (ic_conn, jc_conn) = (lb.issuer_conn.clone(), lb.joiner_conn.clone());
    let ic = Arc::new(FixedConfirmer::new(true));
    let jc = Arc::new(FixedConfirmer::new(true));
    let ic2 = ic.clone();
    let jc2 = jc.clone();

    // Issuer advertised a different sid than the joiner presents.
    let issuer = tokio::spawn(async move {
        let (is, ir) = ic_conn.accept_bi().await.unwrap();
        matches!(
            issuer_establish(is, ir, [1u8; 16], "austin's PC", ic2.as_ref()).await,
            Err(PairChannelError::SidMismatch)
        )
    });
    let joiner = tokio::spawn(async move {
        let (js, jr) = jc_conn.open_bi().await.unwrap();
        joiner_establish(js, jr, [2u8; 16], jc2.as_ref()).await.is_ok()
    });

    assert!(issuer.await.unwrap(), "issuer rejects the mismatched offer");
    assert!(!joiner.await.unwrap(), "joiner cannot complete against a rejected offer");
}

#[tokio::test]
async fn two_ceremonies_with_same_long_term_keys_derive_different_sas() {
    // Forward secrecy in miniature: k_enc/SAS come only from the ephemeral DH,
    // so re-running with identical long-term device keys yields an independent
    // SAS. A recorded ceremony therefore cannot be replayed or decrypted from a
    // long-term key — there is none in the schedule.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2 {
        let lb = loopback_conns().await;
        let (ic_conn, jc_conn) = (lb.issuer_conn.clone(), lb.joiner_conn.clone());
        let ic = Arc::new(FixedConfirmer::new(true));
        let jc = Arc::new(FixedConfirmer::new(true));
        let ic2 = ic.clone();
        let jc2 = jc.clone();
        let issuer = tokio::spawn(async move {
            let (is, ir) = ic_conn.accept_bi().await.unwrap();
            issuer_establish(is, ir, SID, "pc", ic2.as_ref()).await.map(|c| c.sas())
        });
        let joiner = tokio::spawn(async move {
            let (js, jr) = jc_conn.open_bi().await.unwrap();
            joiner_establish(js, jr, SID, jc2.as_ref()).await.map(|c| c.sas())
        });
        let s = issuer.await.unwrap().unwrap();
        let _ = joiner.await.unwrap().unwrap();
        seen.insert(s);
    }
    assert_eq!(seen.len(), 2, "independent ceremonies must not share a SAS/key");
}
