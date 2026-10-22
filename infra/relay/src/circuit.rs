// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay circuit registry + stream bridge — the relayed connectivity fallback
//! (RFC-0024 sprint 07 item 2).
//!
//! A `relayable` node holds a **reservation** (a control WebSocket on
//! `/relay/reserve`). An initiator opens a circuit on `/relay/open?to=<DID>`; the
//! relay tells the target (over its reservation) to dial back a **data** WebSocket
//! on `/relay/accept?circuit=<id>`, then **bridges** the two streams byte-for-byte.
//! The end-to-end TLS 1.3 mTLS runs *inside* the bridge, so the relay terminates no
//! TLS and reads nothing — it forwards opaque frames.
//!
//! The `circuit_id` is an unguessable UUID the relay sends only to the specific
//! target over its (authenticated) reservation, so it doubles as the capability
//! that authorises the data leg.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

/// Cap on concurrent reservations — simple metering. Counts *holders*, not
/// addresses, because an address may have more than one (see [`Circuits`]).
const MAX_RESERVATIONS: usize = 10_000;

/// Cap on holders of one address. Two is the case that exists — a device and the
/// vault it handed its doors to — and the bound is here so a node that reconnects
/// without releasing cannot grow the list without limit.
const MAX_HOLDERS_PER_ADDRESS: usize = 8;

/// Identifier the relay hands a target to dial back the data leg of a circuit.
pub type CircuitId = String;

/// Registry of live reservations and in-flight circuits awaiting their data leg.
/// One address's holders: each a generation and the control channel that sends
/// it [`CircuitId`]s to dial. Named because the type it is a field of is what
/// clippy's `type_complexity` reads, and a reader needs the same two words
/// clippy does.
type Holders = Vec<Holder>;

/// What a holder presented at `/relay/reserve`: the timestamp its handle signed
/// and the admission tag beside it, if any. Kept for the reservation's life so
/// that a rule set after it can ask the same door again, and drop a holder the
/// new rule no longer admits
/// (`TASK-a-tenant-with-no-key-reads-as-held-under-a-loaded-suite`).
///
/// It is nothing the door did not already read, bound to the one handle it came
/// with — which the relay already holds as the reservation's address — and it
/// goes with the reservation. A tag is a MAC under a key every member shares, so
/// it says *a member*, never which, and two tags under two handles join nothing.
#[derive(Clone, Debug, Default)]
pub struct Presented {
    pub ts: i64,
    pub tag: Option<String>,
}

/// One node holding an address.
struct Holder {
    generation: u64,
    tx: mpsc::Sender<CircuitId>,
    presented: Presented,
}

#[derive(Clone, Default)]
pub struct Circuits {
    /// DID → **every** node holding that address, each with the generation that
    /// names its reservation and the control channel that sends it [`CircuitId`]s
    /// to dial.
    ///
    /// A list rather than one holder, because one address legitimately has two:
    /// a person's device reserves its own pair door, and the vault they rent
    /// reserves the same door, since that is what a door is for (`DEC-0056`) —
    /// the vault answers it while every device of theirs is asleep. Holding one
    /// meant the two took the address from each other forever, and whenever the
    /// live one went away the address answered nothing until the other's
    /// reconnect interval elapsed. That gap is precisely when a message to a
    /// sleeping device arrives.
    ///
    /// This widens nobody's reach: a holder still proves the address's signing
    /// key to `/relay/reserve`, and both of these hold it by construction. What
    /// changes is only that the relay stops forgetting one of them.
    ///
    /// The generation is what makes `release` safe — a holder removes its own
    /// entry and never another's.
    reservations: Arc<DashMap<String, Holders>>,
    /// Total holders across every address, kept alongside the map so the capacity
    /// check and the readout do not have to walk it.
    holders: Arc<AtomicUsize>,
    /// Hands each reservation an identity of its own.
    next_generation: Arc<AtomicU64>,
    /// circuit id → slot where the initiator awaits the target's data WebSocket.
    pending: Arc<DashMap<CircuitId, oneshot::Sender<WebSocket>>>,
    /// How many circuits have been bridged since start — a count and nothing
    /// about whose, so two readings compose into nobody's history. It is the
    /// one instrument outside this process that says a relay carried a dial,
    /// which a sender dialling several relays at once is tested by.
    bridged: Arc<AtomicU64>,
}

impl Circuits {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many holders are live across every address.
    pub fn reservation_count(&self) -> usize {
        self.holders.load(Ordering::Relaxed)
    }

    /// How many circuits have been bridged since this relay started.
    pub fn bridged_count(&self) -> u64 {
        self.bridged.load(Ordering::Relaxed)
    }

    /// How many nodes hold `did` — 0 when nothing answers there.
    pub fn holders_of(&self, did: &str) -> usize {
        self.reservations.get(did).map(|r| r.value().len()).unwrap_or(0)
    }

    /// Every address a reservation is held under, for a test that reads what
    /// the relay holds.
    #[cfg(test)]
    pub fn addresses(&self) -> Vec<String> {
        self.reservations.iter().map(|e| e.key().clone()).collect()
    }

    pub fn has_reservation(&self, did: &str) -> bool {
        self.holders_of(did) > 0
    }

    /// Add a holder for `did`. Returns **which** reservation this is and the
    /// receiver of [`CircuitId`]s the node must dial back, or `None` if the relay
    /// is at capacity or this address already has as many holders as it may.
    ///
    /// A second call for an address already held **joins** it rather than
    /// replacing it — see the field. The caller must pass the returned generation
    /// back to [`release`](Self::release).
    pub fn reserve(
        &self,
        did: String,
        presented: Presented,
    ) -> Option<(u64, mpsc::Receiver<CircuitId>)> {
        if self.holders.load(Ordering::Relaxed) >= MAX_RESERVATIONS {
            return None;
        }
        let (tx, rx) = mpsc::channel(8);
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut entry = self.reservations.entry(did).or_default();
        if entry.len() >= MAX_HOLDERS_PER_ADDRESS {
            return None;
        }
        entry.push(Holder {
            generation,
            tx,
            presented,
        });
        drop(entry);
        self.holders.fetch_add(1, Ordering::Relaxed);
        Some((generation, rx))
    }

    /// Drop one holder (its control WebSocket closed).
    ///
    /// Removes this generation and nothing else, so a node tearing down takes its
    /// own reservation away and never another holder's — the address keeps
    /// answering as long as anyone is still there.
    pub fn release(&self, did: &str, generation: u64) {
        let mut emptied = false;
        if let Some(mut entry) = self.reservations.get_mut(did) {
            let before = entry.len();
            entry.retain(|h| h.generation != generation);
            let removed = before - entry.len();
            if removed > 0 {
                self.holders.fetch_sub(removed, Ordering::Relaxed);
            }
            emptied = entry.is_empty();
        }
        if emptied {
            // Only when nothing is left, and only if it is still empty — a holder
            // may have joined between the two locks.
            self.reservations.remove_if(did, |_, hs| hs.is_empty());
        }
    }

    /// Drop every holder `admits` no longer lets in, and say how many went.
    ///
    /// Called when the rule changes, with the rule as it now stands: a
    /// reservation is a standing presence, and one held under a rule that has
    /// since narrowed would otherwise be carried until its own socket ended —
    /// which is whenever its holder chose. Removing a holder drops the only
    /// long-lived sender of its control loop, so [`run_reservation`] ends and the
    /// socket closes; the holder's next upgrade meets the rule at the door.
    ///
    /// This is what keeps `open_handler`'s reasoning true — *the target was
    /// admitted at its own door* — under the rule held now, rather than asking
    /// the target again at every open.
    pub fn drop_unadmitted(&self, admits: impl Fn(&str, &Presented) -> bool) -> usize {
        let mut dropped = 0usize;
        self.reservations.retain(|did, holders| {
            let before = holders.len();
            holders.retain(|h| admits(did, &h.presented));
            dropped += before - holders.len();
            !holders.is_empty()
        });
        if dropped > 0 {
            self.holders.fetch_sub(dropped, Ordering::Relaxed);
        }
        dropped
    }

    /// Open a circuit to `target`: notify **every** node holding that address and
    /// return the circuit id plus a receiver that resolves with the first data
    /// WebSocket to arrive. `None` if nobody holds it, or if no holder could be
    /// told.
    ///
    /// Every holder is told rather than one chosen, and the race settles itself:
    /// [`accept`](Self::accept) takes the pending slot exactly once, so the first
    /// to dial back is bridged and any other is closed. That is the behaviour
    /// `DEC-0056` wants without the relay having to model it — an awake device
    /// answers its own door before the vault holding it does, and the vault
    /// answers when nothing of theirs is awake.
    pub async fn open(&self, target: &str) -> Option<(CircuitId, oneshot::Receiver<WebSocket>)> {
        // Clone the senders and drop the DashMap guard *before* awaiting.
        let holders: Vec<(u64, mpsc::Sender<CircuitId>)> = self
            .reservations
            .get(target)
            .map(|r| r.value().iter().map(|h| (h.generation, h.tx.clone())).collect())?;
        if holders.is_empty() {
            return None;
        }
        let circuit_id = uuid::Uuid::new_v4().to_string();
        let (data_tx, data_rx) = oneshot::channel();
        self.pending.insert(circuit_id.clone(), data_tx);

        let mut told = 0usize;
        let mut gone: Vec<u64> = Vec::new();
        for (generation, sender) in holders {
            if sender.send(circuit_id.clone()).await.is_ok() {
                told += 1;
            } else {
                // That holder's control loop is gone; reap it rather than leaving
                // an address that looks answered and is not.
                gone.push(generation);
            }
        }
        for generation in gone {
            self.release(target, generation);
        }
        if told == 0 {
            self.pending.remove(&circuit_id);
            return None;
        }
        Some((circuit_id, data_rx))
    }

    /// The target delivers its data WebSocket for `circuit_id`. Returns `false` if
    /// the circuit is unknown/expired (or the initiator already gave up).
    pub fn accept(&self, circuit_id: &str, ws: WebSocket) -> bool {
        match self.pending.remove(circuit_id) {
            Some((_, tx)) => {
                let bridged = tx.send(ws).is_ok();
                if bridged {
                    self.bridged.fetch_add(1, Ordering::Relaxed);
                }
                bridged
            }
            None => false,
        }
    }

    /// Drop a pending circuit (initiator gave up before the target dialed back).
    pub fn cancel(&self, circuit_id: &str) {
        self.pending.remove(circuit_id);
    }
}

/// Bridge two WebSocket streams until either side closes. The relay forwards
/// opaque frames (the inner mTLS records); it never inspects content.
pub async fn bridge(a: WebSocket, b: WebSocket) {
    let (mut a_tx, mut a_rx) = a.split();
    let (mut b_tx, mut b_rx) = b.split();

    let a_to_b = async {
        while let Some(Ok(msg)) = a_rx.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
            if b_tx.send(msg).await.is_err() {
                break;
            }
        }
    };
    let b_to_a = async {
        while let Some(Ok(msg)) = b_rx.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
            if a_tx.send(msg).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = a_to_b => {}
        _ = b_to_a => {}
    }
    debug!("circuit bridge closed");
}

/// Pump circuit ids to a reserved node over its control socket until it
/// disconnects. Each id tells the node to dial `/relay/accept?circuit=<id>`.
pub async fn run_reservation(socket: WebSocket, mut rx: mpsc::Receiver<CircuitId>) {
    let (mut sink, mut stream) = socket.split();
    loop {
        tokio::select! {
            cid = rx.recv() => match cid {
                Some(circuit_id) => {
                    if sink.send(Message::Text(circuit_id)).await.is_err() {
                        break; // node disconnected
                    }
                }
                None => break, // registry dropped the sender
            },
            incoming = stream.next() => {
                // The node closed (or errored) its control socket.
                if matches!(incoming, None | Some(Ok(Message::Close(_))) | Some(Err(_))) {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end test of the relay-side circuit: a target reserves, an initiator
    //! opens a circuit, the target dials back the data leg, and the relay bridges
    //! bytes both ways — exercising `reserve` → `open` → `accept` → `bridge`.

    use super::{Circuits, Presented};
    use crate::admission::{Admission, RuleState};
    use crate::server::{build_router, AppState};
    use crate::store::RendezvousStore;
    use ed25519_dalek::{Signer, SigningKey};
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message as TMessage;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

    fn make_identity() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let vk = sk.verifying_key();
        let mut prefixed = vec![0xed_u8, 0x01];
        prefixed.extend_from_slice(vk.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&prefixed).into_string());
        (sk, did)
    }

    fn auth_header(sk: &SigningKey, did: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let msg = format!("{did}\n{ts}");
        let sig = URL_SAFE_NO_PAD.encode(sk.sign(msg.as_bytes()).to_bytes());
        format!("Ed25519 fingerprint={did} ts={ts} sig={sig}")
    }

    async fn connect(url: &str, auth: Option<&str>) -> Ws {
        let mut req = url.into_client_request().unwrap();
        if let Some(a) = auth {
            req.headers_mut()
                .insert("Authorization", a.parse().unwrap());
        }
        let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        ws
    }

    /// Two holders, one address — and the address answers while any of them is there.
    ///
    /// This is not hypothetical. A person's device reserves its own pair door and
    /// the vault they rent reserves the *same* door, because that is what a door
    /// is for (`DEC-0056`): the vault answers it while every device of theirs is
    /// asleep. So a second `reserve` is the ordinary case, not an error.
    ///
    /// **The order below is the whole test.** The device reserves, the vault joins,
    /// and then the *vault* goes — the holder that a replacing registry would have
    /// treated as the current one. That is the case that was broken: while the
    /// registry kept a single holder, whichever node reserved last owned the
    /// address and its departure emptied it, even though the other was still up
    /// and still holding the same door. Releasing the *displaced* holder instead
    /// passes against the broken code too, which is why an earlier draft of this
    /// test proved nothing.
    ///
    /// Measured on the two-NAT scenario, 2026-09-09
    /// (`TASK-a-vault-holds-the-doors-and-the-relay-answers-404`): the two nodes
    /// took the address from each other on every reconnect, and a sender dialling
    /// in the gap after the live one died was told 404.
    #[test]
    fn a_door_answers_while_any_of_its_holders_is_there() {
        let circuits = Circuits::new();
        let door = "did:key:zDoorSharedByADeviceAndItsVault".to_string();

        let (device, _device_rx) = circuits.reserve(door.clone(), Presented::default()).expect("the device reserves");
        let (vault, _vault_rx) = circuits.reserve(door.clone(), Presented::default()).expect("the vault reserves it too");
        assert_ne!(device, vault, "each holder is told which one it is");
        assert_eq!(
            circuits.holders_of(&door),
            2,
            "the second holder joined the address rather than taking it"
        );

        // The holder that arrived last goes away. The other is still there, so the
        // door must keep answering with no reconnect in between.
        circuits.release(&door, vault);
        assert!(
            circuits.has_reservation(&door),
            "one holder left and took the other's reservation with it, so this door \
             now answers nothing while a node holding it is still up"
        );
        assert_eq!(circuits.holders_of(&door), 1);

        // Releasing a generation that is no longer there changes nothing — a
        // holder that tears down twice must not take the other away.
        circuits.release(&door, vault);
        assert_eq!(circuits.holders_of(&door), 1);

        // And the last holder leaving empties it.
        circuits.release(&door, device);
        assert!(!circuits.has_reservation(&door));
        assert_eq!(circuits.reservation_count(), 0, "no holder is left counted");
    }

    #[tokio::test]
    async fn relayed_circuit_bridges_bytes_end_to_end() {
        // A relay whose rule is *anyone* (every signed handle is admitted).
        let state = Arc::new(AppState {
            store: RendezvousStore::new(),
            ttl_secs: 60,
            require_lookup_auth: true,
            admission: Admission::in_memory(
                &"ab".repeat(32),
                RuleState { rule: kotton_wire::rendezvous::AdmissionRule::Anyone, ..RuleState::default() },
            ),
            circuits: Circuits::new(),
            identity: crate::identity::RelayKey::in_memory(),
            advertise: String::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.unwrap();
        });

        let (target_sk, target_did) = make_identity();
        let (init_sk, init_did) = make_identity();

        // Target holds a reservation.
        let mut reservation = connect(
            &format!("ws://{addr}/relay/reserve"),
            Some(&auth_header(&target_sk, &target_did)),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Initiator opens a circuit to the target.
        let mut initiator = connect(
            &format!("ws://{addr}/relay/open?to={target_did}"),
            Some(&auth_header(&init_sk, &init_did)),
        )
        .await;

        // Target is told to accept circuit <id> over its reservation.
        let circuit_id = match reservation.next().await {
            Some(Ok(TMessage::Text(id))) => id,
            other => panic!("expected circuit id, got {other:?}"),
        };

        // Target dials back the data leg.
        let mut data = connect(&format!("ws://{addr}/relay/accept?circuit={circuit_id}"), None).await;

        // Initiator → target.
        initiator
            .send(TMessage::Binary(b"hello".to_vec()))
            .await
            .unwrap();
        match data.next().await {
            Some(Ok(TMessage::Binary(b))) => assert_eq!(b, b"hello"),
            other => panic!("expected binary hello, got {other:?}"),
        }

        // Target → initiator (reverse direction through the same bridge).
        data.send(TMessage::Binary(b"world".to_vec()))
            .await
            .unwrap();
        match initiator.next().await {
            Some(Ok(TMessage::Binary(b))) => assert_eq!(b, b"world"),
            other => panic!("expected binary world, got {other:?}"),
        }

    }

    #[tokio::test]
    async fn open_to_unreserved_target_is_rejected() {
        let state = Arc::new(AppState {
            store: RendezvousStore::new(),
            ttl_secs: 60,
            require_lookup_auth: true,
            admission: Admission::in_memory(
                &"ab".repeat(32),
                RuleState { rule: kotton_wire::rendezvous::AdmissionRule::Anyone, ..RuleState::default() },
            ),
            circuits: Circuits::new(),
            identity: crate::identity::RelayKey::in_memory(),
            advertise: String::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.unwrap();
        });

        let (init_sk, init_did) = make_identity();
        let (_t_sk, target_did) = make_identity();
        let mut req = format!("ws://{addr}/relay/open?to={target_did}")
            .into_client_request()
            .unwrap();
        req.headers_mut().insert(
            "Authorization",
            auth_header(&init_sk, &init_did).parse().unwrap(),
        );
        // No reservation for the target → the upgrade is refused (404).
        assert!(tokio_tungstenite::connect_async(req).await.is_err());

    }
}
