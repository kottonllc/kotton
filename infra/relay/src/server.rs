// SPDX-License-Identifier: AGPL-3.0-or-later
//! Axum HTTP server — route definitions and request handlers.
//!
//! Routes:
//!   POST /push               — register external address (Ed25519-signed payload)
//!   GET  /lookup/:fp         — retrieve a peer's external address
//!   GET  /health             — liveness probe (also /healthz for backwards compat)
//!   GET  /metrics            — Prometheus-format counters
//!   POST /operator           — the relay's operator reads or sets its one rule
//!   GET  /identity?nonce=<hex> — the relay's own key, and a signature proving it
//!
//! There is no inbox. The relay carries — an address for a handle, a circuit
//! between two awake devices — and keeps nothing (RFC-0083 R1). Offline delivery
//! is the user's own always-on node, never this process.

use std::sync::Arc;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use kotton_wire::rendezvous::{
    AdmissionRule, RelayOperatorRequest, RelayOperatorResponse, RendezvousErrorResponse,
    RendezvousLookupResponse, RendezvousPushPayload, RendezvousPushResponse,
};
use tracing::{info, warn};

use crate::auth::{
    ed25519_key_from_did, verify_lookup_auth, verify_operator_auth, verify_push_sig,
    verify_timestamp, Handle,
};
use crate::logid::tag;
use crate::store::RendezvousStore;

/// Shared state injected into every handler.
pub struct AppState {
    pub store: RendezvousStore,
    /// TTL (seconds) applied to every pushed entry.
    pub ttl_secs: u32,
    /// Whether to enforce signed Authorization headers on lookup requests.
    /// Disable with `--no-auth-lookup` for development / testing.
    pub require_lookup_auth: bool,
    /// The relay's one rule — who may use it — checked at every upgrade before
    /// anything is answered, and set only by its operator
    /// (`TASK-a-relays-admission-rule-is-set-by-its-operator-over-the-wire`).
    pub admission: crate::admission::Admission,
    /// Relayed-circuit registry — the relayed connectivity fallback (RFC-0024
    /// sprint 07 item 2).
    pub circuits: crate::circuit::Circuits,
    /// The relay's own key, proved at `GET /identity`
    /// (`TASK-a-relay-has-a-key-of-its-own-and-proves-it`). Every relay that
    /// serves has one — made at creation, or in memory for a relay with no
    /// state directory (RFC-0084 V18, V19).
    pub identity: crate::identity::RelayKey,
    /// The address the relay announces about itself (`--advertise`), inside the
    /// signature so a dialler learns where the relay says it is. Empty when it
    /// announces none. A hint: nothing compares it to how the relay was dialled.
    pub advertise: String,
}

pub type SharedState = Arc<AppState>;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/push", post(push_handler))
        .route("/presence", post(push_handler)) // RFC-0024 sprint 07 name for /push
        .route("/operator", post(operator_handler))
        .route("/identity", get(identity_handler))
        .route("/relay/reserve", get(reserve_handler)) // RFC-0024 sprint 07 item 2
        .route("/relay/open", get(open_handler))
        .route("/relay/accept", get(accept_handler))
        .route("/lookup/:fingerprint", get(lookup_handler))
        .route("/health", get(health_handler))
        .route("/healthz", get(health_handler)) // backwards compat
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Address-exchange handlers
// ---------------------------------------------------------------------------

/// `POST /push` — verify and store a device's external address.
async fn push_handler(
    State(state): State<SharedState>,
    Json(payload): Json<RendezvousPushPayload>,
) -> Response {
    // 1. Validate timestamp
    if let Err(e) = verify_timestamp(payload.timestamp) {
        warn!(error = %e, device = %tag(&payload.fingerprint), "push rejected: clock skew");
        return error_response(StatusCode::BAD_REQUEST, e.to_string());
    }

    // 2. Extract Ed25519 key from DID fingerprint
    let verifying_key = match ed25519_key_from_did(&payload.fingerprint) {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, device = %tag(&payload.fingerprint), "push rejected: bad fingerprint");
            return error_response(StatusCode::BAD_REQUEST, e.to_string());
        }
    };

    // 3. Verify signature
    if let Err(e) = verify_push_sig(
        &verifying_key,
        &payload.fingerprint,
        &payload.addr,
        payload.timestamp,
        payload.turn_relay_addr.as_deref(),
        payload.relayable,
        &payload.sig,
    ) {
        warn!(error = %e, device = %tag(&payload.fingerprint), "push rejected: bad signature");
        return error_response(StatusCode::UNAUTHORIZED, e.to_string());
    }

    // The rule — after the signature, so it gates a handle that proved itself,
    // and before anything is kept.
    if state
        .admission
        .admit(&payload.fingerprint, payload.timestamp, payload.admission.as_deref())
        .is_err()
    {
        warn!(device = %tag(&payload.fingerprint), "push rejected: not admitted by the relay's rule");
        return not_admitted();
    }

    // 4. Validate addr is a valid SocketAddr
    if payload.addr.parse::<std::net::SocketAddr>().is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid addr: '{}'", payload.addr),
        );
    }

    // 5. Optionally validate turn_relay_addr
    if let Some(ref relay) = payload.turn_relay_addr {
        if relay.parse::<std::net::SocketAddr>().is_err() {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid turn_relay_addr: '{relay}'"),
            );
        }
    }

    // 6. Store
    let ttl = state.store.push(
        &payload.fingerprint,
        payload.addr.clone(),
        payload.turn_relay_addr.clone(),
        payload.relayable,
        state.ttl_secs,
    );
    info!(device = %tag(&payload.fingerprint), ttl_secs = ttl, "relay push accepted");

    Json(RendezvousPushResponse { expires_in: ttl }).into_response()
}

/// `GET /lookup/:fingerprint` — return the stored address for a device.
async fn lookup_handler(
    State(state): State<SharedState>,
    Path(fingerprint): Path<String>,
    headers: HeaderMap,
) -> Response {
    // Verify the requester when signed lookups are required OR the relay's rule
    // reads a tag, which only a signed request can carry.
    let ruled = state.admission.rule() != AdmissionRule::Anyone;
    if state.require_lookup_auth || ruled {
        let auth = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        match verify_lookup_auth(auth) {
            Err(e) => {
                warn!(error = %e, target = %tag(&fingerprint), "lookup rejected: bad auth");
                return error_response(StatusCode::UNAUTHORIZED, e.to_string());
            }
            Ok(requester) => {
                if admit(&state, &requester).is_err() {
                    warn!(requester = %tag(&requester.fingerprint), "lookup rejected: not admitted by the relay's rule");
                    return not_admitted();
                }
            }
        }
    }

    match state.store.lookup(&fingerprint) {
        Some((addr, turn_relay_addr, relayable, remaining)) => Json(RendezvousLookupResponse {
            addr,
            expires_in: remaining,
            turn_relay_addr,
            online: true,
            relayable,
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("no entry for fingerprint '{}'", fingerprint),
        ),
    }
}

// ---------------------------------------------------------------------------
// The rule, and its operator
// ---------------------------------------------------------------------------

fn admit(state: &AppState, handle: &Handle) -> Result<(), crate::admission::Refusal> {
    state
        .admission
        .admit(&handle.fingerprint, handle.ts, handle.admit.as_deref())
}

/// The one refusal the rule gives, whichever rule it is and whatever the caller
/// lacked — so a refusal tells a stranger nothing about which key would have
/// let them in.
fn not_admitted() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "not admitted by this relay's rule".to_string(),
    )
}

/// `POST /operator` — the relay's operator reads its rule or sets it.
///
/// The body is a [`RelayOperatorRequest`]; the header is the operator's own
/// scheme, signed over these exact bytes. A key that is not enrolled at the
/// relay's terminal is refused before the body is read as a request, and the
/// operators are read from their file on every call, so a key revoked there is
/// refused at its next request.
async fn operator_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (key, ts) = match verify_operator_auth(auth, &body) {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "operator request rejected: bad auth");
            return error_response(StatusCode::UNAUTHORIZED, e.to_string());
        }
    };
    if !state.admission.is_operator(&key) {
        warn!(operator = %tag(&key), "operator request rejected: not an operator of this relay");
        return error_response(
            StatusCode::FORBIDDEN,
            "not an operator of this relay".to_string(),
        );
    }
    let request: RelayOperatorRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let answer = state.admission.answer(&request, ts, |rule| {
        // What the relay holds is asked the rule it now keeps: a reservation
        // made under a wider rule is not carried past the set that narrowed it.
        let dropped = state
            .circuits
            .drop_unadmitted(|did, p| rule.admits(did, p.ts, p.tag.as_deref()));
        if dropped > 0 {
            info!(dropped, "reservations the new rule no longer admits were dropped");
        }
    });
    info!(operator = %tag(&key), answer = kind(&answer), "operator request answered");
    Json(answer).into_response()
}

fn kind(answer: &RelayOperatorResponse) -> &'static str {
    match answer {
        RelayOperatorResponse::Rule { .. } => "rule",
        RelayOperatorResponse::Refused { .. } => "refused",
    }
}

// ---------------------------------------------------------------------------
// Relayed circuits (RFC-0024 sprint 07 item 2)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct OpenParams {
    /// DID of the target node to reach through the relay.
    to: String,
}

#[derive(serde::Deserialize)]
struct AcceptParams {
    /// Circuit id the relay sent the target over its reservation.
    circuit: String,
}

/// `GET /relay/reserve` (WebSocket) — a `relayable` node holds this open so the relay
/// can route relayed circuits to it. Signed, and admitted by the rule at the upgrade.
async fn reserve_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let handle = match verify_lookup_auth(auth) {
        Ok(h) => h,
        Err(e) => return error_response(StatusCode::UNAUTHORIZED, e.to_string()),
    };
    let did = handle.fingerprint.clone();
    let presented = crate::circuit::Presented {
        ts: handle.ts,
        tag: handle.admit.clone(),
    };
    // The door and the holding are one step: a set waits for it, so a
    // reservation is never taken under a rule the set's sweep has already passed.
    let reserved = state.admission.admit_then(
        &handle.fingerprint,
        handle.ts,
        handle.admit.as_deref(),
        || state.circuits.reserve(did.clone(), presented),
    );
    let Ok(reserved) = reserved else {
        warn!(device = %tag(&did), "reservation refused: not admitted by the relay's rule");
        return not_admitted();
    };
    let Some((generation, rx)) = reserved else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "relay reservation capacity reached".to_string(),
        );
    };
    info!(device = %tag(&did), active = state.circuits.reservation_count(), "relay reservation opened");
    ws.on_upgrade(move |socket| async move {
        crate::circuit::run_reservation(socket, rx).await;
        // With this generation, so a node replaced while it was live takes only
        // its own reservation away — one address legitimately has two nodes
        // wanting it, a device and the vault holding its doors (`DEC-0056`).
        state.circuits.release(&did, generation);
        info!(device = %tag(&did), active = state.circuits.reservation_count(), "relay reservation closed");
    })
}

/// `GET /relay/open?to=<DID>` (WebSocket) — initiate a relayed circuit to a present,
/// relayable, admitted target. The relay notifies the target and bridges the two
/// streams; the end-to-end mTLS runs inside and the relay reads nothing.
///
/// The rule is read here, at the upgrade. A reservation already held is asked
/// again when the rule changes and dropped if it is no longer admitted
/// (`Circuits::drop_unadmitted`); a circuit already bridged is not cut, and
/// ends when its sockets do.
async fn open_handler(
    State(state): State<SharedState>,
    Query(params): Query<OpenParams>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let initiator = match verify_lookup_auth(auth) {
        Ok(h) => h,
        Err(e) => return error_response(StatusCode::UNAUTHORIZED, e.to_string()),
    };
    // The initiator is the caller at this door. The target was admitted at its
    // own door — a reservation is held only by a handle the rule now held lets
    // in, since a set drops every one it would refuse — so it
    // is not asked again here, and the relay is told nothing about it but the
    // handle it already holds.
    if admit(&state, &initiator).is_err() {
        warn!(device = %tag(&initiator.fingerprint), "circuit refused: not admitted by the relay's rule");
        return not_admitted();
    }
    if !state.circuits.has_reservation(&params.to) {
        return error_response(
            StatusCode::NOT_FOUND,
            "target has no relay reservation".to_string(),
        );
    }
    let target = params.to;
    ws.on_upgrade(move |initiator_ws| async move {
        let Some((circuit_id, data_rx)) = state.circuits.open(&target).await else {
            warn!(target = %tag(&target), "relay open: target reservation vanished");
            return;
        };
        match tokio::time::timeout(std::time::Duration::from_secs(20), data_rx).await {
            Ok(Ok(target_ws)) => {
                info!(target = %tag(&target), circuit = %circuit_id, "relay circuit bridged");
                crate::circuit::bridge(initiator_ws, target_ws).await;
            }
            _ => {
                state.circuits.cancel(&circuit_id);
                warn!(target = %tag(&target), circuit = %circuit_id, "relay open: target did not accept in time");
            }
        }
    })
}

/// `GET /relay/accept?circuit=<id>` (WebSocket) — a reserved node dials back the data
/// leg of a circuit it was notified about. The `circuit` id is the unguessable
/// capability the relay sent over the node's reservation.
async fn accept_handler(
    State(state): State<SharedState>,
    Query(params): Query<AcceptParams>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| async move {
        if !state.circuits.accept(&params.circuit, socket) {
            warn!(circuit = %params.circuit, "relay accept: unknown or expired circuit");
        }
    })
}

// ---------------------------------------------------------------------------
// Health + metrics handlers
// ---------------------------------------------------------------------------

/// `GET /identity?nonce=<hex>` — the relay's key, and a signature over the
/// caller's nonce and the address it announces
/// (`TASK-a-relay-has-a-key-of-its-own-and-proves-it`).
///
/// No auth, and no rule: it is what a stranger asks before trusting the relay,
/// so nothing about the caller is read, kept or logged. The nonce is checked
/// before anything else, so an absent or malformed one is refused the same way
/// whether or not the relay keeps a key.
async fn identity_handler(
    State(state): State<SharedState>,
    Query(q): Query<IdentityQuery>,
) -> Response {
    let Some(nonce) = q.nonce.as_deref().and_then(crate::identity::parse_nonce) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "`nonce=` is hex, one to {} bytes, chosen by the caller",
                kotton_wire::rendezvous::IDENTITY_NONCE_MAX
            ),
        );
    };
    Json(state.identity.prove(&nonce, &state.advertise)).into_response()
}

#[derive(serde::Deserialize)]
struct IdentityQuery {
    nonce: Option<String>,
}

/// `GET /health` (and `/healthz`) — liveness probe, no auth required.
async fn health_handler(State(state): State<SharedState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "address_entries": state.store.len(),
    }))
}

/// `GET /metrics` — Prometheus-format text metrics.
async fn metrics_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let address_entries = state.store.len();
    // How many control sockets are held right now, and nothing about whose.
    // A count is not a join key: it says the relay is carrying work, and two
    // readings of it cannot be composed into anyone's history. It is here
    // because a reservation is otherwise invisible from outside this process —
    // a test that wants to know whether a ceremony reserved a mailbox has no
    // other instrument, and the honest form of that question is a gauge.
    let reservations = state.circuits.reservation_count();
    let bridged = state.circuits.bridged_count();
    let body = format!(
        "# HELP kotton_relay_address_entries Current live address entries\n\
         # TYPE kotton_relay_address_entries gauge\n\
         kotton_relay_address_entries {address_entries}\n\
         # HELP kotton_relay_reservations Control sockets held right now\n\
         # TYPE kotton_relay_reservations gauge\n\
         kotton_relay_reservations {reservations}\n\
         # HELP kotton_relay_circuits_bridged_total Circuits bridged since start\n\
         # TYPE kotton_relay_circuits_bridged_total counter\n\
         kotton_relay_circuits_bridged_total {bridged}\n"
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

fn error_response(status: StatusCode, message: String) -> Response {
    (status, Json(RendezvousErrorResponse { error: message })).into_response()
}
