// SPDX-License-Identifier: AGPL-3.0-or-later
//! This machine's operators, spoken to from a person's own daemon, under a key
//! that is theirs alone.
//!
//! **The key.** Each person's operator key is a private sealed object in their
//! own store ([`kotton_store::runtime::private`], as a vault's operator
//! credential is): minted here the first time it is wanted, sealed under their
//! CEK, in no root — so no sync carries it, no app sees it and no other person
//! on this OS account can open it. It is never the machine keychain's one
//! `device_operator_key`, which `kctl` uses and which every person sharing an
//! OS account shares; `kdeviced` binds a key to one person, and only a key one
//! person holds can honestly be bound.
//!
//! **Speaking.** A connection to `kdeviced`'s socket, authenticated by this key
//! signing the connection's nonce and naming the person it is theirs for
//! (`Authenticate { person }`). What happens is `kdeviced`'s:
//!
//! | the key is… | `kdeviced` answers | here |
//! |---|---|---|
//! | an operator's | `Authenticated` | [`Standing::Operator`] — every act on the connection is kept under it |
//! | the first on an empty machine | `Authenticated`, bound to the person | [`Standing::Operator`] |
//! | neither | `OperatorKeyKept` — kept as the person's, standing for nothing | [`Standing::Kept`] |
//!
//! **An operator makes someone else an operator by naming the person**
//! (`OperatorAdd`), and the key that person then holds is the one *their own*
//! daemon proved and kdeviced kept — so no operator ever names a key they do not
//! hold, and a key is shown to be a person's by the only party that holds it.
//! That is why [`keep`] runs when a person unlocks: it is how a person becomes
//! someone who *can* be made an operator.
//!
//! This file holds the key and speaks; it decides nothing about who may. Every
//! rule — who is an operator, the last is never removed, which key took which
//! act — is `kdeviced`'s, read per request on its side.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use kotton_ipc::IpcClient;
use kotton_store::runtime::user::UserStore;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::{DeviceOperator, DeviceRequest, DeviceResponse};
use std::time::Duration;

/// The private object's name.
const KEPT: &str = "device-operator";

/// How long one exchange with `kdeviced` may take, dial included. It is a
/// socket on this machine; a supervisor that does not answer in this long is
/// not going to.
const WITHIN: Duration = Duration::from_secs(10);

/// This person's own operator key: read from their sealed store, or minted and
/// kept there the first time it is wanted. Refused when the store holds no
/// keys — a person who has not unlocked has no key to speak with.
pub(crate) fn own_key(store: &UserStore) -> anyhow::Result<SigningKey> {
    // Read and mint under one lock: the unlock's `keep` and a pane's first read
    // can both find no key, and two mints would leave the person holding one
    // key while `kdeviced` kept the other. One process serves a person,
    // so a process-wide lock is the whole of the race.
    static MINTING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = MINTING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(bytes) = kotton_store::runtime::private::read(store, KEPT)? {
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("the operator key kept here is not a key"))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    kotton_store::runtime::private::write(store, KEPT, &key.to_bytes())?;
    tracing::info!(user_id = %store.user_id(), "minted this person's own operator key");
    Ok(key)
}

/// The key's `did:key`.
pub(crate) fn did_of(key: &SigningKey) -> String {
    kotton_crypto::DidKeyMethod::from_public_key(&key.verifying_key()).to_string()
}

/// Where this machine's `kdeviced` listens: the runtime's, when it was told one,
/// else the machine's own socket.
pub(crate) fn endpoint(configured: Option<&IpcEndpoint>) -> Result<IpcEndpoint, String> {
    if let Some(e) = configured {
        return Ok(e.clone());
    }
    #[cfg(windows)]
    {
        Ok(IpcEndpoint::NamedPipe(kotton_common::kdeviced_ipc_name()))
    }
    #[cfg(not(windows))]
    {
        kotton_common::kdeviced_door()
            .map(IpcEndpoint::UnixSocket)
            .map_err(|e| format!("this machine's kdeviced has no socket to reach: {e}"))
    }
}

/// What the person's key is to this machine.
pub(crate) enum Standing {
    /// One of its operators, on a connection whose every act is kept under the
    /// key.
    Operator {
        client: IpcClient<DeviceRequest, DeviceResponse>,
        /// The key's `did:key`, as it appears in `SudoersList`.
        own: String,
    },
    /// Kept as the person's own key, standing for nothing yet.
    Kept,
}

/// Dial `kdeviced` and authenticate with `key` as `person`'s own.
pub(crate) async fn speak_as(
    at: &IpcEndpoint,
    key: &SigningKey,
    person: &str,
) -> Result<Standing, String> {
    tokio::time::timeout(WITHIN, dial(at, key, person))
        .await
        .map_err(|_| format!("this machine's kdeviced did not answer within {}s", WITHIN.as_secs()))?
}

async fn dial(at: &IpcEndpoint, key: &SigningKey, person: &str) -> Result<Standing, String> {
    let mut client = IpcClient::<DeviceRequest, DeviceResponse>::connect(at.clone())
        .await
        .map_err(|e| format!("this machine's kdeviced is not running, or cannot be reached: {e}"))?;
    let nonce = match send(&mut client, DeviceRequest::Challenge).await? {
        DeviceResponse::ChallengeIssued { nonce } => nonce,
        other => return Err(unread("Challenge", other)),
    };
    let raw = URL_SAFE_NO_PAD
        .decode(&nonce)
        .map_err(|e| format!("kdeviced sent a nonce that does not decode: {e}"))?;
    let own = did_of(key);
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&raw).to_bytes());
    let answer = send(
        &mut client,
        DeviceRequest::Authenticate {
            did: own.clone(),
            nonce,
            signature,
            person: Some(person.to_owned()),
        },
    )
    .await?;
    match answer {
        DeviceResponse::Authenticated { .. } => Ok(Standing::Operator { client, own }),
        DeviceResponse::OperatorKeyKept { .. } => Ok(Standing::Kept),
        DeviceResponse::AuthFailed { reason } => Err(reason),
        other => Err(unread("Authenticate", other)),
    }
}

async fn send(
    client: &mut IpcClient<DeviceRequest, DeviceResponse>,
    request: DeviceRequest,
) -> Result<DeviceResponse, String> {
    client
        .send(&request)
        .await
        .map_err(|e| format!("this machine's kdeviced closed the connection: {e}"))
}

fn unread(verb: &str, answer: DeviceResponse) -> String {
    match answer {
        DeviceResponse::Error { message } => message,
        other => format!("{verb}: kdeviced answered with something this does not read ({other:?})"),
    }
}

/// **Make sure `kdeviced` knows this person's own key** — kept as theirs if it
/// is not already an operator's. Run when the person unlocks, so that an
/// operator can make them one; it grants nothing.
pub(crate) async fn keep(at: &IpcEndpoint, store: &UserStore, person: &str) -> Result<(), String> {
    let key = own_key(store).map_err(|e| format!("{e:#}"))?;
    speak_as(at, &key, person).await.map(|_| ())
}

/// The machine's operators, as an operator reads them — or `None` when this
/// person is not one, and so may not read them.
pub(crate) async fn read(
    at: &IpcEndpoint,
    store: &UserStore,
    person: &str,
) -> Result<Option<(String, Vec<DeviceOperator>)>, String> {
    let key = own_key(store).map_err(|e| format!("{e:#}"))?;
    match speak_as(at, &key, person).await? {
        Standing::Kept => Ok(None),
        Standing::Operator { mut client, own } => {
            match tokio::time::timeout(WITHIN, send(&mut client, DeviceRequest::SudoersList)).await {
                Ok(Ok(DeviceResponse::SudoersList { operators })) => Ok(Some((own, operators))),
                Ok(Ok(other)) => Err(unread("SudoersList", other)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err("this machine's kdeviced did not answer".to_owned()),
            }
        }
    }
}

/// Make `other` — an account on this machine, by DID — an operator, under this
/// person's own key: by the person, never a key (`OperatorAdd`).
pub(crate) async fn make_operator(at: &IpcEndpoint, store: &UserStore, person: &str, other: &str) -> Result<(), String> {
    act(at, store, person, DeviceRequest::OperatorAdd { person: other.to_owned() }).await
}

/// Step `other` down — every key of theirs — under this person's own key
/// (`SudoersRemove` naming the person). `kdeviced` refuses the last.
pub(crate) async fn step_down(at: &IpcEndpoint, store: &UserStore, person: &str, other: &str) -> Result<(), String> {
    act(at, store, person, DeviceRequest::SudoersRemove { did: other.to_owned() }).await
}

/// Say one operator act under this person's own key: `request` is sent on a
/// connection that key authenticated, and is kept by `kdeviced` under it.
/// Refused before anything is said when the person is not an operator. Two
/// callers above, and no way to reach this with any other request.
async fn act(
    at: &IpcEndpoint,
    store: &UserStore,
    person: &str,
    request: DeviceRequest,
) -> Result<(), String> {
    let key = own_key(store).map_err(|e| format!("{e:#}"))?;
    let Standing::Operator { mut client, .. } = speak_as(at, &key, person).await? else {
        return Err("you are not one of this PC's operators".to_owned());
    };
    let verb = match &request {
        DeviceRequest::OperatorAdd { .. } => "OperatorAdd",
        DeviceRequest::SudoersRemove { .. } => "SudoersRemove",
        _ => "an operator's act",
    };
    match tokio::time::timeout(WITHIN, send(&mut client, request)).await {
        Ok(Ok(DeviceResponse::SudoersModified)) => Ok(()),
        Ok(Ok(other)) => Err(unread(verb, other)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("this machine's kdeviced did not answer".to_owned()),
    }
}
