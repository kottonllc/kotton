// SPDX-License-Identifier: AGPL-3.0-or-later
//! A door on a peer circuit: one request type in, one response type out.
//!
//! The rule is about *acceptors* — a thing that deserializes a wire type is a
//! channel's door, and one type should have one of them. Most doors in the tree
//! are IPC sockets, so "acceptor" and "listener" are nearly the same word, and
//! `channel-check` reads listener call sites to find them.
//!
//! A peer's bytes arrive at a door that is not a socket: a paired peer's
//! circuit, a vault's tenant circuit, a contact's mailbox reached at an address
//! derived from a key pair. What decides what may be *said* there is which type
//! the door decodes. A closure that happened to call `from_slice` would be a
//! door no gate can see — the failure `channel-check`'s own documentation calls
//! being "silently vacuous".
//!
//! So the door is named, and it is the only way to build one.
//! [`PeerHandler`], the type-erased handler every peer transport serves, has a
//! private field and one constructor, [`PeerDoor::serving`]: a closure is not a
//! `PeerHandler`, and nothing outside this module can make one (kotton #278).
//! The type a peer's bytes decode as is therefore always some door's `Req`.
//! The compiler holds that much; it does not hold that the call site writes
//! `Req` out (`PeerDoor::serving` infers it from the closure), so
//! `channel-check` refuses any `PeerDoor` that is not
//! `PeerDoor::<Req, Resp>::serving(..)` with one named `Req`, the form a reader
//! and a check can both find.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

/// What a peer transport serves: one request's bytes, from the peer whose DID
/// the transport proved, to the response's bytes.
///
/// The first argument of [`Self::serve`] is the connecting peer's DID string
/// (e.g. `did:key:z6Mk…`), derived from the peer's TLS certificate; the second
/// is the raw request bytes.
///
/// Built only by [`PeerDoor::serving`]: the field is private to this module and
/// there is no other constructor, so every handler decodes its door's `Req`
/// before anything of the node's runs.
///
/// A door is how one is made:
///
/// ```
/// use kotton_peer::door::PeerDoor;
/// use kotton_peer::PeerHandler;
///
/// let door: PeerHandler =
///     PeerDoor::<String, String>::serving(|_, said| async move { said }, |e| e);
/// ```
///
/// A closure is not one, wherever it is put — a binding, a struct field, an
/// argument, a `Result` — because it does not coerce to a struct (kotton #279):
///
/// ```compile_fail,E0308
/// use kotton_peer::door::Answer;
/// use kotton_peer::PeerHandler;
/// use std::sync::Arc;
///
/// let raw: PeerHandler = Arc::new(|_: String, b: Vec<u8>| -> Answer {
///     Box::pin(async move { b })
/// });
/// ```
///
/// and the field is private, so it cannot be wrapped by hand either:
///
/// ```compile_fail,E0423
/// use kotton_peer::door::Answer;
/// use kotton_peer::PeerHandler;
/// use std::sync::Arc;
///
/// let raw = PeerHandler(Arc::new(|_: String, b: Vec<u8>| -> Answer {
///     Box::pin(async move { b })
/// }));
/// ```
///
/// The error codes on these two are documentation: stable rustdoc runs a
/// `compile_fail` block and checks only that it fails, not why. The reasons
/// were confirmed by hand by compiling each snippet: `E0308` (mismatched
/// types) at the `Arc::new(..)` bound to a `PeerHandler`, and `E0423` (a tuple
/// struct with private fields) at `PeerHandler(..)`. A snippet that stopped
/// compiling for some other reason would still pass here.
#[derive(Clone)]
pub struct PeerHandler(Arc<dyn Fn(String, Vec<u8>) -> Answer + Send + Sync>);

/// The response a [`PeerHandler`] answers with, as bytes.
pub type Answer = Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;

impl PeerHandler {
    /// Answer one request from `peer_did`.
    pub fn serve(&self, peer_did: String, bytes: Vec<u8>) -> Answer {
        (self.0)(peer_did, bytes)
    }
}

/// See the module doc. Constructed only through [`Self::serving`].
pub struct PeerDoor<Req, Resp>(PhantomData<fn() -> (Req, Resp)>);

impl<Req, Resp> PeerDoor<Req, Resp>
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + 'static,
{
    /// A handler that decodes `Req`, answers it with `serve`, and encodes `Resp`.
    ///
    /// `undecodable` answers bytes that are not a `Req` at all. That is not a
    /// refused verb — at a door of one vocabulary there is no other verb to
    /// refuse — so it is given its own arm rather than folded into `serve`.
    pub fn serving<F, Fut, U>(serve: F, undecodable: U) -> PeerHandler
    where
        F: Fn(String, Req) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Resp> + Send + 'static,
        U: Fn(String) -> Resp + Send + Sync + 'static,
    {
        let serve = Arc::new(serve);
        let undecodable = Arc::new(undecodable);
        PeerHandler(Arc::new(move |peer_did: String, bytes: Vec<u8>| {
            let serve = Arc::clone(&serve);
            let undecodable = Arc::clone(&undecodable);
            Box::pin(async move {
                let response = match serde_json::from_slice::<Req>(&bytes) {
                    Ok(request) => serve(peer_did, request).await,
                    Err(e) => undecodable(e.to_string()),
                };
                serde_json::to_vec(&response).unwrap_or_default()
            }) as Answer
        }))
    }
}
