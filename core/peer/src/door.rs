// SPDX-License-Identifier: AGPL-3.0-or-later
//! A door on a peer circuit: one request type in, one response type out.
//!
//! The rule is about *acceptors* — a thing that deserializes a wire type is a
//! channel's door, and one type should have one of them. Most doors in the tree
//! are IPC sockets, so "acceptor" and "listener" are nearly the same word, and
//! `channel-check` reads listener call sites to find them.
//!
//! A contact's mailbox is a door that is not a socket: it is
//! reached over a relayed circuit, at an address derived from a key pair, and
//! the thing that decides what may be *said* there is which type it decodes.
//! Building it as a closure that happens to call `from_slice` would have made
//! it invisible to the gate whose whole purpose is to see acceptors — the
//! failure that gate's own documentation calls being "silently vacuous".
//!
//! So the door is named. `PeerDoor::<Req, Resp>::serving(..)` is a call site a
//! reader and a check can both find, and it says the thing that matters about a
//! door in its own type parameters.

use crate::PeerHandler;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

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
        Arc::new(move |peer_did: String, bytes: Vec<u8>| {
            let serve = Arc::clone(&serve);
            let undecodable = Arc::clone(&undecodable);
            Box::pin(async move {
                let response = match serde_json::from_slice::<Req>(&bytes) {
                    Ok(request) => serve(peer_did, request).await,
                    Err(e) => undecodable(e.to_string()),
                };
                serde_json::to_vec(&response).unwrap_or_default()
            }) as std::pin::Pin<Box<dyn Future<Output = Vec<u8>> + Send>>
        })
    }
}
