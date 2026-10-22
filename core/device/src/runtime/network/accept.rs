// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accept loop handling for incoming peer connections.
//!
//! `spawn_accept_loop` accepts incoming QUIC connections and, for each one,
//! spawns a task that loops calling `connection.serve_one_request` until the
//! peer closes the connection.  Each request is dispatched through the
//! caller-supplied [`PeerHandler`] closure.  The loop ends when its listener
//! closes or its handle is aborted.

use crate::runtime::DeviceRuntime;
use kotton_peer::PeerHandler;
use kotton_sys::net::{Listener, RequestHandler, TransportError};
use kotton_diag::{Event, EventCategory, EventLevel};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

impl DeviceRuntime {
    /// Spawn an accept loop for `listener`.
    ///
    /// For each accepted connection a task is spawned that loops calling
    /// [`Connection::serve_one_request`] with a wrapper around `handler` until
    /// the peer closes the connection or a fatal error occurs.
    ///
    /// The loop runs until its listener closes or whoever holds the returned
    /// handle aborts it — every caller holds one, and shutdown aborts them all.
    /// It does not read whether the runtime is started. It did, after each
    /// accept — a second guard on a lifetime the handle already owned — and so a
    /// listener served on a runtime nobody had started answered one connection and
    /// went deaf, so a contact's second message in an hour found no door.
    pub(crate) fn spawn_accept_loop(
        self: &Arc<Self>,
        listener: Arc<dyn Listener>,
        transport_name: String,
        handler: PeerHandler,
    ) -> tokio::task::JoinHandle<()> {
        let runtime = Arc::clone(self);

        tokio::spawn(async move {
            tracing::info!(transport = %transport_name, "peer accept loop started");

            runtime
                .event_bus
                .publish(Event::new(
                    EventCategory::Network,
                    EventLevel::Info,
                    format!("Peer accept loop started for {transport_name}"),
                ))
                .ok();

            loop {
                match listener.accept().await {
                    Ok(connection) => {
                        let transport_name_clone = transport_name.clone();
                        let handler_clone = Arc::clone(&handler);
                        // Capture the peer's DID (or fall-back socket address) once per
                        // connection — the same identity applies to every request on it.
                        let peer_fingerprint = connection.peer_id().to_owned();

                        tracing::debug!(transport = %transport_name_clone, peer = %peer_fingerprint, "accepted peer connection");

                        tokio::spawn(async move {
                            // Serve requests on this connection until it closes.
                            loop {
                                // Wrap the Arc<dyn Fn> into a Box<dyn FnOnce> for each call.
                                let h = Arc::clone(&handler_clone);
                                let pf = peer_fingerprint.clone();
                                let req_handler: RequestHandler = Box::new(
                                    move |req: Vec<u8>| -> Pin<
                                        Box<dyn Future<Output = Vec<u8>> + Send + 'static>,
                                    > {
                                        Box::pin(async move { h(pf, req).await })
                                    },
                                );

                                match connection.serve_one_request(req_handler).await {
                                    Ok(true) => {} // served one request; continue
                                    Ok(false) => {
                                        tracing::debug!(
                                            transport = %transport_name_clone,
                                            "peer connection closed cleanly"
                                        );
                                        break;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            transport = %transport_name_clone,
                                            error = %e,
                                            "peer request error; closing connection"
                                        );
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(TransportError::ListenerClosed) => {
                        tracing::info!(transport = %transport_name, "peer accept loop stopped");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            transport = %transport_name,
                            error = %e,
                            "accept failed; retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuntimeConfig;
    use kotton_sys::net::{Address, Connection, TransportResult};

    /// A listener that has closed: every accept says so.
    struct Closed(Address);

    #[async_trait::async_trait]
    impl Listener for Closed {
        async fn accept(&self) -> TransportResult<Box<dyn Connection>> {
            Err(TransportError::ListenerClosed)
        }
        fn local_addr(&self) -> &Address {
            &self.0
        }
        async fn close(&self) -> TransportResult<()> {
            Ok(())
        }
    }

    /// The loop's lifetime is its listener's and its handle's, not the runtime's:
    /// on a runtime nobody started, a closed listener ends it.
    #[tokio::test]
    async fn an_accept_loop_ends_when_its_listener_closes() {
        let temp = tempfile::tempdir().unwrap();
        let rt = Arc::new(
            DeviceRuntime::new_with_secrets(
                temp.path().to_path_buf(),
                RuntimeConfig::default(),
                Arc::new(kotton_secret::MemorySecrets::new()),
            )
            .await
            .unwrap(),
        );
        let listener = Arc::new(Closed(Address::Quic("127.0.0.1:1".parse().unwrap())));
        let handler: PeerHandler = Arc::new(|_, _| Box::pin(async { Vec::new() }));
        let accept = rt.spawn_accept_loop(listener, "closed".into(), handler);
        tokio::time::timeout(std::time::Duration::from_secs(2), accept)
            .await
            .expect("the loop kept retrying a closed listener")
            .unwrap();
    }
}
