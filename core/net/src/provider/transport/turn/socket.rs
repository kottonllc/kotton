// SPDX-License-Identifier: AGPL-3.0-or-later
//! `TurnUdpSocket` — a `quinn::AsyncUdpSocket` that tunnels QUIC datagrams
//! through a TURN ChannelData relay.
//!
//! # Usage
//!
//! After `TurnClient::allocate()` + `create_permission()` + `channel_bind()`
//! are complete, consume the client:
//!
//! ```rust,ignore
//! let (socket, channel) = client.into_socket_and_channel(peer_relay_addr)?;
//! let turn_socket = Arc::new(TurnUdpSocket::new(
//!     socket, channel, alloc.relay_addr, peer_relay_addr,
//! ));
//! let endpoint = quinn::Endpoint::new_with_abstract_socket(
//!     EndpointConfig::default(), None, turn_socket, Arc::new(TokioRuntime),
//! )?;
//! ```

use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

// ── ChannelData framing ──────────────────────────────────────────────────────

const CHANNEL_MIN: u16 = 0x4000;
const CHANNEL_MAX: u16 = 0x7FFF;

/// Encode `data` as a RFC 5766 ChannelData message with 4-byte header.
fn encode_channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    // Pad to 4-byte boundary (RFC 5766 §11.4)
    let rem = data.len() % 4;
    if rem != 0 {
        out.extend_from_slice(&[0u8, 0, 0, 0][..4 - rem]);
    }
    out
}

// ── AlwaysReady poller ───────────────────────────────────────────────────────

/// A `UdpPoller` that always reports the socket as writable.
///
/// `tokio::net::UdpSocket::try_send` returns `WouldBlock` only when the
/// kernel TX buffer is transiently full; quinn will retry on the next
/// `try_send` call. There is no need to register a deep write-readiness
/// notification — reporting "ready" unconditionally is correct here.
#[derive(Debug)]
struct AlwaysReady;

impl UdpPoller for AlwaysReady {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── TurnUdpSocket ────────────────────────────────────────────────────────────

/// A `quinn::AsyncUdpSocket` wrapper that tunnels QUIC datagrams through a
/// TURN ChannelData relay.
///
/// **Send path**: `try_send` encodes the payload as a ChannelData frame and
/// calls `socket.try_send()` directly — non-blocking, no background task.
///
/// **Recv path**: a background Tokio task calls `socket.recv()` in a loop,
/// strips the ChannelData header, pushes the payload to an in-process queue,
/// and wakes the task registered by `poll_recv`.
///
/// Constructed via [`TurnUdpSocket::new`] after `TurnClient::channel_bind`
/// completes. The caller must first call
/// `TurnClient::into_socket_and_channel(peer_relay_addr)` to extract the
/// underlying `UdpSocket` and bound channel number.
#[derive(Debug)]
pub struct TurnUdpSocket {
    /// The underlying UDP socket, connected to the TURN server.
    socket: Arc<UdpSocket>,

    /// The ChannelData channel number bound to `peer_relay_addr`.
    channel: u16,

    /// Our relay address on the TURN server — reported as `local_addr()`.
    local_relay_addr: SocketAddr,

    /// The peer's relay address — appears as `RecvMeta::addr` on received
    /// datagrams so quinn knows where they came from.
    peer_relay_addr: SocketAddr,

    /// Inbound payloads stripped of their ChannelData header and pushed by
    /// the background recv task.
    recv_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,

    /// Waker registered by `poll_recv`; notified by the recv task when data
    /// arrives.
    recv_waker: Arc<Mutex<Option<Waker>>>,

    /// Recv task handle — kept alive for the lifetime of the socket.
    _task: Arc<JoinHandle<()>>,
}

impl TurnUdpSocket {
    /// Create a new `TurnUdpSocket` wrapping an already-connected, already-
    /// channel-bound `UdpSocket`.
    ///
    /// - `socket` — underlying `UdpSocket` connected to the TURN server
    /// - `channel` — channel number returned by `TurnClient::channel_bind`
    /// - `local_relay_addr` — our relay address on the TURN server
    /// - `peer_relay_addr` — the peer's relay address on the TURN server
    pub fn new(
        socket: UdpSocket,
        channel: u16,
        local_relay_addr: SocketAddr,
        peer_relay_addr: SocketAddr,
    ) -> Self {
        let socket = Arc::new(socket);
        let recv_queue: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let recv_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));

        let task = {
            let socket = Arc::clone(&socket);
            let recv_queue = Arc::clone(&recv_queue);
            let recv_waker = Arc::clone(&recv_waker);

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = match socket.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(err = %e, "TurnUdpSocket recv task I/O error; stopping");
                            break;
                        }
                    };

                    let pkt = &buf[..n];

                    // ChannelData: first 2 bytes are channel number (0x4000–0x7FFF),
                    // next 2 bytes are data length (without padding).
                    if pkt.len() >= 4 {
                        let chan = u16::from_be_bytes([pkt[0], pkt[1]]);
                        if (CHANNEL_MIN..=CHANNEL_MAX).contains(&chan) {
                            let data_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                            if pkt.len() >= 4 + data_len {
                                let payload = pkt[4..4 + data_len].to_vec();
                                tracing::trace!(
                                    channel = chan,
                                    len = data_len,
                                    "TurnUdpSocket: received datagram"
                                );
                                recv_queue.lock().unwrap().push_back(payload);
                                if let Some(waker) = recv_waker.lock().unwrap().take() {
                                    waker.wake();
                                }
                            }
                        }
                    }
                    // Non-ChannelData packets (TURN indications, etc.) are
                    // silently dropped — they are not relevant to QUIC.
                }
            })
        };

        Self {
            socket,
            channel,
            local_relay_addr,
            peer_relay_addr,
            recv_queue,
            recv_waker,
            _task: Arc::new(task),
        }
    }
}

impl AsyncUdpSocket for TurnUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysReady)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let frame = encode_channel_data(self.channel, transmit.contents);
        // `self.socket` is connected to the TURN server; try_send is
        // non-blocking and returns WouldBlock if the kernel TX buffer is full.
        self.socket.try_send(&frame).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut queue = self.recv_queue.lock().unwrap();
        if let Some(payload) = queue.pop_front() {
            let len = payload.len().min(bufs[0].len());
            bufs[0][..len].copy_from_slice(&payload[..len]);
            meta[0] = RecvMeta {
                addr: self.peer_relay_addr,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            Poll::Ready(Ok(1))
        } else {
            *self.recv_waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_relay_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
