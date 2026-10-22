// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory IPC transport — the second implementation of [`Connection`].
//!
//! Exists for two reasons, and the second is the load-bearing one:
//!
//! 1. It lets a caller exercise [`crate::IpcClient`] — framing, serialization,
//!    length caps, streaming — with no daemon, no socket, and no named pipe.
//! 2. It is a **second implementation of the trait**, which is what keeps the
//!    platform seam honest. A host type that creeps into [`Connection`]
//!    breaks this file, immediately, rather than surfacing years later when
//!    someone implements the trait against hardware. See
//!    `IDEA-tier-discipline`, Category 0.
//!
//! **It simplifies the transport, never the contract.** Framing, the
//! `WriteZero` and `UnexpectedEof` conditions, and the closed-connection
//! semantics behave as the OS transport does. A double that is more permissive
//! than the real thing converts an untested path into a falsely-tested one.

use async_trait::async_trait;
use kotton_sys::ipc::{Connection, IpcError, IpcResult};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// An [`Connection`] backed by in-memory buffers.
///
/// A test preloads the frames the peer should return, hands the connection to
/// [`crate::IpcClient::from_connection`], and afterwards inspects what the
/// client wrote.
///
/// # Example
///
/// ```
/// # use kotton_ipc::{IpcClient, MemoryConnection};
/// # #[derive(serde::Serialize)] struct Req { id: u32 }
/// # #[derive(serde::Deserialize, Debug, PartialEq)] struct Resp { ok: bool }
/// # async fn example() {
/// let conn = MemoryConnection::new();
/// conn.push_response(&serde_json::json!({ "ok": true })).unwrap();
///
/// let mut client: IpcClient<Req, Resp, _> = IpcClient::from_connection(conn.clone());
/// let resp = client.send(&Req { id: 7 }).await.unwrap();
///
/// assert_eq!(resp, Resp { ok: true });
/// assert_eq!(conn.written_frames().len(), 1);
/// # }
/// ```
#[derive(Clone, Default)]
pub struct MemoryConnection {
    inner: Arc<Mutex<Shared>>,
}

#[derive(Default)]
struct Shared {
    /// Bytes the peer will hand back, already framed.
    to_read: VecDeque<u8>,
    /// Every byte the client has written, framed as it sent them.
    written: Vec<u8>,
    /// Set by `shutdown`, or when the preloaded bytes run out mid-read.
    closed: bool,
}

impl MemoryConnection {
    /// A connection with nothing queued. Reading from it reports EOF, which is
    /// what the OS transport does on a closed socket.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue one length-prefixed frame for the client to read.
    ///
    /// `payload` is the frame body; the 4-byte little-endian length prefix that
    /// [`crate::IpcClient`] expects is added here, so callers write the same
    /// bytes a daemon would serialize.
    pub fn push_frame(&self, payload: &[u8]) {
        let mut g = self.inner.lock().unwrap();
        g.to_read
            .extend((payload.len() as u32).to_le_bytes().iter().copied());
        g.to_read.extend(payload.iter().copied());
    }

    /// Queue a value the peer should respond with, serialized as the client
    /// expects to receive it.
    pub fn push_response<T: serde::Serialize>(&self, value: &T) -> Result<(), serde_json::Error> {
        self.push_frame(&serde_json::to_vec(value)?);
        Ok(())
    }

    /// Every frame the client wrote, with length prefixes stripped.
    ///
    /// A trailing partial frame — one the client had not finished writing — is
    /// omitted rather than returned truncated.
    pub fn written_frames(&self) -> Vec<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let buf = &g.written;
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= buf.len() {
            let len = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
            i += 4;
            if i + len > buf.len() {
                break;
            }
            out.push(buf[i..i + len].to_vec());
            i += len;
        }
        out
    }

    /// The frames the client wrote, deserialized.
    pub fn written_requests<T: for<'de> serde::Deserialize<'de>>(
        &self,
    ) -> Result<Vec<T>, serde_json::Error> {
        self.written_frames()
            .iter()
            .map(|f| serde_json::from_slice(f))
            .collect()
    }

    /// Whether `shutdown` has been called or the queued bytes are exhausted.
    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }
}

#[async_trait]
impl Connection for MemoryConnection {
    async fn read(&mut self, buf: &mut [u8]) -> IpcResult<usize> {
        let mut g = self.inner.lock().unwrap();
        if g.closed && g.to_read.is_empty() {
            return Err(IpcError::ConnectionClosed);
        }
        if g.to_read.is_empty() {
            // No bytes and not explicitly closed: report EOF the way the OS
            // transport does, so `read_exact` raises `UnexpectedEof` rather
            // than spinning.
            g.closed = true;
            return Ok(0);
        }
        let n = buf.len().min(g.to_read.len());
        for slot in buf.iter_mut().take(n) {
            *slot = g.to_read.pop_front().expect("checked non-empty");
        }
        Ok(n)
    }

    async fn write(&mut self, buf: &[u8]) -> IpcResult<usize> {
        let mut g = self.inner.lock().unwrap();
        if g.closed {
            return Err(IpcError::ConnectionClosed);
        }
        g.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    async fn shutdown(&mut self) -> IpcResult<()> {
        self.inner.lock().unwrap().closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpcClient;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Req {
        verb: String,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Resp {
        ok: bool,
    }

    /// The whole point: a full request/response round trip through the real
    /// framing and serialization, with no daemon.
    #[tokio::test]
    async fn round_trip_without_a_daemon() {
        let conn = MemoryConnection::new();
        conn.push_response(&Resp { ok: true }).unwrap();

        let mut client: IpcClient<Req, Resp, _> = IpcClient::from_connection(conn.clone());
        let resp = client
            .send(&Req {
                verb: "ListUsers".into(),
            })
            .await
            .unwrap();

        assert_eq!(resp, Resp { ok: true });

        // And the request the client actually put on the wire is inspectable.
        let sent: Vec<Req> = conn.written_requests().unwrap();
        assert_eq!(sent, vec![Req { verb: "ListUsers".into() }]);
    }

    /// An exhausted connection must raise `UnexpectedEof` through `read_exact`,
    /// exactly as a closed socket does — the double may not be more forgiving.
    #[tokio::test]
    async fn exhausted_connection_reports_eof_not_success() {
        let conn = MemoryConnection::new();
        let mut client: IpcClient<Req, Resp, _> = IpcClient::from_connection(conn);
        let err = client
            .send(&Req { verb: "x".into() })
            .await
            .expect_err("no response was queued");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// Writing to a shut-down connection fails rather than silently buffering.
    #[tokio::test]
    async fn write_after_shutdown_fails() {
        let mut conn = MemoryConnection::new();
        conn.shutdown().await.unwrap();
        assert!(conn.is_closed());
        assert!(conn.write(b"x").await.is_err());
    }

    /// Frames are read back whole even when the reader asks for small chunks,
    /// so multi-read framing is exercised rather than assumed.
    #[tokio::test]
    async fn frames_survive_chunked_reads() {
        let conn = MemoryConnection::new();
        let big = Resp { ok: true };
        conn.push_response(&big).unwrap();
        let mut c = conn.clone();
        let mut one = [0u8; 1];
        let mut got = Vec::new();
        while let Ok(n) = c.read(&mut one).await {
            if n == 0 {
                break;
            }
            got.push(one[0]);
        }
        let len = u32::from_le_bytes([got[0], got[1], got[2], got[3]]) as usize;
        assert_eq!(len, got.len() - 4);
    }
}
