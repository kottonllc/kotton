// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::OsConnection;
use kotton_sys::ipc::IpcEndpoint;
use kotton_sys::ipc::Connection;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::sync::mpsc;

/// Maximum IPC response frame length (32 MiB).
///
/// Mirrors the server-side cap. Prevents the client from allocating an
/// unbounded buffer if the server (or an impersonator) sends a huge length.
const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;

/// IPC client for sending requests and receiving responses.
///
/// Generic over the [`Connection`] beneath it, defaulting to the host-OS
/// transport so existing callers are unaffected. The parameter is the seam a
/// test substitutes: [`crate::MemoryConnection`] drives the same framing and
/// serialization with no daemon, no socket, and no named pipe.
pub struct IpcClient<Req, Resp, C = OsConnection> {
    connection: C,
    _phantom: std::marker::PhantomData<(Req, Resp)>,
}

impl<Req, Resp> IpcClient<Req, Resp, OsConnection>
where
    Req: Serialize,
    Resp: for<'de> Deserialize<'de>,
{
    /// Connect to an IPC server at the given endpoint
    pub async fn connect(endpoint: IpcEndpoint) -> io::Result<Self> {
        let connection = OsConnection::connect(&endpoint)
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            connection,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<Req, Resp, C> IpcClient<Req, Resp, C>
where
    Req: Serialize,
    Resp: for<'de> Deserialize<'de>,
    C: Connection,
{
    /// Build a client over an already-established connection.
    ///
    /// The seam for tests and for any transport that is not the host OS.
    pub fn from_connection(connection: C) -> Self {
        Self {
            connection,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Send a request and wait for a response
    pub async fn send(&mut self, request: &Req) -> io::Result<Resp> {
        self.write_request(request).await?;
        self.read_frame().await
    }

    /// Send a request and return a channel that yields a stream of response
    /// frames.  Consumes `self` — the underlying connection is dedicated to
    /// reading stream frames until the sender (daemon) closes it.
    ///
    /// The spawned task sends frames into the channel until either:
    /// - the connection is closed by the server, or
    /// - the returned [`mpsc::Receiver`] is dropped (backpressure: the task
    ///   will stop when the send fails).
    pub async fn send_streaming(mut self, request: &Req) -> io::Result<mpsc::Receiver<Resp>>
    where
        Resp: Send + 'static,
        Req: Send + 'static,
        C: Send + 'static,
    {
        self.write_request(request).await?;

        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            // An error is the connection closing (or failing); either ends the stream.
            while let Ok(frame) = self.read_frame().await {
                if tx.send(frame).await.is_err() {
                    break; // receiver dropped
                }
            }
        });
        Ok(rx)
    }

    async fn write_request(&mut self, request: &Req) -> io::Result<()> {
        let json = serde_json::to_vec(request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = json.len() as u32;
        let mut msg = Vec::with_capacity(4 + json.len());
        msg.extend_from_slice(&len.to_le_bytes());
        msg.extend_from_slice(&json);
        let mut written = 0;
        while written < msg.len() {
            let n = self
                .connection
                .write(&msg[written..])
                .await
                .map_err(io::Error::other)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero bytes"));
            }
            written += n;
        }
        Ok(())
    }

    async fn read_frame(&mut self) -> io::Result<Resp> {
        let mut len_bytes = [0u8; 4];
        self.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_FRAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("IPC response frame too large: {len} bytes (max {MAX_FRAME_LEN})"),
            ));
        }
        let mut buffer = vec![0u8; len];
        self.read_exact(&mut buffer).await?;
        serde_json::from_slice(&buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut read = 0;
        while read < buf.len() {
            let n = self
                .connection
                .read(&mut buf[read..])
                .await
                .map_err(io::Error::other)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            read += n;
        }
        Ok(())
    }
}
