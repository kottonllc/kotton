# Network Transport Layer

Network communication layer for Kotton, enabling file sync and multi-device support.

## Features

- **mDNS Discovery**: Find Kotton instances on local network
- **TLS Transport**: Encrypted connections (using rustls)
- **Generic Protocol**: Domain-agnostic message passing
- **DID-based Auth**: Challenge-response authentication using DIDs
- **Connection Pooling**: Efficient connection reuse

## Architecture

This crate is **transport-only** - it doesn't know about files, sync, or application logic.

Consumers (VFS, daemon, etc.) define their own message types by implementing `NetworkMessage` trait.

## Usage

```rust
use KOTTON_network::{Discovery, NetworkTransport, TlsConfig, Envelope, NetworkMessage};
use serde::{Deserialize, Serialize};

// Define your message type
#[derive(Debug, Serialize, Deserialize)]
enum MyMessage {
    Ping,
    Pong,
}

impl NetworkMessage for MyMessage {
    fn message_type(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }
}

// Discover instances
let discovery = Discovery::new("my-instance".to_string(), 7878, "did:key:...".to_string())?;
discovery.advertise(7878, "did:key:...".to_string(), "0.1.0".to_string())?;

let mut instances = discovery.scan(Duration::from_secs(5))?;
while let Some(instance) = instances.recv().await {
    println!("Found: {} at {}", instance.name, instance.address);
}

// Connect and send messages
let transport = NetworkTransport::new(TlsConfig::self_signed()?);
let mut conn = transport.connect(addr).await?;

let envelope = Envelope::new(MyMessage::Ping);
conn.send(&envelope).await?;

let response = conn.receive().await?;
```

## Design Decisions

### M2 Scope

- Plain TCP (TLS deferred to post-M2 for simplicity)
- mDNS for local discovery only (HTTPS endpoints in M3)
- Bincode serialization (matches IPC, efficient)
- DID-based auth (no pre-shared secrets)

### Protocol

All messages wrapped in `Envelope<M>`:

- Version byte (protocol versioning)
- Optional session token (after auth)
- Request ID (for request/response matching)
- Message payload (generic, consumer-defined)

### Authentication

Challenge-response flow:

1. Client connects, sends DID
2. Server sends random challenge
3. Client signs with device key
4. Server verifies signature, returns session token
5. Future messages include session token

No pre-shared secrets - uses existing DID infrastructure.

## Testing

```bash
# Run all tests
cargo test -p kotton-network

# Test discovery
cargo test -p kotton-network discovery

# Test transport
cargo test -p kotton-network transport
```

## Future Work (Post-M2)

- TLS 1.3 for encryption
- HTTPS transport for cloud endpoints
- WebSocket support for browser clients
- HTTP/REST API for web integration
- QUIC transport for better mobile performance
