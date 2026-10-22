# DHT Discovery - Quick Start Guide

## What is DHT Discovery?

DHT (Distributed Hash Table) discovery enables **decentralized peer-to-peer networking** without any central coordination. It uses libp2p's Kademlia protocol to create a resilient mesh network.

## Use Cases

- 🌐 **Global scale**: Connect peers across the internet
- 🔒 **Censorship resistance**: No central server to shut down
- 🚀 **Decentralized apps**: Build true P2P applications
- 🔐 **Privacy**: Encrypted, authenticated connections

## Basic Usage

### 1. Create a DHT Node

```rust
use KOTTON_providers_network::DhtDiscovery;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = "/ip4/0.0.0.0/tcp/0".parse()?;
    let bootstrap_peers = vec![]; // Empty for standalone node

    let discovery = DhtDiscovery::new(listen_addr, bootstrap_peers).await?;

    println!("Peer ID: {}", discovery.local_peer_id());
    println!("Ready for connections!");

    Ok(())
}
```

### 2. Bootstrap with Existing Peers

```rust
use libp2p::{Multiaddr, PeerId};

let bootstrap_peers = vec![
    (
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".parse::<PeerId>()?,
        "/ip4/192.168.1.100/tcp/7878".parse::<Multiaddr>()?,
    ),
];

let discovery = DhtDiscovery::new(listen_addr, bootstrap_peers).await?;
discovery.bootstrap().await?;
```

### 3. Discover Peers

```rust
// Get current peers (async)
let peers = discovery.get_peers_async().await?;

for peer in peers {
    println!("Found peer: {}", peer.id);
    for addr in peer.addresses {
        println!("  Address: {}", addr);
    }
}

// Or use Discovery trait (sync, returns cached)
use KOTTON_platform_network::Discovery;
let peers = discovery.discover_peers()?;
```

## Running Examples

### Example 1: Standalone DHT Node

```bash
cargo run --example dht_discovery -p kotton-providers-network
```

Output:

```
Local Peer ID: 12D3KooWDjNc3YbCp7yvjUkUhJLHsGNghjbmbrsQrkTmfGYwWMST

To connect another peer, use:
  cargo run --example dht_discovery -- /ip4/192.168.1.100/tcp/61478 12D3KooW...

Waiting for connections...
```

### Example 2: Connect to Existing Node

```bash
# Copy the address and peer ID from Example 1, then run:
cargo run --example dht_discovery -p kotton-providers-network -- \
    /ip4/192.168.1.100/tcp/61478 \
    12D3KooWDjNc3YbCp7yvjUkUhJLHsGNghjbmbrsQrkTmfGYwWMST
```

### Example 3: All Network Providers

```bash
cargo run --example network_providers -p kotton-providers-network
```

Shows DHT alongside mDNS, HTTP, and Static discovery.

## How It Works

### Transport Stack

```
┌─────────────────────┐
│   Kademlia DHT      │  ← Peer routing & discovery
├─────────────────────┤
│   Yamux             │  ← Stream multiplexing
├─────────────────────┤
│   Noise XX          │  ← Authenticated encryption
├─────────────────────┤
│   TCP               │  ← Reliable transport
└─────────────────────┘
```

### Architecture

```rust
┌──────────────────────┐
│   DhtDiscovery       │  ← Public API
│   - local_peer_id    │
│   - command_tx       │
│   - peers (cache)    │
└──────────┬───────────┘
           │ Commands (mpsc channel)
           ▼
┌──────────────────────┐
│   Event Loop         │  ← tokio::spawn
│   - swarm            │
│   - command_rx       │
│   - peer tracking    │
└──────────────────────┘
```

### Event Loop

The DHT runs a background task handling:

1. **Swarm events**: Connections, disconnections, DHT updates
2. **Commands**: Bootstrap, GetPeers, Shutdown
3. **Peer tracking**: Automatic routing table updates

## Configuration

### Listen Addresses

```rust
// All interfaces, random port
"/ip4/0.0.0.0/tcp/0".parse()?

// Specific port
"/ip4/0.0.0.0/tcp/7878".parse()?

// IPv6
"/ip6/::/tcp/7878".parse()?

// Specific interface
"/ip4/192.168.1.100/tcp/7878".parse()?
```

### Bootstrap Peers

Provide known peers to join the DHT network:

```rust
let bootstrap_peers = vec![
    (peer_id_1, addr_1),
    (peer_id_2, addr_2),
    // More peers = faster discovery
];
```

**Best Practices**:

- Use 3-5 bootstrap peers for resilience
- Mix geographic locations
- Prefer stable, long-running nodes

## Integration with DeviceService

```rust
use KOTTON_services_device::DeviceService;
use std::sync::Arc;

// Create DHT discovery
let dht = DhtDiscovery::new(listen_addr, bootstrap_peers).await?;
let dht = Arc::new(dht);

// Inject into service
let device_service = DeviceService::new(dht);

// Use service methods
let peers = device_service.discover_peers()?;
```

## Performance

- **Latency**: O(log n) hops to find peers
- **Memory**: O(k) routing table size (k=20 buckets)
- **Bandwidth**: Minimal - periodic keep-alive + queries
- **Scalability**: Millions of nodes (proven in IPFS)

## Security

### Encryption

All connections use **Noise XX** protocol:

- Authenticated encryption
- Forward secrecy
- Mutual authentication

### Identity

Each peer has a **cryptographic identity**:

```rust
let peer_id = discovery.local_peer_id();
// PeerId derives from public key
```

### Threats Mitigated

- ✅ **Eavesdropping**: Noise encryption
- ✅ **Man-in-the-middle**: Authenticated handshake
- ✅ **Impersonation**: Cryptographic PeerID
- ⚠️ **Sybil attacks**: Mitigated by Kademlia routing

## Troubleshooting

### "No peers discovered"

1. Check firewall/NAT:

   ```bash
   # Allow incoming TCP on DHT port
   netsh advfirewall firewall add rule name="Kotton DHT" dir=in action=allow protocol=TCP localport=7878
   ```

2. Verify bootstrap peers are reachable:

   ```bash
   telnet <bootstrap-ip> <bootstrap-port>
   ```

3. Enable DHT logging:
   ```rust
   env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
   ```

### "Bootstrap failed"

- Ensure bootstrap peers are online
- Check multiaddr format: `/ip4/x.x.x.x/tcp/port`
- Verify PeerId matches the listening node

### "Connection refused"

- Check if port is already in use
- Use port 0 for automatic assignment
- Verify network connectivity

## Advanced Usage

### Custom Protocol Name

```rust
use libp2p::{kad, StreamProtocol};

let protocol = StreamProtocol::new("/my-app/kad/1.0.0");
let config = kad::Config::new(protocol);
// Use config when creating Kademlia behavior
```

### Persistent Routing Table

```rust
// TODO: Future enhancement
// Save routing table on shutdown, restore on startup
```

### Health Monitoring

```rust
loop {
    tokio::time::sleep(Duration::from_secs(60)).await;

    let peer_count = discovery.get_peers_async().await?.len();
    println!("Active peers: {}", peer_count);

    if peer_count == 0 {
        discovery.bootstrap().await?;
    }
}
```

## Comparison with Other Discovery

| Feature                   | DHT      | mDNS        | Static | HTTP   |
| ------------------------- | -------- | ----------- | ------ | ------ |
| **Scope**                 | Global   | Local       | Config | Cloud  |
| **Setup**                 | Auto     | Zero-config | Manual | API    |
| **Central server**        | No       | No          | No     | Yes    |
| **Latency**               | O(log n) | O(1)        | O(1)   | O(ms)  |
| **Privacy**               | High     | Low         | High   | Medium |
| **Censorship resistance** | Yes      | N/A         | No     | No     |

## Resources

- [libp2p Documentation](https://docs.libp2p.io/)
- [Kademlia Paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
- [Noise Protocol](https://noiseprotocol.org/)
- [IPFS DHT](https://docs.ipfs.tech/concepts/dht/)

## Summary

DHT discovery enables **decentralized peer-to-peer networking** with:

- ✅ No central coordination
- ✅ Encrypted connections
- ✅ Global scale
- ✅ Censorship resistance

Perfect for building **truly decentralized applications** with Kotton!
