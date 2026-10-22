# kotton-platform

**Layer 1 — Platform Abstractions**

Trait definitions for every OS capability Kotton needs. There are no
implementations here — a provider crate in Layer 3 supplies the concrete struct
for each trait. This separation allows every OS capability to be swapped or
mocked in tests without touching any higher-layer code.

**Trait modules:**

| Module           | Key traits                                                                             |
| ---------------- | -------------------------------------------------------------------------------------- |
| `auth`           | `AuthenticationProvider`, `RequestAuthProvider`                                        |
| `crypto`         | `Encryptor`, `Decryptor`, `Signer`, `Verifier`, `Hasher`, `KeyDeriver`, `RandomSource` |
| `crypto_suite`   | `CryptoSuite` — bundles a matched set of crypto primitives                             |
| `filesystem`     | `Filesystem` — async read/write/metadata                                               |
| `ipc`            | `IpcConnection`, `IpcListener` — transport-agnostic message passing                    |
| `network`        | `Discovery`, `NetworkMonitor`, `Peer`                                                  |
| `object_storage` | `ObjectStorage`, `ObjectMetadata` — blob key/value store                               |
| `process`        | `Process`, `ProcessConfig`, `ExitStatus`                                               |
| `secrets`        | `SecretsStore` — OS keychain integration                                               |
| `service`        | `Service`, `ServiceStatus` — daemon lifecycle                                          |
| `time`           | `Clock`, `Instant` — testable time source                                              |

**Naming note:** `kotton-platform/src/crypto/` contains _trait definitions_;
`crates/03_providers/crypto/src/` contains _implementations_. The directory names
are the same but the purposes are different — traits vs. concrete algorithms.

**Does not:** contain any implementations. For a working `Filesystem` use
`kotton-providers-filesystem`. For a working `IpcConnection` use
`kotton-providers-ipc`.

**Depends on:** nothing internal.
