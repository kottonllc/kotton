# kotton-providers-crypto

**Layer 3 — Cryptographic Primitives**

Every cryptographic operation used by Kotton, as stateless pure functions and
zero/config-only structs. Nothing in this crate holds mutable runtime state.

**Algorithm coverage:**

| Algorithm                       | Types                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| ChaCha20-Poly1305 AEAD          | `ChaCha20Encryptor`, `ChaCha20Decryptor`                                              |
| AES-256-GCM AEAD                | `AesGcmEncryptor`, `AesGcmDecryptor`                                                  |
| BLAKE3                          | `Blake3Hasher`; `kdf::derive_master_secret`, `derive_db_key`, `derive_migration_seed` |
| SHA-256                         | `Sha256Hasher`                                                                        |
| Ed25519                         | `Ed25519Keypair`, `Ed25519Signer`, `Ed25519Verifier`                                  |
| ML-DSA (FIPS 204, post-quantum) | `MlDsaSuite`                                                                          |
| PBKDF2-HMAC-SHA256              | `Pbkdf2Deriver`                                                                       |
| Argon2id (PIN wrapping)         | `pin_wrap::wrap_seed`, `pin_wrap::unwrap_seed`                                        |
| BIP-39 mnemonic                 | `Bip39MnemonicProvider`, `kdf::master_from_mnemonic`                                  |
| SLIP-10 HD derivation           | `Slip10Deriver`                                                                       |
| `did:key` + `did:web`           | `DidKeyMethod`, `DidKeyResolver`, `DidWebResolver`                                    |
| OS CSPRNG                       | `OsRandom`                                                                            |

**Key hierarchy:**

```
BIP-39 mnemonic  →  SLIP-10 seed  →  Ed25519 device keypair (DID)
                                   ↘  master_secret (32 bytes)
                                         ↓  BLAKE3/HKDF
                                   db_key · file_keys · migration_keys
```

KDF labels (domain separators) are defined in `kotton-static::crypto` so they
are shared consistently across every derivation site.

**Does not:** hold session state, counters, or token maps. For those see
`kotton-services`. For where a domain lives see [Processes and crates](../../docs/design/processes.md).

**Depends on:** `kotton-static`, `kotton-platform`, `kotton-protocol`.
