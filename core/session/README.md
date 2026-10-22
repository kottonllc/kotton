# kotton-providers-auth

**Layer 3 — HTTP Request Authentication Provider**

Provides `BearerProvider`, an implementation of the `RequestAuthProvider` trait
from `kotton-platform` that signs outbound HTTP requests with a JWT bearer token.

**Key public types:**

- `BearerProvider` — attaches `Authorization: Bearer <token>` to an `AuthRequest`.
  Used when making authenticated HTTP calls to external APIs.

**This crate is not the "auth layer".** Despite the name it handles only outbound
HTTP bearer token signing. The components that the name implies are elsewhere:

| What you might want                    | Where it actually lives         |
| -------------------------------------- | ------------------------------- |
| User PIN validation, weak PIN blocking | `kotton-services::PinValidator` |
| Brute-force rate limiting              | `kotton-services::RateLimiter`  |
| Session token issuance/validation      | `kotton-services::AuthService`  |
| Argon2id PIN hashing, DID generation   | `kotton-providers-crypto`       |
| AWS SigV4 / Azure SAS signing          | `crates/04_integrations/`       |

**Does not:** contain any PIN logic, session management, or cryptographic
primitives. All of that lives in `kotton-services` or `kotton-providers-crypto`.

**Depends on:** `kotton-platform`.

For the layer boundary decision table (what belongs here vs. `kotton-providers-crypto` vs. `kotton-services`), see [Processes and crates](../../docs/design/processes.md).
