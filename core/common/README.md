# kotton-static

**Layer 0 — Constants**

Compile-time constants and path-construction functions for Kotton. Nothing in
this crate changes at runtime — no I/O, no state, no external dependencies.

**Modules:**

- `paths` — canonical directory layout and the path-construction functions used
  across the workspace:
  - `base_dir()` → `~/.kotton/` on all platforms
  - `user_dir(base, user_id)`, `users_dir(base)`, `sessions_dir(base)`
  - `ipc_name()` — platform-appropriate socket / named-pipe identifier
- `crypto` — KDF label strings (`LABEL_MASTER`, `LABEL_MIGRATION_SEED`, etc.) and
  algorithm identifier tags used throughout the cryptographic layer for domain
  separation. Every call to `HKDF` that uses these labels produces a key in a
  distinct, non-overlapping key space.

**Does not:** contain any implementations, I/O, or runtime behaviour of any kind.

**Depends on:** nothing internal.
