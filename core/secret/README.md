# kotton-secret

Where an install keeps its secrets, and what holds a user's roots once they are unlocked.

The stores keep named strings and return them as written. The crate implements two traits
from `kotton-sys` (`core/sys/src/secret/mod.rs`): `SecretsStore` (get, set and delete a
named secret) and `DeviceBinding` (a 32-byte secret this machine's hardware can reproduce and
another machine cannot).

## Which store an install gets

`secrets_for_base_dir(base_dir)` opens the store for a runtime rooted at `base_dir`. It is
`SecretsProvider::for_base_dir(base_dir).open(base_dir)`, and the rule is the enum's, read
in this order:

1. **`SecretsProvider::Memory`** when `base_dir` is under the system temp directory. Both
   paths are spelled the same way before they are compared: the deepest ancestor that exists
   is canonicalized and the missing rest put back, so a path not yet created, Windows' 8.3
   short names and its verbatim prefix still match, and on Windows so does a difference in
   case. A base directory none of whose ancestors exists is throwaway. A throwaway root
   writes nothing that outlives the process.
2. **`SecretsProvider::File`** when the environment sets `KOTTON_SECRETS=file`.
3. **`SecretsProvider::Keychain`** otherwise.

A caller that must know the answer before it opens anything asks `for_base_dir` and keeps the
result: `outlives_the_process()` is false only for `Memory`, and `name()` is the word written
for it (`memory`, `file`, `keychain`). `open` returns an error, never an empty store, when the
chosen store exists and cannot be read.

## The three stores

- **`MemorySecrets`** (`src/provider/memory.rs`): a map in this process, gone at exit. It is
  compiled into every build, because it is what a throwaway root gets outside tests too;
  tests also inject it directly.
- **`FileSecrets`** (`src/provider/file.rs`): one `0600` file, `system/secrets.json` under
  the base directory, for a machine with no keychain (a rented vault, a gateway, a node in a
  container). It is chosen by the environment variable, never as a fallback. The file is the
  store and the value holds only its path, so several processes may hold it at once: a read
  reads the file and takes no lock; a write takes an exclusive advisory lock on
  `secrets.json.lock` beside it, re-reads, applies one change, writes beside and renames over.
  Only a file that does not exist opens empty; one that exists and does not parse is an error
  naming it.
- **`OsSecrets`** (`src/provider/os.rs`): the platform keychain through the `keyring` crate:
  Windows Credential Manager, the macOS Keychain, and on Linux the kernel keyring (the
  `linux-no-secret-service` feature, so no D-Bus is needed). Entries sit under the keyring
  service `Kotton` for the default install and `Kotton@<absolute base dir>` for any other, so
  two installs on one machine keep separate entries. On Linux a kernel keyring that refuses
  this process is its own error, `SecretsError::KeyringRefused`.

## Custody: `SealedCustody`

`SealedCustody` (`src/provider/sealed_custody.rs`) wraps an opened store and is itself a
`SecretsStore`. It exists so that a user's operational roots, once a sealed vault holds them,
are kept in this process's memory and not as plaintext in the keychain:

- `adopt_root(label)` takes a root into memory and deletes the platform's copy, as one
  operation. It is called only once a sealed copy exists, or a restart would lose the key.
- Roots are held grouped by the identity that owns them (the owner is read from the label,
  never searched for), so `lock_identity(user_id)` drops one person's roots and no one
  else's; `lock()` drops all of them.
- Every identity held has a deadline: `DEFAULT_WINDOW_SECS`, twelve hours, until the person
  sets their own. A fresh credential re-arms it (`set_open_until`), a read past it reads as
  locked, and `sweep_expired` names the identities whose window closed so the daemon can
  rebuild their stores.
- A read looks in memory first and then in the platform store; anything that is not a root
  passes straight through.

It removes the plaintext at rest. It does not defend against code already running in the
process that holds it.

## Device bindings

`TpmBinding` (Windows, through CNG's Platform Crypto Provider) and `SecureEnclaveBinding`
(macOS) implement `DeviceBinding`. `PlatformBinding` names `SecureEnclaveBinding` on macOS
and `TpmBinding` everywhere else, so `core/identity` asks for a binding without a `cfg` of its
own; off Windows the TPM type is a stub that reports unavailable and errors on use, so Linux
has no device binding. A binding made with `create_with_credential`, where
`supports_credential_policy()` says the platform can, puts the daily credential on the
hardware key. `SecureEnclaveBinding` is built on every platform, but its enclave backend only
when building for macOS, with a stub elsewhere; no gate builds for macOS (every workflow under
`.github/workflows/` runs on `ubuntu-latest`), so no check here compiles or runs the enclave
code. `CountingBinding`, an in-memory binding that counts wrong
credentials, is compiled only under `cfg(test)` or the crate's `test-utils` feature.

## Which processes open the store

Each one opens it through `secrets_for_base_dir` or `SecretsProvider`, so the rule above is
the only one.

| Process | What it keeps or reads |
| --- | --- |
| `kuserd` | Opens it once, when it builds its `DeviceRuntime` (`core/device/src/runtime/mod.rs`), and wraps it in `SealedCustody`, so every read in the process goes through custody: the device operational key and the roots of every user it serves. |
| `kctl` | The operator key, minted only when the store holds none (`client/cli/src/kctl.rs`). |
| `kotton device reset` | Deletes the install's user and device entries after the base directory is gone (`client/cli/src/commands/device.rs`). |
| `kdeviced` | One handler, for a supervised child that asks for the device operational key (`core/kdeviced/src/system.rs`). |
| `kvaultd` | Its own operational key and the mount-domain pins, in the store of its state directory (`core/kvaultd/src/lib.rs`), which it hands to the `DeviceRuntime` it builds, so it too is read through `SealedCustody`; `kvaultd create` refuses a state directory whose store would not outlive the process (`core/kvaultd/src/main.rs`). |
