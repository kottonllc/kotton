// SPDX-License-Identifier: AGPL-3.0-or-later
//! TPM-backed device binding for Windows (RFC-0053 step 8).
//!
//! Binds the at-rest vault to *this machine* by deriving a secret that only this
//! TPM can reproduce. An attacker who copies `vault.json` — with or without the
//! correct credential — gets nothing, because the unlock key mixes in a secret
//! that never existed outside the chip. That is what RFC-0053 means by hardware
//! sealing "removing the offline attack": guessing has to happen here, at this
//! machine's rate.
//!
//! ## The mechanism, and why this one
//!
//! A persisted RSA-2048 key is created in CNG's **Microsoft Platform Crypto
//! Provider**, which is the TPM. Its private half never leaves the chip. A
//! random 32-byte binding secret is encrypted to it once (OAEP-SHA256) and the
//! 256-byte ciphertext stored beside the vault; every later unlock recovers the
//! secret by asking the TPM to decrypt it.
//!
//! Encrypt-to-self was chosen over ECDH key agreement for one practical reason:
//! `NCryptEncrypt`/`NCryptDecrypt` take raw buffers, so there is **no key-blob
//! marshalling** — no `BCRYPT_ECCKEY_BLOB` headers, no X/Y coordinate layout to
//! get subtly wrong. The security property is identical (a secret recoverable
//! only by a non-exportable key), and the FFI surface is six calls instead of
//! twenty.
//!
//! ## Two kinds of binding, and which one counts
//!
//! A binding made with [`TpmBinding::create`] holds a key with **no auth
//! policy**: the TPM decrypts for anyone who can call it as this OS user, so an
//! attacker holding the machine still guesses at full speed. It removes the
//! offline attack and nothing more, and its [`DeviceBinding::counts_attempts`]
//! is `false`.
//!
//! A binding made with [`TpmBinding::create_with_credential`] holds a key
//! whose TPM **auth value is the daily credential** (`NCRYPT_PIN_PROPERTY` on
//! the Platform Crypto Provider). The chip will not decrypt without it, a wrong
//! one is a failed authorization the TPM's own dictionary-attack counter
//! records, and past the lockout threshold the TPM refuses for its recovery
//! period — a counter no attacker holding the disk, or the machine, can reset.
//! That is what RFC-0053 means by hardware attempt-limiting, and it is the one
//! property that lets a short PIN stand (DEC-0046).
//!
//! **`counts_attempts` for such a binding is gated by [`TPM_LOCKOUT_VERIFIED`],
//! which is `false` until a person has bound a vault on a real TPM, entered the
//! wrong credential past the threshold, and seen the chip lock.** The code is
//! type-checked for the Windows target from Linux; it has not run against a
//! TPM. Flipping the constant on a promise would relax the credential bar
//! everywhere Windows runs, on code nobody has watched work — the exact mistake
//! the predicate exists to prevent (`TASK-the-enclave-does-not-count-attempts`).
//!
//! ## Recovery
//!
//! Clearing the TPM, resetting the machine, or moving the disk destroys the key
//! and with it the binding secret — the vault then opens only via the recovery
//! phrase. This is the same bargain BitLocker makes, and it is why binding must
//! stay opt-in and why the mnemonic must always work.

use kotton_sys::secret::{CustodyBackend, DeviceBinding, SecretsError, SecretsResult};

/// The name of Kotton's persisted TPM key. Stable forever: changing it strands
/// every bound vault on every machine.
const KEY_NAME: &str = "kotton-device-binding-v1";
/// CNG provider that fronts the TPM. Only the Windows implementation opens one.
#[cfg(target_os = "windows")]
const PROVIDER: &str = "Microsoft Platform Crypto Provider";
/// Length of the binding secret, in bytes.
const SECRET_LEN: usize = 32;

/// A device binding backed by this machine's TPM.
///
/// Holds the sealed secret rather than the secret itself: the plaintext exists
/// only for the moment a vault is opened.
pub struct TpmBinding {
    /// The OAEP ciphertext of the binding secret.
    sealed: Vec<u8>,
    /// `Some(id)` when the key carries an auth policy: the credential is its
    /// TPM auth value, and the key is named per binding by this id. `None` is a
    /// legacy binding on the shared, policy-less key.
    credential_key: Option<[u8; KEY_ID_LEN]>,
}

/// Whether a person has watched a real TPM lock out a wrong credential on a
/// binding made by [`TpmBinding::create_with_credential`].
///
/// `false` until then, so [`DeviceBinding::counts_attempts`] keeps answering
/// `false` and RFC-0053's passphrase requirement stays in force. The hardware
/// run that flips it is owed to the owner and named in
/// `TASK-the-enclave-does-not-count-attempts`; the flip is this one line.
pub const TPM_LOCKOUT_VERIFIED: bool = false;

/// Leading bytes of a stored binding whose key carries an auth policy. A legacy
/// binding is a bare 256-byte OAEP ciphertext, so a reader tells them apart by
/// this tag — and nothing else, since RSA-2048 OAEP output cannot start with
/// ASCII `KTP1` and also be 256 bytes plus this header.
const CREDENTIAL_MAGIC: &[u8; 4] = b"KTP1";
/// Bytes of the per-binding key id that follows the tag.
const KEY_ID_LEN: usize = 16;
/// Name prefix of a per-binding, credential-policied TPM key; the hex key id
/// follows. Stable forever, like [`KEY_NAME`].
const CREDENTIAL_KEY_PREFIX: &str = "kotton-device-binding-pin-v1-";

fn credential_key_name(id: &[u8; KEY_ID_LEN]) -> String {
    format!("{CREDENTIAL_KEY_PREFIX}{}", hex::encode(id))
}

impl TpmBinding {
    /// Create a fresh binding secret and seal it to this machine's TPM.
    ///
    /// Returns the binding and the ciphertext to persist. Losing that ciphertext
    /// is equivalent to losing the secret, so the caller must write it durably
    /// **before** sealing a vault against it.
    pub fn create() -> SecretsResult<(Self, Vec<u8>)> {
        let mut secret = [0u8; SECRET_LEN];
        getrandom(&mut secret)?;
        let sealed = imp::encrypt_to_key(&secret, KEY_NAME, None)?;
        // The plaintext is dropped here; it is recovered on demand.
        secret.fill(0);
        Ok((
            Self {
                sealed: sealed.clone(),
                credential_key: None,
            },
            sealed,
        ))
    }

    /// Create a binding whose TPM key takes `credential` as its auth value.
    ///
    /// A fresh per-binding key is created with `NCRYPT_PIN_PROPERTY` set before
    /// it is finalized, so the chip will not decrypt without the credential and
    /// counts each wrong one. The stored bytes carry a tag and the key id ahead
    /// of the ciphertext so [`Self::from_sealed`] knows which key, and that a
    /// credential is needed, without holding it.
    ///
    /// The credential is the same daily credential the vault is sealed under
    /// (RFC-0053 tier 2), so there is one secret to remember and it is checked
    /// twice: by Argon2id in software and by the TPM, which is the half that
    /// counts. Changing the credential means a new binding — see
    /// `provisioning::set_user_pin`.
    pub fn create_with_credential(credential: &str) -> SecretsResult<(Self, Vec<u8>)> {
        let mut id = [0u8; KEY_ID_LEN];
        getrandom(&mut id)?;
        let mut secret = [0u8; SECRET_LEN];
        getrandom(&mut secret)?;
        let ciphertext = imp::encrypt_to_key(&secret, &credential_key_name(&id), Some(credential))?;
        secret.fill(0);
        let mut stored = Vec::with_capacity(4 + KEY_ID_LEN + ciphertext.len());
        stored.extend_from_slice(CREDENTIAL_MAGIC);
        stored.extend_from_slice(&id);
        stored.extend_from_slice(&ciphertext);
        Ok((
            Self {
                sealed: ciphertext,
                credential_key: Some(id),
            },
            stored,
        ))
    }

    /// Whether this platform can put an auth policy on the binding key at all.
    /// `true` where the Platform Crypto Provider exists — the property itself
    /// is set at key creation, not probed.
    pub fn supports_credential_policy() -> bool {
        cfg!(target_os = "windows")
    }

    /// Reopen an existing binding from its stored bytes.
    ///
    /// A stored binding is either a legacy bare ciphertext or the tagged form
    /// [`Self::create_with_credential`] writes; the tag decides.
    pub fn from_sealed(stored: Vec<u8>) -> Self {
        if stored.len() > 4 + KEY_ID_LEN && &stored[..4] == CREDENTIAL_MAGIC {
            let mut id = [0u8; KEY_ID_LEN];
            id.copy_from_slice(&stored[4..4 + KEY_ID_LEN]);
            return Self {
                sealed: stored[4 + KEY_ID_LEN..].to_vec(),
                credential_key: Some(id),
            };
        }
        Self {
            sealed: stored,
            credential_key: None,
        }
    }



    /// Whether this machine has a usable TPM-backed provider.
    ///
    /// Probes by opening the provider rather than by reading a capability flag,
    /// because a provider that is registered but unusable (TPM disabled in
    /// firmware, cleared, or owned by another OS install) is the failure this
    /// needs to catch.
    pub fn is_available() -> bool {
        imp::provider_is_usable()
    }
}

impl DeviceBinding for TpmBinding {
    fn backend(&self) -> CustodyBackend {
        CustodyBackend::WindowsTpm
    }

    fn binding_secret(&self, credential: Option<&str>) -> SecretsResult<[u8; SECRET_LEN]> {
        let plain = match &self.credential_key {
            None => imp::decrypt_with_key(&self.sealed, KEY_NAME, None)?,
            Some(id) => {
                let Some(credential) = credential else {
                    return Err(SecretsError::Storage(
                        "this binding's key carries an auth policy; the daily credential is \
                         required to open it"
                            .into(),
                    ));
                };
                imp::decrypt_with_key(&self.sealed, &credential_key_name(id), Some(credential))?
            }
        };
        plain.as_slice().try_into().map_err(|_| {
            SecretsError::Storage(format!(
                "TPM returned {} bytes for the binding secret, expected {SECRET_LEN}",
                plain.len()
            ))
        })
    }

    /// A key with an auth value is counted by the TPM's dictionary-attack
    /// lockout — once that has been seen to happen. A legacy key is not.
    fn counts_attempts(&self) -> bool {
        self.credential_key.is_some() && TPM_LOCKOUT_VERIFIED
    }

    fn requires_credential(&self) -> bool {
        self.credential_key.is_some()
    }

    /// A legacy binding shares [`KEY_NAME`] with every other and is never
    /// deleted; a policied one has its own key, removed here.
    fn discard(&self) {
        if let Some(id) = &self.credential_key {
            let _ = imp::delete_key(&credential_key_name(id));
        }
    }
}

fn getrandom(buf: &mut [u8]) -> SecretsResult<()> {
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|e| SecretsError::Storage(format!("failed to draw random bytes: {e}")))
}

// ── Platform implementation ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod imp {
    use super::{PROVIDER, SECRET_LEN};
    use kotton_sys::secret::{SecretsError, SecretsResult};
    use std::ptr;
    use windows::core::HSTRING;
    use windows::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
        NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, NCRYPT_FLAGS, NCRYPT_HANDLE,
        NCRYPT_KEY_HANDLE, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PIN_PROPERTY, NCRYPT_PROV_HANDLE,
        NCRYPT_RSA_ALGORITHM,
    };

    /// RAII for an `NCRYPT_*` handle, so an early return cannot leak one.
    struct Handle(usize);
    impl Drop for Handle {
        // SAFETY: `self.0` is a handle NCrypt gave us and we have not freed;
        // the zero check keeps a default-constructed Handle from being freed.
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0));
                }
            }
        }
    }

    fn err(what: &str, e: windows::core::Error) -> SecretsError {
        SecretsError::Storage(format!("{what}: {e}"))
    }

    // SAFETY: out-param is a live local; the provider name is a NUL-terminated
    // HSTRING owned for the duration of the call.
    #[allow(unsafe_code)]
    fn open_provider() -> SecretsResult<Handle> {
        let mut prov = NCRYPT_PROV_HANDLE::default();
        unsafe { NCryptOpenStorageProvider(&mut prov, &HSTRING::from(PROVIDER), 0) }
            .map_err(|e| err("opening the TPM storage provider", e))?;
        Ok(Handle(prov.0))
    }

    pub(super) fn provider_is_usable() -> bool {
        open_provider().is_ok()
    }

    /// The credential as the TPM auth value: UTF-16, NUL-terminated, the form
    /// `NCRYPT_PIN_PROPERTY` takes. Set on a fresh key before it is finalized
    /// (which is what gives the key the policy) and on an opened key before
    /// use (which is the authorization the chip checks and counts).
    // SAFETY: `pin` is a live local for the call; the handle is one we hold.
    #[allow(unsafe_code)]
    fn set_key_credential(key: &Handle, credential: &str) -> SecretsResult<()> {
        let wide: Vec<u16> = credential.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|u| u.to_le_bytes()).collect();
        unsafe {
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0),
                NCRYPT_PIN_PROPERTY,
                &bytes,
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(|e| err("setting the TPM key's auth value", e))
    }

    /// Delete a persisted key by name. Best-effort; a missing key is fine.
    // SAFETY: as `open_or_create_key`; a deleted handle is not freed again.
    #[allow(unsafe_code)]
    pub(super) fn delete_key(name: &str) -> SecretsResult<()> {
        let prov = open_provider()?;
        let name = HSTRING::from(name);
        let mut key = NCRYPT_KEY_HANDLE::default();
        if unsafe {
            NCryptOpenKey(
                NCRYPT_PROV_HANDLE(prov.0),
                &mut key,
                &name,
                windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .is_err()
        {
            return Ok(());
        }
        // NCryptDeleteKey frees the handle on success; only free it ourselves
        // if the delete failed.
        match unsafe { NCryptDeleteKey(key, 0) } {
            Ok(()) => Ok(()),
            Err(e) => {
                drop(Handle(key.0));
                Err(err("deleting a TPM binding key", e))
            }
        }
    }

    /// Open the persisted TPM key called `name`, creating it on first use.
    ///
    /// With `credential`, a *created* key gets it as its auth value before
    /// finalization and an *opened* one has it set before use. Without,
    /// the key has no policy — the legacy shared binding key.
    // SAFETY: `prov` outlives both calls (it is borrowed), and every out-param
    // is a live local. Handles returned are wrapped in `Handle` before any
    // fallible operation, so no path leaks one.
    #[allow(unsafe_code)]
    fn open_or_create_key(prov: &Handle, name: &str, credential: Option<&str>) -> SecretsResult<Handle> {
        let name = HSTRING::from(name);
        let mut key = NCRYPT_KEY_HANDLE::default();

        if unsafe {
            NCryptOpenKey(
                NCRYPT_PROV_HANDLE(prov.0),
                &mut key,
                &name,
                windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .is_ok()
        {
            let handle = Handle(key.0);
            if let Some(c) = credential {
                set_key_credential(&handle, c)?;
            }
            return Ok(handle);
        }

        // Not present — create it. The TPM generates the key internally and the
        // private half is non-exportable by construction, which is the whole
        // point: there is no flag to forget here.
        let mut fresh = NCRYPT_KEY_HANDLE::default();
        match unsafe {
            NCryptCreatePersistedKey(
                NCRYPT_PROV_HANDLE(prov.0),
                &mut fresh,
                NCRYPT_RSA_ALGORITHM,
                &name,
                windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        } {
            // Another process created it between our open and our create — the
            // two-process first-use race (kuserd and the CLI starting together).
            // Re-open rather than fail, and never overwrite: the key that exists
            // is the right one, and replacing it would strand every vault
            // already bound to it. This is not hypothetical — running the tests
            // in parallel produced exactly this, as `0x80280084` on a decrypt
            // against a key that had been recreated underneath.
            Ok(()) => {}
            Err(create_err) => {
                let mut existing = NCRYPT_KEY_HANDLE::default();
                unsafe {
                    NCryptOpenKey(
                        NCRYPT_PROV_HANDLE(prov.0),
                        &mut existing,
                        &name,
                        windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
                        NCRYPT_FLAGS(0),
                    )
                }
                .map_err(|_| err("creating the TPM binding key", create_err))?;
                // Already finalized by whoever created it — returning here skips
                // the finalize below, which would error on a finished key.
                let handle = Handle(existing.0);
                if let Some(c) = credential {
                    set_key_credential(&handle, c)?;
                }
                return Ok(handle);
            }
        }

        let handle = Handle(fresh.0);
        // The auth policy has to be on the key *before* it is finalized; a
        // property set afterwards is a per-handle authorization, not a policy.
        if let Some(c) = credential {
            set_key_credential(&handle, c)?;
        }
        unsafe { NCryptFinalizeKey(NCRYPT_KEY_HANDLE(handle.0), NCRYPT_FLAGS(0)) }
            .map_err(|e| err("finalizing the TPM binding key", e))?;
        Ok(handle)
    }

    /// OAEP-SHA256 parameters. The label is empty, matching the probe and .NET's
    /// `OaepSHA256`.
    fn oaep() -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        }
    }

    // SAFETY: buffers are live locals for the duration of each call, and the
    // two-call size-then-fill protocol is what NCryptEncrypt documents.
    #[allow(unsafe_code)]
    pub(super) fn encrypt_to_key(
        secret: &[u8; SECRET_LEN],
        name: &str,
        credential: Option<&str>,
    ) -> SecretsResult<Vec<u8>> {
        let prov = open_provider()?;
        let key = open_or_create_key(&prov, name, credential)?;
        let padding = oaep();

        let mut needed = 0u32;
        unsafe {
            NCryptEncrypt(
                NCRYPT_KEY_HANDLE(key.0),
                Some(secret.as_slice()),
                Some(&padding as *const _ as *const _),
                None,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
        .map_err(|e| err("sizing the TPM-sealed binding secret", e))?;

        let mut out = vec![0u8; needed as usize];
        let mut written = 0u32;
        unsafe {
            NCryptEncrypt(
                NCRYPT_KEY_HANDLE(key.0),
                Some(secret.as_slice()),
                Some(&padding as *const _ as *const _),
                Some(out.as_mut_slice()),
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
        .map_err(|e| err("sealing the binding secret to the TPM", e))?;
        out.truncate(written as usize);
        Ok(out)
    }

    // SAFETY: as `encrypt_to_tpm`. `sealed` is borrowed for the call only.
    #[allow(unsafe_code)]
    pub(super) fn decrypt_with_key(
        sealed: &[u8],
        name: &str,
        credential: Option<&str>,
    ) -> SecretsResult<Vec<u8>> {
        let prov = open_provider()?;
        let key = open_or_create_key(&prov, name, credential)?;
        let padding = oaep();

        let mut needed = 0u32;
        unsafe {
            NCryptDecrypt(
                NCRYPT_KEY_HANDLE(key.0),
                Some(sealed),
                Some(&padding as *const _ as *const _),
                None,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
        .map_err(|e| err("sizing the TPM-unsealed binding secret", e))?;

        let mut out = vec![0u8; needed as usize];
        let mut written = 0u32;
        unsafe {
            NCryptDecrypt(
                NCRYPT_KEY_HANDLE(key.0),
                Some(sealed),
                Some(&padding as *const _ as *const _),
                Some(out.as_mut_slice()),
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
        .map_err(|e| err("recovering the binding secret from the TPM", e))?;
        out.truncate(written as usize);
        Ok(out)
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    use super::SECRET_LEN;
    use kotton_sys::secret::{SecretsError, SecretsResult};

    fn unsupported() -> SecretsError {
        SecretsError::Storage("TPM device binding is a Windows backend".into())
    }

    pub(super) fn provider_is_usable() -> bool {
        false
    }
    pub(super) fn encrypt_to_key(
        _: &[u8; SECRET_LEN],
        _: &str,
        _: Option<&str>,
    ) -> SecretsResult<Vec<u8>> {
        Err(unsupported())
    }
    pub(super) fn decrypt_with_key(_: &[u8], _: &str, _: Option<&str>) -> SecretsResult<Vec<u8>> {
        Err(unsupported())
    }
    pub(super) fn delete_key(_: &str) -> SecretsResult<()> {
        Err(unsupported())
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    /// The whole contract, against the real chip: a secret sealed to this TPM
    /// comes back byte-identical, and only through the TPM.
    ///
    /// Skips rather than fails where no usable TPM exists, because a CI machine
    /// without one is an environment fact rather than a defect — but it prints,
    /// so a silent skip cannot be mistaken for a pass.
    #[test]
    #[serial_test::serial(kotton_tpm_key)]
    fn a_secret_sealed_to_this_tpm_comes_back() {
        if !TpmBinding::is_available() {
            eprintln!("SKIPPED: no usable TPM-backed provider on this machine");
            return;
        }
        let (binding, sealed) = TpmBinding::create().expect("seal to TPM");
        assert_eq!(sealed.len(), 256, "RSA-2048 OAEP ciphertext");

        let secret = binding.binding_secret(None).expect("recover from TPM");
        assert_eq!(secret.len(), 32);
        assert_ne!(secret, [0u8; 32], "a zero secret would mean nothing sealed");

        // Reopening from the stored ciphertext must give the same secret — this
        // is what makes the binding stable across daemon restarts.
        let reopened = TpmBinding::from_sealed(sealed);
        assert_eq!(
            reopened.binding_secret(None).expect("recover again"),
            secret,
            "the binding secret must be stable, or every restart strands the vault"
        );
    }

    /// Two bindings must differ, or a vault bound on one machine would open on
    /// another that happened to derive the same constant.
    #[test]
    #[serial_test::serial(kotton_tpm_key)]
    fn separate_bindings_are_distinct() {
        if !TpmBinding::is_available() {
            eprintln!("SKIPPED: no usable TPM-backed provider on this machine");
            return;
        }
        let (a, _) = TpmBinding::create().expect("first");
        let (b, _) = TpmBinding::create().expect("second");
        assert_ne!(
            a.binding_secret(None).unwrap(),
            b.binding_secret(None).unwrap(),
            "each binding must carry its own randomness"
        );
    }

    /// A binding whose key carries the credential as its auth value opens with
    /// it and refuses without it — and refuses a wrong one, which is the event
    /// the TPM's dictionary-attack counter records. **Bring-up test**: written
    /// on Linux against the Windows target's types; the first run on a TPM is
    /// what `TPM_LOCKOUT_VERIFIED` waits for.
    #[test]
    #[serial_test::serial(kotton_tpm_key)]
    fn a_credential_policied_key_opens_only_with_its_credential() {
        if !TpmBinding::is_available() {
            eprintln!("SKIPPED: no usable TPM-backed provider on this machine");
            return;
        }
        let (binding, stored) = TpmBinding::create_with_credential("correct horse").expect("seal");
        assert!(binding.requires_credential());
        assert!(stored.starts_with(CREDENTIAL_MAGIC), "tagged form");
        let secret = binding.binding_secret(Some("correct horse")).expect("opens with the credential");
        let reopened = TpmBinding::from_sealed(stored);
        assert!(reopened.requires_credential());
        assert_eq!(reopened.binding_secret(Some("correct horse")).unwrap(), secret);
        assert!(reopened.binding_secret(None).is_err(), "no credential, no secret");
        assert!(
            reopened.binding_secret(Some("wrong horse")).is_err(),
            "a wrong credential is a failed TPM authorization"
        );
        binding.discard();
    }

    /// Corrupted ciphertext must fail loudly rather than yielding a wrong
    /// secret, which would silently produce an unopenable vault.
    #[test]
    #[serial_test::serial(kotton_tpm_key)]
    fn tampered_ciphertext_is_refused() {
        if !TpmBinding::is_available() {
            eprintln!("SKIPPED: no usable TPM-backed provider on this machine");
            return;
        }
        let (_, mut sealed) = TpmBinding::create().expect("seal");
        sealed[0] ^= 0xff;
        assert!(TpmBinding::from_sealed(sealed).binding_secret(None).is_err());
    }
}

#[cfg(test)]
mod format_tests {
    use super::*;

    /// A legacy binding is a bare ciphertext and needs no credential; a tagged
    /// one names its key and does. The reader tells them apart by the tag, so a
    /// daemon learns a vault's limiting before anyone types anything.
    #[test]
    fn stored_form_says_whether_a_credential_is_needed() {
        let legacy = TpmBinding::from_sealed(vec![0x5a; 256]);
        assert!(!legacy.requires_credential());
        assert!(!legacy.counts_attempts());

        let mut stored = Vec::new();
        stored.extend_from_slice(CREDENTIAL_MAGIC);
        stored.extend_from_slice(&[7u8; KEY_ID_LEN]);
        stored.extend_from_slice(&[0x5a; 256]);
        let tagged = TpmBinding::from_sealed(stored);
        assert!(tagged.requires_credential());
        assert_eq!(tagged.sealed.len(), 256, "the tag and id are stripped from the ciphertext");
        assert_eq!(tagged.credential_key, Some([7u8; KEY_ID_LEN]));
    }

    /// The gate: a credential-policied binding does not claim to count until a
    /// person has watched the chip lock. This test is the tripwire for the flip —
    /// when `TPM_LOCKOUT_VERIFIED` becomes true, it must be updated to assert the
    /// opposite, and the record must carry the run that justified it.
    #[test]
    fn counting_is_not_claimed_before_the_hardware_run() {
        let mut stored = Vec::new();
        stored.extend_from_slice(CREDENTIAL_MAGIC);
        stored.extend_from_slice(&[1u8; KEY_ID_LEN]);
        stored.extend_from_slice(&[0u8; 256]);
        let tagged = TpmBinding::from_sealed(stored);
        assert_eq!(
            tagged.counts_attempts(),
            TPM_LOCKOUT_VERIFIED,
            "counts_attempts follows the verified flag exactly"
        );
        // Through the instance, not the constant: the day the flag flips, this
        // is the assertion that must be re-read, and the message says why.
        assert!(
            !tagged.counts_attempts(),
            "the TPM lockout has not been seen on hardware; the credential bar stays at 50 bits"
        );
    }
}
