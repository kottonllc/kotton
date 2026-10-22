// SPDX-License-Identifier: AGPL-3.0-or-later
//! Secure Enclave device binding for macOS (RFC-0053 step 8).
//!
//! The macOS counterpart of [`crate::tpm_binding`], and deliberately the same
//! shape: a binding secret encrypted to a key whose private half cannot leave
//! the hardware, so a copied `vault.json` is useless on another machine.
//!
//! # ⚠ UNVERIFIED
//!
//! **This backend has never been compiled or run.** It was written on Windows,
//! where `cfg(target_os = "macos")` means even `cargo check` does not look at
//! it. Every other part of RFC-0053 step 8 was verified against real hardware
//! before merging; this was not, and it is labelled here rather than in a commit
//! message so the next person to open the file learns it immediately.
//!
//! Treat the first run on a Mac as bring-up, not regression testing. The design
//! is settled and mirrors the TPM backend; the FFI details are where mistakes
//! will be. `crate::tpm_binding`'s tests are the contract to port across.
//!
//! # Why ECIES rather than the TPM's RSA
//!
//! The Secure Enclave holds **only NIST P-256** keys — no RSA, at any size — so
//! the "encrypt 32 bytes to my own key" trick the TPM backend uses cannot be
//! done with the same primitive. `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM`
//! is the equivalent: it does an ephemeral ECDH against the enclave key's public
//! half, derives an AES-GCM key by X9.63 KDF, and seals the payload. Decryption
//! runs the agreement inside the enclave, so the private scalar never surfaces.
//!
//! The security property is therefore identical to the Windows path — a secret
//! recoverable only by hardware — reached with the one asymmetric primitive the
//! enclave actually offers.
//!
//! # What it does not do
//!
//! As with the TPM: no attempt counting. That needs an access-control policy on
//! the key (`SecAccessControlCreateWithFlags` with `.userPresence` or
//! `.biometryCurrentSet`), which is the piece that would let the enclave refuse
//! guesses and finally justify a short PIN. Until then
//! [`kotton_sys::secret::CustodyBackend::counts_attempts`] answers `false`
//! and RFC-0053's passphrase requirement stands.
//!
//! Adding that policy is a small change *here* and a large change to the user
//! experience — every unlock would prompt Touch ID — so it belongs with the
//! biometrics design in RFC-0053, not with this file.

use kotton_sys::secret::{CustodyBackend, DeviceBinding, SecretsError, SecretsResult};

/// Keychain application tag identifying Kotton's enclave key. Stable forever:
/// changing it strands every bound vault on every Mac.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const KEY_TAG: &[u8] = b"sh.kotton.device-binding.v1";
/// Length of the binding secret, in bytes.
const SECRET_LEN: usize = 32;

/// A device binding backed by this Mac's Secure Enclave.
pub struct SecureEnclaveBinding {
    /// The ECIES ciphertext of the binding secret, as stored on disk.
    sealed: Vec<u8>,
}

impl SecureEnclaveBinding {
    /// Create a fresh binding secret and seal it to this Mac's Secure Enclave.
    ///
    /// Returns the binding and the ciphertext to persist; see
    /// [`crate::tpm_binding::TpmBinding::create`] for why the caller must write
    /// that ciphertext durably *before* sealing a vault against it.
    pub fn create() -> SecretsResult<(Self, Vec<u8>)> {
        let mut secret = [0u8; SECRET_LEN];
        {
            use rand::RngCore;
            rand::rngs::OsRng
                .try_fill_bytes(&mut secret)
                .map_err(|e| SecretsError::Storage(format!("failed to draw random bytes: {e}")))?;
        }
        let sealed = imp::encrypt_to_enclave(&secret)?;
        secret.fill(0);
        Ok((
            Self {
                sealed: sealed.clone(),
            },
            sealed,
        ))
    }

    /// Not yet: the enclave backend has no access-control policy on its key.
    /// Kept as an error rather than absent so `PlatformBinding` has one surface
    /// on both platforms; see the module doc for the `SecAccessControl` work.
    pub fn create_with_credential(_credential: &str) -> SecretsResult<(Self, Vec<u8>)> {
        Err(SecretsError::Storage(
            "the Secure Enclave binding has no credential policy yet".into(),
        ))
    }

    /// See [`Self::create_with_credential`].
    pub fn supports_credential_policy() -> bool {
        false
    }

    /// Reopen an existing binding from its stored ciphertext.
    pub fn from_sealed(sealed: Vec<u8>) -> Self {
        Self { sealed }
    }

    /// Whether this machine has a usable Secure Enclave.
    pub fn is_available() -> bool {
        imp::enclave_is_usable()
    }
}

impl DeviceBinding for SecureEnclaveBinding {
    fn backend(&self) -> CustodyBackend {
        CustodyBackend::AppleSecureEnclave
    }

    /// The enclave key has no access-control policy yet, so the credential is
    /// not consulted; see the module doc for what would change that.
    fn binding_secret(&self, _credential: Option<&str>) -> SecretsResult<[u8; SECRET_LEN]> {
        let plain = imp::decrypt_with_enclave(&self.sealed)?;
        plain.as_slice().try_into().map_err(|_| {
            SecretsError::Storage(format!(
                "the Secure Enclave returned {} bytes for the binding secret, expected {SECRET_LEN}",
                plain.len()
            ))
        })
    }

    /// No `SecAccessControl` policy on the key yet, so nothing counts.
    fn counts_attempts(&self) -> bool {
        false
    }

    /// And nothing needs the credential to open.
    fn requires_credential(&self) -> bool {
        false
    }
}

// ── Platform implementation ──────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod imp {
    //! Direct Security.framework FFI.
    //!
    //! Hand-declared rather than taken from `security-framework`, because the
    //! Secure Enclave key-creation attributes this needs sit at the edge of that
    //! crate's coverage and vary across its versions — and an unverifiable
    //! dependency on an API surface I could not check is a worse bet than the C
    //! API, which has been stable since macOS 10.12.

    use super::{KEY_TAG, SECRET_LEN};
    use core_foundation::base::{CFRelease, CFTypeRef, TCFType};
    use core_foundation::data::{CFData, CFDataRef};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::error::CFErrorRef;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use kotton_sys::secret::{SecretsError, SecretsResult};
    use std::ptr;

    type SecKeyRef = CFTypeRef;
    type OSStatus = i32;
    type SecKeyAlgorithm = CFStringRef;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFErrorRef) -> SecKeyRef;
        fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
        fn SecKeyCreateEncryptedData(
            key: SecKeyRef,
            algorithm: SecKeyAlgorithm,
            plaintext: CFDataRef,
            error: *mut CFErrorRef,
        ) -> CFDataRef;
        fn SecKeyCreateDecryptedData(
            key: SecKeyRef,
            algorithm: SecKeyAlgorithm,
            ciphertext: CFDataRef,
            error: *mut CFErrorRef,
        ) -> CFDataRef;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;

        static kSecAttrKeyType: CFStringRef;
        static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
        static kSecAttrKeySizeInBits: CFStringRef;
        static kSecAttrTokenID: CFStringRef;
        static kSecAttrTokenIDSecureEnclave: CFStringRef;
        static kSecPrivateKeyAttrs: CFStringRef;
        static kSecAttrIsPermanent: CFStringRef;
        static kSecAttrApplicationTag: CFStringRef;
        static kSecAttrLabel: CFStringRef;
        static kSecClass: CFStringRef;
        static kSecClassKey: CFStringRef;
        static kSecAttrKeyClass: CFStringRef;
        static kSecAttrKeyClassPrivate: CFStringRef;
        static kSecReturnRef: CFStringRef;
        static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM: CFStringRef;
        static kCFBooleanTrue: CFTypeRef;
    }

    /// Frees a retained CoreFoundation object on drop, so an early return cannot
    /// leak one.
    struct Owned(CFTypeRef);
    impl Drop for Owned {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` came from a Copy/Create call, so we own a
                // reference and have not released it.
                unsafe { CFRelease(self.0) }
            }
        }
    }

    fn fail(what: &str) -> SecretsError {
        SecretsError::Storage(format!("Secure Enclave: {what}"))
    }

    /// The attribute dictionary describing Kotton's enclave key.
    #[allow(unsafe_code)]
    fn key_attributes() -> CFDictionary {
        // SAFETY: the `kSec*` symbols are framework constants, valid for the
        // process lifetime; `CFString::wrap_under_get_rule` borrows without
        // taking ownership, which is correct for them.
        unsafe {
            let private_attrs = CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecAttrIsPermanent).as_CFType(),
                    CFString::wrap_under_get_rule(kCFBooleanTrue as CFStringRef).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrApplicationTag).as_CFType(),
                    CFData::from_buffer(KEY_TAG).as_CFType(),
                ),
            ]);

            CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyType).as_CFType(),
                    CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
                ),
                // P-256 is the only size the enclave holds; this is not a
                // tunable.
                (
                    CFString::wrap_under_get_rule(kSecAttrKeySizeInBits).as_CFType(),
                    CFNumber::from(256i32).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrTokenID).as_CFType(),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrLabel).as_CFType(),
                    CFString::new("Kotton device binding").as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecPrivateKeyAttrs).as_CFType(),
                    private_attrs.as_CFType(),
                ),
            ])
        }
    }

    /// Look up Kotton's existing enclave key, if it has been created.
    #[allow(unsafe_code)]
    fn find_key() -> Option<Owned> {
        // SAFETY: the query dictionary outlives the call; `result` is a live
        // local, and a non-null result is a +1 reference we take ownership of.
        unsafe {
            let query = CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecClass).as_CFType(),
                    CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyClass).as_CFType(),
                    CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrApplicationTag).as_CFType(),
                    CFData::from_buffer(KEY_TAG).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrTokenID).as_CFType(),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecReturnRef).as_CFType(),
                    CFString::wrap_under_get_rule(kCFBooleanTrue as CFStringRef).as_CFType(),
                ),
            ]);
            let mut out: CFTypeRef = ptr::null();
            if SecItemCopyMatching(query.as_concrete_TypeRef(), &mut out) == 0 && !out.is_null() {
                Some(Owned(out))
            } else {
                None
            }
        }
    }

    /// Open Kotton's enclave key, creating it on first use.
    ///
    /// Mirrors the TPM backend's race handling: if creation loses to another
    /// process, look the existing key up rather than failing, and never replace
    /// one — replacing it would strand every vault already bound to it.
    #[allow(unsafe_code)]
    fn open_or_create_key() -> SecretsResult<Owned> {
        if let Some(existing) = find_key() {
            return Ok(existing);
        }
        // SAFETY: attributes outlive the call; a non-null return is a +1
        // reference we take ownership of, and `error` is a live local we do not
        // read on success.
        let created = unsafe {
            let attrs = key_attributes();
            let mut err: CFErrorRef = ptr::null_mut();
            SecKeyCreateRandomKey(attrs.as_concrete_TypeRef(), &mut err)
        };
        if !created.is_null() {
            return Ok(Owned(created));
        }
        find_key().ok_or_else(|| fail("could not create or find the device-binding key"))
    }

    pub(super) fn enclave_is_usable() -> bool {
        open_or_create_key().is_ok()
    }

    #[allow(unsafe_code)]
    pub(super) fn encrypt_to_enclave(secret: &[u8; SECRET_LEN]) -> SecretsResult<Vec<u8>> {
        let key = open_or_create_key()?;
        // SAFETY: `key` is live for the call; the public key and ciphertext are
        // +1 references wrapped in `Owned` immediately.
        unsafe {
            let public = Owned(SecKeyCopyPublicKey(key.0));
            if public.0.is_null() {
                return Err(fail("the enclave key has no public half"));
            }
            let plaintext = CFData::from_buffer(secret.as_slice());
            let mut err: CFErrorRef = ptr::null_mut();
            let ct = SecKeyCreateEncryptedData(
                public.0,
                kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                plaintext.as_concrete_TypeRef(),
                &mut err,
            );
            if ct.is_null() {
                return Err(fail("sealing the binding secret to the enclave failed"));
            }
            let owned = Owned(ct as CFTypeRef);
            Ok(CFData::wrap_under_get_rule(owned.0 as CFDataRef)
                .bytes()
                .to_vec())
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn decrypt_with_enclave(sealed: &[u8]) -> SecretsResult<Vec<u8>> {
        let key = open_or_create_key()?;
        // SAFETY: as `encrypt_to_enclave`. The private key never leaves the
        // enclave; this hands it a ciphertext and receives a plaintext buffer.
        unsafe {
            let ciphertext = CFData::from_buffer(sealed);
            let mut err: CFErrorRef = ptr::null_mut();
            let pt = SecKeyCreateDecryptedData(
                key.0,
                kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                ciphertext.as_concrete_TypeRef(),
                &mut err,
            );
            if pt.is_null() {
                return Err(fail(
                    "recovering the binding secret failed — wrong device, or the key was removed",
                ));
            }
            let owned = Owned(pt as CFTypeRef);
            Ok(CFData::wrap_under_get_rule(owned.0 as CFDataRef)
                .bytes()
                .to_vec())
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::SECRET_LEN;
    use kotton_sys::secret::{SecretsError, SecretsResult};

    fn unsupported() -> SecretsError {
        SecretsError::Storage("Secure Enclave binding is a macOS backend".into())
    }

    pub(super) fn enclave_is_usable() -> bool {
        false
    }
    pub(super) fn encrypt_to_enclave(_: &[u8; SECRET_LEN]) -> SecretsResult<Vec<u8>> {
        Err(unsupported())
    }
    pub(super) fn decrypt_with_enclave(_: &[u8]) -> SecretsResult<Vec<u8>> {
        Err(unsupported())
    }
}
