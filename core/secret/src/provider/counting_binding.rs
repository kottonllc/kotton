// SPDX-License-Identifier: AGPL-3.0-or-later
//! A device binding that counts wrong credentials and locks — in memory.
//!
//! The shape of a TPM or enclave with an auth policy on its key, for tests that
//! need one where no hardware is: it is what lets the credential ladder — bar
//! flips to 19.9 bits, a six-digit PIN seals the vault, the seventh wrong guess
//! is refused even with the right one after — be proven end to end on any
//! machine. It claims `counts_attempts` **because it does count**, which is the
//! whole of what that predicate means; it binds to nothing, and says so.

use kotton_sys::secret::{CustodyBackend, DeviceBinding, SecretsError, SecretsResult};
use std::sync::Mutex;

/// See the module doc.
pub struct CountingBinding {
    secret: [u8; 32],
    credential: String,
    max_wrong: u32,
    wrong: Mutex<u32>,
}

impl CountingBinding {
    /// A binding that opens for `credential` and locks after `max_wrong`
    /// wrong ones.
    pub fn new(secret: [u8; 32], credential: &str, max_wrong: u32) -> Self {
        Self {
            secret,
            credential: credential.to_owned(),
            max_wrong,
            wrong: Mutex::new(0),
        }
    }

    /// Wrong credentials seen so far.
    pub fn wrong_attempts(&self) -> u32 {
        *self.wrong.lock().unwrap()
    }
}

impl DeviceBinding for CountingBinding {
    fn backend(&self) -> CustodyBackend {
        // Not a device binding at all — a counter standing in for one.
        CustodyBackend::None
    }

    fn binding_secret(&self, credential: Option<&str>) -> SecretsResult<[u8; 32]> {
        let mut wrong = self.wrong.lock().unwrap();
        if *wrong >= self.max_wrong {
            return Err(SecretsError::Storage(
                "locked: too many wrong credentials, the hardware refuses".into(),
            ));
        }
        match credential {
            Some(c) if c == self.credential => Ok(self.secret),
            _ => {
                *wrong += 1;
                Err(SecretsError::Storage("wrong credential".into()))
            }
        }
    }

    fn counts_attempts(&self) -> bool {
        true
    }

    fn requires_credential(&self) -> bool {
        true
    }
}
