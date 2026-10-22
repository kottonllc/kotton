// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's own key, and the proof it gives whoever dials it
//! (`TASK-a-relay-has-a-key-of-its-own-and-proves-it`, RFC-0084 V9).
//!
//! **Why a relay has one.** Until this, what made a relay *this relay* was the
//! spelling of its address, so a stranger answering at the same address was
//! indistinguishable from it. A key the relay proves is what lets a device, a
//! vault and a desktop holding the relay's line refuse a stand-in: the stand-in can answer at the
//! address, and cannot sign.
//!
//! **What it is.** An Ed25519 key made at first start, kept in the state
//! directory beside `rule.json` as [`KEY_FILE`], mode `0600`, and found again at
//! every start after. It signs one thing: [`identity_signing_input`] of a
//! caller's nonce and the address the relay announces, under a domain of its
//! own — so the relay signing whatever nonce a stranger chose can never be read
//! as it signing anything else.
//!
//! **What it is not.** Not a certificate and not the transport: plain HTTP stays
//! plain, and a relay that moves behind a different certificate, or to a
//! different address, is still the same relay. Not a name for anyone the relay
//! carries: the key is the relay's, public, and joins nothing about a person.
//!
//! **Made at creation.** `kotton-relay create` makes it, before the relay
//! serves (RFC-0084 V18), so the relay's line and its key exist together. A
//! relay with no state directory is created as it starts, and its key lives in
//! memory for the life of the process: a relay that changes key at every
//! restart is one every device refuses after its first restart, which is the
//! price of keeping nothing on disk.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use kotton_wire::rendezvous::{identity_signing_input, RelayIdentity, IDENTITY_NONCE_MAX};

/// The key's file, beside `rule.json` and `operators` in the state directory.
pub const KEY_FILE: &str = "identity.key";

/// The relay's signing key, held for as long as the process.
pub struct RelayKey {
    sk: SigningKey,
}

impl RelayKey {
    /// Find the key in `dir`, or make it there if this is the relay's first
    /// start. A file that is there and does not read as a key is an error: making
    /// a new one would be the relay silently becoming a stranger to every device
    /// that knows it, and failing to start says so instead.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(KEY_FILE);
        match read_key_file(&path) {
            Ok(seed) => Ok(Self { sk: SigningKey::from_bytes(&seed) }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let seed: [u8; 32] = rand::random();
                crate::admission::write_private(&path, format!("{}\n", hex(&seed)).as_bytes())
                    .map_err(|e| anyhow::anyhow!("the relay's key could not be kept at {}: {e}", path.display()))?;
                tracing::info!(file = %path.display(), "made the relay's key: this is its first start");
                Ok(Self { sk: SigningKey::from_bytes(&seed) })
            }
            Err(e) => Err(anyhow::anyhow!(
                "{}: {e}; refusing to start rather than become a relay nobody knows",
                path.display()
            )),
        }
    }

    /// The key in `dir`, if one is there — read, never made. `create` adopts
    /// a relay's state only with the key it already has.
    pub fn open_existing(dir: &Path) -> anyhow::Result<Option<Self>> {
        let path = dir.join(KEY_FILE);
        match read_key_file(&path) {
            Ok(seed) => Ok(Some(Self { sk: SigningKey::from_bytes(&seed) })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("{}: {e}", path.display())),
        }
    }

    /// A fresh key held in memory only: a relay with no state directory, for
    /// the life of its process.
    pub fn in_memory() -> Self {
        Self { sk: SigningKey::from_bytes(&rand::random()) }
    }

    /// A key held in memory only, for a test.
    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { sk: SigningKey::from_bytes(&bytes) }
    }

    /// The public key.
    pub fn public(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    /// The public key, 64 hex.
    pub fn public_hex(&self) -> String {
        hex(self.sk.verifying_key().as_bytes())
    }

    /// The proof for one caller: the public key, the address announced, and the
    /// signature over the caller's nonce and that address.
    pub fn prove(&self, nonce: &[u8], addr: &str) -> RelayIdentity {
        let sig = self.sk.sign(&identity_signing_input(nonce, addr));
        RelayIdentity {
            key: self.public_hex(),
            addr: addr.to_owned(),
            sig: hex(&sig.to_bytes()),
        }
    }
}

/// A caller's nonce, as `GET /identity?nonce=` carries it: hex, at least one
/// byte and at most [`IDENTITY_NONCE_MAX`]. Anything else is `None` and refused.
pub fn parse_nonce(text: &str) -> Option<Vec<u8>> {
    let bytes = unhex(text)?;
    (!bytes.is_empty() && bytes.len() <= IDENTITY_NONCE_MAX).then_some(bytes)
}

/// The key's seed from its file: 64 hex and an optional newline, in a regular
/// file only the relay's user can read.
///
/// Opened without following a link (`O_NOFOLLOW`) and without waiting
/// (`O_NONBLOCK`), then `fstat`ed on the descriptor read — the same care the
/// operators' file gets (`admission::read_operators`), since the directory's
/// owner can make the name anything.
fn read_key_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read as _;
    let bad = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_owned());
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        #[cfg(unix)]
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENXIO)) => {
            return Err(bad("is a link, a socket or a device, not the relay's key"))
        }
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(bad("is not a regular file, so it is not the relay's key"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(bad(
                "can be read by others than the relay's user; the key is kept mode 0600 \
                 (`chmod 600` it if it is the relay's own, or remove it to make a new one)",
            ));
        }
    }
    let mut text = String::new();
    (&mut f).take(256).read_to_string(&mut text).map_err(|_| bad("does not read as a key"))?;
    unhex(text.trim_end_matches('\n'))
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| bad("does not read as a key (64 hex)"))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    // Digits only: `from_str_radix` alone would take a leading `+`.
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
