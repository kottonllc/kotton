// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `identity` domain — who the user is, and how they prove it again after
//! losing a device.
//!
//! Reached through [`KottonClient::identity`], which binds the user once:
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut identity = client.identity("did:key:…");
//! let status = identity.recovery_status().await?;
//! # let _ = status;
//! # Ok(())
//! # }
//! ```
//!
//! Split from `session` because they answer different questions. Identity is who
//! the user *is* — a DID, its key history, the recovery path back to it — and
//! survives every device. A session is a bounded, revocable right to act as that
//! user on one device right now. Kotton has no identity authority to appeal to
//! (`docs/design/principles.md`), so recovery lives here rather
//! than behind a support desk, which is exactly why the two must not blur.
//!
//! The domain name is RFC-0054's;
//! grouping the verbs under it is RFC-0055.

use std::io;

use super::{KottonClient, UserRequest, UserResponse};

/// What [`KottonClient::recover`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// The `did:kel` AID, unchanged by recovery.
    pub did: String,
    /// The identity's new operational key — this device's own, hex.
    pub new_key_hex: String,
    /// This device kept a copy of the identity key sealed under the person's
    /// old passphrase, and the daemon replaced it, because it sealed the key the
    /// recovery replaced. Either way the roots are sealed under the passphrase
    /// the recovery was given.
    pub sealed_copy_removed: bool,
}

/// The `identity` domain, bound to one user.
///
/// Borrows the client, so it costs nothing to construct and cannot outlive the
/// connection it speaks over.
pub struct Identity<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `identity` domain for a user.
    ///
    /// [`Identity::list`] and [`Identity::login_with_recovery_key`] do not use the
    /// bound user — the first spans all of them, and the second is how you act
    /// before you have one.
    pub fn identity(&mut self, user_id: &str) -> Identity<'_> {
        Identity {
            client: self,
            user_id: user_id.to_string(),
        }
    }
}

impl Identity<'_> {
    /// Provision a new identity. See [`KottonClient::create_user`].
    pub async fn create(&mut self, passphrase: &str) -> io::Result<(String, String)> {
        let u = self.user_id.clone();
        self.client.create_user(&u, passphrase).await
    }

    /// End this identity's session on this device. See [`KottonClient::logout_user`].
    pub async fn logout(&mut self) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.logout_user(&u).await
    }

    /// Every identity on this device. See [`KottonClient::list_users`].
    pub async fn list(&mut self) -> io::Result<Vec<String>> {
        self.client.list_users().await
    }

    /// Recover onto a device using the recovery key. Takes no bound user: this is
    /// the verb for when you do not have one yet.
    /// See [`KottonClient::login_with_recovery_key`].
    pub async fn login_with_recovery_key(
        &mut self,
        recovery_key: &str,
        user_id: Option<String>,
        device_name: Option<String>,
    ) -> io::Result<(String, String)> {
        self.client
            .login_with_recovery_key(recovery_key, user_id, device_name)
            .await
    }

    /// Take this identity back onto a device that holds only the phrase.
    /// See [`KottonClient::recover`].
    pub async fn recover(&mut self, recovery_key: &str, passphrase: &str) -> io::Result<Recovery> {
        let u = self.user_id.clone();
        self.client.recover(&u, recovery_key, passphrase).await
    }

    /// Rotate to a new key, retiring the old one. See [`KottonClient::rotate_identity`].
    pub async fn rotate(&mut self, recovery_key: &str, credential: Option<&str>) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.rotate_identity(&u, recovery_key, credential).await
    }

    /// Bind a hardware authenticator. See [`KottonClient::bind_device_hardware`].
    pub async fn bind_hardware(&mut self, credential: &str) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.bind_device_hardware(&u, credential).await
    }

    /// Record that the user has written the recovery phrase down.
    /// See [`KottonClient::confirm_mnemonic`].
    pub async fn confirm_mnemonic(&mut self) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.confirm_mnemonic(&u).await
    }

    /// How recoverable this identity currently is.
    /// See [`KottonClient::get_recovery_status`].
    pub async fn recovery_status(&mut self) -> io::Result<(bool, bool, bool, u8)> {
        let u = self.user_id.clone();
        self.client.get_recovery_status(&u).await
    }
}

impl KottonClient {
    /// Create a new user. Returns `(did, device_fingerprint)`.
    /// A session token is stored automatically and will be used for subsequent requests.
    ///
    /// No recovery phrase comes back, because creation no longer mints one — an
    /// identity starts with a random key and no recovery authority. Set one up
    /// afterwards; until then the account has no way back in, which is a state the
    /// KEL records rather than one anybody has to remember.
    pub async fn create_user(
        &mut self,
        user_id: &str,
        passphrase: &str,
    ) -> io::Result<(String, String)> {
        let request = UserRequest::CreateUser {
            user_id: user_id.to_string(),
            passphrase: kotton_wire::ipc::SecretText::new(passphrase),
        };
        match self.client.send(&request).await? {
            UserResponse::UserCreated {
                did,
                device_fingerprint,
                session_token,
            } => {
                self.authenticate(session_token.expose()).await?;
                self.cache_session(user_id, session_token.expose());
                Ok((did, device_fingerprint))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Give this identity a recovery phrase. Returns it once; nothing stores it.
    ///
    /// Separate from `create_user` because creation mints no phrase — an identity
    /// starts with a random key and no recovery authority. This is the "set up
    /// recovery" action, and it may be called more than once to add further
    /// authorities: the committed set only ever grows.
    ///
    /// **Two things come back, not one.** Recovery needs an authority and a
    /// locator: the phrase proves who you are, and the nodes returned beside it
    /// are where the sealed copy went — the only place a wiped device can get it
    /// back from, and the only moment anything says so. The daemon has reported
    /// them all along; this method dropped them at a `..` until 2026-09-12
    /// (`TASK-add-recovery-prints-the-card`).
    pub async fn add_recovery_phrase(&mut self, user_id: &str) -> io::Result<String> {
        Ok(self.add_recovery_phrase_with_copies(user_id).await?.0)
    }

    /// [`add_recovery_phrase`](Self::add_recovery_phrase) with the locator: the
    /// phrase, and every node that took the sealed copy, whole.
    ///
    /// Each node carries what `peer add <label> <did> <pubkey-hex> <addr>` takes,
    /// which is what a fresh device must run before `id recover` can ask anyone
    /// for anything.
    pub async fn add_recovery_phrase_with_copies(
        &mut self,
        user_id: &str,
    ) -> io::Result<(String, Vec<kotton_wire::peer::PairedNode>)> {
        let request = UserRequest::AddRecoveryPhrase {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::RecoveryPhraseAdded {
                recovery_key,
                copies_delivered_to,
            } => Ok((recovery_key.expose().to_owned(), copies_delivered_to)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Logout (remove) a user from this device.
    pub async fn logout_user(&mut self, user_id: &str) -> io::Result<()> {
        let request = UserRequest::LogoutUser {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::UserLoggedOut => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Recover an account using a 24-word BIP-39 recovery phrase.
    /// Returns `(user_id, device_fingerprint)`. A session token is stored automatically.
    pub async fn login_with_recovery_key(
        &mut self,
        recovery_key: &str,
        user_id: Option<String>,
        device_name: Option<String>,
    ) -> io::Result<(String, String)> {
        let request = UserRequest::LoginWithRecoveryKey {
            recovery_key: kotton_wire::ipc::SecretText::new(recovery_key),
            device_name,
            user_id,
        };
        match self.client.send(&request).await? {
            UserResponse::LoginSuccessful {
                user_id,
                device_fingerprint,
                session_token,
            } => {
                self.authenticate(session_token.expose()).await?;
                self.cache_session(&user_id, session_token.expose());
                Ok((user_id, device_fingerprint))
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Rotate the user's operational identity key via a mnemonic recovery rotation
    /// (RFC-0038 — survive key compromise). The `did:kel` AID is unchanged; returns
    /// the new operational verifying key (hex). Requires an authenticated session.
    ///
    /// `credential` is the person's daily passphrase: the rotation re-seals their
    /// vault under it so the new key is still the key after a restart, and a
    /// person with a vault is refused without it.
    pub async fn rotate_identity(
        &mut self,
        user_id: &str,
        recovery_key: &str,
        credential: Option<&str>,
    ) -> io::Result<String> {
        let request = UserRequest::RotateIdentity {
            user_id: user_id.to_string(),
            recovery_key: kotton_wire::ipc::SecretText::new(recovery_key),
            credential: credential.map(kotton_wire::ipc::SecretText::new),
        };
        match self.client.send(&request).await? {
            UserResponse::IdentityRotated { new_key_hex } => Ok(new_key_hex),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Take the account back on a device that holds only the phrase
    /// (`RFC-0081`). Fetches the identity's chain and sealed recovery copy from
    /// a paired node, proves the phrase, installs the data roots, rotates the
    /// identity onto this device's key, and seals the roots under `passphrase`,
    /// replacing a copy of the replaced key this device kept sealed under an old
    /// one ([`Recovery`]). Read `passphrase` at a terminal, as the phrase is.
    ///
    /// Run after `login_with_recovery_key` claimed the name and `peer_add` said
    /// where the data is. Rotates every time it runs, so run it once.
    pub async fn recover(
        &mut self,
        user_id: &str,
        recovery_key: &str,
        passphrase: &str,
    ) -> io::Result<Recovery> {
        let request = UserRequest::Recover {
            user_id: user_id.to_string(),
            recovery_key: kotton_wire::ipc::SecretText::new(recovery_key),
            passphrase: kotton_wire::ipc::SecretText::new(passphrase),
        };
        match self.client.send(&request).await? {
            UserResponse::Recovered { did, new_key_hex, sealed_copy_removed } => {
                Ok(Recovery { did, new_key_hex, sealed_copy_removed })
            }
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// List all user IDs loaded on this device.
    pub async fn list_users(&mut self) -> io::Result<Vec<String>> {
        let request = UserRequest::ListUsers;
        match self.client.send(&request).await? {
            UserResponse::UserList { users } => Ok(users),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Bind this identity's vault to this device's hardware (RFC-0053 step 8).
    ///
    /// Returns the backend that holds the binding. Opt-in and consequential:
    /// afterwards the vault opens only on this machine.
    pub async fn bind_device_hardware(
        &mut self,
        user_id: &str,
        credential: &str,
    ) -> io::Result<String> {
        let request = UserRequest::BindDeviceHardware {
            user_id: user_id.to_string(),
            credential: kotton_wire::ipc::SecretText::new(credential),
        };
        match self.client.send(&request).await? {
            UserResponse::DeviceBound { backend } => Ok(backend),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Mark that the user has confirmed their BIP-39 recovery mnemonic.
    pub async fn confirm_mnemonic(&mut self, user_id: &str) -> io::Result<()> {
        let request = UserRequest::ConfirmMnemonic {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::MnemonicConfirmed => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the recovery layer coverage for `user_id`.
    ///
    /// Returns `(mnemonic_confirmed, pin_set, escrow_set, guardian_count)`.
    pub async fn get_recovery_status(
        &mut self,
        user_id: &str,
    ) -> io::Result<(bool, bool, bool, u8)> {
        let request = UserRequest::GetRecoveryStatus {
            user_id: user_id.to_string(),
        };
        match self.client.send(&request).await? {
            UserResponse::RecoveryStatus {
                mnemonic_confirmed,
                pin_set,
                escrow_set,
                guardian_count,
            } => Ok((mnemonic_confirmed, pin_set, escrow_set, guardian_count)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}
