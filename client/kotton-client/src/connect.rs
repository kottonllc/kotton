// SPDX-License-Identifier: AGPL-3.0-or-later
use std::io;
use std::io::IsTerminal;

use kotton_sys::ipc::IpcEndpoint;
use kotton_ipc::IpcClient;
#[cfg(unix)]
use kotton_common::kuserd_door;
#[cfg(windows)]
use kotton_common::kuserd_ipc_name;

use super::{KottonClient, PinUnlock, UserRequest, UserResponse};

/// How many times `connect_as` offers the keyboard before falling back to the
/// recovery phrase. Not a security bound — the daemon's attempt budget is that
/// (see `kuserd`'s `lock_policy`) — just how long a person is left retyping.
const PIN_PROMPT_ATTEMPTS: u8 = 3;

/// Whether the PIN leg of `connect_as` produced a session.
enum PinOutcome {
    /// Authenticated; the token is cached.
    Unlocked,
    /// No session from the PIN. The caller continues to the recovery phrase —
    /// distinct from an `Err`, which would end the login instead of falling to
    /// the credential that always works.
    FellThrough,
}

impl KottonClient {
    /// Connect to the running system daemon (unauthenticated).
    pub async fn connect() -> io::Result<Self> {
        #[cfg(windows)]
        let endpoint = IpcEndpoint::NamedPipe(kuserd_ipc_name());
        #[cfg(unix)]
        let endpoint = IpcEndpoint::UnixSocket(
            kuserd_door().map_err(io::Error::other)?,
        );

        // The default daemon: its tokens are the ones the cache is for.
        let mut client = Self::connect_to(endpoint).await?;
        client.caches_sessions = true;
        Ok(client)
    }

    /// Connect to the daemon and authenticate as `user_id`, using the cached
    /// session token, then the daily credential, then the recovery phrase.
    ///
    /// This is the right call for any CLI command that operates on behalf of a
    /// specific user — the caller never needs to manage auth manually.
    ///
    /// ## Why the PIN is tried first (RFC-0053 step 2)
    ///
    /// Sessions live in daemon memory, so every daemon restart lands here. Until
    /// now the only thing that could mint a new one was the recovery phrase —
    /// the root secret, whose whole job under RFC-0031 is to be the
    /// safety-deposit-box key, handled rarely and ceremonially. Asking for it
    /// several times a day is what puts it in shell history and environment
    /// variables; the first serious attempt to drive this CLI non-interactively
    /// asked for a `KOTTON_RECOVERY_KEY` variable within minutes.
    ///
    /// The daily tier existed already — `set_user_pin` sealed the operational
    /// roots under `Argon2id(PIN)` and `unlock_with_pin` opened them — it was
    /// simply unreachable from the front door. This is that connection.
    ///
    /// **Requires a terminal.** With no cached token and nothing to prompt, this
    /// fails rather than waiting; see the guard below for why.
    pub async fn connect_as(user_id: &str) -> io::Result<Self> {
        let mut client = Self::connect().await?;

        // Try the cached token first.
        if let Some(token) = client.cached_session(user_id) {
            if client.authenticate(&token).await.is_ok() {
                return Ok(client);
            }
            // Token expired — clear stale cache and fall through to a credential.
            client.clear_cached_session(user_id);
        }

        // Ask the daemon which credential to prompt for, rather than reading its
        // files or guessing. Fail-soft: a daemon that cannot answer (an older
        // one, or one that errors) leaves the recovery phrase, which every
        // identity has.
        let pin_available = client
            .get_unlock_methods(user_id)
            .await
            .map(|(pin, _recovery_key)| pin)
            .unwrap_or(false);

        // A prompt only means something at a terminal. Under a script, a test
        // harness, or an agent, `rpassword` reads the console directly and waits
        // on input that will never arrive: the process hangs with no output and
        // no error, and no timeout ever fires. That is the worst failure mode a
        // CLI has — it is indistinguishable from a deadlock in the daemon, and
        // it sent one investigation here looking for a VFS bug that did not
        // exist. Degradation has to stay legible, so say what is wrong and what
        // to do about it.
        if !std::io::stdin().is_terminal() {
            let credential = if pin_available { "PIN" } else { "recovery key" };
            return Err(io::Error::other(format!(
                "no valid session for '{user_id}' and no terminal to ask for the {credential} \
                 — run `kotton login {user_id}` from a terminal first (a daemon restart \
                 invalidates cached sessions)"
            )));
        }

        if pin_available {
            match Self::unlock_by_pin(&mut client, user_id).await? {
                // Fall through to the recovery phrase, which is the honest
                // remedy for both a forgotten PIN and a spent attempt budget:
                // it is the credential the PIN vault is a convenience over, and
                // RFC-0053 keeps it as the floor beneath every other method.
                PinOutcome::FellThrough => {}
                PinOutcome::Unlocked => return Ok(client),
            }
        }

        // The recovery phrase — the root credential, and after this the fallback
        // rather than the front door.
        let key = rpassword::prompt_password(format!("Recovery key for '{user_id}': "))
            .map_err(io::Error::other)?;
        let key = key.trim().to_owned();

        client
            .login_with_recovery_key(&key, Some(user_id.to_string()), None)
            .await
            .map_err(|e| io::Error::other(format!("authentication failed: {e}")))?;

        Ok(client)
    }

    /// Prompt for the PIN, up to [`PIN_PROMPT_ATTEMPTS`] times.
    ///
    /// The retry loop is here rather than in the daemon because a typo should
    /// not cost a whole login: the daemon's budget is the security bound, and
    /// this is only how many times a person is offered the keyboard before being
    /// sent to the phrase.
    async fn unlock_by_pin(client: &mut Self, user_id: &str) -> io::Result<PinOutcome> {
        for attempt in 1..=PIN_PROMPT_ATTEMPTS {
            let pin = rpassword::prompt_password(format!("PIN for '{user_id}': "))
                .map_err(io::Error::other)?;
            let pin = pin.trim().to_owned();

            // An empty PIN is how someone asks for the other door without having
            // to guess wrong five times to get there.
            if pin.is_empty() {
                return Ok(PinOutcome::FellThrough);
            }

            match client.unlock_with_pin(user_id, &pin).await? {
                PinUnlock::Unlocked => return Ok(PinOutcome::Unlocked),
                PinUnlock::Wrong { attempts_remaining } => {
                    eprintln!(
                        "  wrong PIN — {attempts_remaining} attempt(s) before a cooldown"
                    );
                    if attempt == PIN_PROMPT_ATTEMPTS {
                        eprintln!("  falling back to your recovery key");
                    }
                }
                PinUnlock::RateLimited { retry_after_secs } => {
                    eprintln!(
                        "  too many failed attempts — the PIN is refused for {}; \
                         falling back to your recovery key",
                        crate::format_wait(retry_after_secs)
                    );
                    return Ok(PinOutcome::FellThrough);
                }
            }
        }
        Ok(PinOutcome::FellThrough)
    }

    /// Connect to a daemon at an explicit [`IpcEndpoint`].
    ///
    /// Useful for integration tests and development instances running on
    /// non-default sockets.
    #[doc(hidden)]
    pub async fn connect_to(endpoint: IpcEndpoint) -> io::Result<Self> {
        let client = IpcClient::connect(endpoint.clone()).await?;
        Ok(Self {
            client,
            endpoint,
            session_token: None,
            // A caller naming an endpoint is reaching a specific daemon — a
            // test, or a dev instance. Its tokens must not be filed under a
            // cache the default daemon will read.
            caches_sessions: false,
        })
    }

    /// Return a mutable reference to the underlying [`IpcClient`].
    ///
    /// Useful in tests for sending raw `UserRequest` values and inspecting
    /// `UserResponse` variants directly.
    #[doc(hidden)]
    /// Raw protocol access — the request/response enums beneath the typed API.
    ///
    /// **Not part of the supported surface.** Every production call site reaches
    /// the daemon through a typed method; this exists for protocol-level tests
    /// and for bringing a new verb up before it has one. Reaching for it in
    /// application code means a typed method is missing — add that instead, so
    /// the god-enum stays an implementation detail rather than the API
    /// (RFC-0055).
    #[doc(hidden)]
    pub fn inner(&mut self) -> &mut IpcClient<UserRequest, UserResponse> {
        &mut self.client
    }
}
