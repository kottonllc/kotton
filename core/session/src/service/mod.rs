// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authentication service - Composes authentication providers
//!
//! This service wraps one or more AuthenticationProvider implementations
//! and provides additional business logic:
//! - Rate limiting for authentication attempts
//! - PIN validation rules
//! - Audit logging
//! - Session management
//!
//! The actual authentication logic is delegated to pluggable providers
//! (e.g., KottonAuthProvider, OAuthProvider, etc.)

mod error;
mod pin_validator;
mod rate_limiter;
pub mod tokens;

pub use error::{AuthError, Result};
pub use pin_validator::{PinError, PinValidator};
pub use rate_limiter::{RateLimitError, RateLimiter};

use kotton_sys::session::{AuthenticationProvider, AuthenticationResult, Credentials};
use std::sync::{Arc, Mutex};

/// Authentication service that composes providers and adds business logic
pub struct AuthService {
    /// The authentication provider implementation
    provider: Arc<dyn AuthenticationProvider>,

    /// Rate limiter for failed authentication attempts
    rate_limiter: Mutex<RateLimiter>,

    /// PIN validation rules
    pin_validator: PinValidator,
}

impl AuthService {
    /// Create new auth service with a specific provider
    pub fn new(provider: Arc<dyn AuthenticationProvider>) -> Self {
        Self {
            provider,
            rate_limiter: Mutex::new(RateLimiter::new()),
            pin_validator: PinValidator::new(),
        }
    }

    /// Create new user identity with PIN
    pub async fn create_user(&self, username: &str, pin: &str) -> Result<AuthenticationResult> {
        // Validate PIN meets requirements
        self.pin_validator.validate(pin)?;

        // Check rate limiting
        if !self.rate_limiter.lock().unwrap().allow_attempt(username) {
            return Err(AuthError::RateLimited(username.to_string()));
        }

        // Delegate to provider
        let credentials = Credentials::Pin(pin.to_string());
        let result = self
            .provider
            .create_user(username, &credentials)
            .await
            .inspect_err(|_e| {
                self.rate_limiter.lock().unwrap().record_failure(username);
            })?;

        self.rate_limiter.lock().unwrap().record_success(username);
        Ok(result)
    }

    /// Authenticate user with PIN
    pub async fn authenticate(&self, username: &str, pin: &str) -> Result<AuthenticationResult> {
        // Check rate limiting
        if !self.rate_limiter.lock().unwrap().allow_attempt(username) {
            return Err(AuthError::RateLimited(username.to_string()));
        }

        // Delegate to provider
        let credentials = Credentials::Pin(pin.to_string());
        let result = self
            .provider
            .authenticate(username, &credentials)
            .await
            .inspect_err(|_e| {
                self.rate_limiter.lock().unwrap().record_failure(username);
            })?;

        self.rate_limiter.lock().unwrap().record_success(username);
        Ok(result)
    }

    /// Verify a session token
    pub async fn verify_token(&self, token: &str) -> Result<AuthenticationResult> {
        self.provider
            .verify_token(token)
            .await
            .map_err(AuthError::from)
    }

    /// Check if user exists
    pub async fn user_exists(&self, username: &str) -> bool {
        self.provider.user_exists(username).await
    }

    /// Get provider name for debugging
    pub fn provider_name(&self) -> &str {
        self.provider.provider_name()
    }
}
