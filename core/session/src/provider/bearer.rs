// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bearer token authentication provider
//!
//! Generic provider for adding Bearer tokens to request headers.
//! Works with any bearer token (JWT, opaque tokens, API tokens, etc.)

use super::{AuthRequest, RequestAuthProvider, RequestAuthResult};
use async_trait::async_trait;

/// Bearer token authentication provider
///
/// Adds a pre-generated token to the Authorization header as "Bearer {token}".
/// Token generation is the responsibility of the caller.
pub struct BearerProvider {
    token: String,
}

impl BearerProvider {
    /// Create a new bearer provider with the given token
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[async_trait]
impl RequestAuthProvider for BearerProvider {
    async fn authenticate_request(&self, request: &mut AuthRequest) -> RequestAuthResult<()> {
        request.headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", self.token),
        );
        Ok(())
    }

    fn provider_name(&self) -> &str {
        "Bearer"
    }

    fn credentials_info(&self) -> Option<String> {
        Some(format!(
            "Token: {}...",
            self.token.chars().take(8).collect::<String>()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bearer_provider() {
        let provider = BearerProvider::new("test-token-123");

        let mut request = AuthRequest::new("GET", "https://api.example.com/data");
        provider.authenticate_request(&mut request).await.unwrap();

        assert_eq!(
            request.get_header("Authorization"),
            Some(&"Bearer test-token-123".to_string())
        );
    }

    #[test]
    fn test_provider_name() {
        let provider = BearerProvider::new("token");
        assert_eq!(provider.provider_name(), "Bearer");
    }
}
