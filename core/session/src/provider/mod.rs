// SPDX-License-Identifier: AGPL-3.0-or-later
//! HTTP request authentication providers
//!
//! Provides generic implementations of RequestAuthProvider.

mod bearer;

pub use bearer::BearerProvider;

// Re-export platform types for convenience
pub use kotton_sys::session::{
    AuthRequest, RequestAuthError, RequestAuthProvider, RequestAuthResult,
};
