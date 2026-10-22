// SPDX-License-Identifier: AGPL-3.0-or-later
mod core;
mod document;
mod error;
mod verification;

pub use core::Did;
pub use document::DidDocument;
pub use error::{DidError, Result};
pub use verification::VerificationMethod;
