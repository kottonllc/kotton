// SPDX-License-Identifier: AGPL-3.0-or-later
pub mod key_method;
pub mod resolver;

pub use key_method::DidKeyMethod;
pub use resolver::{CompositeDidResolver, DidKeyResolver, DidResolver, DidWebResolver};
