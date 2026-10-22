// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `grant` domain — delegated permission, and who is trusted to issue it.
//!
//! A grant is authority one principal hands another, bounded and revocable. Two
//! kinds live here because they answer the same question at different scopes:
//!
//! - **Grant envelopes** (RFC-0073) — signed, cross-DID, verifiable by anyone
//!   holding the issuer's key. The trusted-issuer registry decides whose
//!   signature counts, and the revocation list decides which envelopes stopped
//!   counting.
//! - **Schema grants** (RFC-0003) — a local app's read/write/register access to
//!   one schema, plus the quota that bounds it.
//!
//! They are one domain rather than two because the question is identical —
//! *may this principal do this, on whose say-so, and until when?* — and only the
//! issuer differs: a remote org for the first, this user for the second.
//!
//! **Grant is checked, never assumed.** A permission that reads as granted while
//! enforcing nothing is the failure mode this domain exists to prevent, and it
//! has happened here: a stale envelope once went inert while still presenting as
//! valid. Every read path returns what it actually verified.
pub mod ephemeral;
pub mod daemon;
