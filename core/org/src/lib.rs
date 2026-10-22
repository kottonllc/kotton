// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `org` domain — shared authority: a household, a team, a company.
//!
//! An org holds a signing key that no single device holds alone. A plain org has
//! one key; a FROST org splits it `threshold`-of-`total` across holders, so
//! acting as the org needs a quorum rather than a device.
//!
//! Both issue the same grant envelopes. The difference is how a signature is
//! produced, not what authority means — which is why they are one domain rather
//! than two (RFC-0054).

/// Node enrollment — the security gate on the FROST accept side.
///
/// Moved here from `05_runtime` (RFC-0060). It verifies a received FROST key
/// share and the quorum-signed delegation binding it to this device, which is
/// FROST material, and FROST lives here. `peer` calls into it during a pairing
/// ceremony; the ceremony is peer business and the share is org business.
pub mod daemon;
pub mod enrollment;
pub mod frost_signing;
