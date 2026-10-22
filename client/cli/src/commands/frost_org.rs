// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton org frost` — FROST multi-sig org sub-commands.
//!
//! ```text
//! kotton org frost new <name> --threshold <t> --total <n>  [--user <id>]
//! kotton org frost join <name> --org-did <did> --share <hex> --index <n>
//!                                                           [--user <id>]
//! kotton org frost sign-contribute <session-id>
//!     --org <did> --message-hex <hex>
//!     --coordinator-id <hex> --coordinator-commitment <hex> [--user <id>]
//! kotton org frost sign-finalize <session-id>
//!     --cosigner-id <hex> --cosigner-commitment <hex>
//!     --cosigner-share <hex>                               [--user <id>]
//! ```
//!
//! ## Phase A note
//!
//! These commands use manual blob exchange (copy-paste) instead of the peer
//! transport.  Each command prints the exact arguments to pass to the next
//! command so the copy-paste is as frictionless as possible.

use clap::Subcommand;
use kotton::KottonClient;
use std::io;

#[derive(Subcommand)]
pub enum FrostOrgCommand {
    /// Create a new FROST multi-sig org (trusted-dealer key generation).
    ///
    /// The initiator generates all key shares. Shares for other participants
    /// are printed and must be sent to each participant over a secure channel.
    /// Each participant imports their share with `kotton org frost join`.
    New {
        /// Human-readable org name.
        name: String,
        /// Minimum co-signers required for a valid signature (t in t-of-n).
        #[arg(long)]
        threshold: u16,
        /// Total number of participants (n in t-of-n).
        #[arg(long)]
        total: u16,
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
    /// Join a FROST org by importing the key share sent by the initiator.
    Join {
        /// Human-readable org name (used locally for display).
        name: String,
        /// Org DID (`did:key:…`) as printed by `kotton org frost new`.
        #[arg(long)]
        org_did: String,
        /// Key share blob (hex) assigned to this participant by the initiator.
        #[arg(long)]
        share: String,
        /// Participant index assigned to this share (printed by the initiator).
        #[arg(long)]
        index: u16,
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
    /// Co-signer: contribute to an in-progress signing ceremony.
    ///
    /// Run this on the co-signer's device.  The coordinator starts the ceremony
    /// with `kotton org grant issue --org <name>` and shares the session ID,
    /// message, and their commitment.  This command prints the arguments to
    /// paste back to the coordinator's `sign-finalize` command.
    SignContribute {
        /// Session ID printed by `kotton org grant issue` on the coordinator.
        session_id: String,
        /// Org DID (`did:key:…`).
        #[arg(long)]
        org: String,
        /// Message bytes to sign (hex), as printed by the coordinator.
        #[arg(long)]
        message_hex: String,
        /// Coordinator's FROST Identifier (hex), as printed by the coordinator.
        #[arg(long)]
        coordinator_id: String,
        /// Coordinator's round-1 commitment (hex), as printed by the coordinator.
        #[arg(long)]
        coordinator_commitment: String,
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
    /// Coordinator: finalize the signing ceremony and issue the GrantEnvelope.
    ///
    /// Paste the three values printed by the co-signer's `sign-contribute` here.
    SignFinalize {
        /// Session ID from `kotton org grant issue`.
        session_id: String,
        /// Co-signer's FROST Identifier (hex), as printed by `sign-contribute`.
        #[arg(long)]
        cosigner_id: String,
        /// Co-signer's round-1 commitment (hex), as printed by `sign-contribute`.
        #[arg(long)]
        cosigner_commitment: String,
        /// Co-signer's signature share (hex), as printed by `sign-contribute`.
        #[arg(long)]
        cosigner_share: String,
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
}

impl FrostOrgCommand {
    /// The person every verb here acts as; `kotton org` opens its connection as them.
    pub(super) fn user(&self) -> &str {
        match self {
            FrostOrgCommand::New { user, .. }
            | FrostOrgCommand::Join { user, .. }
            | FrostOrgCommand::SignContribute { user, .. }
            | FrostOrgCommand::SignFinalize { user, .. } => user,
        }
    }

    pub async fn execute(&self, client: &mut KottonClient) -> io::Result<()> {
        match self {
            FrostOrgCommand::New {
                name,
                threshold,
                total,
                user,
            } => {
                let (org_did, shares) =
                    client.org_frost_new(user, name, *threshold, *total).await?;

                println!("✓ FROST org created");
                println!("  Name      : {name}");
                println!("  DID       : {org_did}");
                println!("  Threshold : {threshold}-of-{total}");
                println!();
                println!("Key shares for other participants (send each securely):");
                println!();
                for (idx, share_hex) in &shares {
                    println!("  ── Participant {idx} ──────────────────────────────────");
                    println!("  Run on participant {idx}'s device:");
                    println!(
                        "    kotton org frost join {name:?} \\\n      \
                         --org-did {org_did} \\\n      \
                         --share {share_hex} \\\n      \
                         --index {idx}"
                    );
                    println!();
                }
                println!("Participant 1 (you) is already set up on this device.");
                Ok(())
            }

            FrostOrgCommand::Join {
                name,
                org_did,
                share,
                index,
                user,
            } => {
                let joined_did = client
                    .org_frost_join(user, name, org_did, share, *index)
                    .await?;
                println!("✓ Joined FROST org");
                println!("  Name : {name}");
                println!("  DID  : {joined_did}");
                println!("  Your participant index: {index}");
                Ok(())
            }

            FrostOrgCommand::SignContribute {
                session_id,
                org,
                message_hex,
                coordinator_id,
                coordinator_commitment,
                user,
            } => {
                let (cosigner_id, cosigner_commitment, cosigner_share) = client
                    .org_frost_sign_contribute(
                        user,
                        session_id,
                        org,
                        message_hex,
                        coordinator_id,
                        coordinator_commitment,
                    )
                    .await?;

                println!("✓ Contribution generated. Paste to coordinator:");
                println!();
                println!(
                    "  kotton org frost sign-finalize {session_id} \\\n    \
                     --cosigner-id {cosigner_id} \\\n    \
                     --cosigner-commitment {cosigner_commitment} \\\n    \
                     --cosigner-share {cosigner_share}"
                );
                Ok(())
            }

            FrostOrgCommand::SignFinalize {
                session_id,
                cosigner_id,
                cosigner_commitment,
                cosigner_share,
                user,
            } => {
                let (envelope_id, envelope_json) = client
                    .org_frost_sign_finalize(
                        user,
                        session_id,
                        cosigner_id,
                        cosigner_commitment,
                        cosigner_share,
                    )
                    .await?;
                println!("✓ FROST grant issued: {envelope_id}");
                println!();
                println!("{envelope_json}");
                Ok(())
            }
        }
    }
}
