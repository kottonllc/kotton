// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton records` — the project's records, in a root its org owns (RFC-0088, phase one).
//!
//! ```text
//! kotton org create <name>                          # the project's identity
//! kotton records init --org <org_did> [--name N]    # the root, owned by it
//! kotton records invite <contact>    [--root R]     # under org.invite; refused without it
//! kotton records import <dir>        [--root R]     # every record file, by name, idempotent
//! kotton records export <dir>        [--root R]     # every row back, byte for byte
//! ```
//!
//! `--root` falls back to `KOTTON_RECORDS_ROOT`, which `init` prints. Import and export act as
//! the converter's own principal, under the schema grant `init` issues and says it issued, and
//! are refused without it — see [`kotton::records_import`].
//!
//! `invite` names the person as every verb that names a contact does: as `kotton contact list`
//! shows them, or by their AID, resolved by `contact::resolve`, and prints the AID it invited.

use std::io;
use std::path::PathBuf;

use super::contact;
use clap::Subcommand;
use kotton::{records_export, records_import, KottonClient, OrgRootDelegation};
use kotton_record_file::{row::NSID, schema};

#[derive(Subcommand)]
pub enum RecordsCommand {
    /// Create the project's root under an org's identity, with you as its first member and
    /// `org.invite` on it delegated to you; register the record schema; and grant the
    /// converter read and write on it.
    Init {
        /// The org's identity (`did:key:…`), from `kotton org create`.
        #[arg(long)]
        org: String,
        /// The root's name — the project's.
        #[arg(long, default_value = "kotton")]
        name: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Let someone into the project's root, under the `org.invite` you hold on it. Name them
    /// as `kotton contact list` shows them, or by their AID; the AID invited is printed, with
    /// their membership grant, for them to hold.
    Invite {
        /// A contact's name, as `kotton contact list` shows it, or their AID (`did:kel:…`).
        contact: String,
        /// The project's root (defaults to KOTTON_RECORDS_ROOT)
        #[arg(long, env = "KOTTON_RECORDS_ROOT")]
        root: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Read every record file in a directory into the project's root, inserting or replacing
    /// each by its name. A second import of the same files changes nothing.
    Import {
        /// A directory of record files.
        dir: PathBuf,
        /// The project's root (defaults to KOTTON_RECORDS_ROOT)
        #[arg(long, env = "KOTTON_RECORDS_ROOT")]
        root: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Write every row of the project's root back to a directory, one file per record.
    Export {
        /// Where to write the files.
        dir: PathBuf,
        /// The project's root (defaults to KOTTON_RECORDS_ROOT)
        #[arg(long, env = "KOTTON_RECORDS_ROOT")]
        root: String,
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
}

impl RecordsCommand {
    fn user(&self) -> &str {
        match self {
            RecordsCommand::Init { user, .. }
            | RecordsCommand::Invite { user, .. }
            | RecordsCommand::Import { user, .. }
            | RecordsCommand::Export { user, .. } => user,
        }
    }

    pub async fn execute(self) -> io::Result<()> {
        // Every verb here acts as `--user`, and the daemon answers none of them on a connection
        // that has not authenticated as that person: the cached session, or a credential at
        // the terminal, as `connect_as` orders them.
        let mut client = KottonClient::connect_as(self.user()).await?;
        match self {
            RecordsCommand::Init { org, name, user } => {
                client.schema_register(&user, &schema::definition().to_string()).await?;
                let made = client.org_root_create(&user, &org, &name).await?;
                client.schema_grant_set(schema::PRINCIPAL, NSID, true, true, false).await?;
                println!("✓ Root created: {}", made.root);
                println!("  Owner     : {} (the org — not you)", made.owner);
                println!("  Member    : you");
                match made.delegation {
                    OrgRootDelegation::Held { envelope_id } => {
                        println!("  org.invite: delegated to you by the org ({envelope_id})");
                    }
                    OrgRootDelegation::Ceremony {
                        session_id,
                        message_hex,
                        coordinator_id_hex,
                        coordinator_commitment_hex,
                    } => {
                        println!("  org.invite: the org signs by quorum; run on a co-signer's device:");
                        println!(
                            "    kotton org frost sign-contribute {session_id} --org {org} \\\n      \
                             --message-hex {message_hex} --coordinator-id {coordinator_id_hex} \\\n      \
                             --coordinator-commitment {coordinator_commitment_hex}"
                        );
                        println!("  then `kotton org frost sign-finalize` here, and hold the envelope with");
                        println!("    kotton trust add {org} && kotton grant import <envelope.json>");
                    }
                }
                println!(
                    "  Granted   : {} read and write on {NSID} — what `records import` and \
                     `records export` run under",
                    schema::PRINCIPAL
                );
                println!();
                println!("export KOTTON_RECORDS_ROOT={}", made.root);
                Ok(())
            }
            RecordsCommand::Invite { contact, root, user } => {
                // Resolved here, as the messaging verbs resolve a contact: the daemon is handed
                // an AID and decides the rest, and its refusal is passed on as it said it.
                let whom = contact::resolve(&mut client, &user, &contact).await?;
                let (added, grant_json) = client.org_root_invite(&user, &root, &whom.did).await?;
                if added {
                    println!("✓ {whom} is a member of the project's root");
                } else {
                    println!("✓ {whom} was already a member; a fresh grant was issued");
                }
                println!();
                println!("{grant_json}");
                Ok(())
            }
            RecordsCommand::Import { dir, root, user } => {
                let report = records_import(&mut client, &user, &root, &dir).await?;
                println!(
                    "✓ {} inserted, {} replaced, {} unchanged",
                    report.inserted, report.replaced, report.unchanged
                );
                Ok(())
            }
            RecordsCommand::Export { dir, root, user } => {
                let written = records_export(&mut client, &user, &root, &dir).await?;
                println!("✓ {written} records written to {}", dir.display());
                Ok(())
            }
        }
    }
}
