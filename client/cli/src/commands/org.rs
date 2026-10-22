// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton org` — org identity sub-commands.
//!
//! ```text
//! kotton org new <name>   (or: kotton org create <name>)       [--user <id>]
//! kotton org show <org_did>                                      [--user <id>]
//! kotton org list                                                [--user <id>]
//! kotton org grant issue --org <did> --to <did> --caps <cap...>
//!                        [--ttl <secs>] [--node <did>]          [--user <id>]
//! kotton org grant list --org <did>                             [--user <id>]
//! kotton org member remove --org <did> <member_did>             [--user <id>]
//! kotton org frost new <name> --threshold <t> --total <n>       [--user <id>]
//! kotton org frost join <name> --org-did <did> --share <hex>    [--user <id>]
//! kotton org frost sign-contribute/sign-finalize ...
//! ```

use clap::Subcommand;
use kotton::{org_grant_issue_full, OrgGrantIssueResult, KottonClient};
use std::io;

use super::frost_org::FrostOrgCommand;

#[derive(Subcommand)]
pub enum OrgCommand {
    /// Create a new single-key org identity. `create` names the same verb.
    #[command(alias = "create")]
    New {
        /// Human-readable name for the org.
        name: String,
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
    /// Show metadata for an org DID.
    Show {
        /// The org DID (`did:key:…`).
        org_did: String,
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
    /// List all org identities owned by the user.
    List {
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
    /// Grant management for an org.
    #[command(subcommand)]
    Grant(OrgGrantCommand),
    /// Member management for an org.
    #[command(subcommand)]
    Member(OrgMemberCommand),
    /// FROST multi-sig key management and signing ceremonies.
    #[command(subcommand)]
    Frost(FrostOrgCommand),
}

#[derive(Subcommand)]
pub enum OrgGrantCommand {
    /// Issue a GrantEnvelope from an org DID to a member DID.
    ///
    /// Prints the envelope JSON to stdout so you can share it out-of-band.
    Issue {
        /// The org DID (`did:key:…`) that issues the grant.
        #[arg(long)]
        org: String,
        /// The member DID (`did:key:…`) that receives the grant.
        #[arg(long)]
        to: String,
        /// Capabilities to grant, e.g. `schema.read:sh.kotton.notes`.
        /// Repeat for multiple capabilities.
        #[arg(long = "cap", required = true)]
        caps: Vec<String>,
        /// Optional time-to-live in seconds.
        #[arg(long)]
        ttl: Option<i64>,
        /// Optional node DID to restrict scope to a specific node.
        #[arg(long)]
        node: Option<String>,
        /// User ID who owns the org key.
        #[arg(long)]
        user: String,
    },
    /// List all grants issued by an org.
    List {
        /// The org DID (`did:key:…`).
        #[arg(long)]
        org: String,
        /// User ID to act on behalf of.
        #[arg(long)]
        user: String,
    },
}

#[derive(Subcommand)]
pub enum OrgMemberCommand {
    /// Revoke all grants issued to a member DID and remove them from the org.
    Remove {
        /// The org DID (`did:key:…`).
        #[arg(long)]
        org: String,
        /// The member DID (`did:key:…`) to remove.
        member_did: String,
        /// User ID who owns the org key.
        #[arg(long)]
        user: String,
    },
}

impl OrgCommand {
    fn user(&self) -> &str {
        match self {
            OrgCommand::New { user, .. }
            | OrgCommand::Show { user, .. }
            | OrgCommand::List { user } => user,
            OrgCommand::Grant(c) => c.user(),
            OrgCommand::Member(c) => c.user(),
            OrgCommand::Frost(c) => c.user(),
        }
    }

    pub async fn execute(&self) -> io::Result<()> {
        // Every verb acts as `--user`, whose sealed store holds the org's key, and the daemon
        // answers none of them on a connection that has not authenticated as that person.
        let mut client = KottonClient::connect_as(self.user()).await?;

        match self {
            OrgCommand::New { name, user } => {
                let org_did = client.org_new(user, name).await?;
                println!("✓ Org created");
                println!("  DID  : {org_did}");
                println!("  Name : {name}");
                Ok(())
            }

            OrgCommand::Show { org_did, user } => {
                let (did, name, owner, created_at) = client.org_show(user, org_did).await?;
                println!("DID        : {did}");
                println!("Name       : {name}");
                println!("Owner      : {owner}");
                println!("Created at : {created_at}");
                Ok(())
            }

            OrgCommand::List { user } => {
                let orgs = client.org_list(user).await?;
                if orgs.is_empty() {
                    println!("(no orgs)");
                } else {
                    for o in &orgs {
                        println!("{:48}  {}", o.org_did, o.name);
                    }
                }
                Ok(())
            }

            OrgCommand::Grant(grant_cmd) => grant_cmd.execute(&mut client).await,
            OrgCommand::Member(member_cmd) => member_cmd.execute(&mut client).await,
            OrgCommand::Frost(frost_cmd) => frost_cmd.execute(&mut client).await,
        }
    }
}

impl OrgGrantCommand {
    fn user(&self) -> &str {
        match self {
            OrgGrantCommand::Issue { user, .. } | OrgGrantCommand::List { user, .. } => user,
        }
    }

    async fn execute(&self, client: &mut KottonClient) -> io::Result<()> {
        match self {
            OrgGrantCommand::Issue {
                org,
                to,
                caps,
                ttl,
                node,
                user,
            } => {
                let result = org_grant_issue_full(
                    client,
                    user,
                    org,
                    to,
                    caps.clone(),
                    *ttl,
                    node.clone(),
                )
                .await?;
                match result {
                    OrgGrantIssueResult::Issued {
                        envelope_id,
                        envelope_json,
                    } => {
                        println!("✓ Grant issued: {envelope_id}");
                        println!();
                        println!("{envelope_json}");
                    }
                    OrgGrantIssueResult::FrostSession {
                        session_id,
                        message_hex,
                        coordinator_id_hex,
                        coordinator_commitment_hex,
                    } => {
                        println!("FROST signing session initiated (needs ≥1-of-n co-signers).");
                        println!("  Session ID : {session_id}");
                        println!();
                        println!("Run on a co-signer's device:");
                        println!(
                            "  kotton org frost sign-contribute {session_id} \\\n    \
                             --org {org} \\\n    \
                             --message-hex {message_hex} \\\n    \
                             --coordinator-id {coordinator_id_hex} \\\n    \
                             --coordinator-commitment {coordinator_commitment_hex}"
                        );
                        println!();
                        println!("Then paste the co-signer output into:");
                        println!(
                            "  kotton org frost sign-finalize {session_id} \\\n    \
                             --cosigner-id <id> \\\n    \
                             --cosigner-commitment <commitment> \\\n    \
                             --cosigner-share <share>"
                        );
                    }
                }
                Ok(())
            }

            OrgGrantCommand::List { org, user } => {
                let grants = client.org_grant_list(user, org).await?;
                if grants.is_empty() {
                    println!("(no grants)");
                } else {
                    for g in &grants {
                        println!(
                            "{:48}  member={}  issued_at={}",
                            g.envelope_id, g.member_did, g.issued_at
                        );
                    }
                }
                Ok(())
            }
        }
    }
}

impl OrgMemberCommand {
    fn user(&self) -> &str {
        match self {
            OrgMemberCommand::Remove { user, .. } => user,
        }
    }

    async fn execute(&self, client: &mut KottonClient) -> io::Result<()> {
        match self {
            OrgMemberCommand::Remove {
                org,
                member_did,
                user,
            } => {
                let revoked = client.org_member_remove(user, org, member_did).await?;
                println!("✓ Member removed: {member_did}");
                println!("  Revoked {revoked} envelope(s)");
                Ok(())
            }
        }
    }
}
