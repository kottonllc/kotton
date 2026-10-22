// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

pub struct IssuerCommand;

#[async_trait]
impl Command for IssuerCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;

        match args.first().map(String::as_str) {
            Some("add") => {
                let org_did = match args.get(1) {
                    Some(d) => d.clone(),
                    None => return Ok(CommandOutput::fail("usage: issuer add <org-did>", None)),
                };
                client
                    .trust_add(&user_id, &org_did)
                    .await
                    .map_err(|e| anyhow::anyhow!("issuer add: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "trusted issuer".into(),
                    subject: org_did,
                }]))
            }

            Some("remove") | Some("rm") => {
                let org_did = match args.get(1) {
                    Some(d) => d.clone(),
                    None => return Ok(CommandOutput::fail("usage: issuer remove <org-did>", None)),
                };
                client
                    .trust_remove(&user_id, &org_did)
                    .await
                    .map_err(|e| anyhow::anyhow!("issuer remove: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: "removed issuer".into(),
                    subject: org_did,
                }]))
            }

            Some("list") | None => {
                let dids = client
                    .trust_list(&user_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("issuer list: {e}"))?;
                let rows: Vec<Vec<String>> = dids.into_iter().map(|d| vec![d]).collect();
                Ok(CommandOutput::shapes(vec![Out::Table {
                    columns: vec!["trusted issuer".into()],
                    rows,
                }]))
            }

            Some("help") => Ok(CommandOutput::success_with_output(HELP.to_string())),

            Some(other) => Ok(CommandOutput::fail(
                format!("unknown subcommand '{other}' — try `issuer help`"),
                None,
            )),
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["add", "remove", "list", "help"]
    }

    fn help_text(&self) -> &'static str {
        HELP
    }
}

const HELP: &str = "\
issuer — manage trusted capability-grant issuers

USAGE:
  issuer add <org-did>     trust an org DID to issue capability grants
  issuer remove <org-did>  remove an org DID from the trusted-issuer registry
  issuer list              list all trusted-issuer DIDs";
