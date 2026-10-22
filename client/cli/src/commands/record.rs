// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton record` subcommands — record addressing via `kotton://` URLs.

use clap::Subcommand;
use kotton::KottonClient;
use std::io;

#[derive(Subcommand)]
pub enum RecordCommand {
    /// Open a record by its kotton:// URL and print its JSON body.
    ///
    /// Example:
    ///   kotton record open kotton://records/sh.kotton.notes/019612ab-e3f2-7000-abcd-1234567890ab
    Open {
        /// The full `kotton://records/<nsid>/<id>` URL.
        url: String,
        /// Identity that owns the record (defaults to the active identity / KOTTON_USER)
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
}

impl RecordCommand {
    pub async fn execute(self) -> io::Result<()> {
        match self {
            RecordCommand::Open { url, user } => {
                // The record is `user`'s, read under their keys, so the connection is theirs.
                let mut client = KottonClient::connect_as(&user).await?;
                match client.record_open(&user, &url).await? {
                    Some((nsid, record)) => {
                        println!("nsid: {nsid}");
                        println!("{}", serde_json::to_string_pretty(&record).unwrap());
                    }
                    None => {
                        eprintln!("not found: {url}");
                        std::process::exit(1);
                    }
                }
                Ok(())
            }
        }
    }
}
