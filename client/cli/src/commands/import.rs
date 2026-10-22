// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton import <path>` — bring your history with you.
//!
//! ```text
//! kotton import ~/Downloads/calendar.ics [--user <id>]
//! ```
//!
//! The format comes from the file's extension and is sent as a named choice;
//! the daemon never sniffs it. What travels is the file's **bytes** and its
//! **name** — not its path, which would tell every device the person owns where
//! they keep their downloads, and would make the daemon open a file on the
//! caller's say-so.
//!
//! `TASK-a-person-brings-their-history-with-them`. `.ics` today; `.vcf`, a
//! message export and a folder of photos are the rest of that record.

use std::io;
use std::path::PathBuf;

use clap::Args;
use kotton::{ImportFormat, KottonClient};

/// The largest export this can hand to the daemon in one IPC frame.
///
/// `MAX_FRAME_LEN` in `core/ipc` is 32 MiB and the connection is *closed* when a
/// frame exceeds it — so a large export would fail as a dropped connection with
/// nothing saying why. Byte arrays cost roughly four bytes of JSON each, hence
/// the quarter. Refusing here, by name, is the difference between a bug report
/// and a sentence the person can act on.
const MAX_EXPORT_BYTES: u64 = 6 * 1024 * 1024;

#[derive(Args)]
pub struct ImportCommand {
    /// The export to read: a `.ics` calendar file.
    pub path: PathBuf,
    /// Identity to import into (defaults to the active identity / KOTTON_USER)
    #[arg(long, env = "KOTTON_USER")]
    pub user: String,
}

impl ImportCommand {
    pub async fn execute(self) -> io::Result<()> {
        let format = format_of(&self.path)?;

        let size = std::fs::metadata(&self.path)?.len();
        if size > MAX_EXPORT_BYTES {
            return Err(io::Error::other(format!(
                "{} is {size} bytes; the import channel carries at most {MAX_EXPORT_BYTES}. \
                 Split the export and import the parts.",
                self.path.display(),
            )));
        }
        let content = std::fs::read(&self.path)?;

        // Provenance, not a path (see the module doc).
        let source_name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "import".to_owned());

        let mut client = KottonClient::connect_as(&self.user).await?;
        let (schema_nsid, imported, skipped) = client
            .import(&self.user, format, &source_name, content)
            .await?;

        println!("imported {imported} item(s) from {source_name} as {schema_nsid}");
        if skipped > 0 {
            // Never folded into the total: the person is the only one who can
            // say whether the ones that did not make it mattered.
            println!("{skipped} item(s) skipped — the export had no usable start time for them");
        }
        Ok(())
    }
}

/// Choose the reader from the file's extension.
///
/// An unknown extension is refused rather than guessed at: guessing decides what
/// the bytes *mean*, and a wrong guess files a person's history under the wrong
/// shape without saying so.
fn format_of(path: &std::path::Path) -> io::Result<ImportFormat> {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "ics" | "ical" | "ifb" | "icalendar" => Ok(ImportFormat::Ics),
        "" => Err(io::Error::other(format!(
            "{} has no extension, so there is nothing to say what it is. \
             Supported today: .ics",
            path.display(),
        ))),
        other => Err(io::Error::other(format!(
            "no reader for '.{other}' yet. Supported today: .ics",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_extension_picks_the_reader() {
        assert_eq!(
            format_of(std::path::Path::new("/tmp/cal.ics")).unwrap(),
            ImportFormat::Ics
        );
        assert_eq!(
            format_of(std::path::Path::new("/tmp/CAL.ICS")).unwrap(),
            ImportFormat::Ics
        );
    }

    /// The formats the rest of `TASK-a-person-brings-their-history-with-them`
    /// will add are refused by name today, not silently read as a calendar.
    #[test]
    fn an_unread_format_says_so() {
        for name in ["contacts.vcf", "photo.jpg", "notes"] {
            assert!(
                format_of(std::path::Path::new(name)).is_err(),
                "{name} should be refused until there is a reader for it"
            );
        }
    }
}
