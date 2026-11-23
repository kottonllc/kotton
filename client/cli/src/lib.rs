// SPDX-License-Identifier: AGPL-3.0-or-later
use clap::Parser;

pub mod active_identity;
pub mod bridge;
pub mod commands;
/// The shell the doors share, for the tools that read its registry (`cargo xtask-docs verb-check`).
pub use kotton_shell as shell;
use commands::Commands;

/// How every binary in this crate ends: a failure is said as its message, alone,
/// on one line of stderr, and the process exits 1.
///
/// A refusal the daemon writes is written for a person, so it reaches them as it
/// was written — not behind an `Error:` prefix, and not in the debug form a `main`
/// returning `io::Result` prints. The exit code is what tells a script it failed.
/// One function for every `main`, so no subcommand needs to know any of this.
/// Clap's own usage errors exit before this is reached, with clap's code, 2.
pub fn finish(result: std::io::Result<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// How a name is printed in what `kotton` says, what `--json` carries for it, and how a
/// printed command is typed at the REPL and at a terminal's own shell: the
/// top-level command's long help (`kotton --help`, not `-h`), which the CLI reference
/// renders at the top of `kotton`'s own section. It holds the decision on which
/// characters the quoted print's rule names (`kotton_wire::note::quoted`). Each
/// paragraph is one line, as clap prints a paragraph and Markdown reads one.
const NAMES_AS_PRINTED: &str = "\
With `--json`, a name in a table or a record is carried as stored, where styled text prints it \
with each character shown, one that would not be seen or would change the line by its escape. \
A note's sentence is carried as a person reads it, its names printed so.

In a sentence a name is printed between backticks, so a person reading it can tell where the \
name ends. Between them the delimiter and each character drawn as it (U+02CB, U+02F4, U+1FEF, \
U+2035, U+FF40) are printed by their escape, the backtick as `\\u{60}`, and so are the two grave \
marks U+0300 and U+0340 where what they are drawn on is a space; every other character is \
printed as a table prints it. A table's cell, a listing and `--json` print or carry a name as \
before. The list is by name, as no table of Unicode's says what a character is drawn as, and it \
may grow. What it costs falls by script, and in sentences alone: a reader of Bopomofo sees its \
fourth tone mark (U+02CB, also the tone letter of some romanisations) by its escape, a reader of \
phonetic transcription U+02F4, a reader of polytonic Greek the spacing varia (U+1FEF, which \
composed text holds as the backtick itself), a reader of mathematics the reversed prime \
(U+2035), a reader of fullwidth text its grave (U+FF40), and any reader a grave mark standing \
alone after a space. A letter with a grave written as two characters is printed as it is, and so \
are quotes, apostrophes, acutes and the other primes (U+2032).

A note's sentence gives a command to type only with a name that is one plain word, in ASCII. \
That is a concession. A device, vault or relay named in another script is stored, listed, shown \
in full and taken by its verb whole; what it costs is the line to copy: its note gives the DID \
as stored to copy, or the verb and the name with no line. It is made because a printed command \
must reach its row typed as printed, and names are compared byte for byte: a name a vault or a \
relay is minted under is in composed form (NFC), but a device's label and a DID are in no normal \
form, and none is applied where a typed name is compared. The seam: once a normal form is \
applied where a name is stored and where it is compared, the set of plain words widens, and no \
store or message changes for it.

A command a readout prints, as `peer show` prints the `peer add` line, is a line the REPL takes \
as printed. Typed after `kotton` at a terminal it is read first by that shell, which hands the \
verb its words. An address is printed as `<ip>:<port>`, and an IPv6 one in brackets, as \
`[2001:db8::7]:7710`; a POSIX shell reads an unquoted word in brackets as a pattern, so there a \
word that holds an IPv6 address in brackets is put in quotes, `'[2001:db8::7]:7710'`, and so is \
a line that holds one, as a vault's line given to `enrol`. In quotes the shell hands the word on \
as typed.";

/// Top-level CLI entry point — re-exported so `xtask gen-docs` can walk the
/// command tree without duplicating the parser definition.
#[derive(Parser)]
#[command(name = "Kotton")]
#[command(about = "Kotton - Your data sovereignty platform", version = kotton_version::VERSION)]
#[command(after_long_help = NAMES_AS_PRINTED)]
pub struct Cli {
    /// Machine-readable output: print shapes as JSON instead of styled text. Put it
    /// before the verb (`kotton --json issuer list`). Only the shared verbs that
    /// emit shapes honor it. A verb that reads `--json` among its own words (`drive`,
    /// `pin`) is handed the word instead, so `kotton --json drive list` is
    /// `kotton drive list --json`, as the REPL's `drive list --json` is. There it is for
    /// `list` and `show` alone, and any other verb refuses it, exit 2 (`kotton --json
    /// drive create …`, `kotton --json pin <drive> whole`).
    ///
    /// What it carries for a name, and how a name inside a sentence is printed, is said
    /// in `kotton`'s own help text (`kotton --help`).
    #[arg(long)]
    pub json: bool,
    /// No subcommand → enter the runtime (identity-first). The front door is the
    /// REPL, not a wall of help: bare `kotton` drops you in as your active identity
    /// (or onboards you), exactly like `kotton repl`. Verbs remain for scripting.
    #[command(subcommand)]
    pub command: Option<Commands>,
}
