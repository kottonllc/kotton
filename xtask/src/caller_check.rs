// SPDX-License-Identifier: AGPL-3.0-or-later
//! `caller-check`: no way to accept a request without being told who sent it.
//!
//! ## Why this exists
//!
//! `ChannelAcceptor` had four `accept*` variants. Three carried the caller's OS
//! identity to the handler; one did not — and the one that did not held most of
//! the call sites, while `accept_authenticated`, which existed *for* the
//! identity, had **zero**. The evidence was plumbed end to end by someone and
//! discarded at every binding site: `kdeviced` bound it as `_peer`, `kuserd`
//! used it once to fill a reported field.
//!
//! Nobody was denied the evidence. It was optional, and an option nobody must
//! take is an option nobody takes.
//!
//! Deleting the opt-out fixed the state. This fixes the tendency — the next
//! `accept` variant added for a good reason cannot quietly omit the caller,
//! because omitting it is what this check looks for.
//!
//! ## What it checks
//!
//! Every `pub async fn accept*` on `ChannelAcceptor` declares a handler bound whose
//! parameter list contains `Caller`. That is a syntactic check on one file, not
//! a claim about semantics: a handler is still free to ignore the argument. The
//! point is that ignoring it has to be written down in the acceptor's own
//! source, where a reviewer sees it, rather than chosen by picking a shorter
//! method name.

use std::path::Path;

const ACCEPTOR: &str = "core/ipc/src/provider/acceptor.rs";

pub fn caller_check() {
    let Ok(src) = std::fs::read_to_string(Path::new(ACCEPTOR)) else {
        eprintln!("caller-check: could not read {ACCEPTOR}. Run from the workspace root.");
        std::process::exit(1);
    };

    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if !t.starts_with("pub async fn accept") {
            continue;
        }
        let name: String = t
            .trim_start_matches("pub async fn ")
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();

        // Scan only this declaration's signature — stop at the body, or at the
        // next item, whichever comes first.
        //
        // Two earlier versions of this got it wrong and a planted violation
        // caught both. A fixed 12-line window bled into the *next* declaration,
        // so an opt-out variant borrowed its neighbour's `Caller`. Breaking on
        // "line ends with `{`" then missed a one-line body (`{ todo!() }`),
        // which ends with `}`. Hence both conditions, and hence planting the
        // violation twice rather than trusting the fix.
        let mut window = String::new();
        for (k, l) in lines[i..].iter().enumerate() {
            let lt = l.trim();
            if k > 0 && (lt.starts_with("pub ") || lt.starts_with("}")) {
                break;
            }
            window.push_str(l);
            window.push('\n');
            if k > 0 && (lt.starts_with('{') || lt.ends_with('{')) {
                break;
            }
        }
        checked += 1;
        if !window.contains("Caller") {
            offenders.push(name);
        }
    }

    if checked == 0 {
        eprintln!(
            "caller-check: found no `pub async fn accept*` in {ACCEPTOR}. Either the API moved \
             or the parser is broken — and a check that inspects nothing reports success."
        );
        std::process::exit(1);
    }

    if offenders.is_empty() {
        println!("caller-check: OK — all {checked} accept variant(s) name their caller.");
        return;
    }

    eprintln!(
        "caller-check: {} accept variant(s) take a handler that is never told who called:\n",
        offenders.len()
    );
    for o in &offenders {
        eprintln!("  {o}");
    }
    eprintln!(
        "\nAn acceptor that does not want the caller should ignore the argument in its own \
         source, where a reviewer sees it. It should not be able to opt out by choosing a \
         method name — that is how `accept_authenticated` ended up with zero call sites."
    );
    std::process::exit(1);
}
