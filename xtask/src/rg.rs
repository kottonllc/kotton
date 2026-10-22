// SPDX-License-Identifier: AGPL-3.0-or-later
//! `rg`: the one way a gate runs ripgrep.
//!
//! `rg`'s exit is three answers, not a success/failure pair: **0** matched, **1** no match,
//! **2** a real error — a root it could not read, a bad pattern — *while still printing the
//! matches it did find*. A gate that reads stdout without the status turns an `rg` that never
//! started into "nothing found", and an `rg` that errored into a partial read nobody can tell
//! from a whole one. `windows-check` and `seam-check` both did, and both exited 0 having
//! searched nothing (`TASK-windows-check-and-seam-check-report-clean-when-rg-cannot-run`).
//!
//! `measure-check` read the three answers correctly, in its own private copy. So the fix is one
//! reader that every gate calls, not a status check added at each site: "no match" is an
//! answer and comes back as one, and "could not search" is an `Err` that names why.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// What a search that ran to the end found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Found {
    /// Exit 0: `rg`'s stdout, whole.
    Matched(String),
    /// Exit 1: it searched everything and matched nothing. An answer, not an error.
    Nothing,
}

/// Run `rg <args>` in `cwd`. `Err` means nothing was measured: `rg` could not start, exited 2,
/// or was killed. Its partial stdout is dropped on purpose — a partial read is not a result.
pub(crate) fn search<I, S>(cwd: &Path, args: I) -> Result<Found, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    search_on(None, cwd, args)
}

/// [`search`], with the child's `PATH` overridden — how the tests reach the "no process" arm
/// without touching this process's environment.
fn search_on<I, S>(path: Option<&OsStr>, cwd: &Path, args: I) -> Result<Found, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new("rg");
    cmd.current_dir(cwd).args(args);
    if let Some(p) = path {
        cmd.env("PATH", p);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("could not start `rg`: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(Found::Matched(
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )),
        Some(1) => Ok(Found::Nothing),
        code => {
            let why = String::from_utf8_lossy(&out.stderr);
            let why = why.trim_end();
            let exit = code.map_or_else(|| "no exit code".to_string(), |c| format!("exit {c}"));
            Err(if why.is_empty() {
                format!("`rg` could not search ({exit})")
            } else {
                format!("`rg` could not search ({exit}):\n{why}")
            })
        }
    }
}

impl Found {
    /// The matched output, or nothing — for a caller that has already refused on `Err`.
    pub(crate) fn stdout(&self) -> &str {
        match self {
            Found::Matched(s) => s,
            Found::Nothing => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn here() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn no_rg_on_path_is_not_an_empty_answer() {
        let r = search_on(Some(OsStr::new("/nonexistent")), here(), ["-l", "-e", "fn"]);
        let e = r.expect_err("an rg that never started came back as an answer");
        assert!(e.contains("could not start"), "{e}");
    }

    #[test]
    fn a_bad_pattern_is_not_an_empty_answer() {
        let e = search(here(), ["-e", "(", "src"]).expect_err("exit 2 read as an answer");
        assert!(e.contains("exit 2"), "{e}");
    }

    /// The partial read: one root that exists, one that does not. `rg` prints the matches in
    /// the first and exits 2, and those matches must not come back as the result.
    #[test]
    fn a_partial_read_is_not_a_result() {
        let e = search(here(), ["-l", "-e", "fn", "src", "no-such-root"])
            .expect_err("a partial read came back as a whole one");
        assert!(e.contains("no-such-root"), "{e}");
    }

    /// Exit 1 is the answer "nothing", and the reason this reader is three-valued.
    #[test]
    fn no_match_is_an_answer() {
        let pat = concat!("NoSuchIdentifier", "AnywhereInXtask");
        assert_eq!(search(here(), ["-l", "-e", pat, "src"]), Ok(Found::Nothing));
    }

    #[test]
    fn a_match_returns_the_output() {
        let r = search(here(), ["-l", "-e", "fn search_on", "src"]).unwrap();
        assert!(r.stdout().contains("rg.rs"), "{r:?}");
    }
}
