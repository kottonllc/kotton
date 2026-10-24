// SPDX-License-Identifier: AGPL-3.0-or-later
//! Secrets provider for managing cryptographic keys
//!
//! This crate provides implementations of SecretsStore trait:
//! - OsSecrets: OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service)
//! - MemorySecrets: In-memory storage for testing

pub mod file;
pub mod memory;
pub mod os;
pub mod sealed_custody;
pub mod secure_enclave_binding;
pub mod tpm_binding;
#[cfg(any(test, feature = "test-utils"))]
pub mod counting_binding;

pub use file::FileSecrets;
pub use os::OsSecrets;
pub use sealed_custody::SealedCustody;
pub use secure_enclave_binding::SecureEnclaveBinding;
pub use tpm_binding::TpmBinding;
#[cfg(any(test, feature = "test-utils"))]
pub use counting_binding::CountingBinding;

/// The device-binding backend for the platform this was built for.
///
/// One name so callers above tier 03 do not carry `cfg` for a decision that is
/// entirely a property of the machine. On a platform with neither backend this
/// resolves to the TPM type, whose non-Windows stub reports unavailable and
/// errors on use — which is the correct behaviour (no binding is possible) with
/// no third type to maintain.
#[cfg(target_os = "macos")]
pub type PlatformBinding = SecureEnclaveBinding;
#[cfg(not(target_os = "macos"))]
pub type PlatformBinding = TpmBinding;

pub use memory::MemorySecrets;

/// The secrets store for a Kotton runtime rooted at `base_dir`.
///
/// A real install gets the OS keychain. A **throwaway root** — a base directory
/// under the system temp dir — gets an in-process store that persists nothing.
///
/// ## Why this rule exists
///
/// `OsSecrets` namespaces by base dir, so a runtime rooted at a temp directory
/// writes entries under a service name unique to that directory. The entries are
/// scoped correctly and are also **permanent**: the temp directory is deleted,
/// the credentials are not. Every spawned test daemon left a handful behind for
/// good, and on 2026-08-17 the Windows credential store reached its ceiling and
/// began refusing writes — which surfaces as a daemon that will not start, with
/// `Windows error code 8`, nowhere near the code that caused it. 250 stale
/// entries were cleared by hand.
///
/// The rule is deliberately **structural rather than a flag**. An env var or a
/// test-harness opt-in is something the next test to spawn a daemon can forget,
/// and this failure is invisible until the store is full — the worst possible
/// combination of "easy to miss" and "hard to diagnose". A root under the system
/// temp dir is not a real install, and treating it as one is what caused this.
///
/// The cost is honest and small: a throwaway-rooted daemon loses its secrets if
/// the *process* restarts. Its data directory is equally throwaway, so there is
/// nothing for those secrets to have unlocked.
///
/// An error when the chosen store is there and cannot be read (a `file`
/// store's `secrets.json` that does not parse): never an empty store, which a
/// caller would mint a new key into ([`FileSecrets::at`]).
pub fn secrets_for_base_dir(
    base_dir: &std::path::Path,
) -> kotton_sys::secret::SecretsResult<std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>> {
    SecretsProvider::for_base_dir(base_dir).open(base_dir)
}

/// Which store [`secrets_for_base_dir`] gives a runtime rooted at a base
/// directory — decided once, by [`Self::for_base_dir`], so a caller that must
/// know (a service's `create`, which keeps a key the start must find) asks the
/// same rule the store is opened by and records the answer rather than
/// deriving it again later from a path's spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsProvider {
    /// An in-process store: a throwaway root. Nothing outlives the process.
    Memory,
    /// `KOTTON_SECRETS=file`: a `0600` file under the base directory's `system/`.
    File,
    /// The OS keychain, scoped to the base directory.
    Keychain,
}

impl SecretsProvider {
    /// The provider for `base_dir`: the rule [`secrets_for_base_dir`] states.
    pub fn for_base_dir(base_dir: &std::path::Path) -> Self {
        if is_throwaway_root(base_dir) {
            Self::Memory
        } else if std::env::var("KOTTON_SECRETS").as_deref() == Ok("file") {
            Self::File
        } else {
            Self::Keychain
        }
    }

    /// Whether what this provider keeps outlives the process.
    pub fn outlives_the_process(self) -> bool {
        self != Self::Memory
    }

    /// Its name, as a record of it is written and read.
    pub fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::File => "file",
            Self::Keychain => "keychain",
        }
    }

    /// The store, for `base_dir`. An error when the store is there and cannot
    /// be read — a `file` store's `secrets.json` that does not parse — rather
    /// than an empty store a caller would mint a key into (see `FileSecrets::at`).
    pub fn open(
        self,
        base_dir: &std::path::Path,
    ) -> kotton_sys::secret::SecretsResult<std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>> {
        Ok(match self {
            Self::Memory => {
                tracing::info!(
                    base_dir = %base_dir.display(),
                    "secrets: throwaway root — using an in-process store, nothing reaches the OS keychain"
                );
                std::sync::Arc::new(MemorySecrets::new())
            }
            // A machine with no keychain — a rented vault, a gateway host, a node in a
            // container — says so explicitly. Never a fallback: see `file.rs`.
            Self::File => {
                tracing::info!(
                    base_dir = %base_dir.display(),
                    "secrets: KOTTON_SECRETS=file — a 0600 file under system/, chosen for a machine with no keychain"
                );
                std::sync::Arc::new(FileSecrets::for_base_dir(base_dir)?)
            }
            Self::Keychain => std::sync::Arc::new(OsSecrets::for_base_dir(base_dir)),
        })
    }
}

/// Whether `base_dir` sits under the system temp directory.
///
/// Normalized on both sides before comparing, because the same directory
/// arrives in several spellings and a mismatch here fails **open** — it silently
/// restores the keychain writes this exists to prevent, with no error anywhere.
/// The spellings that actually bite:
///
/// - `canonicalize` adds Windows' `\\?\` verbatim prefix; `temp_dir()` has no
///   such prefix, so a canonical path never `starts_with` a plain one.
/// - `canonicalize` fails outright on a path that does not exist yet. Falling
///   back to the raw form for that side alone left one side canonical and the
///   other not: on a Windows runner `temp_dir()` is `C:\Users\RUNNER~1\…`, an
///   8.3 short name, which canonicalizes to `C:\Users\runneradmin\…` for the temp
///   side and stays short for a base directory not created yet.
/// - Windows paths are case-insensitive.
///
/// So both sides go through [`resolve`]: the deepest ancestor that exists is
/// canonicalized (which expands short names and adds the verbatim prefix) and the
/// rest of the path is applied to it by its text, `..` included, and then
/// [`spelling`] drops the prefix and, on Windows, the case. Each side is spelled
/// by the same two steps.
///
/// **A base directory with no ancestor that exists is throwaway** (fails closed):
/// not even its root or volume is there, so nothing installed can live under it,
/// an in-process store loses nothing, and the keychain is not written for it. A
/// path through a missing directory and back out with `..` is not that case:
/// `/home/u/missing/../.kotton` names `/home/u/.kotton`, and is spelled as such.
/// The temp directory not resolving says nothing about the base, so it is then
/// compared as spelled.
fn is_throwaway_root(base_dir: &std::path::Path) -> bool {
    let canonical =
        |p: &str| std::fs::canonicalize(p).ok().map(|c| c.to_string_lossy().into_owned());
    let Ok(base) = std::path::absolute(base_dir) else {
        return true;
    };
    throwaway_by(
        &base.to_string_lossy(),
        &std::env::temp_dir().to_string_lossy(),
        cfg!(windows),
        &canonical,
    )
}

/// [`is_throwaway_root`]'s rule over an absolute `base` and the `temp` directory's
/// text, with the filesystem's answer as `canonical`, so a test can hand it a
/// filesystem in which nothing exists.
fn throwaway_by(
    base: &str,
    temp: &str,
    windows: bool,
    canonical: &dyn Fn(&str) -> Option<String>,
) -> bool {
    let Some(base) = resolve(base, windows, canonical) else {
        return true;
    };
    let temp = resolve(temp, windows, canonical).unwrap_or_else(|| temp.to_string());
    is_under(&spelling(&base, windows), &spelling(&temp, windows))
}

/// `path` (absolute) with its deepest ancestor that `canonical` resolves replaced by
/// what it resolves to, and the components below that ancestor applied to it by
/// their text: a name is appended, `.` is nothing, and `..` removes the last name.
/// Lexical is right below that ancestor, because nothing there exists, so nothing
/// there is a link `..` could leave by another way. `None` only when no ancestor
/// resolves, its root included.
///
/// Over the path's text, splitting on `/` and, for Windows, on `\` too, rather than
/// over `Path`: so the Windows walk is the same code on every platform, and is tested
/// as such where `C:\` does not exist.
fn resolve(path: &str, windows: bool, canonical: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let is_separator = |c: char| c == '/' || (windows && c == '\\');
    let joint = if windows { '\\' } else { '/' };
    let mut missing: Vec<&str> = Vec::new();
    let mut at = path;
    let found = loop {
        if let Some(found) = canonical(at) {
            break found;
        }
        let trimmed = at.trim_end_matches(is_separator);
        let cut = trimmed.rfind(is_separator)?;
        missing.push(&trimmed[cut + 1..]);
        // Keep the separator, so the parent of `C:\Users` is the root `C:\` and of
        // `/tmp` is `/`.
        at = &trimmed[..=cut];
    };
    let mut out = found.trim_end_matches(is_separator).to_string();
    let root = root_len(&out, windows);
    for name in missing.iter().rev() {
        match *name {
            "" | "." => {}
            ".." => {
                // Up one name, never into the root (`root_len`).
                if let Some(cut) = out.rfind(is_separator).filter(|cut| *cut >= root) {
                    out.truncate(cut);
                }
            }
            name => {
                out.push(joint);
                out.push_str(name);
            }
        }
    }
    if out.is_empty() {
        out.push(joint);
    }
    Some(out)
}

/// How much of `path` is its root, which `..` never climbs into. Off Windows the root
/// is the leading `/`, which [`resolve`] holds as the empty string, so nothing: a
/// directory named `dir:` there is a name like any other. On Windows: a drive
/// (`C:`), a verbatim drive or volume (`\\?\C:`, `\\?\Volume{…}`), or a share,
/// plain (`\\host\share`) or verbatim (`\\?\UNC\host\share`), so `..` from a share
/// stops at the share and never re-roots onto its host or a drive.
fn root_len(path: &str, windows: bool) -> usize {
    if !windows {
        return 0;
    }
    let is_separator = |c: char| c == '/' || c == '\\';
    // `host\share` at the start of `rest`, as a length: both names, or all there is.
    let share = |rest: &str| match rest.find(is_separator) {
        None => rest.len(),
        Some(i) => i + 1 + rest[i + 1..].find(is_separator).unwrap_or(rest.len() - i - 1),
    };
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        r"\\?\UNC\".len() + share(rest)
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        r"\\?\".len() + rest.find(is_separator).unwrap_or(rest.len())
    } else if let Some(rest) = path.strip_prefix(r"\\") {
        2 + share(rest)
    } else if path.as_bytes().get(1) == Some(&b':') {
        2
    } else {
        0
    }
}

/// One spelling of a resolved path: no `\\?\` verbatim prefix (`\\?\UNC\` back to
/// `\\`), no trailing separator, and on Windows one case and one separator.
fn spelling(path: &str, windows: bool) -> String {
    let s = if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
    };
    let s = if windows { s.replace('/', r"\").to_lowercase() } else { s };
    let trimmed = s.trim_end_matches(['\\', '/']);
    // A root is its separator, not the empty string.
    if trimmed.is_empty() { s[..1.min(s.len())].to_string() } else { trimmed.to_string() }
}

/// `base` is `temp` or below it, at a separator boundary, so `/tmpfoo` is not
/// read as being under `/tmp`.
fn is_under(base: &str, temp: &str) -> bool {
    base == temp
        || base
            .strip_prefix(temp)
            .is_some_and(|rest| rest.starts_with(['\\', '/']))
}

#[cfg(test)]
mod secrets_selection_tests {
    use super::*;

    /// A temp-rooted runtime must not reach the OS keychain. Pinned because the
    /// failure it prevents is invisible until a machine-wide store fills up.
    #[test]
    fn a_temp_root_gets_an_in_process_store() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            is_throwaway_root(dir.path()),
            "a tempfile::tempdir() root must be recognised as throwaway"
        );
    }

    /// And a real install still gets the keychain — the rule must not be so
    /// broad that it disables the OS store generally.
    #[test]
    fn an_ordinary_root_is_not_throwaway() {
        let cwd = std::env::current_dir().unwrap();
        assert!(
            !is_throwaway_root(&cwd),
            "the working directory is a real root, not a throwaway one"
        );
    }

    /// A path that does not exist yet must still be recognised. `canonicalize`
    /// fails on a missing path, and the fallback used to leave the two sides in
    /// different spellings — which fails *open*, quietly restoring keychain
    /// writes. A base dir the daemon has not created yet is the ordinary case.
    #[test]
    fn a_not_yet_created_temp_root_is_still_throwaway() {
        let missing = std::env::temp_dir().join("kotton-does-not-exist-yet-12345");
        assert!(
            !missing.exists(),
            "precondition: the probe path must not exist"
        );
        assert!(
            is_throwaway_root(&missing),
            "a temp path must be recognised before it is created, not only after"
        );
    }

    /// **The Windows runner's spelling, on any platform.** `temp_dir()` there is an
    /// 8.3 short name; canonicalizing expands it and adds the verbatim prefix, and
    /// a base directory not created yet cannot be canonicalized itself. Resolving
    /// its deepest existing ancestor and spelling both sides alike puts the two in
    /// one form. The canonicalizer is a table, so this runs where `C:\` is not.
    #[test]
    fn a_missing_base_under_a_short_named_temp_is_spelled_as_the_temp_is() {
        let long = r"\\?\C:\Users\runneradmin\AppData\Local\Temp";
        let temp = r"C:\Users\RUNNER~1\AppData\Local\Temp";
        let base = r"C:\Users\RUNNER~1\AppData\Local\Temp\kotton-does-not-exist-yet";
        // What the filesystem answers on the runner: the temp dir exists, under its
        // long name; the base below it does not.
        let as_the_runner_canonicalizes = |p: &str| -> Option<String> {
            p.trim_end_matches('\\').eq_ignore_ascii_case(temp).then(|| long.to_string())
        };
        let resolved_base = resolve(base, true, &as_the_runner_canonicalizes).unwrap();
        let resolved_temp = resolve(temp, true, &as_the_runner_canonicalizes).unwrap();
        assert_eq!(resolved_base, format!(r"{long}\kotton-does-not-exist-yet"));
        let (base_s, temp_s) = (spelling(&resolved_base, true), spelling(&resolved_temp, true));
        assert_eq!(temp_s, r"c:\users\runneradmin\appdata\local\temp");
        assert!(is_under(&base_s, &temp_s), "{base_s} is not under {temp_s}");
        // The defect this replaces: the base left as spelled, the temp canonical.
        assert!(!is_under(&spelling(base, true), &temp_s));
        // The verbatim UNC form and a forward slash spell the same as the plain one.
        assert_eq!(spelling(r"\\?\UNC\host\share\Temp\", true), r"\\host\share\temp");
        assert_eq!(spelling(r"C:/Users/X/Temp/", true), r"c:\users\x\temp");
        assert!(!is_under(r"c:\users\x\tempfoo", r"c:\users\x\temp"));
    }

    /// `resolve` itself, through a canonicalizer that renames one existing
    /// directory the way a short name or a symlink is renamed: the missing tail is
    /// kept below the renamed ancestor, and a missing `..` cannot be resolved.
    #[test]
    fn resolve_canonicalizes_the_deepest_existing_ancestor_and_keeps_the_tail() {
        let renamed = |p: &str| -> Option<String> {
            match p {
                "/short~1" | "/short~1/" => Some("/long/name".into()),
                "/" => Some("/".into()),
                _ => None,
            }
        };
        assert_eq!(resolve("/short~1/a/b", false, &renamed).as_deref(), Some("/long/name/a/b"));
        assert_eq!(resolve("/elsewhere/a", false, &renamed).as_deref(), Some("/elsewhere/a"));
        // Through a missing directory and back out: the `..` cancels the missing name,
        // and may climb into the canonical ancestor, never past the root.
        assert_eq!(resolve("/short~1/missing/../a", false, &renamed).as_deref(), Some("/long/name/a"));
        assert_eq!(resolve("/short~1/missing/../../x", false, &renamed).as_deref(), Some("/long/x"));
        assert_eq!(resolve("/missing/../../../x", false, &renamed).as_deref(), Some("/x"));
        assert_eq!(resolve("/short~1/./a/.", false, &renamed).as_deref(), Some("/long/name/a"));
        // Off Windows a name ending in `:` is a name, and `..` leaves it like any other.
        let colon = |p: &str| -> Option<String> {
            matches!(p, "/" | "/x:" | "/x:/").then(|| p.trim_end_matches('/').to_string())
        };
        assert_eq!(resolve("/x:/missing/../../y", false, &colon).as_deref(), Some("/y"));
        // A backslash is a name's character off Windows, not a separator.
        assert_eq!(resolve(r"/short~1/a\b", false, &renamed).as_deref(), Some(r"/long/name/a\b"));
        let nothing = |_: &str| -> Option<String> { None };
        assert_eq!(resolve("/a/b", false, &nothing), None, "nothing resolves, so nothing is claimed");
        assert_eq!(resolve(r"C:\a\b", true, &nothing), None);
    }

    /// On Windows, `..` stops at the root the canonical ancestor has: a share stays a
    /// share (never its host, never a drive), and a drive stays a drive.
    #[test]
    fn dot_dot_never_climbs_out_of_a_windows_root() {
        let share = r"\\?\UNC\host\share";
        let at_share = |p: &str| -> Option<String> {
            (p.trim_end_matches('\\') == share).then(|| share.to_string())
        };
        assert_eq!(
            resolve(r"\\?\UNC\host\share\..\x", true, &at_share).as_deref(),
            Some(r"\\?\UNC\host\share\x")
        );
        assert_eq!(
            resolve(r"\\?\UNC\host\share\missing\..\..\..\x", true, &at_share).as_deref(),
            Some(r"\\?\UNC\host\share\x")
        );
        assert_eq!(spelling(r"\\?\UNC\host\share\x", true), r"\\host\share\x");
        let drive = |p: &str| -> Option<String> {
            (p.trim_end_matches('\\') == "C:").then(|| r"\\?\C:\".to_string())
        };
        assert_eq!(resolve(r"C:\a\..\..\x", true, &drive).as_deref(), Some(r"\\?\C:\x"));
        assert_eq!(root_len(r"\\?\UNC\host\share\x", true), share.len());
        assert_eq!(root_len(r"\\host\share\x", true), r"\\host\share".len());
        assert_eq!(root_len(r"\\?\C:\x", true), r"\\?\C:".len());
        assert_eq!(root_len("C:\\x", true), 2);
        assert_eq!(root_len("/x:/y", false), 0);
    }

    /// **A real install named through a missing directory and `..` is not
    /// throwaway.** `std::path::absolute` keeps `..` on Unix, so
    /// `<existing>/missing/../.kotton` names `<existing>/.kotton`; read as
    /// unresolvable it would be sent to memory and its secrets lost at exit.
    #[test]
    fn a_base_through_a_missing_directory_and_back_names_where_it_lands() {
        let existing = std::env::current_dir().unwrap();
        assert!(!is_throwaway_root(&existing), "precondition: the working directory is a real root");
        let missing = existing.join("kotton-no-such-directory-12345");
        assert!(!missing.exists(), "precondition: the probe directory must not exist");
        let base = missing.join("..").join(".kotton");
        assert!(
            !is_throwaway_root(&base),
            "{} names {} and is not throwaway",
            base.display(),
            existing.join(".kotton").display()
        );
        // And the same walk back out of a missing directory under temp lands under temp.
        let under_temp = std::env::temp_dir().join("kotton-no-such-dir-12345").join("..").join("x");
        assert!(is_throwaway_root(&under_temp), "{} is under the temp dir", under_temp.display());
    }

    /// **Fails closed**: a base none of whose ancestors exists, not even its root,
    /// is throwaway, through the rule [`is_throwaway_root`] applies.
    #[test]
    fn a_base_with_no_ancestor_that_exists_is_throwaway() {
        let nothing = |_: &str| -> Option<String> { None };
        assert!(throwaway_by("/a/b", "/tmp", false, &nothing));
        assert!(throwaway_by(r"Z:\Kotton", r"C:\Temp", true, &nothing));
        // Where the filesystem answers, the same rule tells a real root from a temp one.
        let only_roots = |p: &str| -> Option<String> { (p == "/").then(|| "/".to_string()) };
        assert!(!throwaway_by("/home/u/.kotton", "/tmp", false, &only_roots));
        assert!(throwaway_by("/tmp/k", "/tmp", false, &only_roots));
    }

    /// The boundary is a path separator, so a sibling whose name merely starts
    /// with the temp dir's is not swept in.
    #[test]
    fn a_sibling_sharing_the_prefix_is_not_throwaway() {
        let temp = std::env::temp_dir();
        let sibling = std::path::PathBuf::from(format!(
            "{}-not-actually-temp",
            temp.to_string_lossy().trim_end_matches(['\\', '/'])
        ));
        assert!(
            !is_throwaway_root(&sibling),
            "prefix matching must respect the separator boundary"
        );
    }
}
