// SPDX-License-Identifier: AGPL-3.0-or-later
//! The vault's own reader of its settings file, `vault.env`: what `kvaultd` takes into
//! its environment before every verb but `serve` (`take_installed_env` in `main.rs`), and
//! through which `create` reads the address it announces.
//!
//! One of three readers of that file — `install-server.sh` and systemd's
//! `EnvironmentFile=` are the others — and it reads exactly the one plain form the
//! installer admits, so the three agree by construction rather than by luck: a line is
//! blank, a comment (`#` or `;` first, after any blanks), or `KEY=value`, `KEY="value"` or
//! `KEY='value'` at the start of the line, one wrapping pair of quotes not part of the
//! value. Anything else is an error naming the line, never trimmed into a setting or kept
//! with its quotes. Held to the other two by
//! `core/kvaultd/tests/the_vault_reads_its_settings_as_the_installer_and_systemd_do.rs`
//! (`TASK-the-vaults-own-reader-of-its-settings-reads-the-plain-form-the-installer-admits`).
//!
//! **One source, compiled twice.** `xtask`'s `release-server-test` reads the env file it
//! installs with this same function, compiled into xtask from this file by `#[path]`
//! (`release_server::env_pairs`) rather than linked, because a dependency on `kvaultd`
//! would build its whole closure into every `cargo xtask`. So this file names nothing but
//! `std` — a `use crate::…` here fails xtask's build, which is the point, and a name both
//! crates link, which no build catches, fails xtask's test of every `#[path]`-shared file
//! (`xtask/src/std_only.rs`, kotton #306) — and its tests find the repository from
//! whichever crate compiles them
//! (`TASK-release-server-tests-reader-of-the-env-file-is-not-the-plain-form`).

/// The file's settings, in order, or why it is not in the plain form: the line, and what
/// is wrong with it. The last assignment of a key wins when they are set in order, as it
/// does for systemd. The checks are the installer's, line for line: no NUL and no carriage
/// return anywhere, no line ending in a backslash, and every line that is not blank or a
/// comment printable ASCII in the plain form.
pub fn env_file_pairs(text: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();
    for (i, line) in text.split(|b| *b == b'\n').enumerate() {
        let n = i + 1;
        if line.contains(&0) {
            return Err(format!("line {n} holds a NUL byte"));
        }
        if line.contains(&b'\r') {
            return Err(format!("line {n} holds a carriage return"));
        }
        if line.ends_with(b"\\") {
            return Err(format!("line {n} ends in a backslash"));
        }
        let first = line.iter().find(|b| **b != b' ' && **b != b'\t');
        match first {
            None | Some(b'#') | Some(b';') => continue,
            Some(_) => {}
        }
        match plain(line) {
            Some((key, value)) => pairs.push((key, value)),
            None => {
                return Err(format!(
                    "line {n} is not in the plain form KEY=value, KEY=\"value\" or KEY='value': `{}`",
                    String::from_utf8_lossy(line)
                ))
            }
        }
    }
    Ok(pairs)
}

/// `KEY=value`, `KEY="value"` or `KEY='value'`: the key a name from column 0, the value
/// printable ASCII holding no quote and no backslash, an unquoted one neither starting nor
/// ending in a space.
fn plain(line: &[u8]) -> Option<(String, String)> {
    if !line.iter().all(|b| (b' '..=b'~').contains(b)) {
        return None;
    }
    let line = std::str::from_utf8(line).ok()?;
    let (key, value) = line.split_once('=')?;
    let mut chars = key.chars();
    let lead = chars.next()?;
    if !(lead.is_ascii_alphabetic() || lead == '_') || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let inner = |s: &str| !s.contains(['"', '\'', '\\']);
    let value = if value.len() >= 2 && ((value.starts_with('"') && value.ends_with('"')) || (value.starts_with('\'') && value.ends_with('\''))) {
        let unwrapped = &value[1..value.len() - 1];
        if !inner(unwrapped) {
            return None;
        }
        unwrapped
    } else {
        if !inner(value) || value.starts_with(' ') || value.ends_with(' ') {
            return None;
        }
        value
    };
    Some((key.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Result<Vec<(String, String)>, String> {
        env_file_pairs(text.as_bytes())
    }

    #[test]
    fn the_plain_form_is_read_and_one_wrapping_pair_of_quotes_is_not_part_of_the_value() {
        assert_eq!(
            read("# a comment\n\n; another\n  # indented\nKVAULTD_IPC_NAME=vault\nKOTTON_PUBLIC_ADDR=\"192.0.2.7\"\nKOTTON_BASE_DIR='/var/lib/elsewhere'\nE=\nQ=\"\"\nS=a b #c\n"),
            Ok(vec![
                ("KVAULTD_IPC_NAME".to_string(), "vault".to_string()),
                ("KOTTON_PUBLIC_ADDR".to_string(), "192.0.2.7".to_string()),
                ("KOTTON_BASE_DIR".to_string(), "/var/lib/elsewhere".to_string()),
                ("E".to_string(), String::new()),
                ("Q".to_string(), String::new()),
                ("S".to_string(), "a b #c".to_string()),
            ])
        );
    }

    #[test]
    fn any_other_line_is_refused_naming_it_and_never_trimmed_into_a_setting() {
        for (text, line) in [
            ("A=1\n  XDG_RUNTIME_DIR=/run/kotton-vault\n", 2),
            ("XDG_RUNTIME_DIR = /run/kotton-vault\n", 1),
            ("A=1 \n", 1),
            ("export A=1\n", 1),
            ("not a setting\n", 1),
            ("A=\"a\" \"b\n", 1),
            ("A=x \"b\n", 1),
            ("A=\"a\\b\"\n", 1),
            ("A=1\\\n", 1),
            ("# c\\\n", 1),
            ("# note\rA=1\n", 1),
            ("A=\u{e9}\n", 1),
            ("A=1\nB=\t2\n", 2),
            ("A=\0\n", 1),
        ] {
            let why = read(text).expect_err(text);
            assert!(why.starts_with(&format!("line {line} ")), "{text:?}: {why}");
        }
        // A comment may hold any byte but a NUL and a carriage return.
        assert_eq!(env_file_pairs(b"# caf\xff\nA=1\n"), Ok(vec![("A".to_string(), "1".to_string())]));
    }

    #[test]
    fn the_shipped_settings_are_in_the_plain_form() {
        // Found above whichever crate compiles this file: `core/kvaultd`, or `xtask`.
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        while !dir.join("infra/vault/vault.env").exists() {
            assert!(dir.pop(), "no infra/vault/vault.env above {}", env!("CARGO_MANIFEST_DIR"));
        }
        let shipped = std::fs::read(dir.join("infra/vault/vault.env")).unwrap();
        let pairs = env_file_pairs(&shipped).unwrap();
        // The file the repository ships names the door the unit makes.
        assert!(pairs.contains(&("KVAULTD_IPC_NAME".to_string(), "vault".to_string())));
        assert!(pairs.contains(&("XDG_RUNTIME_DIR".to_string(), "/run/kotton-vault".to_string())));
    }
}
