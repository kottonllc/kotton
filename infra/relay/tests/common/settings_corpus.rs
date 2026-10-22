// SPDX-License-Identifier: AGPL-3.0-or-later
//! The settings files every reader of a host's settings is held to: the fixed forms the
//! installer refuses and accepts, the seeded generator, the call into systemd's own
//! `load_env_file`, and the installer's own verdict and reading taken from
//! `install-server.sh` itself (`TASK-the-installer-tells-the-relay-the-address-it-announces`),
//! and where systemd's parser is found or its absence is refused (`systemds_parser.rs`).
//! Shared by the relay's install tests and the vault's, which add `kvaultd`'s own reader
//! as a third column; included by `#[path]`, so it is not a test target of its own.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Command, Output};

/// The checkout's root, found from whichever crate includes this.
pub fn repo() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !dir.join("infra/release/install-server.sh").exists() {
        assert!(dir.pop(), "no infra/release/install-server.sh above {}", env!("CARGO_MANIFEST_DIR"));
    }
    dir
}

/// The relay's settings as the archive ships them.
pub fn shipped() -> String {
    std::fs::read_to_string(repo().join("infra/relay/relay.env")).unwrap()
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `text` with its one `from` replaced by `to`, as bytes: a kept file need not be UTF-8.
pub fn replaced(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = text.windows(from.len()).position(|w| w == from).expect("the shipped settings hold the line replaced");
    [&text[..at], to, &text[at + from.len()..]].concat()
}

/// The line in a form-test case's insertion that the refusal names is its last, unless
/// the case names another.
pub const LAST: &[u8] = b"";

/// The kept files the installer must refuse: the shipped settings with one `from` line
/// replaced by `to`, and the line of `to` the refusal names.
pub fn refused_forms() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
    vec![
        ("KOTTON_RELAY_ADVERTISE=\n", b"  KOTTON_RELAY_ADVERTISE=http://kept.example:7700\n" as &[u8], LAST),
        ("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE = http://kept.example:7700\n" as &[u8], LAST),
        ("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=http://kept.example:7700 \n" as &[u8], LAST),
        ("KOTTON_RELAY_ADVERTISE=\n", b"export KOTTON_RELAY_ADVERTISE=http://kept.example:7700\n" as &[u8], LAST),
        ("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=http://kept.example:7700\\\n" as &[u8], LAST),
        // A line naming nothing it reads, continued onto one that does.
        ("KOTTON_RELAY_TTL=60\n", b"KOTTON_RELAY_TTL=60\\\nKOTTON_RELAY_STATE_DIR=/var/lib/elsewhere\n" as &[u8], b"KOTTON_RELAY_TTL=60\\" as &[u8]),
        ("KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n", b"\tKOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n" as &[u8], LAST),
        ("KOTTON_RELAY_BIND=0.0.0.0:7700\n", b"KOTTON_RELAY_BIND= 0.0.0.0:7800\n" as &[u8], LAST),
        // A comment continued onto the line that sets it: systemd before v254 reads the
        // line as part of the comment, so the state would be made where the relay never looks.
        ("KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n", b"# kept here \\\nKOTTON_RELAY_STATE_DIR=/var/lib/elsewhere\n" as &[u8], b"# kept here \\" as &[u8]),
        // A backslash inside quotes, which systemd reads as an escape.
        ("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=\"http://kept.example\\:7700\"\n" as &[u8], LAST),
        ("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE='http://kept.example\\:7700'\n" as &[u8], LAST),
        // A byte outside printable ASCII: systemd ignores an assignment whose value is not
        // UTF-8, so the installer would read it set where the unit reads it unset — and
        // after a valid line, the installer the invalid one and systemd the valid one.
        ("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=http://kept.example\xff:7700\n" as &[u8], LAST),
        ("KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n", b"KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\nKOTTON_RELAY_STATE_DIR=/var/lib/\xffelsewhere\n" as &[u8], LAST),
        // A NUL, where systemd's parser stops and a shell drops it.
        ("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=http://kept.example\x00:7700\n" as &[u8], LAST),
        // A NUL on a line naming nothing read, and one in a comment: systemd's parser walks
        // the file as a C string and stops at the first NUL, so every later setting is
        // hidden from it while the installer reads on. Refused for the whole file, at the
        // first line holding one.
        ("KOTTON_RELAY_TTL=60\n", b"KOTTON_RELAY_TTL=6\x000\n" as &[u8], LAST),
        ("# Seconds a stored address entry lives.\n", b"# Seconds a stored\x00 address entry lives.\n" as &[u8], LAST),
        // A quote opened on a line and not closed on it, on any line, naming a value read
        // or not: systemd runs a quoted value across newlines, so the lines it spans are
        // part of that value and set nothing — closed later, or never, to the end.
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE=\"multi\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\nend\"\n" as &[u8], b"NOTE=\"multi" as &[u8]),
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE='multi\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\nend'\n" as &[u8], b"NOTE='multi" as &[u8]),
        ("KOTTON_RELAY_TTL=60\n", b"KOTTON_RELAY_TTL=\"60\n" as &[u8], LAST),
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE=\"ends in an escaped quote\\\"\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\n\"\n" as &[u8], b"NOTE=\"ends in an escaped quote\\\"" as &[u8]),
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE = \"spaced\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\n\"\n" as &[u8], b"NOTE = \"spaced" as &[u8]),
        // Invalid UTF-8 on a line naming nothing read: systemd's load_env_file, which
        // EnvironmentFile= calls, fails the whole file with EINVAL (checked against
        // libsystemd-shared 255), so the unit would not start on settings the installer took.
        ("KOTTON_RELAY_TTL=60\n", b"NOTE=\xff\nKOTTON_RELAY_TTL=60\n" as &[u8], b"NOTE=\xff" as &[u8]),
        // A quote after a closing quote: systemd opens a second quoted run, which crosses
        // newlines like the first, so the address after it is part of NOTE.
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE=\"a\" \"b\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\nend\"\n" as &[u8], b"NOTE=\"a\" \"b" as &[u8]),
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE='a' 'b\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\nend'\n" as &[u8], b"NOTE='a' 'b" as &[u8]),
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE=\"a\"'b\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\nend'\n" as &[u8], b"NOTE=\"a\"'b" as &[u8]),
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE=\"a\"\"b\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\nend\"\n" as &[u8], b"NOTE=\"a\"\"b" as &[u8]),
        // A quote inside an unquoted value: systemd reads it literally, and it is refused
        // anyway — a value holds quotes only as one pair around all of it.
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE=x \"b\nKOTTON_RELAY_ADVERTISE=http://kept.example:7700\n" as &[u8], b"NOTE=x \"b" as &[u8]),
        // And a quote outside any value — on a line that sets nothing, or before its `=` —
        // which systemd 255 also reads literally: one rule, quotes only as a value's pair.
        ("KOTTON_RELAY_TTL=60\n", b"note \"open\nKOTTON_RELAY_TTL=60\n" as &[u8], b"note \"open" as &[u8]),
        ("KOTTON_RELAY_TTL=60\n", b"NO'TE=x\nKOTTON_RELAY_TTL=60\n" as &[u8], b"NO'TE=x" as &[u8]),
        // Seed 83's file: a line ending in a backslash continues into the next even when
        // that looks like a comment, so `;'\xff` is part of NOTE's value to systemd, which
        // fails the whole file. Any line ending in a backslash is refused.
        ("KOTTON_RELAY_ADVERTISE=\n", b"NOTE==a\\\n;'\xff\nKOTTON_RELAY_ADVERTISE=;\n" as &[u8], b"NOTE==a\\" as &[u8]),
        // A carriage return, which systemd reads as a line break even inside a comment:
        // the comment ends there and what follows sets a value the installer would not see.
        ("KOTTON_RELAY_ADVERTISE=\n", b"# note\rKOTTON_RELAY_ADVERTISE=http://kept.example:7700\n" as &[u8], LAST),
        ("KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n", b"# note\rKOTTON_RELAY_STATE_DIR=/var/lib/elsewhere\n" as &[u8], LAST),
        // UTF-8 that systemd would take is still outside the one form read here.
        ("KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n", "KOTTON_RELAY_STATE_DIR=/var/lib/k\u{f6}tton-relay\n".as_bytes(), LAST),
    ]
}

/// The kept files the installer must accept: each a whole `relay.env`.
pub fn accepted_forms() -> Vec<(&'static str, Vec<u8>)> {
    let shipped = shipped();
    let with = |from: &str, to: &[u8]| replaced(shipped.as_bytes(), from.as_bytes(), to);
    vec![
        ("shipped", shipped.clone().into_bytes()),
        ("address plain", with("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=http://kept.example:7700\n")),
        ("address double-quoted", with("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=\"http://kept.example:7700\"\n")),
        ("address single-quoted", with("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE='http://kept.example:7700'\n")),
        ("address quoted empty", with("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=\"\"\n")),
        ("address set twice", with("KOTTON_RELAY_ADVERTISE=\n", b"KOTTON_RELAY_ADVERTISE=http://first.example:7700\nKOTTON_RELAY_ADVERTISE=http://last.example:7700\n")),
        ("address commented out", with("KOTTON_RELAY_ADVERTISE=\n", b"#KOTTON_RELAY_ADVERTISE=http://old.example:7700\n")),
        ("bind quoted", with("KOTTON_RELAY_BIND=0.0.0.0:7700\n", b"KOTTON_RELAY_BIND=\"0.0.0.0:7800\"\n")),
        ("state directory single-quoted", with("KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n", b"KOTTON_RELAY_STATE_DIR='/var/lib/kotton-relay'\n")),
        ("another line quoted and closed", with("KOTTON_RELAY_TTL=60\n", b"NOTE=\"a b\"\nOTHER='c'\nKOTTON_RELAY_TTL=60\n")),
        ("invalid UTF-8 in a comment", with("KOTTON_RELAY_TTL=60\n", b"# caf\xff\nKOTTON_RELAY_TTL=60\n")),
        ("a quote inside a comment", with("KOTTON_RELAY_TTL=60\n", b"# it's \"open\nKOTTON_RELAY_TTL=60\n")),
        ("a read key in a semicolon comment", with("KOTTON_RELAY_ADVERTISE=\n", b"; KOTTON_RELAY_ADVERTISE=http://commented.example:7700\nKOTTON_RELAY_ADVERTISE=\n")),
        ("a semicolon comment, which systemd reads as one", with("KOTTON_RELAY_TTL=60\n", b"; note=\"open, and caf\xc3\xa9\nKOTTON_RELAY_TTL=60\n")),
        ("no last newline", shipped.trim_end_matches('\n').as_bytes().to_vec()),
    ]
}

/// One file as systemd's parser read it: what `load_env_file` returned, and each key's value.
pub type Reading = (i32, Vec<Option<String>>);

/// Where systemd's parser is, found once for every reader that asks: these tests and
/// `xtask`'s release gate and `doctor`.
#[path = "systemds_parser.rs"]
pub mod parser;

/// systemd's parser for the differential test `test`. Where it is missing the test fails,
/// naming what is missing
/// (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
///
/// A run that declares `KOTTON_NO_SYSTEMD_PARSER` does not reach here: the crate's build
/// script sets `kotton_no_systemd_parser`, under which each differential test is
/// `#[ignore]`d with a reason, so libtest's own verdict counts it ignored, by name. Run with
/// `--include-ignored` under the declaration, this writes `SKIPPED <test>` to the terminal,
/// uncaptured, and returns `None`.
pub fn systemds_parser_for(test: &str) -> Option<parser::SystemdsParser> {
    use std::io::Write as _;
    match parser::for_test(test, parser::find(), parser::skip_declared()) {
        Ok(Ok(found)) => Some(found),
        Ok(Err(line)) => {
            let _ = std::io::stderr().write_all(format!("\n*** {line}\n\n").as_bytes());
            None
        }
        Err(why) => panic!("{why}"),
    }
}

/// **The declaration is true where it is made.** Compiled only where the run declares
/// `KOTTON_NO_SYSTEMD_PARSER`, and never ignored: it fails where systemd's parser is on the
/// machine after all, so the declaration cannot hide a comparison that could have been made.
#[cfg(kotton_no_systemd_parser)]
#[test]
fn kotton_no_systemd_parser_is_declared_only_where_systemds_parser_is_absent() {
    if let Ok(found) = parser::find() {
        panic!(
            "KOTTON_NO_SYSTEMD_PARSER is set, and systemd's parser is here ({} through {}): unset it, \
             so the differential compares against it",
            found.library.display(),
            found.python.display()
        );
    }
}

/// What systemd's own parser makes of each file: `load_env_file` in `libsystemd-shared`,
/// through Python's ctypes — `int load_env_file(FILE *f, const char *fname, char ***ret)`,
/// called with no `FILE`, returning a NULL-terminated strv of `KEY=value`. The library's
/// path, then per file the parser's return and the value of each key asked for (`None`
/// where no assignment set it). Any failure of the call fails the test.
pub fn systemds_reading(parser: &parser::SystemdsParser, files: &[PathBuf], keys: &[&str]) -> (String, Vec<Reading>) {
    const PY: &str = r#"
import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
f = lib.load_env_file
f.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p))]
f.restype = ctypes.c_int
keys = sys.argv[2].split(",")
print(sys.argv[1])
for path in sys.argv[3:]:
    strv = ctypes.POINTER(ctypes.c_char_p)()
    r = f(None, path.encode(), ctypes.byref(strv))
    seen = {}
    i = 0
    while r >= 0 and strv and strv[i]:  # an empty file gives no strv at all
        k, _, v = strv[i].partition(b"=")
        seen[k.decode("latin-1")] = v
        i += 1
    print(" ".join([str(r)] + ["-" if seen.get(k) is None else "=" + seen[k].hex() for k in keys]))
"#;
    let out = Command::new(&parser.python)
        .arg("-c")
        .arg(PY)
        .arg(&parser.library)
        .arg(keys.join(","))
        .args(files)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", parser.python.display()));
    assert!(out.status.success(), "the call into {} failed: {}", parser.library.display(), said(&out));
    // One line naming the library, then per file: the return, and each key's value as
    // `=<hex>` or `-` where nothing set it.
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines();
    let lib = lines.next().unwrap().to_string();
    let mut files_out = Vec::new();
    for line in lines {
        let mut fields = line.split(' ');
        let r = fields.next().unwrap().parse().unwrap();
        let values = fields
            .map(|v| {
                v.strip_prefix('=').map(|hex| {
                    let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
                    String::from_utf8_lossy(&bytes).into_owned()
                })
            })
            .collect();
        files_out.push((r, values));
    }
    (lib, files_out)
}

/// A small, seeded generator: the same seed gives the same files on every machine.
pub struct Rng(u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The installer's verdict and reading, by the script's own functions: `settings_refusal`
/// — the one function an install runs each settings file through before it writes
/// anything — then `setting` for each key, as an install reads what it hands `create`.
/// Taken from `install-server.sh` itself, so the checks are the install's, not a copy;
/// that the install refuses exactly when `settings_refusal` speaks is held by the form
/// tests, which run the whole install. The grammar is the same for every line, so the
/// verdict is the same for both servers' files.
pub fn installers_verdicts(files: &[PathBuf], keys: &[&str]) -> Vec<Option<Vec<String>>> {
    let script = std::fs::read_to_string(repo().join("infra/release/install-server.sh")).unwrap();
    let function = |name: &str| {
        let start = script.find(&format!("\n{name}() {{")).unwrap_or_else(|| panic!("install-server.sh has {name}()"));
        let end = start + script[start..].find("\n}\n").unwrap() + 3;
        script[start..end].to_string()
    };
    let mut program = String::new();
    for name in ["file_form", "setting", "settings_refusal"] {
        program.push_str(&function(name));
    }
    program.push_str("for f in \"$@\"; do\n  if [ -n \"$(settings_refusal \"$f\")\" ]; then echo refused; continue; fi\n  printf 'read'\n");
    for key in keys {
        program.push_str(&format!("  printf ' %s' \"$(setting {key} \"$f\" | od -An -tx1 | tr -d ' \\n')\"\n"));
    }
    program.push_str("  echo\ndone\n");
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(program)
        .arg("sh")
        .args(files)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LC_ALL", "C.UTF-8")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", said(&out));
    let text = String::from_utf8(out.stdout).unwrap();
    let verdicts: Vec<Option<Vec<String>>> = text
        .lines()
        .map(|line| {
            let mut fields = line.split(' ');
            match fields.next() {
                Some("read") => Some(
                    keys.iter()
                        .map(|_| {
                            let hex = fields.next().unwrap_or("");
                            let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
                            String::from_utf8_lossy(&bytes).into_owned()
                        })
                        .collect(),
                ),
                _ => None,
            }
        })
        .collect();
    assert_eq!(verdicts.len(), files.len());
    verdicts
}

/// The seeds every run generates from: twenty, among them 83, which found a comment line a
/// trailing backslash continued into a value. `KOTTON_DIFF_SEED=<n>` adds one.
pub const SEEDS: [u64; 20] = [3, 83, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71];

/// One seed's short files, from the alphabet that has made every disagreement so far.
pub fn generated_files(seed: u64, lines_wanted: usize) -> Vec<Vec<u8>> {
    const KEYS: [&str; 5] = ["KOTTON_RELAY_ADVERTISE", "KOTTON_RELAY_BIND", "KOTTON_RELAY_STATE_DIR", "KOTTON_PUBLIC_ADDR", "KOTTON_BASE_DIR"];
    // The read keys, others, and the read keys written so a reader matching by text could
    // mistake them: indented, prefixed, suffixed.
    const NAMES: [&str; 10] = [
        "KOTTON_RELAY_ADVERTISE",
        "KOTTON_RELAY_BIND",
        "KOTTON_RELAY_STATE_DIR",
        "KOTTON_PUBLIC_ADDR",
        "KOTTON_BASE_DIR",
        "NOTE",
        "A",
        " KOTTON_RELAY_ADVERTISE",
        "XKOTTON_RELAY_BIND",
        "KOTTON_RELAY_BIND6",
    ];
    // Weighted by repetition: quotes and plain letters often, the bytes that refuse a whole
    // line rarely, so enough files are accepted for the comparison to reach quoting. A
    // carriage return, a form feed and a vertical tab are among them.
    const PIECES: [&[u8]; 25] = [
        b"=", b"=", b"\"", b"\"", b"\"", b"'", b"'", b"'", b"\\", b" ", b" ", b"\t", b"#", b";", b"a", b"a", b"a", b"a", b"7", b"0",
        "\u{e9}".as_bytes(), b"\xff", b"\r", b"\x0c", b"\x0b",
    ];
    let mut rng = Rng(seed.max(1));
    let mut files = Vec::new();
    let mut lines = 0;
    while lines < lines_wanted {
        let mut text = Vec::new();
        let mut continued = false;
        for _ in 0..1 + rng.below(8) {
            // After a line ending in a backslash, often a comment-shaped line: the join
            // systemd makes there is where the last gap was.
            let kind = if continued && rng.below(2) == 0 { 3 } else { rng.below(9) };
            match kind {
                // A third of the lines set a read value in the plain form, so a file is often
                // accepted and there is a value for the noise around it to hide from systemd.
                0..=2 => {
                    text.extend_from_slice(KEYS[rng.below(KEYS.len())].as_bytes());
                    text.extend_from_slice([&b"=a"[..], b"=\"a a\"", b"='a'", b"=", b"=aa", b"=;", b"=7700", b"=a=b"][rng.below(8)]);
                    text.push(b'\n');
                    lines += 1;
                    continued = false;
                    continue;
                }
                3 => text.push(if rng.below(2) == 0 { b'#' } else { b';' }),
                4 => {}
                _ => {
                    text.extend_from_slice(NAMES[rng.below(NAMES.len())].as_bytes());
                    text.push(b'=');
                }
            }
            for _ in 0..rng.below(6) {
                text.extend_from_slice(PIECES[rng.below(PIECES.len())]);
            }
            // A third of the other lines end in a backslash.
            continued = rng.below(3) == 0;
            if continued {
                text.push(b'\\');
            }
            // Now and then a CRLF ending.
            if rng.below(12) == 0 {
                text.push(b'\r');
            }
            text.push(b'\n');
            lines += 1;
        }
        files.push(text);
    }
    files
}
