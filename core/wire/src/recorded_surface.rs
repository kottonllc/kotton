// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one reader of a recorded wire surface: the `core/wire/*-surface.txt` files that
//! `cargo xtask wire-surface` writes (`render` in `xtask/src/wire_check.rs`) and
//! `cargo xtask wire-check` gates.
//!
//! A recording is a header of `#` lines, one of them `# variants: N`, then one block per
//! variant: its name on a line of its own, and under it each field attribute and field
//! indented by [`INDENT`]. Every reader of that format reads it here: `wire-check`'s twin
//! rule, and the kotton-wire tests that hold each peer verb to its door twin and each field
//! named for a secret to a secret type. Before this file each of them spelled the format
//! itself (`starts_with(' ')`, `starts_with('#')`), and only xtask's spelling was held to
//! the header, so five spellings of one format were five places to drift (kotton #297).
//!
//! **Every reader is held to the header.** [`read`] refuses a recording whose
//! `# variants: N` differs from the number of variants it parsed, one with no such
//! header or with two (the printer writes one, and a second would leave which count is
//! held to whichever came last), one with an indented line before any variant, and one
//! that records no variant at all. Each means the printer and this reader no longer agree, or the file was edited
//! by hand, and a rule over misread blocks would compare the wrong lines and say so in
//! green.
//!
//! **One source, compiled twice, no dependency.** xtask compiles this file by `#[path]`
//! (`wire_check::recorded_surface`) rather than linking kotton-wire, and kotton-wire
//! compiles it for its tests. A dependency was the other seam, and xtask should not take
//! it: it would build kotton-wire's closure into every `cargo xtask`, and `wire-check`
//! reads the wire as text precisely so that it needs no compile of the crate it checks. So
//! this file names nothing but `std`; a `use crate::…` here fails xtask's build, which is
//! the point, and a name both crates link (`serde_json`), which no build catches, fails
//! xtask's test of every `#[path]`-shared file (`xtask/src/std_only.rs`, kotton #306). It
//! is how xtask already compiles `kvaultd`'s reader of its settings file.

/// The indent the printer writes before a field or attribute line, and the one [`read`]
/// takes as "this line belongs to the variant above". xtask's `render` writes this
/// constant, so the printer and the reader spell it once; the header count catches a
/// drift that does not go through it.
pub const INDENT: &str = "    ";

/// One indented line of a block: the 1-based line of the file it is on, and the line raw.
///
/// Each line keeps its own number, so a blank or a comment a hand edit put inside a block
/// does not shift the number printed for the lines after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line<'a> {
    pub at: usize,
    pub text: &'a str,
}

/// One variant of a recording: its name, the 1-based file line it is on, and its indented
/// lines (field attributes and fields) raw, in order.
#[derive(Debug)]
pub struct Block<'a> {
    pub name: &'a str,
    pub at: usize,
    pub lines: Vec<Line<'a>>,
}

impl<'a> Block<'a> {
    /// The block's lines raw, without their numbers: what two blocks are compared by.
    pub fn texts(&self) -> Vec<&'a str> {
        self.lines.iter().map(|l| l.text).collect()
    }
}

/// The variants of a recording, in file order, or why it cannot be read as one.
///
/// A line starting with `#` is a header line; every other non-empty line is a variant name
/// unless it starts with [`INDENT`], when it belongs to the variant above.
pub fn read(text: &str) -> Result<Vec<Block<'_>>, String> {
    let mut header: Option<(usize, usize)> = None;
    let mut out: Vec<Block<'_>> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let at = i + 1;
        if line.starts_with(INDENT) {
            let Some(block) = out.last_mut() else {
                return Err(format!("line {at} is indented before any variant, so it belongs to none"));
            };
            block.lines.push(Line { at, text: line });
        } else if let Some(rest) = line.strip_prefix('#') {
            if let Some(n) = rest.trim().strip_prefix("variants:") {
                if let Some((first, _)) = header {
                    return Err(format!(
                        "line {at} is a second `# variants:` header after line {first}: the \
                         printer writes one, so which count the recording holds is not known"
                    ));
                }
                let n = n
                    .trim()
                    .parse()
                    .map_err(|_| format!("line {at} has a `# variants:` header that is not a count"))?;
                header = Some((at, n));
            }
        } else if !line.trim().is_empty() {
            out.push(Block {
                name: line.trim_end(),
                at,
                lines: Vec::new(),
            });
        }
    }
    match header {
        None => Err("it has no `# variants: N` header, so its count cannot be held".into()),
        Some((_, n)) if n != out.len() => Err(format!(
            "its header records {n} variants and the reader parsed {}: the printer (`render` in \
             xtask/src/wire_check.rs) and the reader (core/wire/src/recorded_surface.rs) no \
             longer agree on the format, so a rule over it would compare the wrong lines",
            out.len()
        )),
        Some(_) if out.is_empty() => {
            Err("it records no variant, so a rule over it would hold nothing".into())
        }
        Some(_) => Ok(out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each block line is numbered by its own line in the file, so a blank and a comment
    /// inside a block, as a hand edit leaves them, do not shift the lines after them.
    #[test]
    fn a_blank_or_comment_inside_a_block_keeps_every_line_number() {
        let text = "# h\n# variants: 2\nA\n    x: u8\n\n# a note\n    y: u8\nB\n    z: u8\n";
        let blocks = read(text).expect("a readable recording");
        assert_eq!(blocks.len(), 2);
        assert_eq!((blocks[0].name, blocks[0].at), ("A", 3));
        assert_eq!(
            blocks[0].lines,
            [Line { at: 4, text: "    x: u8" }, Line { at: 7, text: "    y: u8" }]
        );
        assert_eq!(blocks[0].texts(), ["    x: u8", "    y: u8"]);
        assert_eq!((blocks[1].name, blocks[1].at, blocks[1].lines[0].at), ("B", 8, 9));
    }

    /// Every way a recording is not one is refused, with the reason, rather than read as
    /// blocks a rule would then compare.
    #[test]
    fn a_text_that_is_not_a_recording_is_refused_with_the_reason() {
        let refused = |text: &str, why: &str| match read(text) {
            Err(e) => assert!(e.contains(why), "{e}"),
            Ok(b) => panic!("read {} blocks from {text:?}", b.len()),
        };
        refused("A\n    x: u8\n", "no `# variants: N` header");
        refused("# variants: 1\nA\n\tx: u8\n", "header records 1 variants and the reader parsed 2");
        refused("# variants: 0\n    x: u8\n", "line 2 is indented before any variant");
        refused("# variants: many\nA\n", "line 1 has a `# variants:` header that is not a count");
        refused("# variants: 0\n", "records no variant");
        refused("# variants: 1\n# variants: 1\nA\n", "line 2 is a second `# variants:` header after line 1");
        refused("# variants: 2\nA\n# variants: 1\n", "line 3 is a second `# variants:` header after line 1");
    }

    /// The recordings in this tree are each read whole, by this reader, from whichever
    /// crate compiles it.
    #[test]
    fn every_recording_in_this_tree_is_read() {
        let wire = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let wire = if wire.ends_with("xtask") { wire.join("../core/wire") } else { wire.to_path_buf() };
        let mut seen = 0;
        for entry in std::fs::read_dir(&wire).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.ends_with("-surface.txt") {
                let text = std::fs::read_to_string(&path).unwrap();
                read(&text).unwrap_or_else(|e| panic!("{name} cannot be read as a recording: {e}"));
                seen += 1;
            }
        }
        assert!(seen >= 6, "found {seen} recordings under {}", wire.display());
    }
}
