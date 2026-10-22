// SPDX-License-Identifier: AGPL-3.0-or-later
//! A TOML file as the key paths it assigns, for the gates that read `Cargo.toml` and an app's
//! `manifest.toml`.
//!
//! xtask has no TOML parser of its own: `toml` reaches it only as a dev-dependency, through
//! `workspace-hack`, so the code a gate runs cannot name it. This reader is the part of TOML
//! those two files use, read whole: tables and arrays of tables (`[a . "b"]`, `[[a]]`, spaces
//! anywhere TOML allows), dotted and quoted keys, inline tables flattened into their keys,
//! values that run over several lines inside brackets, basic, literal and multi-line strings,
//! and comments. Each assignment comes back as its full key path, its value's text and its
//! line. A line it cannot read is an `Err` naming the line, never a line skipped: a gate that
//! skipped one would pass over what it was for.

/// One assignment: `path` is every key from the root, an array of tables' entry being the
/// segment `[n]`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub path: Vec<String>,
    pub value: String,
    pub line: usize,
}

/// What a file assigns, and every table its headers open, each with its line.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Doc {
    pub entries: Vec<Entry>,
    pub tables: Vec<(Vec<String>, usize)>,
}

/// Reads `text`, or names the first line it cannot.
pub(crate) fn read(text: &str) -> Result<Doc, String> {
    let mut doc = Doc::default();
    let mut table: Vec<String> = Vec::new();
    let mut counts: Vec<(Vec<String>, usize)> = Vec::new();
    for (stmt, line) in statements(text)? {
        if let Some(inner) = stmt.strip_prefix("[[") {
            let inner = inner.strip_suffix("]]").ok_or(format!("line {line}: `{stmt}` does not close with `]]`"))?;
            let path = key_path(inner).map_err(|e| format!("line {line}: {e}"))?;
            let n = match counts.iter_mut().find(|(p, _)| *p == path) {
                Some((_, n)) => {
                    *n += 1;
                    *n
                }
                None => {
                    counts.push((path.clone(), 0));
                    0
                }
            };
            table = path;
            table.push(format!("[{n}]"));
            doc.tables.push((table.clone(), line));
        } else if let Some(inner) = stmt.strip_prefix('[') {
            let inner = inner.strip_suffix(']').ok_or(format!("line {line}: `{stmt}` does not close with `]`"))?;
            table = key_path(inner).map_err(|e| format!("line {line}: {e}"))?;
            doc.tables.push((table.clone(), line));
        } else {
            assign(&table, &stmt, line, &mut doc.entries)?;
        }
    }
    Ok(doc)
}

/// `key = value` under `table`, an inline table flattened into one entry per key.
fn assign(table: &[String], stmt: &str, line: usize, out: &mut Vec<Entry>) -> Result<(), String> {
    let eq = split_top(stmt, '=', true)
        .filter(|parts| !parts.is_empty())
        .ok_or(format!("line {line}: `{stmt}` is neither a table header nor `key = value`"))?;
    let key = &stmt[..eq[0]];
    let value = stmt[eq[0] + 1..].trim();
    let mut path = table.to_vec();
    path.extend(key_path(key).map_err(|e| format!("line {line}: {e}"))?);
    if value.is_empty() {
        return Err(format!("line {line}: `{stmt}` assigns nothing"));
    }
    if let Some(inner) = value.strip_prefix('{') {
        let inner = inner.strip_suffix('}').ok_or(format!("line {line}: `{value}` does not close with `}}`"))?;
        if inner.trim().is_empty() {
            out.push(Entry { path, value: "{}".into(), line });
            return Ok(());
        }
        let mut start = 0;
        let commas = split_top(inner, ',', false).unwrap_or_default();
        for end in commas.into_iter().chain([inner.len()]) {
            let part = inner[start..end].trim();
            start = end + 1;
            if part.is_empty() {
                continue;
            }
            assign(&path, part, line, out)?;
        }
        return Ok(());
    }
    out.push(Entry { path, value: value.to_string(), line });
    Ok(())
}

/// The byte offsets of every `sep` in `s` outside strings and, for `,`, outside brackets.
/// With `first`, only the first one. `None` when a string does not close.
fn split_top(s: &str, sep: char, first: bool) -> Option<Vec<usize>> {
    let mut at = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match quote {
            Some(q) => {
                if q == '"' && c == '\\' {
                    chars.next();
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                _ if c == sep && (sep == '=' || depth == 0) => {
                    at.push(i);
                    if first {
                        return Some(at);
                    }
                }
                _ => {}
            },
        }
    }
    quote.is_none().then_some(at)
}

/// A dotted key, each segment bare or quoted, whitespace around the dots allowed.
fn key_path(key: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let c: Vec<char> = key.trim().chars().collect();
    let mut i = 0;
    loop {
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        let mut seg = String::new();
        match c.get(i) {
            Some(&q @ ('"' | '\'')) => {
                i += 1;
                while i < c.len() && c[i] != q {
                    if q == '"' && c[i] == '\\' && i + 1 < c.len() {
                        i += 1;
                    }
                    seg.push(c[i]);
                    i += 1;
                }
                if i >= c.len() {
                    return Err(format!("the key `{key}` has a quote that does not close"));
                }
                i += 1;
            }
            Some(_) => {
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_' || c[i] == '-') {
                    seg.push(c[i]);
                    i += 1;
                }
                if seg.is_empty() {
                    return Err(format!("`{key}` is not a key"));
                }
            }
            None => return Err(format!("`{key}` is not a key")),
        }
        out.push(seg);
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        match c.get(i) {
            None => return Ok(out),
            Some('.') => i += 1,
            Some(_) => return Err(format!("`{key}` is not a key")),
        }
    }
}

/// The file's statements, comments removed, each with the line it starts on. A statement ends
/// at a newline outside strings and brackets.
fn statements(text: &str) -> Result<Vec<(String, usize)>, String> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut line, mut start) = (1usize, 1usize);
    let mut depth = 0i32;
    let mut i = 0;
    let header = |cur: &str| cur.trim_start().starts_with('[');
    while i < c.len() {
        let ch = c[i];
        let triple = |q: char| c.get(i + 1) == Some(&q) && c.get(i + 2) == Some(&q);
        if (ch == '"' || ch == '\'') && triple(ch) {
            // A multi-line string, whole.
            let q = ch;
            cur.extend([q, q, q]);
            i += 3;
            loop {
                if i >= c.len() {
                    return Err(format!("line {start}: a multi-line string does not close"));
                }
                if c[i] == q && c.get(i + 1) == Some(&q) && c.get(i + 2) == Some(&q) {
                    cur.extend([q, q, q]);
                    i += 3;
                    break;
                }
                if q == '"' && c[i] == '\\' && i + 1 < c.len() {
                    cur.push(c[i]);
                    i += 1;
                }
                if c[i] == '\n' {
                    line += 1;
                }
                cur.push(c[i]);
                i += 1;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                cur.push(ch);
                i += 1;
                while i < c.len() && c[i] != ch && c[i] != '\n' {
                    if ch == '"' && c[i] == '\\' && i + 1 < c.len() {
                        cur.push(c[i]);
                        i += 1;
                    }
                    cur.push(c[i]);
                    i += 1;
                }
                if i >= c.len() || c[i] != ch {
                    return Err(format!("line {line}: a string does not close on its line"));
                }
                cur.push(ch);
                i += 1;
            }
            '#' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '\n' => {
                line += 1;
                i += 1;
                if depth > 0 && !header(&cur) {
                    cur.push(' ');
                    continue;
                }
                if depth != 0 {
                    return Err(format!("line {start}: `{}` does not close", cur.trim()));
                }
                if !cur.trim().is_empty() {
                    out.push((cur.trim().to_string(), start));
                }
                cur.clear();
                start = line;
            }
            _ => {
                if cur.trim().is_empty() {
                    start = line;
                }
                if matches!(ch, '[' | '{') {
                    depth += 1;
                } else if matches!(ch, ']' | '}') {
                    depth -= 1;
                }
                cur.push(ch);
                i += 1;
            }
        }
    }
    if depth != 0 {
        return Err(format!("line {start}: `{}` does not close", cur.trim()));
    }
    if !cur.trim().is_empty() {
        out.push((cur.trim().to_string(), start));
    }
    Ok(out)
}

/// A value's text as the string it is, if it is a basic or literal string on one line.
pub(crate) fn string(value: &str) -> Option<String> {
    let v = value.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) && !v.starts_with("\"\"\"") {
            return Some(v[1..v.len() - 1].to_string());
        }
    }
    None
}

/// The strings in an array value's text, in order.
pub(crate) fn strings(value: &str) -> Vec<String> {
    let v = value.trim();
    let Some(inner) = v.strip_prefix('[').and_then(|v| v.strip_suffix(']')) else { return Vec::new() };
    let mut out = Vec::new();
    let mut start = 0;
    let commas = split_top(inner, ',', false).unwrap_or_default();
    for end in commas.into_iter().chain([inner.len()]) {
        if let Some(s) = string(&inner[start..end]) {
            out.push(s);
        }
        start = end + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(doc: &Doc) -> Vec<(String, String, usize)> {
        doc.entries.iter().map(|e| (e.path.join("/"), e.value.clone(), e.line)).collect()
    }

    #[test]
    fn every_form_a_cargo_manifest_uses_is_read_to_its_key_path() {
        let text = "[package]\nname = \"x\" # the name\n\n[ dependencies ]\nreqwest.version = \"0.12\"\n\
                    web = { version = \"1\", package = \"hyper\" }\n\
                    tokio = { version = \"1\", features = [\n  \"rt\",\n  \"net\", # sockets\n] }\n\n\
                    [target.'cfg(unix)'.\"dev-dependencies\".ureq]\nversion = \"2\"\n";
        let doc = read(text).unwrap();
        assert_eq!(
            paths(&doc),
            [
                ("package/name".into(), "\"x\"".into(), 2),
                ("dependencies/reqwest/version".into(), "\"0.12\"".into(), 5),
                ("dependencies/web/version".into(), "\"1\"".into(), 6),
                ("dependencies/web/package".into(), "\"hyper\"".into(), 6),
                ("dependencies/tokio/version".into(), "\"1\"".into(), 7),
                ("dependencies/tokio/features".into(), "[   \"rt\",   \"net\",  ]".into(), 7),
                ("target/cfg(unix)/dev-dependencies/ureq/version".into(), "\"2\"".into(), 13),
            ]
        );
        assert_eq!(strings(&doc.entries[5].value), ["rt", "net"]);
        assert_eq!(doc.tables[2], (vec!["target".into(), "cfg(unix)".into(), "dev-dependencies".into(), "ureq".into()], 12));
    }

    #[test]
    fn arrays_of_tables_are_numbered_and_quoted_keys_kept_whole() {
        let doc = read("[ capabilities ]\n\"files.read\" = [\"/\"]\n[[capabilities]]\ntype = \"vfs-tree\"\n[[ capabilities ]]\ntype = 'x'\n").unwrap();
        assert_eq!(
            paths(&doc),
            [
                ("capabilities/files.read".into(), "[\"/\"]".into(), 2),
                ("capabilities/[0]/type".into(), "\"vfs-tree\"".into(), 4),
                ("capabilities/[1]/type".into(), "'x'".into(), 6),
            ]
        );
        assert_eq!(string("'x'"), Some("x".into()));
    }

    #[test]
    fn a_hash_or_a_bracket_inside_a_string_is_text() {
        let doc = read("a = \"#not a comment ]\"\nb = '''\nmulti # line\n'''\n").unwrap();
        assert_eq!(doc.entries[0].value, "\"#not a comment ]\"");
        assert_eq!(doc.entries[1].line, 2);
    }

    #[test]
    fn what_cannot_be_read_is_refused_naming_its_line() {
        for (text, line) in [
            ("a = 1\nnot a statement\n", "line 2"),
            ("a = \"open\n", "line 1"),
            ("[table\nb = 1\n", "line 1"),
            ("a = [1,\n", "line 1"),
            ("x.\"y = 1\n", "line 1"),
        ] {
            let e = read(text).expect_err(text);
            assert!(e.starts_with(line), "{text:?}: {e}");
        }
    }
}
