// SPDX-License-Identifier: AGPL-3.0-or-later
//! Principle III, *identity is self-sovereign*, as `constitution-check` reads the tree.
//!
//! An identifier in Kotton is the digest of the inception event its own key signs
//! (`derive_aid` in `core/crypto/src/provider/kel_verify.rs`), so nothing has to be asked who
//! someone is. A user database is the other arrangement: a store that keeps an account, the
//! record a party other than the key holder reads to say who a person is and lets them in by.
//! What marks one in source is a table named for accounts, or a column or a field that keeps
//! the secret a person is let in by or the address they are reached at. These two inspections
//! refuse each; decision 0020 says what they leave alone and why.
//!
//! **What they read.** Every `.sql` file under the code roots ([`crate::tree::CODE_ROOTS`]),
//! and every string literal in every `.rs` file under them but `xtask/`, whose own tests plant
//! what this refuses: the name and the columns of each table created there, and each column
//! added. And the type declarations of every `.rs` file under `core/` and `infra/relay/src/`.
//!
//! **What they cannot see.** They are syntactic. A name assembled at run time (`format!`,
//! `concat!`), a field renamed by `serde` and a type alias are not read; an author who means
//! to hide one can. The check exists to make the rule visible and to fail the accidental and
//! the ordinary, which is how a users table arrives.

use std::path::{Path, PathBuf};

/// Table names a store of accounts goes by, compared without case or quoting.
pub(crate) const ACCOUNT_TABLES: &[&str] = &[
    "users",
    "user",
    "user_accounts",
    "accounts",
    "account",
    "logins",
    "login",
    "credentials",
    "passwords",
];

/// What a column or a field is named when it keeps a secret a person is let in by, or an
/// address they are reached at: a name that holds any of these, compared without case.
pub(crate) const KEPT_FOR_A_PERSON: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pw_hash",
    "pin_hash",
    "secret_hash",
    "token_hash",
    "email",
    "phone",
];

/// Words that hold one of [`KEPT_FOR_A_PERSON`] and are not it, each removed from a name
/// before the name is read: a `microphone` is not a `phone`.
pub(crate) const NOT_THE_WORD: &[&str] = &["microphone"];

/// The fields in the tree whose names hold one of [`KEPT_FOR_A_PERSON`] and are not an
/// account's, each by file, type and field, with why; an entry covers every field of that name
/// in that type, an enum's variants included. Fail-closed: a named field that is no longer
/// there is a broken check, and a new one is refused until it is named here.
pub(crate) const NAMED_FIELDS: &[(&str, &str, &str, &str)] = &[
    (
        "core/session/src/lock_policy.rs",
        "LockPolicy",
        "pin_hash",
        "the secret that opens a session on the person's own device, kept on that device and \
         sent nowhere; it keys nothing across machines, and no one but the device can be asked \
         for it",
    ),
    (
        "core/kuserd/src/agent/handlers/user.rs",
        "NewIdentity",
        "passphrase",
        "the device's unlock secret, carried on the device's local channel to the daemon that \
         seals the device's copy under it; the request is not one a remote caller can send",
    ),
    (
        "core/wire/src/ipc/request.rs",
        "UserRequest",
        "passphrase",
        "the device's unlock secret, carried on the device's local channel to the daemon that \
         seals the device's copy under it; the request is not one a remote caller can send",
    ),
    (
        "core/wire/src/runner.rs",
        "RunnerAuthVerb",
        "passphrase",
        "the device's unlock secret, carried on the device's local channel to the daemon that \
         seals the device's copy under it; the request is not one a remote caller can send",
    ),
    (
        "core/net/src/provider/transport/turn/client.rs",
        "TurnClient",
        "password",
        "a TURN server's credential, which Kotton presents to that server",
    ),
    (
        "core/peer/src/nat.rs",
        "NatConfig",
        "turn_password",
        "a TURN server's credential, which Kotton presents to that server",
    ),
    (
        "core/peer/src/nat.rs",
        "NatNetworkConfig",
        "turn_password",
        "a TURN server's credential, which Kotton presents to that server",
    ),
    (
        "core/device/src/config/transport.rs",
        "HttpAuth",
        "password",
        "a field nothing reads: no transport or discovery code reads `auth`",
    ),
    (
        "core/sys/src/net/address.rs",
        "HttpAuth",
        "password",
        "a field nothing reads: no transport or discovery code reads `auth`",
    ),
];

/// The columns in the tree's SQL whose names hold one of [`KEPT_FOR_A_PERSON`] and are not an
/// account's, each by file, table and column, with why; fail-closed as [`NAMED_FIELDS`] is.
pub(crate) const NAMED_COLUMNS: &[(&str, &str, &str, &str)] = &[
    (
        "core/device/migrations/0019_web_shell_credentials.sql",
        "web_shell_credentials",
        "token_hash",
        "a table `0022_drop_web_shell_credentials.sql` drops; a migration that has run is not edited",
    ),
    (
        "core/kuserd/migrations_user/0005_network_user_tables.sql",
        "web_shell_credentials",
        "token_hash",
        "a table `0010_drop_web_shell_credentials.sql` drops; a migration that has run is not edited",
    ),
];

/// Type names an account record goes by. One of these has a `did` field.
pub(crate) const ACCOUNT_TYPES: &[&str] = &["User", "UserAccount", "UserRecord", "Account", "Login"];

/// The field a type named for an account has.
const DID_FIELD: &str = "did";

/// The trees whose type declarations are read.
pub(crate) const TYPE_TREES: &[&str] = &["core", "infra/relay/src"];

/// Directories never read: build output and vendored trees.
const SKIP_DIRS: &[&str] = &["target", "out", "node_modules", ".git"];

/// Whether `name` holds one of [`KEPT_FOR_A_PERSON`], and which.
fn kept_for_a_person(name: &str) -> Option<&'static str> {
    let mut lower = name.to_ascii_lowercase();
    for word in NOT_THE_WORD {
        lower = lower.replace(word, " ");
    }
    KEPT_FOR_A_PERSON.iter().copied().find(|m| lower.contains(m))
}

/// Article III: no SQL in the workspace creates a table named for accounts, or a column whose
/// name holds a secret's or an address's word.
pub(crate) fn no_account_table(root: &Path, violations: &mut Vec<String>) {
    let mut read = 0usize;
    let mut columns_seen = vec![false; NAMED_COLUMNS.len()];
    for tree in crate::tree::CODE_ROOTS {
        let mut files = Vec::new();
        walk(&root.join(tree), &mut files);
        for path in files {
            let rel = rel(root, &path);
            let is_sql = path.extension().is_some_and(|x| x == "sql");
            let is_rs = path.extension().is_some_and(|x| x == "rs") && *tree != "xtask";
            if !is_sql && !is_rs {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                violations.push(format!(
                    "constitution-check is BROKEN: cannot read `{rel}`. Article III's table rule is \
                     unverified for it."
                ));
                continue;
            };
            read += 1;
            let found: Vec<SqlTable> = if is_sql {
                sql_tables(&text, true)
            } else {
                crate::host_word_check::string_literals(&text)
                    .into_iter()
                    .flat_map(|(line, lit)| {
                        sql_tables(&lit, false).into_iter().map(move |mut t| {
                            t.line += line - 1;
                            for c in &mut t.columns {
                                c.1 += line - 1;
                            }
                            t
                        })
                    })
                    .collect()
            };
            for t in found {
                if t.created && ACCOUNT_TABLES.contains(&t.name.to_ascii_lowercase().as_str()) {
                    violations.push(format!(
                        "Article III: {rel} line {}: creates a table named `{}`. An identifier is \
                         the digest of its own key's inception, so no store keeps accounts; a \
                         table of people is named for what it records of them and keeps no \
                         secret they are let in by.",
                        t.line, t.name
                    ));
                }
                for (column, line) in &t.columns {
                    let named = NAMED_COLUMNS
                        .iter()
                        .position(|(f, tb, c, _)| *f == rel && *tb == t.name && c == column);
                    if let Some(at) = named {
                        columns_seen[at] = true;
                        continue;
                    }
                    if let Some(word) = kept_for_a_person(column) {
                        violations.push(format!(
                            "Article III: {rel} line {line}: table `{}` has a column `{column}`, \
                             whose name holds `{word}`. Kotton lets a person in by their key and \
                             reaches them by their DID; a table that keeps a secret or an \
                             address for them is an account.",
                            t.name
                        ));
                    }
                }
            }
        }
    }
    if read == 0 {
        violations.push(
            "constitution-check is BROKEN: Article III's table rule read no `.sql` or `.rs` file \
             under the code roots — it is passing over nothing. Repoint it."
                .to_string(),
        );
    }
    for (seen, (file, table, column, _)) in columns_seen.iter().zip(NAMED_COLUMNS) {
        if read > 0 && !seen {
            violations.push(format!(
                "constitution-check is BROKEN: `NAMED_COLUMNS` names `{table}.{column}` in {file}, \
                 and no such column is there. Take it out, so the list names only what it lets \
                 pass."
            ));
        }
    }
}

/// Article III: no type in `core/` or the relay has a field whose name holds a secret's or an
/// address's word, but the fields [`NAMED_FIELDS`] names; and a type named for an account has
/// a `did` field.
pub(crate) fn no_account_record(root: &Path, violations: &mut Vec<String>) {
    let mut read = 0usize;
    let mut named_seen = vec![false; NAMED_FIELDS.len()];
    for tree in TYPE_TREES {
        let dir = root.join(tree);
        if !dir.is_dir() {
            violations.push(format!(
                "constitution-check is BROKEN: `{tree}` is not a directory. Article III's type \
                 rule is unverified there — repoint it."
            ));
            continue;
        }
        let mut files = Vec::new();
        walk(&dir, &mut files);
        for path in files.iter().filter(|p| p.extension().is_some_and(|x| x == "rs")) {
            let rel = rel(root, path);
            let Ok(text) = std::fs::read_to_string(path) else {
                violations.push(format!(
                    "constitution-check is BROKEN: cannot read `{rel}`. Article III's type rule is \
                     unverified for it."
                ));
                continue;
            };
            read += 1;
            for why in account_records(&rel, &text, &mut named_seen) {
                violations.push(format!("Article III: {rel} {why}"));
            }
        }
    }
    if read == 0 {
        violations.push(
            "constitution-check is BROKEN: Article III's type rule read no `.rs` file under \
             `core/` or `infra/relay/src/`. Repoint it."
                .to_string(),
        );
    }
    for (seen, (file, ty, field, _)) in named_seen.iter().zip(NAMED_FIELDS) {
        if read > 0 && !seen {
            violations.push(format!(
                "constitution-check is BROKEN: `NAMED_FIELDS` names `{ty}.{field}` in {file}, and \
                 no such field is there. Take it out, so the list names only what it lets pass."
            ));
        }
    }
}

/// What in one Rust source, at `rel`, refuses Article III's type rule, each as `line N: why`.
/// Marks in `named_seen` each entry of [`NAMED_FIELDS`] it meets.
pub(crate) fn account_records(rel: &str, src: &str, named_seen: &mut [bool]) -> Vec<String> {
    let mut out = Vec::new();
    for ty in types(src) {
        for (field, line) in &ty.fields {
            let Some(word) = kept_for_a_person(field) else { continue };
            let named = NAMED_FIELDS
                .iter()
                .position(|(f, t, n, _)| *f == rel && *t == ty.name && n == field);
            if let Some(at) = named {
                if let Some(seen) = named_seen.get_mut(at) {
                    *seen = true;
                }
                continue;
            }
            out.push(format!(
                "line {line}: `{}` has a field `{field}`, whose name holds `{word}`. Kotton lets a \
                 person in by their key and reaches them by their DID; a type that keeps a secret \
                 or an address for them is an account.",
                ty.name
            ));
        }
        if ACCOUNT_TYPES.contains(&ty.name.as_str()) && !ty.fields.iter().any(|(f, _)| f == DID_FIELD) {
            out.push(format!(
                "line {}: `{}` is named for an account and has no `{DID_FIELD}` field. A record of a \
                 person names them by the DID their own key made.",
                ty.line, ty.name
            ));
        }
    }
    out
}

/// A table a piece of SQL creates, or alters to add columns, with the columns it names.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SqlTable {
    /// Its name, schema qualifier and quoting removed.
    pub name: String,
    /// The line its name is on.
    pub line: usize,
    /// Whether this statement creates the table or renames one to this name; `false` when it
    /// only adds columns.
    pub created: bool,
    /// Each column it declares or adds, with its line.
    pub columns: Vec<(String, usize)>,
}

/// Every table a piece of SQL creates (`CREATE [TEMP|TEMPORARY] [VIRTUAL] TABLE [IF NOT
/// EXISTS] name (columns…)`), renames one to (`RENAME TO name`), or adds a column to
/// (`ALTER TABLE name ADD [COLUMN] column`), with the line of `text` each name is on.
/// `sql_comments` drops `--` comments, which a `.sql` file means as comments and a Rust literal
/// may not.
pub(crate) fn sql_tables(text: &str, sql_comments: bool) -> Vec<SqlTable> {
    let tokens = sql_tokens(text, sql_comments);
    let is = |k: usize, word: &str| tokens.get(k).is_some_and(|(t, _)| t.eq_ignore_ascii_case(word));
    let name_at = |k: usize| {
        tokens.get(k).map(|(name, line)| {
            let bare = unquote(name.rsplit('.').next().unwrap_or(name)).to_string();
            (bare, *line)
        })
    };
    let mut found = Vec::new();
    for i in 0..tokens.len() {
        if is(i, "CREATE") {
            let mut k = i + 1;
            while is(k, "TEMP") || is(k, "TEMPORARY") || is(k, "VIRTUAL") {
                k += 1;
            }
            if !is(k, "TABLE") {
                continue;
            }
            k += 1;
            if is(k, "IF") && is(k + 1, "NOT") && is(k + 2, "EXISTS") {
                k += 3;
            }
            let Some((name, line)) = name_at(k) else { continue };
            // The column list: the first `(` after the name, before any `AS`, past `USING m`.
            let mut columns = Vec::new();
            let mut open = None;
            for j in k + 1..(k + 4).min(tokens.len()) {
                if is(j, "AS") || is(j, ";") {
                    break;
                }
                if is(j, "(") {
                    open = Some(j);
                    break;
                }
            }
            if let Some(open) = open {
                let mut depth = 0;
                let mut first = true;
                for (tok, tline) in &tokens[open..] {
                    match tok.as_str() {
                        "(" => depth += 1,
                        ")" => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        "," if depth == 1 => first = true,
                        _ if depth == 1 && first => {
                            first = false;
                            let constraint = ["CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"]
                                .iter()
                                .any(|w| tok.eq_ignore_ascii_case(w));
                            if !constraint {
                                columns.push((unquote(tok).to_string(), *tline));
                            }
                        }
                        _ => {}
                    }
                }
            }
            found.push(SqlTable { name, line, created: true, columns });
        } else if is(i, "RENAME") && is(i + 1, "TO") {
            if let Some((name, line)) = name_at(i + 2) {
                found.push(SqlTable { name, line, created: true, columns: Vec::new() });
            }
        } else if is(i, "ALTER") && is(i + 1, "TABLE") {
            let Some((name, line)) = name_at(i + 2) else { continue };
            if is(i + 3, "ADD") {
                let at = if is(i + 4, "COLUMN") { i + 5 } else { i + 4 };
                if let Some((column, cline)) = name_at(at) {
                    found.push(SqlTable { name, line, created: false, columns: vec![(column, cline)] });
                }
            }
        }
    }
    found
}

/// SQL's tokens, each with its line: words, quoted names whole, `'…'` strings as one token,
/// and `(`, `)`, `,` and `;` alone.
fn sql_tokens(text: &str, sql_comments: bool) -> Vec<(String, usize)> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch == '\n' {
            line += 1;
            i += 1;
        } else if ch.is_whitespace() || ch == '\\' {
            i += 1;
        } else if sql_comments && ch == '-' && c.get(i + 1) == Some(&'-') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if matches!(ch, '(' | ')' | ',' | ';') {
            out.push((ch.to_string(), line));
            i += 1;
        } else if matches!(ch, '\'' | '"' | '`' | '[') {
            let close = if ch == '[' { ']' } else { ch };
            let (start, mut tok) = (line, String::from(ch));
            i += 1;
            while i < c.len() && c[i] != close {
                if c[i] == '\n' {
                    line += 1;
                }
                tok.push(c[i]);
                i += 1;
            }
            tok.push(close);
            i += 1;
            // A quoted name may carry a qualifier after it: `"main"."users"`.
            while i < c.len() && !c[i].is_whitespace() && !matches!(c[i], '(' | ')' | ',' | ';') {
                tok.push(c[i]);
                i += 1;
            }
            out.push((tok, start));
        } else {
            let mut tok = String::new();
            while i < c.len() && !c[i].is_whitespace() && !matches!(c[i], '(' | ')' | ',' | ';' | '\\') {
                tok.push(c[i]);
                i += 1;
            }
            out.push((tok, line));
        }
    }
    out
}

/// A token without the quoting SQL puts around a name.
fn unquote(raw: &str) -> &str {
    raw.trim_matches(|c: char| matches!(c, '"' | '`' | '[' | ']'))
}

/// One struct or enum, with every named field it declares (an enum's, from all its variants).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TypeDecl {
    pub name: String,
    /// The line its name is on.
    pub line: usize,
    /// Each named field and its line.
    pub fields: Vec<(String, usize)>,
}

/// Every `struct` and `enum` declared in one Rust source, with their named fields.
///
/// Comments and the insides of literals are blanked first, so a word in either declares
/// nothing. A tuple struct and a unit struct have no named fields; an enum's fields are its
/// struct-like variants'.
pub(crate) fn types(src: &str) -> Vec<TypeDecl> {
    let code: Vec<char> = code_only(src).chars().collect();
    let line_at = |at: usize| 1 + code[..at].iter().filter(|c| **c == '\n').count();
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let ident_at = |at: usize| -> (String, usize) {
        let mut end = at;
        while end < code.len() && word(code[end]) {
            end += 1;
        }
        (code[at..end].iter().collect(), end)
    };
    let skip_ws = |mut at: usize| {
        while at < code.len() && code[at].is_whitespace() {
            at += 1;
        }
        at
    };

    let mut out = Vec::new();
    let mut i = 0;
    while i < code.len() {
        if !word(code[i]) || (i > 0 && word(code[i - 1])) {
            i += 1;
            continue;
        }
        let (kw, after) = ident_at(i);
        if kw != "struct" && kw != "enum" {
            i = after;
            continue;
        }
        let at = skip_ws(after);
        let (name, mut k) = ident_at(at);
        if name.is_empty() {
            i = after;
            continue;
        }
        // Past generics, then to whatever opens the body: `{` for named fields, `(` or `;`
        // for none.
        let mut angle = 0i32;
        while k < code.len() {
            match code[k] {
                '<' => angle += 1,
                '>' => angle -= 1,
                '{' | '(' | ';' if angle <= 0 => break,
                _ => {}
            }
            k += 1;
        }
        if k >= code.len() || code[k] != '{' {
            i = k.max(after);
            continue;
        }
        let decl_line = line_at(at);
        let depth_of_fields = if kw == "struct" { 1 } else { 2 };
        let mut fields = Vec::new();
        let (mut brace, mut paren) = (0i32, 0i32);
        let mut j = k;
        while j < code.len() {
            match code[j] {
                '{' => brace += 1,
                '}' => {
                    brace -= 1;
                    if brace == 0 {
                        break;
                    }
                }
                '(' | '[' => paren += 1,
                ')' | ']' => paren -= 1,
                c if word(c) && !word(code[j - 1]) && brace == depth_of_fields && paren == 0 => {
                    let (field, end) = ident_at(j);
                    let colon = skip_ws(end);
                    let preceded = code[..j].iter().rev().find(|c| !c.is_whitespace());
                    if code.get(colon) == Some(&':')
                        && code.get(colon + 1) != Some(&':')
                        && preceded != Some(&':')
                    {
                        let field = field.strip_prefix("r#").unwrap_or(&field).to_string();
                        fields.push((field, line_at(j)));
                    }
                    j = end;
                    continue;
                }
                _ => {}
            }
            j += 1;
        }
        out.push(TypeDecl { name, line: decl_line, fields });
        i = k + 1;
    }
    out
}

/// `src` with every comment and the inside of every string and char literal blanked to
/// spaces, newlines kept, so a position in it is a position in `src`'s lines.
pub(crate) fn code_only(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let word = |k: usize| k < c.len() && (c[k].is_alphanumeric() || c[k] == '_');
    let mut out = String::with_capacity(src.len());
    let blank = |out: &mut String, ch: char| out.push(if ch == '\n' { '\n' } else { ' ' });
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    blank(&mut out, c[i]);
                    i += 1;
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                let mut depth = 0;
                while i < c.len() {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        out.push_str("  ");
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        out.push_str("  ");
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        blank(&mut out, c[i]);
                        i += 1;
                    }
                }
            }
            '\'' => {
                // A char literal, or else a lifetime or a label, which is kept.
                let end = if c.get(i + 1) == Some(&'\\') {
                    let mut k = i + 3;
                    while k < c.len() && c[k] != '\'' {
                        k += 1;
                    }
                    Some(k + 1)
                } else if c.get(i + 2) == Some(&'\'') {
                    Some(i + 3)
                } else {
                    None
                };
                match end {
                    Some(end) => {
                        while i < end.min(c.len()) {
                            blank(&mut out, c[i]);
                            i += 1;
                        }
                    }
                    None => {
                        out.push('\'');
                        i += 1;
                    }
                }
            }
            'r' if !word(i.wrapping_sub(1)) || (i >= 1 && c[i - 1] == 'b' && !word(i.wrapping_sub(2))) => {
                let mut k = i + 1;
                while c.get(k) == Some(&'#') {
                    k += 1;
                }
                if c.get(k) != Some(&'"') {
                    out.push('r');
                    i += 1;
                    continue;
                }
                let hashes = k - i - 1;
                while i <= k {
                    blank(&mut out, c[i]);
                    i += 1;
                }
                while i < c.len() {
                    if c[i] == '"' && (1..=hashes).all(|h| c.get(i + h) == Some(&'#')) {
                        for _ in 0..=hashes {
                            out.push(' ');
                        }
                        i += 1 + hashes;
                        break;
                    }
                    blank(&mut out, c[i]);
                    i += 1;
                }
            }
            '"' => {
                out.push(' ');
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        blank(&mut out, c[i]);
                        blank(&mut out, c[i + 1]);
                        i += 2;
                        continue;
                    }
                    blank(&mut out, c[i]);
                    i += 1;
                }
                if i < c.len() {
                    out.push(' ');
                    i += 1;
                }
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// Every file under `dir`, past build output.
pub(crate) fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| SKIP_DIRS.contains(&n.to_string_lossy().as_ref())) {
                continue;
            }
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// `path` relative to `root`, with `/` separators.
pub(crate) fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    fn names(found: &[SqlTable]) -> Vec<&str> {
        found.iter().map(|t| t.name.as_str()).collect()
    }

    /// The findings that are not about the list of named fields, which a scratch tree lacks.
    fn about_the_tree(v: Vec<String>) -> Vec<String> {
        v.into_iter()
            .filter(|m| !m.contains("`NAMED_FIELDS` names") && !m.contains("`NAMED_COLUMNS` names"))
            .collect()
    }

    fn records(src: &str) -> Vec<String> {
        account_records("core/x/src/lib.rs", src, &mut vec![false; NAMED_FIELDS.len()])
    }

    #[test]
    fn a_create_table_is_read_in_every_spelling_sql_has() {
        let sql = "CREATE TABLE users (id TEXT);\n\
                   create temp table IF NOT EXISTS \"Accounts\"(x);\n\
                   CREATE TABLE IF NOT EXISTS\n  main.`logins` (x);\n\
                   CREATE VIRTUAL TABLE [credentials] USING fts5(x);\n\
                   ALTER TABLE staging RENAME TO users;\n";
        let found = sql_tables(sql, true);
        assert_eq!(names(&found), ["users", "Accounts", "logins", "credentials", "users"]);
        assert_eq!(found[2].line, 4, "a name on the line after its keywords is reported on its own line");
        assert_eq!(found[3].columns, [("x".to_string(), 5)]);
    }

    #[test]
    fn a_tables_columns_are_read_past_types_constraints_and_strings() {
        let sql = "CREATE TABLE members (\n  did TEXT PRIMARY KEY,\n  note TEXT DEFAULT 'a, (b)',\n  \"Email\" TEXT,\n  amount NUMERIC(10, 2),\n  PRIMARY KEY (did, note),\n  UNIQUE (note)\n);\nALTER TABLE members ADD COLUMN pw_hash BLOB;\nALTER TABLE members ADD pin_hash BLOB;\n";
        let found = sql_tables(sql, true);
        let cols: Vec<&str> = found.iter().flat_map(|t| t.columns.iter().map(|c| c.0.as_str())).collect();
        assert_eq!(cols, ["did", "note", "Email", "amount", "pw_hash", "pin_hash"]);
        assert_eq!(found[0].columns[2].1, 4);
        assert!(!found[1].created, "ALTER TABLE … ADD creates no table");
    }

    #[test]
    fn a_comment_in_a_sql_file_creates_nothing_and_a_table_of_people_by_did_is_not_named_for_accounts() {
        let sql = "-- CREATE TABLE users (x);\nCREATE TABLE operators (did TEXT PRIMARY KEY); -- users\n";
        assert_eq!(names(&sql_tables(sql, true)), ["operators"]);
    }

    #[test]
    fn a_column_that_keeps_a_secret_or_an_address_is_refused_in_any_table() {
        let dir = tree(&[(
            "core/thing/migrations/0001.sql",
            "CREATE TABLE members (did TEXT, email TEXT, password_hash BLOB);\nCREATE TABLE ok (did TEXT, emailed_at INTEGER);\nALTER TABLE ok ADD COLUMN passwd TEXT;\nCREATE TABLE more (phone TEXT, token_hash BLOB, secret_hash BLOB, passphrase TEXT, microphone INTEGER);\n",
        )]);
        let mut v = Vec::new();
        no_account_table(dir.path(), &mut v);
        let v = about_the_tree(v);
        assert_eq!(v.len(), 8, "{v:#?}");
        assert!(!v.iter().any(|m| m.contains("microphone")), "{v:#?}");
        assert!(v[0].starts_with("Article III: core/thing/migrations/0001.sql line 1: table `members` has a column `email`"), "{}", v[0]);
        assert!(v[1].contains("column `password_hash`, whose name holds `password`"), "{}", v[1]);
        assert!(v[2].contains("column `emailed_at`, whose name holds `email`"), "{}", v[2]);
        assert!(v[3].starts_with("Article III: core/thing/migrations/0001.sql line 3: table `ok` has a column `passwd`"), "{}", v[3]);
    }

    #[test]
    fn a_rust_literal_is_read_for_the_table_it_creates() {
        let dir = tree(&[
            (
                "core/thing/src/db.rs",
                "// CREATE TABLE users in a comment is not SQL\nfn f() {\n    sqlx::query(\"CREATE TABLE IF NOT EXISTS \\\n         users (id TEXT)\");\n}\n",
            ),
            ("core/thing/migrations/0001.sql", "CREATE TABLE device_config (k TEXT);\n"),
            ("xtask/src/fixture.rs", "const F: &str = \"CREATE TABLE users (x)\";\n"),
        ]);
        let mut v = Vec::new();
        no_account_table(dir.path(), &mut v);
        let v = about_the_tree(v);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].starts_with("Article III: core/thing/src/db.rs line 4: creates a table named `users`"), "{}", v[0]);
    }

    #[test]
    fn a_tree_with_nothing_to_read_is_a_broken_check_not_a_pass() {
        let dir = tree(&[("docs/x.md", "nothing")]);
        let mut v = Vec::new();
        no_account_table(dir.path(), &mut v);
        assert!(v.iter().any(|m| m.contains("BROKEN")), "{v:#?}");
        let mut v = Vec::new();
        no_account_record(dir.path(), &mut v);
        assert!(v.iter().any(|m| m.contains("BROKEN")), "{v:#?}");
    }

    #[test]
    fn types_and_their_named_fields_are_read_and_comments_and_literals_declare_nothing() {
        let src = "/// struct Fake { email: String }\n\
                   pub struct Roster<T: Clone> where T: Send {\n    pub did: String,\n    pub(crate) name: T,\n    map: HashMap<String, std::path::PathBuf>,\n}\n\
                   struct Pair(String, u8);\n\
                   enum Proxy { None, Basic { username: String, password: String } }\n\
                   const S: &str = \"struct Hidden { email: u8 }\";\n\
                   fn f(email: &str) { let x = Roster { did: 1 }; }\n";
        let got = types(src);
        let summary: Vec<(String, Vec<String>)> =
            got.iter().map(|t| (t.name.clone(), t.fields.iter().map(|f| f.0.clone()).collect())).collect();
        let want: Vec<(String, Vec<String>)> = vec![
            ("Roster".into(), vec!["did".into(), "name".into(), "map".into()]),
            ("Proxy".into(), vec!["username".into(), "password".into()]),
        ];
        assert_eq!(summary, want, "a tuple struct declares no named field and is not listed");
        assert_eq!(got[0].line, 2);
        assert_eq!(got[0].fields[0].1, 3);
    }

    #[test]
    fn a_field_whose_name_holds_a_secrets_or_an_addresss_word_is_refused_wherever_it_is() {
        let v = records("struct Profile {\n    did: String,\n    email: String,\n}\n");
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].starts_with("line 3: `Profile` has a field `email`, whose name holds `email`"), "{}", v[0]);
        for field in [
            "pw_hash",
            "email_addr",
            "pin_hash",
            "passwd",
            "password_hash",
            "UserPassword",
            "passphrase_hash",
            "token_hash",
            "secret_hash",
            "phone",
            "phone_number",
        ] {
            let v = records(&format!("struct Member {{ did: String, {field}: String }}"));
            assert_eq!(v.len(), 1, "`{field}`: {v:#?}");
        }
        let v = records("enum Session { Open { password_hash: Vec<u8> } }\n");
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(records("struct Member { did: String, pin: u8, hash: String }").is_empty());
        assert!(records("struct Grants { media_microphone: bool }").is_empty(), "a microphone is not a phone");
    }

    #[test]
    fn a_named_field_passes_only_in_its_own_file_and_type() {
        let mut seen = vec![false; NAMED_FIELDS.len()];
        let src = "pub struct LockPolicy { pub pin_hash: Option<String> }\n";
        assert!(account_records("core/session/src/lock_policy.rs", src, &mut seen).is_empty());
        assert!(seen[0]);
        assert_eq!(account_records("core/other/src/lib.rs", src, &mut seen).len(), 1);
        let renamed = "pub struct Policy { pub pin_hash: Option<String> }\n";
        assert_eq!(account_records("core/session/src/lock_policy.rs", renamed, &mut seen).len(), 1);
    }

    #[test]
    fn a_named_field_that_is_gone_is_a_broken_check() {
        let dir = tree(&[("core/x/src/lib.rs", "struct A { did: String }\n"), ("infra/relay/src/main.rs", "")]);
        let mut v = Vec::new();
        no_account_record(dir.path(), &mut v);
        assert_eq!(v.len(), NAMED_FIELDS.len(), "{v:#?}");
        assert!(v.iter().all(|m| m.contains("BROKEN") && m.contains("`NAMED_FIELDS` names")));
    }

    #[test]
    fn a_type_named_for_an_account_has_a_did_field() {
        // What the shell host's roster entry looks like today.
        assert!(records("struct Account { user_id: String, did: String, name: String }").is_empty());
        let v = records("struct Account {\n    password_hash: String,\n}\n");
        assert_eq!(v.len(), 2, "{v:#?}");
        assert!(v.iter().any(|m| m.contains("has a field `password_hash`")));
        assert!(v.iter().any(|m| m.starts_with("line 1: `Account` is named for an account and has no `did`")));
        assert_eq!(records("struct User { name: String }").len(), 1);
    }

    #[test]
    fn the_type_rule_walks_core_and_the_relay_and_names_the_file() {
        let dir = tree(&[
            ("core/thing/src/lib.rs", "pub struct Login {\n    pub email: String,\n}\n"),
            ("infra/relay/src/main.rs", "struct Tenant { did: String }\n"),
            ("client/x/src/lib.rs", "struct User { password: String }\n"),
        ]);
        let mut v = Vec::new();
        no_account_record(dir.path(), &mut v);
        let v = about_the_tree(v);
        assert_eq!(v.len(), 2, "{v:#?}");
        assert!(v.iter().all(|m| m.starts_with("Article III: core/thing/src/lib.rs ")), "{v:#?}");
    }

    #[test]
    fn a_named_column_passes_only_in_its_own_file_and_table() {
        let (file, table, column, _) = NAMED_COLUMNS[0];
        let sql = format!("CREATE TABLE {table} (id TEXT, {column} BLOB);\n");
        let dir = tree(&[(file, sql.as_str()), ("core/other/migrations/0001.sql", sql.as_str())]);
        let mut v = Vec::new();
        no_account_table(dir.path(), &mut v);
        let v = about_the_tree(v);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].starts_with("Article III: core/other/migrations/0001.sql line 1"), "{}", v[0]);
    }

    /// The rules hold on the tree as it is: the gate is green before anything is planted.
    #[test]
    fn the_real_tree_keeps_no_account() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut v = Vec::new();
        no_account_table(root, &mut v);
        no_account_record(root, &mut v);
        assert_eq!(v, Vec::<String>::new());
    }
}
