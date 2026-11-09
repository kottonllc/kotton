// SPDX-License-Identifier: AGPL-3.0-or-later
//! The JSON Canonicalization Scheme (RFC 8785), for what a schema's digest is taken over.
//!
//! A schema's version is BLAKE3 over its definition serialised this way (the protocol's
//! decision *A schema is named by the key that publishes it*), so two implementations that
//! hold the same definition write the same digest. The rules, as RFC 8785 gives them:
//!
//! - an object's members are sorted by their keys as sequences of UTF-16 code units
//!   (section 3.2.3), and an array keeps its order;
//! - no whitespace anywhere;
//! - a string is escaped as section 3.2.2.2 says: `"` and `\` with a backslash, the five
//!   control characters that have a short form as `\b`, `\t`, `\n`, `\f` and `\r`, every
//!   other character below U+0020 as `\u00xx` with lowercase hex, and everything else,
//!   non-ASCII included, written raw;
//! - a number that is an integer is written as its decimal digits, with a leading `-` when
//!   negative;
//! - `true`, `false` and `null` as themselves.
//!
//! **A number that is not an integer is refused**, naming the member it sits in. RFC 8785
//! writes a non-integer as ECMAScript's shortest round-tripping decimal, an algorithm this
//! crate would otherwise carry only for a field whose default is a float, and the decision
//! needs no float: a definition's own members are strings, an integer, booleans and lists of
//! objects. A schema whose default is a float has no digest, and so no version, until the
//! protocol says how one is written; the refusal is the honest answer, and it names the field.

use serde_json::Value;
use std::fmt::Write as _;
use thiserror::Error;

/// Why a value has no canonical form.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A number at `path` is not an integer (module doc).
    #[error("`{path}` is {value}, not an integer: the canonical form (RFC 8785) of a non-integer is not written here, so the definition has no digest")]
    NonInteger { path: String, value: String },
}

/// The canonical form of `value`, as RFC 8785 writes it (module doc).
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out, &mut String::from("$"))?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String, path: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                write!(out, "{i}").expect("writing to a String");
            } else if let Some(u) = n.as_u64() {
                write!(out, "{u}").expect("writing to a String");
            } else {
                return Err(CanonicalError::NonInteger { path: path.clone(), value: n.to_string() });
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let len = path.len();
                write!(path, "[{i}]").expect("writing to a String");
                write_value(item, out, path)?;
                path.truncate(len);
            }
            out.push(']');
        }
        Value::Object(members) => {
            // Sorted by the key's UTF-16 code units, not its UTF-8 bytes: the two orders
            // differ where a key holds a character above the Basic Multilingual Plane.
            let mut keys: Vec<(&String, Vec<u16>)> =
                members.keys().map(|k| (k, k.encode_utf16().collect())).collect();
            keys.sort_by(|a, b| a.1.cmp(&b.1));
            out.push('{');
            for (i, (key, _)) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                let len = path.len();
                write!(path, ".{key}").expect("writing to a String");
                write_value(&members[*key], out, path)?;
                path.truncate(len);
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A string as RFC 8785 section 3.2.2.2 escapes it.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32).expect("writing to a String"),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn members_are_sorted_by_utf16_code_units() {
        // RFC 8785 section 3.2.3's example: the keys, in the order the scheme puts them.
        let input = r#"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        let value: Value = serde_json::from_str(input).unwrap();
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(canonical_json(&value).unwrap(), expected);
    }

    #[test]
    fn strings_are_escaped_as_the_scheme_says() {
        let value = json!("a\"b\\c\u{8}\t\n\u{c}\r\u{1}\u{1f}\u{7f}\u{e9} \u{1f600}/");
        assert_eq!(
            canonical_json(&value).unwrap(),
            "\"a\\\"b\\\\c\\b\\t\\n\\f\\r\\u0001\\u001f\u{7f}\u{e9} \u{1f600}/\""
        );
    }

    #[test]
    fn no_whitespace_and_arrays_keep_their_order() {
        let value = json!({ "b": [3, 1, 2], "a": { "z": null, "y": true, "x": false }, "n": -7 });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":{"x":false,"y":true,"z":null},"b":[3,1,2],"n":-7}"#
        );
        assert_eq!(canonical_json(&json!([])).unwrap(), "[]");
        assert_eq!(canonical_json(&json!({})).unwrap(), "{}");
        assert_eq!(canonical_json(&json!(u64::MAX)).unwrap(), "18446744073709551615");
        assert_eq!(canonical_json(&json!(i64::MIN)).unwrap(), "-9223372036854775808");
    }

    #[test]
    fn a_non_integer_is_refused_by_the_member_it_sits_in() {
        let value = json!({ "fields": [{ "name": "ratio", "default": 0.5 }] });
        let err = canonical_json(&value).unwrap_err();
        assert_eq!(err, CanonicalError::NonInteger { path: "$.fields[0].default".into(), value: "0.5".into() });
        // `1.0` parsed from text is a float to serde_json, and so to this.
        let value: Value = serde_json::from_str(r#"{"x": 1.0}"#).unwrap();
        assert!(matches!(canonical_json(&value), Err(CanonicalError::NonInteger { path, .. }) if path == "$.x"));
        let value: Value = serde_json::from_str("1e3").unwrap();
        assert!(matches!(canonical_json(&value), Err(CanonicalError::NonInteger { path, .. }) if path == "$"));
    }
}
