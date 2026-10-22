// SPDX-License-Identifier: AGPL-3.0-or-later
//! Crockford base32 — the project's one encoding for machine-generated
//! identifiers that a human might have to read, type, or see in a path.
//!
//! Two callers with different reasons for wanting the same alphabet:
//!
//! - **Pairing connection codes** (RFC-0040 §3) — typed by a human off one
//!   screen onto another, so the alphabet must exclude `i`/`l`/`o`/`u` and the
//!   decoder must forgive the substitutions people make anyway.
//! - **Blinded object keys** (RFC-0044) — never typed, but they become path
//!   components, so they must be filesystem-safe and as short as possible
//!   against `MAX_PATH`. Base32 gives 26 characters for 16 bytes where hex
//!   would give 32.
//!
//! The alphabet is lowercase. Case is not significant on decode, so a key is
//! stable across a case-insensitive filesystem.

/// Crockford's alphabet: digits then consonants, with `i`, `l`, `o`, and `u`
/// omitted because they are the characters people misread.
const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Encode bytes as Crockford base32. Output length is `ceil(len * 8 / 5)`.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buf >> bits) & 0x1f) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(CROCKFORD[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Decode Crockford base32, tolerating case, the `i→1 l→1 o→0` look-alikes, and
/// any `-`/space grouping a human might introduce.
///
/// Returns `None` on a character that is not recoverable to a symbol.
pub fn decode(code: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(code.len() * 5 / 8 + 1);
    let (mut buf, mut bits) = (0u32, 0u32);
    for ch in code.chars() {
        let c = ch.to_ascii_lowercase();
        if c == '-' || c == ' ' {
            continue;
        }
        // Crockford's documented substitutions for the omitted characters.
        let c = match c {
            'i' | 'l' => '1',
            'o' => '0',
            other => other,
        };
        let v = CROCKFORD.iter().position(|&x| x as char == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for case in [
            vec![],
            vec![0u8],
            vec![0xff, 0x00, 0xff],
            (0u8..=255).collect::<Vec<_>>(),
        ] {
            assert_eq!(decode(&encode(&case)).unwrap(), case, "round trip");
        }
    }

    /// 16 bytes must encode to exactly 26 characters — RFC-0044 budgets path
    /// depth against `MAX_PATH` on that number.
    #[test]
    fn sixteen_bytes_is_twenty_six_chars() {
        assert_eq!(encode(&[0xab; 16]).len(), 26);
    }

    #[test]
    fn tolerates_look_alikes_and_grouping() {
        let encoded = encode(&[0x12, 0x34, 0x56]);
        let mangled = encoded.to_uppercase().replace('1', "I");
        assert_eq!(decode(&mangled).unwrap(), decode(&encoded).unwrap());
        assert_eq!(
            decode(&format!("{}-{}", &encoded[..2], &encoded[2..])).unwrap(),
            decode(&encoded).unwrap(),
        );
    }

    #[test]
    fn rejects_a_character_outside_the_alphabet() {
        assert!(decode("abc!def").is_none());
    }
}
