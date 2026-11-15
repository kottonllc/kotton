// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Ed25519 verifying key, and the one Ed25519 check in the tree.
//!
//! [`VerifyingKey::from_bytes`] is the rule for a key: a key is the canonical encoding of a point
//! of the prime-order subgroup other than the identity (kotton-protocol states this rule for
//! every Ed25519 key and signature; kottonllc/kotton#565 placed the crate). 32 bytes that do
//! not decode, are not their point's canonical encoding, decode to the identity, or decode to
//! a point outside that subgroup are [`Refused`]. So a held [`VerifyingKey`] is one that
//! passed, one key has one encoding, and a set of them keyed by bytes is a set of keys.
//!
//! [`VerifyingKey::verify`] is the rule for a signature: `S` reduced, `R` canonical and not of
//! small order, and the equation without the cofactor. It is the library's strict check, and
//! this file is the one in the tree that calls it (`cargo xtask ed25519-check` holds that, the
//! relay's workspace included).
//!
//! The type offers nothing else: no conversion to or from the library's key, and a refusal
//! does not say which clause refused. [`Signature`] is the library's, which parses 64 bytes and
//! checks nothing of its own.
//!
//! This crate is beneath `kotton-pair`, so the pairing ceremony, `kotton-crypto` and every
//! crate above it, and the relay reach the same type. It builds for every target `kotton-pair`
//! does, `wasm32-unknown-unknown` among them.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use curve25519_dalek::traits::IsIdentity as _;

pub use ed25519_dalek::Signature;

/// What the rule says of bytes that are not a key, or a signature that does not check. It does
/// not say which clause refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("refused by the Ed25519 rule")
    }
}

impl std::error::Error for Refused {}

/// An Ed25519 public key that passed the rule. Equal, hashed and ordered by its bytes.
#[derive(Clone, Copy)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// `bytes` as a key, if they pass the rule: they decode to a curve point, they are that
    /// point's canonical encoding, the point is not the identity, and it is in the prime-order
    /// subgroup. Each is a test of its own, made of the decoded point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Refused> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Refused)?;
        let point = key.to_edwards();
        if point.compress().as_bytes() != bytes {
            return Err(Refused);
        }
        if point.is_identity() {
            return Err(Refused);
        }
        if !point.is_torsion_free() {
            return Err(Refused);
        }
        Ok(Self(key))
    }

    /// The key's 32 bytes: its canonical encoding.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Whether `signature` is this key's over `message`, by the rule: `S` reduced, `R`
    /// canonical and not of small order, and `[S]B = R + [k]A` without the cofactor.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Refused> {
        self.0.verify_strict(message, signature).map_err(|_| Refused)
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for VerifyingKey {}

impl Hash for VerifyingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialOrd for VerifyingKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerifyingKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifyingKey(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// Keys and signatures the rule refuses, each named with the clause it is for, for the tests
/// that hold a check to it and as the rule's vectors.
#[cfg(any(test, feature = "test-utils"))]
pub mod refused {
    use curve25519_dalek::scalar::{clamp_integer, Scalar};
    use ed25519_dalek::{Signature, Signer as _, SigningKey};
    use sha2::{Digest as _, Sha512};

    /// 64 hex digits as 32 bytes.
    const fn hex32(s: &str) -> [u8; 32] {
        const fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("not a lowercase hex digit"),
            }
        }
        let s = s.as_bytes();
        assert!(s.len() == 64);
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
            i += 1;
        }
        out
    }

    /// The canonical encodings of the eight points of small order: the identity, the point of
    /// order two, the two of order four and the four of order eight. Each decodes and is
    /// canonical; the subgroup clause refuses each.
    pub const SMALL_ORDER_KEYS: [[u8; 32]; 8] = [
        hex32("0100000000000000000000000000000000000000000000000000000000000000"),
        hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("0000000000000000000000000000000000000000000000000000000000000000"),
        hex32("0000000000000000000000000000000000000000000000000000000000000080"),
        hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    ];

    /// The encoding of the curve's identity point: a key of small order.
    pub const SMALL_ORDER_KEY: [u8; 32] = SMALL_ORDER_KEYS[0];

    /// The identity's three encodings other than its canonical one ([`SMALL_ORDER_KEY`]): `y = 1`
    /// with the sign bit set, and `y = 2^255 - 18` (`p + 1`) without and with it. Each decodes to
    /// the identity and is not its canonical encoding.
    pub const IDENTITY_OTHER_ENCODINGS: [[u8; 32]; 3] = [
        hex32("0100000000000000000000000000000000000000000000000000000000000080"),
        hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];

    /// `y = p + 3`, little-endian: an encoding of the point whose `y` is 3, which is on the curve
    /// and not of small order, but not that point's canonical encoding (`y` is not below `p`).
    /// The canonical clause refuses it, and so does the subgroup clause: the point is not in the
    /// prime-order subgroup, in which only the identity has a second encoding.
    pub const NON_CANONICAL_KEY: [u8; 32] =
        hex32("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

    /// `y = 2`: canonical, but no point of the curve has it. The decoding clause refuses it.
    pub const NOT_A_POINT: [u8; 32] =
        hex32("0200000000000000000000000000000000000000000000000000000000000000");

    /// The canonical encoding of a point of mixed order: the honest key of the seed `[42; 32]`
    /// plus a point of order eight. It decodes, is canonical and is not of small order; the
    /// subgroup clause refuses it.
    pub fn mixed_order_key() -> [u8; 32] {
        let prime = SigningKey::from_bytes(&[42; 32]).verifying_key().to_edwards();
        (prime + curve25519_dalek::constants::EIGHT_TORSION[1]).compress().to_bytes()
    }

    /// A signature for [`SMALL_ORDER_KEY`]: `R` the identity point, `S` zero.
    pub fn under_small_order_key() -> Signature {
        Signature::from_bytes(&under_small_order_key_bytes())
    }

    /// [`under_small_order_key`] as its 64 bytes.
    pub fn under_small_order_key_bytes() -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&SMALL_ORDER_KEY);
        sig
    }

    /// Two signatures by `key` over `message` the rule refuses: [`small_order_r`], and
    /// [`unreduced_s`].
    pub fn non_canonical(key: &SigningKey, message: &[u8]) -> [Signature; 2] {
        [small_order_r(key, message), unreduced_s(key, message)]
    }

    /// A signature by `key` over `message` whose `R` is the identity point, with the `S` that
    /// completes the equation. The clause on `R` refuses it.
    pub fn small_order_r(key: &SigningKey, message: &[u8]) -> Signature {
        with_r(key, message, SMALL_ORDER_KEY)
    }

    /// A signature by `key` over `message` whose `R` is `r`, with the `S` that completes the
    /// equation when `r` encodes the identity.
    pub fn with_r(key: &SigningKey, message: &[u8], r: [u8; 32]) -> Signature {
        let expanded: [u8; 64] = Sha512::digest(key.to_bytes()).into();
        let mut lower = [0u8; 32];
        lower.copy_from_slice(&expanded[..32]);
        let a = Scalar::from_bytes_mod_order(clamp_integer(lower));
        let k: [u8; 64] = Sha512::new()
            .chain_update(r)
            .chain_update(key.verifying_key().as_bytes())
            .chain_update(message)
            .finalize()
            .into();
        let s = Scalar::from_bytes_mod_order_wide(&k) * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(s.as_bytes());
        Signature::from_bytes(&sig)
    }

    /// `key`'s signature over `message` with the group order added to its `S`. The clause on
    /// `S` refuses it.
    pub fn unreduced_s(key: &SigningKey, message: &[u8]) -> Signature {
        let mut sig = key.sign(message).to_bytes();
        // The group order: one more than the largest scalar.
        let order_minus_one = (Scalar::ZERO - Scalar::ONE).to_bytes();
        let mut carry = 1u16;
        for i in 0..32 {
            let sum = sig[32 + i] as u16 + order_minus_one[i] as u16 + carry;
            sig[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        Signature::from_bytes(&sig)
    }
}

#[cfg(test)]
mod tests {
    use super::refused::*;
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }

    fn honest() -> VerifyingKey {
        VerifyingKey::from_bytes(signer().verifying_key().as_bytes()).expect("an honest key passes")
    }

    /// The vectors are the points they say: the eight small-order encodings are the canonical
    /// encodings of the curve's eight-torsion, the mixed-order key is canonical and of neither
    /// small nor prime order, the non-canonical key decodes to a point not of small order with
    /// another encoding, and the non-point does not decode.
    #[test]
    fn the_vectors_are_what_they_name() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let mut torsion: Vec<[u8; 32]> = EIGHT_TORSION.iter().map(|p| p.compress().to_bytes()).collect();
        let mut named = SMALL_ORDER_KEYS.to_vec();
        torsion.sort();
        named.sort();
        assert_eq!(torsion, named);

        let mixed = mixed_order_key();
        let point = CompressedEdwardsY(mixed).decompress().expect("the mixed-order key decodes");
        assert_eq!(point.compress().to_bytes(), mixed);
        assert!(!point.is_small_order());
        assert!(!point.is_torsion_free());

        let point = CompressedEdwardsY(NON_CANONICAL_KEY).decompress().expect("y = 3 is on the curve");
        assert!(!point.is_small_order());
        assert_ne!(point.compress().to_bytes(), NON_CANONICAL_KEY);

        assert!(CompressedEdwardsY(NOT_A_POINT).decompress().is_none());
    }

    /// Each clause of the key rule, by a case that refuses it. The identity and subgroup
    /// clauses each have a case that fails when that clause is removed from `from_bytes`. The
    /// re-encoding clause has none of its own, because each non-canonical encoding that decodes
    /// is the identity or outside the subgroup (`from_bytes_refuses_every_non_canonical_encoding`
    /// shows it); its cases fail when it is removed together with the identity clause, or with
    /// the subgroup clause weakened.
    #[test]
    fn from_bytes_refuses_each_clause() {
        let names = [
            "identity",
            "order two",
            "order four, x positive",
            "order four, x negative",
            "order eight, a",
            "order eight, a negated",
            "order eight, b",
            "order eight, b negated",
        ];
        let cases = names
            .iter()
            .map(|n| format!("small order: {n}"))
            .zip(SMALL_ORDER_KEYS)
            .chain(
                ["identity, y = 1 with the sign bit", "identity, y = p + 1", "identity, y = p + 1 with the sign bit"]
                    .map(String::from)
                    .into_iter()
                    .zip(IDENTITY_OTHER_ENCODINGS),
            )
            .chain([
                ("mixed order".to_string(), mixed_order_key()),
                ("not canonical".to_string(), NON_CANONICAL_KEY),
                ("not a point".to_string(), NOT_A_POINT),
            ]);
        let passed: Vec<String> = cases.filter(|(_, bytes)| VerifyingKey::from_bytes(bytes).is_ok()).map(|(n, _)| n).collect();
        assert!(passed.is_empty(), "the rule did not refuse: {passed:?}");
    }

    /// A point of the prime-order subgroup plus a point of order eight: canonical and not of
    /// small order, and refused.
    #[test]
    fn from_bytes_refuses_a_mixed_order_key() {
        assert_eq!(VerifyingKey::from_bytes(&mixed_order_key()), Err(Refused));
    }

    #[test]
    fn from_bytes_refuses_a_non_canonical_encoding_of_a_valid_point() {
        assert_eq!(VerifyingKey::from_bytes(&NON_CANONICAL_KEY), Err(Refused));
    }

    /// Every encoding that is not canonical: `y` from `p` to `2^255 - 1`, with either sign bit,
    /// and `x = 0` with the sign bit set. Each is refused, and each that decodes is the identity
    /// or outside the prime-order subgroup.
    #[test]
    fn from_bytes_refuses_every_non_canonical_encoding() {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let mut encodings = Vec::new();
        for k in 0..19u8 {
            // p + k, little-endian: p is 2^255 - 19.
            let mut y = [0xffu8; 32];
            y[0] = 0xed + k;
            y[31] = 0x7f;
            encodings.push(y);
            y[31] |= 0x80;
            encodings.push(y);
        }
        let mut one = [0u8; 32];
        one[0] = 1;
        one[31] = 0x80;
        let mut minus_one = SMALL_ORDER_KEYS[1];
        minus_one[31] |= 0x80;
        encodings.extend([one, minus_one]);
        for bytes in encodings {
            assert_eq!(VerifyingKey::from_bytes(&bytes), Err(Refused), "{bytes:02x?}");
            if let Some(point) = CompressedEdwardsY(bytes).decompress() {
                assert_ne!(point.compress().to_bytes(), bytes);
                assert!(point.is_identity() || !point.is_torsion_free(), "{bytes:02x?}");
            }
        }
    }

    #[test]
    fn from_bytes_refuses_the_identity() {
        assert_eq!(VerifyingKey::from_bytes(&SMALL_ORDER_KEY), Err(Refused));
    }

    /// The identity's other encodings: `y = 1` with the sign bit, and `p + 1` with and without
    /// it.
    #[test]
    fn from_bytes_refuses_each_other_encoding_of_the_identity() {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        for bytes in IDENTITY_OTHER_ENCODINGS {
            let point = CompressedEdwardsY(bytes).decompress().expect("decodes");
            assert!(point.is_identity(), "{bytes:02x?}");
            assert_ne!(point.compress().to_bytes(), bytes);
            assert_eq!(VerifyingKey::from_bytes(&bytes), Err(Refused), "{bytes:02x?}");
        }
    }

    /// A key of small order other than the identity: the point of order eight.
    #[test]
    fn from_bytes_refuses_a_small_order_key() {
        assert_eq!(VerifyingKey::from_bytes(&SMALL_ORDER_KEYS[4]), Err(Refused));
    }

    #[test]
    fn from_bytes_refuses_bytes_that_are_not_a_point() {
        assert_eq!(VerifyingKey::from_bytes(&NOT_A_POINT), Err(Refused));
    }

    #[test]
    fn an_honest_key_and_signature_pass_and_a_wrong_message_fails() {
        let key = honest();
        assert_eq!(key.as_bytes(), signer().verifying_key().as_bytes());
        let message = b"a message";
        let sig = signer().sign(message);
        assert_eq!(key.verify(message, &sig), Ok(()));
        assert_eq!(key.verify(b"another message", &sig), Err(Refused));
    }

    /// `R` the identity, a point of small order, with the `S` that completes the equation.
    #[test]
    fn verify_refuses_a_small_order_r() {
        let message = b"a message";
        assert_eq!(honest().verify(message, &small_order_r(&signer(), message)), Err(Refused));
    }

    /// `R` an encoding of the identity other than its canonical one, with the `S` that would
    /// complete the equation, and with `S` zero.
    #[test]
    fn verify_refuses_an_r_that_encodes_the_identity_otherwise() {
        let message = b"a message";
        for r in IDENTITY_OTHER_ENCODINGS {
            assert_eq!(honest().verify(message, &with_r(&signer(), message, r)), Err(Refused), "{r:02x?}");
            let mut zero_s = [0u8; 64];
            zero_s[..32].copy_from_slice(&r);
            assert_eq!(honest().verify(message, &Signature::from_bytes(&zero_s)), Err(Refused), "{r:02x?}");
        }
    }

    #[test]
    fn verify_refuses_an_unreduced_s() {
        let message = b"a message";
        assert_eq!(honest().verify(message, &unreduced_s(&signer(), message)), Err(Refused));
    }

    #[test]
    fn verify_refuses_both_non_canonical_signatures() {
        let message = b"a message";
        for sig in non_canonical(&signer(), message) {
            assert_eq!(honest().verify(message, &sig), Err(Refused));
        }
    }

    /// Equal, hashed and ordered by bytes, so a set of keys keyed by bytes is a set of keys.
    #[test]
    fn keys_compare_by_bytes() {
        use std::collections::HashSet;
        let a = honest();
        let b = VerifyingKey::from_bytes(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()).unwrap();
        assert_eq!(a, VerifyingKey::from_bytes(a.as_bytes()).unwrap());
        assert_ne!(a, b);
        assert_eq!(a.cmp(&b), a.as_bytes().cmp(b.as_bytes()));
        let set: HashSet<VerifyingKey> = [a, b, a].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    /// The library's other check accepts what the rule refuses: a signature under the identity
    /// key with `R` the identity and `S` zero, over any message, and a signature whose `R` is the
    /// identity by an honest key. `from_bytes` refuses the first key, and `verify` refuses the
    /// second signature.
    ///
    /// The tree's one exemption from the workspace's refusal of the library's other check,
    /// named in `cargo xtask ed25519-check`: this test holds the difference between the two
    /// checks, so it makes the other one.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn the_library_s_other_check_accepts_what_the_rule_refuses() {
        use ed25519_dalek::Verifier as _;
        let identity = ed25519_dalek::VerifyingKey::from_bytes(&SMALL_ORDER_KEY).expect("the identity point decodes");
        identity
            .verify(b"any message", &under_small_order_key())
            .expect("the other check accepts a signature under the identity key");
        assert_eq!(VerifyingKey::from_bytes(&SMALL_ORDER_KEY), Err(Refused));

        let message = b"a message";
        let sig = small_order_r(&signer(), message);
        signer().verifying_key().verify(message, &sig).expect("the other check accepts R of small order");
        assert_eq!(honest().verify(message, &sig), Err(Refused));
    }
}
