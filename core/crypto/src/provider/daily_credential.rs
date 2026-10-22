// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daily unlock credential — generating one, and judging one (RFC-0053).
//!
//! This is the tier-2 credential from RFC-0053: what a person supplies once per
//! lock boundary to open the device key, so that the mnemonic goes back to being
//! the rarely-handled root it is meant to be. It is stretched with Argon2id and
//! seals the operational roots ([`crate::vault`]); this module decides only
//! **what may be used as one**.
//!
//! ## The honest position on strength
//!
//! An attacker who copies `vault.json` guesses offline, at their own rate, where
//! no counter of Kotton's is in the room. So the credential's own entropy is the
//! defence, and the two paths here are not equally knowable:
//!
//! - [`generate`] draws words uniformly from the 2048-word BIP-39 list. Its
//!   entropy is **exactly** `words × 11` bits. Nothing is estimated.
//! - [`assess`] on a passphrase the user wrote scores it the way an attacker
//!   searches: in **likelihood order** — frequency-ranked dictionaries, l33t
//!   substitutions, repeats, sequences, keyboard walks, dates, then brute force
//!   for the remainder. That is zxcvbn, taken as a dependency on 2026-09-06
//!   (`TASK-the-entropy-estimator-scores-a-dictionary-password-at-83-bits`).
//!   Until then the fallback was length times the log of the character space,
//!   which models an attacker enumerating the charset uniformly; no attacker
//!   does, and it scored `passwordpassword1` at 83 bits against a bar of 50.
//!   Now it is 13, and `Tr0ub4dor&3xyz` is 44 and refused.
//!
//! The estimate is still a **ceiling on what may be claimed**, not a floor on
//! what an attacker needs: zxcvbn knows the public dictionaries and patterns,
//! not a person's own name, their other passwords, or a famous phrase that is
//! in a cracker's list but not in its own. That is why generation stays the
//! offered path rather than merely an option, and why the number attached to a
//! user-chosen phrase is never shown as a total.

use std::collections::HashSet;

use bip39::Language;
use kotton_common::crypto::daily_credential as policy;
use rand::rngs::OsRng;
use rand::RngCore;

/// Why a candidate credential was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum Weakness {
    /// Shorter than [`policy::MIN_CHARS`].
    TooShort { chars: usize, needed: usize },
    /// Too few distinct characters — repetition does not buy entropy.
    TooRepetitive { unique: usize, needed: usize },
    /// Clears the floor tests but still falls short of the required entropy.
    NotEnoughEntropy { bits: f64, needed: f64 },
    /// Cheap for an attacker searching in likelihood order — a dictionary word,
    /// a keyboard walk, a date, a repeat — and the estimator can say which.
    /// `why` is the pattern in plain words, for the person who typed it.
    Guessable { bits: f64, needed: f64, why: String },
    /// Digits only, where nothing outside Kotton limits the guess rate. This is
    /// its own variant because it is the case RFC-0053 names explicitly and the
    /// one a user arrives at by habit — every other lock they own takes a PIN.
    ShortPinWithoutHardwareLimit { needed_bits: f64 },
}

/// So a `Weakness` can ride inside `anyhow::Error` and be recovered with
/// `downcast_ref` rather than by matching on its message. `create_user` refuses
/// weak credentials deep in `core/device`, and the daemon two layers up has to
/// tell "ask them again" from "something broke" — which is a question about the
/// error's type, and was answerable only by parsing prose until this impl.
impl std::error::Error for Weakness {}

impl std::fmt::Display for Weakness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { chars, needed } => write!(
                f,
                "too short — {chars} characters, at least {needed} needed"
            ),
            Self::TooRepetitive { unique, needed } => write!(
                f,
                "too repetitive — {unique} different characters, at least {needed} needed"
            ),
            Self::NotEnoughEntropy { bits, needed } => write!(
                f,
                "not strong enough — about {bits:.0} bits, at least {needed:.0} needed"
            ),
            Self::Guessable { bits, needed, why } => write!(
                f,
                "too easy to guess — {why}; about {bits:.0} bits, at least {needed:.0} needed"
            ),
            Self::ShortPinWithoutHardwareLimit { needed_bits } => write!(
                f,
                "a digits-only PIN is only safe where hardware counts failed attempts, \
                 and this device has none — a PIN long enough to stand alone would need \
                 about {} digits, so use a passphrase instead",
                // Each digit carries log2(10) bits.
                (needed_bits / std::f64::consts::LOG2_10).ceil() as u32
            ),
        }
    }
}

/// Generate a passphrase of [`policy::GENERATED_WORDS`] words.
///
/// Uniform over the 2048-word BIP-39 list, drawn from the OS CSPRNG with
/// rejection sampling so the modulo bias of `% 2048` cannot skew the draw.
///
/// **Drawn without replacement**, which is a correctness requirement and not a
/// nicety: [`entropy_bits`] credits *distinct* words, because it cannot tell a
/// randomly-drawn duplicate from a user typing one word five times. A generator
/// that could repeat would therefore occasionally emit a phrase that fails
/// Kotton's own bar — which is exactly what the tests caught. Entropy is
/// `log2(2048 × 2047 × … )` ≈ 54.997 bits for five words, a hair under the 55
/// that `distinct × 11` credits it with; the 0.004-bit difference is noted for
/// honesty rather than because it matters.
///
/// Words are hyphen-joined because a space-separated phrase is the shape of the
/// 24-word recovery mnemonic, and these two secrets must never be mistaken for
/// one another — this one is typed daily, that one is written down and kept.
/// The BIP-39 English list, for anything that needs words a person can say
/// aloud and type back without ambiguity — a pairing code (RFC-0022) as much
/// as a passphrase.
pub fn spoken_word_list() -> &'static [&'static str] {
    Language::English.word_list()
}

pub fn generate() -> String {
    let list = Language::English.word_list();
    let mut picked: Vec<usize> = Vec::with_capacity(policy::GENERATED_WORDS);
    while picked.len() < policy::GENERATED_WORDS {
        let index = uniform_index(list.len());
        if !picked.contains(&index) {
            picked.push(index);
        }
    }
    picked
        .into_iter()
        .map(|i| list[i])
        .collect::<Vec<_>>()
        .join("-")
}

/// A uniform index in `0..n` from the OS CSPRNG, without modulo bias.
///
/// `n` is 2048 here, so `u32::MAX + 1` is an exact multiple of it and the
/// rejection branch is unreachable in practice. It is written anyway because
/// the correctness of the entropy claim should not depend on the list length
/// happening to be a power of two.
fn uniform_index(n: usize) -> usize {
    let n = n as u64;
    let limit = u64::from(u32::MAX) + 1;
    let ceiling = limit - (limit % n);
    loop {
        let draw = u64::from(OsRng.next_u32());
        if draw < ceiling {
            return (draw % n) as usize;
        }
    }
}

/// The entropy Kotton is willing to credit `candidate` with, in bits.
///
/// Two regimes, and the difference matters more than either number:
///
/// - **Diceware-shaped** — three or more distinct words, every one of them on
///   the BIP-39 list — is credited `words × 11` bits. Sound because the only
///   way to produce that shape is to draw from the list, and an attacker who
///   guesses that is what happened searches exactly that space.
/// - **Anything else** gets `length × log2(alphabet)`, an upper bound on a
///   random string of that shape and an over-estimate for any string a human
///   composed. It is used only as a floor test, never reported as a total.
///
/// Repeated words are counted once: `abandon-abandon-abandon-abandon-abandon`
/// is one draw, not five.
pub fn entropy_bits(candidate: &str) -> f64 {
    if let Some(bits) = wordlist_entropy_bits(candidate) {
        return bits;
    }
    let searched = guessability(candidate).0;
    match pin_space_bits(candidate) {
        // A run of digits is at most its space, and usually far less: a date or
        // a sequence is found long before the space is exhausted.
        Some(space) => searched.min(space),
        None => searched,
    }
}

/// `log2(10^len)` for a digits-only candidate — the size of the space an
/// attacker must cover when they cannot choose the order they cover it in.
///
/// That is the counted case: hardware that limits attempts (RFC-0053 step 8)
/// gives the attacker a budget, not a search, and DEC-0046 derived
/// [`policy::MIN_ENTROPY_BITS_HARDWARE_LIMITED`] from exactly this number for six
/// digits (19.93). `None` for anything that is not all digits.
fn pin_space_bits(candidate: &str) -> Option<f64> {
    if candidate.is_empty() || !candidate.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(candidate.chars().count() as f64 * 10f64.log2())
}

/// Whether `required_bits` is the bar for an attacker whose attempts are
/// counted. The bar *is* the attacker model — [`required_entropy_bits`] chooses
/// it from the same platform probe — so a bar at or below the hardware-limited
/// constant means something outside Kotton counts failures, and a credential
/// is then measured by its space rather than by search order (see
/// [`pin_space_bits`]).
fn attempts_are_counted(required_bits: f64) -> bool {
    required_bits <= policy::MIN_ENTROPY_BITS_HARDWARE_LIMITED
}

/// Bits of work for an attacker who searches in **likelihood order**, and the
/// pattern that made the candidate cheap, if one did.
///
/// This is zxcvbn's estimate: the cost of the cheapest way to reach the
/// candidate through dictionaries (ranked by frequency), l33t substitutions,
/// repeats, sequences, keyboard walks, dates, and brute force for whatever is
/// left — the search a real cracker runs, in the order it runs it. Until
/// 2026-09-06 the fallback was length times the log of the character space,
/// which models an attacker enumerating the charset uniformly; no attacker
/// does, and it called `passwordpassword1` 83 bits
/// (`TASK-the-entropy-estimator-scores-a-dictionary-password-at-83-bits`).
///
/// `guesses` converts to bits as `log2(guesses)`. The estimate is a *ceiling on
/// what may be claimed*, not a floor on what an attacker needs: zxcvbn knows the
/// common dictionaries and patterns, not the person's own name or a phrase they
/// reused elsewhere, which is why generation stays the offered path.
fn guessability(candidate: &str) -> (f64, Option<String>) {
    let estimate = zxcvbn::zxcvbn(candidate, &[]);
    let bits = estimate.guesses_log10() * std::f64::consts::LOG2_10;
    let why = estimate
        .feedback()
        .and_then(|f| f.warning())
        .map(|w| w.to_string());
    (bits, why)
}

/// `Some(bits)` when `candidate` is a diceware-shaped phrase drawn from the
/// BIP-39 list, `None` when it is anything else.
fn wordlist_entropy_bits(candidate: &str) -> Option<f64> {
    let list = Language::English.word_list();
    let words: Vec<&str> = candidate
        .split(|c: char| c == '-' || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .collect();

    if words.len() < 3 {
        return None;
    }
    let lowered: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
    if !lowered.iter().all(|w| list.contains(&w.as_str())) {
        return None;
    }
    // Distinct draws only.
    let distinct = lowered.iter().collect::<HashSet<_>>().len();
    Some(distinct as f64 * policy::BITS_PER_WORD)
}


/// Whether `candidate` may be used as the daily credential, given how much
/// entropy this device requires.
///
/// `required_bits` comes from the caller's reading of
/// `kotton_sys::secret::attempt_limiting` — the rule is "a short PIN only
/// where hardware can count failures", so the bar is a property of the device,
/// not of this function.
/// The entropy this device requires of a daily credential.
///
/// Reads the platform's attempt-limiting capability rather than deciding by
/// platform name: the rule (`DEC-0046`) is that a short credential is
/// defensible only where hardware counts failures, and the hardware is what
/// answers. Today nothing reports `Hardware`, so the bar is
/// [`policy::MIN_ENTROPY_BITS`] everywhere.
///
/// **Lives here because `assess` is the only thing it is ever passed to.** It
/// stood in `core/session::lock_policy` with a verbatim second copy in the CLI —
/// two implementations of one bar, which is the drift this repository keeps
/// finding, and which was reachable here the whole time: `core/crypto` already
/// depends on both crates it reads.
pub fn required_entropy_bits() -> f64 {
    required_entropy_bits_for(kotton_sys::secret::attempt_limiting())
}

/// The bar for a credential whose guesses are limited as `limiting` says.
///
/// The form the daemon uses once a vault is bound: it asks the user's binding
/// what counts (`attempt_limiting_for`) and passes the answer here, so a
/// six-digit PIN clears the bar exactly where a TPM or enclave with an auth
/// policy on the key would refuse the seventh wrong one, and nowhere else.
pub fn required_entropy_bits_for(limiting: kotton_sys::secret::AttemptLimiting) -> f64 {
    match limiting {
        kotton_sys::secret::AttemptLimiting::Hardware => policy::MIN_ENTROPY_BITS_HARDWARE_LIMITED,
        kotton_sys::secret::AttemptLimiting::None => policy::MIN_ENTROPY_BITS,
    }
}

pub fn assess(candidate: &str, required_bits: f64) -> Result<(), Weakness> {
    // Under a counted budget a PIN is worth its space — the case DEC-0046 sized
    // the lower bar for. Everything else, and every PIN where nothing counts
    // attempts, is worth what an attacker searching in likelihood order pays.
    let bits = match pin_space_bits(candidate) {
        Some(space) if attempts_are_counted(required_bits) => space,
        _ => entropy_bits(candidate),
    };
    if bits >= required_bits {
        return Ok(());
    }

    // Name the digits-only case for what it is. A user who typed six digits did
    // not fail a length check, they reached for the credential every other lock
    // they own accepts, and being told "too short" invites them to type eight.
    if !candidate.is_empty() && candidate.chars().all(|c| c.is_ascii_digit()) {
        return Err(Weakness::ShortPinWithoutHardwareLimit {
            needed_bits: required_bits,
        });
    }

    let chars = candidate.chars().count();
    if chars < policy::MIN_CHARS {
        return Err(Weakness::TooShort {
            chars,
            needed: policy::MIN_CHARS,
        });
    }
    let unique = candidate.chars().collect::<HashSet<_>>().len();
    if unique < policy::MIN_UNIQUE_CHARS {
        return Err(Weakness::TooRepetitive {
            unique,
            needed: policy::MIN_UNIQUE_CHARS,
        });
    }
    // Say *why* it is cheap when the estimator can: "a top-100 common password"
    // is a different message from "not long enough", and the one a person can
    // act on.
    if let (_, Some(why)) = guessability(candidate) {
        return Err(Weakness::Guessable {
            bits,
            needed: required_bits,
            why,
        });
    }
    Err(Weakness::NotEnoughEntropy {
        bits,
        needed: required_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;


    const BAR: f64 = policy::MIN_ENTROPY_BITS;

    /// Ran at 20 iterations first and caught a duplicate draw
    /// (`cool-gift-rib-test-test`, credited 44 bits against a 50-bit bar), which
    /// is why `generate` now samples without replacement. Kept at a count high
    /// enough to have found that: the birthday odds of a repeat in five draws
    /// from 2048 are ~0.5%, so a handful of iterations would pass for a long
    /// time before failing on someone else's machine.
    #[test]
    fn a_generated_passphrase_clears_the_bar_it_was_sized_for() {
        for _ in 0..500 {
            let phrase = generate();
            assert_eq!(phrase.split('-').count(), policy::GENERATED_WORDS);
            assert!(
                assess(&phrase, BAR).is_ok(),
                "generated passphrase {phrase} must clear its own bar"
            );
        }
    }

    /// The distinctness the bar depends on, asserted directly rather than left
    /// to the probabilistic test above.
    #[test]
    fn generated_words_are_never_repeated() {
        for _ in 0..500 {
            let phrase = generate();
            let words: HashSet<&str> = phrase.split('-').collect();
            assert_eq!(
                words.len(),
                policy::GENERATED_WORDS,
                "repeated word in {phrase}"
            );
        }
    }

    /// The generator must actually vary. A stuck CSPRNG or an index bug would
    /// otherwise ship a constant secret that still passes every other test.
    #[test]
    fn generated_passphrases_differ() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
    }

    /// Hyphens, not spaces — a space-separated phrase looks like the 24-word
    /// recovery mnemonic, and confusing the two is a real hazard.
    #[test]
    fn generated_passphrases_are_not_shaped_like_the_recovery_mnemonic() {
        assert!(!generate().contains(' '));
    }

    /// The case RFC-0053 exists to close, and the one a user reaches for by
    /// habit. It must be refused *by name*, not as a length complaint.
    #[test]
    fn a_six_digit_pin_is_refused_where_nothing_counts_failures() {
        assert_eq!(
            assess("135790", BAR),
            Err(Weakness::ShortPinWithoutHardwareLimit { needed_bits: BAR })
        );
        // Even a long one: digits alone cannot reach the bar at any usable
        // length, and saying "too short" would invite an eight-digit retry.
        assert!(matches!(
            assess("13579024", BAR),
            Err(Weakness::ShortPinWithoutHardwareLimit { .. })
        ));
    }

    /// The same PIN is fine once hardware counts the failures — which is the
    /// whole point of expressing this as a bar rather than a ban.
    #[test]
    fn a_six_digit_pin_is_accepted_where_hardware_counts_failures() {
        assert!(assess("135790", policy::MIN_ENTROPY_BITS_HARDWARE_LIMITED).is_ok());
    }

    #[test]
    fn repetition_does_not_buy_length() {
        assert!(matches!(
            assess("aaaaaaaaaaaaaaaaaaaaaaaa", BAR),
            Err(Weakness::TooRepetitive { .. })
        ));
        // Nor does repeating a wordlist word: five draws of the same word is
        // one draw.
        assert!(
            entropy_bits("abandon-abandon-abandon-abandon-abandon")
                < policy::BITS_PER_WORD * 2.0
        );
    }

    #[test]
    fn short_things_are_refused() {
        assert!(matches!(assess("hunter2!", BAR), Err(Weakness::TooShort { .. })));
    }

    #[test]
    fn wordlist_phrases_are_credited_per_word() {
        // Three distinct BIP-39 words = 33 bits — under the bar, so the shape
        // alone is not a pass.
        let three = "abandon-ability-able";
        assert!((entropy_bits(three) - 33.0).abs() < f64::EPSILON);
        assert!(assess(three, BAR).is_err());

        // Five clears it.
        let five = "abandon-ability-able-about-above";
        assert!((entropy_bits(five) - 55.0).abs() < f64::EPSILON);
        assert!(assess(five, BAR).is_ok());
    }

    /// A phrase that merely *looks* like diceware but is not on the list falls
    /// back to the character estimate rather than being credited 11 bits a word.
    #[test]
    fn made_up_words_are_not_credited_as_wordlist_draws() {
        assert!(wordlist_entropy_bits("zzzz-yyyy-xxxx-wwww-vvvv").is_none());
    }

    /// Space-separated wordlist phrases still count — a user pasting a phrase
    /// with spaces should not be told it is weak when it is not.
    #[test]
    fn spaces_are_accepted_in_a_wordlist_phrase() {
        assert!(assess("abandon ability able about above", BAR).is_ok());
    }

    /// Documents the known limit rather than hiding it: this passes, and a real
    /// estimator would not credit it nearly as much. Recorded so the gap is
    /// visible in the suite and not only in prose.
    #[test]
    fn a_human_chosen_phrase_is_scored_by_search_order_not_charset() {
        // `Tr0ub4dor&3xyz` cleared the old charset model at ~90 bits and was
        // pinned here as a known-wrong pass. Search order prices the l33t word
        // plus a short tail at about 44 bits, under the bar.
        let bits = entropy_bits("Tr0ub4dor&3xyz");
        assert!(bits < BAR, "search order should price this under the bar, got {bits:.1}");
        assert!(assess("Tr0ub4dor&3xyz", BAR).is_err());
    }

    /// The six candidates the record measured on 2026-08-29, when four of them
    /// passed a 50-bit bar. Every dictionary, repeat, and keyboard-walk one is
    /// now well under it; only the phrase of uncommon words clears
    /// (TASK-the-entropy-estimator-scores-a-dictionary-password-at-83-bits).
    #[test]
    fn dictionary_passwords_are_refused_regardless_of_length() {
        for weak in [
            "iloveyoubaby2026forever",
            "Summer2026!Summer2026!",
            "passwordpassword1",
            "qwertyuiopasdfgh",
            "aaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let bits = entropy_bits(weak);
            assert!(bits < BAR, "{weak} scored {bits:.1}, over the bar");
            assert!(assess(weak, BAR).is_err(), "{weak} must be refused");
        }
        assert!(assess("canyon ember thistle plover quartz", BAR).is_ok());
        // The refusal names the pattern when there is one.
        assert!(matches!(
            assess("passwordpassword1", BAR),
            Err(Weakness::Guessable { .. })
        ));
    }

    /// Where hardware counts attempts, a PIN is worth its space (DEC-0046), but
    /// a *word* is still worth what search order pays: a counted budget of a
    /// few tries is exactly enough to reach the top of the dictionary.
    #[test]
    fn a_counted_budget_measures_a_pin_by_space_and_a_word_by_search_order() {
        let counted = policy::MIN_ENTROPY_BITS_HARDWARE_LIMITED;
        assert!(assess("135790", counted).is_ok(), "six digits are their space, 19.93 bits");
        assert!(assess("password", counted).is_err(), "the first guess in any list");
    }
}


