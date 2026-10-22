// SPDX-License-Identifier: AGPL-3.0-or-later
//! A relay is created for its operator's key, and the operator set is never
//! empty (RFC-0084, the amendment of 2026-10-01: V18, V19, forks 3 and 4).
//!
//! In process, as the state directory's owner: `create` and the offline
//! operator verbs as `type_verb` runs them for the owner. The start's refusal,
//! the line a start prints and the exclusion between a running relay and
//! `create` are the suite's (`tests/tests/suite/instance.rs`), against the
//! binary.

use std::path::Path;

use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

use crate::admission::{self, Revoke};
use crate::identity::{RelayKey, KEY_FILE};
use crate::instance::{self, StateLock};
use crate::rule_tests::state_dir;

const OPERATOR: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// Every file in `dir` and what it holds, sorted — the instrument for
/// *changes nothing*.
fn everything(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut all: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap_or_default()))
        .collect();
    all.sort();
    all
}

fn operators(dir: &Path) -> Vec<String> {
    admission::read_operators(dir).unwrap()
}

/// **`create` makes the relay's state, its key and its first operator, and
/// returns its line naming that key** — the line `main` prints as the verb's
/// last output, with the address it announces.
#[test]
fn an_instance_is_created_for_its_operators_key_and_creation_prints_its_line() {
    let dir = state_dir();
    let line = instance::create(&dir, OPERATOR, "http://relay.example:7700").unwrap();
    assert_eq!(operators(&dir), [OPERATOR], "the key it was created for is its first operator");
    let key = RelayKey::open_existing(&dir).unwrap().expect("its own key is made at creation");
    assert_eq!(
        line,
        InstanceLine { kind: OperatedService::Relay, hint: "http://relay.example:7700".into(), key: key.public() }
    );
    assert_eq!(InstanceLine::parse(&line.to_text()).unwrap(), line, "the line reads back");
    assert!(!dir.join("rule.json").exists(), "creation sets no rule: the operator's first set does");
    let _ = std::fs::remove_dir_all(dir);
}

/// **A second `create`, with another key, over a relay that has an operator,
/// refuses and changes nothing** — its key, its operators and its line are as
/// they were.
#[test]
fn creating_over_an_existing_instance_refuses_and_changes_nothing() {
    let dir = state_dir();
    let line = instance::create(&dir, OPERATOR, "").unwrap();
    let before = everything(&dir);
    let e = instance::create(&dir, OTHER, "").unwrap_err().to_string();
    assert!(e.contains("has an operator") && e.contains("operator enrol"), "{e}");
    assert_eq!(everything(&dir), before, "a refused create changed the state");
    let key = RelayKey::open_existing(&dir).unwrap().unwrap();
    assert_eq!(instance::line(&key, ""), line, "the line is the one creation printed");
    let _ = std::fs::remove_dir_all(dir);
}

/// **State from before `create` existed, naming no operator, is adopted**
/// (fork 4, the owner's ruling): `create --operator K` records K and keeps the
/// key the relay already had — its line names that key — and its rule.
#[test]
fn create_adopts_state_with_no_operator_keeping_its_key() {
    let dir = state_dir();
    // A relay that ran before creation existed: a key, a rule, an empty set.
    let old = RelayKey::open(&dir).unwrap().public();
    std::fs::write(dir.join("rule.json"), br#"{"rule":"Anyone","mine":{"epoch":0},"invited":{"epoch":0},"last_set":7}"#)
        .unwrap();
    let rule_before = std::fs::read(dir.join("rule.json")).unwrap();
    let line = instance::create(&dir, OPERATOR, "").unwrap();
    assert_eq!(line.key, old, "the key the state already had");
    assert_eq!(operators(&dir), [OPERATOR]);
    assert_eq!(std::fs::read(dir.join("rule.json")).unwrap(), rule_before, "its rule is kept");
    let _ = std::fs::remove_dir_all(dir);
}

/// **`create` never makes a key over existing state**: a relay's state with no
/// key of its own is refused, and nothing is written.
#[test]
fn create_never_mints_a_key_over_existing_state() {
    let dir = state_dir();
    std::fs::write(dir.join("rule.json"), br#"{"rule":"Anyone","mine":{"epoch":0},"invited":{"epoch":0},"last_set":7}"#)
        .unwrap();
    let before = everything(&dir);
    let e = instance::create(&dir, OPERATOR, "").unwrap_err().to_string();
    assert!(e.contains("never") && e.contains("key"), "{e}");
    assert!(!dir.join(KEY_FILE).exists(), "a key was made over existing state");
    let after: Vec<_> = everything(&dir).into_iter().filter(|(f, _)| f != instance::LOCK_FILE).collect();
    assert_eq!(after, before, "a refused create changed the state");
    let _ = std::fs::remove_dir_all(dir);
}

/// **The offline `operator enrol` refuses an empty set, writes nothing and
/// names `create --operator`; at a relay with an operator it still adds one**
/// — so creation is the one way into an empty operator set (V18).
#[test]
fn relay_operator_enrol_refuses_an_empty_set_and_names_create() {
    let dir = state_dir();
    let before = everything(&dir);
    let e = admission::enrol_operator(&dir, OPERATOR).unwrap_err().to_string();
    assert!(e.contains("create --state-dir") && e.contains("--operator <key>"), "{e}");
    assert_eq!(everything(&dir), before, "a refused enrol wrote something");

    instance::create(&dir, OPERATOR, "").unwrap();
    assert!(admission::enrol_operator(&dir, OTHER).unwrap(), "a relay with an operator takes another");
    assert_eq!(operators(&dir), [OPERATOR, OTHER]);
    let _ = std::fs::remove_dir_all(dir);
}

/// **The last operator cannot be revoked** (fork 3, the owner's ruling): naming
/// it is refused and writes nothing; *every one but* a key not enrolled is
/// refused; with two, one goes, and `--all --keep` leaves exactly the one
/// named.
#[test]
fn the_last_operator_cannot_be_revoked() {
    let dir = state_dir();
    instance::create(&dir, OPERATOR, "").unwrap();
    let e = admission::revoke_operator(&dir, Revoke::One(OPERATOR)).unwrap_err().to_string();
    assert!(e.contains("last operator"), "{e}");
    let e = admission::revoke_operator(&dir, Revoke::AllBut(OTHER)).unwrap_err().to_string();
    assert!(e.contains("not one of this relay's operators"), "{e}");
    assert_eq!(operators(&dir), [OPERATOR], "a refused revoke changed the set");

    admission::enrol_operator(&dir, OTHER).unwrap();
    assert_eq!(admission::revoke_operator(&dir, Revoke::One(OPERATOR)).unwrap(), 1);
    assert_eq!(operators(&dir), [OTHER]);
    admission::enrol_operator(&dir, OPERATOR).unwrap();
    assert_eq!(admission::revoke_operator(&dir, Revoke::AllBut(OPERATOR)).unwrap(), 1);
    assert_eq!(operators(&dir), [OPERATOR]);
    let _ = std::fs::remove_dir_all(dir);
}

/// **A state directory with no operator is refused its start, with the
/// sentence that names it and `create --operator`**, before anything is made.
#[test]
fn a_relay_state_with_no_operator_is_refused_its_start_in_one_sentence() {
    let dir = state_dir();
    let e = instance::refuse_unless_operated(&dir).unwrap_err().to_string();
    assert_eq!(e, instance::no_operator(&dir));
    assert!(e.contains(&dir.display().to_string()) && e.contains("create --state-dir"), "{e}");
    assert!(everything(&dir).is_empty(), "the refusal made something");
    instance::create(&dir, OPERATOR, "").unwrap();
    instance::refuse_unless_operated(&dir).unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

/// **`create` refuses while the state is held**, and changes nothing — the
/// lock a serving relay holds for its whole life.
#[test]
fn create_refuses_while_the_state_is_held() {
    let dir = state_dir();
    let held = StateLock::take(&dir).unwrap();
    let e = instance::create(&dir, OPERATOR, "").unwrap_err().to_string();
    assert!(e.contains("held by another kotton-relay"), "{e}");
    assert!(operators(&dir).is_empty() && !dir.join(KEY_FILE).exists(), "create wrote under a held state");
    drop(held);
    instance::create(&dir, OPERATOR, "").unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

/// **Adoption deletes a leftover claim file**: state from before creation may
/// keep the deleted claim's file, with an open secret in it; `create` adopts
/// the state and the file is gone, and a refused `create` leaves it for the
/// start to remove ([`instance::remove_leftover_secret`]).
#[test]
fn adoption_deletes_a_leftover_claim_file() {
    let dir = state_dir();
    let old = RelayKey::open(&dir).unwrap().public();
    let leftover = dir.join(instance::LEFTOVER_SECRET_FILE);
    std::fs::write(&leftover, br#"{"open":{"secret":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","until":1,"hint":""}}"#).unwrap();
    let line = instance::create(&dir, OPERATOR, "").unwrap();
    assert_eq!(line.key, old);
    assert!(!leftover.exists(), "adoption left the claim's secret on disk");

    // An operated relay's leftover: `create` refuses and changes nothing; the
    // start's removal takes it.
    std::fs::write(&leftover, b"secret").unwrap();
    assert!(instance::create(&dir, OTHER, "").is_err());
    assert!(leftover.exists(), "a refused create changed the state");
    assert!(instance::remove_leftover_secret(&dir).unwrap());
    assert!(!leftover.exists());
    assert!(!instance::remove_leftover_secret(&dir).unwrap(), "nothing to remove the second time");
    let _ = std::fs::remove_dir_all(dir);
}

/// **Revoking a key that is not enrolled is refused, naming it, and writes
/// nothing** — as the vault refuses it — so a typo never reads as a
/// revocation.
#[test]
fn revoking_a_key_that_is_not_enrolled_is_refused_naming_it() {
    let dir = state_dir();
    instance::create(&dir, OPERATOR, "").unwrap();
    admission::enrol_operator(&dir, OTHER).unwrap();
    let before = everything(&dir);
    let stranger = "ab".repeat(32);
    let e = admission::revoke_operator(&dir, Revoke::One(&stranger)).unwrap_err().to_string();
    assert!(e.contains(&stranger) && e.contains("not one of this relay's operators"), "{e}");
    assert_eq!(everything(&dir), before, "a refused revoke changed the state");
    let _ = std::fs::remove_dir_all(dir);
}

/// **A start never makes a key over existing state**: a relay created and
/// then missing its `identity.key` is refused its key, and nothing is made —
/// where `RelayKey::open` would have minted a stranger.
#[test]
fn a_start_never_mints_a_key_over_existing_state() {
    let dir = state_dir();
    instance::create(&dir, OPERATOR, "").unwrap();
    let first = instance::existing_key(&dir).unwrap().public();
    std::fs::remove_file(dir.join(KEY_FILE)).unwrap();
    let e = instance::existing_key(&dir).err().expect("a start keyed itself anew").to_string();
    assert!(e.contains("never makes a") && e.contains(KEY_FILE), "{e}");
    assert!(!dir.join(KEY_FILE).exists(), "a key was made over existing state");
    let _ = first;
    let _ = std::fs::remove_dir_all(dir);
}
