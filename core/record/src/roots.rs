// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which roots a person may read and write records in (RFC-0071 R12, R17).
//!
//! A record belongs to exactly one root (R17), and **a root's membership is who
//! may read it** (R12). This is the one place a request's root is turned into
//! something the store can act on, so it is the one place that question is
//! asked.
//!
//! ## Membership and grants are two questions, asked in two places
//!
//! A schema grant is *what an app may see* — `schema.read` on
//! `sh.kotton.calendar` — and it is checked where it always was, by
//! `schema_grants_db` in the verbs, unchanged. Membership is *which roots the
//! person is in*, and it is checked here. Neither widens the other: an app
//! holding `schema.read` on calendar sees calendar rows in every root the
//! person is a member of, and no row from a root they are not — because the
//! row is not in any selection this type can produce (Article IV: a grant to
//! software is not membership).
//!
//! ## Why this is not in `core/store`
//!
//! The root set is the store's, sealed under the person's keys, and `record`
//! does not depend on `store`. The daemon opens the set and hands over the two
//! facts this needs — which root is Personal, and which roots the person is a
//! member of — and nothing else crosses: no names, no targets, no key.

use crate::record_store::RootSelection;

/// What the daemon could establish about the person's roots, for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAccess {
    /// Personal's id, where the daemon could read the person's roots.
    personal: Option<String>,
    /// Every root the person is a member of, by id, Personal included when
    /// they are a member of it. Never the core root, which holds no records.
    member_of: Vec<String>,
}

/// A request named a root the person may not use.
///
/// One answer for *no such root* and *not a member of it*: a caller that may
/// not read a root learns nothing about whether it exists by asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAMember;

impl std::fmt::Display for NotAMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no root this person is a member of has that id")
    }
}

impl std::error::Error for NotAMember {}

impl RootAccess {
    /// The person's roots as the daemon read them: Personal's id, and the ids
    /// of every root they are a member of.
    pub fn new(personal: impl Into<String>, member_of: Vec<String>) -> Self {
        Self {
            personal: Some(personal.into()),
            member_of,
        }
    }

    /// The daemon could not read the person's roots — no chain to name them
    /// by, or a store that is not loaded.
    ///
    /// **Personal's rows and nothing else**, for reads and writes alike. Every
    /// row written before records had a root is Personal's, so a request that
    /// names no root is answered exactly as it was before; a request naming any
    /// root is refused, because nobody could say whether the person is in it.
    pub fn unresolved() -> Self {
        Self {
            personal: None,
            member_of: Vec::new(),
        }
    }

    /// Personal's id, where it is known.
    pub fn personal(&self) -> Option<&str> {
        self.personal.as_deref()
    }

    fn is_member(&self, root: &str) -> bool {
        self.member_of.iter().any(|m| m == root)
    }

    /// Whether the person is a member of Personal. Always, in practice — its
    /// first member is the person — but read rather than assumed.
    fn in_personal(&self) -> bool {
        match &self.personal {
            Some(p) => self.is_member(p),
            None => true,
        }
    }

    /// The rows a read of `root` may return.
    ///
    /// No root is **every root the person is a member of** — the person's own
    /// view across their roots, which the record's ruling makes the default. A
    /// named root must be one of those.
    ///
    /// **Personal is read unmarked and by its id alike.** Nothing on this
    /// device writes Personal's id on a row — a write into Personal is stored
    /// unmarked — but a row can arrive carrying it: merged from a peer whose
    /// Personal happens to be this one once the core root travels (R16), or
    /// written by a version that stamped it. Such a row is Personal's, and a
    /// selection that admitted only the unmarked form would make it readable by
    /// nobody at all.
    pub fn read(&self, root: Option<&str>) -> Result<RootSelection, NotAMember> {
        match root {
            None => Ok(RootSelection {
                personal: self.in_personal(),
                others: self.member_of.clone(),
            }),
            Some(r) if Some(r) == self.personal() => {
                if self.in_personal() {
                    Ok(RootSelection { personal: true, others: vec![r.to_owned()] })
                } else {
                    Err(NotAMember)
                }
            }
            Some(r) if self.is_member(r) => Ok(RootSelection::only(r)),
            Some(_) => Err(NotAMember),
        }
    }

    /// Where a write into `root` lands, as the store records it: `None` is
    /// Personal, which is unmarked.
    ///
    /// No root is **Personal** — so nothing existing moves, and every caller
    /// that predates roots writes where it always did.
    pub fn write(&self, root: Option<&str>) -> Result<Option<String>, NotAMember> {
        match root {
            None if self.in_personal() => Ok(None),
            None => Err(NotAMember),
            Some(r) if Some(r) == self.personal() => {
                if self.in_personal() {
                    Ok(None)
                } else {
                    Err(NotAMember)
                }
            }
            Some(r) if self.is_member(r) => Ok(Some(r.to_owned())),
            Some(_) => Err(NotAMember),
        }
    }

    /// The root a row belongs to, by id, from what the store holds: an
    /// unmarked row is Personal's. `None` only where Personal's id is unknown.
    pub fn label(&self, stored: Option<&str>) -> Option<String> {
        match stored {
            Some(r) => Some(r.to_owned()),
            None => self.personal.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERSONAL: &str = "p0";
    const FAMILY: &str = "f1";
    const THEIRS: &str = "t2";

    fn family_member() -> RootAccess {
        RootAccess::new(PERSONAL, vec![PERSONAL.into(), FAMILY.into()])
    }

    /// **R12 against records: membership is who may read.** A person in
    /// Personal and Family reads both by default, either by name, and a root
    /// they are not in — whether it exists or not — by no request at all.
    #[test]
    fn a_read_reaches_the_roots_the_person_is_a_member_of_and_no_other() {
        let access = family_member();
        assert_eq!(
            access.read(None).unwrap(),
            RootSelection { personal: true, others: vec![PERSONAL.into(), FAMILY.into()] }
        );
        assert_eq!(
            access.read(Some(PERSONAL)).unwrap(),
            RootSelection { personal: true, others: vec![PERSONAL.into()] }
        );
        assert_eq!(access.read(Some(FAMILY)).unwrap(), RootSelection::only(FAMILY));
        assert_eq!(access.read(Some(THEIRS)), Err(NotAMember));
        assert!(!access.read(None).unwrap().admits(Some(THEIRS)));
    }

    /// **A row stamped with Personal's own id is Personal's**, by default and
    /// by name — not a row no selection can reach — and it is still not
    /// another root's.
    #[test]
    fn a_row_stamped_with_personals_id_is_read_as_personal() {
        let access = family_member();
        for sel in [access.read(None).unwrap(), access.read(Some(PERSONAL)).unwrap()] {
            assert!(sel.admits(None), "unmarked Personal row not admitted: {sel:?}");
            assert!(sel.admits(Some(PERSONAL)), "stamped Personal row not admitted: {sel:?}");
        }
        assert!(!access.read(Some(FAMILY)).unwrap().admits(Some(PERSONAL)));
    }

    /// A write lands where it is asked to, Personal unmarked, and never in a
    /// root the person is not a member of.
    #[test]
    fn a_write_lands_in_a_root_the_person_is_a_member_of_or_nowhere() {
        let access = family_member();
        assert_eq!(access.write(None).unwrap(), None);
        assert_eq!(access.write(Some(PERSONAL)).unwrap(), None);
        assert_eq!(access.write(Some(FAMILY)).unwrap(), Some(FAMILY.to_owned()));
        assert_eq!(access.write(Some(THEIRS)), Err(NotAMember));
    }

    /// Where the daemon could not read the roots, the answer is what it was
    /// before records had a root: Personal's rows, and nothing named.
    #[test]
    fn unresolved_roots_answer_personal_and_refuse_every_named_root() {
        let access = RootAccess::unresolved();
        assert_eq!(access.read(None).unwrap(), RootSelection::personal());
        assert_eq!(access.write(None).unwrap(), None);
        assert_eq!(access.read(Some(FAMILY)), Err(NotAMember));
        assert_eq!(access.write(Some(FAMILY)), Err(NotAMember));
        assert_eq!(access.label(None), None);
    }
}
