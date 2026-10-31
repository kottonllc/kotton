// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shell's verb tables, as the tests of `verb-check` and its retired-words sweep read them:
//! one fixture for both, held to the live registry.
//!
//! Each noun here is a table `client/shell/src/commands/` declares (`drive.rs`, `pin.rs`,
//! `sync.rs`, `device.rs`), in its declared order. The fixture is the unit tests' copy, so
//! they run without building the command trees; [`tests::the_fixture_is_the_live_registrys_tables`]
//! (under the `cli-docs` feature, which builds them) holds it equal to what
//! `kotton_cli::bridge::repl_executor`'s registry declares, read the way `verb-check` reads it
//! ([`crate::verb_check::tables_of`]). So a shell edit to a table fails that test, not only the
//! gate.

use std::collections::BTreeMap;

use crate::verb_check::Is;

/// Every noun's verb table, as the REPL's registry declares it.
pub fn tables() -> BTreeMap<String, Vec<(String, Is)>> {
    let table = |rows: &[(&str, Is)]| rows.iter().map(|(w, is)| (w.to_string(), is.clone())).collect::<Vec<_>>();
    let mut t = BTreeMap::new();
    t.insert(
        "drive".to_string(),
        table(&[
            ("create", Is::Current),
            ("list", Is::Current),
            ("show", Is::Current),
            ("move", Is::Current),
            ("enrol", Is::Current),
        ]),
    );
    t.insert("pin".to_string(), table(&[("default", Is::Current), ("<drive>", Is::Current), ("list", Is::Current)]));
    t.insert(
        "sync".to_string(),
        table(&[
            ("", Is::Current),
            ("now", Is::Alias("sync".into())),
            ("add", Is::Gone("pin".into())),
            ("list", Is::Gone("pin list".into())),
            ("remove", Is::Gone("pin".into())),
            ("<remote>", Is::Gone("sync".into())),
        ]),
    );
    t.insert("device".to_string(), table(&[("admit", Is::Gone("drive enrol".into()))]));
    t
}

#[cfg(test)]
mod tests {
    /// **The fixture is the live registry's tables**: every noun the REPL's registry declares a
    /// table for, and each table entry for entry, in order, retired words and their
    /// replacements included. A noun added, a verb retired or a replacement renamed in the
    /// shell fails here first.
    #[cfg(feature = "cli-docs")]
    #[test]
    fn the_fixture_is_the_live_registrys_tables() {
        let repl = kotton_cli::bridge::repl_executor().registry();
        let live = crate::verb_check::tables_of(&repl);
        assert_eq!(
            super::tables(),
            live,
            "xtask/src/verb_tables.rs is not the shell's verb tables: make it what `client/shell/src/commands/` declares"
        );
    }
}
