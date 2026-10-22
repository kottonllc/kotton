// SPDX-License-Identifier: AGPL-3.0-or-later
//! `KOTTON_NO_SYSTEMD_PARSER` at build time: the one source is `infra/relay/tests/common/systemd_parser_cfg.rs`, which says what it does.
macro_rules! shared { () => { "tests/common/systemd_parser_cfg.rs" } }
include!(shared!());
fn main() { declare_systemd_parser_cfg(shared!()) }
