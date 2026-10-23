// SPDX-License-Identifier: AGPL-3.0-or-later
//! The integration suite — **one** test binary, not forty-two.
//!
//! Cargo compiles every `.rs` directly under `tests/` as its own crate, so this
//! directory used to produce 42 executables, each statically linking the whole
//! workspace. Measured 2026-08-24: 51s to relink one of them, 115 test
//! executables totalling 8 GB in `target/debug/deps`, and a touch to
//! `kotton-wire` relinking all of them. That is where `just test` spent its
//! time and where the disk went — the same cause, twice.
//!
//! A directory with a `main.rs` is a single test target, so this is one link.
//!
//! **Adding a test file?** Put it beside this one and add a `mod` line below.
//! A file with no `mod` line compiles to nothing and runs silently — which is
//! why `suite-check` in `just lint` refuses that.
//!
//! Everything here shares one process now. `common` is declared once, and a test
//! that reaches for process-global state — `std::env::set_var`, the current
//! directory — is no longer isolated from its neighbours by luck of being its
//! own binary.

mod common;

mod app_launch_message;
mod browser_channel;
mod contact_pairing;
mod app_lifecycle;
mod app_long_lived;
mod app_roles;
mod app_runner_protocol;
mod cli_failure;
mod cli_identity;
mod crypto_recovery;
mod daily_credential;
mod device_add_join;
mod device_operators;
mod did_transport;
mod enroll_threshold_sign;
mod extension_install;
mod frost_org;
mod grant_enforcement;
mod handler_registry;
mod household_channel;
mod http_gateway;
mod import_ics;
mod inbox;
mod vault;
mod drive_sync;
mod instance;
mod introduction;
mod ipc_hardening;
mod keep;
mod key_distribution;
mod kuid_surface;
mod local_door;
mod messaging;
mod name_travels;
mod model_install;
mod net_status;
mod operator_copy;
mod org_identity;
mod peer_sync;
mod principal_sessions;
mod project_records;
mod quic_gateway;
mod record_ops;
mod relay_circuit;
mod relay_peer_sync;
mod relay_presence;
mod headless;
mod repl_verbs;
mod rendezvous_handles;
mod runner_confinement;
mod restarted_daemon;
mod runtime_inspection;
mod schema_grants;
mod schema_management;
mod session_activation;
mod share;
mod trust_and_grants;
mod turn_relay;
mod two_node_transfer;
mod user_lifecycle;
mod vfs_operations;
mod vfs_watch;
