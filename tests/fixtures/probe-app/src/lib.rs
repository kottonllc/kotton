// SPDX-License-Identifier: AGPL-3.0-or-later
//! A guest that imports two capability interfaces and uses neither for
//! anything. Its whole purpose is to be *linked*: a component's imports are the
//! interfaces its code names, so naming `apps` and `schema` here is what
//! makes the host's decision about each one observable at instantiation.
//!
//! **It runs one-shot** (its manifest names no `kind`), so both are interfaces
//! a one-shot runner serves. It imported `files` until 2026-09-24; a one-shot
//! runner has no channel to the daemon and is handed no `files` handle, so the
//! grant behind that import could reach nothing
//! (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
//!
//! See `confinement` in the integration suite, and
//! `TASK-the-app-sandbox-is-imported-by-nothing` for why it exists.

use kotton_app::_generated::kotton::app::{apps, schema, surface::InputEvent, surface::Surface};
use kotton_app::Guest;

struct Probe;

impl Guest for Probe {
    /// Touch `schema`; `apps` is named in `on_message`, which no test sends.
    /// If either was withheld, this function never runs: the component fails
    /// to instantiate against a linker missing the import, which is the
    /// refusal the test asserts on.
    /// The surface argument is dropped without being used, which is itself the
    /// observable thing: a probe that never draws still receives one, because
    /// the host hands every instance its first surface at launch (RFC-0087).
    fn on_launch(
        _first_surface: kotton_app::surface::Surface,
        _args: Vec<(String, String)>,
    ) -> Result<(), String> {
        let _rows = schema::query("sh.kotton.probe", None)?;
        Ok(())
    }

    /// Names `apps`, so the component imports it. A launch asked for here is
    /// only buffered, under the `apps.launch` check, and no test sends one.
    fn on_message(msg: String) -> Result<(), String> {
        apps::launch(&msg, None)
    }

    fn on_terminate() -> Result<(), String> {
        Ok(())
    }

    fn launch() {}

    fn on_input(_surface: &Surface, _event: InputEvent) {}

    fn on_surface_error(_reason: String) {}
}

kotton_app::export_app!(Probe);
