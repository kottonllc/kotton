// SPDX-License-Identifier: AGPL-3.0-or-later
//! An occupant that tries every door to the person's files and paints what
//! each one answered.
//!
//! See `tests/fixtures/roots-probe/Cargo.toml`. The report is one JSON object,
//! committed to the first surface as a raw patch with format byte `0x00`, so
//! the test reads it back out of `UserResponse::AppLaunched` — the same trick
//! the mock runner's `report-input` mode uses.

use kotton_app::_generated::kotton::app::{
    files, roots,
    surface::{InputEvent, Surface},
};
use kotton_app::Guest;

/// The file the test seeds in the person's tree and then reads back.
const TARGET: &str = "mine.md";

struct RootsProbe;

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn answer(r: Result<(), String>) -> String {
    match r {
        Ok(()) => quote("ok"),
        Err(e) => quote(&format!("err: {e}")),
    }
}

impl Guest for RootsProbe {
    fn on_launch(first_surface: Surface, _args: Vec<(String, String)>) -> Result<(), String> {
        let mut fields: Vec<String> = Vec::new();

        // Door one: the handle the person's `files` grant minted.
        let granted = files::preopens();
        fields.push(format!("\"granted_handles\":{}", granted.len()));
        if let Some(dir) = granted.first() {
            fields.push(format!("\"granted_writable\":{}", dir.writable()));
            fields.push(format!(
                "\"granted_write\":{}",
                answer(dir.write(TARGET, b"overwritten through the granted handle"))
            ));
        }

        // Door two: every root the occupant is handed, and its tree.
        let mut rows: Vec<String> = Vec::new();
        match roots::list_roots() {
            Ok(list) => {
                for root in list {
                    let name = root.name();
                    let granted = root.granted();
                    let row = match root.tree() {
                        Ok(dir) => format!(
                            "{{\"name\":{},\"granted\":{granted},\"tree\":\"ok\",\"writable\":{},\"write\":{}}}",
                            quote(&name),
                            dir.writable(),
                            answer(dir.write(TARGET, b"overwritten through roots.tree"))
                        ),
                        Err(e) => format!(
                            "{{\"name\":{},\"granted\":{granted},\"tree\":{}}}",
                            quote(&name),
                            quote(&format!("err: {e}"))
                        ),
                    };
                    rows.push(row);
                }
            }
            Err(e) => fields.push(format!("\"list_roots\":{}", quote(&format!("err: {e}")))),
        }
        fields.push(format!("\"roots\":[{}]", rows.join(",")));

        let mut patch = vec![0x00u8];
        patch.extend_from_slice(format!("{{{}}}", fields.join(",")).as_bytes());
        first_surface.commit(&patch)?;
        Ok(())
    }

    fn on_message(_msg: String) -> Result<(), String> {
        Ok(())
    }

    fn on_terminate() -> Result<(), String> {
        Ok(())
    }

    fn launch() {}

    fn on_input(_surface: &Surface, _event: InputEvent) {}

    fn on_surface_error(_reason: String) {}
}

kotton_app::export_app!(RootsProbe);
