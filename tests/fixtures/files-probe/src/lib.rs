// SPDX-License-Identifier: AGPL-3.0-or-later
//! An ordinary app that writes, reads and lists through the handle its `files`
//! grant minted, and paints what each call answered.
//!
//! See `tests/fixtures/files-probe/Cargo.toml`. The report is one JSON object,
//! committed to the first surface as a raw patch with format byte `0x00`, so
//! the test reads it back out of `UserResponse::AppLaunched` — the trick
//! `roots-probe` uses.
//!
//! **Two launches, one program.** On the first, the note is not there yet: the
//! probe writes it and a second file one folder down, then reads the note back
//! and lists the root. On the second — after the test has packed the store —
//! the note is there, and the probe only reads and lists. So one fixture shows
//! a write landing and a read coming back from the packed store.
//!
//! **Told what to do, by its launch arguments**, it does only that and lists:
//!
//! - `write` and `body` — write `body` at the path `write` names, on the first
//!   handle. The forged-member test uses it to try the write the assessor made
//!   on 2026-09-24: `network/members/<did>` with an own-device record.
//! - `read` — read the path it names on the first handle.
//! - `list` — nothing but the listing.
//! - `path` — the file the person picked, as the daemon's hand-off rewrote it
//!   (the file's own name, on the handle minted for it). The probe reads it on
//!   every handle it holds and reports the first that answers.

use kotton_app::_generated::kotton::app::{
    files,
    surface::{InputEvent, Surface},
};
use kotton_app::Guest;

/// The file the probe writes, and the one it looks for first.
const NOTE: &str = "probe-note.md";
/// A second file, one folder down, so the listing has a directory in it.
const INNER: &str = "folder/inner.md";
/// What the note says. Distinctive on purpose: the test searches every byte
/// under the person's data directory for it and must find none.
const NOTE_BODY: &str = "PLAINTEXT-MARKER-4f1c9a: a note an app wrote through files.write";

struct FilesProbe;

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

fn read(dir: &files::Directory, path: &str) -> String {
    match dir.read(path) {
        Ok(bytes) => quote(&format!("ok: {}", String::from_utf8_lossy(&bytes))),
        Err(e) => quote(&format!("err: {e}")),
    }
}

impl Guest for FilesProbe {
    fn on_launch(first_surface: Surface, args: Vec<(String, String)>) -> Result<(), String> {
        let arg = |key: &str| args.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        let mut fields: Vec<String> = Vec::new();
        let handles = files::preopens();
        fields.push(format!("\"handles\":{}", handles.len()));
        if let Some(picked) = arg("path") {
            let answers: Vec<String> = handles.iter().map(|dir| read(dir, &picked)).collect();
            let first_ok = answers.iter().find(|a| a.starts_with("\"ok")).cloned();
            fields.push(format!("\"picked_name\":{}", quote(&picked)));
            fields.push(format!(
                "\"picked\":{}",
                first_ok.unwrap_or_else(|| quote(&format!("err: no handle read it: {}", answers.join(" | "))))
            ));
        } else if let (Some(path), Some(body)) = (arg("write"), arg("body")) {
            if let Some(dir) = handles.first() {
                fields.push(format!("\"arg_write\":{}", answer(dir.write(&path, body.as_bytes()))));
                fields.push(format!("\"arg_read\":{}", read(dir, &path)));
            }
        } else if let Some(path) = arg("read") {
            if let Some(dir) = handles.first() {
                fields.push(format!("\"arg_read\":{}", read(dir, &path)));
            }
        } else if arg("list").is_some() {
            // The listing below is the whole of it.
        } else if let Some(dir) = handles.first() {
            fields.push(format!("\"writable\":{}", dir.writable()));
            let before = read(dir, NOTE);
            fields.push(format!("\"read_before\":{before}"));
            if before.starts_with("\"err") {
                fields.push(format!(
                    "\"write\":{}",
                    answer(dir.write(NOTE, NOTE_BODY.as_bytes()))
                ));
                fields.push(format!(
                    "\"write_inner\":{}",
                    answer(dir.write(INNER, b"one folder down"))
                ));
            }
            fields.push(format!("\"read_after\":{}", read(dir, NOTE)));
            fields.push(format!("\"read_inner\":{}", read(dir, INNER)));
        }
        if let Some(dir) = handles.first() {
            match dir.list_entries("") {
                Ok(entries) => {
                    let rows: Vec<String> = entries
                        .iter()
                        .map(|e| {
                            format!(
                                "{{\"name\":{},\"is_dir\":{},\"size\":{}}}",
                                quote(&e.name),
                                e.is_dir,
                                e.size
                            )
                        })
                        .collect();
                    fields.push(format!("\"listing\":[{}]", rows.join(",")));
                }
                Err(e) => fields.push(format!("\"listing\":{}", quote(&format!("err: {e}")))),
            }
        }

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

kotton_app::export_app!(FilesProbe);
