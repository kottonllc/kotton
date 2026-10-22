// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sh.kotton.governance.record` — the schema a record's row belongs to (RFC-0088).
//!
//! Carried as the JSON `SchemaRegister` takes, so this crate links nothing the header parser
//! does not need; `the_definition_is_a_schema_the_registry_accepts` holds the JSON to
//! `kotton_schemas::SchemaDefinition`, and holds every field a row carries to a declaration.
//!
//! Two departures from the RFC's table, each for a reason the table could not see:
//!
//! - **`opened` is a `string`, not a date.** The type system has `datetime` — an instant —
//!   and no date; `2026-09-23` is not an instant, and inventing a midnight would be a value
//!   the file never said.
//! - **`form` is a field the table does not have.** Rule 2 asks for byte-for-byte, and the
//!   table holds values only; where a named line sat, its padding and its continuation mark
//!   are form. [`crate::row`] says why one field holds them and why it holds no value.

use serde_json::{json, Value};

/// The schema's version. Additive changes bump it; a breaking one is a new NSID.
pub const VERSION: u32 = 1;

/// The principal the converter acts as when it reads and writes rows, so that `import` and
/// `export` run under a grant on the schema a person issued and can read (RFC-0088 rules 6
/// and 7), and are refused without one.
///
/// Named for what it is — the record-file converter — and never for a role (DEC-0080). It is
/// not the records app of RFC-0088's second phase, which will be its own principal with its
/// own manifest and its own grant.
///
/// **Deliberately not an app id.** A schema grant is keyed by the id it names, and nothing at
/// install asks whether a grant already names the id being installed, so a grant to an
/// app-shaped id passes to whatever app later installs under it
/// (`TASK-a-schema-grant-to-an-id-no-app-holds-passes-to-the-next-install-under-it`). This one
/// has a colon and no dot: an app's id must be an NSID (`Nsid::new` refuses the colon) and an
/// extension's must contain a dot, so no manifest can take it, and the grant `records init`
/// issues can only ever be the converter's.
pub const PRINCIPAL: &str = "record-file:converter";

fn text(name: &str) -> Value {
    json!({ "name": name, "type": "string" })
}

fn maybe(name: &str) -> Value {
    json!({ "name": name, "type": "string", "nullable": true })
}

fn list(name: &str) -> Value {
    json!({ "name": name, "type": { "list": "string" }, "nullable": true })
}

/// The definition, as the JSON `kotton schema register` and `SchemaRegister` take.
pub fn definition() -> Value {
    json!({
        "nsid": crate::row::NSID,
        "version": VERSION,
        "description": "A governance record: one record file as a row. \
                        The file is the wire format.",
        "fields": [
            text("name"),
            text("kind"),
            text("title"),
            maybe("status"),
            maybe("type"),
            list("region"),
            list("domains"),
            maybe("blocked_by"),
            maybe("built"),
            list("evidence"),
            maybe("authority"),
            maybe("serves"),
            maybe("security"),
            maybe("opened"),
            maybe("updated"),
            {
                "name": "header_rest",
                "type": { "list": { "record": [text("key"), text("value")] } }
            },
            text("body"),
            {
                "name": "form",
                "type": { "record": [
                    maybe("lead"),
                    {
                        "name": "lines",
                        "type": { "list": { "record": [text("key"), text("pad"), text("tail")] } }
                    }
                ] }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::{FieldType, SchemaDefinition};

    /// **No app and no extension can be installed under the converter's principal**, so the
    /// grant a person issues it cannot be inherited by an install.
    #[test]
    fn no_manifest_can_take_the_converters_principal() {
        let app = |id: &str| format!("[app]\nid = \"{id}\"\nname = \"X\"\nversion = \"0.1.0\"\n");
        let ext = |id: &str| {
            format!("[extension]\nid = \"{id}\"\nname = \"X\"\nversion = \"0.1.0\"\nclass = \"fetcher\"\n")
        };
        // The same manifests with an app-shaped id install, so the refusal below is the id's.
        assert!(kotton_schemas::AppManifest::from_toml(&app("sh.kotton.record-file")).is_ok());
        assert!(kotton_schemas::ExtensionManifest::from_toml(&ext("sh.kotton.record-file")).is_ok());
        assert!(kotton_schemas::AppManifest::from_toml(&app(PRINCIPAL)).is_err(), "an app took {PRINCIPAL}");
        assert!(kotton_schemas::ExtensionManifest::from_toml(&ext(PRINCIPAL)).is_err(), "an extension took {PRINCIPAL}");
    }

    /// The JSON is a definition the registry accepts, under the project's own namespace and
    /// outside the sealed core set (Article IX), and every field a row carries is declared.
    #[test]
    fn the_definition_is_a_schema_the_registry_accepts() {
        let def: SchemaDefinition = serde_json::from_value(definition()).unwrap();
        assert_eq!(def.nsid.as_str(), crate::row::NSID);
        assert!(
            !kotton_schemas::CoreSchema::all().iter().any(|c| c.nsid() == def.nsid),
            "the governance record is an extension schema, never a core one"
        );
        for (_, field, is_list) in crate::row::NAMED {
            let f = def.field(field).unwrap_or_else(|| panic!("`{field}` is not declared"));
            assert!(f.nullable, "`{field}` is absent from records that do not carry it");
            assert_eq!(matches!(f.field_type, FieldType::List(_)), *is_list, "{field}");
        }
        let row = crate::row::to_row(
            "TASK-t",
            "# T\n\n**Status:** open \\\n**Power:** judicial\n\nb\n",
        )
        .unwrap();
        for key in row.as_object().unwrap().keys().filter(|k| *k != "id") {
            assert!(def.field(key).is_some(), "a row carries `{key}` and the schema does not declare it");
        }
    }
}
