// SPDX-License-Identifier: AGPL-3.0-or-later
//! Schema field type system.
//!
//! [`FieldType`] and [`SchemaField`] describe the structure of a single column
//! in a record table. Every field has a name, a type, and an optional default
//! value used when migrating older records forward.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// The data type of a schema field.
///
/// **Closed by `DEC-0043`: every variant is something the node can decode.** There is no
/// escape hatch, and that absence is the whole design — a schema composes primitives Kotton
/// understands, so the owner can always read their own bytes.
///
/// `Json` was a variant until 2026-08-25, documented as *"escape hatch for unstructured
/// extension data."* It existed because the set below could not say what a developer meant:
/// [`FieldType::Map`] is homogeneous, so `{ name: string, age: int }` had nowhere to go, and
/// there was no binary type, so bytes travelled base64 inside a [`FieldType::String`] — which
/// `core.rs` still does in six places. Every reach for the hatch was a reach for opacity that
/// this enum manufactured.
///
/// **An under-expressive type system is a security defect**, because it creates the escape
/// hatch it then cannot police. Adding a variant here is adding expressiveness; adding an
/// *opaque* one is removing the guarantee. `no_opaque_variant` below is the guard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// UTF-8 text of arbitrary length.
    String,
    /// Boolean true/false.
    Bool,
    /// 64-bit signed integer.
    Int,
    /// 64-bit IEEE 754 float.
    Float,
    /// ISO 8601 datetime string (UTC, stored as TEXT in SQLite).
    Datetime,
    /// Ordered list of a single inner type.
    List(Box<FieldType>),
    /// String-keyed map to a single value type.
    Map(Box<FieldType>),
    /// Raw binary. Declared as binary rather than smuggled through a `String`, so the node
    /// knows it is looking at bytes and can say so.
    Bytes,
    /// A nested group of named, typed fields — **the facet**.
    ///
    /// Structural, not nominal: it carries no name, no registry entry and nothing to resolve.
    /// Two schemas holding `{ due_at: datetime, reminder_at: datetime }` are compatible because
    /// they *are the same shape*, which is why this composes without reintroducing the naming
    /// authority `DEC-0042` retired.
    Record(Vec<SchemaField>),
}

impl FieldType {
    /// Every leaf type reachable from here.
    ///
    /// Walks nested `List`, `Map` and `Record`. Used by the guard below and by anything that
    /// needs to answer *"can the node decode all of this?"* — which, while this enum stays
    /// closed, is always yes.
    pub fn leaves(&self) -> Vec<&FieldType> {
        match self {
            FieldType::List(inner) | FieldType::Map(inner) => inner.leaves(),
            FieldType::Record(fields) => {
                fields.iter().flat_map(|f| f.field_type.leaves()).collect()
            }
            leaf => vec![leaf],
        }
    }
}

/// Declaration of a single field in a [`SchemaDefinition`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaField {
    /// Column name — lowercase, underscores allowed, no spaces.
    pub name: String,
    /// The field's data type.
    #[serde(rename = "type")]
    pub field_type: FieldType,
    /// Whether this field may be NULL. Defaults to false.
    #[serde(default)]
    pub nullable: bool,
    /// Default value applied to existing records when this field is added
    /// via an additive migration. Must be compatible with `field_type`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<JsonValue>,
}

impl SchemaField {
    pub fn required(name: impl Into<String>, field_type: FieldType) -> Self {
        Self {
            name: name.into(),
            field_type,
            nullable: false,
            default: None,
        }
    }

    pub fn nullable(name: impl Into<String>, field_type: FieldType) -> Self {
        Self {
            name: name.into(),
            field_type,
            nullable: true,
            default: None,
        }
    }

    pub fn with_default(
        name: impl Into<String>,
        field_type: FieldType,
        default: JsonValue,
    ) -> Self {
        Self {
            name: name.into(),
            field_type,
            nullable: false,
            default: Some(default),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_roundtrip() {
        let field = SchemaField::required("title", FieldType::String);
        let json = serde_json::to_string(&field).unwrap();
        let back: SchemaField = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "title");
        assert_eq!(back.field_type, FieldType::String);
        assert!(!back.nullable);
    }

    /// **The guard on the guarantee, and it is the compiler.**
    ///
    /// `DEC-0043` closes `FieldType` so a record composes only what the node can decode. That
    /// property lives in an *absence*, and an absence is what a later convenience quietly fills
    /// in — this repository has now catalogued that failure eight times.
    ///
    /// So this match is **exhaustive on purpose**. Adding a variant to `FieldType` makes it
    /// non-exhaustive and the crate stops compiling until somebody writes down how the node
    /// reads the new thing. **A variant that cannot be read has no honest line to write here**,
    /// which is the whole mechanism.
    ///
    /// The first version of this guard counted entries in a list the test itself maintained.
    /// Adding an `Opaque` variant left the count unchanged and the test passed — a gate
    /// checking its own bookkeeping rather than the thing. Verified by breaking it.
    fn decodes_as(t: &FieldType) -> &'static str {
        match t {
            FieldType::String => "UTF-8 text",
            FieldType::Bool => "true or false",
            FieldType::Int => "a 64-bit signed integer",
            FieldType::Float => "a 64-bit float",
            FieldType::Datetime => "an ISO 8601 instant",
            FieldType::Bytes => "raw binary — the node can sniff it and say what it is",
            FieldType::List(_) => "a sequence of its inner type",
            FieldType::Map(_) => "string keys onto its inner type",
            FieldType::Record(_) => "named fields, each decoded by this same table",
        }
    }

    /// Every leaf a composed type bottoms out in is one the node reads.
    #[test]
    fn no_opaque_variant() {
        let composed = [
            FieldType::List(Box::new(FieldType::String)),
            FieldType::Map(Box::new(FieldType::Int)),
            FieldType::Record(vec![SchemaField::required("inner", FieldType::Bytes)]),
        ];
        for c in &composed {
            for leaf in c.leaves() {
                // Reaching a leaf whose reading nobody stated is impossible while `decodes_as`
                // compiles, which is the point — this asserts the leaf is genuinely a leaf.
                assert!(!decodes_as(leaf).is_empty());
                assert_eq!(leaf.leaves().len(), 1, "{leaf:?} claims to be a leaf and is not");
            }
        }
    }

    /// Nesting bottoms out in primitives however deep it goes, which is the property that lets
    /// a facet be structural rather than a named fragment.
    #[test]
    fn a_nested_facet_still_bottoms_out_in_primitives() {
        let facet = FieldType::Record(vec![
            SchemaField::required("due_at", FieldType::Datetime),
            SchemaField::nullable("tags", FieldType::List(Box::new(FieldType::String))),
            SchemaField::required(
                "nested",
                FieldType::Record(vec![SchemaField::required("blob", FieldType::Bytes)]),
            ),
        ]);
        // Three: `datetime`, the `string` inside the list, and the `bytes` inside the nested
        // record. A `List` contributes its inner leaf, not itself.
        let leaves = facet.leaves();
        assert_eq!(leaves.len(), 3, "leaves are the decodable bottom, not the constructors");
        assert!(leaves.contains(&&FieldType::Bytes));
        assert!(leaves.contains(&&FieldType::Datetime));
        // Round-trips, so a facet survives being written to the store and read back.
        let json = serde_json::to_string(&facet).unwrap();
        let back: FieldType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, facet);
    }

    /// Two schemas that declare the same shape *are* the same shape — no name, nothing to
    /// resolve. This is what lets `DEC-0043` compose without reintroducing `DEC-0042`'s
    /// retired naming authority.
    #[test]
    fn identical_shapes_compare_equal_without_a_name() {
        let a = FieldType::Record(vec![SchemaField::required("due_at", FieldType::Datetime)]);
        let b = FieldType::Record(vec![SchemaField::required("due_at", FieldType::Datetime)]);
        assert_eq!(a, b);
        let c = FieldType::Record(vec![SchemaField::required("due_at", FieldType::Int)]);
        assert_ne!(a, c, "a different shape is a different type, and needs no ruling to say so");
    }

    #[test]
    fn list_field() {
        let field = SchemaField::required("tags", FieldType::List(Box::new(FieldType::String)));
        let json = serde_json::to_string(&field).unwrap();
        let back: SchemaField = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.field_type,
            FieldType::List(Box::new(FieldType::String))
        );
    }
}
