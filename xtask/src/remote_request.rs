// SPDX-License-Identifier: AGPL-3.0-or-later
//! `remote-request`: the remote-eligible half of `UserRequest`, as a type.
//!
//! ## Why it is generated
//!
//! `khttpd` and `kquicd` decode untrusted bytes off the network into
//! `UserRequest` — all 147 variants — and then ask
//! `required_trust() > ConnTrustOrigin::Remote` and refuse. The refusal is
//! correct and it is a runtime check standing where a type could stand: a
//! browser can *name* `PurgeFile`, and only a line of code stops it.
//!
//! `RemoteRequest` holds exactly the 109 variants a remote caller may invoke,
//! so `{"PurgeFile":…}` arriving from a browser fails to **deserialize**. Not
//! rejected — unconstructible. That is the difference between a check that can
//! be edited wrongly and a case that cannot be expressed.
//!
//! ## Why generated rather than written
//!
//! A hand-written copy of 109 variants is a mirror, and a mirror drifts. This
//! reads the `Remote` arm group out of `required_trust()` — the same source the
//! existing `remote_eligible_set_is_pinned` test reads — and emits the enum plus
//! its lowering to `UserRequest`. The trust decision stays in one place; this is
//! a view of it.
//!
//! Adding a variant to the `Remote` group and forgetting to regenerate fails
//! `remote-request-check` in `just lint`, so the two cannot disagree.
//!
//! ## The header is generated too
//!
//! The file opens with the `SPDX-License-Identifier:` line `license-check` requires of
//! every source file under `core/`, and the id is asked of
//! [`crate::license_check::file_license`] — the crate's own license, read by the code
//! that check reads it with. Until 2026-09-27 the generator wrote no header, the header
//! was added by hand, and the two gates contradicted each other on this one file
//! (`TASK-the-remote-request-generator-drops-the-spdx-header-license-check-requires`).

use std::path::Path;

const SRC: &str = "core/wire/src/ipc/request.rs";
const OUT: &str = "core/wire/src/ipc/remote_request.rs";

pub fn run(bless: bool) {
    let Ok(src) = std::fs::read_to_string(Path::new(SRC)) else {
        eprintln!("remote-request: could not read {SRC}. Run from the workspace root.");
        std::process::exit(1);
    };

    let remote = remote_variant_names(&src);
    if remote.is_empty() {
        eprintln!(
            "remote-request: found no variants in the `Remote` arm group of \
             `required_trust()`. Either the marker comment moved or the parser is broken — \
             and generating an empty enum would silently make every remote request \
             unrepresentable."
        );
        std::process::exit(1);
    }

    let all = crate::wire_check::parse_enum_public(&src, "UserRequest");
    if all.is_empty() {
        eprintln!("remote-request: could not parse `UserRequest`; refusing to generate.");
        std::process::exit(1);
    }

    let mut chosen = Vec::new();
    for name in &remote {
        match all.iter().find(|v| &v.name == name) {
            Some(v) => chosen.push(v),
            None => {
                eprintln!(
                    "remote-request: `{name}` is in the Remote arm group but is not a \
                     variant of UserRequest. The trust match and the enum disagree."
                );
                std::process::exit(1);
            }
        }
    }

    let license = match crate::license_check::file_license(Path::new("."), OUT) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("remote-request: cannot tell which license {OUT} is under: {e}");
            std::process::exit(1);
        }
    };
    let rendered = render(&license, &chosen);

    if bless {
        if let Err(e) = std::fs::write(OUT, &rendered) {
            eprintln!("remote-request: could not write {OUT}: {e}");
            std::process::exit(1);
        }
        println!("Wrote {OUT} — {} variants.", chosen.len());
        return;
    }

    let Ok(existing) = std::fs::read_to_string(OUT) else {
        eprintln!(
            "remote-request: {OUT} is missing. Generate it with `cargo xtask remote-request`."
        );
        std::process::exit(1);
    };
    if existing == rendered {
        println!(
            "remote-request: OK — {OUT} matches the Remote arm group ({} variants).",
            chosen.len()
        );
        return;
    }
    eprintln!(
        "remote-request: {OUT} is out of date.\n\n{}",
        explain(&existing, &rendered)
    );
    std::process::exit(1);
}

/// Why the file on disk and the one the generator would write differ, said as what
/// differs: bytes no line shows, else the variant set, else code with the same set, else
/// comments only. Only the
/// first is a change to which requests a remote caller can express; a message that
/// claimed that for a moved comment would teach its reader to regenerate without
/// reading, on the one diff that exists to be read.
fn explain(existing: &str, rendered: &str) -> String {
    let regen = "Regenerate with `cargo xtask remote-request` and commit the result";
    // The check compares bytes and everything below compares `lines()`, which drops a
    // `\r` before each `\n` and a missing final newline. A difference only bytes can see
    // is said as what it is, before anything reads lines.
    if existing.lines().eq(rendered.lines()) {
        let what = if existing.contains('\r') != rendered.contains('\r') {
            "the file on disk has CRLF line endings and the generator writes LF — a checkout \
             with `core.autocrlf=true` does this"
        } else {
            "the two differ only in the final newline"
        };
        return format!(
            "No line differs: {what}. The set a browser or a peer can express is unchanged.\n\n\
             {regen}."
        );
    }
    let (was, now) = (variants_in(existing), variants_in(rendered));
    let added: Vec<&str> = now
        .iter()
        .filter(|v| !was.contains(v))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = was
        .iter()
        .filter(|v| !now.contains(v))
        .map(String::as_str)
        .collect();
    if !added.is_empty() || !removed.is_empty() {
        let mut o = String::from(
            "The `Remote` arm group of `required_trust()` changed, so the set a browser or a \
             peer can express changed with it.",
        );
        if !added.is_empty() {
            o.push_str(&format!("\n  now remote-eligible: {}", added.join(", ")));
        }
        if !removed.is_empty() {
            o.push_str(&format!(
                "\n  no longer remote-eligible: {}",
                removed.join(", ")
            ));
        }
        o.push_str(&format!(
            "\n\n{regen} **in the same commit** — the diff of that file is how a widened \
             remote surface gets reviewed."
        ));
        return o;
    }
    let first = existing
        .lines()
        .zip(rendered.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| existing.lines().count().min(rendered.lines().count()));
    let line = |t: &str| {
        t.lines()
            .nth(first)
            .map_or("(end of file)".to_string(), |l| format!("`{l}`"))
    };
    // Comments are every line that opens with `//` — the SPDX header, the module doc and
    // the doc comments; everything else is code, and code decides what parses.
    let code = |t: &str| -> Vec<String> {
        t.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(str::to_string)
            .collect()
    };
    let what = if code(existing) == code(rendered) {
        "Only comments differ — the SPDX header, the module doc or a doc comment — so the \
         set a browser or a peer can express is unchanged."
    } else {
        "The variant set is unchanged, but the code differs — a variant's fields, a derive or \
         serde attribute, an import, or the order — which can change what a browser or a \
         peer sends in a request it could already name. Read the diff."
    };
    format!(
        "{what}\n  first difference, line {}:\n    on disk:   {}\n    generated: {}\n\n{regen}.",
        first + 1,
        line(existing),
        line(rendered),
    )
}

/// The variant names a generated file lowers, read from its `From` arms.
fn variants_in(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("RemoteRequest::"))
        .map(|r| {
            r.split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|n| !n.is_empty())
        .collect()
}

/// Variant names inside the `── Remote-eligible ─` arm group.
///
/// Reads the same marker the `remote_eligible_set_is_pinned` test reads, so the
/// generator and that test cannot disagree about where the group is.
fn remote_variant_names(src: &str) -> Vec<String> {
    let Some((_, after)) = src.split_once("── Remote-eligible ─") else {
        return Vec::new();
    };
    let Some((group, _)) = after.split_once("=> Remote,") else {
        return Vec::new();
    };
    let mut out: Vec<String> = group
        .match_indices("Self::")
        .map(|(i, _)| {
            let rest = &group[i + "Self::".len()..];
            let end = rest
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            rest[..end].to_string()
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn render(license: &str, variants: &[&crate::wire_check::Variant]) -> String {
    let mut o = format!("// SPDX-License-Identifier: {license}\n");
    o.push_str("//! What a **remote** caller may ask of the user channel.\n//!\n");
    o.push_str("//! GENERATED by `cargo xtask remote-request` from the `Remote` arm group of\n");
    o.push_str("//! [`UserRequest::required_trust`]. Do not edit: change the trust match, then\n");
    o.push_str(
        "//! regenerate. `remote-request-check` in `just lint` holds the two together.\n//!\n",
    );
    o.push_str("//! `khttpd` and `kquicd` decode network bytes into this type rather than into\n");
    o.push_str("//! `UserRequest`, so a `Local`-tier operation is not something a browser or a\n");
    o.push_str("//! peer can name. It used to be something they could name and be refused.\n//!\n");
    o.push_str("//! ## Authentication — who may speak on these channels\n//!\n");
    o.push_str("//! Two channels share this vocabulary and authenticate differently, so each\n");
    o.push_str("//! says how:\n//!\n");
    o.push_str("//! - **browser → `khttpd`**: a session cookie, issued after `POST /auth`\n");
    o.push_str("//!   validated it, and marked\n");
    o.push_str("//!   `HttpOnly; Secure; SameSite=Strict`.\n");
    o.push_str("//! - **peer → `kquicd`**: QUIC mTLS. The peer's certificate is the identity;\n");
    o.push_str("//!   there is no separate token.\n//!\n");
    o.push_str("//! Both gateways then authenticate to `kuserd` on the caller's behalf, which\n");
    o.push_str("//! makes them deputies. `MintPrincipalSession` is what keeps them *disarmed*\n");
    o.push_str("//! ones: a gateway's own bootstrap token may mint a session for a third party\n");
    o.push_str("//! it has evidence about, and do nothing else.\n\n");
    // A glob over the module the variants are copied from, rather than a hand-kept
    // list: a new variant naming a new type would otherwise fail to compile here
    // and the generator would need editing for a change that is purely mechanical.
    o.push_str("#![allow(unused_imports)]\n\n");
    o.push_str("use crate::ipc::*;\n");
    o.push_str("use crate::peer::*;\n");
    o.push_str("use crate::remote::*;\n");
    o.push_str("use serde::{Deserialize, Serialize};\n");
    o.push_str("use std::net::SocketAddr;\n\n");
    o.push_str("/// The remote-eligible half of [`UserRequest`].\n///\n");
    o.push_str("/// Externally tagged like its parent and carrying the same variant names and\n");
    o.push_str("/// fields, so the wire is unchanged: a request that was accepted before this\n");
    o.push_str("/// type existed is accepted now, and one that was refused no longer parses.\n");
    o.push_str("#[derive(Debug, Clone, Serialize, Deserialize)]\n");
    o.push_str("pub enum RemoteRequest {\n");
    for v in variants {
        if v.fields.is_empty() {
            o.push_str(&format!("    {},\n", v.name));
            continue;
        }
        o.push_str(&format!("    {} {{\n", v.name));
        for f in &v.fields {
            for a in &f.attrs {
                o.push_str(&format!("        {a}\n"));
            }
            o.push_str(&format!("        {}: {},\n", f.name, f.ty));
        }
        o.push_str("    },\n");
    }
    o.push_str("}\n\n");

    o.push_str("impl From<RemoteRequest> for UserRequest {\n");
    o.push_str("    /// Widen to the user channel's type for forwarding to `kuserd`.\n    ///\n");
    o.push_str("    /// Total and lossless: every variant here exists there with the same\n");
    o.push_str("    /// fields. The direction is one-way by construction — there is no\n");
    o.push_str("    /// `From<UserRequest>`, because that is exactly the narrowing a gateway\n");
    o.push_str("    /// must not be able to assume.\n");
    o.push_str("    fn from(r: RemoteRequest) -> Self {\n        match r {\n");
    for v in variants {
        if v.fields.is_empty() {
            o.push_str(&format!(
                "            RemoteRequest::{n} => UserRequest::{n},\n",
                n = v.name
            ));
            continue;
        }
        let names: Vec<&str> = v.fields.iter().map(|f| f.name.as_str()).collect();
        let binds = names.join(", ");
        o.push_str(&format!(
            "            RemoteRequest::{n} {{ {b} }} => UserRequest::{n} {{ {b} }},\n",
            n = v.name,
            b = binds
        ));
    }
    o.push_str("        }\n    }\n}\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_check::{Field, Variant};

    fn sample(names: &[&str]) -> String {
        let vs: Vec<Variant> = names
            .iter()
            .map(|n| Variant {
                name: n.to_string(),
                fields: vec![Field {
                    attrs: vec![],
                    name: "id".into(),
                    ty: "String".into(),
                }],
            })
            .collect();
        render("Apache-2.0", &vs.iter().collect::<Vec<_>>())
    }

    /// The generated file opens with the line `license-check` reads, naming the id the
    /// generator was given — which `run` asks of `license_check::file_license`.
    #[test]
    fn the_generated_file_opens_with_the_header_license_check_reads() {
        let vs = [Variant {
            name: "Ping".into(),
            fields: vec![],
        }];
        let out = render("AGPL-3.0-or-later", &vs.iter().collect::<Vec<_>>());
        assert_eq!(
            crate::license_check::spdx_header(&out),
            Some("AGPL-3.0-or-later")
        );
    }

    /// The found case: the header was the only difference, and the message said the
    /// remote surface had changed.
    #[test]
    fn a_header_only_difference_does_not_claim_the_remote_surface_changed() {
        let generated = sample(&["A", "B"]);
        let on_disk = generated.replacen("// SPDX-License-Identifier: Apache-2.0\n", "", 1);
        let why = explain(&on_disk, &generated);
        assert!(
            !why.contains("arm group of `required_trust()` changed"),
            "{why}"
        );
        assert!(
            why.contains("set a browser or a peer can express is unchanged"),
            "{why}"
        );
        assert!(why.contains("line 1:"), "{why}");
        assert!(why.contains("SPDX-License-Identifier: Apache-2.0"), "{why}");
    }

    #[test]
    fn a_changed_variant_set_is_named_variant_by_variant() {
        let why = explain(&sample(&["A", "B"]), &sample(&["B", "C"]));
        assert!(
            why.contains("arm group of `required_trust()` changed"),
            "{why}"
        );
        assert!(why.contains("now remote-eligible: C"), "{why}");
        assert!(why.contains("no longer remote-eligible: A"), "{why}");
    }

    #[test]
    fn a_changed_field_with_the_same_variants_says_so() {
        let generated = sample(&["A"]);
        let on_disk = generated.replace("id: String", "id: u64");
        let why = explain(&on_disk, &generated);
        assert!(why.contains("variant set is unchanged"), "{why}");
        assert!(why.contains("`        id: u64,`"), "{why}");
    }

    /// The check compares bytes; a difference `lines()` cannot see is not called a
    /// comment, and does not print "(end of file)" for both sides.
    #[test]
    fn a_line_ending_or_final_newline_difference_is_named_as_one() {
        let generated = sample(&["A"]);
        for (on_disk, says) in [
            (generated.replace('\n', "\r\n"), "CRLF line endings"),
            (
                generated.trim_end_matches('\n').to_string(),
                "only in the final newline",
            ),
        ] {
            assert_ne!(on_disk, generated);
            let why = explain(&on_disk, &generated);
            assert!(why.contains(says), "{why}");
            assert!(!why.contains("Only comments differ"), "{why}");
            assert!(!why.contains("(end of file)"), "{why}");
        }
    }

    /// A serde attribute sits above `pub enum` and can change the wire shape, so it is
    /// code, not "the text above the enum".
    #[test]
    fn a_changed_attribute_above_the_enum_is_not_called_a_comment() {
        let generated = sample(&["A"]);
        let on_disk = generated.replace(
            "#[derive(Debug, Clone, Serialize, Deserialize)]\n",
            "#[derive(Debug, Clone, Serialize, Deserialize)]\n#[serde(tag = \"t\")]\n",
        );
        assert_ne!(on_disk, generated);
        let why = explain(&on_disk, &generated);
        assert!(why.contains("the code differs"), "{why}");
        assert!(!why.contains("Only comments differ"), "{why}");
    }
}
