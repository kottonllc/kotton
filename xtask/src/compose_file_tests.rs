// SPDX-License-Identifier: AGPL-3.0-or-later
//! `infra/vault/docker-compose.yml`, held to what it now is: the relay and the
//! vault as containers for the scenarios, which `include:` it and build both from
//! this tree. It was the host's contract until DEC-0085 — what a host pulled, by a
//! release tag and two digests — and a host now runs the released binaries under
//! systemd (`release_server`). What is pinned here is that it no longer pretends
//! to be that: it names no registry and no release, and the environment it hands
//! the vault derives from one address, as the host's env file does.
//! `release_server::tests::the_env_files_carry_the_compose_files_environment`
//! holds the two environments to each other.
//!
//! Read as text, not rendered: `docker compose config` would need Docker on the
//! machine running the tests, and a test that skips without it passes on
//! nothing.

use std::path::Path;

fn compose() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent");
    std::fs::read_to_string(root.join("infra/vault/docker-compose.yml")).expect("the scenarios' compose file")
}

/// The `image:` line of `service`, which is the only one under it.
fn image_line(text: &str, service: &str) -> String {
    let at = text
        .find(&format!("\n  {service}:\n"))
        .unwrap_or_else(|| panic!("no `{service}:` service in the compose file"));
    text[at..]
        .lines()
        .find_map(|l| l.trim().strip_prefix("image: "))
        .unwrap_or_else(|| panic!("`{service}` names no image"))
        .to_owned()
}

/// **Each image is a local build, and nothing here names a release.** The image
/// names are what the scenarios' build tags; a registry name, a required release
/// tag or a digest would say this file is something a host pulls, which since
/// DEC-0085 nothing is.
#[test]
fn each_image_is_a_local_build_and_names_no_release() {
    let text = compose();
    for (service, name) in [("relay", "kotton-relay:local"), ("vault", "kotton-vault:local")] {
        assert_eq!(image_line(&text, service), name, "{service}");
    }
    for gone in ["ghcr.io", "KOTTON_BOX_REVISION", "_DIGEST", "KOTTON_REVISION"] {
        assert!(!text.contains(gone), "the compose file still names `{gone}`");
    }
}

/// **No line names a recipe or a workflow that no longer exists, and the file
/// sends a reader to how a vault runs.**
#[test]
fn the_file_names_no_retired_recipe_and_points_at_the_release() {
    let text = compose();
    for gone in ["box::", "release::box", "publish-box-images"] {
        assert!(!text.contains(gone), "the compose file names `{gone}`");
    }
    assert!(text.contains("cargo xtask release-server"), "the header does not say how a vault runs");
    assert!(text.contains("docs/use/run-a-vault.md"));
}

/// **One variable is the deployment's configuration.** The vault is told the
/// public address (`TASK-a-box-has-one-public-address`), and no relay: where it
/// stands is what its owner's desktop tells it
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`).
#[test]
fn the_public_address_is_the_one_variable() {
    let text = compose();
    assert!(text.contains(r#"KOTTON_PUBLIC_ADDR: "${KOTTON_PUBLIC_ADDR:-}""#));
    assert!(!text.contains("KOTTON_RELAY_URL:"), "the vault's compose service names a relay");
}
