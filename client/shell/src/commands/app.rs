// SPDX-License-Identifier: AGPL-3.0-or-later
//! `app` — manage installed apps (WASM + web bundle).
//!
//! ```text
//! app list                    list all installed apps
//! app new <name>              scaffold an app: a manifest and one wasm32-wasip2 crate
//! app sideload <path>         register a WASM app from the host filesystem
//! app install <path>          install a web bundle (production)
//! app dev <path>              register a dev bundle (reads app id from manifest)
//! app rm <id>                 remove an installed app
//! ```
//!
//! `<path>` for `sideload`, `install`, and `dev` can be the app source directory
//! or its `dist/` subdirectory.  `manifest.toml` is found automatically.
//!
//! Authentication is implicit — the shell is already connected as the current user.

use anyhow::Result;
use async_trait::async_trait;
use kotton_schemas::{AppManifest, CapabilityGrant};
use std::path::PathBuf;

use super::{Command, CommandOutput};
use crate::grant_prompt::{self, quoted, words_line, Known, Signer, OFFER_CAUTION};
use crate::out::Out;
use crate::state::ShellState;

pub struct AppCommand;

#[async_trait]
impl Command for AppCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        match args.first().map(String::as_str) {
            Some("list") | None => handle_list(state).await,
            Some("new") => handle_new(args).await,
            Some("open") | Some("launch") => handle_open(args, state).await,
            Some("sideload") => handle_sideload(args, state).await,
            Some("install") => handle_install(args, state).await,
            Some("dev") => handle_dev(args, state).await,
            Some("add") => Ok(CommandOutput::error(
                1,
                "app add was renamed — use: app sideload <host-path>".to_string(),
            )),
            Some("remove") | Some("rm") => handle_rm(args, state).await,
            Some("build") => handle_build(args, state).await,
            Some("set-role") => handle_set_role(args, state).await,
            Some("verify") => handle_verify(args, state).await,
            Some("grants") => handle_grants(args, state).await,
            Some("help") => Ok(CommandOutput::success_with_output(HELP.to_string())),
            Some(other) => Ok(CommandOutput::error(
                1,
                format!("app: unknown subcommand '{}'. Try 'app help'.", other),
            )),
        }
    }

    /// `app new` writes files and asks the daemon nothing, so it runs without a session.
    async fn execute_without_session(
        &self,
        args: &[String],
        _named: Option<&str>,
    ) -> Option<Result<CommandOutput>> {
        match args.first().map(String::as_str) {
            Some("new") => Some(handle_new(args).await),
            _ => None,
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec![
            "list", "new", "open", "launch", "sideload", "install", "dev", "remove", "rm",
            "build", "set-role", "verify", "help",
        ]
    }

    fn help_text(&self) -> &'static str {
        HELP
    }
}

const HELP: &str = "\
app — manage installed apps

USAGE:
  app list                      list all installed apps
  app new <name>                scaffold an app: a manifest and one wasm32-wasip2 crate
  app sideload <path>           show what a WASM app asks for, then --approve it
  app grants <id>               what an installed app asked for, and what it holds
  app launch <id> [key=value …] launch an installed app with optional args
  app install <path>            install a web bundle (production)
  app dev <path>                register a live dev bundle (shows '(dev)' in list)
  app rm <id>                   remove an installed app
  app build <path>              build logic/ (cargo component) and ui/ (pnpm build)
  app set-role <role> <id>      assign a named system role to an app id
  app verify <id>               re-hash the WASM binary and check integrity

<path> can be the app source directory (e.g. ./apps/kotton-shell) or its
dist/ subdirectory.  The app id is read from manifest.toml automatically.

EXAMPLES:
  app new my-app
  app sideload ./apps/kotton-shell
  app sideload ./apps/kotton-shell --approve
  app grants sh.kotton.shell
  app launch sh.kotton.shell
  app build ./apps/kotton-shell
  app set-role shell sh.kotton.shell
  app list
  app rm sh.kotton.shell";

// ── `app new` ────────────────────────────────────────────────────────────────

/// `app new <name>` — scaffold the smallest app the SDK compiles: a manifest and one Rust
/// crate built for `wasm32-wasip2`, which draws one line through the SDK's renderer.
///
/// An app is the component and its manifest, and nothing else: the host renders what the
/// component commits to its surface, and nothing in it loads a web page for an app, so
/// the scaffold writes none. `guest/examples/hello` is this scaffold's output for the name
/// `hello`, byte for byte but the SDK's dependency line, and `cargo xtask build-apps`
/// builds it, so what this writes is held compiling by the tree's own gate.
///
/// Writes files and nothing else; it asks the daemon nothing, so it is the command's
/// `execute_without_session`, and the `kotton` door runs it without connecting.
async fn handle_new(args: &[String]) -> Result<CommandOutput> {
    let name = match args.get(1) {
        Some(n) => n.clone(),
        None => {
            return Ok(CommandOutput::error(
                1,
                "app new: missing name.\nUsage: app new <name>".to_string(),
            ))
        }
    };

    if !valid_app_name(&name) {
        return Ok(CommandOutput::error(
            1,
            format!(
                "app new: '{name}' is not a valid app name: a lowercase letter, then \
                 lowercase letters, digits or '-'"
            ),
        ));
    }

    match scaffold_new_app(std::path::Path::new(&name), &name) {
        Ok(output) => Ok(CommandOutput::success_with_output(output)),
        Err(e) => Ok(CommandOutput::error(1, format!("app new: {e}"))),
    }
}

/// Whether `name` can name a scaffolded app. It becomes the crate's name and the last
/// segment of the app's id, so it is held to the rule for one segment of an id: a
/// manifest the daemon cannot read is not an app.
fn valid_app_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && kotton_schemas::AppId::new(scaffold_app_id(name)).is_ok()
}

/// The id the scaffold gives an app called `name`, for its author to replace.
fn scaffold_app_id(name: &str) -> String {
    format!("com.example.{name}")
}

/// How a scaffolded app reaches the SDK: by its repository. `kotton-app` is published to
/// no registry, and a name a registry resolves is a name someone else can claim, so the
/// scaffold names the source rather than a version.
pub const SDK_FROM_REPOSITORY: &str = "\
# The SDK, from its repository. The first build pins the commit it resolved in
# Cargo.lock; add `rev = \"<sha>\"` here to pin one in this file instead.
kotton-app = { git = \"https://github.com/kottonllc/kotton\", features = [\"dioxus\"] }";

const SCAFFOLD_CARGO_TOML: &str = "\
[package]
name = \"@NAME@\"
version = \"0.1.0\"
edition = \"2021\"
license = \"Apache-2.0\"
publish = false

[lib]
# `cdylib` is what emits the .wasm the host runs. Build it with
# `cargo build --target wasm32-wasip2 --release`; `cargo test` runs on this
# machine's own target, as usual.
crate-type = [\"cdylib\"]

[dependencies]
@SDK@

# Its own workspace root, so it builds wherever it is put, inside another
# workspace's directory too.
[workspace]
";

const SCAFFOLD_MANIFEST: &str = "\
[app]
id      = \"@ID@\"
name    = \"@NAME@\"
version = \"0.1.0\"
kind    = \"long-lived\"

# Everything this app may reach, which is nothing yet. Installing it shows the
# person this list and asks, and what they approve is all the app can reach.
# To keep notes, for one:
#
# [capabilities]
# \"schema.read\"  = [\"<publisher>/<name>\"]
# \"schema.write\" = [\"<publisher>/<name>\"]
";

const SCAFFOLD_LIB_RS: &str = "\
// SPDX-License-Identifier: Apache-2.0
//! @NAME@, a Kotton app.
//!
//! It draws one line on the surface the host hands it at launch, and reaches nothing
//! else, because `manifest.toml` asks for nothing. Once the manifest names a schema or a
//! tree, `kotton_app::record` and `kotton_app::fs` reach it.

use kotton_app::prelude::*;

#[component]
fn App() -> Element {
    rsx! {
        p { \"@NAME@\" }
    }
}

// `app!` implements every export the host calls: it draws `App` at launch, draws it
// again when state written through `app_state!` changes, and hands a click on the
// surface to the `onclick` of the element under it. Write your own `Guest`, as
// `guest/examples/notes` does, to read what a field holds, take keys, or handle messages.
kotton_app::app!(App);
";

/// Every file `app new` writes for an app called `name`, as (path under the app's
/// directory, contents), with `sdk` as the SDK's dependency entry. The command passes
/// [`SDK_FROM_REPOSITORY`]; the test that holds `guest/examples/hello` to it, which is
/// xtask's because the fixture is the tree's and not this crate's, passes the fixture's path
/// entry, and the two outputs differ in that entry and nowhere else.
pub fn scaffold_files(name: &str, sdk: &str) -> Vec<(&'static str, String)> {
    let fill = |template: &str| {
        template
            .replace("@SDK@", sdk)
            .replace("@ID@", &scaffold_app_id(name))
            .replace("@NAME@", name)
    };
    vec![
        ("manifest.toml", fill(SCAFFOLD_MANIFEST)),
        ("Cargo.toml", fill(SCAFFOLD_CARGO_TOML)),
        ("src/lib.rs", fill(SCAFFOLD_LIB_RS)),
    ]
}

/// Write the scaffold for `name` into `dir`, which must not exist yet.
fn scaffold_new_app(dir: &std::path::Path, name: &str) -> std::io::Result<String> {
    if dir.exists() {
        return Err(std::io::Error::other(format!(
            "directory '{}' already exists",
            dir.display()
        )));
    }

    for (path, contents) in scaffold_files(name, SDK_FROM_REPOSITORY) {
        let path = dir.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, contents)?;
    }

    let app_id = scaffold_app_id(name);
    let shown = dir.display();
    Ok(format!(
        "✓ Scaffolded '{name}' in {shown}/\n\
         \n\
         App id (edit in manifest.toml): {app_id}\n\
         \n\
         {shown}/manifest.toml  what the app may reach: nothing yet\n\
         {shown}/Cargo.toml     one dependency, the SDK, from its repository\n\
         {shown}/src/lib.rs     the app: one component, drawn at launch\n\
         \n\
         Licensed Apache-2.0, as the SDK is; the licence is yours to choose\n\
         (Cargo.toml, and the first line of src/lib.rs).\n\
         \n\
         Next, in a terminal in {shown}/:\n\
         rustup target add wasm32-wasip2\n\
         cargo build --target wasm32-wasip2 --release\n\
         (`cargo test` runs on this machine's own target, as usual.)\n\
         Then: app sideload {shown}    — shows what it asks for, then --approve it"
    ))
}

// ── `app open` ───────────────────────────────────────────────────────────────

/// `app open <id> [key=value …]` — launch an installed app via daemon IPC.
///
/// Extra arguments are parsed as `key=value` pairs and forwarded to the
/// app’s `on-launch` export.  The host’s event watcher opens the window
/// reactively when the daemon emits the WASM launch event.
///
/// This is the canonical launch path.  `edit <file>` is an alias for
/// `app open sh.kotton.edit path=<file>`.
pub(crate) async fn handle_open(args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
    let app_id = match args.get(1) {
        Some(id) => id.clone(),
        None => {
            return Ok(CommandOutput::error(
                1,
                "app open: missing app-id.\nUsage: app open <id> [key=value …]".to_string(),
            ))
        }
    };

    // Parse remaining args as key=value pairs.
    let launch_args: Vec<(String, String)> = args[2..]
        .iter()
        .filter_map(|a| {
            let mut parts = a.splitn(2, '=');
            Some((
                parts.next()?.to_owned(),
                parts.next().unwrap_or("").to_owned(),
            ))
        })
        .collect();

    let mut client = state.client.lock().await;
    client
        .app_launch(&app_id, launch_args)
        .await
        .map_err(|e| anyhow::anyhow!("app open: {e}"))?;

    Ok(CommandOutput::success())
}

// ── `app sideload` ────────────────────────────────────────────────────────────

/// `app sideload <host-path>` — read manifest.toml + compiled WASM from the host
/// filesystem and register them with the daemon as the current user.
///
/// This is the same operation as `kotton app sideload` in the CLI, but runs inside
/// the REPL session so no separate binary invocation (and no Windows exe-lock) is needed.
async fn handle_sideload(args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
    let path_str = match args.get(1) {
        Some(p) => p.clone(),
        None => {
            return Ok(CommandOutput::error(
                1,
                "app sideload: missing path.\nUsage: app sideload <host-path>".to_string(),
            ))
        }
    };

    let app_dir = resolve_path(&path_str, state);
    if !app_dir.is_dir() {
        return Ok(CommandOutput::error(
            1,
            format!("app sideload: '{}' is not a directory", app_dir.display()),
        ));
    }

    let manifest_path = app_dir.join("manifest.toml");
    if !manifest_path.exists() {
        return Ok(CommandOutput::error(
            1,
            format!(
                "app sideload: manifest.toml not found in '{}'",
                app_dir.display()
            ),
        ));
    }

    let manifest_toml = std::fs::read_to_string(&manifest_path)
        .map_err(|e| anyhow::anyhow!("app sideload: read manifest: {e}"))?;

    let wasm_path = match find_wasm(&app_dir) {
        Ok(p) => p,
        Err(e) => return Ok(CommandOutput::error(1, format!("app sideload: {e}"))),
    };

    let wasm_bytes = std::fs::read(&wasm_path)
        .map_err(|e| anyhow::anyhow!("app sideload: read wasm: {e}"))?;

    let user_id = state.user_id.clone();
    let client_handle = std::sync::Arc::clone(&state.client);
    let mut client = client_handle.lock().await;

    // ── The consent ceremony ────────────────────────────────────────────────
    //
    // Always preview first. This mints nothing and writes nothing, so an
    // unapproved sideload leaves no trace — and the capability list shown below
    // is the daemon's own reading of the manifest, not this command's, so what
    // the user approves is what the daemon will sign.
    let preview = match client
        .app_install_preview(&user_id, manifest_toml.clone(), wasm_bytes.clone())
        .await
    {
        Ok(preview) => preview,
        Err(e) => return Ok(refused(PREVIEW_REFUSED, &e.to_string())),
    };

    // `--bind <shape-id>=<path>` — RFC-0021's "the user can accept the default
    // or type any path they like", in a surface that cannot prompt. Repeatable;
    // a shape left unbound keeps the manifest's suggestion.
    let bindings: Vec<(String, String)> = args
        .iter()
        .zip(args.iter().skip(1))
        .filter(|(flag, _)| flag.as_str() == "--bind")
        .filter_map(|(_, spec)| spec.split_once('=' ))
        .map(|(id, path)| (id.to_owned(), path.to_owned()))
        .collect();

    for (id, _) in &bindings {
        if !preview.shapes.iter().any(|s| &s.id == id) {
            return Ok(CommandOutput::error(1, no_such_shape(id, &preview.shapes).join("\n")));
        }
    }

    // Where each shape will actually point once this install goes through —
    // the manifest's suggestion unless the user moved it.
    let effective: Vec<(String, String)> = preview
        .shapes
        .iter()
        .map(|s| {
            let target = bindings
                .iter()
                .find(|(id, _)| id == &s.id)
                .map(|(_, p)| p.clone())
                .unwrap_or_else(|| s.default_target.clone());
            (s.id.clone(), target)
        })
        .collect();

    // A grant over the whole VFS is the one RFC-0021 singles out: legitimate for
    // a shell or a backup tool, and far too broad to accept with the same
    // keystroke as "read /notes".
    //
    // Checked against the **bound** targets, not the declared ones. A user who
    // binds a modest-looking shape to `/` is choosing whole-tree access just as
    // surely as a manifest that declared it, and checking the request would have
    // waved that through.
    let mut wildcards: Vec<String> = effective
        .iter()
        .filter(|(_, path)| path == "/" || path == "*")
        .map(|(id, _)| id.clone())
        .collect();
    wildcards.extend(
        preview
            .requested_display
            .iter()
            .filter(|d| d.starts_with("vfs.") && (d.ends_with(":/") || d.ends_with(":*")))
            .filter(|_| bindings.is_empty())
            .cloned(),
    );

    let approval = args.iter().position(|a| a == "--approve");
    let typed = approval.and_then(|i| args.get(i + 1)).map(String::as_str);
    // The key that signed the app's manifest and code is the manifest's `[publisher]`, read
    // here from the manifest the daemon read, and only when the daemon's preview checked its
    // signature over both.
    let publisher_did = AppManifest::from_toml(&manifest_toml).ok().and_then(|m| m.publisher_did);
    let signer = Signer::of(publisher_did.as_deref(), preview.publisher_verified);

    if approval.is_none() {
        // The default is not to install. Saying what it wants and stopping is
        // the whole point: there is no flagless path that grants anything.
        //
        // What the device checked comes first, in its own words, and the app's own words
        // follow, each quoted on a line of its own (`crate::grant_prompt`).
        let mut known = known(&mut client, &user_id).await;
        let preview = Preview {
            name: &preview.name,
            version: &preview.version,
            app_id: &preview.app_id,
            requested: &preview.requested,
            shapes: &preview.shapes,
        };
        let footer = sideload_footer(&path_str, !wildcards.is_empty());
        // The first meeting: a key the prompt shows unnamed is offered to be named after the
        // prompt is shown, so the person names it knowing what it stands behind.
        let unnamed = grant_prompt::unnamed_keys(&signer, preview.requested, &known);
        let mut said = Vec::new();
        let mut asked = false;
        if !unnamed.is_empty() && state.asking != crate::state::Asking::Nobody {
            asked = true;
            said.push(Out::Data(sideload_prompt(&preview, &signer, &known).join("\n")));
            match name_the_unnamed(state, &mut client, &user_id, &signer, &unnamed, &known, &mut said).await {
                // Nobody answered the first question: as if nobody was here to ask.
                None => {
                    said.clear();
                    asked = false;
                }
                Some(true) => {
                    known = self::known(&mut client, &user_id).await;
                    said.push(Out::Note("With the names you gave, it reads:".into()));
                    asked = false;
                }
                Some(false) => {}
            }
        }
        // Asked and nothing named: the prompt stands above as it was, and is not said twice.
        let mut lines = if asked { Vec::new() } else { sideload_prompt(&preview, &signer, &known) };
        lines.extend(footer);
        let mut out = CommandOutput::success_with_output(lines.join("\n"));
        out.out = said;
        return Ok(out);
    }

    if !wildcards.is_empty() && typed != Some("GRANT") {
        return Ok(CommandOutput::error(1, whole_tree_refusal(&path_str, &preview.name).join("\n")));
    }

    // The VFS grants are not echoed back: the daemon builds those from the
    // bindings and its own reading of the manifest, so this client cannot hand
    // it a path-bearing grant at all. Everything else is echoed as reviewed.
    let non_vfs: Vec<_> = preview
        .requested
        .iter()
        .filter(|g| !matches!(g.target, kotton_schemas::CapabilityTarget::Vfs { .. }))
        .cloned()
        .collect();
    let send_bindings = if preview.shapes.is_empty() {
        Vec::new()
    } else {
        effective
    };
    let (app_id, name, capabilities) = match client
        .app_install(&user_id, manifest_toml, wasm_bytes, non_vfs, send_bindings)
        .await
    {
        Ok(installed) => installed,
        Err(e) => return Ok(refused(INSTALL_REFUSED, &e.to_string())),
    };
    let known = known(&mut client, &user_id).await;
    let lines = receipt(&name, &app_id, &capabilities, &signer, &known);
    Ok(CommandOutput::success_with_output(lines.join("\n")))
}

/// The device's line when the daemon would not preview an app; the reason follows.
const PREVIEW_REFUSED: &str =
    "app sideload: the daemon did not take this app's manifest, and nothing was installed.";

/// The device's line when no answer says an install went through (refused, or the answer was
/// lost after the request was sent); the reason follows.
const INSTALL_REFUSED: &str =
    "app sideload: no answer says this app was installed; `app list` shows whether it was.";

/// The device's line when the daemon would not say what an app holds; the reason follows.
const GRANTS_REFUSED: &str = "app grants: the daemon did not answer for this app.";

/// A refusal of the daemon's: the device's `head`, then the reason it gave, which can quote
/// the app's manifest, so it is shown as another party's words are, behind the gutter and
/// within [`grant_prompt::REASON_MAX`] columns.
fn refused(head: &str, reason: &str) -> CommandOutput {
    let mut lines = vec![head.to_owned()];
    lines.extend(grant_prompt::reason_line(reason));
    CommandOutput::error(1, lines.join("\n"))
}

/// At most this many of an app's shape ids are listed when a `--bind` names none of them.
const SHAPES_LISTED: usize = 20;

/// A `--bind` naming no shape the app declares: the device's line, with the id the person
/// typed, then the first [`SHAPES_LISTED`] ids of the app's shapes (the app's own, or the
/// device's `vfs:<n>` for the flat form), each quoted, and how many more there are.
fn no_such_shape(id: &str, shapes: &[kotton_schemas::CapabilityShape]) -> Vec<String> {
    let mut lines = vec![format!(
        "app sideload: no shape {} in this app. The ids of its shapes:",
        quoted(id)
    )];
    if shapes.is_empty() {
        lines.push("  none".to_owned());
    }
    for shape in shapes.iter().take(SHAPES_LISTED) {
        lines.extend(words_line("the id for it", &shape.id));
    }
    if shapes.len() > SHAPES_LISTED {
        lines.push(format!("  and {} more", shapes.len() - SHAPES_LISTED));
    }
    lines
}

/// The refusal of a grant over the whole file tree approved without the word: the device's
/// sentence first, then the app's name as its words, then what to type.
fn whole_tree_refusal(path_str: &str, name: &str) -> Vec<String> {
    let mut lines = vec!["app sideload: this app asks for access to your whole file tree.".to_owned()];
    lines.extend(words_line("the app's name", name));
    lines.extend([
        "Approving that takes the word, not the flag:".to_owned(),
        String::new(),
        format!("    app sideload {path_str} --approve GRANT"),
        String::new(),
        "Nothing has been installed.".to_owned(),
    ]);
    lines
}

/// What an install says it granted, in the prompt's own form ([`grant_prompt::grant_lines`]):
/// each capability the daemon answers, read back as its grant; one this device cannot read
/// back is shown as the daemon's words, behind the gutter.
fn receipt(name: &str, app_id: &str, capabilities: &[String], signer: &Signer, known: &Known) -> Vec<String> {
    let mut lines = vec!["✓ Sideloaded the app".to_string()];
    lines.extend(words_line("the app's name", name));
    lines.extend(words_line("the app's id", app_id));
    if capabilities.is_empty() {
        lines.push("It holds nothing.".to_string());
        return lines;
    }
    lines.push("It holds, as the daemon says:".to_string());
    for cap in capabilities {
        match CapabilityGrant::from_display_string(cap) {
            Some(grant) => lines.extend(grant_prompt::grant_lines(&grant, signer, known)),
            None => {
                lines.push("  a grant this device cannot read back".to_string());
                lines.extend(words_line("the daemon's words for it", cap));
            }
        }
    }
    lines
}

/// What the prompt knows to say who stands behind a thing: the person's names for keys and
/// the schemas this device holds, each as read, or that the read failed
/// ([`grant_prompt::Known`]).
async fn known(client: &mut kotton::KottonClient, user_id: &str) -> Known {
    let names = crate::petnames::read(client, user_id).await;
    let held = client.schema_list(user_id).await.map_err(|e| e.to_string());
    Known::new(names, held)
}

/// What the daemon's preview said of an app, as the prompt shows it.
struct Preview<'a> {
    name: &'a str,
    version: &'a str,
    app_id: &'a str,
    requested: &'a [kotton_schemas::CapabilityGrant],
    shapes: &'a [kotton_schemas::CapabilityShape],
}

/// The sideload preview, before its footer: the device's lines on who the app is from and
/// what their signature over its manifest and code covers, or that no signature checked and
/// nothing it asks for is signed; then the app's own words, then what it asks for, then where
/// its files will live. Every string the app chose is on a [`grant_prompt::GUTTER`] line.
fn sideload_prompt(preview: &Preview<'_>, signer: &Signer, known: &Known) -> Vec<String> {
    let mut lines = grant_prompt::signer_lines(signer, known);
    lines.push(String::new());
    lines.extend(grant_prompt::app_words(preview.name, preview.version, preview.app_id));
    lines.push(String::new());
    if preview.requested.is_empty() {
        lines.push("It asks for nothing.".to_string());
    } else {
        lines.push("It asks to:".to_string());
        for grant in preview.requested {
            lines.extend(grant_prompt::grant_lines(grant, signer, known));
        }
    }
    if !preview.shapes.is_empty() {
        lines.push(String::new());
        lines.push("Where its files will live (change with --bind id=path):".to_string());
        for s in preview.shapes {
            let access = s
                .access
                .iter()
                .map(|k| match k {
                    kotton_schemas::CapabilityKind::Write => "write",
                    kotton_schemas::CapabilityKind::Read => "read",
                    kotton_schemas::CapabilityKind::Use => "use",
                })
                .collect::<Vec<_>>()
                .join(" + ");
            // A path tells the person where, and only the author can say what for; all of it
            // is the app's own text, so each is a line of the app's words.
            lines.push(format!("  {access} files at a place the app suggests"));
            if let Some(label) = &s.label {
                lines.extend(words_line("the app's label", label));
            }
            if let Some(desc) = &s.desc {
                lines.extend(words_line("the app's description", desc));
            }
            lines.extend(words_line("the app's path", &s.default_target));
            // The id the shape was declared with, or `vfs:<n>`, the device's, for a manifest in
            // the flat form: said as neither's, and quoted as another party's words are.
            lines.extend(words_line("the id for it (for --bind)", &s.id));
        }
    }
    lines
}

/// The sideload preview's footer: the warning for a grant over the whole tree, and what to
/// type to install.
fn sideload_footer(path_str: &str, whole_tree: bool) -> Vec<String> {
    let mut lines = vec![String::new()];
    if whole_tree {
        lines.push("  !  This includes access to your whole file tree.".to_string());
        lines.push("     Only approve this for an app you trust completely.".to_string());
        lines.push(String::new());
        lines.push(format!("To install:  app sideload {path_str} --approve GRANT"));
    } else {
        lines.push(format!("To install:  app sideload {path_str} --approve"));
    }
    lines.push("Nothing has been installed.".to_string());
    lines
}

/// **The first meeting with a key**, where the person decides what to call it, as they do a
/// contact's: for each key the prompt shows unnamed, once the prompt has been shown (it is
/// in `said` already), ask for a name. A name that already names another key (compared as
/// names are, case and spacing aside) is said to, with that key, and asked again: the same
/// name is kept only on an explicit `yes`, another answer is taken as the name instead, and
/// an empty one leaves the key unnamed. An answer is written as a petname record through the
/// ordinary insert, so the daemon holds it to a petname's rules; a refusal is said and the key
/// left unnamed. With nobody to ask ([`crate::state::Asking::Nobody`]) the caller asks
/// nothing. `Some(true)` when a name was written, `None` when nobody answered the first
/// question.
async fn name_the_unnamed(
    state: &mut ShellState,
    client: &mut kotton::KottonClient,
    user_id: &str,
    signer: &Signer,
    unnamed: &[kotton_schemas::Publisher],
    known: &Known,
    said: &mut Vec<Out>,
) -> Option<bool> {
    let mut given: Vec<(kotton_schemas::Publisher, String)> = Vec::new();
    let mut answered = false;
    'keys: for key in unnamed {
        let what = if signer.key() == Some(key) { "signed this app's code" } else { "publishes a schema it asks for" };
        said.push(Out::Note(format!(
            "The key {key} {what}, and you have not named it. {OFFER_CAUTION} Name it now, as \
             you would a contact, and every prompt about it says that name; or press Enter to \
             leave it unnamed."
        )));
        let mut answer = match state.ask(said, "Name:") {
            Ok(Some(answer)) => answer.trim().to_string(),
            _ => break,
        };
        answered = true;
        loop {
            if answer.is_empty() {
                continue 'keys;
            }
            // Held to a name's rules first, so a name no key may have (`kotton` for another
            // key among them) is said to break its rule, never to be one the person gave.
            if let Err(rule) = kotton_schemas::petname::check_name(key, &answer) {
                said.push(Out::Note(format!(
                    "This key cannot have that name: {rule}. Type another name, or press Enter to \
                     leave it unnamed."
                )));
                answer = match state.ask(said, "Name:") {
                    Ok(Some(again)) => again.trim().to_string(),
                    _ => break 'keys,
                };
                continue;
            }
            let folded = kotton_schemas::petname::folded(&answer);
            let others: Vec<String> = known
                .names
                .iter()
                .flat_map(|names| names.keys_called(&answer))
                .map(|k| k.to_string())
                .chain(given.iter().filter(|(_, n)| kotton_schemas::petname::folded(n) == folded).map(|(k, _)| k.to_string()))
                .filter(|k| k != key.as_str())
                .collect();
            if others.is_empty() {
                break;
            }
            // The keys on lines of their own, so none is wrapped where the person reads it.
            said.push(Out::Note(already_given(&answer, others.len())));
            said.push(Out::Data(others.iter().map(|k| format!("  {k}")).collect::<Vec<_>>().join("\n")));
            said.push(Out::Note(
                "Two keys with one name are told apart only by the key, so every prompt will say \
                 the name is shared. Type yes to give this key that name too, another name to give \
                 it that instead, or press Enter to leave it unnamed."
                    .into(),
            ));
            let again = match state.ask(said, "Same name? (yes, or another name):") {
                Ok(Some(again)) => again.trim().to_string(),
                _ => break 'keys,
            };
            if again.eq_ignore_ascii_case("yes") {
                break;
            }
            answer = again;
        }
        let body = serde_json::json!({ "key": key.as_str(), "name": answer });
        match client
            .record_insert_in(user_id, Some(kotton_wire::ipc::PERSONAL_ROOT), None, kotton_common::namespace::NSID_PETNAME, body)
            .await
        {
            Ok(_) => given.push((key.clone(), answer)),
            Err(e) => said.push(Out::Warn { what: format!("not named: {e}"), consequence: "the key is left unnamed".into() }),
        }
    }
    answered.then_some(!given.is_empty())
}

/// The offer's line when the person's answer already names `others` other keys: the answer
/// said as they typed it ([`grant_prompt::persons`]), since it is their own name.
fn already_given(answer: &str, others: usize) -> String {
    format!(
        "You already gave the name {} to {}:",
        grant_prompt::persons(answer),
        if others == 1 { "another key" } else { "other keys" }
    )
}

/// Locate the compiled WASM file inside an app directory.
/// Search order:
///   1. `<app_dir>/app.wasm`             — pre-built artefact (e.g. from `cargo xtask build-apps`)
///   2. `<app_dir>/logic/target/wasm32-wasip2/{release,debug}/*.wasm`
///   3. `<app_dir>/target/wasm32-wasip2/{release,debug}/*.wasm`
fn find_wasm(app_dir: &std::path::Path) -> std::io::Result<PathBuf> {
    let root_wasm = app_dir.join("app.wasm");
    if root_wasm.exists() {
        return Ok(root_wasm);
    }

    for sub in &["logic", ""] {
        let base = if sub.is_empty() {
            app_dir.to_path_buf()
        } else {
            app_dir.join(sub)
        };
        for profile in &["release", "debug"] {
            let search = base.join("target").join("wasm32-wasip2").join(profile);
            if !search.exists() {
                continue;
            }
            let wasm = std::fs::read_dir(&search)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .find(|p| p.extension().map(|e| e == "wasm").unwrap_or(false));
            if let Some(path) = wasm {
                return Ok(path);
            }
        }
    }

    Err(std::io::Error::other(format!(
        "no compiled .wasm found in '{}'. \
         Run 'cargo component build --release --target wasm32-wasip2' in logic/ first, \
         or place a pre-built app.wasm at the app root.",
        app_dir.display()
    )))
}

// ── Subcommand handlers ───────────────────────────────────────────────────────

async fn handle_list(state: &mut ShellState) -> Result<CommandOutput> {
    let mut client = state.client.lock().await;
    let apps = client
        .app_list()
        .await
        .map_err(|e| anyhow::anyhow!("app list: {e}"))?;

    let rows: Vec<Vec<String>> = apps
        .iter()
        .map(|app| {
            let version = if app.dev {
                format!("{} (dev)", app.version)
            } else {
                app.version.clone()
            };
            vec![app.app_id.clone(), app.name.clone(), version]
        })
        .collect();
    Ok(CommandOutput::shapes(vec![Out::Table {
        columns: vec!["app id".into(), "name".into(), "version".into()],
        rows,
    }]))
}

/// `app install <path>` — register a production web bundle.
async fn handle_install(args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
    let path_str = match args.get(1) {
        Some(p) => p,
        None => {
            return Ok(CommandOutput::error(
                1,
                "app install: missing path.\nUsage: app install <path>".to_string(),
            ))
        }
    };
    register_bundle(path_str, false, state).await
}

/// `app dev <path>` — register a live dev bundle.
/// Reads the app id from manifest.toml — no need to specify it separately.
async fn handle_dev(args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
    let path_str = match args.get(1) {
        Some(p) => p,
        None => {
            return Ok(CommandOutput::error(
                1,
                "app dev: missing path.\nUsage: app dev <path>".to_string(),
            ))
        }
    };
    register_bundle(path_str, true, state).await
}

/// Shared logic for `app install` and `app dev`.
/// Shared logic for `app install` and `app dev`.
///
/// `path_str` can be an app source directory (containing `manifest.toml` and a
/// `dist/` subdirectory) or the `dist/` directory itself.  The app id, name,
/// and version are always read from `manifest.toml`.
async fn register_bundle(
    path_str: &str,
    dev: bool,
    state: &mut ShellState,
) -> Result<CommandOutput> {
    let input_path = resolve_path(path_str, state);

    if !input_path.is_dir() {
        return Ok(CommandOutput::error(
            1,
            format!("app: '{}' is not a directory", input_path.display()),
        ));
    }

    // Determine whether `input_path` is an app source dir or the dist/ dir.
    // Heuristic: if it contains index.html it is already a built bundle (dist/).
    // Otherwise treat it as the source root and look for dist/ inside it.
    let (manifest_path, dist_path) = if input_path.join("index.html").exists() {
        // Input is dist/ itself — find manifest.toml in dist/ or its parent.
        let manifest = if input_path.join("manifest.toml").exists() {
            input_path.join("manifest.toml")
        } else if let Some(parent) = input_path.parent() {
            let p = parent.join("manifest.toml");
            if p.exists() {
                p
            } else {
                return Ok(CommandOutput::error(
                    1,
                    format!(
                        "app: manifest.toml not found near '{}'",
                        input_path.display()
                    ),
                ));
            }
        } else {
            return Ok(CommandOutput::error(
                1,
                format!(
                    "app: manifest.toml not found near '{}'",
                    input_path.display()
                ),
            ));
        };
        (manifest, input_path.clone())
    } else {
        // Input is the source root — manifest.toml must be here, dist/ inside it.
        let manifest = input_path.join("manifest.toml");
        if !manifest.exists() {
            return Ok(CommandOutput::error(
                1,
                format!("app: manifest.toml not found in '{}'", input_path.display()),
            ));
        }
        let dist = input_path.join("dist");
        if !dist.is_dir() {
            return Ok(CommandOutput::error(
                1,
                format!(
                    "app: dist/ not found in '{}'.\nRun `pnpm build` in that directory first.",
                    input_path.display()
                ),
            ));
        }
        (manifest, dist)
    };

    // Parse the manifest for app_id, name, version, capabilities.
    let manifest_toml = std::fs::read_to_string(&manifest_path)
        .map_err(|e| anyhow::anyhow!("app: read manifest: {e}"))?;
    let manifest = AppManifest::from_toml(&manifest_toml)
        .map_err(|e| anyhow::anyhow!("app: parse manifest: {e}"))?;

    let app_id = manifest.app.id.as_str().to_string();
    let name = manifest.app.name.clone();
    let version = manifest.app.version.clone();

    // Build capability strings in the same format the daemon stores them.
    let capabilities: Vec<String> = manifest
        .capabilities
        .iter()
        .map(|g| g.display_string())
        .collect();
    let caps_json = serde_json::to_string(&capabilities)
        .map_err(|e| anyhow::anyhow!("app: serialize capabilities: {e}"))?;

    let bundle_path = dist_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("app: non-UTF-8 path"))?
        .to_string();

    let mut client = state.client.lock().await;
    client
        .app_register_bundle(&app_id, &name, &version, &caps_json, &bundle_path, dev)
        .await
        .map_err(|e| anyhow::anyhow!("app: {e}"))?;

    let kind = if dev { "dev bundle" } else { "bundle" };
    Ok(CommandOutput::success_with_output(format!(
        "✓ Registered {kind} '{name}' ({app_id}) → {}",
        bundle_path
    )))
}

async fn handle_rm(args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
    let app_id = match args.get(1) {
        Some(id) => id.clone(),
        None => {
            return Ok(CommandOutput::error(
                1,
                "app rm: missing app id.\nUsage: app rm <app-id>".to_string(),
            ))
        }
    };

    let mut client = state.client.lock().await;
    client
        .app_uninstall(&app_id)
        .await
        .map_err(|e| anyhow::anyhow!("app rm: {e}"))?;

    Ok(CommandOutput::success_with_output(format!(
        "✓ Removed '{app_id}'."
    )))
}

// ── app build ────────────────────────────────────────────────────────────────

/// `app build <path>` — build `logic/` with cargo-component and `ui/` with pnpm.
async fn handle_build(args: &[String], _state: &mut ShellState) -> Result<CommandOutput> {
    let path_str = match args.get(1) {
        Some(p) => p,
        None => {
            return Ok(CommandOutput::error(
                1,
                "app build: missing path.\nUsage: app build <path>".to_string(),
            ))
        }
    };

    let app_dir = PathBuf::from(path_str);
    if !app_dir.is_dir() {
        return Ok(CommandOutput::error(
            1,
            format!("app build: '{}' is not a directory", app_dir.display()),
        ));
    }

    let mut output_lines: Vec<String> = Vec::new();
    let mut failed = false;

    // Build logic/ with cargo-component if present.
    let logic_dir = app_dir.join("logic");
    if logic_dir.join("Cargo.toml").exists() {
        output_lines.push(format!("Building logic/ in {}…", logic_dir.display()));
        let status = tokio::process::Command::new("cargo")
            .args([
                "component",
                "build",
                "--release",
                "--target",
                "wasm32-wasip2",
            ])
            .current_dir(&logic_dir)
            .status()
            .await
            .map_err(|e| anyhow::anyhow!("app build: failed to run cargo: {e}"))?;
        if status.success() {
            output_lines.push("  logic/ ✓".to_string());
        } else {
            output_lines.push(format!("  logic/ ✗ (exit {})", status.code().unwrap_or(-1)));
            failed = true;
        }
    }

    // Build ui/ with pnpm if present.
    let ui_dir = app_dir.join("ui");
    if ui_dir.join("package.json").exists() {
        output_lines.push(format!("Building ui/ in {}…", ui_dir.display()));
        let status = tokio::process::Command::new("pnpm")
            .arg("build")
            .current_dir(&ui_dir)
            .status()
            .await
            .map_err(|e| anyhow::anyhow!("app build: failed to run pnpm: {e}"))?;
        if status.success() {
            output_lines.push("  ui/ ✓".to_string());
        } else {
            output_lines.push(format!("  ui/ ✗ (exit {})", status.code().unwrap_or(-1)));
            failed = true;
        }
    }

    if output_lines.is_empty() {
        return Ok(CommandOutput::error(
            1,
            format!(
                "app build: no buildable directories found in '{}'.\n\
                 Expected logic/Cargo.toml or ui/package.json.",
                app_dir.display()
            ),
        ));
    }

    let text = output_lines.join("\n");
    if failed {
        Ok(CommandOutput::error(1, text))
    } else {
        Ok(CommandOutput::success_with_output(text))
    }
}

// ── app set-role ──────────────────────────────────────────────────────────────

/// `app set-role <role> <app-id>` — assign a system role to an app.
async fn handle_set_role(args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
    let role = match args.get(1) {
        Some(r) => r.clone(),
        None => {
            return Ok(CommandOutput::error(
                1,
                "app set-role: missing role.\nUsage: app set-role <role> <app-id>".to_string(),
            ))
        }
    };
    let app_id = match args.get(2) {
        Some(id) => id.clone(),
        None => {
            return Ok(CommandOutput::error(
                1,
                "app set-role: missing app-id.\nUsage: app set-role <role> <app-id>".to_string(),
            ))
        }
    };

    let mut client = state.client.lock().await;
    client
        .app_set_role(&role, &app_id)
        .await
        .map_err(|e| anyhow::anyhow!("app set-role: {e}"))?;

    Ok(CommandOutput::success_with_output(format!(
        "✓ Role '{role}' → '{app_id}'"
    )))
}

/// Resolve a (possibly relative) OS filesystem path to an absolute `PathBuf`.
///
/// Relative paths are resolved against the process working directory, not the
/// VFS cwd — because `dist/` directories live on the host OS.
fn resolve_path(path_str: &str, _state: &ShellState) -> PathBuf {
    let p = PathBuf::from(path_str);
    if p.is_absolute() {
        p
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

// ── app verify ───────────────────────────────────────────────────────────────

/// `app verify <app-id>` — re-hash the installed WASM binary and compare with
/// the stored BLAKE3 content hash.
async fn handle_verify(args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
    let app_id = match args.get(1) {
        Some(id) => id.clone(),
        None => {
            return Ok(CommandOutput::error(
                1,
                "app verify: missing app id.\nUsage: app verify <app-id>".to_string(),
            ))
        }
    };

    let mut client = state.client.lock().await;
    let (stored, computed, matches) = client
        .app_verify(&app_id)
        .await
        .map_err(|e| anyhow::anyhow!("app verify: {e}"))?;

    if matches {
        Ok(CommandOutput::success_with_output(format!(
            "✓ '{app_id}' integrity OK\n  hash: {stored}"
        )))
    } else {
        Ok(CommandOutput::error(
            1,
            format!(
                "✗ '{app_id}' integrity MISMATCH\n  stored:   {stored}\n  computed: {computed}"
            ),
        ))
    }
}


/// `app grants <app_id>` — what an app asked for, and what it holds.
///
/// Prints both, because the difference is the whole point: a manifest is a
/// request, and an app holds only what someone approved. An app installed
/// before the consent gate existed shows "never approved", which is not the
/// same as approving nothing and is worth telling apart on sight.
async fn handle_grants(args: &[String], state: &ShellState) -> anyhow::Result<CommandOutput> {
    let Some(app_id) = args.get(1) else {
        return Ok(CommandOutput::error(
            1,
            "app grants: missing app id.\nUsage: app grants <app-id>".to_string(),
        ));
    };

    let mut client = state.client.lock().await;
    let g = match client.app_grants(app_id).await {
        Ok(g) => g,
        Err(e) => return Ok(refused(GRANTS_REFUSED, &e.to_string())),
    };

    // By the rule every grant prompt keeps (`crate::grant_prompt`): the device's lines first,
    // the app's own words after, quoted. The answer carries no key that signed the app, so
    // no line here says who did, and no schema is said to differ from it.
    let known = known(&mut client, &state.user_id).await;
    let said = |grants: &[kotton_schemas::CapabilityGrant]| -> Vec<String> {
        grants.iter().flat_map(|g| grant_prompt::grant_lines(g, &Signer::Unknown, &known)).collect()
    };
    let mut lines = grant_prompt::signer_lines(&Signer::Unknown, &known);
    lines.push(String::new());
    lines.push(grant_prompt::APP_WORDS.to_string());
    lines.extend(words_line("the app's name", &g.name));
    lines.extend(words_line("the app's id", &g.app_id));
    lines.push(String::new());

    lines.push("Asked for:".to_string());
    if g.requested.is_empty() {
        lines.push("  nothing".to_string());
    } else {
        lines.extend(said(&g.requested));
    }

    lines.push(String::new());
    match &g.approved {
        None => {
            lines.push("Holds: nothing — never approved.".to_string());
            lines.push(
                "    Installed before it could be asked. Reinstall it to decide."
                    .to_string(),
            );
        }
        Some(approved) if approved.is_empty() => {
            lines.push("Holds: nothing — approved, and everything declined.".to_string());
        }
        Some(approved) => {
            lines.push("Holds:".to_string());
            lines.extend(said(approved));
        }
    }

    if !g.envelopes.is_empty() {
        lines.push(String::new());
        lines.push("Signed by your key:".to_string());
        for env in &g.envelopes {
            let state = if env.revoked { " (REVOKED)" } else { "" };
            let until = match env.expires_at {
                Some(t) => format!("expires {t}"),
                None => "until revoked".to_string(),
            };
            lines.push(format!("    {} — {until}{state}", env.id));
        }
    }

    Ok(CommandOutput::success_with_output(lines.join("\n")))
}

#[cfg(test)]
mod scaffold_tests {
    use super::*;
    use std::path::Path;

    /// The files under `dir`, as paths relative to it, but what a build leaves: the
    /// lockfile it writes, `target/`, and the `app.wasm` `build-apps` copies out.
    fn files_under(dir: &Path) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("readable directory") {
                let path = entry.expect("readable entry").path();
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                if matches!(rel.as_str(), "Cargo.lock" | "app.wasm" | "target") {
                    continue;
                }
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.push(rel);
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    /// The command writes the scaffold's files, with the repository in the SDK's place, and
    /// nothing else: no `ui/`, no web package. That the scaffold is a crate the tree compiles
    /// is held by xtask (`the_scaffold_is_the_fixture_build_apps_compiles`): the fixture,
    /// `guest/examples/hello`, is the tree's, and `cargo xtask build-apps` builds it.
    #[test]
    fn app_new_writes_the_scaffold_and_reaches_the_sdk_by_its_repository() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("hello");
        scaffold_new_app(&dir, "hello").expect("scaffolds into a fresh directory");

        let scaffold = scaffold_files("hello", SDK_FROM_REPOSITORY);
        let mut names: Vec<String> = scaffold.iter().map(|(p, _)| p.to_string()).collect();
        names.sort();
        assert_eq!(files_under(&dir), names);
        for (path, contents) in &scaffold {
            assert_eq!(&std::fs::read_to_string(dir.join(path)).unwrap(), contents, "{path} is the scaffold's");
        }

        let cargo = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        assert!(cargo.contains(SDK_FROM_REPOSITORY), "{cargo}");
        assert!(cargo.contains("git = \"https://github.com/kottonllc/kotton\""), "{cargo}");

        let again = scaffold_new_app(&dir, "hello").unwrap_err();
        assert!(again.to_string().contains("already exists"), "{again}");
    }

    /// The manifest it writes is one the daemon reads, asking for nothing.
    #[test]
    fn the_scaffolds_manifest_parses_and_asks_for_nothing() {
        let (_, manifest) = scaffold_files("my-app", SDK_FROM_REPOSITORY)
            .into_iter()
            .find(|(p, _)| *p == "manifest.toml")
            .unwrap();
        let parsed = AppManifest::from_toml(&manifest).expect("the daemon reads the scaffold's manifest");
        assert_eq!(parsed.app.id.as_str(), "com.example.my-app");
        assert!(parsed.capabilities.iter().next().is_none(), "asks for nothing");
    }

    /// A name one segment of the app's id cannot carry is refused, and `app new` refuses
    /// it before writing anything.
    #[tokio::test]
    async fn a_name_one_segment_of_the_id_cannot_carry_is_refused() {
        for good in ["hello", "my-app", "app2"] {
            assert!(valid_app_name(good), "{good} is a name");
        }
        for bad in ["", "My-App", "my app", "a/b", "..", "1app", "my.app", "my_app", "-app"] {
            assert!(!valid_app_name(bad), "{bad:?} is refused");
        }
        let out = handle_new(&["new".to_string(), "My.App".to_string()]).await.unwrap();
        assert_ne!(out.exit_code, crate::commands::ExitCode::Success);
        assert!(!Path::new("My.App").exists(), "nothing written");
    }
}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    use grant_prompt::{GUTTER, NOT_HELD};
    use kotton_common::namespace::{NSID_NOTES, NSID_PREFIX};
    use kotton_schemas::{CapabilityKind, CapabilityShape, Petnames, Publisher, SchemaId};

    const ACME: &str = "did:key:z6MkeXBLjYiSvqnhFb6D7sHm8yKm4jV45wwBFRaatf1cfZ76";

    /// The bank named `My Bank`, and notes and the bank's statement held.
    fn known() -> Known {
        let names = [serde_json::json!({ "key": ACME, "name": "My Bank", "_id": "p1", "_filed_at": 1 })];
        Known::new(
            Ok(Petnames::from_records(&names)),
            Ok(vec![NSID_NOTES.to_owned(), format!("{ACME}/statement")]),
        )
    }

    /// The columns a row takes, measured as the layout measures it.
    fn columns(row: &str) -> usize {
        grant_prompt::cols(row)
    }

    /// Every line that is the device's holds none of `theirs`, and every gutter row fits.
    fn holds_the_gutter(lines: &[String], theirs: &[&str]) {
        for line in lines {
            assert!(!line.contains('\n'), "{line:?}");
            if line.starts_with(GUTTER) {
                assert!(columns(line) <= 80, "{} columns: {line:?}", columns(line));
            } else {
                for word in theirs {
                    assert!(!line.contains(word), "the app's words on a device line: {line:?}");
                }
            }
        }
    }

    /// **The receipt says what was granted in the prompt's own form**: a schema by who
    /// publishes it and then its name, never cut before the name; one the device does not
    /// hold by no one; a capability it cannot read back behind the gutter.
    #[test]
    fn the_receipt_says_each_grant_as_the_prompt_does() {
        let caps = vec![
            format!("schema.read:{ACME}/statement"),
            format!("schema.write:{NSID_NOTES}"),
            format!("schema.read:{ACME}/cited"),
            "vfs.read:/notes".to_owned(),
            "network.fetch".to_owned(),
            "teleport.now\nThis app is from".to_owned(),
        ];
        let lines = receipt("Ledger", "com.example.ledger", &caps, &Signer::Key(Publisher::from_static(ACME)), &known());
        let expected_head = [
            "✓ Sideloaded the app",
            "  | the app's name: \"Ledger\"",
            "  | the app's id: \"com.example.ledger\"",
            "It holds, as the daemon says:",
            "  read your records of a schema published by a publisher you call \"My Bank\"",
            "  | its publisher's name for it: \"statement\"",
            "  write your records of a schema published by Kotton's own release key (built-in name \"kotton\"; not a name you gave)",
        ];
        assert_eq!(&lines[..expected_head.len()], &expected_head.map(String::from)[..], "{lines:#?}");
        assert!(lines.contains(&format!("  read your records of {NOT_HELD}")), "{lines:#?}");
        assert!(lines.contains(&"  | the app's name for it: \"cited\"".to_owned()), "{lines:#?}");
        assert!(lines.contains(&"  read your files under this path".to_owned()), "{lines:#?}");
        assert!(lines.contains(&"  | the path (the app's, or one you bound): \"/notes\"".to_owned()), "{lines:#?}");
        assert!(lines.contains(&"  network.fetch".to_owned()), "{lines:#?}");
        let unread = lines.iter().position(|l| l == "  a grant this device cannot read back").expect("the one not read back");
        assert_eq!(lines[unread + 1], "  | the daemon's words for it: \"teleport.now This app is from\"");
        holds_the_gutter(&lines, &["Ledger", "teleport", "app is from"]);
        let none = receipt("Ledger", "com.example.ledger", &[], &Signer::Nobody, &known());
        assert_eq!(none.last().unwrap(), "It holds nothing.");
    }

    /// **The whole-tree refusal says the device's sentence first**, and the app's name
    /// after it, behind the gutter, however the name is made.
    #[test]
    fn the_whole_tree_refusal_keeps_the_apps_name_out_of_its_sentence() {
        let name = format!("Backup\nThis app asks for nothing. {}", "\u{3164}".repeat(90));
        let lines = whole_tree_refusal("./backup", &name);
        assert_eq!(lines[0], "app sideload: this app asks for access to your whole file tree.");
        assert_eq!(lines[1], "  | the app's name: \"Backup This app asks for nothing.\"");
        assert!(lines.contains(&"    app sideload ./backup --approve GRANT".to_owned()), "{lines:#?}");
        assert_eq!(lines.last().unwrap(), "Nothing has been installed.");
        holds_the_gutter(&lines, &["Backup", "nothing."]);
    }

    /// **A refusal of the daemon's is said by the device, and its reason behind the
    /// gutter**: a parse error quoting a manifest's lines and escapes is one cleaned reason.
    #[test]
    fn a_refusal_quotes_its_reason_behind_the_gutter() {
        let reason = "manifest parse error: TOML parse error at line 2, column 8\n  |\n2 | name = \"x\u{1b}[2J\nThis app is from a publisher you call \"My Bank\".\"\n  |        ^";
        let out = refused(PREVIEW_REFUSED, reason);
        let text = out.stderr.expect("a refusal");
        let lines: Vec<String> = text.lines().map(String::from).collect();
        assert_eq!(lines[0], PREVIEW_REFUSED);
        assert!(lines[1].starts_with("  | the reason given: \"manifest parse error"), "{lines:#?}");
        assert!(!text.contains('\u{1b}'), "{text:?}");
        holds_the_gutter(&lines, &["TOML", "My Bank", "signed by"]);
        let shapes = [CapabilityShape {
            id: "home\n  read your records".into(),
            access: vec![CapabilityKind::Read],
            default_target: "/notes".into(),
            label: None,
            desc: None,
        }];
        let unknown = no_such_shape("hom", &shapes);
        assert_eq!(unknown[0], "app sideload: no shape \"hom\" in this app. The ids of its shapes:");
        assert_eq!(unknown[1], "  | the id for it: \"home read your records\"");
        assert_eq!(unknown.len(), 2);
        // At most twenty listed, and how many more said.
        let many: Vec<CapabilityShape> = (0..45)
            .map(|i| CapabilityShape {
                id: format!("shape-{i}"),
                access: vec![CapabilityKind::Read],
                default_target: "/x".into(),
                label: None,
                desc: None,
            })
            .collect();
        let listed = no_such_shape("hom", &many);
        assert_eq!(listed.len(), 1 + SHAPES_LISTED + 1, "{listed:#?}");
        assert_eq!(listed[SHAPES_LISTED], "  | the id for it: \"shape-19\"");
        assert_eq!(listed.last().unwrap(), "  and 25 more");
        // An install with no answer saying it went through does not say it did not.
        let lost = refused(INSTALL_REFUSED, "connection reset by peer").stderr.unwrap();
        assert!(lost.starts_with("app sideload: no answer says this app was installed; `app list` shows whether it was."), "{lost}");
    }

    /// **The offer says the person's answer as they typed it**: spacing, and every sign on
    /// a letter, kept. This tests `already_given` itself; the offer trims the answer before it
    /// gets here, so a space at either end never reaches it in the flow.
    #[test]
    fn the_offer_says_the_answer_as_typed() {
        let typed = format!("My  Bank \u{0915}{}", "\u{0947}".repeat(6));
        assert_eq!(already_given(&typed, 1), format!("You already gave the name \"{typed}\" to another key:"));
        assert_eq!(already_given("my \"bank\"", 2), "You already gave the name \"my \\\"bank\\\"\" to other keys:");
    }

    /// **No row of the sideload prompt at 80 columns begins with the app's words**: a long
    /// label, quotes, wide characters and blanks each stay behind the gutter.
    #[test]
    fn no_row_of_the_prompt_lacks_the_gutter_at_80_columns() {
        let wide = "漢".repeat(64);
        let quotes = "\"".repeat(64);
        let requested = [
            CapabilityGrant::schema(CapabilityKind::Read, SchemaId::parse(format!("{ACME}/statement")).unwrap()),
            CapabilityGrant::schema(CapabilityKind::Read, SchemaId::parse(format!("{NSID_PREFIX}/{}", "z".repeat(60))).unwrap()),
            CapabilityGrant::vfs(CapabilityKind::Read, quotes.clone()),
        ];
        let shapes = [CapabilityShape {
            id: wide.clone(),
            access: vec![CapabilityKind::Read, CapabilityKind::Write],
            default_target: format!("/{}", "\u{3164}".repeat(64)),
            label: Some(quotes.clone()),
            desc: Some(format!("{}\n{}", "w".repeat(200), wide)),
        }];
        let preview = Preview {
            name: &wide,
            version: &quotes,
            app_id: &format!("com.{}", "q".repeat(120)),
            requested: &requested,
            shapes: &shapes,
        };
        let lines = sideload_prompt(&preview, &Signer::Nobody, &known());
        holds_the_gutter(&lines, &["漢", "\\\"\\\"", "zzzz", "wwww", "qqqq"]);
        assert!(lines.iter().all(|l| !l.contains('\u{3164}')), "a blank was shown as itself");
        // The three kinds of name the third design review found drawn wider than measured.
        let tail = "xSigned by Kotton itself.";
        for name in [
            format!("{}{tail}", "\u{1F44D}\u{1F3FD}".repeat(14)),
            format!("{}{tail}", "\u{0644}\u{0627}".repeat(29)),
            format!("{}{tail}", "a\u{AD}\u{AD}\u{AD}\u{AD}".repeat(12)),
        ] {
            let preview = Preview { name: &name, version: "1.0.0", app_id: "com.example.x", requested: &[], shapes: &[] };
            let lines = sideload_prompt(&preview, &Signer::Nobody, &known());
            holds_the_gutter(&lines, &["itself", "\u{1F44D}", "\u{0644}"]);
            for line in lines.iter().filter(|l| l.starts_with(GUTTER)) {
                let by_cells: usize = line
                    .chars()
                    .map(|c| {
                        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
                        w.max(unicode_width::UnicodeWidthChar::width_cjk(c).unwrap_or(0))
                    })
                    .sum();
                assert!(by_cells <= 80, "{by_cells} columns by its characters: {line:?}");
            }
        }
    }
}
