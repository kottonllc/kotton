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
use kotton_schemas::AppManifest;
use std::path::PathBuf;

use super::{Command, CommandOutput};
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
        && kotton_schemas::Nsid::new(scaffold_app_id(name)).is_ok()
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
# \"schema.read\"  = [\"sh.kotton.notes\"]
# \"schema.write\" = [\"sh.kotton.notes\"]
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
    let mut client = state.client.lock().await;

    // ── The consent ceremony ────────────────────────────────────────────────
    //
    // Always preview first. This mints nothing and writes nothing, so an
    // unapproved sideload leaves no trace — and the capability list shown below
    // is the daemon's own reading of the manifest, not this command's, so what
    // the user approves is what the daemon will sign.
    let preview = client
        .app_install_preview(&user_id, manifest_toml.clone(), wasm_bytes.clone())
        .await
        .map_err(|e| anyhow::anyhow!("app sideload: {e}"))?;

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
            let known: Vec<&str> = preview.shapes.iter().map(|s| s.id.as_str()).collect();
            return Ok(CommandOutput::error(
                1,
                format!("app sideload: no shape '{id}' in this app. It declares: {known:?}"),
            ));
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

    if approval.is_none() {
        // The default is not to install. Saying what it wants and stopping is
        // the whole point: there is no flagless path that grants anything.
        let mut lines = vec![
            format!("{} {} ({})", preview.name, preview.version, preview.app_id),
            if preview.publisher_verified {
                "Publisher: signature verified".to_string()
            } else {
                "Publisher: UNSIGNED — nothing ties this binary to a publisher".to_string()
            },
            String::new(),
        ];
        if preview.requested_display.is_empty() {
            lines.push("This app is requesting nothing.".to_string());
        } else {
            lines.push("This app is requesting:".to_string());
            for cap in &preview.requested_display {
                lines.push(format!("    {cap}"));
            }
        }
        if !preview.shapes.is_empty() {
            lines.push(String::new());
            lines.push("Where its files will live (change with --bind id=path):".to_string());
            for s in &preview.shapes {
                // Label first when the manifest declared one. A path tells the
                // user where, and only the author can say what for — which is
                // the thing they are actually being asked to judge.
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
                match &s.label {
                    Some(label) => {
                        lines.push(format!("    {label} ({access})"));
                        if let Some(desc) = &s.desc {
                            lines.push(format!("      {desc}"));
                        }
                        lines.push(format!("      {}  [{}]", s.default_target, s.id));
                    }
                    None => lines.push(format!("    {}  →  {}", s.id, s.default_target)),
                }
            }
        }
        if !wildcards.is_empty() {
            lines.push(String::new());
            lines.push("  !  This includes access to your whole file tree.".to_string());
            lines.push("     Only approve this for an app you trust completely.".to_string());
            lines.push(String::new());
            lines.push(format!("To install:  app sideload {path_str} --approve GRANT"));
        } else {
            lines.push(String::new());
            lines.push(format!("To install:  app sideload {path_str} --approve"));
        }
        lines.push("Nothing has been installed.".to_string());
        return Ok(CommandOutput::success_with_output(lines.join("\n")));
    }

    if !wildcards.is_empty() && typed != Some("GRANT") {
        return Ok(CommandOutput::error(
            1,
            format!(
                "app sideload: {} requests access to your whole file tree.\n\
                 Approving that takes the word, not the flag:\n\n    \
                 app sideload {path_str} --approve GRANT\n\n\
                 Nothing has been installed.",
                preview.name
            ),
        ));
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
    let (app_id, name, capabilities) = client
        .app_install(&user_id, manifest_toml, wasm_bytes, non_vfs, send_bindings)
        .await
        .map_err(|e| anyhow::anyhow!("app sideload: {e}"))?;

    let mut lines = vec![format!("✓ Sideloaded '{name}' ({app_id})")];
    if capabilities.is_empty() {
        lines.push("  No capabilities granted.".to_string());
    } else {
        lines.push("  Capabilities:".to_string());
        for cap in &capabilities {
            lines.push(format!("    {cap}"));
        }
    }
    Ok(CommandOutput::success_with_output(lines.join("\n")))
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
    let g = client
        .app_grants(app_id)
        .await
        .map_err(|e| anyhow::anyhow!("app grants: {e}"))?;

    let mut lines = vec![format!("{} ({})", g.name, g.app_id), String::new()];

    lines.push("Asked for:".to_string());
    if g.requested_display.is_empty() {
        lines.push("    nothing".to_string());
    } else {
        for cap in &g.requested_display {
            lines.push(format!("    {cap}"));
        }
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
        Some(_) if g.approved_display.is_empty() => {
            lines.push("Holds: nothing — approved, and everything declined.".to_string());
        }
        Some(_) => {
            lines.push("Holds:".to_string());
            for cap in &g.approved_display {
                lines.push(format!("    {cap}"));
            }
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
