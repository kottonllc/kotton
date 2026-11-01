// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capability grants — the minimum-surface access declarations apps must provide.
//!
//! Every operation a Kotton app performs must be covered by a declared
//! [`CapabilityGrant`]. Blanket grants are rejected — every grant must
//! reference a specific schema or a specific VFS path.
//!
//! The daemon enforces grants at every IPC call. The v0.6 WASM sandbox
//! enforces them at the process boundary — a WASM app literally cannot issue
//! an IPC request it was not granted, regardless of what it tries.
//!
//! ## Examples
//!
//! ```
//! # use kotton_schemas::capability::{CapabilityGrant, CapabilityKind};
//! # use kotton_schemas::Nsid;
//! // A notes app that reads and writes notes, and reads contacts:
//! let grants = vec![
//!     CapabilityGrant::schema(CapabilityKind::Read,  Nsid::from_static("sh.kotton.notes")),
//!     CapabilityGrant::schema(CapabilityKind::Write, Nsid::from_static("sh.kotton.notes")),
//!     CapabilityGrant::schema(CapabilityKind::Read,  Nsid::from_static("sh.kotton.contacts")),
//! ];
//! ```

use crate::Nsid;
use serde::{Deserialize, Serialize};

/// The access direction a capability grant covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// Read records / read VFS files.
    Read,
    /// Create, update, or delete records / write VFS files.
    Write,
    /// Invoke an action capability that is neither a read nor a write of a named
    /// resource — using a media device, initiating/receiving a call, launching an
    /// app, etc. (H1 — see `ideas/CAPABILITY-UNIFICATION-MEDIA-CALL.md`).
    Use,
}

/// A media device an app may be granted the use of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum MediaDevice {
    Microphone,
    Camera,
    Screen,
}

/// The direction of a call capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum CallDirection {
    Initiate,
    Receive,
}

/// The direction of a messaging capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    Send,
    Receive,
}

/// The resource or action a capability grant applies to.
///
/// `Schema`/`Vfs` are read/write resources; the remaining variants are **action**
/// capabilities (kind [`CapabilityKind::Use`]) that unify media/call/apps/etc.
/// onto the same signed, revocable grant path as schema/VFS
/// (H1 — see `ideas/CAPABILITY-UNIFICATION-MEDIA-CALL.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
#[serde(tag = "resource", rename_all = "snake_case")]
pub enum CapabilityTarget {
    /// A named schema — `schema.read:sh.kotton.notes`.
    Schema { nsid: Nsid },
    /// A VFS path prefix — `vfs.read:/notes`.
    Vfs { path: String },
    /// A media device — `media.microphone` / `media.camera` / `media.screen`.
    Media { device: MediaDevice },
    /// A call capability — `call.initiate` / `call.receive`.
    Call { direction: CallDirection },
    /// A messaging capability — `messages.send` / `messages.receive`.
    Messages { direction: MessageDirection },
    /// Subscribe to the event bus — `events.subscribe`.
    Events,
    /// Outbound network fetch — `network.fetch`.
    Network,
    /// Ask a model that runs on this machine — `infer.run` (RFC-0085).
    ///
    /// **Exclusive with every outbound interface**, which is enforced where the
    /// interfaces are handed out rather than here: granted alongside `Call` or
    /// `Messages`, it makes the component fail to instantiate, because
    /// `DeclaredInterfaces::add_to_linker` refuses to build a linker holding
    /// both. `Network` is not in that list and needs no refusal — it lights no
    /// interface in `world app` at all; `external-net` belongs to `world
    /// fetcher`, whose linker this one cannot be. RFC-0085 IN8 is what the
    /// exclusion buys: a hostile instruction in an imported passage reaches at
    /// worst a wrong answer, because there is nothing in the same component to
    /// carry it out.
    ///
    /// Not scoped by model. Which models exist is the person's installation, not
    /// the app's declaration, and a grant naming one would be a durable
    /// identifier two apps could join on for no benefit.
    Infer,
    /// Launch another installed app as a separate confined guest — `apps.launch`.
    AppLaunch,
    /// Render custom UI surfaces — `ui.custom`.
    Ui,
    /// An extension's own quarantine namespace — `quarantine:<extension-id>`
    /// (RFC-0049).
    ///
    /// The landing zone a **fetcher** writes external content into. Deliberately
    /// *not* a [`CapabilityTarget::Vfs`] grant, because its semantics are the
    /// opposite of a path grant's: a fetcher may write here and read back **only
    /// what it itself wrote**, and may reach nothing else in the store. Modelling
    /// it as its own target keeps that asymmetry structural rather than a
    /// convention some future call site could forget.
    ///
    /// The `extension_id` scopes the namespace, so one extension can never name
    /// another's quarantine — the id is bound at grant issue time by the daemon,
    /// never taken from the guest.
    ///
    /// There is deliberately **no manifest key** for this target: an author
    /// declares the *fetcher class*, and the daemon mints the quarantine grant
    /// against the id it verified at install. `AppManifest::from_toml` rejects
    /// unknown capability keys, so an author cannot hand-write one naming
    /// somebody else's namespace.
    Quarantine { extension_id: String },
    /// Authority to admit a member to one root — `org.invite:<root>`, kind
    /// [`CapabilityKind::Use`] (RFC-0088 rule 5).
    ///
    /// **Held by a person, never by an app.** A root an org owns is the org's to let people
    /// into, and the org delegates that by issuing this in a grant envelope to a member;
    /// whoever holds it may admit someone. It is a capability and not a role: the code asks
    /// whether an envelope from the root's owner carries this target, and a *name* for a
    /// bundle that includes it — "maintainer", say — lives in the project's records and
    /// nowhere in the code (DEC-0038, DEC-0080). There is deliberately **no manifest key** for
    /// it, so an app cannot ask for it and `AppManifest::from_toml` refuses the attempt.
    ///
    /// `root` is the root's id as its members' sets hold it.
    OrgInvite { root: String },
    /// Membership of one root — `root.member:<root>`, kind [`CapabilityKind::Read`] — the
    /// grant that says an identity is in the root (R12: membership is who may read).
    ///
    /// Issued by the root's owner, or by a holder of [`CapabilityTarget::OrgInvite`] on the
    /// same root with the owner's envelope beside it. Like `OrgInvite`, it has no manifest
    /// key: membership is a person's, and a grant to software is not membership (Article IV).
    RootMember { root: String },
}

/// A single capability declaration. Apps must list all grants they require.
///
/// At install time the daemon presents the list to the user for approval.
/// After approval the daemon enforces every grant at the IPC boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct CapabilityGrant {
    pub kind: CapabilityKind,
    pub target: CapabilityTarget,
}

impl CapabilityGrant {
    /// Construct a schema-scoped capability grant.
    pub fn schema(kind: CapabilityKind, nsid: Nsid) -> Self {
        Self {
            kind,
            target: CapabilityTarget::Schema { nsid },
        }
    }

    /// Construct a VFS path–scoped capability grant.
    pub fn vfs(kind: CapabilityKind, path: impl Into<String>) -> Self {
        Self {
            kind,
            target: CapabilityTarget::Vfs { path: path.into() },
        }
    }

    /// Construct a `Use`-kind action grant for the given target. Used for the
    /// media/call/messages/events/network/apps.launch/ui capabilities (H1).
    pub fn action(target: CapabilityTarget) -> Self {
        Self {
            kind: CapabilityKind::Use,
            target,
        }
    }

    /// Use of a media device (`media.microphone` / `media.camera` / `media.screen`).
    pub fn media(device: MediaDevice) -> Self {
        Self::action(CapabilityTarget::Media { device })
    }

    /// A call capability (`call.initiate` / `call.receive`).
    pub fn call(direction: CallDirection) -> Self {
        Self::action(CapabilityTarget::Call { direction })
    }

    /// A messaging capability (`messages.send` / `messages.receive`).
    pub fn messages(direction: MessageDirection) -> Self {
        Self::action(CapabilityTarget::Messages { direction })
    }

    /// Authority to admit a member to `root` (`org.invite:<root>`), which a root's owner
    /// delegates to a person (RFC-0088 rule 5).
    pub fn org_invite(root: impl Into<String>) -> Self {
        Self::action(CapabilityTarget::OrgInvite { root: root.into() })
    }

    /// Membership of `root` (`root.member:<root>`) — read, because membership is who may
    /// read a root (RFC-0071 R12).
    pub fn root_member(root: impl Into<String>) -> Self {
        Self {
            kind: CapabilityKind::Read,
            target: CapabilityTarget::RootMember { root: root.into() },
        }
    }

    /// Render this grant as its canonical display / storage string, matching the
    /// manifest capability keys: `schema.read:nsid`, `vfs.write:/path`, or an
    /// action key like `media.camera` / `call.initiate` / `apps.launch`. Single
    /// source of truth so a new `CapabilityTarget` variant is rendered in one
    /// place, not re-matched across the shell / CLI / daemon (H1).
    pub fn display_string(&self) -> String {
        let rw = match self.kind {
            CapabilityKind::Read => "read",
            CapabilityKind::Write => "write",
            CapabilityKind::Use => "use",
        };
        match &self.target {
            CapabilityTarget::Schema { nsid } => format!("schema.{rw}:{}", nsid.as_str()),
            CapabilityTarget::Vfs { path } => format!("vfs.{rw}:{path}"),
            CapabilityTarget::Media { device } => match device {
                MediaDevice::Microphone => "media.microphone",
                MediaDevice::Camera => "media.camera",
                MediaDevice::Screen => "media.screen",
            }
            .to_string(),
            CapabilityTarget::Call { direction } => match direction {
                CallDirection::Initiate => "call.initiate",
                CallDirection::Receive => "call.receive",
            }
            .to_string(),
            CapabilityTarget::Messages { direction } => match direction {
                MessageDirection::Send => "messages.send",
                MessageDirection::Receive => "messages.receive",
            }
            .to_string(),
            CapabilityTarget::Events => "events.subscribe".to_string(),
            CapabilityTarget::Network => "network.fetch".to_string(),
            CapabilityTarget::Infer => "infer.run".to_string(),
            CapabilityTarget::AppLaunch => "apps.launch".to_string(),
            CapabilityTarget::Ui => "ui.custom".to_string(),
            CapabilityTarget::Quarantine { extension_id } => {
                format!("quarantine.{rw}:{extension_id}")
            }
            CapabilityTarget::OrgInvite { root } => format!("org.invite:{root}"),
            CapabilityTarget::RootMember { root } => format!("root.member:{root}"),
        }
    }
}

/// A set of [`CapabilityGrant`]s declared by an app.
///
/// Used by the sandbox and the daemon to check whether a particular operation
/// is permitted before executing it.
///
/// # Examples
///
/// ```
/// # use kotton_schemas::capability::{CapabilityGrant, CapabilityKind, CapabilityTarget, CapabilitySet};
/// # use kotton_schemas::Nsid;
/// let grants = vec![
///     CapabilityGrant::schema(CapabilityKind::Read, Nsid::from_static("sh.kotton.notes")),
/// ];
/// let set = CapabilitySet::new(grants);
/// assert!(set.allows(&CapabilityKind::Read, &CapabilityTarget::Schema {
///     nsid: Nsid::from_static("sh.kotton.notes"),
/// }));
/// assert!(!set.allows(&CapabilityKind::Write, &CapabilityTarget::Schema {
///     nsid: Nsid::from_static("sh.kotton.notes"),
/// }));
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet(Vec<CapabilityGrant>);

/// Who approved an install's capabilities, and therefore whose decision the
/// user's signing key is about to attest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsentSource {
    /// A human was shown these grants and said yes, through a client holding
    /// their session. The only source that may mint authority for an app the
    /// user chose to install.
    User,
    /// An app compiled into the Kotton binary, installed at boot before any user
    /// has logged in. Nobody is at the keyboard, and no envelope is signed on
    /// this path — the app runs on its declared set until a user approves it.
    SystemBundled,
}

/// Capabilities a caller has **explicitly approved** for an install.
///
/// Before this type existed, `app_install` read `manifest.capabilities` and
/// signed them with the user's identity key, 365-day validity, no approval step
/// ([`IDEA-install-consent-gate`], security-audit finding H2). The signature
/// attested "the user's key signed these bytes" and was produced automatically
/// for whatever the app asked for — including, after H1, `media.camera`.
///
/// **There is deliberately no `From<AppManifest>` and no `Default`.** The defect
/// was not a missing check; it was that "what the app declared" could reach a
/// signature without anyone having said yes, and a check would have been one
/// more thing to remember. A value of this type is a claim that something
/// outside the install function approved these grants, and [`ConsentSource`]
/// names which something. Constructing one is the distinct step the audit asked
/// for — you cannot write the auto-mint back by accident, only on purpose and
/// under a name that says what you did.
///
/// [`IDEA-install-consent-gate`]: https://kotton.sh/records/IDEA-install-consent-gate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedCapabilities {
    grants: Vec<CapabilityGrant>,
    source: ConsentSource,
}

impl ApprovedCapabilities {
    /// A human approved exactly these grants, through a client holding their session.
    ///
    /// The daemon cannot cryptographically verify that a human was present — that
    /// is the structural limit `IDEA-install-consent-gate` names, and it is why
    /// the guarantee here is "the daemon signs only a set a caller named", not
    /// "consent is proven". What this removes is the path where nobody named one.
    pub fn approved_by_user(grants: Vec<CapabilityGrant>) -> Self {
        Self { grants, source: ConsentSource::User }
    }

    /// An app compiled into the binary, installed at boot with no user present.
    ///
    /// Named separately so that a reader of the install path can see, at the call
    /// site, that no human approved this and no user key signs it.
    pub fn system_bundled(grants: Vec<CapabilityGrant>) -> Self {
        Self { grants, source: ConsentSource::SystemBundled }
    }

    /// The approved grants.
    pub fn grants(&self) -> &[CapabilityGrant] {
        &self.grants
    }

    /// Who approved them.
    pub fn source(&self) -> ConsentSource {
        self.source
    }

    /// Build the approved set from **bindings**, not from grants a caller sent.
    ///
    /// This is the constructor RFC-0021's ceremony needs, and it exists instead
    /// of loosening [`Self::is_subset_of`]. The subset rule refuses anything the
    /// manifest did not request, which is what stops a client widening a grant —
    /// and it also refuses a user's rebinding of `/notes` to `/journal`, because
    /// that is not a grant the manifest requested either
    /// ([`TASK-the-subset-rule-forbids-the-binding`]).
    ///
    /// Loosening the rule for VFS targets would have let a client move a grant to
    /// `/` and call it a rebinding. So the client does not send a grant at all:
    /// it sends `(shape id, chosen path)`, and this builds the grant from the
    /// **host's own reading of the manifest**, substituting only the target. A
    /// capability the manifest never declared cannot be produced here — not
    /// because it is checked for, but because there is no shape to name.
    ///
    /// An unknown shape id is an error rather than a skip: a client naming a
    /// shape that does not exist has misread the manifest, and silently
    /// installing with fewer grants than the user was shown is the wrong
    /// recovery.
    ///
    /// [`TASK-the-subset-rule-forbids-the-binding`]: https://kotton.sh/records/TASK-the-subset-rule-forbids-the-binding
    pub fn from_bindings(
        shapes: &[crate::CapabilityShape],
        bindings: &[(String, String)],
        also_approved: Vec<CapabilityGrant>,
    ) -> Result<Self, String> {
        for (id, _) in bindings {
            if !shapes.iter().any(|s| &s.id == id) {
                return Err(format!(
                    "no capability shape '{id}' in this app's manifest — \
                     the daemon binds only what the app declared"
                ));
            }
        }

        let mut grants = Vec::new();
        for shape in shapes {
            let target = bindings
                .iter()
                .find(|(id, _)| id == &shape.id)
                .map(|(_, path)| path.as_str())
                .unwrap_or(&shape.default_target);
            // One shape, one target, one grant per kind it carries. Binding
            // moves the resource; it never changes what may be done there.
            for kind in &shape.access {
                grants.push(CapabilityGrant::vfs(kind.clone(), target));
            }
        }
        grants.extend(also_approved);

        Ok(Self {
            grants,
            source: ConsentSource::User,
        })
    }

    /// Whether this approval is admissible for an app declaring `requested`
    /// and `shapes`.
    ///
    /// The rule [`Self::is_subset_of`] enforces — every approved grant must be
    /// one the manifest asked for — is right for everything except the resource
    /// a user is invited to *move*. A rebinding of `/notes` to `/journal` is not
    /// a grant the manifest requested, and refusing it refuses RFC-0021's
    /// ceremony ([`TASK-the-subset-rule-forbids-the-binding`]).
    ///
    /// So VFS grants are judged against the **shapes** rather than the targets:
    /// admissible if the manifest declared a shape of that kind. Everything else
    /// is judged exactly as before.
    ///
    /// **What this gives up, stated plainly.** Where the daemon could previously
    /// say "this app holds exactly the paths its manifest named", it can now say
    /// only "this app holds as many VFS resources as its manifest declared, of
    /// the kinds it declared". Binding moves *which path* from the manifest to
    /// the caller — that is what binding is — and the daemon cannot verify a
    /// human chose it, only that the shape set was not grown. That bound is the
    /// one worth keeping and it is kept: an app declaring one read shape cannot
    /// come out of install holding two, or holding a write.
    ///
    /// Evaluated from the manifest at the point of use rather than trusted from
    /// how the value was constructed, so a value built by any route gets the
    /// same answer.
    ///
    /// [`TASK-the-subset-rule-forbids-the-binding`]: https://kotton.sh/records/TASK-the-subset-rule-forbids-the-binding
    pub fn is_admissible_for(
        &self,
        requested: &[CapabilityGrant],
        shapes: &[crate::CapabilityShape],
    ) -> bool {
        let asked: Vec<String> = requested.iter().map(|g| g.display_string()).collect();
        let mut vfs_seen = 0usize;
        for grant in &self.grants {
            match &grant.target {
                CapabilityTarget::Vfs { .. } => {
                    if !shapes.iter().any(|s| s.access.contains(&grant.kind)) {
                        return false;
                    }
                    vfs_seen += 1;
                }
                _ => {
                    if !asked.contains(&grant.display_string()) {
                        return false;
                    }
                }
            }
        }
        // The count is half the bound. Without it an app declaring one read
        // shape could be approved for ten, each individually "of a declared
        // kind" — widening by repetition rather than by naming something new.
        //
        // Counted over *kinds*, not shapes, since 2026-09-03: one shape with
        // `access = ["read", "write"]` legitimately yields two grants.
        let allowed: usize = shapes.iter().map(|s| s.access.len()).sum();
        vfs_seen <= allowed
    }

    /// Whether every approved grant was actually requested by `requested`.
    ///
    /// The daemon will not sign a capability the app never asked for, so a
    /// client cannot use the approval channel to *widen* a grant — only to
    /// narrow or accept what the manifest declared. Compared by
    /// [`CapabilityGrant::display_string`], which is the same rendering the user
    /// was shown.
    pub fn is_subset_of(&self, requested: &[CapabilityGrant]) -> bool {
        let asked: Vec<String> = requested.iter().map(|g| g.display_string()).collect();
        self.grants
            .iter()
            .all(|g| asked.contains(&g.display_string()))
    }
}

impl CapabilitySet {
    /// Create a new set from a list of grants.
    /// The grants in this set.
    ///
    /// Added 2026-08-24 so the host can build a component linker from what an app
    /// *declared* rather than handing every app every interface. `allows` answers
    /// "may it do this", which is the wrong question at link time — there the
    /// question is "does it get to ask at all" (RFC-0068).
    pub fn grants_slice(&self) -> &[CapabilityGrant] {
        &self.0
    }

    pub fn new(grants: Vec<CapabilityGrant>) -> Self {
        Self(grants)
    }

    /// Returns `true` if the set contains a grant that covers `kind` on `target`.
    ///
    /// VFS grants match prefix-style: a grant for `/notes` covers `/notes/todo.md`.
    /// A root grant (`/`) covers the entire VFS — the broad, user-approved breadth a
    /// shell or backup tool requests (RFC-0021/RFC-0028).
    ///
    /// Both the grant prefix and the requested path are normalized before comparison
    /// so that `..` traversal sequences cannot bypass the prefix check.
    pub fn allows(&self, kind: &CapabilityKind, target: &CapabilityTarget) -> bool {
        self.0.iter().any(|g| {
            if &g.kind != kind {
                return false;
            }
            match (&g.target, target) {
                (CapabilityTarget::Schema { nsid: a }, CapabilityTarget::Schema { nsid: b }) => {
                    a == b
                }
                (CapabilityTarget::Vfs { path: prefix }, CapabilityTarget::Vfs { path: req }) => {
                    let norm_prefix = normalize_vfs_path(prefix);
                    let norm_req = normalize_vfs_path(req);
                    // A root grant covers everything (every normalized path is under `/`).
                    // Otherwise require an exact match or a descendant of `prefix/` — the
                    // trailing slash stops `/notes` from covering a sibling like
                    // `/notesother`. (Without the root special-case, `format!("{}/", "/")`
                    // is `"//"` and a `/` grant would cover only `/` itself.)
                    norm_prefix == "/"
                        || norm_req == norm_prefix
                        || norm_req.starts_with(&format!("{}/", norm_prefix))
                }
                // Action capabilities (H1) match by exact target equality — there
                // is no prefix/scope semantics for using the camera or launching an
                // app. `kind` already matched above (Use == Use).
                (CapabilityTarget::Media { device: a }, CapabilityTarget::Media { device: b }) => {
                    a == b
                }
                (CapabilityTarget::Call { direction: a }, CapabilityTarget::Call { direction: b }) => {
                    a == b
                }
                (
                    CapabilityTarget::Messages { direction: a },
                    CapabilityTarget::Messages { direction: b },
                ) => a == b,
                (CapabilityTarget::Events, CapabilityTarget::Events)
                | (CapabilityTarget::Network, CapabilityTarget::Network)
                | (CapabilityTarget::Infer, CapabilityTarget::Infer)
                | (CapabilityTarget::AppLaunch, CapabilityTarget::AppLaunch)
                | (CapabilityTarget::Ui, CapabilityTarget::Ui) => true,
                // A quarantine grant covers exactly one extension's own
                // namespace — never another's, and never with prefix breadth.
                (
                    CapabilityTarget::Quarantine { extension_id: a },
                    CapabilityTarget::Quarantine { extension_id: b },
                ) => a == b,
                // Authority over one root covers that root and no other — never a prefix,
                // never "every root the org owns".
                (CapabilityTarget::OrgInvite { root: a }, CapabilityTarget::OrgInvite { root: b })
                | (CapabilityTarget::RootMember { root: a }, CapabilityTarget::RootMember { root: b }) => {
                    a == b
                }
                _ => false,
            }
        })
    }

    /// Iterate over all grants in the set.
    pub fn iter(&self) -> impl Iterator<Item = &CapabilityGrant> {
        self.0.iter()
    }

    /// Number of grants in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the set contains no grants.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
/// Moved here from `core/fs` 2026-08-21. Its own doc already said why it must be
/// shared — *"the sealed replication verbs address the same key space and must
/// agree with it exactly"* — and holding it in `fs` made `sync` depend on `fs`
/// to get that agreement. Beside `normalize_vfs_path`, which it wraps, both see
/// one copy and neither owns it.
///
/// Map a caller's path onto a storage key.
///
/// Normalises separators, collapses `.` and `..` so a traversal cannot resolve
/// to a sibling key, and strips the leading slash. The capability check already
/// rejects traversal (audit H3); this must not honour it either, which is
/// defence in depth rather than duplication.
///
/// Public because the VFS views above this crate (`kotton_store::fs_view`, the
/// app daemon) address the same key space and must agree with it exactly — a
/// second implementation is how the two would quietly diverge. The sealed
/// replication verbs do not use it: a key a peer names is refused when it is
/// not canonical, never rewritten into one that is
/// (`kotton_sys::store::StorageKey`, kotton #275).
pub fn to_object_key(path: &str) -> String {
    let unix = path.replace('\\', "/");
    normalize_vfs_path(&unix)
        .trim_start_matches('/')
        .to_string()
}


/// Normalize a VFS path string by resolving `.` and `..` components.
///
/// The result always starts with `/` and never escapes the root. For example:
/// - `/notes/../secrets` → `/secrets`
/// - `/notes/../../etc/passwd` → `/etc/passwd` (traversal visible; grant check will reject it)
/// - `/../../../etc` → `/etc`
///
/// This function does **not** enforce access boundaries — it only canonicalizes the
/// string so that `CapabilitySet::allows` can do a reliable prefix comparison.
/// The escape guard lives in the sandbox layer.
pub fn normalize_vfs_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let grant = CapabilityGrant::vfs(CapabilityKind::Read, "/notes");
        let json = serde_json::to_string(&grant).unwrap();
        let back: CapabilityGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, CapabilityKind::Read);
        match back.target {
            CapabilityTarget::Vfs { path } => assert_eq!(path, "/notes"),
            _ => panic!("expected Vfs target"),
        }
    }

    #[test]
    fn normalize_vfs_path_basic() {
        assert_eq!(normalize_vfs_path("/notes"), "/notes");
        assert_eq!(normalize_vfs_path("/notes/todo.md"), "/notes/todo.md");
        assert_eq!(normalize_vfs_path("/"), "/");
        assert_eq!(normalize_vfs_path(""), "/");
    }

    #[test]
    fn normalize_vfs_path_traversal() {
        assert_eq!(normalize_vfs_path("/notes/../secrets"), "/secrets");
        assert_eq!(normalize_vfs_path("/notes/../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_vfs_path("/../../../etc"), "/etc");
        assert_eq!(normalize_vfs_path("/a/b/c/../../d"), "/a/d");
    }

    #[test]
    fn normalize_vfs_path_dots() {
        assert_eq!(normalize_vfs_path("/notes/./todo.md"), "/notes/todo.md");
        assert_eq!(normalize_vfs_path("/./notes"), "/notes");
    }

    /// **Inviting is a capability on one root, checked as a capability** (RFC-0088 rule 5,
    /// DEC-0080). An invite on one root is not an invite on another, it is not membership,
    /// and membership is not an invite — each is asked for by its own target and kind.
    #[test]
    fn inviting_and_membership_are_capabilities_on_one_root() {
        let held = CapabilitySet::new(vec![CapabilityGrant::org_invite("r1")]);
        let invite = |r: &str| CapabilityTarget::OrgInvite { root: r.into() };
        let member = |r: &str| CapabilityTarget::RootMember { root: r.into() };
        assert!(held.allows(&CapabilityKind::Use, &invite("r1")));
        assert!(!held.allows(&CapabilityKind::Use, &invite("r2")), "an invite is for one root");
        assert!(!held.allows(&CapabilityKind::Read, &member("r1")), "inviting is not membership");
        let member_of = CapabilitySet::new(vec![CapabilityGrant::root_member("r1")]);
        assert!(member_of.allows(&CapabilityKind::Read, &member("r1")));
        assert!(!member_of.allows(&CapabilityKind::Use, &invite("r1")), "membership is not inviting");
        assert_eq!(CapabilityGrant::org_invite("r1").display_string(), "org.invite:r1");
        assert_eq!(CapabilityGrant::root_member("r1").display_string(), "root.member:r1");
    }

    /// Neither has a manifest key: an app cannot ask to admit people to a root, or to be in
    /// one, because both are a person's (Article IV — a grant to software is not membership).
    #[test]
    fn an_app_cannot_declare_inviting_or_membership() {
        for key in ["org.invite", "root.member"] {
            let src = format!(
                "[app]\nid = \"com.acme.x\"\nname = \"X\"\nversion = \"0.1.0\"\n\n[capabilities]\n\"{key}\" = []\n"
            );
            assert!(crate::AppManifest::from_toml(&src).is_err(), "{key} was accepted from a manifest");
        }
    }

    #[test]
    fn allows_traversal_bypasses_prefix_check() {
        // With normalization, a grant for /notes does NOT cover /etc/passwd
        // even when the raw path contains /notes/../../../etc/passwd.
        let grants = vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")];
        let set = CapabilitySet::new(grants);
        assert!(!set.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Vfs {
                path: "/notes/../../../etc/passwd".to_string(),
            }
        ));
    }

    #[test]
    fn allows_sibling_prefix_is_not_covered() {
        // A grant for /notes must NOT cover a sibling whose name merely shares the
        // prefix (e.g. /notesother) — the trailing-slash boundary guards this.
        let grants = vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")];
        let set = CapabilitySet::new(grants);
        assert!(!set.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Vfs {
                path: "/notesother/x".to_string(),
            }
        ));
    }

    #[test]
    fn allows_rejects_h3_ephemeral_guest_attack_vectors() {
        // The ephemeral-guest path (kuserd `handle_peer_request`) used to gate
        // scoping with a raw `req_path.starts_with(grant_path)`, which a
        // network peer could bypass two ways (audit H3). Both must be denied
        // when routed through `allows`, which now guards that path.
        let set = CapabilitySet::new(vec![CapabilityGrant::vfs(CapabilityKind::Read, "/shared")]);
        let read = CapabilityKind::Read;
        let denied = [
            "/shared/../../etc/identity", // traversal escapes the grant root
            "/shared-private/secret",     // sibling whose name shares the prefix
        ];
        for path in denied {
            assert!(
                !set.allows(&read, &CapabilityTarget::Vfs { path: path.into() }),
                "H3: `/shared` grant must NOT cover `{path}`"
            );
        }
        // The legitimate in-scope path is still allowed.
        assert!(set.allows(
            &read,
            &CapabilityTarget::Vfs {
                path: "/shared/report.txt".into()
            }
        ));
    }

    #[test]
    fn root_grant_covers_entire_vfs() {
        // A `/` grant (what the shell requests) covers the root itself and every
        // descendant — read and write alike.
        let set = CapabilitySet::new(vec![
            CapabilityGrant::vfs(CapabilityKind::Read, "/"),
            CapabilityGrant::vfs(CapabilityKind::Write, "/"),
        ]);
        for path in ["/", "/hello.txt", "/notes", "/notes/todo.md", "/a/b/c"] {
            assert!(
                set.allows(
                    &CapabilityKind::Write,
                    &CapabilityTarget::Vfs { path: path.into() }
                ),
                "root write grant should cover {path}"
            );
            assert!(
                set.allows(
                    &CapabilityKind::Read,
                    &CapabilityTarget::Vfs { path: path.into() }
                ),
                "root read grant should cover {path}"
            );
        }
        // Kind still discriminates: a read-only root grant does not permit writes.
        let read_only = CapabilitySet::new(vec![CapabilityGrant::vfs(CapabilityKind::Read, "/")]);
        assert!(!read_only.allows(
            &CapabilityKind::Write,
            &CapabilityTarget::Vfs {
                path: "/hello.txt".into()
            }
        ));
    }

    // ── Quarantine (RFC-0049 fetcher class) ───────────────────────────────────

    #[test]
    fn a_quarantine_grant_covers_only_its_own_extension() {
        let mine = CapabilityTarget::Quarantine {
            extension_id: "sh.kotton.feed-reader".into(),
        };
        let theirs = CapabilityTarget::Quarantine {
            extension_id: "sh.kotton.other".into(),
        };
        let set = CapabilitySet::new(vec![
            CapabilityGrant {
                kind: CapabilityKind::Write,
                target: mine.clone(),
            },
            CapabilityGrant {
                kind: CapabilityKind::Read,
                target: mine.clone(),
            },
        ]);
        assert!(set.allows(&CapabilityKind::Write, &mine));
        assert!(set.allows(&CapabilityKind::Read, &mine));
        assert!(
            !set.allows(&CapabilityKind::Read, &theirs),
            "one extension must never reach another's quarantine"
        );
    }

    /// The asymmetry that makes a fetcher safe: holding quarantine grants gives
    /// it no reach into the user's actual store, and a VFS grant does not
    /// silently confer quarantine either. These are separate namespaces on
    /// purpose (RFC-0049).
    #[test]
    fn quarantine_and_vfs_grants_never_substitute_for_each_other() {
        let quarantine = CapabilityTarget::Quarantine {
            extension_id: "sh.kotton.feed-reader".into(),
        };
        let fetcher = CapabilitySet::new(vec![
            CapabilityGrant {
                kind: CapabilityKind::Write,
                target: quarantine.clone(),
            },
            CapabilityGrant {
                kind: CapabilityKind::Read,
                target: quarantine.clone(),
            },
        ]);
        for path in ["/", "/notes", "/notes/todo.md"] {
            assert!(
                !fetcher.allows(
                    &CapabilityKind::Read,
                    &CapabilityTarget::Vfs { path: path.into() }
                ),
                "a fetcher holding quarantine must not read {path}"
            );
            assert!(
                !fetcher.allows(
                    &CapabilityKind::Write,
                    &CapabilityTarget::Vfs { path: path.into() }
                ),
                "a fetcher holding quarantine must not write {path}"
            );
        }

        // And the converse: even a root VFS grant confers no quarantine access.
        let root = CapabilitySet::new(vec![
            CapabilityGrant::vfs(CapabilityKind::Read, "/"),
            CapabilityGrant::vfs(CapabilityKind::Write, "/"),
        ]);
        assert!(!root.allows(&CapabilityKind::Read, &quarantine));
        assert!(!root.allows(&CapabilityKind::Write, &quarantine));
    }

    /// An author cannot mint themselves a quarantine grant: there is no manifest
    /// key for it, and unknown keys are rejected rather than ignored. The daemon
    /// binds the namespace to the id it verified at install.
    #[test]
    fn quarantine_cannot_be_declared_in_a_manifest() {
        let err = crate::AppManifest::from_toml(
            r#"
[app]
id = "sh.kotton.sneaky"
name = "Sneaky"
version = "0.1.0"

[capabilities]
"quarantine.read" = ["sh.kotton.someone-else"]
"#,
        )
        .expect_err("a hand-written quarantine key must be rejected");
        assert!(
            format!("{err}").contains("quarantine"),
            "error should name the offending key, got: {err}"
        );
    }

    #[test]
    fn quarantine_renders_a_distinct_manifest_key() {
        let g = CapabilityGrant {
            kind: CapabilityKind::Write,
            target: CapabilityTarget::Quarantine {
                extension_id: "sh.kotton.feed-reader".into(),
            },
        };
        assert_eq!(g.display_string(), "quarantine.write:sh.kotton.feed-reader");
    }

    #[test]
    fn allows_legitimate_subpath() {
        let grants = vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")];
        let set = CapabilitySet::new(grants);
        assert!(set.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Vfs {
                path: "/notes/todo.md".to_string(),
            }
        ));
    }

    // ── H1: action capabilities ────────────────────────────────────────────────

    #[test]
    fn allows_action_capabilities_by_exact_target() {
        let set = CapabilitySet::new(vec![
            CapabilityGrant::media(MediaDevice::Camera),
            CapabilityGrant::call(CallDirection::Initiate),
            CapabilityGrant::action(CapabilityTarget::AppLaunch),
        ]);
        // Granted actions are allowed under kind `Use`.
        let use_ = CapabilityKind::Use;
        assert!(set.allows(&use_, &CapabilityTarget::Media { device: MediaDevice::Camera }));
        assert!(set.allows(&use_, &CapabilityTarget::Call { direction: CallDirection::Initiate }));
        assert!(set.allows(&use_, &CapabilityTarget::AppLaunch));
        // A different device / direction / action is NOT covered.
        assert!(!set.allows(&use_, &CapabilityTarget::Media { device: MediaDevice::Microphone }));
        assert!(!set.allows(&use_, &CapabilityTarget::Call { direction: CallDirection::Receive }));
        assert!(!set.allows(&use_, &CapabilityTarget::Network));
        // Wrong kind never matches an action target.
        assert!(!set.allows(
            &CapabilityKind::Read,
            &CapabilityTarget::Media { device: MediaDevice::Camera }
        ));
    }

    // ── The consent gate (security-audit H2) ──────────────────────────────
    //
    // `ApprovedCapabilities` exists so that "what the app declared" cannot reach
    // a signature without a caller naming it. These test the one rule the type
    // enforces on its own — the approval channel narrows, never widens — and the
    // one it enforces by construction, which is that there is no way to build one
    // from a manifest. That second property is checked by the compiler and by
    // reading, not by a test: a test asserting `From` is absent would pass
    // forever by describing a thing that does not exist.

    #[test]
    fn an_approval_may_narrow_what_was_requested() {
        let requested = vec![
            CapabilityGrant::vfs(CapabilityKind::Read, "/notes"),
            CapabilityGrant::vfs(CapabilityKind::Write, "/notes"),
            CapabilityGrant::media(MediaDevice::Camera),
        ];
        // The user said yes to reading notes and no to the camera.
        let approved = ApprovedCapabilities::approved_by_user(vec![CapabilityGrant::vfs(
            CapabilityKind::Read,
            "/notes",
        )]);
        assert!(approved.is_subset_of(&requested));
        assert_eq!(approved.grants().len(), 1);
        assert_eq!(approved.source(), ConsentSource::User);
    }

    #[test]
    fn an_approval_may_not_widen_what_was_requested() {
        let requested = vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")];

        // Write was never asked for — a client cannot use the approval channel
        // to add it, so a compromised or buggy client cannot mint authority the
        // app never declared.
        let widened = ApprovedCapabilities::approved_by_user(vec![
            CapabilityGrant::vfs(CapabilityKind::Read, "/notes"),
            CapabilityGrant::vfs(CapabilityKind::Write, "/notes"),
        ]);
        assert!(!widened.is_subset_of(&requested));

        // Nor a different resource of the same shape.
        let elsewhere = ApprovedCapabilities::approved_by_user(vec![CapabilityGrant::vfs(
            CapabilityKind::Read,
            "/secrets",
        )]);
        assert!(!elsewhere.is_subset_of(&requested));

        // Nor a whole new shape.
        let camera =
            ApprovedCapabilities::approved_by_user(vec![CapabilityGrant::media(MediaDevice::Camera)]);
        assert!(!camera.is_subset_of(&requested));
    }

    #[test]
    fn approving_nothing_is_a_legal_answer() {
        let requested = vec![CapabilityGrant::media(MediaDevice::Camera)];
        let none = ApprovedCapabilities::approved_by_user(vec![]);
        assert!(
            none.is_subset_of(&requested),
            "installing an app and granting it nothing must be expressible"
        );
        assert!(none.grants().is_empty());
    }

    #[test]
    fn a_bundled_install_says_so_in_its_source() {
        let bundled = ApprovedCapabilities::system_bundled(vec![CapabilityGrant::vfs(
            CapabilityKind::Read,
            "/",
        )]);
        assert_eq!(
            bundled.source(),
            ConsentSource::SystemBundled,
            "a boot-time install must not read back as a user decision"
        );
    }

    // ── Binding (RFC-0021) ────────────────────────────────────────────────
    //
    // The ceremony has the user bind a declared shape to a resource they pick.
    // `is_subset_of` refuses that, because a rebound grant is not one the
    // manifest requested — so the client sends a binding and the daemon builds
    // the grant. These test that the daemon cannot be made to build one the app
    // never declared.

    fn shapes_for(toml: &str) -> Vec<crate::CapabilityShape> {
        crate::AppManifest::from_toml(toml).expect("manifest").vfs_shapes()
    }

    const NOTES: &str = r#"
[app]
id = "sh.kotton.b"
name = "B"
version = "1.0.0"

[capabilities]
"files.read"  = ["/notes"]
"files.write" = ["/notes"]
"#;

    #[test]
    fn a_binding_moves_the_target_and_keeps_every_kind() {
        // One path with read and write is **one** shape carrying both, not two
        // shapes — you choose where your notes live once.
        let shapes = shapes_for(NOTES);
        assert_eq!(shapes.len(), 1, "one path, one bindable resource");
        assert_eq!(shapes[0].access.len(), 2, "carrying read and write");

        let approved = ApprovedCapabilities::from_bindings(
            &shapes,
            &[(shapes[0].id.clone(), "/journal".to_owned())],
            vec![],
        )
        .expect("binding a declared shape");

        let rendered: Vec<String> =
            approved.grants().iter().map(|g| g.display_string()).collect();
        assert!(
            rendered.contains(&"vfs.read:/journal".to_string())
                && rendered.contains(&"vfs.write:/journal".to_string()),
            "both kinds move with the resource: {rendered:?}"
        );
        assert!(
            !rendered.iter().any(|d| d.ends_with(":/notes")),
            "the old target must not survive alongside the new one: {rendered:?}"
        );
    }

    #[test]
    fn a_binding_cannot_name_a_shape_the_app_never_declared() {
        let shapes = shapes_for(NOTES);
        let err = ApprovedCapabilities::from_bindings(
            &shapes,
            &[("vfs:7".to_owned(), "/".to_owned())],
            vec![],
        )
        .expect_err("an unknown shape id must be refused, not skipped");
        assert!(err.contains("vfs:7"), "the error should name it: {err}");
    }

    #[test]
    fn bindings_do_not_add_capabilities() {
        // Two shapes declared, two grants out, however many bindings arrive.
        // A client cannot use the binding channel to grow the set, because the
        // set comes from the manifest and only the targets are substituted.
        let shapes = shapes_for(NOTES);
        let approved = ApprovedCapabilities::from_bindings(
            &shapes,
            &[(shapes[0].id.clone(), "/a".to_owned())],
            vec![],
        )
        .expect("the shape bound");
        assert_eq!(
            approved.grants().len(),
            2,
            "one shape with two kinds yields two grants and no more"
        );
    }

    #[test]
    fn shape_ids_are_stable_across_reads() {
        // `capabilities` deserializes into a HashMap, whose iteration order is
        // not stable. An id that moved between reads would rebind an app to a
        // different resource on reinstall — silently, and in the direction of
        // more access.
        //
        // **Not the guard**, measured: removing the sort leaves this green,
        // because a HashMap's order is stable enough within one run to fool a
        // repeat read. `shape_ids_are_stable_when_the_manifest_lists_several`
        // is the one that catches it, by pinning the order itself.
        let first: Vec<String> = shapes_for(NOTES).into_iter().map(|s| s.id).collect();
        for _ in 0..10 {
            let again: Vec<String> = shapes_for(NOTES).into_iter().map(|s| s.id).collect();
            assert_eq!(again, first, "shape ids must be a function of the manifest");
        }
    }

    #[test]
    fn shape_ids_are_stable_when_the_manifest_lists_several() {
        let many = r#"
[app]
id = "sh.kotton.m"
name = "M"
version = "1.0.0"

[capabilities]
"files.read" = ["/zebra", "/alpha", "/middle"]
"#;
        let ids: Vec<(String, String)> = shapes_for(many)
            .into_iter()
            .map(|s| (s.id, s.default_target))
            .collect();
        // Sorted by target, so position — and therefore identity — does not
        // depend on the order the TOML happened to be walked in.
        assert_eq!(
            ids,
            vec![
                ("vfs:0".to_owned(), "/alpha".to_owned()),
                ("vfs:1".to_owned(), "/middle".to_owned()),
                ("vfs:2".to_owned(), "/zebra".to_owned()),
            ]
        );
    }

    // ── The two manifest forms ────────────────────────────────────────────

    /// The same app, written both ways, grants the same thing.
    ///
    /// **The load-bearing test of the grammar change.** The flat form is what
    /// every installed app carries on disk; the `[[capabilities]]` form is what
    /// RFC-0021 ratified. If they diverged, an app would mean one thing before
    /// an author rewrote its manifest and another after — and the difference
    /// would be in what the user's key signed.
    #[test]
    fn both_manifest_forms_grant_the_same_thing() {
        let flat = r#"
[app]
id = "sh.kotton.two"
name = "Two"
version = "1.0.0"

[capabilities]
"files.read"  = ["/notes"]
"files.write" = ["/notes"]
"#;
        let shaped = r#"
[app]
id = "sh.kotton.two"
name = "Two"
version = "1.0.0"

[[capabilities]]
id      = "home"
type    = "vfs-tree"
access  = ["read", "write"]
default = "/notes"
label   = "Notes storage"
desc    = "The directory where your notes are stored."
"#;
        let a = crate::AppManifest::from_toml(flat).expect("flat");
        let b = crate::AppManifest::from_toml(shaped).expect("shaped");

        let mut ga: Vec<String> = a.capabilities.iter().map(|g| g.display_string()).collect();
        let mut gb: Vec<String> = b.capabilities.iter().map(|g| g.display_string()).collect();
        ga.sort();
        gb.sort();
        assert_eq!(ga, gb, "the two forms must mean the same grants");

        // One bindable resource either way. What differs is only what can be
        // said about it.
        assert_eq!(a.vfs_shapes().len(), 1);
        assert_eq!(b.vfs_shapes().len(), 1);
        assert_eq!(a.vfs_shapes()[0].label, None, "the flat form has nowhere for one");
        assert_eq!(
            b.vfs_shapes()[0].label.as_deref(),
            Some("Notes storage"),
            "and the declared form carries it"
        );
        assert_eq!(b.vfs_shapes()[0].id, "home", "the author's id, not a derived one");
    }

    #[test]
    fn an_unknown_shape_type_is_an_error_not_a_skip() {
        // A host that ignored an unknown `type` would install the app, report
        // success, and grant nothing — the failure mode where the user believes
        // they approved something.
        let future = r#"
[app]
id = "sh.kotton.future"
name = "Future"
version = "1.0.0"

[[capabilities]]
id      = "cam"
type    = "camera-stream"
access  = ["read"]
default = "front"
"#;
        let err = crate::AppManifest::from_toml(future).expect_err("unknown type must not parse");
        assert!(
            format!("{err}").contains("camera-stream"),
            "the error should name what it did not understand: {err}"
        );
    }

    #[test]
    fn two_shapes_cannot_share_an_id() {
        // A binding names a shape by id. Two shapes with one id is a binding
        // that cannot say which resource it meant.
        let dupe = r#"
[app]
id = "sh.kotton.dupe"
name = "Dupe"
version = "1.0.0"

[[capabilities]]
id      = "home"
type    = "vfs-tree"
access  = ["read"]
default = "/a"

[[capabilities]]
id      = "home"
type    = "vfs-tree"
access  = ["read"]
default = "/b"
"#;
        let err = crate::AppManifest::from_toml(dupe).expect_err("duplicate ids must not parse");
        assert!(format!("{err}").contains("home"), "name the id: {err}");
    }

    // ── Admissibility (the shape-aware rule) ─────────────────────────────

    #[test]
    fn a_rebinding_is_admissible() {
        let shapes = shapes_for(NOTES);
        let requested = vec![
            CapabilityGrant::vfs(CapabilityKind::Read, "/notes"),
            CapabilityGrant::vfs(CapabilityKind::Write, "/notes"),
        ];
        let moved = ApprovedCapabilities::approved_by_user(vec![
            CapabilityGrant::vfs(CapabilityKind::Read, "/journal"),
            CapabilityGrant::vfs(CapabilityKind::Write, "/journal"),
        ]);
        assert!(
            moved.is_admissible_for(&requested, &shapes),
            "the ceremony's whole point is that the user may move where a shape points"
        );
        assert!(
            !moved.is_subset_of(&requested),
            "and the old rule refuses it — which is why this one exists"
        );
    }

    #[test]
    fn a_kind_the_manifest_never_declared_is_not_admissible() {
        let read_only = r#"
[app]
id = "sh.kotton.r"
name = "R"
version = "1.0.0"

[capabilities]
"files.read" = ["/notes"]
"#;
        let shapes = shapes_for(read_only);
        let requested = vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")];
        let sneaky_write = ApprovedCapabilities::approved_by_user(vec![
            CapabilityGrant::vfs(CapabilityKind::Write, "/notes"),
        ]);
        assert!(
            !sneaky_write.is_admissible_for(&requested, &shapes),
            "binding must move a target, never add a kind"
        );
    }

    #[test]
    fn widening_by_repetition_is_not_admissible() {
        // Each grant is individually "of a declared kind". The count is the
        // other half of the bound: one declared read shape, one read grant.
        let read_only = r#"
[app]
id = "sh.kotton.r"
name = "R"
version = "1.0.0"

[capabilities]
"files.read" = ["/notes"]
"#;
        let shapes = shapes_for(read_only);
        let requested = vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")];
        let many = ApprovedCapabilities::approved_by_user(vec![
            CapabilityGrant::vfs(CapabilityKind::Read, "/a"),
            CapabilityGrant::vfs(CapabilityKind::Read, "/b"),
            CapabilityGrant::vfs(CapabilityKind::Read, "/c"),
        ]);
        assert!(
            !many.is_admissible_for(&requested, &shapes),
            "one declared shape must not come out of install as three grants"
        );
    }

    #[test]
    fn a_non_vfs_capability_is_still_judged_exactly() {
        // Binding loosened VFS and nothing else. The camera is not a resource
        // with a location, so there is nothing to move and no reason to relax.
        let shapes = shapes_for(NOTES);
        let requested = vec![CapabilityGrant::vfs(CapabilityKind::Read, "/notes")];
        let camera = ApprovedCapabilities::approved_by_user(vec![CapabilityGrant::media(
            MediaDevice::Camera,
        )]);
        assert!(!camera.is_admissible_for(&requested, &shapes));
    }

    #[test]
    fn display_string_renders_action_and_resource_keys() {
        assert_eq!(
            CapabilityGrant::schema(CapabilityKind::Read, Nsid::from_static("sh.kotton.notes"))
                .display_string(),
            "schema.read:sh.kotton.notes"
        );
        assert_eq!(
            CapabilityGrant::vfs(CapabilityKind::Write, "/notes").display_string(),
            "vfs.write:/notes"
        );
        assert_eq!(
            CapabilityGrant::media(MediaDevice::Camera).display_string(),
            "media.camera"
        );
        assert_eq!(
            CapabilityGrant::call(CallDirection::Initiate).display_string(),
            "call.initiate"
        );
        assert_eq!(
            CapabilityGrant::messages(MessageDirection::Send).display_string(),
            "messages.send"
        );
        assert_eq!(
            CapabilityGrant::action(CapabilityTarget::AppLaunch).display_string(),
            "apps.launch"
        );
        assert_eq!(
            CapabilityGrant::action(CapabilityTarget::Network).display_string(),
            "network.fetch"
        );
    }
}
