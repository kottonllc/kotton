// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daemon's implementation of [`AppHost`].
//!
//! Three providers behind one trait: the event bus, the `kuid` compositor
//! client, and the device's user registration file. `apps.rs` used to take the
//! first two as parameters and read the third off disk itself.
//!
//! **The compositor's failure model lives here, not in the domain.** Patch
//! delivery is best-effort: a node with no `kuid` running is headless,
//! not broken, and every proxy call returns `Ok(())` after a warning. The
//! handlers used to spell that as `.await.ok()` at each of the seven call
//! sites, which is a policy decision repeated seven times and repairable in six
//! of them. It is stated once now, in the return type — the trait's surface
//! verbs return nothing, so a caller cannot mistake delivery for a guarantee.

use crate::device_users;
use crate::surface_proxy::SurfaceProxy;
use kotton_app::daemon::apps::{AppHost, RegisteredUser};
use kotton_diag::service::EventBus;
use kotton_wire::runner::{RootsUnread, RunnerRoot};
use std::path::Path;
use std::sync::Arc;

/// The event bus, the compositor client, the device user list, and the runner
/// binary, as one host.
pub struct DaemonAppHost<'a> {
    pub events: &'a Arc<EventBus>,
    pub surface: &'a Arc<SurfaceProxy>,
    /// See [`DeviceDaemon::runner`](super::DeviceDaemon) for where it comes from.
    pub runner: &'a Path,
    /// The base directory this daemon was constructed with — what
    /// [`registered_users`](AppHost::registered_users) reads `device/users.json`
    /// relative to, rather than the process-global
    /// [`kotton_common::base_dir`], so the device user registry is not read
    /// from a process-global base.
    pub base: &'a Path,
    /// The machine's keychain. Used at launch only to re-mint a grant envelope
    /// that predates the signed `app_id` binding.
    pub secrets: &'a dyn kotton_sys::secret::SecretsStore,
    /// Whose stores are loaded in this process, and with them their keys.
    ///
    /// **This is where "the keys stay resident after the first unlock" lives.**
    /// The registry holds an `Arc<UserStore>` from the unlock that created it
    /// until logout or shutdown — `LockSession` takes a session token and
    /// touches nothing here — so the roots index can be read back across a
    /// screen lock without the person typing anything, which is what iOS calls
    /// *Protected Until First User Authentication*. The roots index is sealed
    /// before it travels.
    pub users: &'a crate::residency::UserRegistry,
    /// What the person's tree may tell the sync engine: that a hand-over landed
    /// in their Inbox, so the next loop packs it into the log rather than the
    /// next scheduled pass.
    /// The signal and not the engine — see [`HandOverSignal`].
    ///
    /// [`HandOverSignal`]: kotton_sync::engine::HandOverSignal
    pub hand_overs: kotton_sync::engine::HandOverSignal,
}

#[async_trait::async_trait]
impl AppHost for DaemonAppHost<'_> {
    fn events(&self) -> &Arc<EventBus> {
        self.events
    }

    /// Read from `device/users.json` at call time rather than cached: the shell
    /// asks on launch, and a user registered since boot must appear — and a
    /// name set since boot must be the one the next launch draws.
    fn registered_users(&self) -> Vec<RegisteredUser> {
        device_users::load(self.base)
            .unwrap_or_default()
            .into_iter()
            .map(|(user_id, record)| RegisteredUser {
                user_id,
                display_name: record.display_name,
            })
            .collect()
    }

    async fn surface_open(
        &self,
        handle: kotton_wire::SurfaceHandle,
        app_id: &str,
        spec: kotton_wire::SurfaceSpec,
    ) {
        let _ = self.surface.open(handle, app_id, spec).await;
    }

    async fn surface_commit(&self, handle: kotton_wire::SurfaceHandle, patch: Vec<u8>) {
        let _ = self.surface.commit(handle, patch).await;
    }

    async fn surface_close(&self, handle: kotton_wire::SurfaceHandle) {
        let _ = self.surface.close(handle).await;
    }

    async fn surface_resize(&self, handle: kotton_wire::SurfaceHandle, width: u32, height: u32) {
        let _ = self.surface.resize(handle, width, height).await;
    }

    async fn surface_set_title(&self, handle: kotton_wire::SurfaceHandle, title: String) {
        let _ = self.surface.set_title(handle, title).await;
    }

    async fn surface_raise(&self, handle: kotton_wire::SurfaceHandle) {
        let _ = self.surface.raise(handle).await;
    }

    async fn surface_windows(&self) -> Vec<kotton_wire::HostWindow> {
        self.surface.windows()
    }

    async fn surface_restore(&self, handle: kotton_wire::SurfaceHandle) {
        let _ = self.surface.restore(handle).await;
    }

    fn runner(&self) -> &Path {
        self.runner
    }

    fn secrets(&self) -> &dyn kotton_sys::secret::SecretsStore {
        self.secrets
    }

    /// This person's roots, read out of their own store.
    ///
    /// **Here because `core/app` may not reach the object store**, and roots
    /// are the store's: `core/app`'s own `Cargo.toml` keeps `kotton-store` a
    /// dev-dependency so that domain cannot touch a user's objects in
    /// production. The daemon can, and does.
    ///
    /// **Through the loaded store, because the index is sealed.** The meaning
    /// half — every root's name and its members' AIDs — is sealed under this
    /// person's own keys, and the only thing in this process holding those keys
    /// is the `UserStore` their unlock created. The index cannot be opened from
    /// its path, because the file is sealed, and that is the point rather than
    /// a cost. A
    /// device that has booted and has never been unlocked answers `None` here
    /// and names no root, while still routing every root's bytes through
    /// `RoutingIndex`.
    ///
    /// Reading is also what *migrates*, once: the first read lays down the core
    /// root, adopts the existing tree as *This PC* — in place, with nothing
    /// re-encrypted — and records the vaults this device has already enrolled
    /// as that root's targets. `RootSet::open` is idempotent, so every read
    /// after the first is only a read.
    ///
    /// **A failure is a warning here and a cause at the far end, never an empty
    /// list.** A person whose roots could not be read still has a shell, and
    /// its *Locations* says the roots could not be read and why. Answered as
    /// `None`, the launch would turn it into an empty set, so a store not
    /// loaded, a store loaded without keys and an index that would not open
    /// would all draw as a person with no places.
    fn user_roots(
        &self,
        _base: &Path,
        user_id: &str,
        own_aid: &str,
    ) -> Result<Vec<RunnerRoot>, RootsUnread> {
        roots_of(self.users, user_id, own_aid)
    }

    fn keys_loaded(&self, user_id: &str) -> bool {
        self.users
            .get(user_id)
            .is_some_and(|store| store.sealing_keys().is_some())
    }

    /// This person's own files, answered by the store their unlock loaded —
    /// the same `UserStore` a `kotton fs write` writes through, so a file an
    /// app writes is sealed, blinded and packable exactly as that one is, and
    /// never rests in the clear in the sealed store's own directory.
    ///
    /// `None` where the store is not loaded: the keys that open it arrive with
    /// an unlock, and a device that has not been unlocked has nothing to answer
    /// a file from.
    fn personal_tree(
        &self,
        user_id: &str,
    ) -> Option<Arc<dyn kotton_app::daemon::apps::PersonalTree>> {
        let store = self.users.get(user_id)?;
        Some(Arc::new(DaemonPersonalTree {
            store,
            user_id: user_id.to_string(),
            hand_overs: self.hand_overs.clone(),
        }))
    }
}

/// This person's roots out of their loaded store, or which of three things
/// stopped the read — each logged here, where it happened.
///
/// The three arms are three different facts about this device, and the
/// surface draws each in its own words: the store is **not loaded**; it is
/// loaded **without keys** (locked — the meaning half is sealed under keys only
/// an unlock brings, and `UserStore::roots` refuses to guess); or it has keys
/// and the sealed index still **would not open**. The operator-facing error
/// goes to the log and no further.
fn roots_of(
    users: &crate::residency::UserRegistry,
    user_id: &str,
    own_aid: &str,
) -> Result<Vec<RunnerRoot>, RootsUnread> {
    let Some(store) = users.get(user_id) else {
        tracing::warn!(
            user = %user_id,
            "roots: this person's store is not loaded, so their index cannot be opened"
        );
        return Err(RootsUnread::StoreNotLoaded);
    };
    if store.sealing_keys().is_none() {
        tracing::warn!(
            user = %user_id,
            "roots: this person's store is loaded without keys — locked — so the \
             meaning half of their index cannot be opened until they unlock"
        );
        return Err(RootsUnread::Locked);
    }
    // This device's no-auth-policy binding, where its hardware can hold
    // one: it seals the routing half — the addresses a daemon reads before
    // anybody has unlocked anything — to this machine, and `None` on a
    // machine without it leaves that half in the clear with its first line
    // saying so. The routing half of the roots index seals under the device's
    // binding.
    let binding = kotton_identity::provisioning::routing_binding(store.base_dir());
    let set = store
        .roots(own_aid, binding.as_deref())
        .map_err(|e| {
            tracing::warn!(
                user = %user_id,
                error = %e,
                "roots: this person's store has keys and their index still would not open"
            );
            RootsUnread::IndexUnopenable
        })?;
    Ok(runner_roots(&set, store.base_dir(), own_aid))
}

/// A person's own tree, over their loaded store.
///
/// Every verb is one `UserStore` call and nothing else: the path is routed by
/// the person's own mount table like any other path, resolved beneath
/// `PERSON_TREE_ROOT` — so nothing of this daemon's own, the membership set or
/// the read marks, is a path here — sealed under their key, blinded, and
/// packed by the next pass. Errors are the store's own words.
///
/// One verb does one thing more: a write into Inbox tells the sync engine a
/// hand-over landed ([`is_a_hand_over`]).
struct DaemonPersonalTree {
    store: Arc<kotton_store::runtime::user::UserStore>,
    /// Whose tree this is — the person the hand-over signal names.
    user_id: String,
    hand_overs: kotton_sync::engine::HandOverSignal,
}

/// The folder of the person's tree a hand-over to a device of theirs lands in:
/// *a thing sent to a device of your own lands in Personal under Inbox*. A protocol name, so the host may know it; the shell's `INBOX` in
/// `guest/apps/kotton-shell/logic/src/view.rs` is the same name, from the same
/// rule, for the sheet that writes there.
const INBOX: &str = "Inbox";

/// Whether a write at `path` is a hand-over — a file written into the person's
/// Inbox, at any depth under it.
///
/// **Read from where the write lands, never from who wrote it.** The sheet does
/// not say it is handing a file over and need not: the landing place is the
/// hand-over's whole mechanism, so a write there is one by
/// definition, whichever app made it. Every other write keeps the schedule it
/// had. `path` is the canonical form `service_files_call` in `core/app` hands
/// the tree — absolute, `/`-separated, `..` resolved.
fn is_a_hand_over(path: &str) -> bool {
    path.strip_prefix('/')
        .and_then(|rest| rest.strip_prefix(INBOX))
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|name| !name.is_empty())
}

#[async_trait::async_trait]
impl kotton_app::daemon::apps::PersonalTree for DaemonPersonalTree {
    async fn read(&self, path: &str) -> Result<Vec<u8>, String> {
        self.store.read_file(path).await.map_err(|e| format!("{e:#}"))
    }

    /// A write, and — when it lands in Inbox — the signal that a hand-over is
    /// waiting to enter the log. After the write returns, never before: the
    /// engine packs what is loose when it runs, and a signal sent ahead of the
    /// bytes could pack without them.
    async fn write(&self, path: &str, data: &[u8]) -> Result<(), String> {
        self.store.write_file(path, data).await.map_err(|e| format!("{e:#}"))?;
        if is_a_hand_over(path) {
            self.hand_overs.landed(&self.user_id);
        }
        Ok(())
    }

    /// `not found`, in those words, when there was nothing to delete — what
    /// `files.delete-file` promises the guest. Asked first because the store
    /// deletes an absent key as quietly as a present one.
    async fn delete(&self, path: &str) -> Result<(), String> {
        use kotton_store::runtime::user::files::PathKind;
        match self.store.path_kind(path).await {
            Ok(Some(PathKind::File)) => {}
            Ok(_) => return Err("not found".to_string()),
            Err(e) => return Err(format!("{e:#}")),
        }
        self.store.delete_file(path).await.map_err(|e| format!("{e:#}"))
    }

    async fn create_dir(&self, path: &str) -> Result<(), String> {
        self.store.create_dir(path).await.map_err(|e| format!("{e:#}"))
    }

    async fn list(&self, path: &str) -> Result<Vec<kotton_wire::runner::RunnerDirEntry>, String> {
        let children = self
            .store
            .list_children(path)
            .await
            .map_err(|e| format!("{e:#}"))?;
        Ok(children
            .into_iter()
            .map(|c| kotton_wire::runner::RunnerDirEntry {
                name: c.name,
                is_dir: c.is_dir,
                size: c.size,
                modified: c.modified,
            })
            .collect())
    }

    async fn logged(&self, path: &str) -> Result<Option<u64>, String> {
        self.store.file_logged(path).await.map_err(|e| format!("{e:#}"))
    }

    async fn kind(&self, path: &str) -> Result<Option<kotton_wire::runner::RunnerPathKind>, String> {
        use kotton_store::runtime::user::files::PathKind;
        use kotton_wire::runner::RunnerPathKind;
        Ok(match self.store.path_kind(path).await.map_err(|e| format!("{e:#}"))? {
            Some(PathKind::File) => Some(RunnerPathKind::File),
            Some(PathKind::Dir) => Some(RunnerPathKind::Dir),
            None => None,
        })
    }
}

/// This person's roots, resolved the way a launch resolves them.
///
/// `core/app` replays the AID from the local KEL before calling
/// [`AppHost::user_roots`]; the occupant host has no `AppHost` to call, so this
/// is the same two steps as one function. `Err` where there is no chain to
/// name the person by, where their store is not loaded or holds no keys, or
/// where the sealed index will not open — every one is *this device cannot
/// say*, never *there are no roots*.
///
/// [`AppHost::user_roots`]: kotton_app::daemon::apps::AppHost::user_roots
pub(crate) fn user_runner_roots(
    users: &crate::residency::UserRegistry,
    base: &Path,
    user_id: &str,
) -> Result<Vec<RunnerRoot>, RootsUnread> {
    let own_aid = kotton_identity::kel_store::load_chain(base, user_id)
        .ok()
        .and_then(|chain| chain.into_iter().next())
        .map(|inception| inception.aid.to_string())
        .ok_or_else(|| {
            tracing::warn!(
                user = %user_id,
                "roots: no KEL chain names this person, so their index cannot be opened \
                 under the right member (RFC-0038 8c)"
            );
            RootsUnread::NoIdentity
        })?;
    roots_of(users, user_id, &own_aid)
}

/// The roots a guest may be handed, out of the person's whole set.
///
/// **The core root is not among them, and that is the fix rather than a
/// filter on a surface.** The core root is the index's *home* and not a place: it holds the
/// root index, the identity material, the device set and the settings, and
/// nothing in it is a folder a person browses. A `RunnerRoot` carries
/// `tree_path`, and `roots.tree` turns any root a guest holds into a directory
/// handle on that path — so naming core to a guest *is* handing it the index,
/// and an app granted `roots` so a file browser could draw a sidebar could read
/// every root the person has, who each is shared with, and which vault each is
/// kept at. **That handle can write where the host hands a root writable** —
/// nowhere until the owner
/// rules — so this filter is also what would stand between the occupant and
/// overwriting the index, the device set and the settings: a person is a
/// member of every root they can name, and core is not one they can name.
///
/// Not naming it deletes the handle rather than guarding it (`CLAUDE.md`, the
/// second design test): there is no `RootHandle` for core for `roots.tree` to
/// refuse, so no check in the sandbox is necessary and none was added. The
/// shell already drew no row for it, which is the surface half of the same
/// finding and not the same thing as the reach being closed.
///
/// **Sealing the index does not make this unnecessary.** It makes it sharper: a
/// guest walking the core tree today would read `roots.sealed`, which it cannot
/// open — but it would also see the routing half, the device set and every
/// other thing the core root holds, and "it is only ciphertext" is not a reason to
/// hand somebody a tree that is none of their business.
fn runner_roots(
    set: &kotton_store::runtime::roots::RootSet,
    user_dir: &Path,
    own_aid: &str,
) -> Vec<RunnerRoot> {
    use kotton_store::runtime::roots::{Kept, Residency};
    use kotton_wire::runner::{RunnerKeeping, RunnerResidency, RunnerRootMember, RunnerRootTarget};

    set.all()
        .into_iter()
        .filter(|root| !root.is_core())
        .map(|root| RunnerRoot {
            members: root
                .members
                .iter()
                .map(|aid| RunnerRootMember {
                    // The host decides this, as it does for a paired
                    // device: a guest cannot recognise an AID it has no
                    // other way to know.
                    is_you: aid == own_aid,
                    aid: aid.clone(),
                })
                .collect(),
            targets: root
                .targets
                .iter()
                .map(|t| RunnerRootTarget {
                    handle: t.handle.clone(),
                    label: t.label.clone(),
                })
                .collect(),
            residency: match root.residency {
                Residency::Full => RunnerResidency::Full,
                Residency::OnDemand => RunnerResidency::OnDemand,
            },
            kept: match root.kept() {
                Kept::ThisDeviceOnly => RunnerKeeping::ThisDeviceOnly,
                Kept::Replicated => RunnerKeeping::Replicated,
                Kept::NotYetKeptAnywhereButHere => RunnerKeeping::NotYetKeptAnywhereButHere,
            },
            // **Only a tree of the root's own**, and empty otherwise — which the
            // sandbox's `roots.tree` answers with *no tree* and `runner_profile`
            // grants nothing for. *This PC*'s tree is the VFS mount, and what an
            // app may do there is its `files` grant's to say through the one
            // handle minted from it: handing the same directory over here too,
            // as a handle that writes, let an occupant the person approved only
            // to *read* its files write them. One tree, one door.
            tree_path: root
                .tree_of_its_own(user_dir)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            // **And the host says which root that is**, from the store's own
            // marker, so the file browser draws the granted handle and the root
            // it adopts as one row without matching a name — *This PC*, the
            // one root everyone starts with; *Personal* on a device whose first
            // run named it so; or whatever the person renamed it to.
            granted: root.adopts_the_mount(),
            // **Read-only until the owner rules** on whether the occupant may
            // write in a root's tree. The person is a member of every root here
            // and a member may write — but the occupant is software any
            // installed app can be designated, and no capability means no data
            // reach, no code path reaches user data without a grant, and a
            // grant to software is not membership (`docs/design/grants.md`): so
            // designation alone reaches no data. The write is built and
            // withheld here, in the one place both the sandbox's handle and the
            // runner's kernel profile read it from. A yes flips this line and
            // amends the design pages that say so on the same branch.
            writable: false,
            id: root.id,
            name: root.name,
        })
        .collect()
}

/// Build a host for one dispatch arm.
#[allow(clippy::too_many_arguments)]
pub fn app_host<'a>(
    events: &'a Arc<EventBus>,
    surface: &'a Arc<SurfaceProxy>,
    runner: &'a Path,
    base: &'a Path,
    secrets: &'a dyn kotton_sys::secret::SecretsStore,
    users: &'a crate::residency::UserRegistry,
    hand_overs: kotton_sync::engine::HandOverSignal,
) -> DaemonAppHost<'a> {
    DaemonAppHost {
        events,
        surface,
        runner,
        base,
        secrets,
        users,
        hand_overs,
    }
}

#[cfg(test)]
mod tests {
    use super::{is_a_hand_over, runner_roots};

    /// **A write is a hand-over when it lands in Inbox, and only then.**
    ///
    /// The paths are the canonical ones `service_files_call` hands the tree.
    /// Inbox itself is a folder, not a write; a name that only begins with
    /// *Inbox*, or an Inbox one folder down, is not the person's Inbox.
    #[test]
    fn a_write_is_a_hand_over_when_it_lands_in_inbox_and_only_then() {
        assert!(is_a_hand_over("/Inbox/beach.jpg"));
        assert!(is_a_hand_over("/Inbox/beach 2.jpg"));
        assert!(is_a_hand_over("/Inbox/from the trip/beach.jpg"));
        for not_one in [
            "/Inbox",
            "/Inbox/",
            "/Inboxes/beach.jpg",
            "/InboxAll/beach.jpg",
            "/inbox/beach.jpg",
            "/photos/Inbox/beach.jpg",
            "/beach.jpg",
            "Inbox/beach.jpg",
        ] {
            assert!(!is_a_hand_over(not_one), "{not_one} read as a hand-over");
        }
    }
    use kotton_store::runtime::roots::{Owner, Residency, RootSet, RoutingIndex};
    use kotton_store::runtime::user::UserStore;
    use kotton_store::runtime::UserKeys;

    const AID: &str = "did:kel:z6MkPersonsOwnAid";

    /// **A guest holding `roots` is never named the core root, so there is no
    /// handle on the tree the index lives in.**
    ///
    /// The three calls a guest makes are `list-roots`, `tree` and
    /// `list-entries`, and this drives the host's side of all three: the list it
    /// is answered, the path each root in that list resolves to, and what is
    /// inside it. `roots.tree` turns a `RunnerRoot` into a handle on
    /// `tree_path` — one that can write where the host says so — and
    /// `list-entries` is
    /// `read_dir` on it, so a root that is not
    /// in the list is a directory the guest has no way to name — there is no
    /// refusal to write because there is nothing left to refuse.
    ///
    /// The last assertion is the one that makes the rest mean anything: the
    /// index really is in the core tree, so a list that named core would be a
    /// list that handed it over.
    #[test]
    fn a_guest_is_never_named_the_core_root_whose_tree_holds_the_index() {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir.clone(),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let mut set = store.roots(AID, None).unwrap();
        set.add("Family", Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();

        // `list-roots`: the person's roots, and the core root is not one of the
        // rows a guest is answered.
        let listed = runner_roots(&set, store.base_dir(), AID);
        assert!(
            !listed.is_empty(),
            "a guest that is answered nothing at all proves nothing here"
        );
        assert!(
            listed.iter().all(|r| r.id != "core" && r.name != "Core"),
            "the core root was named to a guest: {:?}",
            listed.iter().map(|r| &r.name).collect::<Vec<_>>()
        );

        // `tree` then `list-entries`: every tree a guest can name, walked the
        // way the sandbox walks one — and the index is in none of them.
        let core_tree = user_dir.join("core");
        for root in listed.iter().filter(|r| !r.tree_path.is_empty()) {
            let tree = std::path::PathBuf::from(&root.tree_path);
            assert_ne!(tree, core_tree, "a guest was handed the core root's tree");
            for entry in std::fs::read_dir(&tree).unwrap() {
                let name = entry.unwrap().file_name();
                assert_ne!(name, std::ffi::OsStr::new(RootSet::SEALED_FILE));
                assert_ne!(name, std::ffi::OsStr::new(RoutingIndex::FILE));
            }
        }

        // And the index is in the core root's tree, which is what the two
        // assertions above are about.
        assert!(core_tree.join(RootSet::SEALED_FILE).exists());
        assert!(core_tree.join(RoutingIndex::FILE).exists());
    }

    /// **The occupant is handed no tree for *This PC*, so a read grant on its
    /// files cannot be written around through `roots.tree`** — **and it is
    /// handed the word that this is the granted root**, so the sidebar draws it
    /// once without matching a name.
    ///
    /// An occupant the person approved only to *read* its files —
    /// `files.read = ["/"]` — holds a granted handle that refuses writes; if
    /// `runner_roots` handed *Personal* over with its tree, the VFS mount
    /// itself, it could ask `roots.tree` for *Personal* and write through that,
    /// because `roots.tree` mints every tree writable. So the host does not
    /// hand that tree over: the adopting root is still listed —
    /// the sidebar draws it and the details column reads its members — but its
    /// `tree_path` is empty, which `roots.tree` answers with *no tree* and
    /// `runner_profile` grants nothing for. The sandbox half of that sentence is
    /// `a_read_only_occupant_cannot_write_its_files_through_the_personal_root`
    /// in `core/wasm`.
    ///
    /// A root the person made is still handed its own tree, which is the
    /// control: a projection that handed nothing would pass the rest.
    #[test]
    fn this_pc_is_listed_with_no_tree_and_as_granted_so_its_files_have_one_door() {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir.clone(),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let mut set = store.roots(AID, None).unwrap();
        let family = set
            .add("Family", kotton_store::runtime::roots::Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();

        let listed = runner_roots(&set, store.base_dir(), AID);
        let granted: Vec<&kotton_wire::runner::RunnerRoot> =
            listed.iter().filter(|r| r.granted).collect();
        assert_eq!(granted.len(), 1, "exactly one root is the granted tree: {listed:?}");
        let this_pc = granted[0];
        assert_eq!(
            this_pc.name,
            kotton_store::runtime::roots::Root::THIS_PC,
            "the granted root is the one first run named This PC"
        );
        assert!(
            this_pc.tree_path.is_empty(),
            "This PC was handed its tree, the VFS mount, beside the files grant that governs it: {}",
            this_pc.tree_path
        );
        assert!(!listed.iter().any(|r| r.name == "Core"), "the core root is never listed");
        let mount = user_dir.join(kotton_store::runtime::roots::VFS_TREE);
        for root in &listed {
            assert!(
                !std::path::Path::new(&root.tree_path).starts_with(&mount) || root.tree_path.is_empty(),
                "{} was handed a tree inside the VFS mount: {}",
                root.name,
                root.tree_path
            );
        }
        let made = listed.iter().find(|r| r.id == family).expect("Family is listed");
        assert_eq!(
            std::path::PathBuf::from(&made.tree_path),
            user_dir.join("roots").join(&family),
            "a root the person made is handed its own tree"
        );
    }

    /// **No root is handed to the occupant writable until the owner rules** on
    /// whether it may write in a root's tree.
    ///
    /// The write path is built — `roots.tree` honours `RunnerRoot::writable`
    /// and `runner_profile` grants `Write` where it is set — and withheld here,
    /// because the occupant writing a root on its designation alone crosses
    /// *a grant to software is not membership*, and that is the owner's to
    /// answer rather than a default's. A root the person made is the case that
    /// matters: it is the one a yes would make writable.
    #[test]
    fn no_root_is_handed_writable_until_the_owner_rules() {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir.clone(),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let mut set = store.roots(AID, None).unwrap();
        let family = set
            .add("Family", kotton_store::runtime::roots::Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();

        let listed = runner_roots(&set, store.base_dir(), AID);
        assert!(listed.iter().any(|r| r.id == family && !r.tree_path.is_empty()), "the control");
        for root in &listed {
            assert!(
                !root.writable,
                "{} was handed writable before the owner ruled that designation is enough",
                root.name
            );
        }
    }

    /// **The ruled-yes shape**: if the owner rules that the occupant may write a
    /// root it is designated for, a root the person made is handed writable and
    /// *Personal* still is not (its door is the `files` grant). Ignored, and not because it is flaky: the gate it
    /// holds is the owner's ruling on whether a member writes in a root's tree,
    /// and it is un-ignored in the commit that flips `runner_roots`.
    #[test]
    #[ignore = "ruled-yes shape: waits on the owner's answer to question 1 on TASK-a-member-writes-in-a-roots-tree"]
    fn a_root_the_person_made_is_handed_writable_once_the_owner_rules_yes() {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir.clone(),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let mut set = store.roots(AID, None).unwrap();
        let family = set
            .add("Family", kotton_store::runtime::roots::Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();
        let listed = runner_roots(&set, store.base_dir(), AID);
        for root in &listed {
            assert_eq!(root.writable, root.id == family, "{}", root.name);
        }
    }

    /// **An admitted vault is listed, and a rebuilt routing half does not make
    /// it the target of a root the person kept here.**
    ///
    /// The state: a person with a vault that is both
    /// admitted (an own-device member under the blind posture, which is what
    /// the readout lists) and synced to (a Kotton remote, which is what first
    /// run and the roots' labels read). First run makes it *Personal*'s target —
    /// the migration, since *Personal* is already kept there — and the person
    /// makes a second root and keeps it nowhere but here. Then the routing half
    /// is lost, as a cleared chip or an interrupted save loses it.
    ///
    /// After the reopen, *Personal* is still kept at the vault, the second root
    /// is still kept nowhere, and the readout still lists the vault and says
    /// what it holds. Make `RootSet::read_halves` take its rebuilt targets from
    /// the enrolled set again and the second assertion is the one that fails.
    #[tokio::test]
    async fn a_rebuilt_routing_half_keeps_a_root_kept_here_off_an_admitted_vault() {
        use kotton_peer::membership::Membership as _;
        use kotton_schemas::membership::{Ceremony, Member, Posture, Role};
        use kotton_store::runtime::roots::Kept;

        const VAULT: &str = "did:key:z6MkAdmittedVault";
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir.clone(),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();

        // Admitted: what `finalize_enrolled_node` writes.
        store
            .write_member(&Member {
                did: VAULT.to_string(),
                public_key: [3u8; 32],
                role: Role::OwnDevice,
                admitted_by: Ceremony::DeviceEnroll,
                added_at: "2026-09-23T00:00:00Z".to_string(),
                posture: Some(Posture::BlindStorage),
                label: Some("vault".to_string()),
                reach: None,
            })
            .await
            .unwrap();
        // Synced to: what `sync_mount` registers the first time it pushes.
        let shelf = store.local_store_with(
            temp.path().join("shelf"),
            kotton_fs::OsFilesystem,
            kotton_wire::remote::KeyFormat::Blinded,
        );
        store
            .add_remote(
                "vault".to_string(),
                shelf,
                kotton_wire::remote::RemoteConfig {
                    backend: kotton_wire::remote::RemoteBackend::Kotton {
                        peer_did: VAULT.to_string(),
                        label: "vault".to_string(),
                    },
                    cache_dir: None,
                    key_format: kotton_wire::remote::KeyFormat::Blinded,
                },
            )
            .unwrap();

        let mut set = store.roots(AID, None).unwrap();
        let personal = set.personal().expect("first run lays down This PC").id;
        let kept_here = set
            .add("Drafts", Owner::ThePerson, vec![AID.to_string()], Vec::new(), Residency::Full)
            .unwrap();

        std::fs::remove_file(RoutingIndex::path(&user_dir)).unwrap();
        let reopened = store.roots(AID, None).unwrap();

        assert_eq!(
            reopened.get(&personal).unwrap().targets.iter().map(|t| t.handle.as_str()).collect::<Vec<_>>(),
            vec![VAULT],
            "Personal was kept at the vault and came back kept nowhere"
        );
        assert!(
            reopened.get(&kept_here).unwrap().targets.is_empty(),
            "a root kept on this device only was made the vault's by the rebuild"
        );
        assert_eq!(reopened.get(&kept_here).unwrap().kept(), Kept::ThisDeviceOnly);

        // And the readout still lists the vault, and says it holds Personal
        // and not Drafts.
        let admitted = crate::agent::occupant_host::admitted_vaults(&store).await.unwrap();
        let rows = crate::agent::network_readout::vault_rows(
            &admitted,
            &[],
            &runner_roots(&reopened, store.base_dir(), AID),
            &|_| false,
            &[],
            &[],
        );
        assert_eq!(rows.len(), 1, "the admitted vault is listed: {rows:?}");
        assert_eq!(rows[0].label.as_deref(), Some("vault"));
        assert_eq!(rows[0].holds, kotton_store::runtime::roots::Root::THIS_PC);
    }

    // ── A roots failure says which failure it is ─────────────────────────────
    //
    // A roots failure is never drawn as no roots: the three failures this host
    // can see, each its own cause, each one sentence with one full stop. The
    // other two — a launch for nobody, and a person no chain names — are
    // `core/app`'s and are pinned there.

    fn one_sentence(why: kotton_wire::runner::RootsUnread) {
        let words = why.words();
        assert_eq!(words.matches('.').count(), 1, "{why:?}: {words}");
        assert!(words.ends_with('.'), "{why:?}: {words}");
    }

    /// A person whose store this daemon has not loaded.
    #[test]
    fn a_store_that_is_not_loaded_answers_store_not_loaded_and_not_no_roots() {
        let users = crate::residency::UserRegistry::new();
        let answer = super::roots_of(&users, "alice", AID);
        assert_eq!(answer, Err(kotton_wire::runner::RootsUnread::StoreNotLoaded));
        assert_eq!(
            kotton_wire::runner::RootsUnread::StoreNotLoaded.words(),
            "Your account isn't loaded on this device, so Kotton can't list your locations."
        );
        one_sentence(kotton_wire::runner::RootsUnread::StoreNotLoaded);
    }

    /// **The owner's case**: a store loaded without keys — the daemon started
    /// before this identity was unlocked. The index is sealed under keys this
    /// store does not hold, and the answer is *locked*, not *none*.
    #[test]
    fn a_store_with_no_keys_answers_locked_and_not_no_roots() {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let keyless = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir,
            UserKeys::keyless(),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        assert!(keyless.sealing_keys().is_none(), "the fixture holds no CEK");
        let users = crate::residency::UserRegistry::new();
        users.insert("alice".to_string(), std::sync::Arc::new(keyless));

        let answer = super::roots_of(&users, "alice", AID);
        assert_eq!(answer, Err(kotton_wire::runner::RootsUnread::Locked));
        assert_eq!(
            kotton_wire::runner::RootsUnread::Locked.words(),
            "Your files are locked on this device, so Kotton can't list your locations until you unlock."
        );
        one_sentence(kotton_wire::runner::RootsUnread::Locked);
    }

    /// A store with keys whose meaning half will not open: the sealed file is
    /// there and is not an envelope this person's key opens.
    #[test]
    fn a_meaning_half_that_does_not_open_answers_index_unopenable_and_not_no_roots() {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir.clone(),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        // First run lays the index down under this person's key…
        store.roots(AID, None).unwrap();
        // …and something overwrites the sealed half with bytes that are not it.
        std::fs::write(RootSet::sealed_path(&user_dir), b"not an envelope").unwrap();
        let users = crate::residency::UserRegistry::new();
        users.insert("alice".to_string(), std::sync::Arc::new(store));

        let answer = super::roots_of(&users, "alice", AID);
        assert_eq!(answer, Err(kotton_wire::runner::RootsUnread::IndexUnopenable));
        assert_eq!(
            kotton_wire::runner::RootsUnread::IndexUnopenable.words(),
            "Kotton couldn't open your list of locations on this device."
        );
        one_sentence(kotton_wire::runner::RootsUnread::IndexUnopenable);
    }

    /// And the control: a loaded, keyed store with an index that opens answers
    /// its roots — an empty `Ok` would be a person with none, and this one has
    /// *This PC*. `keys_loaded` is the same fact asked the other way.
    #[test]
    fn a_keyed_store_answers_its_roots_and_says_its_keys_are_loaded() {
        let temp = tempfile::tempdir().unwrap();
        let user_dir = temp.path().join("users").join("alice");
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            user_dir,
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let users = crate::residency::UserRegistry::new();
        users.insert("alice".to_string(), std::sync::Arc::new(store));

        let roots = super::roots_of(&users, "alice", AID).expect("the index opens");
        assert_eq!(roots.len(), 1, "This PC, and the core root is not listed: {roots:?}");
        assert_eq!(roots[0].name, kotton_store::runtime::roots::Root::THIS_PC);
        assert!(roots[0].granted);
        assert!(
            users
                .get("alice")
                .is_some_and(|s| s.sealing_keys().is_some()),
            "the keyed store is what `keys_loaded` answers true for"
        );
    }

    /// **The daemon makes a guest's folder in the person's sealed store**:
    /// `create-dir` reaches
    /// `UserStore::create_dir` through the same tree `write` does, the folder is
    /// listed empty and answers as a directory, and a second ask is refused in
    /// the WIT's own words.
    #[tokio::test]
    async fn a_guests_folder_is_made_in_the_persons_store() {
        use kotton_app::daemon::apps::PersonalTree as _;
        use kotton_wire::runner::RunnerPathKind;
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            temp.path().join("users").join("alice"),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let (_engine_dir, _engine, tree) = a_tree_with_its_engine(store).await;
        tree.create_dir("/notes/trip").await.expect("made");
        let listed = tree.list("/notes").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].is_dir && listed[0].name == "trip", "{listed:?}");
        assert!(tree.list("/notes/trip").await.unwrap().is_empty());
        assert_eq!(tree.kind("/notes/trip").await.unwrap(), Some(RunnerPathKind::Dir));
        assert_eq!(tree.create_dir("/notes/trip").await, Err("already exists".to_string()));
    }

    /// A person's tree as the daemon builds one, over `store`, and the real sync
    /// engine its hand-over signal reaches — built on the daemon's own host
    /// (`DaemonUserResources`) with `store` resident in it, as an unlock leaves
    /// it.
    async fn a_tree_with_its_engine(
        store: UserStore,
    ) -> (
        tempfile::TempDir,
        std::sync::Arc<kotton_sync::engine::SyncEngine>,
        super::DaemonPersonalTree,
    ) {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let secrets: Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
            Arc::new(kotton_secret::MemorySecrets::new());
        let runtime = Arc::new(
            kotton_device::DeviceRuntime::new_with_secrets(
                dir.path().join("device"),
                kotton_device::config::RuntimeConfig::default(),
                secrets,
            )
            .await
            .expect("DeviceRuntime"),
        );
        let store = Arc::new(store);
        let users = crate::residency::UserRegistry::new();
        users.insert(store.user_id().to_string(), Arc::clone(&store));
        let resources = crate::residency::DaemonUserResources::new(
            users,
            crate::residency::RecordStores::new(),
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            Arc::clone(&runtime),
        );
        let db = Arc::new(
            kotton_record::open_sqlite(&dir.path().join("agent.db"))
                .await
                .expect("db"),
        );
        let engine = kotton_sync::engine::SyncEngine::new(
            db,
            Arc::clone(&runtime),
            resources,
            runtime.paired_keys(),
        );
        let tree = super::DaemonPersonalTree {
            user_id: store.user_id().to_string(),
            store,
            hand_overs: engine.hand_over_signal(),
        };
        (dir, engine, tree)
    }

    /// **Only a write into Inbox tells the engine a hand-over landed.**
    ///
    /// Asked of the engine directly, with its loop not running, so nothing
    /// takes the mark before it is read: a write elsewhere, and a folder made in
    /// Inbox, leave the engine with nothing waiting; a file written into Inbox
    /// leaves it a hand-over waiting for exactly this person.
    #[tokio::test]
    async fn only_a_write_into_inbox_tells_the_engine_a_hand_over_landed() {
        use kotton_app::daemon::apps::PersonalTree as _;
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            temp.path().join("users").join("alice"),
            UserKeys::new(Some([7u8; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let (_engine_dir, engine, tree) = a_tree_with_its_engine(store).await;

        tree.write("/notes/trip.md", b"not a hand-over").await.expect("write");
        tree.create_dir("/Inbox/from the trip").await.expect("folder");
        assert!(
            !engine.hand_over_waiting("alice"),
            "a write outside Inbox, or a folder made in it, must keep the schedule it had"
        );

        tree.write("/Inbox/beach.jpg", b"a photo of the beach").await.expect("write");
        assert!(engine.hand_over_waiting("alice"), "a write into Inbox is a hand-over");
        assert!(!engine.hand_over_waiting("bob"), "and it is this person's, nobody else's");
    }

    /// **A file written into Inbox through the person's tree is in their log
    /// within seconds, on a daemon whose sync engine runs**, not at the next
    /// packing pass.
    ///
    /// The write is the one a hand-over makes: `files.write` reaches this tree
    /// from the sheet's `DirListing::hand_over_through`, and the sheet's *sent*
    /// reads `UserStore::file_logged`, asked here as `logged`. Remove the signal
    /// from `DaemonPersonalTree::write` and the hand-over waits for a tick five
    /// minutes off, and this fails at its deadline.
    ///
    /// Thirty seconds rather than five because the pack is what fills it, and a
    /// pack is slow in an unoptimised build — about 4.8 s here for two small
    /// files. That is the pass's own cost, the one a later pass
    /// would pay; what this holds is that the pass starts at once.
    #[tokio::test]
    async fn a_file_written_into_inbox_is_in_the_log_within_seconds() {
        use kotton_app::daemon::apps::PersonalTree as _;
        use std::time::{Duration, Instant};
        let temp = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:z6MkAliceDevice",
            temp.path().join("users").join("alice"),
            UserKeys::new(Some([7u8; 32])).with_log("did:key:z6MkAliceDevice", &[3u8; 32]),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let (_engine_dir, engine, tree) = a_tree_with_its_engine(store).await;
        std::sync::Arc::clone(&engine).spawn_background();
        // Let the loop park on its wait, so what moves it is the signal.
        tokio::time::sleep(Duration::from_millis(300)).await;

        tree.write("/Inbox/beach.jpg", b"a photo of the beach").await.expect("write");
        let deadline = Instant::now() + Duration::from_secs(30);
        while tree.logged("/Inbox/beach.jpg").await.expect("logged").is_none() {
            assert!(
                Instant::now() < deadline,
                "a hand-over was not in the log within thirty seconds of its write"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
