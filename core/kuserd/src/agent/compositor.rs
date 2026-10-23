// SPDX-License-Identifier: AGPL-3.0-or-later
//! Draining what the compositor tells us — the kuid → kuserd direction.
//!
//! ## Why this is a loop and not a dispatch arm
//!
//! These three messages are not `UserRequest` variants on kuserd's **named**
//! socket, from `kuid` acting as an ordinary authenticated client. They are
//! [`CompositorEvent`]s riding the pair kuserd hands kuid at spawn, so they
//! arrive on a channel rather than a connection, and there is no session to
//! resolve them against.
//!
//! That difference is the point, not an inconvenience. A session token names a
//! **user**, and a machine on its first boot has none — so a display server
//! that needed one could not run before anybody had logged in, and first run
//! would have nothing to draw on. Possession
//! of the handed descriptor is the authorisation here, and the compositor has
//! that from the moment it is forked.
//!
//! ## Which user an event belongs to
//!
//! [`user_db_for`]'s existing fallback: `None` resolves to the single resident
//! user — on a one-user node, the same user a session of kuid's would name.
//!
//! It is deliberately *not* read from the event. An `app_id` arriving over a
//! channel cannot vouch for whose app it is, and a compositor that could name
//! the owner of the surface it is reporting would be asserting something only
//! kuserd knows.
//!
//! ## Which app an event belongs to
//!
//! An event names a [`SurfaceHandle`](kotton_wire::SurfaceHandle) and nothing
//! else, and the app is resolved here, out of `SurfaceProxy`'s own record of
//! what it opened.
//!
//! So the rule is a property rather than a discipline. There is no `app_id`
//! on this channel for a future reader to reach for, and the only answer
//! available is the one this daemon wrote down itself. An event whose handle is
//! unknown — a surface already closed, or one this daemon never opened — is
//! dropped with a line saying so, because there is no instance it could belong
//! to.

use std::sync::Arc;

use kotton_wire::CompositorEvent;
use tokio::sync::mpsc;

use super::DeviceDaemon;

impl DeviceDaemon {
    /// Install the compositor's event sink and drain it for the daemon's life.
    ///
    /// Called once at startup, **before** any `kuid` is supervised, so an event
    /// from a compositor that starts quickly finds a sink rather than a warning.
    pub(super) fn start_compositor_events(self: &Arc<Self>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<CompositorEvent>();
        self.surface_proxy.on_event(tx);

        let this = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                this.handle_compositor_event(event).await;
            }
            tracing::info!("kuserd: compositor event stream ended");
        });
    }

    /// Which app holds the surface an event names, or `None` with a line saying
    /// why not.
    ///
    /// The whole of the handle→app translation, in one place so there is one
    /// answer. It reads `SurfaceProxy`'s map — this daemon's own record of what
    /// it opened — and never the frame, which carries nothing to read.
    fn owner_of(&self, handle: kotton_wire::SurfaceHandle, what: &str) -> Option<String> {
        let owner = self.surface_proxy.owner(handle);
        if owner.is_none() {
            // Ordinary during teardown: the window closed, the daemon dropped
            // the surface, and one more event was already in flight.
            tracing::debug!(surface = %handle, event = what, "kuserd: event for a surface nobody holds");
        }
        owner
    }

    async fn handle_compositor_event(self: &Arc<Self>, event: CompositorEvent) {
        match event {
            CompositorEvent::SurfaceInputEvent { handle, event } => {
                let Some(app_id) = self.owner_of(handle, "SurfaceInputEvent") else {
                    return;
                };
                self.compositor_input(app_id, handle, event).await;
            }
            CompositorEvent::SurfaceError { handle, reason } => {
                let Some(app_id) = self.owner_of(handle, "SurfaceError") else {
                    return;
                };
                if let Err(e) = kotton_app::daemon::apps::app_surface_error(
                    Arc::clone(&self.live_instances),
                    app_id,
                    reason,
                )
                .await
                {
                    tracing::warn!(error = %e, "kuserd: surface error not delivered to the guest");
                }
            }
            CompositorEvent::SurfaceClosed { handle } => {
                let Some(app_id) = self.owner_of(handle, "SurfaceClosed") else {
                    return;
                };
                // The surface is gone at the glass, so this daemon's record of
                // who held it goes too — `SurfaceProxy::close` covers the other
                // direction only.
                self.surface_proxy.forget(handle);
                // **The instance ends when its *last* surface does, not when any one of
                // them does.** An app may have several surfaces: tearing the runner down
                // when one closes would mean the person closes one window of the desktop
                // and the desktop exits, taking every other window with it.
                //
                // What is still true is the reason the teardown exists — the user dismissed
                // the app, and an instance that lingers is a process with nothing on screen
                // that only the next launch of the app would end. That is a statement about
                // an app with nothing left on screen, and that is what is checked here.
                let mut live = self.live_instances.lock().await;
                let gone = match live.get_mut(&app_id) {
                    Some(instance) => {
                        instance.surfaces.retain(|h| *h != handle);
                        instance.surfaces.is_empty()
                    }
                    // Nothing live to ask: fall through to the teardown, which is a no-op,
                    // and to the grant sweep, which is not.
                    None => true,
                };
                let dying = if gone { live.remove(&app_id) } else { None };
                drop(live);
                if !gone {
                    tracing::debug!(
                        %app_id,
                        surface = %handle,
                        "kuserd: a surface closed and the app still has others"
                    );
                    return;
                }
                if let Some(mut instance) = dying {
                    kotton_app::daemon::apps::terminate_long_lived_instance(&mut instance).await;
                }
                // The instance exited, so its `while_open` grants end with it: a
                // later launch does not inherit them. Resolve the resident user's db the same way
                // input delivery does (`None` → the single resident user).
                if let Ok(user_db) = super::dispatch::user_db_for_compositor(
                    &self.runtime,
                    &self.users,
                    &self.user_dbs,
                    &self.base,
                )
                .await
                {
                    kotton_app::daemon::apps::app_closed(&user_db, &app_id).await;
                }
            }
            // **Recorded, and the designated app told to ask again.** The report is the
            // compositor saying what the app stack now holds, and the designated app reads
            // it when it asks for the window list. The handles are joined against this
            // daemon's own record of who holds what — `SurfaceProxy::windows` — so the
            // attribution in that list is the host's own words rather than anything that
            // travelled.
            //
            // *When* it asks matters. Asking only when it repaints, the dock would repaint
            // when the shell's own state changed — in the same breath as the click that
            // opened a window, before this report had arrived — and list the window before
            // last. So a report that moved the stack is followed by a nudge carrying
            // nothing; see [`Self::nudge_the_window_list`].
            CompositorEvent::WindowsChanged { windows } => {
                if self.surface_proxy.note_windows(windows) {
                    self.nudge_the_window_list().await;
                }
            }
            CompositorEvent::ShellReopenRequested => {
                // No session travelled with the gesture — a tray click says
                // *show me the desktop*, not *I am So-and-so*. See
                // `launch_designated_shell`'s `authenticated` parameter.
                let _ = self.launch_designated_shell("tray", None).await;
            }
            // **The person quit, so the daemon stops too**; closing the window does
            // not stop it.
            //
            // The same framing as every other arm here: the compositor said
            // what happened at the glass and this daemon decides what it means.
            // What it means is the whole of the rule — closing the window is
            // closing a window, and *Quit Kotton* is the one gesture that ends
            // the long-running process behind it.
            //
            // No session, for the reason the tray's *Open* has none: a menu
            // click says *I am done*, not *I am So-and-so*. That is worth
            // stating plainly because this verb ends a daemon rather than
            // starting an app, and the obvious next thought is that it should
            // therefore be authenticated. It should not, and the reason is
            // structural rather than a judgement call: possession of the
            // handed descriptor is the authorisation on this channel (see the
            // module doc), and the only holder is the compositor this daemon
            // forked itself. There is no third party who could send this, so
            // there is no caller for a check to distinguish.
            //
            // [`DeviceDaemon::quit`] does not tear anything down — it ends
            // `serve`, and `run` performs the one ordered shutdown this daemon
            // has.
            CompositorEvent::QuitRequested => {
                tracing::info!("kuserd: the person quit Kotton at the tray");
                self.quit();
            }
            // **Never routed here.** `SurfaceProxy`'s reader hands a prompt's answer
            // straight to the door waiting on it, because that door is usually
            // being serviced *inside* an event this drain is still handling.
            // An answer that reached this arm had nobody waiting.
            CompositorEvent::PromptAnswered { id, .. } => {
                tracing::debug!(id, "kuserd: a prompt's answer reached the drain with no one waiting");
            }
        }
    }

    /// **The daemon's end of the compositor's pair** — where the platform's prompts are asked.
    /// Public for the in-process harness, which stands a fake desk on it where
    /// `supervise_kuid` would attach the real one; nothing a guest holds reaches it.
    pub fn desk(&self) -> &crate::surface_proxy::SurfaceProxy {
        &self.surface_proxy
    }

    /// The pre-auth host a guest in `world occupant` calls into.
    ///
    /// One builder, because two call sites in this file built the same eight
    /// borrows and a third was about to. The host is deliberately *per call*:
    /// it carries what the exchange it was lent to did — see
    /// [`occupant_host::DaemonOccupantHost::unlocked_as`] — so sharing one
    /// across calls would be sharing an answer.
    pub fn occupant_host(&self) -> super::occupant_host::DaemonOccupantHost<'_> {
        super::occupant_host::occupant_host(
            &self.runtime,
            &self.users,
            &self.sessions,
            &self.base,
            &self.db,
            &self.record_stores,
            &self.ceremonies,
            &self.user_dbs,
            &self.event_log_tasks,
            &self.device_db,
            &self.connected_peers,
            &self.surface_proxy,
            self.browser_admissions(),
        )
    }

    /// The revoke-only handle on this daemon's browser admissions — built from
    /// the maps the daemon holds, so a revoke through it ends what is live.
    pub(super) fn browser_admissions(&self) -> super::browser_channel::BrowserAdmissions {
        super::browser_channel::BrowserAdmissions::new(
            Arc::clone(&self.sessions),
            Arc::clone(&self.principal_sessions),
            Arc::clone(&self.browser_channels),
        )
    }

    /// Tell the designated app its window list moved, so the dock asks again.
    ///
    /// The frame is a constant and the recipient is chosen by the daemon; both halves are
    /// [`app_windows_changed`](kotton_app::daemon::apps::app_windows_changed)'s. What is
    /// here is the lending: the repaint this causes is a render like any other, and a
    /// render may make the occupant's, infer's or records' calls, so it is lent the same
    /// hosts an input event is. Lending none would turn a repaint into a screen of
    /// refusals.
    async fn nudge_the_window_list(self: &Arc<Self>) {
        let occupant = self.occupant_host();
        let infer = super::infer_host::infer_host(
            &self.runtime,
            &self.record_stores,
            self.users.any(),
            &self.infer_proxy,
        );
        let records = super::record_access::records_host(&self.runtime, &self.users, &self.base, &self.record_stores, super::record_access::the_one_loaded(self.users.ids()));
        if let Err(e) = kotton_app::daemon::apps::app_windows_changed(
            &super::app_host::app_host(
                self.runtime.event_bus(),
                &self.surface_proxy,
                &self.runner,
                &self.base,
                self.runtime.secrets(),
                &self.users,
                self.sync_engine.hand_over_signal(),
            ),
            Arc::clone(&self.live_instances),
            Some(&occupant),
            Some(&infer),
            Some(&records),
        )
        .await
        {
            tracing::warn!(error = %e, "kuserd: the window-list nudge was not delivered");
        }
    }

    async fn compositor_input(
        self: &Arc<Self>,
        app_id: String,
        // The surface the compositor hit-tested. It is what found `app_id`
        // above, and it travels on to the guest so an app with two windows can
        // tell which one was clicked.
        surface: kotton_wire::SurfaceHandle,
        event: kotton_wire::ipc::types::InputEventPayload,
    ) {
        // Absent before anybody has enrolled, and that is not an error. The
        // pre-identity shell is launched deliberately with no user
        // (`launch_system_shell`) and handed `create-identity` so a person can
        // enrol; refusing to route its input made that unreachable, because the
        // click that enrols was dropped for want of the user it would create.
        //
        // Only a launch the guest raises reads this, and there is nothing to
        // launch out of yet — `app_input_event` says so where it ignores them.
        let user_db = super::dispatch::user_db_for_compositor(
            &self.runtime,
            &self.users,
            &self.user_dbs,
            &self.base,
        )
        .await
        .ok();

        // The occupant host is built unconditionally and handed to every input
        // event. It is not the gate: `apps.rs` reads the user's own `app_roles`
        // designation to decide whether *this* app is instantiated into
        // `world occupant`, and an app that is not has no `auth` import to call.
        let occupant = self.occupant_host();

        // Whoever is resident. A guest calling `infer` from an input event must
        // get the same answer it would from any other frame, so this is built
        // here rather than passed as `None`.
        let infer = super::infer_host::infer_host(
            &self.runtime,
            &self.record_stores,
            self.users.any(),
            &self.infer_proxy,
        );
        // The person's kept records (`schema.kept`): any app may hold
        // `schema.read`, so this is not occupant-gated. Not `users.any()`, as
        // infer is built above — with two people loaded that is a guess over
        // whose records an app is handed, so this path hands none.
        let records = super::record_access::records_host(&self.runtime, &self.users, &self.base, &self.record_stores, super::record_access::the_one_loaded(self.users.ids()));

        // **Who lives here, read before the event is delivered.**
        //
        // The occupant world is a world with no user in it, and the
        // one verb that can end it — `create-identity` — is reached by typing a
        // passphrase and pressing a button, which is this call. So the daemon's
        // side of `UserCreated` is exactly *this answer changing across this
        // await*: nobody was resident, and now somebody is.
        //
        // Read from the registry rather than from a flag the occupant host sets,
        // because the registry is the daemon's own record of who exists and a
        // flag would be a second one. `None` before means the running shell can
        // only be the one `app_launch_system_shell` started — a resident-but-
        // locked person answers `Some` here (loaded and unlocked are not the
        // same thing), so an unlock does not take this branch.
        let resident_before = self.users.any();

        if let Err(e) = kotton_app::daemon::apps::app_input_event(
            &super::app_host::app_host(
                self.runtime.event_bus(),
                &self.surface_proxy,
                &self.runner,
                &self.base,
                self.runtime.secrets(),
                &self.users,
                self.sync_engine.hand_over_signal(),
            ),
            user_db.as_ref(),
            &self.base,
            Arc::clone(&self.live_instances),
            app_id.clone(),
            surface,
            event,
            None,
            Some(&occupant),
            Some(&infer),
            Some(&records),
        )
        .await
        {
            tracing::warn!(error = %e, "kuserd: input event failed");
        }

        // **Two doors, one move.** Both are read after the exchange, not inside
        // the verb: `app_input_event` holds the `live_instances` lock for the
        // whole of it and the relaunch re-acquires it, so a launch raised from
        // inside the verb would deadlock against the call that raised it — the
        // same reason a guest's own `apps::launch` is drained afterwards rather
        // than serviced inline.
        //
        // The identity now exists, so the world the person is looking at is the
        // wrong one.
        let born = if resident_before.is_none() {
            self.users.any()
        } else {
            None
        };
        if let Some(user_id) = born {
            let _ = self.end_the_occupant_world(&app_id, &user_id).await;
        }
        // **`else`, because one exchange replaces the screen at most once.** The
        // ceremony door has already torn the instance down, so the second door
        // would find nothing live under that id, read that as *nothing to
        // spare*, and launch a second shell over the first. The two triggers are
        // disjoint today — `create_identity` mints its session through
        // `create_user` and never reaches `open_session`, so `unlocked_as`
        // answers `None` after a ceremony — and this is what keeps that a
        // property of this function rather than of that one.
        //
        // The person typed their credential at the lock screen and it was
        // right, so the world they are looking at is the wrong one for the same
        // reason: the instance drawing it was launched for nobody, and a shell
        // launched for nobody has no mount, no `did`, and no grant any app it
        // raises can be given. The shell's own `handle_lock_input` still sets
        // `AppMode::Authenticated` in place, which is now the fallback rather
        // than the path — exactly as the ceremony's in-place transition is.
        //
        // **The trigger is the exchange's own answer**, not the world
        // afterwards: an unlock changes no record the daemon could read back,
        // because the person was registered and loaded before they typed.
        // `unlocked_as` is what this host let in during this call.
        //
        // **The tray door is not this door and is deliberately not answered
        // here.** A tray click after a successful unlock carries no exchange to
        // read, so it keeps launching locked; answering it means the daemon
        // holding a notion of *who this screen is authenticated as*, which is a
        // design of the seat and not a line to guess at.
        else if let Some(user_id) = occupant.unlocked_as() {
            let _ = self.end_the_locked_screen(&app_id, &user_id).await;
        }
    }

    /// **The occupant world ends when the identity exists.**
    ///
    /// The welcome screen runs in a world with no user in it: no data mount, no
    /// grants, `occupant: true` unconditionally, because there was nobody yet
    /// whose designation could be consulted. All three stop being right the
    /// moment `create-identity` returns. If nothing happened at that moment,
    /// the same instance would carry on and draw a desktop over a world with no
    /// user in it, and the file browser it opened would say *no file capability
    /// was granted to this app*.
    ///
    /// Two steps, in this order, and they are [`Self::replace_the_screen`]'s
    /// because the unlock door performs the same two:
    ///
    /// 1. **Tear the occupant instance down**, on the one path every relaunch
    ///    uses ([`teardown_live_instance`](kotton_app::daemon::apps::teardown_live_instance)).
    /// 2. **Launch it as the resident shell** — `app_launch`, which computes the
    ///    mount at `base/users/<uid>/data`, reads the grants the install
    ///    recorded, and derives `mode` from the session.
    ///
    /// **Nothing is designated here.** The `shell` row a resident launch resolves
    /// is seeded on the user database's open path (`db/user_db.rs`, an
    /// `INSERT OR IGNORE` that yields to the person's own choice), so the identity
    /// this is called for already has one by the time it exists.
    ///
    /// **Teardown before launch, and the person sees a blank moment.** A launch
    /// ends the live instance of the app it launches, and only that one
    /// (`launch_instance`); the occupant's app need not be the app the person
    /// designated, so the occupant is ended here by its own id rather than left
    /// to the launch. A blank moment is the cost of the map being keyed by app
    /// id; the alternative is a leaked surface, and a brief blank is acceptable
    /// where a stuck welcome screen is not. Surfaces keyed by instance id is what
    /// removes the blank, and that is not built.
    ///
    /// **The guest is not asked and does not have to cooperate.** The shell's
    /// own welcome flow still transitions in place after `create-identity`
    /// returns, which is now a fallback rather than the path: if this relaunch
    /// fails the person still reaches a desktop, without their files, rather
    /// than sitting on a welcome screen that has nothing left to do.
    ///
    /// Returns what the launch answered, so a caller — and the test that pins
    /// this — can see what the new instance was handed. `compositor_input`
    /// drops it; the launch has already logged its own outcome.
    pub async fn end_the_occupant_world(
        self: &Arc<Self>,
        // The app whose instance ran the welcome: the one the input event that
        // minted the identity was delivered to.
        occupant_app_id: &str,
        // Who now lives here.
        user_id: &str,
    ) -> Option<kotton_wire::UserResponse> {
        tracing::info!(
            %occupant_app_id, %user_id,
            "kuserd: the identity exists, so the occupant world is over"
        );
        self.replace_the_screen("identity created", occupant_app_id, user_id)
            .await
    }

    /// **The lock screen ends when the credential is accepted**, and the desktop
    /// that follows has its mount.
    ///
    /// The second door, and deliberately the same move as
    /// [`Self::end_the_occupant_world`] rather than a second answer to it. The
    /// ceremony's trigger is *the registry answered nobody before and somebody
    /// after*; this one's is *the exchange opened a session for a named user
    /// and the instance that raised it has no mount*. Same place — after the
    /// exchange, never inside the verb — same teardown, same relaunch with the
    /// user threaded from the call that knows.
    ///
    /// **Why the relaunch and not a message to the running shell.** The
    /// instance drawing the lock screen was launched for nobody: no
    /// `user_vfs_path`, so no app it raises can be granted a file capability,
    /// and no `did`/`display_name`, so the menubar has no fingerprint to draw.
    /// Those three are launch arguments, read once at `init` by design — the
    /// shell learns who it runs as from its launch — so the only thing that
    /// can change the answer is another launch.
    ///
    /// **This is one door of three, and it says so.** A tray reopen after a
    /// successful unlock has no exchange to hang this on and keeps launching
    /// locked; answering it means the daemon holding a notion of *who this
    /// screen is authenticated as*, which is a design act rather than a task:
    /// that door stays open until the seat is designed.
    pub async fn end_the_locked_screen(
        self: &Arc<Self>,
        // The app whose instance drew the lock screen: the one the input event
        // that carried the credential was delivered to.
        occupant_app_id: &str,
        // Who just came in, as the exchange that let them in named them.
        user_id: &str,
    ) -> Option<kotton_wire::UserResponse> {
        tracing::info!(
            %occupant_app_id, %user_id,
            "kuserd: the person is in, so the locked screen is over"
        );
        self.replace_the_screen("unlocked", occupant_app_id, user_id)
            .await
    }

    /// Tear the instance at this screen down and launch the shell for
    /// `user_id`. The body both doors share.
    ///
    /// **It asks two things of the instance that raised the event, and refuses
    /// on either.** The doors above decide *that* the world is wrong; this
    /// decides whether the instance in hand is the one to replace.
    ///
    /// 1. **It must be the occupant's.** The flip is tied to the instance the
    ///    host put in `world occupant`, not to whichever app took the event.
    ///    Today the ceremony door can only be reached by the occupant, because
    ///    no other instance can run before a user exists — but that is a fact
    ///    about the world rather than about the code: a recovery-key login over
    ///    IPC (`handlers/user.rs`) flips the registry too, and the next event to
    ///    *any* instance would then end it. Ending somebody else's app because
    ///    the person logged in elsewhere is the failure, and this is the line
    ///    that stops it.
    /// 2. **It must have no mount.** An instance already launched for somebody
    ///    is already the world it should be; replacing it would cost the person
    ///    their open windows to arrive back where they are. This is what makes
    ///    a re-entered credential at an unlocked desktop a no-op.
    ///
    /// `None` from [`instance_world`](kotton_app::daemon::apps::instance_world)
    /// is not `false` on either: nothing of that app is live, so there is no
    /// instance to spare and nothing to end — the teardown below is a no-op and
    /// the launch is the whole of what happens. That is the case the suite
    /// drives the ceremony door in, and it is what a screen whose instance died
    /// mid-exchange looks like.
    async fn replace_the_screen(
        self: &Arc<Self>,
        reason: &str,
        occupant_app_id: &str,
        user_id: &str,
    ) -> Option<kotton_wire::UserResponse> {
        let world =
            kotton_app::daemon::apps::instance_world(&self.live_instances, occupant_app_id).await;
        if let Err(refusal) = a_screen_to_replace(world) {
            tracing::warn!(
                %occupant_app_id, %user_id, %reason, ?world,
                "kuserd: leaving this screen alone — {}", refusal.why()
            );
            return None;
        }
        if kotton_app::daemon::apps::teardown_live_instance(
            &super::app_host::app_host(
                self.runtime.event_bus(),
                &self.surface_proxy,
                &self.runner,
                &self.base,
                self.runtime.secrets(),
                &self.users,
                self.sync_engine.hand_over_signal(),
            ),
            &self.live_instances,
            occupant_app_id,
        )
        .await
        {
            tracing::info!(%occupant_app_id, %reason, "kuserd: tore the occupant instance down");
        }
        self.launch_designated_shell(reason, Some(user_id.to_string()))
            .await
    }

    /// Resolve which app the user designated `shell` and launch it.
    ///
    /// This work used to live in `kuid`: it asked kuserd `AppGetRole { role:
    /// "shell" }`, fell back to a hardcoded id if that failed, and sent
    /// `AppLaunch`. Two client verbs, a second connection and a bearer token, so
    /// that the display server could decide what the desktop is.
    ///
    /// It belongs here. kuserd owns `app_roles`, kuserd owns the app registry
    /// the launch reads, and kuserd spawned the compositor asking. The
    /// compositor reports a gesture — a tray click, being freshly started, or an
    /// identity that has just come into existence — and what that gesture
    /// *means* is this daemon's call.
    ///
    /// `reason` is for the log only; nothing branches on it.
    ///
    /// `authenticated` is **who this launch is for**, and passing `Some` is the
    /// claim that they are in: `app_launch` computes the data mount at
    /// `base/users/<uid>/data` from it and derives `mode=authenticated` from it,
    /// so a shell launched with `None` draws the unlock screen and can read no
    /// files. Every gesture this daemon hears about — a boot, a tray click —
    /// carries no session and passes `None`; the callers that pass `Some` are
    /// the two doors of [`Self::replace_the_screen`], where the person has just
    /// performed the ceremony at this screen (`create_user` minted their
    /// session as part of it) or just unlocked at it (the exchange that opened
    /// the session named them).
    ///
    /// **It is not read from the session map**, though a token naming them is in
    /// there. A process-scoped sidecar token names its user too
    /// (`mint_gateway_bootstrap_token`, `SidecarToken`), so "somebody holds a
    /// token for this user" is not "this person is in at this screen" — reading
    /// it that way would hand the data mount to a boot nobody had authenticated.
    /// The daemon has no notion of *the screen's session* to read instead, which
    /// is why this is threaded from the call that knows rather than resolved
    /// here.
    ///
    /// Returns what the launch answered, or `None` when it said why it could not
    /// launch anything.
    ///
    /// **`pub` for the same reason [`Self::end_the_occupant_world`] is.** This is
    /// what a boot does, and the only way to ask *which screen does this daemon
    /// open on* is to make it do it and read what the instance was handed —
    /// nothing else in the process records it. The suite's
    /// `a_second_boot_with_a_registered_identity_opens_the_lock_screen` calls it
    /// with the daemon's own `"boot"` reason and no session, which is exactly the
    /// call in `run`.
    pub async fn launch_designated_shell(
        self: &Arc<Self>,
        reason: &str,
        authenticated: Option<String>,
    ) -> Option<kotton_wire::UserResponse> {
        let occupant = self.occupant_host();

        // Whoever is resident. A guest calling `infer` must get the same answer
        // whichever frame it asked from, so this is built beside the occupant
        // host rather than passed as `None`.
        let infer = super::infer_host::infer_host(
            &self.runtime,
            &self.record_stores,
            self.users.any(),
            &self.infer_proxy,
        );
        // The person's kept records (`schema.kept`): any app may hold
        // `schema.read`, so this is not occupant-gated. Not `users.any()`, as
        // infer is built above — with two people loaded that is a guess over
        // whose records an app is handed, so this path hands none.
        let records = super::record_access::records_host(&self.runtime, &self.users, &self.base, &self.record_stores, super::record_access::the_one_loaded(self.users.ids()));

        // The seam, and it is checked here rather than inside either branch: a
        // resident user's own designation wins, always. The system-shell path
        // below hands `world occupant` to a fixed path with no designation
        // behind it, so it must be unreachable the moment a designation can be
        // *read* — and that means "a user is resident", which is exactly this
        // test. A registered user who is not loaded has a designation nobody can
        // read (their database is sealed), so there is nothing here to defer to.
        //
        // **This answers what to run, and it does not answer which screen.**
        // A constant `mode=welcome` would make *either* arm that reaches
        // `app_launch_system_shell` draw the first-run screen, this one and the
        // `Locked` one below; a person's ordinary second boot takes the second,
        // and would be shown a welcome whose one door then refused them, because
        // `create_identity` reads the device registry and the registry knows they
        // exist. The screen comes from that registry on both paths
        // (`push_shell_mode`), so this test decides only whose designation is
        // consultable.
        let resident = self.users.any();
        if resident.is_none() {
            match kotton_app::daemon::apps::app_launch_system_shell(
                &super::app_host::app_host(
                    self.runtime.event_bus(),
                    &self.surface_proxy,
                    &self.runner,
                    &self.base,
                    self.runtime.secrets(),
                    &self.users,
                    self.sync_engine.hand_over_signal(),
                ),
                &self.base,
                Arc::clone(&self.live_instances),
                Some(&occupant),
                Some(&infer),
                Some(&records),
                resident.as_deref(),
            )
            .await
            {
                Ok(resp) => return Some(resp),
                Err(e) => {
                    tracing::warn!(error = %e, %reason, "kuserd: system shell did not launch");
                    return None;
                }
            }
        }

        let user_db = match super::dispatch::user_db_for_compositor(
            &self.runtime,
            &self.users,
            &self.user_dbs,
            &self.base,
        )
        .await
        {
            Ok(db) => db,
            Err(e) => {
                // **Two failures, and only one of them has a remedy the person can perform.**
                //
                // Saying `no user to launch a shell for` for both, at WARN, would hold the
                // real reason in the same line where nobody reads it. A WARN does not reach
                // the terminal, so a locked account would produce no window and no
                // explanation, and the lock would sit on the outside of the only door that
                // could open it.
                //
                // **Locked is recoverable, so it gets a surface.** A resident user can be
                // locked at the same time, which is why this is reached at all
                // rather than the branch above: `users.any()` answers *loaded*, not
                // *unlocked*. The system shell needs no user database to start, and
                // `app_launch_system_shell` routes it to the unlock screen — the host sets
                // `mode=locked` and hands it the registered users whenever nobody holds a
                // session.
                //
                // The rule lives in one place (`push_shell_mode`) and both launch paths
                // ask it, so this arm never reaches a shell that draws the welcome screen.
                if let Some(locked) = kotton_record::open::Locked::in_error(&e) {
                    tracing::info!(
                        user_id = %locked.user_id, %reason,
                        "kuserd: the account is locked — opening the unlock screen"
                    );
                    match kotton_app::daemon::apps::app_launch_system_shell(
                        &super::app_host::app_host(
                            self.runtime.event_bus(),
                            &self.surface_proxy,
                            &self.runner,
                            &self.base,
                            self.runtime.secrets(),
                            &self.users,
                            self.sync_engine.hand_over_signal(),
                        ),
                        &self.base,
                        Arc::clone(&self.live_instances),
                        Some(&occupant),
                        Some(&infer),
                        Some(&records),
                        // **No resident.** Passing the locked user here would have the host
                        // call this an authenticated launch and hand the shell a session it
                        // does not have. The person is loaded and locked, and for the purpose
                        // of *which screen to draw* that is the same as nobody.
                        None,
                    )
                    .await
                    {
                        Ok(resp) => return Some(resp),
                        Err(e) => {
                            tracing::error!(error = %e, %reason, "kuserd: the unlock screen did not launch");
                            return None;
                        }
                    }
                }
                // Not locked: missing, or it will not open. There is no credential that
                // fixes that, so offering one would be a lie.
                tracing::error!(
                    error = %e, %reason,
                    "kuserd: could not open the user database, so no shell can start"
                );
                return None;
            }
        };

        // The role table is the user's own designation. There is no fallback to
        // a hardcoded id: kuid had one (`sh.kotton.shell`), which meant a node
        // whose user had designated something else would silently get the
        // built-in instead — the designation losing to a constant in the
        // process that was least entitled to hold it.
        let app_id =
            match kotton_app::daemon::apps::app_get_role(&user_db, "shell".to_string()).await {
                Ok(kotton_wire::UserResponse::AppRole { app_id, .. }) => app_id,
                Ok(other) => {
                    tracing::warn!(?other, %reason, "kuserd: no app is designated `shell`");
                    return None;
                }
                Err(e) => {
                    tracing::warn!(error = %e, %reason, "kuserd: could not read the `shell` role");
                    return None;
                }
            };

        match kotton_app::daemon::apps::app_launch(
            &super::app_host::app_host(
                self.runtime.event_bus(),
                &self.surface_proxy,
                &self.runner,
                &self.base,
                self.runtime.secrets(),
                &self.users,
                self.sync_engine.hand_over_signal(),
            ),
            &user_db,
            &self.base,
            Arc::clone(&self.live_instances),
            app_id.clone(),
            vec![],
            authenticated,
            Some(&occupant),
            Some(&infer),
            Some(&records),
        )
        .await
        {
            Ok(resp) => {
                tracing::info!(%app_id, %reason, "kuserd: launched the designated shell");
                Some(resp)
            }
            Err(e) => {
                tracing::warn!(%app_id, %reason, error = %e, "kuserd: shell launch failed");
                None
            }
        }
    }
}

/// Why a screen was left alone.
///
/// Spelled out rather than logged as prose at each site, so the two grounds are
/// one list a reader can count and a test can name. Both doors ask the same
/// two questions, in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeftAlone {
    /// Somebody else's app took the event. The flip is tied to the instance the
    /// host put in `world occupant`, never to whichever app was on screen.
    NotTheOccupants,
    /// The instance already carries the person's data mount, so it is already
    /// the world it should be. This is what makes a credential re-entered at an
    /// unlocked desktop a no-op rather than a relaunch that costs the person
    /// their open windows.
    AlreadyMounted,
}

impl LeftAlone {
    fn why(self) -> &'static str {
        match self {
            Self::NotTheOccupants => "the instance that raised it is not the occupant's",
            Self::AlreadyMounted => "it already carries a mount",
        }
    }
}

/// Whether the instance that raised the event is a screen to replace.
///
/// A function of one reading and nothing else, so that *what the rule is* can
/// be asked without a daemon, a runner and a live instance to ask it through —
/// which matters here because the two grounds cannot be separated from the
/// outside. Every instance the suite can launch through IPC belongs to a
/// resident user and therefore carries a mount, so an integration test that
/// aims the door at somebody else's app is refused on **both** grounds and
/// cannot say which one did it. These four cases can.
///
/// `None` — nothing of that app is live — is not a refusal: there is no
/// instance to spare and nothing to end, which is the state the suite drives
/// the ceremony door in and what a screen whose instance died mid-exchange
/// looks like. The teardown is then a no-op and the launch is the whole of what
/// happens.
fn a_screen_to_replace(
    world: Option<kotton_app::daemon::apps::InstanceWorld>,
) -> Result<(), LeftAlone> {
    match world {
        Some(world) if !world.occupant => Err(LeftAlone::NotTheOccupants),
        Some(world) if world.mounted => Err(LeftAlone::AlreadyMounted),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_app::daemon::apps::InstanceWorld;

    fn world(occupant: bool, mounted: bool) -> Option<InstanceWorld> {
        Some(InstanceWorld { occupant, mounted })
    }

    /// The lock screen: the occupant's instance, launched for nobody. This is
    /// the one the person is looking at when they type their credential.
    #[test]
    fn the_occupants_unmounted_screen_is_replaced() {
        assert_eq!(a_screen_to_replace(world(true, false)), Ok(()));
    }

    /// **The line, on its own.** An ordinary app's
    /// instance is left alone even when it has no mount — so the rule is the
    /// designation, not the absence of a mount standing in for it.
    #[test]
    fn a_bystanders_instance_is_left_alone_however_it_was_launched() {
        assert_eq!(
            a_screen_to_replace(world(false, false)),
            Err(LeftAlone::NotTheOccupants)
        );
        assert_eq!(
            a_screen_to_replace(world(false, true)),
            Err(LeftAlone::NotTheOccupants)
        );
    }

    /// A credential typed at a desktop that already belongs to somebody costs
    /// them nothing.
    #[test]
    fn a_screen_that_already_has_a_mount_is_not_replaced() {
        assert_eq!(
            a_screen_to_replace(world(true, true)),
            Err(LeftAlone::AlreadyMounted)
        );
    }

    /// Nothing live under that id: not a refusal. The ceremony door is driven
    /// in exactly this state by
    /// `kuid_surface::the_shell_that_follows_the_ceremony_carries_the_users_data_mount`.
    #[test]
    fn no_live_instance_is_not_a_refusal() {
        assert_eq!(a_screen_to_replace(None), Ok(()));
    }
}
