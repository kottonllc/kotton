// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every event logged on this thread while a [`Capture`] is held, as text.
//!
//! For a test that has to say what a log line did **not** carry. Built on
//! `tracing` alone rather than `tracing-subscriber`, so no dependency is added
//! to hold it. A `#[tokio::test]` on the default `current_thread` flavour runs
//! its spawned tasks on the test's own thread, so a door served in the test is
//! seen, and a test on another thread is not. Under `multi_thread` the sink sees
//! nothing (measured 0 of 20 at review, 2026-09-28); the two tests that use this
//! stay on the default flavour for that reason.
//!
//! **Global, not `set_default`, and why.** The first version held a scoped
//! subscriber, and it failed one full run in seven with the event missing.
//! `tracing-core` caches each callsite's interest the first time any thread
//! reaches it, and while only one dispatcher is registered it asks *that
//! thread's* default — so a parallel test with no subscriber, reaching the same
//! `debug!` first, cached `never` and the line was dropped before any subscriber
//! saw it. A process-wide subscriber that always wants the event, writing to a
//! sink only the capturing thread has set, leaves no thread for which the answer
//! is `never`. What is left is the instant the global is first installed, and
//! [`Capture::start`] rebuilds the cache after it, so a callsite registered
//! before then is asked again.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, Once};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

type Sink = Arc<Mutex<Vec<String>>>;

thread_local! {
    static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

static INSTALL: Once = Once::new();

/// Holds the capture on, on this thread, for as long as it lives.
pub(crate) struct Capture {
    lines: Sink,
}

impl Capture {
    pub(crate) fn start() -> Self {
        INSTALL.call_once(|| {
            tracing::subscriber::set_global_default(Lines)
                .expect("nothing else in kotton-ipc's tests installs a global subscriber");
        });
        tracing::callsite::rebuild_interest_cache();
        let lines: Sink = Arc::new(Mutex::new(Vec::new()));
        SINK.with(|s| *s.borrow_mut() = Some(Arc::clone(&lines)));
        Self { lines }
    }

    /// Every event so far, one line each: ` message=… field=value …`.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines.lock().expect("capture").clone()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        SINK.with(|s| *s.borrow_mut() = None);
    }
}

struct Lines;

struct Text(String);

impl Visit for Text {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl Subscriber for Lines {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        SINK.with(|s| {
            if let Some(sink) = s.borrow().as_ref() {
                let mut text = Text(String::new());
                event.record(&mut text);
                sink.lock().expect("capture").push(text.0);
            }
        });
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}
