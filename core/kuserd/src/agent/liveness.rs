// SPDX-License-Identifier: AGPL-3.0-or-later
//! Whether a sidecar's exit means *restart it* or *it has never worked*.
//!
//! A supervisor that restarts with backoff and no ceiling makes a process that
//! has never once started look exactly like one that started a thousand times
//! and crashed: the same warning, repeating, forever. A sidecar refused by an
//! argument check on every start would be that process, and nothing would say
//! so.
//!
//! Backoff is for a process that worked and stopped. A process that exits
//! within moments of every start, and has never run longer than that, is not
//! transient: after a few tries it is reported as a failure, once, and left
//! alone. The distinction is made by run time, which every supervisor can
//! measure, rather than by exit code, which every sidecar spells differently.

use std::time::Duration;

/// A start that ends sooner than this never got going.
pub(crate) const EARLY: Duration = Duration::from_secs(5);
/// Early exits in a row before the supervisor stops calling them transient.
pub(crate) const EARLY_EXITS_ALLOWED: u32 = 3;

#[derive(Default, Debug)]
pub(crate) struct Liveness {
    /// The process has run past [`EARLY`] at least once: it works, and any later
    /// exit is a crash to restart from.
    ran_once: bool,
    early_exits: u32,
}

impl Liveness {
    /// Note an exit (or a failed spawn) that ran for `ran_for`. `Some(reason)`
    /// means *stop supervising and report this*; `None` means restart as usual.
    pub(crate) fn exited(
        &mut self,
        ran_for: Duration,
        outcome: &std::io::Result<std::process::ExitStatus>,
    ) -> Option<String> {
        if ran_for >= EARLY {
            self.ran_once = true;
            self.early_exits = 0;
            return None;
        }
        if self.ran_once {
            return None;
        }
        self.early_exits += 1;
        if self.early_exits < EARLY_EXITS_ALLOWED {
            return None;
        }
        let how = match outcome {
            Ok(status) => match status.code() {
                Some(code) => format!("exited with code {code}"),
                None => "was killed by a signal".to_string(),
            },
            Err(e) => format!("could not be spawned: {e}"),
        };
        Some(format!(
            "{how} within {}s of every start, {} times, and has never run — not retrying. \
             Its own error is above in this log.",
            EARLY.as_secs(),
            self.early_exits
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::ExitStatus;

    fn failed() -> std::io::Result<ExitStatus> {
        Ok(ExitStatus::from_raw(1 << 8))
    }

    #[test]
    fn three_early_exits_and_no_run_is_a_failure() {
        let mut l = Liveness::default();
        assert!(l.exited(Duration::from_millis(30), &failed()).is_none());
        assert!(l.exited(Duration::from_millis(30), &failed()).is_none());
        let reason = l
            .exited(Duration::from_millis(30), &failed())
            .expect("the third gives up");
        assert!(reason.contains("code 1"), "{reason}");
        assert!(reason.contains("never run"), "{reason}");
    }

    #[test]
    fn a_process_that_once_ran_is_always_restarted() {
        let mut l = Liveness::default();
        assert!(l.exited(Duration::from_secs(60), &failed()).is_none());
        for _ in 0..10 {
            assert!(l.exited(Duration::from_millis(1), &failed()).is_none());
        }
    }

    #[test]
    fn a_run_past_the_window_resets_the_count() {
        let mut l = Liveness::default();
        assert!(l.exited(Duration::from_millis(1), &failed()).is_none());
        assert!(l.exited(Duration::from_millis(1), &failed()).is_none());
        assert!(l.exited(Duration::from_secs(6), &failed()).is_none());
        assert!(l.exited(Duration::from_millis(1), &failed()).is_none());
    }

    #[test]
    fn a_binary_that_cannot_be_spawned_says_so() {
        let mut l = Liveness::default();
        let missing: std::io::Result<ExitStatus> =
            Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(l.exited(Duration::ZERO, &missing).is_none());
        assert!(l.exited(Duration::ZERO, &missing).is_none());
        let reason = l.exited(Duration::ZERO, &missing).unwrap();
        assert!(reason.contains("could not be spawned"), "{reason}");
    }
}
