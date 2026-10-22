// SPDX-License-Identifier: AGPL-3.0-or-later
//! The inference sidecar, end to end: a real process on a real pipe (RFC-0085).
//!
//! What this proves that the unit tests do not: `supervise_kinferd` — the
//! function the daemon calls at boot — spawns the real `kinferd` binary, hands
//! it two pipes made by that spawn, attaches the daemon's end, and carries a
//! whole generation across and back.
//!
//! The unit tests either side of this one drive the same code over
//! `tokio::io::duplex`, which proves the framing and proves nothing about the
//! process. That distinction is the reason this file exists: RFC-0085's criterion
//! is *"reached only over a pipe the daemon handed it, never a named socket"*,
//! and a pipe the daemon handed it is a claim about a spawn.
//!
//! It is also where IN1 is measured instead of asserted: the child's own
//! `/proc/<pid>/environ` is read through the pid the supervisor recorded, so
//! "spawned with no environment" is checked against the kernel rather than
//! against the spawn builder three lines above it.
//!
//! It is also where the sidecar stops being unreachable. Before
//! `kotton config inference set on` existed, `inference.enabled` had a reader
//! and no writer, so nothing in the product could start this process and nothing
//! in the suite ran it — the code was live and unreached at once.

use kotton_infer::{
    Context, Licence, ModelFormat, ModelKind, ModelManifest, Options, Origin, Passage, Provenance,
    FIXTURE,
};
use kuserd::agent::{supervise_kinferd, SidecarState};
use kuserd::infer_proxy::InferProxy;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Path to the compiled `kinferd`, or a failure that names every binary the suite
/// runs that is not built: `kinferd` is bin-only, so it cannot be a dev-dependency,
/// and `common::bins` checks it with the rest.
fn kinferd_bin() -> &'static str {
    crate::common::bins::require(crate::common::bins::Bin::Kinferd)
        .to_str()
        .expect("build.rs emits a UTF-8 path")
}

fn manifest() -> ModelManifest {
    ModelManifest {
        name: "fixture".to_string(),
        version: "0".to_string(),
        weights: "0000".to_string(),
        format: ModelFormat::Gguf,
        kind: ModelKind::Chat,
        parameters: 0,
        quantisation: "none".to_string(),
        size: FIXTURE.len() as u64,
        context_window: 4096,
        template: "{question}".to_string(),
        licence: Licence {
            spdx: "Apache-2.0".to_string(),
            text_hash: "0000".to_string(),
        },
        publisher: None,
    }
}

fn context() -> Context {
    Context {
        question: "when was the boiler serviced?".to_string(),
        passages: vec![Passage {
            reference: "record://kotton/msg/1".to_string(),
            provenance: Provenance {
                origin: Origin::Import,
                from: None,
                at: "2026-09-15T09:00:00Z".to_string(),
            },
            text: "the boiler was serviced in March".to_string(),
        }],
        template: "{question}".to_string(),
    }
}

/// The daemon spawns the runtime, and a question crosses the pipe that spawn
/// made.
#[tokio::test]
async fn the_supervisor_spawns_kinferd_and_a_generation_crosses_the_handed_pipe() {
    let bin = std::path::PathBuf::from(kinferd_bin());
    let states: Arc<RwLock<HashMap<String, SidecarState>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let proxy = Arc::new(InferProxy::new());

    let supervisor = tokio::spawn(supervise_kinferd(
        bin,
        Arc::clone(&states),
        Arc::clone(&proxy),
    ));

    // The supervisor attaches before it awaits the child, so this is a short
    // wait on a spawn rather than on a handshake. Polled rather than slept
    // through: a fixed sleep is either too short on a loaded machine or wasted
    // on an idle one.
    let mut waited = Duration::ZERO;
    while !proxy.is_attached().await && waited < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += Duration::from_millis(20);
    }
    assert!(
        proxy.is_attached().await,
        "the supervisor did not attach a channel within 10s"
    );

    // The supervisor's own bookkeeping: a pid means a process, which is the
    // half of "handed it at spawn" that a duplex cannot show.
    let pid = {
        let guard = states.read().unwrap();
        let state = guard.get("kinferd").expect("the supervisor recorded kinferd");
        assert!(state.running, "kinferd should be recorded as running");
        state.pid.expect("a spawned child has a pid")
    };
    assert!(pid > 0);

    // IN1, measured on the real child rather than read off the spawn: the
    // process the daemon started holds no environment at all.
    //
    // `/proc/<pid>/environ` is what `execve` was handed, so this is the kernel's
    // answer, not the supervisor's. Nothing was added to `kinferd` to make this
    // observable — a `--dump-env` flag or an echo frame would be a production
    // affordance existing only for a test, and the thing it proved would then be
    // the affordance. The daemon already records the pid; /proc already has the
    // answer.
    //
    // The comparison is the point. `environ` being empty means little on its own
    // (an unreadable file is empty too), so the test first shows that this
    // process — the parent the child would have inherited from — has a
    // substantial environment of its own.
    #[cfg(target_os = "linux")]
    {
        let parent_vars = std::env::vars().count();
        assert!(
            parent_vars > 0,
            "the test process has no environment, so inheriting nothing proves nothing"
        );

        let environ = std::fs::read(format!("/proc/{pid}/environ"))
            .expect("the child is alive and ours, so its environ is readable");
        let entries: Vec<&[u8]> = environ
            .split(|b| *b == 0)
            .filter(|e| !e.is_empty())
            .collect();
        assert!(
            entries.is_empty(),
            "kinferd inherited {} variable(s) from a parent holding {}: {:?}\n\
             `supervise_kinferd` must call `.env_clear()` (RFC-0085, IN1)",
            entries.len(),
            parent_vars,
            entries
                .iter()
                .map(|e| String::from_utf8_lossy(e).split('=').next().unwrap_or("").to_string())
                .collect::<Vec<_>>()
        );
    }

    let handle = proxy
        .load(&manifest(), FIXTURE.as_bytes())
        .await
        .expect("the runtime loads the fixture weights");

    let mut answer = String::new();
    let metering = proxy
        .generate(handle, &context(), &Options::default(), |t| {
            answer.push_str(t)
        })
        .await
        .expect("the runtime answers");

    assert_eq!(
        answer,
        "You asked: when was the boiler serviced? The passages say so. [1]",
        "the question and the host's labels did not survive the pipe"
    );
    assert_eq!(metering.tokens, 12);

    // The citation the answer carries is one the host issued, so it resolves
    // (IN6). A `[2]` would not, and nothing in this stream could have produced
    // one that did.
    assert_eq!(
        context()
            .passage_for_label("[1]")
            .map(|p| p.reference.clone()),
        Some("record://kotton/msg/1".to_string())
    );

    // Leave no process behind. Aborting the supervisor drops the daemon's end of
    // the pipe, and `kinferd` exits on the close — which is the shutdown path
    // the daemon itself uses, so this is the real one rather than a kill.
    supervisor.abort();
    proxy.detach().await;
}

// -- A refused frame is not a clean exit --------------------------------------
//
// `TASK-a-refused-frame-reads-as-a-clean-exit`. These drive the built binary
// over real pipes with inputs no test had sent, which is how the defect was
// found in the first place: an undecodable frame, and a length header over the
// frame ceiling, both made `kinferd` log *"the handed pipe closed"* and **exit
// 0** — so `supervise_kinferd` read a clean stop, ended supervision, and
// recorded nothing.

/// Spawn the real `kinferd` as the daemon does, with pipes for all three
/// standard streams and no environment.
///
/// `.env_clear()` matches `supervise_kinferd` and is not decoration here: it
/// pins the log filter to the sidecar's own default, so a `RUST_LOG` the
/// harness happens to export cannot decide whether this test can see the line
/// it is asserting on.
fn spawn_kinferd() -> tokio::process::Child {
    tokio::process::Command::new(kinferd_bin())
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("kinferd spawns")
}

/// Write `bytes` to the child's stdin, then read its exit status and stderr.
async fn say_and_wait(mut child: tokio::process::Child, bytes: &[u8]) -> (Option<i32>, String) {
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        // A refusal can kill the child before the write completes, and that is
        // the runtime doing its job rather than a test failure.
        let _ = stdin.write_all(bytes).await;
        let _ = stdin.flush().await;
    }
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut said = String::new();
    let read = tokio::time::timeout(
        Duration::from_secs(10),
        stderr.read_to_string(&mut said),
    )
    .await
    .expect("kinferd should close its stderr when it exits");
    read.expect("stderr is readable");

    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("kinferd should exit rather than wait for more")
        .expect("waited on");
    (status.code(), said)
}

/// An undecodable frame ends the real process with a non-zero status and the
/// reason on stderr.
///
/// The body here is well-formed JSON and well-formed framing, and simply not an
/// `InferRequest` — the shape a stray line from a future backend would have.
#[tokio::test]
async fn an_undecodable_frame_exits_kinferd_non_zero_with_the_reason_on_stderr() {
    let junk = br#"{"NotAVariant":{}}"#;
    let mut framed = (junk.len() as u32).to_le_bytes().to_vec();
    framed.extend_from_slice(junk);

    let (code, said) = say_and_wait(spawn_kinferd(), &framed).await;

    assert_eq!(
        code,
        Some(2),
        "a refused frame must not exit 0 — that is what a supervisor reads as \
         'it was asked to stop'. stderr said: {said}"
    );
    assert!(
        said.contains("undecodable"),
        "the reason has to be on stderr, because that is all the supervisor can \
         record: {said}"
    );
}

/// A 33 MiB length header, and nothing behind it, does the same — and does it
/// on four bytes, before anything is allocated for a body that never comes.
#[tokio::test]
async fn a_33_mib_length_header_exits_kinferd_non_zero_with_the_reason_on_stderr() {
    let over = 33 * 1024 * 1024u32;
    assert!(
        over as usize > kotton_ipc::MAX_FRAME_LEN,
        "this test's header must be over the cap it is testing"
    );

    let (code, said) = say_and_wait(spawn_kinferd(), &over.to_le_bytes()).await;

    assert_eq!(
        code,
        Some(2),
        "an over-cap length header must not exit 0. stderr said: {said}"
    );
    assert!(
        said.contains("34603008"),
        "the reason has to name what it read: {said}"
    );
}

/// And the supervisor **records** it: a refusal reaches `SidecarState.failed`
/// naming the cause, where before it reached nothing at all.
///
/// The bad frame is sent down a production path rather than injected. Nothing
/// the daemon can say is undecodable to the runtime — both ends share one
/// type — so the reachable refusal is the other one: a frame whose serialised
/// length is over the ceiling. `write_frame` does not enforce the cap that
/// `read_frame` does, so an over-sized request really does leave this process
/// and really is refused by that one.
///
/// Injecting the undecodable frame instead would mean a way into the child's
/// stdin that is not `InferProxy`, and the daemon holding the only other end is
/// the whole security property (RFC-0085 IN1). The two tests above drive that
/// half against the real binary; this one is about what the supervisor knows.
#[tokio::test]
async fn the_supervisor_records_a_refusal_as_a_failure_naming_the_cause() {
    let bin = std::path::PathBuf::from(kinferd_bin());
    let states: Arc<RwLock<HashMap<String, SidecarState>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let proxy = Arc::new(InferProxy::new());

    let supervisor = tokio::spawn(supervise_kinferd(
        bin,
        Arc::clone(&states),
        Arc::clone(&proxy),
    ));

    let mut waited = Duration::ZERO;
    while !proxy.is_attached().await && waited < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += Duration::from_millis(20);
    }
    assert!(
        proxy.is_attached().await,
        "the supervisor did not attach a channel within 10s"
    );

    // Nothing here is a test hook: this is `embed`, with a text longer than one
    // frame may carry.
    let enormous = "a".repeat(kotton_ipc::MAX_FRAME_LEN + 2 * 1024 * 1024);
    proxy
        .embed(kotton_infer::ModelHandle(1), &enormous)
        .await
        .expect_err("a frame over the ceiling cannot be answered");

    // The supervisor restarts the runtime after this, with backoff — the
    // failure is recorded, not swallowed by the restart.
    let mut waited = Duration::ZERO;
    let reason = loop {
        if let Some(reason) = states
            .read()
            .unwrap()
            .get("kinferd")
            .and_then(|s| s.failed.clone())
        {
            break reason;
        }
        assert!(
            waited < Duration::from_secs(20),
            "the supervisor recorded no failure for a runtime that refused a frame — \
             which is the defect `TASK-a-refused-frame-reads-as-a-clean-exit` names"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    };

    assert!(
        reason.contains("refused frame"),
        "the recorded failure must say a frame was refused: {reason}"
    );
    assert!(
        reason.contains("exceeds"),
        "and must name the cause rather than only the exit code: {reason}"
    );

    supervisor.abort();
    proxy.detach().await;
}

/// **The other direction, and the one a compromised runtime controls.** The
/// daemon refuses a frame the runtime sent, and the supervisor records a failure
/// instead of reading the child's exit as a shutdown.
///
/// This is the half of `TASK-a-refused-frame-reads-as-a-clean-exit` that a
/// first pass at the record left open, and it is the half its `Security:` marker
/// is about. Refusing drops the daemon's end of the pair, which closes the
/// child's stdin, so the child reads end-of-stream and exits **0** — the one
/// status that means *I was asked to stop*. Read on its own it sent supervision
/// home with `failed` still `None`, and a parser made to emit one bad frame had
/// ended inference for the daemon's lifetime, unreported and unrestarted.
///
/// **Nothing is injected.** The bad frame is made the way RFC-0085 IN1 says the
/// danger arrives — out of the weights. `StubBackend`'s fixture *is* the bytes
/// it was loaded with, and `generate` substitutes the question into it, so
/// weights that name `{question}` ten times turn a 4 MiB question into a 40 MiB
/// answer. With no whitespace in it that answer is one token, so it is one frame
/// over the 32 MiB ceiling: the request is well inside the cap, and the reply is
/// not. A real backend will not amplify like this one, but "a weights file
/// decides what the runtime says" is the property that made it untrusted input
/// in the first place.
#[tokio::test]
async fn a_frame_the_daemon_refuses_is_a_failure_not_a_shutdown() {
    let bin = std::path::PathBuf::from(kinferd_bin());
    let states: Arc<RwLock<HashMap<String, SidecarState>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let proxy = Arc::new(InferProxy::new());

    let supervisor = tokio::spawn(supervise_kinferd(
        bin,
        Arc::clone(&states),
        Arc::clone(&proxy),
    ));

    let mut waited = Duration::ZERO;
    while !proxy.is_attached().await && waited < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += Duration::from_millis(20);
    }
    assert!(
        proxy.is_attached().await,
        "the supervisor did not attach a channel within 10s"
    );

    // Weights that repeat the substitution. Ordinary bytes on an ordinary load.
    let amplifying = "{question}".repeat(10);
    let mut manifest = manifest();
    manifest.size = amplifying.len() as u64;
    let handle = proxy
        .load(&manifest, amplifying.as_bytes())
        .await
        .expect("the runtime loads these weights like any others");

    // A question with no whitespace, so the answer comes back as one token and
    // therefore one frame.
    let mut question = context();
    question.question = "a".repeat(4 * 1024 * 1024);
    let err = proxy
        .generate(handle, &question, &Options::default(), |_| {})
        .await
        .expect_err("a reply over the frame ceiling cannot be read");
    assert!(
        err.to_string().contains("refused frame"),
        "the daemon's own error should name the refusal: {err}"
    );

    // And the supervisor knows. Polled, because the child's exit and the
    // supervisor's bookkeeping happen after our error returns.
    let mut waited = Duration::ZERO;
    let reason = loop {
        if let Some(reason) = states
            .read()
            .unwrap()
            .get("kinferd")
            .and_then(|s| s.failed.clone())
        {
            break reason;
        }
        assert!(
            waited < Duration::from_secs(20),
            "the runtime sent a frame this end refused, the child exited 0 on the \
             closed pipe, and the supervisor recorded nothing — which is \
             `TASK-a-refused-frame-reads-as-a-clean-exit` verbatim, in the \
             direction a compromised parser controls"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    };

    assert!(
        reason.contains("this end refused what it sent"),
        "the failure must say the daemon refused, not merely that the child left: {reason}"
    );
    assert!(
        reason.contains("exceeds"),
        "and must name the cause: {reason}"
    );

    supervisor.abort();
    proxy.detach().await;
}
