// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unit tests for the mock runner binary itself — no daemon required.
//!
//! These tests spawn `kotton-mock-runner` as a child process, write JSON
//! frames to its stdin, and read/validate JSON frames from its stdout.
//! They verify the runner wire protocol in isolation before the full
//! integration tests run.

use kotton_wire::{RunnerInput, RunnerMessage, RunnerOp, RunnerOutput};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Build a minimal [`RunnerInput`] with a Launch op.
fn launch_input() -> RunnerInput {
    RunnerInput {
        approved: Vec::new(),
        manifest_toml: "[app]\nid = \"sh.kotton.test\"\nname = \"Test\"\nversion = \"0.1.0\"\n"
            .to_string(),
        wasm_path: "/tmp/test.wasm".to_string(),
        app_data_path: "/tmp/test-data".to_string(),
        envelopes: vec![],
        revoked_ids: vec![],
        trusted_issuers: vec![],
        kel_keys: vec![],
        user_vfs_path: None,
        // No roots: `kotton:app/roots` is the occupant's alone (RFC-0071 R11).
        roots: None,
        occupant: false,
        op: RunnerOp::Launch {
            launch_args: vec![],
            // Every launch carries the surface the daemon minted for it
            // (RFC-0087). A fixture mints its own rather than taking a
            // parameter, because no assertion in this file is about *which*
            // surface — only that the protocol carries one.
            surface: kotton_wire::SurfaceHandle::mint(),
        },
    }
}

/// Build a minimal [`RunnerInput`] with a Message op.
fn message_input(msg: impl Into<String>) -> RunnerInput {
    RunnerInput {
        approved: Vec::new(),
        manifest_toml: "[app]\nid = \"sh.kotton.test\"\nname = \"Test\"\nversion = \"0.1.0\"\n"
            .to_string(),
        wasm_path: "/tmp/test.wasm".to_string(),
        app_data_path: "/tmp/test-data".to_string(),
        envelopes: vec![],
        revoked_ids: vec![],
        trusted_issuers: vec![],
        kel_keys: vec![],
        user_vfs_path: None,
        // No roots: `kotton:app/roots` is the occupant's alone (RFC-0071 R11).
        roots: None,
        occupant: false,
        op: RunnerOp::Message { msg: msg.into() },
    }
}

// ── one-shot mode ─────────────────────────────────────────────────────────────

/// Send a Launch frame, expect a `Launched` response.
#[test]
fn oneshot_launch_roundtrip() {
    let mut child = Command::new(crate::common::mock_runner_bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mock-runner");

    let input_json =
        serde_json::to_string(&launch_input()).expect("serialize") + "\n";
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input_json.as_bytes())
        .expect("write stdin");

    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).expect("read line");

    let output: RunnerOutput = serde_json::from_str(line.trim()).expect("deserialize output");
    assert!(
        matches!(output, RunnerOutput::Launched { .. }),
        "expected Launched, got {output:?}"
    );
    // No patches from a no-op launch in the mock runner — that's expected.
    if let RunnerOutput::Launched { patches, .. } = output {
        let _ = patches; // patches may be empty for the mock runner
    }

    child.wait().expect("wait for child");
}

/// Send a Message frame, expect a `MessageHandled` response.
#[test]
fn oneshot_message_roundtrip() {
    let mut child = Command::new(crate::common::mock_runner_bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mock-runner");

    let input_json =
        serde_json::to_string(&message_input(r#"{"type":"ping"}"#)).expect("serialize") + "\n";
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input_json.as_bytes())
        .expect("write stdin");

    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).expect("read line");

    let output: RunnerOutput = serde_json::from_str(line.trim()).expect("deserialize output");
    assert!(
        matches!(output, RunnerOutput::MessageHandled { .. }),
        "expected MessageHandled, got {output:?}"
    );
    if let RunnerOutput::MessageHandled { patches, .. } = output {
        // Mock runner encodes counter as a raw JSON patch.
        let has_counter = patches.iter().any(|p| {
            p.patch.first() == Some(&0x00)
                && std::str::from_utf8(&p.patch[1..]).is_ok_and(|s| s.contains("counter:"))
        });
        assert!(has_counter, "expected counter patch, got {patches:?}");
    }

    child.wait().expect("wait for child");
}

// ── long-lived mode ───────────────────────────────────────────────────────────

/// Send an init frame + 3 message frames; expect 4 response lines and
/// verify the counter increments across messages.
#[test]
fn long_lived_multi_message_roundtrip() {
    let mut child = Command::new(crate::common::mock_runner_bin())
        .arg("--long-lived")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mock-runner --long-lived");

    let mut stdin = child.stdin.take().unwrap();

    // Init frame (Launch op).
    let init = serde_json::to_string(&launch_input()).expect("serialize init") + "\n";
    stdin.write_all(init.as_bytes()).expect("write init");

    // 3 subsequent message frames.
    for n in 0..3 {
        let msg_frame = RunnerMessage {
            op: RunnerOp::Message {
                msg: format!(r#"{{"seq":{n}}}"#),
            },
        };
        let frame = serde_json::to_string(&msg_frame).expect("serialize frame") + "\n";
        stdin.write_all(frame.as_bytes()).expect("write message frame");
    }
    drop(stdin); // EOF triggers clean shutdown

    let reader = BufReader::new(child.stdout.take().unwrap());
    let responses: Vec<RunnerOutput> = reader
        .lines()
        .map(|l| {
            let line = l.expect("read line");
            serde_json::from_str(&line).expect("deserialize")
        })
        .collect();

    assert_eq!(responses.len(), 4, "expected init response + 3 message responses");

    // First response is for the Launch op.
    assert!(
        matches!(&responses[0], RunnerOutput::Launched { .. }),
        "first response should be Launched"
    );

    // Subsequent responses are MessageHandled with monotonic counters encoded as patches.
    let counters: Vec<u32> = responses[1..]
        .iter()
        .map(|r| match r {
            RunnerOutput::MessageHandled { patches, .. } => {
                let counter_patch = patches.iter().find(|p| {
                    p.patch.first() == Some(&0x00)
                && std::str::from_utf8(&p.patch[1..]).is_ok_and(|s| s.contains("counter:"))
                }).expect("counter patch missing");
                let s = std::str::from_utf8(&counter_patch.patch[1..]).unwrap();
                // Format is JSON string: "counter:N"
                let inner = s.trim_matches('"');
                inner.strip_prefix("counter:").unwrap().parse().expect("parse counter")
            }
            other => panic!("expected MessageHandled, got {other:?}"),
        })
        .collect();

    assert!(
        counters.windows(2).all(|w| w[1] == w[0] + 1),
        "counters should be monotonically increasing: {counters:?}"
    );

    child.wait().expect("wait for child");
}

/// Close stdin; the long-lived runner should exit with code 0.
#[test]
fn long_lived_eof_exits_cleanly() {
    let mut child = Command::new(crate::common::mock_runner_bin())
        .arg("--long-lived")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mock-runner --long-lived");

    // Drop stdin immediately → runner sees EOF without any init frame.
    drop(child.stdin.take());

    let status = child.wait().expect("wait for child");
    assert!(status.success(), "runner should exit 0 on EOF, got: {status:?}");
}
