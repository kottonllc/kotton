// SPDX-License-Identifier: AGPL-3.0-or-later
//! How a `kotton` command that fails ends: with the message, as written, and
//! exit code 1.
//!
//! A refusal the daemon writes is written for a person — it names who, what is
//! missing, and the next step. The command line is where that person reads it,
//! so it reaches them as the daemon wrote it: one line on stderr, with no prefix
//! and nothing of the error type it travelled in. The exit code carries the
//! failure for a script; the words carry it for a person.
//!
//! Every subcommand ends through the same `main`, so one refused subcommand is
//! the whole of the claim. Clap's own usage errors are clap's, and exit 2.

use crate::common::cli::{said, Cli};
use crate::common::{TestEnv, TEST_PASSPHRASE};
use kotton::KottonClient;

const ALEX: &str = "alex";

/// Alex sends to Blair, whom Alex never paired with. The daemon refuses, and the
/// terminal says exactly that refusal and nothing else.
///
/// The refusal is taken from the daemon through the client first, so this holds
/// the CLI to passing the daemon's words on as they are, not to any wording.
#[tokio::test]
async fn a_refused_command_says_the_daemons_words_alone_and_exits_one() {
    let mut env = TestEnv::spawn_cli_reachable().await;
    env.client.create_user(ALEX, TEST_PASSPHRASE).await.expect("create alex");
    let token = env.client.session_token.clone().expect("create_user bound alex a session");
    let mut blair = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect");
    let (blair_did, _) = blair.create_user("blair", TEST_PASSPHRASE).await.expect("create blair");
    let cli = Cli::for_env(&env);
    cli.seed_session(ALEX, &token);

    let refusal = env
        .client
        .message_send_delivery(ALEX, &blair_did, "hello", None)
        .await
        .expect_err("blair is nobody alex holds a key for")
        .to_string();

    let refused = cli.run(&["message", "send", &blair_did, "hello", "--user", ALEX]);
    assert_eq!(refused.status.code(), Some(1), "a refused command exits 1.\n{}", said(&refused));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        format!("{refusal}\n"),
        "stderr is the daemon's refusal and nothing else.\n{}",
        said(&refused)
    );
}
