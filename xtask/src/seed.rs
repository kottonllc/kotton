// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask seed` — populate a running daemon with a plausible household.
//!
//! For demos, for looking at a UI that isn't empty, and — the reason it earns
//! its keep — because **verifying sync between two empty stores proves almost
//! nothing.** A convergence test needs a corpus with volume, threads, and
//! conflicts before it means anything.
//!
//! # Two constraints, both load-bearing
//!
//! **It seeds through the front door.** Every action here shells out to the real
//! `kotton` CLI, exactly as a person would. Nothing writes storage directly.
//! This is stricter than "use the public API" and deliberately so: if the seeder
//! can produce a state, a user can produce it too, so a demo cannot pass on a
//! state the product could never reach. When seeding fails because a command
//! doesn't exist yet, that is the seeder reporting a real gap rather than
//! papering over it.
//!
//! **It is deterministic.** No clocks, no RNG — the household is a fixed script.
//! Same invocation, same state, so a demo is repeatable and a bug found while
//! demoing is reproducible. (A future `--scale n` would repeat the script, not
//! randomise it.)
//!
//! # What it does not do
//!
//! Seed anything the product cannot yet do. Contacts have no CLI verb today, so
//! the household members are not yet linked as contacts, and messaging is
//! therefore self-addressed. That gap is reported at the end rather than hidden
//! behind a direct database write.
//!
//! # What it found on its first run (2026-08-11)
//!
//! Both are the seeder earning its keep — neither is visible from the test
//! suite, because both live on the CLI path rather than the IPC path the
//! integration tests drive.
//!
//! 1. **No CLI verb grants a channel key to another member.** A channel's
//!    creator can post; nobody else can, so a household conversation is not yet
//!    expressible. Reported by the run, not worked around.
//!
//! 2. **Every `--user` command hung forever once the session cache went stale.**
//!    No output, no error, no timeout. It looked like a VFS deadlock — `vfs
//!    ls`/`read`/`write` all hung while `kotton id list` returned fine — but
//!    that split was the tell: `id list` calls `KottonClient::connect()`, and
//!    everything user-scoped calls `connect_as()`, which fell through to an
//!    interactive `rpassword` prompt for the recovery key. With no terminal, it
//!    waited on input that could never arrive.
//!
//!    Sessions live in the daemon's memory, so **every daemon restart** lands
//!    there; `connect_as` then clears the stale cache, so the next run has
//!    nothing to fall back on either. Fixed at the source in
//!    `client/kotton-client/src/connect.rs`: with no terminal it now says which
//!    identity has no session and to run `kotton login <user>`.
//!
//!    The seeder is why this was found at all — it is the first thing to drive
//!    the CLI non-interactively at length. The remaining gap is real and not
//!    yet closed: **there is no non-interactive way to establish a session**,
//!    so seeding still needs a human to log in first. Worth solving properly
//!    rather than by putting a recovery key in an environment variable — that
//!    key is the safety-deposit-box key, not a daily credential.

use std::path::Path;
use std::process::Command;

/// One household member: the identity, and the files they keep.
struct Person {
    user: &'static str,
    files: &'static [(&'static str, &'static str)],
}

/// A fixed household. Ordinary domestic content on purpose — a demo lands when
/// the data looks like a life rather than like `lorem ipsum` — and obviously
/// synthetic, so nothing here could be mistaken for a real person's records.
const HOUSEHOLD: &[Person] = &[
    Person {
        user: "avery",
        files: &[
            ("home/notes/groceries.md", "# Groceries\n\n- milk\n- eggs\n- coffee\n"),
            (
                "home/notes/house.md",
                "# House\n\nBoiler serviced March. Next due next spring.\nSpare key is with the neighbour.\n",
            ),
            (
                "home/documents/broadband.md",
                "Contract ends in November. Cancel before renewal or it rolls over.\n",
            ),
        ],
    },
    Person {
        user: "sam",
        files: &[
            (
                "home/notes/school.md",
                "# School\n\nParents evening on the 14th.\nPE kit on Tuesdays and Thursdays.\n",
            ),
            (
                "home/notes/recipes.md",
                "# Recipes\n\n## Sunday roast\nPotatoes in at 180 for an hour.\n",
            ),
        ],
    },
];

const CHANNEL: &str = "household";
const CHANNEL_MESSAGES: &[(&str, &str)] = &[
    ("avery", "boiler engineer coming thursday morning"),
    ("sam", "noted — I'll be back by four"),
    ("avery", "can you grab coffee on the way?"),
];

// ── Corpus at scale ───────────────────────────────────────────────────────────

/// Weeks of calendar generated per `--years`, and how many events land in each.
///
/// Six a week is an ordinary person's calendar — a couple of work commitments, a
/// recurring thing, an appointment, something social. Dense enough that a year is
/// a few hundred records and three years is a corpus; sparse enough that it still
/// reads like a life rather than a stress test.
const EVENTS_PER_WEEK: u32 = 6;

/// The first year a needle can land in. Needle `i` belongs to `NEEDLE_BASE_YEAR + i`,
/// which is what keeps each unique across a corpus assembled one year at a time.
const NEEDLE_BASE_YEAR: u32 = 2023;

/// The distractor vocabulary. Fixed arrays rather than an RNG, because the
/// seeder's second constraint is determinism: same invocation, same corpus, so a
/// retrieval result that changes means the *code* changed.
const PEOPLE: &[&str] = &[
    "R. Delaney",
    "P. Okafor",
    "Mrs Whitlock",
    "Jan",
    "the Hargreaves",
    "Dr Adeyemi",
    "Tomas",
    "Nadia",
    "the Brook Street team",
    "Ellis",
];
const PLACES: &[&str] = &[
    "the Brook Street unit",
    "the surgery",
    "St Aidan's hall",
    "the depot",
    "home",
    "the Tuesday Club",
    "Meridian House",
    "the allotment",
];
const SUBJECTS: &[&str] = &[
    "site walk",
    "handover",
    "review",
    "catch-up",
    "delivery window",
    "parents evening",
    "check-up",
    "committee",
    "practice",
    "inspection",
];

/// Events whose content exists **once** in the whole corpus.
///
/// **This is what makes retrieval testable and it is the reason this function is
/// not just a loop.** A corpus of ten thousand plausible-but-interchangeable
/// records cannot tell a good retriever from a bad one: everything matches
/// everything, so precision has nothing to be wrong about. A needle is a record
/// whose distinguishing terms appear nowhere else, so a question about it has
/// exactly one right answer and a retriever that returns something else has
/// measurably failed.
///
/// Kept obviously synthetic, and deliberately boring: a demo lands when the data
/// looks like a life, and nothing here could be mistaken for a real person's.
const NEEDLES: &[(&str, &str, &str)] = &[
    (
        "Harding Supply — invoice INV-2291 settled",
        "Harding Supply, invoice INV-2291, 4,820 GBP, marked paid on the 9th. \
Covers the replacement units and the freight; nothing further owed.",
        "the depot",
    ),
    (
        "Boiler service — Kesgrave Heating, badge 4417",
        "Annual service by Kesgrave Heating, engineer badge 4417. Next due the \
following spring. Filter replaced, pressure reset to 1.4 bar.",
        "home",
    ),
    (
        "Passport renewal — reference PX-70318",
        "Renewal submitted under reference PX-70318. Photos accepted; the old \
document returns separately.",
        "Meridian House",
    ),
];

/// One iCalendar export covering `years` of a person's life.
///
/// Through the front door like everything else here: this is handed to
/// `kotton import`, which is the same path a person's real export takes, rather
/// than written into the store. If the importer cannot take it, that is a finding
/// and not a reason to reach around.
fn generate_ics(years: u32, start_year: u32) -> String {
    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Kotton Seed//EN\r\nCALSCALE:GREGORIAN\r\n",
    );

    let weeks = years * 52;

    // Which needle, if any, belongs to *this* year, and at which week.
    //
    // **Keyed on the absolute year, because the corpus is assembled a year at a
    // time.** `seed_calendar` calls this once per year and imports each
    // separately, so a needle placed by position-within-the-call would be emitted
    // again in every year — which is exactly what happened: a three-year corpus
    // carried three copies of each needle, and a question about one had three
    // right answers instead of one. Found by a retrieval run reporting rank 3
    // with the correct record at rank 1.
    //
    // Needle `i` belongs to year `NEEDLE_BASE_YEAR + i`, so each appears exactly
    // once however the years are assembled, and they stay spread across the range.
    let mine: Vec<(u32, usize)> = (0..NEEDLES.len())
        .filter(|i| start_year == NEEDLE_BASE_YEAR + *i as u32)
        .map(|i| ((weeks / 2).max(1), i))
        .collect();

    let mut n: u32 = 0;
    for week in 0..weeks {
        if let Some((_, i)) = mine.iter().find(|(w, _)| *w == week).copied() {
            let (summary, description, place) = NEEDLES[i];
            let year = start_year + week / 52;
            let (month, dom) = day_of_year_to_date((week % 52) * 7 + 3);
            out.push_str("BEGIN:VEVENT\r\n");
            out.push_str(&format!(
                "UID:seed-needle-{start_year}-{i}@kotton.example\r\n"
            ));
            out.push_str(&format!("DTSTAMP:{year}{month:02}{dom:02}T080000Z\r\n"));
            out.push_str(&format!("DTSTART:{year}{month:02}{dom:02}T110000Z\r\n"));
            out.push_str(&format!("DTEND:{year}{month:02}{dom:02}T120000Z\r\n"));
            out.push_str(&format!("SUMMARY:{summary}\r\n"));
            out.push_str(&format!("LOCATION:{place}\r\n"));
            out.push_str(&format!("DESCRIPTION:{description}\r\n"));
            out.push_str("END:VEVENT\r\n");
        }
        for slot in 0..EVENTS_PER_WEEK {
            // Everything below is arithmetic on the index. No clock, no RNG.
            let day = (slot * 5 / EVENTS_PER_WEEK) + 1;
            let hour = 9 + (slot * 3) % 9;
            let year = start_year + week / 52;
            let doy = (week % 52) * 7 + day;
            let (month, dom) = day_of_year_to_date(doy);
            let subject = SUBJECTS[(n as usize) % SUBJECTS.len()];
            let who = PEOPLE[(n as usize * 3) % PEOPLE.len()];
            let place = PLACES[(n as usize * 5) % PLACES.len()];

            out.push_str("BEGIN:VEVENT\r\n");
            out.push_str(&format!("UID:seed-{start_year}-{n}@kotton.example\r\n"));
            out.push_str(&format!("DTSTAMP:{year}{month:02}{dom:02}T080000Z\r\n"));
            out.push_str(&format!(
                "DTSTART:{year}{month:02}{dom:02}T{hour:02}0000Z\r\n"
            ));
            out.push_str(&format!(
                "DTEND:{year}{month:02}{dom:02}T{:02}0000Z\r\n",
                hour + 1
            ));
            out.push_str(&format!("SUMMARY:{subject} with {who}\r\n"));
            out.push_str(&format!("LOCATION:{place}\r\n"));
            out.push_str(&format!(
                "DESCRIPTION:{subject} with {who} at {place}. Week {week} of the seeded corpus.\r\n"
            ));
            out.push_str("END:VEVENT\r\n");
            n += 1;
        }
    }

    out.push_str("END:VCALENDAR\r\n");
    out
}

/// Day-of-year to (month, day), on a non-leap year.
///
/// A fixed table rather than a date library: the seeder has no dependencies on
/// purpose, and a corpus that shifts because a crate changed its rounding is a
/// corpus that cannot be compared with last week's.
fn day_of_year_to_date(doy: u32) -> (u32, u32) {
    const LENGTHS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut left = doy.clamp(1, 365);
    for (i, len) in LENGTHS.iter().enumerate() {
        if left <= *len {
            return (i as u32 + 1, left);
        }
        left -= len;
    }
    (12, 31)
}

/// Deterministic message bodies, in the same household voice as the fixed script.
fn generated_message(i: u32) -> String {
    let who = PEOPLE[(i as usize * 7) % PEOPLE.len()];
    let place = PLACES[(i as usize * 11) % PLACES.len()];
    let subject = SUBJECTS[(i as usize * 13) % SUBJECTS.len()];
    format!("{subject} with {who} at {place} — message {i} of the seeded corpus")
}

/// `cargo xtask seed [--years N] [--messages N]`
///
/// With neither flag this is the original fixed household — two people, their
/// files, and a three-line conversation. That is a **demo** corpus: enough to look
/// at a UI that is not empty, and the header above says why it earns its keep.
///
/// It is not enough to test anything about *retrieval*, which is what the flags
/// are for. Over three records, retrieval is the identity function: precision,
/// ranking and the index all report success on a corpus where failure is not
/// possible. `DEC-0071` rules that the product **is** the corpus with an assistant
/// over it, so the thing the product is has been going untested.
///
/// Both constraints still hold. `--years` generates an iCalendar export and hands
/// it to the real `kotton import`; `--messages` sends through `message channel
/// send`. Nothing writes storage directly, and nothing uses a clock or an RNG.
pub fn run(workspace_root: &Path, args: &[String]) {
    let years = flag(args, "--years").unwrap_or(0);
    let messages = flag(args, "--messages").unwrap_or(0);

    // `--dump-ics <path>` writes the generated calendar and stops. No daemon, no
    // identities: it exists so a tool that measures something *over* the corpus —
    // an index, a retrieval run — can have the same bytes the seeder would import,
    // without standing up a node first. One generator, two consumers.
    if let Some(i) = args.iter().position(|a| a == "--dump-ics") {
        let path = args.get(i + 1).map(String::as_str).unwrap_or("corpus.ics");
        let y = years.max(1);
        let mut all = String::new();
        for year in 0..y {
            all.push_str(&generate_ics(1, 2023 + year));
        }
        match std::fs::write(path, &all) {
            Ok(()) => println!(
                "[seed] wrote {} event(s) over {y} year(s) to {path} ({} KiB)",
                all.matches("BEGIN:VEVENT").count(),
                all.len() / 1024
            ),
            Err(e) => eprintln!("[seed] could not write {path}: {e}"),
        }
        return;
    }
    let kotton = super::bin_path("kotton");
    if !kotton.exists() {
        eprintln!(
            "[seed] {} not built — run `cargo build` first",
            kotton.display()
        );
        std::process::exit(1);
    }

    println!("[seed] seeding a household through the real CLI");
    let mut gaps: Vec<String> = Vec::new();

    for person in HOUSEHOLD {
        println!("[seed] {}", person.user);
        // **Through a pseudo-terminal, because `id create` reads its passphrase
        // from the console device rather than stdin.** That is deliberate — a
        // credential must not reach a shell's history — and a pipe does not
        // satisfy it: with no terminal the command fails with `No such device or
        // address`. A terminal is what a person has, so driving one is the
        // front-door rule honoured rather than worked around.
        //
        // Until 2026-09-16 this was a plain `step`, which meant it failed on
        // every machine without a terminal, and failed *silently* because the
        // call tolerated it — so a seeding run on a fresh device reported gaps
        // that were all downstream of a first step nobody saw fail.
        if !create_identity(&kotton, workspace_root, person.user) {
            gaps.push(format!(
                "could not create the identity '{}' — `kotton id create` did not complete at a \
                 terminal",
                person.user
            ));
            // Everything below needs this identity, and a run that continues
            // reports failures whose cause is three steps back.
            continue;
        }

        for (path, contents) in person.files {
            if !step(
                &kotton,
                workspace_root,
                &["vfs", "write", "--user", person.user, path, contents],
                false,
            ) {
                gaps.push(format!("could not write {path} for {}", person.user));
            }
        }
    }

    // The household channel. Only the creator holds its key until contacts and
    // key-granting have CLI verbs, so the others' lines are seeded as their own
    // channels rather than faked into one they cannot actually read.
    let owner = HOUSEHOLD[0].user;
    println!("[seed] channel '{CHANNEL}' (owner {owner})");
    step(
        &kotton,
        workspace_root,
        &["message", "channel", "new", CHANNEL, "--user", owner],
        true,
    );

    for (who, body) in CHANNEL_MESSAGES {
        let sent = step(
            &kotton,
            workspace_root,
            &["message", "channel", "send", CHANNEL, body, "--user", who],
            true,
        );
        if !sent && *who != owner {
            gaps.push(format!(
                "{who} could not post to '{CHANNEL}' — no CLI verb grants a channel key to \
                 another member yet"
            ));
        }
    }

    if years > 0 {
        seed_calendar(&kotton, workspace_root, years, &mut gaps);
    }
    if messages > 0 {
        seed_messages(&kotton, workspace_root, owner, messages, &mut gaps);
    }

    println!("\n[seed] done.");
    if gaps.is_empty() {
        return;
    }
    // Report rather than hide: each line is a product gap the seeder ran into,
    // and the seeder refusing to reach around it is the point.
    println!("[seed] {} thing(s) the product cannot do yet:", gaps.len());
    let mut seen = std::collections::BTreeSet::new();
    for gap in gaps {
        if seen.insert(gap.clone()) {
            println!("  - {gap}");
        }
    }
    println!(
        "[seed] these are reported, not worked around — the seeder only uses the same commands \
         a person has."
    );
}

/// Create one identity at a pseudo-terminal, or report that it could not be.
///
/// Idempotent: an identity that already exists makes `id create` refuse, which is
/// success for the seeder's purposes and is why the existing-identity case is
/// checked rather than inferred from the exit status.
///
/// The passphrase is derived from the username so a re-run produces the same one,
/// which is the seeder's determinism rule applied to a credential. These are
/// throwaway development identities in a throwaway base directory; the rule that
/// a real credential never reaches a script still holds, because nothing here is
/// a real credential.
fn create_identity(kotton: &Path, cwd: &Path, user: &str) -> bool {
    // Already there: a re-run tops up rather than failing.
    let listed = Command::new(kotton)
        .args(["id", "list"])
        .current_dir(cwd)
        .output();
    if let Ok(o) = listed {
        if String::from_utf8_lossy(&o.stdout).contains(user) {
            return true;
        }
    }

    let phrase = format!("seed-{user}-canyon-orbit-velvet");
    // **Absolute, because the child's environment is cleared and it does not
    // inherit this process's working directory.** A relative `KOTTON_BASE_DIR`
    // resolves against wherever the child happens to start, which is how a
    // correct terminal drive still failed with `NotFound("connect")` — it was
    // looking for the daemon's socket under a path that did not exist.
    let base = std::env::var("KOTTON_BASE_DIR").unwrap_or_else(|_| ".kotton".to_string());
    let base = std::fs::canonicalize(&base)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or(base);
    let mut envs: Vec<(&str, &str)> = vec![("KOTTON_BASE_DIR", &base)];
    let ipc = std::env::var("KUSERD_IPC_NAME").unwrap_or_default();
    if !ipc.is_empty() {
        envs.push(("KUSERD_IPC_NAME", &ipc));
    }

    // Two answers: the passphrase, and the confirmation a person types.
    let t = kotton_pty_drive::run_on_a_terminal(
        kotton,
        &["id", "create", user],
        &envs,
        &[&phrase, &phrase],
        std::time::Duration::from_secs(60),
    );
    if !t.ok {
        eprintln!(
            "[seed] `kotton id create {user}` did not complete:\n{}",
            t.text
        );
    }
    t.ok
}

/// Run one CLI step. Returns whether it succeeded.
///
/// `tolerate` marks steps that legitimately fail on a re-run (creating an
/// identity that already exists), so the seeder stays idempotent.
fn step(kotton: &Path, cwd: &Path, args: &[&str], tolerate: bool) -> bool {
    let out = Command::new(kotton).args(args).current_dir(cwd).output();
    match out {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            if !tolerate {
                eprintln!(
                    "[seed] `kotton {}` failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            false
        }
        Err(e) => {
            eprintln!("[seed] could not run `kotton {}`: {e}", args.join(" "));
            false
        }
    }
}

/// Read `--flag <n>`, absent meaning zero.
fn flag(args: &[String], name: &str) -> Option<u32> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1)?.parse().ok()
}

/// Generate a calendar and bring it in the way a person brings theirs.
///
/// **One import call, thousands of records.** `kotton import` takes the file's
/// bytes in a single IPC frame and the CLI refuses anything over 6 MiB, because
/// `MAX_FRAME_LEN` is 32 MiB and a byte array costs roughly four bytes of JSON
/// each. A year of this corpus is well inside that; the split is per year anyway,
/// since that is also how a person's export usually arrives.
fn seed_calendar(kotton: &Path, workspace_root: &Path, years: u32, gaps: &mut Vec<String>) {
    let owner = HOUSEHOLD[0].user;
    println!("[seed] calendar — {years} year(s) for {owner}");

    for year in 0..years {
        // **A distinct year per pass.** Until this carried `start_year`, every
        // pass generated identical bytes with identical UIDs, so years 1 and 2
        // were re-imports of year 0 — the seeder reported 945 events and the
        // store held at most 315. Found by noticing three imports took 0.9s.
        let ics = generate_ics(1, 2023 + year);
        let path = std::env::temp_dir().join(format!("kotton-seed-{owner}-{year}.ics"));
        if std::fs::write(&path, ics.as_bytes()).is_err() {
            gaps.push(format!(
                "could not write a temporary export at {}",
                path.display()
            ));
            return;
        }
        let bytes = ics.len();
        let events = ics.matches("BEGIN:VEVENT").count();
        // The importer's own count, not the generator's: what matters is what
        // the store took, and a seeder that reports its own optimism is how the
        // year bug above went unnoticed for an afternoon.
        let out = Command::new(kotton)
            .args(["import", path.to_str().unwrap_or_default(), "--user", owner])
            .current_dir(workspace_root)
            .output();
        let _ = std::fs::remove_file(&path);
        let said = out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let ok = out.map(|o| o.status.success()).unwrap_or(false);
        if ok {
            println!(
                "[seed]   year {}: offered {events} ({} KiB) — {said}",
                2023 + year,
                bytes / 1024
            );
        } else {
            gaps.push(format!(
                "could not import {events} calendar events — `kotton import` refused a \
                 {} KiB .ics",
                bytes / 1024
            ));
            return;
        }
    }
}

/// Send `count` messages into the household channel.
///
/// **One CLI process per message, because that is the only door there is.** There
/// is no bulk message import — `ImportFormat` has exactly one variant and it is
/// `.ics` — so a message corpus costs a process spawn and an IPC round trip
/// apiece. The seeder reports what that costs rather than reaching past it; if
/// the number is bad, the finding is that the product has no way to bring a
/// message history with you, which is a real gap and is on the record.
fn seed_messages(
    kotton: &Path,
    workspace_root: &Path,
    owner: &str,
    count: u32,
    gaps: &mut Vec<String>,
) {
    println!("[seed] messages — {count} into '{CHANNEL}' (one CLI call each)");
    let started = std::time::Instant::now();
    let mut sent = 0u32;

    for i in 0..count {
        let body = generated_message(i);
        if step(
            kotton,
            workspace_root,
            &[
                "message", "channel", "send", CHANNEL, &body, "--user", owner,
            ],
            true,
        ) {
            sent += 1;
        }
        if i > 0 && i % 250 == 0 {
            println!(
                "[seed]   {i}/{count} ({:.1}s elapsed)",
                started.elapsed().as_secs_f64()
            );
        }
    }

    let secs = started.elapsed().as_secs_f64();
    println!(
        "[seed]   {sent}/{count} sent in {secs:.1}s ({:.1} ms each)",
        secs * 1000.0 / count.max(1) as f64
    );
    if sent < count {
        gaps.push(format!(
            "only {sent} of {count} messages sent — the channel key is the creator's alone"
        ));
    }
    if secs > 60.0 {
        gaps.push(format!(
            "seeding {count} messages took {secs:.0}s at one CLI call each — there is no message \
             import, so a real history cannot be brought in at all"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The export is well formed, carries the volume it claims, and is stable.
    ///
    /// **Verified here rather than end to end, and that is not a preference.**
    /// `cargo xtask seed` cannot reach a daemon on a fresh device at all: `kotton
    /// id create` reads its passphrase from `/dev/tty`, so with no terminal it
    /// fails with `No such device or address`, and a pipe does not satisfy it
    /// either. Until that is closed this is the part of the corpus that can be
    /// held to anything — see
    /// `TASK-the-seeder-cannot-create-an-identity-without-a-terminal`.
    #[test]
    fn the_generated_corpus_is_well_formed_and_deterministic() {
        let one = generate_ics(1, 2023);
        assert!(
            one.starts_with("BEGIN:VCALENDAR"),
            "must be an iCalendar export"
        );
        assert!(one.trim_end().ends_with("END:VCALENDAR"), "must be closed");
        assert_eq!(
            one.matches("BEGIN:VEVENT").count(),
            one.matches("END:VEVENT").count(),
            "every event is closed"
        );

        // A year is a corpus, not a script: enough records that retrieval over it
        // can be wrong about something.
        let events = one.matches("BEGIN:VEVENT").count();
        assert!(
            events > 300,
            "a year should carry hundreds of events, got {events}"
        );

        // Determinism is this seeder's second constraint — same invocation, same
        // corpus, so a retrieval result that moved means the code moved.
        assert_eq!(
            one,
            generate_ics(1, 2023),
            "the same call must produce the same bytes"
        );

        // Well inside `kotton import`'s 6 MiB refusal, which exists because the
        // IPC frame cap is 32 MiB and a byte array costs ~4 bytes of JSON each.
        assert!(one.len() < 6 * 1024 * 1024, "a year must fit one import");
    }

    /// Each needle appears exactly once, and the identifiers a question would ask
    /// about appear nowhere else.
    ///
    /// **This is the property that makes the corpus a test rather than a pile.**
    /// Over records that all resemble one another, retrieval cannot be wrong:
    /// everything matches everything, so precision has nothing to fail at. A
    /// needle is a record with exactly one right answer.
    /// **Assembled year by year, as `seed_calendar` does it.** An earlier version
    /// of this test called `generate_ics(3, 2023)` — one call covering three years
    /// — which the seeder never does, and so it passed while the real corpus
    /// carried three copies of every needle. A test that builds its input
    /// differently from the product tests a shape nothing produces.
    fn three_years_as_the_seeder_builds_them() -> String {
        (0..3).map(|y| generate_ics(1, 2023 + y)).collect()
    }

    #[test]
    fn every_needle_is_unique_in_the_corpus() {
        let corpus = three_years_as_the_seeder_builds_them();
        for (summary, _, _) in NEEDLES {
            assert_eq!(
                corpus.matches(summary).count(),
                1,
                "needle {summary:?} must appear exactly once"
            );
        }
        // Counted per *event*, not per occurrence: a needle names its identifier
        // in both the summary and the description of the one event it belongs to,
        // which is how a real record reads. What must be unique is the record.
        for token in ["INV-2291", "4417", "PX-70318"] {
            let events_holding = corpus
                .split("BEGIN:VEVENT")
                .filter(|e| e.contains(token))
                .count();
            assert_eq!(
                events_holding, 1,
                "{token} must sit in exactly one event, or a question about it has no \
                 single answer"
            );
        }
    }

    /// Needles are spread through the corpus rather than clustered, so a
    /// retriever that favoured one end of the range cannot score well for a
    /// reason that is not retrieval.
    #[test]
    fn needles_are_spread_across_the_range() {
        let corpus = three_years_as_the_seeder_builds_them();
        let span = corpus.len();
        for (i, (summary, _, _)) in NEEDLES.iter().enumerate() {
            let pos = corpus.find(summary).expect("needle present");
            let frac = pos as f64 / span as f64;
            assert!(
                frac > 0.05 && frac < 0.99,
                "needle {i} sits at {frac:.2} of the corpus — too close to an edge"
            );
        }
    }
}
