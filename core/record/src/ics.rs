// SPDX-License-Identifier: AGPL-3.0-or-later
//! An iCalendar (RFC 5545) reader — the `.ics` half of
//! `TASK-a-person-brings-their-history-with-them`.
//!
//! **This module reads bytes and produces values. It writes nothing and names no
//! store.** Turning an [`IcsEvent`] into a record is
//! [`crate::import_cmds`]'s job, and sealing it is the store's — an importer that
//! wrote its own layout would break `DEC-0071`'s cohesion rule.
//!
//! ## What it keeps, and why that is the whole point
//!
//! A person brings their history with them or they do not. An importer that
//! parses `SUMMARY`, `DTSTART` and `DTEND` and drops the recurrence rule has not
//! brought a weekly standup — it has brought one meeting on one morning in 2019
//! and lost the fact that it happened every week since. So every property this
//! reader understands is carried through verbatim, and what it cannot yet
//! interpret (an `RRULE`, a `TZID`) is carried **as written** rather than
//! discarded or guessed at.
//!
//! ## What it deliberately does not do
//!
//! - **It does not expand a recurrence.** `RRULE` is stored verbatim on the one
//!   record the `VEVENT` produced. Expanding it would invent records the export
//!   does not contain, over an unbounded range, and the rule is still there to
//!   expand later.
//! - **It does not resolve `TZID` to UTC.** Doing that honestly needs the IANA
//!   time-zone database, which this tree does not carry. A wall-clock time is
//!   recorded as a wall-clock time and the zone's name travels beside it in
//!   `time_zone`; the alternative — stamping a `Z` on a time that is not UTC —
//!   is the confident wrong answer, six hours out, that nothing downstream can
//!   detect.
//! - **It does not re-interpret an exclusive `DTEND`.** RFC 5545 §3.6.1 makes the
//!   end of an all-day event exclusive (a one-day event on the 14th ends on the
//!   15th). That is what the export says, so that is what is recorded, with
//!   `all_day` set so a reader knows which convention it is looking at.
//!
//! ## It does not panic, and `no_deformation_of_a_content_line_makes_the_reader_panic` is why that sentence is here
//!
//! These bytes arrive from outside and are read **inside the daemon**. A panic
//! here is not a parse failure a caller can act on — it unwinds the task, and
//! the person gets a closed socket with nothing said.
//!
//! **That claim was made twice before it was true.** Both times it was kept by a
//! list of sites, and both times the list was one shorter than the input:
//! unchecked time arithmetic (`DURATION:P200000000000D`), then a byte index into
//! a display name (`ORGANIZER:abcdefé`). A property held by attention is held
//! until the next person's attention runs out. So it is held by a test that
//! attacks this reader — every line of a real export and of a hostile corpus,
//! deformed at every byte offset, run through [`read`] under `catch_unwind` —
//! and the sentence above stands only as long as that test does.
//!
//! What the test backs up, in the code: every fallible step returns `Option`,
//! every chrono value is built with a `try_*` constructor, every date arithmetic
//! goes through `checked_add_signed`, and **no `&str` derived from the file is
//! indexed by byte offset** — `strip_prefix`, `split_once`, `char_indices` and
//! `get` only. A file that chooses a large enough `DURATION`, or puts a
//! two-byte character where a byte count expected a letter, loses its own
//! `VEVENT` to the skip count and nothing else.
//!
//! Two greps audit the mechanical half. `Duration::(seconds|minutes|hours|days|
//! weeks)(` finds nothing. `\[[^]]*\.\.[^]]*\]` finds two comments and three
//! slices of `&[u8]` inside the sweep's own variant generator — an owned byte
//! buffer, indexed over `0..=len`, where a byte offset is what is meant. **No
//! `&str` from the file is sliced anywhere**, which is the property; a reviewer
//! reading the grep output should be able to check that claim in five lines
//! rather than re-deriving it. `TASK-a-daemon-reader-of-caller-bytes-can-be-made-to-panic` carries
//! the gate that would hold this for every reader rather than for this one by
//! hand, and `crate::daemon::import` carries the boundary that keeps the class
//! costing a reply rather than the connection.

use chrono::{Duration, NaiveDate, NaiveDateTime};

/// One `VEVENT`, with every property this reader understands resolved.
///
/// `start_at` and `end_at` are ISO 8601. They carry a trailing `Z` **only** when
/// the export said UTC; a wall-clock time keeps its zone's name in `time_zone`
/// instead of being converted (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IcsEvent {
    /// `UID` — the export's own identifier for this event.
    pub uid: Option<String>,
    /// `SUMMARY`.
    pub summary: Option<String>,
    /// `DESCRIPTION`.
    pub description: Option<String>,
    /// `LOCATION`.
    pub location: Option<String>,
    /// `DTSTART`, ISO 8601.
    pub start_at: String,
    /// `DTEND`, or `DTSTART` plus `DURATION`, or the RFC 5545 default.
    pub end_at: String,
    /// True when `DTSTART` was a `DATE` rather than a `DATE-TIME`.
    pub all_day: bool,
    /// The `TZID` parameter as written, when the export gave one.
    pub time_zone: Option<String>,
    /// `RRULE`, verbatim — the rule, not its expansion.
    pub recurrence: Option<String>,
    /// `RECURRENCE-ID` — set on the `VEVENT`s that override one occurrence of a
    /// series. Without it a modified occurrence is indistinguishable from a
    /// duplicate of the series it belongs to.
    pub recurrence_id: Option<String>,
    /// `ATTENDEE` values with the `mailto:` prefix removed, and `ORGANIZER`
    /// first when there was one.
    pub participants: Vec<String>,
}

/// What one `.ics` file yielded.
#[derive(Debug, Clone, Default)]
pub struct IcsRead {
    /// The events, in the order the file listed them.
    pub events: Vec<IcsEvent>,
    /// `VEVENT`s this reader could not make an event of: no usable `DTSTART`, or
    /// a `DURATION` it cannot represent.
    ///
    /// An event with no start is not an event, and there is nothing honest to
    /// put in a required field — so it is counted rather than invented, and the
    /// count reaches the person who ran the import.
    pub skipped: usize,
}

/// Read an iCalendar stream.
///
/// Returns `Err` only when the bytes are not UTF-8 — RFC 5545 §6 makes UTF-8 the
/// charset, so anything else is a file this is not. Malformed *content* inside a
/// well-formed stream is skipped and counted, never fatal: one unparseable event
/// in a decade of calendar must not cost the person the other four thousand.
pub fn read(bytes: &[u8]) -> Result<IcsRead, IcsError> {
    let text = std::str::from_utf8(bytes).map_err(|_| IcsError::NotUtf8)?;
    // A UTF-8 BOM is common in exports written on Windows and is not part of any
    // property name.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let mut out = IcsRead::default();
    // The component stack: `BEGIN:` pushes, `END:` pops. Properties are collected
    // only when the innermost open component is the `VEVENT` — otherwise a
    // `VALARM`'s trigger or, worse, a `VTIMEZONE`'s own `DTSTART` would be read
    // as the event's.
    let mut stack: Vec<String> = Vec::new();
    let mut current: Option<Draft> = None;

    for line in unfold(text) {
        let Some(prop) = Property::parse(&line) else {
            continue;
        };
        match prop.name.as_str() {
            "BEGIN" => {
                let component = prop.value.to_ascii_uppercase();
                if component == "VEVENT" && stack.iter().all(|c| c != "VEVENT") {
                    current = Some(Draft::default());
                }
                stack.push(component);
            }
            "END" => {
                let component = prop.value.to_ascii_uppercase();
                if component == "VEVENT" {
                    if let Some(draft) = current.take() {
                        match draft.finish() {
                            Some(event) => out.events.push(event),
                            None => out.skipped += 1,
                        }
                    }
                }
                stack.pop();
            }
            _ => {
                // Only the event's own properties, not a nested component's.
                if stack.last().map(String::as_str) == Some("VEVENT") {
                    if let Some(draft) = current.as_mut() {
                        draft.absorb(&prop);
                    }
                }
            }
        }
    }

    Ok(out)
}

/// The one way reading a stream can fail outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IcsError {
    #[error("not a UTF-8 iCalendar stream (RFC 5545 §6 makes UTF-8 the charset)")]
    NotUtf8,
}

// ── Content lines ────────────────────────────────────────────────────────────

/// Undo RFC 5545 §3.1 line folding.
///
/// A line beginning with a space or a tab is a continuation of the one before
/// it, and the whitespace is not part of the value. Exports fold at 75 octets,
/// so a long `DESCRIPTION` arrives in pieces; reading the pieces as separate
/// lines silently truncates it at the first fold.
fn unfold(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        match raw.strip_prefix([' ', '\t']) {
            Some(rest) => {
                if let Some(last) = lines.last_mut() {
                    last.push_str(rest);
                    continue;
                }
                lines.push(rest.to_owned());
            }
            None => lines.push(raw.to_owned()),
        }
    }
    lines
}

/// One content line: `NAME[;param=value]*:VALUE`.
struct Property {
    name: String,
    params: Vec<(String, String)>,
    value: String,
}

impl Property {
    /// Split a content line, respecting quoted parameter values.
    ///
    /// The colon that ends the name+params is the first one **outside quotes**:
    /// `ATTENDEE;CN="Doe, John":mailto:j@example.com` has three, and only the
    /// third from the left is the separator. Splitting on the first colon
    /// unconditionally mangles every attendee whose display name is quoted, and
    /// splitting on the last mangles every `mailto:`.
    fn parse(line: &str) -> Option<Self> {
        if line.trim().is_empty() {
            return None;
        }
        let mut in_quotes = false;
        let mut colon = None;
        for (i, c) in line.char_indices() {
            match c {
                '"' => in_quotes = !in_quotes,
                ':' if !in_quotes => {
                    colon = Some(i);
                    break;
                }
                _ => {}
            }
        }
        // `get`, not `[..]`. The index came from `char_indices`, so it *is* a
        // boundary — but "this index is provably a char boundary" is a claim about
        // code that changes, and the panic it licenses lands in a daemon. `get`
        // costs an `Option` and cannot be wrong.
        let colon = colon?;
        let head = line.get(..colon)?;
        let value = line.get(colon..)?.strip_prefix(':')?;

        let mut parts = split_unquoted(head, ';');
        let name = parts.next()?.to_ascii_uppercase();
        let params = parts
            .filter_map(|p| {
                let (k, v) = p.split_once('=')?;
                Some((
                    k.trim().to_ascii_uppercase(),
                    v.trim().trim_matches('"').to_owned(),
                ))
            })
            .collect();

        Some(Self {
            name,
            params,
            value: value.to_owned(),
        })
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Split on a delimiter, ignoring delimiters inside double quotes.
///
/// Pieces are cut with `get`, so a bound this function computed wrongly yields
/// nothing rather than aborting the task that called it.
fn split_unquoted(s: &str, delim: char) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;
    let mut bounds: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == delim && !in_quotes {
            bounds.push((start, i));
            start = i + c.len_utf8();
        }
    }
    bounds.push((start, s.len()));
    bounds.into_iter().filter_map(move |(a, b)| s.get(a..b))
}

/// Undo RFC 5545 §3.3.11 TEXT escaping.
fn unescape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') | Some('N') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(',') => out.push(','),
            Some(';') => out.push(';'),
            // An escape this reader does not know keeps both characters rather
            // than eating the one after the backslash.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

// ── One event, under construction ────────────────────────────────────────────

#[derive(Default)]
struct Draft {
    uid: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    location: Option<String>,
    start: Option<IcsTime>,
    end: Option<IcsTime>,
    duration: Option<String>,
    recurrence: Option<String>,
    recurrence_id: Option<String>,
    organizer: Option<String>,
    attendees: Vec<String>,
}

impl Draft {
    fn absorb(&mut self, prop: &Property) {
        match prop.name.as_str() {
            "UID" => self.uid = Some(prop.value.clone()),
            "SUMMARY" => self.summary = Some(unescape_text(&prop.value)),
            "DESCRIPTION" => self.description = Some(unescape_text(&prop.value)),
            "LOCATION" => self.location = Some(unescape_text(&prop.value)),
            "DTSTART" => self.start = IcsTime::parse(prop),
            "DTEND" => self.end = IcsTime::parse(prop),
            "DURATION" => self.duration = Some(prop.value.clone()),
            "RRULE" => self.recurrence = Some(prop.value.clone()),
            "RECURRENCE-ID" => self.recurrence_id = Some(prop.value.clone()),
            "ORGANIZER" => self.organizer = Some(strip_mailto(&prop.value)),
            "ATTENDEE" => self.attendees.push(strip_mailto(&prop.value)),
            _ => {}
        }
    }

    /// Resolve the draft, or give it up.
    ///
    /// `None` when there is no usable `DTSTART`: a required field with nothing
    /// honest to put in it is a skip, not a guess.
    fn finish(self) -> Option<IcsEvent> {
        let start = self.start.clone()?;
        let end = self.resolved_end(&start)?;

        let mut participants = Vec::new();
        if let Some(organizer) = self.organizer {
            participants.push(organizer);
        }
        for attendee in self.attendees {
            if !participants.contains(&attendee) {
                participants.push(attendee);
            }
        }

        Some(IcsEvent {
            uid: self.uid,
            summary: self.summary,
            description: self.description,
            location: self.location,
            start_at: start.iso.clone(),
            end_at: end,
            all_day: start.all_day,
            time_zone: start.tzid.clone(),
            recurrence: self.recurrence,
            recurrence_id: self.recurrence_id,
            participants,
        })
    }

    /// `DTEND`, else `DTSTART` + `DURATION`, else the RFC 5545 §3.6.1 default:
    /// one day for a `DATE`, zero length for a `DATE-TIME`.
    ///
    /// `None` when the file names an end that cannot exist — a `DURATION` whose
    /// magnitude carries the start past the calendar. **That is a skip, not a
    /// fallback**: silently substituting the RFC default would report an end the
    /// export does not say, and silently substituting a panic would take the
    /// connection (see [`parse_duration`]).
    fn resolved_end(&self, start: &IcsTime) -> Option<String> {
        if let Some(end) = &self.end {
            return Some(end.iso.clone());
        }
        if let Some(raw) = self.duration.as_deref() {
            // The file stated an end. If it cannot be read — nonsense, or a
            // magnitude no instant can hold — the honest answer is that this
            // event's end is unknown, so the event is skipped and counted.
            // Falling back to the RFC default here would record a *zero-length*
            // event, which is a claim the export never made.
            let duration = parse_duration(raw)?;
            return start.plus(duration).map(|t| t.iso);
        }
        if start.all_day {
            // One day, from a value the file cannot influence.
            let day = Duration::try_days(1)?;
            return start.plus(day).map(|t| t.iso);
        }
        Some(start.iso.clone())
    }
}

/// Drop a `mailto:` prefix, whatever case the export wrote it in.
///
/// **The third panic this reader shipped**, and the plainest: it took seven
/// *bytes* to compare against `"mailto:"`, so `ORGANIZER:abcdefé` — six ASCII
/// characters and one two-byte char, written by whoever sent the invite — cut a
/// character in half and aborted the connection's task at
/// *"byte index 7 is not a char boundary"*. A byte count is not a character
/// count in any text a stranger wrote, and `\u{feff}`, `é` and an emoji all
/// appear in real display names.
///
/// `strip_prefix` on a case-folded copy asks the question that was meant —
/// *does this start with `mailto:`* — and has no index to get wrong.
fn strip_mailto(value: &str) -> String {
    let trimmed = value.trim();
    let lowered = trimmed.to_ascii_lowercase();
    match lowered.strip_prefix("mailto:") {
        // The prefix is seven ASCII characters in both copies, so the remainder
        // of the *lowered* copy is the same length as the original's — but the
        // original is what the person wrote, so it is the original that is cut,
        // by a `strip_prefix` of its own first seven characters.
        Some(_) => trimmed.chars().skip("mailto:".chars().count()).collect(),
        None => trimmed.to_owned(),
    }
}

// ── Times ────────────────────────────────────────────────────────────────────

/// A resolved `DATE` or `DATE-TIME`, with the naive value kept so arithmetic on
/// it stays exact.
#[derive(Debug, Clone)]
struct IcsTime {
    iso: String,
    naive: NaiveDateTime,
    all_day: bool,
    utc: bool,
    tzid: Option<String>,
}

impl IcsTime {
    fn parse(prop: &Property) -> Option<Self> {
        let raw = prop.value.trim();
        let is_date = prop.param("VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"))
            || raw.len() == 8;

        if is_date {
            let date = NaiveDate::parse_from_str(raw, "%Y%m%d").ok()?;
            let naive = date.and_hms_opt(0, 0, 0)?;
            return Some(Self::build(naive, true, false, None));
        }

        let (body, utc) = match raw.strip_suffix('Z') {
            Some(body) => (body, true),
            None => (raw, false),
        };
        let naive = NaiveDateTime::parse_from_str(body, "%Y%m%dT%H%M%S").ok()?;
        let tzid = match utc {
            true => None,
            false => prop.param("TZID").map(str::to_owned),
        };
        Some(Self::build(naive, false, utc, tzid))
    }

    fn build(naive: NaiveDateTime, all_day: bool, utc: bool, tzid: Option<String>) -> Self {
        Self {
            iso: render(naive, utc),
            naive,
            all_day,
            utc,
            tzid,
        }
    }

    /// Move this instant by `delta`, or say it cannot be moved.
    ///
    /// `checked_add_signed`, never `+`. The operator panics when the result
    /// leaves the representable calendar, and the magnitude is chosen by the
    /// file: `DURATION:P100000000000D` on any event is enough. A panic here is
    /// not a parse failure — it unwinds the connection's task, so the person
    /// sees a dropped socket and no reason, which is the outcome the import
    /// path's size check exists to avoid producing.
    fn plus(&self, delta: Duration) -> Option<Self> {
        let naive = self.naive.checked_add_signed(delta)?;
        Some(Self::build(naive, self.all_day, self.utc, self.tzid.clone()))
    }
}

/// ISO 8601, with `Z` **only** when the export said UTC.
fn render(naive: NaiveDateTime, utc: bool) -> String {
    let base = naive.format("%Y-%m-%dT%H:%M:%S").to_string();
    match utc {
        true => format!("{base}Z"),
        false => base,
    }
}

/// Parse an RFC 5545 §3.3.6 duration (`P1DT2H`, `PT30M`, `P2W`, `-PT15M`).
///
/// Returns `None` for anything it does not understand. The caller treats that
/// as an unknown end and skips the event, rather than recording the RFC's
/// default — a `DURATION` the file stated and this could not read is missing
/// information, not an absent property.
///
/// **Every arithmetic step is checked, including the constructor.** The first
/// version of this function guarded its own multiplication with `checked_mul`
/// and then handed the result to `Duration::seconds`, which panics past
/// `i64::MAX / 1000` milliseconds — so `DURATION:P200000000000D` multiplied
/// safely and then aborted the connection's task in the constructor. Guarding
/// the arithmetic and not the constructor is the shape of that defect: the
/// bound that matters belongs to the type being built, not to the sum.
fn parse_duration(raw: &str) -> Option<Duration> {
    let raw = raw.trim();
    let (negative, rest) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw.strip_prefix('+').unwrap_or(raw)),
    };
    let rest = rest.strip_prefix('P').or_else(|| rest.strip_prefix('p'))?;

    let mut seconds: i64 = 0;
    let mut digits = String::new();
    let mut in_time = false;
    let mut saw_unit = false;
    for c in rest.chars() {
        match c {
            'T' | 't' => in_time = true,
            '0'..='9' => digits.push(c),
            unit => {
                let n: i64 = digits.parse().ok()?;
                digits.clear();
                let scale = match (unit.to_ascii_uppercase(), in_time) {
                    ('W', _) => 7 * 24 * 3600,
                    ('D', _) => 24 * 3600,
                    ('H', true) => 3600,
                    ('M', true) => 60,
                    ('S', true) => 1,
                    _ => return None,
                };
                seconds = seconds.checked_add(n.checked_mul(scale)?)?;
                saw_unit = true;
            }
        }
    }
    if !saw_unit || !digits.is_empty() {
        return None;
    }
    let signed = match negative {
        true => seconds.checked_neg()?,
        false => seconds,
    };
    Duration::try_seconds(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "\
BEGIN:VCALENDAR\r
VERSION:2.0\r
BEGIN:VEVENT\r
UID:abc-123\r
SUMMARY:Standup\r
DTSTART:20260115T130000Z\r
DTEND:20260115T131500Z\r
END:VEVENT\r
END:VCALENDAR\r
";

    #[test]
    fn a_utc_event_keeps_its_z() {
        let read = read(ONE.as_bytes()).expect("utf-8");
        assert_eq!(read.events.len(), 1);
        assert_eq!(read.skipped, 0);
        let e = &read.events[0];
        assert_eq!(e.uid.as_deref(), Some("abc-123"));
        assert_eq!(e.summary.as_deref(), Some("Standup"));
        assert_eq!(e.start_at, "2026-01-15T13:00:00Z");
        assert_eq!(e.end_at, "2026-01-15T13:15:00Z");
        assert!(!e.all_day);
        assert_eq!(e.time_zone, None);
    }

    /// A `DATE` start makes an all-day event, and RFC 5545's default end is the
    /// next day — exclusive, as the spec has it.
    #[test]
    fn an_all_day_event_ends_the_next_day() {
        let ics = "BEGIN:VEVENT\nDTSTART;VALUE=DATE:20260704\nSUMMARY:Holiday\nEND:VEVENT\n";
        let read = read(ics.as_bytes()).unwrap();
        let e = &read.events[0];
        assert!(e.all_day);
        assert_eq!(e.start_at, "2026-07-04T00:00:00");
        assert_eq!(e.end_at, "2026-07-05T00:00:00");
        assert!(!e.start_at.ends_with('Z'), "a floating date is not UTC");
    }

    /// The recurrence rule survives, verbatim and unexpanded.
    #[test]
    fn a_recurring_event_keeps_its_rule_and_stays_one_record() {
        let ics = "BEGIN:VEVENT\nDTSTART:20260105T090000Z\nRRULE:FREQ=WEEKLY;BYDAY=MO\n\
                   SUMMARY:Weekly\nEND:VEVENT\n";
        let read = read(ics.as_bytes()).unwrap();
        assert_eq!(read.events.len(), 1, "a rule is not an expansion");
        assert_eq!(
            read.events[0].recurrence.as_deref(),
            Some("FREQ=WEEKLY;BYDAY=MO")
        );
    }

    /// A zone's name travels beside a wall-clock time rather than being resolved
    /// into a `Z` this tree cannot compute.
    #[test]
    fn a_zoned_time_is_not_stamped_utc() {
        let ics = "BEGIN:VEVENT\nDTSTART;TZID=America/New_York:20260115T090000\n\
                   SUMMARY:Local\nEND:VEVENT\n";
        let e = &read(ics.as_bytes()).unwrap().events[0];
        assert_eq!(e.start_at, "2026-01-15T09:00:00");
        assert_eq!(e.time_zone.as_deref(), Some("America/New_York"));
    }

    #[test]
    fn duration_resolves_the_end() {
        let ics = "BEGIN:VEVENT\nDTSTART:20260115T130000Z\nDURATION:PT1H30M\n\
                   SUMMARY:Long\nEND:VEVENT\n";
        let e = &read(ics.as_bytes()).unwrap().events[0];
        assert_eq!(e.end_at, "2026-01-15T14:30:00Z");
    }

    #[test]
    fn durations_parse_or_refuse() {
        // `try_*` on both sides of every assertion. A panicking constructor in a
        // *test* still teaches the next reader that the panicking form is the
        // normal one, which is how the defect above got written — so this file
        // holds none of them, and `Duration::(seconds|minutes|hours|days|weeks)(`
        // finding nothing in it is the audit.
        assert_eq!(parse_duration("PT15M"), Duration::try_minutes(15));
        assert_eq!(parse_duration("P2W"), Duration::try_days(14));
        assert_eq!(parse_duration("P1DT2H"), Duration::try_hours(26));
        assert_eq!(parse_duration("-PT15M"), Duration::try_minutes(-15));
        assert_eq!(parse_duration("PT"), None);
        assert_eq!(parse_duration("P1"), None, "a number with no unit is not a duration");
        assert_eq!(parse_duration("garbage"), None);
    }

    /// **The magnitudes a file can choose, and the constructor each one reaches.**
    ///
    /// Both were reproduced against the daemon before this test existed:
    /// `P200000000000D` panicked inside `Duration::seconds` — the arithmetic was
    /// checked and the constructor was not — and `P100000000000D` got past the
    /// constructor and panicked adding to the `NaiveDateTime`. A panic in a
    /// reader of caller-supplied bytes is not a parse error: it unwinds the
    /// connection's task, so the person gets a dropped socket and no sentence.
    ///
    /// Each case names the bound it crosses, because the two are different
    /// bounds and a single "huge number" case would stop covering one of them
    /// the day the other moved.
    #[test]
    fn a_duration_too_large_to_exist_refuses_rather_than_panics() {
        // Past `TimeDelta`'s own range — the constructor's bound.
        assert_eq!(parse_duration("P200000000000D"), None);
        assert_eq!(parse_duration("-P200000000000D"), None);
        assert_eq!(parse_duration("P30000000000W"), None);
        // `TimeDelta` holds more seconds than this: the bound is `i64::MAX`
        // *milliseconds*, so 9e15 seconds is legal and 9.3e15 is not. Pinned
        // either side of it, because a case that sits comfortably inside the
        // range stops testing the constructor the day the range changes.
        assert!(parse_duration("PT9000000000000000S").is_some());
        assert_eq!(parse_duration("PT9300000000000000S"), None);
        // Past `i64` before any of chrono's bounds are reached.
        assert_eq!(parse_duration("P99999999999999999999D"), None);

        // Inside `TimeDelta` and outside the calendar — the arithmetic's bound.
        let big = parse_duration("P100000000000D").expect("this one is a legal TimeDelta");
        let start = IcsTime::parse(&Property::parse("DTSTART:20260115T130000Z").unwrap())
            .expect("a well-formed start");
        assert!(
            start.plus(big).is_none(),
            "an end past the calendar is refused, not asserted"
        );
        // Parsed rather than negated: unary `-` on a `TimeDelta` panics on its
        // minimum, so even in a test the sign comes from the reader's own path.
        let back = parse_duration("-P100000000000D").expect("a legal negative TimeDelta");
        assert!(
            start.plus(back).is_none(),
            "and so is one before it — a negative DURATION is legal syntax"
        );
    }

    /// The whole reader's contract, on the two inputs that broke it: a `VEVENT`
    /// whose end cannot exist is **skipped and counted**, like any other
    /// malformed one, and the events around it still arrive.
    #[test]
    fn a_hostile_duration_costs_its_own_event_and_nothing_else() {
        for hostile in ["P200000000000D", "P100000000000D", "-P100000000000D"] {
            let ics = format!(
                "BEGIN:VCALENDAR\n\
                 BEGIN:VEVENT\nUID:a\nDTSTART:20260115T130000Z\nSUMMARY:Before\nEND:VEVENT\n\
                 BEGIN:VEVENT\nUID:b\nDTSTART:20260115T130000Z\nDURATION:{hostile}\nSUMMARY:Hostile\nEND:VEVENT\n\
                 BEGIN:VEVENT\nUID:c\nDTSTART:20260116T130000Z\nSUMMARY:After\nEND:VEVENT\n\
                 END:VCALENDAR\n"
            );
            let read = read(ics.as_bytes()).expect("a well-formed UTF-8 stream");
            assert_eq!(read.events.len(), 2, "{hostile}: the neighbours survive");
            assert_eq!(read.skipped, 1, "{hostile}: and the bad one is counted");
            assert!(read.events.iter().all(|e| e.summary.as_deref() != Some("Hostile")));
        }
    }

    /// The all-day default adds a day the file did not choose — but it adds it to
    /// a date the file *did*, so the addition is checked like every other.
    #[test]
    fn an_all_day_event_at_the_end_of_the_calendar_does_not_panic() {
        let ics = "BEGIN:VEVENT\nDTSTART;VALUE=DATE:99991231\nSUMMARY:Last day\nEND:VEVENT\n";
        let read = read(ics.as_bytes()).expect("a well-formed UTF-8 stream");
        // 9999-12-31 is inside `NaiveDate`'s range, so this one resolves; the
        // assertion is that it resolves *through the checked path*.
        assert_eq!(read.events.len(), 1);
        // chrono writes a five-digit year in ISO 8601's expanded form, sign and
        // all. Asserted as it actually is rather than as it reads: the point of
        // the case is the checked addition, and quietly "fixing" the format
        // would be inventing a year zero-padding rule nothing asked for.
        assert_eq!(read.events[0].end_at, "+10000-01-01T00:00:00");
    }

    /// The failure a fold causes is a *truncated* description, which reads as
    /// success — so this asserts the whole of it.
    #[test]
    fn folded_lines_are_rejoined() {
        // The fold takes the CRLF *and* the one whitespace character after it —
        // an export breaks mid-word at 75 octets, so re-inserting a space here
        // would corrupt every long description rather than repair it.
        let ics = "BEGIN:VEVENT\r\nDTSTART:20260115T130000Z\r\nDESCRIPTION:one two thr\r\n ee fo\r\n\tur\r\nEND:VEVENT\r\n";
        let e = &read(ics.as_bytes()).unwrap().events[0];
        assert_eq!(e.description.as_deref(), Some("one two three four"));
    }

    #[test]
    fn text_escapes_are_undone() {
        let ics = "BEGIN:VEVENT\nDTSTART:20260115T130000Z\nSUMMARY:Tea\\, cake\\; and a \\\\ break\\nupstairs\nEND:VEVENT\n";
        let e = &read(ics.as_bytes()).unwrap().events[0];
        assert_eq!(e.summary.as_deref(), Some("Tea, cake; and a \\ break\nupstairs"));
    }

    /// **The third panic, as a test.** A display name is text a stranger wrote,
    /// and `ORGANIZER:abcdefé` put a two-byte character across the seventh byte
    /// — which is where a `mailto:` check that counted bytes cut.
    #[test]
    fn a_multibyte_participant_is_kept_whole() {
        let ics = "BEGIN:VEVENT\nDTSTART:20260115T130000Z\n\
                   ORGANIZER:abcdefé\n\
                   ATTENDEE:MailTo:Ünïcode@example.com\n\
                   ATTENDEE:mailto:é@example.com\n\
                   ATTENDEE:𝄞\nEND:VEVENT\n";
        let e = &read(ics.as_bytes()).unwrap().events[0];
        assert_eq!(
            e.participants,
            vec![
                "abcdefé",
                // The prefix goes whatever case it was written in, and what is
                // left is what the person wrote — not a lowercased copy of it.
                "Ünïcode@example.com",
                "é@example.com",
                "𝄞",
            ]
        );
    }

    /// A quoted `CN` containing a comma and a colon must not split the line in
    /// the wrong place.
    #[test]
    fn a_quoted_parameter_does_not_split_the_line() {
        let ics = "BEGIN:VEVENT\nDTSTART:20260115T130000Z\n\
                   ORGANIZER;CN=\"Doe, John: chair\":mailto:john@example.com\n\
                   ATTENDEE;CN=Ann:mailto:ann@example.com\nEND:VEVENT\n";
        let e = &read(ics.as_bytes()).unwrap().events[0];
        assert_eq!(e.participants, vec!["john@example.com", "ann@example.com"]);
    }

    /// **The nested-component trap.** A `VTIMEZONE` carries its own `DTSTART`,
    /// and a `VALARM` sits *inside* the `VEVENT`. Reading either as the event's
    /// gives a confidently wrong time — 1970 for the timezone's rule — with
    /// nothing downstream able to tell.
    #[test]
    fn nested_components_do_not_leak_into_the_event() {
        let ics = "\
BEGIN:VCALENDAR
BEGIN:VTIMEZONE
TZID:Europe/London
BEGIN:STANDARD
DTSTART:19701025T020000
TZOFFSETFROM:+0100
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:with-alarm
DTSTART:20260115T130000Z
SUMMARY:Has an alarm
BEGIN:VALARM
TRIGGER:-PT10M
DESCRIPTION:Reminder
END:VALARM
END:VEVENT
END:VCALENDAR
";
        let read = read(ics.as_bytes()).unwrap();
        assert_eq!(read.events.len(), 1, "VTIMEZONE and VALARM are not events");
        let e = &read.events[0];
        assert_eq!(e.start_at, "2026-01-15T13:00:00Z");
        assert_eq!(
            e.description, None,
            "the alarm's description is the alarm's, not the event's"
        );
    }

    #[test]
    fn an_event_with_no_start_is_counted_not_invented() {
        let ics = "BEGIN:VEVENT\nSUMMARY:When?\nEND:VEVENT\nBEGIN:VEVENT\nDTSTART:20260115T130000Z\nEND:VEVENT\n";
        let read = read(ics.as_bytes()).unwrap();
        assert_eq!(read.events.len(), 1);
        assert_eq!(read.skipped, 1);
    }

    #[test]
    fn a_modified_occurrence_says_so() {
        let ics = "BEGIN:VEVENT\nUID:series\nDTSTART:20260112T090000Z\n\
                   RECURRENCE-ID:20260112T090000Z\nSUMMARY:Moved\nEND:VEVENT\n";
        let e = &read(ics.as_bytes()).unwrap().events[0];
        assert_eq!(e.recurrence_id.as_deref(), Some("20260112T090000Z"));
    }

    #[test]
    fn non_utf8_is_not_an_ics_stream() {
        assert!(matches!(read(&[0xff, 0xfe, 0x00]), Err(IcsError::NotUtf8)));
    }

    #[test]
    fn a_byte_order_mark_is_not_a_property_name() {
        let ics = format!("\u{feff}{ONE}");
        assert_eq!(read(ics.as_bytes()).unwrap().events.len(), 1);
    }

    // ── The sweep ────────────────────────────────────────────────────────────

    /// The export the integration suite imports, read at compile time.
    ///
    /// The real file rather than a copy of it: a second copy drifts, and the
    /// point of sweeping *these* lines is that they are the shapes a real export
    /// contains. If the fixture moves this stops compiling, which is the loud
    /// failure rather than the quiet one.
    const FIXTURE: &str = include_str!("../../../tests/fixtures/calendar/a-life.ics");

    /// Lines chosen to sit on the reader's own decisions: the quoting, the
    /// escapes, the numbers, and the places it has already been caught indexing.
    const HOSTILE: &[&str] = &[
        "ORGANIZER;CN=\"Doe, John: chair\":mailto:john@example.com",
        "ATTENDEE:mailto:é@example.com",
        "ORGANIZER:abcdefé",
        "DTSTART;TZID=America/New_York:20260115T093000",
        "DTSTART;VALUE=DATE:20260704",
        "DURATION:P1DT2H30M",
        "DURATION:-PT15M",
        "RRULE:FREQ=WEEKLY;BYDAY=MO,TU",
        r"SUMMARY:Tea\, cake\; and a \\ break\nupstairs",
        "DESCRIPTION:",
        "X-UNKNOWN;P=1;Q=\"2\":value",
        "BEGIN:VALARM",
        "END:VEVENT",
        ":",
        ";",
        "\"",
    ];

    /// Characters that are more than one byte, including two that are not
    /// letters: a combining mark and a zero-width joiner both appear in real
    /// display names and neither survives being cut.
    const MULTIBYTE: &[&str] = &["é", "𝄞", "\u{0301}", "\u{200d}"];

    /// Every way this sweep deforms one line.
    ///
    /// Bytes, not text, and deliberately: an insertion or a truncation at an
    /// arbitrary offset can leave invalid UTF-8, and *that document is also an
    /// input the reader must answer*. It answers `Err(NotUtf8)`, which is an
    /// answer. Building the variants as `String` would have made this test panic
    /// on the very cases it exists to find.
    fn variants(line: &str) -> Vec<Vec<u8>> {
        let bytes = line.as_bytes();
        let mut out: Vec<Vec<u8>> = Vec::new();

        // A multibyte character inserted at every byte boundary — the shape that
        // caught `strip_mailto`.
        for ch in MULTIBYTE {
            for at in 0..=bytes.len() {
                let mut v = Vec::with_capacity(bytes.len() + ch.len());
                v.extend_from_slice(&bytes[..at]);
                v.extend_from_slice(ch.as_bytes());
                v.extend_from_slice(&bytes[at..]);
                out.push(v);
            }
        }

        // Truncation at every byte boundary — a line cut mid-character, and a
        // line cut mid-property.
        for at in 0..=bytes.len() {
            out.push(bytes[..at].to_vec());
        }

        // Every digit run replaced by something a reader of numbers has to
        // survive: a single zero, a twenty-digit run, a bare sign, and the
        // largest u64.
        let long = "2".repeat(20);
        let max = u64::MAX.to_string();
        for replacement in ["0", long.as_str(), "-", max.as_str()] {
            let mut rebuilt = String::with_capacity(line.len() + 32);
            let mut in_digits = false;
            for c in line.chars() {
                match c.is_ascii_digit() {
                    true => {
                        if !in_digits {
                            rebuilt.push_str(replacement);
                            in_digits = true;
                        }
                    }
                    false => {
                        rebuilt.push(c);
                        in_digits = false;
                    }
                }
            }
            out.push(rebuilt.into_bytes());
        }

        out
    }

    /// **The property, proven by attacking it — not by listing the sites.**
    ///
    /// Two refusals on this reader fixed the lines a reviewer named and left the
    /// class alone: unchecked time arithmetic, then a byte index into text
    /// somebody else wrote. A list of sites is only ever as long as the last
    /// person's attention, so the claim in this module's header is held here
    /// instead — by deforming every line of a real export, and of the corpus
    /// above, in every way this reader has been broken by, and running each
    /// result through [`read`] under `catch_unwind`.
    ///
    /// It asserts one thing: **no input panics.** Not that any of them parse. A
    /// deformed line is usually nonsense, and nonsense is meant to be skipped,
    /// counted or ignored. The failure this catches is the reader aborting the
    /// task it runs on, which in the daemon is the person's connection.
    ///
    /// Deterministic and finite — no RNG, and a corpus of the fixture plus
    /// sixteen lines — so the count is stable, and a failure prints the exact
    /// bytes that caused it.
    #[test]
    fn no_deformation_of_a_content_line_makes_the_reader_panic() {
        let lines: Vec<&str> = FIXTURE
            .lines()
            .chain(HOSTILE.iter().copied())
            .filter(|l| !l.is_empty())
            .collect();

        let mut checked = 0usize;
        for line in &lines {
            for variant in variants(line) {
                // Wrapped, so the deformed line is also read where a property is
                // read: inside an event, with a valid start already seen.
                let mut doc: Vec<u8> =
                    b"BEGIN:VCALENDAR\nBEGIN:VEVENT\nDTSTART:20260115T130000Z\n".to_vec();
                doc.extend_from_slice(&variant);
                doc.extend_from_slice(b"\nEND:VEVENT\nEND:VCALENDAR\n");

                for input in [variant.clone(), doc] {
                    let outcome = std::panic::catch_unwind(|| read(&input));
                    assert!(
                        outcome.is_ok(),
                        "the reader aborted on {} byte(s): {:?}\n  deformed from: {line:?}",
                        input.len(),
                        String::from_utf8_lossy(&input),
                    );
                    checked += 1;
                }
            }
        }

        // A sweep that silently stopped generating would pass while measuring
        // nothing — the instrument failure this repository keeps cataloguing.
        assert!(
            checked > 20_000,
            "the sweep covered only {checked} inputs; it is supposed to be thousands"
        );
    }
}
