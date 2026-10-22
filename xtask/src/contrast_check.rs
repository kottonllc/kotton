// SPDX-License-Identifier: AGPL-3.0-or-later
//! `contrast-check` — the token palette actually meets the contrast it claims.
//!
//! `ui/tokens.css` states its ratios in comments — *"14.07 AAA / 6.59 AA /
//! 4.87 AA"*, *"16.50 on `--color-accent`"*, *"9.53 on the light canvas"* — and
//! nothing computed them. The skill's quality floor says *"contrast >= WCAG AA
//! for all text (the tokens are built to pass; don't override them into
//! failing)"*, which is a rule addressed to a reader rather than a check.
//!
//! That is the shape this repository keeps finding: a number in a comment, and a
//! floor nobody stands on. Written here before re-pointing Tier 1 warm, because
//! changing every neutral on the claim that the ramp passes — with nothing
//! verifying it — is how a palette silently drops below AA on one pair nobody
//! looks at.
//!
//! ## What it checks
//!
//! Only **text on a ground**, both themes. Contrast is a property of a pair, so
//! the pairs are declared: a token is not "AA", it is AA *against something*.
//! A *solid fill* is a ground like any other, and since 2026-09-21 three pairs
//! say so: `--color-danger-ink` on `--color-danger`, and its two siblings. The
//! ink a fill carries used to be a number in a preview, which is the same shape
//! as a ratio in a comment.
//! Non-text pairs (borders, separators, hairlines) are out of scope — WCAG's
//! 3:1 non-text rule applies to interface *components*, and a hairline that
//! deliberately does not draw an edge is not one.
//!
//! Translucent values (`rgba(...)`) are skipped rather than guessed at: their
//! effective contrast depends on what is behind them, which a static file does
//! not know.
//!
//! ## The one exception, and why it is not one
//!
//! `--panel-material` is translucent on purpose: a dock or a menubar is a
//! material over a blurred copy of whatever the compositor drew beneath it
//! (`TASK-a-backdrop-blur-behind-a-panel-is-the-second-pass`). The rule above
//! still holds — its effective contrast depends on what is behind it — so this
//! does not guess. It states the **worst two backdrops there are**, pure white
//! and pure black, composites the material over each, and measures the panel's
//! text on the result. A claim about a worst case is not a guess; it is the only
//! honest contrast claim a surface over unknown pixels can make, and it is what
//! `DEC-0022`'s and `DEC-0047`'s 2026-09-21 amendments say the ground under a
//! panel now costs their argument.
//!
//! ## Two models, and which of them fails the build where
//!
//! Since 2026-09-21 every pair above is measured twice: WCAG 2's ratio, and
//! APCA's lightness contrast `Lc`. **In the default scopes WCAG 2 is still the
//! only model that exits non-zero.** APCA is printed beside it and its
//! shortfalls are reported as findings, because APCA is a draft whose
//! thresholds are guidance, and a gate that fails on a draft is a gate people
//! learn to silence.
//!
//! **In the increased-contrast scopes both models fail the build**, at WCAG
//! AAA (7:1) and APCA `|Lc|` 60 — the body rung. That is the flip
//! `TASK-contrast-check-reads-apca-beside-wcag` named when it left the second
//! column advisory: *"an increased-contrast block is exactly the surface that
//! should be held to Lc 60 or 75 while the default block keeps WCAG AA"*. The
//! reason it can be enforced there and not here is the same reason that record
//! gave for not enforcing it at all — enforcing a rung on the default palette
//! would be a palette decision made by a tool, on ladder stops the owner has
//! ruled on. The increased-contrast blocks are not that palette: they exist
//! *because* of a floor, they were written against these two numbers, and a
//! stop in them that stops clearing one is a defect rather than a taste.
//!
//! 60 and not 75. The small rung is where text below body size lands, and this
//! gate cannot know a pair's size — but adopting 75 here would have forced two
//! changes it has no business forcing: `--panel-material` opaque (secondary
//! text over a panel on a black backdrop reads Lc 68.5 in light at the declared
//! 84%) and the state ramps two stops paler than the floor needs. Pairs between
//! the two rungs are printed under the failures as a list, so the higher rung
//! is visible rather than dropped.
//!
//! ## A mark is not text, and three of them are fenced
//!
//! A mark is a glyph or a graphical object rather than words, and the two
//! models hold it a rung lower: WCAG 2.1's 1.4.11 asks 3:1 of a non-text
//! component, and APCA's non-text rung is Lc 45. In the increased-contrast
//! scopes a mark is **lifted with everything else** — to 4.5 and to Lc 60, both
//! enforced ([`Rung::Mark`], since 2026-09-21). It is not lifted to the *text*
//! floor: 7:1 is for words, and the dock's six hues cannot reach it without
//! ceasing to be hues. But it is lifted, because a scope whose whole promise is
//! *more* cannot mean *more except the launcher* —
//! `TASK-a-launcher-mark-is-held-to-the-non-text-rung-even-where-contrast-is-increased`.
//!
//! **Three pairs are fenced out of that lift** ([`Rung::MarkFenced`]) —
//! `--frame-control-mark` on each stoplight — and they keep their declared 4.5
//! and their advisory APCA in **every** scope, increased contrast included.
//! Not because a mark deserves less, but because this axis cannot move them:
//! the lights are `--red-500` / `--yellow-300` / `--green-400` in Tier 3, the
//! same in both themes, and no Tier 2 block reaches them
//! (`DEC-0062` — only Tier 2 branches). Two of the three clear 7:1 and Lc 60
//! anyway; close reads 5.45 and Lc 41.60, and
//! `TASK-the-close-lights-mark-is-under-apcas-non-text-rung` owns that pair
//! and says in its own words that it should not be closed by picking a lever
//! quietly. Failing the build on it here would be this gate making that choice.
//!
//! The second column exists because WCAG 2's ratio is symmetric and vision is
//! not: it over-rates light text on a dark ground and under-rates dark text on a
//! light one. Kotton is dark by default, so that error runs in the direction of
//! this product's entire surface — a secondary ink that reads as mud on the
//! near-black ground still clears 4.5 comfortably. APCA is polarity-aware, which
//! is why `Lc` is signed here and never `abs()`ed in the print: a negative number
//! is light text on a dark ground, and that sign is the finding.

use std::collections::HashMap;
use std::path::Path;

/// What a pair's foreground *is*, which is what decides whether a scope's
/// stricter floor applies to it.
///
/// Three values and not a number, because the distinction is about which lever
/// exists rather than about how much contrast is wanted. A `Text` pair can
/// always be fixed in Tier 2 — that is what the semantic layer is — a `Mark`
/// pair can be fixed there too but is not words, and a `MarkFenced` pair
/// cannot be fixed on this axis at all: see the header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rung {
    /// Words, or a glyph that is the only thing carrying a meaning words would.
    Text,
    /// A mark — a glyph or a graphical object, not words — whose colour a
    /// semantic block *can* re-map.
    ///
    /// Held at its declared non-text floor in the default scopes, and lifted a
    /// rung in the increased-contrast ones
    /// (`TASK-a-launcher-mark-is-held-to-the-non-text-rung-even-where-contrast-is-increased`).
    /// It is not raised to the *text* floor there — 7:1 is for words, and a hue
    /// cannot reach it without ceasing to be a hue — but it is raised, because
    /// a scope that promises more contrast and gives the launcher none is
    /// promising more except where you look first.
    Mark,
    /// A mark on a solid fill whose colour no semantic block can re-map.
    ///
    /// The three stoplight pairs and nothing else today: the lights are Tier 3
    /// stops, the same in both themes, and `DEC-0062` says only Tier 2
    /// branches — so no scope on this axis reaches them and lifting their floor
    /// would fail the build on a pair the axis cannot move. The header's *one of
    /// them is fenced* section is the argument, and
    /// `TASK-the-close-lights-mark-is-under-apcas-non-text-rung` owns the pair
    /// that shows it.
    MarkFenced,
}

/// How hard a scope is held. The two regimes, and the only thing that differs
/// between them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Held {
    /// WCAG 2 AA fails the build; APCA is printed and advisory.
    Aa,
    /// WCAG 2 AAA *and* APCA's body rung both fail the build — the
    /// increased-contrast blocks, and nothing else.
    AaaAndApca,
}

/// The two floors one pair faces in one scope. `apca: None` is the advisory
/// column: measured, printed, reported as a finding, never a failure.
#[derive(Clone, Copy, Debug)]
struct Floor {
    wcag: f64,
    apca: Option<f64>,
}

impl Held {
    /// The floor a pair of this rung faces in a scope held this way.
    fn floor(self, declared: f64, rung: Rung) -> Floor {
        match (self, rung) {
            (Held::AaaAndApca, Rung::Text) => Floor {
                wcag: declared.max(WCAG_AAA),
                apca: Some(APCA_BODY),
            },
            (Held::AaaAndApca, Rung::Mark) => Floor {
                wcag: declared.max(WCAG_NON_TEXT_LIFTED),
                apca: Some(APCA_BODY),
            },
            _ => Floor {
                wcag: declared,
                apca: None,
            },
        }
    }
}

/// WCAG 2's AAA ratio for body text. The increased-contrast scopes' floor, and
/// the number `TASK-an-increased-contrast-theme-is-one-more-block` states.
const WCAG_AAA: f64 = 7.0;

/// What a [`Rung::Mark`] pair must clear in an increased-contrast scope.
///
/// One rung up the same ladder text climbs: words go 4.5 -> 7.0, a graphical
/// object goes 3.0 -> 4.5. **WCAG 2 does not state this number** — 1.4.11 holds
/// a non-text component at 3:1 and the standard has no enhanced success
/// criterion for one — so it is this repository's choice and not a citation, and
/// it is 4.5 because that is the next ratio WCAG names above 3:1 and because the
/// APCA side of the same lift is already 60, the body rung, for which 4.5 is the
/// WCAG-side neighbour everywhere else in this file.
/// `TASK-a-launcher-mark-is-held-to-the-non-text-rung-even-where-contrast-is-increased`
/// asked for it as "WCAG's own reading of enhanced for graphical objects"; the
/// number is right and that sentence is not, which is recorded there.
const WCAG_NON_TEXT_LIFTED: f64 = 4.5;

/// A foreground token, a background token, the floor it must clear, and what
/// its foreground is.
///
/// 4.5 is AA for body text and 3.0 is AA for large text. Everything here is
/// held to 4.5 except where the token's own role is large-only. In a scope held
/// at [`Held::AaaAndApca`] the declared floor is raised to 7.0 for every
/// [`Rung::Text`] pair — the number is per pair so that a pair which already
/// declares something stricter keeps it.
const PAIRS: &[(&str, &str, f64, Rung)] = &[
    ("--color-text", "--color-bg", 4.5, Rung::Text),
    ("--color-text", "--color-surface", 4.5, Rung::Text),
    ("--color-text", "--color-surface-raised", 4.5, Rung::Text),
    ("--color-text", "--color-surface-sunken", 4.5, Rung::Text),
    ("--color-text-secondary", "--color-bg", 4.5, Rung::Text),
    ("--color-text-secondary", "--color-surface", 4.5, Rung::Text),
    ("--color-text-tertiary", "--color-bg", 4.5, Rung::Text),
    ("--color-text-tertiary", "--color-surface", 4.5, Rung::Text),
    // A WINDOW'S PANE AND ITS SIDEBAR are grounds of their own since 2026-09-30
    // (`TASK-the-desktop-is-set-in-geist-and-layered-as-the-mock-up`): Settings,
    // Files and Calendar draw their words straight on them, so the three text
    // tokens face the floor there as they do on `--color-bg`.
    ("--color-text", "--color-surface-pane", 4.5, Rung::Text),
    ("--color-text-secondary", "--color-surface-pane", 4.5, Rung::Text),
    ("--color-text-tertiary", "--color-surface-pane", 4.5, Rung::Text),
    ("--color-text", "--color-surface-side", 4.5, Rung::Text),
    ("--color-text-secondary", "--color-surface-side", 4.5, Rung::Text),
    ("--color-text-tertiary", "--color-surface-side", 4.5, Rung::Text),
    ("--color-text-on-accent", "--color-accent", 4.5, Rung::Text),
    (
        "--color-text-on-system",
        "--color-system-fill",
        4.5,
        Rung::Text,
    ),
    // Feedback colours carry words — "too short", "incorrect passphrase" — so
    // they are text, not decoration, and face the text floor.
    ("--color-info", "--color-bg", 4.5, Rung::Text),
    ("--color-success", "--color-bg", 4.5, Rung::Text),
    ("--color-warning", "--color-bg", 4.5, Rung::Text),
    ("--color-danger", "--color-bg", 4.5, Rung::Text),
    ("--color-info", "--color-surface", 4.5, Rung::Text),
    ("--color-success", "--color-surface", 4.5, Rung::Text),
    ("--color-warning", "--color-surface", 4.5, Rung::Text),
    ("--color-danger", "--color-surface", 4.5, Rung::Text),
    // A NOTICE IS A CARD ON A QUIET FILL, so the quiet fills are grounds — the
    // one kind of ground this list did not have until 2026-09-21
    // (`TASK-a-notice-is-a-card-at-the-foot-of-the-app-and-yellow-says-info`).
    // Two things sit on one: the severity's glyph, and the message. The glyph is
    // a 16px stroke mark and WCAG would hold a graphic at 3.0; it is held at the
    // text floor here because it is the only thing on the card carrying the
    // severity, and a mark that says "this is the bad one" is read, not
    // decorated. The message is --color-text, which is the same token on every
    // other surface in the product and has never been measured on a coloured
    // one.
    ("--color-info", "--color-info-quiet", 4.5, Rung::Text),
    ("--color-success", "--color-success-quiet", 4.5, Rung::Text),
    ("--color-warning", "--color-warning-quiet", 4.5, Rung::Text),
    ("--color-danger", "--color-danger-quiet", 4.5, Rung::Text),
    ("--color-text", "--color-info-quiet", 4.5, Rung::Text),
    ("--color-text", "--color-success-quiet", 4.5, Rung::Text),
    ("--color-text", "--color-warning-quiet", 4.5, Rung::Text),
    ("--color-text", "--color-danger-quiet", 4.5, Rung::Text),
    // The same three tokens are also FILLS — the stoplights, the danger button,
    // a badge — and a fill carries ink. That pairing lived in a preview's
    // numbers until the derived spectrum landed (2026-09-20); it is three
    // tokens now, so it is three pairs here. A solid whose ink cannot be read
    // is the same defect as unreadable text, arriving from the other side.
    ("--color-info-ink", "--color-info", 4.5, Rung::Text),
    ("--color-success-ink", "--color-success", 4.5, Rung::Text),
    ("--color-warning-ink", "--color-warning", 4.5, Rung::Text),
    ("--color-danger-ink", "--color-danger", 4.5, Rung::Text),
    // THE CALENDAR'S BLOCKS, 2026-09-21 (`TASK-the-calendar-is-the-drawn-one`).
    // An event is a block in its calendar's colour: the hue's quiet stop as the
    // ground, `--color-text` as the title on it, and the hue itself as the rule
    // down its leading edge. The same card a notice is made of, one role over:
    // the arrangement is `--color-<role>` on `--color-<role>-quiet` with
    // `--color-text` on the fill, eight pairs up, with `--tint-*` in the role's
    // place.
    //
    // **The text at 4.5 and the rule at 3.0, and the rule is a `Rung::Mark`.**
    // A 2px rule down the edge of a block is a user-interface component, which
    // is the 3:1 rung WCAG 2.1's 1.4.11 states, and it stands beside the title
    // rather than being read as one. `Rung::Mark` is a second decision on top
    // of that and it is deliberate: unlike the dock's six, whose lift had to be
    // argued for, these are held at the increased-contrast 4.5 and Lc 60 with
    // enormous headroom, because the hues move one ladder stop AWAY from these
    // fills in both of those scopes while the fills do not move at all. Dark +
    // more contrast reads **8.57 to 9.11** at Lc -68.0 to -73.6; light + more
    // contrast reads **8.58 to 9.20** at Lc 83.0 to 84.1. There is no reading
    // of *more contrast* under which a calendar's colours are exempt, and no
    // cost to saying so.
    ("--color-text", "--tint-red-quiet", 4.5, Rung::Text),
    ("--color-text", "--tint-orange-quiet", 4.5, Rung::Text),
    ("--color-text", "--tint-green-quiet", 4.5, Rung::Text),
    ("--color-text", "--tint-blue-quiet", 4.5, Rung::Text),
    ("--color-text", "--tint-violet-quiet", 4.5, Rung::Text),
    ("--tint-red", "--tint-red-quiet", 3.0, Rung::Mark),
    ("--tint-orange", "--tint-orange-quiet", 3.0, Rung::Mark),
    ("--tint-green", "--tint-green-quiet", 3.0, Rung::Mark),
    ("--tint-blue", "--tint-blue-quiet", 3.0, Rung::Mark),
    ("--tint-violet", "--tint-violet-quiet", 3.0, Rung::Mark),
    // The stoplights are fills too, and since 2026-09-21 they are not those
    // three tokens any more: the state trio is picked for words at one ladder
    // stop, and the owner read the result as a flat red beside two vivid
    // neighbours. The lights take each hue's cusp stop instead, the same in
    // both themes — so their ink is one colour in both themes, and these three
    // pairs are what says it can still be read on all three.
    (
        "--frame-control-mark",
        "--frame-close",
        4.5,
        Rung::MarkFenced,
    ),
    (
        "--frame-control-mark",
        "--frame-minimise",
        4.5,
        Rung::MarkFenced,
    ),
    (
        "--frame-control-mark",
        "--frame-maximise",
        4.5,
        Rung::MarkFenced,
    ),
    // The reserved system hue names the trust surface; if it cannot be read it
    // cannot do that job.
    ("--color-system", "--color-bg", 4.5, Rung::Text),
    ("--color-system", "--color-surface", 4.5, Rung::Text),
    // THE DESK IS A DRAWN GROUND and a drawn ground has no single colour, so
    // `--color-bg` above stopped being the whole answer for anything sitting on
    // it (`TASK-the-desk-is-a-drawn-ground-and-not-a-flat-colour`, 2026-09-21).
    // `DEC-0047` measured its pairs against one flat ground per theme; the rule
    // it stated for a panel — *a claim about a worst case is not a guess* —
    // applies here with the advantage that this ground's extremes are known,
    // because they are tokens.
    //
    // All four stops, not "the lightest one", and that is the point. The text on
    // the desk is light on dark and dark on light, so the worst case is the
    // ground's *lightest* point in one theme and its *darkest* in the other —
    // two different tokens, in a list that is walked identically in every scope.
    // Declaring the extremes rather than the extreme means the gate keeps
    // answering the question after somebody moves a stop: every pixel of the
    // composition is a blend of these four, so whichever of them is the worst
    // case, it is measured.
    //
    // One foreground, because the desk carries one piece of text — the
    // empty-desk sentence. It is `--color-text-secondary` and it moved there on
    // this date: at `--color-text-tertiary` it reads 4.32 on `--desk-glow-warm`
    // in dark and 4.31 on `--desk-horizon` in light, both under AA, against 5.31
    // and 4.63 on the flat base. Same trade `DEC-0047` made for the menubar's
    // DID over a material, arriving from the other side: the tertiary tier is
    // correct on a ground that does not move.
    ("--color-text-secondary", "--desk-ground", 4.5, Rung::Text),
    ("--color-text-secondary", "--desk-horizon", 4.5, Rung::Text),
    (
        "--color-text-secondary",
        "--desk-glow-warm",
        4.5,
        Rung::Text,
    ),
    (
        "--color-text-secondary",
        "--desk-glow-cool",
        4.5,
        Rung::Text,
    ),
];

/// **The desk's grain, as a ceiling on the amount rather than a picture of it.**
///
/// `TASK-the-grain-on-the-desk-is-the-compositors`, 2026-09-21. The compositor
/// adds a zero-mean per-pixel term to the desk's own colour — `--desk-grain`,
/// peak to peak, in the 0..1 channel space it composites in — so the ground the
/// empty-desk sentence sits on is not the four stops above any more. It is each
/// of them plus or minus half of that amount, and the half that moves a stop
/// *toward* the text is the worst case.
///
/// So the desk pairs are measured twice: at the stop, and at the stop's worst
/// grained pixel. This is the same move `DESK_STOPS` made one unit earlier —
/// *a claim about a worst case is not a guess* — applied to a term that is a
/// number rather than a colour. Its value is that the amount now has a ceiling
/// somebody raising it will run into: the tightest desk pair in this file is
/// dark's `--color-text-secondary on --desk-glow-warm`, and it is the pair that
/// fails first. At `--desk-grain: 0.02` — the artboard's amount, which the token
/// carries since 2026-09-21 — that pair reads **5.62** against a 4.5 floor,
/// where the stop itself reads 5.82. (At the `0.07` this token briefly held, by
/// reading the artboard's SVG *opacity* as an amplitude, the same pair read
/// 5.15: the ceiling was doing its job while the number under it was wrong,
/// which is the limit of what a gate on one number can tell you.)
///
/// **Only the bare desk pairs, and deliberately not the material-over-desk
/// ones.** A panel's ground is this desk *blurred*, and the blur is the one
/// operation that removes a zero-mean per-pixel term: a gaussian over noise
/// averages it away, so a grain peak measured under a panel would be a worst
/// case the compositor cannot produce. Overstating a worst case reads as rigour
/// and costs real contrast headroom, which is the trade `DEC-0047` already
/// refused in the other direction.
const DESK_GRAIN: &str = "--desk-grain";

/// The drawn desk's four stops, in the order they are declared.
///
/// Every pixel of the ground is a blend of these, so a panel over the desk is a
/// material over one of them at worst — which is what makes them usable as
/// backdrops beside pure white and pure black below.
const DESK_STOPS: &[&str] = &[
    "--desk-ground",
    "--desk-horizon",
    "--desk-glow-warm",
    "--desk-glow-cool",
];

/// A foreground token, a translucent material, a backdrop, and the floor.
///
/// The ground is the material composited over the backdrop, which is what a
/// panel actually puts behind its text. Two backdrops, because there are
/// exactly two worst cases and every real one is between them.
///
/// `--color-text-tertiary` is deliberately absent and its absence is load
/// bearing: at 5.31 on the flat ground it has no headroom for any translucency
/// at all, so a panel does not carry it. `ui/tokens.css` under PANEL has the
/// measurement, and the shell's menubar moved its DID off that tier on the same
/// day. Adding the pair here without moving the text would fail this gate, which
/// is the order those two facts should be discovered in.
const COMPOSITE_PAIRS: &[(&str, &str, f64, Rung)] = &[
    ("--color-text", "--panel-material", 4.5, Rung::Text),
    (
        "--color-text-secondary",
        "--panel-material",
        4.5,
        Rung::Text,
    ),
    // THE DOCK'S TINTED GLYPHS, 2026-09-21
    // (`TASK-the-shell-draws-its-glyphs-from-one-sheet-and-the-dock-style-is-a-setting`).
    // One hue per system app, drawn on the pill — which is `--panel-material`
    // over whatever the compositor already put under it, so these belong here
    // beside the panel's text rather than in `PAIRS`, and for the same reason:
    // a translucent token skipped as "depends what is behind it" would be the
    // whole of a dock going unmeasured.
    //
    // **At 3.0 and at `Rung::Mark`, and both halves of that are deliberate.** A
    // glyph is a user-interface *component*, which is the 3:1 rung WCAG 2.1's
    // 1.4.11 states and APCA's Lc 45 answers to — it is a picture of what a
    // launcher opens, standing beside nothing it has to be read *against*. And
    // `Rung::Mark`, so the increased-contrast scopes do not raise it to AAA:
    // that floor is for words, and there is no semantic re-map that would lift
    // a hue without taking the hue away.
    //
    // **The declared 3.0 is the default scopes' floor, not every scope's**, and
    // that changed on 2026-09-21
    // (`TASK-a-launcher-mark-is-held-to-the-non-text-rung-even-where-contrast-is-increased`).
    // In the two increased-contrast scopes these six are held at 4.5 and at Lc
    // 60, both enforced — a rung up, the way words go 4.5 -> 7.0 — because the
    // `--tint-*` roles they point at are Tier 2 and this axis does reach them.
    // That is the difference between these and the three stoplight pairs above,
    // which is why those are `Rung::MarkFenced` and these are not.
    //
    // These are the pairs that would fail first if somebody re-pointed a
    // `--tint-*` role at a stop nearer the ground; the tightest of them today is
    // light's `--dock-tint-files`, which is why that one takes --orange-700
    // where the sheet drew 600.
    ("--dock-tint-ask", "--panel-material", 3.0, Rung::Mark),
    ("--dock-tint-terminal", "--panel-material", 3.0, Rung::Mark),
    ("--dock-tint-files", "--panel-material", 3.0, Rung::Mark),
    ("--dock-tint-contacts", "--panel-material", 3.0, Rung::Mark),
    ("--dock-tint-calendar", "--panel-material", 3.0, Rung::Mark),
    ("--dock-tint-settings", "--panel-material", 3.0, Rung::Mark),
];

/// The two backdrops a panel's worst case is measured over.
const WORST_BACKDROPS: &[(&str, [f64; 3])] = &[
    ("pure white", [1.0, 1.0, 1.0]),
    ("pure black", [0.0, 0.0, 0.0]),
];

/// **The lower material, and the backdrops it is allowed to be measured over.**
///
/// `TASK-the-dock-the-menubar-and-a-windows-chrome-are-materials`, 2026-09-24.
/// `--panel-material-desk` is what the compositor lays under a panel only when
/// it knows the desk's own ground is the only thing its blur can read — no
/// other layer's pixels and no other layer's shadow, a window's or another
/// panel's, within the blur's reach of the panel's rect this frame
/// (`anything_under` in `core/kuid`) — so its proof is
/// against the desk's four stops and **not** against pure white and pure
/// black. That is the whole point of the second token: the same guarantee,
/// measured against the backdrop that is really there rather than the worst
/// one imaginable.
///
/// **And under the dock's own shadow**, which is then the one thing the
/// compositor itself puts beneath a panel besides the desk (any other layer's
/// shadow within reach sends the panel to the floor). The pill's shadow is drawn
/// before its backdrop is taken, so the blurred ground under the dock is the
/// desk darkened by `--dock-shadow`'s colour at its alpha — for most of the
/// pill's interior at nearly the full alpha, since the shadow's rect is the
/// pill's own shifted a few pixels down. On light that is the darkest pixel a
/// panel can sit over, and it is darker than any of the four stops. A proof
/// that stopped at the stops would be a worst case the compositor can exceed.
///
/// The same rungs as [`COMPOSITE_PAIRS`] and for the same reasons, and the
/// tertiary tier is absent for the same reason it is absent there.
const DESK_COMPOSITE_PAIRS: &[(&str, &str, f64, Rung)] = &[
    ("--color-text", "--panel-material-desk", 4.5, Rung::Text),
    (
        "--color-text-secondary",
        "--panel-material-desk",
        4.5,
        Rung::Text,
    ),
    ("--dock-tint-ask", "--panel-material-desk", 3.0, Rung::Mark),
    (
        "--dock-tint-terminal",
        "--panel-material-desk",
        3.0,
        Rung::Mark,
    ),
    (
        "--dock-tint-files",
        "--panel-material-desk",
        3.0,
        Rung::Mark,
    ),
    (
        "--dock-tint-contacts",
        "--panel-material-desk",
        3.0,
        Rung::Mark,
    ),
    (
        "--dock-tint-calendar",
        "--panel-material-desk",
        3.0,
        Rung::Mark,
    ),
    (
        "--dock-tint-settings",
        "--panel-material-desk",
        3.0,
        Rung::Mark,
    ),
];

/// The shadow the compositor draws under the dock's pill — the one thing
/// besides the desk it puts beneath a panel.
const DOCK_SHADOW: &str = "--dock-shadow";

/// Parse `--name: value;` declarations out of one selector block.
///
/// The selector is matched **at the start of a line**, because this file
/// discusses its own selectors in prose: `[data-theme="light"]` first appears in
/// a comment 263 lines above the block it names, and a plain `find` picked that
/// one and returned an empty scope. Every light-theme pair then came back
/// "unresolved" — which the checker reported rather than passing over, and is
/// why that path exits non-zero instead of quietly checking fewer pairs.
fn block(css: &str, selector: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(start) = css
        .match_indices(selector)
        .find(|(i, _)| *i == 0 || css.as_bytes()[i - 1] == b'\n')
        .map(|(i, _)| i)
    else {
        return out;
    };
    let Some(open) = css[start..].find('{') else {
        return out;
    };
    let body_start = start + open + 1;
    let Some(close) = css[body_start..].find("\n}") else {
        return out;
    };
    for line in css[body_start..body_start + close].lines() {
        let line = line.split("/*").next().unwrap_or(line).trim();
        for decl in line.split(';') {
            let Some((k, v)) = decl.split_once(':') else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            if k.starts_with("--") && !v.is_empty() {
                out.insert(k.to_string(), v.to_string());
            }
        }
    }
    out
}

/// Follow `var(--x)` until a literal falls out. `None` for a value that is not a
/// resolvable opaque colour — translucent, a shadow, a missing reference.
fn resolve(
    name: &str,
    scope: &HashMap<String, String>,
    tier1: &HashMap<String, String>,
) -> Option<[f64; 3]> {
    let mut value = scope.get(name).or_else(|| tier1.get(name))?.clone();
    for _ in 0..8 {
        let v = value.trim().to_string();
        if let Some(hex) = v.strip_prefix('#') {
            return hex_rgb(hex);
        }
        let inner = v
            .strip_prefix("var(")?
            .strip_suffix(')')?
            .trim()
            .to_string();
        // `var(--x, fallback)` — take the reference, which is what renders.
        let key = inner.split(',').next()?.trim().to_string();
        value = scope.get(&key).or_else(|| tier1.get(&key))?.clone();
    }
    None
}

/// A token whose value is a bare number, with its `var(--…)` chain followed —
/// `--desk-grain` and nothing else today.
///
/// Separate from [`resolve`] because that one ends at a hex colour and this one
/// ends at a float; a single function returning "whatever fell out" is how a
/// length gets measured as a colour.
fn resolve_number(
    name: &str,
    scope: &HashMap<String, String>,
    tier1: &HashMap<String, String>,
) -> Option<f64> {
    let mut value = scope.get(name).or_else(|| tier1.get(name))?.clone();
    for _ in 0..8 {
        let v = value.trim().to_string();
        let Some(inner) = v.strip_prefix("var(").and_then(|x| x.strip_suffix(')')) else {
            return v.parse::<f64>().ok().filter(|n| n.is_finite() && *n >= 0.0);
        };
        let key = inner.split(',').next()?.trim().to_string();
        value = scope.get(&key).or_else(|| tier1.get(&key))?.clone();
    }
    None
}

/// One stop moved by the grain's peak, **toward** the text that sits on it —
/// which is the direction that costs contrast and therefore the one measured.
///
/// The peak is half of `--desk-grain`, because the term is peak-to-peak: the
/// compositor's grain runs `[-amp/2, +amp/2]`, so two neighbouring desk pixels
/// differ by at most the amount and either one is at most half of it from the
/// stop. Added in the same 0..1 channel space the compositor works in, which is
/// sRGB-encoded and is what [`resolve`] already hands back.
fn at_grain_peak(stop: [f64; 3], text: [f64; 3], grain: f64) -> [f64; 3] {
    let peak = grain / 2.0;
    let toward = if luminance(text) > luminance(stop) {
        peak
    } else {
        -peak
    };
    [
        (stop[0] + toward).clamp(0.0, 1.0),
        (stop[1] + toward).clamp(0.0, 1.0),
        (stop[2] + toward).clamp(0.0, 1.0),
    ]
}

/// `color-mix(in srgb, var(--x) <pct>%, transparent)` — the colour, and the
/// alpha separately.
///
/// The token file's own idiom for a translucent component token, and the only
/// shape accepted: a component token that named a colour **by value** would be
/// the direction the three tiers forbid, and `DEC-0047` found one that had been
/// shipping for months precisely because nothing could see it. `core/kuid`
/// parses the same declaration the same way, for the compositor's half of this.
fn resolve_mix(
    name: &str,
    scope: &HashMap<String, String>,
    tier1: &HashMap<String, String>,
) -> Option<([f64; 3], f64)> {
    let value = scope
        .get(name)
        .or_else(|| tier1.get(name))?
        .trim()
        .to_string();
    let inner = value.strip_prefix("color-mix(")?.strip_suffix(')')?;
    let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
    let [space, first, second] = parts.as_slice() else {
        return None;
    };
    if *space != "in srgb" || *second != "transparent" {
        return None;
    }
    let (reference, percent) = first.rsplit_once(' ')?;
    let alpha: f64 = percent.trim().strip_suffix('%')?.parse().ok()?;
    let key = reference
        .trim()
        .strip_prefix("var(")?
        .strip_suffix(')')?
        .split(',')
        .next()?
        .trim();
    Some((resolve(key, scope, tier1)?, (alpha / 100.0).clamp(0.0, 1.0)))
}

/// A `box-shadow` token's colour and alpha, with its `var(--…)` chain followed —
/// `--dock-shadow` → `--elevation-dock` → `0 4px 12px rgba(0, 0, 0, 0.40)`.
///
/// Only the colour: the offset and the blur say where the shadow is, and under
/// the pill's own rect it is everywhere, so the worst pixel is the shadow at
/// its full alpha over the stop. Separate from [`resolve`] for the reason
/// [`resolve_number`] is — a function returning whatever fell out is how a
/// length gets measured as a colour.
fn resolve_shadow(
    name: &str,
    scope: &HashMap<String, String>,
    tier1: &HashMap<String, String>,
) -> Option<([f64; 3], f64)> {
    let mut value = scope.get(name).or_else(|| tier1.get(name))?.clone();
    for _ in 0..8 {
        let v = value.trim().to_string();
        let Some(inner) = v.strip_prefix("var(").and_then(|x| x.strip_suffix(')')) else {
            let start = v.find("rgba(")?;
            let end = v[start..].find(')')? + start;
            let parts: Vec<&str> = v[start + 5..end].split(',').map(str::trim).collect();
            let [r, g, b, a] = parts.as_slice() else {
                return None;
            };
            let c = |s: &str| s.parse::<f64>().ok().map(|n| n / 255.0);
            return Some((
                [c(r)?, c(g)?, c(b)?],
                a.parse::<f64>().ok()?.clamp(0.0, 1.0),
            ));
        };
        let key = inner.split(',').next()?.trim().to_string();
        value = scope.get(&key).or_else(|| tier1.get(&key))?.clone();
    }
    None
}

/// Source-over of an opaque colour at `alpha` onto an opaque backdrop.
fn composite(over: [f64; 3], alpha: f64, under: [f64; 3]) -> [f64; 3] {
    [
        over[0] * alpha + under[0] * (1.0 - alpha),
        over[1] * alpha + under[1] * (1.0 - alpha),
        over[2] * alpha + under[2] * (1.0 - alpha),
    ]
}

fn hex_rgb(hex: &str) -> Option<[f64; 3]> {
    if hex.len() != 6 {
        return None;
    }
    let c = |i: usize| {
        u8::from_str_radix(&hex[i..i + 2], 16)
            .ok()
            .map(|b| b as f64 / 255.0)
    };
    Some([c(0)?, c(2)?, c(4)?])
}

/// WCAG 2.1 relative luminance.
fn luminance(rgb: [f64; 3]) -> f64 {
    let lin = |c: f64| {
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(rgb[0]) + 0.7152 * lin(rgb[1]) + 0.0722 * lin(rgb[2])
}

fn ratio(a: [f64; 3], b: [f64; 3]) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

// ---------------------------------------------------------------------------
// APCA — SAPC-8, 0.0.98G-series constant 4g (the "W3 compatible" constants).
//
// Transcribed from the APCA-W3 reference implementation's `SA98G` object,
// <https://github.com/Myndex/apca-w3>, `src/apca-w3.js`. Every constant is
// named, and named the same as it is there, for two reasons: a magic number in
// a perceptual model is exactly the kind of thing a later reader "simplifies"
// into a different model, and a constant set carries a version — these are the
// 4g constants for a 2.4 exponent, and mixing them with another set silently
// produces numbers that are not APCA's.
// ---------------------------------------------------------------------------

/// Exponent emulating actual monitor perception. **Not** WCAG 2's piecewise
/// transfer curve: APCA has no 0.03928 knee, which is one of the two reasons
/// the two columns cannot be derived from each other.
const APCA_MAIN_TRC: f64 = 2.4;

/// sRGB luminance coefficients. Also **not** WCAG 2's (0.2126 / 0.7152 /
/// 0.0722) — near, deliberately more precise, and the second reason above.
const APCA_S_RCO: f64 = 0.2126729;
const APCA_S_GCO: f64 = 0.7151522;
const APCA_S_BCO: f64 = 0.0721750;

/// The polarity exponents. `NORM_*` is dark text on a light ground (BoW),
/// `REV_*` is light text on a dark one (WoB) — four numbers rather than two
/// because the model is asymmetric, which is the whole of what it adds here.
const APCA_NORM_BG: f64 = 0.56;
const APCA_NORM_TXT: f64 = 0.57;
const APCA_REV_TXT: f64 = 0.62;
const APCA_REV_BG: f64 = 0.65;

/// Clamps and scalers. The black soft clamp keeps very dark grounds from
/// running away; the low clip rolls contrast to zero rather than letting it
/// reverse polarity near the bottom.
const APCA_BLK_THRS: f64 = 0.022;
const APCA_BLK_CLMP: f64 = 1.414;
const APCA_SCALE_BOW: f64 = 1.14;
const APCA_SCALE_WOB: f64 = 1.14;
const APCA_LO_BOW_OFFSET: f64 = 0.027;
const APCA_LO_WOB_OFFSET: f64 = 0.027;
const APCA_DELTA_Y_MIN: f64 = 0.0005;
const APCA_LO_CLIP: f64 = 0.1;

/// APCA's reference thresholds, in `|Lc|`, as the APCA project publishes them.
///
/// `BODY` is the one this gate reports against, because `ui/tokens.css`
/// declares colours and not sizes: a token file cannot say whether the words a
/// pair will carry are 16px or 11px, so the gate holds every pair it has to the
/// body rung and prints the other two for a reader who knows the role. The
/// mapping is written out in `TASK-contrast-check-reads-apca-beside-wcag`.
const APCA_BODY: f64 = 60.0;
const APCA_SMALL_BODY: f64 = 75.0;
const APCA_LARGE_OR_NON_TEXT: f64 = 45.0;

/// APCA's screen luminance `Y`. Channels arrive already 0..1, which is
/// `sRGBtoY`'s `chan / 255.0` done by `hex_rgb` — and, for a composite, a value
/// that was never an 8-bit channel at all, which is fine: the reference divides
/// by 255 to reach exactly this range.
fn apca_y(rgb: [f64; 3]) -> f64 {
    let e = |c: f64| c.clamp(0.0, 1.0).powf(APCA_MAIN_TRC);
    APCA_S_RCO * e(rgb[0]) + APCA_S_GCO * e(rgb[1]) + APCA_S_BCO * e(rgb[2])
}

/// Lightness contrast `Lc` of text on a ground, **polarity kept**.
///
/// Positive is dark text on a light ground, negative is light text on a dark
/// one, and the two are not interchangeable — swapping the arguments is a
/// different measurement, not a sign flip. The sign is the reason this column
/// was added, so nothing here or in the print takes its absolute value; only
/// the threshold comparison does.
fn apca_lc(text: [f64; 3], ground: [f64; 3]) -> f64 {
    let soft_clamp = |y: f64| {
        if y > APCA_BLK_THRS {
            y
        } else {
            y + (APCA_BLK_THRS - y).powf(APCA_BLK_CLMP)
        }
    };
    let txt = soft_clamp(apca_y(text));
    let bg = soft_clamp(apca_y(ground));

    // Two colours this close are not a contrast, they are noise.
    if (bg - txt).abs() < APCA_DELTA_Y_MIN {
        return 0.0;
    }

    let out = if bg > txt {
        let sapc = (bg.powf(APCA_NORM_BG) - txt.powf(APCA_NORM_TXT)) * APCA_SCALE_BOW;
        if sapc < APCA_LO_CLIP {
            0.0
        } else {
            sapc - APCA_LO_BOW_OFFSET
        }
    } else {
        let sapc = (bg.powf(APCA_REV_BG) - txt.powf(APCA_REV_TXT)) * APCA_SCALE_WOB;
        if sapc > -APCA_LO_CLIP {
            0.0
        } else {
            sapc + APCA_LO_WOB_OFFSET
        }
    };
    out * 100.0
}

/// What one pass over every scope accumulates: the two-column report, the WCAG
/// failures that exit non-zero, and the APCA findings that do not.
///
/// One type rather than four locals because the two models are measured in the
/// same place on purpose — a later reader who wants to add a pair should not be
/// able to add it to one column and not the other.
#[derive(Default)]
struct Tally {
    /// One line per pair, both numbers, grouped under a scope heading.
    lines: Vec<String>,
    /// Below a floor its scope enforces. These, and only these, fail the build.
    failures: Vec<String>,
    /// Clears WCAG 2 AA and falls under APCA's body threshold, in a scope where
    /// APCA is advisory. Never a failure.
    findings: Vec<String>,
    /// Clears the body rung in a scope that enforces it, and falls under the
    /// small rung. Printed so that 75 is visible rather than quietly dropped.
    small_rung: Vec<String>,
    checked: usize,
}

impl Tally {
    /// Measure one pair under both models and file it.
    ///
    /// The APCA finding is deliberately `else if`: a pair already below the WCAG
    /// floor is a failure, and reporting it twice would make the advisory list
    /// read as a second opinion on the same defect instead of what it is — the
    /// pairs the first model says are fine.
    fn measure(
        &mut self,
        theme: &str,
        label: &str,
        text: [f64; 3],
        ground: [f64; 3],
        floor: Floor,
    ) {
        self.checked += 1;
        let r = ratio(text, ground);
        let lc = apca_lc(text, ground);
        self.lines
            .push(format!("    {label:<60} {r:>6.2}   Lc {lc:>7.1}"));
        if r < floor.wcag {
            self.failures.push(format!(
                "  {theme}: {label} — WCAG {r:.2}, needs {:.1}",
                floor.wcag
            ));
            return;
        }
        match floor.apca {
            // APCA enforced: under the body rung is a failure like any other,
            // and between the rungs is a line under the list rather than
            // silence — the small rung is not this gate's floor and is not
            // therefore nothing.
            Some(min) if lc.abs() < min => self.failures.push(format!(
                "  {theme}: {label} — WCAG {r:.2} clears {:.1}, APCA Lc {lc:.2} under {min:.0}",
                floor.wcag
            )),
            Some(_) if lc.abs() < APCA_SMALL_BODY => self
                .small_rung
                .push(format!("  {theme}: {label} — Lc {lc:.2}")),
            Some(_) => {}
            None if lc.abs() < APCA_BODY => self
                .findings
                .push(format!("  {theme}: {label} — WCAG {r:.2} (AA), Lc {lc:.2}")),
            None => {}
        }
    }

    /// Print the advisory column's verdict. Never exits.
    fn report_apca(&self) {
        println!(
            "APCA reference thresholds, in |Lc|: {APCA_BODY:.0} body text,\n\
             {APCA_SMALL_BODY:.0} small or thin text, {APCA_LARGE_OR_NON_TEXT:.0} large headings or non-text.\n\
             Every pair above is held to the body rung: a token file declares\n\
             colours and not sizes, so the gate cannot know which rung a pair\n\
             will land on and takes the one that is safe to be wrong about.\n\
             In the increased-contrast scopes that rung FAILS the build; in the\n\
             default scopes it is advisory and is the list below."
        );
        if !self.small_rung.is_empty() {
            println!(
                "\nIn an enforced scope, {} pair(s) clear Lc {APCA_BODY:.0} and fall under the small\n\
                 rung of {APCA_SMALL_BODY:.0}. Not a failure — the floor adopted for those scopes is the body\n\
                 rung — and printed so that the higher rung is visible to whoever next sets\n\
                 small text in one of these pairs:",
                self.small_rung.len()
            );
            for s in &self.small_rung {
                println!("{s}");
            }
            println!();
        }
        if self.findings.is_empty() {
            println!("APCA: OK — every pair that meets WCAG AA also reaches Lc {APCA_BODY:.0}.\n");
            return;
        }
        println!(
            "\nAPCA (advisory, does not fail this build): {} pair(s) meet WCAG 2 AA and fall\n\
             under Lc {APCA_BODY:.0} —",
            self.findings.len()
        );
        for f in &self.findings {
            println!("{f}");
        }
        println!(
            "\nA pair in that list is the case the second model exists for: the ratio says\n\
             fine and the eye says otherwise. Read it before shipping the surface it is on.\n"
        );
    }
}

pub fn run() {
    let path = Path::new("ui/tokens.css");
    let css = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("contrast-check: cannot read {}: {e}", path.display());
            std::process::exit(1);
        }
    };

    // Tier 1 lives on the first `:root`; the semantic layers re-map on top.
    let tier1 = block(&css, ":root {");

    // **Every combination of both axes**, not just the themes (`DEC-0062`).
    //
    // This enumerated two scopes by name until 2026-09-10. When the form-factor
    // axis was added, a whole new colour mapping could have shipped without a
    // single pair being measured against it and this gate would have gone on
    // printing OK — a check that passes because it is not looking is worse than
    // no check, because it is also reassuring.
    //
    // A scope is a *stack* of blocks, innermost last, because a form-factor block
    // re-maps only what it changes and inherits the rest from its theme. Handheld
    // light is deliberately just the light theme: `ui/ink` is dark, so there
    // is nothing ruled to overlay. It is still listed, so the pairs a phone shows
    // in light are measured rather than assumed.
    let dark = block(&css, ":root, [data-theme=\"dark\"]");
    let light = block(&css, "[data-theme=\"light\"]");
    let handheld_dark = block(
        &css,
        ":root[data-form-factor=\"handheld\"],\n[data-theme=\"dark\"][data-form-factor=\"handheld\"]",
    );
    // **Tier 3 is a layer of every scope, since 2026-09-21.** It is one block at
    // the foot of the file — `:root, [data-theme], [data-form-factor]` — and no
    // theme block declares any name it declares, so it flattens on top of each
    // theme the way source order puts it in a browser. Nothing in it was
    // checkable until now: a component token is exactly where a fill and the ink
    // it carries meet, and the three stoplights are the pairs that made that
    // gap visible (the checker reported them "unresolved", which is the path
    // this file already says is worse than a failure because it reads as a pass).
    let component = block(
        &css,
        ":root, [data-theme], [data-form-factor], [data-contrast]",
    );
    // **The third axis, 2026-09-21** — one block per theme, re-mapping the
    // reading roles further from a ground that does not move
    // (`TASK-an-increased-contrast-theme-is-one-more-block`, `DEC-0062`'s
    // argument applied a third time).
    let more_dark = block(&css, "[data-contrast=\"more\"]");
    let more_light = block(&css, "[data-theme=\"light\"][data-contrast=\"more\"]");
    // **And the light theme stacks ON the dark block, which is what a browser
    // does.** That block's selector is `:root, [data-theme="dark"]`, and a root
    // element matches `:root` whatever its `data-theme` says — so in a
    // light-themed document both blocks apply and the later one wins only for
    // what it re-maps. The light scope was the light block alone until
    // 2026-09-21, which happened to resolve every pair because the light block
    // re-maps every token the list named. The first semantic token deliberately
    // NOT re-mapped there — `--color-ink-on-solid`, one colour in both themes
    // because the fill under it is one colour in both themes — came back
    // unresolved, and unresolved is the state this file already calls worse than
    // a failure.
    // **The increased-contrast scopes stack the same way the light one does**,
    // and the light arm stacks on the first block for the same reason: that
    // block's selector is a bare `[data-contrast="more"]`, which matches an
    // element in either theme — it has to be bare, because the shell writes
    // this attribute on a nested div and `data-theme=""` for dark, so an
    // anchored selector would match nothing the shell draws. A name the light
    // arm forgets to re-declare renders the dark theme's value on linen, and
    // this stack is what makes the gate see that rather than assume it away.
    let themes = [
        ("dark", vec![&dark, &component], Held::Aa),
        ("light", vec![&dark, &light, &component], Held::Aa),
        (
            "dark + handheld",
            vec![&dark, &handheld_dark, &component],
            Held::Aa,
        ),
        (
            "light + handheld",
            vec![&dark, &light, &component],
            Held::Aa,
        ),
        (
            "dark + more contrast",
            vec![&dark, &more_dark, &component],
            Held::AaaAndApca,
        ),
        (
            "light + more contrast",
            vec![&dark, &light, &more_dark, &more_light, &component],
            Held::AaaAndApca,
        ),
    ];

    // **Four axis combinations are deliberately not enumerated**, and this is
    // what keeps that honest rather than reassuring. The handheld block carries
    // `--screen-gutter` and nothing else since 2026-09-20, so
    // `dark + handheld + more contrast` would measure the colours
    // `dark + more contrast` already measures — the duplication
    // `TASK-two-contrast-scopes-measure-the-same-colours-twice` was filed for,
    // which this unit declined to double. The day that block declares a colour
    // again, the combinations it forms with this axis have to be enumerated,
    // and this says so on that day instead of quietly measuring fewer pairs.
    if handheld_dark.keys().any(|k| {
        [
            "--color-",
            "--fill-",
            "--panel-",
            "--mist-",
            "--elevation-",
            "--desk-",
        ]
        .iter()
        .any(|p| k.starts_with(p))
    }) {
        eprintln!(
            "contrast-check: the handheld block declares a colour again, so it is no longer\n\
             independent of the contrast axis — enumerate `handheld + more contrast` here."
        );
        std::process::exit(1);
    }

    let mut tally = Tally::default();
    let mut unresolved = Vec::new();

    for (theme, layers, held) in &themes {
        if layers.iter().any(|l| l.is_empty()) {
            eprintln!(
                "contrast-check: a block in the {theme} scope parsed empty — a selector moved"
            );
            std::process::exit(1);
        }
        // Flatten innermost-last, so a form-factor block wins over its theme for
        // the roles it re-maps and inherits the rest.
        let mut scope: HashMap<String, String> = HashMap::new();
        for layer in layers {
            for (k, v) in layer.iter() {
                scope.insert(k.clone(), v.clone());
            }
        }
        let scope = &scope;
        tally.lines.push(format!("  {theme}"));
        for (fg, bg, floor, rung) in PAIRS {
            let (Some(f), Some(b)) = (resolve(fg, scope, &tier1), resolve(bg, scope, &tier1))
            else {
                unresolved.push(format!("{theme}: {fg} on {bg}"));
                continue;
            };
            tally.measure(
                theme,
                &format!("{fg} on {bg}"),
                f,
                b,
                held.floor(*floor, *rung),
            );
            // **And the same stop with the compositor's grain on it** — see
            // `DESK_GRAIN`. The stop stays measured beside it, because the
            // number a person reads before moving a stop is the stop's, and the
            // number that stops them moving the *grain* is this one.
            if bg.starts_with("--desk-") {
                let Some(grain) = resolve_number(DESK_GRAIN, scope, &tier1) else {
                    unresolved.push(format!("{theme}: {fg} on {bg} at grain peak"));
                    continue;
                };
                tally.measure(
                    theme,
                    &format!("{fg} on {bg} at grain peak"),
                    f,
                    at_grain_peak(b, f, grain),
                    held.floor(*floor, *rung),
                );
            }
        }

        // **A material over the worst two backdrops there are.** The ground under
        // a panel is no longer one colour, so the pairs above cannot reach it and
        // a translucent token skipped as "depends on what is behind it" would be
        // the whole of a dock going unmeasured.
        for (fg, material, floor, rung) in COMPOSITE_PAIRS {
            let (Some(f), Some((m, alpha))) = (
                resolve(fg, scope, &tier1),
                resolve_mix(material, scope, &tier1),
            ) else {
                unresolved.push(format!("{theme}: {fg} on {material}"));
                continue;
            };
            for (name, backdrop) in WORST_BACKDROPS {
                tally.measure(
                    theme,
                    &format!("{fg} on {material} over {name}"),
                    f,
                    composite(m, alpha, *backdrop),
                    held.floor(*floor, *rung),
                );
            }
            // **And over the ground the dock actually sits on.** Pure white and
            // pure black bound every backdrop there is, including this one, so
            // these four cannot fail where those two pass — which is exactly
            // why they are worth printing. The dock's labels are the pairs
            // `TASK-the-desk-is-a-drawn-ground-and-not-a-flat-colour` names,
            // and a worst case wide enough to be safe is too wide to tell
            // anyone how much headroom the real desk leaves. A number measured
            // on the shipped ground is the one a person reads before moving a
            // stop.
            for stop in DESK_STOPS {
                let Some(backdrop) = resolve(stop, scope, &tier1) else {
                    unresolved.push(format!("{theme}: {fg} on {material} over {stop}"));
                    continue;
                };
                tally.measure(
                    theme,
                    &format!("{fg} on {material} over {stop}"),
                    f,
                    composite(m, alpha, backdrop),
                    held.floor(*floor, *rung),
                );
            }
        }
        // **The lower material over the ground it is actually allowed on** — the
        // desk's stops, each bare and each under the dock's shadow — and never
        // over pure white or pure black, which is what makes it the lower one.
        // See `DESK_COMPOSITE_PAIRS`.
        let dock_shadow = resolve_shadow(DOCK_SHADOW, scope, &tier1);
        for (fg, material, floor, rung) in DESK_COMPOSITE_PAIRS {
            let (Some(f), Some((m, alpha))) = (
                resolve(fg, scope, &tier1),
                resolve_mix(material, scope, &tier1),
            ) else {
                unresolved.push(format!("{theme}: {fg} on {material}"));
                continue;
            };
            for stop in DESK_STOPS {
                let Some(backdrop) = resolve(stop, scope, &tier1) else {
                    unresolved.push(format!("{theme}: {fg} on {material} over {stop}"));
                    continue;
                };
                tally.measure(
                    theme,
                    &format!("{fg} on {material} over {stop}"),
                    f,
                    composite(m, alpha, backdrop),
                    held.floor(*floor, *rung),
                );
                let Some((shadow, shadow_alpha)) = dock_shadow else {
                    unresolved.push(format!(
                        "{theme}: {fg} on {material} over {stop} under {DOCK_SHADOW}"
                    ));
                    continue;
                };
                tally.measure(
                    theme,
                    &format!("{fg} on {material} over {stop} under the dock's shadow"),
                    f,
                    composite(m, alpha, composite(shadow, shadow_alpha, backdrop)),
                    held.floor(*floor, *rung),
                );
            }
        }
    }

    // **Both numbers, every pair.** The second column is only useful to someone
    // looking at it beside the first: the whole finding APCA exists to surface
    // here is "this one passes and still reads badly", which is a statement about
    // two numbers and cannot be made by printing either alone.
    println!(
        "contrast-check: WCAG 2 ratio and APCA Lc for every declared pair.\n\
         Lc is signed — negative is light text on a dark ground.\n"
    );
    for line in &tally.lines {
        println!("{line}");
    }
    println!();

    if !unresolved.is_empty() {
        eprintln!(
            "contrast-check: {} pair(s) could not be resolved to opaque colours:",
            unresolved.len()
        );
        for u in &unresolved {
            eprintln!("  {u}");
        }
        eprintln!("\nA token that does not resolve is not checked, which is the same as not having a floor.");
        std::process::exit(1);
    }

    // **The advisory column reports before the gate rules**, and in both
    // directions: a finding is worth reading whether or not WCAG failed, and a
    // reader who only ever sees it on a red build learns it is part of the
    // failure. It is printed on stdout with the passes, not on stderr with the
    // failures, because it is not one.
    tally.report_apca();

    if tally.failures.is_empty() {
        println!(
            "contrast-check: OK — {} text pair(s) across {} scope(s). WCAG AA in the default\n\
             scopes; WCAG AAA ({WCAG_AAA:.0}:1) and APCA Lc {APCA_BODY:.0}, both enforced, in the {}\n\
             increased-contrast ones. Includes {} composite(s) of a panel's material over\n\
             pure white, pure black and each of the drawn desk's four stops, and {} of the\n\
             desk material over each stop bare and under the dock's shadow.",
            tally.checked,
            themes.len(),
            themes.iter().filter(|(_, _, h)| *h == Held::AaaAndApca).count(),
            COMPOSITE_PAIRS.len() * (WORST_BACKDROPS.len() + DESK_STOPS.len()) * themes.len(),
            DESK_COMPOSITE_PAIRS.len() * DESK_STOPS.len() * 2 * themes.len()
        );
        return;
    }

    eprintln!(
        "contrast-check: {} pair(s) below their floor:\n",
        tally.failures.len()
    );
    for f in &tally.failures {
        eprintln!("{f}");
    }
    eprintln!(
        "\nContrast is a property of a pair, so a token is never \"AA\" on its own — it is AA\n\
         against something. Fix the ramp stop, not the pair list. A pair failing only in a\n\
         `more contrast` scope is a stop in that block, not in the theme under it: those two\n\
         blocks are held at AAA and at APCA's body rung, which is what they exist for."
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published reference values this file's APCA half is pinned to.
    ///
    /// Source: the APCA-W3 reference implementation — `src/apca-w3.js` at
    /// <https://github.com/Myndex/apca-w3>, which names its constant set in its
    /// own header as *"SAPC-8, 0.0.98G-series constant 4g"*. The numbers below
    /// were produced by running that file's `APCAcontrast(sRGBtoY(txt),
    /// sRGBtoY(bg))` on each pair, unmodified, on 2026-09-21; they are the
    /// same values the APCA project quotes for these colours (black on white is
    /// its well-known Lc 106.04, white on black its Lc -107.88).
    ///
    /// They are here rather than in a comment because a perceptual model
    /// transcribed by hand is exactly the kind of code that is *almost* right:
    /// swap `revTXT` and `revBG`, or reach for WCAG's luminance coefficients
    /// next door, and every number still looks plausible. Only a reference
    /// vector catches that, and only if it is checked.
    ///
    /// `(text, ground, Lc)`.
    const REFERENCE: &[(&str, &str, f64)] = &[
        // The two polarity anchors.
        ("000000", "ffffff", 106.04067321268862),
        ("ffffff", "000000", -107.88473318309848),
        // Mid tones, both polarities.
        ("888888", "ffffff", 63.056469930209424),
        ("ffffff", "888888", -68.54146436644962),
        ("000000", "aaaaaa", 58.146262578561334),
        ("aaaaaa", "000000", -56.24113336839742),
        ("112233", "ddeeff", 91.66830811481631),
        ("ddeeff", "112233", -93.06770049484275),
    ];

    /// Reference values are quoted to full float precision; this is loose
    /// enough for a different language's `pow` and far tighter than any
    /// transcription error would survive.
    const EPSILON: f64 = 1e-6;

    fn lc(text: &str, ground: &str) -> f64 {
        apca_lc(hex_rgb(text).unwrap(), hex_rgb(ground).unwrap())
    }

    #[test]
    fn black_on_white_is_the_published_reference_value() {
        assert!((lc("000000", "ffffff") - 106.04067321268862).abs() < EPSILON);
    }

    #[test]
    fn white_on_black_is_the_published_reference_value() {
        // Negative, and not the mirror of the line above: 107.88 against
        // 106.04 is the polarity asymmetry that is the entire reason this
        // column sits beside WCAG 2's symmetric ratio.
        assert!((lc("ffffff", "000000") + 107.88473318309848).abs() < EPSILON);
    }

    #[test]
    fn every_reference_pair_matches_the_published_value() {
        for (text, ground, expected) in REFERENCE {
            let got = lc(text, ground);
            assert!(
                (got - expected).abs() < EPSILON,
                "#{text} on #{ground}: expected Lc {expected}, got {got}"
            );
        }
    }

    #[test]
    fn the_low_clip_fires_on_one_polarity_and_not_the_other() {
        // The same two greys, swapped. `#777` on `#888` rolls to exactly zero
        // under the BoW low clip; `#888` on `#777` does not, and reports -7.32.
        // A symmetric implementation gives the same magnitude both ways and
        // passes every threshold test above, so this is the vector that catches
        // one.
        assert_eq!(lc("777777", "888888"), 0.0);
        assert!((lc("888888", "777777") + 7.320188639714409).abs() < EPSILON);
    }

    #[test]
    fn two_identical_colours_are_not_a_contrast() {
        // `deltaYmin`: below it the model returns zero rather than a number
        // that would round to one.
        assert_eq!(lc("808080", "808080"), 0.0);
    }

    #[test]
    fn the_wcag_column_is_untouched_by_the_second_model() {
        // 21:1 is WCAG 2's own ceiling, and this file's floor of 4.5 is read
        // against it. Pinned here because "no behaviour change to the WCAG
        // side" is a claim, and a claim in a commit message is not a check.
        let (black, white) = (hex_rgb("000000").unwrap(), hex_rgb("ffffff").unwrap());
        assert!((ratio(black, white) - 21.0).abs() < 1e-9);
        assert!((ratio(white, black) - 21.0).abs() < 1e-9);
    }

    #[test]
    fn a_finding_is_a_pair_that_passes_wcag_and_fails_apca() {
        // The gate's rule, on three pairs that sit in each of its cases.
        // `#767676` on black is the canonical one and the reason this unit
        // exists: WCAG 2 calls it 4.62, comfortably AA, and APCA reads it at
        // Lc -30.1 — under half the body rung. That is dark-mode grey text,
        // which is most of this product's secondary surface.
        let mut tally = Tally::default();
        let white = hex_rgb("ffffff").unwrap();
        let black = hex_rgb("000000").unwrap();

        // Passes both: WCAG 7.00, Lc 84.3.
        let aa = Held::Aa.floor(4.5, Rung::Text);
        tally.measure(
            "test",
            "dark grey on white",
            hex_rgb("595959").unwrap(),
            white,
            aa,
        );
        assert!(tally.findings.is_empty(), "{:?}", tally.findings);
        assert!(tally.failures.is_empty(), "{:?}", tally.failures);

        // Passes WCAG, falls under Lc 60 — the finding.
        tally.measure(
            "test",
            "mid grey on black",
            hex_rgb("767676").unwrap(),
            black,
            aa,
        );
        assert_eq!(tally.findings.len(), 1, "{:?}", tally.findings);
        assert!(
            tally.findings[0].contains("Lc -30.1"),
            "{:?}",
            tally.findings
        );
        assert!(tally.failures.is_empty(), "{:?}", tally.failures);

        // Fails WCAG (2.32) and would also miss Lc 60 (45.8): it is a failure
        // and is NOT also filed as a finding, so the advisory list stays what
        // it claims to be — the pairs the first model says are fine.
        tally.measure(
            "test",
            "light grey on white",
            hex_rgb("aaaaaa").unwrap(),
            white,
            aa,
        );
        assert_eq!(tally.failures.len(), 1, "{:?}", tally.failures);
        assert_eq!(tally.findings.len(), 1, "{:?}", tally.findings);

        // Every pair is on the report, whatever its verdict.
        assert_eq!(tally.lines.len(), 3);
        assert_eq!(tally.checked, 3);
    }

    /// **The flip, as a rule rather than as a claim.** The same pair, measured
    /// twice: advisory where the default palette is, a failure where the
    /// increased-contrast blocks are.
    ///
    /// `#767676` on black is the canonical dark-mode grey — WCAG 4.62, Lc
    /// -30.1. In a default scope it is a finding and the build goes on; in an
    /// increased-contrast scope it fails twice over, on 4.62 against 7.0 and on
    /// the rung. The first failure is reported and the second is not, because a
    /// pair under the WCAG floor returns before APCA is consulted — one defect,
    /// one line.
    #[test]
    fn the_increased_contrast_scopes_fail_where_the_default_ones_advise() {
        let black = hex_rgb("000000").unwrap();
        let grey = hex_rgb("767676").unwrap();

        let mut advisory = Tally::default();
        advisory.measure(
            "dark",
            "grey on black",
            grey,
            black,
            Held::Aa.floor(4.5, Rung::Text),
        );
        assert!(advisory.failures.is_empty(), "{:?}", advisory.failures);
        assert_eq!(advisory.findings.len(), 1, "{:?}", advisory.findings);

        let mut enforced = Tally::default();
        enforced.measure(
            "dark + more contrast",
            "grey on black",
            grey,
            black,
            Held::AaaAndApca.floor(4.5, Rung::Text),
        );
        assert_eq!(enforced.failures.len(), 1, "{:?}", enforced.failures);
        assert!(
            enforced.failures[0].contains("needs 7.0"),
            "{:?}",
            enforced.failures
        );
        assert!(enforced.findings.is_empty(), "{:?}", enforced.findings);
    }

    /// A pair that clears AAA and misses the body rung fails an enforced scope
    /// on the *second* model, which is the half that did not exist before.
    ///
    /// `#9A9A9A` on black reads WCAG 7.45 — AAA — and Lc -50.2. Nothing in the
    /// first column can see it, which is the whole argument for the second.
    #[test]
    fn an_enforced_scope_fails_a_pair_the_ratio_calls_aaa() {
        let mut tally = Tally::default();
        tally.measure(
            "dark + more contrast",
            "grey on black",
            hex_rgb("9a9a9a").unwrap(),
            hex_rgb("000000").unwrap(),
            Held::AaaAndApca.floor(4.5, Rung::Text),
        );
        assert_eq!(tally.failures.len(), 1, "{:?}", tally.failures);
        assert!(
            tally.failures[0].contains("clears 7.0"),
            "{:?}",
            tally.failures
        );
        assert!(
            tally.failures[0].contains("under 60"),
            "{:?}",
            tally.failures
        );
    }

    /// A pair between the two rungs is neither a failure nor silence.
    ///
    /// `#BBBBBB` on black is WCAG 10.87 and Lc -69.5: over the body rung this
    /// gate adopts, under the small one it prints. The list is what makes 75
    /// visible to whoever next puts 12px text in one of these pairs.
    #[test]
    fn a_pair_between_the_rungs_is_printed_and_does_not_fail() {
        let mut tally = Tally::default();
        tally.measure(
            "light + more contrast",
            "grey on black",
            hex_rgb("bbbbbb").unwrap(),
            hex_rgb("000000").unwrap(),
            Held::AaaAndApca.floor(4.5, Rung::Text),
        );
        assert!(tally.failures.is_empty(), "{:?}", tally.failures);
        assert!(tally.findings.is_empty(), "{:?}", tally.findings);
        assert_eq!(tally.small_rung.len(), 1, "{:?}", tally.small_rung);
    }

    /// **A fenced mark keeps its floor where text is raised**, in every scope.
    ///
    /// The stoplights are Tier 3 fills that no semantic block reaches, so
    /// raising their floor in the increased-contrast scopes would fail the
    /// build on a pair this axis cannot move — and on the one pair an open
    /// record (`TASK-the-close-lights-mark-is-under-apcas-non-text-rung`) says
    /// should not be closed by picking a lever quietly. The ink on close reads
    /// 5.45 and Lc 41.60, which is what these numbers are.
    #[test]
    fn a_fenced_mark_keeps_its_declared_floor_where_text_is_raised() {
        let ink = hex_rgb("0E0C0B").unwrap();
        let close = hex_rgb("F34949").unwrap();

        let text = Held::AaaAndApca.floor(4.5, Rung::Text);
        let mark = Held::AaaAndApca.floor(4.5, Rung::MarkFenced);
        assert_eq!(text.wcag, 7.0);
        assert_eq!(mark.wcag, 4.5);
        assert!(mark.apca.is_none());

        let mut tally = Tally::default();
        tally.measure("dark + more contrast", "mark on close", ink, close, mark);
        assert!(tally.failures.is_empty(), "{:?}", tally.failures);
        assert_eq!(tally.findings.len(), 1, "{:?}", tally.findings);
        assert!(
            tally.findings[0].contains("Lc 41.60"),
            "{:?}",
            tally.findings
        );

        // And the three in the real table are the three fenced marks — the fence
        // is the exception, so a fourth pair inside it should be on purpose.
        let fenced: Vec<&str> = PAIRS
            .iter()
            .chain(COMPOSITE_PAIRS)
            .filter(|(_, _, _, r)| *r == Rung::MarkFenced)
            .map(|(fg, _, _, _)| *fg)
            .collect();
        assert_eq!(fenced, ["--frame-control-mark"; 3]);
    }

    /// **A launcher mark is lifted where contrast is increased** — a rung, not
    /// to the text floor.
    ///
    /// `TASK-a-launcher-mark-is-held-to-the-non-text-rung-even-where-contrast-is-increased`.
    /// The six dock tints are `Rung::Mark`: their `--tint-*` roles are Tier 2,
    /// so this axis reaches them, and a scope that promises more contrast has
    /// to spend some of it on the thing a person looks at first. Three things
    /// are pinned — the floor moves 3.0 -> 4.5, APCA stops being advisory and
    /// becomes a failure at the body rung, and the default scopes are untouched.
    #[test]
    fn a_launcher_mark_is_lifted_in_the_increased_contrast_scopes() {
        // The lift itself.
        let lifted = Held::AaaAndApca.floor(3.0, Rung::Mark);
        assert_eq!(
            lifted.wcag, 4.5,
            "a mark's floor did not move off the non-text rung"
        );
        assert_eq!(
            lifted.apca,
            Some(APCA_BODY),
            "a mark's APCA is still advisory here"
        );
        // And not to the text floor: 7:1 is for words.
        assert!(lifted.wcag < WCAG_AAA);

        // The default scopes keep the non-text rung, advisory APCA and all.
        let default = Held::Aa.floor(3.0, Rung::Mark);
        assert_eq!(default.wcag, 3.0);
        assert!(default.apca.is_none());

        // A hue that clears 3.0 and misses the lifted floor fails the build in
        // an increased-contrast scope and does not in a default one. `#767676`
        // on white reads 4.54 — over the lift — so this uses `#8A8A8A`, 3.54.
        let grey = hex_rgb("8a8a8a").unwrap();
        let white = hex_rgb("ffffff").unwrap();
        let mut enforced = Tally::default();
        enforced.measure(
            "dark + more contrast",
            "tint on material",
            grey,
            white,
            lifted,
        );
        assert_eq!(enforced.failures.len(), 1, "{:?}", enforced.failures);
        assert!(
            enforced.failures[0].contains("needs 4.5"),
            "{:?}",
            enforced.failures
        );

        let mut advisory = Tally::default();
        advisory.measure("dark", "tint on material", grey, white, default);
        assert!(advisory.failures.is_empty(), "{:?}", advisory.failures);

        // Everything the lift is for. A pair joining this rung is a
        // launcher-mark-shaped decision and reads like one here.
        //
        // **Eleven since 2026-09-21** (`TASK-the-calendar-is-the-drawn-one`).
        // Six dock tints and the calendar's five: the rule down the leading
        // edge of an event block, the hue on its own quiet fill. They are marks
        // by the same argument the dock's are — a component standing beside
        // words rather than one of them, WCAG 1.4.11's 3:1 rung — and they take
        // the lift for a reason the dock's six had to be measured into: the
        // hues move one ladder stop AWAY from these fills in both
        // increased-contrast scopes while the fills do not move, so the five
        // read 8.57-9.11 (dark, Lc -68.0 to -73.6) and 8.58-9.20 (light, Lc
        // 83.0 to 84.1) against a 4.5 and an Lc 60. A scope whose promise is
        // *more contrast* cannot mean more on every word and none on a
        // calendar, and here it costs nothing to keep that promise.
        //
        // The five `--color-text` on `--tint-*-quiet` pairs beside them are
        // NOT here, and that is the split this list is checking: the title on a
        // block is words, so it is `Rung::Text` and goes to AAA in those scopes
        // like every other word in the product.
        let lifted_marks: Vec<&str> = PAIRS
            .iter()
            .chain(COMPOSITE_PAIRS)
            .filter(|(_, _, _, r)| *r == Rung::Mark)
            .map(|(fg, _, _, _)| *fg)
            .collect();
        assert_eq!(
            lifted_marks,
            [
                "--tint-red",
                "--tint-orange",
                "--tint-green",
                "--tint-blue",
                "--tint-violet",
                "--dock-tint-ask",
                "--dock-tint-terminal",
                "--dock-tint-files",
                "--dock-tint-contacts",
                "--dock-tint-calendar",
                "--dock-tint-settings",
            ]
        );
    }

    /// The design file this gate reads, so the two cannot drift apart silently.
    fn tokens_css() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask crate has a parent workspace dir")
            .join("ui/tokens.css");
        std::fs::read_to_string(&path).expect("ui/tokens.css is readable")
    }

    /// **The block exists, under the selector this gate names.**
    ///
    /// `block()` matches a selector at the start of a line, so a moved or
    /// re-spelled selector parses empty — and `run()` exits on an empty layer
    /// rather than checking fewer pairs. This says the same thing one step
    /// earlier and without a process exit: both arms are there, and each one
    /// declares something.
    #[test]
    fn both_increased_contrast_blocks_parse() {
        let css = tokens_css();
        let dark = block(&css, "[data-contrast=\"more\"]");
        let light = block(&css, "[data-theme=\"light\"][data-contrast=\"more\"]");
        assert!(
            dark.contains_key("--color-text"),
            "the dark arm parsed: {dark:?}"
        );
        assert!(
            light.contains_key("--color-text"),
            "the light arm parsed: {light:?}"
        );
        // The ground does not move — the record's own "what it is not".
        for ground in [
            "--color-bg",
            "--color-surface",
            "--color-surface-raised",
            "--color-surface-sunken",
            "--color-surface-pane",
            "--color-surface-side",
        ] {
            assert!(
                !dark.contains_key(ground),
                "{ground} is re-mapped in the dark arm"
            );
            assert!(
                !light.contains_key(ground),
                "{ground} is re-mapped in the light arm"
            );
        }
    }

    /// **The desk's four stops are declared in both themes, at the stops the
    /// ruling names, and the drawn ground agrees with the flat fallback.**
    ///
    /// `TASK-the-desk-is-a-drawn-ground-and-not-a-flat-colour` fixes all four by
    /// name — the dark base is `--neutral-900` and the light base
    /// `--neutral-100`, the horizon is one step off the base *away from the
    /// text* in each theme, and the glows are the orange and violet ramps'
    /// deepest stop on dark and palest on light. Resolved through this file's
    /// own `resolve`, so what is asserted is the colour a renderer arrives at
    /// rather than the spelling of a `var()` chain.
    ///
    /// The last assertion is the one the record calls the point of the whole
    /// move: `--desk-ground` and `--color-bg` are the same colour, so the flat
    /// fallback and the drawing cannot disagree.
    #[test]
    fn the_desk_declares_its_four_stops_in_both_themes() {
        let css = tokens_css();
        let tier1 = block(&css, ":root {");
        let dark_block = block(&css, ":root, [data-theme=\"dark\"]");
        let light_block = block(&css, "[data-theme=\"light\"]");

        let mut light: HashMap<String, String> = dark_block.clone();
        for (k, v) in light_block.iter() {
            light.insert(k.clone(), v.clone());
        }

        let expected: [(&str, &str, &str); 4] = [
            ("--desk-ground", "181513", "EDEAE7"),
            ("--desk-horizon", "211D1B", "E6E2DF"),
            ("--desk-glow-warm", "362418", "F9EBE3"),
            ("--desk-glow-cool", "321C49", "F1ECF7"),
        ];
        for (name, on_dark, on_light) in expected {
            assert!(
                dark_block.contains_key(name),
                "{name} is not declared in the dark theme block"
            );
            assert!(
                light_block.contains_key(name),
                "{name} is not declared in the light theme block"
            );
            assert_eq!(
                resolve(name, &dark_block, &tier1),
                hex_rgb(on_dark),
                "{name} on dark is not #{on_dark}"
            );
            assert_eq!(
                resolve(name, &light, &tier1),
                hex_rgb(on_light),
                "{name} on light is not #{on_light}"
            );
        }

        for (scope, theme) in [(&dark_block, "dark"), (&light, "light")] {
            assert_eq!(
                resolve("--desk-ground", scope, &tier1),
                resolve("--color-bg", scope, &tier1),
                "the {theme} desk's base and its flat fallback are different colours"
            );
        }
    }

    /// **A window's pane and sidebar are the mock-up's, and the ground under them did not
    /// move** (`TASK-the-desktop-is-set-in-geist-and-layered-as-the-mock-up`). The pane is
    /// `--neutral-950` on dark and `--neutral-100` on light, the sidebar `--neutral-940` and
    /// `--neutral-50` — in each theme one step lighter than the pane and below the cards'
    /// `--color-surface-raised` — while `--color-bg` stays `#181513` / `#EDEAE7`, so the desk,
    /// which is `--color-bg`, is the owner's open question still.
    #[test]
    fn a_windows_pane_and_sidebar_are_the_mock_ups_and_the_ground_is_unmoved() {
        let css = tokens_css();
        let tier1 = block(&css, ":root {");
        let dark = block(&css, ":root, [data-theme=\"dark\"]");
        let mut light: HashMap<String, String> = dark.clone();
        light.extend(block(&css, "[data-theme=\"light\"]"));
        let lum = |c: Option<[f64; 3]>| c.map(|c| c[0] + c[1] + c[2]).expect("a colour");
        for (scope, theme, pane, side, bg) in [
            (&dark, "dark", "0E0C0B", "141110", "181513"),
            (&light, "light", "EDEAE7", "F3F0EE", "EDEAE7"),
        ] {
            let at = |t: &str| resolve(t, scope, &tier1);
            assert_eq!(at("--color-surface-pane"), hex_rgb(pane), "{theme} pane");
            assert_eq!(at("--color-surface-side"), hex_rgb(side), "{theme} sidebar");
            assert_eq!(at("--color-bg"), hex_rgb(bg), "{theme} --color-bg moved");
            let (p, s, r) = (at("--color-surface-pane"), at("--color-surface-side"), at("--color-surface-raised"));
            assert!(lum(p) < lum(s) && lum(s) < lum(r), "{theme}: the sidebar is not between the pane and the cards");
        }
    }

    /// **The two window grounds face the text floor** — each of the three text tokens on
    /// each, in `PAIRS`, so `contrast-check` measures them in every theme and contrast.
    #[test]
    fn the_window_grounds_are_rows_in_pairs() {
        for ground in ["--color-surface-pane", "--color-surface-side"] {
            for text in ["--color-text", "--color-text-secondary", "--color-text-tertiary"] {
                assert!(
                    PAIRS.iter().any(|(fg, bg, floor, _)| *fg == text && *bg == ground && *floor >= 4.5),
                    "PAIRS has no row for {text} on {ground}"
                );
            }
        }
    }

    /// **Every desk stop this gate measures against is a stop the file declares.**
    ///
    /// `DESK_STOPS` is walked as backdrops for the panel composites and the four
    /// names also appear in `PAIRS`; a stop renamed in `ui/tokens.css` would
    /// make `run()` exit on an unresolved pair, which is the right outcome but
    /// only after a build. This says it without one, and it says the two lists
    /// are the same four names rather than two lists that happen to agree today.
    #[test]
    fn the_desk_stops_this_gate_names_are_the_ones_the_file_declares() {
        let css = tokens_css();
        let tier1 = block(&css, ":root {");
        let dark_block = block(&css, ":root, [data-theme=\"dark\"]");
        for stop in DESK_STOPS {
            assert!(
                resolve(stop, &dark_block, &tier1).is_some(),
                "{stop} does not resolve in ui/tokens.css"
            );
        }
        let mut paired: Vec<&str> = PAIRS
            .iter()
            .map(|(_, bg, _, _)| *bg)
            .filter(|bg| bg.starts_with("--desk-"))
            .collect();
        paired.sort_unstable();
        paired.dedup();
        let mut declared: Vec<&str> = DESK_STOPS.to_vec();
        declared.sort_unstable();
        assert_eq!(
            paired, declared,
            "PAIRS and DESK_STOPS name different desk stops"
        );
    }

    /// **The light arm re-declares every name the dark one does.**
    ///
    /// The first block's selector is a bare `[data-contrast="more"]` — it must
    /// be, or it would match nothing the shell draws — so in a light document
    /// both blocks apply and this one wins only on equal specificity and source
    /// order. A name the light arm leaves out is the dark theme's value
    /// rendering on linen, which is the same silent failure the light scope's
    /// own stack was fixed for on 2026-09-21.
    #[test]
    fn the_light_arm_re_maps_every_name_the_dark_one_declares() {
        let css = tokens_css();
        let dark = block(&css, "[data-contrast=\"more\"]");
        let light = block(&css, "[data-theme=\"light\"][data-contrast=\"more\"]");
        let mut missing: Vec<&String> = dark.keys().filter(|k| !light.contains_key(*k)).collect();
        missing.sort();
        assert!(
            missing.is_empty(),
            "the light arm does not re-map: {missing:?}"
        );
    }

    /// **Tier 3 recomputes at this boundary too.**
    ///
    /// The comment above that block calls its selector load-bearing: a custom
    /// property is substituted where it is declared, so every alias has to be
    /// re-declared at each boundary where Tier 2 changes. This axis is such a
    /// boundary, and the failure of forgetting it is silent — Tier 2 still
    /// resolves and only the aliases are wrong.
    #[test]
    fn the_component_tier_re_declares_at_the_contrast_boundary() {
        let css = tokens_css();
        assert!(
            css.contains(":root, [data-theme], [data-form-factor], [data-contrast] {"),
            "the Tier 3 selector no longer names the contrast axis"
        );
    }
}
