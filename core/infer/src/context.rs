// SPDX-License-Identifier: AGPL-3.0-or-later
//! What the model is shown, and the label on every piece of it (RFC-0085 IN6).
//!
//! A [`Context`] is composed by the host: it selects the passages, it writes the
//! label on each one, and it keeps the map from label to record. Nothing in this
//! crate can add a passage, because nothing in this crate can read a record.
//!
//! That asymmetry is the whole of IN6. The model's output is text; a `[n]` in it
//! is resolved by the host against the labels *it* issued, and dropped if it
//! names nothing. A string the model produced never becomes a reference, so
//! there is no `resolve` here to be called by the wrong side.

use serde::{Deserialize, Serialize};

/// Where a passage came from, as the host knows it — never as the text claims.
///
/// `#[serde(rename_all = "lowercase")]` so the wire spells these the way
/// RFC-0085's Mechanism sketch does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// Brought in by an import — a mailbox archive, a calendar file, a folder.
    Import,
    /// A message in the person's own store.
    Message,
    /// A calendar entry.
    Calendar,
    /// A file in the person's VFS.
    File,
}

/// Who and when, beside the record — shown to the person next to the citation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub origin: Origin,
    /// The contact this came from, where there is one. A reference the host
    /// resolves, not a display name the model could have invented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// RFC-3339, as the record carries it.
    pub at: String,
}

/// One host-selected, host-labelled span of the person's own data.
///
/// `reference` rather than `ref`, which is a keyword. The wire name is `ref`, as
/// RFC-0085 writes it, so the rename is the field attribute rather than a second
/// spelling for a reader to reconcile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passage {
    /// The record this came from (RFC-0003 addressing).
    #[serde(rename = "ref")]
    pub reference: String,
    pub provenance: Provenance,
    pub text: String,
}

/// The question, the passages, and the prompt shape the manifest asked for.
///
/// The question is the person's words **verbatim**. Nothing here rewrites it:
/// an assistant that silently improves the question is answering a question
/// nobody asked, and the person cannot see that it happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub question: String,
    /// In the order the host labelled them: `passages[0]` is `[1]`.
    pub passages: Vec<Passage>,
    /// From the model manifest ([`crate::ModelManifest::template`]), copied here
    /// so a backend needs no access to the manifest store to assemble a prompt.
    pub template: String,
}

impl Context {
    /// The label the host issued for `index`, one-based as a citation is written.
    ///
    /// The host owns the numbering, so this is the one place it is spelled. A
    /// second implementation of "which passage is `[2]`?" is how a citation
    /// comes to resolve to the wrong record.
    pub fn label_of(index: usize) -> String {
        format!("[{}]", index + 1)
    }

    /// The passage a label names, or `None` — which is a citation to drop.
    pub fn passage_for_label(&self, label: &str) -> Option<&Passage> {
        let n: usize = label.trim_start_matches('[').trim_end_matches(']').parse().ok()?;
        self.passages.get(n.checked_sub(1)?)
    }
}

/// What the caller asks of one generation.
///
/// Deliberately small: these are the knobs a host sets per question, not a
/// place for the model's own configuration, which belongs to the manifest and
/// arrives with the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Options {
    /// Ceiling on tokens produced. The host's context budget is enforced when
    /// the passages are selected, not here.
    pub max_tokens: u32,
    pub temperature: f32,
    /// Fixed for a reproducible answer; `None` lets the backend choose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_tokens: 512,
            temperature: 0.2,
            seed: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passage(reference: &str, text: &str) -> Passage {
        Passage {
            reference: reference.to_string(),
            provenance: Provenance {
                origin: Origin::Message,
                from: None,
                at: "2026-09-15T00:00:00Z".to_string(),
            },
            text: text.to_string(),
        }
    }

    /// IN6's drop rule, at the level the host resolves it: a label the host did
    /// not issue names nothing, whatever the model wrote.
    #[test]
    fn a_label_the_host_did_not_issue_resolves_to_nothing() {
        let ctx = Context {
            question: "when".to_string(),
            passages: vec![passage("record://a", "first")],
            template: "{question}".to_string(),
        };
        assert_eq!(Context::label_of(0), "[1]");
        assert_eq!(ctx.passage_for_label("[1]").map(|p| p.reference.as_str()), Some("record://a"));
        assert!(ctx.passage_for_label("[2]").is_none());
        assert!(ctx.passage_for_label("[0]").is_none());
        assert!(ctx.passage_for_label("[not-a-number]").is_none());
    }
}
