//! Local helpers for the agent's daily review. The agent fetches tracker activity with `gh` and
//! `curl`; these tools read those responses, screen them, resolve the advisories they cite, build
//! research batches from the agent's decisions, and apply impact answers and verdicts in bulk.
//! They never fetch issue trackers; advisory lookups reuse the CLI's advisory integrations.
pub mod advisories;
pub mod cases;
pub mod draft;
pub mod evaluate;
pub mod hits;
pub mod queue;
pub mod raw;
pub mod screen;
#[cfg(test)]
mod tests;
pub mod workspace;

use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Issue,
    PullRequest,
    MergeRequest,
    Release,
    Advisory,
    Discussion,
    Commit,
}

impl ItemKind {
    pub fn event_kind(self) -> crate::research::EventKind {
        use crate::research::EventKind;
        match self {
            Self::Issue => EventKind::Issue,
            Self::PullRequest => EventKind::PullRequest,
            Self::MergeRequest => EventKind::MergeRequest,
            Self::Release => EventKind::Release,
            Self::Advisory => EventKind::Advisory,
            Self::Discussion => EventKind::Discussion,
            Self::Commit => EventKind::Commit,
        }
    }

    pub fn is_proposed_change(self) -> bool {
        matches!(self, Self::PullRequest | Self::MergeRequest)
    }
}

/// One upstream item normalized from a provider response, or written by the agent for a tracker
/// without a supported response format.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Item {
    /// Stable provider identifier, for example `owner/repo#123`, `owner/repo@v1.2.3` or `HHH-123`.
    pub key: String,
    pub kind: ItemKind,
    /// Original public HTTPS permalink.
    pub url: String,
    pub title: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub labels: Vec<String>,
    /// The source's RFC3339 update time, or commit time for commits.
    pub updated_at: String,
    /// Complete description, release notes or commit message within the raw-file budget.
    #[serde(default)]
    pub body: String,
    /// Keys of the issues a proposed change says it closes.
    #[serde(default)]
    pub closes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<RepositoryAdvisory>,
}

/// A security advisory published in the upstream repository.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAdvisory {
    pub ghsa_id: String,
    #[serde(default)]
    pub cve_id: Option<String>,
    #[serde(default)]
    pub packages: Vec<AdvisoryPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryPackage {
    /// GitHub advisory ecosystem, for example `maven`, `rust` or `npm`.
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub vulnerable_range: String,
    #[serde(default)]
    pub patched: String,
}

/// RFC3339 with second precision, keeping the source's offset (`+00:00` for UTC). Accepts RFC3339,
/// Jira's `2026-10-16T12:00:00.000+0000` and offset-less timestamps, which are read as UTC.
pub fn normalize_time(value: &str) -> Option<String> {
    let value = value.trim();
    let parsed: DateTime<FixedOffset> = DateTime::parse_from_rfc3339(value)
        .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f%z"))
        .ok()
        .or_else(|| {
            let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f"))
                .ok()?;
            Some(naive.and_utc().fixed_offset())
        })?;
    Some(parsed.to_rfc3339_opts(SecondsFormat::Secs, false))
}

/// Whether an RFC3339 time lies inside the inclusive `from`/`until` window.
pub fn in_window(value: &str, from: &str, until: &str) -> bool {
    let (Ok(value), Ok(from), Ok(until)) = (
        DateTime::parse_from_rfc3339(value),
        DateTime::parse_from_rfc3339(from),
        DateTime::parse_from_rfc3339(until),
    ) else {
        return false;
    };
    from <= value && value <= until
}

pub fn same_instant(left: &str, right: &str) -> bool {
    match (
        DateTime::parse_from_rfc3339(left),
        DateTime::parse_from_rfc3339(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// The first `limit` characters of `text`.
pub fn truncate_chars(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((end, _)) => text[..end].to_owned(),
        None => text.to_owned(),
    }
}

/// The longest prefix of `text` within `limit` bytes that ends on a character boundary.
pub fn truncate_bytes(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
