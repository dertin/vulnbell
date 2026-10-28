use crate::model::{Applicability, SourceFacts};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBatch {
    pub schema_version: u32,
    pub project_id: String,
    pub snapshot_id: String,
    pub sources: Vec<SourceReview>,
    pub events: Vec<ResearchEvent>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceReview {
    pub upstream: String,
    pub from: String,
    pub until: String,
    pub coverage: ReviewCoverage,
    pub detail: String,
    pub continuation: Option<SourceContinuation>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceContinuation {
    pub cursor: String,
    pub url: Option<String>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCoverage {
    Complete,
    Partial,
    Unavailable,
}
/// `not_applicable`: a security claim that, per the cited source, does not affect the monitored
/// version or build. It requires `not_applicable_reason`, is counted and remembered, and opens no case.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Review,
    Informational,
    NotApplicable,
    Ignore,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotApplicableReason {
    /// The monitored resolved version already contains the fix.
    FixedInMonitoredVersion,
    /// Only other release lines or unreleased branches are affected.
    AffectsOtherVersion,
    /// The affected module, feature or platform is absent from the monitored build.
    ComponentNotInBuild,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Issue,
    PullRequest,
    MergeRequest,
    MergeProposal,
    Comment,
    Review,
    News,
    Discussion,
    Documentation,
    Changelog,
    Release,
    Advisory,
    Commit,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvent {
    pub upstream: String,
    pub instance_ids: Vec<String>,
    /// Candidate instances examined when choosing the case scope.
    pub reviewed_instance_ids: Vec<String>,
    pub provider: String,
    pub external_id: String,
    pub kind: EventKind,
    pub url: String,
    pub title: String,
    pub excerpt: String,
    /// Original RFC3339 timestamp or YYYY-MM-DD when the source provides only a date.
    /// Empty means unknown. Unknown/day precision keeps coverage partial and never advances checkpoints.
    pub updated_at: String,
    pub assessment: Assessment,
    /// Required with `not_applicable`; forbidden otherwise.
    #[serde(default)]
    pub not_applicable_reason: Option<NotApplicableReason>,
    pub rationale: String,
    /// Answers to the research questions as the item states them. `fixed_in_monitored_version`
    /// requires `fixed_in`, and `affects_other_version` requires `affected_versions`.
    #[serde(default)]
    pub source_facts: SourceFacts,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ResearchComponent {
    pub instance_id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub requested_version: Option<String>,
    pub resolved_version: Option<String>,
    pub origin: crate::model::Origin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<crate::model::ReleaseDate>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ResearchTarget {
    pub upstream: String,
    /// Fingerprint of the exact monitored instances in this target.
    pub context_sha256: String,
    pub instance_ids: Vec<String>,
    pub components: Vec<ResearchComponent>,
    pub from: String,
    pub until: String,
    pub last_complete_review: Option<String>,
    pub seen: Vec<SeenEvent>,
    pub seen_truncated: bool,
    pub continuation: Option<SourceContinuation>,
    /// Persisted incomplete source review, including its stated blocker and pinned window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<SourceReview>,
    /// Older progress is retained as context but must not be resumed against changed artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_progress: Option<SourceReview>,
    /// True when the source window was reopened because its monitored context changed.
    #[serde(default)]
    pub context_reopened: bool,
}
/// An imported event with the agent's previous reading, so an item whose `updated_at` is unchanged
/// needs no new review.
#[derive(Debug, Serialize, Deserialize)]
pub struct SeenEvent {
    pub external_id: String,
    pub url: String,
    pub content_sha256: String,
    pub updated_at: String,
    /// False when the monitored instances changed since the recorded assessment or the target
    /// gained instances the event does not cover; the event then needs a new review even with the
    /// same `updated_at`.
    pub context_current: bool,
    pub assessment: Option<Assessment>,
    pub not_applicable_reason: Option<NotApplicableReason>,
    /// First 300 characters of the recorded rationale.
    pub rationale: String,
}
#[derive(Debug, Serialize)]
pub struct ResearchPlan {
    pub schema_version: u32,
    pub project_id: String,
    pub snapshot_id: String,
    pub targets: Vec<ResearchTarget>,
    /// Inventory instances outside tracker exploration; advisories are still scanned separately.
    pub tracker_scope: crate::profile::TrackerScope,
    pub deferred_transitive_instances: usize,
    pub deferred_unknown_instances: usize,
    /// No inventory instance was selected for tracker research.
    pub scope_unselected: bool,
    /// Evidence-backed candidates for focused investigation; these do not change the scope.
    pub follow_suggestions: Vec<FollowSuggestion>,
    pub follow_suggestions_total: usize,
    pub required_agent_sites: Vec<String>,
    pub policy: String,
    pub next_cursor: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct FollowSuggestion {
    #[serde(rename = "ref")]
    pub reference: String,
    pub version: Option<String>,
    pub case_id: String,
    pub advisory_id: String,
    pub applicability: Applicability,
    pub evidence: crate::model::Evidence,
}
