use crate::{model::EvidenceReference, profile::Component};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct DiscoveryPlan {
    pub schema_version: u32,
    pub project_id: String,
    pub scope_sha256: String,
    pub enabled: bool,
    pub workspace: Vec<FileSlice>,
    pub components: Vec<PublicTarget>,
    pub summary: DiscoverySummary,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DiscoverySummary {
    pub enabled: bool,
    pub directories_pending: usize,
    pub files_pending: usize,
    pub files_reviewed: usize,
    pub files_excluded: usize,
    pub files_unavailable: usize,
    pub components_unmapped: usize,
    /// Mapped components without a repository, so upstream research cannot cover them.
    pub sources_unavailable: usize,
    pub complete: bool,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryGap {
    pub id: String,
    pub path: String,
    pub state: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct GapPage {
    pub items: Vec<DiscoveryGap>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FileSlice {
    pub file_id: String,
    pub path: String,
    pub offset: u64,
    pub end: u64,
    pub sha256: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct PublicTarget {
    pub instance_id: String,
    pub fingerprint: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub version: Option<String>,
    pub upstream: Option<String>,
    pub required_sources: Vec<SourceKind>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiscoveryBatch {
    Workspace {
        schema_version: u32,
        project_id: String,
        scope_sha256: String,
        reviews: Vec<FileReview>,
    },
    Sources {
        schema_version: u32,
        project_id: String,
        scope_sha256: String,
        observations: Vec<IdentityObservation>,
    },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileReview {
    pub file_id: String,
    pub offset: u64,
    pub sha256: String,
    pub rationale: String,
    pub coverage: crate::research::ReviewCoverage,
    pub packages: Vec<PackageObservation>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageObservation {
    pub component: Component,
    pub excerpt: String,
    /// Literal version definition from the same chunk when `excerpt` references it through a
    /// `${name}` placeholder (for example a Maven `<properties>` entry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_excerpt: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityObservation {
    pub instance_id: String,
    pub fingerprint: String,
    pub version: Option<String>,
    pub cpe_product: Option<String>,
    pub rationale: String,
    pub sources: Vec<SourceMapping>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceMapping {
    pub kind: SourceKind,
    pub state: MappingState,
    pub url: Option<String>,
    pub detail: String,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Website,
    Repository,
    Issues,
    ProposedChanges,
    Discussions,
    Documentation,
    Changelog,
    Releases,
    Advisories,
}

pub const SOURCE_KINDS: [SourceKind; 9] = [
    SourceKind::Website,
    SourceKind::Repository,
    SourceKind::Issues,
    SourceKind::ProposedChanges,
    SourceKind::Discussions,
    SourceKind::Documentation,
    SourceKind::Changelog,
    SourceKind::Releases,
    SourceKind::Advisories,
];

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingState {
    Mapped,
    Unavailable,
    NotApplicable,
}
