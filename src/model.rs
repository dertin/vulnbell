use crate::profile::Component;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Checked,
    Partial,
    Unsupported,
    Unavailable,
    Unresolved,
    Disabled,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Coverage {
    pub source: String,
    pub scope: String,
    pub state: CoverageState,
    pub detail: String,
}
impl Coverage {
    pub fn new(source: &str, scope: &str, state: CoverageState, detail: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            scope: scope.into(),
            state,
            detail: detail.into(),
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Declared,
    Locked,
    AgentObserved,
    ObservedArtifact,
    Deployed,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Provenance {
    pub path: Option<String>,
    pub sha256: String,
    pub observed_at: String,
    pub workspace: Option<String>,
    pub direct: Option<bool>,
    pub resolution: Option<String>,
    pub artifact_integrity: Option<String>,
    /// 1-based line in `path` where the package entry or cited excerpt starts.
    /// Display-only: excluded from the context fingerprint so unrelated edits do not reopen cases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Instance {
    pub id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub requested_version: Option<String>,
    pub resolved_version: Option<String>,
    pub origin: Origin,
    pub provenance: Provenance,
    pub purl: Option<String>,
    pub cpe_product: Option<String>,
    pub upstream: Option<String>,
    pub identity_evidence: Vec<Evidence>,
}
impl Instance {
    pub fn declared(component: &Component) -> Self {
        let origin = if component.usage == crate::profile::Usage::Deployed {
            Origin::Deployed
        } else {
            Origin::Declared
        };
        let id = crate::digest(
            format!(
                "declared:{}:{:?}:{:?}",
                component.reference, component.version, component.upstream
            )
            .as_bytes(),
        );
        Self {
            id,
            reference: component.reference.clone(),
            requested_version: component.version.clone(),
            resolved_version: component
                .version
                .clone()
                .filter(|version| version != "latest"),
            origin,
            provenance: Provenance {
                path: None,
                sha256: crate::digest(
                    &serde_json::to_vec(component).expect("component serializes"),
                ),
                observed_at: crate::now(),
                workspace: None,
                direct: Some(true),
                resolution: None,
                artifact_integrity: None,
                line: None,
            },
            purl: None,
            cpe_product: None,
            upstream: component.upstream.clone(),
            identity_evidence: Vec::new(),
        }
    }

    pub fn context_fingerprint(&self) -> String {
        // A lockfile hash records provenance, but unrelated dependency edits are not new facts.
        let declaration = match self.origin {
            Origin::Locked => None,
            _ => Some(&self.provenance.sha256),
        };
        // Upstream and CPE are source identity; mapping them later enriches the same artifact.
        // `identity_replaced` detects a real change of an already mapped identity.
        let context = (
            &self.id,
            &self.reference,
            &self.resolved_version,
            self.origin,
            &self.provenance.path,
            &self.provenance.workspace,
            self.provenance.direct,
            &self.provenance.resolution,
            &self.provenance.artifact_integrity,
            &self.purl,
            declaration,
        );
        crate::digest(&serde_json::to_vec(&context).expect("instance context serializes"))
    }

    /// True when a previously mapped upstream or CPE now points elsewhere.
    pub fn identity_replaced(&self, current: &Instance) -> bool {
        let replaced = |old: &Option<String>, new: &Option<String>| old.is_some() && old != new;
        replaced(&self.upstream, &current.upstream)
            || replaced(&self.cpe_product, &current.cpe_product)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub id: String,
    pub sha256: String,
    pub source: String,
    pub url: Option<String>,
    pub observed_at: String,
    pub kind: EvidenceKind,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Identity,
    Advisory,
    Context,
    Attestation,
    NonApplicability,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Applicability {
    Affected,
    NotAffected,
    Possible,
    Unknown,
    Conflict,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    SourceConfirmed,
    LabReproduced,
    NotReproduced,
    Inconclusive,
    Disproven,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Actionable,
    Review,
    Informational,
    Dismissed,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Claim {
    pub id: String,
    pub source: String,
    pub aliases: Vec<String>,
    pub instance_id: String,
    pub summary: String,
    pub applicability: Applicability,
    pub evidence: Evidence,
    pub known_exploited: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpstreamEvent {
    pub provider: String,
    pub kind: String,
    pub id: String,
    pub url: String,
    pub title: String,
    pub updated_at: Option<String>,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "SourceFacts::is_empty")]
    pub source_facts: SourceFacts,
}
/// What an upstream item itself states, quoted or closely paraphrased; an empty field means the
/// item does not say. These are the item's statements, not the agent's conclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceFacts {
    /// CVE, GHSA, RUSTSEC or other advisory IDs the item cites.
    #[serde(default)]
    pub identifiers: Vec<String>,
    /// Versions or release lines the item says are affected.
    #[serde(default)]
    pub affected_versions: String,
    /// Version, release or backport the item says contains the fix.
    #[serde(default)]
    pub fixed_in: String,
    /// Pull request, commit or release that carries the fix.
    #[serde(default)]
    pub fix_reference: String,
    /// Feature, configuration or deployment condition the item says the issue requires.
    #[serde(default)]
    pub required_feature: String,
}
impl SourceFacts {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Case {
    pub schema_version: u32,
    pub case_id: String,
    pub project_id: String,
    pub snapshot_id: String,
    pub instances: Vec<Instance>,
    pub claims: Vec<Claim>,
    pub upstream_events: Vec<UpstreamEvent>,
    pub evidence: Vec<Evidence>,
    pub coverage: Vec<Coverage>,
    pub applicability: Applicability,
    pub verification: Verification,
    pub decision: Decision,
    pub facts_sha256: String,
    pub open_questions: Vec<String>,
    pub suggested_search_queries: Vec<String>,
    pub sandbox: SandboxAvailability,
    pub updated_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SandboxAvailability {
    pub available: bool,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Snapshot {
    pub schema_version: u32,
    pub id: String,
    pub project_id: String,
    pub profile_sha256: String,
    pub started_at: String,
    pub finished_at: String,
    pub instances: Vec<Instance>,
    pub coverage: Vec<Coverage>,
    pub cases: Vec<Case>,
    pub partial: bool,
    pub alert_status: String,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub schema_version: u32,
    pub case_id: String,
    pub facts_sha256: String,
    pub applicability: Applicability,
    pub verification: Verification,
    pub decision: Decision,
    pub rationale: String,
    pub evidence: Vec<EvidenceReference>,
}
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub id: String,
    pub sha256: String,
}
