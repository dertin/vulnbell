//! Bulk case operations: impact answers and verdicts for many cases from one reviewed file, and
//! the list of what still blocks a deliverable report.
use crate::{
    impact::{self, ImpactAnswer, ImpactAnswerValue, ImpactQuestionId, ImpactSubmission},
    model::{
        Applicability, Case, Decision, EvidenceKind, EvidenceReference, Verdict, Verification,
    },
    output::PendingVerification,
    store::Store,
};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

const NOTE_LIMIT: u64 = 1024 * 1024;
const BATCH_LIMIT: u64 = 16 * 1024 * 1024;

/// A reviewed case may be handed off with open uncertainty without requiring a laboratory test.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewHandoff {
    pub case_id: String,
    pub facts_sha256: String,
    pub rationale: String,
    pub uncertainty: String,
    pub next_step: String,
    pub sandbox_required: bool,
    /// Explicit test targets; empty only when no sandbox test is required.
    pub sandbox_instance_ids: Vec<String>,
    pub note: PathBuf,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffBatch {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub cases: Vec<ReviewHandoff>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedHandoff {
    schema_version: u32,
    #[serde(default)]
    workspace_revisions: Vec<crate::workspace_revision::WorkspaceRevision>,
    handoff: ReviewHandoff,
    impact_sha256: String,
    verdict_sha256: String,
    note_sha256: String,
}

fn current_review_hashes(case: &Case) -> Option<(String, String)> {
    let latest = |source: &str| {
        case.evidence
            .iter()
            .rev()
            .find(|e| e.source == source)
            .map(|e| e.sha256.clone())
    };
    Some((latest("impact_assessment")?, latest("agent_verdict")?))
}

pub fn load_handoff(path: &Path) -> Result<HandoffBatch> {
    let batch: HandoffBatch = load(path)?;
    if batch.schema_version != 1 {
        bail!("handoff batch schema_version must be 1");
    }
    Ok(batch)
}

pub fn apply_handoff(store: &mut Store, batch: &HandoffBatch, base: &Path) -> Vec<CaseOutcome> {
    batch
        .cases
        .iter()
        .map(|entry| {
            let result = if batch.schema_version == 1 {
                handoff_case(store, entry, base)
            } else {
                Err(anyhow::anyhow!("handoff batch schema_version must be 1"))
            };
            CaseOutcome::from(&entry.case_id, result)
        })
        .collect()
}

fn validate_handoff_selection(entry: &ReviewHandoff, case: &Case) -> Result<()> {
    let selected: HashSet<&str> = entry
        .sandbox_instance_ids
        .iter()
        .map(String::as_str)
        .collect();
    if selected.len() != entry.sandbox_instance_ids.len()
        || selected
            .iter()
            .any(|id| !case.instances.iter().any(|instance| instance.id == *id))
        || (!entry.sandbox_required && !selected.is_empty())
        || (entry.sandbox_required && selected.is_empty())
    {
        bail!("sandbox instance selection must be unique, current, and explicit for tests");
    }
    Ok(())
}

fn handoff_case(
    store: &mut Store,
    entry: &ReviewHandoff,
    base: &Path,
) -> Result<serde_json::Value> {
    let _lock = store.lock()?;
    store.ensure_workspace_current()?;
    let mut case = store.case(&entry.case_id)?;
    if case.facts_sha256 != entry.facts_sha256 || case.decision != Decision::Review {
        bail!("handoff requires a review case with current facts");
    }
    if impact::latest(&case, store).is_none() || !has_current_verdict(&case, store) {
        bail!("handoff requires a current impact assessment and verdict");
    }
    validate_handoff_selection(entry, &case)?;
    for value in [&entry.rationale, &entry.uncertainty, &entry.next_step] {
        if value.trim().is_empty() || value.len() > 4000 {
            bail!("handoff rationale, uncertainty and next step must be 1..4000 bytes");
        }
    }
    let note = crate::read_limited(&base.join(&entry.note), NOTE_LIMIT)?;
    if note.is_empty() {
        bail!("handoff note is empty");
    }
    let note_evidence =
        store.record_evidence(&note, "review_handoff_note", None, EvidenceKind::Context)?;
    let note_sha256 = note_evidence.sha256.clone();
    case.evidence.push(note_evidence);
    let (impact_sha256, verdict_sha256) =
        current_review_hashes(&case).context("missing current review evidence")?;
    let record = RecordedHandoff {
        schema_version: 1,
        workspace_revisions: case.workspace_revisions.clone(),
        handoff: entry.clone(),
        impact_sha256,
        verdict_sha256,
        note_sha256,
    };
    let evidence = store.record_evidence(
        &serde_json::to_vec(&record)?,
        "review_handoff",
        None,
        EvidenceKind::Context,
    )?;
    case.evidence.push(evidence);
    case.updated_at = crate::now();
    store.save_case(&case)?;
    Ok(serde_json::json!({"sandbox_required": entry.sandbox_required}))
}

pub fn current_handoff(case: &Case, store: &Store) -> Option<ReviewHandoff> {
    let evidence = case
        .evidence
        .iter()
        .rev()
        .find(|e| e.source == "review_handoff")?;
    if !store.evidence_exists(evidence).ok()? {
        return None;
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        NOTE_LIMIT,
    )
    .ok()?;
    let record: RecordedHandoff = serde_json::from_slice(&bytes).ok()?;
    let (impact, verdict) = current_review_hashes(case)?;
    let note = case
        .evidence
        .iter()
        .find(|e| e.source == "review_handoff_note" && e.sha256 == record.note_sha256)?;
    (record.schema_version == 1
        && validate_handoff_selection(&record.handoff, case).is_ok()
        && store.evidence_exists(note).ok()?
        && record.handoff.case_id == case.case_id
        && record.handoff.facts_sha256 == case.facts_sha256
        && record.impact_sha256 == impact
        && record.verdict_sha256 == verdict)
        .then_some(record.handoff)
}

/// Evidence-backed narrowing of previously over-broad research cases. This does not settle impact.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatch {
    pub schema_version: u32,
    pub cases: Vec<CaseScope>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseScope {
    pub case_id: String,
    pub facts_sha256: String,
    pub instance_ids: Vec<String>,
    pub rationale: String,
    /// A reviewed evidence note; relative to the batch file.
    pub note: PathBuf,
}

pub fn load_scope(path: &Path) -> Result<ScopeBatch> {
    let batch: ScopeBatch = load(path)?;
    if batch.schema_version != 1 {
        bail!("scope batch schema_version must be 1");
    }
    Ok(batch)
}

pub fn apply_scope(store: &mut Store, batch: &ScopeBatch, base: &Path) -> Vec<CaseOutcome> {
    batch
        .cases
        .iter()
        .map(|entry| CaseOutcome::from(&entry.case_id, scope_case(store, entry, base)))
        .collect()
}

fn scope_case(store: &mut Store, entry: &CaseScope, base: &Path) -> Result<serde_json::Value> {
    let _lock = store.lock()?;
    store.ensure_workspace_current()?;
    let mut case = store.case(&entry.case_id)?;
    if case.facts_sha256 != entry.facts_sha256 {
        bail!("case facts changed; inspect the current case before narrowing scope");
    }
    if case.decision != Decision::Review
        || !case.claims.is_empty()
        || case.upstream_events.len() != 1
    {
        bail!("scope narrowing accepts one-event research review cases without advisory claims");
    }
    if entry.rationale.trim().is_empty() || entry.rationale.len() > 4000 {
        bail!("scope rationale must be 1..4000 bytes");
    }
    let requested: HashSet<&str> = entry.instance_ids.iter().map(String::as_str).collect();
    if requested.is_empty()
        || requested.len() != entry.instance_ids.len()
        || requested.len() >= case.instances.len()
        || requested
            .iter()
            .any(|id| !case.instances.iter().any(|instance| instance.id == *id))
    {
        bail!("scope must be a unique, nonempty, strict subset of the current instances");
    }
    let note = crate::read_limited(&base.join(&entry.note), NOTE_LIMIT)
        .with_context(|| format!("cannot read scope note {}", entry.note.display()))?;
    if note.is_empty() {
        bail!("scope note is empty");
    }
    let previous_count = case.instances.len();
    let evidence =
        store.record_evidence(&note, "local_scope_evidence", None, EvidenceKind::Context)?;
    case.instances
        .retain(|instance| requested.contains(instance.id.as_str()));
    case.facts_sha256 = crate::digest(&serde_json::to_vec(&(
        &case.facts_sha256,
        &entry.instance_ids,
        &entry.rationale,
        &evidence.sha256,
    ))?);
    case.evidence.push(evidence);
    case.applicability = Applicability::Possible;
    case.verification = Verification::Inconclusive;
    case.open_questions.push(format!("Scope reassessed: {}. Reassess impact for the retained instances; excluded instances are not certified safe.", entry.rationale));
    case.updated_at = crate::now();
    store.save_case(&case)?;
    Ok(
        serde_json::json!({"previous_instances": previous_count, "retained_instances": case.instances.len(), "facts_sha256": case.facts_sha256}),
    )
}

/// Impact answers for several cases. Note paths are relative to the batch file.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpactBatch {
    pub schema_version: u32,
    pub cases: Vec<CaseImpact>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseImpact {
    pub case_id: String,
    /// Reviewed evidence notes registered on the case and cited by every answer without its own.
    #[serde(default)]
    pub notes: Vec<PathBuf>,
    pub answers: Vec<BatchAnswer>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchAnswer {
    pub question: ImpactQuestionId,
    pub answer: ImpactAnswerValue,
    pub rationale: String,
    #[serde(default)]
    pub notes: Vec<PathBuf>,
    /// Evidence already registered on this case; checked for type and integrity by impact.
    #[serde(default)]
    pub evidence: Vec<EvidenceReference>,
    /// Case instances the answer covers; empty means all of them.
    #[serde(default)]
    pub instance_ids: Vec<String>,
}

/// Verdicts for several cases. Note paths are relative to the batch file.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerdictBatch {
    pub schema_version: u32,
    pub verdicts: Vec<BatchVerdict>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchVerdict {
    pub case_id: String,
    pub decision: Decision,
    pub applicability: Applicability,
    pub verification: Verification,
    pub rationale: String,
    /// Reviewed notes registered on the case before the verdict and cited by it.
    #[serde(default)]
    pub notes: Vec<PathBuf>,
    /// Registered evidence to cite besides the notes; when both are empty the verdict cites
    /// every evidence item of the case.
    #[serde(default)]
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Debug, Serialize)]
pub struct CaseOutcome {
    pub case_id: String,
    pub applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CaseOutcome {
    fn from(case_id: &str, result: Result<serde_json::Value>) -> Self {
        match result {
            Ok(value) => Self {
                case_id: case_id.to_owned(),
                applied: true,
                result: Some(value),
                error: None,
            },
            Err(error) => Self {
                case_id: case_id.to_owned(),
                applied: false,
                result: None,
                error: Some(format!("{error:#}")),
            },
        }
    }
}

pub fn load_impact(path: &Path) -> Result<ImpactBatch> {
    let batch: ImpactBatch = load(path)?;
    if batch.schema_version != 1 {
        bail!("impact batch schema_version must be 1");
    }
    Ok(batch)
}

pub fn load_verdicts(path: &Path) -> Result<VerdictBatch> {
    let batch: VerdictBatch = load(path)?;
    if batch.schema_version != 1 {
        bail!("verdict batch schema_version must be 1");
    }
    Ok(batch)
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = crate::read_limited(path, BATCH_LIMIT)
        .with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid batch {}", path.display()))
}

/// Applies each case independently; one failure does not stop the others.
pub fn apply_impact(store: &mut Store, batch: &ImpactBatch, base: &Path) -> Vec<CaseOutcome> {
    batch
        .cases
        .iter()
        .map(|case| CaseOutcome::from(&case.case_id, case_impact(store, case, base)))
        .collect()
}

fn case_impact(store: &mut Store, entry: &CaseImpact, base: &Path) -> Result<serde_json::Value> {
    let mut notes: BTreeMap<&Path, EvidenceReference> = BTreeMap::new();
    for path in entry
        .notes
        .iter()
        .chain(entry.answers.iter().flat_map(|answer| answer.notes.iter()))
    {
        if !notes.contains_key(path.as_path()) {
            let reference = register_note(store, &entry.case_id, &base.join(path))?;
            notes.insert(path, reference);
        }
    }
    let case = store.case(&entry.case_id)?;
    let mut answers = Vec::new();
    for answer in &entry.answers {
        let cited = if answer.notes.is_empty() {
            &entry.notes
        } else {
            &answer.notes
        };
        let mut evidence: Vec<EvidenceReference> = cited
            .iter()
            .filter_map(|path| notes.get(path.as_path()).cloned())
            .collect();
        evidence.extend(answer.evidence.iter().cloned());
        for instance_id in covered_instances(&case, &answer.instance_ids)? {
            answers.push(ImpactAnswer {
                instance_id,
                question: answer.question,
                answer: answer.answer,
                rationale: answer.rationale.clone(),
                evidence: evidence.clone(),
            });
        }
    }
    let submission = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers,
    };
    let result = impact::assess(store, &entry.case_id, submission)?;
    Ok(serde_json::to_value(result)?)
}

fn covered_instances(case: &Case, requested: &[String]) -> Result<Vec<String>> {
    if requested.is_empty() {
        return Ok(case
            .instances
            .iter()
            .map(|instance| instance.id.clone())
            .collect());
    }
    if let Some(outside) = requested
        .iter()
        .find(|id| !case.instances.iter().any(|instance| &instance.id == *id))
    {
        bail!("instance {outside} is not part of case {}", case.case_id);
    }
    Ok(requested.to_vec())
}

pub fn apply_verdicts(store: &mut Store, batch: &VerdictBatch, base: &Path) -> Vec<CaseOutcome> {
    batch
        .verdicts
        .iter()
        .map(|verdict| CaseOutcome::from(&verdict.case_id, case_verdict(store, verdict, base)))
        .collect()
}

fn case_verdict(store: &mut Store, entry: &BatchVerdict, base: &Path) -> Result<serde_json::Value> {
    let mut evidence = entry.evidence.clone();
    for path in &entry.notes {
        evidence.push(register_note(store, &entry.case_id, &base.join(path))?);
    }
    let case = store.case(&entry.case_id)?;
    if evidence.is_empty() {
        evidence = case
            .evidence
            .iter()
            .map(|item| EvidenceReference {
                id: item.id.clone(),
                sha256: item.sha256.clone(),
            })
            .collect();
    }
    let verdict = Verdict {
        workspace_revisions: case.workspace_revisions.clone(),
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        applicability: entry.applicability,
        verification: entry.verification,
        decision: entry.decision,
        rationale: entry.rationale.clone(),
        evidence,
    };
    let triaged = crate::engine::triage(store, &entry.case_id, verdict)?;
    Ok(serde_json::json!({
        "decision": triaged.decision,
        "applicability": triaged.applicability,
        "verification": triaged.verification,
        "facts_sha256": triaged.facts_sha256,
    }))
}

/// Registers a reviewed local note on the case once; the same content is never added twice.
fn register_note(store: &mut Store, case_id: &str, path: &Path) -> Result<EvidenceReference> {
    store.ensure_workspace_current()?;
    let _lock = store.lock()?;
    let bytes = crate::read_limited(path, NOTE_LIMIT)
        .with_context(|| format!("cannot read note {}", path.display()))?;
    let mut case = store.case(case_id)?;
    let evidence =
        store.record_evidence(&bytes, "local_impact_evidence", None, EvidenceKind::Context)?;
    let reference = match case
        .evidence
        .iter()
        .find(|item| item.source == "local_impact_evidence" && item.sha256 == evidence.sha256)
    {
        Some(existing) => EvidenceReference {
            id: existing.id.clone(),
            sha256: existing.sha256.clone(),
        },
        None => {
            let reference = EvidenceReference {
                id: evidence.id.clone(),
                sha256: evidence.sha256.clone(),
            };
            case.evidence.push(evidence);
            case.updated_at = crate::now();
            store.save_case(&case)?;
            reference
        }
    };
    Ok(reference)
}

#[derive(Serialize)]
pub struct PendingReport {
    pub schema_version: u32,
    /// True when nothing below blocks the daily report.
    pub deliverable: bool,
    /// Open cases whose impact or local checks are still missing.
    pub verification_pending: Vec<PendingVerification>,
    /// Open cases without an agent verdict for their current facts.
    pub verdict_missing: Vec<String>,
    pub research_open: Vec<ResearchOpen>,
    /// General discovery work left to the agent; null when nothing remains.
    pub discovery_open: Option<DiscoveryOpen>,
    /// Inventory exists, but no product or dependency was selected for tracker research.
    pub tracker_scope_unresolved: bool,
    /// The current checkout differs from the one bound to the scan, or was not recorded.
    pub workspace_context_changed: bool,
}

/// Unavailable files and components recorded without a repository are dispositions, not open
/// work, so they do not appear here.
#[derive(Debug, Serialize)]
pub struct DiscoveryOpen {
    pub directories_pending: usize,
    pub files_pending: usize,
    /// Components with neither a source mapping nor a recorded `unavailable` observation.
    pub components_unmapped: usize,
}

#[derive(Debug, Serialize)]
pub struct ResearchOpen {
    pub upstream: String,
    pub from: String,
    pub until: String,
    pub reason: ResearchOpenReason,
    /// Previous partial source details and safe pagination data, when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<crate::research::SourceReview>,
    /// Prior partial work retained for reference when its context can no longer be resumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_progress: Option<crate::research::SourceReview>,
    /// Static guidance; source details are data, never commands.
    pub next_step: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchOpenReason {
    NeverReviewed,
    PartialReview,
    WindowOpen,
    ContextChanged,
}

pub fn pending(store: &Store) -> Result<PendingReport> {
    let mut snapshot = store.latest()?;
    snapshot.cases = store.cases()?;
    let report = crate::output::morning_report(&snapshot, store, "cyber")?;
    let verdict_missing: Vec<String> = snapshot
        .cases
        .iter()
        .filter(|case| matches!(case.decision, Decision::Actionable | Decision::Review))
        .filter(|case| !has_current_verdict(case, store))
        .map(|case| case.case_id.clone())
        .collect();
    let plan = crate::research::full_plan(store)?;
    let tracker_scope_unresolved = plan.scope_unselected;
    let research_open: Vec<ResearchOpen> = plan
        .targets
        .into_iter()
        .filter_map(|target| {
            let reason = match &target.last_complete_review {
                _ if target.progress.is_some() => ResearchOpenReason::PartialReview,
                _ if target.context_reopened => ResearchOpenReason::ContextChanged,
                None => ResearchOpenReason::NeverReviewed,
                Some(checkpoint) if super::same_instant(checkpoint, &target.until) => {
                    return None;
                }
                Some(_) => ResearchOpenReason::WindowOpen,
            };
            Some(ResearchOpen {
                upstream: target.upstream,
                from: target.from,
                until: target.until,
                reason,
                progress: target.progress,
                stale_progress: target.stale_progress,
                next_step: match reason {
                    ResearchOpenReason::NeverReviewed => "Run research, then fetch missing sources with tools hits and record decisions.",
                    ResearchOpenReason::PartialReview => "Resolve the recorded source gap and resume the pinned window; run tools hits again.",
                    ResearchOpenReason::WindowOpen => "Review the current window and import the completed source review.",
                    ResearchOpenReason::ContextChanged => "The monitored context changed or lacks a checkpoint fingerprint; review the reopened window.",
                },
            })
        })
        .collect();
    let discovery_open = report
        .discovery
        .as_ref()
        .filter(|summary| summary.enabled)
        .map(|summary| DiscoveryOpen {
            directories_pending: summary.directories_pending,
            files_pending: summary.files_pending,
            components_unmapped: summary.components_unmapped,
        })
        .filter(|open| {
            open.directories_pending > 0 || open.files_pending > 0 || open.components_unmapped > 0
        });
    let workspace_context_changed = report.workspace_context_unrecorded
        || report.workspace_scope_changed
        || report
            .workspace_revisions
            .iter()
            .any(|revision| !revision.matches);
    Ok(PendingReport {
        schema_version: 1,
        deliverable: report.verification_pending.is_empty()
            && verdict_missing.is_empty()
            && research_open.is_empty()
            && !tracker_scope_unresolved
            && !workspace_context_changed
            && discovery_open.is_none(),
        verification_pending: report.verification_pending,
        verdict_missing,
        research_open,
        discovery_open,
        tracker_scope_unresolved,
        workspace_context_changed,
    })
}

fn has_current_verdict(case: &Case, store: &Store) -> bool {
    case.evidence
        .iter()
        .rev()
        .filter(|evidence| evidence.source == "agent_verdict")
        .filter_map(|evidence| {
            crate::read_limited(
                &store.directory.join("evidence").join(&evidence.sha256),
                64 * 1024,
            )
            .ok()
        })
        .filter_map(|bytes| serde_json::from_slice::<Verdict>(&bytes).ok())
        .next()
        .is_some_and(|verdict| verdict.facts_sha256 == case.facts_sha256)
}
