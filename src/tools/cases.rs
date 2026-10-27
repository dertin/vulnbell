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
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const NOTE_LIMIT: u64 = 1024 * 1024;
const BATCH_LIMIT: u64 = 16 * 1024 * 1024;

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
        let evidence: Vec<EvidenceReference> = cited
            .iter()
            .filter_map(|path| notes.get(path.as_path()).cloned())
            .collect();
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
}

#[derive(Debug, Serialize)]
pub struct ResearchOpen {
    pub upstream: String,
    pub from: String,
    pub until: String,
    pub reason: ResearchOpenReason,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchOpenReason {
    NeverReviewed,
    PartialReview,
    WindowOpen,
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
    let research_open: Vec<ResearchOpen> = plan
        .targets
        .into_iter()
        .filter_map(|target| {
            let reason = match &target.last_complete_review {
                _ if target.continuation.is_some() => ResearchOpenReason::PartialReview,
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
            })
        })
        .collect();
    Ok(PendingReport {
        schema_version: 1,
        deliverable: report.verification_pending.is_empty()
            && verdict_missing.is_empty()
            && research_open.is_empty(),
        verification_pending: report.verification_pending,
        verdict_missing,
        research_open,
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
