use crate::{
    model::{Case, Evidence, EvidenceKind, EvidenceReference, Origin, Verification},
    store::Store,
};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub(crate) mod automation;

const MAX_IMPACT_RESULT_BYTES: usize = 32 * 1024 * 1024;

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum ImpactQuestionId {
    ArtifactDeployed,
    AffectedFeatureUsed,
    UntrustedInputReachesFeature,
    RequiredConditionsPresent,
    FixOrMitigationApplied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImpactAnswerValue {
    Yes,
    No,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImpactVerdict {
    UrgentUpdate,
    PriorityUpdate,
    RoutineUpdate,
    Mitigated,
    NotAffected,
    NeedsEvidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImpactConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ImpactQuestion {
    pub id: ImpactQuestionId,
    pub prompt: String,
    pub evidence_needed: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ImpactTarget {
    pub instance_id: String,
    pub component: String,
    pub version: Option<String>,
    pub origin: Origin,
    pub affected_version_confirmed: bool,
    pub questions: Vec<ImpactQuestion>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ImpactPlan {
    pub schema_version: u32,
    pub question_set_sha256: String,
    pub case_id: String,
    pub codebase_revisions: Vec<crate::codebase_revision::CodebaseRevision>,
    pub facts_sha256: String,
    pub affected_version_confirmed: bool,
    pub targets: Vec<ImpactTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpactAnswer {
    pub instance_id: String,
    pub question: ImpactQuestionId,
    pub answer: ImpactAnswerValue,
    pub rationale: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpactSubmission {
    pub schema_version: u32,
    pub question_set_sha256: String,
    pub case_id: String,
    pub facts_sha256: String,
    pub answers: Vec<ImpactAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct InstanceImpact {
    pub instance_id: String,
    pub verdict: ImpactVerdict,
    pub confidence: ImpactConfidence,
    pub reasons: Vec<String>,
    pub open_questions: Vec<ImpactQuestionId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpactResult {
    pub schema_version: u32,
    pub question_set_sha256: String,
    pub case_id: String,
    pub codebase_revisions: Vec<crate::codebase_revision::CodebaseRevision>,
    pub facts_sha256: String,
    pub verdict: ImpactVerdict,
    pub confidence: ImpactConfidence,
    pub answers: Vec<ImpactAnswer>,
    pub instances: Vec<InstanceImpact>,
    pub assessed_at: String,
}

pub fn plan(case: &Case, store: &Store) -> ImpactPlan {
    let targets = case
        .instances
        .iter()
        .map(|instance| (instance, questions()))
        .collect();
    plan_selected(case, store, targets)
}

pub(crate) fn plan_selected(
    case: &Case,
    store: &Store,
    targets: Vec<(&crate::model::Instance, Vec<ImpactQuestion>)>,
) -> ImpactPlan {
    let confirmed = confirmed_instances(case, store);
    ImpactPlan {
        schema_version: 1,
        question_set_sha256: question_set_sha256(),
        case_id: case.case_id.clone(),
        codebase_revisions: case.codebase_revisions.clone(),
        facts_sha256: case.facts_sha256.clone(),
        affected_version_confirmed: case
            .instances
            .iter()
            .any(|instance| confirmed.contains(&instance.id)),
        targets: targets
            .into_iter()
            .map(|(instance, questions)| ImpactTarget {
                instance_id: instance.id.clone(),
                component: instance.reference.clone(),
                version: instance.resolved_version.clone(),
                origin: instance.origin,
                affected_version_confirmed: confirmed.contains(&instance.id),
                questions,
            })
            .collect(),
    }
}

pub fn assess(store: &mut Store, id: &str, submission: ImpactSubmission) -> Result<ImpactResult> {
    assess_checked(store, id, submission, None, Vec::new())
}

pub(crate) fn assess_if_current(
    store: &mut Store,
    id: &str,
    submission: ImpactSubmission,
    expected_case: &Case,
    new_evidence: Vec<Evidence>,
) -> Result<ImpactResult> {
    assess_checked(store, id, submission, Some(expected_case), new_evidence)
}

fn assess_checked(
    store: &mut Store,
    id: &str,
    submission: ImpactSubmission,
    expected_case: Option<&Case>,
    new_evidence: Vec<Evidence>,
) -> Result<ImpactResult> {
    let _lock = store.lock()?;
    store.ensure_codebases_current()?;
    let mut case = store.case(id)?;
    if let Some(expected) = expected_case {
        let latest_impact = |case: &Case| {
            case.evidence
                .iter()
                .rev()
                .find(|evidence| evidence.source == "impact_assessment")
                .map(|evidence| evidence.sha256.clone())
        };
        if latest_impact(&case) != latest_impact(expected)
            || case.snapshot_id != expected.snapshot_id
            || case.decision != expected.decision
            || case.verification != expected.verification
            || valid_attestations(&case, store) != valid_attestations(expected, store)
            || !crate::codebase_revision::same_revisions(
                &case.codebase_revisions,
                &expected.codebase_revisions,
            )
        {
            bail!("impact assessment changed during source review; retry with the latest answers");
        }
    }
    for evidence in new_evidence {
        if evidence.source != "local_impact_evidence"
            || evidence.kind != EvidenceKind::Context
            || !store.evidence_exists(&evidence)?
        {
            bail!("source review note has invalid evidence or integrity");
        }
        if !case.evidence.iter().any(|existing| {
            existing.source == evidence.source && existing.sha256 == evidence.sha256
        }) {
            case.evidence.push(evidence);
        }
    }
    validate_submission(&case, store, id, &submission)?;

    let instances = assess_instances(&case, store, &submission.answers)?;
    let result = ImpactResult {
        schema_version: 1,
        question_set_sha256: question_set_sha256(),
        case_id: case.case_id.clone(),
        codebase_revisions: case.codebase_revisions.clone(),
        facts_sha256: case.facts_sha256.clone(),
        verdict: aggregate_verdict(&instances),
        confidence: aggregate_confidence(&instances),
        answers: submission.answers.clone(),
        instances,
        assessed_at: crate::now(),
    };
    let bytes = serde_json::to_vec(&result)?;
    if bytes.len() > MAX_IMPACT_RESULT_BYTES {
        bail!("impact assessment exceeds the 32 MiB evidence limit");
    }
    let evidence =
        store.record_evidence(&bytes, "impact_assessment", None, EvidenceKind::Context)?;
    case.evidence.push(evidence);
    case.updated_at = result.assessed_at.clone();
    store.save_case(&case)?;
    Ok(result)
}

pub fn latest(case: &Case, store: &Store) -> Option<ImpactResult> {
    let index = case
        .evidence
        .iter()
        .rposition(|evidence| evidence.source == "impact_assessment")?;
    if case.evidence[index + 1..].iter().any(|evidence| {
        evidence.kind == EvidenceKind::Attestation
            && crate::sandbox::read_attestation(case, store, evidence).is_ok()
    }) {
        return None;
    }
    let result = read_result(case, store, &case.evidence[index]).ok()??;
    let instances = assess_instances(case, store, &result.answers).ok()?;
    if result.instances != instances
        || result.verdict != aggregate_verdict(&instances)
        || result.confidence != aggregate_confidence(&instances)
    {
        return None;
    }
    Some(result)
}

pub(crate) fn previous(case: &Case, store: &Store) -> Result<Option<ImpactResult>> {
    let Some(evidence) = case
        .evidence
        .iter()
        .rev()
        .find(|evidence| evidence.source == "impact_assessment")
    else {
        return Ok(None);
    };
    read_result(case, store, evidence)
}

pub(crate) fn valid_attestations(case: &Case, store: &Store) -> Vec<String> {
    case.evidence
        .iter()
        .filter(|evidence| {
            evidence.kind == EvidenceKind::Attestation
                && crate::sandbox::read_attestation(case, store, evidence).is_ok()
        })
        .map(|evidence| evidence.sha256.clone())
        .collect()
}

/// Binds answers to the exact questions and evidence requirements presented to the reviewer.
pub fn question_set_sha256() -> String {
    crate::digest(&serde_json::to_vec(&questions()).expect("impact questions serialize"))
}

pub(crate) fn questions() -> Vec<ImpactQuestion> {
    vec![
        ImpactQuestion {
            id: ImpactQuestionId::ArtifactDeployed,
            prompt: "If already known, is this exact version present in a deployed or shipped artifact?".into(),
            evidence_needed: "Optional context: an artifact inventory or deployment record. Do not investigate deployment just to assess codebase risk; a lockfile or isolated sandbox test alone does not establish deployment.".into(),
        },
        ImpactQuestion {
            id: ImpactQuestionId::AffectedFeatureUsed,
            prompt: "Does an in-scope project configuration, including local development or tests, call or enable the affected function, module, or protocol?".into(),
            evidence_needed: "Source location, configuration, call path, or a codebase-copy sandbox result. Identify test-only paths without excluding them solely because production use is unconfirmed.".into(),
        },
        ImpactQuestion {
            id: ImpactQuestionId::UntrustedInputReachesFeature,
            prompt: "Can untrusted input reach the affected value without a trusted transformation?".into(),
            evidence_needed: "Input-to-call data flow, configuration boundary, or a controlled local result.".into(),
        },
        ImpactQuestion {
            id: ImpactQuestionId::RequiredConditionsPresent,
            prompt: "Are the advisory's required permissions, settings, platform, and runtime conditions present?".into(),
            evidence_needed: "Advisory prerequisites compared with deployment configuration or a controlled test.".into(),
        },
        ImpactQuestion {
            id: ImpactQuestionId::FixOrMitigationApplied,
            prompt: "Is a vendor fix or verified mitigation already applied to this exact artifact?".into(),
            evidence_needed: "Fixed artifact identity, vendor guidance, patch record, or a positive non-applicability test.".into(),
        },
    ]
}

/// Only intact advisory evidence or a current reproduction confirms an instance.
fn confirmed_instances(case: &Case, store: &Store) -> HashSet<String> {
    let mut confirmed = HashSet::new();
    for claim in &case.claims {
        if claim.applicability == crate::model::Applicability::Affected
            && store.evidence_exists(&claim.evidence).unwrap_or(false)
        {
            confirmed.insert(claim.instance_id.clone());
        }
    }
    for evidence in &case.evidence {
        if evidence.kind == EvidenceKind::Attestation
            && let Ok(attestation) = crate::sandbox::read_attestation(case, store, evidence)
            && attestation.verification == Verification::LabReproduced
        {
            confirmed.insert(attestation.instance_id);
        }
    }
    confirmed
}

fn assess_instances(
    case: &Case,
    store: &Store,
    answers: &[ImpactAnswer],
) -> Result<Vec<InstanceImpact>> {
    let confirmed = confirmed_instances(case, store);
    let mut grouped = BTreeMap::<&str, Vec<&ImpactAnswer>>::new();
    for answer in answers {
        grouped.entry(&answer.instance_id).or_default().push(answer);
    }
    case.instances
        .iter()
        .map(|instance| {
            let answers = grouped
                .get(instance.id.as_str())
                .cloned()
                .unwrap_or_default();
            assess_instance(
                case,
                store,
                &instance.id,
                confirmed.contains(&instance.id),
                &answers,
            )
        })
        .collect()
}

fn validate_submission(
    case: &Case,
    store: &Store,
    id: &str,
    submission: &ImpactSubmission,
) -> Result<()> {
    if submission.schema_version != 1
        || submission.question_set_sha256 != question_set_sha256()
        || submission.case_id != id
        || submission.facts_sha256 != case.facts_sha256
    {
        bail!("stale or mismatched impact submission; reopen the current case");
    }
    let instance_ids: HashSet<&str> = case
        .instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect();
    let mut answered = HashSet::new();
    let mut checked_evidence = HashSet::new();
    for answer in &submission.answers {
        if !instance_ids.contains(answer.instance_id.as_str()) {
            bail!("impact answer references an unknown instance");
        }
        if !answered.insert((answer.instance_id.as_str(), answer.question)) {
            bail!("duplicate impact answer for an instance and question");
        }
        if answer.rationale.trim().is_empty() || answer.rationale.len() > 4000 {
            bail!("impact answers require a concise rationale");
        }
        if answer.answer != ImpactAnswerValue::Unknown && answer.evidence.is_empty() {
            bail!("conclusive impact answers require registered evidence");
        }
        if answer.answer == ImpactAnswerValue::NotApplicable
            && answer.question != ImpactQuestionId::RequiredConditionsPresent
        {
            bail!("not_applicable is valid only when an advisory has no extra required conditions");
        }
        for reference in &answer.evidence {
            let evidence = case
                .evidence
                .iter()
                .find(|item| item.id == reference.id && item.sha256 == reference.sha256)
                .context("impact answer references unknown evidence")?;
            if checked_evidence.insert((&evidence.id, &evidence.sha256))
                && !store.evidence_exists(evidence)?
            {
                bail!("impact answer evidence integrity failed");
            }
            if answer.answer != ImpactAnswerValue::Unknown
                && !supports_question(answer.question, answer.answer, evidence.kind)
            {
                bail!("evidence type does not support this project-impact question");
            }
        }
    }
    Ok(())
}

fn supports_question(
    question: ImpactQuestionId,
    answer: ImpactAnswerValue,
    kind: EvidenceKind,
) -> bool {
    match question {
        ImpactQuestionId::ArtifactDeployed if answer == ImpactAnswerValue::Yes => {
            kind == EvidenceKind::Context
        }
        ImpactQuestionId::ArtifactDeployed => matches!(
            kind,
            EvidenceKind::Context | EvidenceKind::Attestation | EvidenceKind::NonApplicability
        ),
        ImpactQuestionId::AffectedFeatureUsed
        | ImpactQuestionId::UntrustedInputReachesFeature
        | ImpactQuestionId::RequiredConditionsPresent => matches!(
            kind,
            EvidenceKind::Context | EvidenceKind::Attestation | EvidenceKind::NonApplicability
        ),
        ImpactQuestionId::FixOrMitigationApplied => matches!(
            kind,
            EvidenceKind::Advisory
                | EvidenceKind::Context
                | EvidenceKind::Attestation
                | EvidenceKind::NonApplicability
        ),
    }
}

fn assess_instance(
    case: &Case,
    store: &Store,
    instance_id: &str,
    source_confirmed: bool,
    answers: &[&ImpactAnswer],
) -> Result<InstanceImpact> {
    let values: BTreeMap<ImpactQuestionId, ImpactAnswerValue> = answers
        .iter()
        .map(|answer| (answer.question, answer.answer))
        .collect();
    let open_questions = questions()
        .into_iter()
        .filter(|question| {
            question.id != ImpactQuestionId::ArtifactDeployed
                && values
                    .get(&question.id)
                    .is_none_or(|answer| *answer == ImpactAnswerValue::Unknown)
        })
        .map(|question| question.id)
        .collect::<Vec<_>>();
    let negative = answers.iter().find(|answer| {
        matches!(
            answer.question,
            ImpactQuestionId::AffectedFeatureUsed | ImpactQuestionId::RequiredConditionsPresent
        ) && answer.answer == ImpactAnswerValue::No
    });
    let strong_negative = negative.is_some_and(|answer| {
        answer
            .evidence
            .iter()
            .any(|reference| is_non_applicability(case, store, instance_id, reference))
    });

    let used = values.get(&ImpactQuestionId::AffectedFeatureUsed);
    let input = values.get(&ImpactQuestionId::UntrustedInputReachesFeature);
    let conditions = values.get(&ImpactQuestionId::RequiredConditionsPresent);
    let mitigated = values.get(&ImpactQuestionId::FixOrMitigationApplied);

    // An absent project condition or a recorded mitigation settles exposure whether or not the
    // version is confirmed affected; only an exposure claim needs that confirmation.
    let (verdict, reason) = if negative.is_some() {
        (
            ImpactVerdict::NotAffected,
            if strong_negative {
                "A required project condition was disproven with positive non-applicability evidence."
            } else {
                "A required project condition is recorded as absent; this assessment does not dismiss the underlying case."
            },
        )
    } else if mitigated == Some(&ImpactAnswerValue::Yes) {
        (
            ImpactVerdict::Mitigated,
            "A fix or mitigation is recorded; keep the evidence and normal upgrade plan current.",
        )
    } else if !source_confirmed {
        (
            ImpactVerdict::NeedsEvidence,
            "The exact version is not confirmed affected by authoritative evidence or a successful local reproduction.",
        )
    } else if used == Some(&ImpactAnswerValue::Yes)
        && input == Some(&ImpactAnswerValue::Yes)
        && matches!(
            conditions,
            Some(ImpactAnswerValue::Yes | ImpactAnswerValue::NotApplicable)
        )
        && mitigated == Some(&ImpactAnswerValue::No)
    {
        (
            ImpactVerdict::UrgentUpdate,
            "The affected feature is in scope, reachable from untrusted input, its prerequisites hold, and no fix or mitigation is recorded.",
        )
    } else if used == Some(&ImpactAnswerValue::Yes) && input != Some(&ImpactAnswerValue::No) {
        (
            ImpactVerdict::PriorityUpdate,
            "The affected feature is in scope and no mitigation is established; verify any remaining reachability or prerequisites.",
        )
    } else if used == Some(&ImpactAnswerValue::Yes) && input == Some(&ImpactAnswerValue::No) {
        (
            ImpactVerdict::RoutineUpdate,
            "The affected feature is in scope, but current evidence does not show untrusted input reaching it.",
        )
    } else {
        (
            ImpactVerdict::NeedsEvidence,
            "The library finding is known, but use of the affected feature in the reviewed codebase is not established.",
        )
    };

    let confidence = confidence(case, store, instance_id, answers, verdict);
    Ok(InstanceImpact {
        instance_id: instance_id.into(),
        verdict,
        confidence,
        reasons: vec![reason.into()],
        open_questions,
    })
}

fn confidence(
    case: &Case,
    store: &Store,
    instance_id: &str,
    answers: &[&ImpactAnswer],
    verdict: ImpactVerdict,
) -> ImpactConfidence {
    if verdict == ImpactVerdict::NeedsEvidence {
        return ImpactConfidence::Low;
    }
    let all_strong = answers.iter().all(|answer| {
        answer.answer == ImpactAnswerValue::Unknown
            || answer
                .evidence
                .iter()
                .any(|reference| is_strong(case, store, instance_id, reference))
    });
    if all_strong {
        ImpactConfidence::High
    } else {
        ImpactConfidence::Medium
    }
}

fn is_strong(case: &Case, store: &Store, instance_id: &str, reference: &EvidenceReference) -> bool {
    let Some(evidence) = case
        .evidence
        .iter()
        .find(|item| item.id == reference.id && item.sha256 == reference.sha256)
    else {
        return false;
    };
    evidence.kind == EvidenceKind::NonApplicability
        || crate::sandbox::read_attestation(case, store, evidence)
            .ok()
            .filter(|attestation| attestation.instance_id == instance_id)
            .is_some_and(|attestation| {
                matches!(
                    attestation.verification,
                    Verification::LabReproduced | Verification::Disproven
                )
            })
}

fn is_non_applicability(
    case: &Case,
    store: &Store,
    instance_id: &str,
    reference: &EvidenceReference,
) -> bool {
    let Some(evidence) = case
        .evidence
        .iter()
        .find(|item| item.id == reference.id && item.sha256 == reference.sha256)
    else {
        return false;
    };
    evidence.kind == EvidenceKind::NonApplicability
        || crate::sandbox::read_attestation(case, store, evidence)
            .ok()
            .filter(|attestation| attestation.instance_id == instance_id)
            .is_some_and(|attestation| attestation.verification == Verification::Disproven)
}

fn aggregate_verdict(instances: &[InstanceImpact]) -> ImpactVerdict {
    instances
        .iter()
        .map(|instance| instance.verdict)
        .max_by_key(|verdict| verdict_priority(*verdict))
        .unwrap_or(ImpactVerdict::NeedsEvidence)
}

pub(crate) fn verdict_priority(verdict: ImpactVerdict) -> u8 {
    match verdict {
        ImpactVerdict::UrgentUpdate => 6,
        ImpactVerdict::PriorityUpdate => 5,
        ImpactVerdict::NeedsEvidence => 4,
        ImpactVerdict::RoutineUpdate => 3,
        ImpactVerdict::Mitigated => 2,
        ImpactVerdict::NotAffected => 1,
    }
}

fn aggregate_confidence(instances: &[InstanceImpact]) -> ImpactConfidence {
    if instances
        .iter()
        .any(|instance| instance.confidence == ImpactConfidence::Low)
    {
        ImpactConfidence::Low
    } else if instances
        .iter()
        .any(|instance| instance.confidence == ImpactConfidence::Medium)
    {
        ImpactConfidence::Medium
    } else {
        ImpactConfidence::High
    }
}

fn read_result(case: &Case, store: &Store, evidence: &Evidence) -> Result<Option<ImpactResult>> {
    if !store.evidence_exists(evidence)? {
        bail!("impact assessment integrity failed");
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        MAX_IMPACT_RESULT_BYTES as u64,
    )?;
    let Ok(result) = serde_json::from_slice::<ImpactResult>(&bytes) else {
        return Ok(None);
    };
    if result.schema_version != 1 || result.case_id != case.case_id {
        bail!("invalid or mismatched impact assessment");
    }
    if result.question_set_sha256 != question_set_sha256()
        || result.facts_sha256 != case.facts_sha256
        || !crate::codebase_revision::same_revisions(
            &result.codebase_revisions,
            &case.codebase_revisions,
        )
    {
        return Ok(None);
    }
    validate_submission(
        case,
        store,
        &case.case_id,
        &ImpactSubmission {
            schema_version: result.schema_version,
            question_set_sha256: result.question_set_sha256.clone(),
            case_id: result.case_id.clone(),
            facts_sha256: result.facts_sha256.clone(),
            answers: result.answers.clone(),
        },
    )?;
    Ok(Some(result))
}
