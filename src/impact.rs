use crate::{
    model::{Case, Evidence, EvidenceKind, EvidenceReference, Origin, Verification},
    store::Store,
};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

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
    pub case_id: String,
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
    pub case_id: String,
    pub facts_sha256: String,
    pub answers: Vec<ImpactAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InstanceImpact {
    pub instance_id: String,
    pub verdict: ImpactVerdict,
    pub confidence: ImpactConfidence,
    pub reasons: Vec<String>,
    pub open_questions: Vec<ImpactQuestionId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ImpactResult {
    pub schema_version: u32,
    pub case_id: String,
    pub facts_sha256: String,
    pub verdict: ImpactVerdict,
    pub confidence: ImpactConfidence,
    #[serde(default)]
    pub answers: Vec<ImpactAnswer>,
    pub instances: Vec<InstanceImpact>,
    pub assessed_at: String,
}

pub fn plan(case: &Case) -> ImpactPlan {
    ImpactPlan {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        affected_version_confirmed: case
            .instances
            .iter()
            .any(|instance| affected_instance_confirmed(case, &instance.id)),
        targets: case
            .instances
            .iter()
            .map(|instance| ImpactTarget {
                instance_id: instance.id.clone(),
                component: instance.reference.clone(),
                version: instance.resolved_version.clone(),
                origin: instance.origin,
                affected_version_confirmed: affected_instance_confirmed(case, &instance.id),
                questions: questions(),
            })
            .collect(),
    }
}

pub fn assess(store: &mut Store, id: &str, submission: ImpactSubmission) -> Result<ImpactResult> {
    let _lock = store.lock()?;
    let mut case = store.case(id)?;
    validate_submission(&case, store, id, &submission)?;

    let mut grouped = BTreeMap::<String, Vec<&ImpactAnswer>>::new();
    for answer in &submission.answers {
        grouped
            .entry(answer.instance_id.clone())
            .or_default()
            .push(answer);
    }

    let mut instances = Vec::new();
    for instance in &case.instances {
        let answers = grouped.get(&instance.id).cloned().unwrap_or_default();
        instances.push(assess_instance(
            &case,
            store,
            &instance.id,
            affected_instance_confirmed(&case, &instance.id),
            &answers,
        )?);
    }
    let result = ImpactResult {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        verdict: aggregate_verdict(&instances),
        confidence: aggregate_confidence(&instances),
        answers: submission.answers.clone(),
        instances,
        assessed_at: crate::now(),
    };
    let evidence = store.record_evidence(
        &serde_json::to_vec(&result)?,
        "impact_assessment",
        None,
        EvidenceKind::Context,
    )?;
    case.evidence.push(evidence);
    case.updated_at = result.assessed_at.clone();
    store.save_case(&case)?;
    Ok(result)
}

pub fn latest(case: &Case, store: &Store) -> Option<ImpactResult> {
    case.evidence
        .iter()
        .rev()
        .filter(|evidence| evidence.source == "impact_assessment")
        .find_map(|evidence| read_result(case, store, evidence).ok())
}

fn questions() -> Vec<ImpactQuestion> {
    vec![
        ImpactQuestion {
            id: ImpactQuestionId::ArtifactDeployed,
            prompt: "Is this exact version present in a deployed or shipped artifact?".into(),
            evidence_needed: "Lockfile, SBOM, image inventory, deployment record, or a bounded workspace check.".into(),
        },
        ImpactQuestion {
            id: ImpactQuestionId::AffectedFeatureUsed,
            prompt: "Does the project call or enable the affected function, module, or protocol?".into(),
            evidence_needed: "Source location, configuration, call path, or a workspace-copy sandbox result.".into(),
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

fn affected_instance_confirmed(case: &Case, instance_id: &str) -> bool {
    case.claims.iter().any(|claim| {
        claim.instance_id == instance_id
            && claim.applicability == crate::model::Applicability::Affected
    }) || (case.instances.len() == 1 && case.verification == Verification::LabReproduced)
}

fn validate_submission(
    case: &Case,
    store: &Store,
    id: &str,
    submission: &ImpactSubmission,
) -> Result<()> {
    if submission.schema_version != 1
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
            if !store.evidence_exists(evidence)? {
                bail!("impact answer evidence integrity failed");
            }
            if answer.answer != ImpactAnswerValue::Unknown
                && !supports_question(answer.question, evidence.kind)
            {
                bail!("evidence type does not support this project-impact question");
            }
        }
    }
    Ok(())
}

fn supports_question(question: ImpactQuestionId, kind: EvidenceKind) -> bool {
    match question {
        ImpactQuestionId::ArtifactDeployed => matches!(
            kind,
            EvidenceKind::Identity
                | EvidenceKind::Context
                | EvidenceKind::Attestation
                | EvidenceKind::NonApplicability
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
            values
                .get(&question.id)
                .is_none_or(|answer| *answer == ImpactAnswerValue::Unknown)
        })
        .map(|question| question.id)
        .collect::<Vec<_>>();
    let negative = answers.iter().find(|answer| {
        matches!(
            answer.question,
            ImpactQuestionId::ArtifactDeployed
                | ImpactQuestionId::AffectedFeatureUsed
                | ImpactQuestionId::RequiredConditionsPresent
        ) && answer.answer == ImpactAnswerValue::No
    });
    let strong_negative = negative.is_some_and(|answer| {
        answer
            .evidence
            .iter()
            .any(|reference| is_non_applicability(case, store, instance_id, reference))
    });

    let deployed = values.get(&ImpactQuestionId::ArtifactDeployed);
    let used = values.get(&ImpactQuestionId::AffectedFeatureUsed);
    let input = values.get(&ImpactQuestionId::UntrustedInputReachesFeature);
    let conditions = values.get(&ImpactQuestionId::RequiredConditionsPresent);
    let mitigated = values.get(&ImpactQuestionId::FixOrMitigationApplied);

    let (verdict, reason) = if !source_confirmed {
        (
            ImpactVerdict::NeedsEvidence,
            "The exact version is not confirmed affected by authoritative evidence or a successful local reproduction.",
        )
    } else if negative.is_some() {
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
    } else if deployed == Some(&ImpactAnswerValue::Yes)
        && used == Some(&ImpactAnswerValue::Yes)
        && input == Some(&ImpactAnswerValue::Yes)
        && matches!(
            conditions,
            Some(ImpactAnswerValue::Yes | ImpactAnswerValue::NotApplicable)
        )
        && mitigated == Some(&ImpactAnswerValue::No)
    {
        (
            ImpactVerdict::UrgentUpdate,
            "The affected feature is deployed, reachable from untrusted input, its prerequisites hold, and no fix or mitigation is present.",
        )
    } else if deployed == Some(&ImpactAnswerValue::Yes)
        && used == Some(&ImpactAnswerValue::Yes)
        && mitigated == Some(&ImpactAnswerValue::No)
        && input != Some(&ImpactAnswerValue::No)
    {
        (
            ImpactVerdict::PriorityUpdate,
            "The affected feature is deployed without a mitigation; input reachability or another prerequisite is not fully closed.",
        )
    } else if deployed == Some(&ImpactAnswerValue::Yes)
        && used == Some(&ImpactAnswerValue::Yes)
        && input == Some(&ImpactAnswerValue::No)
        && mitigated == Some(&ImpactAnswerValue::No)
    {
        (
            ImpactVerdict::RoutineUpdate,
            "The affected feature is deployed, but current evidence does not show untrusted input reaching it.",
        )
    } else {
        (
            ImpactVerdict::NeedsEvidence,
            "The library finding is known, but project deployment or reachability is not established.",
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

fn verdict_priority(verdict: ImpactVerdict) -> u8 {
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

fn read_result(case: &Case, store: &Store, evidence: &Evidence) -> Result<ImpactResult> {
    if !store.evidence_exists(evidence)? {
        bail!("impact assessment integrity failed");
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        1024 * 1024,
    )?;
    let result: ImpactResult = serde_json::from_slice(&bytes)?;
    if result.schema_version != 1
        || result.case_id != case.case_id
        || result.facts_sha256 != case.facts_sha256
    {
        bail!("stale or mismatched impact assessment");
    }
    Ok(result)
}
