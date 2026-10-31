//! Evidence-bound second assessments of a case; reviewer independence is self-reported.
use crate::{
    model::{Case, EvidenceKind, EvidenceReference},
    store::Store,
};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    Supported,
    Disputed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerRelationship {
    Independent,
    SameReviewer,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub schema_version: u32,
    pub case_id: String,
    pub facts_sha256: String,
    pub impact_sha256: String,
    pub verdict_sha256: String,
    /// Reviewer identity as supplied by the operator, not authenticated by VulnBell.
    pub reviewer: String,
    pub relationship: ReviewerRelationship,
    pub conclusion: Conclusion,
    pub rationale: String,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Serialize)]
pub struct RecordedChallenge {
    pub case_id: String,
    pub evidence: EvidenceReference,
    pub requires_new_verdict: bool,
    pub independence_verified: bool,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OpenReason {
    Disputed,
    Inconclusive,
    AssessmentChanged,
    EvidenceUnavailable,
}

#[derive(Serialize, JsonSchema)]
pub struct OpenChallenge {
    pub evidence: EvidenceReference,
    pub reason: OpenReason,
    pub rationale: Option<String>,
}

pub fn open(case: &Case, store: &Store) -> Vec<OpenChallenge> {
    unresolved_challenges(case, store)
        .into_iter()
        .map(|evidence| {
            let challenge = read_challenge(case, store, evidence);
            let reason = match challenge.as_ref().map(|item| item.conclusion) {
                Some(Conclusion::Disputed) => OpenReason::Disputed,
                Some(Conclusion::Inconclusive) => OpenReason::Inconclusive,
                Some(Conclusion::Supported) => OpenReason::AssessmentChanged,
                None => OpenReason::EvidenceUnavailable,
            };
            OpenChallenge {
                evidence: EvidenceReference {
                    id: evidence.id.clone(),
                    sha256: evidence.sha256.clone(),
                },
                reason,
                rationale: challenge.map(|item| item.rationale),
            }
        })
        .collect()
}

pub fn record(store: &mut Store, challenge: Challenge) -> Result<RecordedChallenge> {
    let _lock = store.lock()?;
    store.ensure_workspace_current()?;
    let mut case = store.case(&challenge.case_id)?;
    let active: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
        [&challenge.case_id],
        |row| row.get(0),
    )?;
    if !active || challenge.schema_version != 1 || challenge.facts_sha256 != case.facts_sha256 {
        bail!("challenge requires an active case with current facts");
    }
    if challenge.reviewer.trim().is_empty()
        || challenge.reviewer.len() > 120
        || challenge.reviewer.chars().any(char::is_control)
        || challenge.rationale.trim().is_empty()
        || challenge.rationale.len() > 4000
        || challenge.evidence.is_empty()
        || challenge.evidence.len() > 100
    {
        bail!("challenge needs a reviewer, bounded rationale and 1..100 evidence references");
    }
    crate::impact::latest(&case, store)
        .context("challenge requires a current impact assessment")?;
    crate::engine::current_verdict(&case, store).context("challenge requires a current verdict")?;
    let latest_hash = |source: &str| {
        case.evidence
            .iter()
            .rev()
            .find(|item| item.source == source)
            .map(|item| item.sha256.as_str())
    };
    if latest_hash("impact_assessment") != Some(challenge.impact_sha256.as_str())
        || latest_hash("agent_verdict") != Some(challenge.verdict_sha256.as_str())
    {
        bail!("challenge references a stale assessment or verdict");
    }
    for reference in &challenge.evidence {
        let evidence = case
            .evidence
            .iter()
            .find(|item| item.id == reference.id && item.sha256 == reference.sha256)
            .context("challenge references unknown evidence")?;
        if matches!(
            evidence.source.as_str(),
            "review_challenge" | "impact_assessment" | "agent_verdict"
        ) {
            bail!("challenge must cite primary case evidence, not another assessment");
        }
        if !store.evidence_exists(evidence)? {
            bail!("challenge evidence integrity failed");
        }
    }
    let evidence = store.record_evidence(
        &serde_json::to_vec(&challenge)?,
        "review_challenge",
        None,
        EvidenceKind::Context,
    )?;
    let reference = EvidenceReference {
        id: evidence.id.clone(),
        sha256: evidence.sha256.clone(),
    };
    case.evidence.push(evidence);
    case.updated_at = crate::now();
    store.save_case(&case)?;
    Ok(RecordedChallenge {
        case_id: case.case_id,
        evidence: reference,
        requires_new_verdict: challenge.conclusion != Conclusion::Supported,
        independence_verified: false,
    })
}

/// An unresolved or unreadable challenge after the latest verdict invalidates that verdict.
pub(crate) fn blocks_verdict(case: &Case, store: &Store) -> bool {
    !unresolved_challenges(case, store).is_empty()
}

pub(crate) fn unresolved_challenges<'a>(
    case: &'a Case,
    store: &Store,
) -> Vec<&'a crate::model::Evidence> {
    let latest_impact = case
        .evidence
        .iter()
        .rev()
        .find(|item| item.source == "impact_assessment");
    let latest_verdict = case
        .evidence
        .iter()
        .rev()
        .find(|item| item.source == "agent_verdict");
    case.evidence
        .iter()
        .rev()
        .take_while(|evidence| evidence.source != "agent_verdict")
        .filter(|evidence| evidence.source == "review_challenge")
        .filter(|evidence| {
            let stale = || -> Option<bool> {
                if !store.evidence_exists(evidence).ok()? {
                    return None;
                }
                let bytes = crate::read_limited(
                    &store.directory.join("evidence").join(&evidence.sha256),
                    128 * 1024,
                )
                .ok()?;
                let challenge: Challenge = serde_json::from_slice(&bytes).ok()?;
                (challenge.case_id == case.case_id)
                    .then_some(challenge.facts_sha256 != case.facts_sha256)
            };
            if stale() == Some(true) {
                return false;
            }
            read_challenge(case, store, evidence).is_none_or(|challenge| {
                challenge.conclusion != Conclusion::Supported
                    || latest_impact.is_none_or(|impact| impact.sha256 != challenge.impact_sha256)
                    || latest_verdict
                        .is_none_or(|verdict| verdict.sha256 != challenge.verdict_sha256)
            })
        })
        .collect()
}

pub(crate) fn read_challenge(
    case: &Case,
    store: &Store,
    evidence: &crate::model::Evidence,
) -> Option<Challenge> {
    if evidence.source != "review_challenge" || !store.evidence_exists(evidence).ok()? {
        return None;
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        128 * 1024,
    )
    .ok()?;
    let challenge: Challenge = serde_json::from_slice(&bytes).ok()?;
    if challenge.schema_version != 1
        || challenge.case_id != case.case_id
        || challenge.facts_sha256 != case.facts_sha256
        || challenge.evidence.is_empty()
        || challenge.evidence.len() > 100
    {
        return None;
    }
    for (source, hash) in [
        ("impact_assessment", &challenge.impact_sha256),
        ("agent_verdict", &challenge.verdict_sha256),
    ] {
        let cited = case
            .evidence
            .iter()
            .find(|item| item.source == source && item.sha256 == *hash)?;
        if !store.evidence_exists(cited).ok()? {
            return None;
        }
    }
    for reference in &challenge.evidence {
        let cited = case
            .evidence
            .iter()
            .find(|item| item.id == reference.id && item.sha256 == reference.sha256)?;
        if matches!(
            cited.source.as_str(),
            "review_challenge" | "impact_assessment" | "agent_verdict"
        ) || !store.evidence_exists(cited).ok()?
        {
            return None;
        }
    }
    Some(challenge)
}
