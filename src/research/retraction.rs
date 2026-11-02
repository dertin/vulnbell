use super::{Assessment, NotApplicableReason, ResearchEvent, validation};
use crate::{
    model::{Case, Decision, EvidenceKind, Instance},
    store::Store,
};

pub(super) fn can_retract(case: &Case, event: &ResearchEvent, store: &Store) -> bool {
    static ADVISORY_ID: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|(?:RUSTSEC|PYSEC|GO|OSV)-[0-9]{4}-[0-9]+|DSA-[0-9]+(?:-[0-9]+)?|(?:RHSA|USN)-[0-9]{4}[:-][0-9]+)\b")
            .expect("static advisory identifier pattern")
    });
    if crate::tools::challenge::blocks_verdict(case, store)
        || !case.claims.is_empty()
        || matches!(case.decision, Decision::Actionable | Decision::Dismissed)
        || case.instances.len() != event.instance_ids.len()
        || case
            .instances
            .iter()
            .any(|instance| !event.instance_ids.contains(&instance.id))
        || case.upstream_events.len() != 1
        || case.upstream_events[0].url != event.url
        || !case.evidence.iter().any(|item| {
            item.source == "agent_upstream_observation"
                && item.sha256 == case.upstream_events[0].sha256
        })
        || ADVISORY_ID.is_match(&event.title)
        || ADVISORY_ID.is_match(&event.excerpt)
        || case
            .evidence
            .iter()
            .any(|item| matches!(item.kind, EvidenceKind::Advisory))
        || case.upstream_events.iter().any(|item| {
            item.kind == "advisory"
                || item
                    .source_facts
                    .identifiers
                    .iter()
                    .any(|id| !id.trim().is_empty())
        })
        || event
            .source_facts
            .identifiers
            .iter()
            .any(|id| !id.trim().is_empty())
    {
        return false;
    }
    for evidence in case
        .evidence
        .iter()
        .filter(|item| item.source == "agent_upstream_observation")
    {
        if !store.evidence_exists(evidence).unwrap_or(false) {
            return false;
        }
        let Ok(bytes) = crate::read_limited(
            &store.directory.join("evidence").join(&evidence.sha256),
            64 * 1024,
        ) else {
            return false;
        };
        let Ok(content) = std::str::from_utf8(&bytes) else {
            return false;
        };
        if ADVISORY_ID.is_match(content) {
            return false;
        }
    }
    let verdict = crate::engine::current_verdict(case, store);
    if verdict.is_none()
        && case
            .evidence
            .iter()
            .any(|item| item.source == "agent_verdict")
    {
        return false;
    }
    if verdict
        .is_some_and(|verdict| matches!(verdict.decision, Decision::Actionable | Decision::Review))
    {
        return false;
    }
    let impact = crate::impact::latest(case, store);
    if impact.is_none()
        && case
            .evidence
            .iter()
            .any(|item| item.source == "impact_assessment")
    {
        return false;
    }
    !impact.is_some_and(|impact| {
        matches!(
            impact.verdict,
            crate::impact::ImpactVerdict::UrgentUpdate
                | crate::impact::ImpactVerdict::PriorityUpdate
                | crate::impact::ImpactVerdict::RoutineUpdate
                | crate::impact::ImpactVerdict::NeedsEvidence
        )
    })
}

pub(crate) fn retraction_valid(
    case: &Case,
    instances: &[Instance],
    revisions: &[crate::codebase_revision::CodebaseRevision],
    store: &Store,
) -> bool {
    retraction_valid_cached(
        case,
        instances,
        revisions,
        store,
        &mut std::collections::HashMap::new(),
    )
}

fn retraction_valid_cached(
    case: &Case,
    instances: &[Instance],
    revisions: &[crate::codebase_revision::CodebaseRevision],
    store: &Store,
    cache: &mut std::collections::HashMap<super::ArtifactEvidence, bool>,
) -> bool {
    let Some(evidence) = case
        .evidence
        .iter()
        .rev()
        .find(|item| item.source == "agent_retraction_assessment")
    else {
        return false;
    };
    if !store.evidence_exists(evidence).unwrap_or(false) {
        return false;
    }
    let Ok(bytes) = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        32 * 1024 * 1024,
    ) else {
        return false;
    };
    let Ok(event) = serde_json::from_slice::<ResearchEvent>(&bytes) else {
        return false;
    };
    if event.assessment != Assessment::NotApplicable || event.not_applicable_reason.is_none() {
        return false;
    }
    if event.not_applicable_reason != Some(NotApplicableReason::ComponentNotInBuild) {
        return true;
    }
    let Some(artifact) = &event.artifact_evidence else {
        return false;
    };
    if !event.instance_ids.contains(&artifact.instance_id)
        || validation::verify_observed_artifact(artifact, case).is_err()
    {
        return false;
    }
    let snapshot = crate::model::Snapshot {
        schema_version: 1,
        id: case.snapshot_id.clone(),
        project_id: case.project_id.clone(),
        profile_sha256: String::new(),
        started_at: String::new(),
        finished_at: String::new(),
        codebase_revisions: revisions.to_vec(),
        instances: instances
            .iter()
            .filter(|instance| event.instance_ids.contains(&instance.id))
            .cloned()
            .collect(),
        coverage: Vec::new(),
        cases: Vec::new(),
        partial: false,
        alert_status: String::new(),
    };
    *cache.entry(artifact.clone()).or_insert_with(|| {
        validation::verify_artifact(artifact, &snapshot, &event.instance_ids, store).is_ok()
    })
}

/// Reopen stale retractions in read-only output without rewriting the stored history.
pub fn project_retractions(
    snapshot: &crate::model::Snapshot,
    store: &Store,
) -> crate::model::Snapshot {
    let mut projected = snapshot.clone();
    let mut cache = std::collections::HashMap::new();
    let active: std::collections::HashSet<&str> = snapshot
        .instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect();
    for pass in 0..2 {
        if pass == 1 {
            for (artifact, valid) in &mut cache {
                if *valid
                    && validation::verify_artifact(
                        artifact,
                        snapshot,
                        std::slice::from_ref(&artifact.instance_id),
                        store,
                    )
                    .is_err()
                {
                    *valid = false;
                }
            }
        }
        for case in &mut projected.cases {
            if case.decision == Decision::Retracted
                && case
                    .instances
                    .iter()
                    .any(|instance| active.contains(instance.id.as_str()))
                && !retraction_valid_cached(
                    case,
                    &snapshot.instances,
                    &snapshot.codebase_revisions,
                    store,
                    &mut cache,
                )
            {
                case.decision = Decision::Review;
                case.applicability = crate::model::Applicability::Unknown;
                case.verification = crate::model::Verification::Inconclusive;
                case.facts_sha256 =
                    crate::digest(format!("stale-retraction:{}", case.facts_sha256).as_bytes());
                case.open_questions.push(
                    "Retraction evidence is no longer current; rescan and reassess this case."
                        .into(),
                );
            }
        }
    }
    projected
}
