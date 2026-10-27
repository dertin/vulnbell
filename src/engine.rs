use crate::{
    model::{
        Applicability, Case, Claim, Coverage, CoverageState, Decision, EvidenceKind, Instance,
        Snapshot, Verdict, Verification,
    },
    network::Http,
    profile::{Profile, WebResearch},
    store::Store,
};
use anyhow::{Context, Result, bail};
use std::{collections::HashSet, path::Path};

/// Evidence sources written by the agent through `triage` and `impact`.
const AGENT_EVIDENCE: [&str; 2] = ["agent_verdict", "impact_assessment"];

pub fn scan(profile: &Profile, path: &Path, offline: bool) -> Result<Snapshot> {
    if profile.workspaces.is_empty() && profile.components.is_empty() {
        bail!("empty_scope: add components or authorized workspaces before scanning");
    }
    let mut store = Store::open(&profile.project_id.to_string())?;
    store.check_schema()?;
    store.register_project(&profile.name, path)?;
    let _lock = store.lock()?;
    let start = crate::now();
    if let Some(previous) = store.meta("last_scan")? {
        store.set_meta("previous_scan", &previous)?;
    }
    if store.meta("first_scan")?.is_none() {
        store.set_meta("first_scan", &start)?;
    }
    store.set_meta("last_scan", &start)?;
    let result = scan_inner(profile, path, offline, &store, &start);
    match result {
        Ok(mut snapshot) => {
            let alerts = if offline {
                Ok("offline: notification delivery skipped".to_owned())
            } else {
                crate::output::notify(profile, &snapshot, &store)
            };
            snapshot.alert_status = match alerts {
                Ok(status) => status,
                Err(error) => {
                    snapshot.partial = true;
                    format!("failed: {error}")
                }
            };
            store.save_snapshot(&snapshot)?;
            if !snapshot.partial {
                store.set_meta("last_successful_scan", &snapshot.finished_at)?;
            }
            store.set_meta("last_completed_scan", &snapshot.finished_at)?;
            store.set_meta(
                "last_scan_outcome",
                if snapshot.partial {
                    "partial"
                } else {
                    "checked"
                },
            )?;
            Ok(snapshot)
        }
        Err(error) => {
            store.set_meta("last_failure", &format!("{}: {error}", crate::now()))?;
            Err(error)
        }
    }
}
fn scan_inner(
    profile: &Profile,
    path: &Path,
    offline: bool,
    store: &Store,
    start: &str,
) -> Result<Snapshot> {
    let profile_bytes = crate::read_limited(path, 1024 * 1024)?;
    let profile_hash = crate::digest(&profile_bytes);
    let mut instances: Vec<Instance> = profile.components.iter().map(Instance::declared).collect();
    let remaining = 100_000usize.saturating_sub(instances.len());
    let inventory = crate::inventory::discover(&profile.workspaces, path, store, remaining);
    instances.extend(inventory.instances);
    let mut coverage = inventory.coverage;
    let discovery_coverage =
        crate::discovery::augment(profile, path, store, &mut instances, &mut coverage)?;
    coverage.extend(discovery_coverage);
    let mut http = Http::new(store, offline);
    for instance in &mut instances {
        coverage.extend(crate::identity::resolve(instance, &mut http));
    }
    let mut intelligence = crate::sources::scan(&instances, &mut http);
    let vendor = crate::vendor::feeds(profile, &instances, &mut http);
    intelligence.claims.extend(vendor.claims);
    coverage.extend(intelligence.coverage);
    coverage.extend(vendor.coverage);
    let snapshot_id = uuid::Uuid::new_v4().to_string();
    let mut cases = cases_from_claims(
        &intelligence.claims,
        &instances,
        profile,
        &snapshot_id,
        &coverage,
    )?;
    coverage.push(Coverage::new("upstream_agent", "project", CoverageState::Partial, "GitHub, GitLab, Launchpad and similar sites are reviewed by the local agent; run research to obtain windows and seen IDs, then import its evidence"));
    let previous_cases = store.cases()?;
    let mut merged_previous_ids = HashSet::new();
    for case in &mut cases {
        let related: Vec<&Case> = previous_cases
            .iter()
            .filter(|previous| same_advisory_instance(case, previous))
            .collect();
        // Verdicts and impact assessments are stored under the case ID, so a claim case keeps its
        // ID and an assessed one wins over a case without agent evidence.
        if let Some(previous) = related.iter().min_by_key(|previous| {
            (
                previous.claims.is_empty(),
                !previous
                    .evidence
                    .iter()
                    .any(|evidence| AGENT_EVIDENCE.contains(&evidence.source.as_str())),
                &previous.case_id,
            )
        }) {
            case.case_id = previous.case_id.clone();
        }
        for previous in &related {
            for event in &previous.upstream_events {
                if !case
                    .upstream_events
                    .iter()
                    .any(|kept| kept.id == event.id && kept.url == event.url)
                {
                    case.upstream_events.push(event.clone());
                }
            }
        }
        for previous in related.iter().filter(|previous| previous.claims.is_empty()) {
            for evidence in &previous.evidence {
                if !case
                    .evidence
                    .iter()
                    .any(|kept| kept.sha256 == evidence.sha256)
                {
                    case.evidence.push(evidence.clone());
                }
            }
        }
        merged_previous_ids.extend(related.iter().map(|previous| previous.case_id.clone()));
    }
    for case in &mut cases {
        // Registry, KEV catalogue and other context documents change daily without changing
        // the claim; instance context is already part of the base facts.
        let mut fact_hashes: Vec<&str> = case
            .evidence
            .iter()
            .filter(|evidence| {
                matches!(
                    evidence.kind,
                    EvidenceKind::Advisory | EvidenceKind::NonApplicability
                )
            })
            .map(|evidence| evidence.sha256.as_str())
            .collect();
        fact_hashes.sort_unstable();
        case.facts_sha256 =
            crate::digest(format!("{}:{fact_hashes:?}", case.facts_sha256).as_bytes());
        let Ok(previous) = store.case(&case.case_id) else {
            continue;
        };
        if previous.facts_sha256 == case.facts_sha256 {
            case.applicability = previous.applicability;
            case.verification = previous.verification;
            case.decision = previous.decision;
            case.evidence = previous.evidence;
        } else if previous
            .evidence
            .iter()
            .any(|evidence| AGENT_EVIDENCE.contains(&evidence.source.as_str()))
        {
            case.open_questions.push(format!(
                "Advisory evidence changed after the recorded {:?} verdict or impact assessment; reassess with the previous rationale in case history.",
                previous.decision
            ));
        }
    }
    let active_ids: HashSet<&str> = instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect();
    let current_ids: HashSet<String> = cases.iter().map(|case| case.case_id.clone()).collect();
    for mut previous in previous_cases {
        if merged_previous_ids.contains(&previous.case_id)
            || current_ids.contains(&previous.case_id)
            || !previous
                .instances
                .iter()
                .any(|instance| active_ids.contains(instance.id.as_str()))
        {
            continue;
        }
        previous.snapshot_id = snapshot_id.clone();
        let mut context_changed = false;
        for old_instance in &mut previous.instances {
            if let Some(current) = instances
                .iter()
                .find(|current| current.id == old_instance.id)
            {
                context_changed |= old_instance.context_fingerprint()
                    != current.context_fingerprint()
                    || old_instance.identity_replaced(current);
                *old_instance = current.clone();
            }
        }
        if context_changed {
            previous.facts_sha256 = crate::digest(
                format!(
                    "{}:{:?}",
                    previous.facts_sha256,
                    previous
                        .instances
                        .iter()
                        .map(Instance::context_fingerprint)
                        .collect::<Vec<_>>()
                )
                .as_bytes(),
            );
        }
        if !previous.claims.is_empty() || context_changed {
            previous.applicability = Applicability::Unknown;
            previous.verification = Verification::Inconclusive;
            previous.decision = Decision::Review;
            let question = if context_changed {
                "Monitored artifact or context changed; reassess the hypothesis and rerun any relevant verification."
            } else {
                "Previous advisory was not matched in this scan; source absence/failure is not proof of safety. Reassess."
            }.to_owned();
            if !previous.open_questions.contains(&question) {
                previous.open_questions.push(question);
            }
        }
        cases.push(previous);
    }
    coverage.push(Coverage::new(
        "research_web",
        "project",
        if matches!(profile.research.web, WebResearch::Agent) {
            CoverageState::Partial
        } else {
            CoverageState::Disabled
        },
        "upstream tracker review is performed by the configured local agent and imported separately",
    ));
    coverage.push(Coverage::new(
        "http_metrics",
        "project",
        CoverageState::Checked,
        format!(
            "requests={}, cache_hits={}, budget={}",
            http.requests, http.cache_hits, http.budget
        ),
    ));
    let partial = coverage
        .iter()
        .any(|item| !matches!(item.state, CoverageState::Checked | CoverageState::Disabled));
    Ok(Snapshot {
        schema_version: 1,
        id: snapshot_id,
        project_id: profile.project_id.to_string(),
        profile_sha256: profile_hash,
        started_at: start.into(),
        finished_at: crate::now(),
        instances,
        coverage,
        cases,
        partial,
        alert_status: "pending".into(),
    })
}
fn same_advisory_instance(current: &Case, previous: &Case) -> bool {
    let shared_instance = current
        .instances
        .iter()
        .any(|instance| previous.instances.iter().any(|old| old.id == instance.id));
    if !shared_instance {
        return false;
    }
    // A research case that announced the advisory before a source published it folds into the
    // claim case only when the claim covers every one of its instances.
    let research_case = previous.claims.is_empty()
        && previous.instances.iter().all(|old| {
            current
                .instances
                .iter()
                .any(|instance| instance.id == old.id)
        });
    for claim in &current.claims {
        for identifier in std::iter::once(&claim.id).chain(&claim.aliases) {
            if previous
                .claims
                .iter()
                .any(|old| old.id == *identifier || old.aliases.contains(identifier))
            {
                return true;
            }
            if research_case
                && previous.upstream_events.iter().any(|event| {
                    event.kind == "advisory"
                        && (event.id == *identifier
                            || event.id.ends_with(&format!("/{identifier}")))
                })
            {
                return true;
            }
        }
    }
    false
}
pub fn cases_from_claims(
    claims: &[Claim],
    instances: &[Instance],
    profile: &Profile,
    snapshot_id: &str,
    coverage: &[Coverage],
) -> Result<Vec<Case>> {
    // Connected alias sets merge transitively, but only within the same exact instance.
    let mut groups: Vec<Vec<Claim>> = Vec::new();
    for claim in claims {
        let identifiers: HashSet<&str> = std::iter::once(claim.id.as_str())
            .chain(claim.aliases.iter().map(String::as_str))
            .collect();
        let mut merged = vec![claim.clone()];
        let mut index = 0;
        while index < groups.len() {
            let overlaps = groups[index].iter().any(|existing| {
                existing.instance_id == claim.instance_id
                    && std::iter::once(&existing.id)
                        .chain(&existing.aliases)
                        .any(|id| {
                            identifiers.contains(id.as_str())
                                || merged
                                    .iter()
                                    .any(|item| item.id == *id || item.aliases.contains(id))
                        })
            });
            if overlaps {
                merged.extend(groups.remove(index));
                index = 0;
            } else {
                index += 1;
            }
        }
        groups.push(merged);
    }
    let mut cases = Vec::new();
    for mut group in groups {
        group.sort_by(|left, right| (&left.id, &left.source).cmp(&(&right.id, &right.source)));
        let instance = instances
            .iter()
            .find(|instance| instance.id == group[0].instance_id)
            .context("claim instance missing")?
            .clone();
        let mut identifiers: Vec<&str> = group
            .iter()
            .flat_map(|claim| {
                std::iter::once(claim.id.as_str()).chain(claim.aliases.iter().map(String::as_str))
            })
            .collect();
        identifiers.sort_unstable();
        let canonical = identifiers
            .iter()
            .find(|id| id.starts_with("CVE-"))
            .copied()
            .unwrap_or(identifiers[0]);
        let case_id = format!(
            "SIG-{}",
            &crate::digest(format!("{}:{canonical}", instance.id).as_bytes())[..20]
        );
        let affected = group
            .iter()
            .any(|claim| claim.applicability == Applicability::Affected);
        let conflict = group
            .iter()
            .any(|claim| claim.applicability == Applicability::Conflict)
            || affected
                && group
                    .iter()
                    .any(|claim| claim.applicability == Applicability::NotAffected);
        let observed_identity = instance.origin == crate::model::Origin::AgentObserved
            || instance
                .identity_evidence
                .iter()
                .any(|item| item.source == "agent_product_mapping");
        let applicability = if observed_identity {
            Applicability::Unknown
        } else if conflict {
            Applicability::Conflict
        } else if affected {
            Applicability::Affected
        } else if group
            .iter()
            .all(|claim| claim.applicability == Applicability::NotAffected)
        {
            Applicability::NotAffected
        } else {
            Applicability::Possible
        };
        let mut evidence: Vec<_> = group.iter().map(|claim| claim.evidence.clone()).collect();
        evidence.extend(instance.identity_evidence.clone());
        let facts = crate::digest(
            format!(
                "{}:{:?}:{:?}",
                instance.context_fingerprint(),
                instance.resolved_version,
                group
                    .iter()
                    .map(|claim| (
                        &claim.id,
                        &claim.source,
                        claim.applicability,
                        claim.known_exploited,
                        &claim.evidence.sha256
                    ))
                    .collect::<Vec<_>>()
            )
            .as_bytes(),
        );
        let verification = if affected && !conflict && !observed_identity {
            Verification::SourceConfirmed
        } else {
            Verification::Inconclusive
        };
        let decision = if affected && !conflict && !observed_identity {
            Decision::Actionable
        } else if applicability == Applicability::NotAffected {
            Decision::Informational
        } else {
            Decision::Review
        };
        let queries = search_queries(&instance, profile);
        cases.push(Case {
            schema_version: 1,
            case_id,
            project_id: profile.project_id.to_string(),
            snapshot_id: snapshot_id.into(),
            instances: vec![instance],
            claims: group,
            upstream_events: Vec::new(),
            evidence,
            coverage: coverage.to_owned(),
            applicability,
            verification,
            decision,
            facts_sha256: facts,
            open_questions: vec!["Confirm deployment, vendor build and relevant runtime conditions before remediation.".into()],
            suggested_search_queries: queries,
            sandbox: crate::sandbox::availability(),
            updated_at: crate::now(),
        });
    }
    Ok(cases)
}
fn search_queries(instance: &Instance, profile: &Profile) -> Vec<String> {
    if !matches!(profile.research.web, WebResearch::Agent) {
        return Vec::new();
    }
    // Only public package/product identifiers; no paths, profile names or freeform secrets.
    let name = &instance.reference;
    if name.len() > 200
        || name.contains(['\\', '\n', '\r', ':']) && !name.starts_with("pkg:")
        || name.contains("https://")
    {
        return Vec::new();
    }
    vec![format!(
        "{name} {} security advisory backport",
        instance
            .resolved_version
            .as_deref()
            .unwrap_or("version unknown")
    )]
}
pub fn triage(store: &mut Store, id: &str, verdict: Verdict) -> Result<Case> {
    let _lock = store.lock()?;
    let mut case = store.case(id)?;
    if verdict.schema_version != 1
        || verdict.case_id != id
        || verdict.facts_sha256 != case.facts_sha256
    {
        bail!("stale or mismatched verdict; reopen the current case");
    }
    if verdict.evidence.is_empty() || verdict.rationale.trim().is_empty() {
        bail!("verdict requires rationale and registered evidence");
    }
    let mut has_attestation = false;
    let mut positive_nonapplicability = false;
    for reference in &verdict.evidence {
        let evidence = case
            .evidence
            .iter()
            .find(|evidence| evidence.id == reference.id && evidence.sha256 == reference.sha256)
            .context("unknown evidence or forged attestation")?;
        if !store.evidence_exists(evidence)? {
            bail!("evidence integrity failed");
        }
        if evidence.kind == EvidenceKind::Attestation {
            let attestation = crate::sandbox::read_attestation(&case, store, evidence)?;
            has_attestation |= attestation.verification == Verification::LabReproduced;
            positive_nonapplicability |= attestation.verification == Verification::Disproven
                && attestation
                    .control
                    .as_ref()
                    .is_some_and(|control| control.oracle_matched && control.policy_verified);
        }
        positive_nonapplicability |= evidence.kind == EvidenceKind::NonApplicability;
    }
    if verdict.verification == Verification::LabReproduced && !has_attestation {
        bail!("lab_reproduced requires a CLI runtime attestation");
    }
    if verdict.decision == Decision::Dismissed
        && !(verdict.applicability == Applicability::NotAffected && positive_nonapplicability)
    {
        bail!(
            "dismissal requires positive non-applicability evidence; failure to reproduce is inconclusive"
        );
    }
    if verdict.decision == Decision::Actionable && verdict.applicability != Applicability::Affected
    {
        bail!("actionable requires affected applicability");
    }
    if verdict.verification == Verification::SourceConfirmed
        && !case
            .claims
            .iter()
            .any(|claim| claim.applicability == Applicability::Affected)
    {
        bail!("no authoritative affected claim for source_confirmed");
    }
    let authoritative_affected = case
        .claims
        .iter()
        .any(|claim| claim.applicability == Applicability::Affected);
    if verdict.decision == Decision::Actionable && !(authoritative_affected || has_attestation) {
        bail!(
            "actionable requires an authoritative affected claim or positive runtime attestation"
        );
    }
    if verdict.verification == Verification::Disproven && !positive_nonapplicability {
        bail!("disproven requires positive non-applicability evidence");
    }
    case.applicability = verdict.applicability;
    case.verification = verdict.verification;
    case.decision = verdict.decision;
    case.updated_at = crate::now();
    let verdict_evidence = store.record_evidence(
        &serde_json::to_vec(&verdict)?,
        "agent_verdict",
        None,
        EvidenceKind::Context,
    )?;
    case.evidence.push(verdict_evidence);
    store.save_case(&case)?;
    store.set_meta("last_agent_review", &case.updated_at)?;
    Ok(case)
}
