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
    if profile.codebases.is_empty() && profile.components.is_empty() {
        bail!("empty_scope: add components or authorized codebases before scanning");
    }
    let mut store = Store::open(&profile.project_id.to_string())?;
    store.check_schema()?;
    let _lock = store.lock()?;
    store.register_project(&profile.name, path)?;
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
    let codebase_revisions = crate::codebase_revision::capture(profile, path);
    let snapshot_id = uuid::Uuid::new_v4().to_string();
    let codebase_context = crate::codebase_revision::fingerprint(&codebase_revisions);
    let profile_bytes = crate::read_limited(path, 1024 * 1024)?;
    let profile_hash = crate::digest(&profile_bytes);
    let mut instances: Vec<Instance> = profile.components.iter().map(Instance::declared).collect();
    let remaining = 100_000usize.saturating_sub(instances.len());
    let inventory = crate::inventory::discover(&profile.codebases, path, store, remaining);
    instances.extend(inventory.instances);
    let mut coverage = inventory.coverage;
    let discovery_coverage =
        crate::discovery::augment(profile, path, store, &mut instances, &mut coverage)?;
    coverage.extend(discovery_coverage);
    let previous_instances = if store.meta("last_snapshot")?.is_some() {
        store.latest()?.instances
    } else {
        Vec::new()
    };
    preserve_observation_ids(&mut instances, &mut coverage, &previous_instances, false);
    for instance in &mut instances {
        instance.provenance.codebase_context_sha256 = codebase_context.clone();
    }
    let mut http = Http::new(store, offline);
    for instance in &mut instances {
        coverage.extend(crate::identity::resolve(
            instance,
            &mut http,
            profile.python.verify_pypi_hashes,
        ));
        if profile.research.release_windows && profile.research.tracks(instance) {
            let declared_upstream = profile.components.iter().any(|component| {
                component.reference == instance.reference
                    && component.version == instance.requested_version
                    && component.upstream.is_some()
                    && component.upstream == instance.upstream
            });
            coverage.push(crate::research::release::acquire(
                instance,
                &mut http,
                declared_upstream,
            ));
        }
    }
    crate::inventory::merge_python(&mut instances, &mut coverage, &previous_instances, store);
    crate::discovery::apply_source_mappings(profile, path, store, &mut instances)?;
    let previous_cases = store.cases()?;
    let mut intelligence =
        crate::sources::scan(&instances, &mut http, &profile.research, &previous_cases);
    let vendor = crate::vendor::feeds(profile, &instances, &mut http);
    intelligence.claims.extend(vendor.claims);
    coverage.extend(intelligence.coverage);
    coverage.extend(vendor.coverage);
    let mut cases = cases_from_claims(
        &intelligence.claims,
        &instances,
        profile,
        &snapshot_id,
        &coverage,
    )?;
    for case in &mut cases {
        case.codebase_revisions = codebase_revisions.clone();
    }
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
            case.evidence = previous.evidence;
            if crate::codebase_revision::same_revisions(
                &previous.codebase_revisions,
                &case.codebase_revisions,
            ) {
                case.applicability = previous.applicability;
                case.verification = previous.verification;
                case.decision = previous.decision;
            } else {
                case.open_questions.push(
                    "Codebase revision changed; reassess the previous verdict and any local verification."
                        .into(),
                );
            }
        } else if previous
            .evidence
            .iter()
            .any(|evidence| AGENT_EVIDENCE.contains(&evidence.source.as_str()))
        {
            for evidence in &previous.evidence {
                if !case
                    .evidence
                    .iter()
                    .any(|existing| existing.sha256 == evidence.sha256)
                {
                    case.evidence.push(evidence.clone());
                }
            }
            case.applicability = Applicability::Unknown;
            case.verification = Verification::Inconclusive;
            case.decision = Decision::Review;
            case.open_questions.push(format!(
                "Advisory or monitored identity evidence changed after the recorded {:?} verdict or impact assessment; reassess with the previous rationale in case history.",
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
        {
            continue;
        }
        let mut context_changed = reconcile_research_instances(&mut previous, &instances)
            || !crate::codebase_revision::same_revisions(
                &previous.codebase_revisions,
                &codebase_revisions,
            );
        if !previous
            .instances
            .iter()
            .any(|instance| active_ids.contains(instance.id.as_str()))
        {
            continue;
        }
        previous.snapshot_id = snapshot_id.clone();
        previous.codebase_revisions = codebase_revisions.clone();
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
    let deferred_transitive = instances
        .iter()
        .filter(|instance| {
            !profile.research.tracks(instance) && instance.provenance.direct == Some(false)
        })
        .count();
    let deferred_unknown = instances
        .iter()
        .filter(|instance| {
            !profile.research.tracks(instance) && instance.provenance.direct.is_none()
        })
        .count();
    if deferred_transitive > 0 || deferred_unknown > 0 {
        coverage.push(Coverage::new("tracker_scope", "project", CoverageState::Partial, format!("tracker and repository-advisory research deferred for {deferred_transitive} transitive and {deferred_unknown} unknown-depth instances; OSV queries the full supported inventory independently and can be partial; unpublished repository advisories may be missed; use research.follow to inspect specific references")));
    }
    coverage.push(Coverage::new(
        "http_metrics",
        "project",
        CoverageState::Checked,
        format!(
            "requests={}, cache_hits={}, budget={}",
            http.requests, http.cache_hits, http.budget
        ),
    ));
    if !crate::codebase_revision::unchanged_during_scan(&codebase_revisions) {
        bail!("codebase Git context changed during scan; retry after the codebase is stable");
    }
    if codebase_revisions.iter().any(|revision| {
        revision.state == crate::codebase_revision::RepositoryState::Unavailable
            || revision.state == crate::codebase_revision::RepositoryState::Git
                && (revision.commit.is_none()
                    || revision.dirty.is_none()
                    || revision.worktree_status_sha256.is_none())
    }) {
        coverage.push(Coverage::new(
            "codebase_git",
            "project",
            CoverageState::Partial,
            "Git codebase identity or changed-file fingerprint could not be determined safely",
        ));
    }
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
        codebase_revisions,
        instances,
        coverage,
        cases,
        partial,
        alert_status: "pending".into(),
    })
}

pub(crate) fn preserve_observation_ids(
    instances: &mut [Instance],
    coverage: &mut [Coverage],
    previous: &[Instance],
    require_same_observation: bool,
) {
    use std::collections::{HashMap, HashSet};

    fn key(instance: &Instance) -> Option<(String, Option<String>, String, String)> {
        (instance.origin == crate::model::Origin::AgentObserved).then_some((
            instance.reference.clone(),
            instance.requested_version.clone(),
            instance.provenance.codebase.clone()?,
            instance.provenance.path.clone()?,
        ))
    }
    let mut old: HashMap<_, Vec<&Instance>> = HashMap::new();
    for instance in previous {
        if let Some(key) = key(instance) {
            old.entry(key).or_default().push(instance);
        }
    }
    let mut counts = HashMap::new();
    for instance in instances.iter() {
        if let Some(key) = key(instance) {
            *counts.entry(key).or_insert(0usize) += 1;
        }
    }
    let mut used: HashSet<String> = instances.iter().map(|item| item.id.clone()).collect();
    let mut replacements = HashMap::new();
    for instance in instances {
        let Some(k) = key(instance) else { continue };
        let Some([previous]) = old.get(&k).map(Vec::as_slice) else {
            continue;
        };
        let id = &previous.id;
        if require_same_observation
            && (previous.provenance.sha256 != instance.provenance.sha256
                || previous.provenance.direct != instance.provenance.direct)
        {
            continue;
        }
        if counts.get(&k) != Some(&1) || instance.id == *id || used.contains(id) {
            continue;
        }
        used.remove(&instance.id);
        used.insert(id.clone());
        replacements.insert(std::mem::replace(&mut instance.id, id.clone()), id.clone());
    }
    for item in coverage {
        if let Some(id) = replacements.get(&item.scope) {
            item.scope = id.clone();
        }
    }
}

fn reconcile_research_instances(case: &mut Case, current: &[Instance]) -> bool {
    if !case.claims.is_empty() || case.upstream_events.len() != 1 {
        return false;
    }
    let mut changed = false;
    for previous in &mut case.instances {
        if current.iter().any(|instance| instance.id == previous.id) {
            continue;
        }
        let mut candidates = current.iter().filter(|instance| {
            instance.reference == previous.reference
                && instance.origin == previous.origin
                && instance.provenance.codebase == previous.provenance.codebase
                && instance.provenance.path == previous.provenance.path
                && !previous.identity_replaced(instance)
        });
        if let (Some(replacement), None) = (candidates.next(), candidates.next()) {
            *previous = replacement.clone();
            changed = true;
        }
    }
    if changed {
        let mut retained = HashSet::new();
        case.instances
            .retain(|instance| retained.insert(instance.id.clone()));
    }
    changed
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
            codebase_revisions: Vec::new(),
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

fn has_affected_claim(case: &Case, store: &Store) -> bool {
    case.claims.iter().any(|claim| {
        claim.applicability == Applicability::Affected
            && store.evidence_exists(&claim.evidence).unwrap_or(false)
    })
}

fn valid_translation(
    case: &Case,
    store: &Store,
    translation: &crate::model::AdvisoryTranslation,
) -> bool {
    !translation.summary.trim().is_empty()
        && translation.summary.len() <= 4000
        && case.claims.iter().any(|claim| {
            claim.evidence.sha256 == translation.source_sha256
                && matches!(claim.source.as_str(), "osv" | "ghsa" | "github_repository")
                && store.evidence_exists(&claim.evidence).unwrap_or(false)
        })
}

pub fn current_verdict(case: &Case, store: &Store) -> Option<Verdict> {
    if crate::tools::challenge::blocks_verdict(case, store) {
        return None;
    }
    let (verdict_index, evidence) = case
        .evidence
        .iter()
        .enumerate()
        .rev()
        .find(|(_, item)| item.source == "agent_verdict")?;
    if let Some(impact_index) = case
        .evidence
        .iter()
        .rposition(|item| item.source == "impact_assessment")
        && (impact_index > verdict_index || crate::impact::latest(case, store).is_none())
    {
        return None;
    }
    if case.evidence.iter().skip(verdict_index + 1).any(|item| {
        item.kind == EvidenceKind::Attestation
            && crate::sandbox::read_attestation(case, store, item).is_ok()
    }) {
        return None;
    }
    if !store.evidence_exists(evidence).ok()? {
        return None;
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        64 * 1024,
    )
    .ok()?;
    let verdict: Verdict = serde_json::from_slice(&bytes).ok()?;
    if verdict.schema_version != 1
        || verdict.case_id != case.case_id
        || verdict.facts_sha256 != case.facts_sha256
        || !crate::codebase_revision::same_revisions(
            &verdict.codebase_revisions,
            &case.codebase_revisions,
        )
        || verdict.decision != case.decision
        || verdict.applicability != case.applicability
        || verdict.verification != case.verification
        || verdict.rationale.trim().is_empty()
        || verdict.evidence.is_empty()
        || verdict
            .advisory_translation
            .as_ref()
            .is_some_and(|translation| !valid_translation(case, store, translation))
    {
        return None;
    }
    let mut has_attestation = false;
    for reference in &verdict.evidence {
        let cited = case
            .evidence
            .iter()
            .find(|item| item.id == reference.id && item.sha256 == reference.sha256)?;
        if !store.evidence_exists(cited).ok()? {
            return None;
        }
        if cited.source == "review_challenge"
            && crate::tools::challenge::read_challenge(case, store, cited).is_none()
        {
            return None;
        }
        if cited.kind == EvidenceKind::Attestation {
            let attestation = crate::sandbox::read_attestation(case, store, cited).ok()?;
            has_attestation |= attestation.verification == Verification::LabReproduced;
        }
    }
    if (verdict.verification == Verification::SourceConfirmed
        || verdict.decision == Decision::Actionable && !has_attestation)
        && !has_affected_claim(case, store)
    {
        return None;
    }
    Some(verdict)
}

pub fn triage(store: &mut Store, id: &str, mut verdict: Verdict) -> Result<Case> {
    triage_checked(store, id, &mut verdict, None, Vec::new())
}

pub(crate) fn triage_if_current(
    store: &mut Store,
    id: &str,
    mut verdict: Verdict,
    expected: &Case,
    new_evidence: Vec<crate::model::Evidence>,
) -> Result<Case> {
    triage_checked(store, id, &mut verdict, Some(expected), new_evidence)
}

fn triage_checked(
    store: &mut Store,
    id: &str,
    verdict: &mut Verdict,
    expected: Option<&Case>,
    new_evidence: Vec<crate::model::Evidence>,
) -> Result<Case> {
    let _lock = store.lock()?;
    store.ensure_codebases_current()?;
    let mut case = store.case(id)?;
    if let Some(expected) = expected
        && serde_json::to_vec(&case)? != serde_json::to_vec(expected)?
    {
        bail!("case changed during verdict submission; review the current case");
    }
    for evidence in new_evidence {
        if evidence.source != "local_impact_evidence"
            || evidence.kind != EvidenceKind::Context
            || !store.evidence_exists(&evidence)?
        {
            bail!("verdict note has invalid evidence or integrity");
        }
        if !case
            .evidence
            .iter()
            .any(|item| item.source == evidence.source && item.sha256 == evidence.sha256)
        {
            case.evidence.push(evidence);
        }
    }
    if case
        .evidence
        .iter()
        .any(|item| item.source == "impact_assessment")
        && crate::impact::latest(&case, store).is_none()
    {
        bail!(
            "impact assessment is stale, invalid or incompatible; reassess it before recording a verdict"
        );
    }
    verdict.codebase_revisions = case.codebase_revisions.clone();
    if verdict.schema_version != 1
        || verdict.case_id != id
        || verdict.facts_sha256 != case.facts_sha256
    {
        bail!("stale or mismatched verdict; reopen the current case");
    }
    if verdict.evidence.is_empty() || verdict.rationale.trim().is_empty() {
        bail!("verdict requires rationale and registered evidence");
    }
    if verdict
        .advisory_translation
        .as_ref()
        .is_some_and(|translation| !valid_translation(&case, store, translation))
    {
        bail!(
            "advisory translation requires a bounded summary and intact original advisory evidence"
        );
    }
    if crate::tools::challenge::unresolved_challenges(&case, store)
        .iter()
        .any(|challenge| {
            !verdict.evidence.iter().any(|reference| {
                reference.id == challenge.id && reference.sha256 == challenge.sha256
            })
        })
    {
        bail!("new verdict must address and cite the unresolved challenge");
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
        if evidence.source == "review_challenge"
            && crate::tools::challenge::read_challenge(&case, store, evidence).is_none()
        {
            bail!("challenge evidence integrity failed");
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
    if (verdict.verification == Verification::SourceConfirmed
        || verdict.decision == Decision::Actionable && !has_attestation)
        && !has_affected_claim(&case, store)
    {
        if verdict.verification == Verification::SourceConfirmed {
            bail!("no authoritative affected claim with intact evidence for source_confirmed");
        }
        bail!(
            "actionable requires an affected claim with intact evidence or positive runtime attestation"
        );
    }
    if verdict.verification == Verification::Disproven && !positive_nonapplicability {
        bail!("disproven requires positive non-applicability evidence");
    }
    let verdict_bytes = serde_json::to_vec(&verdict)?;
    if verdict_bytes.len() > 64 * 1024 {
        bail!("verdict exceeds the 64 KiB evidence limit");
    }
    case.applicability = verdict.applicability;
    case.verification = verdict.verification;
    case.decision = verdict.decision;
    case.updated_at = crate::now();
    let verdict_evidence =
        store.record_evidence(&verdict_bytes, "agent_verdict", None, EvidenceKind::Context)?;
    case.evidence.push(verdict_evidence);
    store.save_case(&case)?;
    store.set_meta("last_agent_review", &case.updated_at)?;
    Ok(case)
}

#[cfg(test)]
mod observation_id_tests {
    use super::preserve_observation_ids;
    use crate::{
        model::{Coverage, CoverageState, Instance, Origin},
        profile::{Component, Usage},
    };

    fn observed(id: &str, path: &str) -> Instance {
        let mut instance = Instance::declared(&Component {
            reference: "pkg:pypi/example".into(),
            version: Some("1.0.0".into()),
            usage: Usage::Tracked,
            upstream: None,
            feeds: vec![],
        });
        instance.id = id.into();
        instance.origin = Origin::AgentObserved;
        instance.provenance.path = Some(path.into());
        instance.provenance.codebase = Some("/project".into());
        instance
    }

    #[test]
    fn refreshed_observation_preserves_cases_only_for_an_unambiguous_identity() {
        let old = observed("previous", "compose.yml");
        let mut current = vec![observed("new", "compose.yml")];
        let mut gaps = vec![Coverage::new(
            "identity",
            "new",
            CoverageState::Partial,
            "gap",
        )];
        preserve_observation_ids(&mut current, &mut gaps, std::slice::from_ref(&old), false);
        assert_eq!(current[0].id, "previous");
        assert_eq!(gaps[0].scope, "previous");

        let mut changed = vec![observed("new", "compose.yml")];
        changed[0].provenance.sha256 = "different".into();
        preserve_observation_ids(&mut changed, &mut [], std::slice::from_ref(&old), true);
        assert_eq!(changed[0].id, "new");
        let mut changed_relation = vec![observed("new", "compose.yml")];
        changed_relation[0].provenance.direct = Some(false);
        preserve_observation_ids(
            &mut changed_relation,
            &mut [],
            std::slice::from_ref(&old),
            true,
        );
        assert_eq!(changed_relation[0].id, "new");

        let mut ambiguous = vec![
            observed("one", "compose.yml"),
            observed("two", "compose.yml"),
        ];
        preserve_observation_ids(&mut ambiguous, &mut [], &[old], false);
        assert_eq!(ambiguous[0].id, "one");
        assert_eq!(ambiguous[1].id, "two");
    }
}
