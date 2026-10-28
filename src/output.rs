use crate::{
    discovery::{MappingState, SourceKind},
    impact::{ImpactAnswerValue, ImpactQuestionId, ImpactResult, ImpactVerdict},
    model::{Decision, Snapshot, SourceFacts},
    profile::{Language, Profile},
    store::Store,
};
use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::params;
use sha2::Sha256;
use std::collections::BTreeSet;
use text::fill;
mod details;
pub(crate) mod text;
mod verification;
pub use details::AdvisoryDetail;
pub use text::report_language;
pub use verification::{FindingCheck, FindingReference, LocalCheck, LocalResult};

/// Names listed inline before the remainder is counted and deferred to the JSON report.
const SUMMARY_LIST: usize = 30;

pub fn notify(profile: &Profile, snapshot: &Snapshot, store: &Store) -> Result<String> {
    let Some(variable) = &profile.alerts.webhook_env else {
        return Ok("not_configured; inbox and reports available".into());
    };
    let url = std::env::var(variable).context("configured webhook environment variable missing")?;
    let key =
        std::env::var("VULNBELL_WEBHOOK_HMAC_KEY").context("VULNBELL_WEBHOOK_HMAC_KEY missing")?;
    if key.len() < 32 {
        bail!("webhook HMAC key must contain at least 32 bytes");
    }
    let (client, url) = crate::network::public_client(&url)?;
    let mut sent = 0;
    for case in &snapshot.cases {
        if !matches!(case.decision, Decision::Actionable | Decision::Review) {
            continue;
        }
        let id = crate::digest(
            format!(
                "{}:{}:{}:{:?}",
                snapshot.project_id, case.case_id, case.facts_sha256, case.decision
            )
            .as_bytes(),
        );
        let exists: bool = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM alerts WHERE id=?1)",
            [&id],
            |row| row.get(0),
        )?;
        if exists {
            continue;
        }
        // Public-safe envelope: no paths, unpublished issues, proprietary source, or vulnerability details.
        let body = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"id":id,"project_id":snapshot.project_id,"case_id":case.case_id,"decision":case.decision,"applicability":case.applicability,"verification":case.verification,"facts_sha256":case.facts_sha256,"message":"Review the local VulnBell inbox for evidence and coverage"}),
        )?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())?;
        mac.update(&body);
        let signature = hex::encode(mac.finalize().into_bytes());
        let response = client
            .post(url.clone())
            .header("X-VulnBell-Signature", format!("sha256={signature}"))
            .header("Idempotency-Key", &id)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|_| anyhow::anyhow!("webhook delivery failed"))?;
        if !response.status().is_success() {
            bail!(
                "webhook returned HTTP {}; retry uses the same idempotency key",
                response.status()
            );
        }
        store.connection.execute(
            "INSERT OR IGNORE INTO alerts VALUES (?1,?2)",
            params![id, crate::now()],
        )?;
        sent += 1;
    }
    Ok(format!(
        "delivered={sent}; deduplicated by case facts and decision"
    ))
}
pub fn markdown(snapshot: &Snapshot) -> String {
    let mut report = format!(
        "# VulnBell\n\nProject: `{}`\n\nScan: {}\n\nCoverage: **{}**. Alerts: {}\n\n{} instances; {} cases.\n\n",
        snapshot.project_id,
        snapshot.finished_at,
        if snapshot.partial {
            "partial"
        } else {
            "checked"
        },
        snapshot.alert_status,
        snapshot.instances.len(),
        snapshot.cases.len()
    );
    for case in &snapshot.cases {
        report.push_str(&format!(
            "- `{}`: {:?}; {:?}; {:?}\n",
            case.case_id, case.decision, case.applicability, case.verification
        ));
    }
    report.push_str("\n## Coverage\n\n");
    for coverage in &snapshot.coverage {
        report.push_str(&format!(
            "- {} / `{}`: {:?} — {}\n",
            coverage.source,
            coverage.scope,
            coverage.state,
            coverage.detail.replace(['\n', '\r'], " ")
        ));
    }
    report
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct MorningReport {
    /// Current report contract distinguishes candidates from explicitly required checks.
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub audience: String,
    /// Report language from the profile; the generated sentences in this report use it.
    pub language: Language,
    pub project_id: String,
    pub project_name: String,
    pub generated_at: String,
    pub last_scan: String,
    pub last_successful_scan: Option<String>,
    pub last_agent_review: Option<String>,
    pub scheduler_id: Option<String>,
    pub inventory: Vec<MonitoredComponent>,
    pub actionable: Vec<HandoffItem>,
    pub needs_review: Vec<HandoffItem>,
    pub informational_count: usize,
    pub dismissed_count: usize,
    /// Upstream events the agent assessed as not affecting the monitored versions; no case is opened.
    pub not_applicable_count: usize,
    pub coverage_gaps: Vec<crate::model::Coverage>,
    pub notification_status: String,
    pub finding_checks: Vec<FindingCheck>,
    pub discovery: Option<crate::discovery::DiscoverySummary>,
    pub source_map: Vec<crate::discovery::IdentityObservation>,
    /// Open cases whose verification is unfinished; a deliverable report requires none.
    pub verification_pending: Vec<PendingVerification>,
}
#[derive(serde::Serialize, schemars::JsonSchema, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum PendingReason {
    /// `vulnbell impact` has not been answered for the current case facts.
    ImpactNotAssessed,
    /// An unconfirmed signal needs an explicit review disposition, not necessarily a test.
    ReviewDispositionMissing,
    /// A test was explicitly required and has neither a result nor a categorized blocker.
    SandboxCheckMissing,
    /// Recorded verification evidence could not be validated.
    InvalidVerificationEvidence,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct PendingVerification {
    pub case_id: String,
    pub reason: PendingReason,
}
fn pending_verification(check: &FindingCheck) -> Option<PendingReason> {
    if !matches!(check.decision, Decision::Actionable | Decision::Review) {
        return None;
    }
    if check.impact.is_none() {
        return Some(PendingReason::ImpactNotAssessed);
    }
    if check
        .local_checks
        .iter()
        .any(|local| local.result == LocalResult::InvalidEvidence)
    {
        return Some(PendingReason::InvalidVerificationEvidence);
    }
    if check.decision == Decision::Review
        && check
            .review_handoff
            .as_ref()
            .is_some_and(|handoff| !handoff.sandbox_required)
    {
        return None;
    }
    let unsettled = |local: &LocalCheck| match local.result {
        LocalResult::NotRun => true,
        LocalResult::Blocked => local.blocker.is_none(),
        _ => false,
    };
    if check
        .local_checks
        .iter()
        .any(|local| local.sandbox_needed && unsettled(local))
    {
        return Some(PendingReason::SandboxCheckMissing);
    }
    if (check.decision == Decision::Review && check.review_handoff_stale)
        || (check.review_handoff.is_none()
            && check
                .local_checks
                .iter()
                .any(|local| local.sandbox_candidate && unsettled(local)))
    {
        return Some(PendingReason::ReviewDispositionMissing);
    }
    None
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct MonitoredComponent {
    pub instance_id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub requested_version: Option<String>,
    pub resolved_version: Option<String>,
    pub origin: crate::model::Origin,
    pub workspace: Option<String>,
    pub path: Option<String>,
    pub line: Option<usize>,
    pub upstream: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct HandoffItem {
    pub case_id: String,
    pub components: Vec<String>,
    /// Where each component version was read: `workspace/path:line`, or the profile.
    pub provenance: Vec<String>,
    pub origin: Vec<crate::model::Origin>,
    /// Latest recorded agent verdict (`decision: rationale`), when one exists.
    pub recorded_verdict: Option<String>,
    pub summary: String,
    pub advisory_details: Vec<AdvisoryDetail>,
    pub detail_gaps: Vec<String>,
    pub applicability: crate::model::Applicability,
    pub verification: crate::model::Verification,
    pub known_exploited: bool,
    pub evidence_links: Vec<String>,
    pub evidence_sha256: Vec<String>,
    pub open_questions: Vec<String>,
    pub recommended_action: String,
    /// What the cited upstream items state (affected versions, fix, required feature).
    pub source_facts: Vec<SourceFacts>,
}
pub fn morning_report(snapshot: &Snapshot, store: &Store, audience: &str) -> Result<MorningReport> {
    let (discovery, source_map, language) = match store.meta("profile_path")? {
        Some(path) => {
            let path = std::path::Path::new(&path);
            match crate::profile::load(path) {
                Ok(profile) => (
                    Some(crate::discovery::summary(&profile, path, store)?),
                    crate::discovery::source_map(&profile, path, store)?,
                    profile.report.language,
                ),
                Err(_) => (None, Vec::new(), Language::default()),
            }
        }
        None => (None, Vec::new(), Language::default()),
    };
    let words = text::text(language);
    let active_ids: std::collections::HashSet<&str> = snapshot
        .instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect();
    let mut actionable = Vec::new();
    let mut needs_review = Vec::new();
    let mut informational_count = 0;
    let mut dismissed_count = 0;
    for case in &snapshot.cases {
        if !case
            .instances
            .iter()
            .any(|instance| active_ids.contains(instance.id.as_str()))
        {
            continue;
        }
        match case.decision {
            Decision::Informational => {
                informational_count += 1;
                continue;
            }
            Decision::Dismissed => {
                dismissed_count += 1;
                continue;
            }
            _ => (),
        }
        let mut links: Vec<String> = case
            .evidence
            .iter()
            .filter_map(|evidence| evidence.url.clone())
            .chain(case.upstream_events.iter().map(|event| event.url.clone()))
            .collect();
        links.sort();
        links.dedup();
        let components: Vec<String> = case
            .instances
            .iter()
            .map(|instance| {
                format!(
                    "{} {}",
                    instance.reference,
                    instance
                        .resolved_version
                        .as_deref()
                        .unwrap_or(words.unresolved)
                )
            })
            .collect();
        let origin: Vec<crate::model::Origin> = case
            .instances
            .iter()
            .map(|instance| instance.origin)
            .collect();
        let summary = match (case.claims.first(), case.upstream_events.first()) {
            (Some(claim), _) => claim.summary.clone(),
            (_, Some(event)) => event.title.clone(),
            _ => words.investigation_pending.to_owned(),
        };
        let recommended_action = if case.decision == Decision::Actionable {
            words.action_actionable
        } else {
            words.action_review
        };
        let mut advisory_details = Vec::new();
        let mut detail_gaps = Vec::new();
        for claim in &case.claims {
            match details::read(claim, &case.instances, store) {
                Ok(Some(detail)) => advisory_details.push(detail),
                Ok(None) => (),
                Err(_) => detail_gaps.push(fill(words.detail_gap, &[&claim.source, &claim.id])),
            }
        }
        let item = HandoffItem {
            case_id: case.case_id.clone(),
            components,
            provenance: case
                .instances
                .iter()
                .map(|instance| provenance_label(instance, language))
                .collect(),
            origin,
            recorded_verdict: recorded_verdict(case, store, language),
            summary,
            advisory_details,
            detail_gaps,
            applicability: case.applicability,
            verification: case.verification,
            known_exploited: case.claims.iter().any(|claim| claim.known_exploited),
            evidence_links: links,
            evidence_sha256: case
                .evidence
                .iter()
                .map(|evidence| evidence.sha256.clone())
                .collect(),
            open_questions: case
                .open_questions
                .iter()
                .map(|question| text::open_question(language, question))
                .collect(),
            recommended_action: recommended_action.into(),
            source_facts: case
                .upstream_events
                .iter()
                .map(|event| event.source_facts.clone())
                .filter(|facts| !facts.is_empty())
                .fold(Vec::new(), |mut kept, facts| {
                    if !kept.contains(&facts) {
                        kept.push(facts);
                    }
                    kept
                }),
        };
        if case.decision == Decision::Actionable {
            actionable.push(item);
        } else {
            needs_review.push(item);
        }
    }
    actionable.sort_by_key(|item| !item.known_exploited);
    let finding_checks: Vec<FindingCheck> = snapshot
        .cases
        .iter()
        .filter(|case| {
            case.instances
                .iter()
                .any(|instance| active_ids.contains(instance.id.as_str()))
        })
        .map(|case| verification::finding_check(case, store, language))
        .collect();
    Ok(MorningReport {
        schema_version: 1,
        audience: audience.into(),
        language,
        project_id: snapshot.project_id.clone(),
        project_name: store
            .meta("project_name")?
            .unwrap_or_else(|| snapshot.project_id.clone()),
        generated_at: crate::now(),
        last_scan: snapshot.finished_at.clone(),
        last_successful_scan: store.meta("last_successful_scan")?,
        last_agent_review: store.meta("last_agent_review")?,
        scheduler_id: store.meta("scheduler_id")?,
        inventory: snapshot
            .instances
            .iter()
            .map(|instance| MonitoredComponent {
                instance_id: instance.id.clone(),
                reference: instance.reference.clone(),
                requested_version: instance.requested_version.clone(),
                resolved_version: instance.resolved_version.clone(),
                origin: instance.origin,
                workspace: instance.provenance.workspace.clone(),
                path: instance.provenance.path.clone(),
                line: instance.provenance.line,
                upstream: instance.upstream.clone(),
            })
            .collect(),
        actionable,
        needs_review,
        informational_count,
        dismissed_count,
        not_applicable_count: store.connection.query_row(
            "SELECT COUNT(*) FROM research_events WHERE json_extract(body,'$.assessment')='not_applicable'",
            [],
            |row| row.get(0),
        )?,
        coverage_gaps: snapshot
            .coverage
            .iter()
            .filter(|coverage| {
                if coverage.source == "general_discovery"
                    && coverage.scope == "project"
                    && discovery.is_some()
                {
                    return false;
                }
                !matches!(
                    coverage.state,
                    crate::model::CoverageState::Checked | crate::model::CoverageState::Disabled
                )
            })
            .cloned()
            .chain(
                discovery
                    .as_ref()
                    .filter(|summary| summary.enabled && !summary.complete)
                    .map(crate::discovery::coverage),
            )
            .collect(),
        discovery,
        source_map,
        notification_status: snapshot.alert_status.clone(),
        verification_pending: finding_checks
            .iter()
            .filter_map(|check| {
                pending_verification(check).map(|reason| PendingVerification {
                    case_id: check.case_id.clone(),
                    reason,
                })
            })
            .collect(),
        finding_checks,
    })
}
fn case_impact<'a>(report: &'a MorningReport, case_id: &str) -> Option<&'a ImpactResult> {
    report
        .finding_checks
        .iter()
        .find(|check| check.case_id == case_id)?
        .impact
        .as_ref()
}

/// Cases without an assessment rank with those that need evidence.
fn impact_rank(report: &MorningReport, case_id: &str) -> u8 {
    crate::impact::verdict_priority(
        case_impact(report, case_id).map_or(ImpactVerdict::NeedsEvidence, |impact| impact.verdict),
    )
}

/// An affected library version whose recorded project impact rules out exposure.
fn contained(impact: &ImpactResult) -> bool {
    matches!(
        impact.verdict,
        ImpactVerdict::NotAffected | ImpactVerdict::Mitigated
    )
}

/// The rationale of the answer that closed the project impact.
fn containment_reason(impact: &ImpactResult) -> &str {
    impact
        .answers
        .iter()
        .find(|answer| {
            answer.answer == ImpactAnswerValue::No
                && answer.question != ImpactQuestionId::FixOrMitigationApplied
        })
        .or_else(|| {
            impact.answers.iter().find(|answer| {
                answer.answer == ImpactAnswerValue::Yes
                    && answer.question == ImpactQuestionId::FixOrMitigationApplied
            })
        })
        .map_or("", |answer| answer.rationale.as_str())
}

fn impact_action(language: Language, verdict: ImpactVerdict, fixes: &str) -> Option<String> {
    let words = text::text(language);
    let target = if fixes.is_empty() {
        words.fix_target_default
    } else {
        fixes
    };
    let template = match verdict {
        ImpactVerdict::UrgentUpdate => words.action_urgent,
        ImpactVerdict::PriorityUpdate => words.action_priority,
        ImpactVerdict::RoutineUpdate => words.action_routine,
        ImpactVerdict::NeedsEvidence | ImpactVerdict::NotAffected | ImpactVerdict::Mitigated => {
            return None;
        }
    };
    Some(fill(template, &[&target]))
}

fn fixed_versions(item: &HandoffItem) -> String {
    let mut fixes: Vec<&str> = item
        .advisory_details
        .iter()
        .flat_map(|detail| detail.fixed_versions.iter().map(String::as_str))
        .collect();
    fixes.sort_unstable();
    fixes.dedup();
    fixes.join(", ")
}

fn impact_summary(report: &MorningReport, case_id: &str) -> Option<String> {
    let impact = case_impact(report, case_id)?;
    Some(fill(
        text::text(report.language).impact_summary,
        &[
            &text::impact_verdict(report.language, impact.verdict),
            &text::confidence(report.language, impact.confidence),
        ],
    ))
}

fn provenance_label(instance: &crate::model::Instance, language: Language) -> String {
    let words = text::text(language);
    let version = instance
        .resolved_version
        .as_deref()
        .unwrap_or(words.unresolved);
    let location = match (&instance.provenance.workspace, &instance.provenance.path) {
        (workspace, Some(path)) => {
            let file = match workspace {
                Some(workspace) => format!("{}/{path}", workspace.trim_end_matches('/')),
                None => path.clone(),
            };
            match instance.provenance.line {
                Some(line) => format!("{file}:{line}"),
                None => file,
            }
        }
        (_, None) => words.profile_location.to_owned(),
    };
    format!("{} {version} — {location}", instance.reference)
}

const LISTED_COMPONENTS: usize = 3;

/// Component labels of one case; more than a few that share version and location, such as every
/// artifact of one release in an SBOM, become one count with examples. JSON keeps the full list.
fn components_label(provenance: &[String], language: Language) -> String {
    if provenance.len() <= LISTED_COMPONENTS {
        return provenance.join("; ");
    }
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
    for label in provenance {
        let (component, origin) = label
            .split_once(' ')
            .map_or((label.as_str(), ""), |(reference, rest)| (reference, rest));
        match groups.iter_mut().find(|(known, _)| *known == origin) {
            Some((_, components)) => components.push(component),
            None => groups.push((origin, vec![component])),
        }
    }
    groups
        .into_iter()
        .map(|(origin, components)| {
            if components.len() <= LISTED_COMPONENTS {
                return components
                    .iter()
                    .map(|component| format!("{component} {origin}"))
                    .collect::<Vec<_>>()
                    .join("; ");
            }
            let examples = components
                .iter()
                .take(2)
                .map(|component| component.rsplit('/').next().unwrap_or(component))
                .collect::<Vec<_>>()
                .join(", ");
            fill(
                text::text(language).components_group,
                &[&components.len(), &origin, &examples],
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn recorded_verdict(
    case: &crate::model::Case,
    store: &Store,
    language: Language,
) -> Option<String> {
    let evidence = case
        .evidence
        .iter()
        .rev()
        .find(|evidence| evidence.source == "agent_verdict")?;
    if !store.evidence_exists(evidence).ok()? {
        return None;
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        64 * 1024,
    )
    .ok()?;
    let verdict: crate::model::Verdict = serde_json::from_slice(&bytes).ok()?;
    Some(format!(
        "{}: {}",
        text::decision(language, verdict.decision),
        verdict.rationale
    ))
}

pub fn discovery_markdown(report: &MorningReport) -> String {
    let language = report.language;
    let words = text::text(language);
    let mut text = String::new();
    if let Some(discovery) = &report.discovery {
        let state = if !discovery.enabled {
            words.discovery_disabled
        } else if discovery.complete {
            words.discovery_complete
        } else {
            words.discovery_partial
        };
        text.push_str(&fill(
            words.discovery,
            &[
                &state,
                &discovery.directories_pending,
                &discovery.files_pending,
                &discovery.files_reviewed,
                &discovery.files_excluded,
                &discovery.files_unavailable,
                &discovery.components_unmapped,
                &discovery.sources_unavailable,
                &discovery.deferred_transitive,
                &discovery.deferred_unknown_depth,
            ],
        ));
    }
    if !report.source_map.is_empty() {
        let open_instances: std::collections::HashSet<&str> = report
            .finding_checks
            .iter()
            .filter(|check| matches!(check.decision, Decision::Actionable | Decision::Review))
            .flat_map(|check| {
                check
                    .local_checks
                    .iter()
                    .map(|local| local.instance_id.as_str())
            })
            .collect();
        let without_repository: Vec<&str> = report
            .source_map
            .iter()
            .filter(|mapping| {
                !mapping.sources.iter().any(|source| {
                    source.kind == SourceKind::Repository && source.state == MappingState::Mapped
                })
            })
            .map(|mapping| {
                report
                    .inventory
                    .iter()
                    .find(|item| item.instance_id == mapping.instance_id)
                    .map(|item| item.reference.as_str())
                    .unwrap_or(&mapping.instance_id)
            })
            .collect();
        text.push_str(&fill(
            words.source_map,
            &[
                &report.source_map.len(),
                &(report.source_map.len() - without_repository.len()),
                &without_repository.len(),
            ],
        ));
        if !without_repository.is_empty() {
            let mut names: Vec<&str> = without_repository.clone();
            names.sort_unstable();
            names.dedup();
            let shown = names
                .iter()
                .take(SUMMARY_LIST)
                .map(|name| inline(name))
                .collect::<Vec<_>>();
            let more = if names.len() > SUMMARY_LIST {
                fill(words.and_more_json, &[&(names.len() - SUMMARY_LIST)])
            } else {
                String::new()
            };
            text.push_str(&fill(words.without_repository, &[&shown.join(", "), &more]));
        }
        let detailed: Vec<_> = report
            .source_map
            .iter()
            .filter(|mapping| open_instances.contains(mapping.instance_id.as_str()))
            .collect();
        if detailed.is_empty() {
            return text;
        }
        text.push_str(words.source_map_table);
        let mut shown = BTreeSet::new();
        let mut rows: Vec<SourceMapRow> = Vec::new();
        for mapping in detailed {
            let reference = report
                .inventory
                .iter()
                .find(|item| item.instance_id == mapping.instance_id)
                .map(|item| item.reference.as_str())
                .unwrap_or(&mapping.instance_id);
            if !shown.insert(reference) {
                continue;
            }
            let repository = mapping
                .sources
                .iter()
                .find(|source| source.kind == SourceKind::Repository);
            let repository_url = repository.and_then(|source| source.url.as_deref());
            let repository_cell = match repository {
                Some(source) if source.state == MappingState::Mapped => {
                    inline(repository_url.unwrap_or("—"))
                }
                Some(source) => fill(words.repository_unavailable, &[&inline(&source.detail)]),
                None => "—".to_owned(),
            };
            let mut others = Vec::new();
            let mut releases = None;
            let mut unmapped = Vec::new();
            // The scan reads the advisories of a mapped GitHub repository and reports their
            // coverage separately, so they are not an unmapped source.
            let repository_advisories_read = repository.is_some_and(|source| {
                source.state == MappingState::Mapped
                    && repository_url.is_some_and(|url| url.starts_with("https://github.com/"))
            });
            for source in &mapping.sources {
                if source.kind == SourceKind::Repository
                    || source.kind == SourceKind::Advisories && repository_advisories_read
                {
                    continue;
                }
                match (source.state, source.url.as_deref()) {
                    (MappingState::Mapped, Some(url)) if Some(url) != repository_url => {
                        let label = format!(
                            "{}: {}",
                            text::source_kind(language, source.kind),
                            inline(url)
                        );
                        if source.kind == SourceKind::Releases {
                            releases = Some(label);
                        } else {
                            others.push(label);
                        }
                    }
                    (MappingState::Mapped, _) => {}
                    (MappingState::Unavailable, _) => {
                        unmapped.push(text::source_kind(language, source.kind));
                    }
                    (MappingState::NotApplicable, _) => {}
                }
            }
            let row = SourceMapRow {
                repository: repository_cell,
                others: others.join("; "),
                unmapped: unmapped.join(", "),
                members: vec![(reference.to_owned(), releases)],
            };
            match rows.iter_mut().find(|known| {
                known.repository == row.repository
                    && known.others == row.others
                    && known.unmapped == row.unmapped
            }) {
                Some(known) => known.members.extend(row.members),
                None => rows.push(row),
            }
        }
        for row in rows {
            let unmapped = if row.unmapped.is_empty() {
                "—".to_owned()
            } else {
                row.unmapped.clone()
            };
            if row.members.len() <= LISTED_COMPONENTS {
                for (reference, releases) in &row.members {
                    let others: Vec<&str> = [row.others.as_str()]
                        .into_iter()
                        .chain(releases.as_deref())
                        .filter(|value| !value.is_empty())
                        .collect();
                    text.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        inline(reference),
                        row.repository,
                        if others.is_empty() {
                            "—".to_owned()
                        } else {
                            others.join("; ")
                        },
                        unmapped
                    ));
                }
                continue;
            }
            let examples = row
                .members
                .iter()
                .take(2)
                .map(|(reference, _)| inline(reference))
                .collect::<Vec<_>>()
                .join(", ");
            let releases = row
                .members
                .iter()
                .filter(|(_, releases)| releases.is_some())
                .count();
            let others: Vec<String> = [row.others.clone()]
                .into_iter()
                .chain((releases > 0).then(|| fill(words.releases_per_component, &[&releases])))
                .filter(|value| !value.is_empty())
                .collect();
            text.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                fill(words.components_examples, &[&row.members.len(), &examples]),
                row.repository,
                if others.is_empty() {
                    "—".to_owned()
                } else {
                    others.join("; ")
                },
                unmapped
            ));
        }
        text.push('\n');
    }
    text
}

/// Components with the same repository, other sources and unmapped categories share one row;
/// their per-component release pages stay in JSON.
struct SourceMapRow {
    repository: String,
    others: String,
    unmapped: String,
    members: Vec<(String, Option<String>)>,
}

pub fn morning_markdown(report: &MorningReport) -> String {
    let language = report.language;
    let words = text::text(language);
    let mut text = fill(
        words.header,
        &[
            &inline(&report.project_name),
            &report.last_scan,
            &report.last_agent_review.as_deref().unwrap_or(words.pending),
            &report.actionable.len(),
            &report.needs_review.len(),
            &report.informational_count,
            &report.dismissed_count,
            &report.not_applicable_count,
            &coverage_groups(&report.coverage_gaps).len(),
            &report.coverage_gaps.len(),
        ],
    );
    for (items, label) in [
        (&report.actionable, words.contained_actionable_prefix),
        (&report.needs_review, words.contained_review_prefix),
    ] {
        let contained_count = items
            .iter()
            .filter(|item| case_impact(report, &item.case_id).is_some_and(contained))
            .count();
        if contained_count > 0 {
            text.push_str(&fill(
                words.contained_split,
                &[&label, &(items.len() - contained_count), &contained_count],
            ));
        }
    }
    if !report.verification_pending.is_empty() {
        let count = |reason| {
            report
                .verification_pending
                .iter()
                .filter(|pending| pending.reason == reason)
                .count()
        };
        text.insert_str(
            text.find("\n\n").map_or(0, |index| index + 2),
            &fill(
                words.incomplete_banner,
                &[
                    &count(PendingReason::ImpactNotAssessed),
                    &count(PendingReason::ReviewDispositionMissing),
                    &count(PendingReason::SandboxCheckMissing),
                    &count(PendingReason::InvalidVerificationEvidence),
                ],
            ),
        );
    }
    text.push_str(&inventory_markdown(&report.inventory, language));
    text.push_str(&discovery_markdown(report));
    for (decision, items) in [
        (Decision::Actionable, &report.actionable),
        (Decision::Review, &report.needs_review),
    ] {
        let label = if decision == Decision::Actionable {
            words.heading_actionable
        } else {
            words.heading_review
        };
        text.push_str(&format!("## {label}\n\n"));
        if items.is_empty() {
            text.push_str(words.no_findings);
            continue;
        }
        if decision == Decision::Review {
            let (contained_items, mut rows): (Vec<&HandoffItem>, Vec<&HandoffItem>) = items
                .iter()
                .partition(|item| case_impact(report, &item.case_id).is_some_and(contained));
            rows.sort_by_key(|item| std::cmp::Reverse(impact_rank(report, &item.case_id)));
            if rows.is_empty() {
                text.push_str(words.no_exposed_hypotheses);
            } else {
                text.push_str(words.review_table_header);
            }
            for item in rows {
                let handoff = report
                    .finding_checks
                    .iter()
                    .find(|check| check.case_id == item.case_id)
                    .and_then(|check| check.review_handoff.as_ref());
                let mut review_context = fill(
                    words.review_context,
                    &[
                        &text::applicability(language, item.applicability),
                        &text::verification(language, item.verification),
                    ],
                );
                for facts in &item.source_facts {
                    review_context.push_str(words.per_source);
                    review_context.push_str(&source_facts_text(facts, language));
                    review_context.push('.');
                }
                if handoff.is_none() {
                    for question in &item.open_questions {
                        review_context.push(' ');
                        review_context.push_str(question);
                    }
                }
                if let Some(verdict) = &item.recorded_verdict {
                    review_context.push_str(words.recorded_verdict_inline);
                    review_context.push_str(verdict);
                }
                if let Some(impact) = impact_summary(report, &item.case_id) {
                    review_context.push_str(words.impact_inline);
                    review_context.push_str(&impact);
                }
                if let Some(handoff) = handoff {
                    review_context.push(' ');
                    review_context.push_str(&handoff.rationale);
                    review_context.push(' ');
                    review_context.push_str(&handoff.uncertainty);
                }
                let link = item
                    .evidence_links
                    .first()
                    .map(|link| {
                        format!(
                            "<{}>",
                            link.replace(['<', '>', '\n', '\r'], "").replace('|', "%7C")
                        )
                    })
                    .unwrap_or_else(|| words.no_link.into());
                let blocked = report
                    .finding_checks
                    .iter()
                    .find(|check| check.case_id == item.case_id)
                    .is_some_and(|check| {
                        !check.local_checks.is_empty()
                            && check
                                .local_checks
                                .iter()
                                .all(|local| local.result == LocalResult::Blocked)
                    });
                let next_step = if let Some(handoff) = handoff {
                    inline(&handoff.next_step)
                } else if blocked {
                    words.resolve_blocker.to_owned()
                } else {
                    inline(&item.recommended_action)
                };
                text.push_str(&format!(
                    "| {} / {} | {} | {} | {} | {} |\n",
                    inline(&item.case_id),
                    inline(&components_label(&item.provenance, language)),
                    inline(&item.summary),
                    inline(&review_context),
                    next_step,
                    link
                ));
            }
            text.push('\n');
            text.push_str(&contained_markdown(
                report,
                &contained_items,
                words.contained_review_heading,
            ));
            continue;
        }
        let (contained_items, mut cards): (Vec<&HandoffItem>, Vec<&HandoffItem>) = items
            .iter()
            .partition(|item| case_impact(report, &item.case_id).is_some_and(contained));
        cards.sort_by_key(|item| std::cmp::Reverse(impact_rank(report, &item.case_id)));
        if cards.is_empty() {
            text.push_str(words.no_exposed_findings);
        }
        for item in cards {
            let impact = case_impact(report, &item.case_id);
            let fixes = fixed_versions(item);
            text.push_str(&format!(
                "### {} — {}\n\n",
                item.case_id,
                inline(&item.summary)
            ));
            if item.provenance.len() > LISTED_COMPONENTS {
                text.push_str(&fill(
                    words.card_components,
                    &[
                        &item.provenance.len(),
                        &inline(&components_label(&item.provenance, language)),
                    ],
                ));
            } else {
                for provenance in &item.provenance {
                    text.push_str(&fill(words.card_component, &[&inline(provenance)]));
                }
            }
            if let Some(verdict) = &item.recorded_verdict {
                text.push_str(&fill(words.card_verdict, &[&inline(verdict)]));
            }
            text.push_str(&fill(
                words.card_impact,
                &[&impact_summary(report, &item.case_id)
                    .unwrap_or_else(|| words.impact_not_assessed.to_owned())],
            ));
            text.push_str(&fill(
                words.card_state,
                &[
                    &text::applicability(language, item.applicability),
                    &text::verification(language, item.verification),
                    &if item.known_exploited {
                        words.kev_yes
                    } else {
                        words.kev_none
                    },
                ],
            ));
            for facts in &item.source_facts {
                text.push_str(&fill(
                    words.card_source_facts,
                    &[&inline(&source_facts_text(facts, language))],
                ));
            }
            let mut severities = item
                .advisory_details
                .iter()
                .filter_map(|detail| {
                    detail.severity.as_ref().map(|severity| {
                        format!(
                            "{}: {} ({})",
                            text::source_label(language, &detail.source),
                            severity,
                            detail.advisory_id
                        )
                    })
                })
                .collect::<Vec<_>>();
            severities.sort();
            severities.dedup();
            if !severities.is_empty() {
                text.push_str(&fill(
                    words.card_severity,
                    &[&inline(&severities.join("; "))],
                ));
            }
            let mut descriptions = Vec::new();
            for detail in &item.advisory_details {
                let normalized = advisory_excerpt(&detail.description);
                if !normalized.is_empty() && !descriptions.contains(&normalized) {
                    descriptions.push(normalized);
                }
            }
            for description in descriptions.iter().take(2) {
                let excerpt = description.chars().take(300).collect::<String>();
                text.push_str(&fill(
                    words.card_problem,
                    &[
                        &inline(&excerpt),
                        &if description.chars().count() > 300 {
                            words.excerpt_more
                        } else {
                            ""
                        },
                    ],
                ));
            }
            text.push_str(&fill(
                words.card_fixes,
                &[&if fixes.is_empty() {
                    words.no_fix.to_owned()
                } else {
                    fill(words.fix_check, &[&inline(&fixes)])
                }],
            ));
            match impact {
                Some(impact) => {
                    let mut seen = std::collections::BTreeSet::new();
                    for answer in &impact.answers {
                        let assessed = !matches!(
                            answer.question,
                            ImpactQuestionId::ArtifactDeployed
                                | ImpactQuestionId::FixOrMitigationApplied
                        );
                        if assessed && seen.insert((answer.question, answer.rationale.as_str())) {
                            let label = text::impact_question(language, answer.question);
                            let mut label_chars = label.chars();
                            let label = label_chars.next().map_or(String::new(), |first| {
                                first.to_uppercase().chain(label_chars).collect()
                            });
                            text.push_str(&format!(
                                "- **{}:** {} — {}\n",
                                label,
                                text::impact_answer(language, answer.answer),
                                inline(&answer.rationale)
                            ));
                        }
                    }
                    let mut open: Vec<&str> = impact
                        .instances
                        .iter()
                        .flat_map(|instance| instance.open_questions.iter())
                        .map(|question| text::impact_question(language, *question))
                        .collect();
                    open.sort_unstable();
                    open.dedup();
                    if !open.is_empty() {
                        text.push_str(&format!(
                            "- **{}:** {}.\n",
                            words.to_check,
                            inline(&open.join(", "))
                        ));
                    }
                }
                None => {
                    for question in &item.open_questions {
                        text.push_str(&format!("- **{}:** {}\n", words.to_check, inline(question)));
                    }
                }
            }
            let action = impact
                .and_then(|impact| impact_action(language, impact.verdict, &fixes))
                .unwrap_or_else(|| item.recommended_action.clone());
            text.push_str(&format!("- **{}:** {}\n", words.action, inline(&action)));
            for link in &item.evidence_links {
                text.push_str(&format!(
                    "- **{}:** <{}>\n",
                    words.evidence,
                    link.replace(['<', '>', '\n', '\r'], "")
                ));
            }
            for gap in &item.detail_gaps {
                text.push_str(&format!(
                    "- **{}:** {}\n",
                    words.detail_pending,
                    inline(gap)
                ));
            }
            text.push('\n');
        }
        text.push_str(&contained_markdown(
            report,
            &contained_items,
            words.contained_actionable_heading,
        ));
    }
    text.push_str(&coverage_markdown(report));
    text.push_str(&fill(
        words.delivery,
        &[&inline(&text::notification_status(
            language,
            &report.notification_status,
        ))],
    ));
    text.push_str(&verification_section(report, false));
    text
}
/// Advisories that match the version but whose recorded impact rules out project exposure, one
/// row per component and recorded reason; per-case detail stays in the JSON report.
fn contained_markdown(report: &MorningReport, items: &[&HandoffItem], heading: &str) -> String {
    if items.is_empty() {
        return String::new();
    }
    let words = text::text(report.language);
    let mut groups: std::collections::BTreeMap<(String, String), Vec<&HandoffItem>> =
        std::collections::BTreeMap::new();
    for item in items {
        let reason = case_impact(report, &item.case_id)
            .map(containment_reason)
            .unwrap_or_default()
            .to_owned();
        groups
            .entry((components_label(&item.provenance, report.language), reason))
            .or_default()
            .push(item);
    }
    let mut text = fill(words.contained_table, &[&heading, &items.len()]);
    for ((component, reason), group) in groups {
        let mut labels: Vec<String> = group.iter().flat_map(|item| case_labels(item)).collect();
        labels.sort();
        labels.dedup();
        let shown = if labels.len() > CONTAINED_LABELS {
            fill(
                words.and_more,
                &[
                    &labels[..CONTAINED_LABELS].join(", "),
                    &(labels.len() - CONTAINED_LABELS),
                ],
            )
        } else {
            labels.join(", ")
        };
        let mut fixes: Vec<String> = group.iter().map(|item| fixed_versions(item)).collect();
        fixes.retain(|fix| !fix.is_empty());
        fixes.sort();
        fixes.dedup();
        text.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            inline(&component),
            inline(&shown),
            inline(&reason),
            inline(&fixes.join("; "))
        ));
    }
    text.push('\n');
    text
}

const CONTAINED_LABELS: usize = 6;

/// Advisory IDs, or `owner/repo#number` for upstream research events, so a reader can find the
/// source without the internal case ID.
fn case_labels(item: &HandoffItem) -> Vec<String> {
    if !item.advisory_details.is_empty() {
        return item
            .advisory_details
            .iter()
            .map(|detail| detail.advisory_id.clone())
            .collect();
    }
    let forge = item.evidence_links.iter().find_map(|link| {
        let url = url::Url::parse(link).ok()?;
        let segments: Vec<&str> = url.path_segments()?.collect();
        match segments.as_slice() {
            [owner, repo, "issues" | "pull", number, ..] => {
                Some(format!("{owner}/{repo}#{number}"))
            }
            _ => None,
        }
    });
    vec![forge.unwrap_or_else(|| item.case_id.clone())]
}

/// Locked packages are summarized per lockfile; declared, deployed and observed components are
/// listed with their source location. The full inventory stays in the JSON report.
fn inventory_markdown(inventory: &[MonitoredComponent], language: Language) -> String {
    let words = text::text(language);
    let mut text = words.inventory_heading.to_owned();
    let mut lockfiles: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut listed = Vec::new();
    for component in inventory {
        let location = match (&component.workspace, &component.path) {
            (Some(workspace), Some(path)) => format!("{}/{path}", workspace.trim_end_matches('/')),
            (None, Some(path)) => path.clone(),
            (_, None) => words.profile_location.to_owned(),
        };
        if component.origin == crate::model::Origin::Locked {
            *lockfiles.entry(location).or_default() += 1;
        } else {
            let location = match component.line {
                Some(line) => format!("{location}:{line}"),
                None => location,
            };
            listed.push((component, location));
        }
    }
    if !lockfiles.is_empty() {
        text.push_str(words.lockfile_table);
        for (location, count) in &lockfiles {
            text.push_str(&format!("| {} | {count} |\n", inline(location)));
        }
        text.push('\n');
    }
    if !listed.is_empty() {
        text.push_str(words.inventory_table);
        for (component, location) in listed {
            text.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                inline(&component.reference),
                inline(
                    component
                        .resolved_version
                        .as_deref()
                        .unwrap_or(words.unresolved)
                ),
                inline(&location),
                text::origin(language, component.origin)
            ));
        }
        text.push('\n');
    }
    text.push_str(&fill(words.inventory_total, &[&inventory.len()]));
    text
}

/// Gaps sharing source, state and detail are one row with a count and example scopes.
fn coverage_groups(gaps: &[crate::model::Coverage]) -> Vec<(&crate::model::Coverage, Vec<&str>)> {
    let mut groups: Vec<(&crate::model::Coverage, Vec<&str>)> = Vec::new();
    for gap in gaps {
        match groups.iter_mut().find(|(first, _)| {
            first.source == gap.source && first.state == gap.state && first.detail == gap.detail
        }) {
            Some((_, scopes)) => scopes.push(&gap.scope),
            None => groups.push((gap, vec![&gap.scope])),
        }
    }
    groups
}

/// Scopes are instance IDs; readers need the component they stand for.
fn coverage_markdown(report: &MorningReport) -> String {
    let language = report.language;
    let words = text::text(language);
    let scope_label = |scope: &str| {
        report
            .inventory
            .iter()
            .find(|component| component.instance_id == scope)
            .map_or_else(
                || inline(scope),
                |component| {
                    let version = component
                        .resolved_version
                        .as_deref()
                        .or(component.requested_version.as_deref())
                        .unwrap_or(words.no_version);
                    inline(&format!("{} {version}", component.reference))
                },
            )
    };
    let mut text = words.coverage_table.to_owned();
    for (gap, scopes) in coverage_groups(&report.coverage_gaps) {
        let examples = scopes
            .iter()
            .take(3)
            .map(|scope| scope_label(scope))
            .collect::<Vec<_>>();
        let scope = if scopes.len() > 3 {
            fill(words.scope_examples, &[&scopes.len(), &examples.join(", ")])
        } else {
            examples.join(", ")
        };
        text.push_str(&format!(
            "| {} | {} | {}: {} |\n",
            inline(&text::source_label(language, &gap.source)),
            scope,
            text::coverage_state(language, gap.state),
            inline(&gap.detail)
        ));
    }
    text
}

/// Standalone section for outputs that do not render the case cards.
pub fn verification_markdown(report: &MorningReport) -> String {
    verification_section(report, true)
}

/// Only open cases with possible project exposure get references and local checks; the rest are
/// counted and keep their detail in the JSON report.
fn verification_section(report: &MorningReport, impact_answers: bool) -> String {
    let open: Vec<&FindingCheck> = report
        .finding_checks
        .iter()
        .filter(|check| matches!(check.decision, Decision::Actionable | Decision::Review))
        .collect();
    let (contained_checks, exposed): (Vec<&FindingCheck>, Vec<&FindingCheck>) = open
        .iter()
        .partition(|check| check.impact.as_ref().is_some_and(contained));
    let words = text::text(report.language);
    let mut text = verification::markdown(&exposed, impact_answers, report.language);
    if !contained_checks.is_empty() {
        text.push_str(&fill(words.open_contained_note, &[&contained_checks.len()]));
    }
    let closed = report.finding_checks.len() - open.len();
    if closed > 0 {
        text.push_str(&fill(words.closed_note, &[&closed]));
    }
    text
}
fn advisory_excerpt(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !(line.starts_with('_') && line.ends_with('_'))
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn inline(value: &str) -> String {
    let escaped = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('|', "\\|");
    escape_underscores(&escaped)
}

/// An underscore between two alphanumerics never opens or closes emphasis (`KC_DB_URL`).
fn escape_underscores(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut escaped = String::with_capacity(value.len());
    for (index, character) in characters.iter().enumerate() {
        let intraword = index > 0
            && characters[index - 1].is_alphanumeric()
            && characters
                .get(index + 1)
                .is_some_and(|next| next.is_alphanumeric());
        if *character == '_' && !intraword {
            escaped.push('\\');
        }
        escaped.push(*character);
    }
    escaped
}

fn source_facts_text(facts: &SourceFacts, language: Language) -> String {
    let words = text::text(language);
    let mut parts = Vec::new();
    if !facts.identifiers.is_empty() {
        parts.push(fill(words.cites, &[&facts.identifiers.join(", ")]));
    }
    for (label, value) in [
        (words.affects, &facts.affected_versions),
        (words.fixed_in, &facts.fixed_in),
        (words.fix, &facts.fix_reference),
        (words.requires, &facts.required_feature),
    ] {
        if !value.trim().is_empty() {
            parts.push(format!("{label}: {}", value.trim()));
        }
    }
    parts.join("; ")
}
