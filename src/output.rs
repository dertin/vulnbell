use crate::{
    model::{Decision, Snapshot, SourceFacts},
    profile::{Language, Profile},
    store::Store,
};
use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::params;
use sha2::Sha256;
use text::fill;
mod details;
mod discovery;
mod markdown;
pub(crate) mod text;
mod verification;
pub use details::AdvisoryDetail;
pub use discovery::discovery_markdown;
use markdown::inline;
pub use markdown::{morning_markdown, verification_markdown};
pub use text::report_language;
pub use verification::{FindingCheck, FindingReference, LocalCheck, LocalResult};

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
