use crate::{
    model::{CoverageState, Decision, Snapshot, SourceFacts},
    profile::{Language, Profile},
    store::Store,
};
use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::params;
use sha2::Sha256;
use text::fill;
mod audit;
pub(crate) mod branding;
mod details;
mod discovery;
mod history;
mod markdown;
mod pdf;
mod report_paths;
pub(crate) use pdf::browser_path;
pub(crate) mod text;
mod verification;
pub use audit::{audit_markdown, audit_markdown_with_closed, markdown};
pub use details::AdvisoryDetail;
pub use discovery::discovery_markdown;
pub use history::{AuditReport, enrich_json as enrich_report_json, retracted_cases};
use markdown::inline;

pub fn custom_content_notice(language: Language, reason: &str) -> String {
    let reason = inline(reason);
    match language {
        Language::Es => format!(
            "> **Contenido personalizado:** el texto fue editado fuera de VulnBell y no fue validado por la CLI. Motivo indicado: {reason}.\n\n"
        ),
        Language::En => format!(
            "> **Custom content:** the text was edited outside VulnBell and was not validated by the CLI. Stated reason: {reason}.\n\n"
        ),
    }
}
pub use markdown::{morning_markdown, verification_markdown};

pub fn custom_report_branding(markdown: &str, language: Language) -> Result<String> {
    branding::custom(markdown, language)
}

pub fn report_codebase_paths(text: &str, roots: &[String]) -> String {
    report_paths::relative_paths(text, roots.iter().map(String::as_str))
}

fn report_codebase_roots(snapshot: &Snapshot) -> Vec<String> {
    snapshot
        .codebase_revisions
        .iter()
        .chain(
            snapshot
                .cases
                .iter()
                .flat_map(|case| &case.codebase_revisions),
        )
        .map(|revision| revision.codebase.clone())
        .collect()
}

fn report_codebase_roots_with_history(
    existing_roots: &[String],
    expected_project_id: &str,
    store: &Store,
) -> Result<Vec<String>> {
    const MAX_SNAPSHOTS: usize = 10_000;
    const MAX_ROOTS: usize = 1_024;
    let mut roots: std::collections::BTreeSet<String> = existing_roots.iter().cloned().collect();
    let mut statement = store.connection.prepare(
        "SELECT id, json_extract(body, '$.id'), json_extract(body, '$.project_id'), \
         json_extract(body, '$.schema_version'), json_extract(body, '$.codebase_revisions') \
         FROM snapshots LIMIT 10001",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next().context("invalid historical snapshot JSON")? {
        count += 1;
        if count > MAX_SNAPSHOTS {
            bail!("historical snapshot limit exceeded; cannot safely render portable report paths");
        }
        let id: String = row.get(0)?;
        let recorded_id: String = row.get(1).context("historical snapshot ID is missing")?;
        let project_id: String = row
            .get(2)
            .context("historical snapshot project is missing")?;
        let schema: u32 = row
            .get(3)
            .context("historical snapshot schema is missing")?;
        let revisions: String = row
            .get(4)
            .context("historical codebase revisions are missing")?;
        if id != recorded_id || project_id != expected_project_id || schema != 1 {
            bail!(
                "historical snapshot metadata is incompatible; cannot safely render portable report paths"
            );
        }
        let revisions: Vec<crate::codebase_revision::CodebaseRevision> =
            serde_json::from_str(&revisions).context("invalid historical codebase revisions")?;
        roots.extend(revisions.into_iter().map(|revision| revision.codebase));
        if roots.len() > MAX_ROOTS {
            bail!("historical codebase limit exceeded; cannot safely render portable report paths");
        }
    }
    if roots.len() > MAX_ROOTS {
        bail!("codebase limit exceeded; cannot safely render portable report paths");
    }
    Ok(roots.into_iter().collect())
}

/// Load and validate historical path metadata once before producing a shareable report.
pub fn prepare_report_paths(report: &mut MorningReport, store: &Store) -> Result<()> {
    ensure_morning_report_store(report, store)?;
    if !report.codebase_paths_ready {
        let roots = report_codebase_roots_with_history(
            &report.codebase_path_roots,
            &report.project_id,
            store,
        )?;
        report.codebase_path_roots = roots;
        report.codebase_paths_ready = true;
    }
    Ok(())
}

fn ensure_morning_report_store(report: &MorningReport, store: &Store) -> Result<()> {
    ensure_report_store(&report.project_id, store)?;
    if report.store_directory != store.directory {
        bail!("report and store use different local state directories");
    }
    Ok(())
}

fn ensure_report_store(project_id: &str, store: &Store) -> Result<()> {
    if store.directory.file_name().and_then(|name| name.to_str()) != Some(project_id) {
        bail!("report and store refer to different projects");
    }
    Ok(())
}

pub fn normalize_report_paths(report: &MorningReport, text: &str) -> Result<String> {
    if !report.codebase_paths_ready {
        bail!(
            "report paths have not been prepared; validate historical snapshots before rendering"
        );
    }
    Ok(report_codebase_paths(text, &report.codebase_path_roots))
}

/// Report research coverage from current checkpoints, separately from the scan snapshot.
pub fn add_research_coverage(
    report: &mut MorningReport,
    pending: &crate::tools::cases::PendingReport,
) {
    if !pending.research_open.is_empty()
        || pending.tracker_scope_unresolved
        || pending.stale_observations > 0
        || pending.codebase_context_changed
    {
        let detail = match report.language {
            Language::Es => format!(
                "{} ventanas upstream pendientes; {} observaciones desactualizadas requieren un nuevo escaneo; alcance de fuentes sin resolver: {}; codebase cambiada o no disponible: {}",
                pending.research_open.len(),
                pending.stale_observations,
                if pending.tracker_scope_unresolved {
                    "sí"
                } else {
                    "no"
                },
                if pending.codebase_context_changed {
                    "sí"
                } else {
                    "no"
                }
            ),
            Language::En => format!(
                "{} upstream windows pending; {} stale observations require a new scan; tracker scope unresolved: {}; codebase changed or unavailable: {}",
                pending.research_open.len(),
                pending.stale_observations,
                if pending.tracker_scope_unresolved {
                    "yes"
                } else {
                    "no"
                },
                if pending.codebase_context_changed {
                    "yes"
                } else {
                    "no"
                }
            ),
        };
        report.coverage_gaps.push(crate::model::Coverage::new(
            "research_web",
            "project",
            crate::model::CoverageState::Partial,
            &detail,
        ));
    }
}

/// Summarize the actual delivery gate without hiding unresolved work.
pub fn delivery_status_markdown(
    pending: &crate::tools::cases::PendingReport,
    scan_partial: bool,
    language: crate::profile::Language,
) -> String {
    if pending.deliverable && !scan_partial {
        return String::new();
    }
    let discovery = pending.discovery_open.is_some();
    match language {
        crate::profile::Language::Es => format!(
            "> **Cobertura o revisión incompleta:** verificaciones pendientes: {}; veredictos pendientes: {}; hallazgos de código por reevaluar: {}; revisiones de código pendientes: {}; ventanas upstream pendientes: {}; observaciones desactualizadas: {}; descubrimiento pendiente: {}; alcance de fuentes sin resolver: {}; codebase cambiada o sin identificar: {}; escaneo parcial: {}. Consulte `vulnbell tools pending` para el detalle.\n\n",
            pending.verification_pending.len(),
            pending.verdict_missing.len(),
            pending.code_findings_pending.len(),
            pending.code_reviews_pending.len(),
            pending.research_open.len(),
            pending.stale_observations,
            if discovery { "sí" } else { "no" },
            if pending.tracker_scope_unresolved {
                "sí"
            } else {
                "no"
            },
            if pending.codebase_context_changed {
                "sí"
            } else {
                "no"
            },
            if scan_partial { "sí" } else { "no" },
        ),
        crate::profile::Language::En => format!(
            "> **Incomplete coverage or review:** {} pending verifications, {} verdicts, {} code findings to reassess, {} code reviews pending, {} upstream windows and {} stale observations; discovery pending: {}; tracker scope unresolved: {}; codebase changed or unidentified: {}; partial scan: {}. See `vulnbell tools pending` for details.\n\n",
            pending.verification_pending.len(),
            pending.verdict_missing.len(),
            pending.code_findings_pending.len(),
            pending.code_reviews_pending.len(),
            pending.research_open.len(),
            pending.stale_observations,
            if discovery { "yes" } else { "no" },
            if pending.tracker_scope_unresolved {
                "yes"
            } else {
                "no"
            },
            if pending.codebase_context_changed {
                "yes"
            } else {
                "no"
            },
            if scan_partial { "yes" } else { "no" },
        ),
    }
}
pub use pdf::{prepared_pdf_markdown, report_body as pdf_report_body, write_pdf};
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
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct MorningReport {
    /// Local roots used only to render portable report references.
    #[serde(skip)]
    codebase_path_roots: Vec<String>,
    #[serde(skip)]
    codebase_paths_ready: bool,
    #[serde(skip)]
    store_directory: std::path::PathBuf,
    /// Current report contract distinguishes candidates from explicitly required checks.
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub audience: String,
    pub closed: ClosedMode,
    /// Report language from the profile; the generated sentences in this report use it.
    pub language: Language,
    pub project_id: String,
    pub project_name: String,
    pub generated_at: String,
    pub last_scan: String,
    pub last_successful_scan: Option<String>,
    pub last_agent_review: Option<String>,
    pub scheduler_id: Option<String>,
    /// Git identities recorded by the scan and the codebase state at report time.
    pub codebase_revisions: Vec<crate::codebase_revision::CodebaseComparison>,
    pub codebase_context_unrecorded: bool,
    pub codebase_scope_changed: bool,
    pub inventory: Vec<MonitoredComponent>,
    pub actionable: Vec<HandoffItem>,
    /// Agent-reviewed codebase findings, separate from dependency advisories.
    pub code_findings: Vec<CodeFinding>,
    /// Recorded independent codebase reviews; an absent entry means none was recorded.
    pub code_reviews: Vec<crate::tools::code_review::Review>,
    pub scheduled_code_review: bool,
    pub needs_review: Vec<HandoffItem>,
    pub informational_count: usize,
    pub informational: Vec<InformationalSummary>,
    /// Closed case details and evidence, regardless of Markdown detail mode.
    pub closed_cases: Vec<crate::model::Case>,
    /// Retracted cases and their recorded revisions, retained for audit.
    pub retracted: Vec<RetractedCase>,
    pub dismissed_count: usize,
    /// Recorded upstream non-applicability assessments, including cases later reopened.
    pub not_applicable_count: usize,
    pub coverage_gaps: Vec<crate::model::Coverage>,
    pub notification_status: String,
    pub finding_checks: Vec<FindingCheck>,
    pub discovery: Option<crate::discovery::DiscoverySummary>,
    pub source_map: Vec<crate::discovery::IdentityObservation>,
    /// Open cases whose verification is unfinished; a deliverable report requires none.
    pub verification_pending: Vec<PendingVerification>,
}
#[derive(
    Clone, Copy, Debug, serde::Serialize, schemars::JsonSchema, clap::ValueEnum, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum ClosedMode {
    Summary,
    Full,
    None,
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct InformationalSummary {
    pub case_id: String,
    pub components: Vec<String>,
    pub reason: String,
    pub impact_assessed: bool,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct RetractedCase {
    pub case: crate::model::Case,
    pub history: Vec<crate::model::Case>,
    pub research_events: Vec<crate::research::ResearchEvent>,
    /// Missing, corrupt or undecodable evidence IDs; `agent_retraction_assessment:missing`
    /// indicates that no retraction assessment was recorded.
    pub evidence_gaps: Vec<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct CodeFinding {
    pub id: String,
    pub finding: crate::tools::code_findings::Submission,
    pub recorded_at: String,
    pub current: bool,
    pub source_removed: bool,
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
#[derive(Clone, serde::Serialize, schemars::JsonSchema)]
pub struct PendingVerification {
    pub case_id: String,
    pub reason: PendingReason,
}
fn pending_verification(check: &FindingCheck) -> Option<PendingReason> {
    if !matches!(check.decision, Decision::Actionable | Decision::Review)
        && !check.impact_reassessment_required
    {
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
    /// Canonical PURL with the resolved version, when both are known.
    pub versioned_purl: Option<String>,
    pub origin: crate::model::Origin,
    pub codebase: Option<String>,
    pub path: Option<String>,
    pub line: Option<usize>,
    pub direct: Option<bool>,
    pub direct_source: Option<crate::model::SourceLine>,
    pub dependency_parents: Vec<String>,
    pub upstream: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct HandoffItem {
    pub case_id: String,
    pub components: Vec<String>,
    /// Where each component version was read: `codebase/path:line`, or the profile.
    pub provenance: Vec<String>,
    pub origin: Vec<crate::model::Origin>,
    /// Latest recorded agent verdict (`decision: rationale`), when one exists.
    pub recorded_verdict: Option<String>,
    pub summary: String,
    pub advisory_details: Vec<AdvisoryDetail>,
    pub advisory_translation: Option<crate::model::AdvisoryTranslation>,
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
    let projected = crate::research::project_retractions(snapshot, store);
    morning_report_current(&projected, store, audience)
}

/// Render a snapshot whose retraction evidence has already been checked for this operation.
pub fn morning_report_current(
    snapshot: &Snapshot,
    store: &Store,
    audience: &str,
) -> Result<MorningReport> {
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
    let codebase_revisions = crate::codebase_revision::compare(&snapshot.codebase_revisions);
    let codebase_scope_changed = if !snapshot.codebase_revisions.is_empty() {
        store
            .meta("profile_path")?
            .and_then(|path| {
                let profile = crate::profile::load(std::path::Path::new(&path)).ok()?;
                Some(!crate::codebase_revision::configured_paths_match(
                    &snapshot.codebase_revisions,
                    &profile,
                    std::path::Path::new(&path),
                ))
            })
            .unwrap_or(true)
    } else {
        false
    };
    let codebase_context_unrecorded = if snapshot.codebase_revisions.is_empty() {
        store
            .meta("profile_path")?
            .and_then(|path| {
                let profile = crate::profile::load(std::path::Path::new(&path)).ok()?;
                Some(!profile.codebases.is_empty())
            })
            .unwrap_or(false)
    } else {
        false
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
    let mut informational = Vec::new();
    let mut dismissed_count = 0;
    for case in &snapshot.cases {
        if case.decision != Decision::Retracted
            && !case
                .instances
                .iter()
                .any(|instance| active_ids.contains(instance.id.as_str()))
        {
            continue;
        }
        match case.decision {
            Decision::Retracted => continue,
            Decision::Informational | Decision::Dismissed
                if crate::tools::cases::verdict_missing(case, store) => {}
            Decision::Informational => {
                informational_count += 1;
                informational.push(InformationalSummary {
                    case_id: case.case_id.clone(),
                    components: case
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
                        .collect(),
                    reason: case.open_questions.first().cloned().unwrap_or_default(),
                    impact_assessed: crate::impact::latest(case, store).is_some(),
                });
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
            advisory_translation: crate::engine::current_verdict(case, store)
                .and_then(|verdict| verdict.advisory_translation),
            detail_gaps,
            applicability: if crate::tools::cases::verdict_missing(case, store) {
                crate::model::Applicability::Unknown
            } else {
                case.applicability
            },
            verification: if crate::tools::cases::verdict_missing(case, store) {
                crate::model::Verification::Inconclusive
            } else {
                case.verification
            },
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
                .chain(
                    (case.evidence.iter().any(|item| item.source == "impact_assessment")
                        && crate::impact::latest(case, store).is_none())
                    .then(|| match (language, crate::impact::previous(case, store).is_err()) {
                        (Language::Es, true) => "La evaluación de impacto registrada o su evidencia no es válida; revise su integridad antes de continuar.".to_owned(),
                        (Language::En, true) => "The recorded impact assessment or its evidence is invalid; check integrity before continuing.".to_owned(),
                        (Language::Es, false) => "La evaluación de impacto registrada no está vigente o es incompatible; revise la evidencia y responda las preguntas actuales.".to_owned(),
                        (Language::En, false) => "The recorded impact assessment is stale or incompatible; review the evidence and answer the current questions.".to_owned(),
                    }),
                )
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
        .filter(|case| case.decision != Decision::Retracted)
        .filter(|case| {
            case.instances
                .iter()
                .any(|instance| active_ids.contains(instance.id.as_str()))
        })
        .map(|case| verification::finding_check(case, store, language))
        .collect();
    Ok(MorningReport {
        codebase_path_roots: report_codebase_roots(snapshot),
        codebase_paths_ready: false,
        store_directory: store.directory.clone(),
        schema_version: 1,
        audience: audience.into(),
        closed: if audience == "audit" { ClosedMode::Full } else { ClosedMode::Summary },
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
        codebase_revisions,
        codebase_context_unrecorded,
        codebase_scope_changed,
        inventory: snapshot
            .instances
            .iter()
            .map(|instance| MonitoredComponent {
                instance_id: instance.id.clone(),
                reference: instance.reference.clone(),
                requested_version: instance.requested_version.clone(),
                resolved_version: instance.resolved_version.clone(),
                versioned_purl: instance.purl.as_ref().zip(instance.resolved_version.as_ref()).and_then(|(purl, version)| {
                    let mut purl: packageurl::PackageUrl<'_> = purl.parse().ok()?;
                    purl.with_version(version.as_str()).ok()?;
                    Some(purl.to_string())
                }),
                origin: instance.origin,
                codebase: instance.provenance.codebase.clone(),
                path: instance.provenance.path.clone(),
                line: instance.provenance.line,
                direct: instance.provenance.direct,
                direct_source: instance.python_lock.as_ref().and_then(|lock| lock.direct_source.clone()),
                dependency_parents: instance.python_lock.as_ref().map(|lock| lock.via.iter().filter(|entry| !entry.starts_with("-r ")).cloned().collect()).unwrap_or_default(),
                upstream: instance.upstream.clone(),
            })
            .collect(),
        actionable,
        scheduled_code_review: match store.meta("profile_path")? {
            Some(path) => crate::profile::load(std::path::Path::new(&path))?.scheduled_code_review,
            None => false,
        },
        code_reviews: crate::tools::code_review::current(store, snapshot)?,
        code_findings: crate::tools::code_findings::current(store, snapshot)?
            .into_iter()
            .map(|entry| CodeFinding {
                id: entry.id,
                finding: entry.finding,
                recorded_at: entry.recorded_at,
                current: entry.current,
                source_removed: entry.source_removed,
            })
            .collect(),
        needs_review,
        informational_count,
        informational,
        closed_cases: Vec::new(),
        retracted: Vec::new(),
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
            .map(|mut coverage| {
                coverage.detail = text::coverage_detail(language, &coverage.detail);
                coverage
            })
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
    let location = match (&instance.provenance.codebase, &instance.provenance.path) {
        (codebase, Some(path)) => {
            let file = match codebase {
                Some(codebase) => format!("{}/{path}", codebase.trim_end_matches('/')),
                None => path.clone(),
            };
            match instance.provenance.line {
                Some(line) => format!("{file}:{line}"),
                None => file,
            }
        }
        (_, None) => words.profile_location.to_owned(),
    };
    let direct_source = instance
        .python_lock
        .as_ref()
        .and_then(|lock| lock.direct_source.as_ref());
    match direct_source {
        Some(source) => {
            let label = match language {
                Language::Es => "declaración directa",
                Language::En => "direct declaration",
            };
            format!(
                "{} {version} - {location}; {label}: {}:{}",
                instance.reference, source.path, source.line
            )
        }
        None => format!("{} {version} - {location}", instance.reference),
    }
}

fn recorded_verdict(
    case: &crate::model::Case,
    store: &Store,
    language: Language,
) -> Option<String> {
    let verdict = crate::engine::current_verdict(case, store)?;
    Some(format!(
        "{}: {}",
        text::decision(language, verdict.decision),
        verdict.rationale
    ))
}
