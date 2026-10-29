//! Resumable review work; progress is operational metadata, never a case verdict.
use crate::{
    model::{Applicability, Case, Decision},
    store::Store,
    tools::cases,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const MAX_EVENTS: usize = 1000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkState {
    InProgress,
    Reviewed,
    HumanReview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkEvent {
    pub facts_sha256: String,
    #[serde(default)]
    pub workspace_revisions: Vec<crate::workspace_revision::WorkspaceRevision>,
    /// Fingerprint of case evidence and outcome when the interval was recorded.
    #[serde(default)]
    pub context_sha256: String,
    pub state: WorkState,
    pub recorded_at: String,
    pub started_at: String,
    pub elapsed_seconds: u64,
    pub next_step: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QueueItem {
    pub case_id: String,
    pub facts_sha256: String,
    pub summary: String,
    pub source_urls: Vec<String>,
    pub versions: Vec<String>,
    pub instance_count: usize,
    pub latest_source_update: Option<String>,
    pub priority_reasons: Vec<&'static str>,
    pub verification_pending: bool,
    pub verdict_missing: bool,
    pub progress: Option<WorkEvent>,
    pub previous_progress_stale: bool,
    pub recorded_elapsed_seconds: u64,
}

#[derive(Serialize)]
pub struct Queue {
    pub schema_version: u32,
    pub total: usize,
    pub open_total: usize,
    pub returned: usize,
    pub offset: usize,
    pub items: Vec<QueueItem>,
    pub disclaimer: &'static str,
}

#[derive(Serialize)]
pub struct GroupMember {
    pub monitor: String,
    pub facts_sha256: String,
    pub instance_count: usize,
}

#[derive(Serialize)]
pub struct SharedCase {
    pub case_id: String,
    pub source_urls: Vec<String>,
    pub artifact_versions: Vec<String>,
    pub monitors: Vec<GroupMember>,
}

#[derive(Serialize)]
pub struct DuplicateAdvisory {
    pub advisory_id: String,
    pub component: String,
    pub version: String,
    pub cases: Vec<String>,
}

/// Find case-level duplicates by exact advisory, package reference and resolved version.
pub fn duplicate_advisories(store: &Store) -> Result<Vec<DuplicateAdvisory>> {
    let mut groups: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
    for case in store.cases()? {
        if !matches!(case.decision, Decision::Actionable | Decision::Review) {
            continue;
        }
        for claim in &case.claims {
            if claim.id.trim().is_empty() {
                continue;
            }
            let Some(instance) = case.instances.iter().find(|i| i.id == claim.instance_id) else {
                continue;
            };
            let Some(version) = &instance.resolved_version else {
                continue;
            };
            groups
                .entry((
                    claim.id.clone(),
                    instance.reference.clone(),
                    version.clone(),
                ))
                .or_default()
                .insert(case.case_id.clone());
        }
    }
    Ok(groups
        .into_iter()
        .filter(|(_, cases)| cases.len() > 1)
        .map(
            |((advisory_id, component, version), cases)| DuplicateAdvisory {
                advisory_id,
                component,
                version,
                cases: cases.into_iter().collect(),
            },
        )
        .collect())
}

/// Candidate reuse only: per-project impact, artifact identity and features still need checking.
pub fn shared_cases(monitors: &[(String, Store)]) -> Result<Vec<SharedCase>> {
    let mut groups: BTreeMap<(String, Vec<String>, Vec<String>), Vec<GroupMember>> =
        BTreeMap::new();
    for (name, store) in monitors {
        for case in store.cases()? {
            if !matches!(case.decision, Decision::Actionable | Decision::Review)
                || case.instances.is_empty()
                || case.instances.iter().any(|i| i.resolved_version.is_none())
            {
                continue;
            }
            let urls: Vec<String> = case
                .upstream_events
                .iter()
                .map(|e| e.url.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if urls.is_empty() {
                continue;
            }
            let versions: Vec<String> = case
                .instances
                .iter()
                .filter_map(|i| i.resolved_version.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            groups
                .entry((case.case_id, urls, versions))
                .or_default()
                .push(GroupMember {
                    monitor: name.clone(),
                    facts_sha256: case.facts_sha256,
                    instance_count: case.instances.len(),
                });
        }
    }
    Ok(groups
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .map(
            |((case_id, source_urls, artifact_versions), monitors)| SharedCase {
                case_id,
                source_urls,
                artifact_versions,
                monitors,
            },
        )
        .collect())
}

fn key(case_id: &str) -> String {
    format!("review_progress:{case_id}")
}

fn context_hash(case: &Case) -> Result<String> {
    Ok(crate::digest(&serde_json::to_vec(&(
        &case.facts_sha256,
        &case.evidence,
        case.decision,
        case.applicability,
        case.verification,
    ))?))
}

fn history(store: &Store, case_id: &str) -> Result<Vec<WorkEvent>> {
    match store.meta(&key(case_id))? {
        Some(value) => serde_json::from_str(&value).context("invalid saved review progress"),
        None => Ok(Vec::new()),
    }
}

pub fn progress_history(store: &Store, case_id: &str) -> Result<Vec<WorkEvent>> {
    store.case(case_id)?;
    history(store, case_id)
}

/// Start or finish one unit of work; this never changes case facts, impact or verdict.
pub fn record(
    store: &Store,
    case_id: &str,
    state: WorkState,
    next_step: Option<&str>,
) -> Result<WorkEvent> {
    let _lock = store.lock()?;
    store.ensure_workspace_current()?;
    let active: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
        [case_id],
        |row| row.get(0),
    )?;
    if !active {
        bail!("review progress requires an active case");
    }
    let case = store.case(case_id)?;
    let mut events = history(store, case_id)?;
    if events.len() >= MAX_EVENTS {
        bail!("review progress history is full; retain it for audit");
    }
    let now = Utc::now();
    let started_at = if state == WorkState::InProgress {
        if events.last().is_some_and(|e| {
            e.state == WorkState::InProgress && e.facts_sha256 == case.facts_sha256
        }) {
            bail!("review is already in progress for these facts");
        }
        if next_step.is_some() {
            bail!("next step belongs to a finished work interval");
        }
        now.to_rfc3339()
    } else {
        let step = next_step.context("a next step is required when recording review progress")?;
        if step.trim().is_empty() || step.len() > 2000 {
            bail!("next step must be 1..2000 bytes");
        }
        let previous = events
            .last()
            .context("start this case before recording progress")?;
        if previous.state != WorkState::InProgress || previous.facts_sha256 != case.facts_sha256 {
            bail!("no current started review for these case facts");
        }
        previous.started_at.clone()
    };
    let start = DateTime::parse_from_rfc3339(&started_at)?.with_timezone(&Utc);
    let elapsed_seconds = (now - start).num_seconds().max(0) as u64;
    let event = WorkEvent {
        facts_sha256: case.facts_sha256.clone(),
        workspace_revisions: case.workspace_revisions.clone(),
        context_sha256: context_hash(&case)?,
        state,
        recorded_at: now.to_rfc3339(),
        started_at,
        elapsed_seconds,
        next_step: next_step.map(str::to_owned),
    };
    events.push(event.clone());
    store.set_meta(&key(case_id), &serde_json::to_string(&events)?)?;
    Ok(event)
}

fn item(
    case: &Case,
    store: &Store,
    pending: bool,
    missing: bool,
    followed: &[String],
) -> Result<QueueItem> {
    let events = history(store, &case.case_id)?;
    let last = events.last();
    let context = context_hash(case)?;
    let is_current = |e: &&WorkEvent| {
        e.facts_sha256 == case.facts_sha256
            && (e.state == WorkState::InProgress || e.context_sha256 == context)
    };
    let progress = last.filter(is_current).cloned();
    let stale = last.is_some() && progress.is_none();
    let recorded_elapsed_seconds = events
        .iter()
        .filter(|e| e.facts_sha256 == case.facts_sha256 && e.state != WorkState::InProgress)
        .fold(0_u64, |total, e| total.saturating_add(e.elapsed_seconds));
    let mut priority_reasons = Vec::new();
    if case.claims.iter().any(|c| c.known_exploited) {
        priority_reasons.push("known_exploited");
    }
    if case
        .claims
        .iter()
        .any(|c| c.applicability == Applicability::Affected)
    {
        priority_reasons.push("affected_advisory_claim");
    }
    if case.decision == Decision::Actionable {
        priority_reasons.push("actionable");
    }
    if case
        .upstream_events
        .iter()
        .any(|e| !e.source_facts.identifiers.is_empty())
    {
        priority_reasons.push("cited_advisory_identifier");
    }
    if case
        .instances
        .iter()
        .any(|i| i.provenance.direct == Some(true))
    {
        priority_reasons.push("direct_dependency");
    }
    if case
        .instances
        .iter()
        .any(|i| followed.contains(&i.reference) || i.origin == crate::model::Origin::Declared)
    {
        priority_reasons.push("selected_product_or_dependency");
    }
    let urls: BTreeSet<String> = case
        .upstream_events
        .iter()
        .map(|e| e.url.clone())
        .chain(case.claims.iter().filter_map(|c| c.evidence.url.clone()))
        .collect();
    let versions: BTreeSet<String> = case
        .instances
        .iter()
        .map(|i| {
            format!(
                "{} {}",
                i.reference,
                i.resolved_version.as_deref().unwrap_or("unknown")
            )
        })
        .collect();
    Ok(QueueItem {
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        summary: case
            .claims
            .first()
            .map(|c| c.summary.clone())
            .or_else(|| case.upstream_events.first().map(|e| e.title.clone()))
            .unwrap_or_default(),
        source_urls: urls.into_iter().collect(),
        versions: versions.into_iter().collect(),
        instance_count: case.instances.len(),
        latest_source_update: case
            .upstream_events
            .iter()
            .filter_map(|e| e.updated_at.as_ref())
            .filter_map(|t| DateTime::parse_from_rfc3339(t).ok())
            .max()
            .map(|t| t.with_timezone(&Utc).to_rfc3339()),
        priority_reasons,
        verification_pending: pending,
        verdict_missing: missing,
        progress,
        previous_progress_stale: stale,
        recorded_elapsed_seconds,
    })
}

pub fn list(store: &Store, limit: usize, offset: usize, unworked: bool) -> Result<Queue> {
    if !(1..=1000).contains(&limit) {
        bail!("limit must be 1..1000");
    }
    let pending = cases::pending(store)?;
    let checks: HashSet<&str> = pending
        .verification_pending
        .iter()
        .map(|p| p.case_id.as_str())
        .collect();
    let missing: HashSet<&str> = pending.verdict_missing.iter().map(String::as_str).collect();
    let followed = match store.meta("profile_path")? {
        Some(path) => {
            crate::profile::load(std::path::Path::new(&path))?
                .research
                .follow
        }
        None => Vec::new(),
    };
    let mut ranked: Vec<(u8, QueueItem)> = Vec::new();
    for case in store.cases()? {
        if !matches!(case.decision, Decision::Actionable | Decision::Review) {
            continue;
        }
        let q = item(
            &case,
            store,
            checks.contains(case.case_id.as_str()),
            missing.contains(case.case_id.as_str()),
            &followed,
        )?;
        let score = u8::from(q.priority_reasons.contains(&"known_exploited")) * 32
            + u8::from(q.priority_reasons.contains(&"affected_advisory_claim")) * 16
            + u8::from(q.priority_reasons.contains(&"actionable")) * 8
            + u8::from(q.priority_reasons.contains(&"cited_advisory_identifier")) * 4
            + u8::from(
                q.priority_reasons.contains(&"direct_dependency")
                    || q.priority_reasons
                        .contains(&"selected_product_or_dependency"),
            ) * 2;
        ranked.push((score, q));
    }
    let open_total = ranked.len();
    if unworked {
        ranked.retain(|(_, item)| {
            !item
                .progress
                .as_ref()
                .is_some_and(|p| matches!(p.state, WorkState::Reviewed | WorkState::HumanReview))
        });
    }
    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.latest_source_update.cmp(&a.1.latest_source_update))
            .then_with(|| a.1.case_id.cmp(&b.1.case_id))
    });
    let total = ranked.len();
    let items: Vec<QueueItem> = ranked
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(_, q)| q)
        .collect();
    Ok(Queue {
        schema_version: 1,
        total,
        open_total,
        returned: items.len(),
        offset,
        items,
        disclaimer: "Priority is an ordering hint, not severity or applicability. Progress never closes a case or settles a check. Offsets can change when case facts or verdicts change.",
    })
}
