use crate::{
    model::{
        Applicability, Case, Coverage, CoverageState, Decision, EvidenceKind, UpstreamEvent,
        Verification,
    },
    store::Store,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
pub(crate) mod automation;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBatch {
    pub schema_version: u32,
    pub project_id: String,
    pub snapshot_id: String,
    pub sources: Vec<SourceReview>,
    pub events: Vec<ResearchEvent>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceReview {
    pub upstream: String,
    pub from: String,
    pub until: String,
    pub coverage: ReviewCoverage,
    pub detail: String,
    pub continuation: Option<SourceContinuation>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceContinuation {
    pub cursor: String,
    pub url: Option<String>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCoverage {
    Complete,
    Partial,
    Unavailable,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Review,
    Informational,
    Ignore,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Issue,
    PullRequest,
    MergeRequest,
    MergeProposal,
    Comment,
    Review,
    News,
    Discussion,
    Documentation,
    Changelog,
    Release,
    Advisory,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvent {
    pub upstream: String,
    pub instance_ids: Vec<String>,
    pub provider: String,
    pub external_id: String,
    pub kind: EventKind,
    pub url: String,
    pub title: String,
    pub excerpt: String,
    /// Original RFC3339 timestamp or YYYY-MM-DD when the source provides only a date.
    /// Empty means unknown. Unknown/day precision keeps coverage partial and never advances checkpoints.
    pub updated_at: String,
    pub assessment: Assessment,
    pub rationale: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ResearchComponent {
    pub instance_id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub requested_version: Option<String>,
    pub resolved_version: Option<String>,
    pub origin: crate::model::Origin,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ResearchTarget {
    pub upstream: String,
    pub instance_ids: Vec<String>,
    pub components: Vec<ResearchComponent>,
    pub from: String,
    pub until: String,
    pub last_complete_review: Option<String>,
    pub seen: Vec<SeenEvent>,
    pub seen_truncated: bool,
    pub continuation: Option<SourceContinuation>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SeenEvent {
    pub external_id: String,
    pub url: String,
    pub content_sha256: String,
    pub updated_at: String,
}
#[derive(Debug, Serialize)]
pub struct ResearchPlan {
    pub schema_version: u32,
    pub project_id: String,
    pub snapshot_id: String,
    pub targets: Vec<ResearchTarget>,
    pub required_agent_sites: Vec<String>,
    pub policy: String,
    pub next_cursor: Option<String>,
}
pub fn plan_page(store: &Store, after: &str, limit: usize) -> Result<ResearchPlan> {
    if !(1..=20).contains(&limit) {
        bail!("research page size must be 1..20");
    }
    build_plan(store, after, limit, true)
}
fn build_plan(
    store: &Store,
    after: &str,
    limit: usize,
    include_seen: bool,
) -> Result<ResearchPlan> {
    use rusqlite::OptionalExtension;
    let snapshot = store.latest()?;
    let mut repositories: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for instance in &snapshot.instances {
        if let Some(upstream) = &instance.upstream {
            repositories
                .entry(upstream.trim_end_matches('/').into())
                .or_default()
                .push(instance.id.clone());
        }
    }
    if let Some(path) = store.meta("profile_path")? {
        let path = std::path::Path::new(&path);
        let profile = crate::profile::load(path)?;
        for (instance_id, url) in crate::discovery::mapped_sources(&profile, path, store)? {
            if snapshot
                .instances
                .iter()
                .any(|instance| instance.id == instance_id)
            {
                let ids = repositories
                    .entry(url.trim_end_matches('/').to_owned())
                    .or_default();
                if !ids.contains(&instance_id) {
                    ids.push(instance_id);
                }
            }
        }
    }
    let first_scan = store
        .meta("first_scan")?
        .unwrap_or_else(|| snapshot.started_at.clone());
    let initial = DateTime::parse_from_rfc3339(&first_scan)? - Duration::days(30);
    let instances_by_id: BTreeMap<_, _> = snapshot
        .instances
        .iter()
        .map(|instance| (instance.id.as_str(), instance))
        .collect();
    let mut targets = Vec::new();
    let mut next_cursor = None;
    for (upstream, instance_ids) in repositories
        .into_iter()
        .filter(|(url, _)| url.as_str() > after)
    {
        if targets.len() == limit {
            next_cursor = targets
                .last()
                .map(|target: &ResearchTarget| target.upstream.clone());
            break;
        }
        let checkpoint: Option<String> = store
            .connection
            .query_row(
                "SELECT reviewed_until FROM research_cursors WHERE upstream=?1",
                [&upstream],
                |row| row.get(0),
            )
            .optional()?;
        let mut from = match &checkpoint {
            Some(checkpoint) => {
                (DateTime::parse_from_rfc3339(checkpoint)? - Duration::minutes(5)).to_rfc3339()
            }
            None => initial.to_rfc3339(),
        };
        let progress: Option<String> = store
            .connection
            .query_row(
                "SELECT body FROM research_progress WHERE upstream=?1",
                [&upstream],
                |row| row.get(0),
            )
            .optional()?;
        let mut until = snapshot.finished_at.clone();
        let mut continuation = None;
        if let Some(body) = progress {
            let progress: SourceReview = serde_json::from_str(&body)?;
            from = progress.from;
            until = progress.until;
            continuation = progress.continuation;
        }
        let mut seen = Vec::new();
        let mut seen_bytes = 0;
        let mut seen_truncated = false;
        if include_seen {
            let mut statement = store.connection.prepare("SELECT external_id,url,content_sha256,updated_at FROM research_events WHERE upstream=?1 ORDER BY updated_at DESC")?;
            let rows = statement.query_map([&upstream], |row| {
                Ok(SeenEvent {
                    external_id: row.get(0)?,
                    url: row.get(1)?,
                    content_sha256: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })?;
            for row in rows {
                let event = row?;
                seen_bytes += serde_json::to_vec(&event)?.len();
                if seen_bytes > 512 * 1024 {
                    seen_truncated = true;
                    break;
                }
                seen.push(event);
            }
        }
        let components: Vec<ResearchComponent> = instance_ids
            .iter()
            .filter_map(|id| instances_by_id.get(id.as_str()))
            .map(|instance| ResearchComponent {
                instance_id: instance.id.clone(),
                reference: instance.reference.clone(),
                requested_version: instance.requested_version.clone(),
                resolved_version: instance.resolved_version.clone(),
                origin: instance.origin,
            })
            .collect();
        targets.push(ResearchTarget {
            upstream,
            instance_ids,
            components,
            from,
            until,
            last_complete_review: checkpoint,
            seen,
            seen_truncated,
            continuation,
        });
    }
    Ok(ResearchPlan {schema_version:1,project_id:snapshot.project_id,snapshot_id:snapshot.id,targets,next_cursor,required_agent_sites:vec!["github.com".into(),"gitlab.com".into(),"launchpad.net (bugs and merge proposals)".into()],policy:"Review issues, proposed changes, discussions, documentation, changelogs, releases and advisories at each mapped source. Exhaust relevant pages and linked context in the supplied window. Only complete reviews advance source checkpoints. Follow next_cursor for remaining targets. seen_truncated means the prompt contains only a sample; the CLI still deduplicates all imported events. Initial window is 30 days; later windows overlap the last completed review by 5 minutes.".into()})
}
pub fn import(store: &mut Store, mut batch: ResearchBatch) -> Result<serde_json::Value> {
    use rusqlite::{OptionalExtension, params};
    let _lock = store.lock()?;
    let plan = build_plan(store, "", usize::MAX, false)?;
    if batch.schema_version != 1
        || batch.project_id != plan.project_id
        || batch.snapshot_id != plan.snapshot_id
    {
        bail!("research batch is stale or belongs to another snapshot/project");
    }
    if batch.sources.len() > 1000 || batch.events.len() > 10000 {
        bail!("research batch exceeds limits");
    }
    let snapshot = store.latest()?;
    let mut sources = HashSet::new();
    for review in &batch.sources {
        if let Some(continuation) = &review.continuation {
            if review.coverage == ReviewCoverage::Complete
                || continuation.cursor.is_empty()
                || continuation.cursor.len() > 4096
                || continuation.cursor.chars().any(char::is_control)
            {
                bail!("continuation requires an incomplete review and a bounded cursor");
            }
            if let Some(url) = &continuation.url {
                crate::profile::public_https_syntax(url)?;
            }
        }
        let target = plan
            .targets
            .iter()
            .find(|target| target.upstream == review.upstream)
            .context("research source is outside this snapshot's verified upstream scope")?;
        if !sources.insert(&review.upstream)
            || review.from != target.from
            || review.until != target.until
            || review.detail.len() > 2000
        {
            bail!("research window mismatch/duplicate; reread research plan");
        }
    }
    let mut cases_by_link: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for case in store.cases()? {
        if !case.claims.is_empty() {
            continue;
        }
        for event in &case.upstream_events {
            let Ok(url) = crate::profile::public_https_syntax(&event.url) else {
                continue;
            };
            for instance in &case.instances {
                cases_by_link
                    .entry((instance.id.clone(), url.to_string()))
                    .or_default()
                    .insert(case.case_id.clone());
            }
        }
    }
    let mut merged_case_ids = HashSet::new();
    for identifiers in cases_by_link.values() {
        merged_case_ids.extend(identifiers.iter().skip(1).cloned());
    }
    let mut prepared = Vec::new();
    let mut duplicates = 0;
    let mut imprecise_sources: HashSet<String> = HashSet::new();
    for event in &batch.events {
        if !sources.contains(&event.upstream) {
            bail!("event has no source review");
        }
        let target = plan
            .targets
            .iter()
            .find(|target| target.upstream == event.upstream)
            .context("event upstream missing")?;
        let event_url = crate::profile::public_https_syntax(&event.url)?;
        if event.instance_ids.is_empty()
            || event
                .instance_ids
                .iter()
                .any(|id| !target.instance_ids.contains(id))
        {
            bail!("event instance is outside declared upstream scope");
        }
        if event.external_id.is_empty()
            || event.external_id.len() > 300
            || event.title.len() > 2000
            || event.excerpt.len() > 8000
            || event.rationale.trim().is_empty()
            || event.rationale.len() > 4000
        {
            bail!("event identifiers/text exceed limits or rationale missing");
        }
        let from = DateTime::parse_from_rfc3339(&target.from)?;
        let until = DateTime::parse_from_rfc3339(&target.until)?;
        let in_window = if event.updated_at.trim().is_empty() {
            imprecise_sources.insert(event.upstream.clone());
            true
        } else {
            match DateTime::parse_from_rfc3339(&event.updated_at) {
                Ok(updated) => updated >= from && updated <= until,
                Err(_) => {
                    let day=NaiveDate::parse_from_str(&event.updated_at,"%Y-%m-%d").context("event updated_at must be the source's RFC3339 timestamp or original YYYY-MM-DD date")?;
                    imprecise_sources.insert(event.upstream.clone());
                    day >= from.date_naive() && day <= until.date_naive()
                }
            }
        };
        if !in_window {
            bail!("event timestamp is outside review window");
        }
        let content = serde_json::to_vec(&(
            &event.kind,
            event_url.as_str(),
            event.title.as_str(),
            event.excerpt.as_str(),
            event.updated_at.as_str(),
        ))?;
        let target_facts: Vec<_> = snapshot
            .instances
            .iter()
            .filter(|instance| event.instance_ids.contains(&instance.id))
            .map(|instance| (&instance.id, instance.context_fingerprint()))
            .collect();
        let hash = crate::digest(&serde_json::to_vec(&(&content, target_facts))?);
        // The original permalink identifies the event; agent/provider ID formatting may vary.
        let key = crate::digest(format!("{}:{}", event.upstream, event_url).as_bytes());
        let previous: Option<String> = store
            .connection
            .query_row(
                "SELECT content_sha256 FROM research_events WHERE key=?1",
                [&key],
                |row| row.get(0),
            )
            .optional()?;
        if previous.as_deref() == Some(&hash) {
            duplicates += 1;
            continue;
        }
        let evidence = store.record_evidence(
            &content,
            "agent_upstream_observation",
            Some(event.url.clone()),
            EvidenceKind::Context,
        )?;
        let mut cases = Vec::new();
        if event.assessment != Assessment::Ignore {
            for id in &event.instance_ids {
                let instance = snapshot
                    .instances
                    .iter()
                    .find(|instance| &instance.id == id)
                    .context("event instance missing")?
                    .clone();
                let facts =
                    crate::digest(format!("{hash}:{}", instance.context_fingerprint()).as_bytes());
                let case_id = match cases_by_link
                    .get(&(id.clone(), event_url.to_string()))
                    .and_then(|ids| ids.first())
                {
                    Some(existing) => existing.clone(),
                    None => format!(
                        "SIG-{}",
                        &crate::digest(format!("research:{key}:{id}").as_bytes())[..20]
                    ),
                };
                let upstream_event = UpstreamEvent {
                    provider: event.provider.clone(),
                    kind: format!("{:?}", event.kind).to_lowercase(),
                    id: event.external_id.clone(),
                    url: event.url.clone(),
                    title: event.title.clone(),
                    updated_at: if event.updated_at.is_empty() {
                        None
                    } else {
                        Some(event.updated_at.clone())
                    },
                    sha256: evidence.sha256.clone(),
                };
                let decision = match event.assessment {
                    Assessment::Informational => Decision::Informational,
                    Assessment::Review => Decision::Review,
                    Assessment::Ignore => continue,
                };
                let coverage = vec![Coverage::new(
                    "agent_upstream",
                    &event.upstream,
                    CoverageState::Partial,
                    "Agent observation; security applicability not established",
                )];
                cases.push(Case {
                    schema_version: 1,
                    case_id,
                    project_id: batch.project_id.clone(),
                    snapshot_id: batch.snapshot_id.clone(),
                    instances: vec![instance],
                    claims: Vec::new(),
                    upstream_events: vec![upstream_event],
                    evidence: vec![evidence.clone()],
                    coverage,
                    applicability: Applicability::Unknown,
                    verification: Verification::Inconclusive,
                    decision,
                    facts_sha256: facts,
                    open_questions: vec![event.rationale.clone(),"Check release code and attack prerequisites before asserting a real attack vector.".into()],
                    suggested_search_queries: Vec::new(),
                    sandbox: crate::sandbox::availability(),
                    updated_at: crate::now(),
                });
            }
        }
        prepared.push((key, hash, event, cases));
    }
    for source in &mut batch.sources {
        if imprecise_sources.contains(&source.upstream) {
            source.coverage = ReviewCoverage::Partial;
            source.detail.push_str(
                " CLI: source timestamps are imprecise/unknown; checkpoint was not advanced.",
            );
        }
    }
    let transaction = store.connection.transaction()?;
    for id in &merged_case_ids {
        transaction.execute("DELETE FROM cases WHERE id=?1", [id])?;
    }
    let mut changed_cases = 0;
    for (key, hash, event, cases) in &prepared {
        transaction.execute(
            "INSERT OR REPLACE INTO research_events VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                key,
                event.upstream,
                event.external_id,
                event.url,
                hash,
                event.updated_at,
                serde_json::to_string(event)?
            ],
        )?;
        for case in cases {
            let body = serde_json::to_string(case)?;
            transaction.execute(
                "INSERT OR REPLACE INTO cases VALUES (?1,?2)",
                params![case.case_id, body],
            )?;
            transaction.execute(
                "INSERT INTO history(case_id,body,recorded_at) VALUES (?1,?2,?3)",
                params![case.case_id, body, case.updated_at],
            )?;
            changed_cases += 1;
        }
    }
    for source in &batch.sources {
        if source.coverage == ReviewCoverage::Complete {
            transaction.execute(
                "INSERT OR REPLACE INTO research_cursors VALUES (?1,?2)",
                params![source.upstream, source.until],
            )?;
            transaction.execute(
                "DELETE FROM research_progress WHERE upstream=?1",
                [&source.upstream],
            )?;
        } else {
            transaction.execute(
                "INSERT OR REPLACE INTO research_progress VALUES (?1,?2)",
                params![source.upstream, serde_json::to_string(source)?],
            )?;
        }
    }
    let reviewed_at = Utc::now().to_rfc3339();
    transaction.execute(
        "INSERT OR REPLACE INTO meta VALUES ('last_agent_review',?1)",
        [&reviewed_at],
    )?;
    transaction.execute(
        "INSERT INTO research_reviews(body,recorded_at) VALUES (?1,?2)",
        params![serde_json::to_string(&batch)?, reviewed_at],
    )?;
    transaction.commit()?;
    let evidence = store.record_evidence(
        &serde_json::to_vec(&batch)?,
        "agent_research_batch",
        None,
        EvidenceKind::Context,
    )?;
    Ok(
        serde_json::json!({"schema_version":1,"changed_events":prepared.len(),"duplicates":duplicates,"changed_cases":changed_cases,"merged_cases":merged_case_ids.len(),"evidence":evidence,"sources":batch.sources}),
    )
}
