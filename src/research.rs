use crate::{
    model::{
        Applicability, Case, Coverage, CoverageState, Decision, EvidenceKind, Instance,
        SourceFacts, UpstreamEvent, Verification,
    },
    store::Store,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
pub(crate) mod automation;
pub(crate) mod release;

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
/// `not_applicable`: a security claim that, per the cited source, does not affect the monitored
/// version or build. It requires `not_applicable_reason`, is counted and remembered, and opens no case.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Review,
    Informational,
    NotApplicable,
    Ignore,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotApplicableReason {
    /// The monitored resolved version already contains the fix.
    FixedInMonitoredVersion,
    /// Only other release lines or unreleased branches are affected.
    AffectsOtherVersion,
    /// The affected module, feature or platform is absent from the monitored build.
    ComponentNotInBuild,
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
    Commit,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvent {
    pub upstream: String,
    pub instance_ids: Vec<String>,
    /// Candidate instances examined when choosing the case scope. Older observations omit this
    /// and retain their original instance-based freshness semantics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviewed_instance_ids: Vec<String>,
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
    /// Required with `not_applicable`; forbidden otherwise.
    #[serde(default)]
    pub not_applicable_reason: Option<NotApplicableReason>,
    pub rationale: String,
    /// Answers to the research questions as the item states them. `fixed_in_monitored_version`
    /// requires `fixed_in`, and `affects_other_version` requires `affected_versions`.
    #[serde(default)]
    pub source_facts: SourceFacts,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ResearchComponent {
    pub instance_id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub requested_version: Option<String>,
    pub resolved_version: Option<String>,
    pub origin: crate::model::Origin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<crate::model::ReleaseDate>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ResearchTarget {
    pub upstream: String,
    /// Fingerprint of the exact monitored instances in this target.
    pub context_sha256: String,
    pub instance_ids: Vec<String>,
    pub components: Vec<ResearchComponent>,
    pub from: String,
    pub until: String,
    pub last_complete_review: Option<String>,
    pub seen: Vec<SeenEvent>,
    pub seen_truncated: bool,
    pub continuation: Option<SourceContinuation>,
    /// Persisted incomplete source review, including its stated blocker and pinned window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<SourceReview>,
    /// Older progress is retained as context but must not be resumed against changed artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_progress: Option<SourceReview>,
    /// True when the source window was reopened because its monitored context changed.
    #[serde(default)]
    pub context_reopened: bool,
}
/// An imported event with the agent's previous reading, so an item whose `updated_at` is unchanged
/// needs no new review.
#[derive(Debug, Serialize, Deserialize)]
pub struct SeenEvent {
    pub external_id: String,
    pub url: String,
    pub content_sha256: String,
    pub updated_at: String,
    /// False when the monitored instances changed since the recorded assessment or the target
    /// gained instances the event does not cover; the event then needs a new review even with the
    /// same `updated_at`.
    pub context_current: bool,
    pub assessment: Option<Assessment>,
    pub not_applicable_reason: Option<NotApplicableReason>,
    /// First 300 characters of the recorded rationale.
    pub rationale: String,
}
#[derive(Deserialize)]
struct RecordedEvent {
    assessment: Assessment,
    #[serde(default)]
    not_applicable_reason: Option<NotApplicableReason>,
    rationale: String,
}
#[derive(Debug, Serialize)]
pub struct ResearchPlan {
    pub schema_version: u32,
    pub project_id: String,
    pub snapshot_id: String,
    pub targets: Vec<ResearchTarget>,
    /// Inventory instances outside tracker exploration; advisories are still scanned separately.
    pub tracker_scope: crate::profile::TrackerScope,
    pub deferred_transitive_instances: usize,
    pub deferred_unknown_instances: usize,
    /// No inventory instance was selected for tracker research.
    pub scope_unselected: bool,
    /// Evidence-backed candidates for focused investigation; these do not change the scope.
    pub follow_suggestions: Vec<FollowSuggestion>,
    pub follow_suggestions_total: usize,
    pub required_agent_sites: Vec<String>,
    pub policy: String,
    pub next_cursor: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct FollowSuggestion {
    #[serde(rename = "ref")]
    pub reference: String,
    pub version: Option<String>,
    pub case_id: String,
    pub advisory_id: String,
    pub applicability: Applicability,
    pub evidence: crate::model::Evidence,
}
pub fn plan_page(store: &Store, after: &str, limit: usize) -> Result<ResearchPlan> {
    if !(1..=20).contains(&limit) {
        bail!("research page size must be 1..20");
    }
    build_plan(store, after, limit, true)
}
/// Every target with its seen events, for local tools that read the whole plan at once.
pub(crate) fn full_plan(store: &Store) -> Result<ResearchPlan> {
    build_plan(store, "", usize::MAX, true)
}
fn build_plan(
    store: &Store,
    after: &str,
    limit: usize,
    include_seen: bool,
) -> Result<ResearchPlan> {
    use rusqlite::OptionalExtension;
    let snapshot = store.latest()?;
    let configured = store
        .meta("profile_path")?
        .map(|path| crate::profile::load(std::path::Path::new(&path)))
        .transpose()?;
    let research = configured
        .as_ref()
        .map(|profile| &profile.research)
        .cloned()
        .unwrap_or_default();
    let selected = |instance: &Instance| research.tracks(instance);
    let deferred_transitive_instances = snapshot
        .instances
        .iter()
        .filter(|instance| !selected(instance) && instance.provenance.direct == Some(false))
        .count();
    let deferred_unknown_instances = snapshot
        .instances
        .iter()
        .filter(|instance| !selected(instance) && instance.provenance.direct.is_none())
        .count();
    let scope_unselected =
        !snapshot.instances.is_empty() && !snapshot.instances.iter().any(selected);
    let instances_by_id: BTreeMap<_, _> = snapshot
        .instances
        .iter()
        .map(|instance| (instance.id.as_str(), instance))
        .collect();
    let mut suggestions = Vec::new();
    for case in store.cases()? {
        for claim in case.claims {
            if claim.applicability == Applicability::NotAffected {
                continue;
            }
            let Some(instance) = instances_by_id.get(claim.instance_id.as_str()).copied() else {
                continue;
            };
            if selected(instance) || !store.evidence_exists(&claim.evidence).unwrap_or(false) {
                continue;
            }
            suggestions.push(FollowSuggestion {
                reference: instance.reference.clone(),
                version: instance.resolved_version.clone(),
                case_id: case.case_id.clone(),
                advisory_id: claim.id,
                applicability: claim.applicability,
                evidence: claim.evidence,
            });
        }
    }
    suggestions.sort_by(|a, b| {
        (&a.reference, &a.version, &a.advisory_id, &a.case_id).cmp(&(
            &b.reference,
            &b.version,
            &b.advisory_id,
            &b.case_id,
        ))
    });
    suggestions.dedup_by(|a, b| {
        a.reference == b.reference
            && a.version == b.version
            && a.advisory_id == b.advisory_id
            && a.case_id == b.case_id
    });
    let follow_suggestions_total = suggestions.len();
    suggestions.truncate(100);
    let mut repositories: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for instance in snapshot
        .instances
        .iter()
        .filter(|instance| selected(instance))
    {
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
            if instances_by_id
                .get(instance_id.as_str())
                .is_some_and(|instance| selected(instance))
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
    let mut initial = DateTime::parse_from_rfc3339(&first_scan)? - Duration::days(30);
    if let Some(path) = store.meta("profile_path")? {
        let profile = crate::profile::load(std::path::Path::new(&path))?;
        if let Some(since) = profile.research.initial_since {
            initial = DateTime::parse_from_rfc3339(&since)?;
            if initial > DateTime::parse_from_rfc3339(&snapshot.finished_at)? {
                bail!(
                    "research.initial_since is after the completed scan; run a new scan or correct the date"
                );
            }
        }
    }
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
        let context_key = format!("research_context:{}", crate::digest(upstream.as_bytes()));
        let context =
            tracker_context(&instance_ids, &snapshot.instances, research.release_windows)?;
        let reviewed_context = store.meta(&context_key)?;
        let mut context_reopened =
            checkpoint.is_some() && reviewed_context.as_deref() != Some(&context);
        let checkpoint = if context_reopened { None } else { checkpoint };
        let mut from = match &checkpoint {
            Some(checkpoint) => {
                (DateTime::parse_from_rfc3339(checkpoint)? - Duration::minutes(5)).to_rfc3339()
            }
            None if research.release_windows && research.initial_since.is_none() => {
                let mut dates = Vec::new();
                for id in &instance_ids {
                    let date = instances_by_id
                        .get(id.as_str())
                        .and_then(|instance| {
                            instance.release.as_ref().filter(|release| {
                                instance.resolved_version.as_deref()
                                    == Some(release.version.as_str())
                            })
                        })
                        .and_then(|release| {
                            DateTime::parse_from_rfc3339(&release.published_at).ok()
                        });
                    dates.push(date.unwrap_or(initial));
                }
                dates.into_iter().min().unwrap_or(initial).to_rfc3339()
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
        let progress_key = format!(
            "research_progress_context:{}",
            crate::digest(upstream.as_bytes())
        );
        let progress_context = store.meta(&progress_key)?;
        let progress: Option<SourceReview> = progress
            .map(|body| serde_json::from_str(&body))
            .transpose()?;
        let (progress, stale_progress) = if progress_context.as_deref() == Some(&context) {
            (progress, None)
        } else {
            context_reopened |= progress.is_some();
            (None, progress)
        };
        if let Some(progress) = &progress {
            from = progress.from.clone();
            until = progress.until.clone();
            continuation = progress.continuation.clone();
        }
        let mut seen = Vec::new();
        let mut seen_bytes = 0;
        let mut seen_truncated = false;
        if include_seen {
            let mut statement = store.connection.prepare("SELECT external_id,url,content_sha256,updated_at,body FROM research_events WHERE upstream=?1 ORDER BY updated_at DESC")?;
            let rows = statement.query_map([&upstream], |row| {
                Ok((
                    SeenEvent {
                        external_id: row.get(0)?,
                        url: row.get(1)?,
                        content_sha256: row.get(2)?,
                        updated_at: row.get(3)?,
                        context_current: false,
                        assessment: None,
                        not_applicable_reason: None,
                        rationale: String::new(),
                    },
                    row.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (mut event, body) = row?;
                if let Ok(recorded) = serde_json::from_str::<RecordedEvent>(&body) {
                    event.assessment = Some(recorded.assessment);
                    event.not_applicable_reason = recorded.not_applicable_reason;
                    event.rationale = recorded.rationale.chars().take(300).collect();
                }
                event.context_current = serde_json::from_str::<ResearchEvent>(&body)
                    .ok()
                    .is_some_and(|recorded| {
                        let reviewed = if recorded.reviewed_instance_ids.is_empty() {
                            &recorded.instance_ids
                        } else {
                            &recorded.reviewed_instance_ids
                        };
                        instance_ids.iter().all(|id| reviewed.contains(id))
                            && event_content(&recorded)
                                .and_then(|content| {
                                    event_hash(&content, reviewed, &snapshot.instances)
                                })
                                .is_ok_and(|hash| hash == event.content_sha256)
                    });
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
                release: instance.release.clone(),
            })
            .collect();
        targets.push(ResearchTarget {
            upstream,
            context_sha256: context,
            instance_ids,
            components,
            from,
            until,
            last_complete_review: checkpoint,
            seen,
            seen_truncated,
            continuation,
            progress,
            stale_progress,
            context_reopened,
        });
    }
    Ok(ResearchPlan {schema_version:1,project_id:snapshot.project_id,snapshot_id:snapshot.id,targets,tracker_scope:research.tracker_scope,deferred_transitive_instances,deferred_unknown_instances,scope_unselected,follow_suggestions:suggestions,follow_suggestions_total,next_cursor,required_agent_sites:vec!["github.com".into(),"gitlab.com".into(),"launchpad.net (bugs and merge proposals)".into()],policy:"Review issues, proposed changes, discussions, documentation, changelogs, releases and advisories at each selected mapped source. Deferred transitive and unknown-depth instances remain in the inventory and advisory scan, not proven safe; inspect follow_suggestions and add exact references to research.follow for targeted investigation where warranted. Exhaust relevant pages and linked context in the supplied window. Screen each item on its title, labels and full acquired body, not the title alone; for a proposed change also read the issue it closes. For every item with a security claim, answer from the item in source_facts: which advisory IDs it cites, which versions it says are affected, where it says the fix is (version, release or backport) and through which change, and which feature or configuration it requires; leave a field empty when the item does not say, never infer it. Then judge it against the monitored version. A seen event whose updated_at is unchanged and whose context_current is true keeps its recorded assessment and needs no new review; resend an event when it changed or its context_current is false. Only complete reviews advance source checkpoints. Follow next_cursor for remaining targets. seen_truncated means the prompt contains only a sample; the CLI still deduplicates all imported events. The initial window uses research.initial_since if configured, otherwise exact registry release dates when enabled or a 30 day fallback; shared targets use the earliest date. Later windows overlap the last completed review by 5 minutes. Earlier activity is outside this window, not established safe; advisory scans are independent.".into()})
}
fn tracker_context(
    instance_ids: &[String],
    instances: &[Instance],
    release_windows: bool,
) -> Result<String> {
    let mut facts: Vec<_> = instances
        .iter()
        .filter(|instance| instance_ids.contains(&instance.id))
        .map(|instance| {
            (
                &instance.id,
                instance.context_fingerprint(),
                if release_windows {
                    instance
                        .release
                        .as_ref()
                        .map(|release| (&release.version, &release.published_at))
                } else {
                    None
                },
            )
        })
        .collect();
    facts.sort_by(|a, b| a.0.cmp(b.0));
    Ok(crate::digest(&serde_json::to_vec(&facts)?))
}
/// Observation recorded as evidence for an event.
fn event_content(event: &ResearchEvent) -> Result<Vec<u8>> {
    let event_url = crate::profile::public_https_syntax(&event.url)?;
    let observed = (
        &event.kind,
        event_url.as_str(),
        event.title.as_str(),
        event.excerpt.as_str(),
        event.updated_at.as_str(),
    );
    // Events without source facts keep the content hash they had before facts existed.
    Ok(if event.source_facts.is_empty() {
        serde_json::to_vec(&observed)?
    } else {
        serde_json::to_vec(&(observed, &event.source_facts))?
    })
}

/// Hash of an event reading: its observation plus the context of the instances it was assessed for.
fn event_hash(content: &[u8], instance_ids: &[String], instances: &[Instance]) -> Result<String> {
    let target_facts: Vec<_> = instances
        .iter()
        .filter(|instance| instance_ids.contains(&instance.id))
        .map(|instance| (&instance.id, instance.context_fingerprint()))
        .collect();
    Ok(crate::digest(&serde_json::to_vec(&(
        content,
        target_facts,
    ))?))
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
    // One research case per upstream permalink; older per-instance cases are folded into it.
    let mut cases_by_link: BTreeMap<String, BTreeMap<String, Case>> = BTreeMap::new();
    for case in store.cases()? {
        if !case.claims.is_empty() {
            continue;
        }
        for event in &case.upstream_events {
            let Ok(url) = crate::profile::public_https_syntax(&event.url) else {
                continue;
            };
            cases_by_link
                .entry(url.to_string())
                .or_default()
                .insert(case.case_id.clone(), case.clone());
        }
    }
    let mut merged_case_ids = HashSet::new();
    let mut linked: BTreeMap<String, Case> = BTreeMap::new();
    let mut folded = Vec::new();
    for (url, group) in cases_by_link {
        let mut members = group.into_values();
        let Some(mut survivor) = members.next() else {
            continue;
        };
        let mut was_folded = false;
        for member in members {
            for instance in member.instances {
                if !survivor.instances.iter().any(|kept| kept.id == instance.id) {
                    survivor.instances.push(instance);
                }
            }
            merged_case_ids.insert(member.case_id);
            was_folded = true;
        }
        if was_folded {
            folded.push(survivor.clone());
        }
        linked.insert(url, survivor);
    }
    merged_case_ids.retain(|id| !linked.values().any(|case| &case.case_id == id));
    let mut assessments: BTreeMap<String, usize> = BTreeMap::new();
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
        if !event.reviewed_instance_ids.is_empty()
            && (event
                .reviewed_instance_ids
                .iter()
                .any(|id| !target.instance_ids.contains(id))
                || event
                    .instance_ids
                    .iter()
                    .any(|id| !event.reviewed_instance_ids.contains(id)))
        {
            bail!("reviewed instances must include the case scope and belong to the upstream");
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
        if (event.assessment == Assessment::NotApplicable) != event.not_applicable_reason.is_some()
        {
            bail!("not_applicable requires not_applicable_reason, and only it accepts one");
        }
        validate_source_facts(&event.source_facts, event.not_applicable_reason)?;
        *assessments
            .entry(
                serde_json::to_value(event.assessment)?
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
            .or_default() += 1;
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
        let content = event_content(event)?;
        let reviewed = if event.reviewed_instance_ids.is_empty() {
            &event.instance_ids
        } else {
            &event.reviewed_instance_ids
        };
        let hash = event_hash(&content, reviewed, &snapshot.instances)?;
        // The original permalink identifies the event; agent/provider ID formatting may vary.
        let key = crate::digest(format!("{}:{}", event.upstream, event_url).as_bytes());
        let previous: Option<(String, String)> = store
            .connection
            .query_row(
                "SELECT content_sha256,body FROM research_events WHERE key=?1",
                [&key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let same_content = previous
            .as_ref()
            .is_some_and(|(old_hash, _)| old_hash == &hash);
        let same_reading = previous
            .as_ref()
            .and_then(|(_, body)| serde_json::from_str::<ResearchEvent>(body).ok())
            .is_some_and(|old| {
                let old_reviewed = if old.reviewed_instance_ids.is_empty() {
                    &old.instance_ids
                } else {
                    &old.reviewed_instance_ids
                };
                old.assessment == event.assessment
                    && old.not_applicable_reason == event.not_applicable_reason
                    && old.rationale == event.rationale
                    && old.instance_ids == event.instance_ids
                    && old_reviewed == reviewed
            });
        if same_content && same_reading {
            duplicates += 1;
            continue;
        }
        // A new assessment must invalidate an earlier case verdict even if upstream text is unchanged.
        let case_facts = if same_content {
            crate::digest(&serde_json::to_vec(&(
                &hash,
                event.assessment,
                event.not_applicable_reason,
                &event.rationale,
                &event.instance_ids,
            ))?)
        } else {
            hash.clone()
        };
        let evidence = store.record_evidence(
            &content,
            "agent_upstream_observation",
            Some(event.url.clone()),
            EvidenceKind::Context,
        )?;
        let existing = linked.get(event_url.as_str());
        let mut open_questions = vec![event.rationale.clone()];
        let (decision, coverage_detail) = match (event.assessment, existing) {
            (Assessment::Review, _) => {
                open_questions.push("Check release code and attack prerequisites before asserting a real attack vector.".into());
                (
                    Some(Decision::Review),
                    "Agent observation; security applicability not established".to_owned(),
                )
            }
            (Assessment::Informational, _) => (
                Some(Decision::Informational),
                "Agent observation; security applicability not established".to_owned(),
            ),
            (Assessment::NotApplicable | Assessment::Ignore, None) => (None, String::new()),
            (_, Some(previous)) => {
                let detail = match event.not_applicable_reason {
                    Some(reason) => format!(
                        "Agent re-assessed as not applicable ({reason:?}); this is not a dismissal"
                    ),
                    None => "Agent re-assessed as lacking a relevant security claim".to_owned(),
                };
                if previous.decision == Decision::Actionable {
                    open_questions.push("Research no longer supports this actionable case; confirm and record a new verdict before closing it.".into());
                    (Some(Decision::Review), detail)
                } else {
                    (Some(Decision::Informational), detail)
                }
            }
        };
        let mut cases = Vec::new();
        if let Some(decision) = decision {
            let instances = event
                .instance_ids
                .iter()
                .map(|id| {
                    snapshot
                        .instances
                        .iter()
                        .find(|instance| &instance.id == id)
                        .cloned()
                        .context("event instance missing")
                })
                .collect::<Result<Vec<_>>>()?;
            let case_id = match existing {
                Some(previous) => previous.case_id.clone(),
                None => format!(
                    "SIG-{}",
                    &crate::digest(format!("research:{key}").as_bytes())[..20]
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
                source_facts: event.source_facts.clone(),
            };
            cases.push(Case {
                schema_version: 1,
                case_id,
                project_id: batch.project_id.clone(),
                snapshot_id: batch.snapshot_id.clone(),
                instances,
                claims: Vec::new(),
                upstream_events: vec![upstream_event],
                evidence: vec![evidence.clone()],
                coverage: vec![Coverage::new(
                    "agent_upstream",
                    &event.upstream,
                    CoverageState::Partial,
                    &coverage_detail,
                )],
                applicability: Applicability::Unknown,
                verification: Verification::Inconclusive,
                decision,
                facts_sha256: case_facts,
                open_questions,
                suggested_search_queries: Vec::new(),
                sandbox: crate::sandbox::availability(),
                updated_at: crate::now(),
            });
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
    let release_windows = store
        .meta("profile_path")?
        .map(|path| crate::profile::load(std::path::Path::new(&path)))
        .transpose()?
        .map(|profile| profile.research.release_windows)
        .unwrap_or(false);
    let transaction = store.connection.transaction()?;
    for id in &merged_case_ids {
        transaction.execute("DELETE FROM cases WHERE id=?1", [id])?;
    }
    let mut changed_cases = 0;
    for case in &folded {
        let body = serde_json::to_string(case)?;
        transaction.execute(
            "INSERT OR REPLACE INTO cases VALUES (?1,?2)",
            params![case.case_id, body],
        )?;
        transaction.execute(
            "INSERT INTO history(case_id,body,recorded_at) VALUES (?1,?2,?3)",
            params![case.case_id, body, crate::now()],
        )?;
    }
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
        let target = plan
            .targets
            .iter()
            .find(|target| target.upstream == source.upstream)
            .context("research source disappeared from plan")?;
        let context = tracker_context(&target.instance_ids, &snapshot.instances, release_windows)?;
        let key_suffix = crate::digest(source.upstream.as_bytes());
        if source.coverage == ReviewCoverage::Complete {
            transaction.execute(
                "INSERT OR REPLACE INTO research_cursors VALUES (?1,?2)",
                params![source.upstream, source.until],
            )?;
            transaction.execute(
                "DELETE FROM research_progress WHERE upstream=?1",
                [&source.upstream],
            )?;
            transaction.execute(
                "INSERT OR REPLACE INTO meta VALUES (?1,?2)",
                params![format!("research_context:{key_suffix}"), context],
            )?;
            transaction.execute(
                "DELETE FROM meta WHERE key=?1",
                [format!("research_progress_context:{key_suffix}")],
            )?;
        } else {
            transaction.execute(
                "INSERT OR REPLACE INTO research_progress VALUES (?1,?2)",
                params![source.upstream, serde_json::to_string(source)?],
            )?;
            transaction.execute(
                "INSERT OR REPLACE INTO meta VALUES (?1,?2)",
                params![format!("research_progress_context:{key_suffix}"), context],
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
        serde_json::json!({"schema_version":1,"changed_events":prepared.len(),"duplicates":duplicates,"changed_cases":changed_cases,"merged_cases":merged_case_ids.len(),"assessments":assessments,"evidence":evidence,"sources":batch.sources}),
    )
}

pub(crate) fn validate_source_facts(
    facts: &SourceFacts,
    reason: Option<NotApplicableReason>,
) -> Result<()> {
    if facts.identifiers.len() > 32
        || facts.identifiers.iter().any(|identifier| {
            identifier.len() > 64
                || !identifier.contains('-')
                || !identifier
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        bail!(
            "source_facts.identifiers takes up to 32 advisory IDs such as CVE-2026-1234 or GHSA-xxxx-xxxx-xxxx"
        );
    }
    let texts = [
        &facts.affected_versions,
        &facts.fixed_in,
        &facts.fix_reference,
        &facts.required_feature,
    ];
    if texts
        .iter()
        .any(|text| text.len() > 500 || text.chars().any(char::is_control))
    {
        bail!("source_facts text fields take one line of up to 500 characters");
    }
    match reason {
        Some(NotApplicableReason::FixedInMonitoredVersion) if facts.fixed_in.trim().is_empty() => {
            bail!("fixed_in_monitored_version requires source_facts.fixed_in as the item states it")
        }
        Some(NotApplicableReason::AffectsOtherVersion)
            if facts.affected_versions.trim().is_empty() =>
        {
            bail!(
                "affects_other_version requires source_facts.affected_versions as the item states it"
            )
        }
        _ => Ok(()),
    }
}

/// Moves completed review checkpoints back so the next plan reviews `since` onward again, for
/// example after the screening method improved. Seen events still deduplicate imports.
pub fn reopen(store: &mut Store, upstream: &str, since: &str) -> Result<serde_json::Value> {
    let _lock = store.lock()?;
    let since = DateTime::parse_from_rfc3339(since).context("--since must be RFC3339")?;
    if since > Utc::now() {
        bail!("--since is in the future");
    }
    let plan = build_plan(store, "", usize::MAX, false)?;
    let targets: Vec<&ResearchTarget> = plan
        .targets
        .iter()
        .filter(|target| upstream == "all" || target.upstream == upstream.trim_end_matches('/'))
        .collect();
    if targets.is_empty() {
        bail!("no research target matches {upstream}; use an upstream from the plan or `all`");
    }
    let transaction = store.connection.transaction()?;
    let mut reopened = Vec::new();
    for target in targets {
        let Some(checkpoint) = &target.last_complete_review else {
            continue;
        };
        if DateTime::parse_from_rfc3339(checkpoint)? <= since {
            continue;
        }
        let rewound = since + Duration::minutes(5);
        transaction.execute(
            "INSERT OR REPLACE INTO research_cursors VALUES (?1,?2)",
            rusqlite::params![target.upstream, rewound.to_rfc3339()],
        )?;
        transaction.execute(
            "DELETE FROM research_progress WHERE upstream=?1",
            [&target.upstream],
        )?;
        reopened.push(serde_json::json!({"upstream": target.upstream, "previous_checkpoint": checkpoint, "from": since.to_rfc3339()}));
    }
    transaction.commit()?;
    Ok(serde_json::json!({"schema_version": 1, "reopened": reopened}))
}
