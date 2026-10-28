use crate::{
    model::{
        Applicability, Case, Coverage, CoverageState, Decision, EvidenceKind, Instance,
        SourceFacts, UpstreamEvent, Verification,
    },
    store::Store,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
pub(crate) mod automation;
mod contracts;
pub(crate) mod release;
pub use contracts::{
    Assessment, EventKind, FollowSuggestion, NotApplicableReason, ResearchBatch, ResearchComponent,
    ResearchEvent, ResearchPlan, ResearchTarget, ReviewCoverage, SeenEvent, SourceContinuation,
    SourceReview,
};

pub(crate) type InstanceIndex<'a> = HashMap<&'a str, Vec<(usize, &'a Instance)>>;

pub(crate) fn index_instances(instances: &[Instance]) -> InstanceIndex<'_> {
    let mut index = HashMap::new();
    for (position, instance) in instances.iter().enumerate() {
        index
            .entry(instance.id.as_str())
            .or_insert_with(Vec::new)
            .push((position, instance));
    }
    index
}

pub(crate) fn select_instances<'a>(
    instance_ids: &[String],
    index: &InstanceIndex<'a>,
) -> Vec<&'a Instance> {
    let mut seen = HashSet::new();
    let mut selected = Vec::new();
    for id in instance_ids {
        if seen.insert(id.as_str())
            && let Some(instances) = index.get(id.as_str())
        {
            selected.extend(instances.iter().copied());
        }
    }
    selected.sort_unstable_by_key(|(position, _)| *position);
    selected.into_iter().map(|(_, instance)| instance).collect()
}

#[cfg(test)]
mod index_tests {
    use super::{event_hash, index_instances, select_instances, tracker_context};
    use crate::{model::Instance, profile::Component};

    #[test]
    fn selection_and_hashes_follow_snapshot_order() {
        let instance = |name: &str, version: &str| {
            Instance::declared(&Component {
                reference: name.into(),
                version: Some(version.into()),
                usage: Default::default(),
                upstream: None,
                feeds: vec![],
            })
        };
        let first = instance("a", "1.0.0");
        let mut duplicate = first.clone();
        duplicate.resolved_version = Some("2.0.0".into());
        let second = instance("b", "1.0.0");
        let instances = vec![first.clone(), second.clone(), duplicate];
        let ids = vec![
            second.id.clone(),
            first.id.clone(),
            first.id.clone(),
            "absent".into(),
        ];
        let old_selection: Vec<_> = instances
            .iter()
            .filter(|item| ids.contains(&item.id))
            .collect();
        let index = index_instances(&instances);
        let selection = select_instances(&ids, &index);
        assert_eq!(selection.len(), old_selection.len());
        for (actual, expected) in selection.iter().zip(&old_selection) {
            assert_eq!(actual.context_fingerprint(), expected.context_fingerprint());
        }

        let old_event_facts: Vec<_> = old_selection
            .iter()
            .map(|item| (&item.id, item.context_fingerprint()))
            .collect();
        let expected_event = crate::digest(
            &serde_json::to_vec(&(b"observation".as_slice(), old_event_facts)).unwrap(),
        );
        assert_eq!(
            event_hash(b"observation", &ids, &index).unwrap(),
            expected_event
        );

        let mut old_tracker_facts: Vec<_> = old_selection
            .iter()
            .map(|item| {
                (
                    &item.id,
                    item.context_fingerprint(),
                    None::<(&String, &String)>,
                )
            })
            .collect();
        old_tracker_facts.sort_by(|a, b| a.0.cmp(b.0));
        let expected_tracker = crate::digest(&serde_json::to_vec(&old_tracker_facts).unwrap());
        assert_eq!(
            tracker_context(&ids, &index, false).unwrap(),
            expected_tracker
        );
    }
}

#[derive(Deserialize)]
struct RecordedEvent {
    assessment: Assessment,
    #[serde(default)]
    not_applicable_reason: Option<NotApplicableReason>,
    rationale: String,
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
    let instance_index = index_instances(&snapshot.instances);
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
    let mut repositories: BTreeMap<String, (Vec<String>, HashSet<String>)> = BTreeMap::new();
    for instance in snapshot
        .instances
        .iter()
        .filter(|instance| selected(instance))
    {
        if let Some(upstream) = &instance.upstream {
            let (ids, seen) = repositories
                .entry(upstream.trim_end_matches('/').into())
                .or_default();
            ids.push(instance.id.clone());
            seen.insert(instance.id.clone());
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
                let (ids, seen) = repositories
                    .entry(url.trim_end_matches('/').to_owned())
                    .or_default();
                if seen.insert(instance_id.clone()) {
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
    for (upstream, (instance_ids, _)) in repositories
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
        let context = tracker_context(&instance_ids, &instance_index, research.release_windows)?;
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
                        let reviewed = &recorded.reviewed_instance_ids;
                        let reviewed_ids: HashSet<&str> =
                            reviewed.iter().map(String::as_str).collect();
                        instance_ids
                            .iter()
                            .all(|id| reviewed_ids.contains(id.as_str()))
                            && event_content(&recorded)
                                .and_then(|content| event_hash(&content, reviewed, &instance_index))
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
    instance_index: &InstanceIndex<'_>,
    release_windows: bool,
) -> Result<String> {
    let mut facts: Vec<_> = select_instances(instance_ids, instance_index)
        .into_iter()
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
    Ok(serde_json::to_vec(&(observed, &event.source_facts))?)
}

/// Hash of an event reading: its observation plus the context of the instances it was assessed for.
fn event_hash(
    content: &[u8],
    instance_ids: &[String],
    instance_index: &InstanceIndex<'_>,
) -> Result<String> {
    let target_facts: Vec<_> = select_instances(instance_ids, instance_index)
        .into_iter()
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
    let instance_index = index_instances(&snapshot.instances);
    let target_ids: HashMap<&str, HashSet<&str>> = plan
        .targets
        .iter()
        .map(|target| {
            (
                target.upstream.as_str(),
                target.instance_ids.iter().map(String::as_str).collect(),
            )
        })
        .collect();
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
    let active_cases: BTreeMap<String, Case> = store
        .cases()?
        .into_iter()
        .map(|case| (case.case_id.clone(), case))
        .collect();
    let mut assessments: BTreeMap<String, usize> = BTreeMap::new();
    let mut prepared = Vec::new();
    let mut duplicates = 0;
    let mut imprecise_sources: HashSet<String> = HashSet::new();
    let mut event_keys = HashSet::new();
    for event in &batch.events {
        if !sources.contains(&event.upstream) {
            bail!("event has no source review");
        }
        let target = plan
            .targets
            .iter()
            .find(|target| target.upstream == event.upstream)
            .context("event upstream missing")?;
        let candidates = target_ids
            .get(event.upstream.as_str())
            .context("event upstream missing")?;
        let reviewed: HashSet<&str> = event
            .reviewed_instance_ids
            .iter()
            .map(String::as_str)
            .collect();
        let event_url = crate::profile::public_https_syntax(&event.url)?;
        if event.instance_ids.is_empty()
            || event
                .instance_ids
                .iter()
                .any(|id| !candidates.contains(id.as_str()))
        {
            bail!("event instance is outside declared upstream scope");
        }
        if event.reviewed_instance_ids.is_empty()
            || event
                .reviewed_instance_ids
                .iter()
                .any(|id| !candidates.contains(id.as_str()))
            || event
                .instance_ids
                .iter()
                .any(|id| !reviewed.contains(id.as_str()))
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
        let reviewed = &event.reviewed_instance_ids;
        let hash = event_hash(&content, reviewed, &instance_index)?;
        // The original permalink identifies the event; agent/provider ID formatting may vary.
        let key = crate::digest(format!("{}:{}", event.upstream, event_url).as_bytes());
        if !event_keys.insert(key.clone()) {
            bail!("duplicate event for the same upstream and URL");
        }
        let case_id = format!(
            "SIG-{}",
            &crate::digest(format!("research:{key}").as_bytes())[..20]
        );
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
                let old_reviewed = &old.reviewed_instance_ids;
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
        let existing = active_cases.get(&case_id);
        let mut open_questions = vec![event.rationale.clone()];
        let (decision, coverage_detail) = match (event.assessment, existing) {
            (_, Some(previous)) if !previous.claims.is_empty() => {
                open_questions
                    .push("Review updated research alongside the advisory evidence.".into());
                (
                    Some(if previous.decision == Decision::Actionable {
                        Decision::Actionable
                    } else {
                        Decision::Review
                    }),
                    "Agent observation; advisory evidence retained".to_owned(),
                )
            }
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
            let coverage = Coverage::new(
                "agent_upstream",
                &event.upstream,
                CoverageState::Partial,
                &coverage_detail,
            );
            let mut case = Case {
                schema_version: 1,
                case_id,
                project_id: batch.project_id.clone(),
                snapshot_id: batch.snapshot_id.clone(),
                instances: instances.clone(),
                claims: Vec::new(),
                upstream_events: vec![upstream_event.clone()],
                evidence: vec![evidence.clone()],
                coverage: vec![coverage.clone()],
                applicability: Applicability::Unknown,
                verification: Verification::Inconclusive,
                decision,
                facts_sha256: case_facts,
                open_questions,
                suggested_search_queries: Vec::new(),
                sandbox: crate::sandbox::availability(),
                updated_at: crate::now(),
            };
            if let Some(previous) = existing {
                case.evidence = previous.evidence.clone();
                if !case
                    .evidence
                    .iter()
                    .any(|old| old.sha256 == evidence.sha256 && old.source == evidence.source)
                {
                    case.evidence.push(evidence.clone());
                }
                if !previous.claims.is_empty() {
                    case.claims = previous.claims.clone();
                    case.instances = previous.instances.clone();
                    for instance in instances {
                        if !case.instances.iter().any(|old| old.id == instance.id) {
                            case.instances.push(instance);
                        }
                    }
                    case.upstream_events = previous.upstream_events.clone();
                    case.upstream_events
                        .retain(|old| old.url != upstream_event.url);
                    case.upstream_events.push(upstream_event);
                    case.coverage = previous.coverage.clone();
                    case.coverage.push(coverage);
                    case.open_questions.extend(previous.open_questions.clone());
                    case.facts_sha256 = crate::digest(&serde_json::to_vec(&(
                        &previous.facts_sha256,
                        &case.facts_sha256,
                    ))?);
                    if decision == Decision::Actionable {
                        case.applicability = previous.applicability;
                        case.verification = previous.verification;
                    }
                }
            }
            cases.push(case);
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
        let target = plan
            .targets
            .iter()
            .find(|target| target.upstream == source.upstream)
            .context("research source disappeared from plan")?;
        let context = tracker_context(&target.instance_ids, &instance_index, release_windows)?;
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
        serde_json::json!({"schema_version":1,"changed_events":prepared.len(),"duplicates":duplicates,"changed_cases":changed_cases,"assessments":assessments,"evidence":evidence,"sources":batch.sources}),
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
