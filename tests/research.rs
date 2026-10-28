use chrono::DateTime;
use std::fs;
use vulnbell::{
    model::Decision,
    research::{
        Assessment, EventKind, NotApplicableReason, ResearchBatch, ResearchEvent, ReviewCoverage,
        SourceReview,
    },
    store::Store,
};

#[test]
fn research_keeps_declared_order_and_deduplicates_mapped_sources() {
    use vulnbell::{
        discovery::{
            self, DiscoveryBatch, IdentityObservation, MappingState, SOURCE_KINDS, SourceKind,
            SourceMapping,
        },
        model::{EvidenceKind, EvidenceReference},
    };
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    let upstream = "https://github.com/example/app";
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: ordering\ncomponents:\n  - ref: first\n    version: '1.0.0'\n    upstream: {upstream}\n  - ref: second\n    version: '1.0.0'\n    upstream: {upstream}\n  - ref: mapped\n    version: '1.0.0'\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    let mut evidence = store
        .record_evidence(
            upstream.as_bytes(),
            "discovery_public_document",
            Some(upstream.into()),
            EvidenceKind::Context,
        )
        .unwrap();
    evidence.id = "DOC-fixture".into();
    store
        .connection
        .execute(
            "INSERT INTO discovery_documents VALUES (?1,?2)",
            rusqlite::params![evidence.id, serde_json::to_string(&evidence).unwrap()],
        )
        .unwrap();
    let observations = page
        .components
        .iter()
        .map(|component| IdentityObservation {
            instance_id: component.instance_id.clone(),
            fingerprint: component.fingerprint.clone(),
            version: None,
            cpe_product: None,
            rationale: "Official source mapping fixture".into(),
            sources: SOURCE_KINDS
                .iter()
                .map(|kind| {
                    let mapped = matches!(kind, SourceKind::Repository | SourceKind::Issues);
                    SourceMapping {
                        kind: *kind,
                        state: if mapped {
                            MappingState::Mapped
                        } else {
                            MappingState::Unavailable
                        },
                        url: mapped.then(|| upstream.to_owned()),
                        detail: "Fixture source".into(),
                        evidence: if mapped {
                            vec![EvidenceReference {
                                id: evidence.id.clone(),
                                sha256: evidence.sha256.clone(),
                            }]
                        } else {
                            vec![]
                        },
                    }
                })
                .collect(),
        })
        .collect();
    discovery::import(
        &profile,
        &path,
        &mut store,
        DiscoveryBatch::Sources {
            schema_version: 1,
            project_id: page.project_id,
            scope_sha256: page.scope_sha256,
            observations,
        },
    )
    .unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(plan.targets.len(), 1);
    assert_eq!(
        plan.targets[0].instance_ids,
        snapshot
            .instances
            .iter()
            .map(|instance| instance.id.clone())
            .collect::<Vec<_>>()
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn initial_window_uses_configured_timestamp_without_changing_advisory_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    let since = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: window-fixture\nresearch:\n  initial_since: '{since}'\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/example\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(
        DateTime::parse_from_rfc3339(&plan.targets[0].from).unwrap(),
        DateTime::parse_from_rfc3339(&since).unwrap()
    );
    assert_eq!(snapshot.instances.len(), 1);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn tracker_scope_defers_transitive_and_unknown_but_explicit_follow_restores_one() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    let profile_text = format!(
        "schema: 1\nproject_id: {project}\nname: scope-fixture\ncomponents:\n  - ref: app\n    version: '1.0.0'\n    upstream: https://github.com/example/app\n  - ref: deep\n    version: '1.0.0'\n    upstream: https://github.com/example/deep\n  - ref: unknown\n    version: '1.0.0'\n    upstream: https://github.com/example/unknown\n"
    );
    fs::write(&path, &profile_text).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let mut snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    snapshot
        .instances
        .iter_mut()
        .find(|instance| instance.reference == "deep")
        .unwrap()
        .provenance
        .direct = Some(false);
    snapshot
        .instances
        .iter_mut()
        .find(|instance| instance.reference == "unknown")
        .unwrap()
        .provenance
        .direct = None;
    let mut store = Store::open(&project).unwrap();
    snapshot.id = uuid::Uuid::new_v4().to_string();
    store.save_snapshot(&snapshot).unwrap();
    let scoped = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(scoped.targets.len(), 1);
    assert_eq!(scoped.deferred_transitive_instances, 1);
    assert_eq!(scoped.deferred_unknown_instances, 1);
    fs::write(
        &path,
        format!("{profile_text}research:\n  follow: [deep]\n"),
    )
    .unwrap();
    let followed = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(followed.targets.len(), 2);
    assert_eq!(followed.deferred_transitive_instances, 0);
    assert_eq!(followed.deferred_unknown_instances, 1);
    fs::write(
        &path,
        format!("{profile_text}research:\n  tracker_scope: all\n"),
    )
    .unwrap();
    let all = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(all.targets.len(), 3);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn shared_tracker_uses_earliest_release_and_suggests_only_evidenced_deferred_advisories() {
    use vulnbell::model::{Applicability, Claim, EvidenceKind, ReleaseDate};
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: releases\nresearch:\n  release_windows: true\ncomponents:\n  - ref: app-a\n    version: '1.0.0'\n    upstream: https://github.com/example/app\n  - ref: app-b\n    version: '2.0.0'\n    upstream: https://github.com/example/app\n  - ref: deep\n    version: '3.0.0'\n    upstream: https://github.com/example/deep\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let mut snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let evidence = store
        .record_evidence(
            b"synthetic metadata",
            "test",
            Some("https://example.org/metadata".into()),
            EvidenceKind::Context,
        )
        .unwrap();
    for instance in &mut snapshot.instances {
        if instance.reference == "deep" {
            instance.provenance.direct = Some(false);
            continue;
        }
        instance.release = Some(ReleaseDate {
            version: instance.resolved_version.clone().unwrap(),
            published_at: if instance.reference == "app-a" {
                "2026-01-01T00:00:00+00:00"
            } else {
                "2026-02-01T00:00:00+00:00"
            }
            .into(),
            evidence: evidence.clone(),
        });
    }
    let deep = snapshot
        .instances
        .iter()
        .find(|item| item.reference == "deep")
        .unwrap();
    let claim = Claim {
        id: "CVE-2026-0001".into(),
        source: "synthetic".into(),
        aliases: vec![],
        instance_id: deep.id.clone(),
        summary: "synthetic".into(),
        applicability: Applicability::Affected,
        evidence,
        known_exploited: false,
    };
    snapshot.id = uuid::Uuid::new_v4().to_string();
    snapshot.cases = vulnbell::engine::cases_from_claims(
        &[claim],
        &snapshot.instances,
        &profile,
        &snapshot.id,
        &[],
    )
    .unwrap();
    store.save_snapshot(&snapshot).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(plan.targets.len(), 1);
    assert_eq!(plan.targets[0].from, "2026-01-01T00:00:00+00:00");
    assert_eq!(plan.follow_suggestions_total, 1);
    assert_eq!(plan.follow_suggestions[0].reference, "deep");
    assert_eq!(plan.follow_suggestions[0].advisory_id, "CVE-2026-0001");
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn pending_explains_partial_review_even_without_a_pagination_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: resume\ncomponents:\n  - ref: app\n    version: '1.0.0'\n    upstream: https://github.com/example/app\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let batch = ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id,
        sources: vec![SourceReview {
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage: ReviewCoverage::Partial,
            detail: "rate limit until reset".into(),
            continuation: None,
        }],
        events: vec![],
    };
    vulnbell::research::import(&mut store, batch).unwrap();
    let pending = serde_json::to_value(vulnbell::tools::cases::pending(&store).unwrap()).unwrap();
    assert_eq!(pending["research_open"][0]["reason"], "partial_review");
    assert_eq!(
        pending["research_open"][0]["progress"]["detail"],
        "rate limit until reset"
    );
    assert!(!pending["deliverable"].as_bool().unwrap());
    let mut snapshot = store.latest().unwrap();
    snapshot.id = uuid::Uuid::new_v4().to_string();
    snapshot.instances[0].resolved_version = Some("2.0.0".into());
    store.save_snapshot(&snapshot).unwrap();
    let pending = serde_json::to_value(vulnbell::tools::cases::pending(&store).unwrap()).unwrap();
    assert_eq!(pending["research_open"][0]["reason"], "context_changed");
    assert_eq!(
        pending["research_open"][0]["stale_progress"]["detail"],
        "rate limit until reset"
    );
    assert!(pending["research_open"][0].get("progress").is_none());
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn changed_monitored_version_reopens_completed_tracker_window() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: context\ncomponents:\n  - ref: app\n    version: '1.0.0'\n    upstream: https://github.com/example/app\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let mut snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let initial_from = target.from.clone();
    vulnbell::research::import(
        &mut store,
        ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id,
            sources: vec![SourceReview {
                upstream: target.upstream.clone(),
                from: target.from.clone(),
                until: target.until.clone(),
                coverage: ReviewCoverage::Complete,
                detail: "synthetic complete".into(),
                continuation: None,
            }],
            events: vec![],
        },
    )
    .unwrap();
    assert!(
        !vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .targets[0]
            .context_reopened
    );
    snapshot.id = uuid::Uuid::new_v4().to_string();
    snapshot.instances[0].resolved_version = Some("2.0.0".into());
    store.save_snapshot(&snapshot).unwrap();
    let reopened = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(reopened.targets[0].context_reopened);
    assert_eq!(reopened.targets[0].from, initial_from);
    assert!(reopened.targets[0].last_complete_review.is_none());
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn scoped_event_stays_current_until_a_reviewed_candidate_changes() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: scoped-research\ncomponents:\n  - ref: example-core\n    version: '2.0.0'\n    upstream: https://launchpad.net/example\n  - ref: example-server\n    version: '2.0.0'\n    upstream: https://launchpad.net/example\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let mut snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let selected = target.instance_ids[0].clone();
    let event = ResearchEvent {
        upstream: target.upstream.clone(),
        instance_ids: vec![selected.clone()],
        reviewed_instance_ids: target.instance_ids.clone(),
        provider: "launchpad".into(),
        external_id: "example#1".into(),
        kind: EventKind::Issue,
        url: "https://bugs.launchpad.net/example/+bug/1".into(),
        title: "Synthetic issue".into(),
        excerpt: "Synthetic issue scoped to one component".into(),
        updated_at: target.until.clone(),
        assessment: Assessment::Review,
        not_applicable_reason: None,
        rationale: "Only one component implements the reported feature.".into(),
        source_facts: Default::default(),
    };
    let batch = ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage: ReviewCoverage::Partial,
            detail: "Synthetic review".into(),
            continuation: None,
        }],
        events: vec![event],
    };
    let mut missing_scope = batch.clone();
    missing_scope.events[0].reviewed_instance_ids = vec![target.instance_ids[1].clone()];
    assert!(vulnbell::research::import(&mut store, missing_scope).is_err());
    let mut outside_scope = batch.clone();
    outside_scope.events[0]
        .reviewed_instance_ids
        .push("outside".into());
    assert!(vulnbell::research::import(&mut store, outside_scope).is_err());
    let mut broad = batch.clone();
    broad.events[0].instance_ids = target.instance_ids.clone();
    vulnbell::research::import(&mut store, broad).unwrap();
    assert_eq!(store.cases().unwrap()[0].instances.len(), 2);
    let before = store.cases().unwrap()[0].facts_sha256.clone();
    fs::write(
        directory.path().join("scope.md"),
        "Reviewed synthetic module scope.",
    )
    .unwrap();
    let case_id = store.cases().unwrap()[0].case_id.clone();
    let mut scope = vulnbell::tools::cases::ScopeBatch {
        schema_version: 1,
        cases: vec![vulnbell::tools::cases::CaseScope {
            case_id,
            facts_sha256: "stale".into(),
            instance_ids: vec![selected.clone()],
            rationale: "The synthetic source names only this component.".into(),
            note: "scope.md".into(),
        }],
    };
    assert!(!vulnbell::tools::cases::apply_scope(&mut store, &scope, directory.path())[0].applied);
    assert_eq!(store.cases().unwrap()[0].instances.len(), 2);
    scope.cases[0].facts_sha256 = before.clone();
    assert!(vulnbell::tools::cases::apply_scope(&mut store, &scope, directory.path())[0].applied);
    let scoped = store.cases().unwrap().remove(0);
    assert_eq!(scoped.instances.len(), 1);
    assert_ne!(scoped.facts_sha256, before);
    assert_eq!(scoped.decision, Decision::Review);
    let imported = vulnbell::research::import(&mut store, batch).unwrap();
    assert_eq!(imported["changed_cases"], 1);
    assert_eq!(store.cases().unwrap()[0].instances.len(), 1);
    assert_ne!(store.cases().unwrap()[0].facts_sha256, before);
    let current = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(current.targets[0].seen[0].context_current);

    let excluded = snapshot
        .instances
        .iter_mut()
        .find(|i| i.id != selected)
        .unwrap();
    excluded.resolved_version = Some("3.0.0".into());
    snapshot.id = uuid::Uuid::new_v4().to_string();
    store.save_snapshot(&snapshot).unwrap();
    let changed = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(!changed.targets[0].seen[0].context_current);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn shared_upstream_event_opens_one_case_and_not_applicable_needs_a_reason() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: shared-upstream-fixture\ncomponents:\n  - ref: example-core\n    version: '2.0.0'\n    upstream: https://launchpad.net/example\n  - ref: example-server\n    version: '2.0.0'\n    upstream: https://launchpad.net/example\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    assert_eq!(target.instance_ids.len(), 2);
    let event = |url: &str, assessment, reason| ResearchEvent {
        upstream: target.upstream.clone(),
        instance_ids: target.instance_ids.clone(),
        reviewed_instance_ids: target.instance_ids.clone(),
        provider: "launchpad".into(),
        external_id: url.rsplit('/').next().unwrap().into(),
        kind: EventKind::Issue,
        url: url.into(),
        title: "SYNTHETIC issue; not an actual finding".into(),
        excerpt: "Synthetic report".into(),
        updated_at: target.until.clone(),
        assessment,
        not_applicable_reason: reason,
        rationale: "Synthetic rationale".into(),
        source_facts: Default::default(),
    };
    let batch = |events| ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage: ReviewCoverage::Partial,
            detail: "Synthetic review".into(),
            continuation: None,
        }],
        events,
    };
    let reported = "https://bugs.launchpad.net/example/+bug/1";
    let imported = vulnbell::research::import(
        &mut store,
        batch(vec![event(reported, Assessment::Review, None)]),
    )
    .unwrap();
    assert_eq!(imported["changed_cases"], 1);
    let cases = store.cases().unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].instances.len(), 2);

    let other_line = "https://bugs.launchpad.net/example/+bug/2";
    assert!(
        vulnbell::research::import(
            &mut store,
            batch(vec![event(other_line, Assessment::NotApplicable, None)])
        )
        .is_err()
    );
    assert!(
        vulnbell::research::import(
            &mut store,
            batch(vec![event(
                other_line,
                Assessment::Review,
                Some(NotApplicableReason::AffectsOtherVersion)
            )])
        )
        .is_err()
    );
    let mut other_version = event(
        other_line,
        Assessment::NotApplicable,
        Some(NotApplicableReason::AffectsOtherVersion),
    );
    assert!(vulnbell::research::import(&mut store, batch(vec![other_version.clone()])).is_err());
    other_version.source_facts.affected_versions = "1.x only".into();
    let counted = vulnbell::research::import(&mut store, batch(vec![other_version])).unwrap();
    assert_eq!(counted["changed_cases"], 0);
    assert_eq!(counted["assessments"]["not_applicable"], 1);
    assert_eq!(store.cases().unwrap().len(), 1);

    let mut reassessed = event(
        reported,
        Assessment::NotApplicable,
        Some(NotApplicableReason::FixedInMonitoredVersion),
    );
    reassessed.excerpt.push_str(" Fixed before 2.0.0.");
    assert!(vulnbell::research::import(&mut store, batch(vec![reassessed.clone()])).is_err());
    reassessed.source_facts.fixed_in = "1.9.0".into();
    reassessed.source_facts.identifiers = vec!["not an id".into()];
    assert!(vulnbell::research::import(&mut store, batch(vec![reassessed.clone()])).is_err());
    reassessed.source_facts.identifiers = vec!["CVE-2026-0001".into()];
    vulnbell::research::import(&mut store, batch(vec![reassessed])).unwrap();
    let seen = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let recorded = seen.targets[0]
        .seen
        .iter()
        .find(|seen| seen.url == reported)
        .unwrap();
    assert_eq!(recorded.assessment, Some(Assessment::NotApplicable));
    assert_eq!(
        recorded.not_applicable_reason,
        Some(NotApplicableReason::FixedInMonitoredVersion)
    );
    assert_eq!(recorded.rationale, "Synthetic rationale");
    assert_eq!(
        store.cases().unwrap()[0].upstream_events[0]
            .source_facts
            .fixed_in,
        "1.9.0"
    );
    let cases = store.cases().unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].decision, Decision::Informational);
    assert!(
        cases[0].coverage[0]
            .detail
            .contains("FixedInMonitoredVersion")
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
#[test]
fn agent_reviews_github_gitlab_launchpad_with_dedupe_and_failure_safe_checkpoints() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path,format!("schema: 1\nproject_id: {project}\nname: research-fixture\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://launchpad.net/example\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let events: Vec<ResearchEvent> = [
        (
            "github",
            "https://github.com/example/project/issues/1#issuecomment-123",
            EventKind::Issue,
        ),
        (
            "gitlab",
            "https://gitlab.com/example/project/-/merge_requests/2",
            EventKind::MergeRequest,
        ),
        (
            "launchpad",
            "https://bugs.launchpad.net/example/+bug/123",
            EventKind::Issue,
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (provider, url, kind))| ResearchEvent {
        upstream: target.upstream.clone(),
        instance_ids: target.instance_ids.clone(),
        reviewed_instance_ids: target.instance_ids.clone(),
        provider: provider.into(),
        external_id: index.to_string(),
        kind,
        url: url.into(),
        title: "SYNTHETIC issue; not an actual finding".into(),
        excerpt: "Synthetic report to test the agent import contract".into(),
        updated_at: target.until.clone(),
        assessment: Assessment::Review,
        not_applicable_reason: None,
        rationale: "Check attack preconditions before classifying; third-party report is not proof"
            .into(),
        source_facts: Default::default(),
    })
    .collect();
    let review = SourceReview {
        continuation: None,
        upstream: target.upstream.clone(),
        from: target.from.clone(),
        until: target.until.clone(),
        coverage: ReviewCoverage::Partial,
        detail: "Synthetic test of three agent site observations".into(),
    };
    let batch = ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![review.clone()],
        events: events.clone(),
    };
    let mut day_precision = batch.clone();
    day_precision.events.truncate(1);
    day_precision.events[0].updated_at = target.until[..10].to_owned();
    day_precision.sources[0].coverage = ReviewCoverage::Complete;
    let day_result = vulnbell::research::import(&mut store, day_precision).unwrap();
    assert_eq!(day_result["sources"][0]["coverage"], "partial");
    assert!(
        vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .targets[0]
            .last_complete_review
            .is_none()
    );
    let mut undated = batch.clone();
    undated.events.truncate(1);
    undated.events[0].updated_at.clear();
    undated.sources[0].coverage = ReviewCoverage::Complete;
    let undated_result = vulnbell::research::import(&mut store, undated).unwrap();
    assert_eq!(undated_result["sources"][0]["coverage"], "partial");
    assert!(
        vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .targets[0]
            .last_complete_review
            .is_none()
    );
    let first = vulnbell::research::import(&mut store, batch.clone()).unwrap();
    assert_eq!(first["changed_cases"], 3);
    assert!(
        vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .targets[0]
            .last_complete_review
            .is_none()
    );
    let mut related_case = store.cases().unwrap()[0].clone();
    related_case.case_id = "ZZZ-synthetic-related-case".into();
    store.save_case(&related_case).unwrap();
    let duplicate = vulnbell::research::import(&mut store, batch.clone()).unwrap();
    assert_eq!(duplicate["duplicates"], 3);
    assert!(store.case("ZZZ-synthetic-related-case").is_ok());
    let mut reformatted = batch.clone();
    for event in &mut reformatted.events {
        event.external_id = format!("project#{}", event.external_id);
        event.provider = event.provider.to_uppercase();
    }
    assert_eq!(
        vulnbell::research::import(&mut store, reformatted).unwrap()["duplicates"],
        3
    );

    assert_eq!(store.cases().unwrap().len(), 4);
    let mut completed = batch;
    completed.sources[0].coverage = ReviewCoverage::Complete;
    vulnbell::research::import(&mut store, completed).unwrap();
    let next = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(
        next.targets[0].last_complete_review.as_deref(),
        Some(target.until.as_str())
    );
    assert!(
        vulnbell::research::reopen(&mut store, "https://example.org/other", &target.from).is_err()
    );
    let reopened = vulnbell::research::reopen(&mut store, "all", &target.from).unwrap();
    assert_eq!(reopened["reopened"].as_array().unwrap().len(), 1);
    let again = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(
        DateTime::parse_from_rfc3339(&again.targets[0].from).unwrap(),
        DateTime::parse_from_rfc3339(&target.from).unwrap()
    );
    let repeated = ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            from: again.targets[0].from.clone(),
            until: again.targets[0].until.clone(),
            coverage: ReviewCoverage::Complete,
            ..review.clone()
        }],
        events: events.clone(),
    };
    assert_eq!(
        vulnbell::research::import(&mut store, repeated).unwrap()["duplicates"],
        3
    );
    let next = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let mut changed = events;
    changed[0].excerpt.push_str(" Substantive new detail.");
    let review = SourceReview {
        continuation: None,
        from: next.targets[0].from.clone(),
        ..review
    };
    let update = ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id,
        sources: vec![review],
        events: changed,
    };
    assert_eq!(
        vulnbell::research::import(&mut store, update).unwrap()["changed_cases"],
        1
    );
    assert!(
        store
            .cases()
            .unwrap()
            .iter()
            .all(|case| case.decision == vulnbell::model::Decision::Review)
    );
    let stale = ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: "stale".into(),
        sources: vec![],
        events: vec![],
    };
    assert!(vulnbell::research::import(&mut store, stale).is_err());
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn same_link_from_distinct_upstreams_preserves_each_case() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: independent-sources\ncomponents:\n  - ref: example-a\n    version: '1.0.0'\n    upstream: https://github.com/example/a\n  - ref: example-b\n    version: '1.0.0'\n    upstream: https://github.com/example/b\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let url = "https://github.com/example/a/issues/1";
    let sources = plan
        .targets
        .iter()
        .map(|target| SourceReview {
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage: ReviewCoverage::Partial,
            detail: "synthetic".into(),
            continuation: None,
        })
        .collect();
    let events = plan
        .targets
        .iter()
        .enumerate()
        .map(|(index, target)| ResearchEvent {
            upstream: target.upstream.clone(),
            instance_ids: target.instance_ids.clone(),
            reviewed_instance_ids: target.instance_ids.clone(),
            provider: "github".into(),
            external_id: format!("item-{index}"),
            kind: EventKind::Issue,
            url: url.into(),
            title: "synthetic".into(),
            excerpt: "synthetic".into(),
            updated_at: target.until.clone(),
            assessment: if index == 0 {
                Assessment::Informational
            } else {
                Assessment::Review
            },
            not_applicable_reason: None,
            rationale: "synthetic".into(),
            source_facts: Default::default(),
        })
        .collect();
    vulnbell::research::import(
        &mut store,
        ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id.clone(),
            sources,
            events,
        },
    )
    .unwrap();
    let original = store.cases().unwrap();
    assert_eq!(original.len(), 2);
    assert!(
        original
            .iter()
            .any(|case| case.decision == Decision::Review)
    );
    vulnbell::research::import(
        &mut store,
        ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id,
            sources: vec![],
            events: vec![],
        },
    )
    .unwrap();
    let cases = store.cases().unwrap();
    assert_eq!(cases.len(), 2);
    assert!(cases.iter().any(|case| case.decision == Decision::Review));
    assert!(
        original
            .iter()
            .all(|old| cases.iter().any(|case| case.case_id == old.case_id
                && case.facts_sha256 == old.facts_sha256
                && case.evidence.len() == old.evidence.len()))
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
