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
    let mut legacy_duplicate = store.cases().unwrap()[0].clone();
    legacy_duplicate.case_id = "ZZZ-synthetic-legacy-duplicate".into();
    store.save_case(&legacy_duplicate).unwrap();
    let duplicate = vulnbell::research::import(&mut store, batch.clone()).unwrap();
    assert_eq!(duplicate["duplicates"], 3);
    assert_eq!(duplicate["merged_cases"], 1);
    assert!(store.case("ZZZ-synthetic-legacy-duplicate").is_ok());
    let mut reformatted = batch.clone();
    for event in &mut reformatted.events {
        event.external_id = format!("project#{}", event.external_id);
        event.provider = event.provider.to_uppercase();
    }
    assert_eq!(
        vulnbell::research::import(&mut store, reformatted).unwrap()["duplicates"],
        3
    );

    assert_eq!(store.cases().unwrap().len(), 3);
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
