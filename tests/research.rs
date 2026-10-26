use std::fs;
use vulnbell::{
    research::{Assessment, EventKind, ResearchBatch, ResearchEvent, ReviewCoverage, SourceReview},
    store::Store,
};
#[test]
fn agent_reviews_github_gitlab_launchpad_with_dedupe_and_failure_safe_checkpoints() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("radar.yaml");
    fs::write(&path,format!("schema: 1\nproject_id: {project}\nname: research-fixture\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://launchpad.net/example\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan(&store).unwrap();
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
        rationale: "Check attack preconditions before classifying; third-party report is not proof"
            .into(),
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
        vulnbell::research::plan(&store).unwrap().targets[0]
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
        vulnbell::research::plan(&store).unwrap().targets[0]
            .last_complete_review
            .is_none()
    );
    let first = vulnbell::research::import(&mut store, batch.clone()).unwrap();
    assert_eq!(first["changed_cases"], 3);
    assert!(
        vulnbell::research::plan(&store).unwrap().targets[0]
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
    let next = vulnbell::research::plan(&store).unwrap();
    assert_eq!(
        next.targets[0].last_complete_review.as_deref(),
        Some(target.until.as_str())
    );
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
