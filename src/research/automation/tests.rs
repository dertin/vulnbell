use super::run_with;
use crate::{
    profile,
    research::{ResearchBatch, ReviewCoverage, SourceContinuation, SourceReview},
    store::Store,
};
use chrono::{Duration, Utc};
use std::fs;

fn fixture(upstreams: &[&str]) -> (tempfile::TempDir, String, Store) {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    let mut yaml =
        format!("schema: 1\nproject_id: {project}\nname: scheduled-research\ncomponents:\n");
    for (index, upstream) in upstreams.iter().enumerate() {
        yaml.push_str(&format!(
            "  - ref: example-{index}\n    version: '1.0.0'\n    upstream: {upstream}\n"
        ));
    }
    fs::write(&path, yaml).unwrap();
    let profile = profile::load(&path).unwrap();
    crate::engine::scan(&profile, &path, true).unwrap();
    let store = Store::open(&project).unwrap();
    (directory, project, store)
}

fn batch(
    plan: &crate::research::ResearchPlan,
    coverage: ReviewCoverage,
    cursor: Option<&str>,
) -> ResearchBatch {
    let target = &plan.targets[0];
    ResearchBatch {
        schema_version: 1,
        project_id: plan.project_id.clone(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            recheck_context_sha256: None,
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage,
            detail: "Synthetic source review".into(),
            continuation: cursor.map(|cursor| SourceContinuation {
                cursor: cursor.into(),
                url: None,
            }),
        }],
        events: vec![],
    }
}

#[test]
fn unavailable_codebase_keeps_scheduled_research_incomplete() {
    for discovery in ["", "discovery: off\n"] {
        let directory = tempfile::tempdir().unwrap();
        let workspace = directory.path().join("codebase");
        fs::create_dir(&workspace).unwrap();
        let project = uuid::Uuid::new_v4().to_string();
        let path = directory.path().join("vulnbell.yaml");
        fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\n{discovery}workspaces:\n  - {}\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/example\n", workspace.display())).unwrap();
        let profile = profile::load(&path).unwrap();
        crate::engine::scan(&profile, &path, true).unwrap();
        let mut store = Store::open(&project).unwrap();
        fs::remove_dir(&workspace).unwrap();

        let error = run_with(&mut store, Utc::now() + Duration::minutes(1), |_, _| {
            panic!("unavailable codebase must not start a source review")
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("research coverage remains incomplete")
        );
        assert!(store.meta("research_agent_cursor").unwrap().is_none());
        drop(store);
        fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }
}

#[test]
fn partial_pages_rotate_sources_and_finish_in_the_same_run() {
    let (_directory, project, mut store) = fixture(&[
        "https://github.com/example/a",
        "https://github.com/example/b",
    ]);
    let mut visits = Vec::new();
    run_with(&mut store, Utc::now() + Duration::minutes(1), |plan, _| {
        let target = &plan.targets[0];
        visits.push(target.upstream.clone());
        if target.upstream.ends_with("/a") && target.continuation.is_none() {
            assert!(target.last_complete_review.is_none());
            Ok(batch(plan, ReviewCoverage::Partial, Some("page-2")))
        } else {
            if target.upstream.ends_with("/a") {
                assert_eq!(target.continuation.as_ref().unwrap().cursor, "page-2");
                assert!(target.last_complete_review.is_none());
            }
            Ok(batch(plan, ReviewCoverage::Complete, None))
        }
    })
    .unwrap();
    assert_eq!(
        visits,
        [
            "https://github.com/example/a",
            "https://github.com/example/b",
            "https://github.com/example/a"
        ]
    );
    assert!(
        super::super::full_plan(&store)
            .unwrap()
            .targets
            .iter()
            .all(|target| !super::needs_review(target))
    );
    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn repeated_continuation_stays_partial_without_looping() {
    let (_directory, project, mut store) = fixture(&["https://github.com/example/a"]);
    let mut calls = 0;
    let result = run_with(&mut store, Utc::now() + Duration::minutes(1), |plan, _| {
        calls += 1;
        Ok(batch(plan, ReviewCoverage::Partial, Some("same-page")))
    });
    assert!(result.is_err());
    assert_eq!(calls, 2);
    let plan = super::super::full_plan(&store).unwrap();
    assert!(plan.targets[0].last_complete_review.is_none());
    assert_eq!(
        plan.targets[0].continuation.as_ref().unwrap().cursor,
        "same-page"
    );
    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn finishing_a_pinned_window_continues_to_the_new_snapshot() {
    let (_directory, project, mut store) = fixture(&["https://github.com/example/a"]);
    let mut old = store.latest().unwrap();
    old.id = uuid::Uuid::new_v4().to_string();
    old.finished_at = (Utc::now() - Duration::minutes(1)).to_rfc3339();
    store.save_snapshot(&old).unwrap();
    let plan = super::super::plan_page(&store, "", 1).unwrap();
    super::super::import(
        &mut store,
        batch(&plan, ReviewCoverage::Partial, Some("page-2")),
    )
    .unwrap();
    let mut latest = old.clone();
    latest.id = uuid::Uuid::new_v4().to_string();
    latest.finished_at = Utc::now().to_rfc3339();
    store.save_snapshot(&latest).unwrap();
    let mut windows = Vec::new();
    run_with(&mut store, Utc::now() + Duration::minutes(1), |plan, _| {
        windows.push(plan.targets[0].until.clone());
        Ok(batch(plan, ReviewCoverage::Complete, None))
    })
    .unwrap();
    assert_eq!(windows, [old.finished_at, latest.finished_at]);
    assert!(!super::needs_review(
        &super::super::full_plan(&store).unwrap().targets[0]
    ));
    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn scheduled_review_skips_active_recheck_but_visits_other_sources() {
    let (_directory, project, mut store) = fixture(&[
        "https://github.com/example/a",
        "https://github.com/example/b",
    ]);
    let plan = super::super::plan_page(&store, "", 1).unwrap();
    let since = (chrono::DateTime::parse_from_rfc3339(&plan.targets[0].until).unwrap()
        - Duration::days(1))
    .to_rfc3339();
    super::super::reopen_recheck(&mut store, "https://github.com/example/a", &since).unwrap();
    let mut visits = Vec::new();
    let result = run_with(&mut store, Utc::now() + Duration::minutes(1), |plan, _| {
        visits.push(plan.targets[0].upstream.clone());
        Ok(batch(plan, ReviewCoverage::Complete, None))
    });
    assert!(result.is_err());
    assert_eq!(visits, ["https://github.com/example/b"]);
    let plan = super::super::full_plan(&store).unwrap();
    assert!(plan.targets[0].progress.is_some());
    assert!(!super::needs_review(&plan.targets[1]));
    assert!(
        store
            .meta(&super::super::recheck_key(&plan.targets[0].upstream))
            .unwrap()
            .is_some()
    );
    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}
