use super::*;

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
            recheck_context_sha256: None,
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
            codebase_revisions: Vec::new(),
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
            artifact_evidence: None,
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
            snapshot_id: plan.snapshot_id.clone(),
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
    let target = &plan.targets[0];
    let event = ResearchEvent {
        codebase_revisions: Vec::new(),
        upstream: target.upstream.clone(),
        instance_ids: target.instance_ids.clone(),
        reviewed_instance_ids: target.instance_ids.clone(),
        provider: "github".into(),
        external_id: "item-0".into(),
        kind: EventKind::Issue,
        url: url.into(),
        title: "synthetic".into(),
        excerpt: "synthetic".into(),
        updated_at: target.until.clone(),
        assessment: Assessment::NotApplicable,
        not_applicable_reason: Some(NotApplicableReason::AffectsOtherVersion),
        artifact_evidence: None,
        rationale: "synthetic".into(),
        source_facts: vulnbell::model::SourceFacts {
            affected_versions: "0.x".into(),
            ..Default::default()
        },
    };
    vulnbell::research::import(
        &mut store,
        ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id,
            sources: vec![SourceReview {
                recheck_context_sha256: None,
                upstream: target.upstream.clone(),
                from: target.from.clone(),
                until: target.until.clone(),
                coverage: ReviewCoverage::Partial,
                detail: "synthetic".into(),
                continuation: None,
            }],
            events: vec![event],
        },
    )
    .unwrap();
    let mut snapshot = store.latest().unwrap();
    snapshot.cases = store.cases().unwrap();
    let retracted = vulnbell::output::retracted_cases(&snapshot, &store).unwrap();
    assert_eq!(retracted.len(), 1);
    assert_eq!(retracted[0].research_events.len(), 1);
    assert_eq!(retracted[0].research_events[0].upstream, target.upstream);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
#[test]
fn recheck_retains_since_after_inventory_change() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: test\ncomponents:\n  - ref: app\n    version: '1.0.0'\n    upstream: https://github.com/example/app\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let mut snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let since = "2020-01-01T00:00:00+00:00";
    vulnbell::research::reopen_recheck(&mut store, "all", since).unwrap();
    assert_eq!(
        vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .targets[0]
            .from,
        since
    );
    snapshot.id = uuid::Uuid::new_v4().to_string();
    snapshot.instances[0].resolved_version = Some("2.0.0".into());
    store.save_snapshot(&snapshot).unwrap();
    let next = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert_eq!(next.targets[0].from, since);
    assert!(next.targets[0].context_reopened);
    assert!(next.targets[0].continuation.is_none());
    assert!(
        !vulnbell::tools::cases::pending(&store)
            .unwrap()
            .research_open
            .is_empty()
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
