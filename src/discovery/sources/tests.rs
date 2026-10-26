use super::*;

#[test]
fn mapped_sources_require_acquired_evidence_and_every_category() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let profile: crate::profile::Profile = serde_saphyr::from_str(&format!("schema: 1\nproject_id: {project}\nname: sources\ncomponents:\n  - ref: example\n    version: '1.0.0'\n")).unwrap();
    let instance = Instance::declared(&profile.components[0]);
    store
        .save_snapshot(&crate::model::Snapshot {
            schema_version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            project_id: project.clone(),
            profile_sha256: "test".into(),
            started_at: crate::now(),
            finished_at: crate::now(),
            instances: vec![instance.clone()],
            coverage: vec![],
            cases: vec![],
            partial: true,
            alert_status: "test".into(),
        })
        .unwrap();
    let evidence = record_document(
        &store,
        "https://example.org",
        b"Official project: https://example.org",
    )
    .unwrap();
    let observation = IdentityObservation {
        instance_id: instance.id.clone(),
        fingerprint: fingerprint(&instance),
        version: None,
        cpe_product: None,
        rationale: "Public product documentation links to these sources".into(),
        sources: SOURCE_KINDS
            .iter()
            .map(|kind| SourceMapping {
                kind: *kind,
                state: MappingState::Mapped,
                url: Some("https://example.org".into()),
                detail: "Official public entry point".into(),
                evidence: vec![EvidenceReference {
                    id: evidence.id.clone(),
                    sha256: evidence.sha256.clone(),
                }],
            })
            .collect(),
    };
    let mut store = store;
    let mut invalid = observation.clone();
    invalid.sources.pop();
    assert!(import(&mut store, "test", vec![invalid]).is_err());
    let mut invalid = observation.clone();
    invalid.sources[0].evidence[0].sha256 = "forged".into();
    assert!(import(&mut store, "test", vec![invalid]).is_err());
    assert!(import(&mut store, "test", vec![observation.clone()]).is_ok());
    assert_eq!(mapped(&store, "test").unwrap().len(), 9);
    assert!(targets(&store, "test", 10).unwrap().is_empty());
    let mut unavailable = observation;
    unavailable.sources[0].state = MappingState::Unavailable;
    import(&mut store, "test", vec![unavailable]).unwrap();
    assert!(targets(&store, "test", 10).unwrap().is_empty());
    let mut next_snapshot = store.latest().unwrap();
    next_snapshot.id = uuid::Uuid::new_v4().to_string();
    next_snapshot.started_at = (chrono::Utc::now() + chrono::Duration::seconds(1)).to_rfc3339();
    store.save_snapshot(&next_snapshot).unwrap();
    assert_eq!(targets(&store, "test", 10).unwrap().len(), 1);
    drop(directory);
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn public_source_pages_reach_every_category_and_resume_a_pinned_partial_window() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("radar.yaml");
    let project = uuid::Uuid::new_v4().to_string();
    std::fs::write(&path,format!("schema: 1\nproject_id: {project}\nname: public-sources\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://example.org/Repository\n")).unwrap();
    let profile = crate::profile::load(&path).unwrap();
    crate::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let snapshot = store.latest().unwrap();
    let instance = &snapshot.instances[0];
    let mut observation = IdentityObservation {
        instance_id: instance.id.clone(),
        fingerprint: fingerprint(instance),
        version: None,
        cpe_product: None,
        rationale: "Synthetic official cross-links acquired for every source category".into(),
        sources: Vec::new(),
    };
    for kind in SOURCE_KINDS {
        let url = format!("https://example.org/{kind:?}");
        let evidence = record_document(&store, &url, url.as_bytes()).unwrap();
        observation.sources.push(SourceMapping {
            kind,
            state: MappingState::Mapped,
            url: Some(url),
            detail: "Public fixture document".into(),
            evidence: vec![EvidenceReference {
                id: evidence.id,
                sha256: evidence.sha256,
            }],
        });
    }
    import(
        &mut store,
        &crate::discovery::scope(&profile, &path).unwrap(),
        vec![observation],
    )
    .unwrap();
    let mut cursor = String::new();
    let mut visited = BTreeSet::new();
    loop {
        let page = crate::research::plan_page(&store, &cursor, 1).unwrap();
        for target in &page.targets {
            assert!(visited.insert(target.upstream.clone()));
        }
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    assert_eq!(visited.len(), 9);
    let plan = crate::research::plan_page(&store, "", 1).unwrap();
    let target = &plan.targets[0];
    let review = crate::research::SourceReview {
        upstream: target.upstream.clone(),
        from: target.from.clone(),
        until: target.until.clone(),
        coverage: crate::research::ReviewCoverage::Partial,
        detail: "One more page remains".into(),
        continuation: Some(crate::research::SourceContinuation {
            cursor: "page-2".into(),
            url: Some(format!("{}?page=2", target.upstream)),
        }),
    };
    crate::research::import(
        &mut store,
        crate::research::ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id,
            sources: vec![review.clone()],
            events: vec![],
        },
    )
    .unwrap();
    let mut next_snapshot = store.latest().unwrap();
    next_snapshot.id = uuid::Uuid::new_v4().to_string();
    next_snapshot.finished_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    store.save_snapshot(&next_snapshot).unwrap();
    let resumed = crate::research::plan_page(&store, "", 1).unwrap();
    assert_eq!(resumed.targets[0].until, review.until);
    assert_eq!(
        resumed.targets[0].continuation.as_ref().unwrap().cursor,
        "page-2"
    );
    let mut complete = review;
    complete.coverage = crate::research::ReviewCoverage::Complete;
    complete.continuation = None;
    crate::research::import(
        &mut store,
        crate::research::ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: next_snapshot.id,
            sources: vec![complete],
            events: vec![],
        },
    )
    .unwrap();
    let fresh = crate::research::plan_page(&store, "", 1).unwrap();
    assert_eq!(fresh.targets[0].until, next_snapshot.finished_at);
    assert!(fresh.targets[0].continuation.is_none());
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}
