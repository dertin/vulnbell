use super::*;

#[test]
fn first_party_rejects_poms_with_invalid_utf8() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("pom.xml"),
        b"<project><groupId>example\xff</groupId><artifactId>app</artifactId></project>",
    )
    .unwrap();
    assert!(first_party(&[directory.path().to_string_lossy().into_owned()]).is_empty());
}

#[test]
fn lockfile_hash_changes_keep_mappings_and_declaration_changes_invalidate_them() {
    let profile: crate::profile::Profile = serde_saphyr::from_str(
        "schema: 1\nproject_id: 0de0a8e7-f1a4-4bdc-a198-422b90bbbd84\nname: sources\ncomponents:\n  - ref: example\n    version: '1.0.0'\n",
    )
    .unwrap();
    let declared = Instance::declared(&profile.components[0]);
    let mut edited = declared.clone();
    edited.provenance.sha256 = "other".into();
    assert_ne!(fingerprint(&declared), fingerprint(&edited));
    let mut locked = declared.clone();
    locked.origin = crate::model::Origin::Locked;
    let mut relocked = locked.clone();
    relocked.provenance.sha256 = "other".into();
    assert_eq!(fingerprint(&locked), fingerprint(&relocked));
}

#[test]
fn maven_mappings_from_an_earlier_mapper_revision_are_mapped_again() {
    let profile: crate::profile::Profile = serde_saphyr::from_str(
        "schema: 1\nproject_id: 0de0a8e7-f1a4-4bdc-a198-422b90bbbd84\nname: sources\ncomponents:\n  - ref: pkg:maven/io.quarkus/quarkus-agroal\n    version: '3.40.1'\n",
    )
    .unwrap();
    let instance = Instance::declared(&profile.components[0]);
    let observation =
        |rationale: String, state: MappingState, url: Option<&str>| IdentityObservation {
            instance_id: instance.id.clone(),
            fingerprint: fingerprint(&instance),
            version: None,
            cpe_product: None,
            rationale,
            sources: vec![SourceMapping {
                kind: SourceKind::Repository,
                state,
                url: url.map(str::to_owned),
                detail: "declared".into(),
                evidence: Vec::new(),
            }],
        };
    let earlier = format!(
        "{} from https://repo1.maven.org/x.pom",
        registry::NATIVE_RATIONALE
    );
    let current = format!(
        "{} ({}) from https://repo1.maven.org/x.pom",
        registry::NATIVE_RATIONALE,
        registry::MAVEN_MAPPER
    );
    let unavailable = MappingState::Unavailable;
    assert!(outdated_maven_mapping(
        &instance,
        &observation(earlier.clone(), unavailable, None)
    ));
    assert!(outdated_maven_mapping(
        &instance,
        &observation(
            earlier.clone(),
            MappingState::Mapped,
            Some("https://gitbox.apache.org/repos/asf?p=${commons.repo.name}.git")
        )
    ));
    assert!(outdated_maven_mapping(
        &instance,
        &observation(
            earlier,
            MappingState::Mapped,
            Some("https://github.com/jboss/jboss-parent-pom")
        )
    ));
    assert!(!outdated_maven_mapping(
        &instance,
        &observation(current, unavailable, None)
    ));
    assert!(!outdated_maven_mapping(
        &instance,
        &observation("Agent mapping".into(), unavailable, None)
    ));
}

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
    assert_eq!(mapped(&store, "test").unwrap().len(), 1);
    let second = record_document(
        &store,
        "https://example.net",
        b"Official project: https://example.net",
    )
    .unwrap();
    let mut ordered = observation.clone();
    let changes = ordered
        .sources
        .iter_mut()
        .find(|source| source.kind == SourceKind::ProposedChanges)
        .unwrap();
    changes.url = Some("https://example.net".into());
    changes.evidence = vec![EvidenceReference {
        id: second.id,
        sha256: second.sha256,
    }];
    import(&mut store, "test", vec![ordered]).unwrap();
    assert_eq!(
        mapped(&store, "test").unwrap(),
        vec![
            (instance.id.clone(), "https://example.org".into()),
            (instance.id.clone(), "https://example.net".into()),
        ]
    );
    assert!(
        targets(
            &store,
            "test",
            &BTreeSet::new(),
            &crate::profile::Research::default(),
            Mapper::Agent,
            10
        )
        .unwrap()
        .is_empty()
    );
    let mut enrichment_gap = observation.clone();
    enrichment_gap.sources[0].state = MappingState::Unavailable;
    import(&mut store, "test", vec![enrichment_gap]).unwrap();
    assert_eq!(
        counts(
            &store,
            "test",
            &BTreeSet::new(),
            std::slice::from_ref(&instance),
            &crate::profile::Research::default()
        )
        .unwrap(),
        (0, 0)
    );
    let mut no_repository = observation;
    let repository = no_repository
        .sources
        .iter_mut()
        .find(|source| source.kind == SourceKind::Repository)
        .unwrap();
    repository.state = MappingState::Unavailable;
    let mut native_gap = no_repository.clone();
    native_gap.rationale = format!("{} from https://crates.io/x", registry::NATIVE_RATIONALE);
    import(&mut store, "test", vec![native_gap]).unwrap();
    let pending = |mapper| {
        targets(
            &store,
            "test",
            &BTreeSet::new(),
            &crate::profile::Research::default(),
            mapper,
            10,
        )
        .unwrap()
        .len()
    };
    assert_eq!((pending(Mapper::Agent), pending(Mapper::Registry)), (1, 0));
    import(&mut store, "test", vec![no_repository]).unwrap();
    assert_eq!(
        counts(
            &store,
            "test",
            &BTreeSet::new(),
            std::slice::from_ref(&instance),
            &crate::profile::Research::default()
        )
        .unwrap(),
        (0, 1)
    );
    let mut next_snapshot = store.latest().unwrap();
    next_snapshot.id = uuid::Uuid::new_v4().to_string();
    next_snapshot.started_at = (chrono::Utc::now() + chrono::Duration::seconds(1)).to_rfc3339();
    store.save_snapshot(&next_snapshot).unwrap();
    assert!(
        targets(
            &store,
            "test",
            &BTreeSet::new(),
            &crate::profile::Research::default(),
            Mapper::Agent,
            10
        )
        .unwrap()
        .is_empty()
    );
    let week_old = (chrono::Utc::now() - chrono::Duration::days(8)).to_rfc3339();
    store
        .connection
        .execute("UPDATE discovery_sources SET checked_at=?1", [&week_old])
        .unwrap();
    assert_eq!(
        targets(
            &store,
            "test",
            &BTreeSet::new(),
            &crate::profile::Research::default(),
            Mapper::Agent,
            10
        )
        .unwrap()
        .len(),
        1
    );
    drop(directory);
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn research_pages_reach_every_researched_category_and_resume_a_pinned_partial_window() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vulnbell.yaml");
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
    assert_eq!(visited.len(), 6);
    assert!(!visited.contains("https://example.org/Website"));
    assert!(!visited.contains("https://example.org/Releases"));
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

#[test]
fn workspace_root_poms_mark_their_own_artifacts_as_first_party() {
    let provider = tempfile::tempdir().unwrap();
    std::fs::write(
        provider.path().join("pom.xml"),
        "<project><parent><groupId>com.prex</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>keycloak-provider</artifactId><dependencies><dependency><groupId>org.keycloak</groupId><artifactId>keycloak-core</artifactId></dependency></dependencies></project>",
    )
    .unwrap();
    let templated = tempfile::tempdir().unwrap();
    std::fs::write(
        templated.path().join("pom.xml"),
        "<project><groupId>${group}</groupId><artifactId>app</artifactId></project>",
    )
    .unwrap();
    let without_pom = tempfile::tempdir().unwrap();
    let roots: Vec<String> = [&provider, &templated, &without_pom]
        .iter()
        .map(|directory| directory.path().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        first_party(&roots),
        BTreeSet::from(["pkg:maven/com.prex/keycloak-provider".to_owned()])
    );
    let profile: crate::profile::Profile = serde_saphyr::from_str(
        "schema: 1\nproject_id: 0de0a8e7-f1a4-4bdc-a198-422b90bbbd84\nname: sources\ncomponents:\n  - ref: pkg:maven/com.prex/keycloak-provider\n    version: '2.7.0'\n  - ref: pkg:maven/org.keycloak/keycloak-core\n    version: '26.8.1'\n",
    )
    .unwrap();
    let instances: Vec<Instance> = profile.components.iter().map(Instance::declared).collect();
    let store = Store::open("6f0c2c1e-7d1a-4c5e-9b1f-0a4f1f0d2e31").unwrap();
    assert_eq!(
        counts(
            &store,
            "scope",
            &first_party(&roots),
            &instances,
            &crate::profile::Research::default()
        )
        .unwrap(),
        (1, 0)
    );
}
