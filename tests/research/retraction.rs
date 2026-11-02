use super::*;

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
        codebase_revisions: Vec::new(),
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
        artifact_evidence: None,
        rationale: "Synthetic rationale".into(),
        source_facts: Default::default(),
    };
    let batch = |events| ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            recheck_context_sha256: None,
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
    assert_eq!(cases[0].decision, Decision::Review);
    assert!(
        cases[0].coverage[0]
            .detail
            .contains("FixedInMonitoredVersion")
    );
    let contextual = "https://bugs.launchpad.net/example/+bug/3";
    vulnbell::research::import(
        &mut store,
        batch(vec![event(contextual, Assessment::Informational, None)]),
    )
    .unwrap();
    let before = store
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.upstream_events[0].url == contextual)
        .unwrap();
    let absent = event(
        contextual,
        Assessment::NotApplicable,
        Some(NotApplicableReason::ComponentNotInBuild),
    );
    assert!(vulnbell::research::import(&mut store, batch(vec![absent])).is_err());
    assert_eq!(
        store.case(&before.case_id).unwrap().decision,
        Decision::Informational
    );
    let mut correction = event(
        contextual,
        Assessment::NotApplicable,
        Some(NotApplicableReason::AffectsOtherVersion),
    );
    correction.source_facts.affected_versions = "1.x only".into();
    vulnbell::research::import(&mut store, batch(vec![correction])).unwrap();
    let after = store.case(&before.case_id).unwrap();
    assert_eq!(after.decision, Decision::Retracted);
    assert!(before.evidence.iter().all(|evidence| {
        after
            .evidence
            .iter()
            .any(|current| current.sha256 == evidence.sha256)
    }));
    let revisions: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM history WHERE case_id=?1",
            [&after.case_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(revisions >= 2);
    let mut current = store.latest().unwrap();
    current.cases = store.cases().unwrap();
    let mut report = vulnbell::output::morning_report(&current, &store, "cyber").unwrap();
    vulnbell::output::enrich_report_json(&mut report, &current, &store).unwrap();
    assert_eq!(report.retracted.len(), 1);
    assert!(report.retracted[0].history.len() >= 2);
    assert_eq!(report.informational_count, 0);
    assert_eq!(report.not_applicable_count, 3);
    assert!(
        serde_json::to_string(&report)
            .unwrap()
            .contains(&after.case_id)
    );
    vulnbell::output::prepare_report_paths(&mut report, &store).unwrap();
    assert!(
        !vulnbell::output::morning_markdown(&report)
            .unwrap()
            .contains(&after.case_id)
    );
    let actionable_url = "https://bugs.launchpad.net/example/+bug/4";
    vulnbell::research::import(
        &mut store,
        batch(vec![event(actionable_url, Assessment::Informational, None)]),
    )
    .unwrap();
    let mut actionable = store
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.upstream_events[0].url == actionable_url)
        .unwrap();
    actionable.decision = Decision::Actionable;
    store.save_case(&actionable).unwrap();
    let mut correction = event(
        actionable_url,
        Assessment::NotApplicable,
        Some(NotApplicableReason::AffectsOtherVersion),
    );
    correction.source_facts.affected_versions = "1.x only".into();
    vulnbell::research::import(&mut store, batch(vec![correction.clone()])).unwrap();
    assert_eq!(
        store.case(&actionable.case_id).unwrap().decision,
        Decision::Review
    );
    let mut resolved = store.case(&actionable.case_id).unwrap();
    resolved.decision = Decision::Informational;
    store.save_case(&resolved).unwrap();
    vulnbell::research::import(&mut store, batch(vec![correction])).unwrap();
    assert_eq!(
        store.case(&actionable.case_id).unwrap().decision,
        Decision::Retracted
    );
    let scoped_url = "https://bugs.launchpad.net/example/+bug/5";
    vulnbell::research::import(
        &mut store,
        batch(vec![event(scoped_url, Assessment::Informational, None)]),
    )
    .unwrap();
    let scoped = store
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.upstream_events[0].url == scoped_url)
        .unwrap();
    let mut correction = event(
        scoped_url,
        Assessment::NotApplicable,
        Some(NotApplicableReason::AffectsOtherVersion),
    );
    correction.instance_ids.truncate(1);
    correction.source_facts.affected_versions = "1.x only".into();
    vulnbell::research::import(&mut store, batch(vec![correction])).unwrap();
    let scoped_after = store.case(&scoped.case_id).unwrap();
    assert_eq!(scoped_after.decision, Decision::Review);
    assert_eq!(scoped_after.instances.len(), scoped.instances.len());
    assert!(
        scoped
            .instances
            .iter()
            .all(|old| scoped_after.instances.iter().any(|item| item.id == old.id))
    );
    let advisory_url = "https://bugs.launchpad.net/example/+bug/6";
    let mut advisory = event(advisory_url, Assessment::Informational, None);
    advisory.excerpt = "The issue mentions CVE-2026-12345.".into();
    vulnbell::research::import(&mut store, batch(vec![advisory])).unwrap();
    let advisory = store
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.upstream_events[0].url == advisory_url)
        .unwrap();
    let mut correction = event(
        advisory_url,
        Assessment::NotApplicable,
        Some(NotApplicableReason::AffectsOtherVersion),
    );
    correction.source_facts.affected_versions = "1.x only".into();
    vulnbell::research::import(&mut store, batch(vec![correction])).unwrap();
    assert_eq!(
        store.case(&advisory.case_id).unwrap().decision,
        Decision::Review
    );
    let go_url = "https://bugs.launchpad.net/example/+bug/7";
    let mut advisory = event(go_url, Assessment::Informational, None);
    advisory.excerpt = "The issue mentions GO-2026-1234.".into();
    vulnbell::research::import(&mut store, batch(vec![advisory])).unwrap();
    let advisory = store
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.upstream_events[0].url == go_url)
        .unwrap();
    let mut correction = event(
        go_url,
        Assessment::NotApplicable,
        Some(NotApplicableReason::AffectsOtherVersion),
    );
    correction.source_facts.affected_versions = "1.x only".into();
    vulnbell::research::import(&mut store, batch(vec![correction])).unwrap();
    assert_eq!(
        store.case(&advisory.case_id).unwrap().decision,
        Decision::Review
    );
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: changed-scope\ncomponents:\n  - ref: different-component\n    version: '3.0.0'\n")).unwrap();
    let next_profile = vulnbell::profile::load(&path).unwrap();
    let next = vulnbell::engine::scan(&next_profile, &path, true).unwrap();
    assert!(
        next.cases
            .iter()
            .any(|case| case.case_id == after.case_id && case.decision == Decision::Retracted)
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn component_retraction_is_bound_to_an_observed_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let codebase = directory.path().join("app");
    fs::create_dir(&codebase).unwrap();
    fs::write(codebase.join("artifact.bin"), b"observed artifact").unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\ndiscovery: off\ncodebases: [app]\ncomponents:\n  - ref: example-core\n    version: '2.0.0'\n    upstream: https://github.com/example/project\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let mut snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let instance = &mut snapshot.instances[0];
    instance.origin = vulnbell::model::Origin::ObservedArtifact;
    instance.provenance.sha256 = vulnbell::digest(b"observed artifact");
    instance.provenance.codebase = Some(
        codebase
            .canonicalize()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    );
    snapshot.id = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    store.save_snapshot(&snapshot).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let mut event = ResearchEvent {
        codebase_revisions: Vec::new(),
        upstream: target.upstream.clone(),
        instance_ids: target.instance_ids.clone(),
        reviewed_instance_ids: target.instance_ids.clone(),
        provider: "github".into(),
        external_id: "example/project#1".into(),
        kind: EventKind::PullRequest,
        url: "https://github.com/example/project/pull/1".into(),
        title: "Fixture".into(),
        excerpt: "Fixture".into(),
        updated_at: target.until.clone(),
        assessment: Assessment::Informational,
        not_applicable_reason: None,
        artifact_evidence: None,
        rationale: "The observed code needs review.".into(),
        source_facts: Default::default(),
    };
    let batch = |event| ResearchBatch {
        schema_version: 1,
        project_id: project.clone(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            recheck_context_sha256: None,
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage: ReviewCoverage::Partial,
            detail: "Fixture".into(),
            continuation: None,
        }],
        events: vec![event],
    };
    vulnbell::research::import(&mut store, batch(event.clone())).unwrap();
    let case = store.cases().unwrap().remove(0);
    event.assessment = Assessment::NotApplicable;
    event.not_applicable_reason = Some(NotApplicableReason::ComponentNotInBuild);
    event.artifact_evidence = Some(vulnbell::research::ArtifactEvidence {
        instance_id: target.instance_ids[0].clone(),
        codebase: 0,
        location: vulnbell::research::ArtifactLocation::Codebase,
        path: "artifact.bin".into(),
        sha256: vulnbell::digest(b"wrong"),
        installed_wheel: None,
        installed_archive: None,
    });
    assert!(vulnbell::research::import(&mut store, batch(event.clone())).is_err());
    assert_eq!(
        store.case(&case.case_id).unwrap().decision,
        Decision::Informational
    );
    event.artifact_evidence.as_mut().unwrap().sha256 = vulnbell::digest(b"observed artifact");
    vulnbell::research::import(&mut store, batch(event)).unwrap();
    let retired = store.case(&case.case_id).unwrap();
    assert_eq!(retired.decision, Decision::Retracted);
    assert!(
        retired
            .evidence
            .iter()
            .any(|evidence| evidence.source == "agent_retraction_assessment")
    );
    let mut snapshot = store.latest().unwrap();
    snapshot.cases = store.cases().unwrap();
    let projected = vulnbell::research::project_retractions(&snapshot, &store);
    assert_eq!(projected.cases[0].decision, Decision::Retracted);
    let mut inactive = snapshot.clone();
    inactive.instances.clear();
    let inactive = vulnbell::research::project_retractions(&inactive, &store);
    assert_eq!(inactive.cases[0].decision, Decision::Retracted);
    assert!(
        !vulnbell::tools::cases::pending_current(&store, &inactive)
            .unwrap()
            .verdict_missing
            .contains(&retired.case_id)
    );
    fs::write(codebase.join("artifact.bin"), b"changed artifact").unwrap();
    let projected = vulnbell::research::project_retractions(&snapshot, &store);
    assert_eq!(projected.cases[0].decision, Decision::Review);
    assert_eq!(
        store.case(&retired.case_id).unwrap().decision,
        Decision::Retracted
    );
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .verdict_missing
            .contains(&retired.case_id)
    );
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert!(
        report
            .needs_review
            .iter()
            .any(|case| case.case_id == retired.case_id)
    );
    drop(store);
    for audience in ["cyber", "audit"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_vulnbell"))
            .args([
                "report",
                "--project",
                path.to_str().unwrap(),
                "--audience",
                audience,
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report["retracted"].as_array().unwrap().is_empty());
        let cases = if audience == "audit" {
            &report["cases"]
        } else {
            &report["needs_review"]
        };
        assert!(
            cases
                .as_array()
                .unwrap()
                .iter()
                .any(|case| case["case_id"] == retired.case_id)
        );
    }
    let store = Store::open(&project).unwrap();
    let evidence = retired
        .evidence
        .iter()
        .find(|item| item.source == "agent_retraction_assessment")
        .unwrap();
    fs::remove_file(store.directory.join("evidence").join(&evidence.sha256)).unwrap();
    let historical = vulnbell::output::retracted_cases(&inactive, &store).unwrap();
    assert_eq!(historical[0].evidence_gaps.len(), 1);
    assert_eq!(historical[0].evidence_gaps[0], evidence.id);
    assert!(historical[0].research_events.is_empty());
    let mut without_reference = inactive.clone();
    without_reference.cases[0]
        .evidence
        .retain(|item| item.source != "agent_retraction_assessment");
    let historical = vulnbell::output::retracted_cases(&without_reference, &store).unwrap();
    assert_eq!(
        historical[0].evidence_gaps,
        ["agent_retraction_assessment:missing"]
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
