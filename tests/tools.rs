use chrono::{DateTime, Duration};
use std::{fs, path::Path};
use vulnbell::{
    model::Decision,
    research::Assessment,
    store::Store,
    tools::{cases, draft, hits, queue},
};

#[test]
fn evaluate_cli_reports_known_synthetic_false_negative() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args([
            "tools",
            "evaluate",
            "--from",
            "tests/fixtures/screening-evaluation.json",
            "--top",
            "2",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["total"], 6);
    assert_eq!(result["true_positive"], 3);
    assert_eq!(result["false_negative_keys"][0], "synthetic/6");
    assert_eq!(result["precision_at_top"], 1.0);
}

fn write(directory: &Path, relative: &str, contents: &str) {
    let path = directory.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

#[test]
fn hits_draft_and_case_batches_cover_one_daily_review() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: tools-fixture\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/project\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let until = DateTime::parse_from_rfc3339(&plan.targets[0].until).unwrap();
    let updated = (until - Duration::minutes(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let raw = directory.path().join("raw");
    let repository = "github/example/project";
    write(
        &raw,
        &format!("{repository}/issues.page-1.json"),
        &format!(
            r#"[[
      {{"number": 1, "title": "SYNTHETIC token reuse", "html_url": "https://github.com/example/project/issues/1",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "An attacker can reuse a token. Synthetic fixture."}},
      {{"number": 2, "title": "Check the token audience", "html_url": "https://github.com/example/project/pull/2",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "Fixes #1", "pull_request": {{}}}},
      {{"number": 3, "title": "build(deps): bump example-lib", "html_url": "https://github.com/example/project/pull/3",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "Upstream notes mention a security fix.", "pull_request": {{}}}},
      {{"number": 4, "title": "Docs typo", "html_url": "https://github.com/example/project/issues/4",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "Wording."}}
    ]]"#
        ),
    );
    write(&raw, &format!("{repository}/releases.page-1.json"), "[[]]");
    write(
        &raw,
        &format!("{repository}/security-advisories.page-1.json"),
        "[[]]",
    );

    let prepared = hits::prepare(&store, &raw, true).unwrap();
    let packet = hits::packet(&prepared, None);
    assert_eq!(packet.missing.len(), 1);
    assert_eq!(
        packet.missing[0].path,
        format!("{repository}/discussions.json")
    );
    assert_eq!(packet.summary.listed, 4);
    assert_eq!(packet.summary.selected, 3);
    assert_eq!(packet.summary.rule_resolved, 1);
    let keys: Vec<&str> = packet.review.iter().map(|item| item.key.as_str()).collect();
    assert_eq!(keys, vec!["example/project#1", "example/project#3"]);
    assert!(
        packet
            .review
            .iter()
            .all(|item| item.priority == hits::ReviewPriority::SecurityClaim)
    );

    let decisions_path = directory.path().join("research.json");
    fs::write(&decisions_path, r#"{"schema_version": 1, "decisions": []}"#).unwrap();
    let empty = draft::ResearchDecisions::load(&decisions_path).unwrap();
    assert!(draft::draft(hits::prepare(&store, &raw, true).unwrap(), &empty, false).is_err());

    write(
        &raw,
        &format!("{repository}/discussions.json"),
        r#"[{"data": {"search": {"discussionCount": 0, "nodes": [], "pageInfo": {"hasNextPage": false, "endCursor": null}}}}]"#,
    );
    let decisions = serde_json::json!({
        "schema_version": 1,
        "decisions": [{
            "key": "example/project#1",
            "updated_at": updated,
            "context_sha256": plan.targets[0].context_sha256,
            "assessment": "review",
            "rationale": "Synthetic report of token reuse; check the audience validation in the monitored version."
        }, {
            "key": "example/project#3",
            "updated_at": updated,
            "context_sha256": plan.targets[0].context_sha256,
            "assessment": "ignore",
            "rationale": "The synthetic dependency is not in the monitored inventory."
        }]
    });
    fs::write(&decisions_path, serde_json::to_vec(&decisions).unwrap()).unwrap();
    let decisions = draft::ResearchDecisions::load(&decisions_path).unwrap();
    let (batch, summary) = draft::draft(
        hits::prepare(&store, &raw, true).unwrap(),
        &decisions,
        false,
    )
    .unwrap();
    assert_eq!(summary.complete_sources, 1);
    assert_eq!(summary.events, 3);
    assert_eq!(summary.assessments["ignore"], 2);
    let reviewed = batch
        .events
        .iter()
        .find(|event| event.external_id == "example/project#1")
        .unwrap();
    assert_eq!(reviewed.assessment, Assessment::Review);
    assert_eq!(reviewed.provider, "github");
    let imported = vulnbell::research::import(&mut store, batch).unwrap();
    assert_eq!(imported["changed_cases"], 1);

    let again = hits::packet(&hits::prepare(&store, &raw, true).unwrap(), None);
    assert_eq!(again.summary.unchanged, 3);
    assert!(again.review.is_empty());

    let reconsidered = hits::packet(
        &hits::prepare_with_recheck(&store, &raw, true, true).unwrap(),
        None,
    );
    assert_eq!(reconsidered.summary.unchanged, 0);
    assert!(
        reconsidered
            .review
            .iter()
            .any(|item| item.key == "example/project#1")
    );

    let before_reassessment = store.cases().unwrap()[0].facts_sha256.clone();
    let mut revised = decisions.clone();
    revised.decisions[0].rationale =
        "Reassessed after new local evidence; keep the hypothesis open.".into();
    let (batch, _) = draft::draft(
        hits::prepare_with_recheck(&store, &raw, true, true).unwrap(),
        &revised,
        false,
    )
    .unwrap();
    let reassessed = vulnbell::research::import(&mut store, batch).unwrap();
    assert_eq!(reassessed["changed_cases"], 1);
    assert_ne!(store.cases().unwrap()[0].facts_sha256, before_reassessment);

    let pending = cases::pending(&store).unwrap();
    assert!(pending.research_open.is_empty());
    assert_eq!(pending.verdict_missing.len(), 1);
    let case_id = pending.verdict_missing[0].clone();

    let mut cited = store.case(&case_id).unwrap();
    cited.case_id = "SIG-test-cited".into();
    cited.upstream_events[0]
        .source_facts
        .identifiers
        .push("CVE-2099-0001".into());
    store.save_case(&cited).unwrap();
    let priority = queue::list(&store, 1, 0, true).unwrap();
    assert_eq!(priority.items[0].case_id, cited.case_id);
    assert!(
        priority.items[0]
            .priority_reasons
            .contains(&"cited_advisory_identifier")
    );
    store
        .connection
        .execute("DELETE FROM cases WHERE id=?1", [&cited.case_id])
        .unwrap();

    let before = queue::list(&store, 20, 0, true).unwrap();
    assert_eq!(before.open_total, 1);
    assert_eq!(before.items[0].case_id, case_id);
    assert!(
        queue::record(
            &store,
            &case_id,
            queue::WorkState::HumanReview,
            Some("Next")
        )
        .is_err()
    );
    queue::record(&store, &case_id, queue::WorkState::InProgress, None).unwrap();
    assert!(queue::record(&store, &case_id, queue::WorkState::InProgress, None).is_err());
    let recorded = queue::record(
        &store,
        &case_id,
        queue::WorkState::HumanReview,
        Some("Inspect the exact release"),
    )
    .unwrap();
    assert_eq!(
        recorded.next_step.as_deref(),
        Some("Inspect the exact release")
    );
    assert_eq!(queue::list(&store, 20, 0, true).unwrap().total, 0);
    assert_eq!(queue::list(&store, 20, 0, false).unwrap().total, 1);
    assert_eq!(
        cases::pending(&store).unwrap().verdict_missing,
        vec![case_id.clone()]
    );
    let saved = store.case(&case_id).unwrap();
    let mut new_outcome = saved.clone();
    new_outcome.applicability = vulnbell::model::Applicability::Conflict;
    store.save_case(&new_outcome).unwrap();
    let reopened_on_outcome = queue::list(&store, 20, 0, true).unwrap();
    assert!(reopened_on_outcome.items[0].previous_progress_stale);
    store.save_case(&saved).unwrap();
    let second_project = uuid::Uuid::new_v4().to_string();
    let mut second = Store::open(&second_project).unwrap();
    let mut copy = store.case(&case_id).unwrap();
    copy.project_id = second_project.clone();
    second.save_case(&copy).unwrap();
    let monitors = vec![
        ("first".to_owned(), Store::open(&project).unwrap()),
        ("second".to_owned(), second),
    ];
    let shared = queue::shared_cases(&monitors).unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].monitors.len(), 2);
    copy.instances[0].resolved_version = Some("2.0.0".into());
    let mut second = Store::open(&second_project).unwrap();
    second.save_case(&copy).unwrap();
    assert!(queue::shared_cases(&monitors).unwrap().is_empty());
    drop(monitors);
    drop(second);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(second_project)).unwrap();
    let original = store.case(&case_id).unwrap();
    let mut changed = original.clone();
    changed.facts_sha256 = "new-facts".into();
    store.save_case(&changed).unwrap();
    let reopened = queue::list(&store, 20, 0, true).unwrap();
    assert_eq!(reopened.total, 1);
    assert!(reopened.items[0].previous_progress_stale);
    assert!(reopened.items[0].progress.is_none());
    store.save_case(&original).unwrap();

    let mut advisory_case = original.clone();
    advisory_case.claims.push(vulnbell::model::Claim {
        id: "GHSA-test-duplicate".into(),
        source: "synthetic".into(),
        aliases: vec![],
        instance_id: original.instances[0].id.clone(),
        summary: "fixture".into(),
        applicability: vulnbell::model::Applicability::Affected,
        evidence: vulnbell::model::Evidence {
            id: "fixture".into(),
            sha256: "fixture".into(),
            source: "fixture".into(),
            url: None,
            observed_at: "2026-01-01T00:00:00Z".into(),
            kind: vulnbell::model::EvidenceKind::Advisory,
        },
        known_exploited: false,
    });
    store.save_case(&advisory_case).unwrap();
    let mut duplicate = advisory_case.clone();
    duplicate.case_id = "SIG-test-duplicate".into();
    store.save_case(&duplicate).unwrap();
    let groups = queue::duplicate_advisories(&store).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].cases.len(), 2);
    duplicate.instances[0].resolved_version = Some("2.0.0".into());
    store.save_case(&duplicate).unwrap();
    assert!(queue::duplicate_advisories(&store).unwrap().is_empty());
    store
        .connection
        .execute("DELETE FROM cases WHERE id=?1", [&duplicate.case_id])
        .unwrap();
    store.save_case(&original).unwrap();

    let batches = directory.path().join("run");
    write(
        &batches,
        "notes/token.md",
        "Synthetic note: audience is validated in src/token.rs:42.",
    );
    write(
        &batches,
        "impact.json",
        &serde_json::json!({
            "schema_version": 1,
            "cases": [{
                "case_id": case_id,
                "notes": ["notes/token.md"],
                "answers": [{
                    "question": "artifact_deployed",
                    "answer": "unknown",
                    "rationale": "Synthetic fixture without deployment records."
                }]
            }]
        })
        .to_string(),
    );
    let impact = cases::load_impact(&batches.join("impact.json")).unwrap();
    let outcomes = cases::apply_impact(&mut store, &impact, &batches);
    assert!(outcomes[0].applied, "{:?}", outcomes[0].error);

    let evidence = store
        .case(&case_id)
        .unwrap()
        .evidence
        .into_iter()
        .find(|item| item.source == "local_impact_evidence")
        .unwrap();
    let reference = serde_json::json!({"id": evidence.id, "sha256": evidence.sha256});
    let mut reused: cases::ImpactBatch = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "cases": [{"case_id": case_id, "answers": [{
            "question": "affected_feature_used", "answer": "unknown",
            "rationale": "The registered note covers this fixture.", "evidence": [reference]
        }]}]
    }))
    .unwrap();
    assert!(cases::apply_impact(&mut store, &reused, &batches)[0].applied);
    reused.cases[0].answers[0].evidence[0].sha256 = "forged".into();
    assert!(!cases::apply_impact(&mut store, &reused, &batches)[0].applied);

    write(
        &batches,
        "verdicts.json",
        &serde_json::json!({
            "schema_version": 1,
            "verdicts": [{
                "case_id": case_id,
                "decision": "review",
                "applicability": "possible",
                "verification": "inconclusive",
                "rationale": "Synthetic fixture; the claim needs a source reading.",
                "notes": ["notes/token.md"]
            }]
        })
        .to_string(),
    );
    let verdicts = cases::load_verdicts(&batches.join("verdicts.json")).unwrap();
    let outcomes = cases::apply_verdicts(&mut store, &verdicts, &batches);
    assert!(outcomes[0].applied, "{:?}", outcomes[0].error);
    let case = store.case(&case_id).unwrap();
    assert_eq!(case.decision, Decision::Review);
    assert_eq!(
        case.evidence
            .iter()
            .filter(|evidence| evidence.source == "local_impact_evidence")
            .count(),
        1
    );
    let pending = cases::pending(&store).unwrap();
    assert_eq!(pending.schema_version, 1);
    assert!(pending.verdict_missing.is_empty());

    let handoff = cases::HandoffBatch {
        schema_version: 1,
        cases: vec![cases::ReviewHandoff {
            case_id: case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            rationale: "The source was reviewed; a lab test is not needed for this handoff.".into(),
            uncertainty: "The deployed configuration is unknown.".into(),
            next_step: "Confirm the deployed configuration with the operator.".into(),
            sandbox_required: false,
            sandbox_instance_ids: Vec::new(),
            note: "notes/token.md".into(),
        }],
    };
    let mut missing_targets = serde_json::to_value(&handoff).unwrap();
    missing_targets["cases"][0]
        .as_object_mut()
        .unwrap()
        .remove("sandbox_instance_ids");
    assert!(serde_json::from_value::<cases::HandoffBatch>(missing_targets).is_err());
    let mut old_schema = serde_json::to_value(&handoff).unwrap();
    old_schema["schema_version"] = 2.into();
    write(&batches, "old-handoff.json", &old_schema.to_string());
    assert!(cases::load_handoff(&batches.join("old-handoff.json")).is_err());
    let old_batch: cases::HandoffBatch = serde_json::from_value(old_schema).unwrap();
    assert!(!cases::apply_handoff(&mut store, &old_batch, &batches)[0].applied);
    assert!(cases::apply_handoff(&mut store, &handoff, &batches)[0].applied);
    let current = store.case(&case_id).unwrap();
    assert!(cases::current_handoff(&current, &store).is_some());
    let original = current
        .evidence
        .iter()
        .rev()
        .find(|e| e.source == "review_handoff")
        .unwrap();
    let mut prior: serde_json::Value = serde_json::from_slice(
        &fs::read(store.directory.join("evidence").join(&original.sha256)).unwrap(),
    )
    .unwrap();
    prior.as_object_mut().unwrap().remove("schema_version");
    prior["handoff"]
        .as_object_mut()
        .unwrap()
        .remove("sandbox_instance_ids");
    let old_evidence = store
        .record_evidence(
            &serde_json::to_vec(&prior).unwrap(),
            "review_handoff",
            None,
            vulnbell::model::EvidenceKind::Context,
        )
        .unwrap();
    let mut old_case = current.clone();
    old_case.evidence.push(old_evidence);
    assert!(cases::current_handoff(&old_case, &store).is_none());
    let mut snapshot = store.latest().unwrap();
    snapshot.cases = store.cases().unwrap();
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    let check = report
        .finding_checks
        .iter()
        .find(|check| check.case_id == case_id)
        .unwrap();
    assert!(check.review_handoff.is_some());
    assert!(
        !report
            .verification_pending
            .iter()
            .any(|pending| pending.case_id == case_id)
    );
    assert!(
        vulnbell::output::morning_markdown(&report).contains("Confirm the deployed configuration")
    );
    let mut changed_verdict = verdicts;
    changed_verdict.verdicts[0].rationale =
        "A revised explanation for the same open hypothesis.".into();
    assert!(cases::apply_verdicts(&mut store, &changed_verdict, &batches)[0].applied);
    let changed = store.case(&case_id).unwrap();
    assert!(cases::current_handoff(&changed, &store).is_none());
    snapshot.cases = store.cases().unwrap();
    let stale_report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert!(
        stale_report
            .finding_checks
            .iter()
            .find(|check| check.case_id == case_id)
            .unwrap()
            .review_handoff_stale
    );
    assert!(
        stale_report
            .verification_pending
            .iter()
            .any(|pending| pending.case_id == case_id
                && pending.reason == vulnbell::output::PendingReason::ReviewDispositionMissing)
    );
    let mut stale = changed.clone();
    stale.facts_sha256 = "changed".into();
    assert!(cases::current_handoff(&stale, &store).is_none());
    let mut required = handoff;
    required.cases[0].sandbox_required = true;
    required.cases[0].sandbox_instance_ids = vec!["not-a-current-instance".into()];
    assert!(!cases::apply_handoff(&mut store, &required, &batches)[0].applied);
    required.cases[0].sandbox_instance_ids.clear();
    assert!(!cases::apply_handoff(&mut store, &required, &batches)[0].applied);
    required.cases[0].sandbox_instance_ids = vec![changed.instances[0].id.clone()];
    assert!(cases::apply_handoff(&mut store, &required, &batches)[0].applied);
    let mut snapshot = store.latest().unwrap();
    snapshot.cases = store.cases().unwrap();
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    let pending = report
        .verification_pending
        .iter()
        .find(|pending| pending.case_id == case_id)
        .unwrap();
    assert_eq!(
        pending.reason,
        vulnbell::output::PendingReason::SandboxCheckMissing
    );
    assert!(
        report
            .finding_checks
            .iter()
            .find(|check| check.case_id == case_id)
            .unwrap()
            .local_checks[0]
            .sandbox_needed
    );

    let mut multi = store.case(&case_id).unwrap();
    let first_id = multi.instances[0].id.clone();
    let mut second = multi.instances[0].clone();
    second.id = "second-instance".into();
    multi.instances.push(second);
    store.save_case(&multi).unwrap();
    required.cases[0].sandbox_instance_ids.clear();
    assert!(!cases::apply_handoff(&mut store, &required, &batches)[0].applied);
    required.cases[0].sandbox_instance_ids = vec![first_id.clone()];
    assert!(cases::apply_handoff(&mut store, &required, &batches)[0].applied);
    snapshot.cases = store.cases().unwrap();
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    let checks = &report
        .finding_checks
        .iter()
        .find(|check| check.case_id == case_id)
        .unwrap()
        .local_checks;
    assert!(
        checks
            .iter()
            .find(|check| check.instance_id == first_id)
            .unwrap()
            .sandbox_needed
    );
    assert!(
        !checks
            .iter()
            .find(|check| check.instance_id == "second-instance")
            .unwrap()
            .sandbox_needed
    );

    let invalid = store
        .record_evidence(
            b"invalid handoff",
            "review_handoff",
            None,
            vulnbell::model::EvidenceKind::Context,
        )
        .unwrap();
    let mut invalid_latest = store.case(&case_id).unwrap();
    invalid_latest.evidence.push(invalid);
    store.save_case(&invalid_latest).unwrap();
    assert!(cases::current_handoff(&invalid_latest, &store).is_none());
    snapshot.cases = store.cases().unwrap();
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert!(
        report
            .verification_pending
            .iter()
            .any(|pending| pending.case_id == case_id
                && pending.reason == vulnbell::output::PendingReason::ReviewDispositionMissing)
    );

    drop(store);
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: tools-fixture\ncomponents:\n  - ref: example\n    version: '1.1.0'\n    upstream: https://github.com/example/project\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(
        plan.targets[0]
            .seen
            .iter()
            .all(|seen| !seen.context_current)
    );
    let reassessed = hits::packet(
        &hits::prepare(&store, &raw, true).unwrap(),
        Some(&decisions),
    );
    assert_eq!(reassessed.summary.unchanged, 0);
    let keys: Vec<&str> = reassessed
        .review
        .iter()
        .map(|item| item.key.as_str())
        .collect();
    assert_eq!(keys, vec!["example/project#1", "example/project#3"]);
    assert!(
        draft::draft(
            hits::prepare(&store, &raw, true).unwrap(),
            &decisions,
            false
        )
        .is_err()
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
