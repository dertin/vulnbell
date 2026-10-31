use super::*;

#[test]
fn contained_advisories_collapse_into_one_row_and_exposed_cases_keep_their_card() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let mut instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:cargo/zstd-safe".into(),
        version: Some("7.3.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    instance.purl = Some(instance.reference.clone());
    let context = store
        .record_evidence(
            b"Reviewed actix-http decoder usage.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut cases = Vec::new();
    for (case_id, advisory, used, input) in [
        ("SIG-contained", "RUSTSEC-0001", "no", "no"),
        ("SIG-exposed", "RUSTSEC-0002", "yes", "unknown"),
    ] {
        let osv = json!({"id":advisory,"details":"SYNTHETIC advisory","affected":[{"package":{"ecosystem":"crates.io","name":"zstd-safe","purl":"pkg:cargo/zstd-safe"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"8.2.0"}]}]}]});
        let evidence = store
            .record_evidence(
                &serde_json::to_vec(&osv).unwrap(),
                "osv",
                None,
                EvidenceKind::Advisory,
            )
            .unwrap();
        let case = Case {
            workspace_revisions: Vec::new(),
            schema_version: 1,
            case_id: case_id.into(),
            project_id: project.clone(),
            snapshot_id: "snapshot".into(),
            instances: vec![instance.clone()],
            claims: vec![Claim {
                id: advisory.into(),
                source: "osv".into(),
                aliases: Vec::new(),
                instance_id: instance.id.clone(),
                summary: format!("SYNTHETIC {advisory}"),
                applicability: Applicability::Affected,
                evidence: evidence.clone(),
                known_exploited: false,
            }],
            upstream_events: Vec::new(),
            evidence: vec![evidence, context.clone()],
            coverage: Vec::new(),
            applicability: Applicability::Affected,
            verification: Verification::SourceConfirmed,
            decision: Decision::Actionable,
            facts_sha256: "facts".into(),
            open_questions: vec!["Generic case question.".into()],
            suggested_search_queries: Vec::new(),
            sandbox: SandboxAvailability {
                available: true,
                reason: "synthetic".into(),
            },
            updated_at: vulnbell::now(),
        };
        store.save_case(&case).unwrap();
        let answer = |question, value: &str, rationale: &str| vulnbell::impact::ImpactAnswer {
            instance_id: instance.id.clone(),
            question,
            answer: serde_json::from_value(json!(value)).unwrap(),
            rationale: rationale.into(),
            evidence: vec![EvidenceReference {
                id: context.id.clone(),
                sha256: context.sha256.clone(),
            }],
        };
        use vulnbell::impact::ImpactQuestionId::*;
        vulnbell::impact::assess(
            &mut store,
            case_id,
            vulnbell::impact::ImpactSubmission {
                schema_version: 1,
                case_id: case_id.into(),
                facts_sha256: "facts".into(),
                answers: vec![
                    answer(ArtifactDeployed, "yes", "Service image."),
                    answer(
                        AffectedFeatureUsed,
                        used,
                        &format!("{case_id} feature rationale."),
                    ),
                    answer(UntrustedInputReachesFeature, input, "Input rationale."),
                    answer(
                        RequiredConditionsPresent,
                        "unknown",
                        "Conditions rationale.",
                    ),
                    answer(FixOrMitigationApplied, "no", "Not fixed."),
                ],
            },
        )
        .unwrap();
        cases.push(store.case(case_id).unwrap());
    }
    let snapshot = Snapshot {
        workspace_revisions: Vec::new(),
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: vec![instance],
        cases,
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    let mut report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    report.finding_checks.reverse();
    assert_eq!(report.actionable.len(), 2);
    let markdown = vulnbell::output::morning_markdown(&report);
    assert!(markdown.contains("**1** may be exposed in the project and **1** are not exposed"));
    assert!(markdown.contains("### SIG-exposed"));
    assert!(!markdown.contains("### SIG-contained"));
    assert!(markdown.contains("1 open cases without project exposure keep"));
    assert!(
        report
            .finding_checks
            .iter()
            .any(|check| check.case_id == "SIG-contained" && check.impact.is_some())
    );
    assert!(markdown.contains("| RUSTSEC-0001 | SIG-contained feature rationale. | 8.2.0 |"));
    assert!(markdown.contains("Update with priority to 8.2.0"));
    assert!(markdown.contains("**Affected feature in use:** yes — SIG-exposed feature rationale."));
    assert!(!markdown.contains("Generic case question."));
    assert!(!markdown.contains("**Local verification:** not run"));
    assert!(!markdown.contains("**Instance "));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn unconfirmed_versions_need_a_review_disposition_without_requiring_a_test() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:cargo/hyper-util".into(),
        version: Some("0.1.21".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let context = store
        .record_evidence(
            b"Reviewed listener setup.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let advisory = store
        .record_evidence(
            b"{\"id\":\"RUSTSEC-0003\"}",
            "osv",
            None,
            EvidenceKind::Advisory,
        )
        .unwrap();
    let mut cases = Vec::new();
    for (case_id, claims) in [
        ("SIG-issue", Vec::new()),
        (
            "SIG-advisory",
            vec![Claim {
                id: "RUSTSEC-0003".into(),
                source: "osv".into(),
                aliases: Vec::new(),
                instance_id: instance.id.clone(),
                summary: "SYNTHETIC RUSTSEC-0003".into(),
                applicability: Applicability::Affected,
                evidence: advisory.clone(),
                known_exploited: false,
            }],
        ),
    ] {
        let case = Case {
            workspace_revisions: Vec::new(),
            schema_version: 1,
            case_id: case_id.into(),
            project_id: project.clone(),
            snapshot_id: "snapshot".into(),
            instances: vec![instance.clone()],
            claims,
            upstream_events: Vec::new(),
            evidence: vec![context.clone()],
            coverage: Vec::new(),
            applicability: Applicability::Unknown,
            verification: Verification::Inconclusive,
            decision: Decision::Review,
            facts_sha256: "facts".into(),
            open_questions: Vec::new(),
            suggested_search_queries: Vec::new(),
            sandbox: SandboxAvailability {
                available: true,
                reason: "synthetic".into(),
            },
            updated_at: vulnbell::now(),
        };
        store.save_case(&case).unwrap();
        let answer = |question, value: &str| vulnbell::impact::ImpactAnswer {
            instance_id: instance.id.clone(),
            question,
            answer: serde_json::from_value(json!(value)).unwrap(),
            rationale: "Deployment edge is not documented.".into(),
            evidence: vec![EvidenceReference {
                id: context.id.clone(),
                sha256: context.sha256.clone(),
            }],
        };
        use vulnbell::impact::ImpactQuestionId::*;
        let result = vulnbell::impact::assess(
            &mut store,
            case_id,
            vulnbell::impact::ImpactSubmission {
                schema_version: 1,
                case_id: case_id.into(),
                facts_sha256: "facts".into(),
                answers: vec![
                    answer(ArtifactDeployed, "unknown"),
                    answer(AffectedFeatureUsed, "yes"),
                    answer(UntrustedInputReachesFeature, "unknown"),
                    answer(RequiredConditionsPresent, "unknown"),
                    answer(FixOrMitigationApplied, "no"),
                ],
            },
        )
        .unwrap();
        assert_eq!(
            result.verdict,
            vulnbell::impact::ImpactVerdict::NeedsEvidence
        );
        cases.push(store.case(case_id).unwrap());
    }
    let mut snapshot = Snapshot {
        workspace_revisions: Vec::new(),
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: vec![instance.clone()],
        cases,
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    let pending = |snapshot: &Snapshot, store: &Store| {
        let report = vulnbell::output::morning_report(snapshot, store, "cyber").unwrap();
        let needed: Vec<(String, bool)> = report
            .finding_checks
            .iter()
            .map(|check| {
                assert!(!check.local_checks[0].sandbox_needed);
                (
                    check.case_id.clone(),
                    check.local_checks[0].sandbox_candidate,
                )
            })
            .collect();
        let pending: Vec<String> = report
            .verification_pending
            .iter()
            .map(|item| {
                assert_eq!(
                    item.reason,
                    vulnbell::output::PendingReason::ReviewDispositionMissing
                );
                item.case_id.clone()
            })
            .collect();
        (needed, pending)
    };
    let (needed, open) = pending(&snapshot, &store);
    assert!(needed.contains(&("SIG-issue".into(), true)));
    assert!(needed.contains(&("SIG-advisory".into(), false)));
    assert_eq!(open, ["SIG-issue"]);

    let incomplete_blocker = store
        .record_evidence(
            &serde_json::to_vec(&json!({
                "schema_version": 1,
                "case_id": "SIG-issue",
                "workspace_revisions": [],
                "facts_sha256": "facts",
                "instance_id": instance.id,
                "reason": "Deployment configuration is unavailable.",
            }))
            .unwrap(),
            "local_validation_blocker",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut issue = store.case("SIG-issue").unwrap();
    issue.evidence.push(incomplete_blocker);
    store.save_case(&issue).unwrap();
    snapshot.cases[0] = issue;
    let (_, open) = pending(&snapshot, &store);
    assert_eq!(open, ["SIG-issue"]);

    snapshot.cases[0] = vulnbell::sandbox::record_blocker(
        &mut store,
        "SIG-issue",
        None,
        vulnbell::sandbox::BlockerKind::DetailsUndisclosed,
        "The report withholds the trigger until a fix ships.",
    )
    .unwrap();
    let (_, open) = pending(&snapshot, &store);
    assert!(open.is_empty());
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    let check = &report
        .finding_checks
        .iter()
        .find(|check| check.case_id == "SIG-issue")
        .unwrap()
        .local_checks[0];
    assert_eq!(
        check.blocker,
        Some(vulnbell::sandbox::BlockerKind::DetailsUndisclosed)
    );
    assert!(check.detail.starts_with("details not disclosed: "));
    let old_evidence_count = snapshot.cases[0].evidence.len();
    snapshot.cases[0] = vulnbell::sandbox::clear_blocker(
        &mut store,
        "SIG-issue",
        None,
        "The previous blocker was misclassified; verification is still required.",
    )
    .unwrap();
    assert!(snapshot.cases[0].evidence.len() > old_evidence_count);
    let (_, open) = pending(&snapshot, &store);
    assert_eq!(open, ["SIG-issue"]);
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    let check = &report
        .finding_checks
        .iter()
        .find(|check| check.case_id == "SIG-issue")
        .unwrap()
        .local_checks[0];
    assert_eq!(check.result, vulnbell::output::LocalResult::NotRun);
    assert!(check.detail.contains("misclassified"));
    let invalid = store
        .record_evidence(
            b"not a valid blocker",
            "local_validation_blocker",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut issue = store.case("SIG-issue").unwrap();
    issue.evidence.push(invalid);
    store.save_case(&issue).unwrap();
    snapshot.cases[0] = issue;
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(
        report.verification_pending[0].reason,
        vulnbell::output::PendingReason::InvalidVerificationEvidence
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
