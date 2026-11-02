use super::*;

#[test]
fn affected_verdict_requires_intact_claim_even_when_its_cited_note_is_intact() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:cargo/synthetic".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let snapshot = Snapshot {
        schema_version: 1,
        id: "synthetic-snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "synthetic".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        codebase_revisions: Vec::new(),
        instances: vec![instance.clone()],
        coverage: Vec::new(),
        cases: Vec::new(),
        partial: false,
        alert_status: "none".into(),
    };
    store.save_snapshot(&snapshot).unwrap();
    let claim_bytes = b"synthetic affected advisory";
    let affected = store
        .record_evidence(claim_bytes, "osv", None, EvidenceKind::Advisory)
        .unwrap();
    let note = store
        .record_evidence(
            b"independent source review note",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let claim = Claim {
        id: "SYNTHETIC-ADVISORY".into(),
        source: "osv".into(),
        aliases: Vec::new(),
        instance_id: instance.id.clone(),
        summary: "Synthetic affected advisory".into(),
        applicability: Applicability::Affected,
        evidence: affected.clone(),
        known_exploited: false,
    };
    let case = Case {
        schema_version: 1,
        case_id: "SIG-corrupt-advisory".into(),
        project_id: project.clone(),
        snapshot_id: snapshot.id,
        codebase_revisions: Vec::new(),
        instances: vec![instance],
        claims: vec![claim.clone()],
        upstream_events: Vec::new(),
        evidence: vec![affected.clone(), note.clone()],
        coverage: Vec::new(),
        applicability: Applicability::Affected,
        verification: Verification::SourceConfirmed,
        decision: Decision::Actionable,
        facts_sha256: "synthetic-facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "synthetic".into(),
        },
        updated_at: vulnbell::now(),
    };
    store.save_case(&case).unwrap();
    let verdict = |verification| Verdict {
        advisory_translation: None,
        schema_version: 1,
        case_id: case.case_id.clone(),
        codebase_revisions: Vec::new(),
        facts_sha256: case.facts_sha256.clone(),
        applicability: Applicability::Affected,
        verification,
        decision: Decision::Actionable,
        rationale: "Independent reviewed note.".into(),
        evidence: vec![EvidenceReference {
            id: note.id.clone(),
            sha256: note.sha256.clone(),
        }],
    };
    let advisory_path = store.directory.join("evidence").join(&affected.sha256);
    std::fs::write(&advisory_path, b"corrupted advisory").unwrap();
    for verification in [Verification::SourceConfirmed, Verification::Inconclusive] {
        assert!(
            vulnbell::engine::triage(&mut store, &case.case_id, verdict(verification)).is_err()
        );
    }
    assert_eq!(
        store.case(&case.case_id).unwrap().evidence.len(),
        case.evidence.len()
    );

    std::fs::write(&advisory_path, claim_bytes).unwrap();
    let recorded = vulnbell::engine::triage(
        &mut store,
        &case.case_id,
        verdict(Verification::SourceConfirmed),
    )
    .unwrap();
    assert!(vulnbell::engine::current_verdict(&recorded, &store).is_some());
    assert!(
        !vulnbell::tools::cases::pending(&store)
            .unwrap()
            .verdict_missing
            .contains(&case.case_id)
    );
    std::fs::write(&advisory_path, b"corrupted advisory").unwrap();
    assert!(store.evidence_exists(&note).unwrap());
    assert!(vulnbell::engine::current_verdict(&recorded, &store).is_none());
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .verdict_missing
            .contains(&case.case_id)
    );

    let alternate = store
        .record_evidence(
            b"second affected advisory",
            "osv",
            None,
            EvidenceKind::Advisory,
        )
        .unwrap();
    let mut independently_supported = recorded;
    independently_supported.claims.push(Claim {
        evidence: alternate,
        ..claim
    });
    assert!(vulnbell::engine::current_verdict(&independently_supported, &store).is_some());
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn closed_cases_with_invalid_recorded_verdicts_return_to_review() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&vulnbell::profile::Component {
        reference: "synthetic-component".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let mut snapshot = Snapshot {
        schema_version: 1,
        id: "synthetic-snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "synthetic".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        codebase_revisions: Vec::new(),
        instances: vec![instance.clone()],
        coverage: Vec::new(),
        cases: Vec::new(),
        partial: false,
        alert_status: "none".into(),
    };
    store.save_snapshot(&snapshot).unwrap();
    let case = |id: String, decision| Case {
        schema_version: 1,
        case_id: id,
        project_id: project.clone(),
        snapshot_id: snapshot.id.clone(),
        codebase_revisions: Vec::new(),
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::NotAffected,
        verification: Verification::Inconclusive,
        decision,
        facts_sha256: "synthetic-facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "synthetic".into(),
        },
        updated_at: vulnbell::now(),
    };
    let mut corrupt = Vec::new();
    for (name, decision) in [
        ("informational", Decision::Informational),
        ("dismissed", Decision::Dismissed),
    ] {
        store
            .save_case(&case(format!("auto-{name}"), decision))
            .unwrap();
        for mode in ["missing", "corrupt"] {
            let id = format!("manual-{name}-{mode}");
            let evidence = store
                .record_evidence(
                    id.as_bytes(),
                    "synthetic",
                    None,
                    EvidenceKind::NonApplicability,
                )
                .unwrap();
            let mut item = case(id.clone(), decision);
            item.evidence.push(evidence.clone());
            store.save_case(&item).unwrap();
            vulnbell::engine::triage(
                &mut store,
                &id,
                Verdict {
                    advisory_translation: None,
                    schema_version: 1,
                    case_id: id.clone(),
                    codebase_revisions: Vec::new(),
                    facts_sha256: item.facts_sha256,
                    applicability: Applicability::NotAffected,
                    verification: Verification::Inconclusive,
                    decision,
                    rationale: "Synthetic assessment.".into(),
                    evidence: vec![EvidenceReference {
                        id: evidence.id,
                        sha256: evidence.sha256.clone(),
                    }],
                },
            )
            .unwrap();
            corrupt.push((
                id,
                store.directory.join("evidence").join(evidence.sha256),
                mode,
            ));
        }
    }
    assert!(vulnbell::tools::cases::pending(&store).unwrap().deliverable);
    for (_, path, mode) in &corrupt {
        if *mode == "missing" {
            std::fs::remove_file(path).unwrap();
        } else {
            std::fs::write(path, b"corrupted synthetic evidence").unwrap();
        }
    }
    let pending = vulnbell::tools::cases::pending(&store).unwrap();
    assert!(!pending.deliverable);
    assert_eq!(pending.verdict_missing.len(), corrupt.len());
    for (id, _, _) in &corrupt {
        assert!(pending.verdict_missing.contains(id));
    }
    snapshot.cases = store.cases().unwrap();
    let mut report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(report.informational_count, 1);
    assert_eq!(report.dismissed_count, 1);
    assert_eq!(report.needs_review.len(), corrupt.len());
    for (id, _, _) in &corrupt {
        assert!(report.needs_review.iter().any(|item| &item.case_id == id));
    }
    let summary = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(summary.contains("| `auto-informational` |"));
    assert!(summary.contains("Not impact-assessed: contextual case, no action required."));
    let summary_pdf =
        vulnbell::output::prepared_pdf_markdown(&summary, &snapshot.cases, &store, &report)
            .unwrap();
    assert!(!summary_pdf.contains("## auto-informational"));
    assert!(summary_pdf.contains("## manual-informational-missing"));
    report.closed = vulnbell::output::ClosedMode::None;
    let none = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(!none.contains("| `auto-informational` |"));
    report.closed = vulnbell::output::ClosedMode::Full;
    let full = vulnbell::output::morning_markdown(&report).unwrap();
    let full_pdf =
        vulnbell::output::prepared_pdf_markdown(&full, &snapshot.cases, &store, &report).unwrap();
    assert!(full_pdf.contains("## auto-informational"));
    let audit = vulnbell::output::audit_markdown(&snapshot, &store).unwrap();
    assert!(audit.contains("auto-informational"));
    let audit_none = vulnbell::output::audit_markdown_with_closed(
        &snapshot,
        &store,
        vulnbell::output::ClosedMode::None,
    )
    .unwrap();
    assert!(!audit_none.contains("auto-informational"));
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("vulnbell.yaml");
    std::fs::write(
        &profile,
        format!("schema: 1\nproject_id: {project}\nname: fixture\nreport:\n  language: es\n"),
    )
    .unwrap();
    store.register_project("fixture", &profile).unwrap();
    let spanish = vulnbell::output::audit_markdown_with_closed(
        &snapshot,
        &store,
        vulnbell::output::ClosedMode::Summary,
    )
    .unwrap();
    assert!(spanish.contains("Proyecto:"));
    assert!(spanish.contains("## Casos informativos"));
    assert!(spanish.contains("## Cobertura"));
    let spanish_report = prepared_report(&snapshot, &store, "cyber").unwrap();
    let spanish = vulnbell::output::morning_markdown(&spanish_report).unwrap();
    assert!(spanish.contains("Sin evaluación de impacto: caso de contexto, no requiere acción."));
    assert!(!spanish.contains("`vulnbell impact`"));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

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
            codebase_revisions: Vec::new(),
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
                question_set_sha256: vulnbell::impact::question_set_sha256(),
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
        codebase_revisions: Vec::new(),
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
    let mut report = prepared_report(&snapshot, &store, "cyber").unwrap();
    report.finding_checks.reverse();
    assert_eq!(report.actionable.len(), 2);
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
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
    assert!(markdown.contains("**Affected feature in use:** yes - SIG-exposed feature rationale."));
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
            codebase_revisions: Vec::new(),
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
                question_set_sha256: vulnbell::impact::question_set_sha256(),
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
        let expected = if case_id == "SIG-issue" {
            vulnbell::impact::ImpactVerdict::NeedsEvidence
        } else {
            vulnbell::impact::ImpactVerdict::PriorityUpdate
        };
        assert_eq!(result.verdict, expected);
        cases.push(store.case(case_id).unwrap());
    }
    let mut snapshot = Snapshot {
        codebase_revisions: Vec::new(),
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
        let report = prepared_report(snapshot, store, "cyber").unwrap();
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
                "codebase_revisions": [],
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
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
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
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
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
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(
        report.verification_pending[0].reason,
        vulnbell::output::PendingReason::InvalidVerificationEvidence
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
