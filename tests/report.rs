use serde_json::json;
use vulnbell::{model::*, store::Store};

#[test]
fn report_explains_the_matched_package_without_recommending_another_packages_fix() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    store.set_meta("project_name", "report-fixture").unwrap();
    let mut instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:npm/example".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    instance.purl = Some(instance.reference.clone());
    let osv = json!({"details":"SYNTHETIC: newline injection in an event identifier. <script>untrusted</script>","database_specific":{"severity":"HIGH"},"affected":[
        {"package":{"ecosystem":"npm","name":"different-package"},"ranges":[{"events":[{"fixed":"99.0.0"}]}]},
        {"package":{"ecosystem":"npm","name":"example","purl":"pkg:npm/example"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}
    ]});
    let ghsa = json!([
        {"ghsa_id":"GHSA-unrelated","description":"Different advisory","vulnerabilities":[{"package":{"ecosystem":"npm","name":"example"},"first_patched_version":"88.0.0"}]},
        {"ghsa_id":"GHSA-synthetic","html_url":"https://github.com/advisories/GHSA-synthetic","publisher":{"html_url":"https://github.com/not-a-finding-reference"},"references":["https://github.com/example/project/pull/42"],"description":"SYNTHETIC: attacker-controlled event identifiers can forge events.","severity":"high","vulnerabilities":[
            {"package":{"ecosystem":"npm","name":"another-package"},"first_patched_version":"77.0.0"},
            {"package":{"ecosystem":"npm","name":"example"},"first_patched_version":"1.2.3"}
        ]}
    ]);
    let mut claims = Vec::new();
    for (source, document) in [("osv", osv), ("ghsa", ghsa)] {
        let evidence = store
            .record_evidence(
                &serde_json::to_vec(&document).unwrap(),
                source,
                Some("https://example.org/synthetic-advisory".into()),
                EvidenceKind::Advisory,
            )
            .unwrap();
        claims.push(Claim {
            id: "GHSA-synthetic".into(),
            source: source.into(),
            aliases: Vec::new(),
            instance_id: instance.id.clone(),
            summary: "SYNTHETIC event injection".into(),
            applicability: Applicability::Affected,
            evidence,
            known_exploited: false,
        });
    }
    let mut case = Case {
        schema_version: 1,
        case_id: "SIG-synthetic-report".into(),
        project_id: project.clone(),
        snapshot_id: "synthetic".into(),
        instances: vec![instance.clone()],
        evidence: claims.iter().map(|claim| claim.evidence.clone()).collect(),
        claims,
        upstream_events: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Affected,
        verification: Verification::SourceConfirmed,
        decision: Decision::Actionable,
        facts_sha256: "synthetic".into(),
        open_questions: vec!["Confirmar entrada controlable y uso de SSE.".into()],
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "synthetic".into(),
        },
        updated_at: "2026-10-25T00:00:00Z".into(),
    };
    let project_evidence = store
        .record_evidence(
            b"Reviewed src/stream.rs:42: affected parser is called by the event endpoint.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    case.evidence.push(project_evidence.clone());
    store.save_case(&case).unwrap();
    vulnbell::impact::assess(
        &mut store,
        &case.case_id,
        vulnbell::impact::ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![vulnbell::impact::ImpactAnswer {
                instance_id: instance.id.clone(),
                question: vulnbell::impact::ImpactQuestionId::AffectedFeatureUsed,
                answer: vulnbell::impact::ImpactAnswerValue::Yes,
                rationale: "src/stream.rs:42 calls the affected parser.".into(),
                evidence: vec![EvidenceReference {
                    id: project_evidence.id,
                    sha256: project_evidence.sha256,
                }],
            }],
        },
    )
    .unwrap();
    case = store.case(&case.case_id).unwrap();
    let snapshot = Snapshot {
        schema_version: 1,
        id: "synthetic".into(),
        project_id: project.clone(),
        profile_sha256: "synthetic".into(),
        started_at: "2026-10-25T00:00:00Z".into(),
        finished_at: "2026-10-25T00:00:00Z".into(),
        instances: vec![instance],
        cases: vec![case],
        coverage: Vec::new(),
        partial: false,
        alert_status: "local report only".into(),
    };
    let report = vulnbell::output::morning_report(&snapshot, &store, "manager").unwrap();
    assert_eq!(report.project_name, "report-fixture");
    assert_eq!(report.actionable.len(), 1);
    let item = &report.actionable[0];
    assert!(item.detail_gaps.is_empty());
    assert_eq!(item.advisory_details.len(), 2);
    assert!(
        item.advisory_details
            .iter()
            .all(|detail| detail.fixed_versions == ["1.2.3"])
    );
    let markdown = vulnbell::output::morning_markdown(&report);
    assert!(markdown.contains("newline injection"));
    assert!(markdown.contains("attacker-controlled event identifiers"));
    assert!(markdown.contains("1.2.3"));
    assert!(
        !markdown.contains("99.0.0")
            && !markdown.contains("88.0.0")
            && !markdown.contains("77.0.0")
    );
    assert!(!markdown.contains("<script>"));
    assert!(markdown.contains("&lt;script&gt;"));
    assert!(markdown.contains("funcionalidad afectada en uso: sí"));
    assert!(markdown.contains("src/stream.rs:42 calls the affected parser"));
    assert_eq!(
        report.finding_checks[0]
            .impact
            .as_ref()
            .unwrap()
            .answers
            .len(),
        1
    );
    assert_eq!(
        report.finding_checks[0].local_checks[0].result,
        vulnbell::output::LocalResult::NotRun
    );
    assert_eq!(report.finding_checks[0].references.len(), 3);
    assert!(
        report.finding_checks[0]
            .references
            .iter()
            .any(|reference| reference.url.ends_with("/pull/42"))
    );
    assert!(
        !report.finding_checks[0]
            .references
            .iter()
            .any(|reference| reference.url.contains("not-a-finding-reference"))
    );
    let evidence = &snapshot.cases[0].claims[0].evidence;
    std::fs::write(
        store.directory.join("evidence").join(&evidence.sha256),
        b"corrupt",
    )
    .unwrap();
    let damaged = vulnbell::output::morning_report(&snapshot, &store, "manager").unwrap();
    assert_eq!(damaged.actionable[0].detail_gaps.len(), 1);
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn every_reference_is_kept_for_review_and_dismissed_cases_without_claiming_local_proof() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:npm/example".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let mut case = Case {
        schema_version: 1,
        case_id: "SIG-review".into(),
        project_id: project.clone(),
        snapshot_id: "snapshot".into(),
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: vec![
            UpstreamEvent {
                provider: "github".into(),
                kind: "issue".into(),
                id: "1".into(),
                url: "https://github.com/example/project/issues/1".into(),
                title: "SYNTHETIC hypothesis".into(),
                updated_at: None,
                sha256: "synthetic".into(),
            },
            UpstreamEvent {
                provider: "gitlab".into(),
                kind: "merge_request".into(),
                id: "2".into(),
                url: "https://gitlab.com/example/project/-/merge_requests/2".into(),
                title: "SYNTHETIC proposal".into(),
                updated_at: None,
                sha256: "synthetic".into(),
            },
        ],
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::SourceConfirmed,
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
    let mut snapshot = Snapshot {
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: vec![instance],
        cases: vec![case.clone()],
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    for decision in [
        Decision::Review,
        Decision::Dismissed,
        Decision::Informational,
    ] {
        case.decision = decision;
        snapshot.cases = vec![case.clone()];
        let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
        assert_eq!(report.finding_checks.len(), 1);
        assert_eq!(report.finding_checks[0].references.len(), 2);
        assert_eq!(
            report.finding_checks[0].local_checks[0].result,
            vulnbell::output::LocalResult::NotRun
        );
        let markdown = vulnbell::output::verification_markdown(&report);
        assert!(markdown.contains("https://github.com/example/project/issues/1"));
        assert!(markdown.contains("https://gitlab.com/example/project/-/merge_requests/2"));
        assert!(markdown.contains("no ejecutada"));
    }
    store.save_case(&case).unwrap();
    let blocked = vulnbell::sandbox::record_blocker(
        &mut store,
        &case.case_id,
        &case.instances[0].id,
        "Required proprietary binary is unavailable; no substitute was tested.",
    )
    .unwrap();
    snapshot.cases = vec![blocked.clone()];
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(
        report.finding_checks[0].local_checks[0].result,
        vulnbell::output::LocalResult::Blocked
    );
    assert!(
        report.finding_checks[0].local_checks[0]
            .detail
            .contains("proprietary binary")
    );
    assert_eq!(blocked.verification, Verification::SourceConfirmed);
    assert!(
        vulnbell::sandbox::record_blocker(
            &mut store,
            &case.case_id,
            "unknown-instance",
            "not valid"
        )
        .is_err()
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
