use serde_json::json;
use std::{fs, path::Path};
use vulnbell::{
    impact::{ImpactAnswer, ImpactAnswerValue, ImpactQuestionId, ImpactSubmission},
    model::{
        Applicability, Case, Claim, Coverage, CoverageState, Decision, EvidenceKind,
        EvidenceReference, Instance, SandboxAvailability, Snapshot, Verdict, Verification,
    },
    profile::Component,
    store::Store,
};

#[test]
fn sample_report_matches_current_cli() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let profile = directory.path().join("vulnbell.yaml");
    fs::write(
        &profile,
        format!("schema: 1\nproject_id: {project}\nname: Synthetic example - fictional data\ndiscovery: off\ncomponents:\n  - ref: pkg:npm/example-package\n    version: '1.0.0'\n"),
    )
    .unwrap();
    let mut store = Store::open(&project).unwrap();
    store
        .register_project("Synthetic example - fictional data", &profile)
        .unwrap();
    let mut instance = Instance::declared(&Component {
        reference: "pkg:npm/example-package".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    instance.purl = Some(instance.reference.clone());
    let advisory = json!({
        "details": "Synthetic advisory: untrusted input can reach an unsafe parser.",
        "affected": [{"package": {"ecosystem": "npm", "name": "example-package"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]
    });
    let advisory_evidence = store
        .record_evidence(
            &serde_json::to_vec(&advisory).unwrap(),
            "osv",
            Some("https://example.org/synthetic-advisory".into()),
            EvidenceKind::Advisory,
        )
        .unwrap();
    let code_evidence = store
        .record_evidence(
            b"Synthetic evidence: src/parser.js:42 calls the affected parser.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let case_id = "SIG-synthetic-example";
    let case = Case {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        case_id: case_id.into(),
        project_id: project.clone(),
        snapshot_id: "synthetic-snapshot".into(),
        instances: vec![instance.clone()],
        claims: vec![Claim {
            id: "SYNTHETIC-001".into(),
            source: "osv".into(),
            aliases: Vec::new(),
            instance_id: instance.id.clone(),
            summary: "Synthetic parser issue (fictional example)".into(),
            applicability: Applicability::Affected,
            evidence: advisory_evidence.clone(),
            known_exploited: false,
        }],
        upstream_events: Vec::new(),
        evidence: vec![advisory_evidence.clone(), code_evidence.clone()],
        coverage: Vec::new(),
        applicability: Applicability::Affected,
        verification: Verification::SourceConfirmed,
        decision: Decision::Actionable,
        facts_sha256: "synthetic-facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "Not tested in this fictional example".into(),
        },
        updated_at: "2026-11-01T12:00:00Z".into(),
    };
    let snapshot = Snapshot {
        schema_version: 1,
        id: "synthetic-snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "synthetic-profile".into(),
        started_at: "2026-11-01T12:00:00Z".into(),
        finished_at: "2026-11-01T12:00:00Z".into(),
        codebase_revisions: Vec::new(),
        instances: vec![instance.clone()],
        cases: vec![case.clone()],
        coverage: vec![Coverage::new(
            "Synthetic source",
            "example-package",
            CoverageState::Partial,
            "Fictional example; no actual source was queried",
        )],
        partial: true,
        alert_status: "local report only".into(),
    };
    store.save_snapshot(&snapshot).unwrap();
    let project_reference = EvidenceReference {
        id: code_evidence.id.clone(),
        sha256: code_evidence.sha256.clone(),
    };
    vulnbell::impact::assess(
        &mut store,
        case_id,
        ImpactSubmission {
            schema_version: 1,
            question_set_sha256: vulnbell::impact::question_set_sha256(),
            case_id: case_id.into(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![ImpactAnswer {
                instance_id: instance.id.clone(),
                question: ImpactQuestionId::AffectedFeatureUsed,
                answer: ImpactAnswerValue::Yes,
                rationale: "Synthetic example: src/parser.js:42 calls the affected parser.".into(),
                evidence: vec![project_reference.clone()],
            }],
        },
    )
    .unwrap();
    vulnbell::engine::triage(
        &mut store,
        case_id,
        Verdict {
            schema_version: 1,
            case_id: case_id.into(),
            codebase_revisions: Vec::new(),
            facts_sha256: case.facts_sha256.clone(),
            applicability: Applicability::Affected,
            verification: Verification::SourceConfirmed,
            decision: Decision::Actionable,
            rationale: "Synthetic example: assess the affected parser and update the dependency."
                .into(),
            advisory_translation: None,
            evidence: vec![project_reference],
        },
    )
    .unwrap();
    let mut recorded_case = store.case(case_id).unwrap();
    for evidence in &mut recorded_case.evidence {
        evidence.observed_at = "2026-11-01T12:00:00Z".into();
    }
    for claim in &mut recorded_case.claims {
        claim.evidence.observed_at = "2026-11-01T12:00:00Z".into();
    }
    store.save_case(&recorded_case).unwrap();
    store
        .set_meta("last_agent_review", "2026-11-01T12:00:00Z")
        .unwrap();
    drop(store);
    let mut command = assert_cmd::cargo::cargo_bin_cmd!("vulnbell");
    command
        .args(["report", "--project"])
        .arg(&profile)
        .args(["--audience", "cyber"]);
    if let Some(pdf) = std::env::var_os("VULNBELL_EXAMPLE_PDF") {
        command.arg("--pdf").arg(pdf);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let markdown = String::from_utf8(output.stdout).unwrap();
    let example = Path::new("examples/report.md");
    if std::env::var_os("VULNBELL_UPDATE_EXAMPLE").is_some() {
        fs::write(example, &markdown).unwrap();
    }
    let expected = fs::read_to_string(example).unwrap().replace("\r\n", "\n");
    assert_eq!(markdown, expected);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
