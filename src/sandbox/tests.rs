use super::*;
use crate::model::{
    Applicability, Decision, EvidenceReference, Instance, SandboxAvailability, Snapshot, Verdict,
};

#[test]
fn new_attestation_requires_a_new_verdict_without_running_a_guest() {
    for decision in [
        Decision::Informational,
        Decision::Dismissed,
        Decision::Review,
    ] {
        for verification in [
            Verification::LabReproduced,
            Verification::NotReproduced,
            Verification::Inconclusive,
            Verification::Disproven,
        ] {
            let project = uuid::Uuid::new_v4().to_string();
            let instance = Instance::declared(&crate::profile::Component {
                reference: "synthetic-component".into(),
                version: Some("1.0.0".into()),
                usage: Default::default(),
                upstream: None,
                feeds: Vec::new(),
            });
            let mut case = Case {
                schema_version: 1,
                case_id: "synthetic-case".into(),
                project_id: project.clone(),
                snapshot_id: "synthetic-snapshot".into(),
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
                updated_at: crate::now(),
            };
            let mut snapshot = Snapshot {
                schema_version: 1,
                id: case.snapshot_id.clone(),
                project_id: project.clone(),
                profile_sha256: "synthetic".into(),
                started_at: crate::now(),
                finished_at: crate::now(),
                codebase_revisions: Vec::new(),
                instances: vec![instance.clone()],
                coverage: Vec::new(),
                cases: vec![case.clone()],
                partial: false,
                alert_status: "none".into(),
            };
            let mut store = Store::open(&project).unwrap();
            store.save_snapshot(&snapshot).unwrap();
            let source = store
                .record_evidence(
                    b"synthetic non-applicability",
                    "fixture",
                    None,
                    EvidenceKind::NonApplicability,
                )
                .unwrap();
            case.evidence.push(source.clone());
            store.save_case(&case).unwrap();
            case = crate::engine::triage(
                &mut store,
                &case.case_id,
                Verdict {
                    advisory_translation: None,
                    schema_version: 1,
                    case_id: case.case_id.clone(),
                    codebase_revisions: Vec::new(),
                    facts_sha256: case.facts_sha256.clone(),
                    applicability: Applicability::NotAffected,
                    verification: Verification::Inconclusive,
                    decision,
                    rationale: "Synthetic prior assessment.".into(),
                    evidence: vec![EvidenceReference {
                        id: source.id,
                        sha256: source.sha256,
                    }],
                },
            )
            .unwrap();
            assert!(crate::engine::current_verdict(&case, &store).is_some());
            if decision != Decision::Review {
                assert!(crate::tools::cases::pending(&store).unwrap().deliverable);
            }

            let linked = store
                .record_evidence(
                    b"synthetic runtime evidence",
                    "fixture",
                    None,
                    EvidenceKind::Context,
                )
                .unwrap();
            let attestation = Attestation {
                schema_version: 2,
                project_id: project.clone(),
                case_id: case.case_id.clone(),
                codebase_revisions: Vec::new(),
                facts_sha256: case.facts_sha256.clone(),
                instance_id: instance.id,
                artifact_version: "1.0.0".into(),
                runtime: "microsandbox".into(),
                runtime_version: "synthetic".into(),
                runtime_sha256: "synthetic".into(),
                test_sha256: "synthetic".into(),
                image_reference: "synthetic".into(),
                image_manifest_digest: "synthetic".into(),
                staging_sha256: "synthetic".into(),
                policy_sha256: linked.sha256.clone(),
                input_sha256: Vec::new(),
                oracle: Oracle {
                    stdout_contains: "synthetic".into(),
                    expected_exit: 0,
                    purpose: if verification == Verification::Disproven {
                        OraclePurpose::PositiveNonApplicability
                    } else {
                        OraclePurpose::Reproduction
                    },
                },
                control: (verification == Verification::Disproven).then(|| ControlObservation {
                    artifact_version: "other".into(),
                    input_sha256: Vec::new(),
                    output_sha256: linked.sha256.clone(),
                    oracle_matched: true,
                    policy_verified: true,
                }),
                network_devices: "synthetic".into(),
                host_mounts: Vec::new(),
                memory_mib: 128,
                cpu_count: 1,
                timeout_seconds: 1,
                output_sha256: linked.sha256.clone(),
                execution_status_sha256: linked.sha256.clone(),
                exit_code: Some(0),
                execution_complete: true,
                timed_out: false,
                verification,
                observed_at: crate::now(),
            };
            let mut invalid = attestation.clone();
            invalid.facts_sha256 = "stale".into();
            let invalid_evidence = store
                .record_evidence(
                    &serde_json::to_vec(&invalid).unwrap(),
                    "microsandbox_runtime",
                    None,
                    EvidenceKind::Attestation,
                )
                .unwrap();
            case.evidence.push(linked.clone());
            case.evidence.push(invalid_evidence);
            assert!(crate::engine::current_verdict(&case, &store).is_some());
            let evidence = store
                .record_evidence(
                    &serde_json::to_vec(&attestation).unwrap(),
                    "microsandbox_runtime",
                    None,
                    EvidenceKind::Attestation,
                )
                .unwrap();
            case.evidence.push(evidence.clone());
            assert!(read_attestation(&case, &store, &evidence).is_ok());
            apply_attestation(&mut case, &attestation);
            store.save_case(&case).unwrap();
            assert_eq!(case.decision, Decision::Review);
            assert_eq!(
                case.applicability,
                if decision == Decision::Review {
                    Applicability::NotAffected
                } else {
                    Applicability::Unknown
                }
            );
            assert_eq!(case.verification, verification);
            assert!(crate::engine::current_verdict(&case, &store).is_none());
            let pending = crate::tools::cases::pending(&store).unwrap();
            assert!(!pending.deliverable);
            assert_eq!(pending.verdict_missing, [case.case_id.clone()]);
            snapshot.cases = store.cases().unwrap();
            let report = crate::output::morning_report(&snapshot, &store, "cyber").unwrap();
            assert!(
                report
                    .needs_review
                    .iter()
                    .any(|item| item.case_id == case.case_id)
            );
            case = crate::engine::triage(
                &mut store,
                &case.case_id,
                Verdict {
                    advisory_translation: None,
                    schema_version: 1,
                    case_id: case.case_id.clone(),
                    codebase_revisions: Vec::new(),
                    facts_sha256: case.facts_sha256.clone(),
                    applicability: case.applicability,
                    verification,
                    decision: Decision::Review,
                    rationale: "Synthetic reassessment.".into(),
                    evidence: vec![EvidenceReference {
                        id: evidence.id,
                        sha256: evidence.sha256,
                    }],
                },
            )
            .unwrap();
            assert!(crate::engine::current_verdict(&case, &store).is_some());
            drop(store);
            std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
        }
    }
}
