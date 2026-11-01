use vulnbell::{
    impact::{
        ImpactAnswer, ImpactAnswerValue, ImpactConfidence, ImpactQuestionId, ImpactSubmission,
        ImpactVerdict,
    },
    model::{
        Applicability, Case, Claim, Decision, EvidenceKind, EvidenceReference, Instance,
        SandboxAvailability, Verification,
    },
    profile::Component,
    store::Store,
};

fn fixture() -> (String, Store, Case, EvidenceReference) {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&Component {
        reference: "pkg:npm/example".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let evidence = store
        .record_evidence(
            b"synthetic reviewed project evidence",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let advisory = store
        .record_evidence(
            b"synthetic affected version evidence",
            "synthetic_advisory",
            Some("https://example.org/advisory".into()),
            EvidenceKind::Advisory,
        )
        .unwrap();
    let case = Case {
        workspace_revisions: Vec::new(),
        schema_version: 1,
        case_id: "SIG-impact".into(),
        project_id: project.clone(),
        snapshot_id: "snapshot".into(),
        instances: vec![instance.clone()],
        claims: vec![Claim {
            id: "ADV-impact".into(),
            source: "synthetic".into(),
            aliases: Vec::new(),
            instance_id: instance.id,
            summary: "Synthetic affected version".into(),
            applicability: Applicability::Affected,
            evidence: advisory.clone(),
            known_exploited: false,
        }],
        upstream_events: Vec::new(),
        evidence: vec![advisory, evidence.clone()],
        coverage: Vec::new(),
        applicability: Applicability::Affected,
        verification: Verification::SourceConfirmed,
        decision: Decision::Actionable,
        facts_sha256: "current-facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: true,
            reason: "synthetic".into(),
        },
        updated_at: vulnbell::now(),
    };
    store.save_case(&case).unwrap();
    let reference = EvidenceReference {
        id: evidence.id,
        sha256: evidence.sha256,
    };
    (project, store, case, reference)
}

fn answer(
    instance_id: &str,
    question: ImpactQuestionId,
    value: ImpactAnswerValue,
    evidence: &EvidenceReference,
) -> ImpactAnswer {
    ImpactAnswer {
        instance_id: instance_id.into(),
        question,
        answer: value,
        rationale: "Synthetic bounded observation.".into(),
        evidence: vec![evidence.clone()],
    }
}

fn exposed_answers(case: &Case, evidence: &EvidenceReference) -> ImpactSubmission {
    use ImpactAnswerValue::{No, Yes};
    use ImpactQuestionId::*;
    ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: [
            (ArtifactDeployed, Yes),
            (AffectedFeatureUsed, Yes),
            (UntrustedInputReachesFeature, Yes),
            (RequiredConditionsPresent, Yes),
            (FixOrMitigationApplied, No),
        ]
        .into_iter()
        .map(|(question, value)| answer(&case.instances[0].id, question, value, evidence))
        .collect(),
    }
}

#[test]
fn corrupt_attestation_or_runtime_blob_reopens_impact_and_report() {
    for damaged in ["attestation", "runtime"] {
        let (project, mut store, mut case, source) = fixture();
        case.claims.clear();
        case.decision = Decision::Review;
        case.verification = Verification::LabReproduced;
        let runtime = store
            .record_evidence(
                b"synthetic runtime evidence",
                "fixture",
                None,
                EvidenceKind::Context,
            )
            .unwrap();
        let attestation = serde_json::json!({
            "schema_version":2,"project_id":project,"case_id":case.case_id,
            "workspace_revisions":case.workspace_revisions,"facts_sha256":case.facts_sha256,
            "instance_id":case.instances[0].id,"artifact_version":"1.0.0","runtime":"microsandbox",
            "runtime_version":"synthetic","runtime_sha256":"synthetic","test_sha256":"synthetic",
            "image_reference":"synthetic","image_manifest_digest":"synthetic","staging_sha256":"synthetic",
            "policy_sha256":runtime.sha256,"input_sha256":[],
            "oracle":{"stdout_contains":"synthetic","expected_exit":0,"purpose":"reproduction"},
            "control":null,"network_devices":"synthetic","host_mounts":[],"memory_mib":128,
            "cpu_count":1,"timeout_seconds":1,"output_sha256":runtime.sha256,
            "execution_status_sha256":runtime.sha256,"exit_code":0,"execution_complete":true,
            "timed_out":false,"verification":"lab_reproduced","observed_at":vulnbell::now()
        });
        let attestation = store
            .record_evidence(
                &serde_json::to_vec(&attestation).unwrap(),
                "microsandbox_runtime",
                None,
                EvidenceKind::Attestation,
            )
            .unwrap();
        case.evidence.extend([runtime.clone(), attestation.clone()]);
        store.save_case(&case).unwrap();
        assert!(vulnbell::impact::plan(&case, &store).affected_version_confirmed);
        let submission = exposed_answers(&case, &source);
        let impact =
            vulnbell::impact::assess(&mut store, &case.case_id, submission.clone()).unwrap();
        assert_eq!(impact.verdict, ImpactVerdict::UrgentUpdate);
        let case = store.case(&case.case_id).unwrap();
        assert!(vulnbell::impact::latest(&case, &store).is_some());
        let target = if damaged == "attestation" {
            &attestation
        } else {
            &runtime
        };
        std::fs::write(
            store.directory.join("evidence").join(&target.sha256),
            b"corrupt synthetic evidence",
        )
        .unwrap();
        assert!(!vulnbell::impact::plan(&case, &store).affected_version_confirmed);
        assert!(vulnbell::impact::latest(&case, &store).is_none());
        let impact = vulnbell::impact::assess(&mut store, &case.case_id, submission).unwrap();
        assert_eq!(impact.verdict, ImpactVerdict::NeedsEvidence);
        let case = store.case(&case.case_id).unwrap();
        assert_eq!(
            vulnbell::impact::latest(&case, &store).unwrap().verdict,
            ImpactVerdict::NeedsEvidence
        );
        let snapshot = vulnbell::model::Snapshot {
            schema_version: 1,
            id: case.snapshot_id.clone(),
            project_id: project.clone(),
            profile_sha256: "synthetic".into(),
            started_at: vulnbell::now(),
            finished_at: vulnbell::now(),
            workspace_revisions: Vec::new(),
            instances: case.instances.clone(),
            coverage: Vec::new(),
            cases: vec![case],
            partial: false,
            alert_status: "none".into(),
        };
        let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
        let check = &report.finding_checks[0].local_checks[0];
        assert!(check.sandbox_candidate);
        assert_eq!(
            serde_json::to_value(&check.result).unwrap(),
            "invalid_evidence"
        );
        drop(store);
        std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
    }
}

#[test]
fn corrupt_advisory_claim_invalidates_previous_affected_impact() {
    let (project, mut store, case, evidence) = fixture();
    let submission = exposed_answers(&case, &evidence);
    assert_eq!(
        vulnbell::impact::assess(&mut store, &case.case_id, submission.clone())
            .unwrap()
            .verdict,
        ImpactVerdict::UrgentUpdate
    );
    let case = store.case(&case.case_id).unwrap();
    assert!(vulnbell::impact::plan(&case, &store).affected_version_confirmed);
    assert!(vulnbell::impact::latest(&case, &store).is_some());
    std::fs::write(
        store
            .directory
            .join("evidence")
            .join(&case.claims[0].evidence.sha256),
        b"corrupted advisory",
    )
    .unwrap();
    assert!(!vulnbell::impact::plan(&case, &store).affected_version_confirmed);
    assert!(vulnbell::impact::latest(&case, &store).is_none());
    assert_eq!(
        vulnbell::impact::assess(&mut store, &case.case_id, submission)
            .unwrap()
            .verdict,
        ImpactVerdict::NeedsEvidence
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn impact_plan_is_fixed_for_every_instance() {
    let (project, store, mut case, _) = fixture();
    case.instances.push(Instance::declared(&Component {
        reference: "pkg:npm/unrelated".into(),
        version: Some("2.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    }));
    let plan = vulnbell::impact::plan(&case, &store);
    assert!(plan.affected_version_confirmed);
    assert_eq!(plan.targets.len(), 2);
    assert!(plan.targets[0].affected_version_confirmed);
    assert!(!plan.targets[1].affected_version_confirmed);
    assert_eq!(plan.targets[0].questions.len(), 5);
    assert_eq!(
        plan.targets[0].questions[0].id,
        ImpactQuestionId::ArtifactDeployed
    );
    assert!(
        plan.targets[0].questions[0]
            .evidence_needed
            .contains("lockfile")
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn large_multibatch_impact_remains_readable_and_oversize_keeps_prior_state() {
    let (project, mut store, mut case, _) = fixture();
    let prototype = case.instances[0].clone();
    for index in 1..100 {
        let mut instance = prototype.clone();
        instance.id = format!("batch-instance-{index}");
        case.instances.push(instance);
    }
    store.save_case(&case).unwrap();
    let questions = [
        ImpactQuestionId::AffectedFeatureUsed,
        ImpactQuestionId::UntrustedInputReachesFeature,
        ImpactQuestionId::RequiredConditionsPresent,
        ImpactQuestionId::FixOrMitigationApplied,
    ];
    let mut answers = Vec::new();
    for batch in case.instances.chunks(25) {
        for instance in batch {
            for question in questions {
                answers.push(ImpactAnswer {
                    instance_id: instance.id.clone(),
                    question,
                    answer: ImpactAnswerValue::Unknown,
                    rationale: "a".repeat(3000),
                    evidence: Vec::new(),
                });
            }
        }
        vulnbell::impact::assess(
            &mut store,
            &case.case_id,
            ImpactSubmission {
                schema_version: 1,
                case_id: case.case_id.clone(),
                facts_sha256: case.facts_sha256.clone(),
                answers: answers.clone(),
            },
        )
        .unwrap();
        let saved = store.case(&case.case_id).unwrap();
        assert_eq!(
            vulnbell::impact::latest(&saved, &store)
                .unwrap()
                .answers
                .len(),
            answers.len()
        );
    }
    let saved = store.case(&case.case_id).unwrap();
    let latest = vulnbell::impact::latest(&saved, &store).unwrap();
    assert!(serde_json::to_vec(&latest).unwrap().len() > 1024 * 1024);
    assert_eq!(latest.answers.len(), 400);

    let mut expanded = saved;
    for index in 100..2200 {
        let mut instance = prototype.clone();
        instance.id = format!("batch-instance-{index}");
        expanded.instances.push(instance);
    }
    store.save_case(&expanded).unwrap();
    let before = serde_json::to_vec(&store.case(&case.case_id).unwrap()).unwrap();
    let rationale = "b".repeat(3900);
    let mut oversized = Vec::new();
    for instance in &expanded.instances {
        for question in questions {
            oversized.push(ImpactAnswer {
                instance_id: instance.id.clone(),
                question,
                answer: ImpactAnswerValue::Unknown,
                rationale: rationale.clone(),
                evidence: Vec::new(),
            });
        }
    }
    let error = vulnbell::impact::assess(
        &mut store,
        &case.case_id,
        ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: oversized,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("32 MiB"));
    let after = store.case(&case.case_id).unwrap();
    assert_eq!(serde_json::to_vec(&after).unwrap(), before);
    assert!(vulnbell::impact::latest(&after, &store).is_none());
    let prior = after
        .evidence
        .iter()
        .rev()
        .find(|item| item.source == "impact_assessment")
        .unwrap();
    assert!(store.evidence_exists(prior).unwrap());
    let saved: vulnbell::impact::ImpactResult = serde_json::from_slice(
        &std::fs::read(store.directory.join("evidence").join(&prior.sha256)).unwrap(),
    )
    .unwrap();
    assert_eq!(saved.answers.len(), 400);
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn impact_assessment_is_stale_when_codebase_revision_changes() {
    let (project, mut store, case, evidence) = fixture();
    vulnbell::impact::assess(
        &mut store,
        &case.case_id,
        ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![answer(
                &case.instances[0].id,
                ImpactQuestionId::AffectedFeatureUsed,
                ImpactAnswerValue::Yes,
                &evidence,
            )],
        },
    )
    .unwrap();
    let mut recorded = store.case(&case.case_id).unwrap();
    assert!(vulnbell::impact::latest(&recorded, &store).is_some());
    let other = tempfile::tempdir().unwrap();
    recorded
        .workspace_revisions
        .push(vulnbell::workspace_revision::capture_path(other.path()));
    assert!(vulnbell::impact::latest(&recorded, &store).is_none());
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn artifact_identity_and_lab_evidence_do_not_prove_deployment() {
    let (project, mut store, mut case, context) = fixture();
    let mut references = Vec::new();
    for kind in [
        EvidenceKind::Identity,
        EvidenceKind::Attestation,
        EvidenceKind::NonApplicability,
    ] {
        let evidence = store
            .record_evidence(format!("synthetic {kind:?}").as_bytes(), "test", None, kind)
            .unwrap();
        references.push(EvidenceReference {
            id: evidence.id.clone(),
            sha256: evidence.sha256.clone(),
        });
        case.evidence.push(evidence);
    }
    store.save_case(&case).unwrap();
    for reference in &references {
        let submission = ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![answer(
                &case.instances[0].id,
                ImpactQuestionId::ArtifactDeployed,
                ImpactAnswerValue::Yes,
                reference,
            )],
        };
        assert!(vulnbell::impact::assess(&mut store, &case.case_id, submission).is_err());
    }
    let submission = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![answer(
            &case.instances[0].id,
            ImpactQuestionId::ArtifactDeployed,
            ImpactAnswerValue::Yes,
            &context,
        )],
    };
    let mut result = vulnbell::impact::assess(&mut store, &case.case_id, submission).unwrap();
    result.answers[0].evidence = vec![references[0].clone()];
    let invalid = store
        .record_evidence(
            &serde_json::to_vec(&result).unwrap(),
            "impact_assessment",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut saved = store.case(&case.case_id).unwrap();
    saved.evidence.push(invalid);
    store.save_case(&saved).unwrap();
    assert!(vulnbell::impact::latest(&saved, &store).is_none());
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn complete_reachable_exposure_requires_an_urgent_update() {
    let (project, mut store, case, evidence) = fixture();
    let instance_id = &case.instances[0].id;
    let submission = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![
            answer(
                instance_id,
                ImpactQuestionId::ArtifactDeployed,
                ImpactAnswerValue::Yes,
                &evidence,
            ),
            answer(
                instance_id,
                ImpactQuestionId::AffectedFeatureUsed,
                ImpactAnswerValue::Yes,
                &evidence,
            ),
            answer(
                instance_id,
                ImpactQuestionId::UntrustedInputReachesFeature,
                ImpactAnswerValue::Yes,
                &evidence,
            ),
            answer(
                instance_id,
                ImpactQuestionId::RequiredConditionsPresent,
                ImpactAnswerValue::Yes,
                &evidence,
            ),
            answer(
                instance_id,
                ImpactQuestionId::FixOrMitigationApplied,
                ImpactAnswerValue::No,
                &evidence,
            ),
        ],
    };
    let result = vulnbell::impact::assess(&mut store, &case.case_id, submission).unwrap();
    assert_eq!(result.verdict, ImpactVerdict::UrgentUpdate);
    assert_eq!(result.confidence, ImpactConfidence::Medium);
    assert_eq!(result.answers.len(), 5);
    let mut incomplete = serde_json::to_value(&result).unwrap();
    incomplete.as_object_mut().unwrap().remove("answers");
    assert!(serde_json::from_value::<vulnbell::impact::ImpactResult>(incomplete).is_err());
    let stored = vulnbell::impact::latest(&store.case(&case.case_id).unwrap(), &store).unwrap();
    assert_eq!(stored.answers.len(), 5);
    assert_eq!(
        stored.answers[1].question,
        ImpactQuestionId::AffectedFeatureUsed
    );
    assert_eq!(
        stored.answers[1].rationale,
        "Synthetic bounded observation."
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn negative_project_condition_does_not_silently_dismiss_the_case() {
    let (project, mut store, case, evidence) = fixture();
    let submission = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![answer(
            &case.instances[0].id,
            ImpactQuestionId::AffectedFeatureUsed,
            ImpactAnswerValue::No,
            &evidence,
        )],
    };
    let result = vulnbell::impact::assess(&mut store, &case.case_id, submission).unwrap();
    assert_eq!(result.verdict, ImpactVerdict::NotAffected);
    assert_eq!(result.confidence, ImpactConfidence::Medium);
    assert_eq!(
        store.case(&case.case_id).unwrap().decision,
        Decision::Actionable
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn unconfirmed_cases_settle_containment_but_not_exposure() {
    let (project, mut store, mut case, evidence) = fixture();
    case.claims.clear();
    case.applicability = Applicability::Unknown;
    case.verification = Verification::Inconclusive;
    case.decision = Decision::Review;
    store.save_case(&case).unwrap();
    let instance_id = case.instances[0].id.clone();
    let mut assess = |answers: Vec<(ImpactQuestionId, ImpactAnswerValue)>| {
        let submission = ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: answers
                .into_iter()
                .map(|(question, value)| answer(&instance_id, question, value, &evidence))
                .collect(),
        };
        vulnbell::impact::assess(&mut store, &case.case_id, submission)
            .unwrap()
            .verdict
    };
    assert_eq!(
        assess(vec![(
            ImpactQuestionId::AffectedFeatureUsed,
            ImpactAnswerValue::No
        )]),
        ImpactVerdict::NotAffected
    );
    assert_eq!(
        assess(vec![(
            ImpactQuestionId::FixOrMitigationApplied,
            ImpactAnswerValue::Yes
        )]),
        ImpactVerdict::Mitigated
    );
    assert_eq!(
        assess(vec![
            (ImpactQuestionId::ArtifactDeployed, ImpactAnswerValue::Yes),
            (
                ImpactQuestionId::AffectedFeatureUsed,
                ImpactAnswerValue::Yes
            ),
            (
                ImpactQuestionId::UntrustedInputReachesFeature,
                ImpactAnswerValue::Yes
            ),
            (
                ImpactQuestionId::RequiredConditionsPresent,
                ImpactAnswerValue::Yes
            ),
            (
                ImpactQuestionId::FixOrMitigationApplied,
                ImpactAnswerValue::No
            ),
        ]),
        ImpactVerdict::NeedsEvidence
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn conclusive_answers_reject_missing_or_stale_evidence() {
    let (project, mut store, case, evidence) = fixture();
    let no_evidence = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![ImpactAnswer {
            instance_id: case.instances[0].id.clone(),
            question: ImpactQuestionId::ArtifactDeployed,
            answer: ImpactAnswerValue::Yes,
            rationale: "Synthetic claim without proof.".into(),
            evidence: Vec::new(),
        }],
    };
    assert!(vulnbell::impact::assess(&mut store, &case.case_id, no_evidence).is_err());

    let stale = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: "old-facts".into(),
        answers: Vec::new(),
    };
    assert!(vulnbell::impact::assess(&mut store, &case.case_id, stale).is_err());

    let invalid_not_applicable = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![answer(
            &case.instances[0].id,
            ImpactQuestionId::ArtifactDeployed,
            ImpactAnswerValue::NotApplicable,
            &evidence,
        )],
    };
    assert!(vulnbell::impact::assess(&mut store, &case.case_id, invalid_not_applicable).is_err());

    let advisory = EvidenceReference {
        id: case.evidence[0].id.clone(),
        sha256: case.evidence[0].sha256.clone(),
    };
    let wrong_evidence_type = ImpactSubmission {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![answer(
            &case.instances[0].id,
            ImpactQuestionId::AffectedFeatureUsed,
            ImpactAnswerValue::Yes,
            &advisory,
        )],
    };
    assert!(vulnbell::impact::assess(&mut store, &case.case_id, wrong_evidence_type).is_err());
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
