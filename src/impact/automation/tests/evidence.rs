use super::*;

#[test]
fn changed_attestation_recalculates_impact_without_losing_human_answers() {
    let (directory, project, mut store, mut case, _) = human_fixture();
    let linked = store
        .record_evidence(
            b"synthetic runtime evidence",
            "fixture",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let attestation = serde_json::json!({
        "schema_version":2,"project_id":project,"case_id":case.case_id,
        "codebase_revisions":case.codebase_revisions,"facts_sha256":case.facts_sha256,
        "instance_id":case.instances[0].id,"artifact_version":"1.0.0","runtime":"microsandbox",
        "runtime_version":"synthetic","runtime_sha256":"synthetic","test_sha256":"synthetic",
        "image_reference":"synthetic","image_manifest_digest":"synthetic","staging_sha256":"synthetic",
        "policy_sha256":linked.sha256,"input_sha256":[],
        "oracle":{"stdout_contains":"synthetic","expected_exit":0,"purpose":"reproduction"},
        "control":null,"network_devices":"synthetic","host_mounts":[],"memory_mib":128,
        "cpu_count":1,"timeout_seconds":1,"output_sha256":linked.sha256,"execution_status_sha256":linked.sha256,
        "exit_code":0,"execution_complete":true,"timed_out":false,"verification":"lab_reproduced","observed_at":"synthetic"
    });
    let attestation = store
        .record_evidence(
            &serde_json::to_vec(&attestation).unwrap(),
            "microsandbox_runtime",
            None,
            EvidenceKind::Attestation,
        )
        .unwrap();
    case.evidence.extend([linked, attestation]);
    store.save_case(&case).unwrap();
    assert!(impact::latest(&case, &store).is_none());
    assert_eq!(
        impact::previous(&case, &store).unwrap().unwrap().verdict,
        impact::ImpactVerdict::NeedsEvidence
    );
    let context = source_review_context(&case, &store).unwrap();
    let plan = source_plan(&case, &store, &context).unwrap().unwrap().plan;
    assert!(
        !plan.targets[0]
            .questions
            .iter()
            .any(|question| question.id == ImpactQuestionId::ArtifactDeployed)
    );
    apply(
        &mut store,
        &case,
        SourceReview {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![SourceAnswer {
                instance_id: case.instances[0].id.clone(),
                question: ImpactQuestionId::RequiredConditionsPresent,
                answer: ImpactAnswerValue::Unknown,
                rationale: "Synthetic source review.".into(),
                citations: Vec::new(),
            }],
        },
        directory.path(),
    )
    .unwrap();
    let updated = impact::latest(&store.case(&case.case_id).unwrap(), &store).unwrap();
    assert_eq!(updated.verdict, impact::ImpactVerdict::PriorityUpdate);
    assert!(updated.answers.iter().any(|answer| answer.question
        == ImpactQuestionId::ArtifactDeployed
        && answer.answer == ImpactAnswerValue::Yes
        && answer.rationale == "Confirmed by the operator."));
    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn source_notes_and_assessment_commit_with_concurrent_case_evidence() {
    let (_directory, project, mut store, expected, _) = human_fixture();
    let mut concurrent = store.case(&expected.case_id).unwrap();
    let independently_added = store
        .record_evidence(
            b"concurrent human note",
            "human",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    concurrent.evidence.push(independently_added.clone());
    store.save_case(&concurrent).unwrap();
    let source_note = store
        .record_evidence(
            b"reviewed source note",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut answers = impact::latest(&expected, &store).unwrap().answers;
    answers.push(ImpactAnswer {
        instance_id: expected.instances[0].id.clone(),
        question: ImpactQuestionId::UntrustedInputReachesFeature,
        answer: ImpactAnswerValue::Yes,
        rationale: "Verified source path.".into(),
        evidence: vec![EvidenceReference {
            id: source_note.id.clone(),
            sha256: source_note.sha256.clone(),
        }],
    });
    let submission = || ImpactSubmission {
        schema_version: 1,
        case_id: expected.case_id.clone(),
        facts_sha256: expected.facts_sha256.clone(),
        answers: answers.clone(),
    };
    impact::assess_if_current(
        &mut store,
        &expected.case_id,
        submission(),
        &expected,
        vec![source_note.clone()],
    )
    .unwrap();
    let committed = store.case(&expected.case_id).unwrap();
    assert!(
        committed
            .evidence
            .iter()
            .any(|item| item.sha256 == independently_added.sha256)
    );
    assert!(
        committed
            .evidence
            .iter()
            .any(|item| item.sha256 == source_note.sha256)
    );
    assert!(
        impact::latest(&committed, &store)
            .unwrap()
            .answers
            .iter()
            .any(|answer| answer.question == ImpactQuestionId::UntrustedInputReachesFeature)
    );

    let stale_note = store
        .record_evidence(
            b"stale source note",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    assert!(
        impact::assess_if_current(
            &mut store,
            &expected.case_id,
            submission(),
            &expected,
            vec![stale_note.clone()]
        )
        .is_err()
    );
    let after = store.case(&expected.case_id).unwrap();
    assert!(
        !after
            .evidence
            .iter()
            .any(|item| item.sha256 == stale_note.sha256)
    );
    assert_eq!(
        serde_json::to_vec(&after).unwrap(),
        serde_json::to_vec(&committed).unwrap()
    );
    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn corrupt_previous_impact_or_answer_evidence_cannot_be_overwritten_by_source_review() {
    for damaged in ["impact", "answer"] {
        let (directory, project, mut store, case, reference) = human_fixture();
        let mut stale = case.clone();
        stale.facts_sha256 = "other-context".into();
        assert!(impact::previous(&stale, &store).unwrap().is_none());
        let target = if damaged == "impact" {
            case.evidence
                .iter()
                .rev()
                .find(|item| item.source == "impact_assessment")
                .unwrap()
                .sha256
                .clone()
        } else {
            reference.sha256
        };
        fs::write(
            store.directory.join("evidence").join(target),
            b"corrupted synthetic evidence",
        )
        .unwrap();
        assert!(impact::previous(&case, &store).is_err());
        let context = source_review_context(&case, &store).unwrap();
        assert!(source_plan(&case, &store, &context).is_err());
        let before = serde_json::to_vec(&store.case(&case.case_id).unwrap()).unwrap();
        let error = apply(
            &mut store,
            &case,
            SourceReview {
                schema_version: 1,
                case_id: case.case_id.clone(),
                facts_sha256: case.facts_sha256.clone(),
                answers: vec![SourceAnswer {
                    instance_id: case.instances[0].id.clone(),
                    question: ImpactQuestionId::RequiredConditionsPresent,
                    answer: ImpactAnswerValue::Unknown,
                    rationale: "Synthetic source review.".into(),
                    citations: Vec::new(),
                }],
            },
            directory.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("integrity failed"));
        assert_eq!(
            serde_json::to_vec(&store.case(&case.case_id).unwrap()).unwrap(),
            before
        );
        drop(store);
        fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }
}
