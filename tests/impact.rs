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
    let plan = vulnbell::impact::plan(&case);
    assert!(plan.affected_version_confirmed);
    assert_eq!(plan.targets.len(), 2);
    assert!(plan.targets[0].affected_version_confirmed);
    assert!(!plan.targets[1].affected_version_confirmed);
    assert_eq!(plan.targets[0].questions.len(), 5);
    assert_eq!(
        plan.targets[0].questions[0].id,
        ImpactQuestionId::ArtifactDeployed
    );
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
