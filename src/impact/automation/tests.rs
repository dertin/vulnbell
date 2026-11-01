use super::{
    SourceAnswer, SourceReview, apply, reviewed_keys, run, source_plan, source_review_context,
    source_review_key,
};
use crate::{
    impact::{self, ImpactAnswer, ImpactAnswerValue, ImpactQuestionId, ImpactSubmission},
    model::{
        Applicability, Case, Decision, EvidenceKind, EvidenceReference, Instance,
        SandboxAvailability, Verification,
    },
    profile::Component,
    store::Store,
    tools::citations::Citation,
};
use std::fs;

fn human_fixture() -> (tempfile::TempDir, String, Store, Case, EvidenceReference) {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&Component {
        reference: "synthetic-component".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let evidence = store
        .record_evidence(
            b"synthetic human deployment evidence",
            "human",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let reference = EvidenceReference {
        id: evidence.id.clone(),
        sha256: evidence.sha256.clone(),
    };
    let case = Case {
        schema_version: 1,
        case_id: "synthetic-case".into(),
        project_id: project.clone(),
        snapshot_id: "synthetic-snapshot".into(),
        workspace_revisions: Vec::new(),
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: vec![evidence],
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "synthetic-facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "synthetic".into(),
        },
        updated_at: crate::now(),
    };
    store.save_case(&case).unwrap();
    let answers = [
        (ImpactQuestionId::ArtifactDeployed, ImpactAnswerValue::Yes),
        (
            ImpactQuestionId::AffectedFeatureUsed,
            ImpactAnswerValue::Yes,
        ),
        (
            ImpactQuestionId::FixOrMitigationApplied,
            ImpactAnswerValue::No,
        ),
    ]
    .into_iter()
    .map(|(question, answer)| ImpactAnswer {
        instance_id: instance.id.clone(),
        question,
        answer,
        rationale: "Confirmed by the operator.".into(),
        evidence: vec![reference.clone()],
    })
    .collect();
    let result = impact::assess(
        &mut store,
        &case.case_id,
        ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers,
        },
    )
    .unwrap();
    assert_eq!(result.verdict, impact::ImpactVerdict::NeedsEvidence);
    let case = store.case(&case.case_id).unwrap();
    (directory, project, store, case, reference)
}

mod evidence;

#[test]
fn a_monitor_without_a_codebase_does_not_start_a_source_agent() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\ndiscovery: off\ncomponents:\n  - ref: example\n    version: '1.0.0'\n")).unwrap();
    let profile = crate::profile::load(&path).unwrap();
    crate::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    run(
        &mut store,
        "missing-runner",
        &path,
        directory.path(),
        chrono::Utc::now(),
    )
    .unwrap();

    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn source_review_binds_evidence_and_rejects_wrong_lines_and_deployment_claims() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("code");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("source.rs"), "fn monitored_path() {}\n").unwrap();
    let git = |args: &[&str]| {
        let mut command = std::process::Command::new("git");
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        let status = command
            .current_dir(&root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    git(&["init", "-q", "--template="]);
    git(&["add", "--", "source.rs"]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=disabled-hooks",
        "commit",
        "-qm",
        "fixture",
    ]);
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\nworkspaces:\n  - {}\ndiscovery: off\n", root.display())).unwrap();
    let profile = crate::profile::load(&path).unwrap();
    let snapshot = crate::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&Component {
        reference: "pkg:cargo/example".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let case = Case {
        schema_version: 1,
        case_id: "SIG-source-fixture".into(),
        project_id: project.clone(),
        snapshot_id: snapshot.id,
        workspace_revisions: snapshot.workspace_revisions,
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "fixture".into(),
        },
        updated_at: crate::now(),
    };
    store.save_case(&case).unwrap();
    let answer = |question, hash: &str| SourceReview {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![SourceAnswer {
            instance_id: instance.id.clone(),
            question,
            answer: ImpactAnswerValue::Yes,
            rationale: "The selected code calls the feature.".into(),
            citations: vec![Citation {
                codebase: 0,
                path: "source.rs".into(),
                line: 1,
                line_sha256: Some(hash.into()),
            }],
        }],
    };
    let hash = crate::digest(b"fn monitored_path() {}");
    assert!(
        apply(
            &mut store,
            &case,
            answer(ImpactQuestionId::AffectedFeatureUsed, &"0".repeat(64)),
            directory.path()
        )
        .is_err()
    );
    assert!(
        apply(
            &mut store,
            &case,
            answer(ImpactQuestionId::ArtifactDeployed, &hash),
            directory.path()
        )
        .is_err()
    );
    assert!(impact::latest(&store.case(&case.case_id).unwrap(), &store).is_none());
    let mut changed_case = store.case(&case.case_id).unwrap();
    changed_case.facts_sha256 = "changed-facts".into();
    store.save_case(&changed_case).unwrap();
    assert!(
        apply(
            &mut store,
            &case,
            answer(ImpactQuestionId::AffectedFeatureUsed, &hash),
            directory.path()
        )
        .is_err()
    );
    store.save_case(&case).unwrap();
    fs::write(root.join("source.rs"), "fn changed() {}\n").unwrap();
    assert!(
        apply(
            &mut store,
            &case,
            answer(ImpactQuestionId::AffectedFeatureUsed, &hash),
            directory.path()
        )
        .is_err()
    );
    fs::write(root.join("source.rs"), "fn monitored_path() {}\n").unwrap();
    apply(
        &mut store,
        &case,
        answer(ImpactQuestionId::AffectedFeatureUsed, &hash),
        directory.path(),
    )
    .unwrap();
    let result = impact::latest(&store.case(&case.case_id).unwrap(), &store).unwrap();
    assert_eq!(result.answers[0].answer, ImpactAnswerValue::Yes);
    assert_eq!(result.answers[0].evidence.len(), 1);
    assert!(result.answers[0].rationale.contains("source.rs:1"));

    let deployment = store
        .record_evidence(
            b"deployed artifact fixture",
            "human",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut current = store.case(&case.case_id).unwrap();
    current.evidence.push(deployment.clone());
    store.save_case(&current).unwrap();
    let human_deployment = ImpactAnswer {
        instance_id: instance.id.clone(),
        question: ImpactQuestionId::ArtifactDeployed,
        answer: ImpactAnswerValue::Yes,
        rationale: "Confirmed by the operator.".into(),
        evidence: vec![EvidenceReference {
            id: deployment.id,
            sha256: deployment.sha256,
        }],
    };
    let human_unknown = ImpactAnswer {
        instance_id: instance.id.clone(),
        question: ImpactQuestionId::UntrustedInputReachesFeature,
        answer: ImpactAnswerValue::Unknown,
        rationale: "The human could not determine this.".into(),
        evidence: result.answers[0].evidence.clone(),
    };
    let stale_before_human_update = current.clone();
    impact::assess(
        &mut store,
        &case.case_id,
        ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![result.answers[0].clone(), human_deployment, human_unknown],
        },
    )
    .unwrap();
    let current = store.case(&case.case_id).unwrap();
    assert!(
        impact::assess_if_current(
            &mut store,
            &case.case_id,
            ImpactSubmission {
                schema_version: 1,
                case_id: case.case_id.clone(),
                facts_sha256: case.facts_sha256.clone(),
                answers: result.answers.clone(),
            },
            &stale_before_human_update,
            Vec::new(),
        )
        .is_err()
    );
    assert_eq!(
        impact::latest(&store.case(&case.case_id).unwrap(), &store)
            .unwrap()
            .answers
            .len(),
        3
    );
    let context = source_review_context(&current, &store).unwrap();
    let plan = source_plan(&current, &store, &context)
        .unwrap()
        .unwrap()
        .plan;
    let questions: Vec<_> = plan.targets[0]
        .questions
        .iter()
        .map(|question| question.id)
        .collect();
    assert!(!questions.contains(&ImpactQuestionId::ArtifactDeployed));
    assert!(!questions.contains(&ImpactQuestionId::AffectedFeatureUsed));
    assert!(questions.contains(&ImpactQuestionId::UntrustedInputReachesFeature));
    assert!(questions.contains(&ImpactQuestionId::RequiredConditionsPresent));
    let attempted = source_review_key(
        &context,
        &instance.id,
        ImpactQuestionId::UntrustedInputReachesFeature,
    )
    .unwrap();
    store.set_meta(&attempted, "complete").unwrap();
    let remaining = source_plan(&current, &store, &context)
        .unwrap()
        .unwrap()
        .plan;
    assert!(
        !remaining.targets[0]
            .questions
            .iter()
            .any(|question| question.id == ImpactQuestionId::UntrustedInputReachesFeature)
    );
    assert!(
        remaining.targets[0]
            .questions
            .iter()
            .any(|question| question.id == ImpactQuestionId::RequiredConditionsPresent)
    );
    store
        .connection
        .execute("DELETE FROM meta WHERE key=?1", [&attempted])
        .unwrap();
    let mut many = current.clone();
    for index in 0..30 {
        let mut additional = instance.clone();
        additional.id = format!("fixture-{index}");
        many.instances.push(additional);
    }
    let many_context = source_review_context(&many, &store).unwrap();
    let bounded = source_plan(&many, &store, &many_context).unwrap().unwrap();
    assert!(bounded.more);
    assert_eq!(
        bounded
            .plan
            .targets
            .iter()
            .map(|target| target.questions.len())
            .sum::<usize>(),
        100
    );

    let source_answer = |question, value| SourceAnswer {
        instance_id: instance.id.clone(),
        question,
        answer: value,
        rationale: "Source observation.".into(),
        citations: if value == ImpactAnswerValue::Unknown {
            Vec::new()
        } else {
            vec![Citation {
                codebase: 0,
                path: "source.rs".into(),
                line: 1,
                line_sha256: Some(hash.clone()),
            }]
        },
    };
    let partial = SourceReview {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![
            source_answer(
                ImpactQuestionId::UntrustedInputReachesFeature,
                ImpactAnswerValue::Unknown,
            ),
            source_answer(ImpactQuestionId::AffectedFeatureUsed, ImpactAnswerValue::No),
        ],
    };
    assert!(reviewed_keys(&context, &plan, &partial).is_err());
    let partial = SourceReview {
        answers: vec![source_answer(
            ImpactQuestionId::UntrustedInputReachesFeature,
            ImpactAnswerValue::Unknown,
        )],
        ..partial
    };
    assert_eq!(
        reviewed_keys(&context, &plan, &partial).unwrap(),
        vec![attempted]
    );
    apply(
        &mut store,
        &current,
        SourceReview {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![
                source_answer(ImpactQuestionId::AffectedFeatureUsed, ImpactAnswerValue::No),
                source_answer(
                    ImpactQuestionId::UntrustedInputReachesFeature,
                    ImpactAnswerValue::Unknown,
                ),
                source_answer(
                    ImpactQuestionId::RequiredConditionsPresent,
                    ImpactAnswerValue::Yes,
                ),
            ],
        },
        directory.path(),
    )
    .unwrap();
    let current = store.case(&case.case_id).unwrap();
    let merged = impact::latest(&current, &store).unwrap();
    let get = |question| {
        merged
            .answers
            .iter()
            .find(|answer| answer.question == question)
            .unwrap()
    };
    assert_eq!(
        get(ImpactQuestionId::AffectedFeatureUsed).answer,
        ImpactAnswerValue::Yes
    );
    assert_eq!(
        get(ImpactQuestionId::ArtifactDeployed).rationale,
        "Confirmed by the operator."
    );
    assert_eq!(
        get(ImpactQuestionId::UntrustedInputReachesFeature).rationale,
        "The human could not determine this."
    );
    assert_eq!(
        get(ImpactQuestionId::RequiredConditionsPresent).answer,
        ImpactAnswerValue::Yes
    );
    let previous_unknown = get(ImpactQuestionId::UntrustedInputReachesFeature);
    assert_eq!(previous_unknown.answer, ImpactAnswerValue::Unknown);
    assert_eq!(previous_unknown.evidence.len(), 2);
    let uncited_note = &previous_unknown.evidence[1];
    let note_text =
        fs::read_to_string(store.directory.join("evidence").join(&uncited_note.sha256)).unwrap();
    assert!(note_text.contains("Source observation."));

    let context = source_review_context(&current, &store).unwrap();
    let plan = source_plan(&current, &store, &context)
        .unwrap()
        .unwrap()
        .plan;
    let cited_review = SourceReview {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![SourceAnswer {
            instance_id: instance.id.clone(),
            question: ImpactQuestionId::UntrustedInputReachesFeature,
            answer: ImpactAnswerValue::Unknown,
            rationale: "A cited source observation.".into(),
            citations: vec![Citation {
                codebase: 0,
                path: "source.rs".into(),
                line: 1,
                line_sha256: Some(hash.clone()),
            }],
        }],
    };
    let keys = reviewed_keys(&context, &plan, &cited_review).unwrap();
    apply(&mut store, &current, cited_review, directory.path()).unwrap();
    for key in &keys {
        store.set_meta(key, "complete").unwrap();
    }
    let current = store.case(&case.case_id).unwrap();
    let updated_unknown = impact::latest(&current, &store).unwrap();
    let updated_unknown = updated_unknown
        .answers
        .iter()
        .find(|answer| answer.question == ImpactQuestionId::UntrustedInputReachesFeature)
        .unwrap();
    assert_eq!(updated_unknown.answer, ImpactAnswerValue::Unknown);
    assert_eq!(
        updated_unknown.rationale,
        "The human could not determine this."
    );
    assert_eq!(updated_unknown.evidence.len(), 3);
    let cited_note = fs::read_to_string(
        store
            .directory
            .join("evidence")
            .join(&updated_unknown.evidence[2].sha256),
    )
    .unwrap();
    assert!(cited_note.contains("A cited source observation."));
    assert!(cited_note.contains("source.rs:1"));
    assert!(store.meta(&keys[0]).unwrap().is_some());
    let remaining = source_plan(&current, &store, &context)
        .unwrap()
        .unwrap()
        .plan;
    assert!(
        !remaining.targets[0]
            .questions
            .iter()
            .any(|question| question.id == ImpactQuestionId::UntrustedInputReachesFeature)
    );

    apply(
        &mut store,
        &current,
        SourceReview {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![source_answer(
                ImpactQuestionId::UntrustedInputReachesFeature,
                ImpactAnswerValue::Yes,
            )],
        },
        directory.path(),
    )
    .unwrap();
    let current = store.case(&case.case_id).unwrap();
    let updated = impact::latest(&current, &store).unwrap();
    let promoted = updated
        .answers
        .iter()
        .find(|answer| answer.question == ImpactQuestionId::UntrustedInputReachesFeature)
        .unwrap();
    assert_eq!(promoted.answer, ImpactAnswerValue::Yes);
    assert_eq!(promoted.evidence.len(), 1);
    assert!(updated.answers.iter().any(|answer| answer.question
        == ImpactQuestionId::ArtifactDeployed
        && answer.rationale == "Confirmed by the operator."));

    let question = ImpactQuestionId::FixOrMitigationApplied;
    let context = source_review_context(&current, &store).unwrap();
    let key = source_review_key(&context, &instance.id, question).unwrap();
    let mut changed = current.clone();
    changed.workspace_revisions[0].observed_at = "2030-01-01T00:00:00Z".into();
    changed.snapshot_id = "different-snapshot".into();
    assert_eq!(
        source_review_key(
            &source_review_context(&changed, &store).unwrap(),
            &instance.id,
            question
        )
        .unwrap(),
        key
    );
    changed.facts_sha256 = "new-facts".into();
    assert_ne!(
        source_review_key(
            &source_review_context(&changed, &store).unwrap(),
            &instance.id,
            question
        )
        .unwrap(),
        key
    );
    changed = current.clone();
    changed.workspace_revisions[0].commit = Some("new-commit".into());
    assert_ne!(
        source_review_key(
            &source_review_context(&changed, &store).unwrap(),
            &instance.id,
            question
        )
        .unwrap(),
        key
    );
    changed.workspace_revisions[0].state = crate::workspace_revision::RepositoryState::NotGit;
    let volatile_key = source_review_key(
        &source_review_context(&changed, &store).unwrap(),
        &instance.id,
        question,
    )
    .unwrap();
    changed.snapshot_id = "new-snapshot".into();
    assert_ne!(
        source_review_key(
            &source_review_context(&changed, &store).unwrap(),
            &instance.id,
            question
        )
        .unwrap(),
        volatile_key
    );

    assert!(source_plan(&current, &store, &context).unwrap().is_some());
    let expired = run(
        &mut store,
        "missing-runner",
        &path,
        directory.path(),
        chrono::Utc::now(),
    )
    .unwrap_err();
    assert!(expired.to_string().contains("budget expired"));
    assert!(!directory.path().join("source-review-schema.json").exists());
    assert!(store.meta(&key).unwrap().is_none());
    store.set_meta(&key, "complete").unwrap();
    assert!(source_plan(&current, &store, &context).unwrap().is_none());
    run(
        &mut store,
        "missing-runner",
        &path,
        directory.path(),
        chrono::Utc::now() + chrono::Duration::seconds(5),
    )
    .unwrap();
    // This constructs evidence as data; no sandbox or monitored code is executed.
    let before_attestation = store.case(&case.case_id).unwrap();
    let before_impact = impact::latest(&before_attestation, &store).unwrap();
    let before_context = source_review_context(&before_attestation, &store).unwrap();
    let output = store
        .record_evidence(b"synthetic output", "test", None, EvidenceKind::Context)
        .unwrap();
    let policy = store
        .record_evidence(b"synthetic policy", "test", None, EvidenceKind::Context)
        .unwrap();
    let status = store
        .record_evidence(b"synthetic status", "test", None, EvidenceKind::Context)
        .unwrap();
    let attestation = serde_json::json!({
        "schema_version":2, "project_id":project, "case_id":case.case_id,
        "workspace_revisions":case.workspace_revisions, "facts_sha256":case.facts_sha256,
        "instance_id":instance.id, "artifact_version":"1.0.0", "runtime":"microsandbox",
        "runtime_version":"fixture", "runtime_sha256":hash, "test_sha256":hash,
        "image_reference":"fixture", "image_manifest_digest":hash, "staging_sha256":hash,
        "policy_sha256":policy.sha256, "input_sha256":[],
        "oracle":{"stdout_contains":"ok","expected_exit":0,"purpose":"reproduction"},
        "control":null, "network_devices":"none", "host_mounts":[], "memory_mib":128,
        "cpu_count":1, "timeout_seconds":1, "output_sha256":output.sha256,
        "execution_status_sha256":status.sha256, "exit_code":0, "execution_complete":true,
        "timed_out":false, "verification":"lab_reproduced", "observed_at":"fixture"
    });
    let evidence = store
        .record_evidence(
            &serde_json::to_vec(&attestation).unwrap(),
            "synthetic_attestation",
            None,
            EvidenceKind::Attestation,
        )
        .unwrap();
    let mut after_attestation = before_attestation.clone();
    after_attestation
        .evidence
        .extend([output, policy, status, evidence]);
    store.save_case(&after_attestation).unwrap();
    assert_eq!(
        impact::valid_attestations(&after_attestation, &store).len(),
        1
    );
    assert!(impact::latest(&after_attestation, &store).is_none());
    assert_ne!(
        before_context,
        source_review_context(&after_attestation, &store).unwrap()
    );
    assert!(
        impact::assess_if_current(
            &mut store,
            &case.case_id,
            ImpactSubmission {
                schema_version: 1,
                case_id: case.case_id.clone(),
                facts_sha256: case.facts_sha256.clone(),
                answers: before_impact.answers.clone(),
            },
            &before_attestation,
            Vec::new(),
        )
        .is_err()
    );
    let previous = impact::previous(&after_attestation, &store)
        .unwrap()
        .unwrap();
    assert!(previous.answers.iter().any(|answer| answer.question
        == ImpactQuestionId::ArtifactDeployed
        && answer.rationale == "Confirmed by the operator."));
    let context = source_review_context(&after_attestation, &store).unwrap();
    assert!(
        source_plan(&after_attestation, &store, &context)
            .unwrap()
            .is_some()
    );
    apply(
        &mut store,
        &after_attestation,
        SourceReview {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![source_answer(
                ImpactQuestionId::FixOrMitigationApplied,
                ImpactAnswerValue::Unknown,
            )],
        },
        directory.path(),
    )
    .unwrap();
    let reevaluated = impact::latest(&store.case(&case.case_id).unwrap(), &store).unwrap();
    assert!(reevaluated.answers.iter().any(|answer| answer.question
        == ImpactQuestionId::ArtifactDeployed
        && answer.rationale == "Confirmed by the operator."));

    let mut complete_answers = reevaluated.answers.clone();
    let supporting_evidence = complete_answers
        .iter()
        .find(|answer| answer.question == ImpactQuestionId::AffectedFeatureUsed)
        .unwrap()
        .evidence
        .clone();
    let mitigation = complete_answers
        .iter_mut()
        .find(|answer| answer.question == ImpactQuestionId::FixOrMitigationApplied)
        .unwrap();
    mitigation.answer = ImpactAnswerValue::Yes;
    mitigation.evidence = supporting_evidence;
    impact::assess(
        &mut store,
        &case.case_id,
        ImpactSubmission {
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: complete_answers,
        },
    )
    .unwrap();
    let mut second_attestation = attestation.clone();
    second_attestation["observed_at"] = serde_json::json!("second fixture");
    let evidence = store
        .record_evidence(
            &serde_json::to_vec(&second_attestation).unwrap(),
            "synthetic_attestation",
            None,
            EvidenceKind::Attestation,
        )
        .unwrap();
    let mut stale = store.case(&case.case_id).unwrap();
    stale.evidence.push(evidence);
    store.save_case(&stale).unwrap();
    assert!(impact::latest(&stale, &store).is_none());
    let context = source_review_context(&stale, &store).unwrap();
    assert!(source_plan(&stale, &store, &context).unwrap().is_none());
    run(
        &mut store,
        "missing-runner",
        &path,
        directory.path(),
        chrono::Utc::now() + chrono::Duration::seconds(5),
    )
    .unwrap();
    assert!(
        impact::latest(&store.case(&case.case_id).unwrap(), &store)
            .unwrap()
            .answers
            .iter()
            .any(
                |answer| answer.question == ImpactQuestionId::ArtifactDeployed
                    && answer.rationale == "Confirmed by the operator."
            )
    );
    let mut expanded = store.case(&case.case_id).unwrap();
    let mut second_instance = instance.clone();
    second_instance.id = "second-instance".into();
    expanded.instances.push(second_instance.clone());
    store.save_case(&expanded).unwrap();
    let citation = Citation {
        codebase: 0,
        path: "source.rs".into(),
        line: 1,
        line_sha256: Some(hash.clone()),
    };
    let batch = SourceReview {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![
            SourceAnswer {
                instance_id: second_instance.id.clone(),
                question: ImpactQuestionId::AffectedFeatureUsed,
                answer: ImpactAnswerValue::Yes,
                rationale: "First source observation.".into(),
                citations: vec![citation.clone(), citation.clone()],
            },
            SourceAnswer {
                instance_id: second_instance.id.clone(),
                question: ImpactQuestionId::UntrustedInputReachesFeature,
                answer: ImpactAnswerValue::Yes,
                rationale: "Second source observation.".into(),
                citations: vec![citation.clone()],
            },
        ],
    };
    apply(&mut store, &expanded, batch, directory.path()).unwrap();
    let saved = store.case(&case.case_id).unwrap();
    let result = impact::latest(&saved, &store).unwrap();
    let generated: Vec<_> = result
        .answers
        .iter()
        .filter(|answer| answer.instance_id == second_instance.id)
        .collect();
    assert_eq!(generated.len(), 2);
    assert!(generated.iter().all(|answer| answer.evidence.len() == 1));
    assert_ne!(
        generated[0].evidence[0].sha256,
        generated[1].evidence[0].sha256
    );
    assert!(generated.iter().all(|answer| {
        saved
            .evidence
            .iter()
            .any(|item| item.id == answer.evidence[0].id && store.evidence_exists(item).unwrap())
    }));
    assert!(result.answers.iter().any(|answer| answer.question
        == ImpactQuestionId::ArtifactDeployed
        && answer.rationale == "Confirmed by the operator."));

    let before = serde_json::to_vec(&saved).unwrap();
    let mismatched = SourceReview {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![SourceAnswer {
            instance_id: second_instance.id.clone(),
            question: ImpactQuestionId::RequiredConditionsPresent,
            answer: ImpactAnswerValue::Yes,
            rationale: "A changed line must fail the whole batch.".into(),
            citations: vec![
                citation.clone(),
                Citation {
                    line_sha256: Some("0".repeat(64)),
                    ..citation.clone()
                },
            ],
        }],
    };
    assert!(apply(&mut store, &saved, mismatched, directory.path()).is_err());
    assert_eq!(
        serde_json::to_vec(&store.case(&case.case_id).unwrap()).unwrap(),
        before
    );
    fs::create_dir_all(root.join("node_modules")).unwrap();
    fs::write(
        root.join("node_modules/excluded.rs"),
        "synthetic excluded line\n",
    )
    .unwrap();
    let invalid = SourceReview {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        answers: vec![SourceAnswer {
            instance_id: second_instance.id,
            question: ImpactQuestionId::RequiredConditionsPresent,
            answer: ImpactAnswerValue::Yes,
            rationale: "Must not use dependency code.".into(),
            citations: vec![
                citation,
                Citation {
                    codebase: 0,
                    path: "node_modules/excluded.rs".into(),
                    line: 1,
                    line_sha256: Some(crate::digest(b"synthetic excluded line")),
                },
            ],
        }],
    };
    assert!(apply(&mut store, &saved, invalid, directory.path()).is_err());
    assert_eq!(
        serde_json::to_vec(&store.case(&case.case_id).unwrap()).unwrap(),
        before
    );
    drop(store);
    fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}
