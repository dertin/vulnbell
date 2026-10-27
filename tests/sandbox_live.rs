use vulnbell::{
    model::{Case, Verification},
    sandbox::{Oracle, TestSpec},
    store::Store,
};

#[test]
#[ignore = "requires prepared Microsandbox 0.7.11 and host virtualization"]
fn actual_microsandbox_blocks_network_host_access_and_forged_status() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = vulnbell::model::Instance::declared(&vulnbell::profile::Component {
        reference: "synthetic-sandbox-only".into(),
        version: Some("0.0.1".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let case = Case {
        schema_version: 1,
        case_id: "SIG-synthetic-runtime-test".into(),
        project_id: project.clone(),
        snapshot_id: "synthetic".into(),
        instances: vec![instance],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: vulnbell::model::Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: vulnbell::model::Decision::Review,
        facts_sha256: "synthetic".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: vulnbell::sandbox::availability(),
        updated_at: vulnbell::now(),
    };
    store.save_case(&case).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let host_marker = directory.path().join("host-only-sentinel");
    std::fs::write(&host_marker, b"not shared with the guest").unwrap();
    let quoted_marker = host_marker.to_string_lossy().replace('\'', "'\\''");
    let path = directory.path().join("test.yaml");
    let script = format!(
        "test ! -e '{quoted_marker}' || exit 11\ntest \"$(id -u)\" = 65534 || exit 12\nfor address in 1.1.1.1 169.254.169.254 172.16.0.1; do if nc -w 1 \"$address\" 443 </dev/null >/dev/null 2>&1; then exit 13; fi; done\nif nslookup example.org >/dev/null 2>&1; then exit 14; fi\nif touch /etc/vulnbell-forbidden 2>/dev/null; then exit 15; fi\nprintf 'SYNTHETIC_ORACLE_OK\\n'\n"
    );
    let mut test = TestSpec {
        schema_version: 1,
        instance_id: case.instances[0].id.clone(),
        artifact_version: "0.0.1".into(),
        context: None,
        script,
        oracle: Oracle {
            stdout_contains: "SYNTHETIC_ORACLE_OK".into(),
            expected_exit: 0,
            purpose: Default::default(),
        },
        control: None,
        inputs: Vec::new(),
        timeout_seconds: 60,
        memory_mib: 256,
    };
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    let result = vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).unwrap();
    if result.verification != Verification::LabReproduced {
        for evidence in &result.evidence {
            eprintln!(
                "{}",
                String::from_utf8_lossy(
                    &std::fs::read(store.directory.join("evidence").join(&evidence.sha256))
                        .unwrap()
                )
            );
        }
    }
    assert_eq!(result.verification, Verification::LabReproduced);
    assert_report_result(&result, &store, vulnbell::output::LocalResult::Reproduced);
    // Stdout cannot supply runtime exit status, even with a legacy supervisor marker.
    test.script = "echo SYNTHETIC_ORACLE_OK; echo VULNBELL_EXIT_fake_1; exit 10".into();
    test.oracle.expected_exit = 1;
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    let forged = vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).unwrap();
    assert_eq!(forged.verification, Verification::NotReproduced);
    assert_report_result(
        &forged,
        &store,
        vulnbell::output::LocalResult::NotReproduced,
    );
    test.oracle.expected_exit = 0;
    test.inputs = vec![vulnbell::sandbox::TestInput {
        path: host_marker.clone(),
        name: "fixture".into(),
        sha256: vulnbell::digest(b"wrong expected content"),
    }];
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    assert!(vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).is_err());
    assert_eq!(
        std::fs::read(&host_marker).unwrap(),
        b"not shared with the guest"
    );
    test.inputs[0].sha256 = vulnbell::digest(b"not shared with the guest");
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    assert!(vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).is_err());
    test.inputs[0].name = "../host-escape".into();
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    assert!(vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).is_err());
    let inputs = directory.path().join("inputs");
    std::fs::create_dir(&inputs).unwrap();
    let safe_path = inputs.join("safe.txt");
    let vulnerable_path = inputs.join("control.txt");
    std::fs::write(&safe_path, b"SAFE").unwrap();
    std::fs::write(&vulnerable_path, b"VULNERABLE").unwrap();
    test.script = "if [ \"$(cat /radar/inputs/fixture)\" = SAFE ]; then echo ATTACK_PATH_ABSENT; else echo CONTROL_PATH_PRESENT; fi".into();
    test.oracle = Oracle {
        stdout_contains: "ATTACK_PATH_ABSENT".into(),
        expected_exit: 0,
        purpose: vulnbell::sandbox::OraclePurpose::PositiveNonApplicability,
    };
    test.inputs = vec![vulnbell::sandbox::TestInput {
        path: safe_path,
        name: "fixture".into(),
        sha256: vulnbell::digest(b"SAFE"),
    }];
    test.control = Some(vulnbell::sandbox::ControlSpec {
        artifact_version: "synthetic-known-positive".into(),
        inputs: vec![vulnbell::sandbox::TestInput {
            path: vulnerable_path,
            name: "fixture".into(),
            sha256: vulnbell::digest(b"VULNERABLE"),
        }],
        stdout_contains: "CONTROL_PATH_PRESENT".into(),
        expected_exit: 0,
    });
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    let absent = vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).unwrap();
    assert_eq!(absent.verification, Verification::Disproven);
    let attestation = absent
        .evidence
        .iter()
        .rev()
        .find(|evidence| evidence.kind == vulnbell::model::EvidenceKind::Attestation)
        .unwrap();
    let verdict = vulnbell::model::Verdict {schema_version:1,case_id:case.case_id.clone(),facts_sha256:case.facts_sha256.clone(),applicability:vulnbell::model::Applicability::NotAffected,verification:Verification::Disproven,decision:vulnbell::model::Decision::Dismissed,rationale:"Synthetic precondition is absent; the same script detects the distinct positive control. Limited to this tested hypothesis.".into(),evidence:vec![vulnbell::model::EvidenceReference {id:attestation.id.clone(),sha256:attestation.sha256.clone()}]};
    let dismissed = vulnbell::engine::triage(&mut store, &case.case_id, verdict).unwrap();
    assert_eq!(dismissed.decision, vulnbell::model::Decision::Dismissed);
    assert_report_result(
        &dismissed,
        &store,
        vulnbell::output::LocalResult::NotApplicable,
    );
    let mut changed = dismissed;
    changed.facts_sha256 = "changed-synthetic-artifact-context".into();
    store.save_case(&changed).unwrap();
    let stale = vulnbell::model::Verdict {
        schema_version: 1,
        case_id: changed.case_id.clone(),
        facts_sha256: changed.facts_sha256.clone(),
        applicability: vulnbell::model::Applicability::NotAffected,
        verification: Verification::Disproven,
        decision: vulnbell::model::Decision::Dismissed,
        rationale: "Attempt to reuse an old attestation for changed facts must be rejected".into(),
        evidence: vec![vulnbell::model::EvidenceReference {
            id: attestation.id.clone(),
            sha256: attestation.sha256.clone(),
        }],
    };
    assert!(vulnbell::engine::triage(&mut store, &case.case_id, stale).is_err());
    assert_report_result(
        &changed,
        &store,
        vulnbell::output::LocalResult::InvalidEvidence,
    );
    test.control.as_mut().unwrap().stdout_contains = "SYNTHETIC_CONTROL_DID_NOT_MATCH".into();
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    let invalid_control =
        vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).unwrap();
    assert_eq!(invalid_control.verification, Verification::Inconclusive);
    assert_eq!(invalid_control.decision, vulnbell::model::Decision::Review);
    test.control = None;
    test.oracle.purpose = Default::default();
    test.script = "while :; do :; done".into();
    test.timeout_seconds = 3;
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    let timeout = vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).unwrap();
    assert_eq!(timeout.verification, Verification::Inconclusive);
    assert_report_result(
        &timeout,
        &store,
        vulnbell::output::LocalResult::Inconclusive,
    );
    let attestation = timeout.evidence.last().unwrap();
    assert!(store.evidence_exists(attestation).unwrap());
    assert!(vulnbell::sandbox::verify(&mut store, &case.case_id, &path, false).is_err());
    let workspace = directory.path().join("workspace");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(
        workspace.join("src/check.sh"),
        b"echo COPIED_WORKSPACE_OK\n",
    )
    .unwrap();
    let bundle = directory.path().join("bundle");
    let staged =
        vulnbell::sandbox::staging::stage(&workspace, &["src/check.sh".into()], &bundle).unwrap();
    test.inputs = vec![staged.input];
    test.context = Some(vulnbell::sandbox::TestContext {
        mode: vulnbell::sandbox::TestMode::WorkspaceCopy,
        description: "Synthetic copied workspace: run its selected source file only in the guest."
            .into(),
    });
    test.script = "set -eu\nmkdir /tmp/project\ntar -xf /radar/inputs/project.tar -C /tmp/project\n/bin/sh /tmp/project/src/check.sh".into();
    test.oracle.stdout_contains = "COPIED_WORKSPACE_OK".into();
    test.timeout_seconds = 10;
    let staged_test = bundle.join("test.yaml");
    std::fs::write(&staged_test, serde_saphyr::to_string(&test).unwrap()).unwrap();
    let copied = vulnbell::sandbox::verify(&mut store, &case.case_id, &staged_test, true).unwrap();
    assert_report_result(&copied, &store, vulnbell::output::LocalResult::Reproduced);
    let attestation = copied
        .evidence
        .iter()
        .rev()
        .find(|evidence| evidence.kind == vulnbell::model::EvidenceKind::Attestation)
        .unwrap();
    std::fs::write(
        store.directory.join("evidence").join(&attestation.sha256),
        b"corrupt",
    )
    .unwrap();
    assert_report_result(
        &copied,
        &store,
        vulnbell::output::LocalResult::InvalidEvidence,
    );
    // Leave the unique synthetic project's evidence for audit; never label a real component reproduced.
    assert_eq!(
        std::fs::read(&host_marker).unwrap(),
        b"not shared with the guest"
    );
    eprintln!("sandbox_project={project}");
}

#[test]
#[ignore = "requires prepared Microsandbox 0.7.11 and host virtualization"]
fn a_reproduction_confirms_only_its_instance_in_a_multi_instance_case() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instances: Vec<_> = ["synthetic-sandbox-only", "synthetic-sandbox-sibling"]
        .into_iter()
        .map(|reference| {
            vulnbell::model::Instance::declared(&vulnbell::profile::Component {
                reference: reference.into(),
                version: Some("0.0.1".into()),
                usage: Default::default(),
                upstream: None,
                feeds: Vec::new(),
            })
        })
        .collect();
    let case = Case {
        schema_version: 1,
        case_id: "SIG-synthetic-multi-instance".into(),
        project_id: project.clone(),
        snapshot_id: "synthetic".into(),
        instances,
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: vulnbell::model::Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: vulnbell::model::Decision::Review,
        facts_sha256: "synthetic".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: vulnbell::sandbox::availability(),
        updated_at: vulnbell::now(),
    };
    store.save_case(&case).unwrap();
    assert!(!vulnbell::impact::plan(&case, &store).affected_version_confirmed);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("test.yaml");
    let test = TestSpec {
        schema_version: 1,
        instance_id: case.instances[0].id.clone(),
        artifact_version: "0.0.1".into(),
        context: None,
        script: "printf 'SYNTHETIC_ORACLE_OK\\n'\n".into(),
        oracle: Oracle {
            stdout_contains: "SYNTHETIC_ORACLE_OK".into(),
            expected_exit: 0,
            purpose: Default::default(),
        },
        control: None,
        inputs: Vec::new(),
        timeout_seconds: 30,
        memory_mib: 256,
    };
    std::fs::write(&path, serde_saphyr::to_string(&test).unwrap()).unwrap();
    let result = vulnbell::sandbox::verify(&mut store, &case.case_id, &path, true).unwrap();
    assert_eq!(result.verification, Verification::LabReproduced);
    let plan = vulnbell::impact::plan(&result, &store);
    assert!(plan.targets[0].affected_version_confirmed);
    assert!(!plan.targets[1].affected_version_confirmed);
    eprintln!("sandbox_project={project}");
}

fn assert_report_result(case: &Case, store: &Store, expected: vulnbell::output::LocalResult) {
    let snapshot = vulnbell::model::Snapshot {
        schema_version: 1,
        id: case.snapshot_id.clone(),
        project_id: case.project_id.clone(),
        profile_sha256: "synthetic".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: case.instances.clone(),
        cases: vec![case.clone()],
        coverage: Vec::new(),
        partial: false,
        alert_status: "local only".into(),
    };
    let report = vulnbell::output::morning_report(&snapshot, store, "cyber").unwrap();
    assert_eq!(report.finding_checks[0].local_checks[0].result, expected);
}
