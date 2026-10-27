use std::fs;
use vulnbell::{
    model::*,
    sandbox::{Oracle, TestSpec},
    store::Store,
};

#[test]
fn unavailable_guest_returns_inconclusive_without_executing_the_test_on_the_host() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let store = Store::open(&project).unwrap();
    let component = vulnbell::profile::Component {
        reference: "synthetic-no-host-fallback".into(),
        version: Some("0.0.1".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    };
    let instance = Instance::declared(&component);
    let case = Case {
        schema_version: 1,
        case_id: "SIG-synthetic-unavailable".into(),
        project_id: project.clone(),
        snapshot_id: "synthetic".into(),
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "synthetic".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "synthetic".into(),
        },
        updated_at: vulnbell::now(),
    };
    let mut store = store;
    store.save_case(&case).unwrap();
    let isolated = directory.path().join("isolated-state");
    let project_data = isolated.join(&project);
    fs::create_dir_all(&project_data).unwrap();
    store
        .connection
        .execute(
            "VACUUM INTO ?1",
            [project_data.join("state.sqlite").to_str().unwrap()],
        )
        .unwrap();
    let profile_path = directory.path().join("vulnbell.yaml");
    fs::write(&profile_path,format!("schema: 1\nproject_id: {project}\nname: no-host-fallback\ncomponents:\n - ref: synthetic-no-host-fallback\n   version: '0.0.1'\n")).unwrap();
    let marker = directory.path().join("must-never-exist");
    let quoted = marker.to_string_lossy().replace('\'', "'\\''");
    let spec = TestSpec {
        schema_version: 1,
        instance_id: instance.id,
        artifact_version: "0.0.1".into(),
        context: None,
        script: format!("touch '{quoted}'\necho HOST_EXECUTION_MUST_NOT_HAPPEN"),
        oracle: Oracle {
            stdout_contains: "HOST_EXECUTION_MUST_NOT_HAPPEN".into(),
            expected_exit: 0,
            purpose: Default::default(),
        },
        control: None,
        inputs: Vec::new(),
        timeout_seconds: 3,
        memory_mib: 128,
    };
    let spec_path = directory.path().join("test.yaml");
    fs::write(&spec_path, serde_saphyr::to_string(&spec).unwrap()).unwrap();
    let result = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .env("VULNBELL_DATA_DIR", &isolated)
        .args(["verify", &case.case_id, "--project"])
        .arg(&profile_path)
        .arg("--case")
        .arg(&spec_path)
        .arg("--authorize")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Case = serde_json::from_slice(&result).unwrap();
    assert_eq!(result.verification, Verification::Inconclusive);
    assert!(!result.sandbox.available);
    assert!(!marker.exists());
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.kind != EvidenceKind::Attestation)
    );

    let larger = TestSpec {
        memory_mib: 1024,
        timeout_seconds: 300,
        ..spec
    };
    fs::write(&spec_path, serde_saphyr::to_string(&larger).unwrap()).unwrap();
    let verify = || {
        let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"));
        command
            .env("VULNBELL_DATA_DIR", &isolated)
            .args(["verify", &case.case_id, "--project"])
            .arg(&profile_path)
            .arg("--case")
            .arg(&spec_path)
            .arg("--authorize");
        command
    };
    let rejected = verify().assert().failure().get_output().stderr.clone();
    assert!(String::from_utf8_lossy(&rejected).contains("profile sandbox limits"));
    let mut raised = fs::read_to_string(&profile_path).unwrap();
    raised.push_str("sandbox:\n  max_memory_mib: 1024\n  max_timeout_seconds: 300\n");
    fs::write(&profile_path, raised).unwrap();
    verify().assert().success();
    assert!(!marker.exists());
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
