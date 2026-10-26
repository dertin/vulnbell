use std::fs;

#[test]
fn runner_configuration_is_local_listed_and_checked_before_use() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    let source = directory.path().join("runner.json");
    let executable = assert_cmd::cargo::cargo_bin!("vulnbell");
    let config = vulnbell::runners::RunnerConfig {
        schema_version: 1,
        id: "test-local".into(),
        adapter: vulnbell::runners::AdapterConfig::Codex {
            executable: executable.to_path_buf(),
            model: None,
        },
    };
    fs::write(&source, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

    let configured = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .env("VULNBELL_DATA_DIR", &data)
        .args(["runners", "configure", "--from"])
        .arg(&source)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let configured: serde_json::Value = serde_json::from_slice(&configured).unwrap();
    assert_eq!(configured["id"], "test-local");
    assert_eq!(configured["adapter"], "codex");
    assert!(
        configured["configuration"]
            .as_str()
            .unwrap()
            .ends_with("test-local.json")
    );

    let listed = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .env("VULNBELL_DATA_DIR", &data)
        .args(["runners", "list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listed: serde_json::Value = serde_json::from_slice(&listed).unwrap();
    assert_eq!(listed["runners"][0]["id"], "test-local");
    assert_eq!(listed["adapters"].as_array().unwrap().len(), 2);

    let error = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .env("VULNBELL_DATA_DIR", &data)
        .args(["runners", "check", "test-local", "--json"])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(
        String::from_utf8(error)
            .unwrap()
            .contains("requires tested version")
    );
}
