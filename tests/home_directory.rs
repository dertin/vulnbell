use std::fs;

#[test]
fn cli_uses_userprofile_for_skill_and_state_when_home_is_absent() {
    let directory = tempfile::tempdir().unwrap();
    let mut install = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"));
    install
        .env_remove("HOME")
        .env("USERPROFILE", directory.path())
        .args(["skills", "install", "--host", "opencode"])
        .assert()
        .success();
    assert!(
        directory
            .path()
            .join(".agents/skills/vulnbell/SKILL.md")
            .is_file()
    );
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .env_remove("HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("VULNBELL_DATA_DIR")
        .env("USERPROFILE", directory.path())
        .args(["doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        std::path::Path::new(report["data_directory"].as_str().unwrap()),
        directory.path().join(".local/share/vulnbell")
    );
    assert!(report["skills"][0]["installed"].as_bool().unwrap());
    fs::read(
        directory
            .path()
            .join(".agents/skills/vulnbell/.vulnbell-manifest.json"),
    )
    .unwrap();
}
