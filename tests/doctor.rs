use std::fs;

#[test]
fn doctor_distinguishes_text_and_json_and_reports_missing_tools() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let runners = data.join("runners");
    fs::create_dir_all(&runners).unwrap();
    let executable = dir.path().join("missing-runner");
    fs::write(
        runners.join("missing.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "id": "missing",
            "adapter": { "type": "codex", "executable": executable }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        runners.join("present.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "id": "present",
            "adapter": { "type": "codex", "executable": std::env::current_exe().unwrap() }
        }))
        .unwrap(),
    )
    .unwrap();
    let run = |json: bool| {
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("vulnbell");
        command
            .arg("doctor")
            .env("HOME", dir.path())
            .env("USERPROFILE", dir.path())
            .env("PATH", dir.path())
            .env("VULNBELL_DATA_DIR", &data)
            .env_remove("GITHUB_TOKEN")
            .env_remove("GH_TOKEN");
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    };
    let text = run(false);
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("Interactive review"));
    assert!(text.contains("GitHub credential unavailable"));
    assert!(text.contains("Runner missing executable is missing"));
    assert!(text.contains("INFO  Runner present executable found; compatibility not checked"));
    assert!(text.contains("Network access and credential permissions are not checked"));
    assert!(!text.contains('\x1b'));
    let json = run(true);
    assert!(json.status.success());
    assert!(!json.stdout.contains(&0x1b));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["credentials"]["github"], false);
    assert_eq!(report["runners"]["missing_executables"][0], "missing");
    assert_eq!(report["data_directory_access"], "writable");
    assert!(
        report["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "gh" && tool["executable"].is_null())
    );
}

#[test]
fn doctor_detects_stale_skill_even_when_the_manifest_matches() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let mut install = assert_cmd::cargo::cargo_bin_cmd!("vulnbell");
    assert!(
        install
            .args(["skills", "install"])
            .env("HOME", home)
            .env("USERPROFILE", home)
            .output()
            .unwrap()
            .status
            .success()
    );
    let skill = home.join(".agents/skills/vulnbell");
    let file = skill.join("references/safety.md");
    fs::write(&file, "different local skill content").unwrap();
    let manifest_path = skill.join(".vulnbell-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["files"]["references/safety.md"] = vulnbell::digest(&fs::read(file).unwrap()).into();
    fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["doctor", "--json"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("VULNBELL_DATA_DIR", home.join("data"))
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN")
        .env("PATH", home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["skills"][0]["installed"], true);
    assert_eq!(report["skills"][0]["version_aligned_and_unmodified"], false);
}

#[test]
fn doctor_checks_cursor_skill_when_it_is_installed() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let cursor = home.join(".cursor/skills/vulnbell");
    let installed = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["skills", "install", "--directory"])
        .arg(&cursor)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .unwrap();
    assert!(installed.status.success());
    fs::write(cursor.join("references/safety.md"), "outdated content").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["doctor", "--json"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("VULNBELL_DATA_DIR", home.join("data"))
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN")
        .env("PATH", home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let skills = report["skills"].as_array().unwrap();
    assert_eq!(skills.len(), 2);
    assert_eq!(skills[1]["directory"], cursor.to_string_lossy().as_ref());
    assert_eq!(skills[1]["version_aligned_and_unmodified"], false);
}
