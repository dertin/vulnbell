use std::fs;

#[test]
fn project_doctor_suggests_cross_ecosystem_scanner_for_other_purls() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join("vulnbell.yaml");
    fs::write(&profile, format!("schema: 1\nproject_id: {}\nname: test\ncomponents:\n  - ref: pkg:pub/example\n    version: '1.0.0'\n", uuid::Uuid::new_v4())).unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["doctor", "--json", "--project"])
        .arg(&profile)
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .env("PATH", dir.path())
        .env("VULNBELL_DATA_DIR", dir.path().join("data"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let tools = report["tools"].as_array().unwrap();
    assert_eq!(
        tools
            .iter()
            .find(|item| item["name"] == "osv-scanner")
            .unwrap()["recommended_for_project"],
        true
    );
    assert_eq!(
        tools
            .iter()
            .find(|item| item["name"] == "pip-audit")
            .unwrap()["recommended_for_project"],
        false
    );
}

#[test]
fn project_doctor_recommends_tools_from_inventory_without_creating_state() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join("vulnbell.yaml");
    let data = dir.path().join("data");
    let project = uuid::Uuid::new_v4();
    fs::write(&profile, format!("schema: 1\nproject_id: {project}\nname: test\ndiscovery: off\ncomponents:\n  - ref: pkg:pypi/example\n    version: '1.0.0'\n  - ref: pkg:cargo/example\n    version: '1.0.0'\n  - ref: pkg:docker/library/example\n    version: '1.0.0'\n  - ref: pkg:composer/vendor/example\n    version: '1.0.0'\n  - ref: pkg:golang/github.com/example/library\n    version: '1.0.0'\n  - ref: pkg:maven/org.example/example\n    version: '1.0.0'\n  - ref: pkg:npm/example\n    version: '1.0.0'\n  - ref: pkg:gem/example\n    version: '1.0.0'\n  - ref: pkg:nuget/example\n    version: '1.0.0'\n")).unwrap();
    let run = || {
        assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
            .args(["doctor", "--json", "--project"])
            .arg(&profile)
            .env("HOME", dir.path())
            .env("USERPROFILE", dir.path())
            .env("PATH", dir.path())
            .env("VULNBELL_DATA_DIR", &data)
            .output()
            .unwrap()
    };
    let output = run();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["project"]["inventory"], "not_scanned");
    assert!(!data.join(project.to_string()).exists());
    let tools = report["tools"].as_array().unwrap();
    for name in [
        "pip-audit",
        "cargo-audit",
        "composer",
        "govulncheck",
        "bundle-audit",
        "dotnet",
        "dependency-check",
        "osv-scanner",
        "trivy",
    ] {
        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
        assert_eq!(tool["recommended_for_project"], true, "{name}");
        assert!(
            tool["installation"]
                .as_str()
                .unwrap()
                .starts_with("https://")
        );
        assert!(tool["executable"].is_null());
    }
    assert_eq!(
        tools.iter().find(|tool| tool["name"] == "npm").unwrap()["recommended_for_project"],
        false
    );
    let scan = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["scan", "--offline", "--json", "--project"])
        .arg(&profile)
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .env("PATH", dir.path())
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(!scan.stdout.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(report["project"]["inventory"], "latest_snapshot");
    fs::write(
        &profile,
        fs::read_to_string(&profile).unwrap() + "\n# changed\n",
    )
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(report["project"]["inventory"], "profile_changed_rescan");
}

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
