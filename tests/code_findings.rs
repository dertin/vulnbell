use std::{fs, process::Command};

#[test]
fn changed_non_git_source_cannot_inherit_review_progress() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("app");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("app.py"), "value = 1\n").unwrap();
    let profile = temp.path().join("vulnbell.yaml");
    fs::write(
        &profile,
        format!(
            "schema: 1\nproject_id: {}\nname: fixture\ndiscovery: off\ncodebases: [app]\n",
            uuid::Uuid::new_v4()
        ),
    )
    .unwrap();
    let state = temp.path().join("state");
    let scan = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .env("VULNBELL_DATA_DIR", &state)
        .args(["scan", "--project"])
        .arg(&profile)
        .args(["--offline", "--json"])
        .output()
        .unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let input = temp.path().join("review.json");
    let mut review = serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"codebase":0,"status":"in_progress","scope":[],"gaps":[],"uncertainties":[]});
    let submit = || {
        assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
            .env("VULNBELL_DATA_DIR", &state)
            .args(["tools", "code-review", "--project"])
            .arg(&profile)
            .arg("--from")
            .arg(&input)
            .output()
            .unwrap()
    };
    fs::write(&input, review.to_string()).unwrap();
    let started = submit();
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    review["previous_revision"] =
        serde_json::from_slice::<serde_json::Value>(&started.stdout).unwrap()["revision"].clone();
    fs::write(root.join("app.py"), "value = 2\n").unwrap();
    review["status"] = "complete".into();
    review["scope"] = serde_json::json!(["application"]);
    fs::write(&input, review.to_string()).unwrap();
    let changed = submit();
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("source changed since review began"));
    review["status"] = "in_progress".into();
    review["scope"] = serde_json::json!([]);
    fs::write(&input, review.to_string()).unwrap();
    assert!(submit().status.success());
}

#[test]
fn unavailable_fingerprint_still_allows_partial_progress() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("app");
    fs::create_dir(&root).unwrap();
    fs::File::create(root.join("large.bin"))
        .unwrap()
        .set_len(1024 * 1024 * 1024 + 1)
        .unwrap();
    let profile = temp.path().join("vulnbell.yaml");
    fs::write(
        &profile,
        format!(
            "schema: 1\nproject_id: {}\nname: fixture\ndiscovery: off\ncodebases: [app]\n",
            uuid::Uuid::new_v4()
        ),
    )
    .unwrap();
    let state = temp.path().join("state");
    let scan = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .env("VULNBELL_DATA_DIR", &state)
        .args(["scan", "--project"])
        .arg(&profile)
        .args(["--offline", "--json"])
        .output()
        .unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let input = temp.path().join("review.json");
    let mut review = serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"codebase":0,"status":"in_progress","scope":[],"gaps":[],"uncertainties":[]});
    let submit = || {
        assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
            .env("VULNBELL_DATA_DIR", &state)
            .args(["tools", "code-review", "--project"])
            .arg(&profile)
            .arg("--from")
            .arg(&input)
            .output()
            .unwrap()
    };
    fs::write(&input, review.to_string()).unwrap();
    let first = submit();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["current"], false);
    review["previous_revision"] = first["revision"].clone();
    review["status"] = "partial".into();
    review["gaps"] = serde_json::json!(["CodeGraph index unavailable"]);
    fs::write(&input, review.to_string()).unwrap();
    let second = submit();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second["current"], false);
    assert_eq!(second["submission"]["gaps"].as_array().unwrap().len(), 2);
}

#[test]
fn cli_records_code_findings_without_copying_source_and_reopens_after_changes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("app");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("Dockerfile"),
        "FROM scratch\n# synthetic sensitive fixture\n",
    )
    .unwrap();
    for args in [
        vec!["init", "-b", "main"],
        vec!["config", "user.name", "Fixture"],
        vec!["config", "user.email", "fixture@example.invalid"],
        vec!["add", "Dockerfile"],
        vec!["commit", "-m", "fixture"],
    ] {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(&root)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let profile = temp.path().join("vulnbell.yaml");
    fs::write(
        &profile,
        format!(
            "schema: 1\nproject_id: {}\nname: fixture\ndiscovery: off\ncodebases: [app]\nscheduled_code_review: true\n",
            uuid::Uuid::new_v4()
        ),
    )
    .unwrap();
    let state = temp.path().join("state");
    let mut scan = assert_cmd::cargo::cargo_bin_cmd!("vulnbell");
    scan.env("VULNBELL_DATA_DIR", &state)
        .args(["scan", "--project"])
        .arg(&profile)
        .args(["--offline", "--json"]);
    // Offline advisory gaps return exit 2 while retaining the snapshot.
    let scanned = scan.output().unwrap();
    assert!(
        matches!(scanned.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&scanned.stderr)
    );
    let finding = temp.path().join("finding.json");
    let snapshot: serde_json::Value = serde_json::from_slice(&scanned.stdout).unwrap();
    let pending = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .env("VULNBELL_DATA_DIR", &state)
        .args(["tools", "pending", "--project"])
        .arg(&profile)
        .output()
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&pending.stdout).unwrap();
    assert_eq!(pending["code_reviews_pending"], serde_json::json!([0]));
    let review = temp.path().join("review.json");
    let mut review_data = serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"codebase":0,"status":"partial","scope":["Build configuration"],"gaps":["CodeGraph index is missing"]});
    fs::write(&review, review_data.to_string()).unwrap();
    let submit_review = || {
        assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
            .env("VULNBELL_DATA_DIR", &state)
            .args(["tools", "code-review", "--project"])
            .arg(&profile)
            .arg("--from")
            .arg(&review)
            .output()
            .unwrap()
    };
    let first = submit_review();
    assert!(first.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    review_data["previous_revision"] = first["revision"].clone();
    review_data["scope"] = serde_json::json!(["Build configuration", "Entry point"]);
    fs::write(&review, review_data.to_string()).unwrap();
    let updated = submit_review();
    assert!(updated.status.success());
    let updated: serde_json::Value = serde_json::from_slice(&updated.stdout).unwrap();
    let stale = submit_review();
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("reload its revision"));
    review_data["previous_revision"] = updated["revision"].clone();
    review_data["status"] = "complete".into();
    review_data["gaps"] = serde_json::json!([]);
    fs::write(&review, review_data.to_string()).unwrap();
    let missing_graph = submit_review();
    assert!(!missing_graph.status.success());
    assert!(String::from_utf8_lossy(&missing_graph.stderr).contains("CodeGraph index"));
    let submission = serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"review_revision":updated["revision"],"codebase":0,"path":"Dockerfile","line":2,"line_sha256":vulnbell::digest(b"# synthetic sensitive fixture"),"category":"credential","title":"Credential in build configuration","severity":"high","disposition":"actionable","analysis":"The build configuration embeds a credential.","impact":"Readers may obtain a credential.","recommendation":"Remove and rotate the credential."});
    fs::write(&finding, submission.to_string()).unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .env("VULNBELL_DATA_DIR", &state)
        .args(["tools", "code-finding", "--project"])
        .arg(&profile)
        .arg("--from")
        .arg(&finding)
        .assert()
        .success();
    let render = || {
        assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
            .env("VULNBELL_DATA_DIR", &state)
            .args(["report", "--project"])
            .arg(&profile)
            .args(["--audience", "cyber"])
            .output()
            .unwrap()
    };
    let report = render();
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let text = String::from_utf8(report.stdout).unwrap();
    assert!(text.contains("Credential in build configuration"));
    assert!(text.contains("CodeGraph index is missing"));
    assert!(text.contains("Partial"));
    assert!(!text.contains("synthetic sensitive fixture"));
    fs::write(root.join("Dockerfile"), "FROM scratch\n# changed\n").unwrap();
    let report = render();
    assert!(
        String::from_utf8(report.stdout)
            .unwrap()
            .contains("Context reassessment required")
    );
    let pending = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .env("VULNBELL_DATA_DIR", &state)
        .args(["tools", "pending", "--project"])
        .arg(&profile)
        .output()
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&pending.stdout).unwrap();
    assert_eq!(
        pending["code_findings_pending"].as_array().unwrap().len(),
        1
    );
    assert_eq!(pending["code_reviews_pending"].as_array().unwrap().len(), 1);
}
