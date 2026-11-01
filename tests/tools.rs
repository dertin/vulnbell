use chrono::{DateTime, Duration};
use std::{fs, path::Path};
use vulnbell::{
    model::Decision,
    research::Assessment,
    store::Store,
    tools::{cases, draft, hits, queue},
};

#[test]
fn evaluate_cli_reports_known_synthetic_false_negative() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args([
            "tools",
            "evaluate",
            "--from",
            "tests/fixtures/screening-evaluation.json",
            "--top",
            "2",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["total"], 6);
    assert_eq!(result["true_positive"], 3);
    assert_eq!(result["false_negative_keys"][0], "synthetic/6");
    assert_eq!(result["precision_at_top"], 1.0);
    assert_eq!(result["high_priority"], 2);
    assert_eq!(result["high_priority_missed_keys"][0], "synthetic/6");
    assert_eq!(result["high_priority_recall"], 0.5);
}

#[test]
fn empty_upstream_import_does_not_require_a_decisions_file() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: empty\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/project\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let raw = directory.path().join("raw");
    let root =
        vulnbell::tools::raw::window_directory(&plan.targets[0]).join("github/example/project");
    for name in [
        "issues.page-1.json",
        "releases.page-1.json",
        "security-advisories.page-1.json",
    ] {
        write(&raw, &root.join(name).to_string_lossy(), "[[]]");
    }
    write(
        &raw,
        &root.join("discussions.json").to_string_lossy(),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let output = directory.path().join("batch.json");
    assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["tools", "draft", "--project"])
        .arg(&path)
        .arg("--raw")
        .arg(&raw)
        .arg("--decisions")
        .arg(directory.path().join("missing.json"))
        .arg("--output")
        .arg(&output)
        .args(["--offline", "--import"])
        .assert()
        .failure();
    assert!(!output.exists());
    assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["tools", "draft", "--project"])
        .arg(&path)
        .arg("--raw")
        .arg(&raw)
        .arg("--output")
        .arg(&output)
        .args(["--offline", "--import"])
        .assert()
        .success();
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .research_open
            .is_empty()
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn recheck_resumes_across_limited_batches() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: recheck\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/project\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let initial = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let until = DateTime::parse_from_rfc3339(&initial.targets[0].until).unwrap();
    let since = (until - Duration::days(1)).to_rfc3339();
    vulnbell::research::reopen_recheck(&mut store, "all", &since).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let updated = (until - Duration::minutes(2)).to_rfc3339();
    let raw = directory.path().join("raw");
    let root =
        vulnbell::tools::raw::window_directory(&plan.targets[0]).join("github/example/project");
    let issues: Vec<_> = (1..=12).map(|number| serde_json::json!({
        "number": number, "title": format!("Security issue {number}"),
        "html_url": format!("https://github.com/example/project/issues/{number}"),
        "state": "open", "updated_at": updated, "labels": [], "body": "A synthetic security claim."
    })).collect();
    write(
        &raw,
        &root.join("issues.page-1.json").to_string_lossy(),
        &serde_json::json!([issues]).to_string(),
    );
    for name in ["releases.page-1.json", "security-advisories.page-1.json"] {
        write(&raw, &root.join(name).to_string_lossy(), "[[]]");
    }
    write(
        &raw,
        &root.join("discussions.json").to_string_lossy(),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let packet_path = directory.path().join("hits.json");
    let input_path = directory.path().join("input.json");
    let decisions_path = directory.path().join("decisions.json");
    for expected in [10, 2, 0] {
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("vulnbell");
        command
            .args(["tools", "hits", "--project"])
            .arg(&path)
            .arg("--raw")
            .arg(&raw)
            .arg("--output")
            .arg(&packet_path)
            .args(["--offline", "--recheck", "--review-limit", "10"]);
        if decisions_path.exists() {
            command.arg("--decisions").arg(&decisions_path);
        }
        command.assert().success();
        let packet: serde_json::Value =
            serde_json::from_slice(&fs::read(&packet_path).unwrap()).unwrap();
        let items = packet["review"].as_array().unwrap();
        assert_eq!(items.len(), expected);
        if items.is_empty() {
            break;
        }
        let decisions: Vec<_> = items.iter().map(|item| serde_json::json!({
            "upstream": item["upstream"], "key": item["key"], "updated_at": item["updated_at"],
            "context_sha256": item["context_sha256"], "codebase_revisions": packet["codebase_revisions"],
            "reviewed_instance_ids": item["instance_ids"], "assessment": "review", "rationale": "Review the synthetic claim."
        })).collect();
        fs::write(&input_path, serde_json::to_vec(&serde_json::json!({"schema_version":1,"project_id":project,"recheck":true,"decisions":decisions})).unwrap()).unwrap();
        assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
            .args(["tools", "decide", "--project"])
            .arg(&path)
            .arg("--packet")
            .arg(&packet_path)
            .arg("--from")
            .arg(&input_path)
            .arg("--decisions")
            .arg(&decisions_path)
            .assert()
            .success();
    }
    assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["tools", "draft", "--project"])
        .arg(&path)
        .arg("--raw")
        .arg(&raw)
        .arg("--decisions")
        .arg(&decisions_path)
        .arg("--output")
        .arg(directory.path().join("batch.json"))
        .args(["--offline", "--recheck", "--import"])
        .assert()
        .success();
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .research_open
            .is_empty()
    );
    let stale: vulnbell::research::ResearchBatch =
        serde_json::from_slice(&fs::read(directory.path().join("batch.json")).unwrap()).unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["tools", "hits", "--project"])
        .arg(&path)
        .arg("--raw")
        .arg(&raw)
        .arg("--decisions")
        .arg(&decisions_path)
        .arg("--output")
        .arg(&packet_path)
        .args(["--offline", "--recheck"])
        .assert()
        .failure();
    vulnbell::research::reopen_recheck(&mut store, "all", &since).unwrap();
    assert!(vulnbell::research::import(&mut store, stale.clone()).is_err());
    let mut normal = stale;
    normal.sources[0].recheck_context_sha256 = None;
    assert!(vulnbell::research::import(&mut store, normal).is_err());
    let next_plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    copy_research_responses(
        &raw,
        &root.to_string_lossy().replace('\\', "/"),
        &next_plan.targets[0],
    );
    assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["tools", "hits", "--project"])
        .arg(&path)
        .arg("--raw")
        .arg(&raw)
        .arg("--decisions")
        .arg(&decisions_path)
        .arg("--output")
        .arg(&packet_path)
        .args(["--offline", "--recheck", "--review-limit", "10"])
        .assert()
        .success();
    let next: serde_json::Value = serde_json::from_slice(&fs::read(&packet_path).unwrap()).unwrap();
    assert_eq!(next["review"].as_array().unwrap().len(), 10);
    assert_eq!(next["summary"]["decided"], 0);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

fn write(directory: &Path, relative: &str, contents: &str) {
    let path = directory.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn copy_research_responses(
    raw: &Path,
    repository: &str,
    target: &vulnbell::research::ResearchTarget,
) -> String {
    let next = vulnbell::tools::raw::window_directory(target).join("github/example/project");
    let next = next.to_string_lossy().replace('\\', "/");
    fs::create_dir_all(raw.join(&next)).unwrap();
    for name in [
        "issues.page-1.json",
        "releases.page-1.json",
        "security-advisories.page-1.json",
        "discussions.json",
    ] {
        let original = raw.join(repository).join(name);
        let destination = raw.join(&next).join(name);
        if original != destination {
            fs::copy(original, destination).unwrap();
        }
    }
    next
}

#[path = "tools/daily_review.rs"]
mod daily_review;
