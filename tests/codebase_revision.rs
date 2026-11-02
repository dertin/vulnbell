use std::{fs, path::Path, process::Command};
use vulnbell::{
    codebase_revision::{self, RepositoryState},
    profile,
    research::{Assessment, EventKind, ResearchBatch, ResearchEvent, ReviewCoverage, SourceReview},
    store::Store,
};

fn git(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(path)
        .args([
            "-c",
            "user.name=VulnBell Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn generated_directories_are_excluded_from_git_worktree_fingerprints() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    fs::write(dir.path().join("project.txt"), "initial").unwrap();
    fs::create_dir(dir.path().join("vendor")).unwrap();
    fs::write(dir.path().join("vendor/tracked.txt"), "initial").unwrap();
    git(dir.path(), &["add", "project.txt", "vendor/tracked.txt"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    let initial = codebase_revision::capture_path(dir.path());
    for path in [
        "node_modules/package",
        "nested/target/debug",
        "vendor/package",
        ".venv/lib",
    ] {
        fs::create_dir_all(dir.path().join(path)).unwrap();
        fs::write(dir.path().join(path).join("generated.txt"), "generated").unwrap();
    }
    let excluded = codebase_revision::capture_path(dir.path());
    assert_eq!(initial.dirty, Some(false));
    assert_eq!(excluded.dirty, Some(false));
    assert_eq!(
        initial.worktree_status_sha256,
        excluded.worktree_status_sha256
    );
    fs::write(dir.path().join("vendor/tracked.txt"), "updated dependency").unwrap();
    let tracked_change = codebase_revision::capture_path(dir.path());
    assert_eq!(tracked_change.dirty, Some(true));
    assert!(codebase_revision::ensure_current(std::slice::from_ref(&initial)).is_err());
    fs::write(dir.path().join("vendor/tracked.txt"), "initial").unwrap();
    fs::write(dir.path().join("project.txt"), "changed").unwrap();
    let changed = codebase_revision::capture_path(dir.path());
    assert_eq!(changed.dirty, Some(true));
    assert_ne!(
        initial.worktree_status_sha256,
        changed.worktree_status_sha256
    );
}

#[test]
fn same_size_change_with_index_timestamp_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    let path = dir.path().join("project.txt");
    fs::write(&path, "initial").unwrap();
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    let set_modified = |path: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
    };
    set_modified(&path);
    git(dir.path(), &["add", "project.txt"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    set_modified(&dir.path().join(".git/index"));
    fs::write(&path, "changed").unwrap();
    set_modified(&path);

    let revision = codebase_revision::capture_path(dir.path());
    assert_eq!(revision.dirty, Some(true));
    assert!(revision.worktree_status_sha256.is_some());
}

#[test]
fn generated_directories_are_excluded_for_a_nested_git_codebase() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    let workspace = dir.path().join("service");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("project.txt"), "initial").unwrap();
    git(dir.path(), &["add", "service/project.txt"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    let initial = codebase_revision::capture_path(&workspace);
    fs::create_dir_all(workspace.join("nested/target/debug")).unwrap();
    fs::write(workspace.join("nested/target/debug/output"), "generated").unwrap();
    let after = codebase_revision::capture_path(&workspace);
    assert_eq!(after.dirty, Some(false));
    assert_eq!(initial.worktree_status_sha256, after.worktree_status_sha256);
}

#[test]
fn index_flags_cannot_hide_worktree_changes() {
    for flag in ["--assume-unchanged", "--skip-worktree"] {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-b", "main"]);
        fs::write(dir.path().join("tracked.txt"), "original").unwrap();
        git(dir.path(), &["add", "tracked.txt"]);
        git(dir.path(), &["commit", "-m", "fixture"]);
        let reviewed = codebase_revision::capture_path(dir.path());
        assert_eq!(reviewed.dirty, Some(false));
        git(dir.path(), &["update-index", flag, "tracked.txt"]);
        let flagged = codebase_revision::capture_path(dir.path());
        assert_eq!(flagged.dirty, None);
        assert!(codebase_revision::ensure_current(std::slice::from_ref(&reviewed)).is_err());
        fs::write(dir.path().join("tracked.txt"), "changed").unwrap();
        assert!(codebase_revision::ensure_current(&[flagged]).is_err());
        assert!(codebase_revision::ensure_current(&[reviewed]).is_err());
    }
}

#[test]
fn changed_checkout_blocks_recording_and_keeps_the_scanned_revision_in_reports() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("project");
    fs::create_dir(&workspace).unwrap();
    git(&workspace, &["init", "-b", "main"]);
    fs::write(workspace.join("tracked.txt"), "first\n").unwrap();
    git(&workspace, &["add", "tracked.txt"]);
    git(&workspace, &["commit", "-m", "fixture"]);
    let first_commit = git(&workspace, &["rev-parse", "HEAD"]);
    let project = uuid::Uuid::new_v4();
    let path = dir.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: git-fixture\ncodebases: [project]\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/project\nreport:\n  language: es\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let reviewed = &first.codebase_revisions[0];
    assert_eq!(reviewed.state, RepositoryState::Git);
    assert_eq!(reviewed.branch.as_deref(), Some("main"));
    assert_eq!(reviewed.commit.as_deref(), Some(first_commit.as_str()));
    assert_eq!(reviewed.dirty, Some(false));
    let fingerprint = first.instances[0].context_fingerprint();
    let mut store = Store::open(&project.to_string()).unwrap();
    store.ensure_codebases_current().unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let batch = ResearchBatch {
        schema_version: 1,
        project_id: project.to_string(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            recheck_context_sha256: None,
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage: ReviewCoverage::Partial,
            detail: "Synthetic source".into(),
            continuation: None,
        }],
        events: vec![ResearchEvent {
            codebase_revisions: Vec::new(),
            upstream: target.upstream.clone(),
            instance_ids: target.instance_ids.clone(),
            reviewed_instance_ids: target.instance_ids.clone(),
            provider: "github".into(),
            external_id: "example/project#1".into(),
            kind: EventKind::Issue,
            url: "https://github.com/example/project/issues/1".into(),
            title: "Synthetic issue".into(),
            excerpt: "Synthetic evidence".into(),
            updated_at: target.until.clone(),
            assessment: Assessment::Review,
            not_applicable_reason: None,
            rationale: "Review the synthetic conditions".into(),
            source_facts: Default::default(),
        }],
    };
    vulnbell::research::import(&mut store, batch.clone()).unwrap();
    let case = store.cases().unwrap().remove(0);
    assert_eq!(
        case.codebase_revisions[0].commit.as_deref(),
        Some(first_commit.as_str())
    );
    let citations = dir.path().join("citations.json");
    fs::write(
        &citations,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "citations": [{"codebase": 0, "path": "tracked.txt", "line": 1,
                "line_sha256": vulnbell::digest(b"first")}]
        }))
        .unwrap(),
    )
    .unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["tools", "citations", "--project"])
        .arg(&path)
        .args(["--case", &case.case_id, "--from"])
        .arg(&citations)
        .output()
        .unwrap();
    assert!(output.status.success());
    let checked: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(checked["citations"][0]["status"], "matched");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("first\n"));
    let invalid: vulnbell::tools::citations::CitationBatch =
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "citations": [
                {"codebase": 0, "path": "tracked.txt", "line": 1, "line_sha256": "0".repeat(64)},
                {"codebase": 0, "path": "tracked.txt", "line": 2},
                {"codebase": 0, "path": "../vulnbell.yaml", "line": 1},
                {"codebase": 0, "path": ".env", "line": 1}
            ]
        }))
        .unwrap();
    let checked = serde_json::to_value(
        vulnbell::tools::citations::check(&store, &case.case_id, invalid).unwrap(),
    )
    .unwrap();
    assert!(!checked["complete"].as_bool().unwrap());
    assert_eq!(checked["citations"][0]["status"], "mismatch");
    for entry in &checked["citations"].as_array().unwrap()[1..] {
        assert_eq!(entry["status"], "unavailable");
    }
    let saved: String = store
        .connection
        .query_row("SELECT body FROM research_events LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&saved).unwrap()["codebase_revisions"][0]["branch"],
        "main"
    );
    git(&workspace, &["checkout", "-b", "other"]);
    assert!(store.ensure_codebases_current().is_err());
    let stale: vulnbell::tools::citations::CitationBatch =
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "citations": [{"codebase": 0, "path": "tracked.txt", "line": 1}]
        }))
        .unwrap();
    assert!(vulnbell::tools::citations::check(&store, &case.case_id, stale).is_err());
    assert!(vulnbell::research::import(&mut store, batch).is_err());
    let mut report = vulnbell::output::morning_report(&first, &store, "cyber").unwrap();
    vulnbell::output::prepare_report_paths(&mut report, &store).unwrap();
    assert!(!report.codebase_revisions[0].matches);
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(markdown.contains("## Codebases revisadas"));
    assert!(!markdown.contains(dir.path().to_str().unwrap()));
    assert!(
        markdown.contains("main") && markdown.contains("other") && markdown.contains(&first_commit)
    );
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .codebase_context_changed
    );
    drop(store);
    let second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        second.codebase_revisions[0].branch.as_deref(),
        Some("other")
    );
    assert_ne!(fingerprint, second.instances[0].context_fingerprint());
    assert_ne!(case.facts_sha256, second.cases[0].facts_sha256);
    assert_eq!(
        second.cases[0].codebase_revisions[0].branch.as_deref(),
        Some("other")
    );
    let original_profile = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        original_profile.replace("codebases: [project]", "codebases: []"),
    )
    .unwrap();
    let store = Store::open(&project.to_string()).unwrap();
    assert!(store.ensure_codebases_current().is_err());
    let changed_scope = vulnbell::output::morning_report(&second, &store, "cyber").unwrap();
    assert!(changed_scope.codebase_scope_changed);
    drop(store);
    fs::write(&path, original_profile).unwrap();
    fs::write(workspace.join("tracked.txt"), "modified\n").unwrap();
    let dirty = codebase_revision::capture_path(&workspace);
    assert_eq!(dirty.dirty, Some(true));
    assert!(codebase_revision::ensure_current(&second.codebase_revisions).is_err());
    let dirty_first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let unchanged = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        dirty_first.instances[0].context_fingerprint(),
        unchanged.instances[0].context_fingerprint()
    );
    fs::write(workspace.join("tracked.txt"), "different contents\n").unwrap();
    assert!(codebase_revision::ensure_current(&dirty_first.codebase_revisions).is_err());
    let store = Store::open(&project.to_string()).unwrap();
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .codebase_context_changed
    );
    drop(store);
    let dirty_second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_ne!(
        dirty_first.instances[0].context_fingerprint(),
        dirty_second.instances[0].context_fingerprint()
    );
    fs::write(workspace.join("new.txt"), "untracked\n").unwrap();
    assert!(codebase_revision::ensure_current(&[dirty]).is_err());
    fs::remove_file(workspace.join("new.txt")).unwrap();
    git(&workspace, &["add", "tracked.txt"]);
    git(&workspace, &["commit", "-m", "second fixture"]);
    let second_commit = codebase_revision::capture_path(&workspace);
    assert_ne!(second_commit.commit.as_deref(), Some(first_commit.as_str()));
    assert!(codebase_revision::ensure_current(&second.codebase_revisions).is_err());
    git(&workspace, &["checkout", "--detach", &first_commit]);
    let detached = codebase_revision::capture_path(&workspace);
    assert_eq!(detached.branch, None);
    assert_eq!(detached.commit.as_deref(), Some(first_commit.as_str()));
    assert_eq!(detached.dirty, Some(false));
    fs::remove_dir_all(vulnbell::store::data_root().join(project.to_string())).unwrap();
}

#[test]
fn dirty_untracked_content_is_bound_and_private_files_are_excluded() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    fs::write(dir.path().join("tracked.txt"), "original").unwrap();
    git(dir.path(), &["add", "tracked.txt"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    let nested = dir.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("new.txt"), "first").unwrap();
    let first = codebase_revision::capture_path(&nested);
    assert_eq!(first.dirty, Some(true));
    assert!(codebase_revision::ensure_current(std::slice::from_ref(&first)).is_ok());
    fs::write(nested.join("new.txt"), "other").unwrap();
    assert!(codebase_revision::ensure_current(&[first]).is_err());

    let before_private = codebase_revision::capture_path(&nested);
    fs::write(nested.join("private.tfvars"), "must not be read").unwrap();
    let private = codebase_revision::capture_path(&nested);
    assert_eq!(private.dirty, Some(true));
    assert_eq!(
        private.worktree_status_sha256,
        before_private.worktree_status_sha256
    );
    assert!(codebase_revision::ensure_current(&[private]).is_ok());
}

#[test]
fn tracked_private_paths_are_excluded_from_git_status() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    fs::write(dir.path().join("private.tfvars"), "synthetic original").unwrap();
    git(dir.path(), &["add", "private.tfvars"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    let before = codebase_revision::capture_path(dir.path());
    fs::write(dir.path().join("private.tfvars"), "synthetic changed").unwrap();
    let after = codebase_revision::capture_path(dir.path());
    assert_eq!(after.dirty, Some(false));
    assert_eq!(after.worktree_status_sha256, before.worktree_status_sha256);
}

#[test]
fn git_line_ending_configuration_is_respected() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    git(dir.path(), &["config", "core.autocrlf", "true"]);
    fs::write(dir.path().join("tracked.txt"), "first\nsecond\n").unwrap();
    git(dir.path(), &["add", "tracked.txt"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    fs::remove_file(dir.path().join("tracked.txt")).unwrap();
    git(dir.path(), &["checkout", "--", "tracked.txt"]);
    assert!(
        fs::read(dir.path().join("tracked.txt"))
            .unwrap()
            .windows(2)
            .any(|pair| pair == b"\r\n")
    );
    let revision = codebase_revision::capture_path(dir.path());
    assert_eq!(revision.dirty, Some(false));
    assert!(revision.worktree_status_sha256.is_some());
}

#[cfg(unix)]
#[test]
fn executable_bit_changes_invalidate_a_dirty_file_fingerprint() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    let file = dir.path().join("tracked.txt");
    fs::write(&file, "original").unwrap();
    git(dir.path(), &["add", "tracked.txt"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    fs::write(&file, "changed").unwrap();
    let first = codebase_revision::capture_path(dir.path());
    assert!(first.worktree_status_sha256.is_some());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(codebase_revision::ensure_current(&[first]).is_err());
}

#[test]
fn git_filters_do_not_run_when_capturing_workspace_state() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    fs::write(dir.path().join(".gitattributes"), "*.txt filter=fixture\n").unwrap();
    fs::write(dir.path().join("tracked.txt"), "original").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    git(
        dir.path(),
        &[
            "config",
            "filter.fixture.clean",
            "touch triggered-by-filter; cat",
        ],
    );
    fs::write(dir.path().join("tracked.txt"), "changed").unwrap();

    let revision = codebase_revision::capture_path(dir.path());
    assert_eq!(revision.dirty, Some(true));
    assert!(revision.worktree_status_sha256.is_some());
    assert!(!dir.path().join("triggered-by-filter").exists());
}

#[test]
fn non_git_and_unborn_repositories_are_distinguished() {
    let dir = tempfile::tempdir().unwrap();
    let plain = codebase_revision::capture_path(dir.path());
    assert_eq!(plain.state, RepositoryState::NotGit);
    assert_eq!(plain.commit, None);
    git(dir.path(), &["init", "-b", "empty"]);
    let unborn = codebase_revision::capture_path(dir.path());
    assert_eq!(unborn.state, RepositoryState::Git);
    assert_eq!(unborn.branch.as_deref(), Some("empty"));
    assert_eq!(unborn.commit, None);
    assert!(codebase_revision::ensure_current(&[unborn]).is_err());
}

#[test]
fn added_non_git_codebase_requires_a_new_scan_before_recording() {
    let directory = tempfile::tempdir().unwrap();
    let codebase = directory.path().join("code");
    fs::create_dir(&codebase).unwrap();
    fs::write(codebase.join("source.rs"), "fn synthetic() {}\n").unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let profile = directory.path().join("vulnbell.yaml");
    let initial = format!(
        "schema: 1\nproject_id: {project}\nname: fixture\ndiscovery: off\ncomponents:\n  - ref: synthetic\n    version: '1.0.0'\n    upstream: https://github.com/example/example\n"
    );
    fs::write(&profile, &initial).unwrap();
    let path = profile.to_str().unwrap();
    let cli = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_vulnbell"))
            .env("VULNBELL_DATA_DIR", directory.path().join("data"))
            .args(arguments)
            .output()
            .unwrap()
    };
    let scan = cli(&["scan", "--project", path, "--offline", "--json"]);
    assert!(matches!(scan.status.code(), Some(0 | 2)));
    let snapshot: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert!(
        snapshot["codebase_revisions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let batch = directory.path().join("research.json");
    fs::write(&batch, serde_json::to_vec(&serde_json::json!({"schema_version":1,"project_id":project,"snapshot_id":snapshot["id"],"sources":[],"events":[]})).unwrap()).unwrap();
    fs::write(&profile, format!("{initial}codebases: [code]\n")).unwrap();

    let report = cli(&["report", "--project", path, "--audience", "cyber", "--json"]);
    assert!(report.status.success());
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["codebase_context_unrecorded"], true);
    let pending = cli(&["tools", "pending", "--project", path, "--json"]);
    let pending: serde_json::Value = serde_json::from_slice(&pending.stdout).unwrap();
    assert_eq!(pending["codebase_context_changed"], true);
    assert_eq!(pending["deliverable"], false);
    let attempt = cli(&[
        "research",
        "--project",
        path,
        "--from",
        batch.to_str().unwrap(),
    ]);
    assert!(!attempt.status.success());
    assert!(String::from_utf8_lossy(&attempt.stderr).contains("codebase configuration changed"));

    let rescan = cli(&["scan", "--project", path, "--offline", "--json"]);
    assert!(matches!(rescan.status.code(), Some(0 | 2)));
    let snapshot: serde_json::Value = serde_json::from_slice(&rescan.stdout).unwrap();
    assert_eq!(snapshot["codebase_revisions"][0]["state"], "not_git");
    fs::write(&batch, serde_json::to_vec(&serde_json::json!({"schema_version":1,"project_id":project,"snapshot_id":snapshot["id"],"sources":[],"events":[]})).unwrap()).unwrap();
    let accepted = cli(&[
        "research",
        "--project",
        path,
        "--from",
        batch.to_str().unwrap(),
    ]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let pending = cli(&["tools", "pending", "--project", path, "--json"]);
    let pending: serde_json::Value = serde_json::from_slice(&pending.stdout).unwrap();
    assert_eq!(pending["codebase_context_changed"], false);
}
