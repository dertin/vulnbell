use std::{fs, path::Path, process::Command};
use vulnbell::{
    profile,
    research::{Assessment, EventKind, ResearchBatch, ResearchEvent, ReviewCoverage, SourceReview},
    store::Store,
    workspace_revision::{self, RepositoryState},
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
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: git-fixture\nworkspaces: [project]\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/project\nreport:\n  language: es\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let reviewed = &first.workspace_revisions[0];
    assert_eq!(reviewed.state, RepositoryState::Git);
    assert_eq!(reviewed.branch.as_deref(), Some("main"));
    assert_eq!(reviewed.commit.as_deref(), Some(first_commit.as_str()));
    assert_eq!(reviewed.dirty, Some(false));
    let fingerprint = first.instances[0].context_fingerprint();
    let mut store = Store::open(&project.to_string()).unwrap();
    store.ensure_workspace_current().unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let batch = ResearchBatch {
        schema_version: 1,
        project_id: project.to_string(),
        snapshot_id: plan.snapshot_id.clone(),
        sources: vec![SourceReview {
            upstream: target.upstream.clone(),
            from: target.from.clone(),
            until: target.until.clone(),
            coverage: ReviewCoverage::Partial,
            detail: "Synthetic source".into(),
            continuation: None,
        }],
        events: vec![ResearchEvent {
            workspace_revisions: Vec::new(),
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
        case.workspace_revisions[0].commit.as_deref(),
        Some(first_commit.as_str())
    );
    let saved: String = store
        .connection
        .query_row("SELECT body FROM research_events LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&saved).unwrap()["workspace_revisions"][0]["branch"],
        "main"
    );
    git(&workspace, &["checkout", "-b", "other"]);
    assert!(store.ensure_workspace_current().is_err());
    assert!(vulnbell::research::import(&mut store, batch).is_err());
    let report = vulnbell::output::morning_report(&first, &store, "cyber").unwrap();
    assert!(!report.workspace_revisions[0].matches);
    let markdown = vulnbell::output::morning_markdown(&report);
    assert!(
        markdown.contains("main") && markdown.contains("other") && markdown.contains(&first_commit)
    );
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .workspace_context_changed
    );
    drop(store);
    let second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        second.workspace_revisions[0].branch.as_deref(),
        Some("other")
    );
    assert_ne!(fingerprint, second.instances[0].context_fingerprint());
    assert_ne!(case.facts_sha256, second.cases[0].facts_sha256);
    assert_eq!(
        second.cases[0].workspace_revisions[0].branch.as_deref(),
        Some("other")
    );
    let original_profile = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        original_profile.replace("workspaces: [project]", "workspaces: []"),
    )
    .unwrap();
    let store = Store::open(&project.to_string()).unwrap();
    assert!(store.ensure_workspace_current().is_err());
    let changed_scope = vulnbell::output::morning_report(&second, &store, "cyber").unwrap();
    assert!(changed_scope.workspace_scope_changed);
    drop(store);
    fs::write(&path, original_profile).unwrap();
    fs::write(workspace.join("tracked.txt"), "modified\n").unwrap();
    let dirty = workspace_revision::capture_path(&workspace);
    assert_eq!(dirty.dirty, Some(true));
    assert!(workspace_revision::ensure_current(&second.workspace_revisions).is_err());
    let dirty_first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let unchanged = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        dirty_first.instances[0].context_fingerprint(),
        unchanged.instances[0].context_fingerprint()
    );
    fs::write(workspace.join("tracked.txt"), "different contents\n").unwrap();
    assert!(workspace_revision::ensure_current(&dirty_first.workspace_revisions).is_err());
    let store = Store::open(&project.to_string()).unwrap();
    assert!(
        vulnbell::tools::cases::pending(&store)
            .unwrap()
            .workspace_context_changed
    );
    drop(store);
    let dirty_second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_ne!(
        dirty_first.instances[0].context_fingerprint(),
        dirty_second.instances[0].context_fingerprint()
    );
    fs::write(workspace.join("new.txt"), "untracked\n").unwrap();
    assert!(workspace_revision::ensure_current(&[dirty]).is_err());
    fs::remove_file(workspace.join("new.txt")).unwrap();
    git(&workspace, &["add", "tracked.txt"]);
    git(&workspace, &["commit", "-m", "second fixture"]);
    let second_commit = workspace_revision::capture_path(&workspace);
    assert_ne!(second_commit.commit.as_deref(), Some(first_commit.as_str()));
    assert!(workspace_revision::ensure_current(&second.workspace_revisions).is_err());
    git(&workspace, &["checkout", "--detach", &first_commit]);
    let detached = workspace_revision::capture_path(&workspace);
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
    let first = workspace_revision::capture_path(&nested);
    assert_eq!(first.dirty, Some(true));
    assert!(workspace_revision::ensure_current(std::slice::from_ref(&first)).is_ok());
    fs::write(nested.join("new.txt"), "other").unwrap();
    assert!(workspace_revision::ensure_current(&[first]).is_err());

    let before_private = workspace_revision::capture_path(&nested);
    fs::write(nested.join("private.tfvars"), "must not be read").unwrap();
    let private = workspace_revision::capture_path(&nested);
    assert_eq!(private.dirty, Some(true));
    assert_eq!(
        private.worktree_status_sha256,
        before_private.worktree_status_sha256
    );
    assert!(workspace_revision::ensure_current(&[private]).is_ok());
}

#[test]
fn tracked_private_paths_are_excluded_from_git_status() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    fs::write(dir.path().join("private.tfvars"), "synthetic original").unwrap();
    git(dir.path(), &["add", "private.tfvars"]);
    git(dir.path(), &["commit", "-m", "fixture"]);
    let before = workspace_revision::capture_path(dir.path());
    fs::write(dir.path().join("private.tfvars"), "synthetic changed").unwrap();
    let after = workspace_revision::capture_path(dir.path());
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
    let revision = workspace_revision::capture_path(dir.path());
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
    let first = workspace_revision::capture_path(dir.path());
    assert!(first.worktree_status_sha256.is_some());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(workspace_revision::ensure_current(&[first]).is_err());
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

    let revision = workspace_revision::capture_path(dir.path());
    assert_eq!(revision.dirty, Some(true));
    assert!(revision.worktree_status_sha256.is_some());
    assert!(!dir.path().join("triggered-by-filter").exists());
}

#[test]
fn non_git_and_unborn_repositories_are_distinguished() {
    let dir = tempfile::tempdir().unwrap();
    let plain = workspace_revision::capture_path(dir.path());
    assert_eq!(plain.state, RepositoryState::NotGit);
    assert_eq!(plain.commit, None);
    git(dir.path(), &["init", "-b", "empty"]);
    let unborn = workspace_revision::capture_path(dir.path());
    assert_eq!(unborn.state, RepositoryState::Git);
    assert_eq!(unborn.branch.as_deref(), Some("empty"));
    assert_eq!(unborn.commit, None);
    assert!(workspace_revision::ensure_current(&[unborn]).is_err());
}
