use super::{
    FetchTool, JiraApi, Provider, RawBudget, RawReader, read_target, read_target_with_budget,
    read_values, window_directory,
};
use crate::research::ResearchTarget;
use crate::tools::{ItemKind, raw, screen};
use std::fs;
use std::path::Path;

fn target(upstream: &str) -> ResearchTarget {
    ResearchTarget {
        upstream: upstream.into(),
        context_sha256: "a".repeat(64),
        instance_ids: vec!["instance".into()],
        components: Vec::new(),
        from: "2026-10-19T00:00:00+00:00".into(),
        until: "2026-10-21T00:00:00+00:00".into(),
        last_complete_review: None,
        seen: Vec::new(),
        seen_truncated: false,
        continuation: None,
        progress: None,
        stale_progress: None,
        context_reopened: false,
    }
}

#[test]
fn closing_references_ignore_zero_issue_numbers() {
    let references = super::closes(
        "Fixes #000; closes #0; fixes #42; closes https://github.com/example/other/issues/7",
        "https://github.com/example/project/",
        "example/project",
    );
    assert_eq!(
        references,
        vec![
            "example/project#42",
            "https://github.com/example/other/issues/7"
        ]
    );
}

#[test]
fn response_budget_is_shared_and_rejects_overflow() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("first.json"), b"[1]").unwrap();
    fs::write(directory.path().join("second.json"), b"[2,3]").unwrap();
    let mut budget = RawBudget {
        remaining: 7,
        ..RawBudget::default()
    };
    let mut reader = RawReader {
        root: directory.path(),
        budget: &mut budget,
    };
    assert_eq!(
        read_values(&mut reader, Path::new("first.json"))
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert!(read_values(&mut reader, Path::new("second.json")).is_err());
    assert_eq!(reader.budget.remaining, 4);
}

#[test]
fn json_value_budget_counts_values_without_counting_text_contents() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("first.json"),
        br#"{"text":"[,{}]\\\"ok","n":1}"#,
    )
    .unwrap();
    fs::write(directory.path().join("second.json"), b"[1,2,3]").unwrap();
    let mut budget = RawBudget {
        remaining_values: 6,
        ..RawBudget::default()
    };
    let mut reader = RawReader {
        root: directory.path(),
        budget: &mut budget,
    };
    assert!(
        read_values(&mut reader, Path::new("first.json"))
            .unwrap()
            .is_some()
    );
    let error = read_values(&mut reader, Path::new("second.json")).unwrap_err();
    assert!(error.to_string().contains("JSON value budget"));
}

#[test]
fn exhausted_batch_budget_keeps_source_incomplete() {
    let directory = tempfile::tempdir().unwrap();
    let target = target("https://github.com/example/project");
    let root = directory
        .path()
        .join(window_directory(&target))
        .join("github/example/project");
    fs::create_dir_all(&root).unwrap();
    for name in [
        "issues.page-1.json",
        "releases.page-1.json",
        "security-advisories.page-1.json",
    ] {
        fs::write(root.join(name), "[]").unwrap();
    }
    fs::write(root.join("discussions.json"), "[{\"data\":{}}]").unwrap();
    let result = read_target_with_budget(
        directory.path(),
        &target,
        &mut RawBudget {
            remaining: 7,
            ..RawBudget::default()
        },
    );
    assert!(!result.complete());
    assert!(result.errors.iter().any(|error| error.contains("budget")));
}

#[test]
fn github_release_edits_use_the_release_update_timestamp() {
    let directory = tempfile::tempdir().unwrap();
    let target = target("https://github.com/example/project");
    let root = directory
        .path()
        .join(window_directory(&target))
        .join("github/example/project");
    fs::create_dir_all(&root).unwrap();
    for name in ["issues.page-1.json", "security-advisories.page-1.json"] {
        fs::write(root.join(name), "[]").unwrap();
    }
    fs::write(root.join("discussions.json"), r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#).unwrap();
    let release = serde_json::json!({"tag_name":"v1", "name":"v1", "html_url":"https://github.com/example/project/releases/tag/v1", "created_at":"2025-01-01T00:00:00Z", "published_at":"2025-01-02T00:00:00Z", "updated_at":"2026-10-20T10:00:00Z", "body":"Security update"});
    fs::write(
        root.join("releases.page-1.json"),
        serde_json::json!([release]).to_string(),
    )
    .unwrap();
    let result = read_target(directory.path(), &target);
    assert!(result.complete(), "{:?}", result.errors);
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].updated_at, "2026-10-20T10:00:00+00:00");
    let mut release = release;
    release.as_object_mut().unwrap().remove("updated_at");
    fs::write(
        root.join("releases.page-1.json"),
        serde_json::json!([release]).to_string(),
    )
    .unwrap();
    let result = read_target(directory.path(), &target);
    assert!(!result.complete());
    assert!(
        result
            .errors
            .iter()
            .any(|error| error.contains("lack update timestamps"))
    );
}

#[test]
fn github_release_assets_do_not_exhaust_the_shared_budget_after_each_page() {
    let directory = tempfile::tempdir().unwrap();
    let target = target("https://github.com/example/project");
    let root = directory
        .path()
        .join(window_directory(&target))
        .join("github/example/project");
    fs::create_dir_all(&root).unwrap();
    for name in ["issues.page-1.json", "security-advisories.page-1.json"] {
        fs::write(root.join(name), "[]").unwrap();
    }
    fs::write(root.join("discussions.json"), r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#).unwrap();
    let release = serde_json::json!({
        "tag_name": "v1",
        "html_url": "https://github.com/example/project/releases/tag/v1",
        "updated_at": "2026-10-20T10:00:00Z",
        "body": "Security update",
        "assets": vec![serde_json::json!({"irrelevant": true}); 35],
    });
    let bytes = serde_json::to_vec(&vec![release]).unwrap();
    fs::write(root.join("releases.page-1.json"), &bytes).unwrap();
    let mut budget = RawBudget {
        remaining_values: 130,
        ..RawBudget::default()
    };
    let result = read_target_with_budget(directory.path(), &target, &mut budget);
    assert!(result.complete(), "{:?}", result.errors);
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].body, "Security update");
    assert_eq!(fs::read(root.join("releases.page-1.json")).unwrap(), bytes);

    let mut too_small = RawBudget {
        remaining_values: 10,
        ..RawBudget::default()
    };
    let result = read_target_with_budget(directory.path(), &target, &mut too_small);
    assert!(!result.complete());
    assert!(result.errors.iter().any(|error| error.contains("budget")));
}

#[test]
fn github_issue_metadata_is_compacted_without_changing_the_signal() {
    let directory = tempfile::tempdir().unwrap();
    let target = target("https://github.com/example/project");
    let root = directory
        .path()
        .join(window_directory(&target))
        .join("github/example/project");
    fs::create_dir_all(&root).unwrap();
    for name in ["releases.page-1.json", "security-advisories.page-1.json"] {
        fs::write(root.join(name), "[]").unwrap();
    }
    fs::write(root.join("discussions.json"), r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#).unwrap();
    let issue = serde_json::json!({
        "number": 7,
        "title": "Security fix",
        "html_url": "https://github.com/example/project/pull/7",
        "state": "open",
        "updated_at": "2026-10-20T10:00:00Z",
        "body": "Security update",
        "labels": [{"name": "security", "unused": vec![true; 40]}],
        "pull_request": {"unused": vec![true; 40]},
        "unused": vec![true; 40],
    });
    let bytes = serde_json::to_vec(&vec![issue]).unwrap();
    fs::write(root.join("issues.page-1.json"), &bytes).unwrap();
    let mut budget = RawBudget {
        remaining_values: 60,
        ..RawBudget::default()
    };
    let result = read_target_with_budget(directory.path(), &target, &mut budget);
    assert!(result.complete(), "{:?}", result.errors);
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].kind, ItemKind::PullRequest);
    assert_eq!(result.items[0].labels, ["security"]);
    assert_eq!(result.items[0].body, "Security update");
    assert_eq!(fs::read(root.join("issues.page-1.json")).unwrap(), bytes);
}

#[test]
fn release_pages_do_not_stop_at_an_old_publication() {
    for (upstream, provider, page_size) in [
        (
            "https://gitlab.com/example/project",
            "gitlab/gitlab.com/example/project",
            100,
        ),
        (
            "https://codeberg.org/example/project",
            "forgejo/codeberg.org/example/project",
            50,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let target = target(upstream);
        let root = directory
            .path()
            .join(window_directory(&target))
            .join(provider);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("issues.page-1.json"), "[]").unwrap();
        if upstream.contains("gitlab.com") {
            fs::write(root.join("merge_requests.page-1.json"), "[]").unwrap();
        }
        let base = if upstream.contains("gitlab.com") {
            serde_json::json!({"tag_name":"v1", "name":"v1", "created_at":"2025-01-01T00:00:00Z", "released_at":"2025-01-02T00:00:00Z", "updated_at":"2025-01-02T00:00:00Z", "description":"Old"})
        } else {
            serde_json::json!({"tag_name":"v1", "name":"v1", "html_url":"https://codeberg.org/example/project/releases/tag/v1", "created_at":"2025-01-01T00:00:00Z", "published_at":"2025-01-02T00:00:00Z", "updated_at":"2025-01-02T00:00:00Z", "body":"Old"})
        };
        fs::write(
            root.join("releases.page-1.json"),
            serde_json::json!(vec![base.clone(); page_size]).to_string(),
        )
        .unwrap();
        let partial = read_target(directory.path(), &target);
        assert!(
            partial
                .missing
                .iter()
                .any(|item| item.path.ends_with("releases.page-2.json"))
        );
        let mut edited = base.clone();
        edited["updated_at"] = "2026-10-20T10:00:00Z".into();
        fs::write(
            root.join("releases.page-2.json"),
            serde_json::json!([edited]).to_string(),
        )
        .unwrap();
        let complete = read_target(directory.path(), &target);
        assert!(complete.complete(), "{:?}", complete.errors);
        assert_eq!(complete.items.len(), 1);
        assert_eq!(complete.items[0].updated_at, "2026-10-20T10:00:00+00:00");
        let mut no_update = base;
        no_update.as_object_mut().unwrap().remove("updated_at");
        fs::write(
            root.join("releases.page-2.json"),
            serde_json::json!([no_update]).to_string(),
        )
        .unwrap();
        let partial = read_target(directory.path(), &target);
        assert!(!partial.complete());
        assert!(
            partial
                .errors
                .iter()
                .any(|error| error.contains("lack update timestamps"))
        );
    }
}

fn write(directory: &Path, relative: &str, contents: &str) {
    let path = directory.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

#[test]
fn github_requires_terminal_page_and_fetches_old_linked_issues() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let target = target("https://github.com/example/project");
    let fixture = raw.join(raw::window_directory(&target));
    let repo = "github/example/project";
    let issue = serde_json::json!({"number": 1, "title": "Routine cleanup", "html_url": "https://github.com/example/project/pull/1", "state": "open", "updated_at": "2026-10-20T10:00:00Z", "labels": [], "body": "Fixes #42", "pull_request": {}});
    let page: Vec<_> = (0..100).map(|_| issue.clone()).collect();
    write(
        &fixture,
        &format!("{repo}/issues.page-1.json"),
        &serde_json::to_string(&page).unwrap(),
    );
    write(&fixture, &format!("{repo}/releases.page-1.json"), "[]");
    write(
        &fixture,
        &format!("{repo}/security-advisories.page-1.json"),
        "[]",
    );
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let incomplete = raw::read_target(raw, &target);
    assert!(
        incomplete
            .missing
            .iter()
            .any(|fetch| fetch.path.ends_with("issues.page-2.json"))
    );
    assert!(!incomplete.complete());
    write(&fixture, &format!("{repo}/issues.page-2.json"), "[]");
    let linked_missing = raw::read_target(raw, &target);
    assert!(
        linked_missing
            .missing
            .iter()
            .any(|fetch| fetch.path.ends_with("linked-issues/42.json")
                && fetch.tool == FetchTool::GhRestSingle)
    );
    assert!(!linked_missing.complete());
    write(
        &fixture,
        &format!("{repo}/linked-issues/42.json"),
        r#"{"number":42,"title":"Old report","html_url":"https://github.com/example/project/issues/42","state":"open","updated_at":"2025-01-01T00:00:00Z","labels":[],"body":"An attacker can bypass authentication."}"#,
    );
    let collected = raw::read_target(raw, &target);
    assert!(collected.complete());
    assert_eq!(collected.linked_issues.len(), 1);
    assert!(!collected.items.iter().any(|item| item.key.ends_with("#42")));
    assert!(screen::screen(&collected.items[0], &collected.linked_issues[0].body).is_some());
    let mut title_only = collected.linked_issues[0].clone();
    title_only.title = "SSRF in request handling".into();
    title_only.body = "Details pending".into();
    assert!(screen::screen(&title_only, "").is_some());
    assert!(screen::screen_with_linked(&collected.items[0], &title_only.title, true).is_some());
}

#[test]
fn github_accepts_a_linked_pull_request_from_the_issues_endpoint() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let target = target("https://github.com/example/project");
    let fixture = raw.join(raw::window_directory(&target));
    let repo = "github/example/project";
    write(
        &fixture,
        &format!("{repo}/issues.page-1.json"),
        r#"[{"number":1,"title":"Maintenance","html_url":"https://github.com/example/project/pull/1","state":"open","updated_at":"2026-10-20T00:00:00Z","labels":[],"body":"Fixes #42","pull_request":{}}]"#,
    );
    for name in ["releases.page-1.json", "security-advisories.page-1.json"] {
        write(&fixture, &format!("{repo}/{name}"), "[]");
    }
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let path = format!("{repo}/linked-issues/42.json");
    write(
        &fixture,
        &path,
        r#"{"number":42,"title":"Old fix","html_url":"https://github.com/example/project/pull/42","state":"closed","updated_at":"2025-01-01T00:00:00Z","labels":[],"body":"An attacker can bypass authentication.","pull_request":{}}"#,
    );
    let collected = raw::read_target(raw, &target);
    assert!(collected.complete(), "{:?}", collected.errors);
    assert_eq!(collected.linked_issues[0].kind, ItemKind::PullRequest);
    assert!(screen::screen(&collected.items[0], &collected.linked_issues[0].body).is_some());
    write(
        &fixture,
        &path,
        r#"{"number":42,"title":"Old fix","html_url":"https://github.com/other/project/pull/42","state":"closed","updated_at":"2025-01-01T00:00:00Z","labels":[],"body":"","pull_request":{}}"#,
    );
    let invalid = raw::read_target(raw, &target);
    assert!(!invalid.complete());
    assert!(!invalid.errors.is_empty());
}

#[test]
fn github_resolves_a_linked_discussion_outside_the_window() {
    let directory = tempfile::tempdir().unwrap();
    let target = target("https://github.com/example/project");
    let fixture = directory.path().join(raw::window_directory(&target));
    let repo = "github/example/project";
    write(
        &fixture,
        &format!("{repo}/issues.page-1.json"),
        r#"[{"number":1,"title":"Maintenance","html_url":"https://github.com/example/project/pull/1","state":"open","updated_at":"2026-10-20T00:00:00Z","labels":[],"body":"Closes #42","pull_request":{}}]"#,
    );
    for name in ["releases.page-1.json", "security-advisories.page-1.json"] {
        write(&fixture, &format!("{repo}/{name}"), "[]");
    }
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let path = format!("{repo}/linked-issues/42.json");
    let mut response = serde_json::json!({"data":{"repository":{"discussion":{
        "number":42,"title":"Authentication report","url":"https://github.com/example/project/discussions/42",
        "updatedAt":"2025-01-01T00:00:00Z","body":"An attacker can bypass authentication.","category":{"name":"Q&A"}
    }}}});
    write(&fixture, &path, &response.to_string());
    let collected = raw::read_target(directory.path(), &target);
    assert!(collected.complete(), "{:?}", collected.errors);
    assert_eq!(collected.linked_issues[0].key, "example/project#42");
    assert_eq!(collected.linked_issues[0].kind, ItemKind::Discussion);
    assert!(screen::screen(&collected.items[0], &collected.linked_issues[0].body).is_some());

    response["data"]["repository"]["discussion"]["url"] =
        "https://github.com/other/project/discussions/42".into();
    write(&fixture, &path, &response.to_string());
    assert!(!raw::read_target(directory.path(), &target).complete());
    response["data"]["repository"]["discussion"] = serde_json::Value::Null;
    write(&fixture, &path, &response.to_string());
    assert!(!raw::read_target(directory.path(), &target).complete());
    response["errors"] = serde_json::json!([{"message":"Rate limited"}]);
    write(&fixture, &path, &response.to_string());
    assert!(!raw::read_target(directory.path(), &target).complete());

    fs::remove_file(fixture.join(&path)).unwrap();
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":1,"nodes":[{"number":42,"title":"Authentication report","url":"https://github.com/example/project/discussions/42","updatedAt":"2026-10-20T00:00:00Z","body":"An attacker can bypass authentication.","category":{"name":"Q&A"}}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let in_window = raw::read_target(directory.path(), &target);
    assert!(in_window.complete(), "{:?}", in_window.missing);
    assert_eq!(in_window.linked_issues[0].key, "example/project#42");
    assert!(screen::screen(&in_window.items[0], &in_window.linked_issues[0].body).is_some());
}

#[test]
fn ambiguous_github_reference_requires_an_explicit_matching_issue() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let target = target("https://github.com/example/project");
    let fixture = raw.join(raw::window_directory(&target));
    let repo = "github/example/project";
    write(
        &fixture,
        &format!("{repo}/issues.page-1.json"),
        r#"[{"number":1,"title":"Maintenance","html_url":"https://github.com/example/project/pull/1","state":"open","updated_at":"2026-10-20T00:00:00Z","labels":[],"body":"Fixes example#42","pull_request":{}}]"#,
    );
    for name in ["releases.page-1.json", "security-advisories.page-1.json"] {
        write(&fixture, &format!("{repo}/{name}"), "[]");
    }
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let unresolved = raw::read_target(raw, &target);
    assert!(!unresolved.complete());
    assert!(
        unresolved
            .errors
            .iter()
            .any(|error| error.contains("example#42"))
    );

    let resolution_path = raw::manual_resolution_path(Path::new(repo), "example#42");
    let mut resolution = serde_json::json!({
        "reference": "example#42",
        "rationale": "The change and issue describe the same defect.",
        "issue": {"number":42,"title":"Old issue","html_url":"https://github.com/example/project/issues/42","state":"open","updated_at":"2025-01-01T00:00:00Z","labels":[],"body":"Security issue"}
    });
    resolution["issue"]["number"] = 43.into();
    write(
        &fixture,
        resolution_path.to_str().unwrap(),
        &resolution.to_string(),
    );
    let wrong_issue = raw::read_target(raw, &target);
    assert!(!wrong_issue.complete());

    resolution["issue"]["number"] = 42.into();
    resolution["rationale"] = "".into();
    write(
        &fixture,
        resolution_path.to_str().unwrap(),
        &resolution.to_string(),
    );
    assert!(!raw::read_target(raw, &target).complete());

    resolution["rationale"] = "The change and issue describe the same defect.".into();
    write(
        &fixture,
        resolution_path.to_str().unwrap(),
        &resolution.to_string(),
    );
    let resolved = raw::read_target(raw, &target);
    assert!(resolved.complete(), "{:?}", resolved.errors);
    assert_eq!(resolved.linked_issues[0].key, "example#42");
    assert_eq!(
        resolved.linked_issues[0].url,
        "https://github.com/example/project/issues/42"
    );
}

#[test]
fn raw_responses_are_isolated_by_upstream_and_exact_window() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let mut original = target("https://github.com/example/project");
    let initial_window = raw::window_directory(&original);
    let fixture = raw.join(&initial_window);
    let repo = "github/example/project";
    for file in [
        "issues.page-1.json",
        "releases.page-1.json",
        "security-advisories.page-1.json",
    ] {
        write(&fixture, &format!("{repo}/{file}"), "[]");
    }
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    assert!(raw::read_target(raw, &original).complete());
    original.continuation = Some(crate::research::SourceContinuation {
        cursor: "next".into(),
        url: None,
    });
    assert_eq!(raw::window_directory(&original), initial_window);
    assert!(raw::read_target(raw, &original).complete());

    original.until = "2026-10-22T00:00:00+00:00".into();
    let changed = raw::read_target(raw, &original);
    assert_ne!(raw::window_directory(&original), initial_window);
    assert!(!changed.complete());
    assert_eq!(changed.missing.len(), 4);
    assert!(changed.missing.iter().all(|entry| {
        raw.join(&entry.path)
            .starts_with(raw.join(raw::window_directory(&original)))
    }));
    original.until = "2026-10-21T00:00:00+00:00".into();
    original.from = "2026-10-18T00:00:00+00:00".into();
    assert!(!raw::read_target(raw, &original).complete());
    original.from = "2026-10-19T00:00:00+00:00".into();
    original.upstream = "https://github.com/example/project?different=1".into();
    assert!(!raw::read_target(raw, &original).complete());
}

#[test]
fn github_cross_repository_issue_references_are_fetched_without_following_other_hosts() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let target = target("https://github.com/example/project");
    let fixture = raw.join(raw::window_directory(&target));
    let repo = "github/example/project";
    let issue = serde_json::json!({"number":7,"title":"Issue","html_url":"https://github.com/example/project/issues/7","state":"open","updated_at":"2026-10-20T10:00:00Z","labels":[],"body":"Security issue"});
    let pull = |number, body| serde_json::json!({"number":number,"title":"Fix","html_url":format!("https://github.com/example/project/pull/{number}"),"state":"open","updated_at":"2026-10-20T10:00:00Z","labels":[],"body":body,"pull_request":{}});
    let items = serde_json::json!([
        issue,
        pull(1, "Fixes example/project#7"),
        pull(2, "Fixes https://github.com/example/project/issues/7"),
        pull(3, "Fixes example/other#42"),
        pull(4, "Fixes https://github.com/example/other/issues/43"),
        pull(5, "Fixes https://gitlab.com/group/project/-/issues/44"),
        pull(6, "Fixes project#7")
    ]);
    write(
        &fixture,
        &format!("{repo}/issues.page-1.json"),
        &items.to_string(),
    );
    write(&fixture, &format!("{repo}/releases.page-1.json"), "[]");
    write(
        &fixture,
        &format!("{repo}/security-advisories.page-1.json"),
        "[]",
    );
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let collected = raw::read_target(raw, &target);
    assert_eq!(collected.items[1].closes, vec!["example/project#7"]);
    assert_eq!(collected.items[2].closes, vec!["example/project#7"]);
    assert_eq!(collected.items[6].closes, vec!["example/project#7"]);
    assert!(!collected.complete());
    assert_eq!(collected.errors.len(), 1);
    assert!(
        collected
            .errors
            .iter()
            .all(|error| error.contains("cross-repository reference requires manual research"))
    );
    assert_eq!(collected.missing.len(), 2);
    assert!(collected.missing.iter().any(|fetch| {
        fetch.request == "repos/example/other/issues/42"
            && fetch.path.ends_with("linked-issues/example/other/42.json")
    }));
    assert!(collected.missing.iter().any(|fetch| {
        fetch.request == "repos/example/other/issues/43"
            && fetch.path.ends_with("linked-issues/example/other/43.json")
    }));
    for number in [42, 43] {
        write(
            &fixture,
            &format!("{repo}/linked-issues/example/other/{number}.json"),
            &serde_json::json!({"number":number,"title":"Security issue","html_url":format!("https://github.com/example/other/issues/{number}"),"state":"open","updated_at":"2026-10-20T10:00:00Z","labels":[],"body":"An attacker can bypass authorization."}).to_string(),
        );
    }
    let collected = raw::read_target(raw, &target);
    assert_eq!(collected.linked_issues.len(), 2);
    assert!(collected.missing.is_empty());
    assert_eq!(collected.errors.len(), 1);
    write(
        &fixture,
        &format!("{repo}/linked-issues/example/other/42.json"),
        r#"{"number":42,"title":"Wrong repository","html_url":"https://github.com/evil/other/issues/42","state":"open","updated_at":"2026-10-20T10:00:00Z","labels":[],"body":""}"#,
    );
    let invalid = raw::read_target(raw, &target);
    assert!(
        invalid
            .errors
            .iter()
            .any(|error| error.contains("linked response URL"))
    );
}

#[test]
fn github_screens_security_signals_after_the_old_body_limit() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let target = target("https://github.com/example/project");
    let fixture = raw.join(raw::window_directory(&target));
    let repo = "github/example/project";
    let issue = serde_json::json!({"number": 1, "title": "Parser update", "html_url": "https://github.com/example/project/issues/1", "state": "open", "updated_at": "2026-10-20T10:00:00Z", "labels": [], "body": format!("{} attacker can bypass checks", "x".repeat(9000))});
    write(
        &fixture,
        &format!("{repo}/issues.page-1.json"),
        &serde_json::json!([issue]).to_string(),
    );
    write(&fixture, &format!("{repo}/releases.page-1.json"), "[]");
    write(
        &fixture,
        &format!("{repo}/security-advisories.page-1.json"),
        "[]",
    );
    write(
        &fixture,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let collected = raw::read_target(raw, &target);
    assert!(collected.complete());
    assert!(screen::screen(&collected.items[0], "").is_some());
}

#[test]
fn gitlab_and_forgejo_fetch_linked_issues_outside_the_window() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let gitlab_target = target("https://gitlab.com/example/project");
    let fixture = raw.join(raw::window_directory(&gitlab_target));
    let gitlab = "gitlab/gitlab.com/example/project";
    write(&fixture, &format!("{gitlab}/issues.page-1.json"), "[]");
    write(&fixture, &format!("{gitlab}/releases.page-1.json"), "[]");
    write(
        &fixture,
        &format!("{gitlab}/merge_requests.page-1.json"),
        r#"[{"iid":1,"title":"Maintenance","web_url":"https://gitlab.com/example/project/-/merge_requests/1","state":"opened","updated_at":"2026-10-20T10:00:00Z","labels":[],"description":"Fixes #42"}]"#,
    );
    let missing = raw::read_target(raw, &gitlab_target);
    assert!(missing.missing.iter().any(
        |fetch| fetch.path.ends_with("linked-issues/42.json") && fetch.tool == FetchTool::Curl
    ));
    write(
        &fixture,
        &format!("{gitlab}/linked-issues/42.json"),
        r#"{"iid":42,"title":"Old issue","web_url":"https://gitlab.com/example/project/-/issues/42","state":"opened","updated_at":"2025-01-01T00:00:00Z","labels":[],"description":"Security issue"}"#,
    );
    let linked = raw::read_target(raw, &gitlab_target);
    assert!(linked.complete(), "{:?}", linked.errors);
    assert_eq!(linked.linked_issues[0].key, "example/project#42");

    let forgejo_target = target("https://codeberg.org/example/project");
    let fixture = raw.join(raw::window_directory(&forgejo_target));
    let forgejo = "forgejo/codeberg.org/example/project";
    write(
        &fixture,
        &format!("{forgejo}/issues.page-1.json"),
        r#"[{"number":1,"title":"Maintenance","html_url":"https://codeberg.org/example/project/pulls/1","state":"open","updated_at":"2026-10-20T10:00:00Z","labels":[],"body":"Fixes #42","pull_request":{}}]"#,
    );
    write(&fixture, &format!("{forgejo}/releases.page-1.json"), "[]");
    let missing = raw::read_target(raw, &forgejo_target);
    assert!(
        missing
            .missing
            .iter()
            .any(|fetch| fetch.path.ends_with("linked-issues/42.json"))
    );
    write(
        &fixture,
        &format!("{forgejo}/linked-issues/42.json"),
        r#"{"number":42,"title":"Old issue","html_url":"https://codeberg.org/example/project/issues/42","state":"open","updated_at":"2025-01-01T00:00:00Z","labels":[],"body":"Security issue"}"#,
    );
    let linked = raw::read_target(raw, &forgejo_target);
    assert!(linked.complete(), "{:?}", linked.errors);
    assert_eq!(linked.linked_issues[0].key, "example/project#42");
}

#[test]
fn providers_map_to_their_raw_directories() {
    assert_eq!(
        raw::provider_for("https://github.com/example/project.git"),
        Provider::GitHub {
            owner: "example".into(),
            repository: "project".into(),
            mirror: false
        }
    );
    assert_eq!(
        raw::provider_for("https://gitbox.apache.org/repos/asf?p=commons-io.git"),
        Provider::GitHub {
            owner: "apache".into(),
            repository: "commons-io".into(),
            mirror: true
        }
    );
    assert!(matches!(
        raw::provider_for("https://issues.jboss.org/browse/WFLY"),
        Provider::Jira { api: JiraApi::SearchJqlV3, ref host, ref project, .. }
            if host == "redhat.atlassian.net" && project == "WFLY"
    ));
    assert!(matches!(
        raw::provider_for("https://gitlab.com/group/sub/project/-/issues"),
        Provider::GitLab { ref project, .. } if project == "group/sub/project"
    ));
    let Provider::Manual { directory, .. } =
        raw::provider_for("https://sourceforge.net/projects/../../etc")
    else {
        panic!("unsupported host is manual");
    };
    assert!(!directory.contains(".."));
}

#[test]
fn github_responses_are_parsed_and_missing_files_name_their_request() {
    let directory = tempfile::tempdir().unwrap();
    let raw_dir = directory.path();
    let target = target("https://github.com/example/project");
    let fixture = raw_dir.join(raw::window_directory(&target));
    let partial = raw::read_target(raw_dir, &target);
    assert_eq!(partial.missing.len(), 4);
    assert!(
        partial
            .missing
            .iter()
            .any(|missing| missing.tool == FetchTool::GhGraphqlDiscussions
                && missing.request == "repo:example/project updated:>=2026-10-19T00:00:00Z")
    );

    write(
        &fixture,
        "github/example/project/issues.page-1.json",
        r#"[[
          {"number": 7, "title": "Token reuse", "html_url": "https://github.com/example/project/issues/7",
           "state": "open", "updated_at": "2026-10-20T10:00:00Z", "labels": [{"name": "security"}], "body": "An attacker can reuse a token"},
          {"number": 8, "title": "Check audience", "html_url": "https://github.com/example/project/pull/8",
           "state": "closed", "updated_at": "2026-10-20T11:00:00Z", "labels": [], "body": "Closes #7",
           "pull_request": {"url": "x"}},
          {"number": 9, "title": "Old", "html_url": "https://github.com/example/project/issues/9",
           "state": "open", "updated_at": "2026-10-01T11:00:00Z", "labels": [], "body": null}
        ]]"#,
    );
    write(
        &fixture,
        "github/example/project/releases.page-1.json",
        "[[]]",
    );
    write(
        &fixture,
        "github/example/project/security-advisories.page-1.json",
        r#"[[{"ghsa_id": "GHSA-abcd-1234-wxyz", "cve_id": "CVE-2026-22222", "html_url": "https://github.com/example/project/security/advisories/GHSA-abcd-1234-wxyz",
              "summary": "Old advisory", "description": null, "updated_at": "2025-01-01T00:00:00Z", "withdrawn_at": null, "vulnerabilities": []}]]"#,
    );
    write(
        &fixture,
        "github/example/project/discussions.json",
        r#"[{"data": {"search": {"discussionCount": 0, "nodes": [{}], "pageInfo": {"hasNextPage": false, "endCursor": null}}}}]"#,
    );
    let complete = raw::read_target(raw_dir, &target);
    assert!(complete.complete(), "{:?}", complete.errors);
    let keys: Vec<&str> = complete
        .items
        .iter()
        .map(|item| item.key.as_str())
        .collect();
    assert_eq!(keys, vec!["example/project#7", "example/project#8"]);
    assert_eq!(complete.items[1].kind, ItemKind::PullRequest);
    assert_eq!(complete.items[1].closes, vec!["example/project#7"]);
    assert!(complete.published_identifiers.contains("CVE-2026-22222"));

    write(
        &fixture,
        "github/example/project/discussions.json",
        r#"[{"data":{"search":{"discussionCount":1,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let incomplete_count = raw::read_target(raw_dir, &target);
    assert!(
        incomplete_count
            .errors
            .iter()
            .any(|error| error.contains("discussion results are incomplete"))
    );

    write(
        &fixture,
        "github/example/project/discussions.json",
        r#"[{"data":{"search":{"discussionCount":1,"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"next"}}}}]"#,
    );
    assert!(!raw::read_target(raw_dir, &target).complete());

    write(
        &fixture,
        "github/example/project/releases.page-1.json",
        r#"{"message": "Not Found", "status": "404"}"#,
    );
    assert!(!raw::read_target(raw_dir, &target).errors.is_empty());

    write(
        &fixture,
        "github/example/project/releases.page-1.json",
        " \n",
    );
    let truncated = raw::read_target(raw_dir, &target);
    assert!(truncated.errors.iter().any(|error| {
        error.contains("github/example/project/releases.page-1.json")
            && error.contains("empty response file")
    }));
    write(
        &fixture,
        "github/example/project/releases.page-1.json",
        "[[]]",
    );
    write(
        &fixture,
        "github/example/project/discussions.json",
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    write(
        &fixture,
        "github/example/project/issues.page-1.json",
        r#"[[{"number":7,"title":"Issue","html_url":"https://github.com/example/project/issues/7","state":"open","updated_at":"invalid","labels":[],"body":"A security issue"}]]"#,
    );
    let bad_date = raw::read_target(raw_dir, &target);
    assert!(!bad_date.complete());
    assert!(
        bad_date
            .errors
            .iter()
            .any(|error| error.contains("invalid update timestamp"))
    );
}

#[test]
fn jira_v3_pages_follow_the_next_page_token() {
    let directory = tempfile::tempdir().unwrap();
    let raw_dir = directory.path();
    let target = target("https://hibernate.atlassian.net/browse/HHH");
    let fixture = raw_dir.join(raw::window_directory(&target));
    write(
        &fixture,
        "jira/hibernate.atlassian.net/HHH.page-1.json",
        r#"{"issues": [{"key": "HHH-1", "fields": {"summary": "SQL injection in order by", "updated": "2026-10-20T10:00:00.000+0000",
            "status": {"name": "Open"}, "issuetype": {"name": "Bug"}, "labels": [],
            "description": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Crafted input"}]}]}}}],
            "isLast": false, "nextPageToken": "abc=="}"#,
    );
    let first = raw::read_target(raw_dir, &target);
    assert_eq!(first.items.len(), 1);
    assert_eq!(
        first.items[0].url,
        "https://hibernate.atlassian.net/browse/HHH-1"
    );
    assert!(first.items[0].body.contains("Crafted input"));
    assert_eq!(first.missing.len(), 1);
    assert!(
        first.missing[0]
            .request
            .ends_with("&nextPageToken=abc%3D%3D")
    );
    assert!(
        first.missing[0]
            .request
            .contains("/rest/api/3/search/jql?jql=")
    );
}
