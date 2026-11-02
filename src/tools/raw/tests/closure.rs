#[test]
fn github_pull_request_closure_requires_provider_evidence() {
    let values = serde_json::json!([
        {"number":1,"title":"open","html_url":"https://github.com/a/b/pull/1","state":"open","updated_at":"2026-10-20T00:00:00Z","pull_request":{}},
        {"number":2,"title":"merged","html_url":"https://github.com/a/b/pull/2","state":"closed","updated_at":"2026-10-20T00:00:00Z","pull_request":{"merged_at":"2026-10-19T00:00:00Z"}},
        {"number":3,"title":"closed","html_url":"https://github.com/a/b/pull/3","state":"closed","updated_at":"2026-10-20T00:00:00Z","pull_request":{"merged_at":null}},
        {"number":4,"title":"unknown","html_url":"https://github.com/a/b/pull/4","state":"closed","updated_at":"2026-10-20T00:00:00Z","pull_request":{}},
        {"number":5,"title":"invalid","html_url":"https://github.com/a/b/pull/5","state":"closed","updated_at":"2026-10-20T00:00:00Z","pull_request":{"merged_at":"invalid"}}
    ]);
    let items = super::super::github::github_issues(vec![values], "a/b", "https://github.com/a/b/")
        .unwrap();
    use crate::tools::PullRequestClosure::{ClosedUnmerged, Merged, Open};
    assert_eq!(
        items.iter().map(|item| item.closure).collect::<Vec<_>>(),
        vec![Some(Open), Some(Merged), Some(ClosedUnmerged), None, None]
    );
}
