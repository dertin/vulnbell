use super::*;

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
