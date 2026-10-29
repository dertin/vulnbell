use super::{
    GitHubLabel, GitHubRelease, GitLabIssue, PagedFile, RawReader, TargetItems, body, closes,
    read_pages, time, utc_z,
};
use crate::research::ResearchTarget;
use crate::tools::{Item, ItemKind};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct GitLabRelease {
    tag_name: String,
    name: Option<String>,
    released_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    description: Option<String>,
}

pub(super) fn read_gitlab(
    raw: &mut RawReader<'_>,
    target: &ResearchTarget,
    host: &str,
    project: &str,
    result: &mut TargetItems,
) {
    let directory = result.provider.directory();
    let api = format!(
        "https://{host}/api/v4/projects/{}",
        crate::sources::encode(project)
    );
    let web_base = format!("https://{host}/{project}/");
    result.method = format!(
        "GitLab API v4 {host}/{project}: issues and merge requests updated in the window (all pages), releases"
    );
    let (from, until) = (utc_z(&target.from), utc_z(&target.until));
    for (name, kind, separator) in [
        ("issues", ItemKind::Issue, "#"),
        ("merge_requests", ItemKind::MergeRequest, "!"),
    ] {
        let paged = PagedFile {
            name,
            page_size: 100,
        };
        let request = |page: usize| {
            format!(
                "{api}/{name}?scope=all&updated_after={from}&updated_before={until}&per_page=100&page={page}"
            )
        };
        let Some(records) = read_pages(raw, &directory, &paged, request, target, result) else {
            continue;
        };
        for record in records {
            let issue: GitLabIssue = match serde_json::from_value(record) {
                Ok(issue) => issue,
                Err(error) => {
                    result.errors.push(format!("{name}: {error}"));
                    break;
                }
            };
            let Some(updated_at) = time(Some(&issue.updated_at)) else {
                result
                    .errors
                    .push(format!("{name}: invalid update timestamp"));
                continue;
            };
            let text = issue.description.unwrap_or_default();
            result.items.push(Item {
                key: format!("{project}{separator}{}", issue.iid),
                kind,
                url: issue.web_url,
                title: issue.title,
                state: issue.state,
                labels: issue.labels,
                updated_at,
                closes: closes(&text, &web_base, project),
                body: body(Some(text)),
                advisory: None,
            });
        }
    }
    let paged = PagedFile {
        name: "releases",
        page_size: 100,
    };
    let request = |page: usize| format!("{api}/releases?per_page=100&page={page}");
    let Some(records) = read_pages(raw, &directory, &paged, request, target, result) else {
        return;
    };
    let mut missing_update = false;
    for record in records {
        let release: GitLabRelease = match serde_json::from_value(record) {
            Ok(release) => release,
            Err(error) => {
                result.errors.push(format!("releases: {error}"));
                return;
            }
        };
        let updated = time(release.updated_at.as_deref());
        missing_update |= updated.is_none();
        let updated_at = updated
            .or_else(|| time(release.released_at.as_deref()))
            .or_else(|| time(release.created_at.as_deref()));
        let Some(updated_at) = updated_at else {
            result
                .errors
                .push("GitLab release has no valid publication timestamp".into());
            continue;
        };
        result.items.push(Item {
            key: format!("{project}@{}", release.tag_name),
            kind: ItemKind::Release,
            url: format!("https://{host}/{project}/-/releases/{}", release.tag_name),
            title: release
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| release.tag_name.clone()),
            state: "published".into(),
            labels: Vec::new(),
            updated_at,
            body: body(release.description),
            closes: Vec::new(),
            advisory: None,
        });
    }
    if missing_update {
        result.errors.push(
            "GitLab releases lack update timestamps; edits to older releases are not covered"
                .into(),
        );
    }
}

#[derive(Deserialize)]
struct ForgejoIssue {
    number: u64,
    title: String,
    html_url: String,
    state: String,
    updated_at: String,
    #[serde(default)]
    labels: Vec<GitHubLabel>,
    body: Option<String>,
    pull_request: Option<Value>,
}

pub(super) fn read_forgejo(
    raw: &mut RawReader<'_>,
    target: &ResearchTarget,
    host: &str,
    owner: &str,
    repository: &str,
    result: &mut TargetItems,
) {
    let directory = result.provider.directory();
    let prefix = format!("{owner}/{repository}");
    let api = format!("https://{host}/api/v1/repos/{prefix}");
    let web_base = format!("https://{host}/{prefix}/");
    result.method = format!(
        "Forgejo API {host}/{prefix}: issues and pull requests updated in the window (all pages), releases"
    );
    let (from, until) = (utc_z(&target.from), utc_z(&target.until));
    let paged = PagedFile {
        name: "issues",
        page_size: 50,
    };
    let request = |page: usize| {
        format!("{api}/issues?state=all&since={from}&before={until}&limit=50&page={page}")
    };
    if let Some(records) = read_pages(raw, &directory, &paged, request, target, result) {
        for record in records {
            let issue: ForgejoIssue = match serde_json::from_value(record) {
                Ok(issue) => issue,
                Err(error) => {
                    result.errors.push(format!("issues: {error}"));
                    break;
                }
            };
            let Some(updated_at) = time(Some(&issue.updated_at)) else {
                result
                    .errors
                    .push("Forgejo issue has an invalid update timestamp".into());
                continue;
            };
            let text = issue.body.unwrap_or_default();
            result.items.push(Item {
                key: format!("{prefix}#{}", issue.number),
                kind: if issue.pull_request.is_some_and(|value| !value.is_null()) {
                    ItemKind::PullRequest
                } else {
                    ItemKind::Issue
                },
                url: issue.html_url,
                title: issue.title,
                state: issue.state,
                labels: issue.labels.into_iter().map(|label| label.name).collect(),
                updated_at,
                closes: closes(&text, &web_base, &prefix),
                body: body(Some(text)),
                advisory: None,
            });
        }
    }
    let paged = PagedFile {
        name: "releases",
        page_size: 50,
    };
    let request = |page: usize| format!("{api}/releases?limit=50&page={page}");
    let Some(records) = read_pages(raw, &directory, &paged, request, target, result) else {
        return;
    };
    let mut missing_update = false;
    for record in records {
        let release: GitHubRelease = match serde_json::from_value(record) {
            Ok(release) => release,
            Err(error) => {
                result.errors.push(format!("releases: {error}"));
                return;
            }
        };
        let updated = time(release.updated_at.as_deref());
        missing_update |= updated.is_none();
        let updated_at = updated
            .or_else(|| time(release.published_at.as_deref()))
            .or_else(|| time(release.created_at.as_deref()));
        let Some(updated_at) = updated_at else {
            result
                .errors
                .push("Forgejo release has no valid publication timestamp".into());
            continue;
        };
        result.items.push(Item {
            key: format!("{prefix}@{}", release.tag_name),
            kind: ItemKind::Release,
            url: release.html_url,
            title: release
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| release.tag_name.clone()),
            state: "published".into(),
            labels: Vec::new(),
            updated_at,
            body: body(release.body),
            closes: Vec::new(),
            advisory: None,
        });
    }
    if missing_update {
        result.errors.push(
            "Forgejo releases lack update timestamps; edits to older releases are not covered"
                .into(),
        );
    }
}
