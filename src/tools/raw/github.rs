use super::{FetchTool, MissingFetch};
use super::{
    GitHubLabel, GitHubRelease, MAX_PAGES, RawReader, TargetItems, body, closes, read_values,
    relative, rest_records, time, utc_z,
};
use crate::research::ResearchTarget;
use crate::tools::{AdvisoryPackage, Item, ItemKind, RepositoryAdvisory};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn read_github(
    raw: &mut RawReader<'_>,
    target: &ResearchTarget,
    owner: &str,
    repository: &str,
    mirror: bool,
    result: &mut TargetItems,
) {
    let directory = result.provider.directory();
    let prefix = format!("{owner}/{repository}");
    let web_base = format!("https://github.com/{prefix}/");
    let mirror_note = if mirror {
        format!("official GitHub mirror github.com/{prefix}: ")
    } else {
        String::new()
    };
    result.method = format!(
        "{mirror_note}GitHub REST issues and pull requests (state=all, since=from, all pages), releases, published repository advisories and discussions updated in the window"
    );
    let since = utc_z(&target.from);
    let requests = [
        (
            "issues",
            format!(
                "repos/{prefix}/issues?state=all&since={since}&per_page=100&sort=updated&direction=desc"
            ),
        ),
        ("releases", format!("repos/{prefix}/releases?per_page=100")),
        (
            "security-advisories",
            format!("repos/{prefix}/security-advisories?per_page=100"),
        ),
    ];
    for (name, request) in requests {
        let mut records = Vec::new();
        let mut complete = false;
        for page in 1..=MAX_PAGES {
            let path = directory.join(format!("{name}.page-{page}.json"));
            let values = match read_values(raw, &path) {
                Ok(Some(values)) => values,
                Ok(None) => {
                    result.missing.push(MissingFetch {
                        upstream: target.upstream.clone(),
                        path: relative(&path),
                        tool: FetchTool::GhRest,
                        request: format!("{request}&page={page}"),
                    });
                    break;
                }
                Err(error) => {
                    result.errors.push(format!("{}: {error}", relative(&path)));
                    break;
                }
            };
            match rest_records(values) {
                Ok(page_records) if page_records.len() <= 100 => {
                    let last_page = page_records.len() < 100;
                    records.extend(page_records);
                    if last_page {
                        complete = true;
                        break;
                    }
                    if page == MAX_PAGES {
                        result
                            .errors
                            .push(format!("{name}: more than {MAX_PAGES} pages"));
                    }
                }
                Ok(_) => {
                    result.errors.push(format!(
                        "{}: REST page exceeds 100 records",
                        relative(&path)
                    ));
                    break;
                }
                Err(error) => {
                    result.errors.push(format!("{}: {error}", relative(&path)));
                    break;
                }
            }
        }
        if !complete {
            continue;
        }
        let parsed = match name {
            "issues" => github_issues(records, &prefix, &web_base),
            "releases" => github_releases(records, &prefix, result),
            _ => github_advisories(records, &prefix, result),
        };
        match parsed {
            Ok(items) => result.items.extend(items),
            Err(error) => result.errors.push(format!("{name}: {error}")),
        }
    }
    {
        let path = directory.join("discussions.json");
        let request = format!("repo:{prefix} updated:>={since}");
        let values = match read_values(raw, &path) {
            Ok(Some(values)) => values,
            Ok(None) => {
                result.missing.push(MissingFetch {
                    upstream: target.upstream.clone(),
                    path: relative(&path),
                    tool: FetchTool::GhGraphqlDiscussions,
                    request,
                });
                return;
            }
            Err(error) => {
                result.errors.push(format!("{}: {error}", relative(&path)));
                return;
            }
        };
        let parsed = github_discussions(values, &prefix);
        match parsed {
            Ok(items) => result.items.extend(items),
            Err(error) => result.errors.push(format!("{}: {error}", relative(&path))),
        }
    }
}

#[derive(Deserialize)]
struct GitHubIssue {
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

pub(super) fn github_issues(values: Vec<Value>, prefix: &str, web_base: &str) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for record in rest_records(values)? {
        let issue: GitHubIssue = serde_json::from_value(record)?;
        let Some(updated_at) = time(Some(&issue.updated_at)) else {
            bail!("GitHub issue has an invalid update timestamp");
        };
        let text = issue.body.unwrap_or_default();
        items.push(Item {
            key: format!("{prefix}#{}", issue.number),
            kind: if issue.pull_request.is_some() {
                ItemKind::PullRequest
            } else {
                ItemKind::Issue
            },
            url: issue.html_url,
            title: issue.title,
            state: issue.state,
            labels: issue.labels.into_iter().map(|label| label.name).collect(),
            updated_at,
            closes: closes(&text, web_base, prefix),
            body: body(Some(text)),
            advisory: None,
        });
    }
    Ok(items)
}

fn github_releases(
    values: Vec<Value>,
    prefix: &str,
    result: &mut TargetItems,
) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    let mut missing_update = false;
    for record in rest_records(values)? {
        let release: GitHubRelease = serde_json::from_value(record)?;
        if release.draft {
            continue;
        }
        let updated = time(release.updated_at.as_deref());
        missing_update |= updated.is_none();
        let updated_at = updated
            .or_else(|| time(release.published_at.as_deref()))
            .or_else(|| time(release.created_at.as_deref()));
        let Some(updated_at) = updated_at else {
            bail!("GitHub release has no valid publication timestamp");
        };
        items.push(Item {
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
            "GitHub releases lack update timestamps; edits to older releases are not covered"
                .into(),
        );
    }
    Ok(items)
}

#[derive(Deserialize)]
struct GitHubAdvisoryPackage {
    ecosystem: String,
    name: Option<String>,
}
#[derive(Deserialize)]
struct GitHubAdvisoryVulnerability {
    package: Option<GitHubAdvisoryPackage>,
    vulnerable_version_range: Option<String>,
    patched_versions: Option<String>,
}
#[derive(Deserialize)]
struct GitHubRepositoryAdvisory {
    ghsa_id: String,
    cve_id: Option<String>,
    html_url: String,
    summary: String,
    description: Option<String>,
    updated_at: String,
    withdrawn_at: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<GitHubAdvisoryVulnerability>,
}

fn github_advisories(
    values: Vec<Value>,
    prefix: &str,
    result: &mut TargetItems,
) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for record in rest_records(values)? {
        let advisory: GitHubRepositoryAdvisory = serde_json::from_value(record)?;
        if advisory.withdrawn_at.is_some() {
            continue;
        }
        result
            .published_identifiers
            .insert(advisory.ghsa_id.clone());
        if let Some(cve) = &advisory.cve_id {
            result.published_identifiers.insert(cve.clone());
        }
        let Some(updated_at) = time(Some(&advisory.updated_at)) else {
            bail!("GitHub advisory has an invalid update timestamp");
        };
        let packages = advisory
            .vulnerabilities
            .into_iter()
            .filter_map(|vulnerability| {
                let package = vulnerability.package?;
                Some(AdvisoryPackage {
                    ecosystem: package.ecosystem,
                    name: package.name?,
                    vulnerable_range: vulnerability.vulnerable_version_range.unwrap_or_default(),
                    patched: vulnerability.patched_versions.unwrap_or_default(),
                })
            })
            .collect();
        let description = advisory
            .description
            .filter(|text| !text.trim().is_empty())
            .unwrap_or_else(|| advisory.summary.clone());
        items.push(Item {
            key: format!("{prefix}/{}", advisory.ghsa_id),
            kind: ItemKind::Advisory,
            url: advisory.html_url,
            title: format!("{}: {}", advisory.ghsa_id, advisory.summary),
            state: "published".into(),
            labels: Vec::new(),
            updated_at,
            body: body(Some(description)),
            closes: Vec::new(),
            advisory: Some(RepositoryAdvisory {
                ghsa_id: advisory.ghsa_id,
                cve_id: advisory.cve_id,
                packages,
            }),
        });
    }
    Ok(items)
}

#[derive(Deserialize)]
struct DiscussionCategory {
    name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Discussion {
    number: u64,
    title: String,
    url: String,
    updated_at: String,
    body: Option<String>,
    category: Option<DiscussionCategory>,
}

/// GraphQL pages of `search(type: DISCUSSION)`; nodes of other types are empty objects.
fn github_discussions(values: Vec<Value>, prefix: &str) -> Result<Vec<Item>> {
    let mut pages = Vec::new();
    for value in values {
        match value {
            Value::Array(slurped) => pages.extend(slurped),
            page => pages.push(page),
        }
    }
    let mut items = Vec::new();
    let page_count = pages.len();
    let mut cursors = BTreeSet::new();
    let mut expected_discussions = 0_u64;
    for (index, page) in pages.into_iter().enumerate() {
        if let Some(errors) = page.get("errors") {
            bail!(
                "GraphQL errors: {}",
                crate::tools::truncate_chars(&errors.to_string(), 200)
            );
        }
        let nodes = page
            .pointer("/data/search/nodes")
            .and_then(Value::as_array)
            .context("GraphQL page without data.search.nodes")?;
        let count = page
            .pointer("/data/search/discussionCount")
            .and_then(Value::as_u64)
            .context("GraphQL page without discussionCount; refetch using the current query")?;
        expected_discussions = expected_discussions.max(count);
        let more = page
            .pointer("/data/search/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            .context("GraphQL page without pageInfo.hasNextPage; pagination is unverified")?;
        if more {
            let cursor = page
                .pointer("/data/search/pageInfo/endCursor")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .context("GraphQL continuation has no cursor")?;
            if !cursors.insert(cursor.to_owned()) || index + 1 == page_count {
                bail!("GraphQL discussion pagination is incomplete or repeats a cursor");
            }
        } else if index + 1 != page_count {
            bail!("GraphQL discussion pages continue after the terminal page");
        }
        for node in nodes {
            if node.get("number").is_none() {
                continue;
            }
            let discussion: Discussion = serde_json::from_value(node.clone())?;
            let Some(updated_at) = time(Some(&discussion.updated_at)) else {
                bail!("GitHub discussion has an invalid update timestamp");
            };
            items.push(Item {
                key: format!("{prefix}/discussions/{}", discussion.number),
                kind: ItemKind::Discussion,
                url: discussion.url,
                title: discussion.title,
                state: String::new(),
                labels: discussion
                    .category
                    .map(|category| vec![category.name])
                    .unwrap_or_default(),
                updated_at,
                body: body(discussion.body),
                closes: Vec::new(),
                advisory: None,
            });
        }
    }
    if u64::try_from(items.len()).unwrap_or(u64::MAX) < expected_discussions {
        bail!(
            "GraphQL discussion results are incomplete: {} of {expected_discussions}; narrow the time window and refetch",
            items.len()
        );
    }
    Ok(items)
}
