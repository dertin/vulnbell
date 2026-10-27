//! Layout and parsing of the provider responses the agent fetches with `gh` and `curl` into a
//! run's raw directory. Each research target maps to one provider directory; a missing or
//! incomplete response is reported with the file and API resource still needed.
use super::{AdvisoryPackage, BODY_LIMIT, Item, ItemKind, RepositoryAdvisory};
use crate::research::ResearchTarget;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::LazyLock,
};

const MAX_RAW_FILE: u64 = 256 * 1024 * 1024;
const MAX_PAGES: usize = 50;
const JIRA_FIELDS: &str = "summary,updated,status,issuetype,labels,priority,description";

static CLOSES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+(#|https://[^\s)#]+/issues/)(\d+)",
    )
    .expect("static closing-keyword pattern")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JiraApi {
    /// `/rest/api/2/search` with `startAt` offsets.
    SearchV2,
    /// `/rest/api/3/search/jql` with `nextPageToken`.
    SearchJqlV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    /// `mirror` is set for Apache gitbox repositories, whose issues and pull requests live on
    /// their official GitHub mirror.
    GitHub {
        owner: String,
        repository: String,
        mirror: bool,
    },
    GitLab {
        host: String,
        project: String,
    },
    Forgejo {
        host: String,
        owner: String,
        repository: String,
    },
    Jira {
        api: JiraApi,
        base: String,
        host: String,
        project: String,
    },
    /// No supported response format; the agent writes normalized items for this tracker.
    Manual {
        host: String,
        directory: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FetchTool {
    /// `gh api --paginate --slurp <request>`.
    GhRest,
    /// `gh api graphql --paginate --slurp` with the discussion search query in `request`.
    GhGraphqlDiscussions,
    /// `curl -fsS <request>`.
    Curl,
    /// The agent reviews `request` with its own tools and writes normalized items.
    Agent,
}

#[derive(Debug, Clone, Serialize)]
pub struct MissingFetch {
    pub upstream: String,
    /// Path relative to the raw directory.
    pub path: String,
    pub tool: FetchTool,
    pub request: String,
}

#[derive(Debug, Clone)]
pub struct TargetItems {
    pub provider: Provider,
    pub method: String,
    pub missing: Vec<MissingFetch>,
    pub errors: Vec<String>,
    /// Items updated inside the target window.
    pub items: Vec<Item>,
    /// Advisory IDs and CVEs of every advisory the repository has published, inside the window or not.
    pub published_identifiers: BTreeSet<String>,
}

impl TargetItems {
    pub fn complete(&self) -> bool {
        self.missing.is_empty() && self.errors.is_empty()
    }
}

impl Provider {
    /// Name recorded as the research event provider.
    pub fn event_provider(&self) -> &str {
        match self {
            Self::GitHub { .. } => "github",
            Self::GitLab { host, .. }
            | Self::Forgejo { host, .. }
            | Self::Jira { host, .. }
            | Self::Manual { host, .. } => host,
        }
    }

    pub fn directory(&self) -> PathBuf {
        match self {
            Self::GitHub {
                owner, repository, ..
            } => Path::new("github").join(owner).join(repository),
            Self::GitLab { host, project } => Path::new("gitlab").join(host).join(project),
            Self::Forgejo {
                host,
                owner,
                repository,
            } => Path::new("forgejo").join(host).join(owner).join(repository),
            Self::Jira { host, .. } => Path::new("jira").join(host),
            Self::Manual { directory, .. } => PathBuf::from(directory),
        }
    }
}

pub fn provider_for(upstream: &str) -> Provider {
    let Ok(url) = url::Url::parse(upstream) else {
        return manual("unknown", &[]);
    };
    let host = url.host_str().unwrap_or("unknown").to_ascii_lowercase();
    let segments: Vec<&str> = url
        .path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
        .unwrap_or_default();
    match host.as_str() {
        "github.com" => match segments.as_slice() {
            [owner, repository, ..] if safe(owner) && safe(repository.trim_end_matches(".git")) => {
                Provider::GitHub {
                    owner: (*owner).to_owned(),
                    repository: repository.trim_end_matches(".git").to_owned(),
                    mirror: false,
                }
            }
            _ => manual(&host, &segments),
        },
        "gitbox.apache.org" | "git-wip-us.apache.org" => {
            let from_query = url
                .query_pairs()
                .find(|(key, _)| key == "p")
                .map(|(_, value)| value.into_owned());
            let name = from_query
                .or_else(|| segments.last().map(|segment| (*segment).to_owned()))
                .unwrap_or_default();
            let name = name
                .split(';')
                .next()
                .unwrap_or_default()
                .trim_end_matches(".git")
                .to_owned();
            if safe(&name) {
                Provider::GitHub {
                    owner: "apache".into(),
                    repository: name,
                    mirror: true,
                }
            } else {
                manual(&host, &segments)
            }
        }
        "codeberg.org" => match segments.as_slice() {
            [owner, repository, ..] if safe(owner) && safe(repository) => Provider::Forgejo {
                host,
                owner: (*owner).to_owned(),
                repository: (*repository).to_owned(),
            },
            _ => manual(&host, &segments),
        },
        "issues.apache.org" => jira(
            JiraApi::SearchV2,
            "https://issues.apache.org/jira",
            &host,
            &segments,
        ),
        "issues.redhat.com" | "issues.jboss.org" | "jira.jboss.org" => jira(
            JiraApi::SearchJqlV3,
            "https://redhat.atlassian.net",
            "redhat.atlassian.net",
            &segments,
        ),
        _ if host.ends_with(".atlassian.net") => {
            let base = format!("https://{host}");
            jira(JiraApi::SearchJqlV3, &base, &host, &segments)
        }
        _ if host == "gitlab.com" || host.starts_with("gitlab.") => {
            let project: Vec<&str> = segments
                .iter()
                .copied()
                .take_while(|segment| *segment != "-")
                .filter(|segment| *segment != "issues" && *segment != "merge_requests")
                .collect();
            if project.len() >= 2 && project.iter().all(|segment| safe(segment)) {
                Provider::GitLab {
                    host,
                    project: project.join("/"),
                }
            } else {
                manual(&host, &segments)
            }
        }
        _ => manual(&host, &segments),
    }
}

fn jira(api: JiraApi, base: &str, host: &str, segments: &[&str]) -> Provider {
    let project = segments
        .windows(2)
        .find(|pair| pair[0] == "browse" || pair[0] == "projects")
        .map(|pair| pair[1].split('-').next().unwrap_or_default())
        .filter(|key| {
            key.chars()
                .next()
                .is_some_and(|first| first.is_ascii_uppercase())
                && key
                    .chars()
                    .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
        });
    match project {
        Some(project) => Provider::Jira {
            api,
            base: base.to_owned(),
            host: host.to_owned(),
            project: project.to_owned(),
        },
        None => manual(host, segments),
    }
}

fn manual(host: &str, segments: &[&str]) -> Provider {
    let mut directory = PathBuf::from("manual").join(sanitize(host));
    for segment in segments {
        directory.push(sanitize(segment));
    }
    Provider::Manual {
        host: host.to_owned(),
        directory: directory.to_string_lossy().into_owned(),
    }
}

fn safe(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn sanitize(segment: &str) -> String {
    let cleaned: String = segment
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "._-".contains(character) {
                character
            } else {
                '_'
            }
        })
        .collect();
    if safe(&cleaned) { cleaned } else { "_".into() }
}

/// Reads every response the target needs and keeps the items updated inside its window.
pub fn read_target(raw: &Path, target: &ResearchTarget) -> TargetItems {
    let provider = provider_for(&target.upstream);
    let mut result = TargetItems {
        method: String::new(),
        provider: provider.clone(),
        missing: Vec::new(),
        errors: Vec::new(),
        items: Vec::new(),
        published_identifiers: BTreeSet::new(),
    };
    match &provider {
        Provider::GitHub {
            owner,
            repository,
            mirror,
        } => read_github(raw, target, owner, repository, *mirror, &mut result),
        Provider::GitLab { host, project } => read_gitlab(raw, target, host, project, &mut result),
        Provider::Forgejo {
            host,
            owner,
            repository,
        } => read_forgejo(raw, target, host, owner, repository, &mut result),
        Provider::Jira {
            api, base, project, ..
        } => read_jira(raw, target, *api, base, project, &mut result),
        Provider::Manual { .. } => read_manual(raw, target, &mut result),
    }
    result
        .items
        .retain(|item| super::in_window(&item.updated_at, &target.from, &target.until));
    result
}

fn utc_z(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|time| {
            time.with_timezone(&Utc)
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_owned())
}

fn before(value: &str, limit: &str) -> bool {
    match (
        DateTime::parse_from_rfc3339(value),
        DateTime::parse_from_rfc3339(limit),
    ) {
        (Ok(value), Ok(limit)) => value < limit,
        _ => false,
    }
}

fn relative(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `Ok(None)` when the agent has not written the file yet.
fn read_values(raw: &Path, relative: &Path) -> Result<Option<Vec<Value>>> {
    let path = raw.join(relative);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = crate::read_limited(&path, MAX_RAW_FILE)?;
    let mut values = Vec::new();
    for value in serde_json::Deserializer::from_slice(&bytes).into_iter::<Value>() {
        values.push(value.with_context(|| format!("{} is not JSON", relative.display()))?);
    }
    Ok(Some(values))
}

/// REST list responses as `gh --paginate` prints them: one array per page, or one array of page
/// arrays with `--slurp`. An object with a `message` is an error response.
fn rest_records(values: Vec<Value>) -> Result<Vec<Value>> {
    fn collect(value: Value, records: &mut Vec<Value>) -> Result<()> {
        match value {
            Value::Array(items) => {
                for item in items {
                    collect(item, records)?;
                }
            }
            Value::Object(object)
                if object.contains_key("message") && !object.contains_key("id") =>
            {
                let message = object
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("error response");
                bail!(
                    "provider returned an error: {}",
                    super::truncate_chars(message, 200)
                );
            }
            object @ Value::Object(_) => records.push(object),
            _ => bail!("unexpected JSON value in a list response"),
        }
        Ok(())
    }
    let mut records = Vec::new();
    for value in values {
        collect(value, &mut records)?;
    }
    Ok(records)
}

fn body(text: Option<String>) -> String {
    super::truncate_chars(text.as_deref().unwrap_or_default(), BODY_LIMIT)
}

fn time(value: Option<&str>) -> Option<String> {
    value.and_then(super::normalize_time)
}

/// Keys of issues closed by closing keywords, as `#N` or a full link into the same repository.
fn closes(text: &str, web_base: &str, key_prefix: &str) -> Vec<String> {
    let mut keys: Vec<String> = CLOSES
        .captures_iter(text)
        .filter(|captures| &captures[1] == "#" || captures[1].starts_with(web_base))
        .map(|captures| format!("{key_prefix}#{}", &captures[2]))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn read_github(
    raw: &Path,
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
            "issues.json",
            FetchTool::GhRest,
            format!(
                "repos/{prefix}/issues?state=all&since={since}&per_page=100&sort=updated&direction=desc"
            ),
        ),
        (
            "releases.json",
            FetchTool::GhRest,
            format!("repos/{prefix}/releases?per_page=100"),
        ),
        (
            "security-advisories.json",
            FetchTool::GhRest,
            format!("repos/{prefix}/security-advisories?per_page=100"),
        ),
        (
            "discussions.json",
            FetchTool::GhGraphqlDiscussions,
            format!("repo:{prefix} updated:>={since}"),
        ),
    ];
    for (file, tool, request) in requests {
        let path = directory.join(file);
        let values = match read_values(raw, &path) {
            Ok(Some(values)) => values,
            Ok(None) => {
                result.missing.push(MissingFetch {
                    upstream: target.upstream.clone(),
                    path: relative(&path),
                    tool,
                    request,
                });
                continue;
            }
            Err(error) => {
                result.errors.push(format!("{}: {error}", relative(&path)));
                continue;
            }
        };
        let parsed = match file {
            "issues.json" => github_issues(values, &prefix, &web_base),
            "releases.json" => github_releases(values, &prefix),
            "security-advisories.json" => github_advisories(values, &prefix, result),
            _ => github_discussions(values, &prefix),
        };
        match parsed {
            Ok(items) => result.items.extend(items),
            Err(error) => result.errors.push(format!("{}: {error}", relative(&path))),
        }
    }
}

#[derive(Deserialize)]
struct GitHubLabel {
    name: String,
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

fn github_issues(values: Vec<Value>, prefix: &str, web_base: &str) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for record in rest_records(values)? {
        let issue: GitHubIssue = serde_json::from_value(record)?;
        let Some(updated_at) = time(Some(&issue.updated_at)) else {
            continue;
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

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: Option<String>,
    html_url: String,
    published_at: Option<String>,
    created_at: Option<String>,
    body: Option<String>,
    #[serde(default)]
    draft: bool,
}

fn github_releases(values: Vec<Value>, prefix: &str) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for record in rest_records(values)? {
        let release: GitHubRelease = serde_json::from_value(record)?;
        if release.draft {
            continue;
        }
        let moment = release
            .published_at
            .as_deref()
            .or(release.created_at.as_deref());
        let Some(updated_at) = time(moment) else {
            continue;
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
            continue;
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
    for page in pages {
        if let Some(errors) = page.get("errors") {
            bail!(
                "GraphQL errors: {}",
                super::truncate_chars(&errors.to_string(), 200)
            );
        }
        let nodes = page
            .pointer("/data/search/nodes")
            .and_then(Value::as_array)
            .context("GraphQL page without data.search.nodes")?;
        for node in nodes {
            if node.get("number").is_none() {
                continue;
            }
            let discussion: Discussion = serde_json::from_value(node.clone())?;
            let Some(updated_at) = time(Some(&discussion.updated_at)) else {
                continue;
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
    Ok(items)
}

/// Pages `<name>.page-1.json`, `<name>.page-2.json`, ... read until the first missing file.
struct PagedFile {
    name: &'static str,
    page_size: usize,
    /// Releases list oldest last and ignore the window; later pages are needed only while the
    /// last item read is not older than the window start.
    stop_before_from: bool,
}

/// Records of every page read, or the missing page that must be fetched next.
fn read_pages(
    raw: &Path,
    directory: &Path,
    paged: &PagedFile,
    request: impl Fn(usize) -> String,
    moment: impl Fn(&Value) -> Option<String>,
    target: &ResearchTarget,
    result: &mut TargetItems,
) -> Option<Vec<Value>> {
    let mut records = Vec::new();
    for page in 1..=MAX_PAGES {
        let path = directory.join(format!("{}.page-{page}.json", paged.name));
        let values = match read_values(raw, &path) {
            Ok(Some(values)) => values,
            Ok(None) => {
                result.missing.push(MissingFetch {
                    upstream: target.upstream.clone(),
                    path: relative(&path),
                    tool: FetchTool::Curl,
                    request: request(page),
                });
                return None;
            }
            Err(error) => {
                result.errors.push(format!("{}: {error}", relative(&path)));
                return None;
            }
        };
        let page_records = match rest_records(values) {
            Ok(page_records) => page_records,
            Err(error) => {
                result.errors.push(format!("{}: {error}", relative(&path)));
                return None;
            }
        };
        let full = page_records.len() >= paged.page_size;
        let older = paged.stop_before_from
            && page_records
                .last()
                .and_then(&moment)
                .is_some_and(|last| before(&last, &target.from));
        records.extend(page_records);
        if !full || older {
            return Some(records);
        }
    }
    result
        .errors
        .push(format!("{}: more than {MAX_PAGES} pages", paged.name));
    None
}

#[derive(Deserialize)]
struct GitLabIssue {
    iid: u64,
    title: String,
    web_url: String,
    state: String,
    updated_at: String,
    #[serde(default)]
    labels: Vec<String>,
    description: Option<String>,
}
#[derive(Deserialize)]
struct GitLabRelease {
    tag_name: String,
    name: Option<String>,
    released_at: Option<String>,
    created_at: Option<String>,
    description: Option<String>,
}

fn read_gitlab(
    raw: &Path,
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
    let updated = |value: &Value| time(value.get("updated_at").and_then(Value::as_str));
    for (name, kind, separator) in [
        ("issues", ItemKind::Issue, "#"),
        ("merge_requests", ItemKind::MergeRequest, "!"),
    ] {
        let paged = PagedFile {
            name,
            page_size: 100,
            stop_before_from: false,
        };
        let request = |page: usize| {
            format!(
                "{api}/{name}?scope=all&updated_after={from}&updated_before={until}&per_page=100&page={page}"
            )
        };
        let Some(records) = read_pages(raw, &directory, &paged, request, updated, target, result)
        else {
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
        stop_before_from: true,
    };
    let released = |value: &Value| {
        time(
            value
                .get("released_at")
                .or_else(|| value.get("created_at"))
                .and_then(Value::as_str),
        )
    };
    let request = |page: usize| format!("{api}/releases?per_page=100&page={page}");
    let Some(records) = read_pages(raw, &directory, &paged, request, released, target, result)
    else {
        return;
    };
    for record in records {
        let release: GitLabRelease = match serde_json::from_value(record) {
            Ok(release) => release,
            Err(error) => {
                result.errors.push(format!("releases: {error}"));
                return;
            }
        };
        let moment = release
            .released_at
            .as_deref()
            .or(release.created_at.as_deref());
        let Some(updated_at) = time(moment) else {
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

fn read_forgejo(
    raw: &Path,
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
        stop_before_from: false,
    };
    let updated = |value: &Value| time(value.get("updated_at").and_then(Value::as_str));
    let request = |page: usize| {
        format!("{api}/issues?state=all&since={from}&before={until}&limit=50&page={page}")
    };
    if let Some(records) = read_pages(raw, &directory, &paged, request, updated, target, result) {
        for record in records {
            let issue: ForgejoIssue = match serde_json::from_value(record) {
                Ok(issue) => issue,
                Err(error) => {
                    result.errors.push(format!("issues: {error}"));
                    break;
                }
            };
            let Some(updated_at) = time(Some(&issue.updated_at)) else {
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
        stop_before_from: true,
    };
    let published = |value: &Value| {
        time(
            value
                .get("published_at")
                .or_else(|| value.get("created_at"))
                .and_then(Value::as_str),
        )
    };
    let request = |page: usize| format!("{api}/releases?limit=50&page={page}");
    let Some(records) = read_pages(raw, &directory, &paged, request, published, target, result)
    else {
        return;
    };
    for record in records {
        let release: GitHubRelease = match serde_json::from_value(record) {
            Ok(release) => release,
            Err(error) => {
                result.errors.push(format!("releases: {error}"));
                return;
            }
        };
        let moment = release
            .published_at
            .as_deref()
            .or(release.created_at.as_deref());
        let Some(updated_at) = time(moment) else {
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
}

#[derive(Deserialize)]
struct JiraName {
    name: String,
}
#[derive(Deserialize)]
struct JiraFields {
    #[serde(default)]
    summary: String,
    updated: Option<String>,
    status: Option<JiraName>,
    issuetype: Option<JiraName>,
    priority: Option<JiraName>,
    #[serde(default)]
    labels: Vec<String>,
    description: Option<Value>,
}
#[derive(Deserialize)]
struct JiraIssue {
    key: String,
    fields: JiraFields,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JiraPage {
    #[serde(default)]
    issues: Vec<JiraIssue>,
    #[serde(default)]
    start_at: usize,
    #[serde(default)]
    total: usize,
    #[serde(default = "default_true")]
    is_last: bool,
    next_page_token: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Plain text of a Jira description: a string (REST v2) or an Atlassian Document (REST v3).
fn jira_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Object(node) => {
            let mut text = node
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if let Some(Value::Array(children)) = node.get("content") {
                for child in children {
                    text.push(' ');
                    text.push_str(&jira_text(child));
                }
            }
            text
        }
        Value::Array(children) => children.iter().map(jira_text).collect::<Vec<_>>().join(" "),
        _ => String::new(),
    }
}

fn read_jira(
    raw: &Path,
    target: &ResearchTarget,
    api: JiraApi,
    base: &str,
    project: &str,
    result: &mut TargetItems,
) {
    let directory = result.provider.directory();
    result.method = format!(
        "Jira REST search of project {project} on {base}, updated in the window with a one-day margin, filtered on fields.updated"
    );
    let day = |value: &str, offset: i64| {
        DateTime::parse_from_rfc3339(value)
            .map(|time| {
                (time + Duration::days(offset))
                    .format("%Y-%m-%d")
                    .to_string()
            })
            .unwrap_or_default()
    };
    let jql = format!(
        "project = \"{project}\" AND updated >= \"{}\" AND updated <= \"{}\" ORDER BY updated DESC",
        day(&target.from, -1),
        day(&target.until, 1)
    );
    let query = format!(
        "jql={}&fields={JIRA_FIELDS}&maxResults=100",
        crate::sources::encode(&jql)
    );
    let mut token: Option<String> = None;
    for page in 1..=MAX_PAGES {
        let path = directory.join(format!("{project}.page-{page}.json"));
        let request = match api {
            JiraApi::SearchV2 => format!(
                "{base}/rest/api/2/search?{query}&startAt={}",
                (page - 1) * 100
            ),
            JiraApi::SearchJqlV3 => match &token {
                Some(token) => format!(
                    "{base}/rest/api/3/search/jql?{query}&nextPageToken={}",
                    crate::sources::encode(token)
                ),
                None => format!("{base}/rest/api/3/search/jql?{query}"),
            },
        };
        let values = match read_values(raw, &path) {
            Ok(Some(values)) => values,
            Ok(None) => {
                result.missing.push(MissingFetch {
                    upstream: target.upstream.clone(),
                    path: relative(&path),
                    tool: FetchTool::Curl,
                    request,
                });
                return;
            }
            Err(error) => {
                result.errors.push(format!("{}: {error}", relative(&path)));
                return;
            }
        };
        let Some(value) = values.into_iter().next() else {
            result
                .errors
                .push(format!("{}: empty response file", relative(&path)));
            return;
        };
        if let Some(messages) = value.get("errorMessages") {
            result.errors.push(format!(
                "{}: Jira error {}",
                relative(&path),
                super::truncate_chars(&messages.to_string(), 200)
            ));
            return;
        }
        let parsed: JiraPage = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                result.errors.push(format!("{}: {error}", relative(&path)));
                return;
            }
        };
        let read = parsed.issues.len();
        for issue in parsed.issues {
            let Some(updated_at) = time(issue.fields.updated.as_deref()) else {
                continue;
            };
            let mut labels = issue.fields.labels;
            labels.extend(
                [issue.fields.issuetype, issue.fields.priority]
                    .into_iter()
                    .flatten()
                    .map(|name| name.name),
            );
            result.items.push(Item {
                url: format!("{base}/browse/{}", issue.key),
                key: issue.key,
                kind: ItemKind::Issue,
                title: issue.fields.summary,
                state: issue
                    .fields
                    .status
                    .map(|status| status.name)
                    .unwrap_or_default(),
                labels,
                updated_at,
                body: body(issue.fields.description.as_ref().map(jira_text)),
                closes: Vec::new(),
                advisory: None,
            });
        }
        let more = match api {
            JiraApi::SearchV2 => read > 0 && parsed.start_at + read < parsed.total,
            JiraApi::SearchJqlV3 => {
                token = parsed.next_page_token;
                !parsed.is_last && token.is_some()
            }
        };
        if !more {
            return;
        }
    }
    result
        .errors
        .push(format!("{project}: more than {MAX_PAGES} pages"));
}

fn read_manual(raw: &Path, target: &ResearchTarget, result: &mut TargetItems) {
    let path = result.provider.directory().join("items.json");
    result.method = format!("agent review of {} with its own tools", target.upstream);
    let values = match read_values(raw, &path) {
        Ok(Some(values)) => values,
        Ok(None) => {
            result.missing.push(MissingFetch {
                upstream: target.upstream.clone(),
                path: relative(&path),
                tool: FetchTool::Agent,
                request: target.upstream.clone(),
            });
            return;
        }
        Err(error) => {
            result.errors.push(format!("{}: {error}", relative(&path)));
            return;
        }
    };
    let parsed: Result<Vec<Item>> = values
        .into_iter()
        .map(|value| Ok(serde_json::from_value::<Vec<Item>>(value)?))
        .collect::<Result<Vec<Vec<Item>>>>()
        .map(|pages| pages.into_iter().flatten().collect());
    let items = match parsed {
        Ok(items) => items,
        Err(error) => {
            result.errors.push(format!("{}: {error}", relative(&path)));
            return;
        }
    };
    for mut item in items {
        let checked = crate::profile::public_https_syntax(&item.url).is_ok()
            && !item.key.trim().is_empty()
            && item.key.len() <= 300;
        let Some(updated_at) = super::normalize_time(&item.updated_at).filter(|_| checked) else {
            result.errors.push(format!(
                "{}: item {} needs a key, a public HTTPS URL and an RFC3339 updated_at",
                relative(&path),
                super::truncate_chars(&item.key, 80)
            ));
            continue;
        };
        item.updated_at = updated_at;
        item.body = super::truncate_chars(&item.body, BODY_LIMIT);
        item.advisory = None;
        result.items.push(item);
    }
}
