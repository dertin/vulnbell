//! Layout and parsing of the provider responses the agent fetches with `gh` and `curl` into a
//! run's raw directory. Each research target maps to one provider directory; a missing or
//! incomplete response is reported with the file and API resource still needed.
use super::{Item, ItemKind};
use crate::research::ResearchTarget;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::LazyLock,
};

const MAX_RAW_FILE: u64 = 64 * 1024 * 1024;
const MAX_RAW_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_JSON_VALUES: u64 = 300_000;
const MAX_PAGES: usize = 50;

mod forge;
mod github;
mod jira;
#[cfg(test)]
mod tests;

use forge::{read_forgejo, read_gitlab};
use github::{github_issues, github_linked_discussion, read_github};
use jira::read_jira;

static CLOSES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+(?:(https://[^\s)#]+/(?:-/)?issues/)|((?:[a-z0-9_.-]+/)*[a-z0-9_.-]+)?#)(\d+)",
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
    /// `gh api <request>` for one numbered REST page.
    GhRest,
    /// `gh api <request>` for one identified issue, without pagination.
    GhRestSingle,
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
    /// Linked tracker items outside the activity window, used as context only.
    pub linked_issues: Vec<Item>,
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

/// Aggregate input limit for one research batch.
pub struct RawBudget {
    remaining: u64,
    remaining_values: u64,
}

impl Default for RawBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_RAW_TOTAL,
            remaining_values: MAX_JSON_VALUES,
        }
    }
}

struct RawReader<'a> {
    root: &'a Path,
    budget: &'a mut RawBudget,
}

pub fn read_target(raw: &Path, target: &ResearchTarget) -> TargetItems {
    read_target_with_budget(raw, target, &mut RawBudget::default())
}

/// Directory for responses acquired for this exact upstream and review window.
pub fn window_directory(target: &ResearchTarget) -> PathBuf {
    let key = format!(
        "{}:{}{}:{}{}:{}",
        target.upstream.len(),
        target.upstream,
        target.from.len(),
        target.from,
        target.until.len(),
        target.until
    );
    PathBuf::from("windows").join(crate::digest(key.as_bytes()))
}

/// Reads source responses within the shared batch budget.
pub fn read_target_with_budget(
    raw: &Path,
    target: &ResearchTarget,
    budget: &mut RawBudget,
) -> TargetItems {
    let window = window_directory(target);
    let root = raw.join(&window);
    let mut reader = RawReader {
        root: &root,
        budget,
    };
    let raw = &mut reader;
    let provider = provider_for(&target.upstream);
    let mut result = TargetItems {
        method: String::new(),
        provider: provider.clone(),
        missing: Vec::new(),
        errors: Vec::new(),
        items: Vec::new(),
        linked_issues: Vec::new(),
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
    read_linked_issues(raw, target, &provider, &mut result);
    for missing in &mut result.missing {
        missing.path = crate::slash_path(&window.join(&missing.path));
    }
    result
}

fn read_linked_issues(
    raw: &mut RawReader<'_>,
    target: &ResearchTarget,
    provider: &Provider,
    result: &mut TargetItems,
) {
    let (prefix, web_base, api_base, tool) = match provider {
        Provider::GitHub {
            owner, repository, ..
        } => {
            let prefix = format!("{owner}/{repository}");
            (
                prefix.clone(),
                format!("https://github.com/{prefix}/"),
                format!("repos/{prefix}/issues"),
                FetchTool::GhRestSingle,
            )
        }
        Provider::GitLab { host, project } => (
            project.clone(),
            format!("https://{host}/{project}/"),
            format!(
                "https://{host}/api/v4/projects/{}/issues",
                crate::sources::encode(project)
            ),
            FetchTool::Curl,
        ),
        Provider::Forgejo {
            host,
            owner,
            repository,
        } => {
            let prefix = format!("{owner}/{repository}");
            (
                prefix.clone(),
                format!("https://{host}/{prefix}/"),
                format!("https://{host}/api/v1/repos/{prefix}/issues"),
                FetchTool::Curl,
            )
        }
        Provider::Jira { .. } | Provider::Manual { .. } => return,
    };
    let present: BTreeSet<String> = result
        .items
        .iter()
        .filter(|item| {
            item.kind == super::ItemKind::Issue
                || (matches!(provider, Provider::GitHub { .. })
                    && item.kind == super::ItemKind::PullRequest)
        })
        .map(|item| item.key.clone())
        .collect();
    let links: BTreeSet<String> = result
        .items
        .iter()
        .filter(|item| item.kind.is_proposed_change())
        .flat_map(|item| item.closes.iter().cloned())
        .filter(|key| !present.contains(key))
        .collect();
    for key in links {
        let local = key.strip_prefix(&format!("{prefix}#")).filter(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        });
        let (issue_prefix, issue_web_base, issue_api_base, number, cross_repository) =
            if let Some(number) = local {
                (
                    prefix.clone(),
                    web_base.clone(),
                    api_base.clone(),
                    number.to_owned(),
                    false,
                )
            } else if matches!(provider, Provider::GitHub { .. }) {
                let Some((repository, number)) = github_issue_reference(&key) else {
                    record_manual_github_issue(raw, target, &key, result);
                    continue;
                };
                (
                    repository.clone(),
                    format!("https://github.com/{repository}/"),
                    format!("repos/{repository}/issues"),
                    number,
                    true,
                )
            } else {
                result.errors.push(format!(
                    "cross-repository reference requires manual research: {}",
                    super::truncate_chars(&key, 300)
                ));
                continue;
            };
        let path = result
            .provider
            .directory()
            .join("linked-issues")
            .join(if cross_repository {
                PathBuf::from(&issue_prefix).join(format!("{number}.json"))
            } else {
                PathBuf::from(format!("{number}.json"))
            });
        let values = match read_values(raw, &path) {
            Ok(Some(values)) => values,
            Ok(None) => {
                result.missing.push(MissingFetch {
                    upstream: target.upstream.clone(),
                    path: relative(&path),
                    tool,
                    request: format!("{issue_api_base}/{number}"),
                });
                continue;
            }
            Err(error) => {
                result.errors.push(format!("{}: {error}", relative(&path)));
                continue;
            }
        };
        if matches!(provider, Provider::GitHub { .. })
            && values.len() == 1
            && values[0].get("data").is_some()
        {
            match github_linked_discussion(values[0].clone(), &issue_prefix, &number) {
                Ok(mut discussion) => {
                    discussion.key = key;
                    result.linked_issues.push(discussion);
                }
                Err(error) => result.errors.push(format!("{}: {error}", relative(&path))),
            }
            continue;
        }
        let parsed = if matches!(provider, Provider::GitLab { .. }) {
            rest_records(values).and_then(|records| {
                records
                    .into_iter()
                    .map(|record| {
                        let issue: GitLabIssue = serde_json::from_value(record)?;
                        let updated_at = time(Some(&issue.updated_at))
                            .context("linked issue has an invalid timestamp")?;
                        Ok(Item {
                            key: format!("{prefix}#{}", issue.iid),
                            kind: ItemKind::Issue,
                            url: issue.web_url,
                            title: issue.title,
                            state: issue.state,
                            labels: issue.labels,
                            updated_at,
                            body: body(issue.description),
                            closes: Vec::new(),
                            advisory: None,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
        } else {
            github_issues(values, &issue_prefix, &issue_web_base)
        };
        match parsed {
            Ok(mut issues)
                if issues.len() == 1
                    && issues[0].key == format!("{issue_prefix}#{number}")
                    && (issues[0].kind == super::ItemKind::Issue
                        || (matches!(provider, Provider::GitHub { .. })
                            && issues[0].kind == super::ItemKind::PullRequest)) =>
            {
                let mut issue = issues.remove(0);
                let resource = if issue.kind == super::ItemKind::PullRequest {
                    "pull"
                } else {
                    "issues"
                };
                if (cross_repository || matches!(provider, Provider::GitHub { .. }))
                    && issue.url != format!("{issue_web_base}{resource}/{number}")
                {
                    result.errors.push(format!(
                        "{}: linked response URL does not identify the requested issue",
                        relative(&path)
                    ));
                    continue;
                }
                issue.key = key;
                result.linked_issues.push(issue)
            }
            Ok(_) => result.errors.push(format!(
                "{}: linked response does not identify the requested issue",
                relative(&path)
            )),
            Err(error) => result.errors.push(format!("{}: {error}", relative(&path))),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualGitHubIssue {
    reference: String,
    rationale: String,
    issue: Value,
}

fn record_manual_github_issue(
    raw: &mut RawReader<'_>,
    target: &ResearchTarget,
    key: &str,
    result: &mut TargetItems,
) {
    let directory = result.provider.directory();
    match manually_resolved_github_issue(raw, &directory, key) {
        Ok(Some(issue)) => {
            if !result.method.contains("manual linked issue resolutions") {
                result
                    .method
                    .push_str("; manual linked issue resolutions recorded in raw");
            }
            result.linked_issues.push(issue);
        }
        Ok(None) => {
            let path = window_directory(target).join(manual_resolution_path(&directory, key));
            result.errors.push(format!(
                "cross-repository reference requires manual research: {}; resolution: {}",
                super::truncate_chars(key, 300),
                relative(&path)
            ));
        }
        Err(error) => result.errors.push(format!(
            "manual linked issue {}: {error}",
            super::truncate_chars(key, 300)
        )),
    }
}

fn manual_resolution_path(directory: &Path, key: &str) -> PathBuf {
    directory
        .join("linked-issues/manual")
        .join(format!("{}.json", crate::digest(key.as_bytes())))
}

fn manually_resolved_github_issue(
    raw: &mut RawReader<'_>,
    directory: &Path,
    key: &str,
) -> Result<Option<Item>> {
    let path = manual_resolution_path(directory, key);
    let Some(values) = read_values(raw, &path)? else {
        return Ok(None);
    };
    if values.len() != 1 {
        bail!("expected one manual resolution");
    }
    let resolution: ManualGitHubIssue =
        serde_json::from_value(values.into_iter().next().context("missing resolution")?)?;
    if resolution.reference != key
        || resolution.rationale.trim().is_empty()
        || resolution.rationale.len() > 4000
    {
        bail!("manual resolution requires the exact reference and a bounded rationale");
    }
    let url = resolution
        .issue
        .get("html_url")
        .and_then(Value::as_str)
        .context("missing issue URL")?;
    let (repository, number) = github_issue_reference(url).context("invalid GitHub issue URL")?;
    let expected_number = key
        .rsplit_once('#')
        .map(|(_, number)| number)
        .context("missing reference number")?;
    if number != expected_number {
        bail!("manual issue number does not match the reference");
    }
    let base = format!("https://github.com/{repository}/");
    let mut issues = github_issues(vec![resolution.issue], &repository, &base)?;
    if issues.len() != 1
        || issues[0].kind != ItemKind::Issue
        || issues[0].url != format!("{base}issues/{number}")
        || issues[0].key != format!("{repository}#{number}")
    {
        bail!("manual response does not identify the selected GitHub issue");
    }
    let mut issue = issues.remove(0);
    issue.key = key.to_owned();
    Ok(Some(issue))
}

fn github_issue_reference(key: &str) -> Option<(String, String)> {
    let (repository, number) = if key.starts_with("https://") {
        let url = url::Url::parse(key).ok()?;
        if url.scheme() != "https"
            || url.host_str() != Some("github.com")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let parts: Vec<&str> = url.path_segments()?.collect();
        if parts.len() != 4 || parts[2] != "issues" {
            return None;
        }
        (format!("{}/{}", parts[0], parts[1]), parts[3].to_owned())
    } else {
        let (repository, number) = key.split_once('#')?;
        (repository.to_owned(), number.to_owned())
    };
    let mut parts = repository.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some()
        || owner.len() > 100
        || name.len() > 100
        || !safe(owner)
        || !safe(name)
        || number.is_empty()
        || number.len() > 20
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((repository, number))
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

fn relative(path: &Path) -> String {
    crate::slash_path(path)
}

/// `Ok(None)` when the agent has not written the file yet.
fn read_values(raw: &mut RawReader<'_>, relative: &Path) -> Result<Option<Vec<Value>>> {
    let path = raw.root.join(relative);
    if !path.exists() {
        return Ok(None);
    }
    let limit = MAX_RAW_FILE.min(raw.budget.remaining);
    if limit == 0 {
        bail!("raw response budget exhausted");
    }
    let bytes = crate::read_limited(&path, limit)
        .context("raw response exceeds the remaining input budget")?;
    raw.budget.remaining -= bytes.len() as u64;
    let values = count_json_values(&bytes, raw.budget.remaining_values)?;
    raw.budget.remaining_values -= values;
    let mut values = Vec::new();
    for value in serde_json::Deserializer::from_slice(&bytes).into_iter::<Value>() {
        values.push(value.with_context(|| format!("{} is not JSON", relative.display()))?);
    }
    if values.is_empty() {
        bail!("{} is an empty response file", relative.display());
    }
    Ok(Some(values))
}

fn count_json_values(bytes: &[u8], limit: u64) -> Result<u64> {
    let mut count = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_literal = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => {
                in_string = true;
                count += 1;
                in_literal = false;
            }
            b'{' | b'[' => {
                count += 1;
                in_literal = false;
            }
            b']' | b'}' | b',' | b':' | b' ' | b'\n' | b'\r' | b'\t' => in_literal = false,
            _ if !in_literal => {
                count += 1;
                in_literal = true;
            }
            _ => {}
        }
        if count > limit {
            bail!("raw response exceeds the remaining JSON value budget");
        }
    }
    Ok(count)
}

/// Flattens REST records and rejects provider error objects.
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
    text.unwrap_or_default()
}

fn time(value: Option<&str>) -> Option<String> {
    value.and_then(super::normalize_time)
}

/// Keys of issues named in closing references.
fn closes(text: &str, web_base: &str, key_prefix: &str) -> Vec<String> {
    let mut keys: Vec<String> = CLOSES
        .captures_iter(text)
        .filter(|captures| captures[3].bytes().any(|byte| byte != b'0'))
        .map(|captures| {
            let number = &captures[3];
            if let Some(url) = captures.get(1) {
                let base = url.as_str();
                if base == format!("{web_base}issues/") || base == format!("{web_base}-/issues/") {
                    format!("{key_prefix}#{number}")
                } else {
                    format!("{base}{number}")
                }
            } else if let Some(repository) = captures.get(2) {
                if key_prefix.rsplit('/').next() == Some(repository.as_str()) {
                    format!("{key_prefix}#{number}")
                } else {
                    format!("{}#{number}", repository.as_str())
                }
            } else {
                format!("{key_prefix}#{number}")
            }
        })
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

#[derive(Deserialize)]
struct GitHubLabel {
    name: String,
}
#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: Option<String>,
    html_url: String,
    published_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    body: Option<String>,
    #[serde(default)]
    draft: bool,
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
struct PagedFile {
    name: &'static str,
    page_size: usize,
}

/// Records of every page read, or the missing page that must be fetched next.
fn read_pages(
    raw: &mut RawReader<'_>,
    directory: &Path,
    paged: &PagedFile,
    request: impl Fn(usize) -> String,
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
        records.extend(page_records);
        if !full {
            return Some(records);
        }
    }
    result
        .errors
        .push(format!("{}: more than {MAX_PAGES} pages", paged.name));
    None
}

fn read_manual(raw: &mut RawReader<'_>, target: &ResearchTarget, result: &mut TargetItems) {
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
        item.advisory = None;
        result.items.push(item);
    }
}
