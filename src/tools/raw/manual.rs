use super::{
    Item, ItemKind, RawReader, ResearchTarget, TargetItems, github_issues,
    github_linked_discussion, read_values, relative, safe, window_directory,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualGitHubIssue {
    reference: String,
    rationale: String,
    issue: Value,
}

pub(super) fn record_manual_github_issue(
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
                crate::tools::truncate_chars(key, 300),
                relative(&path)
            ));
        }
        Err(error) => result.errors.push(format!(
            "manual linked issue {}: {error}",
            crate::tools::truncate_chars(key, 300)
        )),
    }
}

pub(super) fn manual_resolution_path(directory: &Path, key: &str) -> PathBuf {
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
    let discussion = resolution.issue.get("data").is_some();
    let url = (if discussion {
        resolution.issue.pointer("/data/repository/discussion/url")
    } else {
        resolution.issue.get("html_url")
    })
    .and_then(Value::as_str)
    .context("missing issue URL")?;
    let issue_url = url
        .replace("/discussions/", "/issues/")
        .replace("/pull/", "/issues/");
    let (repository, number) =
        github_issue_reference(&issue_url).context("invalid GitHub issue URL")?;
    let expected_number = github_issue_reference(key)
        .map(|(_, number)| number)
        .or_else(|| key.rsplit_once('#').map(|(_, number)| number.to_owned()))
        .context("missing reference number")?;
    if number != expected_number {
        bail!("manual issue number does not match the reference");
    }
    let base = format!("https://github.com/{repository}/");
    let mut issue = if discussion {
        github_linked_discussion(resolution.issue, &repository, &number)?
            .context("manual discussion does not identify the selected GitHub reference")?
    } else {
        let mut issues = github_issues(vec![resolution.issue], &repository, &base)?;
        if issues.len() != 1 {
            bail!("manual response does not identify the selected GitHub issue");
        }
        let issue = issues.remove(0);
        let resource = if issue.kind == ItemKind::PullRequest {
            "pull"
        } else {
            "issues"
        };
        if issue.url != format!("{base}{resource}/{number}")
            || issue.key != format!("{repository}#{number}")
        {
            bail!("manual response does not identify the selected GitHub issue");
        }
        issue
    };
    issue.key = key.to_owned();
    Ok(Some(issue))
}

pub(super) fn github_issue_reference(key: &str) -> Option<(String, String)> {
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
