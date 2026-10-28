use super::{
    FetchTool, JiraApi, MAX_PAGES, MissingFetch, RawReader, TargetItems, body, read_values,
    relative, time,
};
use crate::research::ResearchTarget;
use crate::tools::{Item, ItemKind};
use chrono::{DateTime, Duration};
use serde::Deserialize;
use serde_json::Value;

const JIRA_FIELDS: &str = "summary,updated,status,issuetype,labels,priority,description";

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

pub(super) fn read_jira(
    raw: &mut RawReader<'_>,
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
                crate::tools::truncate_chars(&messages.to_string(), 200)
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
                result.errors.push(format!(
                    "{}: Jira item has an invalid update timestamp",
                    relative(&path)
                ));
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
