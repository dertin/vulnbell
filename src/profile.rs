use anyhow::{Result, bail};
use packageurl::PackageUrl;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::Path};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: u32,
    pub project_id: Uuid,
    #[schemars(length(min = 1, max = 120))]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workspaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
    #[serde(default)]
    pub discovery: DiscoveryMode,
    #[serde(default)]
    pub research: Research,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
    #[serde(default)]
    pub alerts: Alerts,
    #[serde(default)]
    pub report: Report,
    #[serde(default, skip_serializing_if = "SandboxLimits::is_default")]
    pub sandbox: SandboxLimits,
}
/// Upper bounds a sandbox test may request. Isolation (no network, no host mounts, one CPU,
/// unprivileged user, official digest-pinned images) is not configurable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxLimits {
    #[serde(default = "SandboxLimits::default_input_file_mib")]
    #[schemars(range(min = 1, max = 512))]
    pub max_input_file_mib: u32,
    /// Sum of all inputs of one test; the guest root disk is 2 GiB.
    #[serde(default = "SandboxLimits::default_inputs_mib")]
    #[schemars(range(min = 1, max = 1024))]
    pub max_inputs_mib: u32,
    #[serde(default = "SandboxLimits::default_memory_mib")]
    #[schemars(range(min = 128, max = 4096))]
    pub max_memory_mib: u32,
    #[serde(default = "SandboxLimits::default_timeout_seconds")]
    #[schemars(range(min = 1, max = 600))]
    pub max_timeout_seconds: u64,
}
impl SandboxLimits {
    pub const CAP_INPUT_FILE_MIB: u32 = 512;
    pub const CAP_INPUTS_MIB: u32 = 1024;
    pub const CAP_MEMORY_MIB: u32 = 4096;
    pub const CAP_TIMEOUT_SECONDS: u64 = 600;
    fn default_input_file_mib() -> u32 {
        16
    }
    fn default_inputs_mib() -> u32 {
        64
    }
    fn default_memory_mib() -> u32 {
        512
    }
    fn default_timeout_seconds() -> u64 {
        120
    }
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}
impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_input_file_mib: Self::default_input_file_mib(),
            max_inputs_mib: Self::default_inputs_mib(),
            max_memory_mib: Self::default_memory_mib(),
            max_timeout_seconds: Self::default_timeout_seconds(),
        }
    }
}
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Language of the rendered report and of every rationale the agent records for it. Technical
    /// terms without a common translation in that language stay as they are.
    #[serde(default)]
    pub language: Language,
}
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Es,
}
impl Language {
    /// English name, used in instructions to report-writing agents.
    pub fn name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Es => "Spanish",
        }
    }
}
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    #[default]
    Agent,
    Off,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Component {
    #[serde(rename = "ref")]
    #[schemars(length(min = 1, max = 500))]
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub version: Option<String>,
    #[serde(default)]
    pub usage: Usage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feeds: Vec<Feed>,
}
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Usage {
    #[default]
    Tracked,
    Deployed,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Schedule {
    Daily,
    Weekdays,
    Weekly,
}
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Research {
    #[serde(default)]
    pub web: WebResearch,
    /// Per-monitor review budget. Host agents must stop at the deadline and preserve open work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 120))]
    pub review_budget_minutes: Option<u16>,
    #[serde(default)]
    #[schemars(length(max = 30))]
    pub topics: Vec<String>,
    /// Optional initial activity window (RFC3339), for example a verified monitored release date.
    /// Advisory scans remain independent of this window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_since: Option<String>,
    /// Acquire exact-version release dates from supported official registries for initial windows.
    #[serde(default)]
    pub release_windows: bool,
    /// Tracker exploration scope; advisory checks continue across the full inventory.
    #[serde(default)]
    pub tracker_scope: TrackerScope,
    /// Exact inventory references explicitly selected for deeper tracker research.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 500))]
    pub follow: Vec<String>,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrackerScope {
    #[default]
    Direct,
    All,
}
impl Research {
    pub fn tracks(&self, instance: &crate::model::Instance) -> bool {
        self.tracker_scope == TrackerScope::All
            || instance.provenance.direct == Some(true)
            || self
                .follow
                .iter()
                .any(|reference| reference == &instance.reference)
    }
}
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebResearch {
    Agent,
    #[default]
    Off,
}
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_env: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub kind: FeedKind,
    pub url: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    Csaf,
    Vex,
    Rss,
    Atom,
}
#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub pointer: String,
    pub code: String,
    pub message: String,
}
#[derive(Debug, Serialize)]
pub struct Validation {
    pub schema_version: u32,
    pub valid: bool,
    pub errors: Vec<Diagnostic>,
    pub warnings: Vec<Diagnostic>,
}

pub fn schema() -> serde_json::Value {
    let mut schema =
        serde_json::to_value(schemars::schema_for!(Profile)).expect("schema serializes");
    schema["$id"] = "urn:vulnbell:schema:profile:1".into();
    schema["properties"]["schema"] = serde_json::json!({"const":1});
    schema
}
pub fn load(path: &Path) -> Result<Profile> {
    let bytes = crate::read_limited(path, 1024 * 1024)?;
    let profile: Profile = crate::parse_yaml(&bytes)?;
    let result = validate(&profile);
    if !result.valid {
        bail!("{}", serde_json::to_string(&result)?);
    }
    Ok(profile)
}
pub fn validate(profile: &Profile) -> Validation {
    let mut errors = Vec::new();
    let mut push = |pointer: String, code: &str, message: &str| {
        errors.push(Diagnostic {
            pointer,
            code: code.into(),
            message: message.into(),
        });
    };
    if profile.schema != 1 {
        push("/schema".into(), "unsupported_schema", "Use schema 1");
    }
    if profile.project_id.is_nil() {
        push(
            "/project_id".into(),
            "invalid_uuid",
            "Use the stable UUID generated by init",
        );
    }
    if profile.name.trim().is_empty() || profile.name.chars().count() > 120 {
        push("/name".into(), "invalid_length", "Use 1..120 characters");
    }
    if profile
        .research
        .review_budget_minutes
        .is_some_and(|minutes| !(1..=120).contains(&minutes))
    {
        push(
            "/research/review_budget_minutes".into(),
            "invalid_review_budget",
            "Use 1..120 minutes",
        );
    }
    if let Some(since) = &profile.research.initial_since
        && chrono::DateTime::parse_from_rfc3339(since).is_err()
    {
        push(
            "/research/initial_since".into(),
            "invalid_timestamp",
            "Use an RFC3339 timestamp with timezone",
        );
    }
    if profile.research.follow.len() > 500
        || profile
            .research
            .follow
            .iter()
            .any(|item| item.is_empty() || item.len() > 500 || item.chars().any(char::is_control))
    {
        push(
            "/research/follow".into(),
            "invalid_follow",
            "Use at most 500 nonempty exact inventory references",
        );
    }
    let mut workspaces = HashSet::new();
    for (index, workspace) in profile.workspaces.iter().enumerate() {
        if workspace.is_empty() || !workspaces.insert(workspace) {
            push(
                format!("/workspaces/{index}"),
                "invalid_workspace",
                "Use nonempty unique paths",
            );
        }
    }
    let mut instances = HashSet::new();
    for (index, component) in profile.components.iter().enumerate() {
        let base = format!("/components/{index}");
        if component.reference.is_empty()
            || component.reference.len() > 500
            || component.reference.chars().any(char::is_control)
        {
            push(
                format!("{base}/ref"),
                "invalid_ref",
                "Use a public product alias or unversioned PURL (1..500 bytes)",
            );
        }
        if component.reference.starts_with("pkg:") {
            match component.reference.parse::<PackageUrl<'_>>() {
                Ok(purl)
                    if purl.version().is_none()
                        && purl.qualifiers().is_empty()
                        && purl.subpath().is_none() => {}
                _ => push(
                    format!("{base}/ref"),
                    "invalid_purl",
                    "Use an unversioned PURL without qualifiers/subpath; put version in the version field",
                ),
            }
        }
        if let Some(version) = &component.version
            && (version.is_empty()
                || version.len() > 128
                || version.chars().any(char::is_whitespace)
                || version.chars().any(char::is_control))
        {
            push(
                format!("{base}/version"),
                "invalid_version",
                "Use one exact version or latest; omit unknown versions",
            );
        }
        if !instances.insert((
            &component.reference,
            &component.version,
            &component.upstream,
        )) {
            push(
                base.clone(),
                "duplicate_instance",
                "Remove duplicate component/version/upstream entries",
            );
        }
        if let Some(upstream) = &component.upstream
            && !public_https_syntax(upstream)
                .is_ok_and(|url| url.query().is_none() && url.fragment().is_none())
        {
            push(
                format!("{base}/upstream"),
                "invalid_url",
                "Use a public HTTPS repository without credentials, query or fragment",
            );
        }
        for (feed_index, feed) in component.feeds.iter().enumerate() {
            if public_https_syntax(&feed.url).is_err() {
                push(
                    format!("{base}/feeds/{feed_index}/url"),
                    "invalid_url",
                    "Use a public HTTPS feed without credentials",
                );
            }
        }
    }
    if let Some(variable) = &profile.alerts.webhook_env {
        let valid = variable
            .chars()
            .enumerate()
            .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
        if variable.is_empty() || !valid {
            push(
                "/alerts/webhook_env".into(),
                "invalid_env",
                "Use an environment variable name, never a secret URL",
            );
        }
    }
    if profile.research.topics.len() > 30 {
        push(
            "/research/topics".into(),
            "limit",
            "Use at most 30 public topics",
        );
    }
    let mut topics = HashSet::new();
    for (index, topic) in profile.research.topics.iter().enumerate() {
        if topic.is_empty()
            || topic.len() > 120
            || !topics.insert(topic)
            || topic.contains('/')
            || topic.contains('\\')
            || topic.chars().any(char::is_control)
        {
            push(
                format!("/research/topics/{index}"),
                "invalid_topic",
                "Use unique public topics (1..120 bytes), without paths or secrets",
            );
        }
    }
    let limits = &profile.sandbox;
    if !(1..=SandboxLimits::CAP_INPUT_FILE_MIB).contains(&limits.max_input_file_mib) {
        push(
            "/sandbox/max_input_file_mib".into(),
            "limit",
            "Use 1..512 MiB",
        );
    }
    if !(limits.max_input_file_mib..=SandboxLimits::CAP_INPUTS_MIB).contains(&limits.max_inputs_mib)
    {
        push(
            "/sandbox/max_inputs_mib".into(),
            "limit",
            "Use max_input_file_mib..1024 MiB",
        );
    }
    if !(128..=SandboxLimits::CAP_MEMORY_MIB).contains(&limits.max_memory_mib) {
        push(
            "/sandbox/max_memory_mib".into(),
            "limit",
            "Use 128..4096 MiB",
        );
    }
    if !(1..=SandboxLimits::CAP_TIMEOUT_SECONDS).contains(&limits.max_timeout_seconds) {
        push(
            "/sandbox/max_timeout_seconds".into(),
            "limit",
            "Use 1..600 seconds",
        );
    }
    let warnings = if profile.workspaces.is_empty() && profile.components.is_empty() {
        vec![Diagnostic {
            pointer: "/".into(),
            code: "empty_scope".into(),
            message: "Add components or authorized workspaces before scan".into(),
        }]
    } else {
        Vec::new()
    };
    Validation {
        schema_version: 1,
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}
pub fn public_https_syntax(value: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(value)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        bail!("public HTTPS URL required");
    }
    Ok(parsed)
}
