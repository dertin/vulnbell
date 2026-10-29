use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

mod codex;
mod opencode;

const CONFIG_LIMIT: u64 = 64 * 1024;
const INPUT_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    pub schema_version: u32,
    pub id: String,
    pub adapter: AdapterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdapterConfig {
    Codex {
        executable: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    },
    #[serde(rename = "opencode")]
    OpenCode { executable: PathBuf, model: String },
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RunnerSummary {
    pub id: String,
    pub adapter: String,
    pub executable: PathBuf,
    pub tested_version: String,
    pub configuration: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct RunnerCheck {
    pub schema_version: u32,
    pub id: String,
    pub adapter: String,
    pub tested_version: String,
    pub ready: bool,
    /// Result of the opt-in live probe; `None` when only isolation and version were checked.
    pub web_research: Option<bool>,
    pub reason: Option<String>,
}

const PROBE_URL: &str = "https://example.com/";
const PROBE_TITLE: &str = "Example Domain";
const PROBE_SECONDS: u64 = 240;

#[derive(Deserialize)]
struct ProbeAnswer {
    reachable: bool,
    title: String,
    detail: String,
}

#[derive(Debug, Serialize)]
pub struct AdapterInfo {
    pub name: &'static str,
    pub tested_version: &'static str,
    pub transport: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) enum AgentRole {
    PublicResearch,
    ToolFree,
}

#[derive(Clone, Copy)]
pub(crate) struct Request<'a> {
    pub directory: &'a Path,
    pub output: &'a Path,
    pub prompt: &'a str,
    pub schema: Option<&'a Path>,
    pub role: AgentRole,
    pub seconds: u64,
    pub log: &'a Path,
}

trait AgentAdapter {
    fn check(&self, directory: &Path) -> Result<()>;
    fn execute(&self, request: Request<'_>) -> Result<()>;
}

impl RunnerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("unsupported runner schema; expected schema_version 1");
        }
        validate_id(&self.id)?;
        let executable = self.adapter.executable();
        if !executable.is_absolute() {
            bail!("runner executable must be an absolute path");
        }
        match &self.adapter {
            AdapterConfig::Codex { model, .. } => {
                if let Some(model) = model {
                    validate_model(model)?;
                }
            }
            AdapterConfig::OpenCode { model, .. } => {
                validate_model(model)?;
                if !model
                    .split_once('/')
                    .is_some_and(|(provider, model)| !provider.is_empty() && !model.is_empty())
                {
                    bail!("OpenCode requires model in provider/model format");
                }
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> Result<RunnerSummary> {
        self.validate()?;
        Ok(RunnerSummary {
            id: self.id.clone(),
            adapter: self.adapter.name().to_owned(),
            executable: self.adapter.executable().to_owned(),
            tested_version: self.adapter.tested_version().to_owned(),
            configuration: config_path(&self.id)?,
        })
    }
}

impl AdapterConfig {
    fn name(&self) -> &'static str {
        match self {
            Self::Codex { .. } => "codex",
            Self::OpenCode { .. } => "opencode",
        }
    }

    fn executable(&self) -> &Path {
        match self {
            Self::Codex { executable, .. } | Self::OpenCode { executable, .. } => executable,
        }
    }

    fn tested_version(&self) -> &'static str {
        match self {
            Self::Codex { .. } => codex::TESTED_VERSION,
            Self::OpenCode { .. } => opencode::TESTED_VERSION,
        }
    }
}

pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        bail!("runner id must contain 1..64 characters");
    }
    if !id.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    }) || !id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
    {
        bail!(
            "runner id must start with a letter or number and use lowercase letters, numbers, '-' or '_'"
        );
    }
    Ok(())
}

fn validate_model(model: &str) -> Result<()> {
    if model.is_empty()
        || model.len() > 200
        || !model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._:-".contains(&byte))
    {
        bail!("runner model must be a bounded model identifier");
    }
    Ok(())
}

fn directory() -> PathBuf {
    crate::store::data_root().join("runners")
}

pub fn config_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(directory().join(format!("{id}.json")))
}

pub fn save(config: &RunnerConfig) -> Result<RunnerSummary> {
    config.validate()?;
    let directory = directory();
    if directory.is_symlink() {
        bail!("runner configuration directory cannot be a symlink");
    }
    fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    crate::atomic_write(
        &config_path(&config.id)?,
        &serde_json::to_vec_pretty(config)?,
    )?;
    config.summary()
}

pub fn load(id: &str) -> Result<RunnerConfig> {
    let path = config_path(id)?;
    let config: RunnerConfig = serde_json::from_slice(&crate::read_limited(&path, CONFIG_LIMIT)?)?;
    config.validate()?;
    if config.id != id {
        bail!("runner configuration id does not match its file name");
    }
    Ok(config)
}

pub fn list() -> Result<Vec<RunnerSummary>> {
    let directory = directory();
    if !directory.exists() {
        return Ok(Vec::new());
    }
    if directory.is_symlink() || !directory.is_dir() {
        bail!("runner configuration directory must be a real directory");
    }
    let mut summaries = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let id = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .context("runner configuration file name must be UTF-8")?
            .to_owned();
        summaries.push(load(&id)?.summary()?);
    }
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(summaries)
}

/// Checks version and isolation; with `live`, also runs one public research request, because
/// an isolated runner can start correctly yet have no working web tool.
pub fn check(id: &str, live: bool) -> Result<RunnerCheck> {
    let config = load(id)?;
    let temporary = tempfile::tempdir()?;
    adapter(&config).check(temporary.path())?;
    let (web_research, reason) = if live {
        match probe(id, temporary.path()) {
            Ok(()) => (Some(true), None),
            Err(error) => (Some(false), Some(error.to_string())),
        }
    } else {
        (None, None)
    };
    Ok(RunnerCheck {
        schema_version: 1,
        id: config.id,
        adapter: config.adapter.name().to_owned(),
        tested_version: config.adapter.tested_version().to_owned(),
        ready: web_research != Some(false),
        web_research,
        reason,
    })
}

fn probe(id: &str, directory: &Path) -> Result<()> {
    let schema = directory.join("probe.schema.json");
    crate::atomic_write(
        &schema,
        &serde_json::to_vec(&serde_json::json!({
            "type": "object",
            "properties": {
                "reachable": {"type": "boolean"},
                "title": {"type": "string"},
                "detail": {"type": "string"}
            },
            "required": ["reachable", "title", "detail"],
            "additionalProperties": false
        }))?,
    )?;
    let output = directory.join("probe.json");
    let prompt = format!(
        "Connectivity probe. Use your web tool to open {PROBE_URL} and return its HTML <title> in `title`. \
         Set `reachable` to false and explain in `detail` if any tool is unavailable or fails. Do not guess the title."
    );
    execute(
        id,
        Request {
            directory,
            output: &output,
            prompt: &prompt,
            schema: Some(&schema),
            role: AgentRole::PublicResearch,
            seconds: PROBE_SECONDS,
            log: &directory.join("probe.log"),
        },
    )?;
    probe_result(&crate::read_limited(&output, 64 * 1024)?)
}

fn probe_result(bytes: &[u8]) -> Result<()> {
    let answer: ProbeAnswer =
        serde_json::from_slice(bytes).context("probe answer does not match its schema")?;
    if !answer.reachable || !answer.title.contains(PROBE_TITLE) {
        let detail: String = answer
            .detail
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect();
        bail!("web research unavailable through this runner: {detail}");
    }
    Ok(())
}

pub fn adapter_catalog() -> Vec<AdapterInfo> {
    vec![
        AdapterInfo {
            name: "codex",
            tested_version: codex::TESTED_VERSION,
            transport: "local_process",
        },
        AdapterInfo {
            name: "opencode",
            tested_version: opencode::TESTED_VERSION,
            transport: "local_process",
        },
    ]
}

pub(crate) fn execute(id: &str, request: Request<'_>) -> Result<()> {
    if request.prompt.len() > INPUT_LIMIT {
        bail!(
            "audited agent input exceeds 4 MiB; split monitor scope; no data was silently truncated"
        );
    }
    let config = load(id).with_context(|| format!("cannot load configured runner '{id}'"))?;
    adapter(&config).execute(request)
}

fn adapter(config: &RunnerConfig) -> Box<dyn AgentAdapter + '_> {
    match &config.adapter {
        AdapterConfig::Codex { executable, model } => Box::new(codex::CodexAdapter {
            executable,
            model: model.as_deref(),
        }),
        AdapterConfig::OpenCode { executable, model } => {
            Box::new(opencode::OpenCodeAdapter { executable, model })
        }
    }
}

fn base_command(executable: &Path, directory: &Path) -> Command {
    let mut command = Command::new(executable);
    command.env_clear().current_dir(directory);
    for key in [
        "HOME",
        "USERPROFILE",
        "CODEX_HOME",
        "PATH",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "LANG",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

#[cfg(test)]
mod tests;
