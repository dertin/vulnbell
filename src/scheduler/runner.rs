use super::{AgentRunner, ScheduleConfig};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{path::Path, process::Command};
mod opencode;

fn base_command(config: &ScheduleConfig, directory: &Path) -> Command {
    let mut command = Command::new(&config.agent_executable);
    command.env_clear().current_dir(directory);
    // Authentication stays with the trusted client. The model gets no filesystem tool or shell.
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
#[derive(Deserialize)]
struct McpServer {
    name: String,
    transport: McpTransport,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum McpTransport {
    Stdio,
    StreamableHttp,
}
fn codex_capabilities(config: &ScheduleConfig, directory: &Path) -> Result<Vec<McpServer>> {
    let mut version = base_command(config, directory);
    version.arg("--version");
    let version = crate::process::run_bounded_agent(&mut version, 5, 4096)?;
    if !version.success || String::from_utf8_lossy(&version.stdout).trim() != "codex-cli 0.164.0" {
        bail!(
            "unattended Codex requires tested 0.164.0; revalidate tool isolation before upgrading"
        );
    }
    // An empty mcp_servers table merges with inherited tables; enumerate and explicitly deny every server.
    // Listing config does not start those servers. Plugins are disabled again on the actual invocation.
    let mut list = base_command(config, directory);
    list.args(["--disable", "plugins", "mcp", "list", "--json"]);
    let result = crate::process::run_bounded_agent(&mut list, 15, 1024 * 1024)?;
    if !result.success {
        bail!("cannot establish the Codex MCP deny list; research not started");
    }
    Ok(serde_json::from_slice(&result.stdout)?)
}
fn runner_command(
    config: &ScheduleConfig,
    directory: &Path,
    output: &Path,
    schema: Option<&Path>,
    mcp_servers: &[McpServer],
) -> Result<Command> {
    if config.use_connected_apps {
        bail!("connected Apps are forbidden in unattended research");
    }
    let mut command = base_command(config, directory);
    let research = schema.is_some();
    match config.agent {
        AgentRunner::Codex => {
            command.args([
                "--no-daemon",
                "--strict-config",
                "--ask-for-approval",
                "never",
            ]);
            for feature in [
                "apps",
                "plugins",
                "hooks",
                "shell_tool",
                "unified_exec",
                "code_mode",
                "code_mode_only",
                "code_mode_host",
                "multi_agent",
                "computer_use",
                "browser_use",
                "in_app_browser",
                "image_generation",
                "view_image",
                "memories",
                "skill_search",
                "tool_suggest",
                "remote_plugin",
            ] {
                command.args(["--disable", feature]);
            }
            for server in mcp_servers {
                let name = toml::Value::String(server.name.clone()).to_string();
                command
                    .arg("-c")
                    .arg(format!("mcp_servers.{name}.enabled=false"));
                // Disabled entries still require a valid transport after user config is ignored.
                let (key, value) = match &server.transport {
                    McpTransport::Stdio => ("command", "/__vulnbell_disabled__"),
                    McpTransport::StreamableHttp => ("url", "https://disabled.invalid"),
                };
                command.arg("-c").arg(format!(
                    "mcp_servers.{name}.{key}={}",
                    toml::Value::String(value.to_owned())
                ));
            }
            command
                .args([
                    "-c",
                    "project_doc_max_bytes=0",
                    "-c",
                    "shell_environment_policy.inherit=\"none\"",
                    "-c",
                    if research {
                        "web_search=\"live\""
                    } else {
                        "web_search=\"disabled\""
                    },
                    "exec",
                    "--ignore-user-config",
                    "--ignore-rules",
                    "--sandbox",
                    "read-only",
                    "--skip-git-repo-check",
                    "--ephemeral",
                    "--json",
                    "--output-last-message",
                ])
                .arg(output)
                .arg("-C")
                .arg(directory);
            if let Some(schema) = schema {
                command.arg("--output-schema").arg(schema);
            }
            if let Some(model) = &config.agent_model {
                command.arg("--model").arg(model);
            }
            command.arg("-");
        }
        AgentRunner::OpenCode => bail!("OpenCode uses its isolated JSONL adapter"),
    }
    Ok(command)
}
pub(super) fn execute_agent(
    config: &ScheduleConfig,
    directory: &Path,
    output: &Path,
    prompt: &str,
    schema: Option<&Path>,
    seconds: u64,
    log: &Path,
) -> Result<()> {
    if config.use_connected_apps {
        bail!("connected Apps are forbidden in unattended research");
    }
    if prompt.len() > 4 * 1024 * 1024 {
        bail!(
            "audited agent input exceeds 4 MiB; split monitor scope; no data was silently truncated"
        );
    }
    if matches!(config.agent, AgentRunner::OpenCode) {
        return opencode::execute(config, directory, output, prompt, schema, seconds, log);
    }
    let mcp_servers = codex_capabilities(config, directory)?;
    let mut command = runner_command(config, directory, output, schema, &mcp_servers)?;
    let process = crate::process::run_agent_with_input(
        &mut command,
        seconds,
        8 * 1024 * 1024,
        prompt.as_bytes(),
    )?;
    crate::atomic_write(log, &process.stdout)?;
    crate::atomic_write(&log.with_extension("stderr"), &process.stderr)?;
    if !process.success {
        bail!("agent runner failed or exceeded its execution window; inspect private job logs");
    }
    let bytes = crate::read_limited(output, 2 * 1024 * 1024)
        .context("agent exited without a readable output artifact; inspect private job logs")?;
    if bytes.is_empty() {
        bail!("agent produced an empty result");
    }
    Ok(())
}
#[cfg(test)]
mod tests;
