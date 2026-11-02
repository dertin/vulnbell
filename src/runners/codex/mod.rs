use super::{AgentAdapter, AgentRole, Request, SourceAccess, base_command};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{path::Path, process::Command};

pub(super) const TESTED_VERSION: &str = "0.166.0";

pub(super) struct CodexAdapter<'a> {
    pub executable: &'a Path,
    pub model: Option<&'a str>,
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

#[derive(Default)]
struct ToolBindings<'a> {
    github: Option<(&'a Path, &'a str)>,
    codebase: Option<CodebaseBinding<'a>>,
}

struct CodebaseBinding<'a> {
    executable: &'a Path,
    project: &'a Path,
    data_root: &'a Path,
    receipt: &'a Path,
}

impl CodexAdapter<'_> {
    fn capabilities(&self, directory: &Path) -> Result<Vec<McpServer>> {
        let mut version = base_command(self.executable, directory);
        version.arg("--version");
        let version = crate::process::run_bounded_agent(&mut version, 5, 4096)?;
        let expected = format!("codex-cli {TESTED_VERSION}");
        if !version.success || String::from_utf8_lossy(&version.stdout).trim() != expected {
            bail!(
                "Codex adapter requires tested version {TESTED_VERSION}; revalidate isolation before upgrading"
            );
        }
        // An empty MCP table can merge with inherited entries, so every configured server is
        // discovered without starting it and explicitly disabled on the real invocation.
        let mut list = base_command(self.executable, directory);
        list.args(["--disable", "plugins", "mcp", "list", "--json"]);
        let result = crate::process::run_bounded_agent(&mut list, 15, 1024 * 1024)?;
        if !result.success {
            bail!("cannot establish the Codex MCP deny list; research not started");
        }
        Ok(serde_json::from_slice(&result.stdout)?)
    }

    fn command(
        &self,
        directory: &Path,
        output: &Path,
        schema: Option<&Path>,
        role: AgentRole,
        mcp_servers: &[McpServer],
        bindings: ToolBindings<'_>,
    ) -> Command {
        let mut command = base_command(self.executable, directory);
        let research = matches!(role, AgentRole::PublicResearch);
        let source_review = matches!(role, AgentRole::CodebaseReview);
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
        if !research && !source_review {
            command.args(["--disable", "code_mode_host"]);
        }
        for server in mcp_servers {
            let name = toml::Value::String(server.name.clone()).to_string();
            command
                .arg("-c")
                .arg(format!("mcp_servers.{name}.enabled=false"));
            let (key, value) = match &server.transport {
                McpTransport::Stdio => ("command", "/__vulnbell_disabled__"),
                McpTransport::StreamableHttp => ("url", "https://disabled.invalid"),
            };
            command.arg("-c").arg(format!(
                "mcp_servers.{name}.{key}={}",
                toml::Value::String(value.to_owned())
            ));
        }
        if let Some((executable, upstream)) = bindings.github.filter(|_| research) {
            let server_name = (0..)
                .map(|index| format!("vulnbell_github_{index}"))
                .find(|name| mcp_servers.iter().all(|server| server.name != *name))
                .expect("an unoccupied server name exists");
            let executable = toml::Value::String(executable.to_string_lossy().into_owned());
            let args = toml::Value::Array(vec![
                toml::Value::String("runner-github".into()),
                toml::Value::String("--upstream".into()),
                toml::Value::String(upstream.into()),
            ]);
            command
                .arg("-c")
                .arg(format!("mcp_servers.{server_name}.enabled=true"));
            command
                .arg("-c")
                .arg(format!("mcp_servers.{server_name}.command={executable}"));
            command
                .arg("-c")
                .arg(format!("mcp_servers.{server_name}.args={args}"));
            command
                .arg("-c")
                .arg(format!("mcp_servers.{server_name}.startup_timeout_sec=45"));
            command.arg("-c").arg(format!(
                "mcp_servers.{server_name}.enabled_tools=[\"github_read\"]"
            ));
            command.arg("-c").arg(format!(
                "mcp_servers.{server_name}.tools.github_read.approval_mode=\"approve\""
            ));
            command.arg("-c").arg(format!(
                "mcp_servers.{server_name}.tools.github_read.output_token_limit=30000"
            ));
            for key in ["GH_CONFIG_DIR", "XDG_CONFIG_HOME"] {
                if let Some(value) = std::env::var_os(key) {
                    command.arg("-c").arg(format!(
                        "mcp_servers.{server_name}.env.{key}={}",
                        toml::Value::String(value.to_string_lossy().into_owned())
                    ));
                }
            }
            command.arg("-c").arg("mcp_optional_startup_grace_ms=0");
        }
        if let Some(CodebaseBinding {
            executable,
            project,
            data_root,
            receipt,
        }) = bindings.codebase.filter(|_| source_review)
        {
            let server_name = (0..)
                .map(|index| format!("vulnbell_codebase_{index}"))
                .find(|name| mcp_servers.iter().all(|server| server.name != *name))
                .expect("an unoccupied server name exists");
            let executable = toml::Value::String(executable.to_string_lossy().into_owned());
            let args = toml::Value::Array(vec![
                toml::Value::String("runner-codebase".into()),
                toml::Value::String("--project".into()),
                toml::Value::String(project.to_string_lossy().into_owned()),
                toml::Value::String("--receipt".into()),
                toml::Value::String(receipt.to_string_lossy().into_owned()),
            ]);
            for setting in [
                format!("mcp_servers.{server_name}.enabled=true"),
                format!("mcp_servers.{server_name}.command={executable}"),
                format!("mcp_servers.{server_name}.args={args}"),
                format!("mcp_servers.{server_name}.startup_timeout_sec=45"),
                format!(
                    "mcp_servers.{server_name}.enabled_tools=[\"codebase_list\",\"codebase_read\",\"codebase_search\",\"codebase_symbols\"]"
                ),
                format!(
                    "mcp_servers.{server_name}.env.VULNBELL_DATA_DIR={}",
                    toml::Value::String(data_root.to_string_lossy().into_owned())
                ),
            ] {
                command.arg("-c").arg(setting);
            }
            for tool in [
                "codebase_list",
                "codebase_read",
                "codebase_search",
                "codebase_symbols",
            ] {
                command.arg("-c").arg(format!(
                    "mcp_servers.{server_name}.tools.{tool}.approval_mode=\"approve\""
                ));
                command.arg("-c").arg(format!(
                    "mcp_servers.{server_name}.tools.{tool}.output_token_limit=30000"
                ));
            }
            command.arg("-c").arg("mcp_optional_startup_grace_ms=0");
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
        if let Some(model) = self.model {
            command.arg("--model").arg(model);
        }
        command.arg("-");
        command
    }
}

impl AgentAdapter for CodexAdapter<'_> {
    fn check(&self, directory: &Path) -> Result<()> {
        self.capabilities(directory)?;
        Ok(())
    }

    fn execute(&self, request: Request<'_>) -> Result<()> {
        let source = SourceAccess::for_request(&request)?;
        let mcp_servers = self.capabilities(request.directory)?;
        let tool_executable = std::env::current_exe()?;
        let github = request.github_upstream.filter(|upstream| {
            matches!(
                crate::tools::raw::provider_for(upstream),
                crate::tools::raw::Provider::GitHub { mirror: false, .. }
            )
        });
        let mut command = self.command(
            request.directory,
            request.output,
            request.schema,
            request.role,
            &mcp_servers,
            ToolBindings {
                github: github.map(|upstream| (tool_executable.as_path(), upstream)),
                codebase: source.as_ref().map(|scope| CodebaseBinding {
                    executable: tool_executable.as_path(),
                    project: &scope.project,
                    data_root: &scope.data_root,
                    receipt: &scope.receipt,
                }),
            },
        );
        let process = crate::process::run_agent_with_input(
            &mut command,
            request.seconds,
            8 * 1024 * 1024,
            request.prompt.as_bytes(),
        )?;
        crate::atomic_write(request.log, &process.stdout)?;
        crate::atomic_write(&request.log.with_extension("stderr"), &process.stderr)?;
        if !process.success {
            bail!(
                "Codex adapter failed or exceeded its execution window; inspect private job logs"
            );
        }
        if let Some(source) = source {
            source.verify()?;
        }
        let bytes = crate::read_limited(request.output, 2 * 1024 * 1024)
            .context("Codex adapter exited without a readable output artifact")?;
        if bytes.is_empty() {
            bail!("Codex adapter produced an empty result");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
