use super::{AgentAdapter, Request, base_command};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{path::Path, process::Command};

pub(super) const TESTED_VERSION: &str = "0.164.0";

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
        mcp_servers: &[McpServer],
    ) -> Command {
        let mut command = base_command(self.executable, directory);
        let research = schema.is_some();
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
        let mcp_servers = self.capabilities(request.directory)?;
        let mut command = self.command(
            request.directory,
            request.output,
            request.schema,
            &mcp_servers,
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
