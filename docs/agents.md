# Agents

The Skill uses the Agent Skills format and installs to `~/.agents/skills/vulnbell`. The local agent reviews public evidence and available project source. The CLI preserves the inventory, evidence references, impact answers, sandbox attestations, and rendered reports across supported adapters.

Scheduled runs support two adapters:

| Agent | Client version | Setup |
|---|---|---|
| Codex | 0.164.0 | Local login and absolute executable path; optional model |
| OpenCode | 1.19.4 | Absolute executable path and `agent_model: provider/model` |

Switching adapters keeps the same inventory, cases, evidence, and reports. The researcher receives its plan through stdin and returns JSON. The report writer receives recorded data and returns Markdown. Format, provider, or permission errors produce a report marked as partial. Scheduled reports currently use Spanish.

## Codex

Uses the local client's login. Personal configuration, MCP, Apps, hooks, plugins, and local tools are disabled. Only the researcher has web tools. The report writer has no tools.

## OpenCode

Uses temporary HOME and XDG folders, `--pure` mode, and deny-by-default permissions. It checks the active configuration and tools before calling the model. Research allows only remote web search. `webfetch`, shell, files, MCP, plugins, and subagents are disabled. The CLI's HTTPS connector handles direct capture of public URLs.

The runner accepts API credentials for the selected provider from OpenCode's local authentication file. It also accepts providers that need no credentials. It does not import OAuth sessions or organization settings. The provider must have enough quota.

```sh
opencode --version
opencode models
opencode auth login
```

Choose a model listed by `opencode models` that your account can access. There is no automatic fallback to a free provider.

## Other agents

Other agents can use the Skill and CLI interactively. Scheduled use needs an adapter with the same input/output contract and permission checks. An arbitrary executable is not an isolated runner.
