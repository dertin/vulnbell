# Local runners

A runner starts the isolated agent used by scheduled and on-demand monitoring. Runner settings are local to one machine and can be shared by multiple project schedules.

## Configure

Inspect the generated contract, save one of the provided adapter configurations, and verify the installed client:

```sh
vulnbell schema runner --json
vulnbell runners configure --from runner.json
vulnbell runners list --json
vulnbell runners check default --json
```

Runner configurations are stored in `<data directory>/runners/<id>.json`. `vulnbell doctor --json` prints the data directory, configured runners, and available adapters. Credentials remain in the selected client; they do not belong in runner or project files.

## Validated adapters

| Adapter | Tested client | Configuration |
|---|---|---|
| `codex` | Codex CLI 0.166.0 | Absolute executable path; optional model |
| `opencode` | OpenCode 1.19.4 | Absolute executable path; required `provider/model` |

Examples are available in [`examples/runner-codex.json`](../examples/runner-codex.json) and [`examples/runner-opencode.json`](../examples/runner-opencode.json).

Both adapters clear the inherited environment and verify the exact tested client version. Workspace extraction has no tools. Public discovery and research permit public web search without workspace access when the client provides a compatible web tool. The CLI validates structured output separately from the role's permissions and renders reports locally. `runners check` verifies the installed client and capability policy. `runners check <id> --live` also sends one public research request through the runner and exits 2 with `web_research: false` and the reason when the client's web tools do not work, even if the client exits successfully. The Codex adapter enables its code-mode host only for public research; local discovery remains tool-free. Shell tools, inherited MCP servers and write access stay restricted. The probe uses the configured model. Run `vulnbell run --project <profile> --now` to check provider access, credentials, research output, and report delivery together.

A successful web probe does not guarantee access to every site or API. If a source is restricted or unavailable, its coverage remains partial. Scheduled runs do not perform a general static impact review of application code; an interactive agent can inspect the selected codebase and register the evidence.

## Project schedule

The project schedule references a runner by ID:

```json
{
  "schema_version": 2,
  "project_id": "<profile UUID>",
  "runner": "default",
  "timezone": "America/Montevideo",
  "at": "08:00",
  "window_minutes": 180,
  "frequency": "daily",
  "report_dir": "/absolute/path/to/reports"
}
```

Changing the local adapter does not require editing every project schedule. `vulnbell status` reports the selected runner and whether its configuration is available.

## Add an adapter

Adapters are compiled into VulnBell. To add one:

1. Add a typed variant to `AdapterConfig` in `src/runners/mod.rs`.
2. Implement `AgentAdapter::check` and `AgentAdapter::execute` in a dedicated module.
3. Register the adapter in the dispatcher and adapter catalog.
4. Enforce an exact tested client version, cleared environment, bounded input/output, no project shell or filesystem tools, public-web-only research, and tool-free workspace extraction. Select permissions from `AgentRole`, independently of the output schema.
5. Add configuration, permission, malformed-output, timeout, provider-failure, and live ignored acceptance tests.
6. Regenerate `schemas/runner.schema.json` and update the validated-adapter table.

An arbitrary executable is not accepted as a generic adapter. Remote/API adapters and cloud report delivery are not currently supported.
