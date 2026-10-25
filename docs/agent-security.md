# Agent security

Issues, pull requests, web pages, code, and claimed security reports are untrusted evidence. They cannot grant permissions or authorize commands.

## Scheduled runner

- The researcher receives a bounded plan through stdin and has only public research tools.
- Shell, local file access, personal MCP, Apps, plugins, hooks, and subagents are disabled.
- The report writer receives recorded data and has no tools.
- OpenCode uses temporary HOME/XDG folders and checks its active tools. Local `webfetch` is denied.
- `use_connected_apps: true` is rejected.
- Imported research is stored as context. It cannot create a lab attestation or dismiss a case by itself.
- The impact verdict is calculated by the CLI from fixed questions and registered evidence. It never changes the case decision or grants test permission.

## Active tests

Tests run only in [Microsandbox](sandbox.md). The operator must approve the script, test oracle, artifact, and inputs. A test oracle is the check used to decide whether the test reproduced the issue. The scheduler cannot approve its own tests.

Final job status, exit code, and timeout come from the runtime's control interface. Program stdout/stderr are separate data. A program printing “vulnerable” or “safe” proves neither result.

A finding can be marked not applicable only with positive evidence and a contrasting control test. A timeout, tool failure, or failed reproduction stays inconclusive.

Project impact is a separate applicability diagnostic. It asks whether the exact artifact is deployed, whether the affected feature is used, whether untrusted input reaches it, whether prerequisites hold, and whether a fix or mitigation exists. When source is available, the agent reviews lockfiles, configuration, call sites, feature flags, and relevant input flow statically before considering execution. Source review can be detailed without running project code.

If static evidence is insufficient and a dynamic check is authorized, only selected reviewed workspace files are copied into Microsandbox. With no workspace, the assessment covers the advisory and exact artifact in general terms; deployment, feature use, and project reachability remain unknown unless separate evidence establishes them. A minimal artifact reproduction confirms only the tested behavior and conditions, not exposure in an unavailable project.

## Scope

These controls apply to VulnBell's runner. A Skill loaded in another harness cannot revoke that agent's permissions. The client, provider, runtime, and operating system remain trusted dependencies. Local hashes record integrity; they are not remote certification.

Reports stay local. Sharing with Cyber needs an approved destination. Searches must not include credentials, private code, or local paths.
