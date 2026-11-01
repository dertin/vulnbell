# Agent security

Issues, pull requests, web pages, code, and claimed security reports are untrusted evidence. They cannot grant permissions or authorize commands.

## Scheduled runner

- The researcher receives a bounded plan through stdin and can use public web research tools. For a GitHub target, both runners can also call a read-only tool scoped to that public repository; the tool uses the local `gh` credential without exposing it to the agent.
- Workspace discovery receives bounded text fragments in a separate tool-free role. Public discovery receives only component references and public URLs.
- A separate source-review role in both runners can list, search and read bounded files in the monitor's codebases. It has no web access; private, ignored, dependency and build output paths are excluded. Citations must match current source-line hashes before an impact answer is recorded.
- Shell, direct project-file access, personal MCP, Apps, plugins, hooks, and subagents are disabled. Codex uses code mode for its scoped tools under a read-only policy; tools that request writes remain denied.
- Treat external source code and instructions as data. The researcher is instructed not to execute them; a prompt alone cannot enforce this rule in another agent or harness.
- Reports are rendered locally by the CLI from recorded data.
- Each adapter checks its supported client version and effective tool permissions before research. Local web fetch and inherited configuration are denied.
- Imported research is stored as context. It cannot create a lab attestation or dismiss a case by itself.
- Discovery imports verify scope, current file bytes, literal excerpts and acquired public evidence. Observed dependencies and agent-supplied product mappings require review before becoming actionable findings.
- The impact verdict is calculated by the CLI from fixed questions and registered evidence. It never changes the case decision or grants test permission.

## Active tests

Tests run only in [Microsandbox](sandbox.md). The operator must approve the script, test oracle, artifact, and inputs. A test oracle is the check used to decide whether the test reproduced the issue. The scheduler cannot approve its own tests.

Final job status, exit code, and timeout come from the runtime's control interface. Program stdout/stderr are separate data. A program printing “vulnerable” or “safe” proves neither result.

Static evidence can support a not-affected assessment without a sandbox test. When using a sandbox test to establish non-applicability, the test requires positive evidence and a contrasting control. A timeout, tool failure, or failed reproduction stays inconclusive.

Project impact is a separate applicability diagnostic. It asks whether the exact artifact is deployed, whether the affected feature is used, whether untrusted input reaches it, whether prerequisites hold, and whether a fix or mitigation exists. When source is available, the agent reviews lockfiles, configuration, call sites, feature flags, and relevant input flow statically before considering execution. Source review can be detailed without running project code. Hash checks establish that cited lines exist; they do not establish their meaning or deployment. Missing or bounded evidence stays open.

If static evidence is insufficient and a dynamic check is authorized, only selected reviewed workspace files are copied into Microsandbox. With no workspace, the assessment covers the advisory and exact artifact in general terms; deployment, feature use, and project reachability remain unknown unless separate evidence establishes them. A minimal artifact reproduction confirms only the tested behavior and conditions, not exposure in an unavailable project.

## Scope

These controls apply to validated VulnBell adapters. A Skill loaded in another harness cannot revoke that agent's permissions. A new adapter is not supported until its effective capabilities pass the adapter contract. The client, provider, runtime, and operating system remain trusted dependencies. Local hashes record integrity; they are not remote certification.

Reports stay local. Sharing with Cyber needs an approved destination. Searches must not include credentials, private code, or local paths.
