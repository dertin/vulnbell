# VulnBell

![VulnBell - software security monitoring with a VB monogram](docs/assets/vulnbell-cover.png)

[![CI](https://github.com/dertin/vulnbell/actions/workflows/ci.yml/badge.svg)](https://github.com/dertin/vulnbell/actions/workflows/ci.yml)

VulnBell helps a local agent monitor the software your projects depend on and produce clear security reports for Engineering and Cyber teams.

Tell the agent what to monitor in any of these ways:

- list products, binaries, libraries, and exact versions;
- give it a project directory so it can inventory lockfiles and dependencies, then inspect source and configuration when impact depends on how a library is used;
- combine a project directory with additional software that is not declared by the project.

A project directory is optional. Without one, VulnBell evaluates the declared software against its published versions and general exposure conditions.

Native parsers extract supported lockfiles first. General discovery is enabled by default for other languages, formats and software: the agent identifies the package system, follows its official documentation, imports evidence-linked dependency observations and maps public sources. Large workspaces are reviewed through resumable pages. Ask the agent to disable this mode, or set `discovery: off` in the profile, to use only native extraction and already configured sources.

Python `requirements.txt` declarations are inventoried locally without assuming a public package source. Recognized `requirements*.txt`/`.in` and `constraints*.txt`/`.in` files are not sent to the discovery agent; includes and uncertain sources keep generic discovery local for that monitor. Pip inputs used directly under other names are not automatically recognized. After verifying a package's public identity and authorization to disclose it, explicitly add its public PURL and version to the monitor for advisory checks.

For Git workspaces, scans and reports record the reviewed branch, full commit and local-change fingerprint. A changed checkout requires a new scan before recording further review results. Private paths, ignored files, untracked dependency/build output and submodule contents are excluded from the fingerprint and require separate review when in scope. Tracked changes remain bound even inside output directories.

VulnBell checks published advisories and CVE data, including OSV, GitHub Security Advisories, RustSec, CVE Records, NVD, and CISA KEV. Unlike a CVE-only monitor, the agent also reviews recent upstream issues, pull requests, merge requests, bug reports, fixes, and release information. This can surface credible security signals before a CVE is published. These early signals remain untrusted until the available evidence supports them.

Tracker research defaults to explicitly monitored products and known direct dependencies. Packages with an eligible public identifier remain candidates for OSV checks, while deeper tracker searches and repository-only advisories are deferred; the report counts transitives and unknown-depth instances and states that coverage limitation. Set `research.follow` to exact inventory references when a particular inner dependency warrants investigation, or `research.tracker_scope: all` for exhaustive tracker research. A lockfile or SBOM may not establish depth: unknown does not mean safe or transitive.

The research plan suggests evidence-backed deferred advisories for selective follow-up without expanding the scope automatically. An unresolved scope with no selected instance prevents a deliverable status. Optional `research.release_windows: true` obtains exact-version publication dates from supported registries or an explicitly declared GitHub product repository; unavailable dates use a documented fallback. Advisory checks remain independent of the time window. Assess screening and ordering using an independently labelled corpus with `vulnbell tools evaluate`; see [the evaluation guide](docs/upstream-screen-evaluation.md).

Each report identifies the affected component and version, project impact, urgency, evidence links, local or sandbox verification, recommended action, and anything that could not be confirmed.

Reports also show the source map and discovery progress, including pending files, excluded inputs and unavailable sources. Incomplete work remains partial.

For a user-requested time-bounded review, set `research.review_budget_minutes` to 1–120 in each monitor profile. The interactive agent prioritizes evidence-backed risks and hands remaining cases to human review without closing them. Scheduled agent phases observe the earlier of this budget and the schedule window; synchronous scan, adapter preflight, report writing and cleanup may overrun it, so this is not a hard whole-process timeout. The incomplete report and `tools pending` status remain visible.

`tools queue` lists open cases in a deterministic order; `tools progress` records resumable work intervals and next steps without altering findings, `tools groups` suggests shared upstream/version investigations across monitors, and `tools duplicates` finds candidate duplicate advisories within one monitor. Changed facts, evidence or outcome invalidate the completed progress view. Grouping is a hint: each project still needs its own build and impact assessment. See the [workspace workflow](skills/vulnbell/references/workspace.md).

`tools citations` checks explicit file and line references for a case against its current codebase context without printing source. It can compare line hashes; it does not establish that a security claim is correct. Use `vulnbell schema citations` for its input contract.

`tools challenge` records a separate evidence-backed assessment of a current impact and verdict. A disputed or inconclusive challenge requires a new verdict that cites it. Reviewer identity and independence are self-reported; the CLI does not launch a reviewer. Use `vulnbell schema challenge` for its input contract.

[See a sample report](examples/report.md).

## Install

Install a prebuilt release with `cargo-binstall`:

```sh
cargo binstall vulnbell
```

Or build it with Rust 1.90+, Git, and a C compiler:

```sh
cargo install vulnbell --locked
```

Then install the Agent Skill:

```sh
vulnbell skills install
vulnbell doctor --json
vulnbell status
```

The Skill uses the Agent Skills format. Its default location is `$HOME/.agents/skills/vulnbell` on Linux and macOS, or `%USERPROFILE%\.agents\skills\vulnbell` on Windows. `vulnbell doctor --json` shows the resolved location and checks the installation.

For authenticated GitHub advisory and release requests, sign in with `gh auth login`. VulnBell reads the active GitHub CLI credential into memory when needed; it does not print it or add it to the agent environment. An explicitly configured `GITHUB_TOKEN` takes precedence. `vulnbell doctor --json` reports whether a credential is available and its source; it does not verify network access or token permissions.

The local agent reviews public upstream evidence and available project codebases. A codebase is a local source tree selected for monitoring; the VulnBell workspace is where monitor artifacts are kept. Profile and JSON fields use `workspaces` for codebase paths. The CLI keeps the inventory, evidence, impact answers, sandbox attestations, and reports as auditable local data.

> **State compatibility:** VulnBell releases support the current state contracts only. Workspaces, profiles, databases, snapshots, evidence, and other state created by an earlier release may be incompatible. Incompatible state is rejected with a clear error and left untouched; VulnBell does not silently delete, overwrite, migrate, or convert it. If a project database is incompatible, create a new monitor with a new project ID. VulnBell does not maintain legacy readers, schema fallbacks, or other code solely to support state from earlier releases.

## Ask your agent to set up monitoring

> Use VulnBell to review WordPress 6.6.2 and my related plugin codebase at `/home/alex/projects/acme-plugin`. Use one monitor for both. Inventory the plugin's dependencies, investigate relevant advisories and upstream activity, and assess whether reported issues affect the plugin or its WordPress environment. Keep unconfirmed deployment and configuration details open, and save a concise Markdown report for Cyber and Engineering.

This example uses one monitor: its profile contains both the WordPress version and the plugin codebase. The agent first checks `vulnbell status --json` for an existing monitor. It then creates or updates the profile, builds the inventory, checks advisories and CVEs, and reviews recent activity from the verified upstream projects. You do not need to write YAML. A declared version does not by itself confirm what is deployed.

To get a fresh report at any time:

> Use VulnBell to prepare an updated security report for my project's Cyber team.

## Optional: schedule reports (experimental)

Scheduled monitoring is experimental and requires a working system scheduler and local agent runner. After setting up a monitor, you can ask separately:

> Schedule this monitor to run daily at 08:00 in my time zone, with a three-hour execution window, and save its Markdown reports locally.

Scheduling is configured per project. Choose `daily`, `weekdays`, or `weekly`, plus a time zone, start time, allowed execution window, local runner, and report folder. Executable paths and model selection are stored once in the local VulnBell data directory instead of every project schedule. Credentials remain in the selected agent client.

If your computer starts during the window, the review runs. If it misses the whole window, that run is skipped. The next run follows the schedule. VulnBell does not send team messages by default.

- Linux: `vulnbell schedule install` installs a user-level systemd timer.
- macOS: configure launchd to call `vulnbell run --project <profile>`.
- Windows: configure Task Scheduler to call the same command.

VulnBell applies the configured schedule window and records completed, failed, and skipped runs on every platform. It does not wake a powered-off computer. Native job installation is currently included for Linux; macOS and Windows use their system schedulers.

Each run writes a Markdown file below the schedule's absolute `report_dir`. `vulnbell status` shows the exact path of the latest report. Private logs and audit data stay in VulnBell's data directory.

[Set up scheduled runs](docs/automation.md) · [General discovery](docs/discovery.md) · [Local runners](docs/runners.md) · [Agent integration](docs/agents.md)

## CLI

```sh
vulnbell status --json
vulnbell scan --project vulnbell.yaml --json
vulnbell inbox --project vulnbell.yaml --json
vulnbell impact SIG-... --project vulnbell.yaml
vulnbell report --project vulnbell.yaml --audience cyber
vulnbell tools pending --project vulnbell.yaml
vulnbell runners list --json
# Optional experimental scheduled workflow:
vulnbell run --project vulnbell.yaml --now
```

`status` lists registered projects, profile availability, scan outcomes, scheduler health, skipped runs, agent failures, and the latest report. `impact` prints five fixed questions for each affected artifact. Save reviewed answers using `schema impact`; the CLI calculates update urgency from those answers and their registered evidence. `report` shows the verdict, confidence, answered conditions, rationales, and remaining questions. `run --now` runs a configured monitor and writes a fresh report. Reports show incomplete coverage; `scan` returns exit code 2 when coverage is partial. Reports use the profile's `report.language`: `en` (default) or `es`. Technical terms that the language usually leaves untranslated, and quoted source text, stay as they are.

The CLI renders Markdown locally for interactive and scheduled reports. To export a PDF with recorded verification details and an evidence appendix, install a Chromium-based browser and run:

```sh
vulnbell report --project vulnbell.yaml --audience cyber --pdf report.pdf > report.md
```

Use `--pdf-browser <executable>` if the browser is not found automatically. Use `--from-markdown <edited.md>` with `--pdf` to export a customized report; the PDF labels that text as user-supplied. The appendix includes registered review notes, textual sandbox output and evidence metadata, not full external responses or binary artifacts. Review it for confidential details before sharing. PDF input is limited to 16 MiB and output to 64 MiB; existing PDFs are not overwritten.

With a workspace, the agent first reviews source, lockfiles, configuration, and reachable call paths without executing project code. If a dynamic check is still needed, only reviewed files are copied into Microsandbox. Without a workspace, VulnBell assesses the exact artifact and published conditions, may use a minimal isolated reproducer, and keeps project-specific deployment or reachability explicitly unknown.

## Security tests

Active tests use Microsandbox 0.7.11 with limited inputs, a non-root user, and blocked network access. Tests need explicit approval and never run proof-of-concept code on the host. Scheduled researchers cannot run tests or enable local tools.

[Sandbox](docs/sandbox.md) · [Agent security](docs/agent-security.md) · [Coverage](docs/coverage.md)

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

[Contribute](CONTRIBUTING.md) · [CI](docs/ci.md) · [Release](docs/releasing.md) · [Report a vulnerability](SECURITY.md) · [MIT license](LICENSE)
