# VulnBell

![VulnBell - software security monitoring with a VB monogram](docs/assets/vulnbell-cover.png)

[![CI](https://github.com/dertin/vulnbell/actions/workflows/ci.yml/badge.svg)](https://github.com/dertin/vulnbell/actions/workflows/ci.yml)

VulnBell is a harness for AI-assisted security monitoring. It gives a local agent a Skill, a CLI and persistent evidence so the agent can investigate vulnerabilities, assess their impact and prepare reports for Engineering and Cyber teams.

The agent researches and reasons about findings. The Skill guides its review, while the CLI inventories software, collects source data, records evidence and renders reports. Together they provide a repeatable workflow that can be resumed later.

Give the agent a local codebase, a list of software and versions, or both. VulnBell inventories the selected software, checks security sources, helps the agent review relevant findings against the available code and records the evidence and decisions. A codebase is optional: without one, the assessment describes the software and published conditions without claiming project-specific impact.

On request, the agent can also review the codebase itself for security issues and record findings separately from dependency advisories. This review requires a current, user-authorized CodeGraph index for supported languages and examines configuration and unsupported formats separately. VulnBell records review progress, scope and gaps, verifies cited source locations and tracks the reviewed context; the agent remains responsible for the security assessment. Do not include credentials or source snippets in finding descriptions. An empty list is not evidence of complete source coverage. Set `scheduled_code_review: true` to include this work in scheduled agent runs; the review receives up to one third of the time remaining after discovery and retains incomplete progress.

To evaluate code review on a private corpus, keep independently reviewed labels separate from agent observations and run `vulnbell tools code-evaluate --labels <labels.json> --observations <observations.json>`. The `code-evaluation-labels` and `code-evaluation-observations` schemas describe the inputs. The results identify missed high-priority cases and unreviewed cases; scores apply only to the reviewed cases in that corpus.

[See a sample report](examples/report.md).

## Install

Install a prebuilt release with `cargo-binstall`:

```sh
cargo binstall vulnbell
```

Or build from crates.io with Rust 1.90+, Git and a C compiler:

```sh
cargo install vulnbell --locked
```

Install the Agent Skill and check the setup:

```sh
vulnbell skills install
vulnbell doctor
```

The Skill uses the Agent Skills format. Its default location is `$HOME/.agents/skills/vulnbell` on Linux and macOS, or `%USERPROFILE%\.agents\skills\vulnbell` on Windows. The agent must be able to read the selected codebase; an interactive session may need additional permission for paths outside its workspace. Configure authorized codebase paths in the monitor for scheduled runs. If access is unavailable, project impact remains open.

For GitHub tracker research, authenticate with `gh auth login`. Advisory scans can also use anonymous requests, subject to lower limits. VulnBell reads the active GitHub CLI credential into memory when needed; it does not print it or add it to the agent environment. An explicitly configured `GITHUB_TOKEN` takes precedence. `vulnbell doctor --json` reports whether a credential is available and its source; it does not verify network access or token permissions.

Run `vulnbell doctor --project <profile>` after scanning to see recommended tools for the monitor. Doctor checks executable presence and the CodeGraph version command, not integration compatibility, index freshness, network access or complete codebase coverage. Optional tools are needed only for their respective workflows.

## Start a review

Ask your agent to use VulnBell, for example:

> Use VulnBell to review WordPress 6.6.2 and my related plugin codebase at `/home/alex/projects/acme-plugin`. Use one monitor for both. Inventory the plugin's dependencies, investigate relevant advisories and upstream activity, and assess whether reported issues affect the plugin or its WordPress environment. Keep unconfirmed deployment and configuration details open, and save a concise Markdown report for Cyber and Engineering.

This creates or updates one monitor containing the WordPress version and the plugin codebase. You do not need to write YAML. To refresh the report later, ask:

> Use VulnBell to prepare an updated security report for my project's Cyber team.

A **codebase** is a source tree selected for review. A VulnBell **workspace** holds monitor profiles and reports; the profile's `codebases` field identifies source paths. The CLI stores inventory, evidence, assessments and verification results as auditable local data. The agent can resume work from these records.

## How a review works

1. **Inventory:** VulnBell reads supported lockfiles and declared software. General discovery helps identify other formats and sources, with evidence linked to each observation.
2. **Research:** it checks applicable advisory feeds and helps the agent investigate relevant upstream issues, pull requests, fixes and releases.
3. **Assess:** the agent reviews available source, configuration and affected paths to determine what the evidence supports. Local and test configurations remain in scope and are labelled. A declared dependency or unknown deployment is not proof of production exposure.
4. **Report:** the CLI renders findings, decisions, evidence and coverage gaps. The agent can add an evidence-based summary and translate relevant source descriptions for the requested audience.

VulnBell checks sources including OSV, GitHub Security Advisories, RustSec, CVE Records, NVD and CISA KEV. Upstream activity can reveal security signals before a CVE is published, but an issue or pull request is not itself proof that a project is affected. Incomplete checks and unresolved questions remain visible in the report.

For Git codebases, scans and reports record the reviewed branch, full commit and local-change fingerprint. A changed checkout requires a new scan before recording further review results. Private paths, ignored files, untracked dependency/build output and submodules are excluded from the fingerprint and require separate review when in scope. Tracked changes remain bound even inside output directories.

## Reports

Reports identify affected components and versions, project impact, priority, supporting evidence, verification, recommended actions and unresolved questions. They also show incomplete discovery and source coverage. Reports use the profile's `report.language`: `en` by default, or `es` for Spanish. Quoted source text and technical terms may remain in their original language.

Markdown and PDF reports link to the VulnBell project at the beginning and end; the PDF closes after the evidence appendix.

Markdown and PDF reports show known codebase paths relative to the reviewed codebase; local state and JSON retain operational paths. With multiple codebases, their names distinguish the references. Report rendering checks up to 10,000 historical snapshots and 1,024 distinct codebase roots; it fails if those limits are exceeded or the history cannot be validated. Review other paths and report content before sharing.

Generate Markdown or export a self-contained PDF with an evidence appendix using a Chromium-based browser:

```sh
vulnbell report --project vulnbell.yaml --audience cyber
vulnbell report --project vulnbell.yaml --audience cyber --pdf report.pdf > report.md
```

Use `--pdf-browser <executable>` if the browser is not found automatically. To export an edited Markdown report, add `--from-markdown <edited.md> --custom-reason '<reason>'`; the PDF labels the text as not validated by the CLI and gives the reason. Close any unfinished Markdown code fences before exporting. The appendix contains registered review notes, textual sandbox output and evidence metadata, not full external responses or binary artifacts. Check reports for confidential details before sharing. PDF input is limited to 16 MiB and output to 64 MiB; existing PDFs are not overwritten.

## Coverage and discovery

Native parsers extract supported lockfiles. General discovery is enabled by default for other languages, formats and software: the agent identifies the package system, follows official documentation, imports evidence-linked observations and maps public sources. Large codebases are reviewed through resumable pages. Ask the agent to disable discovery, or set `discovery: off` in the profile, to use only native extraction and already configured sources.

Tracker research defaults to explicitly monitored products and known direct dependencies. Packages with an eligible public identifier remain candidates for OSV checks; deeper tracker searches and repository-only advisories are deferred and reported as coverage limitations. Set `research.follow` to exact inventory references for selective follow-up, or `research.tracker_scope: all` for exhaustive tracker research. A lockfile or SBOM may not establish depth: unknown does not mean safe or transitive.

The research plan suggests evidence-backed deferred advisories without expanding the scope automatically. An unresolved scope with no selected instance prevents a deliverable status. Optional `research.release_windows: true` obtains exact-version publication dates from supported registries or an explicitly declared GitHub product repository; unavailable dates use a documented fallback. Advisory checks remain independent of the time window. Use an independently labelled corpus to assess screening and ordering with `vulnbell tools evaluate`; see the [evaluation guide](docs/upstream-screen-evaluation.md).

### Python inventories

VulnBell inventories Python requirements files (`requirements*.txt`, `.in`, `.lock`) and supported uv, Poetry, PDM, Pipenv and `pylock.toml` lockfiles locally. For a reviewed public PyPI requirements lock, set `python.verify_pypi_hashes: true` to authorize package-name queries. VulnBell verifies an exact release hash before assigning a public identity. Alternate or ambiguous source directives keep entries local. Structured Python locks and other unverified declarations remain local candidates. Requirements includes and uncertain sources keep generic discovery local. A matched hash does not establish installation or deployment.

For an eligible upstream observation, VulnBell can compare an exact PyPI wheel with a scoped installed directory and check specific absent paths without running package code. The reviewer must establish why that directory represents the assessed build; an unavailable artifact or unsupported wheel layout remains in review. See the [upstream research guide](skills/vulnbell/references/upstream-research.md).

[Coverage details](docs/coverage.md) · [General discovery](docs/discovery.md)

## CLI and review workflow

The agent uses the CLI to record and retrieve work. These commands are also available directly:

```sh
vulnbell status --json
vulnbell scan --project vulnbell.yaml --json
vulnbell inbox --project vulnbell.yaml --json
vulnbell impact SIG-... --project vulnbell.yaml
vulnbell tools pending --project vulnbell.yaml
vulnbell runners list --json
```

`status` lists registered projects, scan outcomes, scheduler health and the latest report. `impact` prints questions for each affected artifact; reviewed answers and evidence determine the impact assessment. `tools pending` lists remaining work. A partial scan returns exit code 2.

For a time-bounded review, set `research.review_budget_minutes` to 1–120 per monitor. The agent prioritizes evidence-backed risks and hands remaining cases to human review without closing them. Scheduled agent phases observe the earlier of this budget and the schedule window; synchronous scans and cleanup may overrun it, so it is not a hard whole-process timeout. The report and `tools pending` retain the incomplete status.

`tools queue` orders open cases; `tools progress` records resumable work without changing findings. `tools groups` suggests shared investigations across monitors and `tools duplicates` identifies candidate duplicate advisories. Grouping is a hint: each project still needs its own build and impact assessment. `tools citations` checks file and line references against the current codebase; it does not establish that a security claim is correct. `tools challenge` records a separate evidence-backed assessment; reviewer identity and independence are self-reported. See the [workspace workflow](skills/vulnbell/references/workspace.md) and the `citations` and `challenge` schema commands.

## Security tests

The agent first reviews source and configuration without executing project code. An active test is considered only when it can change a material decision. Tests use Microsandbox 0.7.11 with limited inputs, a non-root user and blocked network access. They require explicit approval and never run proof-of-concept code on the host. Scheduled reviews use scoped, read-only source tools and cannot run tests.

When project files are available, a feasible test may use reviewed files copied into Microsandbox. Without a codebase, a minimal isolated reproducer may assess the exact artifact and published conditions; it cannot establish project-specific deployment or reachability.

[Sandbox](docs/sandbox.md) · [Agent security](docs/agent-security.md)

## Scheduled reports (experimental)

Scheduled monitoring requires a working system scheduler and local agent runner. After setting up a monitor, you can ask separately:

> Schedule this monitor to run daily at 08:00 in my time zone, with a three-hour execution window, and save its Markdown reports locally.

Scheduling is configured per project: choose `daily`, `weekdays` or `weekly`, a time zone, start time, execution window, runner and report folder. Runner paths and model selection are stored once in the local VulnBell data directory. Credentials remain in the selected agent client.

If the computer starts during the window, the review runs; if it misses the window, that run is skipped. VulnBell records completed, failed and skipped runs but does not wake a powered-off computer or send team messages by default. Each run writes Markdown below the schedule's absolute `report_dir`; `vulnbell status` shows the latest report path. Private logs and audit data stay in VulnBell's data directory.

- Linux: `vulnbell schedule install` installs a user-level systemd timer.
- macOS: configure launchd to call `vulnbell run --project <profile>`.
- Windows: configure Task Scheduler to call the same command.

Native job installation is currently included for Linux; macOS and Windows use their system schedulers. Use `vulnbell run --project <profile> --now` to run a configured monitor immediately.

[Set up scheduled runs](docs/automation.md) · [Local runners](docs/runners.md) · [Agent integration](docs/agents.md)

## State compatibility

VulnBell releases support the current state contracts only. Workspaces, profiles, databases, snapshots, evidence and other state created by an earlier release may be incompatible. Incompatible state is rejected with a clear error and left untouched; VulnBell does not silently delete, overwrite, migrate or convert it. If a project database is incompatible, create a new monitor with a new project ID. VulnBell does not maintain legacy readers, schema fallbacks or other code solely to support state from earlier releases.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

[Contribute](CONTRIBUTING.md) · [CI](docs/ci.md) · [Release](docs/releasing.md) · [Report a vulnerability](SECURITY.md) · [MIT license](LICENSE)
