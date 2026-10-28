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

VulnBell checks published advisories and CVE data, including OSV, GitHub Security Advisories, RustSec, CVE Records, NVD, and CISA KEV. Unlike a CVE-only monitor, the agent also reviews recent upstream issues, pull requests, merge requests, bug reports, fixes, and release information. This can surface credible security signals before a CVE is published. These early signals remain untrusted until the available evidence supports them.

Tracker research defaults to explicitly monitored products and known direct dependencies. All inventoried packages remain eligible for OSV checks, while deeper tracker searches and repository-only advisories are deferred; the report counts transitives and unknown-depth instances and states that coverage limitation. Set `research.follow` to exact inventory references when a particular inner dependency warrants investigation, or `research.tracker_scope: all` for exhaustive tracker research. A lockfile or SBOM may not establish depth: unknown does not mean safe or transitive.

The research plan suggests evidence-backed deferred advisories for selective follow-up without expanding the scope automatically. An unresolved scope with no selected instance prevents a deliverable status. Optional `research.release_windows: true` obtains exact-version publication dates from supported registries or an explicitly declared GitHub product repository; unavailable dates use a documented fallback. Advisory checks remain independent of the time window. Assess screening and ordering using an independently labelled corpus with `vulnbell tools evaluate`; see [the evaluation guide](docs/upstream-screen-evaluation.md).

Each report identifies the affected component and version, project impact, urgency, evidence links, local or sandbox verification, recommended action, and anything that could not be confirmed.

Reports also show the source map and discovery progress, including pending files, excluded inputs and unavailable sources. Incomplete work remains partial.

For a user-requested time-bounded review, set `research.review_budget_minutes` to 1–120 in each monitor profile. The interactive agent prioritizes evidence-backed risks and hands remaining cases to human review without closing them. Scheduled agent phases observe the earlier of this budget and the schedule window; synchronous scan, adapter preflight, report writing and cleanup may overrun it, so this is not a hard whole-process timeout. The incomplete report and `tools pending` status remain visible.

`tools queue` lists open cases in a deterministic order; `tools progress` records resumable work intervals and next steps without altering findings, `tools groups` suggests shared upstream/version investigations across monitors, and `tools duplicates` finds candidate duplicate advisories within one monitor. Changed facts, evidence or outcome invalidate the completed progress view. Grouping is a hint: each project still needs its own build and impact assessment. See the [workspace workflow](skills/vulnbell/references/workspace.md).

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

The local agent reviews public upstream evidence and available project source. The CLI keeps the inventory, evidence, impact answers, sandbox attestations, and reports as auditable local data.

## Ask your agent to set up monitoring

> Use VulnBell to monitor Keycloak 26.8.1, WordPress latest, and the project at `/home/alex/projects/acme-api`. Inspect that workspace to inventory its dependencies and determine whether reported issues affect its source or configuration. Create and validate the profile, investigate new advisories and upstream activity, configure a daily run at 08:00 in my time zone with a three-hour execution window, and save a concise Markdown report.

The agent first checks `vulnbell status --json` for an existing monitor. It then creates or updates the profile, builds the inventory, checks advisories and CVEs, and reviews recent activity from the verified upstream projects. You do not need to write YAML. `latest` follows stable releases; it does not mean that version is deployed in your project.

To get a fresh report at any time:

> Use VulnBell to prepare an updated security report for my project's Cyber team.

## Schedule reports

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
vulnbell run --project vulnbell.yaml --now
```

`status` lists registered projects, profile availability, scan outcomes, scheduler health, skipped runs, agent failures, and the latest report. `impact` prints five fixed questions for each affected artifact. Save reviewed answers using `schema impact`; the CLI calculates update urgency from those answers and their registered evidence. `report` shows the verdict, confidence, answered conditions, rationales, and remaining questions. `run --now` runs a configured monitor and writes a fresh report. Reports show incomplete coverage; `scan` returns exit code 2 when coverage is partial. Reports use the profile's `report.language`: `en` (default) or `es`. Technical terms that the language usually leaves untranslated, and quoted source text, stay as they are.

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
