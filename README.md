# VulnBell

[![CI](https://github.com/dertin/vulnbell/actions/workflows/ci.yml/badge.svg)](https://github.com/dertin/vulnbell/actions/workflows/ci.yml)

Monitor your software for security risks. Get clear reports for Engineering and Cyber teams.

VulnBell combines a Rust CLI with an Agent Skill. Describe products, binaries, and dependencies, add local workspaces, or use both. You do not need a local repository. Reports separate actionable findings, open questions, and sources that could not be checked.

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

Then install the shared Agent Skill:

```sh
vulnbell skills install
vulnbell doctor --json
vulnbell status
```

The Skill installs to `~/.agents/skills/vulnbell`, shared by Codex and OpenCode. The configured local agent reviews upstream evidence and available project source; the CLI keeps inventory, impact answers, sandbox attestations, and reports in auditable contracts.

## Ask your agent to set up monitoring

> Use VulnBell to monitor Keycloak 26.8.1, WordPress latest, and this project's dependencies. Create and validate the profile, investigate security risks, and save a Markdown report.

The agent first checks `vulnbell status --json` for an existing monitor. It then creates or updates the profile, builds the inventory, checks advisories, and reviews recent issues and pull requests. You do not need to write YAML. `latest` follows stable releases; it does not mean that version is deployed in your project.

To get a fresh report at any time:

> Use VulnBell to prepare an updated security report for my project's Cyber team.

## Schedule reports

Set each project's frequency, time zone, start time, allowed time window, agent, and report folder. Linux uses user-level systemd.

If your computer starts during the window, the review runs. If it misses the whole window, that run is skipped. The next run follows the schedule. VulnBell does not send team messages by default.

[Set up daily runs](docs/automation.md) · [Agents and models](docs/agents.md)

## CLI

```sh
vulnbell status --json
vulnbell scan --project radar.yaml --json
vulnbell inbox --project radar.yaml --json
vulnbell impact SIG-... --project radar.yaml
vulnbell report --project radar.yaml --audience cyber
vulnbell run --project radar.yaml --now
```

`status` lists registered projects, profile availability, scan outcomes, scheduler health, skipped runs, agent failures, and the latest report. `impact` prints five fixed questions for each affected artifact. Save reviewed answers using `schema impact`; the CLI calculates update urgency from those answers and their registered evidence. `report` shows the verdict, confidence, answered conditions, rationales, and remaining questions. `run --now` runs a configured monitor and writes a fresh report. Reports show incomplete coverage; `scan` returns exit code 2 when coverage is partial. Generated CLI and scheduled reports currently use Spanish; the documentation and sample report use English.

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
