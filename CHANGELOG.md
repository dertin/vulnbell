# Changelog

## Unreleased

### Changed

- Project schedules now reference a machine-local runner ID. Typed Codex and OpenCode adapter settings are configured and checked separately.
- Scheduled report paths and runner availability are exposed through CLI status.

## 0.1.0 - 2026-10-25

### Added

- Rust CLI and Agent Skill for monitoring products, binaries, repositories, and package inventories.
- Advisory coverage for OSV, GitHub Security Advisories, RustSec, CVE Records, NVD, CISA KEV, CSAF, and OpenVEX.
- Upstream review contracts for GitHub, GitLab, Launchpad, and similar trackers.
- Evidence-bound impact assessment for projects with or without a local workspace.
- Microsandbox verification with reviewed staging, network isolation, positive controls, and attestations.
- Per-project scheduled Codex and OpenCode runs with execution windows, skipped-run tracking, and concise Markdown reports.
- Persistent project status, source coverage, failures, reports, and generated JSON Schemas.
