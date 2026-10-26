# Coverage

| Area | Support |
|---|---|
| Manual inventory | Products, binaries, PURL/CPE, exact versions, and explicitly requested `latest` |
| Workspaces | Cargo.lock through v4; npm v1–v3; Composer; pnpm 6/9; Yarn classic v1 |
| SBOM | CycloneDX JSON 1.4–1.6 and SPDX JSON 2.2/2.3 |
| Advisories | OSV, GHSA, RustSec, CVE Records, NVD, and CISA KEV |
| Vendor feeds | CSAF 2.0 and OpenVEX 0.2.0 with exact identity matching; limited signature and complex relationship checks |
| Issues and proposed changes | GitHub, GitLab, and Launchpad, through the agent and per-upstream review windows |
| Reports | Local Markdown/JSON for manager, cyber, and audit audiences |
| Project status | Registered profiles, scan results, schedule health, skipped runs, agent failures, and latest reports |
| Project impact | Guided evidence-bound questions, static workspace review, saved rationales, and update urgency |
| Scheduled agents | Local runner registry with validated Codex and OpenCode adapters |
| Scheduler | Built-in user-level systemd installation on Linux; launchd and Task Scheduler can invoke `vulnbell run` |
| Sandbox | Microsandbox 0.7.11; real execution tested on Linux x86_64/KVM |

## Limits

- Go/Python, modern Yarn, RSS/Atom, and other formats not implemented are marked as partial coverage or unsupported.
- Local or Git dependencies are not silently treated as public registry packages. Private registries, backports, and binary equivalence need more evidence.
- A declared version does not prove deployment or exposure. Unclear matches stay in review.
- Access restrictions, missing dates, rate limits, and unread pages stay visible. Partial reviews do not advance the checkpoint.
- CI builds and tests the core on Linux, macOS, and Windows. It does not certify VM execution on macOS/Windows.
- Unattended agent runs need valid local credentials and provider quota. Reports are written to the configured local `report_dir`.
- Remote/API runners and cloud report delivery are not implemented.

## Tests

The suite checks every generated schema against its published file. It also covers inventory and advisory fixtures, duplicate handling, artifact changes, impact decisions, project status, history, schedule windows, agent failures, and reports. Real sandbox tests cover host/network isolation, job status, positive controls, outdated attestations, timeouts, staged workspace files, and cleanup.
