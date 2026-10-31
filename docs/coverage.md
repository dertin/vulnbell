# Coverage

| Area | Support |
|---|---|
| Manual inventory | Products, binaries, PURL/CPE, exact versions, and explicitly requested `latest` |
| Native workspace parsers | Cargo.lock through v4; npm v1–v3; Composer; pnpm 6/9; Yarn classic v1; Python `requirements.txt` declarations |
| General discovery | Enabled by default; paginated workspace extraction and source mapping through the agent, including formats without a native parser |
| SBOM | CycloneDX JSON 1.4–1.6 and SPDX JSON 2.2/2.3 |
| Advisories | OSV, GHSA, published GitHub repository advisories, RustSec, CVE Records, NVD, and CISA KEV |
| Vendor feeds | CSAF 2.0 and OpenVEX 0.2.0 with exact identity matching; limited signature and complex relationship checks |
| Public sources | Issues, proposed changes, discussions, docs, changelogs, releases and advisories on mapped public sites, with independent review windows |
| Reports | Local Markdown/JSON for manager, cyber, and audit audiences |
| Project status | Registered profiles, scan results, schedule health, skipped runs, agent failures, and latest reports |
| Project impact | Guided evidence-bound questions, static workspace review, saved rationales, and update urgency |
| Scheduled agents | Local runner registry with validated Codex and OpenCode adapters |
| Scheduler | Built-in user-level systemd installation on Linux; launchd and Task Scheduler can invoke `vulnbell run` |
| Sandbox | Microsandbox 0.7.11; real execution tested on Linux x86_64/KVM |

## Limits

- Go/Python, JVM, .NET, Ruby, C/C++ and other formats can use general discovery. This does not imply native parsing or automatic registry resolution for every ecosystem. Unsupported native formats and incomplete observations remain visible.
- RSS/Atom have no native feed connector. The agent can map and review public release pages through general discovery.
- Discovery resumes across pages and runs. Inaccessible/private sources, binary files and insufficient parsing context cannot be labelled complete.
- Local or Git dependencies are not silently treated as public registry packages. Private registries, backports, and binary equivalence need more evidence.
- Python requirements pins are declarations, not an installed dependency graph. Unpinned ranges, environment markers, includes, constraints, URL/VCS/local entries and index options need further review. They do not establish the installed artifact, source, directness, or target environment. Files with index, include or constraint directives do not infer public package identities. Unsupported entries are counted without exposing their contents. General discovery does not export a requirements file with URLs, `@`, environment expansions, index, include or constraint options; review it locally.
- Some Python version and advisory ranges cannot be ordered by the native advisory matcher; those matches remain unknown rather than being excluded.
- npm v1 lockfiles do not identify direct root dependencies: hoisted packages have unknown depth and are excluded from default tracker research. Advisory scanning still covers supported packages; select specific dependencies with `research.follow` when needed.
- A hidden npm workspace matched by a wildcard has unknown depth when the lockfile alone cannot establish npm's workspace selection.
- Git workspace identity is unavailable when tracked non-private files have `assume-unchanged` or `skip-worktree` flags, including sparse checkouts. Clear those flags or review a full checkout to bind decisions to the current files.
- A declared version does not prove deployment or exposure. Unclear matches stay in review.
- OSV converts GHSA ranges without a patched version into an open `introduced: "0"` range and keeps the real bound in `database_specific.last_known_affected_version_range`. A match then becomes not-affected only when every entry for the package excludes the version. Git ranges, unparsable versions and compound bounds keep the match. A case whose claims are all not-affected is informational.
- Repository advisories are read for components with an exact version and a GitHub upstream, one request per repository within the scan's HTTP budget; `GITHUB_TOKEN` avoids the anonymous rate limit. GitHub ranges are evaluated as comma-separated comparators or a list of exact versions; any other form is listed in coverage and adds no claim. A range with no upper bound is closed by `patched_versions`: a version at or above a single fix, at or above the fix on its release line, or above every listed fix gets a not-affected claim; a bounded range that contains the version while its sole fix, inside the range, is at or below the version contradicts itself and is listed in coverage; otherwise, when no fix line matches, the advisory is listed in coverage. A research case for the same advisory ID and instances becomes part of the claim case.
- Access restrictions, missing dates, rate limits, and unread pages stay visible. Partial reviews do not advance the checkpoint.
- CI builds and tests the core on Linux, macOS, and Windows. It does not certify VM execution on macOS/Windows.
- Unattended agent runs need valid local credentials and provider quota. Reports are written to the configured local `report_dir`.
- Remote/API runners and cloud report delivery are not implemented.

## Tests

The suite checks every generated schema against its published file. It also covers inventory and advisory fixtures, duplicate handling, artifact changes, impact decisions, project status, history, schedule windows, agent failures, and reports. Real sandbox tests cover host/network isolation, job status, positive controls, outdated attestations, timeouts, staged workspace files, and cleanup.
