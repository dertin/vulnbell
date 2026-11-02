# Coverage

| Area | Support |
|---|---|
| Manual inventory | Products, binaries, PURL/CPE, exact versions, and explicitly requested `latest` |
| Native codebase parsers | Cargo.lock through v4; npm v1–v3; Composer; pnpm 6/9; Yarn classic v1; Python requirements files, uv lock v1 revisions 1–5, Poetry lock 1.0–2.1, PDM lock 4.5.0–4.5.1, Pipfile.lock v6 and pylock v1.0 |
| General discovery | Enabled by default; paginated codebase extraction and source mapping through the agent, including formats without a native parser |
| SBOM | CycloneDX JSON 1.4–1.6 and SPDX JSON 2.2/2.3 |
| Advisories | OSV, GHSA, published GitHub repository advisories, RustSec, CVE Records, NVD, and CISA KEV |
| Vendor feeds | CSAF 2.0 and OpenVEX 0.2.0 with exact identity matching; limited signature and complex relationship checks |
| Public sources | Issues, proposed changes, discussions, docs, changelogs, releases and advisories on mapped public sites, with independent review windows |
| Reports | Local Markdown/JSON for manager, cyber, and audit audiences; PDF export with an evidence appendix |
| Project status | Registered profiles, scan results, schedule health, skipped runs, agent failures, and latest reports |
| Project impact | Guided evidence-bound questions, static codebase review, saved rationales, and update urgency |
| Scheduled agents | Local runner registry with validated Codex and OpenCode adapters |
| Scheduler | Built-in user-level systemd installation on Linux; launchd and Task Scheduler can invoke `vulnbell run` with a manually saved schedule configuration |
| Sandbox | Microsandbox 0.7.11; real execution tested on Linux x86_64/KVM |

## Limits

- Go/Python, JVM, .NET, Ruby, C/C++ and other formats can use general discovery. This does not imply native parsing or automatic registry resolution for every ecosystem. Unsupported native formats and incomplete observations remain visible.
- RSS/Atom have no native feed connector. The agent can map and review public release pages through general discovery.
- Discovery resumes across pages and runs. Inaccessible/private sources, binary files and insufficient parsing context cannot be labelled complete.
- Cargo and supported JavaScript lock parsers do not silently treat local or Git dependencies as public registry packages. Private registries, backports, and binary equivalence need more evidence.
- Composer lock entries are retained locally with unverified source identity and are excluded from external lookups. `composer.json` is unavailable to agent discovery because it may contain private names or credentials. An explicitly declared public PURL and exact version can be scanned after source identity and disclosure are verified; remaining lock entries and the manifest retain partial coverage. Scheduled reports are rendered locally.
- Python requirements and lock entries do not establish the installed artifact, source or target environment. With `python.verify_pypi_hashes: true`, a pinned requirements entry without alternate-source directives is matched against the exact PyPI release's SHA-256 values; only a match gains a public identity and advisory lookup. A generated `# via` identifies directness only when the referenced input or parent is found and corroborated. Unpinned ranges, unresolved markers, groups, includes, constraints and URL/VCS/local entries remain gaps. Structured Python locks stay local candidates. Recognized inputs and unrecognized `.lock` files are not exported to the discovery agent; arbitrary pip roots under other names need explicit exclusion when private.
- Some Python version and advisory ranges cannot be ordered by the native advisory matcher; those matches remain unknown rather than being excluded.
- npm v1 lockfiles do not identify direct root dependencies: hoisted packages have unknown depth and are excluded from default tracker research. Advisory scanning still covers supported packages; select specific dependencies with `research.follow` when needed.
- A hidden npm workspace matched by a wildcard has unknown depth when the lockfile alone cannot establish npm's workspace selection.
- Git codebase identity is unavailable when tracked non-private files have `assume-unchanged` or `skip-worktree` flags, including sparse checkouts. Clear those flags or review a full checkout to bind decisions to the current files.
- Untracked dependency/build output is outside the Git worktree fingerprint; tracked changes remain bound. Source citation checks exclude output directories. A separate review is needed if excluded content matters to an assessment.
- A declared version does not prove deployment or exposure. Unclear matches stay in review.
- Scan coverage and upstream research are tracked separately. An open research window makes the report incomplete; a completed review does not erase unrelated scan gaps.
- OSV converts GHSA ranges without a patched version into an open `introduced: "0"` range and keeps the real bound in `database_specific.last_known_affected_version_range`. A match then becomes not-affected only when every entry for the package excludes the version. Git ranges, unparsable versions and compound bounds keep the match. A case whose claims are all not-affected is informational.
- Repository advisories are read for components with an exact version and a GitHub upstream, one request per repository within the scan's HTTP budget; An authenticated `gh` session avoids the anonymous rate limit for supported API requests. GitHub ranges are evaluated as comma-separated comparators or a list of exact versions; any other form is listed in coverage and adds no claim. A range with no upper bound is closed by `patched_versions`: a version at or above a single fix, at or above the fix on its release line, or above every listed fix gets a not-affected claim; a bounded range that contains the version while its sole fix, inside the range, is at or below the version contradicts itself and is listed in coverage; otherwise, when no fix line matches, the advisory is listed in coverage. A research case for the same advisory ID and instances becomes part of the claim case.
- Access restrictions, missing dates, rate limits, and unread pages stay visible. Partial reviews do not advance the checkpoint.
- CI builds and tests the core on Linux, macOS, and Windows. It does not certify VM execution on macOS/Windows.
- Unattended agent runs need valid local credentials and provider quota. Reports are written to the configured local `report_dir`.
- Remote/API runners and cloud report delivery are not implemented.

## Tests

The suite checks every generated schema against its published file. It also covers inventory and advisory fixtures, duplicate handling, artifact changes, impact decisions, project status, history, schedule windows, agent failures, and reports. Real sandbox tests cover host/network isolation, job status, positive controls, outdated attestations, timeouts, staged codebase files, and cleanup.
