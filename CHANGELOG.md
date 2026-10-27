# Changelog

## 0.1.2 - 2026-10-27

### Added

- `not_applicable` research assessment with a required reason (fixed in the monitored version, other version line, component not in build). These events are counted and remembered without opening cases.
- `discovery --map-registries` maps crates.io, npm, PyPI and Maven Central packages from their declared registry metadata, with request pacing and rate-limit stop.
- `discovery --reopen <path>` queues a reviewed or unavailable file again.
- `version_excerpt` resolves Maven-style `${property}` versions defined in the same file.
- Reports show `path:line` version provenance, the recorded verdict and the impact assessment for each case.
- Report JSON `verification_pending` and a Markdown incomplete-report banner for open cases missing impact assessment or a required sandbox check. A check is required (`sandbox_needed` on the instance's local check) only when the impact needs evidence and neither an affected claim nor a lab reproduction confirms that exact version; missing deployment facts stay open impact questions without a test.
- `case --validation-blocker` takes a required `--blocker-kind`: `details_undisclosed`, `artifact_unavailable`, `sandbox_limits`, `runtime_unavailable` or `authorization_declined`. Local checks show the kind. A test that fails to run records a blocker without a kind, and blockers recorded without one do not settle a required check.
- Profile `sandbox` raises the input, memory and time limits a test may request, up to 512 MiB per input, 1024 MiB in total, 4096 MiB of memory and 600 seconds. The defaults stay 16 MiB, 64 MiB, 512 MiB and 120 seconds, and isolation settings are not configurable.
- Published security advisories of each component's GitHub repository are an advisory source, one request per repository. Maintainers publish them before GitHub reviews them into the global database and OSV; a range that contains the exact version adds an affected claim. When an open range contains the version but the advisory's patched versions show the fix on its release line, the source adds a not-affected claim with non-applicability evidence, as OSV does. Ranges and patched versions that cannot be evaluated without guessing, or that contradict each other for the exact version, are listed in coverage.
- `runners check --live` probes the runner's public web research.
- Research events take `source_facts`: advisory IDs, affected versions, fix location, fixing change and required feature, as the upstream item states them. Cases keep them on their upstream event and reports show them. `fixed_in_monitored_version` requires `fixed_in`, and `affects_other_version` requires `affected_versions`.
- Seen events in the research plan carry the recorded assessment, reason and the start of the rationale, so unchanged items are not reviewed again. `context_current` is false when the monitored instances changed since that assessment or the target gained instances the event does not cover; such events are reviewed again.
- `research --reopen <upstream|all> --since <RFC3339>` moves completed review checkpoints back, for example after the screening method improved.
- `schedule remove` uninstalls a project's managed timer and service.
- `tools hits` reads the tracker responses the agent fetched with `gh` and `curl` (GitHub issues, pull requests, releases, repository advisories and discussions; GitLab; Forgejo; Jira REST v2 and v3, with the Red Hat and JBoss trackers requested at their current `redhat.atlassian.net` site; agent-written items for other trackers), lists missing files with their exact request, rejects empty or non-JSON response files, screens items on title, labels, body and closed issues, skips unchanged seen items, resolves cited advisories against the inventory, and settles fix PRs, dependency relays, repository advisories and fully published releases by rule. The CLI still makes no tracker requests.
- `tools draft` builds and optionally imports the research batch from those rules and a durable decisions file keyed by item and update time; `--partial` keeps incomplete sources partial.
- `tools impact` and `tools triage` apply impact answers and verdicts for many cases from one file, registering referenced notes once. `tools pending` lists open verifications, missing verdicts, open research windows and unfinished general discovery (pending directories and files, components with neither a source mapping nor an `unavailable` observation), and exits 2 until the report is deliverable.
- `tools workspace init` creates the monitor folder layout described in the Skill's new `references/workspace.md`.
- Schemas `decisions`, `impact-batch`, `verdict-batch` and `items`, and the `commit` research event kind.
- Profile `report.language` (`en` by default, or `es`) sets the language of the Markdown report, of the sentences the CLI stores in report JSON and of the rationales `tools hits` records. The scheduled reporting and research agents are told to write in it, keep technical terms that the language usually leaves untranslated (issue, pull request, commit, release, lockfile, sandbox, upstream) and quote source text as recorded. Report JSON carries `language`.

### Changed

- Advisory evidence is stored as canonical JSON, and case facts include only advisory and non-applicability evidence. Rescans and source or CPE enrichment keep recorded verdicts. A real advisory change adds a reassessment question when the case had a verdict or an impact assessment.
- Research creates one case per upstream event with every affected instance, folding older per-instance cases.
- Discovery skips git-ignored paths, dependency and build output, files that cannot declare dependencies, and scripts without inline dependency metadata, and records each reason. It expands up to 64 directories per plan, and profile edits keep reviewed files. Adding or removing a workspace keeps the reviews, packages and source maps of the workspaces that stay. When exclusion rules change, walked directories are listed again so existing entries are reclassified without repeating unchanged reviews. Excluding a directory matches its subtree by literal path prefix, and discovery and inventory paths use `/` on every platform.
- Components without a mapped repository count as unavailable sources and are retried after 7 days.
- Source mappings of lockfile and SBOM packages survive edits to the same file that leave the package unchanged; declared and observed components are still remapped when their declaration changes.
- With general discovery enabled, manifests without a native parser that discovery already reviewed or excluded, and workspaces without a native lockfile, no longer add inventory gaps; the discovery coverage row reports them.
- Impact assessments of cases without an authoritative affected claim, such as upstream research cases, return `not_affected` or `mitigated` when a project condition is absent or a mitigation is recorded; exposure still requires confirmation.
- A walk reclassifies entries between unavailable and excluded, so media and other files that cannot declare dependencies no longer block completeness after an earlier read failure.
- A Maven component whose `groupId:artifactId` is the project of a workspace root `pom.xml` (for example the provider JAR inside an image SBOM) is first-party: it needs no public source mapping, is left out of the source map and no longer keeps discovery partial.
- `discovery` offers registry mappings without a repository to the agent until it records its own observation; `--map-registries` does not refetch them before the retry window.
- Markdown report: the source map shows one row per component with open cases (repository, other mapped sources, unmapped categories), a single-instance case no longer repeats its verdict per instance, and "local verification not run" appears only while the case still needs project evidence.
- `discovery --gaps` lists unavailable entries first, then removed ones, then audited exclusions.
- Maven registry mapping builds the effective POM: it follows literal `<parent>` POMs (up to five levels) for undeclared `scm`, `issueManagement` and `url`, interpolates `${...}` from the merged chain properties and `project.*`/`project.scm.tag`, accepts sections with attributes, falls back to `connection`/`developerConnection` (and prefers them when `scm/url` is a non-forge page such as the project website), converts SSH and `git://` coordinates to HTTPS only for GitHub, GitLab and Bitbucket, drops URLs with undefined properties, and records each POM as evidence. Literal URLs are inherited only from reactor parents (same version and related groupId); organisation-wide parents such as `jboss-parent` lend only templated `${...}` URLs, so their own repository and tracker are not attributed to children. The mapper revision is stored in the rationale; native Maven mappings from an earlier revision are mapped again.
- Self-hosted `gitlab.*` links collapse to one project like `gitlab.com`, including legacy `/issues` and `/merge_requests` routes, so a repository and its tracker are one research target.
- Native registry mapping checks a declared GitHub repository: an HTTP 404 leaves the repository (and issues or website on the same repository) unmapped with the reason, so the component is offered to the agent instead of producing a dead research target. An issue tracker on another GitHub repository that answers 404 is left unmapped the same way.
- OSV matches produced only by an open GHSA range are recorded as not affected when `last_known_affected_version_range` and the other entries for the package exclude the version. Cases whose claims are all not affected become informational instead of in review.
- Research plans one target per forge repository, from repository, issue, proposed-change, discussion, changelog and advisory sources only. Clone, tree and issue links collapse to `host/owner/repo`, and URLs with unresolved `${...}` placeholders are dropped.
- Reports list references only for open cases and summarize inventory per lockfile and coverage gaps by reason. Full detail stays in JSON.
- Actionable and in-review cases whose impact is recorded as not affected or mitigated collapse into one table row per component and recorded reason, citing advisory IDs or `owner/repo#number`. Exposed cases keep full cards, ordered by impact, with the action and open questions derived from the impact assessment. Coverage scopes name the component instead of the instance ID.
- A claim case takes over the research case that reported the same advisory ID for the same instances, keeping its upstream events and evidence, instead of leaving two cases. An existing claim case keeps its ID, preferring the one with a recorded verdict or impact assessment, and keeps its upstream events across rescans.
- Case references from a recorded advisory page list only the advisories the case claims, not every advisory of the repository. Repository advisory claims show their `patched_versions` as published fixes, and the source map no longer lists security advisories as unmapped for a mapped GitHub repository, whose advisories the scan reads and reports in coverage.
- Markdown reports name sources, evidence and event kinds in the report language (for example "Repository advisory (GitHub)" instead of `github_repository`), show decisions and coverage states in it, and escape underscores only where Markdown could read them as emphasis. JSON keeps the keys. Reports are no longer fixed to Spanish and no longer mix Spanish and English labels.
- The research plan policy and the Skill require screening titles, labels and bodies (up to the 8000-character excerpt), with strong signals in the body selecting an item for review.
- The Skill assesses a release through its own event when it cites unpublished advisories, and records dependency-update PRs that relay an already assessed advisory as `ignore` naming that event.
- CLI output to a pipe closed early (`| head`) exits cleanly instead of panicking.
- `case` evidence and blocker operations return only the added evidence.
- `case --validation-blocker` without `--instance` records the blocker for every instance of the case.
- A current `lab_reproduced` attestation confirms the affected version of its own instance, also in cases with several instances; other instances stay unconfirmed.
- Markdown report: identical local checks and per-instance impact verdicts of one case are listed once with their instance count. Cards and tables list more than three components that share version and location as one count with examples, and source-map rows that differ only in their per-component release page become one row; JSON keeps every component. A review case whose local checks are all blocked names resolving the recorded blocker as its next step.
- Commands wait up to 120 seconds (`VULNBELL_LOCK_WAIT_SECONDS`) for a busy project lock.
- Sandbox `prepare` and `doctor` name the supported Microsandbox release and show failing runtime checks.
- The Skill requires judging upstream events against the monitored version and resolving pending verification before delivering a report.
- The Skill derives each triage verdict from its impact verdict, so a case assessed `not_affected` or `mitigated` is recorded as informational instead of staying actionable. It defines which technical blockers allow a partial report (the item count and time spent are not among them), requires checking the `--map-registries` output, asks for operating-system packages in image SBOMs, and requires confirming that a lockfile dependency is built for the shipped target and not only called from tests. A new "Use the sandbox" section says when a test confirms a doubtful positive or rules out a false positive, that tests are presented to the user for authorization in one request (a test awaiting authorization is not a blocker), and when to raise the profile limits.
- The documentation, the Skill and `tools workspace init` name the monitor profile `vulnbell.yaml` instead of `radar.yaml`. The CLI still accepts a profile at any path; rename an existing profile, then rerun `scan` to register the new path and `schedule install` to update an installed timer.

## 0.1.1 - 2026-10-26

### Added

- Default-on general discovery with a per-project opt-out, persistent workspace pages, evidence-linked observations and public source maps.
- Tool-free scheduled workspace extraction, separate public discovery, discovery status and report coverage.
- Read-only Python helper and ecosystem-specific Skill guidance for structured manifests.

### Changed

- Updated direct and transitive dependencies, including HTTP/TLS, SQLite, cryptography and manifest parsers.
- Project schedules reference a machine-local runner ID. Typed adapter settings are configured and checked separately.
- Project state uses schema 2. Databases from 0.1.0 are rejected without conversion; create new monitors.
- Scheduled report paths and runner availability are exposed through CLI status.
- Reports explain each case status and show the evidence, unresolved conditions and next step for cases in review.

## 0.1.0 - 2026-10-25

### Added

- Rust CLI and Agent Skill for monitoring products, binaries, repositories, and package inventories.
- Advisory coverage for OSV, GitHub Security Advisories, RustSec, CVE Records, NVD, CISA KEV, CSAF, and OpenVEX.
- Upstream review contracts for GitHub, GitLab, Launchpad, and similar trackers.
- Evidence-bound impact assessment for projects with or without a local workspace.
- Microsandbox verification with reviewed staging, network isolation, positive controls, and attestations.
- Per-project scheduled Codex and OpenCode runs with execution windows, skipped-run tracking, and concise Markdown reports.
- Persistent project status, source coverage, failures, reports, and generated JSON Schemas.
