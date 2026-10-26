# General discovery

General discovery supplements native lockfile parsers. It is enabled by default for workspaces and software described without local files. Set `discovery: off` in the profile, or ask the agent to disable it, to opt out.

## Workspace inventory

The agent identifies the language, package manager, manifest/lock formats, nested projects, includes and dependency scopes. It follows the official format documentation and uses read-only parsers or the bundled Python JSON/TOML/XML helper. Build tools, project plugins and install hooks are never executed on the host.

```sh
vulnbell scan --project radar.yaml --json
vulnbell discovery --project radar.yaml --limit 10 --json
vulnbell schema discovery --json
vulnbell discovery --project radar.yaml --from observations.json --json
```

The CLI enumerates directories in pages and returns bounded text fragments. There is no discovery depth or total file-count cutoff. Each import checks the project scope, file identity, offset, hash and verbatim dependency excerpt. State persists between commands and scheduled runs. Changed content invalidates its imported observations. Ranges and unknown versions are not installed-version evidence; agent observations remain distinct from native lockfile records and deployment evidence.

Private credential paths, symlinks and VCS metadata are excluded. Binary/non-UTF-8 files, inaccessible directories and unsupported text stay visible as gaps. The structured helper has a 16 MiB input budget; the CLI reads larger text files in fragments. Native parser and network budgets remain visible as separate coverage limits.

Inspect every gap page with:

```sh
vulnbell discovery --project radar.yaml --gaps --json
vulnbell discovery --project radar.yaml --gaps --after <next_cursor> --json
```

## Public source map

After importing inventory, rescan. The agent discovers sources for all components, including software with no known repository. Every component maps website, repository, issues, proposed changes, discussions, documentation, changelog, releases and advisories. A category can have several URLs or a documented unavailable/not-applicable disposition.

```sh
vulnbell discovery --project radar.yaml --evidence-url https://example.org/project --json
vulnbell discovery --project radar.yaml --from sources.json --json
vulnbell scan --project radar.yaml --json
vulnbell research --project radar.yaml --json
```

The agent corroborates official identity with vendor, registry and documentation links. The CLI acquires supporting documents with public HTTPS destination checks, no credentials and no redirects. Imported source URLs must be present in acquired evidence or identify the acquired page itself. Acquiring a page establishes its recorded content and provenance; the identity association remains an agent assessment. Guessed mappings cannot certify affectedness or authorize active tests.

Mapped URLs become independent research targets with review windows and seen events. Research covers linked context and pagination. The report keeps the complete source map and references; `status` shows discovery progress. Access limits, incomplete maps and unfinished file reviews remain partial.

## Scheduled runs

Scheduled discovery runs before upstream research. Workspace extraction receives one text fragment at a time and has no tools. Public source discovery receives only component references, versions and known public URLs. It has public web research tools and cannot access workspace files. The CLI acquires proposed source documents before importing them. Report generation has no tools.

The execution window bounds each run. If discovery cannot finish, its queue persists and the report is partial. A later run resumes pending work. Static applicability assessment and active sandbox tests still follow their separate evidence and authorization workflow.
