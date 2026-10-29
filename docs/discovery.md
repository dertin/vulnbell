# General discovery

General discovery supplements native lockfile parsers. It is enabled by default for workspaces and software described without local files. Set `discovery: off` in the profile, or ask the agent to disable it, to opt out.

## Workspace inventory

The agent identifies the language, package manager, manifest/lock formats, nested projects, includes and dependency scopes. It follows the official format documentation and uses read-only parsers or the bundled Python JSON/TOML/XML helper. Build tools, project plugins and install hooks are never executed on the host.

```sh
vulnbell scan --project vulnbell.yaml --json
vulnbell discovery --project vulnbell.yaml --limit 10 --json
vulnbell schema discovery --json
vulnbell discovery --project vulnbell.yaml --from observations.json --json
```

The CLI enumerates directories in pages and returns bounded text fragments. There is no discovery depth or total file-count cutoff. Each import checks the project scope, file identity, offset, hash and verbatim dependency excerpt. State persists between commands and scheduled runs. Changed content invalidates its imported observations. Adding or removing a workspace keeps the reviews of the workspaces that stay; only new or changed files are reviewed again. A VulnBell update with new exclusion rules lists walked directories again and reclassifies their entries; unchanged reviewed files keep their review. Ranges and unknown versions are not installed-version evidence; agent observations remain distinct from native lockfile records and deployment evidence.

Private credential paths, symlinks and VCS metadata are excluded. Paths matched by the workspace `.gitignore` files are also excluded, as are dependency and build output such as `node_modules`, `.venv`, generated `.sqlx` query metadata and a `target` directory next to `Cargo.toml` or `pom.xml`. Files that cannot declare dependencies are skipped without agent review: compiled-language source, documentation, SQL scripts, media, licenses, Java `META-INF/services` registrations and repository metadata such as `.gitignore`. Files with native parsers are skipped too. Python, JavaScript/TypeScript and Ruby scripts are skipped only when they contain no inline dependency metadata (PEP 723 block, URL, `npm:` or `jsr:` imports, `bundler/inline`), and they are inspected again when they change. Binary artifacts such as `.jar`, `.whl` and archives, binary/non-UTF-8 files, inaccessible directories and unsupported text stay visible as gaps. Each exclusion records its reason. `vulnbell discovery --project vulnbell.yaml --reopen <relative-path>` queues a reviewed or unavailable file for review again. Editing the profile without changing the workspace roots keeps reviewed files.

A Maven-style `${property}` version can be imported with `version_excerpt`, a verbatim line from the same file that defines the property. Imported dependencies and native lockfile records carry `path:line` provenance into reports. The structured helper has a 16 MiB input budget; the CLI reads larger text files in fragments. Native parser and network budgets remain visible as separate coverage limits.

Inspect every gap page with:

```sh
vulnbell discovery --project vulnbell.yaml --gaps --json
vulnbell discovery --project vulnbell.yaml --gaps --after <next_cursor> --json
```

## Public source map

After importing inventory, rescan. Registry packages are mapped natively first:

```sh
vulnbell discovery --project vulnbell.yaml --map-registries --limit 200 --json
```

This reads crates.io, npm, PyPI and Maven Central records and stores each document as evidence. It maps the declared repository, website, issue tracker, documentation and changelog, and paces requests to one per second. A Maven POM that leaves `scm`, `issueManagement` or `url` undeclared inherits them from up to five literal `<parent>` POMs, each stored as evidence; a parent with a `${...}` coordinate ends the chain. Literal URLs come only from reactor parents (same version and a related groupId); an organisation-wide parent such as `jboss-parent` describes its own project, so only its templated `${...}` URLs are inherited. `${...}` in URLs is interpolated from the merged chain properties (the child wins) and `project.*` coordinates; a URL with an undefined property is left unmapped. The repository comes from `scm` `url`, then `connection`, then `developerConnection`, preferring the first on GitHub, GitLab or Bitbucket when `url` is another page such as the website; SSH and `git://` coordinates become HTTPS only on GitHub, GitLab and Bitbucket. Native Maven rationales carry the mapper revision, and a mapping from an earlier revision is mapped again on the next `--map-registries` run. A declared GitHub repository that answers HTTP 404 is left unmapped with that reason, together with issues or website on the same repository, and so is an issue tracker on another GitHub repository that answers 404; other forges are not probed because they answer anonymous requests ambiguously. A rate-limit response stops the run; the remaining packages stay pending. `--offline` uses only cached records. A Maven component built by a workspace root `pom.xml` is first-party: its source is the monitored workspace, so it is not mapped. Components still without a repository are offered to the agent in `discovery` `components` until it records its own observation, and appear in the report's source map and are retried after 7 days.

The agent discovers sources within the selected tracker scope, including selected software with no known repository. For each selected component it maps website, repository, issues, proposed changes, discussions, documentation, changelog, releases and advisories. A category can have several URLs or a documented unavailable/not-applicable disposition. Deferred transitives and unknown-depth instances remain inventoried and are reported as a coverage limit.

`research` plans only repository, issues, proposed changes, discussions, changelog and advisories sources. GitHub, GitLab and Bitbucket links (clone URLs, `/tree/...`, `/issues`) collapse to `https://host/owner/repo`, so a project is reviewed once. URLs with unresolved build placeholders such as `${project.scm.tag}` are dropped.

```sh
vulnbell discovery --project vulnbell.yaml --evidence-url https://example.org/project --json
vulnbell discovery --project vulnbell.yaml --from sources.json --json
vulnbell scan --project vulnbell.yaml --json
vulnbell research --project vulnbell.yaml --json
```

The agent corroborates official identity with vendor, registry and documentation links. The CLI acquires supporting documents with public HTTPS destination checks, no credentials and no redirects. Imported source URLs must be present in acquired evidence or identify the acquired page itself. Acquiring a page establishes its recorded content and provenance; the identity association remains an agent assessment. Guessed mappings cannot certify affectedness or authorize active tests.

Mapped URLs become independent research targets with review windows and seen events. Research covers linked context and pagination. The report keeps the complete source map and references; `status` shows discovery progress. Access limits, incomplete maps and unfinished file reviews remain partial.

## Scheduled runs

Scheduled discovery runs before upstream research. Workspace extraction receives one text fragment at a time and has no tools. Public source discovery receives only component references, versions and known public URLs. It has public web research tools and cannot access workspace files. The CLI acquires proposed source documents before importing them. Report generation has no tools.

The execution window bounds each run. If discovery cannot finish, its queue persists and the report is partial. A later run resumes pending work. Static applicability assessment and active sandbox tests still follow their separate evidence and authorization workflow.
