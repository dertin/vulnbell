# Translating user intent to a profile

Load this only when creating or editing a monitor.

1. CLI schema is authoritative: `vulnbell schema profile --json`. The project profile (`radar.yaml`) can describe **zero local workspaces** and **one or more manual components**.
2. Use `vulnbell init --output <approved-path>/radar.yaml` to generate a stable `project_id`, then edit the YAML. Do not put ephemeral resolved inventories in YAML; they belong to the CLI's state database.
3. `workspaces` contains only paths the user explicitly authorized. `components` declares products, binaries or package references given verbally; for packages use **unversioned PURL** in `ref` and put the exact version in `version`.
4. `version` may be exact, the literal `latest` if specifically requested, or omitted (unknown). **Do not infer** a deployment version from a lockfile or set `usage: deployed` without evidence/user statement. Default usage is `tracked`.
5. Aliases such as `keycloak`, `wordpress` or `php` are hypotheses until the CLI resolves their identity from supported sources. For custom binaries, use `upstream` where supplied, but do not claim CVE applicability without validated mapping.
6. Metadata for web/news research belongs in `research.web: agent` and optional public `research.topics`. Do not serialize private URLs, secrets or source fragments into search queries.
7. Validate locally with `vulnbell validate <path> --json`, repair only indicated errors, then `vulnbell scan --project <path> --json` to check external resolution/coverage. Report missing versions and ambiguous identities rather than guess.
8. When changing an existing profile, retain `project_id`, components not targeted by the instruction, history, alerts and schedule. Show an accurate concise diff before making consequential changes.

Use `examples/manual-project.yaml` and `examples/mixed-project.yaml` from the installed project docs as examples; **do not** treat their versions as defaults.
