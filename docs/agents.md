# Agent integration

VulnBell ships an Agent Skills package. Install it with:

```sh
vulnbell skills install
vulnbell doctor --json
```

The default Skill location is:

| System | Directory |
|---|---|
| Linux and macOS | `$HOME/.agents/skills/vulnbell` |
| Windows | `%USERPROFILE%\.agents\skills\vulnbell` |

The Skill guides the current interactive agent through profile creation, inventory, advisory checks, upstream research, impact assessment, sandbox approval, reporting, and status checks. The CLI preserves the same projects, cases, evidence, impact answers, sandbox attestations, and reports when the configured runner changes.

The CLI accepts the current configuration and state contracts. If a project database has an incompatible schema, create a new monitor with a new project ID. Existing state is not converted or deleted.

Scheduled execution starts a separate local runner. It does not reuse the interactive conversation or load the installed Skill. Configure that runner once with `vulnbell runners configure`, reference its ID from project schedules, and verify it with `vulnbell runners check`.

The runner receives bounded requests through standard input and returns validated JSON. Workspace discovery reads supplied fragments without tools. Public discovery and research receive public identities without workspace text. Report generation receives recorded data and returns Markdown. Missing credentials, invalid output, unavailable providers, and permission failures produce a partial report. See [Local runners](runners.md).

Scheduled research can access public web evidence. It cannot inherit local shell access, project tools, plugins, hooks, or connected applications. Report generation has no tools. See [Agent security](agent-security.md) for the permission boundary.
