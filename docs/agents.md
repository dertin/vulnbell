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

The Skill guides the local agent through profile creation, inventory, advisory checks, upstream research, impact assessment, sandbox approval, reporting, and status checks. The CLI preserves the same projects, cases, evidence, impact answers, sandbox attestations, and reports when the configured runner changes.

For unattended runs, choose one of the runner values exposed by `vulnbell schema schedule --json` and provide its absolute executable path. The runner receives a bounded research request through standard input and returns validated JSON. Report generation receives only recorded data and returns Markdown. Missing credentials, invalid output, unavailable providers, and permission failures produce a partial report instead of hiding the failed step.

Scheduled research can access public web evidence. It cannot inherit local shell access, project tools, plugins, hooks, or connected applications. Report generation has no tools. See [Agent security](agent-security.md) for the permission boundary.
