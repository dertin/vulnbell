# Security

Report VulnBell vulnerabilities through [a private GitHub advisory](https://github.com/dertin/vulnbell/security/advisories/new). Do not post credentials, private findings from monitored projects, or exploits in public issues.

Profiles, repositories, feeds, issues, and test results are untrusted inputs. Inventory scans do not execute project code. Active tests run only in Microsandbox, with approval and limits.

The CLI HTTP connector uses HTTPS. It checks public DNS addresses and connects to those checked addresses. It disables redirects and inherited proxies, and limits request time and response size. Tokens go only to their matching provider. `scan --offline` also skips notifications.

Keep data, credentials, reports, and backups private. Local attestations record integrity checks and observations; they do not certify that a program is safe.

[Agent permissions](docs/agent-security.md) · [Sandbox](docs/sandbox.md) · [Coverage](docs/coverage.md)
