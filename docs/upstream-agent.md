# Upstream research

The local agent uses its own browser, search, and connectors to review GitHub issues and pull requests, GitLab issues and merge requests, Launchpad bugs and merge proposals, and related trackers. Rust stores inventory, times, known IDs, hashes, snapshots, cases, and import checks. The CLI does not scrape these sites or classify issues by keywords. Advisory APIs are separate CLI integrations.

`vulnbell research --project radar.yaml --json` returns a review window for each verified upstream. The first window covers 30 days. After a complete review, the next window starts at that checkpoint with a five-minute overlap. Scans can continue while the agent is unavailable without losing the unreviewed period. Seen events include IDs and content hashes. New comments, code changes, or conditions can make a known issue worth reviewing again. Missing or partial research, including rate limits, does not advance the checkpoint.

The agent checks more than titles marked “security.” Ordinary bug reports can describe attack conditions. It records unrelated items as seen, uncertain reports as hypotheses, and useful context as informational. Issues, proposed fixes, and news are not authoritative vulnerability reports. Stronger conclusions need evidence from the exact release, deployment context, public advisories, or a controlled lab test.

The JSON import contract (`schema research`) checks the project, snapshot, upstream, instance IDs, and time window. It hashes observations, keeps history, skips unchanged records, and reopens meaningful changes. `complete` means **the agent reports** that it reviewed the full available window. The CLI cannot verify unseen website content. The Skill requires page coverage, event coverage, and evidence links. Private or inaccessible content remains a gap.

Code and bugs may be hosted on different sites. The agent must verify official links between them rather than infer identity from a name. Launchpad uses bugs and merge proposals. Its resource documentation defines available filters; `modified_since` is not supported on every operation.

See the [research instructions](../skills/vulnbell/references/upstream-research.md), [automation](automation.md), [sandbox](sandbox.md), and [coverage](coverage.md).
