# Workspace layout and daily run

Keep every artifact of a monitor in one VulnBell workspace agreed with the user, for example `~/vulnbell`. Create or complete it with `vulnbell tools workspace init --directory <workspace> --monitor <name>`; it prints these paths, today's run directory and whether the profile exists.

```text
<workspace>/
  notes/                          reviewed deployment facts shared by several monitors
  monitors/<monitor>/
    vulnbell.yaml                 monitor profile
    decisions/research.json       durable research decisions (`vulnbell schema decisions`)
    notes/                        case evidence notes with path:line references
    sources/                      upstream source excerpts read statically, with their sha256
    runs/<YYYY-MM-DD>/
      raw/                        gh/curl responses in the layout `tools hits` reports
      hits.json                   review packet
      batch.json                  research batch written by `tools draft`
      impact.json, verdicts.json  case batches (`vulnbell schema impact-batch|verdict-batch`)
    reports/<YYYY-MM-DD>.md       delivered report
```

- Runs are disposable after the report is delivered. Decisions, notes and reports are durable; never rewrite a delivered report.
- Write no secrets, tokens, `.env` contents or whole private files into the workspace. Notes quote only the lines needed, with `path:line`.
- Do not keep helper scripts here. The tools cover screening, batch building and bulk case updates; when a recurring step is missing, tell the user.
- Never execute anything stored in `raw/` or `sources/`.

## Daily run

Requires `gh` (authenticated), `curl` and `jq`. Paths below are relative to `monitors/<monitor>/`; `<run>` is today's run directory.

1. `vulnbell scan --project vulnbell.yaml --json`, then `vulnbell tools workspace init` for today.
2. `GITHUB_TOKEN=$(gh auth token) vulnbell tools hits --project vulnbell.yaml --raw <run>/raw --decisions decisions/research.json --output <run>/hits.json`. Exit 2 means responses are missing or unreadable: fetch what `missing` lists as described in `references/upstream-research.md`, then rerun. Paged sources list one page at a time.
3. Read every item in `review` (snippets, cited advisories with their build matches, unpublished IDs, the previous decision of an updated item). Open the item URL when the snippets do not settle it. Add one decision per item to `decisions/research.json` with the item's `updated_at`, then rerun `hits` until `review` is empty. Deterministic rules settle unchanged items, fix PRs, dependency relays, repository advisories and fully published releases; a decision for the same key overrides a rule.
4. `vulnbell tools draft --project vulnbell.yaml --raw <run>/raw --decisions decisions/research.json --output <run>/batch.json --import`. Without `--partial` it refuses missing responses and undecided items. With `--partial` those sources stay partial and their checkpoints do not advance; say so in the report.
5. `vulnbell inbox --project vulnbell.yaml --json` and investigate the open cases (`references/investigation.md`). Write notes under `notes/`, then apply impact answers and verdicts in bulk with `vulnbell tools impact --project vulnbell.yaml --from <run>/impact.json` and `vulnbell tools triage --project vulnbell.yaml --from <run>/verdicts.json`. Note paths in a batch are relative to the batch file. Exit 2 lists the cases that failed; the others are applied.
6. `vulnbell tools pending --project vulnbell.yaml` lists open verifications, cases without a verdict for their current facts, and research windows still open. Deliver when it exits 0, or when every remaining item has a recorded technical blocker that the report explains.
7. `vulnbell report --project vulnbell.yaml --audience cyber` into `reports/<YYYY-MM-DD>.md`, following `references/reporting.md`.
