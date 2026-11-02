# Reports

Generate a candidate with `vulnbell report --project <profile> --audience cyber`; the CLI renders recorded facts and decisions. Read the entire candidate, using bounded sections as needed, plus the relevant verification and evidence metadata. Write a concise executive summary in the report language covering the whole report: material actions, review items, overall scope, meaningful coverage gaps and unresolved questions. Distinguish verified facts from assumptions and don't claim complete coverage when gaps remain. Add it near the start of a copy under the heading `Executive summary` or its equivalent in the report language, without adding authorship to the heading; preserve the CLI's status and findings. Summarize recorded evidence; do not invent conclusions or silently omit a material category. Distinguish local or test configurations without suppressing their security relevance, and do not claim production deployment without evidence. If a requested scanner check could not run and that limitation is absent, add a concise labelled agent note with the missing check, reason and next step. Use `--json` and `--audience audit --json` for structured case and evidence metadata.

Keep the VulnBell project link at the start and the generated-with attribution at the end of the Markdown report. The PDF ends with the same attribution after its evidence appendix.

In shareable report text, identify the reviewed codebase by name and cite paths relative to it, including line numbers. When multiple codebases are in scope, identify which codebase each path belongs to. Do not expose local machine paths in agent-written summaries or notes; keep operational paths and original evidence in VulnBell's local state. The CLI normalizes known codebase roots, but review other text and paths for sensitive local details before sharing.

To produce Markdown and a PDF with a verification section and evidence appendix:

```sh
vulnbell report --project <profile> --audience cyber > <candidate.md>
vulnbell report --project <profile> --audience cyber --from-markdown <reviewed.md> --custom-reason '<brief reason>' --pdf <new-report.pdf>
```

A local Chromium-based browser is required. Use `--pdf-browser <executable>` when it is not on PATH. The CLI does not overwrite an existing PDF. Write the summary and any translations into `<reviewed.md>` after reading the candidate, then pass a short, accurate reason such as `Agent summary and reviewed translations` in the report language. The PDF labels edited text as not validated by the CLI and retains current recorded verification details; an edited verification section is preserved separately. Review the resulting Markdown and PDF before delivery. Do not use the em dash character in report prose; preserve evidence and functional URLs.

The appendix contains case statuses, recorded impact answers, source claims, evidence identifiers, SHA-256 values, integrity status, registered local notes and textual sandbox output. It does not embed original external documents, full responses or binary artifacts; unavailable or invalid evidence remains visible. Review the PDF before sharing: notes, paths and deployment details may be confidential. A PDF cannot establish that omitted or unavailable evidence was reviewed.

For each actionable source description in another language, translate the actual advisory accurately into the report language and keep the source and original available. Prefer recording `advisory_translation` on the current verdict with the original advisory evidence SHA-256, target language and reviewed summary; do not change an existing decision merely to translate it. If recording it would alter a valid verdict or the relevant source is unavailable, add a labelled translation to the reviewed report copy or leave an explicit translation-pending indication. Never present a translation as a quotation or replace the source evidence.

If a user requests questions for responsible teams, ask only for facts that could change a decision, identify the related cases and environment, and do not ask for secrets. When answers arrive, record their source and scope, verify the codebase and inventory, then reassess affected cases before regenerating the report. Do not turn uncertainty into a negative verdict or present incomplete work as complete.

For a time-bounded review, retain the CLI's partial status and save the unfiltered `vulnbell tools queue --project <profile> --limit 1000` beside the report; paginate when needed. Progress and priority do not settle a case. Report wall time separately from model execution time.

Closed case detail: `--closed summary` lists informational cases compactly and keeps their details and evidence in JSON; it is the default for Cyber and manager. Use `--closed full` for the full appendix or `--closed none` to omit closed cases. Audit defaults to full. Retracted observations remain in JSON with their history and are omitted from Markdown and PDF.
