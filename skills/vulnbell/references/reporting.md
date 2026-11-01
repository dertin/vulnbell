# Reports

Generate the standard report with `vulnbell report --project <profile> --audience cyber`; the CLI renders the recorded facts and decisions. Do not rewrite or summarize it with an LLM unless the user requests a different presentation. Use `--json` and `--audience audit --json` for structured case and evidence metadata. The report follows the profile's `report.language` and retains coverage gaps and unresolved work.

To produce Markdown and a PDF with a verification section and evidence appendix:

```sh
vulnbell report --project <profile> --audience cyber --pdf <new-report.pdf> > <new-report.md>
```

A local Chromium-based browser is required. Use `--pdf-browser <executable>` when it is not on PATH. The CLI does not overwrite an existing PDF. For a user-requested customization, edit a copy of the Markdown and add `--from-markdown <edited.md>` to the PDF command. The PDF labels customized text as unvalidated by the CLI and retains current recorded verification details; an edited verification section is preserved separately.

The appendix contains case statuses, recorded impact answers, source claims, evidence identifiers, SHA-256 values, integrity status, registered local notes and textual sandbox output. It does not embed original external documents, full responses or binary artifacts; unavailable or invalid evidence remains visible. Review the PDF before sharing: notes, paths and deployment details may be confidential. A PDF cannot establish that omitted or unavailable evidence was reviewed.

If a user requests questions for responsible teams, ask only for facts that could change a decision, identify the related cases and environment, and do not ask for secrets. When answers arrive, record their source and scope, verify the codebase and inventory, then reassess affected cases before regenerating the report. Do not turn uncertainty into a negative verdict or present incomplete work as complete.

For a time-bounded review, retain the CLI's partial status and save the unfiltered `vulnbell tools queue --project <profile> --limit 1000` beside the report; paginate when needed. Progress and priority do not settle a case. Report wall time separately from model execution time.
