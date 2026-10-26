# VulnBell — Sample report

Cutoff: 2026-10-25 22:52 UTC · Coverage: partial

| Status | Cases | Meaning |
|---|---:|---|
| Actionable | 1 | Affected artifact/version confirmed; assess project impact and update or mitigate. |
| In review | 0 | An issue/PR signal, uncertain artifact identity, or incomplete/conflicting evidence still needs corroboration. |
| Informational | 0 | Useful context with no pending security action. |
| Dismissed | 0 | An evidence-backed verdict closed the case within the assessed scope. |

Counts refer to cases. Incomplete source or inventory checks are listed separately under coverage gaps.

## Inventory

| Component | Version | Origin |
|---|---|---|
| @nestjs/core (npm) | 10.4.8 | tracked; declared |

No workspace or deployment inventory was provided.

## Actionable

### SIG-d92c7ad148de84684bab — SSE event injection

- **Component:** @nestjs/core 10.4.8.
- **Status:** affected by GHSA-36xv-jgw5-4q75; reproduced in an isolated minimal project.
- **Problem:** `SseStream._transform()` accepts CR/LF in `message.type` and `message.id`. An application that maps untrusted values to those fields can forge SSE fields or events.
- **Required conditions:** the application uses NestJS SSE and assigns untrusted data to `type` or `id`. Ordinary request input does not reach these fields automatically.
- **Fix:** 11.1.18 removes CR/LF. Confirm branch compatibility or a supported backport before upgrading a 10.x application.
- **Project impact:** **needs evidence** · low confidence. The library behavior is confirmed, but deployment, affected-feature use, input reachability, and mitigation are unknown because this monitor has no workspace or deployment evidence.
- **Action:** if 10.4.8 is deployed, check the five impact questions. Prioritize the update if the affected fields receive untrusted data; otherwise keep it in the normal upgrade plan.

| Project condition | Answer | Evidence |
|---|---|---|
| Exact artifact deployed | Unknown | No workspace, SBOM, or deployment record |
| Affected SSE fields used | Unknown | No project source |
| Untrusted input reaches those fields | Unknown | No project source or data-flow evidence |
| Advisory conditions present | Unknown | No project configuration |
| Fix or mitigation applied | Unknown | No deployment evidence |

## In review

No open hypotheses in this scan.

## Local verification

| Scope | Target | Control | Result |
|---|---|---|---|
| Minimal Node project from checksummed npm artifacts | 10.4.8 emits injected SSE fields | 11.1.18 removes CR/LF | reproduced |

The test ran as a non-root user in Microsandbox 0.7.11 with network denied and no host mounts. The runtime recorded the image digest, artifact hashes, effective policy, job status, stdout, and attestation.

## References

- [Vendor advisory](https://github.com/nestjs/nest/security/advisories/GHSA-36xv-jgw5-4q75)
- [GitHub reviewed advisory](https://github.com/advisories/GHSA-36xv-jgw5-4q75)
- [OSV record](https://osv.dev/vulnerability/GHSA-36xv-jgw5-4q75)
- [CVE record](https://nvd.nist.gov/vuln/detail/CVE-2026-35515)
- [Fix pull request](https://github.com/nestjs/nest/pull/16686)
- [Fix commit](https://github.com/nestjs/nest/commit/83558ae774a990a7916141d3abe0b6548ff3a8b2)
- [Fixed release](https://github.com/nestjs/nest/releases/tag/v11.1.18)
- [Tested package](https://registry.npmjs.org/%40nestjs%2Fcore/10.4.8)

## Coverage gaps

| Source | Gap | Effect |
|---|---|---|
| Deployment | No workspace, SBOM, or deployment record | Project exposure cannot be claimed |
| NVD mapping | No validated CPE for this npm instance | NVD is not used for version applicability |
