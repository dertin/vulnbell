use super::{
    inline,
    text::{self, fill},
};
use crate::{
    impact::{ImpactResult, ImpactVerdict},
    model::{Case, Decision, EvidenceKind, Verification},
    profile::Language,
    sandbox::{BlockerKind, TestContext, TestSpec},
    store::Store,
};
use anyhow::{Result, bail};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Serialize, JsonSchema)]
pub struct FindingReference {
    pub id: String,
    pub kind: String,
    pub url: String,
}
#[derive(Serialize, JsonSchema)]
pub struct FindingCheck {
    pub case_id: String,
    pub decision: Decision,
    pub references: Vec<FindingReference>,
    pub local_checks: Vec<LocalCheck>,
    pub impact: Option<ImpactResult>,
}
#[derive(Serialize, JsonSchema, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LocalResult {
    NotRun,
    Blocked,
    Reproduced,
    NotReproduced,
    Inconclusive,
    NotApplicable,
    InvalidEvidence,
}
#[derive(Serialize, JsonSchema)]
pub struct LocalCheck {
    pub instance_id: String,
    pub artifact_version: Option<String>,
    /// The impact needs evidence and nothing confirms this exact version is affected, so only a
    /// sandbox result or a categorized blocker settles it. Missing deployment facts never set it.
    pub sandbox_needed: bool,
    pub result: LocalResult,
    /// Set for a `blocked` result; absent for blockers recorded without a kind.
    pub blocker: Option<BlockerKind>,
    pub context: Option<TestContext>,
    pub detail: String,
    pub attestation_path: Option<String>,
    pub output_path: Option<String>,
    pub observed_at: Option<String>,
}

pub(super) fn finding_check(case: &Case, store: &Store, language: Language) -> FindingCheck {
    let words = text::text(language);
    let mut references: Vec<FindingReference> = case
        .upstream_events
        .iter()
        .map(|event| FindingReference {
            id: event.id.clone(),
            kind: event.kind.clone(),
            url: event.url.clone(),
        })
        .collect();
    for claim in &case.claims {
        if let Some(url) = &claim.evidence.url {
            references.push(FindingReference {
                id: claim.id.clone(),
                kind: claim.source.clone(),
                url: url.clone(),
            });
        }
    }
    let advisory_ids: Vec<&str> = case
        .claims
        .iter()
        .flat_map(|claim| std::iter::once(&claim.id).chain(&claim.aliases))
        .map(String::as_str)
        .collect();
    for evidence in &case.evidence {
        if let Some(url) = &evidence.url {
            references.push(FindingReference {
                id: evidence.id.clone(),
                kind: evidence.source.clone(),
                url: url.clone(),
            });
        }
        if evidence.kind == EvidenceKind::Advisory {
            references.extend(advisory_references(evidence, &advisory_ids, store));
        }
    }
    references.sort_by(|a, b| a.url.cmp(&b.url));
    references.dedup_by(|a, b| a.url == b.url);
    let impact = crate::impact::latest(case, store);
    let mut local_checks = Vec::new();
    for instance in &case.instances {
        let needs_evidence = impact.as_ref().is_some_and(|impact| {
            impact.instances.iter().any(|assessed| {
                assessed.instance_id == instance.id
                    && assessed.verdict == ImpactVerdict::NeedsEvidence
            })
        });
        let mut check = LocalCheck {
            instance_id: instance.id.clone(),
            artifact_version: instance.resolved_version.clone(),
            sandbox_needed: needs_evidence
                && !crate::impact::affected_instance_confirmed(case, store, &instance.id),
            result: LocalResult::NotRun,
            blocker: None,
            context: None,
            detail: if case.sandbox.available {
                words.check_no_test.into()
            } else {
                fill(words.check_no_test_sandbox, &[&case.sandbox.reason])
            },
            attestation_path: None,
            output_path: None,
            observed_at: None,
        };
        for evidence in case.evidence.iter().rev().filter(|item| {
            item.kind == EvidenceKind::Attestation || item.source == "local_validation_blocker"
        }) {
            if evidence.source == "local_validation_blocker" {
                let blocker = (|| -> Result<crate::sandbox::VerificationBlocker> {
                    if !store.evidence_exists(evidence)? {
                        bail!("blocker integrity failed");
                    }
                    Ok(serde_json::from_slice(&crate::read_limited(
                        &store.directory.join("evidence").join(&evidence.sha256),
                        65536,
                    )?)?)
                })();
                match blocker {
                    Ok(blocker)
                        if blocker.schema_version == 1
                            && blocker.case_id == case.case_id
                            && blocker.facts_sha256 == case.facts_sha256
                            && blocker.instance_id == instance.id =>
                    {
                        check.result = LocalResult::Blocked;
                        check.blocker = blocker.kind;
                        check.detail = match blocker.kind {
                            Some(kind) => {
                                format!(
                                    "{}: {}",
                                    text::blocker_kind(language, kind),
                                    blocker.reason
                                )
                            }
                            None => blocker.reason,
                        };
                        check.observed_at = Some(evidence.observed_at.clone());
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        check.result = LocalResult::InvalidEvidence;
                        check.detail = words.check_blocker_corrupt.into();
                        break;
                    }
                }
            }
            let parsed = crate::sandbox::read_attestation(case, store, evidence);
            match parsed {
                Ok(attestation) if attestation.instance_id == instance.id => {
                    check.result = match attestation.verification {
                        Verification::LabReproduced => LocalResult::Reproduced,
                        Verification::NotReproduced => LocalResult::NotReproduced,
                        Verification::Disproven => LocalResult::NotApplicable,
                        _ => LocalResult::Inconclusive,
                    };
                    check.detail = match check.result {
                        LocalResult::Reproduced => words.check_reproduced,
                        LocalResult::NotReproduced => words.check_not_reproduced,
                        LocalResult::NotApplicable => words.check_not_applicable,
                        _ if attestation.timed_out => words.check_timed_out,
                        _ => words.check_inconclusive,
                    }
                    .into();
                    check.context = read_context(store, &attestation.test_sha256);
                    check.attestation_path = Some(
                        store
                            .directory
                            .join("evidence")
                            .join(&evidence.sha256)
                            .to_string_lossy()
                            .into_owned(),
                    );
                    check.output_path = Some(
                        store
                            .directory
                            .join("evidence")
                            .join(&attestation.output_sha256)
                            .to_string_lossy()
                            .into_owned(),
                    );
                    check.observed_at = Some(attestation.observed_at);
                    break;
                }
                Ok(_) => (),
                Err(_) => {
                    check.result = LocalResult::InvalidEvidence;
                    check.detail = words.check_invalid_attestation.into();
                    break;
                }
            }
        }
        local_checks.push(check);
    }
    FindingCheck {
        case_id: case.case_id.clone(),
        decision: case.decision,
        references,
        local_checks,
        impact,
    }
}

fn advisory_references(
    evidence: &crate::model::Evidence,
    advisory_ids: &[&str],
    store: &Store,
) -> Vec<FindingReference> {
    if !store.evidence_exists(evidence).unwrap_or(false) {
        return Vec::new();
    }
    let Ok(bytes) = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        16 * 1024 * 1024,
    ) else {
        return Vec::new();
    };
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    collect_advisory_urls(&document, advisory_ids, &mut urls);
    urls.into_iter()
        .filter(|url| crate::profile::public_https_syntax(url).is_ok())
        .map(|url| FindingReference {
            id: evidence.id.clone(),
            kind: format!("{} reference", evidence.source),
            url,
        })
        .collect()
}

/// A recorded page lists every advisory of a repository; only those the case claims contribute.
fn collect_advisory_urls(value: &serde_json::Value, advisory_ids: &[&str], urls: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            let ghsa_id = fields.get("ghsa_id").and_then(serde_json::Value::as_str);
            if ghsa_id.is_some_and(|id| !advisory_ids.is_empty() && !advisory_ids.contains(&id)) {
                return;
            }
            if let Some(url) = ghsa_id
                .and_then(|_| fields.get("html_url"))
                .and_then(serde_json::Value::as_str)
            {
                urls.push(url.into());
            }
            if let Some(references) = fields
                .get("references")
                .and_then(serde_json::Value::as_array)
            {
                for reference in references {
                    if let Some(url) = reference.as_str().or_else(|| {
                        reference
                            .as_object()
                            .and_then(|fields| fields.get("url"))
                            .and_then(serde_json::Value::as_str)
                    }) {
                        urls.push(url.into());
                    }
                }
            }
            for nested in fields.values() {
                collect_advisory_urls(nested, advisory_ids, urls);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_advisory_urls(item, advisory_ids, urls);
            }
        }
        _ => {}
    }
}

fn read_context(store: &Store, hash: &str) -> Option<TestContext> {
    let bytes =
        crate::read_limited(&store.directory.join("evidence").join(hash), 1024 * 1024).ok()?;
    if crate::digest(&bytes) != hash {
        return None;
    }
    let test: TestSpec = crate::parse_yaml(&bytes).ok()?;
    test.context
}

/// Without `impact_answers` only verdicts are listed, because the case cards already show them.
pub(super) fn markdown(
    findings: &[&FindingCheck],
    impact_answers: bool,
    language: Language,
) -> String {
    let words = text::text(language);
    let mut text = words.verification_intro.to_owned();
    for finding in findings {
        text.push_str(&format!(
            "### {} — {}\n\n",
            inline(&finding.case_id),
            text::decision(language, finding.decision)
        ));
        if finding.references.is_empty() {
            text.push_str(words.no_reference);
        }
        for reference in &finding.references {
            if crate::profile::public_https_syntax(&reference.url).is_ok() {
                let url = reference
                    .url
                    .replace(['<', '>', '\n', '\r'], "")
                    .replace('|', "%7C");
                let label = text::source_label(language, &reference.kind);
                let label = if reference.id.starts_with("EV-") {
                    label
                } else {
                    format!("{label} {}", reference.id)
                };
                text.push_str(&format!("- **{}:** <{}>\n", inline(&label), url));
            } else {
                text.push_str(words.invalid_reference);
            }
        }
        let mut checks: Vec<(String, String, usize)> = Vec::new();
        for check in finding.local_checks.iter().filter(|check| {
            finding.impact.is_none() || check.sandbox_needed || check.result != LocalResult::NotRun
        }) {
            let status = text::local_result(language, &check.result);
            let scope =
                text::test_mode(language, check.context.as_ref().map(|context| context.mode));
            let summary = fill(
                words.check_summary,
                &[
                    &status,
                    &scope,
                    &inline(
                        check
                            .artifact_version
                            .as_deref()
                            .unwrap_or(words.unknown_version),
                    ),
                    &inline(&check.detail),
                ],
            );
            let mut details = String::new();
            if let Some(context) = &check.context {
                details.push_str(&format!(
                    "- **{}:** {}\n",
                    words.test,
                    inline(&context.description)
                ));
            }
            if let Some(path) = &check.attestation_path {
                details.push_str(&format!(
                    "- **Attestation:** <{}>\n",
                    path.replace(['<', '>', '\n', '\r'], "")
                ));
            }
            if let Some(path) = &check.output_path {
                details.push_str(&format!(
                    "- **{}:** <{}>\n",
                    words.output,
                    path.replace(['<', '>', '\n', '\r'], "")
                ));
            }
            match checks
                .iter_mut()
                .find(|(known, known_details, _)| *known == summary && *known_details == details)
            {
                Some((_, _, count)) => *count += 1,
                None => checks.push((summary, details, 1)),
            }
        }
        for (summary, details, count) in checks {
            let instances = if count > 1 {
                fill(words.instances_count, &[&count])
            } else {
                String::new()
            };
            text.push_str(&format!(
                "- **{}{instances}:** {summary}\n{details}",
                words.local_check
            ));
        }
        if let Some(impact) = &finding.impact {
            text.push_str(&fill(
                words.impact_line,
                &[
                    &text::impact_verdict(language, impact.verdict),
                    &text::confidence(language, impact.confidence),
                ],
            ));
            let single = impact.instances.len() == 1;
            let mut groups: Vec<(String, String, Vec<&str>)> = Vec::new();
            for instance in &impact.instances {
                if single && !impact_answers {
                    continue;
                }
                let verdict = fill(
                    words.instance_verdict,
                    &[
                        &text::impact_verdict(language, instance.verdict),
                        &text::confidence(language, instance.confidence),
                    ],
                );
                let mut body = String::new();
                if impact_answers {
                    for answer in impact
                        .answers
                        .iter()
                        .filter(|answer| answer.instance_id == instance.instance_id)
                    {
                        body.push_str(&format!(
                            "    - {}: {}. {}\n",
                            text::impact_question(language, answer.question),
                            text::impact_answer(language, answer.answer),
                            inline(&answer.rationale)
                        ));
                    }
                    for reason in &instance.reasons {
                        body.push_str(&format!("    - {}: {}\n", words.criterion, inline(reason)));
                    }
                    if !instance.open_questions.is_empty() {
                        let questions = instance
                            .open_questions
                            .iter()
                            .map(|question| text::impact_question(language, *question))
                            .collect::<Vec<_>>()
                            .join(", ");
                        body.push_str(&format!(
                            "    - {}: {}.\n",
                            words.open_questions,
                            inline(&questions)
                        ));
                    }
                }
                match groups
                    .iter_mut()
                    .find(|(known, known_body, _)| *known == verdict && *known_body == body)
                {
                    Some((_, _, ids)) => ids.push(&instance.instance_id),
                    None => groups.push((verdict, body, vec![&instance.instance_id])),
                }
            }
            for (verdict, body, ids) in groups {
                let label = match ids.as_slice() {
                    [id] => fill(words.instance, &[&inline(id)]),
                    [first, ..] => fill(words.instances_example, &[&ids.len(), &inline(first)]),
                    [] => continue,
                };
                text.push_str(&format!("  - **{label}:** {verdict}\n{body}"));
            }
        } else {
            text.push_str(words.impact_not_assessed_long);
        }
        text.push('\n');
    }
    text
}
