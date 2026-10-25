use super::inline;
use crate::{
    impact::{ImpactAnswerValue, ImpactConfidence, ImpactQuestionId, ImpactResult, ImpactVerdict},
    model::{Case, Decision, EvidenceKind, Verification},
    sandbox::{TestContext, TestMode, TestSpec},
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
    pub result: LocalResult,
    pub context: Option<TestContext>,
    pub detail: String,
    pub attestation_path: Option<String>,
    pub output_path: Option<String>,
    pub observed_at: Option<String>,
}

pub(super) fn finding_check(case: &Case, store: &Store) -> FindingCheck {
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
    for evidence in &case.evidence {
        if let Some(url) = &evidence.url {
            references.push(FindingReference {
                id: evidence.id.clone(),
                kind: evidence.source.clone(),
                url: url.clone(),
            });
        }
        if evidence.kind == EvidenceKind::Advisory {
            references.extend(advisory_references(evidence, store));
        }
    }
    references.sort_by(|a, b| a.url.cmp(&b.url));
    references.dedup_by(|a, b| a.url == b.url);
    let mut local_checks = Vec::new();
    for instance in &case.instances {
        let mut check = LocalCheck {
            instance_id: instance.id.clone(),
            artifact_version: instance.resolved_version.clone(),
            result: LocalResult::NotRun,
            context: None,
            detail: if case.sandbox.available {
                "No current local test is recorded. The scheduled reader cannot authorize or run active tests.".into()
            } else {
                format!(
                    "No current local test is recorded. Sandbox: {}",
                    case.sandbox.reason
                )
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
                        check.detail = blocker.reason;
                        check.observed_at = Some(evidence.observed_at.clone());
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        check.result = LocalResult::InvalidEvidence;
                        check.detail =
                            "Recorded validation blocker is corrupt; inspect local evidence."
                                .into();
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
                        LocalResult::Reproduced => "Reproduced only for the tested artifact and conditions; deployment exposure is not established.",
                        LocalResult::NotReproduced => "The test did not reproduce the issue. This does not prove non-applicability.",
                        LocalResult::NotApplicable => "A prerequisite was disproven only within the tested scope, with a contrasting control.",
                        _ if attestation.timed_out => "Test timed out; no safety conclusion is supported.",
                        _ => "Execution or oracle was inconclusive; inspect the recorded output and job status.",
                    }.into();
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
                    check.detail = "A recorded attestation is invalid, stale, or missing matching output/policy/status bytes. Rerun verification for the current case.".into();
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
        impact: crate::impact::latest(case, store),
    }
}

fn advisory_references(evidence: &crate::model::Evidence, store: &Store) -> Vec<FindingReference> {
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
    collect_advisory_urls(&document, &mut urls);
    urls.into_iter()
        .filter(|url| crate::profile::public_https_syntax(url).is_ok())
        .map(|url| FindingReference {
            id: evidence.id.clone(),
            kind: format!("{} reference", evidence.source),
            url,
        })
        .collect()
}

fn collect_advisory_urls(value: &serde_json::Value, urls: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            if let Some(url) = fields
                .contains_key("ghsa_id")
                .then(|| fields.get("html_url"))
                .flatten()
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
                collect_advisory_urls(nested, urls);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_advisory_urls(item, urls);
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

pub(super) fn markdown(findings: &[FindingCheck]) -> String {
    let mut text = "\n## Referencias y verificación local\n\nCada resultado corresponde al caso y al alcance probado; no valida automáticamente todos los reclamos de una referencia.\n\n".to_owned();
    for finding in findings {
        text.push_str(&format!(
            "### {} — {:?}\n\n",
            inline(&finding.case_id),
            finding.decision
        ));
        if finding.references.is_empty() {
            text.push_str("- Sin referencia pública registrada.\n");
        }
        for reference in &finding.references {
            if crate::profile::public_https_syntax(&reference.url).is_ok() {
                let url = reference
                    .url
                    .replace(['<', '>', '\n', '\r'], "")
                    .replace('|', "%7C");
                text.push_str(&format!(
                    "- **{} {}:** <{}>\n",
                    inline(&reference.kind),
                    inline(&reference.id),
                    url
                ));
            } else {
                text.push_str("- Referencia inválida: consultar el JSON de auditoría.\n");
            }
        }
        for check in &finding.local_checks {
            let status = match check.result {
                LocalResult::NotRun => "no ejecutada",
                LocalResult::Blocked => "bloqueada",
                LocalResult::Reproduced => "reproducido",
                LocalResult::NotReproduced => "no reproducido; no descarta",
                LocalResult::Inconclusive => "inconclusa",
                LocalResult::NotApplicable => "no aplicable en el alcance probado",
                LocalResult::InvalidEvidence => "evidencia inválida u obsoleta",
            };
            let scope = match check.context.as_ref().map(|context| context.mode) {
                Some(TestMode::WorkspaceCopy) => "copia de workspace",
                Some(TestMode::ArtifactReproducer) => "proyecto mínimo con artefacto",
                None => "alcance no registrado",
            };
            text.push_str(&format!(
                "- **Verificación local:** {} · {} · versión {}. {}\n",
                status,
                scope,
                inline(check.artifact_version.as_deref().unwrap_or("desconocida")),
                inline(&check.detail)
            ));
            if let Some(context) = &check.context {
                text.push_str(&format!("- **Prueba:** {}\n", inline(&context.description)));
            }
            if let Some(path) = &check.attestation_path {
                text.push_str(&format!(
                    "- **Attestation:** <{}>\n",
                    path.replace(['<', '>', '\n', '\r'], "")
                ));
            }
            if let Some(path) = &check.output_path {
                text.push_str(&format!(
                    "- **Salida:** <{}>\n",
                    path.replace(['<', '>', '\n', '\r'], "")
                ));
            }
        }
        if let Some(impact) = &finding.impact {
            text.push_str(&format!(
                "- **Impacto en el proyecto:** {} · confianza {}.\n",
                impact_label(impact.verdict),
                confidence_label(impact.confidence)
            ));
            for instance in &impact.instances {
                text.push_str(&format!(
                    "  - **Instancia {}:** {} · confianza {}.\n",
                    inline(&instance.instance_id),
                    impact_label(instance.verdict),
                    confidence_label(instance.confidence)
                ));
                for answer in impact
                    .answers
                    .iter()
                    .filter(|answer| answer.instance_id == instance.instance_id)
                {
                    text.push_str(&format!(
                        "    - {}: {}. {}\n",
                        impact_question_label(answer.question),
                        impact_answer_label(answer.answer),
                        inline(&answer.rationale)
                    ));
                }
                for reason in &instance.reasons {
                    text.push_str(&format!("    - Criterio: {}\n", inline(reason)));
                }
                if !instance.open_questions.is_empty() {
                    let questions = instance
                        .open_questions
                        .iter()
                        .map(|question| impact_question_label(*question))
                        .collect::<Vec<_>>()
                        .join(", ");
                    text.push_str(&format!(
                        "    - Preguntas abiertas: {}.\n",
                        inline(&questions)
                    ));
                }
            }
        } else {
            text.push_str("- **Impacto en el proyecto:** sin evaluar. Ejecute `vulnbell impact` para obtener las preguntas deterministas.\n");
        }
        text.push('\n');
    }
    text
}

fn impact_label(verdict: ImpactVerdict) -> &'static str {
    match verdict {
        ImpactVerdict::UrgentUpdate => "actualización urgente",
        ImpactVerdict::PriorityUpdate => "actualización prioritaria",
        ImpactVerdict::RoutineUpdate => "actualización planificada",
        ImpactVerdict::Mitigated => "mitigado",
        ImpactVerdict::NotAffected => "no afectado según el alcance probado",
        ImpactVerdict::NeedsEvidence => "requiere evidencia del proyecto",
    }
}

fn confidence_label(confidence: ImpactConfidence) -> &'static str {
    match confidence {
        ImpactConfidence::High => "alta",
        ImpactConfidence::Medium => "media",
        ImpactConfidence::Low => "baja",
    }
}

fn impact_question_label(question: ImpactQuestionId) -> &'static str {
    match question {
        ImpactQuestionId::ArtifactDeployed => "artefacto desplegado",
        ImpactQuestionId::AffectedFeatureUsed => "funcionalidad afectada en uso",
        ImpactQuestionId::UntrustedInputReachesFeature => {
            "entrada no confiable alcanza la funcionalidad"
        }
        ImpactQuestionId::RequiredConditionsPresent => "condiciones requeridas presentes",
        ImpactQuestionId::FixOrMitigationApplied => "corrección o mitigación aplicada",
    }
}

fn impact_answer_label(answer: ImpactAnswerValue) -> &'static str {
    match answer {
        ImpactAnswerValue::Yes => "sí",
        ImpactAnswerValue::No => "no",
        ImpactAnswerValue::Unknown => "desconocido",
        ImpactAnswerValue::NotApplicable => "no aplica",
    }
}
