use super::{Language, MorningReport, inline};

pub(super) fn code_findings_markdown(report: &MorningReport, language: Language) -> String {
    let mut text = String::new();
    if !report.code_findings.is_empty() {
        text.push_str(match language {
            Language::Es => "## Hallazgos del código propio\n\nLa ubicación fue comprobada; la valoración corresponde a la revisión estática del agente y no demuestra cobertura completa del código.\n\n",
            Language::En => "## Codebase findings\n\nThe location was checked; the assessment is based on the agent's static review and does not establish complete codebase coverage.\n\n",
        });
        for entry in &report.code_findings {
            let finding = &entry.finding;
            let severity = match (language, finding.severity) {
                (Language::Es, crate::tools::code_findings::Severity::Critical) => "Crítica",
                (Language::Es, crate::tools::code_findings::Severity::High) => "Alta",
                (Language::Es, crate::tools::code_findings::Severity::Medium) => "Media",
                (Language::Es, crate::tools::code_findings::Severity::Low) => "Baja",
                (_, crate::tools::code_findings::Severity::Critical) => "Critical",
                (_, crate::tools::code_findings::Severity::High) => "High",
                (_, crate::tools::code_findings::Severity::Medium) => "Medium",
                (_, crate::tools::code_findings::Severity::Low) => "Low",
            };
            let status = match (language, entry.current, finding.disposition) {
                (Language::Es, false, _) => "Requiere reevaluación del contexto",
                (Language::Es, true, crate::tools::code_findings::Disposition::Actionable) => {
                    "Accionable"
                }
                (Language::Es, true, crate::tools::code_findings::Disposition::Resolved) => {
                    "Resuelto según revisión"
                }
                (Language::Es, true, _) => "En revisión",
                (_, false, _) => "Context reassessment required",
                (_, true, crate::tools::code_findings::Disposition::Actionable) => "Actionable",
                (_, true, crate::tools::code_findings::Disposition::Resolved) => {
                    "Resolved by review"
                }
                (_, true, _) => "In review",
            };
            let labels = match language {
                Language::Es => (
                    "Severidad",
                    "Estado",
                    "Ubicación",
                    "Análisis",
                    "Impacto",
                    "Acción",
                ),
                Language::En => (
                    "Severity", "Status", "Location", "Analysis", "Impact", "Action",
                ),
            };
            text.push_str(&format!("### {} ({})\n\n- {}: {}\n- {}: {}\n- {}: codebase {} `{}:{}`\n- {}: {}\n- {}: {}\n- {}: {}\n\n", inline(&finding.title), entry.id, labels.0, severity, labels.1, status, labels.2, finding.codebase + 1, inline(&finding.path), finding.line, labels.3, inline(&finding.analysis), labels.4, inline(&finding.impact), labels.5, inline(&finding.recommendation)));
            if entry.source_removed {
                text.push_str(match language {
                    Language::Es => "La ubicación anterior fue eliminada; la resolución requiere la revisión indicada.\n\n",
                    Language::En => "The former source location was removed; resolution relies on the stated review.\n\n",
                });
            }
            if !finding.evidence.is_empty() {
                text.push_str(match language {
                    Language::Es => "Evidencias adicionales:\n",
                    Language::En => "Additional evidence:\n",
                });
                for citation in &finding.evidence {
                    text.push_str(&format!(
                        "- codebase {} `{}:{}`\n",
                        citation.codebase + 1,
                        inline(&citation.path),
                        citation.line
                    ));
                }
                text.push('\n');
            }
            if entry.current
                && matches!(
                    finding.disposition,
                    crate::tools::code_findings::Disposition::Actionable
                )
            {
                let prompt = match language {
                    Language::Es => {
                        "Prompt para agente: revisa la ubicación citada, confirma las condiciones del hallazgo, aplica una corrección y verifica el resultado. No expongas credenciales."
                    }
                    Language::En => {
                        "Agent prompt: inspect the cited location, confirm the finding's conditions, apply a fix and verify the result. Do not expose credentials."
                    }
                };
                text.push_str(&format!("{prompt}\n\n"));
            }
        }
    }
    text
}
