//! Reader-facing text of reports and of the rationales the CLI records, per report language.
//! Templates take positional `{}` placeholders filled by [`fill`]. Technical terms without a common
//! translation (issue, pull request, commit, release, lockfile, sandbox, upstream) stay as written.
use crate::{
    discovery::SourceKind,
    impact::{ImpactAnswerValue, ImpactConfidence, ImpactQuestionId, ImpactVerdict},
    model::{Applicability, CoverageState, Decision, Origin, Verification},
    output::LocalResult,
    profile::Language,
    sandbox::{BlockerKind, TestMode},
    store::Store,
};
use std::fmt::Display;

macro_rules! catalog {
    ($($field:ident),* $(,)?) => {
        pub(crate) struct Text {
            $(pub(crate) $field: &'static str,)*
        }
        impl Text {
            #[cfg(test)]
            pub(crate) fn entries(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($field), self.$field)),*]
            }
        }
    };
}

catalog! {
    pending,
    investigation_pending,
    header,
    contained_actionable_prefix,
    contained_review_prefix,
    contained_split,
    incomplete_banner,
    heading_actionable,
    heading_review,
    no_findings,
    no_exposed_hypotheses,
    review_table_header,
    review_context,
    per_source,
    recorded_verdict_inline,
    impact_inline,
    no_link,
    resolve_blocker,
    contained_review_heading,
    no_exposed_findings,
    card_components,
    card_component,
    card_verdict,
    card_impact,
    impact_not_assessed,
    card_state,
    kev_yes,
    kev_none,
    card_source_facts,
    card_severity,
    card_problem,
    excerpt_more,
    card_fixes,
    no_fix,
    fix_check,
    to_check,
    action,
    evidence,
    detail_pending,
    contained_actionable_heading,
    delivery,
    contained_table,
    and_more,
    inventory_heading,
    lockfile_table,
    inventory_table,
    profile_location,
    unresolved,
    inventory_total,
    no_version,
    coverage_table,
    scope_examples,
    open_contained_note,
    closed_note,
    impact_summary,
    components_group,
    components_examples,
    discovery,
    discovery_disabled,
    discovery_complete,
    discovery_partial,
    source_map,
    without_repository,
    and_more_json,
    source_map_table,
    repository_unavailable,
    releases_per_component,
    action_actionable,
    action_review,
    fix_target_default,
    action_urgent,
    action_priority,
    action_routine,
    detail_gap,
    verification_intro,
    no_reference,
    invalid_reference,
    check_summary,
    unknown_version,
    test,
    output,
    local_check,
    instances_count,
    impact_line,
    instance_verdict,
    criterion,
    open_questions,
    instance,
    instances_example,
    impact_not_assessed_long,
    check_no_test,
    check_no_test_sandbox,
    check_blocker_corrupt,
    check_reproduced,
    check_not_reproduced,
    check_not_applicable,
    check_timed_out,
    check_inconclusive,
    check_invalid_attestation,
    cites,
    affects,
    fixed_in,
    fix,
    requires,
    reference_of,
    agent_partial,
    runner_failed,
    audit_links,
    rule_release_published,
    rule_fix_pr,
    rule_relay_with_ids,
    and_others,
    rule_advisory_other_package,
    no_package,
    rule_advisory_fixed,
    rule_advisory_outside,
}

const EN: Text = Text {
    pending: "pending",
    investigation_pending: "Investigation pending",
    header: "# VulnBell — {}\n\nCutoff: {} · Agent review: {}\n\n| Status | Cases | Meaning |\n|---|---:|---|\n| Actionable | {} | Affected version confirmed; assess impact, update or mitigation. |\n| In review | {} | Signal from an issue/PR, or incomplete or contradictory evidence; the claim or the artifact identity still needs corroboration. |\n| Informational | {} | Useful context with no pending security action. |\n| Dismissed | {} | An evidence-backed verdict closed the case within the assessed scope. |\n| Not applicable | {} | Upstream events that, per the cited source, do not affect the monitored version or build; they open no case. |\n\nCoverage gaps: **{}** kinds of incomplete source or inventory checks ({} scopes); they are not security findings.\n\n",
    contained_actionable_prefix: "Of the actionable cases",
    contained_review_prefix: "Of the cases in review",
    contained_split: "{}, **{}** may be exposed in the project and **{}** are not exposed according to the recorded impact assessment.\n\n",
    incomplete_banner: "> **Incomplete report:** {} cases without impact assessment, {} needing a review disposition, {} requiring a sandbox check or categorized blocker, and {} with invalid verification evidence. Complete them before delivery.\n\n",
    heading_actionable: "Actionable",
    heading_review: "In review — hypotheses",
    no_findings: "No findings in this category.\n\n",
    no_exposed_hypotheses: "No hypotheses with project exposure.\n\n",
    review_table_header: "| Case / component | Signal investigated | Why it is still in review | Next step | Evidence |\n|---|---|---|---|---|\n",
    review_context: "Applicability: {}; verification: {}.",
    per_source: " According to the source: ",
    recorded_verdict_inline: " Recorded verdict: ",
    impact_inline: " Impact: ",
    no_link: "no link",
    resolve_blocker: "Resolve the recorded blocker (see References and local verification) and rerun `vulnbell impact` with the evidence obtained.",
    contained_review_heading: "Signals without project exposure",
    no_exposed_findings: "No findings with project exposure.\n\n",
    card_components: "- **Components ({}):** {}.\n",
    card_component: "- **Component:** {}.\n",
    card_verdict: "- **Recorded verdict:** {}\n",
    card_impact: "- **Project impact:** {}\n",
    impact_not_assessed: "not assessed; run `vulnbell impact`.",
    card_state: "- **Status:** {} · {} · Known exploitation: {}.\n",
    kev_yes: "yes (KEV source)",
    kev_none: "no recorded evidence",
    card_source_facts: "- **According to the source:** {}.\n",
    card_severity: "- **Published severity:** {}.\n",
    card_problem: "- **Problem / impact:** {}{}\n",
    excerpt_more: "… (full detail in the source)",
    card_fixes: "- **Published fixes:** {}.\n",
    no_fix: "no verified fixed version in the data",
    fix_check: "{}; check the compatible branch and backports",
    to_check: "To check",
    action: "Action",
    evidence: "Evidence",
    detail_pending: "Pending detail",
    contained_actionable_heading: "Affect the version without project exposure",
    delivery: "\n**Delivery:** {}.\n",
    contained_table: "### {} ({})\n\n| Component | Advisories | Recorded reason | Fix |\n|---|---|---|---|\n",
    and_more: "{} and {} more",
    inventory_heading: "## Inventory\n\n",
    lockfile_table: "| Lockfile / SBOM | Packages |\n|---|---:|\n",
    inventory_table: "| Component | Version | Provenance | Origin |\n|---|---|---|---|\n",
    profile_location: "profile",
    unresolved: "unresolved",
    inventory_total: "{} instances in total; full list with path and line in `vulnbell report --json` (`inventory`).\n\n",
    no_version: "no version",
    coverage_table: "## Coverage and delivery\n\n| Source | Scopes | Status / pending |\n|---|---|---|\n",
    scope_examples: "{} (e.g. {}; see JSON)",
    open_contained_note: "{} open cases without project exposure keep their references and full impact assessment in `vulnbell report --json` (`finding_checks`).\n",
    closed_note: "{} closed cases (informational or dismissed) keep their references and checks in `vulnbell report --json` (`finding_checks`).\n",
    impact_summary: "{} ({} confidence).",
    components_group: "{} components {} (e.g. {})",
    components_examples: "{} components (e.g. {})",
    discovery: "## Discovery\n\nStatus: {} · Pending directories: {} · Pending files: {} · Reviewed: {} · Excluded: {} · Unavailable: {} · Unmapped selected components: {} · Unavailable sources: {} · Deferred transitives: {} · Unknown depth: {}. Advisory checks run independently for the inventory, subject to coverage gaps; deferred trackers have not been reviewed.\n\n",
    discovery_disabled: "disabled",
    discovery_complete: "reviewed within the authorized scope",
    discovery_partial: "partial; continue from the checkpoint",
    source_map: "## Source map\n\nMapped components: {} · with repository: {} · without repository (no upstream research): {}. Full detail in `vulnbell report --json` (`source_map`).\n\n",
    without_repository: "Without repository: {}{}.\n\n",
    and_more_json: " and {} more (see JSON)",
    source_map_table: "Sources of the components with open cases; documented associations that do not, by themselves, certify official identity or applicability. The reason for each unmapped source is in the JSON.\n\n| Component | Repository | Other mapped sources | Unmapped |\n|---|---|---|---|\n",
    repository_unavailable: "unavailable — {}",
    releases_per_component: "Releases: one per component ({})",
    action_actionable: "Engineering + Cyber: confirm deployment and exposure; validate the fixed branch or mitigation with the attached evidence.",
    action_review: "Investigate the code of the exact release and the attack conditions; if warranted, validate in an authorized sandbox with controls.",
    fix_target_default: "a fixed version once available",
    action_urgent: "Update now to {} or apply the mitigation; the project impact is confirmed.",
    action_priority: "Update with priority to {} or apply a verified mitigation (see the recorded verdict); meanwhile, close the open conditions.",
    action_routine: "Update to {} in the next dependency cycle.",
    detail_gap: "{} {}: additional advisory details unavailable or invalid; consult the original evidence",
    verification_intro: "\n## References and local verification\n\nEach result belongs to the case and the tested scope; it does not automatically validate every claim of a reference.\n\n",
    no_reference: "- No public reference recorded.\n",
    invalid_reference: "- Invalid reference: see the audit JSON.\n",
    check_summary: "{} · {} · version {}. {}",
    unknown_version: "unknown",
    test: "Test",
    output: "Output",
    local_check: "Local verification",
    instances_count: " ({} instances)",
    impact_line: "- **Project impact:** {} · {} confidence.\n",
    instance_verdict: "{} · {} confidence.",
    criterion: "Criterion",
    open_questions: "Open questions",
    instance: "Instance {}",
    instances_example: "{} instances, e.g. {}",
    impact_not_assessed_long: "- **Project impact:** not assessed. Run `vulnbell impact` to get the deterministic questions.\n",
    check_no_test: "No current local test is recorded. The scheduled reader cannot authorize or run active tests.",
    check_no_test_sandbox: "No current local test is recorded. Sandbox: {}",
    check_blocker_corrupt: "Recorded validation blocker is corrupt; inspect local evidence.",
    check_reproduced: "Reproduced only for the tested artifact and conditions; deployment exposure is not established.",
    check_not_reproduced: "The test did not reproduce the issue. This does not prove non-applicability.",
    check_not_applicable: "A prerequisite was disproven only within the tested scope, with a contrasting control.",
    check_timed_out: "Test timed out; no safety conclusion is supported.",
    check_inconclusive: "Execution or oracle was inconclusive; inspect the recorded output and job status.",
    check_invalid_attestation: "A recorded attestation is invalid, stale, or missing matching output/policy/status bytes. Rerun verification for the current case.",
    cites: "cites {}",
    affects: "affects",
    fixed_in: "fixed in",
    fix: "fix",
    requires: "requires",
    reference_of: "{} reference",
    agent_partial: "{}\n**Agent — partial run:** {}.\n",
    runner_failed: "The runner failed to write the Markdown report",
    audit_links: "{}\n\nAudit: [full data](<{}>) · [research](<{}>).\n",
    rule_release_published: "Release notes reference security fixes; each fix is assessed through its advisory or issue event.",
    rule_fix_pr: "Fix for {}; the security claim is assessed through that issue.",
    rule_relay_with_ids: "Dependency update citing {}{}; the affected packages ({}) are absent from the monitored build or at versions outside the affected ranges.",
    and_others: " and others",
    rule_advisory_other_package: "The advisory names {}; no monitored instance of this upstream is that package.",
    no_package: "no package",
    rule_advisory_fixed: "The advisory's fix for the monitored release line is at or below {}.",
    rule_advisory_outside: "{} is outside the advisory's affected ranges.",
};

const ES: Text = Text {
    pending: "pendiente",
    investigation_pending: "Investigación pendiente",
    header: "# VulnBell — {}\n\nCorte: {} · Revisión del agente: {}\n\n| Estado | Casos | Significado |\n|---|---:|---|\n| Accionables | {} | Versión afectada confirmada; evaluar impacto, actualización o mitigación. |\n| En revisión | {} | Señal de un issue/PR o evidencia incompleta o contradictoria; falta corroborar el reclamo o la identidad del artefacto. |\n| Informativos | {} | Contexto útil sin acción de seguridad pendiente. |\n| Descartados | {} | Un veredicto sustentado por evidencia cerró el caso en el alcance evaluado. |\n| No aplicables | {} | Eventos upstream que, según la fuente citada, no afectan la versión o el build monitoreado; no abren caso. |\n\nBrechas de cobertura: **{}** tipos de comprobación incompleta de fuentes o inventario ({} alcances); no son hallazgos de seguridad.\n\n",
    contained_actionable_prefix: "De los accionables",
    contained_review_prefix: "De los casos en revisión",
    contained_split: "{}, **{}** tienen exposición posible en el proyecto y **{}** no tienen exposición según el análisis de impacto registrado.\n\n",
    incomplete_banner: "> **Reporte incompleto:** {} casos sin evaluación de impacto, {} sin decisión de seguimiento, {} con prueba de sandbox requerida o bloqueo por registrar y {} con evidencia de verificación inválida. Completar antes de entregar.\n\n",
    heading_actionable: "Accionables",
    heading_review: "En revisión — hipótesis",
    no_findings: "Sin hallazgos en esta categoría.\n\n",
    no_exposed_hypotheses: "Sin hipótesis con exposición en el proyecto.\n\n",
    review_table_header: "| Caso / componente | Señal investigada | Por qué sigue en revisión | Próximo paso | Evidencia |\n|---|---|---|---|---|\n",
    review_context: "Aplicabilidad: {}; verificación: {}.",
    per_source: " Según la fuente: ",
    recorded_verdict_inline: " Veredicto registrado: ",
    impact_inline: " Impacto: ",
    no_link: "sin enlace",
    resolve_blocker: "Resolver el bloqueo registrado (ver Referencias y verificación local) y repetir `vulnbell impact` con la evidencia obtenida.",
    contained_review_heading: "Señales sin exposición en el proyecto",
    no_exposed_findings: "Sin hallazgos con exposición en el proyecto.\n\n",
    card_components: "- **Componentes ({}):** {}.\n",
    card_component: "- **Componente:** {}.\n",
    card_verdict: "- **Veredicto registrado:** {}\n",
    card_impact: "- **Impacto en el proyecto:** {}\n",
    impact_not_assessed: "sin evaluar; ejecutar `vulnbell impact`.",
    card_state: "- **Estado:** {} · {} · Explotación conocida: {}.\n",
    kev_yes: "sí (fuente KEV)",
    kev_none: "sin evidencia registrada",
    card_source_facts: "- **Según la fuente:** {}.\n",
    card_severity: "- **Severidad publicada:** {}.\n",
    card_problem: "- **Problema / impacto:** {}{}\n",
    excerpt_more: "… (detalle completo en la fuente)",
    card_fixes: "- **Correcciones publicadas:** {}.\n",
    no_fix: "sin versión corregida verificada en los datos",
    fix_check: "{}; validar rama compatible y backports",
    to_check: "Por comprobar",
    action: "Acción",
    evidence: "Evidencia",
    detail_pending: "Detalle pendiente",
    contained_actionable_heading: "Afectan la versión sin exposición en el proyecto",
    delivery: "\n**Entrega:** {}.\n",
    contained_table: "### {} ({})\n\n| Componente | Avisos | Motivo registrado | Corrección |\n|---|---|---|---|\n",
    and_more: "{} y {} más",
    inventory_heading: "## Inventario\n\n",
    lockfile_table: "| Lockfile / SBOM | Paquetes |\n|---|---:|\n",
    inventory_table: "| Componente | Versión | Procedencia | Origen |\n|---|---|---|---|\n",
    profile_location: "perfil",
    unresolved: "sin resolver",
    inventory_total: "{} instancias en total; lista completa con ruta y línea en `vulnbell report --json` (`inventory`).\n\n",
    no_version: "sin versión",
    coverage_table: "## Cobertura y entrega\n\n| Fuente | Alcances | Estado / pendiente |\n|---|---|---|\n",
    scope_examples: "{} (ej.: {}; ver JSON)",
    open_contained_note: "{} casos abiertos sin exposición en el proyecto conservan referencias y análisis de impacto completo en `vulnbell report --json` (`finding_checks`).\n",
    closed_note: "{} casos cerrados (informativos o descartados) conservan sus referencias y verificaciones en `vulnbell report --json` (`finding_checks`).\n",
    impact_summary: "{} (confianza {}).",
    components_group: "{} componentes {} (p. ej. {})",
    components_examples: "{} componentes (p. ej. {})",
    discovery: "## Descubrimiento\n\nEstado: {} · Directorios pendientes: {} · Archivos pendientes: {} · Revisados: {} · Excluidos: {} · No disponibles: {} · Componentes seleccionados sin mapa: {} · Fuentes no disponibles: {} · Transitivas diferidas: {} · Profundidad desconocida: {}. Los advisories se comprueban independientemente para el inventario, sujetos a brechas de cobertura; los trackers diferidos no se revisaron.\n\n",
    discovery_disabled: "desactivado",
    discovery_complete: "revisado en el alcance autorizado",
    discovery_partial: "parcial; continuar desde el checkpoint",
    source_map: "## Mapa de fuentes\n\nComponentes mapeados: {} · con repositorio: {} · sin repositorio (sin investigación upstream): {}. El detalle completo está en `vulnbell report --json` (`source_map`).\n\n",
    without_repository: "Sin repositorio: {}{}.\n\n",
    and_more_json: " y {} más (ver JSON)",
    source_map_table: "Fuentes de los componentes con casos abiertos; asociaciones documentadas, no certifican por sí solas identidad oficial ni aplicabilidad. Los motivos de cada fuente sin mapear están en el JSON.\n\n| Componente | Repositorio | Otras fuentes mapeadas | Sin mapear |\n|---|---|---|---|\n",
    repository_unavailable: "no disponible — {}",
    releases_per_component: "Releases: una por componente ({})",
    action_actionable: "Ingeniería + Cyber: confirmar despliegue y exposición; validar rama corregida o mitigación con la evidencia adjunta.",
    action_review: "Investigar el código de la release exacta y las condiciones del ataque; si corresponde, validar en sandbox autorizado con controles.",
    fix_target_default: "una versión corregida cuando exista",
    action_urgent: "Actualizar ya a {} o aplicar la mitigación; el impacto en el proyecto está confirmado.",
    action_priority: "Actualizar con prioridad a {} o aplicar una mitigación verificada (ver veredicto registrado); mientras tanto, cerrar las condiciones abiertas.",
    action_routine: "Actualizar a {} en el próximo ciclo de dependencias.",
    detail_gap: "{} {}: detalles adicionales del aviso no disponibles o inválidos; consultar la evidencia original",
    verification_intro: "\n## Referencias y verificación local\n\nCada resultado corresponde al caso y al alcance probado; no valida automáticamente todos los reclamos de una referencia.\n\n",
    no_reference: "- Sin referencia pública registrada.\n",
    invalid_reference: "- Referencia inválida: consultar el JSON de auditoría.\n",
    check_summary: "{} · {} · versión {}. {}",
    unknown_version: "desconocida",
    test: "Prueba",
    output: "Salida",
    local_check: "Verificación local",
    instances_count: " ({} instancias)",
    impact_line: "- **Impacto en el proyecto:** {} · confianza {}.\n",
    instance_verdict: "{} · confianza {}.",
    criterion: "Criterio",
    open_questions: "Preguntas abiertas",
    instance: "Instancia {}",
    instances_example: "{} instancias, p. ej. {}",
    impact_not_assessed_long: "- **Impacto en el proyecto:** sin evaluar. Ejecute `vulnbell impact` para obtener las preguntas deterministas.\n",
    check_no_test: "No hay una prueba local vigente registrada. El lector programado no puede autorizar ni ejecutar pruebas activas.",
    check_no_test_sandbox: "No hay una prueba local vigente registrada. Sandbox: {}",
    check_blocker_corrupt: "El bloqueo de verificación registrado está dañado; revisar la evidencia local.",
    check_reproduced: "Reproducido solo para el artefacto y las condiciones probadas; la exposición del despliegue no está establecida.",
    check_not_reproduced: "La prueba no reprodujo el problema. Esto no prueba que no aplique.",
    check_not_applicable: "Se descartó un prerrequisito solo dentro del alcance probado, con un control de contraste.",
    check_timed_out: "La prueba excedió el tiempo; no permite ninguna conclusión de seguridad.",
    check_inconclusive: "La ejecución o el oráculo fueron inconclusos; revisar la salida registrada y el estado del job.",
    check_invalid_attestation: "Una attestation registrada es inválida, obsoleta o no coincide con los bytes de salida, política o estado. Repetir la verificación para el caso actual.",
    cites: "cita {}",
    affects: "afecta",
    fixed_in: "corregido en",
    fix: "corrección",
    requires: "requiere",
    reference_of: "Referencia de {}",
    agent_partial: "{}\n**Agente — ejecución parcial:** {}.\n",
    runner_failed: "Fallo del runner al redactar el reporte Markdown",
    audit_links: "{}\n\nAuditoría: [datos completos](<{}>) · [investigación](<{}>).\n",
    rule_release_published: "Las notas de la release citan correcciones de seguridad; cada corrección se evalúa en su aviso o issue.",
    rule_fix_pr: "Corrección de {}; el reclamo de seguridad se evalúa en ese issue.",
    rule_relay_with_ids: "Actualización de dependencia que cita {}{}; los paquetes afectados ({}) no están en el build monitoreado o están en versiones fuera de los rangos afectados.",
    and_others: " y otros",
    rule_advisory_other_package: "El aviso nombra {}; ninguna instancia monitoreada de este upstream es ese paquete.",
    no_package: "ningún paquete",
    rule_advisory_fixed: "La corrección del aviso para la línea de release monitoreada es igual o anterior a {}.",
    rule_advisory_outside: "{} está fuera de los rangos afectados del aviso.",
};

pub(crate) fn text(language: Language) -> &'static Text {
    match language {
        Language::En => &EN,
        Language::Es => &ES,
    }
}

/// `template` with each `{}` replaced, in order, by the next value.
pub(crate) fn fill(template: &str, values: &[&dyn Display]) -> String {
    let mut parts = template.split("{}");
    let mut filled = parts.next().unwrap_or_default().to_owned();
    for (index, part) in parts.enumerate() {
        if let Some(value) = values.get(index) {
            filled.push_str(&value.to_string());
        }
        filled.push_str(part);
    }
    filled
}

/// Instruction for agents writing report text or rationales that the report shows.
pub(crate) fn language_rule(language: Language) -> String {
    let name = language.name();
    format!(
        "Write every sentence in {name}. Keep technical terms that {name} technical writing usually leaves untranslated as they are (for example issue, pull request, commit, release, changelog, lockfile, SBOM, sandbox, upstream, build, backport) instead of forcing a translation. Quote upstream titles, advisory text, identifiers, versions, paths and commands exactly as recorded, in their original language."
    )
}

/// The language of the monitor's profile; English when the profile is unknown or invalid.
pub fn report_language(store: &Store) -> Language {
    store
        .meta("profile_path")
        .ok()
        .flatten()
        .and_then(|path| crate::profile::load(std::path::Path::new(&path)).ok())
        .map(|profile| profile.report.language)
        .unwrap_or_default()
}

pub(crate) fn decision(language: Language, decision: Decision) -> &'static str {
    match (language, decision) {
        (Language::En, Decision::Actionable) => "Actionable",
        (Language::En, Decision::Review) => "In review",
        (Language::En, Decision::Informational) => "Informational",
        (Language::En, Decision::Dismissed) => "Dismissed",
        (Language::Es, Decision::Actionable) => "Accionable",
        (Language::Es, Decision::Review) => "En revisión",
        (Language::Es, Decision::Informational) => "Informativo",
        (Language::Es, Decision::Dismissed) => "Descartado",
    }
}

pub(crate) fn coverage_state(language: Language, state: CoverageState) -> &'static str {
    match (language, state) {
        (Language::En, CoverageState::Checked) => "Checked",
        (Language::En, CoverageState::Partial) => "Partial",
        (Language::En, CoverageState::Unsupported) => "Unsupported",
        (Language::En, CoverageState::Unavailable) => "Unavailable",
        (Language::En, CoverageState::Unresolved) => "Unresolved",
        (Language::En, CoverageState::Disabled) => "Disabled",
        (Language::Es, CoverageState::Checked) => "Comprobado",
        (Language::Es, CoverageState::Partial) => "Parcial",
        (Language::Es, CoverageState::Unsupported) => "No soportado",
        (Language::Es, CoverageState::Unavailable) => "No disponible",
        (Language::Es, CoverageState::Unresolved) => "Sin resolver",
        (Language::Es, CoverageState::Disabled) => "Desactivado",
    }
}

pub(crate) fn origin(language: Language, origin: Origin) -> &'static str {
    match (language, origin) {
        (Language::En, Origin::AgentObserved) => "observed by the agent",
        (Language::En, Origin::Declared) => "declared",
        (Language::En, Origin::Locked) => "lockfile",
        (Language::En, Origin::ObservedArtifact) => "observed artifact",
        (Language::En, Origin::Deployed) => "declared deployed",
        (Language::Es, Origin::AgentObserved) => "observado por el agente",
        (Language::Es, Origin::Declared) => "declarado",
        (Language::Es, Origin::Locked) => "lockfile",
        (Language::Es, Origin::ObservedArtifact) => "artefacto observado",
        (Language::Es, Origin::Deployed) => "declarado desplegado",
    }
}

pub(crate) fn applicability(language: Language, applicability: Applicability) -> &'static str {
    match (language, applicability) {
        (Language::En, Applicability::Affected) => "affected per evidence",
        (Language::En, Applicability::NotAffected) => "not affected per evidence",
        (Language::En, Applicability::Possible) => "possible",
        (Language::En, Applicability::Unknown) => "unknown",
        (Language::En, Applicability::Conflict) => "conflicting sources",
        (Language::Es, Applicability::Affected) => "afectado según evidencia",
        (Language::Es, Applicability::NotAffected) => "no afectado según evidencia",
        (Language::Es, Applicability::Possible) => "posible",
        (Language::Es, Applicability::Unknown) => "desconocido",
        (Language::Es, Applicability::Conflict) => "fuentes en conflicto",
    }
}

pub(crate) fn verification(language: Language, verification: Verification) -> &'static str {
    match (language, verification) {
        (Language::En, Verification::SourceConfirmed) => "confirmed by source",
        (Language::En, Verification::LabReproduced) => "reproduced in the lab",
        (Language::En, Verification::NotReproduced) => "not reproduced (does not rule it out)",
        (Language::En, Verification::Inconclusive) => "inconclusive",
        (Language::En, Verification::Disproven) => "prerequisite ruled out in the tested scope",
        (Language::Es, Verification::SourceConfirmed) => "confirmado por fuente",
        (Language::Es, Verification::LabReproduced) => "reproducido en laboratorio",
        (Language::Es, Verification::NotReproduced) => "no reproducido (no descarta)",
        (Language::Es, Verification::Inconclusive) => "inconcluso",
        (Language::Es, Verification::Disproven) => "prerrequisito descartado en el alcance probado",
    }
}

pub(crate) fn source_kind(language: Language, kind: SourceKind) -> &'static str {
    match (language, kind) {
        (Language::En, SourceKind::Website) => "Official website",
        (Language::En, SourceKind::Repository) => "Repository",
        (Language::En, SourceKind::Issues) => "Issues",
        (Language::En, SourceKind::ProposedChanges) => "Proposed changes (PR/MR)",
        (Language::En, SourceKind::Discussions) => "Discussions",
        (Language::En, SourceKind::Documentation) => "Documentation",
        (Language::En, SourceKind::Changelog) => "Changelog",
        (Language::En, SourceKind::Releases) => "Releases",
        (Language::En, SourceKind::Advisories) => "Security advisories",
        (Language::Es, SourceKind::Website) => "Sitio oficial",
        (Language::Es, SourceKind::Repository) => "Repositorio",
        (Language::Es, SourceKind::Issues) => "Issues",
        (Language::Es, SourceKind::ProposedChanges) => "Cambios propuestos (PR/MR)",
        (Language::Es, SourceKind::Discussions) => "Discusiones",
        (Language::Es, SourceKind::Documentation) => "Documentación",
        (Language::Es, SourceKind::Changelog) => "Changelog",
        (Language::Es, SourceKind::Releases) => "Releases",
        (Language::Es, SourceKind::Advisories) => "Avisos de seguridad",
    }
}

pub(crate) fn impact_verdict(language: Language, verdict: ImpactVerdict) -> &'static str {
    match (language, verdict) {
        (Language::En, ImpactVerdict::UrgentUpdate) => "urgent update",
        (Language::En, ImpactVerdict::PriorityUpdate) => "priority update",
        (Language::En, ImpactVerdict::RoutineUpdate) => "planned update",
        (Language::En, ImpactVerdict::Mitigated) => "mitigated",
        (Language::En, ImpactVerdict::NotAffected) => "not affected within the tested scope",
        (Language::En, ImpactVerdict::NeedsEvidence) => "needs project evidence",
        (Language::Es, ImpactVerdict::UrgentUpdate) => "actualización urgente",
        (Language::Es, ImpactVerdict::PriorityUpdate) => "actualización prioritaria",
        (Language::Es, ImpactVerdict::RoutineUpdate) => "actualización planificada",
        (Language::Es, ImpactVerdict::Mitigated) => "mitigado",
        (Language::Es, ImpactVerdict::NotAffected) => "no afectado según el alcance probado",
        (Language::Es, ImpactVerdict::NeedsEvidence) => "requiere evidencia del proyecto",
    }
}

pub(crate) fn confidence(language: Language, confidence: ImpactConfidence) -> &'static str {
    match (language, confidence) {
        (Language::En, ImpactConfidence::High) => "high",
        (Language::En, ImpactConfidence::Medium) => "medium",
        (Language::En, ImpactConfidence::Low) => "low",
        (Language::Es, ImpactConfidence::High) => "alta",
        (Language::Es, ImpactConfidence::Medium) => "media",
        (Language::Es, ImpactConfidence::Low) => "baja",
    }
}

pub(crate) fn impact_question(language: Language, question: ImpactQuestionId) -> &'static str {
    match (language, question) {
        (Language::En, ImpactQuestionId::ArtifactDeployed) => "artifact deployed",
        (Language::En, ImpactQuestionId::AffectedFeatureUsed) => "affected feature in use",
        (Language::En, ImpactQuestionId::UntrustedInputReachesFeature) => {
            "untrusted input reaches the feature"
        }
        (Language::En, ImpactQuestionId::RequiredConditionsPresent) => {
            "required conditions present"
        }
        (Language::En, ImpactQuestionId::FixOrMitigationApplied) => "fix or mitigation applied",
        (Language::Es, ImpactQuestionId::ArtifactDeployed) => "artefacto desplegado",
        (Language::Es, ImpactQuestionId::AffectedFeatureUsed) => "funcionalidad afectada en uso",
        (Language::Es, ImpactQuestionId::UntrustedInputReachesFeature) => {
            "entrada no confiable alcanza la funcionalidad"
        }
        (Language::Es, ImpactQuestionId::RequiredConditionsPresent) => {
            "condiciones requeridas presentes"
        }
        (Language::Es, ImpactQuestionId::FixOrMitigationApplied) => {
            "corrección o mitigación aplicada"
        }
    }
}

pub(crate) fn impact_answer(language: Language, answer: ImpactAnswerValue) -> &'static str {
    match (language, answer) {
        (Language::En, ImpactAnswerValue::Yes) => "yes",
        (Language::En, ImpactAnswerValue::No) => "no",
        (Language::En, ImpactAnswerValue::Unknown) => "unknown",
        (Language::En, ImpactAnswerValue::NotApplicable) => "not applicable",
        (Language::Es, ImpactAnswerValue::Yes) => "sí",
        (Language::Es, ImpactAnswerValue::No) => "no",
        (Language::Es, ImpactAnswerValue::Unknown) => "desconocido",
        (Language::Es, ImpactAnswerValue::NotApplicable) => "no aplica",
    }
}

pub(crate) fn local_result(language: Language, result: &LocalResult) -> &'static str {
    match (language, result) {
        (Language::En, LocalResult::NotRun) => "not run",
        (Language::En, LocalResult::Blocked) => "blocked",
        (Language::En, LocalResult::Reproduced) => "reproduced",
        (Language::En, LocalResult::NotReproduced) => "not reproduced; does not rule it out",
        (Language::En, LocalResult::Inconclusive) => "inconclusive",
        (Language::En, LocalResult::NotApplicable) => "not applicable within the tested scope",
        (Language::En, LocalResult::InvalidEvidence) => "invalid or stale evidence",
        (Language::Es, LocalResult::NotRun) => "no ejecutada",
        (Language::Es, LocalResult::Blocked) => "bloqueada",
        (Language::Es, LocalResult::Reproduced) => "reproducido",
        (Language::Es, LocalResult::NotReproduced) => "no reproducido; no descarta",
        (Language::Es, LocalResult::Inconclusive) => "inconclusa",
        (Language::Es, LocalResult::NotApplicable) => "no aplicable en el alcance probado",
        (Language::Es, LocalResult::InvalidEvidence) => "evidencia inválida u obsoleta",
    }
}

pub(crate) fn blocker_kind(language: Language, kind: BlockerKind) -> &'static str {
    match (language, kind) {
        (Language::En, BlockerKind::DetailsUndisclosed) => "details not disclosed",
        (Language::En, BlockerKind::ArtifactUnavailable) => "artifact unavailable",
        (Language::En, BlockerKind::SandboxLimits) => "exceeds the sandbox limits",
        (Language::En, BlockerKind::RuntimeUnavailable) => "sandbox unavailable",
        (Language::En, BlockerKind::AuthorizationDeclined) => "authorization declined",
        (Language::Es, BlockerKind::DetailsUndisclosed) => "detalles no publicados",
        (Language::Es, BlockerKind::ArtifactUnavailable) => "artefacto no disponible",
        (Language::Es, BlockerKind::SandboxLimits) => "excede los límites del sandbox",
        (Language::Es, BlockerKind::RuntimeUnavailable) => "sandbox no disponible",
        (Language::Es, BlockerKind::AuthorizationDeclined) => "autorización denegada",
    }
}

pub(crate) fn test_mode(language: Language, mode: Option<TestMode>) -> &'static str {
    match (language, mode) {
        (Language::En, Some(TestMode::WorkspaceCopy)) => "workspace copy",
        (Language::En, Some(TestMode::ArtifactReproducer)) => "minimal project with the artifact",
        (Language::En, None) => "scope not recorded",
        (Language::Es, Some(TestMode::WorkspaceCopy)) => "copia de workspace",
        (Language::Es, Some(TestMode::ArtifactReproducer)) => "proyecto mínimo con artefacto",
        (Language::Es, None) => "alcance no registrado",
    }
}

/// Reader-facing name of a source, evidence or event key; JSON keeps the key.
pub(crate) fn source_label(language: Language, key: &str) -> String {
    if let Some(source) = key.strip_suffix(" reference") {
        return fill(
            text(language).reference_of,
            &[&source_label(language, source)],
        );
    }
    let label = match (language, key) {
        (_, "osv") => "OSV",
        (_, "ghsa") => "GitHub Advisory Database",
        (_, "nvd") => "NVD",
        (_, "cisa_kev") => "CISA KEV",
        (_, "rustsec_native") => "RustSec",
        (_, "workspace") => "Workspace",
        (_, "issue") => "Issue",
        (_, "pullrequest" | "pull_request") => "PR",
        (_, "mergerequest" | "merge_request") => "Merge request",
        (_, "mergeproposal" | "merge_proposal") => "Merge proposal",
        (_, "changelog") => "Changelog",
        (_, "release") => "Release",
        (_, "commit") => "Commit",
        (Language::En, "cve_records") => "CVE record (cve.org)",
        (Language::En, "github_repository") => "Repository advisory (GitHub)",
        (Language::En, "github_repository_advisories" | "repository_advisories") => {
            "Repository advisories (GitHub)"
        }
        (Language::En, "vendor" | "configured_vendor" | "vendor_release") => "Vendor source",
        (Language::En, "identity" | "upstream_identity") => "Package identity",
        (Language::En, "inventory") => "Inventory",
        (Language::En, "general_discovery") => "General discovery",
        (Language::En, "upstream_agent" | "agent_upstream") => "Upstream research (agent)",
        (Language::En, "research_web" | "agent_web") => "Web research (agent)",
        (Language::En, "agent_upstream_observation") => "Agent upstream observation",
        (Language::En, "agent_verdict") => "Agent verdict",
        (Language::En, "impact_assessment") => "Impact assessment",
        (Language::En, "local_impact_evidence") => "Project impact evidence",
        (Language::En, "local_validation_blocker") => "Local verification blocker",
        (Language::En, "http_metrics") => "HTTP metrics",
        (Language::En, "advisory") => "Advisory",
        (Language::En, "comment") => "Comment",
        (Language::En, "review") => "Review",
        (Language::En, "news") => "News",
        (Language::En, "discussion") => "Discussion",
        (Language::En, "documentation") => "Documentation",
        (Language::Es, "cve_records") => "Registro CVE (cve.org)",
        (Language::Es, "github_repository") => "Aviso del repositorio (GitHub)",
        (Language::Es, "github_repository_advisories" | "repository_advisories") => {
            "Avisos del repositorio (GitHub)"
        }
        (Language::Es, "vendor" | "configured_vendor" | "vendor_release") => "Fuente del proveedor",
        (Language::Es, "identity" | "upstream_identity") => "Identidad del paquete",
        (Language::Es, "inventory") => "Inventario",
        (Language::Es, "general_discovery") => "Descubrimiento general",
        (Language::Es, "upstream_agent" | "agent_upstream") => "Investigación upstream (agente)",
        (Language::Es, "research_web" | "agent_web") => "Investigación web (agente)",
        (Language::Es, "agent_upstream_observation") => "Observación upstream del agente",
        (Language::Es, "agent_verdict") => "Veredicto del agente",
        (Language::Es, "impact_assessment") => "Evaluación de impacto",
        (Language::Es, "local_impact_evidence") => "Evidencia de impacto del proyecto",
        (Language::Es, "local_validation_blocker") => "Bloqueo de verificación local",
        (Language::Es, "http_metrics") => "Métricas HTTP",
        (Language::Es, "advisory") => "Aviso",
        (Language::Es, "comment") => "Comentario",
        (Language::Es, "review") => "Revisión",
        (Language::Es, "news") => "Noticia",
        (Language::Es, "discussion") => "Discusión",
        (Language::Es, "documentation") => "Documentación",
        (_, other) => return other.replace('_', " "),
    };
    label.to_owned()
}

/// Notification statuses are stored in English by the scan; known ones are shown in the report
/// language and any other text is shown as recorded.
pub(crate) fn notification_status(language: Language, status: &str) -> String {
    if language == Language::En {
        return status.to_owned();
    }
    if status == "not_configured; inbox and reports available" {
        return "sin configurar; bandeja y reportes disponibles".to_owned();
    }
    if status == "offline: notification delivery skipped" {
        return "sin conexión: no se enviaron notificaciones".to_owned();
    }
    if let Some(count) = status
        .strip_prefix("delivered=")
        .and_then(|rest| rest.strip_suffix("; deduplicated by case facts and decision"))
    {
        return format!("enviadas={count}; deduplicadas por hechos y decisión del caso");
    }
    if let Some(error) = status.strip_prefix("failed: ") {
        return format!("falló: {error}");
    }
    status.to_owned()
}

/// Questions the CLI adds to cases are stored in English; known ones are shown in the report
/// language and any other text is shown as recorded.
pub(crate) fn open_question(language: Language, question: &str) -> String {
    if language == Language::En {
        return question.to_owned();
    }
    let translated = match question {
        "Check release code and attack prerequisites before asserting a real attack vector." => {
            "Revisar el código de la release y los prerrequisitos del ataque antes de afirmar un vector de ataque real."
        }
        "Research no longer supports this actionable case; confirm and record a new verdict before closing it." => {
            "La investigación ya no respalda este caso accionable; confirmar y registrar un nuevo veredicto antes de cerrarlo."
        }
        "Confirm deployment, vendor build and relevant runtime conditions before remediation." => {
            "Confirmar despliegue, build del proveedor y condiciones de ejecución relevantes antes de remediar."
        }
        "Monitored artifact or context changed; reassess the hypothesis and rerun any relevant verification." => {
            "Cambió el artefacto monitoreado o su contexto; reevaluar la hipótesis y repetir las verificaciones relevantes."
        }
        "Previous advisory was not matched in this scan; source absence/failure is not proof of safety. Reassess." => {
            "El aviso anterior no coincidió en este escaneo; la ausencia o falla de una fuente no prueba seguridad. Reevaluar."
        }
        _ => {
            return match question
                .strip_prefix("Advisory evidence changed after the recorded ")
                .and_then(|rest| rest.split_once(" verdict or impact assessment;"))
            {
                Some(_) => "La evidencia del aviso cambió después del veredicto o la evaluación de impacto registrados; reevaluar con el razonamiento anterior del historial del caso.".to_owned(),
                None => question.to_owned(),
            };
        }
    };
    translated.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_language_fills_the_same_placeholders() {
        for ((field, english), (_, spanish)) in EN.entries().into_iter().zip(ES.entries()) {
            assert_eq!(
                english.matches("{}").count(),
                spanish.matches("{}").count(),
                "placeholders of {field}"
            );
        }
    }

    #[test]
    fn fill_replaces_placeholders_in_order_without_rescanning_values() {
        assert_eq!(fill("{} and {}", &[&"{}", &2]), "{} and 2");
        assert_eq!(fill("no placeholder", &[&1]), "no placeholder");
    }

    #[test]
    fn stored_english_statuses_are_shown_in_the_report_language_and_unknown_text_as_recorded() {
        assert_eq!(
            notification_status(
                Language::Es,
                "delivered=2; deduplicated by case facts and decision"
            ),
            "enviadas=2; deduplicadas por hechos y decisión del caso"
        );
        assert_eq!(
            notification_status(Language::En, "failed: timeout"),
            "failed: timeout"
        );
        assert_eq!(
            notification_status(Language::Es, "local report only"),
            "local report only"
        );
        assert!(
            open_question(
                Language::Es,
                "Advisory evidence changed after the recorded triage verdict or impact assessment; reassess."
            )
            .starts_with("La evidencia del aviso cambió")
        );
    }
}
