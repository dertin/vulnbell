use crate::{
    model::{Decision, Snapshot},
    profile::Profile,
    store::Store,
};
use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::params;
use sha2::Sha256;
mod details;
mod verification;
pub use details::AdvisoryDetail;
pub use verification::{FindingCheck, FindingReference, LocalCheck, LocalResult};

pub fn notify(profile: &Profile, snapshot: &Snapshot, store: &Store) -> Result<String> {
    let Some(variable) = &profile.alerts.webhook_env else {
        return Ok("not_configured; inbox and reports available".into());
    };
    let url = std::env::var(variable).context("configured webhook environment variable missing")?;
    let key =
        std::env::var("VULNBELL_WEBHOOK_HMAC_KEY").context("VULNBELL_WEBHOOK_HMAC_KEY missing")?;
    if key.len() < 32 {
        bail!("webhook HMAC key must contain at least 32 bytes");
    }
    let (client, url) = crate::network::public_client(&url)?;
    let mut sent = 0;
    for case in &snapshot.cases {
        if !matches!(case.decision, Decision::Actionable | Decision::Review) {
            continue;
        }
        let id = crate::digest(
            format!(
                "{}:{}:{}:{:?}",
                snapshot.project_id, case.case_id, case.facts_sha256, case.decision
            )
            .as_bytes(),
        );
        let exists: bool = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM alerts WHERE id=?1)",
            [&id],
            |row| row.get(0),
        )?;
        if exists {
            continue;
        }
        // Public-safe envelope: no paths, unpublished issues, proprietary source, or vulnerability details.
        let body = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"id":id,"project_id":snapshot.project_id,"case_id":case.case_id,"decision":case.decision,"applicability":case.applicability,"verification":case.verification,"facts_sha256":case.facts_sha256,"message":"Review the local VulnBell inbox for evidence and coverage"}),
        )?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())?;
        mac.update(&body);
        let signature = hex::encode(mac.finalize().into_bytes());
        let response = client
            .post(url.clone())
            .header("X-VulnBell-Signature", format!("sha256={signature}"))
            .header("Idempotency-Key", &id)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|_| anyhow::anyhow!("webhook delivery failed"))?;
        if !response.status().is_success() {
            bail!(
                "webhook returned HTTP {}; retry uses the same idempotency key",
                response.status()
            );
        }
        store.connection.execute(
            "INSERT OR IGNORE INTO alerts VALUES (?1,?2)",
            params![id, crate::now()],
        )?;
        sent += 1;
    }
    Ok(format!(
        "delivered={sent}; deduplicated by case facts and decision"
    ))
}
pub fn markdown(snapshot: &Snapshot) -> String {
    let mut report = format!(
        "# VulnBell\n\nProject: `{}`\n\nScan: {}\n\nCoverage: **{}**. Alerts: {}\n\n{} instances; {} cases.\n\n",
        snapshot.project_id,
        snapshot.finished_at,
        if snapshot.partial {
            "partial"
        } else {
            "checked"
        },
        snapshot.alert_status,
        snapshot.instances.len(),
        snapshot.cases.len()
    );
    for case in &snapshot.cases {
        report.push_str(&format!(
            "- `{}`: {:?}; {:?}; {:?}\n",
            case.case_id, case.decision, case.applicability, case.verification
        ));
    }
    report.push_str("\n## Coverage\n\n");
    for coverage in &snapshot.coverage {
        report.push_str(&format!(
            "- {} / `{}`: {:?} — {}\n",
            coverage.source,
            coverage.scope,
            coverage.state,
            coverage.detail.replace(['\n', '\r'], " ")
        ));
    }
    report
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct MorningReport {
    pub schema_version: u32,
    pub audience: String,
    pub project_id: String,
    pub project_name: String,
    pub generated_at: String,
    pub last_scan: String,
    pub last_successful_scan: Option<String>,
    pub last_agent_review: Option<String>,
    pub scheduler_id: Option<String>,
    pub inventory: Vec<MonitoredComponent>,
    pub actionable: Vec<HandoffItem>,
    pub needs_review: Vec<HandoffItem>,
    pub informational_count: usize,
    pub dismissed_count: usize,
    pub coverage_gaps: Vec<crate::model::Coverage>,
    pub notification_status: String,
    pub finding_checks: Vec<FindingCheck>,
    pub discovery: Option<crate::discovery::DiscoverySummary>,
    pub source_map: Vec<crate::discovery::IdentityObservation>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct MonitoredComponent {
    pub instance_id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub requested_version: Option<String>,
    pub resolved_version: Option<String>,
    pub origin: crate::model::Origin,
    pub workspace: Option<String>,
    pub upstream: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct HandoffItem {
    pub case_id: String,
    pub components: Vec<String>,
    pub origin: Vec<crate::model::Origin>,
    pub summary: String,
    pub advisory_details: Vec<AdvisoryDetail>,
    pub detail_gaps: Vec<String>,
    pub applicability: crate::model::Applicability,
    pub verification: crate::model::Verification,
    pub known_exploited: bool,
    pub evidence_links: Vec<String>,
    pub evidence_sha256: Vec<String>,
    pub open_questions: Vec<String>,
    pub recommended_action: String,
}
pub fn morning_report(snapshot: &Snapshot, store: &Store, audience: &str) -> Result<MorningReport> {
    let (discovery, source_map) = match store.meta("profile_path")? {
        Some(path) => {
            let path = std::path::Path::new(&path);
            match crate::profile::load(path) {
                Ok(profile) => (
                    Some(crate::discovery::summary(&profile, path, store)?),
                    crate::discovery::source_map(&profile, path, store)?,
                ),
                Err(_) => (None, Vec::new()),
            }
        }
        None => (None, Vec::new()),
    };
    let active_ids: std::collections::HashSet<&str> = snapshot
        .instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect();
    let mut actionable = Vec::new();
    let mut needs_review = Vec::new();
    let mut informational_count = 0;
    let mut dismissed_count = 0;
    for case in &snapshot.cases {
        if !case
            .instances
            .iter()
            .any(|instance| active_ids.contains(instance.id.as_str()))
        {
            continue;
        }
        match case.decision {
            Decision::Informational => {
                informational_count += 1;
                continue;
            }
            Decision::Dismissed => {
                dismissed_count += 1;
                continue;
            }
            _ => (),
        }
        let mut links: Vec<String> = case
            .evidence
            .iter()
            .filter_map(|evidence| evidence.url.clone())
            .chain(case.upstream_events.iter().map(|event| event.url.clone()))
            .collect();
        links.sort();
        links.dedup();
        let components: Vec<String> = case
            .instances
            .iter()
            .map(|instance| {
                format!(
                    "{} {}",
                    instance.reference,
                    instance.resolved_version.as_deref().unwrap_or("unresolved")
                )
            })
            .collect();
        let origin: Vec<crate::model::Origin> = case
            .instances
            .iter()
            .map(|instance| instance.origin)
            .collect();
        let summary = match (case.claims.first(), case.upstream_events.first()) {
            (Some(claim), _) => claim.summary.clone(),
            (_, Some(event)) => event.title.clone(),
            _ => "Investigation pending".to_owned(),
        };
        let recommended_action = if case.decision == Decision::Actionable {
            "Ingeniería + Cyber: confirmar despliegue y exposición; validar rama corregida o mitigación con la evidencia adjunta."
        } else {
            "Investigar el código de la release exacta y las condiciones del ataque; si corresponde, validar en sandbox autorizado con controles."
        };
        let mut advisory_details = Vec::new();
        let mut detail_gaps = Vec::new();
        for claim in &case.claims {
            match details::read(claim, &case.instances, store) {
                Ok(Some(detail)) => advisory_details.push(detail),
                Ok(None) => (),
                Err(_) => detail_gaps.push(format!("{} {}: additional advisory details unavailable or invalid; consult original evidence", claim.source, claim.id)),
            }
        }
        let item = HandoffItem {
            case_id: case.case_id.clone(),
            components,
            origin,
            summary,
            advisory_details,
            detail_gaps,
            applicability: case.applicability,
            verification: case.verification,
            known_exploited: case.claims.iter().any(|claim| claim.known_exploited),
            evidence_links: links,
            evidence_sha256: case
                .evidence
                .iter()
                .map(|evidence| evidence.sha256.clone())
                .collect(),
            open_questions: case.open_questions.clone(),
            recommended_action: recommended_action.into(),
        };
        if case.decision == Decision::Actionable {
            actionable.push(item);
        } else {
            needs_review.push(item);
        }
    }
    actionable.sort_by_key(|item| !item.known_exploited);
    Ok(MorningReport {
        schema_version: 1,
        audience: audience.into(),
        project_id: snapshot.project_id.clone(),
        project_name: store
            .meta("project_name")?
            .unwrap_or_else(|| snapshot.project_id.clone()),
        generated_at: crate::now(),
        last_scan: snapshot.finished_at.clone(),
        last_successful_scan: store.meta("last_successful_scan")?,
        last_agent_review: store.meta("last_agent_review")?,
        scheduler_id: store.meta("scheduler_id")?,
        inventory: snapshot
            .instances
            .iter()
            .map(|instance| MonitoredComponent {
                instance_id: instance.id.clone(),
                reference: instance.reference.clone(),
                requested_version: instance.requested_version.clone(),
                resolved_version: instance.resolved_version.clone(),
                origin: instance.origin,
                workspace: instance.provenance.workspace.clone(),
                upstream: instance.upstream.clone(),
            })
            .collect(),
        actionable,
        needs_review,
        informational_count,
        dismissed_count,
        coverage_gaps: snapshot
            .coverage
            .iter()
            .filter(|coverage| {
                if coverage.source == "general_discovery"
                    && coverage.scope == "project"
                    && discovery.is_some()
                {
                    return false;
                }
                !matches!(
                    coverage.state,
                    crate::model::CoverageState::Checked | crate::model::CoverageState::Disabled
                )
            })
            .cloned()
            .chain(
                discovery
                    .as_ref()
                    .filter(|summary| summary.enabled && !summary.complete)
                    .map(crate::discovery::coverage),
            )
            .collect(),
        discovery,
        source_map,
        notification_status: snapshot.alert_status.clone(),
        finding_checks: snapshot
            .cases
            .iter()
            .filter(|case| {
                case.instances
                    .iter()
                    .any(|instance| active_ids.contains(instance.id.as_str()))
            })
            .map(|case| verification::finding_check(case, store))
            .collect(),
    })
}
pub fn discovery_markdown(report: &MorningReport) -> String {
    let mut text = String::new();
    if let Some(discovery) = &report.discovery {
        text.push_str(&format!("## Descubrimiento\n\nEstado: {} · Directorios pendientes: {} · Archivos pendientes: {} · Revisados: {} · Excluidos: {} · No disponibles: {} · Componentes sin mapa: {} · Fuentes no disponibles: {}\n\n",if !discovery.enabled {"desactivado"}else if discovery.complete {"revisado en el alcance autorizado"}else{"parcial; continuar desde el checkpoint"},discovery.directories_pending,discovery.files_pending,discovery.files_reviewed,discovery.files_excluded,discovery.files_unavailable,discovery.components_unmapped,discovery.sources_unavailable));
    }
    if !report.source_map.is_empty() {
        text.push_str("## Mapa de fuentes\n\nAsociaciones documentadas por el agente; no certifican por sí solas identidad oficial ni aplicabilidad.\n\n| Componente | Fuente | Estado | Enlace / detalle |\n|---|---|---|---|\n");
        for mapping in &report.source_map {
            let reference = report
                .inventory
                .iter()
                .find(|item| item.instance_id == mapping.instance_id)
                .map(|item| item.reference.as_str())
                .unwrap_or(&mapping.instance_id);
            for source in &mapping.sources {
                use crate::discovery::{MappingState, SourceKind};
                let kind = match source.kind {
                    SourceKind::Website => "Sitio oficial",
                    SourceKind::Repository => "Repositorio",
                    SourceKind::Issues => "Issues",
                    SourceKind::ProposedChanges => "Cambios propuestos",
                    SourceKind::Discussions => "Discusiones",
                    SourceKind::Documentation => "Documentación",
                    SourceKind::Changelog => "Historial de cambios",
                    SourceKind::Releases => "Versiones",
                    SourceKind::Advisories => "Avisos de seguridad",
                };
                let state = match source.state {
                    MappingState::Mapped => "mapeada",
                    MappingState::Unavailable => "no disponible",
                    MappingState::NotApplicable => "no aplica",
                };
                text.push_str(&format!(
                    "| {} | {} | {} | {} — {} |\n",
                    inline(reference),
                    kind,
                    state,
                    inline(source.url.as_deref().unwrap_or("—")),
                    inline(&source.detail)
                ));
            }
        }
        text.push('\n');
    }
    text
}

pub fn morning_markdown(report: &MorningReport) -> String {
    let mut text = format!(
        "# VulnBell — {}\n\nCorte: {} · Revisión del agente: {}\n\n| Estado | Casos | Significado |\n|---|---:|---|\n| Accionables | {} | Versión afectada confirmada; evaluar impacto, actualización o mitigación. |\n| En revisión | {} | Señal de un issue/PR o evidencia incompleta o contradictoria; falta corroborar el reclamo o la identidad del artefacto. |\n| Informativos | {} | Contexto útil sin acción de seguridad pendiente. |\n| Descartados | {} | Un veredicto sustentado por evidencia cerró el caso en el alcance evaluado. |\n\nBrechas de cobertura: **{}** comprobaciones incompletas de fuentes o inventario; no son hallazgos de seguridad.\n\n",
        inline(&report.project_name),
        report.last_scan,
        report.last_agent_review.as_deref().unwrap_or("pendiente"),
        report.actionable.len(),
        report.needs_review.len(),
        report.informational_count,
        report.dismissed_count,
        report.coverage_gaps.len()
    );
    text.push_str("## Inventario\n\n| Componente | Versión | Procedencia |\n|---|---|---|\n");
    for component in &report.inventory {
        text.push_str(&format!(
            "| {} | {} | {} |\n",
            inline(&component.reference),
            inline(
                component
                    .resolved_version
                    .as_deref()
                    .unwrap_or("sin resolver")
            ),
            origin_label(component.origin)
        ));
    }
    text.push('\n');
    text.push_str(&discovery_markdown(report));
    for (decision, items) in [
        (Decision::Actionable, &report.actionable),
        (Decision::Review, &report.needs_review),
    ] {
        let label = if decision == Decision::Actionable {
            "Accionables"
        } else {
            "En revisión — hipótesis"
        };
        text.push_str(&format!("## {label}\n\n"));
        if items.is_empty() {
            text.push_str("Sin hallazgos en esta categoría.\n\n");
            continue;
        }
        if decision == Decision::Review {
            text.push_str("| Caso / componente | Señal investigada | Por qué sigue en revisión | Próximo paso | Evidencia |\n|---|---|---|---|---|\n");
            for item in items {
                let mut review_context = format!(
                    "Aplicabilidad: {}; verificación: {}.",
                    applicability_label(item.applicability),
                    verification_label(item.verification)
                );
                for question in &item.open_questions {
                    review_context.push(' ');
                    review_context.push_str(question);
                }
                let link = item
                    .evidence_links
                    .first()
                    .map(|link| {
                        format!(
                            "<{}>",
                            link.replace(['<', '>', '\n', '\r'], "").replace('|', "%7C")
                        )
                    })
                    .unwrap_or_else(|| "sin enlace".into());
                text.push_str(&format!(
                    "| {} / {} | {} | {} | {} | {} |\n",
                    inline(&item.case_id),
                    inline(&item.components.join(", ")),
                    inline(&item.summary),
                    inline(&review_context),
                    inline(&item.recommended_action),
                    link
                ));
            }
            text.push('\n');
            continue;
        }
        for item in items {
            text.push_str(&format!(
                "### {} — {}\n\n",
                item.case_id,
                inline(&item.summary)
            ));
            text.push_str(&format!(
                "- **Componente:** {}.\n",
                inline(&item.components.join(", "))
            ));
            text.push_str(&format!(
                "- **Estado:** {} · {} · Explotación conocida: {}.\n",
                applicability_label(item.applicability),
                verification_label(item.verification),
                if item.known_exploited {
                    "sí (fuente KEV)"
                } else {
                    "sin evidencia registrada"
                }
            ));
            let mut severities = item
                .advisory_details
                .iter()
                .filter_map(|detail| {
                    detail.severity.as_ref().map(|severity| {
                        format!("{}: {} ({})", detail.source, severity, detail.advisory_id)
                    })
                })
                .collect::<Vec<_>>();
            severities.sort();
            severities.dedup();
            if !severities.is_empty() {
                text.push_str(&format!(
                    "- **Severidad publicada:** {}.\n",
                    inline(&severities.join("; "))
                ));
            }
            let mut descriptions = Vec::new();
            for detail in &item.advisory_details {
                let normalized = advisory_excerpt(&detail.description);
                if !normalized.is_empty() && !descriptions.contains(&normalized) {
                    descriptions.push(normalized);
                }
            }
            for description in descriptions.iter().take(2) {
                let excerpt = description.chars().take(300).collect::<String>();
                text.push_str(&format!(
                    "- **Problema / impacto:** {}{}\n",
                    inline(&excerpt),
                    if description.chars().count() > 300 {
                        "… (detalle completo en la fuente)"
                    } else {
                        ""
                    }
                ));
            }
            let mut fixes: Vec<&str> = item
                .advisory_details
                .iter()
                .flat_map(|detail| detail.fixed_versions.iter().map(String::as_str))
                .collect();
            fixes.sort_unstable();
            fixes.dedup();
            text.push_str(&format!(
                "- **Correcciones publicadas:** {}.\n",
                if fixes.is_empty() {
                    "sin versión corregida verificada en los datos".into()
                } else {
                    format!(
                        "{}; validar rama compatible y backports",
                        inline(&fixes.join(", "))
                    )
                }
            ));
            for question in &item.open_questions {
                text.push_str(&format!("- **Por comprobar:** {}\n", inline(question)));
            }
            text.push_str(&format!(
                "- **Acción:** {}\n",
                inline(&item.recommended_action)
            ));
            for link in &item.evidence_links {
                text.push_str(&format!(
                    "- **Evidencia:** <{}>\n",
                    link.replace(['<', '>', '\n', '\r'], "")
                ));
            }
            for gap in &item.detail_gaps {
                text.push_str(&format!("- **Detalle pendiente:** {}\n", inline(gap)));
            }
            text.push('\n');
        }
    }
    text.push_str(
        "## Cobertura y entrega\n\n| Fuente | Alcance | Estado / pendiente |\n|---|---|---|\n",
    );
    for gap in &report.coverage_gaps {
        text.push_str(&format!(
            "| {} | {} | {:?}: {} |\n",
            inline(&gap.source),
            inline(&gap.scope),
            gap.state,
            inline(&gap.detail)
        ));
    }
    text.push_str(&format!(
        "\n**Entrega:** {}.\n",
        inline(&report.notification_status)
    ));
    text.push_str(&verification_markdown(report));
    text
}
pub fn verification_markdown(report: &MorningReport) -> String {
    verification::markdown(&report.finding_checks)
}
fn advisory_excerpt(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !(line.starts_with('_') && line.ends_with('_'))
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn inline(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('|', "\\|")
}
fn origin_label(origin: crate::model::Origin) -> &'static str {
    use crate::model::Origin;
    match origin {
        Origin::AgentObserved => "observado por agente / agent observed",
        Origin::Declared => "declarado / tracked",
        Origin::Locked => "lockfile / locked",
        Origin::ObservedArtifact => "artefacto observado",
        Origin::Deployed => "declarado desplegado / deployed",
    }
}
fn applicability_label(applicability: crate::model::Applicability) -> &'static str {
    use crate::model::Applicability;
    match applicability {
        Applicability::Affected => "afectado según evidencia",
        Applicability::NotAffected => "no afectado según evidencia",
        Applicability::Possible => "posible",
        Applicability::Unknown => "desconocido",
        Applicability::Conflict => "fuentes en conflicto",
    }
}
fn verification_label(verification: crate::model::Verification) -> &'static str {
    use crate::model::Verification;
    match verification {
        Verification::SourceConfirmed => "confirmado por fuente",
        Verification::LabReproduced => "reproducido en laboratorio",
        Verification::NotReproduced => "no reproducido (no descarta)",
        Verification::Inconclusive => "inconcluso",
        Verification::Disproven => "prerrequisito descartado en el alcance probado",
    }
}
