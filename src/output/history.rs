use super::{MorningReport, RetractedCase};
use crate::{
    model::{Case, Decision, Snapshot},
    research::ResearchEvent,
    store::Store,
};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};

const MAX_HISTORY: usize = 100_000;

pub fn retracted_cases(snapshot: &Snapshot, store: &Store) -> Result<Vec<RetractedCase>> {
    let cases: Vec<&Case> = snapshot
        .cases
        .iter()
        .filter(|case| case.decision == Decision::Retracted)
        .collect();
    if cases.is_empty() {
        return Ok(Vec::new());
    }
    let ids: HashSet<&str> = cases.iter().map(|case| case.case_id.as_str()).collect();
    let mut histories: HashMap<String, Vec<Case>> = HashMap::new();
    let mut statement = store.connection.prepare("SELECT h.case_id, h.body FROM history h JOIN cases c ON c.id = h.case_id WHERE json_extract(c.body, '$.decision') = 'retracted' ORDER BY h.sequence LIMIT 100001")?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > MAX_HISTORY {
            bail!("retracted case history exceeds 100000 entries");
        }
        let id: String = row.get(0)?;
        if ids.contains(id.as_str()) {
            let body: String = row.get(1)?;
            histories
                .entry(id)
                .or_default()
                .push(serde_json::from_str(&body)?);
        }
    }
    cases
        .into_iter()
        .map(|case| {
            let mut research_events: Vec<ResearchEvent> = Vec::new();
            let mut evidence_gaps = Vec::new();
            for evidence in case
                .evidence
                .iter()
                .filter(|item| item.source == "agent_retraction_assessment")
            {
                let event = store
                    .evidence_exists(evidence)
                    .ok()
                    .filter(|valid| *valid)
                    .and_then(|_| {
                        crate::read_limited(
                            &store.directory.join("evidence").join(&evidence.sha256),
                            32 * 1024 * 1024,
                        )
                        .ok()
                    })
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok());
                if let Some(event) = event {
                    research_events.push(event);
                } else {
                    evidence_gaps.push(evidence.id.clone());
                }
            }
            if research_events.is_empty() && evidence_gaps.is_empty() {
                evidence_gaps.push("agent_retraction_assessment:missing".into());
            }
            Ok(RetractedCase {
                case: case.clone(),
                history: histories.remove(&case.case_id).unwrap_or_default(),
                research_events,
                evidence_gaps,
            })
        })
        .collect()
}

pub fn enrich_json(report: &mut MorningReport, snapshot: &Snapshot, store: &Store) -> Result<()> {
    super::ensure_morning_report_store(report, store)?;
    let active: HashSet<&str> = snapshot
        .instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect();
    report.closed_cases = snapshot
        .cases
        .iter()
        .filter(|case| {
            matches!(case.decision, Decision::Informational | Decision::Dismissed)
                && !crate::tools::cases::verdict_missing(case, store)
                && case
                    .instances
                    .iter()
                    .any(|instance| active.contains(instance.id.as_str()))
        })
        .cloned()
        .collect();
    report.retracted = retracted_cases(snapshot, store)?;
    Ok(())
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct AuditReport {
    #[serde(flatten)]
    pub snapshot: Snapshot,
    pub retracted: Vec<RetractedCase>,
}
