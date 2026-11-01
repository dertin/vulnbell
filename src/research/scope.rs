use super::{ResearchEvent, ResearchTarget, ReviewCoverage, SourceReview};
use crate::store::Store;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate};
use std::collections::HashSet;

pub(super) fn persisted_unreviewed_sources(
    store: &Store,
    sources: &[SourceReview],
    targets: &[ResearchTarget],
    replaced_keys: &HashSet<String>,
) -> Result<HashSet<String>> {
    let mut incomplete = HashSet::new();
    let mut statement = store
        .connection
        .prepare("SELECT key, body FROM research_events WHERE upstream=?1")?;
    for source in sources
        .iter()
        .filter(|source| source.coverage == ReviewCoverage::Complete)
    {
        let target = targets
            .iter()
            .find(|target| target.upstream == source.upstream)
            .context("research source missing from plan")?;
        let from = DateTime::parse_from_rfc3339(&source.from)?;
        let until = DateTime::parse_from_rfc3339(&source.until)?;
        let rows = statement.query_map([&source.upstream], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (key, body) = row?;
            if replaced_keys.contains(&key) {
                continue;
            }
            let event: ResearchEvent = serde_json::from_str(&body)?;
            let in_window = if let Ok(updated) = DateTime::parse_from_rfc3339(&event.updated_at) {
                updated >= from && updated <= until
            } else if let Ok(day) = NaiveDate::parse_from_str(&event.updated_at, "%Y-%m-%d") {
                day >= from.date_naive() && day <= until.date_naive()
            } else {
                true
            };
            if in_window
                && target
                    .instance_ids
                    .iter()
                    .any(|id| !event.reviewed_instance_ids.contains(id))
            {
                incomplete.insert(source.upstream.clone());
                break;
            }
        }
    }
    Ok(incomplete)
}
