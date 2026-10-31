use super::{
    ResearchTarget, ReviewCoverage, SourceReview, build_plan, index_instances, recheck_key,
    tracker_context,
};
use crate::store::Store;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};

/// Moves completed review checkpoints back so the next plan reviews `since` onward again, for
/// example after the screening method improved. Seen events still deduplicate imports.
pub fn reopen(store: &mut Store, upstream: &str, since: &str) -> Result<serde_json::Value> {
    reopen_window(store, upstream, since, false)
}

pub fn reopen_recheck(store: &mut Store, upstream: &str, since: &str) -> Result<serde_json::Value> {
    reopen_window(store, upstream, since, true)
}

fn reopen_window(
    store: &mut Store,
    upstream: &str,
    since: &str,
    recheck: bool,
) -> Result<serde_json::Value> {
    let _lock = store.lock()?;
    let since = DateTime::parse_from_rfc3339(since).context("--since must be RFC3339")?;
    if since > Utc::now() {
        bail!("--since is in the future");
    }
    let plan = build_plan(store, "", usize::MAX, false)?;
    let targets: Vec<&ResearchTarget> = plan
        .targets
        .iter()
        .filter(|target| upstream == "all" || target.upstream == upstream.trim_end_matches('/'))
        .collect();
    if targets.is_empty() {
        bail!("no research target matches {upstream}; use an upstream from the plan or `all`");
    }
    if !recheck {
        for target in &targets {
            if store.meta(&recheck_key(&target.upstream))?.is_some() {
                bail!("an explicit recheck is in progress for {}", target.upstream);
            }
        }
    }
    let snapshot = store.latest()?;
    let instances = index_instances(&snapshot.instances);
    let release_windows = store
        .meta("profile_path")?
        .map(|path| crate::profile::load(std::path::Path::new(&path)))
        .transpose()?
        .is_some_and(|profile| profile.research.release_windows);
    let transaction = store.connection.transaction()?;
    let mut reopened = Vec::new();
    for target in targets {
        if recheck && since > DateTime::parse_from_rfc3339(&target.until)? {
            bail!(
                "--since is after the current research window for {}",
                target.upstream
            );
        }
        if !recheck {
            let Some(checkpoint) = &target.last_complete_review else {
                continue;
            };
            if DateTime::parse_from_rfc3339(checkpoint)? <= since {
                continue;
            }
            let rewound = since + Duration::minutes(5);
            transaction.execute(
                "INSERT OR REPLACE INTO research_cursors VALUES (?1,?2)",
                rusqlite::params![target.upstream, rewound.to_rfc3339()],
            )?;
            transaction.execute(
                "DELETE FROM research_progress WHERE upstream=?1",
                [&target.upstream],
            )?;
        } else {
            let from = if target.progress.is_some() {
                DateTime::parse_from_rfc3339(&target.from)?.min(since)
            } else {
                since
            };
            let progress = SourceReview {
                upstream: target.upstream.clone(),
                from: from.to_rfc3339(),
                until: target.until.clone(),
                coverage: ReviewCoverage::Partial,
                detail: "Recheck requested".into(),
                continuation: None,
                recheck_context_sha256: None,
            };
            let context = tracker_context(&target.instance_ids, &instances, release_windows)?;
            transaction.execute(
                "INSERT OR REPLACE INTO research_progress VALUES (?1,?2)",
                rusqlite::params![target.upstream, serde_json::to_string(&progress)?],
            )?;
            transaction.execute(
                "INSERT OR REPLACE INTO meta VALUES (?1,?2)",
                rusqlite::params![
                    format!(
                        "research_progress_context:{}",
                        crate::digest(target.upstream.as_bytes())
                    ),
                    context
                ],
            )?;
        }
        if recheck {
            transaction.execute(
                "INSERT OR REPLACE INTO meta VALUES (?1,?2)",
                rusqlite::params![
                    recheck_key(&target.upstream),
                    uuid::Uuid::new_v4().to_string()
                ],
            )?;
        }
        reopened.push(serde_json::json!({"upstream": target.upstream, "previous_checkpoint": target.last_complete_review, "from": since.to_rfc3339()}));
    }
    transaction.commit()?;
    Ok(serde_json::json!({"schema_version": 1, "reopened": reopened}))
}
