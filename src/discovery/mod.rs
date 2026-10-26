use crate::{
    model::{Coverage, CoverageState, Instance},
    profile::{DiscoveryMode, Profile},
    store::Store,
};
use anyhow::{Result, bail};
use rusqlite::params;
use std::path::Path;

pub(crate) mod automation;
mod contracts;
mod sources;
mod workspace;
pub use contracts::*;

pub fn scope(profile: &Profile, path: &Path) -> Result<String> {
    Ok(crate::digest(&serde_json::to_vec(&(
        profile,
        path.canonicalize()?,
    ))?))
}

pub fn plan(profile: &Profile, path: &Path, store: &Store, limit: usize) -> Result<DiscoveryPlan> {
    if !(1..=20).contains(&limit) {
        bail!("discovery page size must be 1..20");
    }
    let scope = scope(profile, path)?;
    if profile.discovery == DiscoveryMode::Agent {
        workspace::prepare(profile, path, store, &scope)?;
    }
    let workspace = if profile.discovery == DiscoveryMode::Agent {
        workspace::page(store, &scope, limit)?
    } else {
        Vec::new()
    };
    let components = if profile.discovery == DiscoveryMode::Agent {
        sources::targets(store, &scope, limit)?
    } else {
        Vec::new()
    };
    Ok(DiscoveryPlan {
        schema_version: 1,
        project_id: profile.project_id.to_string(),
        scope_sha256: scope.clone(),
        enabled: profile.discovery == DiscoveryMode::Agent,
        workspace,
        components,
        summary: summary(profile, path, store)?,
    })
}

pub fn import(
    profile: &Profile,
    path: &Path,
    store: &mut Store,
    batch: DiscoveryBatch,
) -> Result<DiscoverySummary> {
    if profile.discovery == DiscoveryMode::Off {
        bail!("general discovery is explicitly disabled in this profile");
    }
    let _lock = store.lock()?;
    let current_scope = scope(profile, path)?;
    match batch {
        DiscoveryBatch::Workspace {
            schema_version,
            project_id,
            scope_sha256,
            reviews,
        } => {
            validate_batch(
                profile,
                &current_scope,
                schema_version,
                &project_id,
                &scope_sha256,
                reviews.len(),
            )?;
            workspace::import(profile, store, &current_scope, reviews)?;
        }
        DiscoveryBatch::Sources {
            schema_version,
            project_id,
            scope_sha256,
            observations,
        } => {
            validate_batch(
                profile,
                &current_scope,
                schema_version,
                &project_id,
                &scope_sha256,
                observations.len(),
            )?;
            sources::import(store, &current_scope, observations)?;
        }
    }
    summary(profile, path, store)
}

fn validate_batch(
    profile: &Profile,
    scope: &str,
    version: u32,
    project: &str,
    submitted_scope: &str,
    count: usize,
) -> Result<()> {
    if version != 1
        || project != profile.project_id.to_string()
        || submitted_scope != scope
        || count > 20
    {
        bail!("discovery batch is stale, outside the project or exceeds 20 tasks");
    }
    Ok(())
}

pub fn acquire(profile: &Profile, store: &Store, url: &str) -> Result<crate::model::Evidence> {
    if profile.discovery == DiscoveryMode::Off {
        bail!("general discovery is disabled");
    }
    sources::acquire(store, url)
}

pub fn augment(
    profile: &Profile,
    path: &Path,
    store: &Store,
    instances: &mut Vec<Instance>,
) -> Result<Vec<Coverage>> {
    if profile.discovery == DiscoveryMode::Off {
        return Ok(vec![Coverage::new(
            "general_discovery",
            "project",
            CoverageState::Disabled,
            "explicitly disabled by the project profile",
        )]);
    }
    let scope = scope(profile, path)?;
    let preparation = workspace::prepare(profile, path, store, &scope);
    append_workspace_instances(store, &scope, instances)?;
    sources::apply(store, &scope, instances)?;
    let summary = summary_for_instances(profile, store, &scope, instances)?;
    let mut coverage_rows = vec![coverage(&summary)];
    if let Err(error) = preparation {
        coverage_rows.push(Coverage::new(
            "general_discovery",
            "workspace",
            CoverageState::Unavailable,
            error.to_string(),
        ));
    }
    Ok(coverage_rows)
}

fn append_workspace_instances(
    store: &Store,
    scope: &str,
    instances: &mut Vec<Instance>,
) -> Result<()> {
    let mut native_keys: std::collections::HashSet<_> = instances
        .iter()
        .map(|instance| {
            (
                instance.reference.clone(),
                instance.resolved_version.clone(),
                instance.provenance.path.clone(),
                instance.provenance.workspace.clone(),
            )
        })
        .collect();
    for discovered in workspace::instances(store, scope)? {
        let key = (
            discovered.reference.clone(),
            discovered.resolved_version.clone(),
            discovered.provenance.path.clone(),
            discovered.provenance.workspace.clone(),
        );
        if native_keys.insert(key) {
            instances.push(discovered);
        }
    }
    Ok(())
}

pub fn summary(profile: &Profile, path: &Path, store: &Store) -> Result<DiscoverySummary> {
    let mut instances: Vec<Instance> = profile.components.iter().map(Instance::declared).collect();
    if store.meta("last_snapshot")?.is_some() {
        let snapshot = store.latest()?;
        let hash = crate::digest(&crate::read_limited(path, 1024 * 1024)?);
        if snapshot.profile_sha256 == hash {
            instances = snapshot.instances;
        }
    }
    let scope = scope(profile, path)?;
    append_workspace_instances(store, &scope, &mut instances)?;
    summary_for_instances(profile, store, &scope, &instances)
}

fn summary_for_instances(
    profile: &Profile,
    store: &Store,
    scope: &str,
    instances: &[Instance],
) -> Result<DiscoverySummary> {
    let count = |table: &str, state: &str| -> Result<usize> {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE scope=?1 AND state=?2");
        Ok(store
            .connection
            .query_row(&sql, params![scope, state], |row| row.get(0))?)
    };
    let enabled = profile.discovery == DiscoveryMode::Agent;
    let directories_pending = count("discovery_walk", "pending")?;
    let directories_unavailable = count("discovery_walk", "unavailable")?;
    let initialized_roots: usize = store.connection.query_row(
        "SELECT COUNT(*) FROM discovery_walk WHERE scope=?1 AND path=''",
        [scope],
        |row| row.get(0),
    )?;
    let files_pending = count("discovery_files", "pending")?;
    let files_unavailable = count("discovery_files", "unavailable")?;
    let (components_unmapped, sources_unavailable) = sources::counts(store, scope, instances)?;
    let complete = enabled
        && initialized_roots >= profile.workspaces.len()
        && directories_pending == 0
        && directories_unavailable == 0
        && files_pending == 0
        && files_unavailable == 0
        && components_unmapped == 0
        && sources_unavailable == 0;
    Ok(DiscoverySummary {
        enabled,
        directories_pending: directories_pending
            + directories_unavailable
            + profile.workspaces.len().saturating_sub(initialized_roots),
        files_pending,
        files_reviewed: count("discovery_files", "done")?,
        files_excluded: count("discovery_files", "excluded")?
            + count("discovery_files", "removed")?,
        files_unavailable,
        components_unmapped,
        sources_unavailable,
        complete,
    })
}

pub fn coverage(summary: &DiscoverySummary) -> Coverage {
    Coverage::new(
        "general_discovery",
        "project",
        if !summary.enabled {
            CoverageState::Disabled
        } else if summary.complete {
            CoverageState::Checked
        } else {
            CoverageState::Partial
        },
        format!(
            "directories_pending={}, file_chunks_pending={}, files_reviewed={}, files_excluded={}, files_unavailable={}, components_unmapped={}, sources_unavailable={}; agent observations are not verified vulnerability claims",
            summary.directories_pending,
            summary.files_pending,
            summary.files_reviewed,
            summary.files_excluded,
            summary.files_unavailable,
            summary.components_unmapped,
            summary.sources_unavailable
        ),
    )
}

pub fn mapped_sources(
    profile: &Profile,
    path: &Path,
    store: &Store,
) -> Result<Vec<(String, String)>> {
    if profile.discovery == DiscoveryMode::Off {
        return Ok(Vec::new());
    }
    sources::mapped(store, &scope(profile, path)?)
}

pub fn source_map(
    profile: &Profile,
    path: &Path,
    store: &Store,
) -> Result<Vec<IdentityObservation>> {
    if profile.discovery == DiscoveryMode::Off || store.meta("last_snapshot")?.is_none() {
        return Ok(Vec::new());
    }
    let snapshot = store.latest()?;
    let fingerprints: std::collections::BTreeMap<_, _> = snapshot
        .instances
        .iter()
        .map(|instance| (instance.id.as_str(), sources::fingerprint(instance)))
        .collect();
    Ok(sources::all(store, &scope(profile, path)?)?
        .into_iter()
        .filter(|observation| {
            fingerprints.get(observation.instance_id.as_str()) == Some(&observation.fingerprint)
        })
        .collect())
}

pub fn gaps(
    profile: &Profile,
    path: &Path,
    store: &Store,
    after: &str,
    limit: usize,
) -> Result<GapPage> {
    if !(1..=1000).contains(&limit) {
        bail!("gap page size must be 1..1000");
    }
    let scope = scope(profile, path)?;
    let mut query=store.connection.prepare("SELECT id,path,state,reason FROM (SELECT id,path,state,reason FROM discovery_files WHERE scope=?1 AND state IN ('excluded','unavailable','removed') UNION ALL SELECT 'directory:'||root||':'||path AS id,path,state,stamp AS reason FROM discovery_walk WHERE scope=?1 AND state IN ('unavailable','removed')) WHERE id>?2 ORDER BY id LIMIT ?3")?;
    let mut items: Vec<DiscoveryGap> = query
        .query_map(params![scope, after, limit + 1], |row| {
            Ok(DiscoveryGap {
                id: row.get(0)?,
                path: row.get(1)?,
                state: row.get(2)?,
                reason: row.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|item| item.id.clone())
    } else {
        None
    };
    Ok(GapPage { items, next_cursor })
}
