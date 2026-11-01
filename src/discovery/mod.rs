use crate::{
    model::{Coverage, CoverageState, Instance},
    profile::{DiscoveryMode, Profile},
    store::Store,
};
use anyhow::{Result, bail};
use rusqlite::params;
use std::{collections::BTreeSet, path::Path};

pub(crate) mod automation;
mod codebase;
mod contracts;
mod sources;
pub(crate) use codebase::{
    checked_path, has_untrusted_sources, open_file, private_name, requirements_file,
};
pub use contracts::*;
pub use sources::{RegistryFailure, RegistryRun};

/// Discovery state is keyed by project and codebase roots only, so editing components,
/// research topics or schedules keeps completed file reviews.
fn roots(profile: &Profile, path: &Path) -> Result<Vec<String>> {
    let profile_path = path.canonicalize()?;
    let base = profile_path.parent().unwrap_or(Path::new("/"));
    let mut roots: Vec<String> = profile
        .codebases
        .iter()
        .map(|codebase| {
            let joined = base.join(codebase);
            joined
                .canonicalize()
                .unwrap_or(joined)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    roots.sort_unstable();
    Ok(roots)
}

pub fn scope(profile: &Profile, path: &Path) -> Result<String> {
    let roots = roots(profile, path)?;
    Ok(crate::digest(&serde_json::to_vec(&(
        "discovery-scope-v5",
        profile.project_id,
        roots,
    ))?))
}

#[derive(Debug, serde::Serialize)]
pub struct RegistryMapping {
    #[serde(flatten)]
    pub run: RegistryRun,
    pub summary: DiscoverySummary,
}

/// Maps pending components from their public registry records (crates.io, npm, PyPI,
/// Maven Central) without agent tasks; unsupported ecosystems stay pending for the agent.
pub fn map_registries(
    profile: &Profile,
    path: &Path,
    store: &mut Store,
    limit: usize,
    offline: bool,
) -> Result<RegistryMapping> {
    if profile.discovery != DiscoveryMode::Agent {
        bail!("agent discovery is not enabled in this profile");
    }
    if !(1..=500).contains(&limit) {
        bail!("registry mapping limit must be 1..500 packages");
    }
    if store.meta("last_snapshot")?.is_none() {
        bail!("run scan before mapping registry sources");
    }
    let _lock = store.lock()?;
    let scope = scope(profile, path)?;
    codebase::prepare(profile, path, store, &scope)?;
    if !codebase::sync_include_guard(store, &scope)? {
        bail!("finish codebase enumeration before mapping registry sources");
    }
    let mut http = crate::network::Http::new(store, offline);
    let first_party = sources::first_party(&roots(profile, path)?);
    let run = sources::map_registries(
        store,
        &scope,
        &first_party,
        &profile.research,
        &mut http,
        limit,
    )?;
    Ok(RegistryMapping {
        run,
        summary: summary(profile, path, store)?,
    })
}

pub fn reopen(
    profile: &Profile,
    path: &Path,
    store: &mut Store,
    relative: &str,
) -> Result<DiscoverySummary> {
    if profile.discovery != DiscoveryMode::Agent {
        bail!("agent discovery is not enabled in this profile");
    }
    let _lock = store.lock()?;
    codebase::reopen(store, &scope(profile, path)?, relative)?;
    summary(profile, path, store)
}

pub fn plan(profile: &Profile, path: &Path, store: &Store, limit: usize) -> Result<DiscoveryPlan> {
    if !(1..=20).contains(&limit) {
        bail!("discovery page size must be 1..20");
    }
    let scope = scope(profile, path)?;
    if profile.discovery == DiscoveryMode::Agent {
        codebase::prepare(profile, path, store, &scope)?;
    }
    let ready =
        profile.discovery == DiscoveryMode::Agent && codebase::sync_include_guard(store, &scope)?;
    let codebase_files = if ready {
        codebase::page(store, &scope, limit)?
    } else {
        Vec::new()
    };
    let components = if ready {
        sources::targets(
            store,
            &scope,
            &sources::first_party(&roots(profile, path)?),
            &profile.research,
            sources::Mapper::Agent,
            limit,
        )?
    } else {
        Vec::new()
    };
    Ok(DiscoveryPlan {
        schema_version: 1,
        project_id: profile.project_id.to_string(),
        scope_sha256: scope.clone(),
        enabled: profile.discovery == DiscoveryMode::Agent,
        codebase_files,
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
    store.ensure_codebases_current()?;
    let current_scope = scope(profile, path)?;
    match batch {
        DiscoveryBatch::Codebase {
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
            codebase::prepare(profile, path, store, &current_scope)?;
            codebase::import(profile, store, &current_scope, reviews)?;
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

/// Native inventory gaps that general discovery covers are replaced by the discovery row:
/// unsupported manifests it already reviewed or excluded, and codebases without lockfiles.
pub fn augment(
    profile: &Profile,
    path: &Path,
    store: &Store,
    instances: &mut Vec<Instance>,
    inventory_coverage: &mut Vec<Coverage>,
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
    let preparation = codebase::prepare(profile, path, store, &scope);
    let ready = preparation.is_ok() && codebase::sync_include_guard(store, &scope)?;
    let settled = codebase::settled_paths(store, &scope)?;
    inventory_coverage.retain(|row| {
        row.source != "inventory"
            || row.detail != crate::inventory::NO_NATIVE_INVENTORY
                && !(row.detail == crate::inventory::UNSUPPORTED_MANIFEST
                    && settled.contains(&row.scope))
    });
    if ready {
        append_codebase_instances(store, &scope, instances)?;
    }
    sources::apply(store, &scope, instances)?;
    let first_party = sources::first_party(&roots(profile, path)?);
    let summary = summary_for_instances(profile, store, &scope, &first_party, instances)?;
    let mut coverage_rows = vec![coverage(&summary)];
    if let Err(error) = preparation {
        coverage_rows.push(Coverage::new(
            "general_discovery",
            "codebase",
            CoverageState::Unavailable,
            error.to_string(),
        ));
    }
    Ok(coverage_rows)
}

fn append_codebase_instances(
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
                instance.provenance.codebase.clone(),
            )
        })
        .collect();
    for discovered in codebase::instances(store, scope)? {
        let key = (
            discovered.reference.clone(),
            discovered.resolved_version.clone(),
            discovered.provenance.path.clone(),
            discovered.provenance.codebase.clone(),
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
    append_codebase_instances(store, &scope, &mut instances)?;
    let first_party = sources::first_party(&roots(profile, path)?);
    summary_for_instances(profile, store, &scope, &first_party, &instances)
}

fn summary_for_instances(
    profile: &Profile,
    store: &Store,
    scope: &str,
    first_party: &BTreeSet<String>,
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
    let (components_unmapped, sources_unavailable) =
        sources::counts(store, scope, first_party, instances, &profile.research)?;
    let complete = enabled
        && initialized_roots >= profile.codebases.len()
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
            + profile.codebases.len().saturating_sub(initialized_roots),
        files_pending,
        files_reviewed: count("discovery_files", "done")?,
        files_excluded: count("discovery_files", "excluded")?
            + count("discovery_files", "removed")?,
        files_unavailable,
        components_unmapped,
        deferred_transitive: instances
            .iter()
            .filter(|instance| {
                !profile.research.tracks(instance) && instance.provenance.direct == Some(false)
            })
            .count(),
        deferred_unknown_depth: instances
            .iter()
            .filter(|instance| {
                !profile.research.tracks(instance) && instance.provenance.direct.is_none()
            })
            .count(),
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
            "directories_pending={}, file_chunks_pending={}, files_reviewed={}, files_excluded={}, files_unavailable={}, components_unmapped={}, sources_unavailable={}, deferred_transitive={}, deferred_unknown_depth={}; agent observations are not verified vulnerability claims",
            summary.directories_pending,
            summary.files_pending,
            summary.files_reviewed,
            summary.files_excluded,
            summary.files_unavailable,
            summary.components_unmapped,
            summary.sources_unavailable,
            summary.deferred_transitive,
            summary.deferred_unknown_depth
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

/// Current, locally validated agent observations; never reuse stale public identities.
pub(crate) fn current_observation_ids(
    profile: &Profile,
    path: &Path,
    store: &Store,
) -> Result<Option<std::collections::HashSet<String>>> {
    let unavailable = || -> Result<bool> {
        Ok(roots(profile, path)?
            .iter()
            .any(|root| std::fs::read_dir(root).is_err()))
    };
    if unavailable()? {
        return Ok(None);
    }
    if profile.discovery == DiscoveryMode::Off {
        return Ok(Some(std::collections::HashSet::new()));
    }
    let scope = scope(profile, path)?;
    if let Err(error) = codebase::prepare(profile, path, store, &scope) {
        if unavailable()? {
            return Ok(None);
        }
        return Err(error);
    }
    if !codebase::sync_include_guard(store, &scope)? {
        return Ok(Some(std::collections::HashSet::new()));
    }
    Ok(Some(
        codebase::instances(store, &scope)?
            .into_iter()
            .map(|instance| instance.id)
            .collect(),
    ))
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
    let first_party = sources::first_party(&roots(profile, path)?);
    let fingerprints: std::collections::BTreeMap<_, _> = snapshot
        .instances
        .iter()
        .filter(|instance| !first_party.contains(&instance.reference))
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
    // Unavailable entries block completeness and come before removed and audited exclusions.
    let mut query=store.connection.prepare("SELECT cursor,id,path,state,reason FROM (SELECT CASE state WHEN 'unavailable' THEN '0' WHEN 'removed' THEN '1' ELSE '2' END||':'||id AS cursor,id,path,state,reason FROM (SELECT id,path,state,reason FROM discovery_files WHERE scope=?1 AND state IN ('excluded','unavailable','removed') UNION ALL SELECT 'directory:'||root||':'||path AS id,path,state,stamp AS reason FROM discovery_walk WHERE scope=?1 AND state IN ('excluded','unavailable','removed'))) WHERE cursor>?2 ORDER BY cursor LIMIT ?3")?;
    let mut rows: Vec<(String, DiscoveryGap)> = query
        .query_map(params![scope, after, limit + 1], |row| {
            Ok((
                row.get(0)?,
                DiscoveryGap {
                    id: row.get(1)?,
                    path: row.get(2)?,
                    state: row.get(3)?,
                    reason: row.get(4)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let next_cursor = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|(cursor, _)| cursor.clone())
    } else {
        None
    };
    let items = rows.into_iter().map(|(_, gap)| gap).collect();
    Ok(GapPage { items, next_cursor })
}
