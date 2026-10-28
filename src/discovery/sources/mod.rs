use super::contracts::*;
use crate::{
    model::{Evidence, EvidenceKind, EvidenceReference, Instance},
    store::Store,
};
use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
};

const INCOMPLETE_RETRY_DAYS: i64 = 7;

/// Without a repository no upstream research is possible; other categories are enrichment.
fn repository_unavailable(observation: &IdentityObservation) -> bool {
    !observation.sources.iter().any(|source| {
        source.kind == SourceKind::Repository && source.state != MappingState::Unavailable
    })
}

/// Native Maven mappings from an earlier POM resolution revision are mapped again.
fn outdated_maven_mapping(instance: &Instance, observation: &IdentityObservation) -> bool {
    instance.reference.starts_with("pkg:maven/")
        && observation
            .rationale
            .starts_with(registry::NATIVE_RATIONALE)
        && !observation.rationale.contains(registry::MAVEN_MAPPER)
}

/// A lockfile or SBOM hash changes with unrelated packages; the instance id already carries the
/// locked name, version and path, so only declared and observed provenance invalidates a mapping.
pub(super) fn fingerprint(instance: &Instance) -> String {
    let declaration: &str = match instance.origin {
        crate::model::Origin::Locked => "",
        _ => &instance.provenance.sha256,
    };
    crate::digest(
        format!(
            "{}:{:?}:{:?}",
            instance.id, instance.requested_version, declaration
        )
        .as_bytes(),
    )
}

/// Maven artifacts that a workspace root `pom.xml` builds; their source is the monitored workspace,
/// so they need no public source mapping.
pub(super) fn first_party(roots: &[String]) -> BTreeSet<String> {
    roots
        .iter()
        .filter_map(|root| {
            crate::read_limited(&Path::new(root).join("pom.xml"), 2 * 1024 * 1024).ok()
        })
        .filter_map(|pom| registry::maven_reference(&String::from_utf8_lossy(&pom)))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mapper {
    Registry,
    /// Also receives registry mappings without a repository, until it records its own observation.
    Agent,
}

pub(super) fn targets(
    store: &Store,
    scope: &str,
    first_party: &BTreeSet<String>,
    research: &crate::profile::Research,
    mapper: Mapper,
    limit: usize,
) -> Result<Vec<PublicTarget>> {
    if store.meta("last_snapshot")?.is_none() {
        return Ok(Vec::new());
    }
    let snapshot = store.latest()?;
    let mut targets = Vec::new();
    for instance in &snapshot.instances {
        if first_party.contains(&instance.reference) || !research.tracks(instance) {
            continue;
        }
        let previous: Option<(String,String,String)> = store
            .connection
            .query_row(
                "SELECT fingerprint,checked_at,body FROM discovery_sources WHERE scope=?1 AND instance_id=?2",
                params![scope, instance.id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            )
            .optional()?;
        let current = fingerprint(instance);
        if let Some((previous, checked_at, body)) = previous {
            let observation: IdentityObservation = serde_json::from_str(&body)?;
            let latest = instance.requested_version.as_deref() == Some("latest");
            let retry_after =
                (chrono::Utc::now() - chrono::Duration::days(INCOMPLETE_RETRY_DAYS)).to_rfc3339();
            let refresh = (latest && checked_at < snapshot.started_at)
                || (repository_unavailable(&observation) && checked_at < retry_after)
                || outdated_maven_mapping(instance, &observation)
                || (mapper == Mapper::Agent
                    && repository_unavailable(&observation)
                    && observation
                        .rationale
                        .starts_with(registry::NATIVE_RATIONALE));
            if previous == current && !refresh {
                continue;
            }
        }
        targets.push(PublicTarget {
            instance_id: instance.id.clone(),
            fingerprint: current,
            reference: instance.reference.clone(),
            version: instance.resolved_version.clone(),
            upstream: instance.upstream.clone(),
            required_sources: SOURCE_KINDS.to_vec(),
        });
        if targets.len() == limit {
            break;
        }
    }
    Ok(targets)
}

pub(super) fn acquire(store: &Store, url: &str) -> Result<Evidence> {
    let (client, url) = crate::network::public_client(url)?;
    let response = client
        .get(url.clone())
        .send()
        .context("cannot acquire public discovery evidence")?;
    if !response.status().is_success() {
        bail!("discovery source returned HTTP {}", response.status());
    }
    let mut bytes = Vec::new();
    response.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        bail!("discovery document exceeds 2 MiB; acquire a bounded official resource");
    }
    record_document(store, url.as_str(), &bytes)
}

fn record_document(store: &Store, url: &str, bytes: &[u8]) -> Result<Evidence> {
    let mut evidence = store.record_evidence(
        bytes,
        "discovery_public_document",
        Some(url.to_owned()),
        EvidenceKind::Context,
    )?;
    evidence.id = format!(
        "DOC-{}",
        &crate::digest(format!("{url}:{}", evidence.sha256).as_bytes())[..24]
    );
    store.connection.execute(
        "INSERT OR REPLACE INTO discovery_documents VALUES (?1,?2)",
        params![evidence.id, serde_json::to_string(&evidence)?],
    )?;
    Ok(evidence)
}

fn document(store: &Store, reference: &EvidenceReference) -> Result<Evidence> {
    let body: String = store.connection.query_row(
        "SELECT body FROM discovery_documents WHERE id=?1",
        [&reference.id],
        |row| row.get(0),
    )?;
    let evidence: Evidence = serde_json::from_str(&body)?;
    if evidence.sha256 != reference.sha256 || !store.evidence_exists(&evidence)? {
        bail!("discovery evidence hash mismatch");
    }
    Ok(evidence)
}

pub(super) fn import(
    store: &mut Store,
    scope: &str,
    observations: Vec<IdentityObservation>,
) -> Result<()> {
    let snapshot = store.latest()?;
    let mut seen = BTreeSet::new();
    for observation in &observations {
        let instance = snapshot
            .instances
            .iter()
            .find(|instance| instance.id == observation.instance_id)
            .context("identity observation is outside the scanned inventory")?;
        if !seen.insert(&observation.instance_id)
            || observation.fingerprint != fingerprint(instance)
            || observation.rationale.trim().is_empty()
            || observation.rationale.len() > 4000
        {
            bail!("duplicate, stale or unexplained identity observation");
        }
        if observation.sources.len() < SOURCE_KINDS.len() || observation.sources.len() > 100 {
            bail!(
                "map all required source categories, including unavailable/not_applicable dispositions"
            );
        }
        for kind in SOURCE_KINDS {
            if !observation.sources.iter().any(|source| source.kind == kind) {
                bail!("required source category is missing");
            }
        }
        for source in &observation.sources {
            if source.detail.trim().is_empty()
                || source.detail.len() > 4000
                || source.evidence.len() > 20
            {
                bail!("source mapping requires bounded detail and evidence");
            }
            if source.state == MappingState::Mapped
                && (source.url.is_none() || source.evidence.is_empty())
            {
                bail!("mapped source needs its URL and acquired public evidence");
            }
            if source.state == MappingState::NotApplicable && source.evidence.is_empty() {
                bail!(
                    "not_applicable requires positive public evidence; use unavailable when uncertain"
                );
            }
            if let Some(url) = &source.url {
                crate::profile::public_https_syntax(url)?;
            }
            let mut linked = source.url.is_none();
            for reference in &source.evidence {
                let evidence = document(store, reference)?;
                let bytes = crate::read_limited(
                    &store.directory.join("evidence").join(&evidence.sha256),
                    2 * 1024 * 1024,
                )?;
                if let Some(url) = &source.url {
                    linked |= evidence.url.as_ref() == Some(url)
                        || std::str::from_utf8(&bytes).is_ok_and(|text| text.contains(url));
                }
            }
            if source.state == MappingState::Mapped && !linked {
                bail!("mapped URL is absent from its acquired evidence");
            }
        }
        if let Some(version) = &observation.version {
            if instance.requested_version.as_deref() != Some("latest")
                || version.is_empty()
                || version.len() > 128
                || version.chars().any(char::is_whitespace)
                || version == "latest"
            {
                bail!("discovered release can resolve only an explicit latest request");
            }
            require_literal(store, observation, SourceKind::Releases, version)?;
        }
        if let Some(cpe) = &observation.cpe_product {
            if !cpe.starts_with("cpe:2.3:")
                || cpe.split(':').count() != 5
                || cpe.contains(['*', '?'])
            {
                bail!("provide an exact CPE product prefix");
            }
            require_literal(store, observation, SourceKind::Advisories, cpe)?;
        }
    }
    let transaction = store.connection.transaction()?;
    for observation in observations {
        transaction.execute("INSERT INTO discovery_history(scope,phase,body,recorded_at) VALUES (?1,'sources',?2,?3)",params![scope,serde_json::to_string(&observation)?,crate::now()])?;
        transaction.execute(
            "INSERT OR REPLACE INTO discovery_sources VALUES (?1,?2,?3,?4,?5)",
            params![
                scope,
                observation.instance_id,
                observation.fingerprint,
                crate::now(),
                serde_json::to_string(&observation)?
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn require_literal(
    store: &Store,
    observation: &IdentityObservation,
    kind: SourceKind,
    literal: &str,
) -> Result<()> {
    for source in &observation.sources {
        if source.kind != kind || source.state != MappingState::Mapped {
            continue;
        }
        for reference in &source.evidence {
            let evidence = document(store, reference)?;
            let bytes = crate::read_limited(
                &store.directory.join("evidence").join(&evidence.sha256),
                2 * 1024 * 1024,
            )?;
            if std::str::from_utf8(&bytes).is_ok_and(|text| text.contains(literal)) {
                return Ok(());
            }
        }
    }
    bail!("identity value is absent from acquired source evidence")
}

pub(super) fn all(store: &Store, scope: &str) -> Result<Vec<IdentityObservation>> {
    let mut query = store
        .connection
        .prepare("SELECT body FROM discovery_sources WHERE scope=?1 ORDER BY instance_id")?;
    let bodies: Vec<String> = query
        .query_map([scope], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    bodies
        .iter()
        .map(|body| Ok(serde_json::from_str(body)?))
        .collect()
}

pub(super) fn apply(store: &Store, scope: &str, instances: &mut [Instance]) -> Result<()> {
    let positions: BTreeMap<_, _> = instances
        .iter()
        .enumerate()
        .map(|(index, instance)| (instance.id.clone(), index))
        .collect();
    for observation in all(store, scope)? {
        let Some(index) = positions.get(&observation.instance_id) else {
            continue;
        };
        let instance = &mut instances[*index];
        if observation.fingerprint != fingerprint(instance) {
            continue;
        }
        if observation.version.is_some() || observation.cpe_product.is_some() {
            instance.identity_evidence.push(store.record_evidence(
                &serde_json::to_vec(&serde_json::json!({"version":observation.version,"cpe_product":observation.cpe_product}))?,
                "agent_product_mapping",
                None,
                EvidenceKind::Context,
            )?);
        }
        if let Some(version) = observation.version {
            instance.resolved_version = Some(version);
        }
        if observation.cpe_product.is_some() {
            instance.cpe_product = observation.cpe_product;
        }
        for source in observation.sources {
            if source.kind == SourceKind::Repository
                && source.state == MappingState::Mapped
                && instance.upstream.is_none()
            {
                instance.upstream = source
                    .url
                    .as_deref()
                    .and_then(crate::identity::canonical_repository);
            }
        }
    }
    Ok(())
}

/// Research targets per instance: places where security activity is published, never websites,
/// documentation or registry records.
pub(super) fn mapped(store: &Store, scope: &str) -> Result<Vec<(String, String)>> {
    let mut sources = Vec::new();
    if store.meta("last_snapshot")?.is_none() {
        return Ok(sources);
    }
    let snapshot = store.latest()?;
    let fingerprints: BTreeMap<_, _> = snapshot
        .instances
        .iter()
        .map(|instance| (instance.id.as_str(), fingerprint(instance)))
        .collect();
    for observation in all(store, scope)? {
        if fingerprints.get(observation.instance_id.as_str()) != Some(&observation.fingerprint) {
            continue;
        }
        for source in observation.sources {
            let researched = matches!(
                source.kind,
                SourceKind::Repository
                    | SourceKind::Issues
                    | SourceKind::ProposedChanges
                    | SourceKind::Discussions
                    | SourceKind::Changelog
                    | SourceKind::Advisories
            );
            if researched
                && source.state == MappingState::Mapped
                && let Some(url) = source
                    .url
                    .as_deref()
                    .and_then(crate::identity::canonical_repository)
                && !sources.contains(&(observation.instance_id.clone(), url.clone()))
            {
                sources.push((observation.instance_id.clone(), url));
            }
        }
    }
    Ok(sources)
}

pub(super) fn counts(
    store: &Store,
    scope: &str,
    first_party: &BTreeSet<String>,
    instances: &[Instance],
    research: &crate::profile::Research,
) -> Result<(usize, usize)> {
    let observations = all(store, scope)?;
    let observations: BTreeMap<_, _> = observations
        .iter()
        .map(|observation| (observation.instance_id.as_str(), observation))
        .collect();
    let mut unmapped = 0;
    let mut unavailable = 0;
    for instance in instances
        .iter()
        .filter(|instance| !first_party.contains(&instance.reference) && research.tracks(instance))
    {
        match observations.get(instance.id.as_str()) {
            Some(observation) if observation.fingerprint == fingerprint(instance) => {
                unavailable += usize::from(repository_unavailable(observation));
            }
            _ => unmapped += 1,
        }
    }
    Ok((unmapped, unavailable))
}

mod registry;
pub(super) use registry::map as map_registries;
pub use registry::{RegistryFailure, RegistryRun};

#[cfg(test)]
mod tests;
