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
};

pub(super) fn fingerprint(instance: &Instance) -> String {
    crate::digest(
        format!(
            "{}:{:?}:{:?}",
            instance.id, instance.requested_version, instance.provenance.sha256
        )
        .as_bytes(),
    )
}

pub(super) fn targets(store: &Store, scope: &str, limit: usize) -> Result<Vec<PublicTarget>> {
    if store.meta("last_snapshot")?.is_none() {
        return Ok(Vec::new());
    }
    let snapshot = store.latest()?;
    let mut targets = Vec::new();
    for instance in &snapshot.instances {
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
            let incomplete = observation
                .sources
                .iter()
                .any(|source| source.state == MappingState::Unavailable);
            let refresh = (instance.requested_version.as_deref() == Some("latest") || incomplete)
                && checked_at < snapshot.started_at;
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
                instance.upstream = source.url;
            }
        }
    }
    Ok(())
}

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
            if source.state == MappingState::Mapped
                && let Some(url) = source.url
            {
                sources.push((observation.instance_id.clone(), url));
            }
        }
    }
    Ok(sources)
}

pub(super) fn counts(store: &Store, scope: &str, instances: &[Instance]) -> Result<(usize, usize)> {
    let observations = all(store, scope)?;
    let observations: BTreeMap<_, _> = observations
        .iter()
        .map(|observation| (observation.instance_id.as_str(), observation))
        .collect();
    let mut unmapped = 0;
    let mut unavailable = 0;
    for instance in instances {
        match observations.get(instance.id.as_str()) {
            Some(observation) if observation.fingerprint == fingerprint(instance) => {
                unavailable += observation
                    .sources
                    .iter()
                    .filter(|source| source.state == MappingState::Unavailable)
                    .count()
            }
            _ => unmapped += 1,
        }
    }
    Ok((unmapped, unavailable))
}

#[cfg(test)]
mod tests;
