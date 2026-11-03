use crate::{
    model::{
        Evidence, EvidenceKind, EvidenceReference, Instance, ManifestDeclaration, Origin,
        SourceLine,
    },
    store::Store,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::{Component, Path},
    rc::Rc,
};

pub(crate) const SOURCE: &str = "manifest_lock_relation";
const FILE_LIMIT: u64 = 16 * 1024 * 1024;
const TOTAL_LIMIT: usize = 64 * 1024 * 1024;
const FILE_COUNT_LIMIT: usize = 4096;
const LINE_COUNT_LIMIT: usize = 200_000;

#[derive(Serialize, Deserialize)]
struct Relation {
    observed_id: String,
    preserved_observation: bool,
    observation_sha256: String,
    observation_evidence: Vec<Evidence>,
    lock_id: String,
    lock_sha256: String,
    source: SourceLine,
    inputs: Vec<RelationInput>,
}

#[derive(Serialize, Deserialize)]
struct RelationInput {
    path: String,
    sha256: String,
}

type FileKey = (String, String);

struct CargoLine {
    start: usize,
    end: usize,
    workspace: Option<bool>,
}

mod files;
use files::Files;

fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn canonical_root(base: &Path, root: &str) -> Option<String> {
    base.join(root)
        .canonicalize()
        .ok()?
        .to_str()
        .map(str::to_owned)
}

mod ecosystems;
#[cfg(test)]
use ecosystems::declaration_section;
use ecosystems::{cargo_link, inherits_workspace, npm_link, workspace_declaration};

pub(super) fn merge(
    instances: &mut Vec<Instance>,
    store: &Store,
    profile_path: &Path,
    previous_instances: &[Instance],
    previous_cases: &[crate::model::Case],
) -> Result<bool> {
    let base = profile_path.parent().unwrap_or(Path::new("."));
    if !instances.iter().any(|instance| {
        instance.origin == Origin::AgentObserved
            && (instance.reference.starts_with("pkg:cargo/")
                || instance.reference.starts_with("pkg:npm/"))
    }) {
        return Ok(true);
    }
    let mut protected: HashSet<String> = previous_cases
        .iter()
        .flat_map(|case| case.instances.iter().map(|instance| instance.id.clone()))
        .collect();
    let mut statement = store.connection.prepare(
        "SELECT instance_id FROM discovery_sources UNION SELECT value FROM research_events, json_each(research_events.body, '$.instance_ids') UNION SELECT value FROM research_events, json_each(research_events.body, '$.reviewed_instance_ids') LIMIT 100001"
    )?;
    let referenced: Vec<String> = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if referenced.len() > 100_000 {
        return Ok(false);
    }
    protected.extend(referenced);
    let key = |instance: &Instance| {
        (
            instance.reference.clone(),
            instance.requested_version.clone(),
            instance.provenance.codebase.clone(),
            instance.provenance.path.clone(),
        )
    };
    let protected_keys: HashSet<_> = previous_cases
        .iter()
        .flat_map(|case| &case.instances)
        .chain(previous_instances)
        .filter(|instance| {
            instance.origin == Origin::AgentObserved && protected.contains(&instance.id)
        })
        .map(key)
        .collect();
    let mut locks: HashMap<(String, String), Vec<usize>> = HashMap::new();
    let mut files = Files::default();
    let mut roots = HashMap::<String, Option<String>>::new();
    let mut lock_hashes = HashMap::<(String, String), Option<String>>::new();
    for (index, instance) in instances.iter().enumerate() {
        if instance.origin == Origin::Locked
            && let Some(root) = &instance.provenance.codebase
            && let Some(path) = &instance.provenance.path
            && safe_path(path)
        {
            let resolved = roots
                .entry(root.clone())
                .or_insert_with(|| canonical_root(base, root));
            if let Some(root) = resolved {
                let hash = lock_hashes
                    .entry((root.clone(), path.clone()))
                    .or_insert_with(|| files.digest(root, path));
                if hash.as_deref() != Some(instance.provenance.sha256.as_str()) {
                    continue;
                }
                locks
                    .entry((root.clone(), instance.reference.clone()))
                    .or_default()
                    .push(index);
            }
        }
    }
    let mut links = Vec::new();
    let mut observations = HashMap::<(String, String), Vec<usize>>::new();
    for (index, instance) in instances.iter().enumerate() {
        if instance.origin == Origin::AgentObserved
            && let Some(root) = &instance.provenance.codebase
        {
            observations
                .entry((root.clone(), instance.reference.clone()))
                .or_default()
                .push(index);
        }
    }
    for (index, instance) in instances.iter().enumerate() {
        if instance.origin != Origin::AgentObserved
            || instance.requested_version.as_deref() == Some("latest")
            || instance
                .resolved_version
                .as_ref()
                .is_some_and(|version| Some(version) != instance.requested_version.as_ref())
        {
            continue;
        }
        if instance.identity_evidence.is_empty()
            || instance.identity_evidence.iter().any(|evidence| {
                evidence.source != "agent_codebase_observation"
                    || evidence.kind != EvidenceKind::Context
                    || evidence_bytes(store, evidence).is_err()
            })
        {
            continue;
        }
        let (Some(root), Some(path), Some(line)) = (
            &instance.provenance.codebase,
            &instance.provenance.path,
            instance.provenance.line,
        ) else {
            continue;
        };
        let candidates: Vec<usize> = locks
            .get(&(root.clone(), instance.reference.clone()))
            .into_iter()
            .flatten()
            .copied()
            .filter(|candidate| {
                if instance
                    .requested_version
                    .as_deref()
                    .is_some_and(|version| {
                        instances[*candidate].resolved_version.as_deref() != Some(version)
                    })
                {
                    return false;
                }
                if instance.reference.starts_with("pkg:cargo/") {
                    let locked = &instances[*candidate];
                    cargo_link(instance, locked, &mut files)
                        && (!workspace_declaration(instance, locked, &mut files)
                            || observations
                                .get(&(root.clone(), instance.reference.clone()))
                                .is_some_and(|members| {
                                    members.iter().any(|member| {
                                        *member != index
                                            && inherits_workspace(&instances[*member], &mut files)
                                            && cargo_link(&instances[*member], locked, &mut files)
                                    })
                                }))
                } else if instance.reference.starts_with("pkg:npm/") {
                    npm_link(instance, &instances[*candidate], &mut files)
                } else {
                    false
                }
            })
            .collect();
        if let [candidate] = candidates.as_slice() {
            let Some(source_hash) = files.digest(root, path) else {
                continue;
            };
            let Some(lock_path) = instances[*candidate].provenance.path.as_ref() else {
                continue;
            };
            let mut inputs = vec![
                RelationInput {
                    path: path.clone(),
                    sha256: source_hash.clone(),
                },
                RelationInput {
                    path: lock_path.clone(),
                    sha256: instances[*candidate].provenance.sha256.clone(),
                },
            ];
            if instance.reference.starts_with("pkg:cargo/") {
                let workspace_manifest = crate::slash_path(
                    &Path::new(lock_path)
                        .parent()
                        .unwrap_or(Path::new(""))
                        .join("Cargo.toml"),
                );
                if workspace_manifest != *path {
                    let Some(sha256) = files.digest(root, &workspace_manifest) else {
                        continue;
                    };
                    inputs.push(RelationInput {
                        path: workspace_manifest,
                        sha256,
                    });
                } else if workspace_declaration(instance, &instances[*candidate], &mut files) {
                    let Some(member) = observations
                        .get(&(root.clone(), instance.reference.clone()))
                        .into_iter()
                        .flatten()
                        .map(|index| &instances[*index])
                        .filter(|member| {
                            member.id != instance.id
                                && inherits_workspace(member, &mut files)
                                && cargo_link(member, &instances[*candidate], &mut files)
                        })
                        .min_by(|left, right| {
                            left.provenance
                                .path
                                .cmp(&right.provenance.path)
                                .then_with(|| left.id.cmp(&right.id))
                        })
                    else {
                        continue;
                    };
                    let Some(member_path) = member.provenance.path.as_ref() else {
                        continue;
                    };
                    let Some(sha256) = files.digest(root, member_path) else {
                        continue;
                    };
                    inputs.push(RelationInput {
                        path: member_path.clone(),
                        sha256,
                    });
                }
            }
            let relation = Relation {
                observed_id: instance.id.clone(),
                preserved_observation: protected.contains(&instance.id)
                    || protected_keys.contains(&key(instance)),
                observation_sha256: instance.provenance.sha256.clone(),
                observation_evidence: instance.identity_evidence.clone(),
                lock_id: instances[*candidate].id.clone(),
                lock_sha256: instances[*candidate].provenance.sha256.clone(),
                source: SourceLine {
                    path: path.clone(),
                    line,
                    sha256: source_hash,
                },
                inputs,
            };
            let evidence = store.record_evidence(
                &serde_json::to_vec(&relation)?,
                SOURCE,
                None,
                EvidenceKind::Context,
            )?;
            if !store.evidence_exists(&evidence).unwrap_or(false) {
                anyhow::bail!("manifest relation evidence has invalid integrity");
            }
            links.push((index, *candidate, evidence, relation.preserved_observation));
        }
    }
    let mut removed = HashSet::new();
    for (observed, locked, evidence, preserved) in links {
        if !preserved {
            removed.insert(observed);
        }
        let target = &mut instances[locked];
        if !target
            .identity_evidence
            .iter()
            .any(|existing| existing.sha256 == evidence.sha256)
        {
            target.identity_evidence.push(evidence);
        }
    }
    let mut index = 0;
    instances.retain(|_| {
        let keep = !removed.contains(&index);
        index += 1;
        keep
    });
    Ok(true)
}

fn evidence_bytes(store: &Store, evidence: &Evidence) -> Result<Vec<u8>> {
    if evidence.sha256.len() != 64 || !evidence.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("invalid manifest relation evidence digest");
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        64 * 1024,
    )?;
    if crate::digest(&bytes) != evidence.sha256 {
        bail!("manifest relation evidence integrity mismatch");
    }
    Ok(bytes)
}

fn verified_relations<'a>(
    instances: &'a [Instance],
    store: &Store,
    require_current_inputs: bool,
) -> Result<Vec<(&'a Instance, &'a Evidence, Relation)>> {
    let base = store
        .meta("profile_path")?
        .map(std::path::PathBuf::from)
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut roots = HashMap::<String, Option<String>>::new();
    let mut hashes = HashMap::<FileKey, Option<String>>::new();
    let mut result = Vec::new();
    for lock in instances {
        'evidence: for evidence in lock
            .identity_evidence
            .iter()
            .filter(|evidence| evidence.source == SOURCE)
        {
            let checked =
                || -> Result<Relation> {
                    if evidence.kind != EvidenceKind::Context || lock.origin != Origin::Locked {
                        bail!("invalid manifest relation kind or lock origin");
                    }
                    let relation: Relation =
                        serde_json::from_slice(&evidence_bytes(store, evidence)?)?;
                    if relation.lock_id != lock.id
                        || relation.lock_sha256 != lock.provenance.sha256
                        || !safe_path(&relation.source.path)
                        || relation.source.line == 0
                        || relation.observation_evidence.is_empty()
                    {
                        bail!("manifest relation does not match the locked package");
                    }
                    for original in &relation.observation_evidence {
                        if original.kind != EvidenceKind::Context
                            || original.source != "agent_codebase_observation"
                        {
                            bail!("invalid declaration observation evidence");
                        }
                        let observation: crate::discovery::PackageObservation =
                            serde_json::from_slice(&evidence_bytes(store, original)?)?;
                        if observation.component.reference != lock.reference {
                            bail!("declaration evidence refers to another package");
                        }
                    }
                    let lock_path = lock
                        .provenance
                        .path
                        .as_deref()
                        .context("lockfile path missing")?;
                    if !relation.inputs.iter().any(|input| {
                        input.path == lock_path && input.sha256 == relation.lock_sha256
                    }) || !relation.inputs.iter().any(|input| {
                        input.path == relation.source.path && input.sha256 == relation.source.sha256
                    }) {
                        bail!("manifest relation inputs are incomplete");
                    }
                    if relation.inputs.iter().any(|input| {
                        !safe_path(&input.path)
                            || input.sha256.len() != 64
                            || !input.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }) {
                        bail!("manifest relation input is invalid");
                    }
                    Ok(relation)
                };
            let relation = checked().context(
                "manifest-to-lock evidence is unavailable or invalid; restore it and rescan",
            )?;
            if !require_current_inputs {
                result.push((lock, evidence, relation));
                continue;
            }
            let original_root = lock
                .provenance
                .codebase
                .as_deref()
                .context("manifest relation codebase missing")?;
            let Some(root) = roots
                .entry(original_root.to_owned())
                .or_insert_with(|| canonical_root(&base, original_root))
                .clone()
            else {
                continue;
            };
            for input in &relation.inputs {
                if !safe_path(&input.path)
                    || input.sha256.len() != 64
                    || !input.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    bail!("manifest relation input is invalid; rescan");
                }
                let hash = hashes
                    .entry((root.clone(), input.path.clone()))
                    .or_insert_with(|| {
                        let file = crate::discovery::open_file(&root, &input.path).ok()?;
                        let meta = file.metadata().ok()?;
                        if !meta.is_file() || meta.len() > FILE_LIMIT {
                            return None;
                        }
                        let mut bytes = Vec::new();
                        file.take(FILE_LIMIT + 1).read_to_end(&mut bytes).ok()?;
                        (bytes.len() as u64 <= FILE_LIMIT).then(|| crate::digest(&bytes))
                    });
                if hash.as_deref() != Some(input.sha256.as_str()) {
                    continue 'evidence;
                }
            }
            result.push((lock, evidence, relation));
        }
    }
    Ok(result)
}

pub(super) fn covered_observations(
    instances: &[Instance],
    store: &Store,
) -> Result<HashMap<String, (String, SourceLine)>> {
    let mut result = HashMap::new();
    for (_, _, relation) in verified_relations(instances, store, true)? {
        if relation.preserved_observation {
            continue;
        }
        if result
            .insert(
                relation.observed_id,
                (relation.observation_sha256, relation.source),
            )
            .is_some()
        {
            bail!("manifest observation has multiple recorded lock relations; rescan");
        }
    }
    Ok(result)
}

pub(crate) fn declaration_sources(
    instances: &[Instance],
    store: &Store,
) -> Result<HashMap<String, Vec<ManifestDeclaration>>> {
    let mut result = HashMap::<String, Vec<ManifestDeclaration>>::new();
    for (lock, evidence, relation) in verified_relations(instances, store, false)? {
        result
            .entry(lock.id.clone())
            .or_default()
            .push(ManifestDeclaration {
                source: relation.source,
                observation_id: relation.observed_id,
                relation_evidence: EvidenceReference {
                    id: evidence.id.clone(),
                    sha256: evidence.sha256.clone(),
                },
                observation_evidence: relation
                    .observation_evidence
                    .into_iter()
                    .map(|item| EvidenceReference {
                        id: item.id,
                        sha256: item.sha256,
                    })
                    .collect(),
            });
    }
    for declarations in result.values_mut() {
        declarations.sort_by(|a, b| {
            (
                &a.source.path,
                a.source.line,
                &a.source.sha256,
                &a.observation_id,
                &a.relation_evidence.id,
            )
                .cmp(&(
                    &b.source.path,
                    b.source.line,
                    &b.source.sha256,
                    &b.observation_id,
                    &b.relation_evidence.id,
                ))
        });
        declarations.dedup_by(|a, b| {
            a.source.path == b.source.path
                && a.source.line == b.source.line
                && a.source.sha256 == b.source.sha256
                && a.observation_id == b.observation_id
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
