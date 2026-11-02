use crate::model::{Coverage, Instance, Origin};
use pep508_rs::pep440_rs::Version;
use std::collections::{BTreeMap, BTreeSet, HashMap};

type PackageKey = (String, Version);

fn package_key(instance: &Instance) -> Option<PackageKey> {
    let purl: packageurl::PackageUrl<'_> = instance.purl.as_deref()?.parse().ok()?;
    if purl.ty() != "pypi" || purl.namespace().is_some() {
        return None;
    }
    let version = instance
        .resolved_version
        .as_deref()?
        .parse::<Version>()
        .ok()?;
    Some((crate::identity::normalize_pypi(purl.name()), version))
}

fn verified_lock(instance: &Instance, store: &crate::store::Store) -> bool {
    instance.python_lock.is_some()
        && instance.identity_evidence.iter().any(|evidence| {
            evidence.source == "registry_hash_match"
                && store.evidence_exists(evidence).unwrap_or(false)
        })
}

pub(crate) fn merge_verified(
    instances: &mut Vec<Instance>,
    coverage: &mut Vec<Coverage>,
    previous: &[Instance],
    store: &crate::store::Store,
) {
    let mut locks: BTreeMap<PackageKey, Vec<usize>> = BTreeMap::new();
    let mut declared: BTreeMap<PackageKey, Vec<usize>> = BTreeMap::new();
    for (index, instance) in instances.iter().enumerate() {
        let Some(key) = package_key(instance) else {
            continue;
        };
        if verified_lock(instance, store) {
            locks.entry(key).or_default().push(index);
        } else if matches!(instance.origin, Origin::Declared | Origin::Deployed)
            && instance.provenance.path.is_none()
        {
            declared.entry(key).or_default().push(index);
        }
    }
    let mut removed = BTreeSet::new();
    let mut replaced = HashMap::new();
    let mut dropped_coverage = BTreeSet::new();
    let mut previous_ids: BTreeMap<PackageKey, Vec<&str>> = BTreeMap::new();
    for item in previous {
        if (item.python_lock.is_some()
            || matches!(item.origin, Origin::Declared | Origin::Deployed)
                && item.provenance.path.is_none())
            && let Some(key) = package_key(item)
        {
            previous_ids.entry(key).or_default().push(&item.id);
        }
    }
    for (key, lock_indices) in locks {
        let [lock_index] = lock_indices.as_slice() else {
            continue;
        };
        let candidates = declared.get(&key).map(Vec::as_slice).unwrap_or_default();
        if candidates.len() > 1 {
            continue;
        }
        let lock_index = *lock_index;
        let canonical_reference = format!("pkg:pypi/{}", key.0);
        let default_component = crate::profile::Component {
            reference: canonical_reference,
            version: instances[lock_index].requested_version.clone(),
            usage: Default::default(),
            upstream: None,
            feeds: Vec::new(),
        };
        let id = if let [index] = candidates {
            let other = instances[*index].clone();
            let current = &instances[lock_index];
            if other.upstream.is_some()
                && current.upstream.is_some()
                && other.upstream != current.upstream
                || other.cpe_product.is_some()
                    && current.cpe_product.is_some()
                    && other.cpe_product != current.cpe_product
            {
                continue;
            }
            let current = &mut instances[lock_index];
            if other.origin == Origin::Deployed {
                current.origin = Origin::Deployed;
            }
            if current.upstream.is_none() {
                current.upstream = other.upstream;
            }
            if current.cpe_product.is_none() {
                current.cpe_product = other.cpe_product;
            }
            for evidence in other.identity_evidence {
                if !current
                    .identity_evidence
                    .iter()
                    .any(|existing| existing.sha256 == evidence.sha256)
                {
                    current.identity_evidence.push(evidence);
                }
            }
            removed.insert(*index);
            dropped_coverage.insert(other.id.clone());
            other.id
        } else if let Some([id]) = previous_ids.get(&key).map(Vec::as_slice) {
            (*id).to_owned()
        } else {
            Instance::declared(&default_component).id
        };
        let old_id = std::mem::replace(&mut instances[lock_index].id, id.clone());
        if old_id != id {
            replaced.insert(old_id, id);
        }
    }
    coverage.retain(|item| !dropped_coverage.contains(&item.scope));
    for item in coverage.iter_mut() {
        if let Some(id) = replaced.get(&item.scope) {
            item.scope = id.clone();
        }
    }
    let mut index = 0;
    instances.retain(|_| {
        let keep = !removed.contains(&index);
        index += 1;
        keep
    });
}

#[cfg(test)]
mod tests {
    use super::merge_verified;
    use crate::model::{EvidenceKind, Instance, Origin, PythonLock};
    use crate::profile::Component;
    use crate::store::Store;

    #[test]
    fn previous_identity_is_reused_only_when_unambiguous() {
        let project = uuid::Uuid::new_v4().to_string();
        let store = Store::open(&project).unwrap();
        let evidence = store
            .record_evidence(
                b"verified registry digest",
                "registry_hash_match",
                None,
                EvidenceKind::Identity,
            )
            .unwrap();
        let component = Component {
            reference: "pkg:pypi/example".into(),
            version: Some("1.0".into()),
            usage: Default::default(),
            upstream: None,
            feeds: Vec::new(),
        };
        let mut lock = Instance::declared(&component);
        lock.id = "current-lock".into();
        lock.origin = Origin::Locked;
        lock.purl = Some(component.reference.clone());
        lock.python_lock = Some(PythonLock {
            sha256: vec!["a".repeat(64)],
            source_eligible: true,
            via: Vec::new(),
            via_complete: false,
            direct_source: None,
        });
        lock.identity_evidence.push(evidence);
        let mut first = lock.clone();
        first.id = "previous-one".into();
        first.resolved_version = Some("1.0.0".into());
        let mut second = first.clone();
        second.id = "previous-two".into();
        let mut current = vec![lock.clone()];
        merge_verified(&mut current, &mut Vec::new(), &[first.clone()], &store);
        assert_eq!(current[0].id, "previous-one");
        let mut current = vec![lock];
        merge_verified(&mut current, &mut Vec::new(), &[first, second], &store);
        assert_eq!(current[0].id, Instance::declared(&component).id);
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }
}
