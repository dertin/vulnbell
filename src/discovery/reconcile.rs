use crate::model::{Coverage, Instance};

pub(crate) fn preserve_observation_ids(
    instances: &mut [Instance],
    coverage: &mut [Coverage],
    previous: &[Instance],
    require_same_observation: bool,
) {
    use std::collections::{HashMap, HashSet};

    fn key(instance: &Instance) -> Option<(String, Option<String>, String, String)> {
        (instance.origin == crate::model::Origin::AgentObserved).then_some((
            instance.reference.clone(),
            instance.requested_version.clone(),
            instance.provenance.codebase.clone()?,
            instance.provenance.path.clone()?,
        ))
    }
    let mut old: HashMap<_, Vec<&Instance>> = HashMap::new();
    for instance in previous {
        if let Some(key) = key(instance) {
            old.entry(key).or_default().push(instance);
        }
    }
    let mut counts = HashMap::new();
    for instance in instances.iter() {
        if let Some(key) = key(instance) {
            *counts.entry(key).or_insert(0usize) += 1;
        }
    }
    let mut used: HashSet<String> = instances.iter().map(|item| item.id.clone()).collect();
    let mut replacements = HashMap::new();
    for instance in instances {
        let Some(k) = key(instance) else { continue };
        let Some([previous]) = old.get(&k).map(Vec::as_slice) else {
            continue;
        };
        let id = &previous.id;
        if require_same_observation
            && (previous.provenance.sha256 != instance.provenance.sha256
                || previous.provenance.direct != instance.provenance.direct)
        {
            continue;
        }
        if counts.get(&k) != Some(&1) || instance.id == *id || used.contains(id) {
            continue;
        }
        used.remove(&instance.id);
        used.insert(id.clone());
        replacements.insert(std::mem::replace(&mut instance.id, id.clone()), id.clone());
    }
    for item in coverage {
        if let Some(id) = replacements.get(&item.scope) {
            item.scope = id.clone();
        }
    }
}

#[cfg(test)]
mod observation_id_tests {
    use super::preserve_observation_ids;
    use crate::{
        model::{Coverage, CoverageState, Instance, Origin},
        profile::{Component, Usage},
    };

    fn observed(id: &str, path: &str) -> Instance {
        let mut instance = Instance::declared(&Component {
            reference: "pkg:pypi/example".into(),
            version: Some("1.0.0".into()),
            usage: Usage::Tracked,
            upstream: None,
            feeds: vec![],
        });
        instance.id = id.into();
        instance.origin = Origin::AgentObserved;
        instance.provenance.path = Some(path.into());
        instance.provenance.codebase = Some("/project".into());
        instance
    }

    #[test]
    fn refreshed_observation_preserves_cases_only_for_an_unambiguous_identity() {
        let old = observed("previous", "compose.yml");
        let mut current = vec![observed("new", "compose.yml")];
        let mut gaps = vec![Coverage::new(
            "identity",
            "new",
            CoverageState::Partial,
            "gap",
        )];
        preserve_observation_ids(&mut current, &mut gaps, std::slice::from_ref(&old), false);
        assert_eq!(current[0].id, "previous");
        assert_eq!(gaps[0].scope, "previous");

        let mut changed = vec![observed("new", "compose.yml")];
        changed[0].provenance.sha256 = "different".into();
        preserve_observation_ids(&mut changed, &mut [], std::slice::from_ref(&old), true);
        assert_eq!(changed[0].id, "new");
        let mut changed_relation = vec![observed("new", "compose.yml")];
        changed_relation[0].provenance.direct = Some(false);
        preserve_observation_ids(
            &mut changed_relation,
            &mut [],
            std::slice::from_ref(&old),
            true,
        );
        assert_eq!(changed_relation[0].id, "new");

        let mut ambiguous = vec![
            observed("one", "compose.yml"),
            observed("two", "compose.yml"),
        ];
        preserve_observation_ids(&mut ambiguous, &mut [], &[old], false);
        assert_eq!(ambiguous[0].id, "one");
        assert_eq!(ambiguous[1].id, "two");
    }
}
