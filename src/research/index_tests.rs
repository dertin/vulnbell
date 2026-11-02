use super::{event_hash, index_instances, select_instances, tracker_context};
use crate::{model::Instance, profile::Component};

#[test]
fn selection_and_hashes_follow_snapshot_order() {
    let instance = |name: &str, version: &str| {
        Instance::declared(&Component {
            reference: name.into(),
            version: Some(version.into()),
            usage: Default::default(),
            upstream: None,
            feeds: vec![],
        })
    };
    let first = instance("a", "1.0.0");
    let mut duplicate = first.clone();
    duplicate.resolved_version = Some("2.0.0".into());
    let second = instance("b", "1.0.0");
    let instances = vec![first.clone(), second.clone(), duplicate];
    let ids = vec![
        second.id.clone(),
        first.id.clone(),
        first.id.clone(),
        "absent".into(),
    ];
    let old_selection: Vec<_> = instances
        .iter()
        .filter(|item| ids.contains(&item.id))
        .collect();
    let index = index_instances(&instances);
    let selection = select_instances(&ids, &index);
    assert_eq!(selection.len(), old_selection.len());
    for (actual, expected) in selection.iter().zip(&old_selection) {
        assert_eq!(actual.context_fingerprint(), expected.context_fingerprint());
    }

    let old_event_facts: Vec<_> = old_selection
        .iter()
        .map(|item| (&item.id, item.context_fingerprint()))
        .collect();
    let expected_event =
        crate::digest(&serde_json::to_vec(&(b"observation".as_slice(), old_event_facts)).unwrap());
    assert_eq!(
        event_hash(b"observation", &ids, &index).unwrap(),
        expected_event
    );

    let mut old_tracker_facts: Vec<_> = old_selection
        .iter()
        .map(|item| {
            (
                &item.id,
                item.context_fingerprint(),
                None::<(&String, &String)>,
            )
        })
        .collect();
    old_tracker_facts.sort_by(|a, b| a.0.cmp(b.0));
    let expected_tracker = crate::digest(&serde_json::to_vec(&old_tracker_facts).unwrap());
    assert_eq!(
        tracker_context(&ids, &index, false).unwrap(),
        expected_tracker
    );
}
