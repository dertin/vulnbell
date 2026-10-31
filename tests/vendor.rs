use vulnbell::{
    model::{Applicability, Evidence, EvidenceKind, Instance},
    profile::Component,
};
fn target() -> Instance {
    let component = Component {
        reference: "pkg:npm/lodash".into(),
        version: Some("4.17.21".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    };
    let mut instance = Instance::declared(&component);
    instance.purl = Some(component.reference);
    instance
}
fn evidence() -> Evidence {
    Evidence {
        id: "EV-synthetic".into(),
        sha256: "synthetic".into(),
        source: "configured_vendor".into(),
        url: Some("https://example.org/advisory.json".into()),
        observed_at: vulnbell::now(),
        kind: EvidenceKind::Advisory,
    }
}
#[test]
fn openvex_requires_exact_version_and_positive_not_affected_justification() {
    let instance = target();
    let payload = serde_json::json!({"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2099-0001"},"products":[{"@id":"pkg:npm/lodash@4.17.21"}],"status":"not_affected","justification":"vulnerable_code_not_present"}]});
    let claims = vulnbell::vendor::parse_openvex(
        &serde_json::to_vec(&payload).unwrap(),
        &[&instance],
        &evidence(),
    )
    .unwrap();
    assert_eq!(claims[0].applicability, Applicability::NotAffected);
    assert_eq!(claims[0].evidence.kind, EvidenceKind::NonApplicability);
    let mut no_justification = payload.clone();
    no_justification["statements"][0]
        .as_object_mut()
        .unwrap()
        .remove("justification");
    assert!(
        vulnbell::vendor::parse_openvex(
            &serde_json::to_vec(&no_justification).unwrap(),
            &[&instance],
            &evidence()
        )
        .is_err()
    );
    let mut wrong_version = payload;
    wrong_version["statements"][0]["products"][0]["@id"] = "pkg:npm/lodash@4.17.20".into();
    assert!(
        vulnbell::vendor::parse_openvex(
            &serde_json::to_vec(&wrong_version).unwrap(),
            &[&instance],
            &evidence()
        )
        .unwrap()
        .is_empty()
    );
}
#[test]
fn csaf_matches_product_identifiers_without_guessing_names() {
    let instance = target();
    let payload = serde_json::json!({"document":{"csaf_version":"2.0"},"product_tree":{"full_product_names":[{"product_id":"product-1","name":"not used as identity","product_identification_helper":{"purl":"pkg:npm/lodash@4.17.21"}}]},"vulnerabilities":[{"cve":"CVE-2099-0001","product_status":{"known_affected":["product-1"]}}]});
    let claims = vulnbell::vendor::parse_csaf(
        &serde_json::to_vec(&payload).unwrap(),
        &[&instance],
        &evidence(),
    )
    .unwrap();
    assert_eq!(claims[0].applicability, Applicability::Affected);
}

#[test]
fn vendor_feeds_do_not_match_unverified_legacy_composer_identity() {
    let project = uuid::Uuid::new_v4().to_string();
    let profile: vulnbell::profile::Profile = serde_saphyr::from_str(&format!(
        "schema: 1\nproject_id: {project}\nname: vendor-scope\ncomponents:\n  - ref: pkg:composer/vendor/package\n    version: '1.2.3'\n    feeds:\n      - kind: vex\n        url: https://example.org/vex.json\n"
    ))
    .unwrap();
    let mut public = Instance::declared(&profile.components[0]);
    public.purl = Some(public.reference.clone());
    let mut legacy = public.clone();
    legacy.id = "legacy-lock-entry".into();
    legacy.origin = vulnbell::model::Origin::Locked;
    legacy.provenance.path = Some("composer.lock".into());
    let store = vulnbell::store::Store::open(&project).unwrap();
    let payload = serde_json::json!({"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2099-0001"},"products":[{"@id":"pkg:composer/vendor/package@1.2.3"}],"status":"not_affected","justification":"vulnerable_code_not_present"}]});
    let key = vulnbell::digest(b"GET:https://example.org/vex.json:");
    store
        .connection
        .execute(
            "INSERT INTO cache VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                key,
                serde_json::to_vec(&payload).unwrap(),
                chrono::Utc::now().timestamp()
            ],
        )
        .unwrap();
    let mut http = vulnbell::network::Http::new(&store, true);
    let result = vulnbell::vendor::feeds(&profile, &[public.clone(), legacy], &mut http);
    assert_eq!(result.claims.len(), 1);
    assert_eq!(result.claims[0].instance_id, public.id);
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
