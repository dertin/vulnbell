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
