use serde_json::json;
use std::fs;
use vulnbell::{
    model::{Applicability, Decision, EvidenceReference, Verdict, Verification},
    profile,
    store::Store,
};

fn cache_raw(store: &Store, method: &str, url: &str, body: Option<serde_json::Value>, raw: &[u8]) {
    let key = vulnbell::digest(
        format!(
            "{method}:{url}:{}",
            body.map(|value| value.to_string()).unwrap_or_default()
        )
        .as_bytes(),
    );
    store
        .connection
        .execute(
            "INSERT OR REPLACE INTO cache VALUES (?1,?2,NULL,?3)",
            rusqlite::params![key, raw, chrono::Utc::now().timestamp()],
        )
        .unwrap();
}

fn cache(
    store: &Store,
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
    response: serde_json::Value,
) {
    cache_raw(
        store,
        method,
        url,
        body,
        &serde_json::to_vec(&response).unwrap(),
    );
}

#[test]
fn mapping_upstream_enriches_identity_but_replacing_it_is_a_context_change() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(
        &path,
        format!(
            "schema: 1\nproject_id: {}\nname: identity-fixture\ncomponents:\n  - ref: pkg:cargo/rustls\n    version: '0.23.46'\n",
            uuid::Uuid::new_v4()
        ),
    )
    .unwrap();
    let profile = profile::load(&path).unwrap();
    let unmapped = vulnbell::model::Instance::declared(&profile.components[0]);
    let mut mapped = unmapped.clone();
    mapped.upstream = Some("https://github.com/rustls/rustls".into());
    assert_eq!(unmapped.context_fingerprint(), mapped.context_fingerprint());
    assert!(!unmapped.identity_replaced(&mapped));
    let mut moved = mapped.clone();
    moved.upstream = Some("https://github.com/example/rustls-fork".into());
    assert!(mapped.identity_replaced(&moved));
    assert!(mapped.identity_replaced(&unmapped));
    let mut direct = unmapped.clone();
    direct.provenance.direct = Some(true);
    assert_eq!(unmapped.context_fingerprint(), direct.context_fingerprint());
    direct.provenance.direct = Some(false);
    assert_eq!(unmapped.context_fingerprint(), direct.context_fingerprint());
}

const ADVISORY: &str = "https://api.osv.dev/v1/vulns/GHSA-synthetic-order";
const KEV: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[test]
fn reordered_feed_keys_and_daily_context_keep_the_recorded_verdict() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(
        &path,
        format!(
            "schema: 1\nproject_id: {project}\nname: stability-fixture\ncomponents:\n  - ref: pkg:npm/lodash\n    version: '4.17.20'\n"
        ),
    )
    .unwrap();
    let profile = profile::load(&path).unwrap();
    let mut store = Store::open(&project.to_string()).unwrap();
    cache(
        &store,
        "GET",
        "https://registry.npmjs.org/lodash/4.17.20",
        None,
        json!({"name":"lodash","version":"4.17.20"}),
    );
    cache(
        &store,
        "POST",
        "https://api.osv.dev/v1/querybatch",
        Some(json!({"queries":[{"package":{"purl":"pkg:npm/lodash"},"version":"4.17.20"}]})),
        json!({"results":[{"vulns":[{"id":"GHSA-synthetic-order"}]}]}),
    );
    cache_raw(
        &store,
        "GET",
        ADVISORY,
        None,
        br#"{"id":"GHSA-synthetic-order","summary":"SYNTHETIC fixture","affected":[{"ecosystem_specific":{"affects":{"os":[],"functions":[],"arch":[]}}}]}"#,
    );
    cache(
        &store,
        "GET",
        "https://api.github.com/advisories?ecosystem=npm&affects=lodash%404.17.20&per_page=100&page=1",
        None,
        json!([]),
    );
    cache(
        &store,
        "GET",
        KEV,
        None,
        json!({"catalogVersion":"2026.10.25","vulnerabilities":[]}),
    );

    let first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let case = first
        .cases
        .first()
        .expect("synthetic advisory creates a case")
        .clone();
    let advisory = case
        .evidence
        .iter()
        .find(|evidence| evidence.source == "osv")
        .unwrap();
    let verdict = Verdict {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Informational,
        rationale: "Synthetic: affected API is not used.".into(),
        evidence: vec![EvidenceReference {
            id: advisory.id.clone(),
            sha256: advisory.sha256.clone(),
        }],
    };
    vulnbell::engine::triage(&mut store, &case.case_id, verdict).unwrap();

    cache_raw(
        &store,
        "GET",
        ADVISORY,
        None,
        br#"{"summary":"SYNTHETIC fixture","id":"GHSA-synthetic-order","affected":[{"ecosystem_specific":{"affects":{"functions":[],"arch":[],"os":[]}}}]}"#,
    );
    cache(
        &store,
        "GET",
        KEV,
        None,
        json!({"catalogVersion":"2026.10.26","vulnerabilities":[]}),
    );
    let second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let kept = second
        .cases
        .iter()
        .find(|item| item.case_id == case.case_id)
        .unwrap();
    assert_eq!(kept.facts_sha256, case.facts_sha256);
    assert_eq!(kept.decision, Decision::Informational);

    cache_raw(
        &store,
        "GET",
        ADVISORY,
        None,
        br#"{"id":"GHSA-synthetic-order","summary":"SYNTHETIC fixture, affected range corrected","affected":[]}"#,
    );
    let third = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let reopened = third
        .cases
        .iter()
        .find(|item| item.case_id == case.case_id)
        .unwrap();
    assert_ne!(reopened.facts_sha256, case.facts_sha256);
    assert!(
        reopened
            .open_questions
            .iter()
            .any(|question| question.contains("after the recorded Informational verdict"))
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project.to_string())).unwrap();
}
