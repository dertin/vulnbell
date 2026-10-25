use super::*;
#[test]
fn osv_and_ghsa_contracts_accept_aliases_and_withdrawals() {
    let batch: OsvBatch = serde_json::from_str(
        r#"{"results":[{"vulns":[{"id":"GHSA-test"}],"next_page_token":"next"}]}"#,
    )
    .unwrap();
    assert_eq!(batch.results[0].next_page_token.as_deref(), Some("next"));
    let advisory: OsvAdvisory = serde_json::from_str(
        r#"{"id":"RUSTSEC-2024-0336","aliases":["CVE-2024-32650"],"withdrawn":"2026-01-01"}"#,
    )
    .unwrap();
    assert!(advisory.withdrawn.is_some());
    let _: Ghsa = serde_json::from_str(
        r#"{"ghsa_id":"GHSA-test","cve_id":null,"summary":"synthetic","withdrawn_at":null}"#,
    )
    .unwrap();
}
#[test]
fn cpe_range_boundaries_do_not_use_lexical_order() {
    let candidate: CpeMatch = serde_json::from_value(serde_json::json!({"vulnerable":true,"criteria":"cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*","versionStartIncluding":"26.8.0","versionEndExcluding":"26.10.0"})).unwrap();
    assert_eq!(
        cpe_applies(&candidate, "cpe:2.3:a:redhat:keycloak", "26.9.0").unwrap(),
        Some(true)
    );
    assert_eq!(
        cpe_applies(&candidate, "cpe:2.3:a:redhat:keycloak", "26.10.0").unwrap(),
        Some(false)
    );
    assert_eq!(
        cpe_applies(&candidate, "cpe:2.3:a:php:php", "26.9.0").unwrap(),
        None
    );
    assert!(cpe_applies(&candidate, "cpe:2.3:a:redhat:keycloak", "26.9.0-vendor1").is_err());
}
#[test]
fn nvd_cve_and_kev_structural_contracts_reject_malformed_payloads() {
    let nvd: NvdResponse = serde_json::from_str(r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0001","vulnStatus":"Rejected","configurations":[]}}]}"#).unwrap();
    assert_eq!(nvd.vulnerabilities[0].cve.status, "Rejected");
    let cve: CveRecord =
        serde_json::from_str(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"REJECTED"}}"#)
            .unwrap();
    assert_eq!(cve.metadata.state, "REJECTED");
    let kev: Kev =
        serde_json::from_str(r#"{"vulnerabilities":[{"cveID":"CVE-2099-0001"}]}"#).unwrap();
    assert_eq!(kev.vulnerabilities[0].id, "CVE-2099-0001");
    assert!(serde_json::from_str::<NvdResponse>("{}").is_err());
}

#[test]
fn enrichment_keeps_kev_provenance_and_rejected_cve_conflicts() {
    let project = uuid::Uuid::new_v4().to_string();
    let store = crate::store::Store::open(&project).unwrap();
    let evidence = store
        .record_evidence(
            b"synthetic authoritative affected claim",
            "osv",
            None,
            EvidenceKind::Advisory,
        )
        .unwrap();
    let claim = Claim {
        id: "GHSA-synthetic".into(),
        source: "osv".into(),
        aliases: vec!["CVE-2099-0001".into()],
        instance_id: "instance".into(),
        summary: "SYNTHETIC fixture".into(),
        applicability: Applicability::Affected,
        evidence,
        known_exploited: false,
    };
    for (url, body) in [
        (
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            serde_json::json!({"vulnerabilities":[{"cveID":"CVE-2099-0001"}]}),
        ),
        (
            "https://cveawg.mitre.org/api/cve/CVE-2099-0001",
            serde_json::json!({"cveMetadata":{"cveId":"CVE-2099-0001","state":"REJECTED"}}),
        ),
    ] {
        let key = crate::digest(format!("GET:{url}:").as_bytes());
        store
            .connection
            .execute(
                "INSERT OR REPLACE INTO cache VALUES (?1,?2,NULL,?3)",
                rusqlite::params![
                    key,
                    serde_json::to_vec(&body).unwrap(),
                    chrono::Utc::now().timestamp()
                ],
            )
            .unwrap();
    }
    let mut intelligence = Intelligence {
        claims: vec![claim],
        coverage: Vec::new(),
    };
    enrich(&mut intelligence, &[], &mut Http::new(&store, true));
    assert!(
        intelligence
            .claims
            .iter()
            .any(|claim| claim.source == "cisa_kev"
                && claim.known_exploited
                && store.evidence_exists(&claim.evidence).unwrap())
    );
    assert!(intelligence.claims.iter().any(
        |claim| claim.source == "cve_records" && claim.applicability == Applicability::Conflict
    ));
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}
