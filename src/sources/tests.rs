use super::*;

#[test]
fn prior_advisory_refreshes_deferred_repository_without_expanding_tracker_scope() {
    use crate::model::{Decision, SandboxAvailability, Verification};
    let project = uuid::Uuid::new_v4().to_string();
    let store = crate::store::Store::open(&project).unwrap();
    let profile: crate::profile::Profile = serde_saphyr::from_str(&format!(
        "schema: 1\nproject_id: {project}\nname: fixture\ncomponents:\n  - ref: pkg:cargo/example\n    version: '1.0.0'\n    upstream: https://github.com/example/example\n")).unwrap();
    let mut instance = Instance::declared(&profile.components[0]);
    instance.provenance.direct = Some(false);
    instance.purl = Some("pkg:cargo/example".into());
    let evidence = store
        .record_evidence(b"synthetic", "fixture", None, EvidenceKind::Advisory)
        .unwrap();
    let claim = Claim {
        id: "GHSA-test".into(),
        source: "github_repository".into(),
        aliases: vec![],
        instance_id: instance.id.clone(),
        summary: "synthetic".into(),
        applicability: Applicability::Affected,
        evidence,
        known_exploited: false,
    };
    let case = Case {
        schema_version: 1,
        case_id: "fixture".into(),
        project_id: project.clone(),
        snapshot_id: "fixture".into(),
        instances: vec![instance.clone()],
        claims: vec![claim],
        upstream_events: vec![],
        evidence: vec![],
        coverage: vec![],
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "fixture".into(),
        open_questions: vec![],
        suggested_search_queries: vec![],
        sandbox: SandboxAvailability {
            available: false,
            reason: "fixture".into(),
        },
        updated_at: "now".into(),
    };
    let mut http = crate::network::Http::new(&store, true);
    let mut absent = Intelligence::default();
    repository_advisories(
        &[instance.clone()],
        &mut http,
        &mut absent,
        &profile.research,
        &[],
    );
    assert!(absent.coverage.is_empty());
    let mut prior = Intelligence::default();
    repository_advisories(
        &[instance.clone()],
        &mut http,
        &mut prior,
        &profile.research,
        &[case],
    );
    assert_eq!(prior.coverage.len(), 1);
    assert_eq!(prior.coverage[0].scope, instance.id);
    assert!(!profile.research.tracks(&instance));
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}
#[test]
fn case_advisory_promotion_requires_official_published_matching_source_and_exact_package() {
    use crate::model::{Decision, SandboxAvailability, SourceFacts, UpstreamEvent, Verification};
    let profile: crate::profile::Profile = serde_saphyr::from_str("schema: 1\nproject_id: 0de0a8e7-f1a4-4bdc-a198-422b90bbbd84\nname: fixture\ncomponents:\n  - ref: postgres\n    version: '42.7.13'\n    upstream: https://github.com/pgjdbc/pgjdbc\n").unwrap();
    let mut instance = Instance::declared(&profile.components[0]);
    instance.purl = Some("pkg:maven/org.postgresql/postgresql".into());
    let evidence = Evidence {
        id: "fixture".into(),
        sha256: "hash".into(),
        source: "agent_web".into(),
        url: None,
        observed_at: "now".into(),
        kind: EvidenceKind::Context,
    };
    let mut case = Case {
        schema_version: 1,
        case_id: "fixture".into(),
        project_id: "fixture".into(),
        snapshot_id: "fixture".into(),
        instances: vec![instance],
        claims: vec![],
        upstream_events: vec![UpstreamEvent {
            provider: "github".into(),
            kind: "advisory".into(),
            id: "GHSA-abcd-1234-wxyz".into(),
            url: "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-abcd-1234-wxyz".into(),
            title: "fixture".into(),
            updated_at: None,
            sha256: "hash".into(),
            source_facts: SourceFacts::default(),
        }],
        evidence: vec![],
        coverage: vec![],
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "hash".into(),
        open_questions: vec![],
        suggested_search_queries: vec![],
        sandbox: SandboxAvailability {
            available: false,
            reason: "fixture".into(),
        },
        updated_at: "now".into(),
    };
    let url = "https://api.github.com/repos/pgjdbc/pgjdbc/security-advisories/GHSA-abcd-1234-wxyz";
    let document = serde_json::json!({"state":"published","ghsa_id":"GHSA-abcd-1234-wxyz","cve_id":null,"summary":"fixture","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"maven","name":"org.postgresql:postgresql"},"vulnerable_version_range":">= 42.7.11, <= 42.7.13","patched_versions":"42.7.14"}]}).to_string();
    assert_eq!(
        case_repository_advisory(&case, url, document.as_bytes(), &evidence)
            .unwrap()
            .1
            .len(),
        1
    );
    assert!(
        case_repository_advisory(
            &case,
            "https://example.com/repos/pgjdbc/pgjdbc/security-advisories/GHSA-abcd-1234-wxyz",
            document.as_bytes(),
            &evidence
        )
        .is_none()
    );
    assert!(
        case_repository_advisory(
            &case,
            url,
            document.replace("published", "draft").as_bytes(),
            &evidence
        )
        .is_none()
    );
    case.instances[0].resolved_version = Some("42.7.14".into());
    assert!(
        case_repository_advisory(&case, url, document.as_bytes(), &evidence)
            .unwrap()
            .1
            .is_empty()
    );
    assert!(
        case_repository_advisory(
            &case,
            url,
            document.replace("published", "withdrawn").as_bytes(),
            &evidence
        )
        .unwrap()
        .1
        .is_empty()
    );
    case.instances[0].resolved_version = Some("42.7.13".into());
    case.upstream_events.clear();
    assert!(case_repository_advisory(&case, url, document.as_bytes(), &evidence).is_none());
}
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
fn repository_advisory_ranges_are_evaluated_only_without_guessing() {
    let version = |value: &str| semver::Version::parse(value).unwrap();
    let check = |range: &str, patched: Option<&str>, value: &str| {
        github_range_match(range, patched, &version(value))
    };
    use RangeMatch::{Affected, FixedOnLine, Outside};
    assert_eq!(
        check(">= 3.0.0, < 3.6.0", Some("3.6.0"), "3.4.0"),
        Some(Affected)
    );
    assert_eq!(check(">= 3.0.0, < 3.6.0", None, "3.6.0"), Some(Outside));
    assert_eq!(check("<= 3.6.0", None, "3.6.0"), Some(Affected));
    assert_eq!(check("= 1.54.0", None, "1.54.1"), Some(Outside));
    assert_eq!(check("0.23.44,0.23.45", None, "0.23.45"), Some(Affected));
    assert_eq!(check("0.23.44,0.23.45", None, "0.23.46"), Some(Outside));
    assert_eq!(check("< 0.5.16, >= 0.6.0 < 0.6.3", None, "0.5.16"), None);
    assert_eq!(check("", None, "1.0.0"), None);
    assert_eq!(check(">= 2.0.0", None, "2.3.0"), Some(Affected));
    assert_eq!(
        check(">=0.10.50", Some("0.10.80"), "0.10.81"),
        Some(FixedOnLine)
    );
    assert_eq!(
        check(">=0.10.50", Some("0.10.80"), "0.10.79"),
        Some(Affected)
    );
    assert_eq!(
        check("> 0.7.0", Some(">= 0.11.18"), "0.11.19"),
        Some(FixedOnLine)
    );
    assert_eq!(
        check(">= 0.101.0", Some("0.104.0-alpha.5, 0.103.10"), "0.103.15"),
        Some(FixedOnLine)
    );
    assert_eq!(
        check(">= 0.101.0", Some("0.104.0-alpha.5, 0.103.10"), "0.102.8"),
        None
    );
    assert_eq!(
        check(
            ">0.35.11",
            Some("~0.35.15, ~0.36.16, ~0.37.25, ~0.38.19"),
            "1.1.5"
        ),
        Some(FixedOnLine)
    );
    assert_eq!(check("<= 0.9.1", Some("0.10.0"), "0.9.1"), Some(Affected));
    assert_eq!(check(">= 2.0.0", Some("<= 2.3.0"), "2.3.0"), None);
    assert_eq!(
        check("< 0.23.46, > 0.24.0-dev.1", Some(">= 0.23.46"), "0.23.45"),
        None
    );
    assert_eq!(
        check(">= 2.21.0, <= 2.22.0", Some("2.21.5"), "2.21.7"),
        None
    );
    assert_eq!(check("< 26.37.1", Some("26.7.1"), "26.8.1"), None);
    assert_eq!(
        check(">= 2.19.0, <= 2.21.7", Some("2.21.8"), "2.21.7"),
        Some(Affected)
    );
    assert_eq!(
        check(">= 3.5.0, < 3.5.11", Some("3.5.11"), "3.5.10"),
        Some(Affected)
    );
    assert_eq!(
        check(">= 2.0.0, < 2.5.0", Some("1.9.0"), "2.3.0"),
        Some(Affected)
    );
    assert_eq!(
        github_repository("https://github.com/modelcontextprotocol/rust-sdk.git"),
        Some("modelcontextprotocol/rust-sdk".into())
    );
    assert_eq!(github_repository("https://gitlab.com/group/project"), None);
    assert!(same_package(
        "maven",
        "org.keycloak:keycloak-services",
        "org.keycloak/keycloak-services"
    ));
    assert!(same_package("pip", "Zope.Interface", "zope_interface"));
    assert!(!same_package("rust", "rmcp-macros", "rmcp"));
    let advisory: RepositoryAdvisory = serde_json::from_str(
        r#"{"ghsa_id":"GHSA-test","cve_id":null,"summary":"synthetic","withdrawn_at":null,
            "vulnerabilities":[{"package":{"ecosystem":"rust","name":"rmcp"},"vulnerable_version_range":">= 3.0.0, < 3.6.0","patched_versions":"3.6.0"},
                               {"package":null,"vulnerable_version_range":null}]}"#,
    )
    .unwrap();
    assert_eq!(advisory.vulnerabilities.len(), 2);
}
#[test]
fn open_ghsa_ranges_use_the_last_known_affected_bound() {
    let purl = "pkg:maven/org.keycloak/keycloak-quarkus-server";
    let advisory = serde_json::json!({"affected":[
        {"package":{"purl":purl},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],
         "versions":["24.0.1","26.8.1"],
         "database_specific":{"last_known_affected_version_range":"< 24.0.9"}},
        {"package":{"purl":purl},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"25.0.0"},{"fixed":"26.0.6"}]}]},
        {"package":{"purl":"pkg:maven/org.keycloak/other"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}
    ]});
    assert!(osv_ranges_exclude(
        &advisory,
        &format!("{purl}@26.8.1"),
        "26.8.1"
    ));
    assert!(!osv_ranges_exclude(&advisory, purl, "24.0.1"));
    assert!(!osv_ranges_exclude(&advisory, purl, "26.0.5"));
    let unbounded = serde_json::json!({"affected":[
        {"package":{"purl":purl},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}
    ]});
    assert!(!osv_ranges_exclude(&unbounded, purl, "26.8.1"));
    let git = serde_json::json!({"affected":[
        {"package":{"purl":purl},"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc"}]}]}
    ]});
    assert!(!osv_ranges_exclude(&git, purl, "26.8.1"));
    let unrelated = serde_json::json!({"affected":[
        {"package":{"purl":"pkg:maven/org.keycloak/other"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}
    ]});
    assert!(!osv_ranges_exclude(&unrelated, purl, "26.8.1"));
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
