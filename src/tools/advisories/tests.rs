use super::*;
use crate::{
    model::Instance,
    profile::Language,
    tools::{
        Item, ItemKind,
        hits::{Disposition, RuleContext, disposition},
        raw::{TargetItems, provider_for},
        screen,
    },
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

fn instance(purl: Option<&str>) -> Instance {
    let profile: crate::profile::Profile = serde_saphyr::from_str(
        "schema: 1\nproject_id: 0de0a8e7-f1a4-4bdc-a198-422b90bbbd84\nname: tests\ncomponents:\n  - ref: example\n    version: '1.0.0'\n",
    )
    .unwrap();
    let mut instance = Instance::declared(&profile.components[0]);
    instance.purl = purl.map(str::to_owned);
    instance
}

fn resolution(record: &Value, instance: &Instance) -> Resolution {
    let mut resolution = Resolution::default();
    osv_record(record, std::slice::from_ref(instance), &mut resolution);
    resolution.published = !resolution.packages.is_empty();
    resolution
}

fn relay_requires_review(resolution: Resolution) -> bool {
    let issue = Item {
        key: "example/project#1".into(),
        kind: ItemKind::PullRequest,
        url: "https://github.com/example/project/pull/1".into(),
        title: "build(deps): bump example".into(),
        state: "open".into(),
        labels: vec![],
        updated_at: "2026-10-20T10:00:00+00:00".into(),
        body: "CVE-2026-12345".into(),
        closes: vec![],
        advisory: None,
    };
    let selected = HashSet::new();
    let collected = TargetItems {
        provider: provider_for("https://github.com/example/project"),
        method: String::new(),
        missing: vec![],
        errors: vec![],
        items: vec![],
        linked_issues: vec![],
        published_identifiers: BTreeSet::new(),
    };
    let resolutions = BTreeMap::from([("CVE-2026-12345".into(), resolution)]);
    let context = RuleContext {
        collected: &collected,
        selected_keys: &selected,
        resolutions: &resolutions,
        target_instances: &[],
        language: Language::En,
    };
    let signal = screen::screen(&issue, "").unwrap();
    matches!(
        disposition(&issue, &signal, &context),
        Disposition::Review { .. }
    )
}

#[test]
fn unknown_identity_and_qualifiers_keep_relays_open() {
    let base = serde_json::json!({"affected":[{
        "package":{"ecosystem":"crates.io", "name":"example", "purl":"pkg:cargo/example?target=windows"},
        "ranges":[{"type":"SEMVER", "events":[{"introduced":"0"},{"fixed":"0.5.0"}]}]
    }]});
    for instance in [
        instance(None),
        instance(Some("pkg:cargo/example?target=linux")),
    ] {
        let result = resolution(&base, &instance);
        assert_eq!(result.in_build[0].status, BuildStatus::Unknown);
        assert!(relay_requires_review(result));
    }
    let unknown_source = serde_json::json!({"affected":[{
        "package":{"ecosystem":"unsupported", "name":"example"}
    }]});
    let result = resolution(&unknown_source, &instance(Some("pkg:cargo/example")));
    assert_eq!(result.in_build[0].status, BuildStatus::Unknown);
    assert!(relay_requires_review(result));
    let different_case = serde_json::json!({"affected":[{
        "package":{"purl":"pkg:maven/org.Example/example", "name":"org.Example:example", "ecosystem":"Maven"}
    }]});
    let result = resolution(
        &different_case,
        &instance(Some("pkg:maven/org.example/example")),
    );
    assert_eq!(result.in_build[0].status, BuildStatus::Unknown);
    assert!(relay_requires_review(result));
}

#[test]
fn aggregate_osv_ranges_keep_conflicting_evidence_open() {
    let record = serde_json::json!({"affected":[
        {"package":{"ecosystem":"crates.io", "name":"example"},
         "ranges":[{"type":"SEMVER", "events":[{"introduced":"0"},{"fixed":"0.5.0"}]}]},
        {"package":{"ecosystem":"crates.io", "name":"example"}, "versions":["1.0.0"],
         "ranges":[{"type":"SEMVER", "events":[{"introduced":"0"},{"fixed":"0.5.0"}]}]}
    ]});
    let result = resolution(&record, &instance(Some("pkg:cargo/example")));
    assert_eq!(result.in_build[0].status, BuildStatus::Unknown);
    assert!(relay_requires_review(result));
}

fn github_resolution(records: Value, instance: &Instance) -> Resolution {
    let project = uuid::Uuid::new_v4().to_string();
    let store = crate::store::Store::open(&project).unwrap();
    let url = "https://api.github.com/advisories?cve_id=CVE-2026-12345";
    let key = crate::digest(format!("GET:{url}:").as_bytes());
    store
        .connection
        .execute(
            "INSERT INTO cache VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                key,
                serde_json::to_vec(&records).unwrap(),
                chrono::Utc::now().timestamp()
            ],
        )
        .unwrap();
    let mut resolution = Resolution::default();
    github(
        "CVE-2026-12345",
        std::slice::from_ref(instance),
        &mut Http::new(&store, true),
        &mut resolution,
    );
    resolution.published = !resolution.packages.is_empty();
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    resolution
}

#[test]
fn github_resolution_keeps_normalized_pypi_and_ambiguous_maven_open() {
    let advisory = |ecosystem: &str, name: &str| {
        serde_json::json!([{
            "summary":"fixture", "withdrawn_at":null,
            "vulnerabilities":[{"package":{"ecosystem":ecosystem,"name":name}, "vulnerable_version_range":">= 1.0.0, < 2.0.0"}]
        }])
    };
    let result = github_resolution(
        advisory("pip", "foo__bar"),
        &instance(Some("pkg:pypi/foo-bar")),
    );
    assert_eq!(result.in_build[0].status, BuildStatus::Affected);
    assert!(relay_requires_review(result));
    let result = github_resolution(
        advisory("maven", "org.Example:example"),
        &instance(Some("pkg:maven/org.example/example")),
    );
    assert_eq!(result.in_build[0].status, BuildStatus::Unknown);
    assert!(relay_requires_review(result));
}

#[test]
fn repository_advisory_disposition_uses_normalized_or_uncertain_identity() {
    let cases = [
        ("pip", "foo__bar", "pkg:pypi/foo-bar"),
        (
            "maven",
            "org.Example:example",
            "pkg:maven/org.example/example",
        ),
    ];
    for (ecosystem, name, purl) in cases {
        let monitored = instance(Some(purl));
        let issue = Item {
            key: "GHSA-1234-1234-1234".into(),
            kind: ItemKind::Advisory,
            url: "https://github.com/example/project/security/advisories/GHSA-1234-1234-1234"
                .into(),
            title: "security advisory".into(),
            state: "published".into(),
            labels: vec![],
            updated_at: "2026-10-20T10:00:00+00:00".into(),
            body: String::new(),
            closes: vec![],
            advisory: Some(crate::tools::RepositoryAdvisory {
                ghsa_id: "GHSA-1234-1234-1234".into(),
                cve_id: None,
                packages: vec![crate::tools::AdvisoryPackage {
                    ecosystem: ecosystem.into(),
                    name: name.into(),
                    vulnerable_range: ">= 1.0.0, < 2.0.0".into(),
                    patched: String::new(),
                }],
            }),
        };
        let selected = HashSet::new();
        let collected = TargetItems {
            provider: provider_for("https://github.com/example/project"),
            method: String::new(),
            missing: vec![],
            errors: vec![],
            items: vec![],
            linked_issues: vec![],
            published_identifiers: BTreeSet::new(),
        };
        let resolutions = BTreeMap::new();
        let targets = [&monitored];
        let context = RuleContext {
            collected: &collected,
            selected_keys: &selected,
            resolutions: &resolutions,
            target_instances: &targets,
            language: Language::En,
        };
        let signal = screen::screen(&issue, "").unwrap();
        assert!(matches!(
            disposition(&issue, &signal, &context),
            Disposition::Review { .. }
        ));
    }
}

#[test]
fn malformed_github_record_prevents_relay_dismissal() {
    let records = serde_json::json!([
        {"summary":"fixture", "withdrawn_at":null, "vulnerabilities":[{"package":{"ecosystem":"rust", "name":"another"}, "vulnerable_version_range":"< 2.0.0"}]},
        {"unexpected":"record"}
    ]);
    let result = github_resolution(records, &instance(Some("pkg:cargo/example")));
    assert!(result.published);
    assert!(result.in_build.is_empty());
    assert!(!result.errors.is_empty());
    assert!(relay_requires_review(result));
}

#[test]
fn distinct_packages_can_still_be_dismissed_as_relays() {
    let record = serde_json::json!({"affected":[{
        "package":{"ecosystem":"crates.io", "name":"another"},
        "ranges":[{"type":"SEMVER", "events":[{"introduced":"0"},{"fixed":"0.5.0"}]}]
    }]});
    let result = resolution(&record, &instance(Some("pkg:cargo/example")));
    assert!(result.in_build.is_empty());
    assert!(!relay_requires_review(result));
}
