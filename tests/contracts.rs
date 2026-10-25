use std::{fs, path::Path};
use vulnbell::{
    inventory::parse_lock,
    profile::{self, Profile},
    scheduler::ScheduleConfig,
};

#[test]
fn generated_profile_schema_matches_committed_contract() {
    let committed: serde_json::Value =
        serde_json::from_slice(&fs::read("schemas/profile.schema.json").unwrap()).unwrap();
    assert_eq!(profile::schema(), committed);
}
#[test]
fn examples_and_empty_scaffold_validate_offline() {
    for path in [
        "examples/manual-project.yaml",
        "examples/mixed-project.yaml",
    ] {
        assert!(profile::validate(&profile::load(Path::new(path)).unwrap()).valid);
    }
    let profile: Profile = serde_saphyr::from_str(
        "schema: 1\nproject_id: 11111111-1111-4111-8111-111111111111\nname: empty",
    )
    .unwrap();
    let validation = profile::validate(&profile);
    assert!(validation.valid);
    assert_eq!(validation.warnings[0].code, "empty_scope");

    let manual = profile::load(Path::new("examples/manual-project.yaml")).unwrap();
    for path in ["examples/schedule.json", "examples/schedule-opencode.json"] {
        let config: ScheduleConfig = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        #[cfg(windows)]
        let config = {
            // These systemd examples intentionally use Unix absolute paths.
            let mut config = config;
            config.agent_executable = std::env::current_exe().unwrap();
            config.report_dir = std::env::temp_dir().join("vulnbell-example-reports");
            config
        };
        config.validate(&manual).unwrap();
    }
}
#[test]
fn profiles_reject_unknown_duplicate_and_versioned_purl_fields() {
    let raw = "schema: 1\nproject_id: 11111111-1111-4111-8111-111111111111\nname: test\n";
    assert!(serde_saphyr::from_str::<Profile>(&format!("{raw}typo: true")).is_err());
    assert!(
        serde_saphyr::from_str::<Profile>(&format!(
            "{raw}components:\n  - ref: php\n    version: '8.0'\n    version: '8.1'"
        ))
        .is_err()
    );
    let profile: Profile = serde_saphyr::from_str(&format!(
        "{raw}components:\n  - ref: pkg:cargo/serde@1.0.0\n    version: '1.0.1'"
    ))
    .unwrap();
    assert_eq!(
        profile::validate(&profile).errors[0].pointer,
        "/components/0/ref"
    );
}
#[test]
fn lockfile_corpus_preserves_distinct_versions_and_namespaces() {
    let expected = [
        ("rust/Cargo.lock", 1),
        ("js/package-lock.json", 3),
        ("php/composer.lock", 2),
        ("pnpm/pnpm-lock.yaml", 2),
        ("yarn/yarn.lock", 1),
        ("sbom/bom.json", 2),
        ("sbom/test.spdx.json", 1),
    ];
    for (relative, count) in expected {
        let path = Path::new("tests/fixtures/workspace").join(relative);
        let packages = parse_lock(
            path.file_name().unwrap().to_str().unwrap(),
            &fs::read(&path).unwrap(),
        )
        .unwrap();
        assert_eq!(packages.len(), count, "{relative}");
    }
    let packages = parse_lock(
        "package-lock.json",
        include_bytes!("fixtures/workspace/js/package-lock.json"),
    )
    .unwrap();
    assert_eq!(packages[0].name, "@example/lib");
    let versions: Vec<&str> = packages
        .iter()
        .filter(|package| package.name == "lodash")
        .map(|package| package.version.as_str())
        .collect();
    assert!(versions.contains(&"4.17.20") && versions.contains(&"4.17.21"));
}
#[test]
fn unsupported_and_malformed_locks_never_report_empty_success() {
    for (name, bytes) in [
        ("package-lock.json", b"{\"lockfileVersion\":99}".as_slice()),
        ("yarn.lock", b"__metadata:\n  version: 8".as_slice()),
        ("Cargo.lock", b"[package broken".as_slice()),
    ] {
        assert!(parse_lock(name, bytes).is_err(), "{name}");
    }
}
#[test]
fn ssrf_and_semver_boundaries_are_explicit() {
    for ip in [
        "127.0.0.1",
        "10.1.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
    ] {
        assert!(!vulnbell::network::is_public(ip.parse().unwrap()));
    }
    assert!(
        vulnbell::identity::normalized_version("26.10.0").unwrap()
            > vulnbell::identity::normalized_version("26.9.0").unwrap()
    );
    assert!(vulnbell::profile::public_https_syntax("http://example.org").is_err());
    assert!(vulnbell::profile::public_https_syntax("https://user:secret@example.org").is_err());
}
#[test]
fn skills_are_idempotent_and_user_edits_are_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("vulnbell");
    vulnbell::skills::install_skill(&destination).unwrap();
    vulnbell::skills::install_skill(&destination).unwrap();
    let path = destination.join("SKILL.md");
    let skill = fs::read_to_string(&path).unwrap();
    let frontmatter = skill
        .strip_prefix("---\n")
        .unwrap()
        .split_once("\n---\n")
        .unwrap()
        .0;
    let metadata: serde_json::Value = vulnbell::parse_yaml(frontmatter.as_bytes()).unwrap();
    assert_eq!(metadata["name"], "vulnbell");
    assert_eq!(metadata["metadata"]["version"], env!("CARGO_PKG_VERSION"));
    fs::write(&path, "user modification").unwrap();
    assert!(vulnbell::skills::install_skill(&destination).is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "user modification");
}
#[test]
#[cfg(unix)]
fn process_limits_terminate_timeouts_and_keep_output_bounded() {
    let mut command = std::process::Command::new("/bin/sh");
    command.env_clear().args([
        "-c",
        "while :; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done",
    ]);
    let result = vulnbell::process::run_bounded(&mut command, 1, 1024).unwrap();
    assert!(result.timed_out);
    assert!(result.stdout.len() <= 1024);
}

#[test]
fn npm_nested_versions_do_not_inherit_the_root_directness() {
    let lock=br#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.20","alias":"npm:lodash@4.17.21"}},"node_modules/lodash":{"version":"4.17.20"},"node_modules/alias":{"name":"lodash","version":"4.17.21"},"node_modules/parent/node_modules/lodash":{"version":"4.17.19"}}}"#;
    let packages = parse_lock("package-lock.json", lock).unwrap();
    assert_eq!(
        packages
            .iter()
            .find(|package| package.version == "4.17.20")
            .unwrap()
            .direct,
        Some(true)
    );
    assert_eq!(
        packages
            .iter()
            .find(|package| package.version == "4.17.21")
            .unwrap()
            .direct,
        Some(true)
    );
    assert_eq!(
        packages
            .iter()
            .find(|package| package.version == "4.17.19")
            .unwrap()
            .direct,
        Some(false)
    );
}

#[test]
fn private_cargo_registry_never_inherits_public_identity() {
    let lock = br#"version = 4
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://registry.example.org/private-index"
"#;
    let error = parse_lock("Cargo.lock", lock).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no verified crates.io equivalence")
    );
}

#[test]
fn yaml_rejects_duplicate_keys_unknown_tags_and_excessive_nesting() {
    assert!(vulnbell::parse_yaml::<serde_json::Value>(b"name: a\nname: b").is_err());
    assert!(vulnbell::parse_yaml::<serde_json::Value>(b"name: !include /etc/passwd").is_err());
    let nested = format!("{}0{}", "[".repeat(300), "]".repeat(300));
    assert!(vulnbell::parse_yaml::<serde_json::Value>(nested.as_bytes()).is_err());
}

#[test]
fn all_published_json_schemas_match_their_rust_contracts() {
    let generated = [
        (
            "verdict",
            serde_json::to_value(schemars::schema_for!(vulnbell::model::Verdict)).unwrap(),
        ),
        (
            "case",
            serde_json::to_value(schemars::schema_for!(vulnbell::model::Case)).unwrap(),
        ),
        (
            "test",
            serde_json::to_value(schemars::schema_for!(vulnbell::sandbox::TestSpec)).unwrap(),
        ),
        (
            "attestation",
            serde_json::to_value(schemars::schema_for!(vulnbell::sandbox::Attestation)).unwrap(),
        ),
        (
            "impact",
            serde_json::to_value(schemars::schema_for!(vulnbell::impact::ImpactSubmission))
                .unwrap(),
        ),
        (
            "research",
            serde_json::to_value(schemars::schema_for!(vulnbell::research::ResearchBatch)).unwrap(),
        ),
        (
            "schedule",
            serde_json::to_value(schemars::schema_for!(vulnbell::scheduler::ScheduleConfig))
                .unwrap(),
        ),
        (
            "report",
            serde_json::to_value(schemars::schema_for!(vulnbell::output::MorningReport)).unwrap(),
        ),
        (
            "snapshot",
            serde_json::to_value(schemars::schema_for!(vulnbell::model::Snapshot)).unwrap(),
        ),
        (
            "status",
            serde_json::to_value(schemars::schema_for!(vulnbell::operations::StatusReport))
                .unwrap(),
        ),
    ];
    for (name, schema) in generated {
        let committed: serde_json::Value =
            serde_json::from_slice(&fs::read(format!("schemas/{name}.schema.json")).unwrap())
                .unwrap();
        assert_eq!(schema, committed, "regenerate schema {name} from the CLI");
    }
}
