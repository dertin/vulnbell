use std::{fs, path::Path};
use vulnbell::{
    inventory::parse_lock,
    profile::{self, Profile},
    runners::RunnerConfig,
    scheduler::ScheduleConfig,
};

#[test]
fn persisted_hashes_keep_the_sha256_wire_format() {
    assert_eq!(
        vulnbell::digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn cargo_lock_records_direct_dependencies_without_guessing_ambiguous_names() {
    let lock = br#"version = 4
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["direct 1.0.0", "ambiguous"]
[[package]]
name = "direct"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["deep"]
[[package]]
name = "deep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "ambiguous"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "ambiguous"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    let packages = parse_lock("Cargo.lock", lock).unwrap();
    assert_eq!(
        packages
            .iter()
            .find(|item| item.name == "direct")
            .unwrap()
            .direct,
        Some(true)
    );
    assert_eq!(
        packages
            .iter()
            .find(|item| item.name == "deep")
            .unwrap()
            .direct,
        Some(false)
    );
    assert!(
        packages
            .iter()
            .filter(|item| item.name == "ambiguous")
            .all(|item| item.direct.is_none())
    );
}

#[test]
fn cargo_lock_with_unresolved_root_reference_does_not_guess_transitive_depth() {
    let lock = br#"version = 4
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["missing", "direct"]
[[package]]
name = "direct"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "unknown"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    let packages = parse_lock("Cargo.lock", lock).unwrap();
    assert_eq!(
        packages
            .iter()
            .find(|item| item.name == "direct")
            .unwrap()
            .direct,
        Some(true)
    );
    assert_eq!(
        packages
            .iter()
            .find(|item| item.name == "unknown")
            .unwrap()
            .direct,
        None
    );
}

#[test]
fn pnpm_importers_identify_exact_direct_versions_and_keep_ambiguous_aliases_unknown() {
    let lock = br#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      foo:
        specifier: ^1
        version: 1.2.3
    devDependencies:
      bar:
        specifier: ^2
        version: 2.0.0(peer@1.0.0)
packages:
  foo@1.2.3: {}
  bar@2.0.0: {}
  deep@1.0.0: {}
"#;
    let packages = parse_lock("pnpm-lock.yaml", lock).unwrap();
    assert_eq!(
        packages.iter().find(|p| p.name == "foo").unwrap().direct,
        Some(true)
    );
    assert_eq!(
        packages.iter().find(|p| p.name == "bar").unwrap().direct,
        Some(true)
    );
    assert_eq!(
        packages.iter().find(|p| p.name == "deep").unwrap().direct,
        Some(false)
    );
    let incomplete = br#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias: {specifier: 'npm:other@1', version: 'npm:other@1.0.0'}
packages:
  other@1.0.0: {}
"#;
    assert_eq!(
        parse_lock("pnpm-lock.yaml", incomplete).unwrap()[0].direct,
        None
    );
}

#[test]
fn npm_missing_root_does_not_make_packages_transitive() {
    let lock = br#"{"lockfileVersion":3,"packages":{"node_modules/foo":{"version":"1.0.0"}}}"#;
    assert_eq!(
        parse_lock("package-lock.json", lock).unwrap()[0].direct,
        None
    );
}

#[test]
fn sqlite_unsigned_values_reject_negative_reads_and_overflowing_writes() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE offsets (value INTEGER NOT NULL)")
        .unwrap();
    let maximum = 9_223_372_036_854_775_807_u64;
    connection
        .execute("INSERT INTO offsets VALUES (?1)", [maximum])
        .unwrap();
    let stored: u64 = connection
        .query_row("SELECT value FROM offsets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, maximum);
    assert!(
        connection
            .execute("INSERT INTO offsets VALUES (?1)", [u64::MAX])
            .is_err()
    );
    assert!(
        connection
            .query_row::<u64, _, _>("SELECT -1", [], |row| row.get(0))
            .is_err()
    );
    let count: usize = connection
        .query_row("SELECT COUNT(*) FROM offsets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn generated_profile_schema_matches_committed_contract() {
    let committed: serde_json::Value =
        serde_json::from_slice(&fs::read("schemas/profile.schema.json").unwrap()).unwrap();
    assert_eq!(profile::schema(), committed);
}

#[test]
fn review_budget_is_optional_and_rejects_out_of_range_values() {
    let base = "schema: 1\nproject_id: 11111111-1111-4111-8111-111111111111\nname: budget\n";
    for (value, valid) in [
        ("1", true),
        ("60", true),
        ("120", true),
        ("0", false),
        ("121", false),
    ] {
        let profile: Profile = serde_saphyr::from_str(&format!(
            "{base}research:\n  review_budget_minutes: {value}\n"
        ))
        .unwrap();
        assert_eq!(profile::validate(&profile).valid, valid, "budget {value}");
    }
    let profile: Profile = serde_saphyr::from_str(base).unwrap();
    assert!(profile.research.review_budget_minutes.is_none());
    assert!(profile::validate(&profile).valid);
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
    let schedule: ScheduleConfig =
        serde_json::from_slice(&fs::read("examples/schedule.json").unwrap()).unwrap();
    #[cfg(windows)]
    let schedule = {
        let mut schedule = schedule;
        schedule.report_dir = std::env::temp_dir().join("vulnbell-example-reports");
        schedule
    };
    schedule.validate(&manual).unwrap();

    for path in [
        "examples/runner-codex.json",
        "examples/runner-opencode.json",
    ] {
        let config: RunnerConfig = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        #[cfg(windows)]
        let config = {
            let mut config = config;
            match &mut config.adapter {
                vulnbell::runners::AdapterConfig::Codex { executable, .. }
                | vulnbell::runners::AdapterConfig::OpenCode { executable, .. } => {
                    *executable = std::env::current_exe().unwrap();
                }
            }
            config
        };
        config.validate().unwrap();
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
fn sandbox_limits_default_to_the_fixed_policy_and_stay_under_their_caps() {
    let raw = "schema: 1\nproject_id: 11111111-1111-4111-8111-111111111111\nname: test\n";
    let plain: Profile = serde_saphyr::from_str(raw).unwrap();
    assert_eq!(plain.sandbox, profile::SandboxLimits::default());
    assert!(
        !serde_json::to_string(&plain)
            .unwrap()
            .contains("\"sandbox\"")
    );
    let raised: Profile = serde_saphyr::from_str(&format!(
        "{raw}sandbox:\n  max_input_file_mib: 256\n  max_inputs_mib: 512\n  max_memory_mib: 2048\n  max_timeout_seconds: 300\n"
    ))
    .unwrap();
    assert!(profile::validate(&raised).valid);
    assert_eq!(raised.sandbox.max_memory_mib, 2048);
    let partial: Profile =
        serde_saphyr::from_str(&format!("{raw}sandbox:\n  max_memory_mib: 1024\n")).unwrap();
    assert_eq!(partial.sandbox.max_timeout_seconds, 120);
    let excessive: Profile = serde_saphyr::from_str(&format!(
        "{raw}sandbox:\n  max_input_file_mib: 600\n  max_inputs_mib: 2048\n  max_memory_mib: 8192\n  max_timeout_seconds: 3600\n"
    ))
    .unwrap();
    let pointers: Vec<String> = profile::validate(&excessive)
        .errors
        .into_iter()
        .map(|error| error.pointer)
        .collect();
    assert_eq!(
        pointers,
        [
            "/sandbox/max_input_file_mib",
            "/sandbox/max_inputs_mib",
            "/sandbox/max_memory_mib",
            "/sandbox/max_timeout_seconds"
        ]
    );
    let inverted: Profile = serde_saphyr::from_str(&format!(
        "{raw}sandbox:\n  max_input_file_mib: 128\n  max_inputs_mib: 64\n"
    ))
    .unwrap();
    assert_eq!(
        profile::validate(&inverted).errors[0].pointer,
        "/sandbox/max_inputs_mib"
    );
    assert!(
        serde_saphyr::from_str::<Profile>(&format!("{raw}sandbox:\n  network: true\n")).is_err()
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
            "discovery",
            serde_json::to_value(schemars::schema_for!(vulnbell::discovery::DiscoveryBatch))
                .unwrap(),
        ),
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
            "runner",
            serde_json::to_value(schemars::schema_for!(vulnbell::runners::RunnerConfig)).unwrap(),
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
        (
            "decisions",
            serde_json::to_value(schemars::schema_for!(
                vulnbell::tools::draft::ResearchDecisions
            ))
            .unwrap(),
        ),
        (
            "impact-batch",
            serde_json::to_value(schemars::schema_for!(vulnbell::tools::cases::ImpactBatch))
                .unwrap(),
        ),
        (
            "verdict-batch",
            serde_json::to_value(schemars::schema_for!(vulnbell::tools::cases::VerdictBatch))
                .unwrap(),
        ),
        (
            "scope-batch",
            serde_json::to_value(schemars::schema_for!(vulnbell::tools::cases::ScopeBatch))
                .unwrap(),
        ),
        (
            "handoff-batch",
            serde_json::to_value(schemars::schema_for!(vulnbell::tools::cases::HandoffBatch))
                .unwrap(),
        ),
        (
            "items",
            serde_json::to_value(schemars::schema_for!(Vec<vulnbell::tools::Item>)).unwrap(),
        ),
    ];
    for (name, schema) in generated {
        let committed: serde_json::Value =
            serde_json::from_slice(&fs::read(format!("schemas/{name}.schema.json")).unwrap())
                .unwrap();
        assert_eq!(schema, committed, "regenerate schema {name} from the CLI");
    }
}
