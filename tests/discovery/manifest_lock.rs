use super::*;
use vulnbell::model::Origin;

#[test]
fn imported_declarations_link_to_locked_packages_without_duplicate_gaps() {
    let (directory, path, profile, mut store) = project();
    let workspace = directory.path().join("workspace");
    fs::write(
        workspace.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"1.0.0\"\n[dependencies]\nexample = \"1\"\n",
    )
    .unwrap();
    fs::write(workspace.join("Cargo.lock"), format!("version = 4\n[[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\"example\"]\n[[package]]\nname = \"example\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n", "a".repeat(64))).unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert_eq!(page.codebase_files.len(), 1);
    let observation = PackageObservation {
        component: serde_saphyr::from_str("ref: pkg:cargo/example\n").unwrap(),
        excerpt: "example = \"1\"".into(),
        version_excerpt: None,
        direct: Some(true),
        direct_rationale: Some("Dependency in Cargo manifest".into()),
    };
    discovery::import(
        &profile,
        &path,
        &mut store,
        review(&page, vec![observation]),
    )
    .unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 1, "{:#?}", snapshot.instances);
    let instance = &snapshot.instances[0];
    assert_eq!(instance.origin, Origin::Locked);
    assert_eq!(instance.resolved_version.as_deref(), Some("1.2.3"));
    assert!(
        !snapshot
            .coverage
            .iter()
            .any(|entry| entry.detail.contains("unresolved_version"))
    );
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(report.inventory[0].declarations.len(), 1);
    assert_eq!(
        report.inventory[0].declarations[0].source.path,
        "Cargo.toml"
    );
    assert_eq!(
        report.inventory[0].declarations[0].source.sha256,
        vulnbell::digest(&fs::read(workspace.join("Cargo.toml")).unwrap())
    );
    assert_eq!(
        report.inventory[0].declarations[0]
            .observation_evidence
            .len(),
        1
    );
    let mut prepared = report;
    vulnbell::output::prepare_report_paths(&mut prepared, &store).unwrap();
    let markdown = vulnbell::output::morning_markdown(&prepared).unwrap();
    assert!(markdown.contains("1.2.3"));
    assert!(markdown.contains("Cargo.toml:5"));
    assert!(markdown.contains("declaration linked to lockfile"));
    let next = discovery::summary(&profile, &path, &store).unwrap();
    assert_eq!(next.components_unmapped, 1);
    let rescanned = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(rescanned.instances.len(), 1);
    assert_eq!(rescanned.instances[0].id, instance.id);
    fs::write(
        workspace.join("Cargo.toml"),
        "[package]\nname = \"changed\"\n",
    )
    .unwrap();
    let historical = vulnbell::output::morning_report_current(&rescanned, &store, "cyber").unwrap();
    assert_eq!(historical.inventory[0].declarations.len(), 1);
    assert!(
        serde_json::to_string(&historical)
            .unwrap()
            .contains("example")
    );
    fs::remove_dir_all(&workspace).unwrap();
    assert!(vulnbell::output::morning_report_current(&rescanned, &store, "cyber").is_ok());
    cleanup(store, &profile);
}

#[test]
fn prior_case_survives_scope_change_and_lockfile_appearance() {
    use vulnbell::model::{Applicability, Case, Decision, SandboxAvailability, Verification};
    let (directory, path, mut profile, mut store) = project();
    let workspace = directory.path().join("workspace");
    fs::write(
        workspace.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"1.0.0\"\n[dependencies]\nexample = \"1\"\n",
    )
    .unwrap();
    let observation = || PackageObservation {
        component: serde_saphyr::from_str("ref: pkg:cargo/example\n").unwrap(),
        excerpt: "example = \"1\"".into(),
        version_excerpt: None,
        direct: Some(true),
        direct_rationale: Some("Dependency in Cargo manifest".into()),
    };
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    discovery::import(
        &profile,
        &path,
        &mut store,
        review(&page, vec![observation()]),
    )
    .unwrap();
    let previous = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let original = previous
        .instances
        .iter()
        .find(|item| item.origin == Origin::AgentObserved)
        .unwrap()
        .clone();
    let case = Case {
        schema_version: 1,
        case_id: "SIG-existing".into(),
        project_id: profile.project_id.to_string(),
        snapshot_id: previous.id.clone(),
        codebase_revisions: Vec::new(),
        instances: vec![original.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: original.identity_evidence.clone(),
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "fixture".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "fixture".into(),
        },
        updated_at: "2026-01-01T00:00:00Z".into(),
    };
    store.save_case(&case).unwrap();
    fs::create_dir(directory.path().join("other")).unwrap();
    profile.codebases.push("other".into());
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    discovery::plan(&profile, &path, &store, 20).unwrap();
    discovery::reopen(&profile, &path, &mut store, "Cargo.toml").unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    discovery::import(
        &profile,
        &path,
        &mut store,
        review(&page, vec![observation()]),
    )
    .unwrap();
    fs::write(workspace.join("Cargo.lock"), format!("version = 4\n[[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\"example\"]\n[[package]]\nname = \"example\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n", "a".repeat(64))).unwrap();
    let current = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(current.instances.iter().any(|item| item.id == original.id));
    assert_eq!(
        store.case("SIG-existing").unwrap().instances[0].id,
        original.id
    );
    let report = vulnbell::output::morning_report(&current, &store, "cyber").unwrap();
    assert!(
        report
            .inventory
            .iter()
            .flat_map(|item| &item.declarations)
            .any(|item| item.observation_id == original.id)
    );
    let mut prepared = report;
    vulnbell::output::prepare_report_paths(&mut prepared, &store).unwrap();
    let markdown = vulnbell::output::morning_markdown(&prepared).unwrap();
    assert_eq!(
        markdown
            .lines()
            .filter(|line| line.starts_with("| ") && line.contains("Cargo.toml:5"))
            .count(),
        1
    );
    assert!(markdown.contains("1 instances in total"));
    cleanup(store, &profile);
}
