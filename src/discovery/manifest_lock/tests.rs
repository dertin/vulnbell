use super::*;
use crate::{
    model::{Applicability, Case, Decision, SandboxAvailability, Verification},
    profile::{Component as Package, Usage},
};
use std::fs;

fn observed(store: &Store, root: &str, path: &str, reference: &str, line: usize) -> Instance {
    let component = Package {
        reference: reference.to_owned(),
        version: None,
        usage: Usage::Tracked,
        upstream: None,
        feeds: Vec::new(),
    };
    let observation = crate::discovery::PackageObservation {
        component: component.clone(),
        excerpt: "synthetic declaration".into(),
        version_excerpt: None,
        direct: Some(true),
        direct_rationale: Some("synthetic fixture".into()),
    };
    let mut instance = Instance::declared(&component);
    instance.id = format!("observed-{path}-{reference}");
    instance.origin = Origin::AgentObserved;
    instance.provenance.codebase = Some(root.to_owned());
    instance.provenance.path = Some(path.to_owned());
    instance.provenance.line = Some(line);
    instance.provenance.sha256 = crate::digest(path.as_bytes());
    instance.identity_evidence.push(
        store
            .record_evidence(
                &serde_json::to_vec(&observation).unwrap(),
                "agent_codebase_observation",
                None,
                EvidenceKind::Context,
            )
            .unwrap(),
    );
    instance
}

fn fixture() -> (tempfile::TempDir, Store, String, Vec<Instance>) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("workspace");
    fs::create_dir_all(root.join("crates/app")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n[workspace.dependencies]\nbase64 = \"0.23\"\n",
    )
    .unwrap();
    fs::write(
        root.join("crates/app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"1.0.0\"\n[dependencies]\nbase64.workspace = true\n",
    )
    .unwrap();
    let lock = format!(
        "version = 4\n[[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\"base64 0.23.1\"]\n[[package]]\nname = \"base64\"\nversion = \"0.22.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n[[package]]\nname = \"base64\"\nversion = \"0.23.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
        "a".repeat(64),
        "b".repeat(64)
    );
    fs::write(root.join("Cargo.lock"), lock).unwrap();
    let profile_path = directory.path().join("vulnbell.yaml");
    fs::write(&profile_path, "fixture").unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let store = Store::open(&project).unwrap();
    let root = root.canonicalize().unwrap().to_string_lossy().into_owned();
    let mut instances =
        crate::inventory::discover(std::slice::from_ref(&root), &profile_path, &store, 100)
            .instances;
    instances.push(observed(&store, &root, "Cargo.toml", "pkg:cargo/base64", 4));
    instances.push(observed(
        &store,
        &root,
        "crates/app/Cargo.toml",
        "pkg:cargo/base64",
        5,
    ));
    (directory, store, root, instances)
}

#[test]
fn cargo_workspace_links_declarations_to_matching_direct_version() {
    let (_directory, store, _root, mut instances) = fixture();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &store.cases().unwrap(),
    )
    .unwrap();
    assert_eq!(instances.len(), 2);
    let direct = instances
        .iter()
        .find(|entry| entry.resolved_version.as_deref() == Some("0.23.1"))
        .unwrap();
    let sources = declaration_sources(&instances, &store)
        .unwrap()
        .remove(&direct.id)
        .unwrap();
    assert_eq!(sources.len(), 2);
    assert!(
        sources
            .iter()
            .any(|source| source.source.path == "Cargo.toml" && source.source.line == 4)
    );
    assert!(
        sources
            .iter()
            .any(|source| source.source.path == "crates/app/Cargo.toml" && source.source.line == 5)
    );
    let other = instances
        .iter()
        .find(|entry| entry.resolved_version.as_deref() == Some("0.22.1"))
        .unwrap();
    assert!(
        !declaration_sources(&instances, &store)
            .unwrap()
            .contains_key(&other.id)
    );
    assert_eq!(covered_observations(&instances, &store).unwrap().len(), 2);
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn incompatible_sources_and_unmatched_workspace_members_remain_unresolved() {
    let (directory, store, root, mut instances) = fixture();
    fs::write(
        directory.path().join("workspace/crates/app/Cargo.toml"),
        "[package]\nname = \"other\"\nversion = \"1.0.0\"\n[dependencies]\nbase64.workspace = true\n",
    )
    .unwrap();
    instances.push(observed(
        &store,
        &root,
        "crates/app/Cargo.toml",
        "pkg:cargo/base64",
        5,
    ));
    let mut private = observed(&store, &root, "Cargo.toml", "pkg:cargo/base64", 4);
    private.id = "other-root".into();
    private.provenance.codebase = Some("/different-codebase".into());
    instances.push(private);
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &store.cases().unwrap(),
    )
    .unwrap();
    assert!(instances.iter().any(|entry| entry.id == "other-root"));
    assert_eq!(
        instances
            .iter()
            .filter(|entry| entry.origin == Origin::AgentObserved)
            .count(),
        4
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn existing_cases_keep_their_original_observation() {
    let (_directory, mut store, _root, mut instances) = fixture();
    let observed = instances
        .iter()
        .find(|entry| entry.provenance.path.as_deref() == Some("Cargo.toml"))
        .unwrap()
        .clone();
    let case = Case {
        schema_version: 1,
        case_id: "SIG-fixture".into(),
        project_id: "fixture".into(),
        snapshot_id: "fixture".into(),
        codebase_revisions: Vec::new(),
        instances: vec![observed.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: Vec::new(),
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
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &store.cases().unwrap(),
    )
    .unwrap();
    assert!(instances.iter().any(|instance| instance.id == observed.id));
    assert_eq!(
        store.case("SIG-fixture").unwrap().instances[0].id,
        observed.id
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

fn npm_fixture(registry: &str) -> (tempfile::TempDir, Store, Vec<Instance>) {
    use base64::Engine;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("workspace");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("package.json"),
        "{\n  \"name\": \"app\",\n  \"dependencies\": { \"example\": \"^1.2.0\" }\n}\n",
    )
    .unwrap();
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode([0u8; 64])
    );
    let lock = serde_json::json!({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"example": "^1.2.0"}},
            "node_modules/example": {"version": "1.2.3", "resolved": format!("https://{registry}/example/-/example-1.2.3.tgz"), "integrity": integrity}
        }
    });
    fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec(&lock).unwrap(),
    )
    .unwrap();
    let profile = directory.path().join("vulnbell.yaml");
    fs::write(&profile, "fixture").unwrap();
    let store = Store::open(&uuid::Uuid::new_v4().to_string()).unwrap();
    let root = root.canonicalize().unwrap().to_string_lossy().into_owned();
    let mut instances =
        crate::inventory::discover(std::slice::from_ref(&root), &profile, &store, 100).instances;
    let item = observed(&store, &root, "package.json", "pkg:npm/example", 3);
    instances.push(item);
    (directory, store, instances)
}

#[test]
fn npm_public_registry_declaration_links_to_its_lockfile_entry() {
    let (_directory, store, mut instances) = npm_fixture("registry.npmjs.org");
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &store.cases().unwrap(),
    )
    .unwrap();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        declaration_sources(&instances, &store).unwrap()[&instances[0].id][0]
            .source
            .path,
        "package.json"
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn npm_private_registry_is_not_linked_by_package_name() {
    let (_directory, store, mut instances) = npm_fixture("private.example.invalid");
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &store.cases().unwrap(),
    )
    .unwrap();
    assert_eq!(instances.len(), 2);
    assert!(
        instances
            .iter()
            .any(|instance| instance.origin == Origin::AgentObserved)
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn matching_multiple_direct_versions_keeps_the_declaration_unresolved() {
    let (directory, store, _root, mut instances) = fixture();
    fs::write(
        directory.path().join("workspace/Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n[workspace.dependencies]\nbase64 = \"*\"\n",
    )
    .unwrap();
    let lock_path = directory.path().join("workspace/Cargo.lock");
    let lock = fs::read_to_string(&lock_path).unwrap().replace(
        "dependencies = [\"base64 0.23.1\"]",
        "dependencies = [\"base64 0.22.1\", \"base64 0.23.1\"]",
    );
    fs::write(&lock_path, &lock).unwrap();
    for instance in &mut instances {
        if instance.origin == Origin::Locked {
            instance.provenance.direct = Some(true);
            instance.provenance.sha256 = crate::digest(lock.as_bytes());
        }
    }
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &store.cases().unwrap(),
    )
    .unwrap();
    assert_eq!(
        instances
            .iter()
            .filter(|instance| instance.origin == Origin::AgentObserved)
            .count(),
        2
    );
    assert!(
        instances
            .iter()
            .any(|instance| instance.origin == Origin::AgentObserved
                && instance.provenance.path.as_deref() == Some("Cargo.toml"))
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn changed_lockfile_is_not_associated_with_a_stale_inventory() {
    let (directory, store, _root, mut instances) = fixture();
    fs::write(
        directory.path().join("workspace/Cargo.lock"),
        "version = 4\n",
    )
    .unwrap();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &store.cases().unwrap(),
    )
    .unwrap();
    assert_eq!(
        instances
            .iter()
            .filter(|instance| instance.origin == Origin::AgentObserved)
            .count(),
        2
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn changed_workspace_member_invalidates_recorded_relations() {
    let (directory, store, _root, mut instances) = fixture();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    assert!(declaration_sources(&instances, &store).is_ok());
    fs::write(
        directory.path().join("workspace/crates/app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"1.0.0\"\n[dependencies]\nbase64 = \"0.23\"\n",
    )
    .unwrap();
    assert!(declaration_sources(&instances, &store).is_ok());
    assert!(covered_observations(&instances, &store).unwrap().is_empty());
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn missing_original_observation_evidence_invalidates_relation() {
    let (_directory, store, _root, mut instances) = fixture();
    let original = instances
        .iter()
        .find(|item| item.origin == Origin::AgentObserved)
        .unwrap()
        .identity_evidence[0]
        .clone();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    fs::remove_file(store.directory.join("evidence").join(original.sha256)).unwrap();
    assert!(declaration_sources(&instances, &store).is_err());
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn file_cache_bounds_repeated_manifest_reads() {
    let (_directory, store, root, _instances) = fixture();
    let mut files = Files::default();
    for _ in 0..1000 {
        assert_eq!(
            declaration_section(&mut files, &root, "Cargo.toml", 4, "base64"),
            Some(true)
        );
    }
    let size = fs::metadata(Path::new(&root).join("Cargo.toml"))
        .unwrap()
        .len() as usize;
    assert_eq!(files.total, size);
    assert_eq!(files.cargo_lines.len(), 1);
    files.total = TOTAL_LIMIT;
    assert!(files.bytes(&root, "Cargo.lock").is_none());
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn mapped_observation_is_preserved() {
    let (_directory, store, _root, mut instances) = fixture();
    let observed = instances
        .iter()
        .find(|item| item.origin == Origin::AgentObserved)
        .unwrap()
        .id
        .clone();
    store.connection.execute(
        "INSERT INTO discovery_sources (scope, instance_id, fingerprint, checked_at, body) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params!["fixture", observed, "fingerprint", "2026-01-01", "{}"],
    ).unwrap();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    assert!(instances.iter().any(|item| item.id == observed));
    let declarations = declaration_sources(&instances, &store).unwrap();
    assert!(
        declarations
            .values()
            .flatten()
            .any(|item| item.observation_id == observed)
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn cargo_multiline_strings_cannot_be_mistaken_for_declarations() {
    let (directory, store, root, mut instances) = fixture();
    fs::write(
        directory.path().join("workspace/Cargo.toml"),
        "[package]\nname = \"root\"\ndescription = \"\"\"\n[workspace.dependencies]\nbase64 = \"0.23\"\n\"\"\"\n[workspace]\nmembers = [\"crates/*\"]\n[workspace.dependencies]\nbase64 = \"0.23\"\n",
    ).unwrap();
    instances
        .iter_mut()
        .find(|item| {
            item.origin == Origin::AgentObserved
                && item.provenance.path.as_deref() == Some("Cargo.toml")
        })
        .unwrap()
        .provenance
        .line = Some(5);
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    assert!(
        instances
            .iter()
            .any(|item| item.origin == Origin::AgentObserved
                && item.provenance.codebase.as_deref() == Some(root.as_str())
                && item.provenance.path.as_deref() == Some("Cargo.toml"))
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn cargo_section_headers_with_comments_do_not_inherit_prior_section() {
    let (directory, store, root, _instances) = fixture();
    fs::write(directory.path().join("workspace/Cargo.toml"),
        "[workspace.dependencies]\nbase64 = \"0.23\"\n[package.metadata] # description\nbase64 = \"0.23\"\n").unwrap();
    let mut files = Files::default();
    assert_eq!(
        declaration_section(&mut files, &root, "Cargo.toml", 2, "base64"),
        Some(true)
    );
    assert_eq!(
        declaration_section(&mut files, &root, "Cargo.toml", 4, "base64"),
        None
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn stale_workspace_member_version_is_not_linked() {
    let (directory, store, _root, mut instances) = fixture();
    let path = directory.path().join("workspace/crates/app/Cargo.toml");
    let source = fs::read_to_string(&path).unwrap().replace("1.0.0", "2.0.0");
    fs::write(path, source).unwrap();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(
        instances
            .iter()
            .filter(|item| item.origin == Origin::AgentObserved)
            .count(),
        2
    );
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn inherited_workspace_package_version_must_match_lockfile() {
    let (directory, store, _root, mut instances) = fixture();
    let workspace = directory.path().join("workspace");
    let root = workspace.join("Cargo.toml");
    let content = fs::read_to_string(&root).unwrap();
    fs::write(
        &root,
        format!("{content}\n[workspace.package]\nversion = \"1.0.0\"\n"),
    )
    .unwrap();
    let member = workspace.join("crates/app/Cargo.toml");
    let content = fs::read_to_string(&member)
        .unwrap()
        .replace("version = \"1.0.0\"", "version.workspace = true");
    fs::write(member, content).unwrap();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(instances.len(), 2);
    assert_eq!(covered_observations(&instances, &store).unwrap().len(), 2);
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn workspace_proof_is_stable_when_observation_order_changes() {
    let (directory, store, root, mut instances) = fixture();
    let other = directory.path().join("workspace/crates/other");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("Cargo.toml"), "[package]\nname = \"other\"\nversion = \"1.0.0\"\n[dependencies]\nbase64.workspace = true\n").unwrap();
    let lock_path = directory.path().join("workspace/Cargo.lock");
    let mut lock = fs::read_to_string(&lock_path).unwrap();
    lock.push_str(
        "[[package]]\nname = \"other\"\nversion = \"1.0.0\"\ndependencies = [\"base64 0.23.1\"]\n",
    );
    fs::write(lock_path, &lock).unwrap();
    for item in &mut instances {
        if item.origin == Origin::Locked {
            item.provenance.sha256 = crate::digest(lock.as_bytes());
        }
    }
    instances.push(observed(
        &store,
        &root,
        "crates/other/Cargo.toml",
        "pkg:cargo/base64",
        5,
    ));
    let mut reversed = instances.clone();
    reversed.reverse();
    merge(
        &mut instances,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    merge(
        &mut reversed,
        &store,
        Path::new("/fixture/profile.yaml"),
        &[],
        &[],
    )
    .unwrap();
    let root_hash = |items: &[Instance]| {
        declaration_sources(items, &store)
            .unwrap()
            .into_values()
            .flatten()
            .find(|item| item.source.path == "Cargo.toml")
            .unwrap()
            .relation_evidence
            .sha256
    };
    assert_eq!(root_hash(&instances), root_hash(&reversed));
    let project = store.directory.clone();
    drop(store);
    fs::remove_dir_all(project).unwrap();
}
