use std::fs;
use vulnbell::{
    model::{CoverageState, Origin},
    profile,
};

#[test]
fn requirements_remain_local_candidates_without_inferred_public_sources() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(
        workspace.join("requirements.txt"),
        "requests==2.31.0; sys_platform == 'win32'\nurllib3>=1,<3\n",
    )
    .unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: python\ncodebases: [workspace]\ndiscovery: off\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 2);
    let pinned = snapshot
        .instances
        .iter()
        .find(|item| item.reference == "python-requirement:requests")
        .unwrap();
    assert_eq!(pinned.origin, Origin::Declared);
    assert_eq!(pinned.resolved_version.as_deref(), Some("2.31.0"));
    assert_eq!(pinned.purl, None);
    assert_eq!(pinned.provenance.line, Some(1));
    assert!(snapshot.instances.iter().all(|item| item.purl.is_none()));
    assert!(snapshot.coverage.iter().any(|row| row.source == "osv"
        && row.scope == pinned.id
        && row.state == CoverageState::Unsupported));
    assert!(snapshot.cases.is_empty());
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn private_index_never_becomes_public_package_identity() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(
        workspace.join("requirements.txt"),
        "requests==2.31.0\n--index-url https://user:synthetic-secret@example.invalid/simple\n",
    )
    .unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: private-python\ncodebases: [workspace]\ndiscovery: off\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 1);
    assert_eq!(
        snapshot.instances[0].reference,
        "python-requirement:requests"
    );
    assert_eq!(snapshot.instances[0].purl, None);
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|row| row.source == "osv" && row.state == CoverageState::Unsupported)
    );
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("synthetic-secret")
    );
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn python_lock_formats_are_local_inventory_with_partial_coverage() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    for (name, content) in [
        ("requirements.lock", "first==1.0\n"),
        ("requirements-dev.txt", "second==2.0\n"),
        (
            "uv.lock",
            "version = 1\n[[package]]\nname = 'third'\nversion = '3.0'\n",
        ),
        (
            "poetry.lock",
            "[[package]]\nname = 'fourth'\nversion = '4.0'\n[metadata]\nlock-version = '2.1'\n",
        ),
        (
            "pdm.lock",
            "[metadata]\nlock_version = '4.5.1'\n[[package]]\nname = 'seventh'\nversion = '7.0'\n",
        ),
        (
            "pylock.test.toml",
            "lock-version = '1.0'\n[[packages]]\nname = 'fifth'\nversion = '5.0'\n",
        ),
        (
            "Pipfile.lock",
            r#"{"_meta":{"pipfile-spec":6},"default":{"sixth":{"version":"==6.0"}}}"#,
        ),
    ] {
        fs::write(workspace.join(name), content).unwrap();
    }
    fs::write(workspace.join("other.lock"), "unrecognized format").unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: locks\ncodebases: [workspace]\ndiscovery: off\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 7);
    assert!(
        snapshot
            .instances
            .iter()
            .all(|item| item.origin == Origin::Declared && item.purl.is_none())
    );
    for name in [
        "requirements.lock",
        "requirements-dev.txt",
        "uv.lock",
        "poetry.lock",
        "pdm.lock",
        "pylock.test.toml",
        "Pipfile.lock",
    ] {
        assert!(
            snapshot
                .coverage
                .iter()
                .any(|row| row.scope == name && row.state == CoverageState::Partial),
            "{name}"
        );
    }
    assert!(snapshot.cases.is_empty());
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|row| row.scope == "other.lock" && row.state == CoverageState::Unsupported)
    );
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
