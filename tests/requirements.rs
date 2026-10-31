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
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: python\nworkspaces: [workspace]\ndiscovery: off\n")).unwrap();
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
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: private-python\nworkspaces: [workspace]\ndiscovery: off\n")).unwrap();
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
