use std::fs;
use vulnbell::{
    model::{Applicability, CoverageState, Decision, Origin},
    profile,
    store::Store,
};

#[test]
fn requirements_are_declared_candidates_with_partial_coverage_and_safe_advisory_triage() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("requirements.txt"), "requests==2.31.0; sys_platform == 'win32'\nurllib3>=1,<3\nprivate @ https://user:synthetic-secret@example.invalid/pkg.whl\n").unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: python\nworkspaces: [workspace]\ndiscovery: off\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let store = Store::open(&project).unwrap();
    let query = serde_json::json!({"queries":[{"package":{"purl":"pkg:pypi/requests"},"version":"2.31.0"}]});
    let advisory = serde_json::json!({"id":"PYSEC-2026-1","summary":"Synthetic","affected":[{"package":{"ecosystem":"PyPI","name":"requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]}]});
    for (method, url, body, value) in [
        (
            "POST",
            "https://api.osv.dev/v1/querybatch",
            query.to_string(),
            serde_json::json!({"results":[{"vulns":[{"id":"PYSEC-2026-1"}]}]}),
        ),
        (
            "GET",
            "https://api.osv.dev/v1/vulns/PYSEC-2026-1",
            String::new(),
            advisory,
        ),
    ] {
        let key = vulnbell::digest(format!("{method}:{url}:{body}").as_bytes());
        store
            .connection
            .execute(
                "INSERT INTO cache VALUES (?1,?2,NULL,?3)",
                rusqlite::params![
                    key,
                    serde_json::to_vec(&value).unwrap(),
                    chrono::Utc::now().timestamp()
                ],
            )
            .unwrap();
    }
    drop(store);
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 2);
    let pinned = snapshot
        .instances
        .iter()
        .find(|item| item.reference == "pkg:pypi/requests")
        .unwrap();
    assert_eq!(pinned.origin, Origin::Declared);
    assert_eq!(pinned.resolved_version.as_deref(), Some("2.31.0"));
    assert_eq!(pinned.provenance.direct, None);
    assert_eq!(pinned.provenance.line, Some(1));
    assert!(snapshot.coverage.iter().any(|row| row.source == "identity"
        && row.scope == pinned.id
        && row.state == CoverageState::Partial));
    let unpinned = snapshot
        .instances
        .iter()
        .find(|item| item.reference == "pkg:pypi/urllib3")
        .unwrap();
    assert_eq!(unpinned.resolved_version, None);
    assert!(snapshot.coverage.iter().any(|row| row.source == "inventory"
        && row.state == CoverageState::Partial
        && row.detail.contains("unsupported entries")));
    assert_eq!(snapshot.cases.len(), 1);
    assert_eq!(snapshot.cases[0].applicability, Applicability::Unknown);
    assert_eq!(snapshot.cases[0].decision, Decision::Review);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("synthetic-secret")
    );
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
