use serde_json::json;
use std::fs;
use vulnbell::store::Store;
#[test]
fn fifteen_hundred_locked_packages_use_batches_and_no_upstream_clones() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("workspace")).unwrap();
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({"name":"synthetic-volume-fixture"}));
    let mut queries = Vec::new();
    for index in 0..1500 {
        let name = format!("synthetic-package-{index:04}");
        packages.insert(format!("node_modules/{name}"), json!({"version":"1.0.0"}));
        queries.push(json!({"package":{"purl":format!("pkg:npm/{name}")},"version":"1.0.0"}));
    }
    fs::write(
        directory.path().join("workspace/package-lock.json"),
        serde_json::to_vec(&json!({"lockfileVersion":3,"packages":packages})).unwrap(),
    )
    .unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let profile_path = directory.path().join("radar.yaml");
    fs::write(
        &profile_path,
        format!(
            "schema: 1\nproject_id: {project}\nname: synthetic-volume\nworkspaces: [workspace]\n"
        ),
    )
    .unwrap();
    let profile = vulnbell::profile::load(&profile_path).unwrap();
    let store = Store::open(&project).unwrap();
    for chunk in queries.chunks(100) {
        let body = json!({"queries":chunk});
        let key =
            vulnbell::digest(format!("POST:https://api.osv.dev/v1/querybatch:{body}").as_bytes());
        let results: Vec<serde_json::Value> = chunk.iter().map(|_| json!({})).collect();
        store
            .connection
            .execute(
                "INSERT OR REPLACE INTO cache VALUES (?1,?2,NULL,?3)",
                rusqlite::params![
                    key,
                    serde_json::to_vec(&json!({"results":results})).unwrap(),
                    chrono::Utc::now().timestamp()
                ],
            )
            .unwrap();
    }
    for _ in 0..2 {
        let snapshot = vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
        assert_eq!(snapshot.instances.len(), 1500);
        assert!(snapshot.cases.is_empty());
        assert_eq!(
            snapshot
                .coverage
                .iter()
                .filter(|item| item.source == "osv"
                    && item.state == vulnbell::model::CoverageState::Checked)
                .count(),
            1500
        );
        assert!(
            snapshot
                .coverage
                .iter()
                .any(|item| item.source == "http_metrics"
                    && item.detail.contains("requests=0, cache_hits=15"))
        );
    }
    let count: u32 = store
        .connection
        .query_row("SELECT COUNT(*) FROM inventory_cache", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
