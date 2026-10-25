use std::fs;
use vulnbell::store::Store;
#[test]
fn concurrent_scans_and_future_schema_versions_fail_closed() {
    let project = uuid::Uuid::new_v4().to_string();
    let store = Store::open(&project).unwrap();
    let lock = store.lock().unwrap();
    assert!(store.lock().is_err());
    drop(lock);
    assert!(store.lock().is_ok());
    store
        .connection
        .execute_batch("PRAGMA user_version=99")
        .unwrap();
    drop(store);
    assert!(Store::open(&project).is_err());
    let connection = rusqlite::Connection::open(
        vulnbell::store::data_root()
            .join(&project)
            .join("state.sqlite"),
    )
    .unwrap();
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 99);
    drop(connection);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
#[test]
fn symlink_and_oversized_inputs_are_not_followed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("data");
    fs::write(&path, "sensitive").unwrap();
    assert!(vulnbell::read_limited(&path, 2).is_err());
    #[cfg(unix)]
    {
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(vulnbell::read_limited(&link, 100).is_err());
        assert!(vulnbell::atomic_write(&link, b"replacement").is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "sensitive");
    }
}

#[test]
#[cfg(target_os = "linux")]
fn a_trusted_agent_can_update_an_existing_large_state_file_while_guest_limits_remain_strict() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("existing-agent-state.db");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(65 * 1024 * 1024)
        .unwrap();
    let mut command = std::process::Command::new("/bin/sh");
    command
        .env_clear()
        .args(["-c", "printf x >> \"$1\"", "vulnbell-test"])
        .arg(&path);
    assert!(
        vulnbell::process::run_bounded_agent(&mut command, 5, 1024)
            .unwrap()
            .success
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        65 * 1024 * 1024 + 1
    );
    let mut isolated = std::process::Command::new("/bin/sh");
    isolated
        .env_clear()
        .args(["-c", "printf x >> \"$1\"", "vulnbell-test"])
        .arg(&path);
    assert!(
        !vulnbell::process::run_bounded(&mut isolated, 5, 1024)
            .unwrap()
            .success
    );
}

#[test]
fn missing_supported_inventory_and_parser_failures_are_explicit_without_source_content() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("radar.yaml");
    let workspace = directory.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("go.mod"), "module synthetic\n").unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let store = Store::open(&project).unwrap();
    let empty = vulnbell::inventory::discover(&["workspace".into()], &profile, &store, 100_000);
    assert!(
        empty
            .coverage
            .iter()
            .any(|item| item.state == vulnbell::model::CoverageState::Unsupported)
    );
    assert!(
        empty
            .coverage
            .iter()
            .any(|item| item.detail.contains("no supported lockfile"))
    );
    std::fs::write(
        workspace.join("Cargo.lock"),
        "SYNTHETIC_SECRET_DO_NOT_REPORT = [invalid",
    )
    .unwrap();
    let failed = vulnbell::inventory::discover(&["workspace".into()], &profile, &store, 100_000);
    assert!(
        failed
            .coverage
            .iter()
            .any(|item| item.state == vulnbell::model::CoverageState::Partial)
    );
    assert!(
        !serde_json::to_string(&failed.coverage)
            .unwrap()
            .contains("SYNTHETIC_SECRET_DO_NOT_REPORT")
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn inventory_budget_is_shared_across_lockfiles_and_workspaces() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    let lock = "version = 4\n[[package]]\nname = 'serde'\nversion = '1.0.0'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\n";
    std::fs::write(first.join("Cargo.lock"), lock).unwrap();
    std::fs::hard_link(first.join("Cargo.lock"), second.join("Cargo.lock")).unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let store = vulnbell::store::Store::open(&project).unwrap();
    let inventory = vulnbell::inventory::discover(
        &["first".into(), "second".into()],
        &directory.path().join("radar.yaml"),
        &store,
        1,
    );
    assert_eq!(inventory.instances.len(), 1);
    assert!(
        inventory
            .coverage
            .iter()
            .any(|row| row.state == vulnbell::model::CoverageState::Partial
                && row.detail.contains("budget"))
    );
    let empty = vulnbell::inventory::discover(
        &["first".into()],
        &directory.path().join("radar.yaml"),
        &store,
        0,
    );
    assert!(empty.instances.is_empty());
    assert!(
        empty
            .coverage
            .iter()
            .any(|row| row.state == vulnbell::model::CoverageState::Partial)
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
