use super::*;

#[test]
fn unavailable_codebase_preserves_partial_report_and_rejects_unchecked_observations() {
    use std::process::Command;
    use vulnbell::{model::Origin, profile::Component};

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("codebase");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("source.js"), "// synthetic source\n").unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\nworkspaces:\n  - {}\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/example\n", workspace.display())).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let mut snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut observation = vulnbell::model::Instance::declared(&Component {
        reference: "pkg:cargo/synthetic-observation".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: Some("https://github.com/example/observed".into()),
        feeds: Vec::new(),
    });
    observation.origin = Origin::AgentObserved;
    snapshot.instances.push(observation);
    snapshot.id = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    store.save_snapshot(&snapshot).unwrap();
    fs::remove_dir_all(&workspace).unwrap();

    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(plan.workspace_unavailable);
    assert_eq!(plan.stale_observations, 1);
    assert!(
        plan.targets
            .iter()
            .all(|target| target.upstream != "https://github.com/example/observed")
    );
    assert!(
        plan.targets
            .iter()
            .any(|target| target.upstream == "https://github.com/example/example")
    );
    let pending = vulnbell::tools::cases::pending(&store).unwrap();
    assert!(!pending.deliverable);
    assert!(pending.workspace_context_changed);
    assert_eq!(pending.stale_observations, 1);
    let report = Command::new(env!("CARGO_BIN_EXE_vulnbell"))
        .args(["report", "--project"])
        .arg(&path)
        .args(["--audience", "cyber", "--json"])
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert!(
        report["coverage_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| {
                gap["source"] == "research_web"
                    && gap["state"] == "partial"
                    && gap["detail"]
                        .as_str()
                        .unwrap_or("")
                        .contains("codebase changed or unavailable: yes")
            })
    );
    let markdown = Command::new(env!("CARGO_BIN_EXE_vulnbell"))
        .args(["report", "--project"])
        .arg(&path)
        .args(["--audience", "cyber"])
        .output()
        .unwrap();
    assert!(markdown.status.success());
    let markdown = String::from_utf8(markdown.stdout).unwrap();
    assert!(markdown.contains("Incomplete coverage or review"));
    assert!(markdown.contains("codebase changed or unavailable: yes"));
    assert!(
        store
            .latest()
            .unwrap()
            .instances
            .iter()
            .any(|instance| instance.origin == Origin::AgentObserved)
    );

    snapshot
        .instances
        .retain(|instance| instance.origin != Origin::AgentObserved);
    snapshot.id = uuid::Uuid::new_v4().to_string();
    store.save_snapshot(&snapshot).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let pending = vulnbell::tools::cases::pending(&store).unwrap();
    assert!(plan.workspace_unavailable);
    assert_eq!(plan.stale_observations, 0);
    assert!(pending.workspace_context_changed);
    assert!(!pending.deliverable);

    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("source.js"), "// synthetic source\n").unwrap();
    assert!(
        !vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .workspace_unavailable
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn unavailable_codebase_remains_incomplete_when_discovery_is_off() {
    use std::process::Command;

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("codebase");
    fs::create_dir(&workspace).unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\ndiscovery: off\nworkspaces:\n  - {}\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/example\n", workspace.display())).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let store = Store::open(&project).unwrap();
    fs::remove_dir(&workspace).unwrap();

    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(plan.workspace_unavailable);
    assert_eq!(plan.stale_observations, 0);
    let pending = vulnbell::tools::cases::pending(&store).unwrap();
    assert!(pending.workspace_context_changed);
    assert!(!pending.deliverable);
    assert!(pending.discovery_open.is_none());

    let report = Command::new(env!("CARGO_BIN_EXE_vulnbell"))
        .args(["report", "--project"])
        .arg(&path)
        .args(["--audience", "cyber", "--json"])
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert!(
        report["coverage_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| {
                gap["source"] == "research_web"
                    && gap["state"] == "partial"
                    && gap["detail"]
                        .as_str()
                        .unwrap_or("")
                        .contains("codebase changed or unavailable: yes")
            })
    );
    let markdown = Command::new(env!("CARGO_BIN_EXE_vulnbell"))
        .args(["report", "--project"])
        .arg(&path)
        .args(["--audience", "cyber"])
        .output()
        .unwrap();
    assert!(markdown.status.success());
    let markdown = String::from_utf8(markdown.stdout).unwrap();
    assert!(markdown.contains("Incomplete coverage or review"));
    assert!(markdown.contains("codebase changed or unavailable: yes"));
    fs::create_dir(&workspace).unwrap();
    assert!(
        !vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .workspace_unavailable
    );
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
