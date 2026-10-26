use serde_json::json;
use std::{fs, path::Path};
use vulnbell::{
    model::{Applicability, Decision, EvidenceReference, Verdict, Verification},
    profile::{self, Profile},
    store::Store,
};
fn cache(
    store: &Store,
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
    response: serde_json::Value,
) {
    let key = vulnbell::digest(
        format!(
            "{method}:{url}:{}",
            body.map(|value| value.to_string()).unwrap_or_default()
        )
        .as_bytes(),
    );
    store
        .connection
        .execute(
            "INSERT OR REPLACE INTO cache VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                key,
                serde_json::to_vec(&response).unwrap(),
                chrono::Utc::now().timestamp()
            ],
        )
        .unwrap();
}
#[test]
fn manual_then_mixed_monitor_is_auditable_and_preserves_history() {
    let directory = tempfile::tempdir().unwrap();
    // Unique project UUID isolates state without mutating process environment in parallel tests.
    let project = uuid::Uuid::new_v4();
    let path = directory.path().join("radar.yaml");
    let yaml = format!(
        "schema: 1\nproject_id: {project}\nname: contract-fixture\ncomponents:\n  - ref: pkg:npm/lodash\n    version: '4.17.20'\nresearch:\n  web: agent\n"
    );
    fs::write(&path, &yaml).unwrap();
    let profile = profile::load(&path).unwrap();
    let mut store = Store::open(&project.to_string()).unwrap();
    cache(
        &store,
        "GET",
        "https://registry.npmjs.org/lodash/4.17.20",
        None,
        json!({"name":"lodash","version":"4.17.20"}),
    );
    let query = json!({"queries":[{"package":{"purl":"pkg:npm/lodash"},"version":"4.17.20"}]});
    cache(
        &store,
        "POST",
        "https://api.osv.dev/v1/querybatch",
        Some(query),
        json!({"results":[{"vulns":[{"id":"GHSA-synthetic-test"}]}]}),
    );
    cache(
        &store,
        "GET",
        "https://api.osv.dev/v1/vulns/GHSA-synthetic-test",
        None,
        json!({"id":"GHSA-synthetic-test","aliases":["CVE-2099-0001"],"summary":"SYNTHETIC fixture; not a real finding"}),
    );
    cache(
        &store,
        "GET",
        "https://api.github.com/advisories?ecosystem=npm&affects=lodash%404.17.20&per_page=100&page=1",
        None,
        json!([{"ghsa_id":"GHSA-synthetic-test","cve_id":"CVE-2099-0001","summary":"SYNTHETIC fixture","withdrawn_at":null}]),
    );
    cache(
        &store,
        "GET",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        None,
        json!({"vulnerabilities":[]}),
    );
    cache(
        &store,
        "GET",
        "https://cveawg.mitre.org/api/cve/CVE-2099-0001",
        None,
        json!({"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED"}}),
    );
    let first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(first.instances.len(), 1);
    assert_eq!(first.cases.len(), 1);
    assert_eq!(first.cases[0].claims.len(), 2);
    assert_eq!(first.cases[0].decision, Decision::Actionable);
    assert!(first.partial);
    let case = &first.cases[0];
    let forged = Verdict {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        applicability: Applicability::Affected,
        verification: Verification::LabReproduced,
        decision: Decision::Actionable,
        rationale: "forged".into(),
        evidence: vec![EvidenceReference {
            id: case.evidence[0].id.clone(),
            sha256: case.evidence[0].sha256.clone(),
        }],
    };
    assert!(vulnbell::engine::triage(&mut store, &case.case_id, forged).is_err());
    let second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(second.cases[0].facts_sha256, case.facts_sha256);
    cache(
        &store,
        "GET",
        "https://api.osv.dev/v1/vulns/GHSA-synthetic-test",
        None,
        json!({"id":"GHSA-synthetic-test","aliases":["CVE-2099-0000","CVE-2099-0001"],"summary":"SYNTHETIC alias assignment update"}),
    );
    let aliased = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(aliased.cases.len(), 1);
    assert_eq!(aliased.cases[0].case_id, case.case_id);
    fs::create_dir(directory.path().join("workspace")).unwrap();
    let mut workspace_lock: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/workspace/js/package-lock.json")).unwrap();
    workspace_lock["packages"][""]["dependencies"] = json!({"lodash":"4.17.20"});
    fs::write(
        directory.path().join("workspace/package-lock.json"),
        serde_json::to_vec(&workspace_lock).unwrap(),
    )
    .unwrap();
    let before = fs::read(directory.path().join("workspace/package-lock.json")).unwrap();
    fs::write(&path, format!("{yaml}workspaces: [workspace]\n")).unwrap();
    let mixed: Profile = profile::load(&path).unwrap();
    let snapshot = vulnbell::engine::scan(&mixed, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 4);
    assert_eq!(snapshot.project_id, first.project_id);
    assert_eq!(
        fs::read(directory.path().join("workspace/package-lock.json")).unwrap(),
        before
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        format!("{yaml}workspaces: [workspace]\n")
    );
    let count: u32 = store
        .connection
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 4);
    let locked_case = snapshot
        .cases
        .iter()
        .find(|case| case.instances[0].origin == vulnbell::model::Origin::Locked)
        .unwrap();
    let mut research_case = locked_case.clone();
    research_case.case_id = "SIG-synthetic-research-context".into();
    research_case.claims.clear();
    research_case.evidence.clear();
    research_case.decision = Decision::Informational;
    store.save_case(&research_case).unwrap();
    let lock_path = directory.path().join("workspace/package-lock.json");
    let mut lock: serde_json::Value = serde_json::from_slice(&before).unwrap();
    lock["packages"]["node_modules/aaa-unrelated"] = json!({"version":"1.0.0"});
    fs::write(&lock_path, serde_json::to_vec_pretty(&lock).unwrap()).unwrap();
    let expanded = vulnbell::engine::scan(&mixed, &path, true).unwrap();
    let unchanged = expanded
        .cases
        .iter()
        .find(|case| case.case_id == locked_case.case_id)
        .unwrap();
    assert_eq!(unchanged.facts_sha256, locked_case.facts_sha256);
    assert_eq!(
        store.case(&research_case.case_id).unwrap().decision,
        Decision::Informational
    );
    assert_ne!(
        unchanged.instances[0].provenance.sha256,
        locked_case.instances[0].provenance.sha256
    );
    lock["packages"]["node_modules/lodash"]["integrity"] = json!("sha512-changed-artifact");
    fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
    let changed = vulnbell::engine::scan(&mixed, &path, true).unwrap();
    let reopened = changed
        .cases
        .iter()
        .find(|case| case.case_id == locked_case.case_id)
        .unwrap();
    assert_ne!(reopened.facts_sha256, locked_case.facts_sha256);
    let research_reopened = store.case(&research_case.case_id).unwrap();
    assert_eq!(research_reopened.decision, Decision::Review);
    assert_ne!(research_reopened.facts_sha256, research_case.facts_sha256);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project.to_string())).unwrap();
}
#[test]
fn cli_scaffold_is_valid_and_scan_rejects_empty_scope() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("radar.yaml");
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["init", "--output"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let initialized: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["validate"])
        .arg(&path)
        .arg("--json")
        .assert()
        .success();
    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["scan", "--project"])
        .arg(&path)
        .arg("--offline")
        .assert()
        .failure();
    assert!(profile::load(Path::new(&path)).is_ok());
    fs::remove_dir_all(
        vulnbell::store::data_root().join(initialized["project_id"].as_str().unwrap()),
    )
    .unwrap();
}

#[test]
fn status_lists_registered_projects_and_persisted_schedule_outcomes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("radar.yaml");
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["init", "--output"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let initialized: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let project_id = initialized["project_id"].as_str().unwrap();
    let mut profile = profile::load(&path).unwrap();
    profile.schedule = Some(vulnbell::profile::Schedule::Daily);
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();

    let store = Store::open(project_id).unwrap();
    let runner_id = format!("status-{project_id}");
    let runner = vulnbell::runners::RunnerConfig {
        schema_version: 1,
        id: runner_id.clone(),
        adapter: vulnbell::runners::AdapterConfig::Codex {
            executable: std::env::current_exe().unwrap(),
            model: None,
        },
    };
    vulnbell::runners::save(&runner).unwrap();
    let config = vulnbell::scheduler::ScheduleConfig {
        schema_version: 2,
        project_id: project_id.into(),
        runner: runner_id.clone(),
        timezone: "America/Montevideo".into(),
        at: "08:00".into(),
        window_minutes: 180,
        frequency: vulnbell::scheduler::Frequency::Daily,
        report_dir: directory.path().join("reports"),
    };
    vulnbell::scheduler::save_config(&profile, &store, &config).unwrap();
    store
        .set_meta(
            "last_skipped_job",
            r#"{"schema_version":1,"state":"skipped_expired","slot":"2026-10-24-0800","expires_at":"2026-10-24T14:00:00Z","next_iteration":"timer schedule; no late catch-up"}"#,
        )
        .unwrap();
    store
        .set_meta("last_job_outcome", "partial_fallback_report")
        .unwrap();
    store
        .set_meta(
            "last_report",
            &directory.path().join("reports/latest.md").to_string_lossy(),
        )
        .unwrap();
    drop(store);

    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let project = status["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|project| project["project_id"] == project_id)
        .unwrap();
    assert_eq!(project["profile_available"], true);
    assert_eq!(project["schedule"]["requested"], "daily");
    assert_eq!(project["schedule"]["configured"], true);
    assert_eq!(project["schedule"]["configuration_valid"], true);
    assert_eq!(project["schedule"]["runner"], runner_id);
    assert_eq!(project["schedule"]["runner_configured"], true);
    assert_eq!(project["schedule"]["installed"], false);
    assert_eq!(project["schedule"]["healthy"], false);
    assert_eq!(
        project["schedule"]["last_skipped_job"]["state"],
        "skipped_expired"
    );
    assert_eq!(
        project["schedule"]["last_job_outcome"],
        "partial_fallback_report"
    );

    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .arg("status")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("requested but not ready"));
    assert!(text.contains("2026-10-24-0800"));

    fs::remove_file(&path).unwrap();
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let project = status["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|project| project["project_id"] == project_id)
        .unwrap();
    assert_eq!(project["profile_available"], false);
    assert!(
        project["errors"][0]
            .as_str()
            .unwrap()
            .contains("profile unavailable or invalid")
    );

    fs::remove_dir_all(vulnbell::store::data_root().join(project_id)).unwrap();
    fs::remove_file(vulnbell::runners::config_path(&runner_id).unwrap()).unwrap();
}

#[test]
fn offline_scan_skips_a_configured_notification_without_resolving_its_secret() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("radar.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: offline-notifications\ncomponents:\n  - ref: unknown-product\n")).unwrap();
    let mut profile = profile::load(&path).unwrap();
    profile.alerts.webhook_env = Some("VULNBELL_TEST_ABSENT_WEBHOOK".into());
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        snapshot.alert_status,
        "offline: notification delivery skipped"
    );
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
