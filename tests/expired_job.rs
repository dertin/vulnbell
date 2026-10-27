use chrono::{Duration, Timelike, Utc};
#[test]
fn an_expired_job_never_scans_or_starts_the_missing_agent() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    std::fs::write(&path,format!("schema: 1\nproject_id: {project}\nname: expired-job-test\ncomponents:\n - ref: unknown\nschedule: daily\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    let store = vulnbell::store::Store::open(&project).unwrap();
    store.register_project(&profile.name, &path).unwrap();
    let expired = Utc::now() - Duration::minutes(10);
    let config = vulnbell::scheduler::ScheduleConfig {
        schema_version: 2,
        project_id: project.clone(),
        runner: format!("missing-{project}"),
        timezone: "UTC".into(),
        at: format!("{:02}:{:02}", expired.hour(), expired.minute()),
        window_minutes: 1,
        frequency: vulnbell::scheduler::Frequency::Daily,
        report_dir: directory.path().join("reports"),
    };
    vulnbell::scheduler::save_config(&profile, &store, &config).unwrap();
    let status = vulnbell::operations::status().unwrap();
    let project_status = status
        .projects
        .iter()
        .find(|item| item.project_id == project)
        .unwrap();
    assert_eq!(
        project_status.schedule.runner.as_deref(),
        Some(config.runner.as_str())
    );
    assert!(!project_status.schedule.runner_configured);
    assert!(
        project_status
            .errors
            .iter()
            .any(|error| error.contains("runner") && error.contains("unavailable"))
    );
    let result = vulnbell::scheduler::run(&profile, &path, false).unwrap();
    assert_eq!(result["state"], "skipped_expired");
    assert!(store.meta("last_scan").unwrap().is_none());
    assert!(!directory.path().join("reports").exists());
    // An explicit request may run now; a missing runner must leave a useful, labeled fallback.
    let cache_key = vulnbell::digest(
        b"GET:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json:",
    );
    store
        .connection
        .execute(
            "INSERT INTO cache VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                cache_key,
                br#"{"vulnerabilities":[]}"#.as_slice(),
                Utc::now().timestamp()
            ],
        )
        .unwrap();
    let forced = vulnbell::scheduler::run(&profile, &path, true).unwrap();
    assert_eq!(forced["state"], "partial_fallback_report");
    assert_eq!(forced["agent_report_written"], false);
    assert!(forced["research_error"].is_string());
    assert!(forced["report_error"].is_string());
    assert!(store.meta("last_agent_failure").unwrap().is_some());
    let report = std::fs::read_to_string(forced["report"].as_str().unwrap()).unwrap();
    assert!(report.contains("**Agent — partial run:**"));
    assert!(report.contains("## Coverage and delivery"));
    assert!(!report.contains("Cobertura"));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
