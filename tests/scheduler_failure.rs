#[cfg(unix)]
mod support;

#[test]
#[cfg(unix)]
fn failed_report_preserves_previous_report_and_allows_retry() {
    if support::isolate_data("failed_report_preserves_previous_report_and_allows_retry") {
        return;
    }
    use std::fs;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("codebase")).unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let profile_path = root.join("vulnbell.yaml");
    fs::write(&profile_path, format!("schema: 1\nproject_id: {project}\nname: failure\nschedule: daily\ndiscovery: off\ncodebases: [codebase]\n")).unwrap();
    let profile = vulnbell::profile::load(&profile_path).unwrap();
    let store = vulnbell::store::Store::open(&project).unwrap();
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
                chrono::Utc::now().timestamp()
            ],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO snapshots VALUES (?1,?2)",
            rusqlite::params!["corrupt-history", "not-json"],
        )
        .unwrap();
    let previous_report = root.join("previous.md");
    fs::write(&previous_report, "previous report").unwrap();
    store.set_meta("last_job", "2020-01-01T00:00:00Z").unwrap();
    store
        .set_meta("last_job_outcome", "report_written")
        .unwrap();
    store
        .set_meta("last_report", previous_report.to_str().unwrap())
        .unwrap();
    let schedule = vulnbell::scheduler::ScheduleConfig {
        schema_version: 2,
        project_id: project,
        runner: "missing-runner".into(),
        timezone: "UTC".into(),
        at: chrono::Utc::now().format("%H:%M").to_string(),
        window_minutes: 180,
        frequency: vulnbell::scheduler::Frequency::Daily,
        report_dir: root.join("reports"),
    };
    vulnbell::scheduler::save_config(&profile, &store, &schedule).unwrap();
    let error = vulnbell::scheduler::run(&profile, &profile_path, false).unwrap_err();
    assert!(format!("{error:#}").contains("historical snapshot"));
    assert_eq!(
        store.meta("last_job_outcome").unwrap().as_deref(),
        Some("failed")
    );
    assert_ne!(
        store.meta("last_job").unwrap().as_deref(),
        Some("2020-01-01T00:00:00Z")
    );
    assert_eq!(
        store.meta("last_report").unwrap().as_deref(),
        previous_report.to_str()
    );
    assert_eq!(
        fs::read_to_string(&previous_report).unwrap(),
        "previous report"
    );
    assert!(std::path::Path::new(&store.meta("last_job_directory").unwrap().unwrap()).is_dir());
    assert!(store.meta("last_completed_slot").unwrap().is_none());
    let status = vulnbell::operations::status().unwrap();
    let project = &status.projects[0];
    assert_eq!(project.schedule.last_job_outcome.as_deref(), Some("failed"));
    assert_eq!(
        project.last_report.as_deref(),
        Some(previous_report.as_path())
    );
    assert!(
        vulnbell::operations::status_markdown(&status).contains("Last report (before failed job)")
    );
    let second = vulnbell::scheduler::run(&profile, &profile_path, false).unwrap_err();
    assert!(format!("{second:#}").contains("historical snapshot"));
    let forced_error = vulnbell::scheduler::run(&profile, &profile_path, true).unwrap_err();
    assert!(format!("{forced_error:#}").contains("historical snapshot"));
    assert!(store.meta("last_completed_slot").unwrap().is_none());
    assert_eq!(
        store.meta("last_report").unwrap().as_deref(),
        previous_report.to_str()
    );
}
