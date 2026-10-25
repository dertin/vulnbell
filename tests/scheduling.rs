use chrono::{DateTime, Utc};
use vulnbell::scheduler::{AgentRunner, Frequency, ScheduleConfig, SlotState};
fn config() -> ScheduleConfig {
    ScheduleConfig {
        schema_version: 1,
        project_id: uuid::Uuid::new_v4().to_string(),
        agent: AgentRunner::Codex,
        agent_executable: std::env::current_exe().unwrap(),
        agent_model: None,
        use_connected_apps: false,
        timezone: "America/Montevideo".into(),
        at: "08:00".into(),
        window_minutes: 180,
        frequency: Frequency::Daily,
        report_dir: std::env::temp_dir(),
    }
}
fn utc(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}
#[test]
fn powered_off_machine_runs_only_inside_the_current_window_and_skips_expired_periods() {
    let config = config();
    assert_eq!(
        config.slot(utc("2026-10-26T10:59:00Z")).unwrap().state,
        SlotState::Expired
    );
    let eligible = config.slot(utc("2026-10-26T11:00:00Z")).unwrap();
    assert_eq!(eligible.state, SlotState::Eligible);
    assert_eq!(
        config.slot(utc("2026-10-26T13:59:59Z")).unwrap().id,
        eligible.id
    );
    assert_eq!(
        config.slot(utc("2026-10-26T14:00:00Z")).unwrap().state,
        SlotState::Expired
    );
    let next = config.slot(utc("2026-10-27T11:01:00Z")).unwrap();
    assert_ne!(next.id, eligible.id);
    assert_eq!(next.state, SlotState::Eligible);
}
#[test]
fn weekdays_and_timezone_windows_cross_midnight_without_replaying_old_days() {
    let mut config = config();
    config.frequency = Frequency::Weekdays;
    assert_eq!(
        config.slot(utc("2026-10-25T12:00:00Z")).unwrap().state,
        SlotState::Expired
    );
    config.frequency = Frequency::Daily;
    config.at = "23:30".into();
    config.window_minutes = 120;
    assert_eq!(
        config.slot(utc("2026-10-26T03:45:00Z")).unwrap().id,
        "2026-10-25-2330"
    );
    assert_eq!(
        config.slot(utc("2026-10-26T03:45:00Z")).unwrap().state,
        SlotState::Eligible
    );
    assert_eq!(
        config.slot(utc("2026-10-26T04:30:00Z")).unwrap().state,
        SlotState::Expired
    );
}

#[test]
fn agent_selection_preserves_the_shared_schedule_and_rejects_invalid_models() {
    let mut config = config();
    let profile: vulnbell::profile::Profile = serde_saphyr::from_str(&format!("schema: 1\nproject_id: {}\nname: agent-contract\nschedule: daily\ncomponents:\n  - ref: unknown\n", config.project_id)).unwrap();
    assert!(config.validate(&profile).is_ok());
    config.agent = AgentRunner::OpenCode;
    assert!(config.validate(&profile).is_err());
    config.agent_model = Some("provider/model".into());
    assert!(config.validate(&profile).is_ok());
    config.agent_model = Some("model\ncommand".into());
    assert!(config.validate(&profile).is_err());
    let serialized = serde_json::to_string(&config).unwrap();
    assert!(
        serde_json::from_str::<ScheduleConfig>(&serialized.replace("opencode", "unknown-runner"))
            .is_err()
    );
}
