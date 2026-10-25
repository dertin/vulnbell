use super::*;
#[test]
fn jsonl_uses_only_the_complete_final_step_and_rejects_errors_or_truncation() {
    let stream = br#"{"type":"step_start"}
{"type":"text","part":{"text":"Progress message"}}
{"type":"step_finish","part":{"reason":"tool-calls"}}
{"type":"step_start"}
{"type":"text","part":{"text":"{\"review\":true}"}}
{"type":"step_finish","part":{"reason":"stop"}}
"#;
    assert_eq!(
        final_output(stream, true).unwrap().trim(),
        r#"{"review":true}"#
    );
    assert!(
        final_output(
            br#"{"type":"error","error":{"name":"QuotaExceeded"}}"#,
            false
        )
        .is_err()
    );
    assert!(final_output(br#"{"type":"text","part":{"text":"partial"}}"#, false).is_err());
    let forbidden = br#"{"type":"tool_use","part":{"tool":"bash","state":{"status":"completed"}}}"#;
    assert!(final_output(forbidden, true).is_err());
    assert!(final_output(b"invalid JSONL", false).is_err());
}
#[test]
fn generated_session_keeps_credentials_and_local_tools_out_of_the_task() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let session = Session::new(&config, directory.path(), true).unwrap();
    let command = session.command(&config).unwrap();
    let settings = command
        .get_envs()
        .find(|(key, _)| *key == "OPENCODE_CONFIG_CONTENT")
        .and_then(|(_, value)| value)
        .unwrap();
    let settings: Value = serde_json::from_str(settings.to_str().unwrap()).unwrap();
    assert_eq!(settings["permission"]["*"], "deny");
    assert_eq!(settings["permission"]["websearch"], "allow");
    assert!(settings["permission"].get("webfetch").is_none());
    assert_eq!(settings["plugin"], json!([]));
    let work = command.get_current_dir().unwrap();
    assert!(work.starts_with(session.directory.path()));
    assert!(command.get_args().any(|arg| arg == "--pure"));
    let stream =
        br#"{"type":"tool_use","part":{"tool":"webfetch","state":{"status":"completed"}}}"#;
    assert!(final_output(stream, true).is_err());
}
fn config(directory: &Path) -> ScheduleConfig {
    ScheduleConfig {
        schema_version: 1,
        project_id: uuid::Uuid::new_v4().to_string(),
        agent: crate::scheduler::AgentRunner::OpenCode,
        agent_executable: std::env::var_os("VULNBELL_OPENCODE_EXECUTABLE")
            .map(PathBuf::from)
            .unwrap_or_else(|| "opencode".into()),
        agent_model: Some("opencode/big-pickle".into()),
        use_connected_apps: false,
        timezone: "UTC".into(),
        at: "08:00".into(),
        window_minutes: 60,
        frequency: crate::scheduler::Frequency::Daily,
        report_dir: directory.to_owned(),
    }
}
#[test]
#[ignore = "requires installed OpenCode 1.19.4; checks native effective grants without model credentials"]
fn actual_opencode_exposes_only_the_permitted_tools() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    for research in [true, false] {
        let session = Session::new(&config, directory.path(), research).unwrap();
        session.preflight(&config, research).unwrap();
    }
}
