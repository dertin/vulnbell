use super::*;

#[test]
fn configurations_are_typed_and_reject_unknown_adapters_or_unsafe_values() {
    let config = RunnerConfig {
        schema_version: 1,
        id: "daily-local".into(),
        adapter: AdapterConfig::Codex {
            executable: std::env::current_exe().unwrap(),
            model: None,
        },
    };
    assert!(config.validate().is_ok());

    let mut invalid_id = config.clone();
    invalid_id.id = "../outside".into();
    assert!(invalid_id.validate().is_err());

    let serialized = serde_json::to_string(&config).unwrap();
    assert!(
        serde_json::from_str::<RunnerConfig>(&serialized.replace("codex", "unknown-agent"))
            .is_err()
    );

    let opencode = RunnerConfig {
        schema_version: 1,
        id: "opencode-local".into(),
        adapter: AdapterConfig::OpenCode {
            executable: std::env::current_exe().unwrap(),
            model: "missing-provider".into(),
        },
    };
    assert!(opencode.validate().is_err());
}

#[test]
fn live_probe_requires_the_fetched_title_and_reports_disabled_tools() {
    assert!(
        probe_result(br#"{"reachable":true,"title":"Example Domain","detail":"fetched"}"#).is_ok()
    );
    let disabled = probe_result(
        br#"{"reachable":false,"title":"","detail":"tool call returned 'code-mode host is disabled'"}"#,
    )
    .unwrap_err()
    .to_string();
    assert!(disabled.contains("code-mode host is disabled"));
    assert!(probe_result(br#"{"reachable":true,"title":"Guessed","detail":""}"#).is_err());
    assert!(probe_result(b"not json").is_err());
}
