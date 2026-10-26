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
