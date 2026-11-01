use super::*;
use crate::runners::AgentAdapter;

fn adapter(directory: &Path) -> OpenCodeAdapter<'_> {
    OpenCodeAdapter {
        executable: directory,
        model: "opencode/big-pickle",
    }
}

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
        final_output(stream, &["websearch"], true).unwrap().trim(),
        r#"{"review":true}"#
    );
    assert!(
        final_output(
            br#"{"type":"error","error":{"name":"QuotaExceeded"}}"#,
            &[],
            false
        )
        .is_err()
    );
    assert!(final_output(br#"{"type":"text","part":{"text":"partial"}}"#, &[], false).is_err());
    let forbidden = br#"{"type":"tool_use","part":{"tool":"bash","state":{"status":"completed"}}}"#;
    assert!(final_output(forbidden, &["websearch"], true).is_err());
    assert!(final_output(b"invalid JSONL", &[], false).is_err());
}

#[test]
fn generated_session_keeps_credentials_and_local_tools_out_of_the_task() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("opencode");
    let adapter = adapter(&executable);
    let session = Session::new(
        &adapter,
        directory.path(),
        AgentRole::PublicResearch,
        None,
        None,
    )
    .unwrap();
    let command = session.command(&adapter).unwrap();
    let settings = command
        .get_envs()
        .find(|(key, _)| *key == "OPENCODE_CONFIG_CONTENT")
        .and_then(|(_, value)| value)
        .unwrap();
    let settings: Value = serde_json::from_str(settings.to_str().unwrap()).unwrap();
    assert_eq!(settings["permission"]["*"], "deny");
    assert_eq!(settings["permission"]["websearch"], "allow");
    assert_eq!(settings["permission"]["vulnbell_web_public_fetch"], "allow");
    assert!(settings["permission"].get("webfetch").is_none());
    assert_eq!(settings["plugin"], json!([]));
    let work = command.get_current_dir().unwrap();
    assert!(work.starts_with(session.directory.path()));
    assert!(command.get_args().any(|arg| arg == "--pure"));
    let stream =
        br#"{"type":"tool_use","part":{"tool":"webfetch","state":{"status":"completed"}}}"#;
    assert!(final_output(stream, &["websearch"], true).is_err());
}

#[test]
fn scoped_tools_are_granted_only_to_the_matching_role() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("opencode");
    let adapter = adapter(&executable);
    let source = SourceAccess {
        project: directory.path().join("vulnbell.yaml"),
        project_id: "fixture".into(),
        data_root: directory.path().join("data"),
        receipt: directory.path().join("receipt"),
    };
    let source_session = Session::new(
        &adapter,
        directory.path(),
        AgentRole::CodebaseReview,
        None,
        Some(&source),
    )
    .unwrap();
    assert_eq!(source_session.settings["permission"]["*"], "deny");
    assert_eq!(
        source_session.settings["permission"]["vulnbell_codebase_codebase_read"],
        "allow"
    );
    assert!(
        source_session.settings["permission"]
            .get("websearch")
            .is_none()
    );
    assert!(
        source_session.settings["mcp"]
            .get("vulnbell_codebase")
            .is_some()
    );
    assert!(
        Session::new(
            &adapter,
            directory.path(),
            AgentRole::PublicResearch,
            None,
            Some(&source)
        )
        .is_err()
    );

    let github_session = Session::new(
        &adapter,
        directory.path(),
        AgentRole::PublicResearch,
        Some("https://github.com/serde-rs/serde"),
        None,
    )
    .unwrap();
    assert_eq!(
        github_session.settings["permission"]["vulnbell_github_github_read"],
        "allow"
    );
    assert!(
        github_session.settings["mcp"]
            .get("vulnbell_codebase")
            .is_none()
    );
    let allowed = br#"{"type":"tool_use","part":{"tool":"vulnbell_codebase_codebase_read","state":{"status":"completed"}}}
{"type":"text","part":{"text":"{\"ok\":true}"}}
{"type":"step_finish","part":{"reason":"stop"}}
"#;
    assert!(final_output(allowed, &source_session.allowed_tools, true).is_ok());
    assert!(final_output(allowed, &github_session.allowed_tools, true).is_err());
}

#[test]
#[ignore = "requires OpenCode 1.19.4 and a locally built VulnBell binary"]
fn actual_opencode_connects_scoped_codebase_tools() {
    let executable = std::env::var_os("VULNBELL_OPENCODE_EXECUTABLE")
        .map(PathBuf::from)
        .expect("OpenCode executable");
    let vulnbell = std::env::var_os("VULNBELL_TEST_BINARY")
        .map(PathBuf::from)
        .expect("VulnBell executable");
    let fixture =
        PathBuf::from(std::env::var_os("VULNBELL_TEST_PROJECT").expect("synthetic project"));
    let project = crate::profile::load(&fixture).unwrap();
    let data_root = crate::store::data_root().canonicalize().unwrap();
    let jobs = data_root.join(project.project_id.to_string()).join("jobs");
    fs::create_dir_all(&jobs).unwrap();
    let source = SourceAccess {
        project: fixture,
        project_id: project.project_id.to_string(),
        data_root,
        receipt: jobs.join("opencode-test-receipt.json"),
    };
    let directory = tempfile::tempdir().unwrap();
    let adapter = adapter(&executable);
    let mut session = Session::new(
        &adapter,
        directory.path(),
        AgentRole::CodebaseReview,
        None,
        Some(&source),
    )
    .unwrap();
    session.settings["mcp"]["vulnbell_codebase"]["command"][0] = json!(vulnbell);
    session
        .preflight(&adapter, AgentRole::CodebaseReview)
        .unwrap();
    let mut command = session.command(&adapter).unwrap();
    command.args(["mcp", "list"]);
    let result = crate::process::run_bounded_agent(&mut command, 45, 1024 * 1024).unwrap();
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(
        result.success
            && output
                .lines()
                .any(|line| line.contains("vulnbell_codebase") && line.contains("connected")),
        "{output}"
    );

    let mut github = Session::new(
        &adapter,
        directory.path(),
        AgentRole::PublicResearch,
        Some("https://github.com/serde-rs/serde"),
        None,
    )
    .unwrap();
    github.settings["mcp"]["vulnbell_github"]["command"][0] = json!(vulnbell);
    github.settings["mcp"]["vulnbell_web"]["command"][0] = json!(vulnbell);
    github
        .preflight(&adapter, AgentRole::PublicResearch)
        .unwrap();
    let mut command = github.command(&adapter).unwrap();
    command.args(["mcp", "list"]);
    let result = crate::process::run_bounded_agent(&mut command, 60, 1024 * 1024).unwrap();
    let output = String::from_utf8(result.stdout).unwrap();
    for server in ["vulnbell_github", "vulnbell_web"] {
        assert!(
            result.success
                && output
                    .lines()
                    .any(|line| line.contains(server) && line.contains("connected")),
            "{output}"
        );
    }
}

#[test]
#[ignore = "requires installed OpenCode 1.19.4; checks native effective grants without model credentials"]
fn actual_opencode_exposes_only_the_permitted_tools() {
    let executable = std::env::var_os("VULNBELL_OPENCODE_EXECUTABLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "opencode".into());
    let adapter = adapter(&executable);
    let directory = tempfile::tempdir().unwrap();
    adapter.check(directory.path()).unwrap();
}
