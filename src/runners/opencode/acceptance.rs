use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

fn respond(stream: &mut TcpStream) -> Result<bool> {
    let mut input = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    input.read_line(&mut line)?;
    let mut length = None;
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            anyhow::bail!("incomplete mock model request");
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let length = length.context("missing content length")?;
    if length > 4 * 1024 * 1024 {
        anyhow::bail!("mock model request exceeds limit");
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    let request: Value = serde_json::from_slice(&bytes)?;
    let tools = request["tools"].as_array().cloned().unwrap_or_default();
    let observed = request["messages"]
        .as_array()
        .is_some_and(|messages| messages.iter().any(|message| message["role"] == "tool"));
    let (delta, reason) = if !tools.is_empty() && !observed {
        assert!(
            tools
                .iter()
                .any(|tool| tool["function"]["name"] == "vulnbell_codebase_codebase_read")
        );
        (
            json!({"role":"assistant","tool_calls":[{"index":0,"id":"call_fixture","type":"function","function":{"name":"vulnbell_codebase_codebase_read","arguments":"{\"codebase\":0,\"path\":\"source.rs\"}"}}]}),
            "tool_calls",
        )
    } else {
        (
            json!({"role":"assistant","content":"{\"reviewed\":true}"}),
            "stop",
        )
    };
    let chunk = |delta: Value, finish: Value| json!({"id":"chatcmpl-fixture","object":"chat.completion.chunk","created":1,"model":"fixture","choices":[{"index":0,"delta":delta,"finish_reason":finish}]});
    let body = format!(
        "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        chunk(delta, Value::Null),
        chunk(json!({}), json!(reason))
    );
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    Ok(observed)
}

#[test]
#[ignore = "requires OpenCode 1.19.4, a built VulnBell binary and a synthetic scanned project"]
fn actual_opencode_reads_codebase_with_synthetic_local_model() {
    let executable = PathBuf::from(
        std::env::var_os("VULNBELL_OPENCODE_EXECUTABLE").expect("OpenCode executable"),
    );
    let binary =
        PathBuf::from(std::env::var_os("VULNBELL_TEST_BINARY").expect("VulnBell executable"));
    let project =
        PathBuf::from(std::env::var_os("VULNBELL_TEST_PROJECT").expect("synthetic project"));
    let profile = crate::profile::load(&project).unwrap();
    let data_root = crate::store::data_root().canonicalize().unwrap();
    let jobs = data_root.join(profile.project_id.to_string()).join("jobs");
    fs::create_dir_all(&jobs).unwrap();
    let source = SourceAccess {
        project,
        project_id: profile.project_id.to_string(),
        data_root,
        receipt: jobs.join(format!("acceptance-{}.json", uuid::Uuid::new_v4())),
        required_codebase: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let adapter = OpenCodeAdapter {
        executable: &executable,
        model: "local/fixture",
    };
    let mut session = Session::new(
        &adapter,
        directory.path(),
        AgentRole::CodebaseReview,
        None,
        Some(&source),
    )
    .unwrap();
    session.settings["mcp"]["vulnbell_codebase"]["command"][0] = json!(binary);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    session.settings["provider"] = json!({"local":{"npm":"@ai-sdk/openai-compatible","name":"Local","options":{"baseURL":format!("http://{address}/v1"),"apiKey":"synthetic"},"models":{"fixture":{"name":"Fixture"}}}});
    session
        .preflight(&adapter, AgentRole::CodebaseReview)
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let server = thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    if respond(&mut stream).unwrap() {
                        return true;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(error) => panic!("mock model listener failed: {error}"),
            }
        }
        false
    });
    let mut command = session.command(&adapter).unwrap();
    command.args([
        "run",
        "--format",
        "json",
        "--agent",
        "vulnbell",
        "--model",
        adapter.model,
    ]);
    let result =
        crate::process::run_agent_with_input(&mut command, 45, 8 * 1024 * 1024, b"Read source.rs")
            .unwrap();
    stop.store(true, Ordering::Relaxed);
    assert!(
        server.join().unwrap(),
        "model did not receive the tool result"
    );
    assert!(
        result.success,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        final_output(&result.stdout, &session.allowed_tools, true)
            .unwrap()
            .trim(),
        r#"{"reviewed":true}"#
    );
    source.verify().unwrap();
}
