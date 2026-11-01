use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn call(
    binary: &str,
    project: &Path,
    data: &Path,
    receipt: &Path,
    tool: &str,
    arguments: serde_json::Value,
) -> std::process::Output {
    let mut child = Command::new(binary)
        .args(["runner-codebase", "--project"])
        .arg(project)
        .arg("--receipt")
        .arg(receipt)
        .env("VULNBELL_DATA_DIR", data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":arguments}})).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn codebase_tool_receipts_require_a_successful_scoped_source_read() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("code");
    let data = directory.path().join("data");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("source.rs"), "fn example() {}\n").unwrap();
    fs::write(root.join(".env"), "synthetic-secret\n").unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let project = directory.path().join("vulnbell.yaml");
    fs::write(
        &project,
        format!(
            "schema: 1\nproject_id: {id}\nname: fixture\ncodebases:\n  - {}\ndiscovery: off\n",
            root.display()
        ),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_vulnbell");
    let scan = Command::new(binary)
        .args(["scan", "--project"])
        .arg(&project)
        .args(["--offline", "--json"])
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(matches!(scan.status.code(), Some(0 | 2)));
    let job = data.join(&id).join("jobs/job");
    fs::create_dir_all(&job).unwrap();
    let receipt = job.join("source.json");
    let listed = call(
        binary,
        &project,
        &data,
        &receipt,
        "codebase_list",
        serde_json::json!({"codebase":0}),
    );
    assert!(listed.status.success());
    assert!(!receipt.exists());
    let denied = call(
        binary,
        &project,
        &data,
        &receipt,
        "codebase_read",
        serde_json::json!({"codebase":0,"path":".env"}),
    );
    assert!(denied.status.success());
    let response: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(response["result"]["isError"], true);
    assert!(!receipt.exists());
    for arguments in [
        serde_json::json!({"codebase":1,"path":"source.rs"}),
        serde_json::json!({"codebase":0,"path":"../outside.rs"}),
    ] {
        let denied = call(
            binary,
            &project,
            &data,
            &receipt,
            "codebase_read",
            arguments,
        );
        let response: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert!(!receipt.exists());
    }
    let read = call(
        binary,
        &project,
        &data,
        &receipt,
        "codebase_read",
        serde_json::json!({"codebase":0,"path":"source.rs"}),
    );
    assert!(read.status.success());
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(saved["project_id"], id);
    assert_eq!(saved["source_read"], true);
    let outside = call(
        binary,
        &project,
        &data,
        &directory.path().join("outside.json"),
        "codebase_read",
        serde_json::json!({"codebase":0,"path":"source.rs"}),
    );
    assert!(!outside.status.success());
    assert!(!directory.path().join("outside.json").exists());
    fs::write(root.join(".gitignore"), "requirements-local.txt\n").unwrap();
    fs::write(
        root.join("requirements-local.txt"),
        "-r hidden-private.txt\n",
    )
    .unwrap();
    let ignored = call(
        binary,
        &project,
        &data,
        &job.join("ignored.json"),
        "codebase_read",
        serde_json::json!({"codebase":0,"path":"source.rs"}),
    );
    assert!(ignored.status.success());
    assert!(job.join("ignored.json").exists());
    fs::write(
        root.join("requirements.txt"),
        format!(
            "{}-r private-dependencies.txt\n",
            "public-package==1.0\n".repeat(2000)
        ),
    )
    .unwrap();
    let blocked = call(
        binary,
        &project,
        &data,
        &job.join("blocked.json"),
        "codebase_read",
        serde_json::json!({"codebase":0,"path":"source.rs"}),
    );
    assert!(!blocked.status.success());
    assert!(!job.join("blocked.json").exists());
    assert!(!String::from_utf8_lossy(&blocked.stderr).contains("private-dependencies.txt"));
}
