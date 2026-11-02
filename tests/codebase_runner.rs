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
    fs::create_dir(root.join(".codegraph")).unwrap();
    fs::write(root.join(".codegraph/index.rs"), "fn indexed_only() {}\n").unwrap();
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
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(".codegraph"));
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
    fs::create_dir(root.join("empty")).unwrap();
    for (tool, arguments) in [
        (
            "codebase_read",
            serde_json::json!({"codebase":0,"path":"source.rs","start_line":99}),
        ),
        (
            "codebase_search",
            serde_json::json!({"codebase":0,"path":"empty","query":"example"}),
        ),
        (
            "codebase_search",
            serde_json::json!({"codebase":0,"query":"not-present"}),
        ),
    ] {
        assert!(
            call(binary, &project, &data, &receipt, tool, arguments)
                .status
                .success()
        );
        assert!(!receipt.exists());
    }
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
    assert!(blocked.status.success());
    let response: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(response["result"]["isError"], true);
    assert!(!job.join("blocked.json").exists());
    assert!(!String::from_utf8_lossy(&blocked.stdout).contains("private-dependencies.txt"));
}

#[cfg(unix)]
#[test]
fn graph_relations_and_review_completion_require_a_current_index() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("code");
    let bin = directory.path().join("bin");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join(".codegraph")).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::write(root.join("app.rs"), "fn handler() {}\n").unwrap();
    let status = serde_json::json!({"projectPath":root, "initialized":true,
        "index":{"state":"complete","reindexRecommended":false,"pendingRefs":0},
        "lastIndexed":"2026-01-01T00:00:00Z","pendingChanges":{"added":0,"modified":0,"removed":0},
        "worktreeMismatch":null,"languages":["rust"]});
    let relations = serde_json::json!({"callers":[{"filePath":"app.rs","startLine":1},{"filePath":".env","startLine":1}]});
    let fake = bin.join("codegraph");
    fs::write(&fake, format!("#!/bin/sh\ncase \"$1\" in\nstatus) printf '%s\\n' '{}' ;;\ncallers) printf '%s\\n' '{}' ;;\n*) exit 1 ;;\nesac\n", status, relations)).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let project = directory.path().join("vulnbell.yaml");
    fs::write(
        &project,
        format!("schema: 1\nproject_id: {id}\nname: fixture\ncodebases: [code]\ndiscovery: off\n"),
    )
    .unwrap();
    let data = directory.path().join("data");
    let binary = env!("CARGO_BIN_EXE_vulnbell");
    let scan = Command::new(binary)
        .args(["scan", "--project"])
        .arg(&project)
        .args(["--offline", "--json"])
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(matches!(scan.status.code(), Some(0 | 2)));
    let snapshot: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let review = directory.path().join("review.json");
    fs::write(&review, serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"codebase":0,"status":"in_progress","scope":[],"gaps":[],"uncertainties":[]}).to_string()).unwrap();
    let started = Command::new(binary)
        .args(["tools", "code-review", "--project"])
        .arg(&project)
        .arg("--from")
        .arg(&review)
        .env("PATH", &path)
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let started: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    fs::write(
        &review,
        serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"codebase":0,
        "previous_revision":started["revision"],
        "status":"complete","scope":["Reviewed handler"],"gaps":[],"uncertainties":["External reachability is unknown"]})
        .to_string(),
    )
    .unwrap();
    let recorded = Command::new(binary)
        .args(["tools", "code-review", "--project"])
        .arg(&project)
        .arg("--from")
        .arg(&review)
        .env("PATH", &path)
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&recorded.stdout).unwrap();
    assert_eq!(record["indexed_languages"][0], "rust");
    assert_eq!(
        record["submission"]["uncertainties"][0],
        "External reachability is unknown"
    );
    let jobs = data.join(&id).join("jobs/job");
    fs::create_dir_all(&jobs).unwrap();
    let mut child = Command::new(binary)
        .args(["runner-codebase", "--project"])
        .arg(&project)
        .arg("--receipt")
        .arg(jobs.join("receipt.json"))
        .env("PATH", &path)
        .env("VULNBELL_DATA_DIR", &data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"codebase_symbols","arguments":{"codebase":0,"query":"handler","relation":"callers"}}})).unwrap();
    let response = child.wait_with_output().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
    let value: serde_json::Value =
        serde_json::from_str(json["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(value["locations"].as_array().unwrap().len(), 1);
    assert_eq!(value["locations"][0]["path"], "app.rs");
    assert_eq!(value["complete"], false);
    fs::write(&review, serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"codebase":0,"previous_revision":record["revision"],"status":"in_progress","scope":[],"gaps":[],"uncertainties":[]}).to_string()).unwrap();
    let restart = Command::new(binary)
        .args(["tools", "code-review", "--project"])
        .arg(&project)
        .arg("--from")
        .arg(&review)
        .env("PATH", &path)
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(restart.status.success());
    let restart: serde_json::Value = serde_json::from_slice(&restart.stdout).unwrap();
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\nprintf 'fn changed() {{}}\\n' > app.rs\nprintf '%s\\n' '{}'\n",
            status
        ),
    )
    .unwrap();
    fs::write(&review, serde_json::json!({"schema_version":1,"snapshot_id":snapshot["id"],"codebase":0,"previous_revision":restart["revision"],"status":"complete","scope":["handler"],"gaps":[],"uncertainties":[]}).to_string()).unwrap();
    let changed = Command::new(binary)
        .args(["tools", "code-review", "--project"])
        .arg(&project)
        .arg("--from")
        .arg(&review)
        .env("PATH", &path)
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(
        String::from_utf8_lossy(&changed.stderr)
            .contains("source changed while checking CodeGraph")
    );
    fs::write(
        directory.path().join("code/app.rs"),
        "fn handler() { /* changed */ }\n",
    )
    .unwrap();
    let pending = Command::new(binary)
        .args(["tools", "pending", "--project"])
        .arg(&project)
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&pending.stdout).unwrap();
    assert_eq!(pending["code_reviews_pending"], serde_json::json!([0]));
}

#[cfg(unix)]
#[test]
fn graph_never_executes_a_tool_from_another_monitored_codebase() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::create_dir(first.join(".codegraph")).unwrap();
    fs::write(first.join("app.rs"), "fn handler() {}\n").unwrap();
    let marker = directory.path().join("executed");
    let fake = second.join("codegraph");
    fs::write(
        &fake,
        format!("#!/bin/sh\nprintf executed > '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let project = directory.path().join("vulnbell.yaml");
    fs::write(&project, format!("schema: 1\nproject_id: {}\nname: fixture\ncodebases: [first, second]\ndiscovery: off\n", uuid::Uuid::new_v4())).unwrap();
    let data = directory.path().join("data");
    let binary = env!("CARGO_BIN_EXE_vulnbell");
    let scan = Command::new(binary)
        .args(["scan", "--project"])
        .arg(&project)
        .args(["--offline", "--json"])
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(matches!(scan.status.code(), Some(0 | 2)));
    let path = std::env::join_paths([second, "/usr/bin".into(), "/bin".into()]).unwrap();
    let mut child = Command::new(binary)
        .args(["runner-codebase", "--project"])
        .arg(&project)
        .env("PATH", path)
        .env("VULNBELL_DATA_DIR", &data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"codebase_symbols","arguments":{"codebase":0,"query":"handler"}}})).unwrap();
    let response = child.wait_with_output().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
    assert_eq!(value["result"]["isError"], true);
    assert!(!marker.exists());
}

#[test]
fn source_receipt_keeps_each_codebase_that_was_actually_read() {
    let directory = tempfile::tempdir().unwrap();
    for name in ["first", "second"] {
        fs::create_dir(directory.path().join(name)).unwrap();
        fs::write(
            directory.path().join(name).join("app.rs"),
            "fn handler() {}\n",
        )
        .unwrap();
    }
    let id = uuid::Uuid::new_v4().to_string();
    let project = directory.path().join("vulnbell.yaml");
    fs::write(&project, format!("schema: 1\nproject_id: {id}\nname: fixture\ncodebases: [first, second]\ndiscovery: off\n")).unwrap();
    let data = directory.path().join("data");
    let binary = env!("CARGO_BIN_EXE_vulnbell");
    let scan = Command::new(binary)
        .args(["scan", "--project"])
        .arg(&project)
        .args(["--offline", "--json"])
        .env("VULNBELL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(matches!(scan.status.code(), Some(0 | 2)));
    let jobs = data.join(&id).join("jobs/job");
    fs::create_dir_all(&jobs).unwrap();
    let receipt = jobs.join("receipt.json");
    for index in [0, 1, 0] {
        let response = call(
            binary,
            &project,
            &data,
            &receipt,
            "codebase_read",
            serde_json::json!({"codebase":index,"path":"app.rs"}),
        );
        let value: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
        assert!(value["result"].get("isError").is_none());
    }
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(saved["codebases_read"], serde_json::json!([0, 1]));
    fs::write(
        directory.path().join("second/requirements.txt"),
        "-r secret-source.txt\n",
    )
    .unwrap();
    let allowed = call(
        binary,
        &project,
        &data,
        &receipt,
        "codebase_read",
        serde_json::json!({"codebase":0,"path":"app.rs"}),
    );
    let allowed: serde_json::Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert!(allowed["result"].get("isError").is_none());
    let denied = call(
        binary,
        &project,
        &data,
        &receipt,
        "codebase_read",
        serde_json::json!({"codebase":1,"path":"app.rs"}),
    );
    let denied: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denied["result"]["isError"], true);
    assert!(!denied.to_string().contains("secret-source.txt"));
}
