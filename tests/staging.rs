use std::{fs, path::PathBuf};
use vulnbell::sandbox::staging::stage;

#[test]
fn capabilities_report_profile_limits_without_starting_the_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("vulnbell.yaml");
    fs::write(&profile, "schema: 1\nproject_id: 0de0a8e7-f1a4-4bdc-a198-422b90bbbd84\nname: fixture\nsandbox:\n  max_input_file_mib: 32\n  max_inputs_mib: 96\n  max_memory_mib: 1024\n  max_timeout_seconds: 180\n").unwrap();
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["sandbox", "capabilities", "--project"])
        .arg(&profile)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["workspace_stage"]["max_files"], 1000);
    assert_eq!(
        value["workspace_stage"]["max_archive_bytes"],
        16 * 1024 * 1024
    );
    assert_eq!(value["test"]["max_inputs"], 20);
    assert_eq!(value["test"]["limits"]["max_input_file_mib"], 32);
    assert_eq!(value["test"]["limits"]["max_memory_mib"], 1024);
    assert_eq!(value["required_network_policy"], "deny_ingress_and_egress");
    assert_eq!(value["explicit_authorization_required"], true);
    assert_eq!(value["runtime_policy_checked_during_verify"], true);
}

#[test]
fn staging_copies_only_reviewed_bytes_preserves_paths_and_never_runs_project_hooks() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("workspace");
    fs::create_dir_all(source.join("src")).unwrap();
    fs::write(source.join("src/main.js"), b"original artifact usage").unwrap();
    fs::write(
        source.join("package.json"),
        br#"{"scripts":{"prepare":"touch HOST_MUST_NOT_RUN"}}"#,
    )
    .unwrap();
    fs::write(source.join(".env"), b"PRIVATE_TEST_VALUE").unwrap();
    let target = directory.path().join("bundle");
    let selected = vec![PathBuf::from("src/main.js"), PathBuf::from("package.json")];
    let bundle = stage(&source, &selected, &target).unwrap();
    let bytes = fs::read(target.join(&bundle.input.path)).unwrap();
    assert_eq!(vulnbell::digest(&bytes), bundle.input.sha256);
    let mut archive = tar::Archive::new(bytes.as_slice());
    let entries: Vec<_> = archive
        .entries()
        .unwrap()
        .map(|item| {
            let entry = item.unwrap();
            assert!(entry.header().entry_type().is_file());
            entry.path().unwrap().into_owned()
        })
        .collect();
    assert_eq!(entries, selected);
    fs::write(source.join("src/main.js"), b"changed source after staging").unwrap();
    assert_eq!(fs::read(target.join(&bundle.input.path)).unwrap(), bytes);
    assert!(!source.join("HOST_MUST_NOT_RUN").exists());
    assert!(!target.join("HOST_MUST_NOT_RUN").exists());
    assert!(stage(&source, &selected, &target).is_err());
    assert_eq!(fs::read(target.join(&bundle.input.path)).unwrap(), bytes);
}

#[test]
fn staging_rejects_secrets_traversal_symlinks_and_oversize_before_publishing() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("workspace");
    fs::create_dir(&source).unwrap();
    fs::write(source.join(".env"), b"PRIVATE_TEST_VALUE").unwrap();
    let target = directory.path().join("bundle");
    for relative in [
        ".env",
        ".git/config",
        "../outside",
        "/etc/passwd",
        "C:secret",
        ".aws/credentials",
    ] {
        assert!(
            stage(&source, &[relative.into()], &target).is_err(),
            "{relative}"
        );
        assert!(!target.exists());
    }
    let large = fs::File::create(source.join("large.bin")).unwrap();
    large.set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(stage(&source, &["large.bin".into()], &target).is_err());
    assert!(!target.exists());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(directory.path(), source.join("link")).unwrap();
        assert!(stage(&source, &["link/outside".into()], &target).is_err());
        assert!(!target.exists());
    }
}
