#[cfg(unix)]
#[test]
fn doctor_reports_gh_credentials_without_exposing_them() {
    use std::{fs, os::unix::fs::PermissionsExt};

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("gh");
    fs::write(
        &executable,
        "#!/bin/sh\nprintf 'synthetic-token-do-not-print\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["doctor", "--json"])
        .env("PATH", directory.path())
        .env("VULNBELL_DATA_DIR", directory.path().join("data"))
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-token-do-not-print"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-token-do-not-print"));
    let doctor: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doctor["credentials"]["github"], true);
    assert_eq!(doctor["credentials"]["github_source"], "gh");

    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["doctor", "--json"])
        .env("PATH", directory.path())
        .env("VULNBELL_DATA_DIR", directory.path().join("data"))
        .env("GITHUB_TOKEN", "explicit-synthetic-token")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("explicit-synthetic-token"));
    let doctor: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doctor["credentials"]["github_source"], "environment");

    fs::remove_file(executable).unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["doctor", "--json"])
        .env("PATH", directory.path())
        .env("VULNBELL_DATA_DIR", directory.path().join("data"))
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN")
        .output()
        .unwrap();
    assert!(output.status.success());
    let doctor: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doctor["credentials"]["github"], false);
    assert!(doctor["credentials"]["github_source"].is_null());
}
