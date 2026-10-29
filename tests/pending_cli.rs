#[test]
fn pending_accepts_json_flag() {
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args([
            "tools",
            "pending",
            "--project",
            "missing-profile.yaml",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("unexpected argument"), "{stderr}");
}
