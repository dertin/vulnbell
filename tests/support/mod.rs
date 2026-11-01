use std::process::Command;

pub fn isolate_data(test: &str) -> bool {
    if std::env::var_os("VULNBELL_TEST_ISOLATED").as_deref() == Some(std::ffi::OsStr::new("1")) {
        return false;
    }
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("VULNBELL_TEST_ISOLATED", "1")
        .env("VULNBELL_DATA_DIR", directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "isolated test failed: {test}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
