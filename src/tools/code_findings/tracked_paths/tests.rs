use super::*;
use std::{fs, process::Command};

#[test]
fn batches_exact_literal_paths_and_rechecks_the_index() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
    fs::create_dir(root.join("folder")).unwrap();
    let mut paths = Vec::new();
    for index in 0..500 {
        let path = format!("folder/file-{index:04}.rs");
        fs::write(root.join(&path), "fixture\n").unwrap();
        paths.push(path);
    }
    fs::write(root.join("literal[1].rs"), "fixture\n").unwrap();
    fs::write(root.join("-leading.rs"), "fixture\n").unwrap();
    fs::write(root.join("untracked.rs"), "fixture\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "--", "folder", "literal[1].rs", "-leading.rs"])
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
    paths.extend([
        "literal[1].rs".into(),
        "-leading.rs".into(),
        "untracked.rs".into(),
        "folder".into(),
        "folder//file-0000.rs".into(),
        "folder/./file-0000.rs".into(),
        "folder/../literal[1].rs".into(),
    ]);
    let root = root.canonicalize().unwrap();
    let found = tracked_in_batches(root.to_str().unwrap(), paths.clone());
    assert_eq!(found.len(), 504);
    assert!(found.contains("literal[1].rs") && found.contains("-leading.rs"));
    assert!(found.contains("folder//file-0000.rs") && found.contains("folder/./file-0000.rs"));
    assert!(!found.contains("folder/../literal[1].rs"));
    assert!(!found.contains("untracked.rs") && !found.contains("folder"));
    assert!(
        Command::new("git")
            .args(["rm", "--cached", "-q", "--", "literal[1].rs"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success()
    );
    assert!(!tracked_in_batches(root.to_str().unwrap(), paths).contains("literal[1].rs"));
    assert!(tracked_in_batches("/nonexistent-vulnbell-root", vec!["anything".into()]).is_empty());
}
