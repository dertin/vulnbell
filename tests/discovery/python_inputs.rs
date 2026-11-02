use super::*;

#[test]
fn requirements_with_credentials_are_not_exported_even_beyond_the_first_chunk() {
    let (directory, path, profile, store) = project();
    let mut content = "# ordinary comment\n".repeat(5000);
    content.push_str(
        "--index-url https://user:synthetic-secret@example.invalid/simple\nrequests==2.31.0\n",
    );
    fs::write(directory.path().join("workspace/requirements.txt"), content).unwrap();
    fs::write(
        directory.path().join("workspace/requirements-dev.txt"),
        "\u{feff}--index-url synthetic-secret\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("workspace/constraints.txt"),
        format!(
            "{}{}{}\nsynthetic-private-key\n-----END PRIVATE KEY-----\n",
            "# filler\n".repeat(8000),
            "-----BEGIN ",
            "PRIVATE KEY-----"
        ),
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert_eq!(page.summary.files_unavailable, 3);
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("synthetic-secret")
    );
    cleanup(store, &profile);
}

#[test]
fn requirements_never_export_private_names_or_local_paths_to_discovery() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    for (name, content) in [
        ("requirements.txt", "synthetic-private-name==1.0\n"),
        ("requirements-dev.txt", "-e ../synthetic-private-project\n"),
        (
            "requirements-test.in",
            "/synthetic-private/path/package.whl\n",
        ),
        ("constraints.txt", "./synthetic-private.wheel\n"),
    ] {
        fs::write(workspace.join(name), content).unwrap();
    }
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert_eq!(page.summary.files_unavailable, 4);
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("synthetic-private")
    );
    cleanup(store, &profile);
}

#[test]
fn python_and_unknown_lockfiles_are_not_exposed_to_discovery() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    for name in [
        "requirements.lock",
        "requirements-dev.lock",
        "constraints.lock",
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "pylock.app.toml",
        "custom.lock",
    ] {
        fs::write(workspace.join(name), "synthetic-private==1.0\n").unwrap();
    }
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    let json = serde_json::to_string(&page).unwrap();
    assert!(!json.contains("synthetic-private"));
    assert!(
        discovery::gaps(&profile, &path, &store, "", 100)
            .unwrap()
            .items
            .iter()
            .any(|gap| gap.path == "custom.lock" && gap.state == "unavailable")
    );
    cleanup(store, &profile);
}

#[test]
fn requirements_lock_include_keeps_referenced_inputs_local() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    fs::write(workspace.join("requirements.lock"), "-r internal.json\n").unwrap();
    fs::write(workspace.join("internal.json"), "synthetic-private-canary").unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("synthetic-private-canary")
    );
    cleanup(store, &profile);
}

#[test]
fn private_lockfiles_are_not_exported_even_if_a_discovery_row_is_pending() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    for name in ["requirements.lock", "pylock.app.toml", "unknown.lock"] {
        fs::write(workspace.join(name), "synthetic-private-canary==1.0\n").unwrap();
    }
    discovery::plan(&profile, &path, &store, 20).unwrap();
    store
        .connection
        .execute("UPDATE discovery_files SET state='pending'", [])
        .unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("synthetic-private-canary")
    );
    cleanup(store, &profile);
}
