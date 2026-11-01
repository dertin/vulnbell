use std::fs;
use vulnbell::{
    discovery::{
        self, DiscoveryBatch, FileReview, IdentityObservation, MappingState, PackageObservation,
        SOURCE_KINDS, SourceMapping,
    },
    profile::{self, DiscoveryMode, Profile},
    research::ReviewCoverage,
    store::Store,
    tools::cases,
};

fn project() -> (tempfile::TempDir, std::path::PathBuf, Profile, Store) {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("workspace")).unwrap();
    let path = directory.path().join("vulnbell.yaml");
    let id = uuid::Uuid::new_v4().to_string();
    fs::write(
        &path,
        format!("schema: 1\nproject_id: {id}\nname: general-discovery\ncodebases: [workspace]\n"),
    )
    .unwrap();
    let profile = profile::load(&path).unwrap();
    let store = Store::open(&id).unwrap();
    store.register_project(&profile.name, &path).unwrap();
    (directory, path, profile, store)
}

#[test]
fn generated_directories_are_pruned_in_both_discovery_paths() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    for name in [
        "node_modules",
        "target",
        "vendor",
        "build",
        "dist",
        ".venv",
        ".terraform",
        ".gradle",
        "__pycache__",
        "bower_components",
    ] {
        let nested = workspace.join("service").join(name).join("deep");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("requirements.txt"), "hidden-noise==1.0\n").unwrap();
        fs::write(nested.join("package.json"), "{\"name\":\"hidden-noise\"}").unwrap();
    }
    fs::write(workspace.join("requirements.txt"), "visible-package==1.0\n").unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    let gaps = discovery::gaps(&profile, &path, &store, "", 100).unwrap();
    for name in [
        "node_modules",
        "target",
        "vendor",
        "build",
        "dist",
        ".venv",
        ".terraform",
        ".gradle",
        "__pycache__",
        "bower_components",
    ] {
        assert!(
            gaps.items
                .iter()
                .any(|gap| gap.path == format!("service/{name}") && gap.state == "excluded")
        );
        assert!(
            !gaps
                .items
                .iter()
                .any(|gap| gap.path.starts_with(&format!("service/{name}/")))
        );
    }
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 1);
    assert_eq!(
        snapshot.instances[0].reference,
        "python-requirement:visible-package"
    );
    cleanup(store, &profile);
}

#[test]
fn an_explicit_codebase_inside_generated_output_is_not_scanned() {
    let (directory, path, mut profile, store) = project();
    let output = directory.path().join("workspace/target/generated");
    fs::create_dir_all(&output).unwrap();
    fs::write(output.join("requirements.txt"), "must-not-be-read==1.0\n").unwrap();
    profile.codebases = vec!["workspace/target/generated".into()];
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(snapshot.instances.is_empty());
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|row| row.detail.contains("cannot be an inventory codebase"))
    );
    assert!(discovery::plan(&profile, &path, &store, 20).is_err());
    assert_eq!(
        vulnbell::codebase_revision::capture_path(&output).state,
        vulnbell::codebase_revision::RepositoryState::Unavailable
    );
    cleanup(store, &profile);
}

fn review(page: &discovery::DiscoveryPlan, packages: Vec<PackageObservation>) -> DiscoveryBatch {
    let chunk = &page.codebase_files[0];
    DiscoveryBatch::Codebase {
        schema_version: 1,
        project_id: page.project_id.clone(),
        scope_sha256: page.scope_sha256.clone(),
        reviews: vec![FileReview {
            file_id: chunk.file_id.clone(),
            offset: chunk.offset,
            sha256: chunk.sha256.clone(),
            rationale: "Reviewed the full returned source fragment as data".into(),
            coverage: ReviewCoverage::Complete,
            packages,
        }],
    }
}

fn package() -> PackageObservation {
    PackageObservation {
        component: serde_saphyr::from_str("ref: pkg:pypi/requests\nversion: '2.31.0'\n").unwrap(),
        excerpt: "requests==2.31.0".into(),
        version_excerpt: None,
        direct: None,
        direct_rationale: None,
    }
}

#[test]
fn direct_scope_reports_unknown_depth_without_mapping_every_tracker() {
    let (directory, path, mut profile, mut store) = project();
    profile.research.tracker_scope = vulnbell::profile::TrackerScope::Direct;
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();
    fs::write(
        directory.path().join("workspace/dependencies.txt"),
        "requests==2.31.0\n",
    )
    .unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    discovery::import(&profile, &path, &mut store, review(&page, vec![package()])).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let summary = discovery::summary(&profile, &path, &store).unwrap();
    assert_eq!(summary.components_unmapped, 0);
    assert_eq!(summary.deferred_unknown_depth, 1);
    assert!(
        discovery::plan(&profile, &path, &store, 20)
            .unwrap()
            .components
            .is_empty()
    );
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|row| row.source == "tracker_scope"
                && row.state == vulnbell::model::CoverageState::Partial)
    );
    let pending = serde_json::to_value(vulnbell::tools::cases::pending(&store).unwrap()).unwrap();
    assert_eq!(pending["tracker_scope_unresolved"], true);
    assert_eq!(pending["deliverable"], false);
    let deferred = snapshot
        .instances
        .iter()
        .find(|item| item.reference == "pkg:pypi/requests")
        .unwrap();
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|row| row.source == "osv" && row.scope == deferred.id)
    );
    cleanup(store, &profile);
}

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
fn requirements_includes_keep_arbitrary_paths_local_before_any_agent_page() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    for index in 0..70 {
        fs::create_dir(workspace.join(format!("a-{index:03}"))).unwrap();
    }
    fs::create_dir(workspace.join("z-config")).unwrap();
    fs::write(
        workspace.join("z-config/requirements.txt"),
        "-\\\nr ../prod.json\n",
    )
    .unwrap();
    fs::write(workspace.join("prod.json"), "--index-url https://user:synthetic-secret@example.invalid/simple\nsynthetic-private==1.0\n").unwrap();
    let first = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(first.codebase_files.is_empty());
    assert!(first.summary.directories_pending > 0);
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert!(page.summary.files_unavailable >= 2);
    let serialized = serde_json::to_string(&page).unwrap();
    assert!(!serialized.contains("synthetic-secret"));
    assert!(!serialized.contains("synthetic-private"));
    cleanup(store, &profile);
}

#[test]
fn requirements_include_guard_blocks_cross_codebase_paths() {
    let (directory, path, old_profile, store) = project();
    fs::create_dir(directory.path().join("other")).unwrap();
    let id = uuid::Uuid::new_v4();
    fs::write(
        &path,
        format!("schema: 1\nproject_id: {id}\nname: isolated\ncodebases: [workspace, other]\n"),
    )
    .unwrap();
    let profile = profile::load(&path).unwrap();
    let isolated_store = Store::open(&id.to_string()).unwrap();
    fs::write(
        directory.path().join("workspace/requirements.txt"),
        "--requirement=../other/private.config\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("other/private.config"),
        "synthetic-secret\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("other/dependencies.manifest"),
        "requests==2.31.0\n",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &isolated_store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("synthetic-secret")
    );
    cleanup(store, &old_profile);
    cleanup(isolated_store, &profile);
}

#[test]
fn bare_relative_python_source_keeps_its_codebase_local() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    let package = workspace.join("packages/privatepkg");
    fs::create_dir_all(&package).unwrap();
    fs::write(workspace.join("requirements.txt"), "packages/privatepkg\n").unwrap();
    fs::write(
        package.join("pyproject.toml"),
        "name='synthetic-private-name'\nsecret='synthetic-canary'\n",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    let json = serde_json::to_string(&page).unwrap();
    assert!(!json.contains("synthetic-private-name"));
    assert!(!json.contains("synthetic-canary"));
    cleanup(store, &profile);
}

#[test]
fn dotted_python_local_sources_do_not_leave_the_codebase() {
    for requirement in [
        ".private",
        ".",
        "  .private ; python_version > '3'",
        "./private",
        "# comment\\\n.private",
        "# comment\\\nprivate.whl[extra]",
    ] {
        let (directory, path, profile, store) = project();
        let workspace = directory.path().join("workspace");
        let package = workspace.join(".private");
        fs::create_dir(&package).unwrap();
        fs::write(
            workspace.join("requirements.txt"),
            format!("{requirement}\n"),
        )
        .unwrap();
        fs::write(
            package.join("pyproject.toml"),
            "name='synthetic-private-name'\nsecret='synthetic-canary'\n",
        )
        .unwrap();
        let page = discovery::plan(&profile, &path, &store, 20).unwrap();
        assert!(page.codebase_files.is_empty(), "{requirement}");
        let json = serde_json::to_string(&page).unwrap();
        assert!(!json.contains("synthetic-canary"));
        assert!(!json.contains("synthetic-private-name"));
        cleanup(store, &profile);
    }
}

#[test]
fn local_python_archives_do_not_leave_the_codebase() {
    for requirement in [
        "private.whl",
        "private.whl[extra]",
        "private.WHL[one,two] ; python_version > '3'",
        "PRIVATE.WHL --hash=sha256:abc",
        "private.zip",
        "private.tar.bz2",
        "private.tbz",
        "private.tar.gz",
        "private.tar.gz[extra]",
        "private#x.tar.gz",
        "private[foo].tar.gz",
        "private[foo].tar.gz[extra]",
        "private[foo]bar.zip",
        "private.tgz",
        "private.tar",
        "private.tar.xz",
        "private.txz",
        "private.tlz",
        "private.tar.lz",
        "private.tar.lzma",
        "'private wheel.whl' ; python_version > '3'",
    ] {
        let (directory, path, profile, store) = project();
        let workspace = directory.path().join("workspace");
        fs::write(
            workspace.join("requirements.txt"),
            format!("{requirement}\n"),
        )
        .unwrap();
        fs::write(
            workspace.join("pyproject.toml"),
            "name='synthetic-private-name'\nsecret='synthetic-canary'\n",
        )
        .unwrap();
        let page = discovery::plan(&profile, &path, &store, 20).unwrap();
        assert!(page.codebase_files.is_empty(), "{requirement}");
        let json = serde_json::to_string(&page).unwrap();
        assert!(!json.contains("synthetic-canary"));
        assert!(!json.contains("synthetic-private-name"));
        cleanup(store, &profile);
    }
}

#[test]
fn requirements_comments_do_not_block_generic_discovery() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    fs::write(
        workspace.join("requirements.txt"),
        "requests==2.0 # see private.whl and ./local\n",
    )
    .unwrap();
    fs::write(
        workspace.join("dependencies.json"),
        "{\"public\":\"fixture\"}",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(
        page.codebase_files
            .iter()
            .any(|item| item.path.ends_with("dependencies.json"))
    );
    cleanup(store, &profile);
}

#[test]
fn requirements_preflight_budget_keeps_the_monitor_local() {
    let (directory, path, profile, store) = project();
    let workspace = directory.path().join("workspace");
    fs::write(
        workspace.join("requirements.txt"),
        "#".repeat(1024 * 1024 + 1),
    )
    .unwrap();
    fs::write(workspace.join("dependency.json"), "synthetic-private-value").unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert_eq!(page.summary.files_unavailable, 2);
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("synthetic-private-value")
    );
    cleanup(store, &profile);
}

#[test]
fn new_requirements_include_retires_previous_agent_observations_before_rescan() {
    let (directory, path, mut profile, mut store) = project();
    profile.research.follow.push("pkg:pypi/requests".into());
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();
    let workspace = directory.path().join("workspace");
    fs::write(
        workspace.join("dependencies.manifest"),
        "requests==2.31.0\n",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    discovery::import(&profile, &path, &mut store, review(&page, vec![package()])).unwrap();
    let mut previous = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(
        previous
            .instances
            .iter()
            .any(|item| item.reference == "pkg:pypi/requests")
    );
    previous.id = uuid::Uuid::new_v4().to_string();
    previous
        .instances
        .iter_mut()
        .find(|item| item.reference == "pkg:pypi/requests")
        .unwrap()
        .upstream = Some("https://github.com/example/private-fixture".into());
    store.save_snapshot(&previous).unwrap();
    assert_eq!(
        vulnbell::research::plan_page(&store, "", 20)
            .unwrap()
            .targets
            .len(),
        1
    );
    fs::write(
        workspace.join("requirements.txt"),
        "-r dependencies.manifest\n",
    )
    .unwrap();
    let before_rescan = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(before_rescan.codebase_files.is_empty());
    assert!(
        before_rescan
            .components
            .iter()
            .all(|item| item.reference != "pkg:pypi/requests")
    );
    let research = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(research.targets.is_empty());
    assert_eq!(research.stale_observations, 1);
    assert_eq!(cases::pending(&store).unwrap().stale_observations, 1);
    let current = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(
        !current
            .instances
            .iter()
            .any(|item| item.reference == "pkg:pypi/requests")
    );
    let blocked = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(blocked.codebase_files.is_empty());
    assert!(
        blocked
            .components
            .iter()
            .all(|item| item.reference != "pkg:pypi/requests")
    );
    fs::write(workspace.join("requirements.txt"), "requests==2.31.0\n").unwrap();
    let reopened = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(
        reopened
            .codebase_files
            .iter()
            .any(|item| item.path == "dependencies.manifest")
    );
    cleanup(store, &profile);
}

#[test]
fn include_guard_retires_observations_from_an_unavailable_later_chunk() {
    let (directory, path, profile, mut store) = project();
    let workspace = directory.path().join("workspace");
    fs::create_dir(workspace.join("a")).unwrap();
    fs::create_dir(workspace.join("b")).unwrap();
    let mut content = b"requests==2.31.0\n".to_vec();
    content.resize(64 * 1024, b'a');
    content.push(0xff);
    fs::write(workspace.join("a/dependencies.manifest"), content).unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    discovery::import(&profile, &path, &mut store, review(&page, vec![package()])).unwrap();
    let next = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(next.codebase_files.is_empty());
    assert_eq!(next.summary.files_unavailable, 1);
    fs::write(
        workspace.join("b/requirements.txt"),
        "-r ../a/dependencies.manifest\n",
    )
    .unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(
        !snapshot
            .instances
            .iter()
            .any(|item| item.reference == "pkg:pypi/requests")
    );
    let observations: usize = store
        .connection
        .query_row("SELECT COUNT(*) FROM discovery_packages", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(observations, 0);
    cleanup(store, &profile);
}

#[test]
fn composer_private_packages_stay_local_even_when_all_trackers_are_selected() {
    let (directory, path, mut profile, store) = project();
    profile.research.tracker_scope = vulnbell::profile::TrackerScope::All;
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();
    fs::write(
        directory.path().join("workspace/composer.lock"),
        r#"{"packages":[{"name":"private-vendor/private-package","version":"1.2.3","source":{"url":"https://secret.invalid/project"}}],"packages-dev":[]}"#,
    )
    .unwrap();
    fs::write(
        directory.path().join("workspace/composer.json"),
        r#"{"require":{"private-vendor/private-package":"1.2.3"},"repositories":[{"type":"composer","url":"https://user:synthetic-secret@private.invalid"}]}"#,
    )
    .unwrap();

    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let package = snapshot
        .instances
        .iter()
        .find(|item| item.reference == "composer-lock:private-vendor/private-package")
        .unwrap();
    assert_eq!(package.resolved_version.as_deref(), Some("1.2.3"));
    assert!(package.purl.is_none());
    assert!(!profile.research.tracks(package));
    assert!(snapshot.coverage.iter().any(|row| row.source == "inventory"
        && row.scope == "composer.lock"
        && row.state == vulnbell::model::CoverageState::Partial));
    assert!(snapshot.coverage.iter().any(|row| row.source == "osv"
        && row.scope == package.id
        && row.state == vulnbell::model::CoverageState::Unsupported));

    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert!(page.components.is_empty());
    assert_eq!(page.summary.files_unavailable, 1);
    let exported = serde_json::to_string(&page).unwrap();
    assert!(!exported.contains("private-vendor"));
    assert!(!exported.contains("synthetic-secret"));

    let mut checked = package.clone();
    checked.purl = Some("pkg:composer/private-vendor/private-package".into());
    checked.upstream = Some("https://github.com/private-vendor/private-package".into());
    checked.provenance.direct = Some(true);
    assert!(!profile.research.tracks(&checked));
    let mut http = vulnbell::network::Http::new(&store, false);
    vulnbell::identity::resolve(&mut checked, &mut http);
    assert_eq!(http.requests, 0);
    assert!(checked.purl.is_none());
    assert!(checked.upstream.is_none());
    let research = vulnbell::research::plan_page(&store, "", 20).unwrap();
    assert!(
        !serde_json::to_string(&research)
            .unwrap()
            .contains("private-vendor")
    );

    profile.components.push(
        serde_saphyr::from_str(
            "ref: pkg:composer/public-vendor/public-package\nversion: '1.2.3'\n",
        )
        .unwrap(),
    );
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(snapshot.instances.iter().any(|item| {
        item.reference == "pkg:composer/public-vendor/public-package"
            && item.purl.as_deref() == Some("pkg:composer/public-vendor/public-package")
    }));
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(
        page.components
            .iter()
            .any(|item| { item.reference == "pkg:composer/public-vendor/public-package" })
    );
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("private-vendor")
    );
    cleanup(store, &profile);
}

#[test]
fn requirements_with_includes_are_not_exported_as_public_package_evidence() {
    let (directory, path, profile, store) = project();
    fs::write(
        directory.path().join("workspace/requirements.txt"),
        "requests==2.31.0\n-r child.txt\n",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 20).unwrap();
    assert!(page.codebase_files.is_empty());
    assert_eq!(page.summary.files_unavailable, 1);
    cleanup(store, &profile);
}

#[test]
fn manifest_directness_requires_a_rationale_and_is_preserved_in_the_inventory() {
    let (directory, path, profile, mut store) = project();
    fs::write(directory.path().join("workspace/pom.xml"),
        "<project><dependencies><dependency><artifactId>requests</artifactId><version>2.31.0</version></dependency></dependencies></project>").unwrap();
    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    let mut observed = package();
    observed.excerpt =
        "<dependency><artifactId>requests</artifactId><version>2.31.0</version></dependency>"
            .into();
    observed.direct = Some(true);
    assert!(discovery::import(&profile, &path, &mut store, review(&page, vec![observed])).is_err());
    let mut observed = package();
    observed.excerpt =
        "<dependency><artifactId>requests</artifactId><version>2.31.0</version></dependency>"
            .into();
    observed.direct = Some(true);
    observed.direct_rationale = Some("Declared under the project's dependencies".into());
    discovery::import(&profile, &path, &mut store, review(&page, vec![observed])).unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        snapshot
            .instances
            .iter()
            .find(|item| item.reference == "pkg:pypi/requests")
            .unwrap()
            .provenance
            .direct,
        Some(true)
    );
    cleanup(store, &profile);
}

#[test]
fn maven_property_versions_resolve_only_from_a_definition_in_the_same_chunk() {
    let (directory, path, profile, mut store) = project();
    fs::write(
        directory.path().join("workspace/pom.xml"),
        "<project>\n  <properties>\n    <keycloak.version>26.8.1</keycloak.version>\n  </properties>\n  <dependency>\n    <groupId>org.keycloak</groupId>\n    <artifactId>keycloak-core</artifactId>\n    <version>${keycloak.version}</version>\n  </dependency>\n</project>\n",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    let observation = |version_excerpt: Option<&str>| PackageObservation {
        component: serde_saphyr::from_str(
            "ref: pkg:maven/org.keycloak/keycloak-core\nversion: '26.8.1'\n",
        )
        .unwrap(),
        excerpt:
            "<artifactId>keycloak-core</artifactId>\n    <version>${keycloak.version}</version>"
                .into(),
        version_excerpt: version_excerpt.map(str::to_owned),
        direct: None,
        direct_rationale: None,
    };
    assert!(
        discovery::import(
            &profile,
            &path,
            &mut store,
            review(&page, vec![observation(None)])
        )
        .is_err()
    );
    assert!(
        discovery::import(
            &profile,
            &path,
            &mut store,
            review(
                &page,
                vec![observation(Some("<other.version>26.8.1</other.version>"))]
            )
        )
        .is_err()
    );
    discovery::import(
        &profile,
        &path,
        &mut store,
        review(
            &page,
            vec![observation(Some(
                "<keycloak.version>26.8.1</keycloak.version>",
            ))],
        ),
    )
    .unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(snapshot.instances.iter().any(|instance| {
        instance.reference == "pkg:maven/org.keycloak/keycloak-core"
            && instance.resolved_version.as_deref() == Some("26.8.1")
            && instance.provenance.path.as_deref() == Some("pom.xml")
    }));
    cleanup(store, &profile);
}

fn cleanup(store: Store, profile: &Profile) {
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(profile.project_id.to_string())).unwrap();
}

#[test]
fn requirements_are_kept_local_and_reinventoried_after_changes() {
    let (directory, path, profile, store) = project();
    let file = directory.path().join("workspace/requirements.txt");
    fs::write(&file, "requests==2.31.0\n").unwrap();
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let item = &snapshot.instances[0];
    assert_eq!(item.reference, "python-requirement:requests");
    assert_eq!(item.origin, vulnbell::model::Origin::Declared);
    assert_eq!(item.resolved_version.as_deref(), Some("2.31.0"));
    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    assert!(page.codebase_files.is_empty());
    assert_eq!(page.summary.files_unavailable, 1);
    fs::write(&file, "requests==2.32.0\n").unwrap();
    let updated = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        updated.instances[0].resolved_version.as_deref(),
        Some("2.32.0")
    );
    assert!(updated.instances[0].purl.is_none());
    cleanup(store, &profile);
}

#[test]
fn pending_blocks_the_report_until_files_are_reviewed_and_components_have_a_source_disposition() {
    let (directory, path, mut profile, mut store) = project();
    profile.research.follow.push("pkg:pypi/requests".into());
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();
    fs::write(
        directory.path().join("workspace/dependencies.txt"),
        "requests==2.31.0\n",
    )
    .unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let unreviewed = cases::pending(&store).unwrap();
    assert!(!unreviewed.deliverable);
    let open = unreviewed.discovery_open.unwrap();
    assert!(open.directories_pending + open.files_pending > 0);

    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    discovery::import(&profile, &path, &mut store, review(&page, vec![package()])).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let unmapped = cases::pending(&store).unwrap();
    assert!(!unmapped.deliverable);
    let open = unmapped.discovery_open.unwrap();
    assert_eq!(
        (
            open.directories_pending,
            open.files_pending,
            open.components_unmapped
        ),
        (0, 0, 1)
    );

    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    let target = &page.components[0];
    let observation = IdentityObservation {
        instance_id: target.instance_id.clone(),
        fingerprint: target.fingerprint.clone(),
        version: None,
        cpe_product: None,
        rationale: "Synthetic fixture: no official source could be corroborated.".into(),
        sources: SOURCE_KINDS
            .iter()
            .map(|kind| SourceMapping {
                kind: *kind,
                state: MappingState::Unavailable,
                url: None,
                detail: "Synthetic fixture without public evidence.".into(),
                evidence: Vec::new(),
            })
            .collect(),
    };
    discovery::import(
        &profile,
        &path,
        &mut store,
        DiscoveryBatch::Sources {
            schema_version: 1,
            project_id: page.project_id.clone(),
            scope_sha256: page.scope_sha256.clone(),
            observations: vec![observation],
        },
    )
    .unwrap();
    assert_eq!(
        discovery::summary(&profile, &path, &store)
            .unwrap()
            .sources_unavailable,
        1
    );
    assert!(cases::pending(&store).unwrap().discovery_open.is_none());
    cleanup(store, &profile);
}

#[test]
fn matched_advisory_on_an_agent_observation_requires_identity_review() {
    let (directory, path, profile, mut store) = project();
    fs::write(
        directory.path().join("workspace/dependencies.txt"),
        "requests==2.31.0\n",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    discovery::import(&profile, &path, &mut store, review(&page, vec![package()])).unwrap();
    let query = serde_json::json!({"queries":[{"package":{"purl":"pkg:pypi/requests"},"version":"2.31.0"}]});
    for (method, url, body, response) in [
        (
            "POST",
            "https://api.osv.dev/v1/querybatch",
            query.to_string(),
            serde_json::json!({"results":[{"vulns":[{"id":"SYNTHETIC-OBSERVATION"}]}]}),
        ),
        (
            "GET",
            "https://api.osv.dev/v1/vulns/SYNTHETIC-OBSERVATION",
            String::new(),
            serde_json::json!({"id":"SYNTHETIC-OBSERVATION","summary":"Synthetic affected package claim"}),
        ),
    ] {
        let key = vulnbell::digest(format!("{method}:{url}:{body}").as_bytes());
        store
            .connection
            .execute(
                "INSERT INTO cache VALUES (?1,?2,NULL,?3)",
                rusqlite::params![
                    key,
                    serde_json::to_vec(&response).unwrap(),
                    chrono::Utc::now().timestamp()
                ],
            )
            .unwrap();
    }
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.cases.len(), 1);
    assert_eq!(
        snapshot.cases[0].decision,
        vulnbell::model::Decision::Review
    );
    assert_eq!(
        snapshot.cases[0].applicability,
        vulnbell::model::Applicability::Unknown
    );
    assert_eq!(
        snapshot.cases[0].verification,
        vulnbell::model::Verification::Inconclusive
    );
    cleanup(store, &profile);
}

#[test]
fn adding_a_workspace_keeps_reviews_of_the_existing_workspace() {
    let (directory, path, profile, mut store) = project();
    fs::write(
        directory.path().join("workspace/dependencies.txt"),
        "requests==2.31.0\n",
    )
    .unwrap();
    let page = discovery::plan(&profile, &path, &store, 1).unwrap();
    discovery::import(&profile, &path, &mut store, review(&page, vec![package()])).unwrap();
    let before = discovery::plan(&profile, &path, &store, 1).unwrap().summary;
    assert_eq!((before.files_pending, before.files_reviewed), (0, 1));
    fs::create_dir(directory.path().join("extra")).unwrap();
    fs::write(
        &path,
        format!(
            "schema: 1\nproject_id: {}\nname: general-discovery\ncodebases: [workspace, extra]\n",
            profile.project_id
        ),
    )
    .unwrap();
    let widened = profile::load(&path).unwrap();
    let page = discovery::plan(&widened, &path, &store, 1).unwrap();
    assert_ne!(
        page.scope_sha256,
        discovery::scope(&profile, &path).unwrap()
    );
    assert!(page.codebase_files.is_empty());
    assert_eq!(
        (page.summary.files_pending, page.summary.files_reviewed),
        (0, 1)
    );
    assert_eq!(page.summary.components_unmapped, before.components_unmapped);
    let snapshot = vulnbell::engine::scan(&widened, &path, true).unwrap();
    assert!(snapshot.instances.iter().any(|instance| {
        instance.reference == "pkg:pypi/requests"
            && instance.provenance.path.as_deref() == Some("dependencies.txt")
    }));
    cleanup(store, &widened);
}

#[path = "discovery/continuation.rs"]
mod continuation;
