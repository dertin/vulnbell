use super::*;
use std::io::Write;
use vulnbell::research::{
    ArtifactEvidence, ArtifactLocation, ArtifactScopeSource, InstalledScopeEvidence,
};

fn record_event(
    store: &mut Store,
    project: &str,
    assessment: Assessment,
    artifact: Option<ArtifactEvidence>,
) {
    record_event_with_id(store, project, 1, assessment, artifact);
}

fn record_event_with_id(
    store: &mut Store,
    project: &str,
    number: usize,
    assessment: Assessment,
    artifact: Option<ArtifactEvidence>,
) {
    try_record_event_with_id(store, project, number, assessment, artifact).unwrap();
}

fn try_record_event_with_id(
    store: &mut Store,
    project: &str,
    number: usize,
    assessment: Assessment,
    artifact: Option<ArtifactEvidence>,
) -> anyhow::Result<()> {
    let plan = vulnbell::research::plan_page(store, "", 20).unwrap();
    let target = plan
        .targets
        .iter()
        .find(|target| target.upstream == "https://github.com/example/project")
        .unwrap_or_else(|| panic!("target missing: {}", serde_json::to_string(&plan).unwrap()));
    let event = ResearchEvent {
        codebase_revisions: Vec::new(),
        upstream: target.upstream.clone(),
        instance_ids: target.instance_ids.clone(),
        reviewed_instance_ids: target.instance_ids.clone(),
        provider: "github".into(),
        external_id: format!("example/project#{number}"),
        kind: EventKind::PullRequest,
        url: format!("https://github.com/example/project/pull/{number}"),
        title: "Synthetic backend change".into(),
        excerpt: "Synthetic source context".into(),
        updated_at: target.until.clone(),
        assessment,
        not_applicable_reason: (assessment == Assessment::NotApplicable)
            .then_some(NotApplicableReason::ComponentNotInBuild),
        artifact_evidence: artifact,
        rationale: "The scoped installed build omits the affected native backend.".into(),
        source_facts: Default::default(),
    };
    vulnbell::research::import(
        store,
        ResearchBatch {
            schema_version: 1,
            project_id: project.into(),
            snapshot_id: plan.snapshot_id,
            sources: vec![SourceReview {
                recheck_context_sha256: None,
                upstream: target.upstream.clone(),
                from: target.from.clone(),
                until: target.until.clone(),
                coverage: ReviewCoverage::Partial,
                detail: "Synthetic review".into(),
                continuation: None,
            }],
            events: vec![event],
        },
    )
    .map(|_| ())
}

#[test]
fn installed_wheel_retraction_reopens_when_lock_appears_or_changes() {
    let directory = tempfile::tempdir().unwrap();
    let codebase = directory.path().join("app");
    fs::create_dir(&codebase).unwrap();
    fs::write(codebase.join("Dockerfile"), "COPY site /app/site\n").unwrap();
    let files = [
        ("example/__init__.py", "synthetic\n"),
        (
            "example-1.0.dist-info/METADATA",
            "Name: example\nVersion: 1.0\n",
        ),
        ("example-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n"),
        ("example-1.0.dist-info/RECORD", "synthetic\n"),
    ];
    let mut wheel =
        zip::ZipWriter::new(fs::File::create(directory.path().join("example.whl")).unwrap());
    for (name, contents) in files {
        wheel
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        wheel.write_all(contents.as_bytes()).unwrap();
        let target = codebase.join("site").join(name);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, contents).unwrap();
    }
    wheel.finish().unwrap();
    let digest = vulnbell::digest(&fs::read(directory.path().join("example.whl")).unwrap());
    let project = uuid::Uuid::new_v4().to_string();
    let profile_path = directory.path().join("vulnbell.yaml");
    fs::write(&profile_path, format!("schema: 1\nproject_id: {project}\nname: wheel-fixture\ndiscovery: off\ncodebases: [app]\npython:\n  verify_pypi_hashes: true\nresearch:\n  follow: [pkg:pypi/example]\ncomponents:\n  - ref: pkg:pypi/example\n    version: '1.0'\n    upstream: https://github.com/example/project\n")).unwrap();
    let mut store = Store::open(&project).unwrap();
    let url = "https://pypi.org/pypi/example/1.0/json";
    let key = vulnbell::digest(format!("GET:{url}:").as_bytes());
    let body = serde_json::json!({"info":{"name":"example","version":"1.0"},"urls":[{"digests":{"sha256":digest}}]});
    store
        .connection
        .execute(
            "INSERT INTO cache VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                key,
                serde_json::to_vec(&body).unwrap(),
                chrono::Utc::now().timestamp()
            ],
        )
        .unwrap();
    let profile = vulnbell::profile::load(&profile_path).unwrap();
    let initial = vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
    assert!(initial.instances[0].python_lock.is_none());
    record_event(&mut store, &project, Assessment::Informational, None);
    let mut case = store.cases().unwrap().remove(0);
    let case_id = case.case_id.clone();
    let note = store
        .record_evidence(
            b"The installed directory is the reviewed build scope.",
            "local_impact_evidence",
            None,
            vulnbell::model::EvidenceKind::Context,
        )
        .unwrap();
    case.evidence.push(note.clone());
    store.save_case(&case).unwrap();
    let artifact = ArtifactEvidence {
        instance_id: initial.instances[0].id.clone(),
        codebase: 0,
        location: ArtifactLocation::MonitorWorkspace,
        path: "example.whl".into(),
        sha256: digest.clone(),
        installed_wheel: Some(InstalledScopeEvidence {
            root: "site".into(),
            absent_paths: vec!["example/_native*.so".into()],
            scope_evidence_id: note.id,
            scope_complete: true,
            scope_source: ArtifactScopeSource {
                path: "Dockerfile".into(),
                line: 1,
                line_sha256: vulnbell::digest(b"COPY site /app/site"),
            },
        }),
        installed_archive: None,
    };
    record_event(
        &mut store,
        &project,
        Assessment::NotApplicable,
        Some(artifact.clone()),
    );
    assert_eq!(store.case(&case_id).unwrap().decision, Decision::Retracted);
    record_event_with_id(&mut store, &project, 2, Assessment::Informational, None);
    let mut second = store
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| {
            case.upstream_events
                .iter()
                .any(|event| event.url.ends_with("/2"))
        })
        .unwrap();
    let second_id = second.case_id.clone();
    let second_note = store
        .record_evidence(
            b"The same installed directory covers the second reviewed build condition.",
            "local_impact_evidence",
            None,
            vulnbell::model::EvidenceKind::Context,
        )
        .unwrap();
    second.evidence.push(second_note.clone());
    store.save_case(&second).unwrap();
    let mut second_artifact = artifact.clone();
    let second_scope = second_artifact.installed_wheel.as_mut().unwrap();
    second_scope.scope_evidence_id = second_note.id;
    second_scope.absent_paths = vec!["example/_other*.so".into()];
    record_event_with_id(
        &mut store,
        &project,
        2,
        Assessment::NotApplicable,
        Some(second_artifact),
    );
    assert_eq!(
        store.case(&second_id).unwrap().decision,
        Decision::Retracted
    );
    let mut current = store.latest().unwrap();
    current.cases = store.cases().unwrap();
    fs::write(
        codebase.join("site/example/_native.cpython-312.so"),
        b"synthetic",
    )
    .unwrap();
    let projected = vulnbell::research::project_retractions(&current, &store);
    assert_eq!(
        projected
            .cases
            .iter()
            .find(|case| case.case_id == case_id)
            .unwrap()
            .decision,
        Decision::Review
    );
    assert_eq!(
        projected
            .cases
            .iter()
            .find(|case| case.case_id == second_id)
            .unwrap()
            .decision,
        Decision::Retracted
    );
    fs::remove_file(codebase.join("site/example/_native.cpython-312.so")).unwrap();
    fs::write(codebase.join("Dockerfile"), "COPY other /app/site\n").unwrap();
    let projected = vulnbell::research::project_retractions(&current, &store);
    assert!(
        projected
            .cases
            .iter()
            .all(|case| case.decision == Decision::Review)
    );
    fs::write(codebase.join("Dockerfile"), "COPY site /app/site\n").unwrap();

    let lock = codebase.join("requirements.lock");
    fs::write(&lock, format!("example==1.0 --hash=sha256:{digest}\n")).unwrap();
    let with_lock = vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
    assert_eq!(with_lock.instances.len(), 1);
    assert_eq!(with_lock.instances[0].id, artifact.instance_id);
    assert!(with_lock.instances[0].python_lock.is_some());
    assert_eq!(store.case(&case_id).unwrap().decision, Decision::Review);
    record_event(
        &mut store,
        &project,
        Assessment::NotApplicable,
        Some(artifact.clone()),
    );
    assert_eq!(store.case(&case_id).unwrap().decision, Decision::Retracted);

    fs::write(
        &lock,
        format!(
            "example==1.0 --hash=sha256:{digest} --hash=sha256:{}\n",
            "a".repeat(64)
        ),
    )
    .unwrap();
    vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
    assert_eq!(store.case(&case_id).unwrap().decision, Decision::Review);
    record_event(
        &mut store,
        &project,
        Assessment::NotApplicable,
        Some(artifact),
    );
    assert_eq!(store.case(&case_id).unwrap().decision, Decision::Retracted);
    fs::remove_file(&lock).unwrap();
    vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
    assert_eq!(store.case(&case_id).unwrap().decision, Decision::Review);
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn locked_package_retractions_reopen_after_lock_or_installed_content_changes() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha512};
    use vulnbell::research::{ArchiveEcosystem, InstalledArchiveEvidence};

    for ecosystem in [ArchiveEcosystem::Cargo, ArchiveEcosystem::Npm] {
        let directory = tempfile::tempdir().unwrap();
        let codebase = directory.path().join("app");
        fs::create_dir(&codebase).unwrap();
        fs::write(codebase.join("Dockerfile"), "COPY packages /app\n").unwrap();
        let (prefix, manifest_path, manifest, installed) = match ecosystem {
            ArchiveEcosystem::Cargo => (
                "example-1.0.0/",
                "Cargo.toml",
                "[package]\nname = 'example'\nversion = '1.0.0'\n",
                "packages/example",
            ),
            ArchiveEcosystem::Npm => (
                "package/",
                "package.json",
                "{\"name\":\"example\",\"version\":\"1.0.0\"}",
                "node_modules/example",
            ),
        };
        let file = fs::File::create(codebase.join("package.tgz")).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, contents) in [(manifest_path, manifest), ("src/lib.txt", "synthetic\n")] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, format!("{prefix}{path}"), contents.as_bytes())
                .unwrap();
            let target = codebase.join(installed).join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, contents).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
        let bytes = fs::read(codebase.join("package.tgz")).unwrap();
        let digest = vulnbell::digest(&bytes);
        let (lock_path, lock_contents) = match ecosystem {
            ArchiveEcosystem::Cargo => ("Cargo.lock", format!("version = 4\n[[package]]\nname = 'example'\nversion = '1.0.0'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\nchecksum = '{digest}'\n")),
            ArchiveEcosystem::Npm => ("package-lock.json", serde_json::json!({"lockfileVersion": 3, "packages": {"node_modules/example": {"version":"1.0.0", "integrity":format!("sha512-{}",STANDARD.encode(Sha512::digest(&bytes)))}}}).to_string()),
        };
        fs::write(codebase.join(lock_path), &lock_contents).unwrap();
        let project = uuid::Uuid::new_v4().to_string();
        let profile_path = directory.path().join("vulnbell.yaml");
        fs::write(&profile_path, format!("schema: 1\nproject_id: {project}\nname: package-fixture\ndiscovery: off\ncodebases: [app]\nresearch:\n  tracker_scope: all\n")).unwrap();
        let profile = vulnbell::profile::load(&profile_path).unwrap();
        let mut snapshot = vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
        assert_eq!(snapshot.instances.len(), 1);
        snapshot.instances[0].upstream = Some("https://github.com/example/project".into());
        snapshot.id = uuid::Uuid::new_v4().to_string();
        let mut store = Store::open(&project).unwrap();
        store.save_snapshot(&snapshot).unwrap();
        record_event(&mut store, &project, Assessment::Informational, None);
        let mut case = store.cases().unwrap().remove(0);
        let case_id = case.case_id.clone();
        let note = store
            .record_evidence(
                b"The installed source represents the reviewed build scope.",
                "local_impact_evidence",
                None,
                vulnbell::model::EvidenceKind::Context,
            )
            .unwrap();
        case.evidence.push(note.clone());
        store.save_case(&case).unwrap();
        let artifact = ArtifactEvidence {
            instance_id: snapshot.instances[0].id.clone(),
            codebase: 0,
            location: ArtifactLocation::Codebase,
            path: "package.tgz".into(),
            sha256: digest,
            installed_wheel: None,
            installed_archive: Some(InstalledArchiveEvidence {
                ecosystem,
                scope: InstalledScopeEvidence {
                    root: installed.into(),
                    absent_paths: vec!["src/missing.rs".into()],
                    scope_evidence_id: note.id,
                    scope_complete: true,
                    scope_source: ArtifactScopeSource {
                        path: "Dockerfile".into(),
                        line: 1,
                        line_sha256: vulnbell::digest(b"COPY packages /app"),
                    },
                },
            }),
        };
        record_event_with_id(&mut store, &project, 99, Assessment::Ignore, None);
        let (key, body): (String, String) = store
            .connection
            .query_row(
                "SELECT key, body FROM research_events WHERE external_id=?1",
                ["example/project#99"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let mut prior: ResearchEvent = serde_json::from_str(&body).unwrap();
        prior.assessment = Assessment::NotApplicable;
        prior.not_applicable_reason = Some(NotApplicableReason::ComponentNotInBuild);
        store
            .connection
            .execute(
                "UPDATE research_events SET body=?1 WHERE key=?2",
                rusqlite::params![serde_json::to_string(&prior).unwrap(), key],
            )
            .unwrap();
        let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
        let target = &plan.targets[0];
        let repeated = ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id.clone(),
            sources: vec![SourceReview {
                recheck_context_sha256: None,
                upstream: target.upstream.clone(),
                from: target.from.clone(),
                until: target.until.clone(),
                coverage: ReviewCoverage::Partial,
                detail: "Synthetic review".into(),
                continuation: None,
            }],
            events: vec![prior],
        };
        let error = vulnbell::research::import(&mut store, repeated).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("registered artifact and scope evidence"),
            "{error:#}"
        );
        let error =
            try_record_event_with_id(&mut store, &project, 99, Assessment::NotApplicable, None)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("registered artifact and scope evidence"),
            "{error:#}"
        );
        let mut unavailable = artifact.clone();
        unavailable.path = "missing.tgz".into();
        let error = try_record_event_with_id(
            &mut store,
            &project,
            99,
            Assessment::NotApplicable,
            Some(unavailable),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("registered scope note"),
            "{error:#}"
        );
        let mut invalid = artifact.clone();
        invalid
            .installed_archive
            .as_mut()
            .unwrap()
            .scope
            .absent_paths = vec!["src/lib.txt".into()];
        let error = try_record_event_with_id(
            &mut store,
            &project,
            1,
            Assessment::NotApplicable,
            Some(invalid),
        )
        .unwrap_err();
        assert!(error.to_string().contains("claimed absent"), "{error:#}");
        if ecosystem == ArchiveEcosystem::Npm {
            let mut altered = bytes.clone();
            altered.push(1);
            fs::write(codebase.join("package.tgz"), &altered).unwrap();
            let mut invalid = artifact.clone();
            invalid.sha256 = vulnbell::digest(&altered);
            let error = try_record_event_with_id(
                &mut store,
                &project,
                1,
                Assessment::NotApplicable,
                Some(invalid),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("npm archive integrity"),
                "{error:#}"
            );
            fs::write(codebase.join("package.tgz"), &bytes).unwrap();
        }
        record_event(
            &mut store,
            &project,
            Assessment::NotApplicable,
            Some(artifact),
        );
        assert_eq!(store.case(&case_id).unwrap().decision, Decision::Retracted);
        let mut current = store.latest().unwrap();
        current.cases = store.cases().unwrap();
        fs::write(codebase.join(installed).join("src/lib.txt"), "changed\n").unwrap();
        assert_eq!(
            vulnbell::research::project_retractions(&current, &store).cases[0].decision,
            Decision::Review
        );
        fs::write(codebase.join(installed).join("src/lib.txt"), "synthetic\n").unwrap();
        let updated_lock = match ecosystem {
            ArchiveEcosystem::Cargo => {
                lock_contents.replace(&vulnbell::digest(&bytes), &"a".repeat(64))
            }
            ArchiveEcosystem::Npm => lock_contents.replace(
                &STANDARD.encode(Sha512::digest(&bytes)),
                &STANDARD.encode([1_u8; 64]),
            ),
        };
        fs::write(codebase.join(lock_path), updated_lock).unwrap();
        vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
        assert_ne!(store.case(&case_id).unwrap().decision, Decision::Retracted);
        drop(store);
        fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
    }
}
