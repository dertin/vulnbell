use super::*;
use std::io::Write;
use vulnbell::research::{
    ArtifactEvidence, ArtifactLocation, ArtifactScopeSource, InstalledWheelEvidence,
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
    .unwrap();
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
        installed_wheel: Some(InstalledWheelEvidence {
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
