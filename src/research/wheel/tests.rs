use crate::{
    codebase_revision,
    model::{
        Applicability, Case, Decision, EvidenceKind, Instance, Origin, SandboxAvailability,
        Snapshot, Verification,
    },
    profile::Component,
    research::{ArtifactEvidence, InstalledScopeEvidence, validation},
    store::Store,
};
use std::{fs, io::Write};

struct Fixture {
    directory: tempfile::TempDir,
    project: String,
    store: Store,
    snapshot: Snapshot,
    case: Case,
    artifact: ArtifactEvidence,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("Dockerfile"), "COPY site /app/site\n").unwrap();
        let files = [
            ("example/__init__.py", "synthetic\n"),
            (
                "example-1.0.dist-info/METADATA",
                "Name: example\nVersion: 1.0\n",
            ),
            ("example-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n"),
            ("example-1.0.dist-info/RECORD", "synthetic\n"),
        ];
        let file = fs::File::create(root.join("example.whl")).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (path, content) in files {
            writer
                .start_file(path, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(content.as_bytes()).unwrap();
            let target = root.join("site").join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, content).unwrap();
        }
        writer.finish().unwrap();
        let digest = crate::digest(&fs::read(root.join("example.whl")).unwrap());
        let project = uuid::Uuid::new_v4().to_string();
        let store = Store::open(&project).unwrap();
        let registry = store.record_evidence(
            serde_json::json!({"info":{"name":"example","version":"1.0"},"urls":[{"digests":{"sha256":digest}}]}).to_string().as_bytes(),
            "registry", Some("https://pypi.org/pypi/example/1.0/json".into()), EvidenceKind::Identity,
        ).unwrap();
        let note = store.record_evidence(
            b"The site directory is the reviewed build output, as documented in the build configuration.",
            "local_impact_evidence", None, EvidenceKind::Context,
        ).unwrap();
        let mut instance = Instance::declared(&Component {
            reference: "pkg:pypi/example".into(),
            version: Some("1.0".into()),
            usage: Default::default(),
            upstream: None,
            feeds: Vec::new(),
        });
        instance.purl = Some("pkg:pypi/example".into());
        instance.identity_evidence.push(registry);
        let snapshot = Snapshot {
            schema_version: 1,
            id: "snapshot".into(),
            project_id: project.clone(),
            profile_sha256: "profile".into(),
            started_at: crate::now(),
            finished_at: crate::now(),
            codebase_revisions: vec![codebase_revision::capture_path(root)],
            instances: vec![instance.clone()],
            coverage: Vec::new(),
            cases: Vec::new(),
            partial: false,
            alert_status: "none".into(),
        };
        let case = Case {
            schema_version: 1,
            case_id: "SIG-fixture".into(),
            project_id: project.clone(),
            snapshot_id: snapshot.id.clone(),
            codebase_revisions: snapshot.codebase_revisions.clone(),
            instances: vec![instance.clone()],
            claims: Vec::new(),
            upstream_events: Vec::new(),
            evidence: vec![note.clone()],
            coverage: Vec::new(),
            applicability: Applicability::Unknown,
            verification: Verification::Inconclusive,
            decision: Decision::Informational,
            facts_sha256: "fixture".into(),
            open_questions: Vec::new(),
            suggested_search_queries: Vec::new(),
            sandbox: SandboxAvailability {
                available: false,
                reason: "fixture".into(),
            },
            updated_at: crate::now(),
        };
        let artifact = ArtifactEvidence {
            instance_id: instance.id,
            codebase: 0,
            location: crate::research::ArtifactLocation::Codebase,
            path: "example.whl".into(),
            sha256: digest,
            installed_wheel: Some(InstalledScopeEvidence {
                root: "site".into(),
                absent_paths: vec!["example/native_backend".into()],
                scope_evidence_id: note.id,
                scope_complete: true,
                scope_source: crate::research::ArtifactScopeSource {
                    path: "Dockerfile".into(),
                    line: 1,
                    line_sha256: crate::digest(b"COPY site /app/site"),
                },
            }),
            installed_archive: None,
        };
        Self {
            directory,
            project,
            store,
            snapshot,
            case,
            artifact,
        }
    }

    fn verify(&self) -> anyhow::Result<()> {
        validation::verify_scope_evidence(&self.artifact, &self.case, &self.store)?;
        let verified = validation::verify_artifact_content(
            &self.artifact,
            &self.snapshot,
            std::slice::from_ref(&self.artifact.instance_id),
            &self.store,
        )?;
        validation::verify_artifact_scope(&self.artifact, &self.snapshot, &verified)
    }

    fn close(self) {
        drop(self.store);
        fs::remove_dir_all(crate::store::data_root().join(self.project)).unwrap();
    }
}

#[test]
fn verified_installed_wheel_works_without_a_lock_and_requires_current_scope() {
    let mut fixture = Fixture::new();
    assert!(fixture.verify().is_ok());
    fs::write(
        fixture.directory.path().join("Dockerfile"),
        "COPY other /app/site\n",
    )
    .unwrap();
    assert!(fixture.verify().is_err());
    fs::write(
        fixture.directory.path().join("Dockerfile"),
        "COPY site /app/site\n",
    )
    .unwrap();
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .scope_complete = false;
    assert!(fixture.verify().is_err());
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .scope_complete = true;
    fixture.case.evidence.clear();
    assert!(fixture.verify().is_err());
    fixture.close();
}

#[test]
fn wheel_verification_rejects_changed_files_present_paths_and_unsafe_paths() {
    let mut fixture = Fixture::new();
    assert!(fixture.verify().is_ok());
    fs::write(
        fixture.directory.path().join("site/example/__init__.py"),
        "changed\n",
    )
    .unwrap();
    assert!(fixture.verify().is_err());
    fs::write(
        fixture.directory.path().join("site/example/__init__.py"),
        "synthetic\n",
    )
    .unwrap();
    fs::create_dir(fixture.directory.path().join("site/example/native_backend")).unwrap();
    assert!(fixture.verify().is_err());
    fs::remove_dir(fixture.directory.path().join("site/example/native_backend")).unwrap();
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .absent_paths = vec!["../outside".into()];
    assert!(fixture.verify().is_err());
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .absent_paths = vec!["unrelated/file".into()];
    assert!(fixture.verify().is_err());
    fixture.close();
}

#[test]
fn absent_extension_pattern_checks_all_names_in_the_package_directory() {
    let mut fixture = Fixture::new();
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .absent_paths = vec!["example/_message*.so".into()];
    assert!(fixture.verify().is_ok());
    fs::write(
        fixture
            .directory
            .path()
            .join("site/example/_message.cpython-312.so"),
        "synthetic",
    )
    .unwrap();
    assert!(fixture.verify().is_err());
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .absent_paths = vec!["example/*/file.so".into()];
    assert!(fixture.verify().is_err());
    fixture.close();
}

#[test]
fn lock_appearing_or_changing_must_match_the_same_wheel() {
    let mut fixture = Fixture::new();
    assert!(fixture.verify().is_ok());
    fixture.snapshot.instances[0].origin = Origin::Locked;
    fixture.snapshot.instances[0].python_lock = Some(crate::model::PythonLock {
        sha256: vec![fixture.artifact.sha256.clone()],
        source_eligible: true,
        via: Vec::new(),
        via_complete: false,
        direct_source: None,
    });
    assert!(fixture.verify().is_ok());
    fixture.snapshot.instances[0]
        .python_lock
        .as_mut()
        .unwrap()
        .sha256 = vec!["a".repeat(64)];
    assert!(fixture.verify().is_err());
    fixture.close();
}

#[test]
fn registry_identity_and_artifact_digest_are_required() {
    let mut fixture = Fixture::new();
    fixture.snapshot.instances[0].identity_evidence.clear();
    assert!(fixture.verify().is_err());
    fixture.snapshot.instances[0].origin = Origin::Deployed;
    fixture.snapshot.instances[0].provenance.sha256 = fixture.artifact.sha256.clone();
    assert!(fixture.verify().is_err());
    fixture.close();
}

#[test]
fn shared_wheel_is_checked_once_per_pass_and_changes_reopen_each_case() {
    use crate::research::{Assessment, EventKind, NotApplicableReason, ResearchEvent, retraction};
    let fixture = Fixture::new();
    let second_note = fixture
        .store
        .record_evidence(
            b"The second observation uses the same verified build output.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let first_artifact = fixture.artifact.clone();
    let mut second_artifact = first_artifact.clone();
    let second_scope = second_artifact.installed_wheel.as_mut().unwrap();
    second_scope.scope_evidence_id = second_note.id.clone();
    second_scope.absent_paths = vec!["example/_other*.so".into()];
    let make_case = |artifact: ArtifactEvidence| {
        let event = ResearchEvent {
            upstream: "https://github.com/example/project".into(),
            codebase_revisions: Vec::new(),
            instance_ids: vec![artifact.instance_id.clone()],
            reviewed_instance_ids: vec![artifact.instance_id.clone()],
            provider: "github".into(),
            external_id: "example/project#1".into(),
            kind: EventKind::PullRequest,
            url: "https://github.com/example/project/pull/1".into(),
            title: "Synthetic".into(),
            excerpt: "Synthetic".into(),
            updated_at: crate::now(),
            assessment: Assessment::NotApplicable,
            not_applicable_reason: Some(NotApplicableReason::ComponentNotInBuild),
            artifact_evidence: Some(artifact),
            rationale: "A scoped component is absent.".into(),
            source_facts: Default::default(),
        };
        let recorded = fixture
            .store
            .record_evidence(
                &serde_json::to_vec(&event).unwrap(),
                "agent_retraction_assessment",
                Some(event.url.clone()),
                EvidenceKind::Context,
            )
            .unwrap();
        let mut case = fixture.case.clone();
        case.decision = Decision::Retracted;
        case.evidence.push(second_note.clone());
        case.evidence.push(recorded);
        case
    };
    let first = make_case(first_artifact);
    let second = make_case(second_artifact);
    let mut cache = retraction::RetractionCache::default();
    validation::reset_content_verifications();
    for case in [&first, &second] {
        assert!(retraction::retraction_valid_cached(
            case,
            &fixture.snapshot.instances,
            &fixture.snapshot.codebase_revisions,
            &fixture.store,
            &mut cache
        ));
    }
    assert_eq!(validation::content_verifications(), 1);
    fs::write(
        fixture.directory.path().join("site/example/__init__.py"),
        "changed\n",
    )
    .unwrap();
    cache.refresh(&fixture.snapshot, &fixture.store);
    assert_eq!(validation::content_verifications(), 2);
    for case in [&first, &second] {
        assert!(!retraction::retraction_valid_cached(
            case,
            &fixture.snapshot.instances,
            &fixture.snapshot.codebase_revisions,
            &fixture.store,
            &mut cache
        ));
    }
    fixture.close();
}

#[test]
fn unsupported_wheel_relocation_is_not_treated_as_verified() {
    let fixture = Fixture::new();
    let mut writer = zip::ZipWriter::new(
        fs::File::create(fixture.directory.path().join("example.whl")).unwrap(),
    );
    writer
        .start_file(
            "example-1.0.data/scripts/example",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(b"synthetic").unwrap();
    writer.finish().unwrap();
    let installed = fixture.artifact.installed_wheel.as_ref().unwrap();
    assert!(
        super::verify(
            &fixture.artifact,
            installed,
            &fixture.snapshot,
            &fixture.store
        )
        .is_err()
    );
    fixture.close();
}

#[test]
fn wheel_with_duplicate_entry_names_is_rejected() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("example.whl");
    let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
    for name in ["example/__init__.py", "example/__init__.pX"] {
        writer
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"synthetic\n").unwrap();
    }
    writer.finish().unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let original = b"example/__init__.pX";
    let replacement = b"example/__init__.py";
    let mut replacements = 0;
    for index in 0..=bytes.len() - original.len() {
        if bytes[index..].starts_with(original) {
            bytes[index..index + original.len()].copy_from_slice(replacement);
            replacements += 1;
        }
    }
    assert_eq!(replacements, 2);
    fs::write(&path, bytes).unwrap();
    let installed = fixture.artifact.installed_wheel.as_ref().unwrap();
    let error = super::verify(
        &fixture.artifact,
        installed,
        &fixture.snapshot,
        &fixture.store,
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate"), "{error:#}");
    fixture.close();
}

#[test]
fn wheel_entry_limit_is_checked_before_entry_loading() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("example.whl");
    let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
    for index in 0..=super::MAX_FILES {
        writer
            .start_file(
                format!("entry-{index}"),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
    }
    writer.finish().unwrap();
    let installed = fixture.artifact.installed_wheel.as_ref().unwrap();
    let error = super::verify(
        &fixture.artifact,
        installed,
        &fixture.snapshot,
        &fixture.store,
    )
    .unwrap_err();
    assert!(error.to_string().contains("entry limit"), "{error:#}");
    fixture.close();
}

#[test]
fn wheel_with_undercounted_central_directory_is_rejected() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("example.whl");
    let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
    for name in ["example/__init__.py", "example/_native.so"] {
        writer
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"synthetic\n").unwrap();
    }
    writer.finish().unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let end = bytes
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .unwrap();
    bytes[end + 8..end + 10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[end + 10..end + 12].copy_from_slice(&1_u16.to_le_bytes());
    fs::write(&path, bytes).unwrap();
    let installed = fixture.artifact.installed_wheel.as_ref().unwrap();
    let error = super::verify(
        &fixture.artifact,
        installed,
        &fixture.snapshot,
        &fixture.store,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("count does not match"),
        "{error:#}"
    );
    fixture.close();
}

#[test]
fn oversized_absent_paths_and_wheel_entry_names_are_rejected() {
    let mut fixture = Fixture::new();
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .absent_paths = vec![format!("example/{}", "a".repeat(super::MAX_PATH_BYTES))];
    assert!(fixture.verify().is_err());
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .absent_paths = vec!["example/missing".into()];
    let path = fixture.directory.path().join("example.whl");
    let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
    writer
        .add_directory(
            format!("{}/", "x".repeat(super::MAX_PATH_BYTES)),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    writer.finish().unwrap();
    let installed = fixture.artifact.installed_wheel.as_ref().unwrap();
    let error = super::verify(
        &fixture.artifact,
        installed,
        &fixture.snapshot,
        &fixture.store,
    )
    .unwrap_err();
    assert!(error.to_string().contains("paths exceed"), "{error:#}");
    fixture.close();
}

#[test]
fn aggregate_wheel_entry_names_are_bounded() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("example.whl");
    let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
    let prefix = format!("{}/", "x".repeat(200)).repeat(20);
    let count = super::MAX_TOTAL_NAME_BYTES / prefix.len() + 2;
    for index in 0..count {
        writer
            .add_directory(
                format!("{prefix}{index:06}/"),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
    }
    writer.finish().unwrap();
    let installed = fixture.artifact.installed_wheel.as_ref().unwrap();
    let error = super::verify(
        &fixture.artifact,
        installed,
        &fixture.snapshot,
        &fixture.store,
    )
    .unwrap_err();
    assert!(error.to_string().contains("paths exceed"), "{error:#}");
    fixture.close();
}

#[test]
fn scope_source_and_package_version_are_bound_to_the_observation() {
    let mut fixture = Fixture::new();
    fixture.snapshot.instances[0].resolved_version = Some("2.0".into());
    assert!(fixture.verify().is_err());
    fixture.snapshot.instances[0].resolved_version = Some("1.0".into());
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .scope_source
        .line_sha256 = "a".repeat(64);
    assert!(fixture.verify().is_err());
    fixture.close();
}

#[cfg(unix)]
#[test]
fn absence_check_rejects_symlinks() {
    let mut fixture = Fixture::new();
    std::os::unix::fs::symlink(
        fixture.directory.path(),
        fixture.directory.path().join("site/example/link"),
    )
    .unwrap();
    fixture
        .artifact
        .installed_wheel
        .as_mut()
        .unwrap()
        .absent_paths = vec!["example/link/missing".into()];
    assert!(fixture.verify().is_err());
    fixture.close();
}
