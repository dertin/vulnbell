use super::*;
use crate::{
    codebase_revision,
    research::{ArtifactLocation, ArtifactScopeSource, InstalledScopeEvidence},
    store::Store,
};
use std::{fs, io::Write};

struct TestStore {
    store: Option<Store>,
    path: std::path::PathBuf,
}

impl std::ops::Deref for TestStore {
    type Target = Store;
    fn deref(&self) -> &Store {
        self.store.as_ref().unwrap()
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        drop(self.store.take());
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

fn fixture(
    ecosystem: ArchiveEcosystem,
) -> (tempfile::TempDir, TestStore, Snapshot, ArtifactEvidence) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let root = root.as_path();
    fs::write(root.join("Dockerfile"), "COPY packages /app\n").unwrap();
    let (prefix, package, manifest_path, manifest, install_root, resolution) = match ecosystem {
        ArchiveEcosystem::Cargo => (
            "example-1.0.0/",
            "pkg:cargo/example",
            "Cargo.toml",
            "[package]\nname = 'example'\nversion = '1.0.0'\n",
            "packages/example",
            "registry+https://github.com/rust-lang/crates.io-index",
        ),
        ArchiveEcosystem::Npm => (
            "package/",
            "pkg:npm/example",
            "package.json",
            "{\"name\":\"example\",\"version\":\"1.0.0\"}",
            "node_modules/example",
            "node_modules/example",
        ),
    };
    let archive_path = root.join("package.tgz");
    let file = fs::File::create(&archive_path).unwrap();
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    for (name, content) in [
        (manifest_path, manifest),
        ("src/lib.txt", "package source\n"),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, format!("{prefix}{name}"), content.as_bytes())
            .unwrap();
        let target = root.join(install_root).join(name);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, content).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
    let bytes = fs::read(&archive_path).unwrap();
    let sha256 = crate::digest(&bytes);
    let integrity = match ecosystem {
        ArchiveEcosystem::Cargo => sha256.clone(),
        ArchiveEcosystem::Npm => format!("sha512-{}", STANDARD.encode(Sha512::digest(&bytes))),
    };
    let project_id = uuid::Uuid::new_v4().to_string();
    let store = TestStore {
        store: Some(Store::open(&project_id).unwrap()),
        path: crate::store::data_root().join(&project_id),
    };
    let (lock_name, lock) = match ecosystem {
        ArchiveEcosystem::Cargo => ("Cargo.lock", format!("version = 4\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\nsource = \"{resolution}\"\nchecksum = \"{integrity}\"\n")),
        ArchiveEcosystem::Npm => ("package-lock.json", serde_json::json!({"lockfileVersion": 3, "packages": {"node_modules/example": {"version": "1.0.0", "integrity": integrity}}}).to_string()),
    };
    fs::write(root.join(lock_name), lock).unwrap();
    let codebase = root.to_str().unwrap().to_owned();
    let inventory = crate::inventory::discover(
        std::slice::from_ref(&codebase),
        &root.join("vulnbell.yaml"),
        &store,
        100,
    );
    let instance = inventory
        .instances
        .into_iter()
        .find(|item| {
            item.purl
                .as_deref()
                .is_some_and(|purl| purl.starts_with(package))
        })
        .expect("package must be discovered from its lock");
    let snapshot = Snapshot {
        schema_version: 1,
        id: "snapshot".into(),
        project_id,
        profile_sha256: String::new(),
        started_at: String::new(),
        finished_at: String::new(),
        codebase_revisions: vec![codebase_revision::capture_path(root)],
        instances: vec![instance.clone()],
        coverage: Vec::new(),
        cases: Vec::new(),
        partial: false,
        alert_status: String::new(),
    };
    let artifact = ArtifactEvidence {
        instance_id: instance.id,
        codebase: 0,
        location: ArtifactLocation::Codebase,
        path: "package.tgz".into(),
        sha256,
        installed_wheel: None,
        installed_archive: Some(InstalledArchiveEvidence {
            ecosystem,
            scope: InstalledScopeEvidence {
                root: install_root.into(),
                absent_paths: vec!["src/missing.rs".into()],
                scope_evidence_id: "note".into(),
                scope_complete: true,
                scope_source: ArtifactScopeSource {
                    path: "Dockerfile".into(),
                    line: 1,
                    line_sha256: crate::digest(b"COPY packages /app"),
                },
            },
        }),
    };
    (directory, store, snapshot, artifact)
}

#[test]
fn cargo_and_npm_require_exact_archive_and_installed_content() {
    for ecosystem in [ArchiveEcosystem::Cargo, ArchiveEcosystem::Npm] {
        let (dir, store, mut snapshot, artifact) = fixture(ecosystem);
        let scope = artifact.installed_archive.as_ref().unwrap();
        let verified = super::super::validation::verify_artifact_content(
            &artifact,
            &snapshot,
            std::slice::from_ref(&artifact.instance_id),
            &store,
        )
        .unwrap();
        super::super::validation::verify_artifact_scope(&artifact, &snapshot, &verified).unwrap();
        fs::write(
            dir.path().join(&scope.scope.root).join("src/lib.txt"),
            "changed",
        )
        .unwrap();
        assert!(
            super::super::validation::verify_artifact_content(
                &artifact,
                &snapshot,
                std::slice::from_ref(&artifact.instance_id),
                &store
            )
            .is_err()
        );
        fs::write(
            dir.path().join(&scope.scope.root).join("src/lib.txt"),
            "package source\n",
        )
        .unwrap();
        snapshot.instances[0].provenance.artifact_integrity = Some("changed".into());
        assert!(
            super::super::validation::verify_artifact_content(
                &artifact,
                &snapshot,
                std::slice::from_ref(&artifact.instance_id),
                &store
            )
            .is_err()
        );
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("package.tgz"))
            .unwrap();
        file.write_all(b"changed").unwrap();
        assert!(
            super::super::validation::verify_artifact_content(
                &artifact,
                &snapshot,
                std::slice::from_ref(&artifact.instance_id),
                &store
            )
            .is_err()
        );
    }
}

#[test]
fn archive_cannot_override_a_present_path_or_wrong_scope() {
    let (dir, store, snapshot, mut artifact) = fixture(ArchiveEcosystem::Npm);
    let verified = super::super::validation::verify_artifact_content(
        &artifact,
        &snapshot,
        std::slice::from_ref(&artifact.instance_id),
        &store,
    )
    .unwrap();
    artifact
        .installed_archive
        .as_mut()
        .unwrap()
        .scope
        .absent_paths = vec!["src/lib.txt".into()];
    assert!(
        super::super::validation::verify_artifact_scope(&artifact, &snapshot, &verified).is_err()
    );
    artifact.installed_archive.as_mut().unwrap().scope.root = "other".into();
    fs::create_dir(dir.path().join("other")).unwrap();
    assert!(
        super::super::validation::verify_artifact_content(
            &artifact,
            &snapshot,
            std::slice::from_ref(&artifact.instance_id),
            &store
        )
        .is_err()
    );
}

#[test]
fn rejects_archive_with_too_many_root_headers() {
    let (dir, store, mut snapshot, mut artifact) = fixture(ArchiveEcosystem::Cargo);
    let file = fs::File::create(dir.path().join("package.tgz")).unwrap();
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut tar = tar::Builder::new(encoder);
    for _ in 0..=MAX_FILES {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        tar.append_data(&mut header, "example-1.0.0/", &[][..])
            .unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
    let bytes = fs::read(dir.path().join("package.tgz")).unwrap();
    artifact.sha256 = crate::digest(&bytes);
    snapshot.instances[0].provenance.artifact_integrity = Some(artifact.sha256.clone());
    let error = super::super::validation::verify_artifact_content(
        &artifact,
        &snapshot,
        std::slice::from_ref(&artifact.instance_id),
        &store,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("entry limit"), "{error:#}");
}

#[test]
fn lock_and_installation_must_both_remain_current() {
    let (_dir, store, mut snapshot, artifact) = fixture(ArchiveEcosystem::Cargo);
    let verify = |snapshot: &Snapshot| {
        super::super::validation::verify_artifact_content(
            &artifact,
            snapshot,
            std::slice::from_ref(&artifact.instance_id),
            &store,
        )
    };
    assert!(verify(&snapshot).is_ok());
    snapshot.instances[0].origin = Origin::Declared;
    assert!(verify(&snapshot).is_err());
    snapshot.instances[0].origin = Origin::Locked;
    assert!(verify(&snapshot).is_ok());
    snapshot.instances[0].provenance.artifact_integrity = Some("f".repeat(64));
    assert!(verify(&snapshot).is_err());
}

#[test]
fn rejects_archive_links_and_another_codebase() {
    let (dir, store, mut snapshot, mut artifact) = fixture(ArchiveEcosystem::Cargo);
    let another = tempfile::tempdir().unwrap();
    snapshot.instances[0].provenance.codebase = Some(
        another
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );
    assert!(
        super::super::validation::verify_artifact_content(
            &artifact,
            &snapshot,
            std::slice::from_ref(&artifact.instance_id),
            &store
        )
        .is_err()
    );
    snapshot.instances[0].provenance.codebase = Some(
        dir.path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );
    let file = fs::File::create(dir.path().join("package.tgz")).unwrap();
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("target").unwrap();
    header.set_cksum();
    tar.append_data(&mut header, "example-1.0.0/src/link", &[][..])
        .unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    artifact.sha256 = crate::digest(&fs::read(dir.path().join("package.tgz")).unwrap());
    snapshot.instances[0].provenance.artifact_integrity = Some(artifact.sha256.clone());
    let error = super::super::validation::verify_artifact_content(
        &artifact,
        &snapshot,
        std::slice::from_ref(&artifact.instance_id),
        &store,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("unsupported entry"), "{error:#}");
}
