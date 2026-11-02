use super::*;

#[test]
fn reports_use_one_path_mapping_for_current_and_historical_codebases() {
    use vulnbell::codebase_revision::{CodebaseRevision, RepositoryState};
    let project = uuid::Uuid::new_v4().to_string();
    let store = Store::open(&project).unwrap();
    let revision = |path: &str| CodebaseRevision {
        codebase: path.into(),
        state: RepositoryState::NotGit,
        repository: Some("/unrelated/repository".into()),
        branch: None,
        commit: None,
        dirty: None,
        worktree_status_sha256: None,
        observed_at: vulnbell::now(),
    };
    let instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:cargo/example".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let note = store
        .record_evidence(
            b"Reviewed /home/alex/archive/src/old.rs:17 and /unrelated/repository/file.rs:3",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let case = Case {
        schema_version: 1,
        case_id: "SIG-historical".into(),
        project_id: project.clone(),
        snapshot_id: "snapshot".into(),
        codebase_revisions: vec![revision("/home/alex/archive")],
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: vec![note.clone()],
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "not run".into(),
        },
        updated_at: vulnbell::now(),
    };
    let snapshot = Snapshot {
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        codebase_revisions: vec![revision("/home/alex/current")],
        instances: vec![instance],
        cases: vec![case.clone()],
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    let standard = vulnbell::output::morning_markdown(&report).unwrap();
    let link = "[VulnBell](https://github.com/dertin/vulnbell)";
    assert!(standard.starts_with(&format!("# {link}")));
    assert!(standard.ends_with(&format!("*Generated with {link}.*\n")));
    let audit = vulnbell::output::audit_markdown(&snapshot, &store).unwrap();
    assert!(audit.starts_with(&format!("# {link}")));
    assert!(audit.ends_with(&format!("*Generated with {link}.*\n")));
    assert!(
        serde_json::to_value(&report)
            .unwrap()
            .get("codebase_path_roots")
            .is_none()
    );
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(markdown.contains("current-2"));
    let custom = vulnbell::output::normalize_report_paths(
        &report,
        &format!("{markdown}\nCurrent /home/alex/current/src/live.rs:4"),
    )
    .unwrap();
    assert!(custom.contains("current-2/src/live.rs:4"));
    let body = vulnbell::output::pdf_report_body(&custom, &report).unwrap();
    let document = vulnbell::output::prepared_pdf_markdown(
        &body,
        std::slice::from_ref(&case),
        &store,
        &report,
    )
    .unwrap();
    assert!(document.starts_with(&format!("# {link}")));
    assert!(document.ends_with(&format!("*Generated with {link}.*\n")));
    assert_eq!(
        document
            .matches(&format!("*Generated with {link}.*"))
            .count(),
        2
    );
    assert!(
        document.rfind("# Evidence appendix").unwrap() < document.rfind("*Generated with").unwrap()
    );
    let quoted = format!("```markdown\n\n---\n\n*Generated with {link}.*\n```\n");
    let custom_pdf = vulnbell::output::prepared_pdf_markdown(
        &format!("# Custom report\n\n{quoted}"),
        std::slice::from_ref(&case),
        &store,
        &report,
    )
    .unwrap();
    assert!(custom_pdf.starts_with(&format!("*Generated with {link}.*")));
    assert!(custom_pdf.contains(&quoted));
    assert!(custom_pdf.ends_with(&format!("*Generated with {link}.*\n")));
    let unclosed = "# Custom report\n\n```text\nEvidence remains unchanged.";
    assert!(
        vulnbell::output::prepared_pdf_markdown(
            unclosed,
            std::slice::from_ref(&case),
            &store,
            &report,
        )
        .is_err()
    );
    let mut outside = case;
    outside.codebase_revisions[0].codebase = "/unregistered/codebase".into();
    assert!(vulnbell::output::prepared_pdf_markdown(&body, &[outside], &store, &report).is_err());
    let different_store = Store {
        connection: rusqlite::Connection::open_in_memory().unwrap(),
        directory: std::path::PathBuf::from("/other-state").join(&project),
    };
    assert!(
        vulnbell::output::prepared_pdf_markdown(&body, &[], &different_store, &report).is_err()
    );
    assert!(document.contains("archive-1/src/old.rs:17"));
    assert!(document.contains("current-2/src/live.rs:4"));
    assert!(!document.contains("/home/alex/archive"));
    assert!(!document.contains("/home/alex/current"));
    assert!(document.contains("/unrelated/repository/file.rs:3"));
    assert!(document.contains(&note.sha256));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn rescan_preserves_known_roots_for_retained_historical_notes() {
    let directory = tempfile::tempdir().unwrap();
    let old_root = directory.path().join("old-codebase");
    let new_root = directory.path().join("new-codebase");
    std::fs::create_dir_all(&old_root).unwrap();
    std::fs::create_dir_all(&new_root).unwrap();
    let project = uuid::Uuid::new_v4();
    let profile_path = directory.path().join("vulnbell.yaml");
    let profile_text = |path: &std::path::Path| {
        format!(
            "schema: 1\nproject_id: {project}\nname: fixture\ndiscovery: off\ncodebases:\n  - '{}'\ncomponents:\n  - ref: pkg:cargo/example\n    version: '1.0.0'\n",
            path.display(),
        )
    };
    std::fs::write(&profile_path, profile_text(&old_root)).unwrap();
    let profile = vulnbell::profile::load(&profile_path).unwrap();
    let first = vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
    let mut store = Store::open(&project.to_string()).unwrap();
    let note_text = format!("Historical source: {}/src/old.rs:17", old_root.display());
    let note = store
        .record_evidence(
            note_text.as_bytes(),
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let case = Case {
        schema_version: 1,
        case_id: "SIG-preserved".into(),
        project_id: project.to_string(),
        snapshot_id: first.id.clone(),
        codebase_revisions: first.codebase_revisions.clone(),
        instances: vec![first.instances[0].clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: vec![note.clone()],
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "not run".into(),
        },
        updated_at: vulnbell::now(),
    };
    store.save_case(&case).unwrap();
    drop(store);
    std::fs::write(&profile_path, profile_text(&new_root)).unwrap();
    let profile = vulnbell::profile::load(&profile_path).unwrap();
    let second = vulnbell::engine::scan(&profile, &profile_path, true).unwrap();
    let store = Store::open(&project.to_string()).unwrap();
    let preserved = store.case("SIG-preserved").unwrap();
    assert_eq!(
        preserved.codebase_revisions[0].codebase,
        new_root.to_str().unwrap()
    );
    assert!(
        preserved
            .evidence
            .iter()
            .any(|item| item.sha256 == note.sha256)
    );
    let mut current = second;
    current.cases = store.cases().unwrap();
    let report = prepared_report(&current, &store, "cyber").unwrap();
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
    let document =
        vulnbell::output::prepared_pdf_markdown(&markdown, &current.cases, &store, &report)
            .unwrap();
    assert!(!document.contains(old_root.to_str().unwrap()));
    assert!(!document.contains(new_root.to_str().unwrap()));
    assert!(document.contains("old-codebase-2/src/old.rs:17"));
    assert!(document.contains("new-codebase-1"));
    assert!(document.contains(&note.sha256));

    store
        .connection
        .execute(
            "INSERT INTO snapshots (id, body) VALUES (?1, ?2)",
            ["damaged", "not-json"],
        )
        .unwrap();
    let mut unprepared = vulnbell::output::morning_report(&current, &store, "cyber").unwrap();
    assert!(vulnbell::output::morning_markdown(&unprepared).is_err());
    assert!(vulnbell::output::pdf_report_body("# Report", &unprepared).is_err());
    assert!(vulnbell::output::verification_markdown(&unprepared).is_err());
    assert!(
        vulnbell::output::prepared_pdf_markdown("# Report", &current.cases, &store, &unprepared)
            .is_err()
    );
    assert!(vulnbell::tools::cases::pending(&store).is_ok());
    assert!(vulnbell::output::prepare_report_paths(&mut unprepared, &store).is_err());
    assert!(vulnbell::output::morning_markdown(&unprepared).is_err());
    let cli = |args: &[&str]| {
        assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
            .args(args)
            .arg("--project")
            .arg(&profile_path)
            .output()
            .unwrap()
    };
    let json = cli(&["report", "--json"]);
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(serde_json::from_slice::<serde_json::Value>(&json.stdout).is_ok());
    let pending = cli(&["tools", "pending", "--json"]);
    assert!(serde_json::from_slice::<serde_json::Value>(&pending.stdout).is_ok());
    let markdown = cli(&["report", "--audience", "cyber"]);
    assert!(!markdown.status.success());
    assert!(String::from_utf8_lossy(&markdown.stderr).contains("historical snapshot"));
    let audit = cli(&["report", "--audience", "audit"]);
    assert!(!audit.status.success());
    assert!(String::from_utf8_lossy(&audit.stderr).contains("historical snapshot"));
    let pdf_path = directory.path().join("report.pdf");
    let pdf = cli(&["report", "--pdf", pdf_path.to_str().unwrap()]);
    assert!(!pdf.status.success());
    assert!(String::from_utf8_lossy(&pdf.stderr).contains("historical snapshot"));
    assert!(!pdf_path.exists());
    store
        .connection
        .execute("DELETE FROM snapshots WHERE id = ?1", ["damaged"])
        .unwrap();
    let mut invalid = serde_json::to_value(&current).unwrap();
    invalid["id"] = json!("different-id");
    store
        .connection
        .execute(
            "INSERT INTO snapshots (id, body) VALUES (?1, ?2)",
            rusqlite::params!["damaged", invalid.to_string()],
        )
        .unwrap();
    assert!(prepared_report(&current, &store, "cyber").is_err());
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project.to_string())).unwrap();
}
