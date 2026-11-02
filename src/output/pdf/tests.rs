use super::{attestation_details, evidence_link, pdf_markdown, safe_html, write_pdf};

#[test]
#[ignore = "requires Chromium and pdftotext"]
fn sample_prompt_title_stays_with_its_content() {
    let directory = tempfile::tempdir().unwrap();
    let pdf = directory.path().join("sample.pdf");
    write_pdf(include_str!("../../../examples/report.md"), &pdf, None).unwrap();
    let output = std::process::Command::new("pdftotext")
        .args(["-layout", pdf.to_str().unwrap(), "-"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.split('\x0c').any(|page| {
        page.contains("Prompt for a development agent:")
            && page.contains("Review case SIG-synthetic-example")
    }));
}

#[test]
fn visible_dashes_are_normalized_without_rewriting_link_destinations() {
    let html = safe_html("Texto — ejemplo [fuente](https://example.org/a%E2%80%94b) `x—y`");
    assert!(html.contains("Texto - ejemplo"));
    assert!(html.contains("x-y"));
    assert!(html.contains("https://example.org/a%E2%80%94b"));
    assert!(!html.contains('—'));
}
#[test]
fn attestation_summary_includes_oracle_and_positive_control() {
    let mut attestation: crate::sandbox::Attestation = serde_json::from_value(serde_json::json!({
        "schema_version":2,"project_id":"project","case_id":"case","codebase_revisions":[],
        "facts_sha256":"facts","instance_id":"instance","artifact_version":"1.0",
        "runtime":"microsandbox","runtime_version":"0.7","runtime_sha256":"runtime",
        "test_sha256":"test","image_reference":"image","image_manifest_digest":"imagehash",
        "staging_sha256":"stage","policy_sha256":"policy","input_sha256":["inputhash"],
        "oracle":{"stdout_contains":"EXPECTED_MARKER","expected_exit":0,"purpose":"positive_non_applicability"},
        "control":{"artifact_version":"2.0","input_sha256":["controlinput"],"output_sha256":"controloutput","oracle_matched":true,"policy_verified":true},
        "network_devices":"none","host_mounts":[],"memory_mib":512,"cpu_count":1,
        "timeout_seconds":120,"output_sha256":"output","execution_status_sha256":"status",
        "exit_code":0,"execution_complete":true,"timed_out":false,"verification":"disproven",
        "observed_at":"2026-01-01T00:00:00Z"
    })).unwrap();
    let text = attestation_details(&attestation, crate::profile::Language::En);
    assert!(text.contains("EXPECTED_MARKER"));
    assert!(text.contains("PositiveNonApplicability"));
    assert!(text.contains("oracle_matched=true"));
    assert!(text.contains("controlinput"));
    assert!(text.contains("controloutput"));
    assert!(text.contains("expected exit `0`; marker `EXPECTED_MARKER`"));
    assert!(text.contains("Execution: complete=true; timeout=false; exit=Some(0)"));
    let spanish = attestation_details(&attestation, crate::profile::Language::Es);
    assert!(spanish.contains("salida esperada `0`; marcador `EXPECTED_MARKER`"));
    assert!(spanish.contains("Ejecución: completo=true; timeout=false; salida=Some(0)"));
    assert!(spanish.contains("entrada SHA-256 controlinput; salida SHA-256 `controloutput`"));

    let project = uuid::Uuid::new_v4().to_string();
    let store = crate::store::Store::open(&project).unwrap();
    let instance = crate::model::Instance::declared(&crate::profile::Component {
        reference: "fixture".into(),
        version: Some("1.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    attestation.project_id = project.clone();
    attestation.instance_id = instance.id.clone();
    let mut evidence = Vec::new();
    for (source, content) in [
        ("stdout", b"stdout".as_slice()),
        ("policy", b"policy"),
        ("status", b"status"),
        ("control", b"control"),
    ] {
        evidence.push(
            store
                .record_evidence(content, source, None, crate::model::EvidenceKind::Context)
                .unwrap(),
        );
    }
    attestation.output_sha256 = evidence[0].sha256.clone();
    attestation.policy_sha256 = evidence[1].sha256.clone();
    attestation.execution_status_sha256 = evidence[2].sha256.clone();
    attestation.control.as_mut().unwrap().output_sha256 = evidence[3].sha256.clone();
    let recorded = store
        .record_evidence(
            &serde_json::to_vec(&attestation).unwrap(),
            "microsandbox_attestation",
            None,
            crate::model::EvidenceKind::Attestation,
        )
        .unwrap();
    evidence.push(recorded);
    let mut case = crate::model::Case {
        schema_version: 1,
        case_id: "case".into(),
        project_id: project.clone(),
        snapshot_id: "snapshot".into(),
        codebase_revisions: vec![],
        instances: vec![instance],
        claims: vec![],
        upstream_events: vec![],
        evidence,
        coverage: vec![],
        applicability: crate::model::Applicability::Unknown,
        verification: crate::model::Verification::Inconclusive,
        decision: crate::model::Decision::Review,
        facts_sha256: "facts".into(),
        open_questions: vec![],
        suggested_search_queries: vec![],
        sandbox: crate::model::SandboxAvailability {
            available: false,
            reason: "fixture".into(),
        },
        updated_at: crate::now(),
    };
    let appendix =
        pdf_markdown("# Report", &[&case], &store, crate::profile::Language::En).unwrap();
    assert!(appendix.contains("EXPECTED_MARKER"));
    assert!(appendix.contains("oracle_matched=true"));
    assert!(appendix.contains("controlinput"));
    let changed = tempfile::tempdir().unwrap();
    case.codebase_revisions
        .push(crate::codebase_revision::capture_path(changed.path()));
    let stale = pdf_markdown("# Report", &[&case], &store, crate::profile::Language::En).unwrap();
    assert!(stale.contains("Attestation unavailable or invalid"));
    assert!(!stale.contains("EXPECTED_MARKER"));
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}
#[test]
fn evidence_links_preserve_underscores_and_reject_credentials() {
    let url = "https://github.com/_owner/repo/issues/1?some_key=value";
    let html = safe_html(&evidence_link(url));
    assert!(html.contains(&format!("href=\"{url}\"")));
    let unsafe_url = evidence_link("https://user:secret@example.com/path");
    assert!(!safe_html(&unsafe_url).contains("href="));
}
#[test]
fn report_html_disables_active_content_and_external_images() {
    let output = safe_html(
        "# Test\n\n<script>alert(1)</script>\n\n![image](https://example.com/x.png) [bad](javascript:alert) [good](https://example.com/advisory)",
    );
    assert!(!output.contains("<script>"));
    assert!(!output.contains("<img"));
    assert!(!output.contains("href=\"javascript:"));
    assert!(output.contains("href=\"https://example.com/advisory\""));
    assert!(output.contains("default-src 'none'"));
}

#[test]
fn report_template_includes_print_footer_and_repeated_table_headers() {
    let output = safe_html(
        "# Report\n\n| Component | Evidence |\n| --- | --- |\n| `example` | [Source](https://example.org/advisory) |\n",
    );
    assert!(output.contains("<table>"));
    assert!(output.contains("<thead>"));
    assert!(output.contains("href=\"https://example.org/advisory\""));
    assert!(output.contains("@bottom-left"));
    assert!(output.contains("counter(page)"));
    assert!(output.contains("counter(pages)"));
    assert!(output.contains("display: table-header-group"));
    assert!(!output.contains("@import"));
}

#[test]
#[ignore = "requires Chromium, pdfinfo and pdftotext"]
fn long_table_remains_readable_across_pages() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.pdf");
    let mut markdown = String::from(
        "# Report\n\n| Case | Component | Status | Evidence |\n| --- | --- | --- | --- |\n",
    );
    let url = format!("https://example.org/{}", "reference".repeat(20));
    for index in 0..90 {
        markdown.push_str(&format!(
            "| SIG-{index:04} | `example-package` | Review | {url} |\n"
        ));
    }
    write_pdf(&markdown, &path, None).unwrap();
    let info = std::process::Command::new("pdfinfo")
        .arg(&path)
        .output()
        .unwrap();
    assert!(info.status.success());
    let info = String::from_utf8(info.stdout).unwrap();
    let pages: usize = info
        .lines()
        .find_map(|line| line.strip_prefix("Pages:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!((2..=20).contains(&pages), "unexpected page count: {pages}");
    let text = std::process::Command::new("pdftotext")
        .args(["-layout", path.to_str().unwrap(), "-"])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert_eq!(text.matches("example-package").count(), 90);
    assert!(text.contains("COMPONENT"));
}

#[test]
#[ignore = "requires Chromium and pdftotext"]
fn finding_blocks_stay_together_when_possible() {
    let directory = tempfile::tempdir().unwrap();
    for (case, (level, marker)) in [("##", "-"), ("###", "-"), ("###", "1.")]
        .into_iter()
        .enumerate()
    {
        let path = directory.path().join(format!("short-{case}.pdf"));
        let mut markdown = String::from("# Report\n\n## Findings\n\n");
        for index in 0..25 {
            markdown.push_str(&format!(
                "Background line {index:02} with context for the review.\n\n"
            ));
        }
        markdown.push_str(&format!("{level} CASE-SHORT Example finding\n\n"));
        for index in 0..7 {
            markdown.push_str(&format!("{marker} **FIELD-{index:02}:** A description with enough context for the project and a recommended action.\n"));
        }
        write_pdf(&markdown, &path, None).unwrap();
        let text = std::process::Command::new("pdftotext")
            .args(["-layout", path.to_str().unwrap(), "-"])
            .output()
            .unwrap();
        assert!(text.status.success());
        let text = String::from_utf8(text.stdout).unwrap();
        let pages: Vec<&str> = text.split('\x0c').collect();
        let page = pages
            .iter()
            .find(|page| page.contains("CASE-SHORT"))
            .unwrap();
        assert!(
            page.contains("FIELD-00") && page.contains("FIELD-06"),
            "short finding was split across pages: {text}"
        );
    }

    let path = directory.path().join("long.pdf");
    let mut markdown = String::from("# Report\n\n");
    for index in 0..12 {
        markdown.push_str(&format!(
            "Additional context {index:02} for the report.\n\n"
        ));
    }
    markdown.push_str("### CASE-LONG Example finding\n\n");
    for index in 0..120 {
        markdown.push_str(&format!(
            "- LONG-{index:03}: Evidence and context for the reviewed project.\n"
        ));
    }
    write_pdf(&markdown, &path, None).unwrap();
    let text = std::process::Command::new("pdftotext")
        .args(["-layout", path.to_str().unwrap(), "-"])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.split('\x0c').next().unwrap().contains("LONG-000"),
        "oversized finding should use the remaining page space: {text}"
    );
    assert_eq!(
        text.matches("LONG-").count(),
        120,
        "oversized finding lost content"
    );
    assert!(
        text.split('\x0c')
            .filter(|page| page.contains("LONG-"))
            .count()
            > 1,
        "oversized finding must span pages"
    );

    let path = directory.path().join("multiline.pdf");
    let mut markdown = String::from("# Report\n\n");
    for index in 0..12 {
        markdown.push_str(&format!("Context {index:02} for the review.\n\n"));
    }
    markdown.push_str("### CASE-MULTILINE Example finding\n\n");
    let details = "evidence ".repeat(28);
    for index in 0..20 {
        markdown.push_str(&format!("- MULTI-{index:02}: {details}\n"));
    }
    write_pdf(&markdown, &path, None).unwrap();
    let text = std::process::Command::new("pdftotext")
        .args(["-layout", path.to_str().unwrap(), "-"])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.split('\x0c').next().unwrap().contains("MULTI-00"),
        "multiline finding should use the remaining page space: {text}"
    );
    assert_eq!(text.matches("MULTI-").count(), 20);
    assert!(
        text.split('\x0c')
            .filter(|page| page.contains("MULTI-"))
            .count()
            > 1
    );

    let path = directory.path().join("wide.pdf");
    let mut markdown = String::from("# Report\n\n");
    for index in 0..12 {
        markdown.push_str(&format!("Context {index:02} for the review.\n\n"));
    }
    markdown.push_str("### CASE-WIDE Example finding\n\n");
    for index in 0..30 {
        markdown.push_str(&format!(
            "- WIDE-{index:02}: `{}`\n",
            "0123456789abcdef".repeat(9)
        ));
    }
    write_pdf(&markdown, &path, None).unwrap();
    let text = std::process::Command::new("pdftotext")
        .args(["-layout", path.to_str().unwrap(), "-"])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.split('\x0c').next().unwrap().contains("WIDE-00"),
        "wide finding should use the remaining page space: {text}"
    );
    assert_eq!(text.matches("WIDE-").count(), 30);

    let path = directory.path().join("paragraphs.pdf");
    let mut markdown = String::from("# Report\n\n");
    for index in 0..12 {
        markdown.push_str(&format!("Context {index:02} for the review.\n\n"));
    }
    markdown.push_str("### CASE-PARAGRAPHS Example finding\n\n");
    for index in 0..10 {
        markdown.push_str(&format!("- PARA-{index:02}: First paragraph.\n"));
        for _ in 0..5 {
            markdown.push_str("\n  Additional paragraph with reviewed context.\n");
        }
        markdown.push('\n');
    }
    write_pdf(&markdown, &path, None).unwrap();
    let text = std::process::Command::new("pdftotext")
        .args(["-layout", path.to_str().unwrap(), "-"])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.split('\x0c').next().unwrap().contains("PARA-00"),
        "finding with paragraphs should use the remaining page space: {text}"
    );
    assert_eq!(text.matches("PARA-").count(), 10);
    assert_eq!(text.matches("Additional paragraph").count(), 50);
}

#[test]
fn evidence_appendix_starts_a_new_page() {
    let output = safe_html("# Report\n\n# Evidence appendix\n\nEvidence.");
    assert!(output.contains("<h1 class=\"evidence-appendix\">Evidence appendix</h1>"));
    assert!(output.contains("h1.evidence-appendix { break-before: page; }"));
}

#[test]
fn appendix_contains_registered_notes_and_reports_missing_evidence() {
    use crate::model::{
        Applicability, Case, Decision, EvidenceKind, SandboxAvailability, Verification,
    };
    let project = uuid::Uuid::new_v4().to_string();
    let store = crate::store::Store::open(&project).unwrap();
    let note = store
        .record_evidence(
            b"Reachable at src/auth.rs:12",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut missing = note.clone();
    missing.id = "EV-missing".into();
    missing.sha256 = "../outside".into();
    let scope = store
        .record_evidence(
            b"Scope verified at src/scope.rs:21",
            "local_scope_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let case = Case {
        schema_version: 1,
        case_id: "SIG-test".into(),
        project_id: project.clone(),
        snapshot_id: "snapshot".into(),
        codebase_revisions: vec![],
        instances: vec![],
        claims: vec![],
        upstream_events: vec![],
        evidence: vec![note.clone(), scope, missing],
        coverage: vec![],
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "facts".into(),
        open_questions: vec![],
        suggested_search_queries: vec![],
        sandbox: SandboxAvailability {
            available: false,
            reason: "not run".into(),
        },
        updated_at: "now".into(),
    };
    let output = pdf_markdown("# Report", &[&case], &store, crate::profile::Language::Es).unwrap();
    assert!(output.contains("SIG-test"));
    assert!(output.contains("Reachable at src/auth.rs:12"));
    assert!(output.contains("Scope verified at src/scope.rs:21"));
    assert!(output.contains(&note.sha256));
    assert!(output.contains("no disponible o integridad inválida"));
    assert!(
        pdf_markdown(
            &"a".repeat(super::MAX_DOCUMENT + 1),
            &[],
            &store,
            crate::profile::Language::En
        )
        .is_err()
    );
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

#[test]
fn existing_pdf_is_not_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.pdf");
    std::fs::write(&path, b"existing").unwrap();
    assert!(
        write_pdf(
            "# Report",
            &path,
            Some(std::path::Path::new("missing-browser"))
        )
        .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), b"existing");
}
