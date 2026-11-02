use serde_json::json;
use vulnbell::{model::*, store::Store};

fn prepared_report(
    snapshot: &Snapshot,
    store: &Store,
    audience: &str,
) -> anyhow::Result<vulnbell::output::MorningReport> {
    let mut report = vulnbell::output::morning_report(snapshot, store, audience)?;
    vulnbell::output::prepare_report_paths(&mut report, store)?;
    Ok(report)
}

#[test]
fn edited_pdf_requires_a_reason_and_displays_it_safely() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args([
            "report",
            "--project",
            "profile.yaml",
            "--pdf",
            "out.pdf",
            "--from-markdown",
            "edited.md",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--custom-reason"));
    let notice = vulnbell::output::custom_content_notice(
        vulnbell::profile::Language::Es,
        "Resumen revisado <externo>",
    );
    assert!(notice.contains("Motivo indicado: Resumen revisado &lt;externo&gt;"));
}

#[test]
fn delivery_status_distinguishes_partial_coverage_from_complete_reports() {
    let mut pending = vulnbell::tools::cases::PendingReport {
        schema_version: 1,
        deliverable: true,
        verification_pending: Vec::new(),
        verdict_missing: Vec::new(),
        code_findings_pending: Vec::new(),
        code_reviews_pending: Vec::new(),
        challenge_open: Vec::new(),
        research_open: Vec::new(),
        stale_observations: 0,
        discovery_open: None,
        tracker_scope_unresolved: false,
        codebase_context_changed: false,
    };
    let render = |pending: &_, partial| {
        vulnbell::output::delivery_status_markdown(
            pending,
            partial,
            vulnbell::profile::Language::Es,
        )
    };
    assert!(render(&pending, false).is_empty());
    assert!(render(&pending, true).contains("escaneo parcial: sí"));
    pending.deliverable = false;
    pending.verdict_missing.push("CASE-1".into());
    pending.tracker_scope_unresolved = true;
    let warning = render(&pending, false);
    assert!(warning.contains("veredictos pendientes: 1"));
    assert!(warning.contains("alcance de fuentes sin resolver: sí"));
}

#[test]
fn coverage_groups_keep_the_first_seen_order_and_scope_labels() {
    let project = uuid::Uuid::new_v4().to_string();
    let store = Store::open(&project).unwrap();
    let snapshot = Snapshot {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: Vec::new(),
        cases: Vec::new(),
        coverage: vec![
            Coverage::new("first", "scope-a", CoverageState::Partial, "first gap"),
            Coverage::new(
                "second",
                "scope-b",
                CoverageState::Unavailable,
                "second gap",
            ),
            Coverage::new("first", "scope-c", CoverageState::Partial, "first gap"),
        ],
        partial: true,
        alert_status: "local".into(),
    };
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(markdown.contains("scope-a, scope-c"));
    assert!(markdown.find("first gap").unwrap() < markdown.find("second gap").unwrap());
    assert_eq!(markdown.matches("first gap").count(), 1);
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn report_explains_the_matched_package_without_recommending_another_packages_fix() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    store.set_meta("project_name", "report-fixture").unwrap();
    let mut instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:npm/example".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    instance.purl = Some(instance.reference.clone());
    let osv = json!({"details":"SYNTHETIC: newline injection in an event identifier. <script>untrusted</script>","database_specific":{"severity":"HIGH"},"affected":[
        {"package":{"ecosystem":"npm","name":"different-package"},"ranges":[{"events":[{"fixed":"99.0.0"}]}]},
        {"package":{"ecosystem":"npm","name":"example","purl":"pkg:npm/example"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}
    ]});
    let ghsa = json!([
        {"ghsa_id":"GHSA-unrelated","description":"Different advisory","vulnerabilities":[{"package":{"ecosystem":"npm","name":"example"},"first_patched_version":"88.0.0"}]},
        {"ghsa_id":"GHSA-synthetic","html_url":"https://github.com/advisories/GHSA-synthetic","publisher":{"html_url":"https://github.com/not-a-finding-reference"},"references":["https://github.com/example/project/pull/42"],"description":"SYNTHETIC: attacker-controlled event identifiers can forge events.","severity":"high","vulnerabilities":[
            {"package":{"ecosystem":"npm","name":"another-package"},"first_patched_version":"77.0.0"},
            {"package":{"ecosystem":"npm","name":"example"},"first_patched_version":"1.2.3"}
        ]}
    ]);
    let mut claims = Vec::new();
    for (source, document) in [("osv", osv), ("ghsa", ghsa)] {
        let evidence = store
            .record_evidence(
                &serde_json::to_vec(&document).unwrap(),
                source,
                Some("https://example.org/synthetic-advisory".into()),
                EvidenceKind::Advisory,
            )
            .unwrap();
        claims.push(Claim {
            id: "GHSA-synthetic".into(),
            source: source.into(),
            aliases: Vec::new(),
            instance_id: instance.id.clone(),
            summary: "SYNTHETIC event_id injection in _parse_".into(),
            applicability: Applicability::Affected,
            evidence,
            known_exploited: false,
        });
    }
    let mut case = Case {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        case_id: "SIG-synthetic-report".into(),
        project_id: project.clone(),
        snapshot_id: "synthetic".into(),
        instances: vec![instance.clone()],
        evidence: claims.iter().map(|claim| claim.evidence.clone()).collect(),
        claims,
        upstream_events: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Affected,
        verification: Verification::SourceConfirmed,
        decision: Decision::Actionable,
        facts_sha256: "synthetic".into(),
        open_questions: vec!["Confirmar entrada controlable y uso de SSE.".into()],
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: false,
            reason: "synthetic".into(),
        },
        updated_at: "2026-10-25T00:00:00Z".into(),
    };
    let project_evidence = store
        .record_evidence(
            b"Reviewed src/stream.rs:42: affected parser is called by the event endpoint.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    case.evidence.push(project_evidence.clone());
    store.save_case(&case).unwrap();
    vulnbell::impact::assess(
        &mut store,
        &case.case_id,
        vulnbell::impact::ImpactSubmission {
            question_set_sha256: vulnbell::impact::question_set_sha256(),
            schema_version: 1,
            case_id: case.case_id.clone(),
            facts_sha256: case.facts_sha256.clone(),
            answers: vec![vulnbell::impact::ImpactAnswer {
                instance_id: instance.id.clone(),
                question: vulnbell::impact::ImpactQuestionId::AffectedFeatureUsed,
                answer: vulnbell::impact::ImpactAnswerValue::Yes,
                rationale: "src/stream.rs:42 calls the affected parser.".into(),
                evidence: vec![EvidenceReference {
                    id: project_evidence.id,
                    sha256: project_evidence.sha256,
                }],
            }],
        },
    )
    .unwrap();
    case = store.case(&case.case_id).unwrap();
    let snapshot = Snapshot {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        id: "synthetic".into(),
        project_id: project.clone(),
        profile_sha256: "synthetic".into(),
        started_at: "2026-10-25T00:00:00Z".into(),
        finished_at: "2026-10-25T00:00:00Z".into(),
        instances: vec![instance],
        cases: vec![case],
        coverage: Vec::new(),
        partial: false,
        alert_status: "local report only".into(),
    };
    let report = prepared_report(&snapshot, &store, "manager").unwrap();
    assert_eq!(report.project_name, "report-fixture");
    assert_eq!(report.actionable.len(), 1);
    let item = &report.actionable[0];
    assert!(item.detail_gaps.is_empty());
    assert_eq!(item.advisory_details.len(), 2);
    assert!(
        item.advisory_details
            .iter()
            .all(|detail| detail.fixed_versions == ["1.2.3"])
    );
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(markdown.contains("event_id injection in \\_parse\\_"));
    assert!(markdown.contains("### SIG-synthetic-report - SYNTHETIC"));
    let verification = vulnbell::output::verification_markdown(&report).unwrap();
    assert!(verification.contains("- **OSV GHSA-synthetic:**"));
    assert!(verification.contains("- **GitHub Advisory Database reference:**"));
    assert!(!markdown.contains("## References and local verification"));
    assert!(markdown.contains("newline injection"));
    assert!(markdown.contains("attacker-controlled event identifiers"));
    assert!(markdown.contains("1.2.3"));
    assert!(
        !markdown.contains("99.0.0")
            && !markdown.contains("88.0.0")
            && !markdown.contains("77.0.0")
    );
    assert!(!markdown.contains("<script>"));
    assert!(markdown.contains("&lt;script&gt;"));
    assert!(markdown.contains(
        "**Affected feature in use:** yes - src/stream.rs:42 calls the affected parser."
    ));
    assert_eq!(
        markdown
            .matches("src/stream.rs:42 calls the affected parser")
            .count(),
        1
    );
    assert!(
        vulnbell::output::verification_markdown(&report)
            .unwrap()
            .contains("affected feature in use: yes. src/stream.rs:42")
    );
    let original = &snapshot.cases[0];
    let claim = &original.claims[0];
    let verdict = Verdict {
        schema_version: 1,
        case_id: original.case_id.clone(),
        codebase_revisions: Vec::new(),
        facts_sha256: original.facts_sha256.clone(),
        applicability: Applicability::Affected,
        verification: Verification::SourceConfirmed,
        decision: Decision::Actionable,
        rationale: "Revisado con evidencia del proyecto.".into(),
        advisory_translation: Some(AdvisoryTranslation {
            source_sha256: "0".repeat(64),
            language: vulnbell::profile::Language::Es,
            summary: "Resumen revisado en español.".into(),
        }),
        evidence: vec![EvidenceReference {
            id: claim.evidence.id.clone(),
            sha256: claim.evidence.sha256.clone(),
        }],
    };
    assert!(vulnbell::engine::triage(&mut store, &original.case_id, verdict).is_err());
    let verdict = Verdict {
        schema_version: 1,
        case_id: original.case_id.clone(),
        codebase_revisions: Vec::new(),
        facts_sha256: original.facts_sha256.clone(),
        applicability: Applicability::Affected,
        verification: Verification::SourceConfirmed,
        decision: Decision::Actionable,
        rationale: "Revisado con evidencia del proyecto.".into(),
        advisory_translation: Some(AdvisoryTranslation {
            source_sha256: claim.evidence.sha256.clone(),
            language: vulnbell::profile::Language::Es,
            summary: "Resumen revisado en español.".into(),
        }),
        evidence: vec![EvidenceReference {
            id: claim.evidence.id.clone(),
            sha256: claim.evidence.sha256.clone(),
        }],
    };
    let recorded = vulnbell::engine::triage(&mut store, &original.case_id, verdict).unwrap();
    let mut translated_snapshot = snapshot.clone();
    translated_snapshot.cases = vec![recorded];
    let mut translated = prepared_report(&translated_snapshot, &store, "cyber").unwrap();
    translated.language = vulnbell::profile::Language::Es;
    translated.actionable[0].advisory_details[1].description = translated.actionable[0]
        .advisory_details[0]
        .description
        .clone();
    translated.actionable[0].evidence_links = vec![
        "https://example.org/advisory".into(),
        "https://example.org/fix".into(),
    ];
    let rendered = vulnbell::output::morning_markdown(&translated).unwrap();
    assert_eq!(rendered.matches("**Problema / impacto:**").count(), 1);
    assert!(rendered.contains("newline injection"));
    assert!(rendered.contains("**Problema / impacto:** Resumen revisado en español."));
    assert!(rendered.contains("**Texto original de la fuente:** SYNTHETIC:"));
    assert!(rendered.contains("**Prompt para un agente de desarrollo:**"));
    assert!(rendered.contains(
        "- **Evidencias:**\n  - <https://example.org/advisory>\n  - <https://example.org/fix>"
    ));
    assert!(!rendered.contains('—'));
    assert!(rendered.find("## Accionables").unwrap() < rendered.find("## Inventario").unwrap());
    let prefix = "common prefix ".repeat(30);
    translated.actionable[0].advisory_details[0].description = format!("{prefix}first ending");
    translated.actionable[0].advisory_details[1].description = format!("{prefix}second ending");
    let distinct = vulnbell::output::morning_markdown(&translated).unwrap();
    assert_eq!(distinct.matches("**Problema / impacto:**").count(), 2);
    assert_eq!(distinct.matches("Resumen revisado en español.").count(), 1);
    assert_eq!(
        report.finding_checks[0]
            .impact
            .as_ref()
            .unwrap()
            .answers
            .len(),
        1
    );
    assert_eq!(
        report.finding_checks[0].local_checks[0].result,
        vulnbell::output::LocalResult::NotRun
    );
    assert_eq!(report.finding_checks[0].references.len(), 3);
    assert!(
        report.finding_checks[0]
            .references
            .iter()
            .any(|reference| reference.url.ends_with("/pull/42"))
    );
    assert!(
        !report.finding_checks[0]
            .references
            .iter()
            .any(|reference| reference.url.contains("not-a-finding-reference"))
    );
    let mapping = |kind, state, url: Option<&str>| vulnbell::discovery::SourceMapping {
        kind,
        state,
        url: url.map(str::to_owned),
        detail: "SYNTHETIC".into(),
        evidence: Vec::new(),
    };
    let mut mapped = prepared_report(&snapshot, &store, "manager").unwrap();
    for repository in [
        "https://github.com/example/project",
        "https://gitlab.com/example/project",
    ] {
        mapped.source_map = vec![vulnbell::discovery::IdentityObservation {
            instance_id: snapshot.instances[0].id.clone(),
            fingerprint: "synthetic".into(),
            version: Some("1.0.0".into()),
            cpe_product: None,
            rationale: "SYNTHETIC".into(),
            sources: vec![
                mapping(
                    vulnbell::discovery::SourceKind::Repository,
                    vulnbell::discovery::MappingState::Mapped,
                    Some(repository),
                ),
                mapping(
                    vulnbell::discovery::SourceKind::Advisories,
                    vulnbell::discovery::MappingState::Unavailable,
                    None,
                ),
                mapping(
                    vulnbell::discovery::SourceKind::Changelog,
                    vulnbell::discovery::MappingState::Unavailable,
                    None,
                ),
            ],
        }];
        let source_map = vulnbell::output::discovery_markdown(&mapped);
        assert!(source_map.contains("Changelog |"), "{source_map}");
        assert_eq!(
            source_map.contains("Security advisories"),
            repository.starts_with("https://gitlab.com/")
        );
    }
    assert!(!markdown.contains("Cobertura") && !markdown.contains("Componente"));

    let profile_path = store.directory.join("vulnbell-es.yaml");
    std::fs::write(
        &profile_path,
        format!(
            "schema: 1\nproject_id: {project}\nname: report-fixture\nreport:\n  language: es\n"
        ),
    )
    .unwrap();
    store
        .set_meta("profile_path", &profile_path.to_string_lossy())
        .unwrap();
    let spanish = prepared_report(&snapshot, &store, "manager").unwrap();
    assert_eq!(spanish.language, vulnbell::profile::Language::Es);
    let markdown = vulnbell::output::morning_markdown(&spanish).unwrap();
    assert!(
        markdown.contains(
            "**Problema / impacto:** Traducción pendiente; consultar la fuente original."
        )
    );
    assert!(markdown.contains("### SIG-synthetic-report - SYNTHETIC"));
    assert!(
        vulnbell::output::verification_markdown(&spanish)
            .unwrap()
            .contains("- **Referencia de GitHub Advisory Database:**")
    );
    assert!(markdown.contains(
        "**Funcionalidad afectada en uso:** sí - src/stream.rs:42 calls the affected parser."
    ));
    assert!(markdown.contains("## Cobertura y entrega"));
    assert!(!markdown.contains("Coverage and delivery") && !markdown.contains("Project impact"));
    store
        .connection
        .execute("DELETE FROM meta WHERE key='profile_path'", [])
        .unwrap();

    let evidence = &snapshot.cases[0].claims[0].evidence;
    std::fs::write(
        store.directory.join("evidence").join(&evidence.sha256),
        b"corrupt",
    )
    .unwrap();
    let damaged = prepared_report(&snapshot, &store, "manager").unwrap();
    assert_eq!(damaged.actionable[0].detail_gaps.len(), 1);
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn open_cases_list_references_and_closed_cases_keep_them_in_json_without_claiming_local_proof() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:npm/example".into(),
        version: Some("1.0.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let mut case = Case {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        case_id: "SIG-review".into(),
        project_id: project.clone(),
        snapshot_id: "snapshot".into(),
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: vec![
            UpstreamEvent {
                provider: "github".into(),
                kind: "issue".into(),
                id: "1".into(),
                url: "https://github.com/example/project/issues/1".into(),
                title: "SYNTHETIC hypothesis".into(),
                updated_at: None,
                sha256: "synthetic".into(),
                source_facts: vulnbell::model::SourceFacts {
                    identifiers: vec!["CVE-2026-0001".into()],
                    affected_versions: "1.0.x".into(),
                    fixed_in: "1.1.0".into(),
                    fix_reference: String::new(),
                    required_feature: "SSE endpoint enabled".into(),
                },
            },
            UpstreamEvent {
                provider: "gitlab".into(),
                kind: "merge_request".into(),
                id: "2".into(),
                url: "https://gitlab.com/example/project/-/merge_requests/2".into(),
                title: "SYNTHETIC proposal".into(),
                updated_at: None,
                sha256: "synthetic".into(),
                source_facts: Default::default(),
            },
        ],
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::SourceConfirmed,
        decision: Decision::Review,
        facts_sha256: "facts".into(),
        open_questions: vec![
            "Confirm whether version 1.0.0 includes the reported function.".into(),
        ],
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: true,
            reason: "synthetic".into(),
        },
        updated_at: vulnbell::now(),
    };
    let mut snapshot = Snapshot {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: vec![instance],
        cases: vec![case.clone()],
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    for decision in [
        Decision::Review,
        Decision::Dismissed,
        Decision::Informational,
    ] {
        case.decision = decision;
        snapshot.cases = vec![case.clone()];
        let report = prepared_report(&snapshot, &store, "cyber").unwrap();
        let summary = vulnbell::output::morning_markdown(&report).unwrap();
        assert!(summary.contains("| Status | Count | Meaning |"));
        assert!(summary.contains("they are not security findings"));
        if decision == Decision::Review {
            assert!(summary.contains("| In review with impact assessment | 0 |"));
            assert!(summary.contains("| Impact assessment pending | 1 |"));
            assert!(summary.contains("SYNTHETIC hypothesis"));
            assert!(summary.contains("Signals without a current assessment"));
            assert!(!summary.contains("Why it is still in review"));
            assert!(summary.contains("https://github.com/example/project/issues/1"));
        }
        assert_eq!(report.finding_checks.len(), 1);
        assert_eq!(report.finding_checks[0].references.len(), 2);
        assert_eq!(
            report.finding_checks[0].local_checks[0].result,
            vulnbell::output::LocalResult::NotRun
        );
        let markdown = vulnbell::output::verification_markdown(&report).unwrap();
        if decision == Decision::Review {
            assert!(markdown.contains("https://github.com/example/project/issues/1"));
            assert!(markdown.contains("https://gitlab.com/example/project/-/merge_requests/2"));
            assert!(markdown.contains("not run"));
        } else {
            assert!(!markdown.contains("https://github.com/example/project/issues/1"));
            assert!(markdown.contains("1 closed cases"));
            assert!(report.verification_pending.is_empty());
        }
    }
    snapshot.cases = (0..12)
        .map(|index| {
            let mut pending = case.clone();
            pending.case_id = format!("SIG-pending-{index}");
            pending.decision = Decision::Review;
            pending
        })
        .collect();
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
    for index in 0..12 {
        assert!(markdown.contains(&format!("SIG-pending-{index}")));
    }
    let reviewed_note = store
        .record_evidence(
            b"reviewed fixture",
            "reviewed_note",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let verdict = Verdict {
        advisory_translation: None,
        schema_version: 1,
        case_id: case.case_id.clone(),
        codebase_revisions: Vec::new(),
        facts_sha256: case.facts_sha256.clone(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        rationale: "Review the current version.".into(),
        evidence: vec![vulnbell::model::EvidenceReference {
            id: reviewed_note.id.clone(),
            sha256: reviewed_note.sha256.clone(),
        }],
    };
    let recorded = store
        .record_evidence(
            &serde_json::to_vec(&verdict).unwrap(),
            "agent_verdict",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut current = case.clone();
    current.decision = Decision::Review;
    current.verification = Verification::Inconclusive;
    current.evidence.push(reviewed_note);
    current.evidence.push(recorded);
    snapshot.cases = vec![current.clone()];
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert!(report.needs_review[0].recorded_verdict.is_some());
    current.facts_sha256 = "different facts".into();
    snapshot.cases = vec![current];
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert!(report.needs_review[0].recorded_verdict.is_none());
    case.decision = Decision::Review;
    store.save_case(&case).unwrap();
    let blocked = vulnbell::sandbox::record_blocker(
        &mut store,
        &case.case_id,
        Some(&case.instances[0].id),
        vulnbell::sandbox::BlockerKind::ArtifactUnavailable,
        "Required proprietary binary is unavailable; no substitute was tested.",
    )
    .unwrap();
    snapshot.cases = vec![blocked.clone()];
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(
        report.finding_checks[0].local_checks[0].result,
        vulnbell::output::LocalResult::Blocked
    );
    assert!(
        report.finding_checks[0].local_checks[0]
            .detail
            .contains("proprietary binary")
    );
    let custom = vulnbell::output::pdf_report_body("# Custom report\n", &report).unwrap();
    assert!(custom.contains("proprietary binary"));
    let standard = vulnbell::output::morning_markdown(&report).unwrap();
    let pdf = vulnbell::output::pdf_report_body(&standard, &report).unwrap();
    assert_eq!(pdf.matches("proprietary binary").count(), 1);
    let custom_copy = vulnbell::output::pdf_report_body(&pdf, &report).unwrap();
    assert_eq!(custom_copy.matches("proprietary binary").count(), 1);
    let edited = pdf.replace("proprietary binary", "customized explanation");
    let with_current = vulnbell::output::pdf_report_body(&edited, &report).unwrap();
    assert!(with_current.contains("customized explanation"));
    assert!(with_current.contains("proprietary binary"));
    assert!(with_current.contains("## Verification recorded by VulnBell"));
    let mut stale_blocker = blocked.clone();
    let changed = tempfile::tempdir().unwrap();
    stale_blocker
        .codebase_revisions
        .push(vulnbell::codebase_revision::capture_path(changed.path()));
    snapshot.cases = vec![stale_blocker];
    let stale_report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert_ne!(
        stale_report.finding_checks[0].local_checks[0].result,
        vulnbell::output::LocalResult::Blocked
    );
    assert_eq!(blocked.verification, Verification::SourceConfirmed);
    assert!(
        vulnbell::sandbox::record_blocker(
            &mut store,
            &case.case_id,
            Some("unknown-instance"),
            vulnbell::sandbox::BlockerKind::DetailsUndisclosed,
            "not valid"
        )
        .is_err()
    );

    for number in 1..5 {
        let mut twin = case.instances[0].clone();
        twin.id = format!("twin-instance-{number}");
        twin.reference = format!("pkg:maven/org.example/artifact-{number}");
        case.instances.push(twin);
    }
    case.decision = Decision::Review;
    store.save_case(&case).unwrap();
    let blocked = vulnbell::sandbox::record_blocker(
        &mut store,
        &case.case_id,
        None,
        vulnbell::sandbox::BlockerKind::SandboxLimits,
        "The server distribution exceeds the sandbox input limits.",
    )
    .unwrap();
    snapshot.cases = vec![blocked];
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert!(
        report.finding_checks[0]
            .local_checks
            .iter()
            .all(|check| check.result == vulnbell::output::LocalResult::Blocked)
    );
    let markdown = vulnbell::output::verification_markdown(&report).unwrap();
    assert_eq!(
        markdown
            .matches("- **Local verification (5 instances):** blocked")
            .count(),
        1
    );
    let summary = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(summary.contains("5 components 1.0.0"));
    assert!(summary.contains("Signals without a current assessment"));
    assert!(!summary.contains("artifact-4 1.0.0"));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn cards_cite_the_lockfile_line_and_the_inventory_is_summarized_per_lockfile() {
    let lock = b"version = 4\n\n[[package]]\nname = \"other\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"rustls\"\nversion = \"0.23.46\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    let packages = vulnbell::inventory::parse_lock("Cargo.lock", lock).unwrap();
    let rustls = packages
        .iter()
        .find(|package| package.name == "rustls")
        .unwrap();
    assert_eq!(rustls.line, Some(9));

    let project = uuid::Uuid::new_v4().to_string();
    let store = Store::open(&project).unwrap();
    let mut locked = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:cargo/rustls".into(),
        version: Some("0.23.46".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    locked.origin = Origin::Locked;
    locked.provenance.codebase = Some("../service".into());
    locked.provenance.path = Some("Cargo.lock".into());
    locked.provenance.line = rustls.line;
    let mut sibling = locked.clone();
    sibling.id = "sibling".into();
    sibling.reference = "pkg:cargo/other".into();
    let case = Case {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        case_id: "SIG-provenance".into(),
        project_id: project.clone(),
        snapshot_id: "snapshot".into(),
        instances: vec![locked.clone()],
        claims: Vec::new(),
        upstream_events: Vec::new(),
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "facts".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: SandboxAvailability {
            available: true,
            reason: "synthetic".into(),
        },
        updated_at: vulnbell::now(),
    };
    let snapshot = Snapshot {
        codebase_revisions: Vec::new(),
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: vec![locked, sibling],
        cases: vec![case],
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    let report = prepared_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(report.schema_version, 1);
    assert_eq!(
        report.needs_review[0].provenance,
        ["pkg:cargo/rustls 0.23.46 - ../service/Cargo.lock:9"]
    );
    assert_eq!(
        report.verification_pending[0].reason,
        vulnbell::output::PendingReason::ImpactNotAssessed
    );
    let markdown = vulnbell::output::morning_markdown(&report).unwrap();
    assert!(markdown.contains("**Incomplete report:** 1 cases without impact assessment"));
    assert!(markdown.contains("| ../service/Cargo.lock | 2 |"));
    assert!(markdown.contains("../service/Cargo.lock:9"));
    assert!(!markdown.contains("pkg:cargo/other"));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[path = "report/cases.rs"]
mod cases;

#[path = "report/paths.rs"]
mod paths;
