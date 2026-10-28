use serde_json::json;
use vulnbell::{model::*, store::Store};

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
    let report = vulnbell::output::morning_report(&snapshot, &store, "manager").unwrap();
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
    let markdown = vulnbell::output::morning_markdown(&report);
    assert!(markdown.contains("event_id injection in \\_parse\\_"));
    assert!(markdown.contains("### SIG-synthetic-report — Actionable"));
    assert!(markdown.contains("- **OSV GHSA-synthetic:**"));
    assert!(markdown.contains("- **GitHub Advisory Database reference:**"));
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
        "**Affected feature in use:** yes — src/stream.rs:42 calls the affected parser."
    ));
    assert_eq!(
        markdown
            .matches("src/stream.rs:42 calls the affected parser")
            .count(),
        1
    );
    assert!(
        vulnbell::output::verification_markdown(&report)
            .contains("affected feature in use: yes. src/stream.rs:42")
    );
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
    let mut mapped = vulnbell::output::morning_report(&snapshot, &store, "manager").unwrap();
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
    let spanish = vulnbell::output::morning_report(&snapshot, &store, "manager").unwrap();
    assert_eq!(spanish.language, vulnbell::profile::Language::Es);
    let markdown = vulnbell::output::morning_markdown(&spanish);
    assert!(markdown.contains("### SIG-synthetic-report — Accionable"));
    assert!(markdown.contains("- **Referencia de GitHub Advisory Database:**"));
    assert!(markdown.contains(
        "**Funcionalidad afectada en uso:** sí — src/stream.rs:42 calls the affected parser."
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
    let damaged = vulnbell::output::morning_report(&snapshot, &store, "manager").unwrap();
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
        let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
        let summary = vulnbell::output::morning_markdown(&report);
        assert!(summary.contains("| Status | Cases | Meaning |"));
        assert!(summary.contains("they are not security findings"));
        if decision == Decision::Review {
            assert!(summary.contains("| In review | 1 |"));
            assert!(summary.contains("SYNTHETIC hypothesis"));
            assert!(summary.contains("Why it is still in review"));
            assert!(summary.contains("Applicability: unknown; verification: confirmed by source"));
            assert!(
                summary.contains("Confirm whether version 1.0.0 includes the reported function")
            );
            assert!(summary.contains(
                "According to the source: cites CVE-2026-0001; affects: 1.0.x; fixed in: 1.1.0; requires: SSE endpoint enabled."
            ));
            assert_eq!(summary.matches("According to the source").count(), 1);
            assert!(summary.contains("Next step"));
            assert!(summary.contains("https://github.com/example/project/issues/1"));
        }
        assert_eq!(report.finding_checks.len(), 1);
        assert_eq!(report.finding_checks[0].references.len(), 2);
        assert_eq!(
            report.finding_checks[0].local_checks[0].result,
            vulnbell::output::LocalResult::NotRun
        );
        let markdown = vulnbell::output::verification_markdown(&report);
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
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(
        report.finding_checks[0].local_checks[0].result,
        vulnbell::output::LocalResult::Blocked
    );
    assert!(
        report.finding_checks[0].local_checks[0]
            .detail
            .contains("proprietary binary")
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
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert!(
        report.finding_checks[0]
            .local_checks
            .iter()
            .all(|check| check.result == vulnbell::output::LocalResult::Blocked)
    );
    let markdown = vulnbell::output::verification_markdown(&report);
    assert_eq!(
        markdown
            .matches("- **Local verification (5 instances):** blocked")
            .count(),
        1
    );
    let summary = vulnbell::output::morning_markdown(&report);
    assert!(summary.contains("5 components 1.0.0"));
    assert!(summary.contains("Resolve the recorded blocker"));
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
    locked.provenance.workspace = Some("../service".into());
    locked.provenance.path = Some("Cargo.lock".into());
    locked.provenance.line = rustls.line;
    let mut sibling = locked.clone();
    sibling.id = "sibling".into();
    sibling.reference = "pkg:cargo/other".into();
    let case = Case {
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
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(report.schema_version, 1);
    assert_eq!(
        report.needs_review[0].provenance,
        ["pkg:cargo/rustls 0.23.46 — ../service/Cargo.lock:9"]
    );
    assert_eq!(
        report.verification_pending[0].reason,
        vulnbell::output::PendingReason::ImpactNotAssessed
    );
    let markdown = vulnbell::output::morning_markdown(&report);
    assert!(markdown.contains("**Incomplete report:** 1 cases without impact assessment"));
    assert!(markdown.contains("| ../service/Cargo.lock | 2 |"));
    assert!(markdown.contains("../service/Cargo.lock:9"));
    assert!(!markdown.contains("pkg:cargo/other"));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn contained_advisories_collapse_into_one_row_and_exposed_cases_keep_their_card() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let mut instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:cargo/zstd-safe".into(),
        version: Some("7.3.0".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    instance.purl = Some(instance.reference.clone());
    let context = store
        .record_evidence(
            b"Reviewed actix-http decoder usage.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut cases = Vec::new();
    for (case_id, advisory, used, input) in [
        ("SIG-contained", "RUSTSEC-0001", "no", "no"),
        ("SIG-exposed", "RUSTSEC-0002", "yes", "unknown"),
    ] {
        let osv = json!({"id":advisory,"details":"SYNTHETIC advisory","affected":[{"package":{"ecosystem":"crates.io","name":"zstd-safe","purl":"pkg:cargo/zstd-safe"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"8.2.0"}]}]}]});
        let evidence = store
            .record_evidence(
                &serde_json::to_vec(&osv).unwrap(),
                "osv",
                None,
                EvidenceKind::Advisory,
            )
            .unwrap();
        let case = Case {
            schema_version: 1,
            case_id: case_id.into(),
            project_id: project.clone(),
            snapshot_id: "snapshot".into(),
            instances: vec![instance.clone()],
            claims: vec![Claim {
                id: advisory.into(),
                source: "osv".into(),
                aliases: Vec::new(),
                instance_id: instance.id.clone(),
                summary: format!("SYNTHETIC {advisory}"),
                applicability: Applicability::Affected,
                evidence: evidence.clone(),
                known_exploited: false,
            }],
            upstream_events: Vec::new(),
            evidence: vec![evidence, context.clone()],
            coverage: Vec::new(),
            applicability: Applicability::Affected,
            verification: Verification::SourceConfirmed,
            decision: Decision::Actionable,
            facts_sha256: "facts".into(),
            open_questions: vec!["Generic case question.".into()],
            suggested_search_queries: Vec::new(),
            sandbox: SandboxAvailability {
                available: true,
                reason: "synthetic".into(),
            },
            updated_at: vulnbell::now(),
        };
        store.save_case(&case).unwrap();
        let answer = |question, value: &str, rationale: &str| vulnbell::impact::ImpactAnswer {
            instance_id: instance.id.clone(),
            question,
            answer: serde_json::from_value(json!(value)).unwrap(),
            rationale: rationale.into(),
            evidence: vec![EvidenceReference {
                id: context.id.clone(),
                sha256: context.sha256.clone(),
            }],
        };
        use vulnbell::impact::ImpactQuestionId::*;
        vulnbell::impact::assess(
            &mut store,
            case_id,
            vulnbell::impact::ImpactSubmission {
                schema_version: 1,
                case_id: case_id.into(),
                facts_sha256: "facts".into(),
                answers: vec![
                    answer(ArtifactDeployed, "yes", "Service image."),
                    answer(
                        AffectedFeatureUsed,
                        used,
                        &format!("{case_id} feature rationale."),
                    ),
                    answer(UntrustedInputReachesFeature, input, "Input rationale."),
                    answer(
                        RequiredConditionsPresent,
                        "unknown",
                        "Conditions rationale.",
                    ),
                    answer(FixOrMitigationApplied, "no", "Not fixed."),
                ],
            },
        )
        .unwrap();
        cases.push(store.case(case_id).unwrap());
    }
    let snapshot = Snapshot {
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: vec![instance],
        cases,
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(report.actionable.len(), 2);
    let markdown = vulnbell::output::morning_markdown(&report);
    assert!(markdown.contains("**1** may be exposed in the project and **1** are not exposed"));
    assert!(markdown.contains("### SIG-exposed"));
    assert!(!markdown.contains("### SIG-contained"));
    assert!(markdown.contains("1 open cases without project exposure keep"));
    assert!(
        report
            .finding_checks
            .iter()
            .any(|check| check.case_id == "SIG-contained" && check.impact.is_some())
    );
    assert!(markdown.contains("| RUSTSEC-0001 | SIG-contained feature rationale. | 8.2.0 |"));
    assert!(markdown.contains("Update with priority to 8.2.0"));
    assert!(markdown.contains("**Affected feature in use:** yes — SIG-exposed feature rationale."));
    assert!(!markdown.contains("Generic case question."));
    assert!(!markdown.contains("**Local verification:** not run"));
    assert!(!markdown.contains("**Instance "));
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}

#[test]
fn unconfirmed_versions_need_a_review_disposition_without_requiring_a_test() {
    let project = uuid::Uuid::new_v4().to_string();
    let mut store = Store::open(&project).unwrap();
    let instance = Instance::declared(&vulnbell::profile::Component {
        reference: "pkg:cargo/hyper-util".into(),
        version: Some("0.1.21".into()),
        usage: Default::default(),
        upstream: None,
        feeds: Vec::new(),
    });
    let context = store
        .record_evidence(
            b"Reviewed listener setup.",
            "local_impact_evidence",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let advisory = store
        .record_evidence(
            b"{\"id\":\"RUSTSEC-0003\"}",
            "osv",
            None,
            EvidenceKind::Advisory,
        )
        .unwrap();
    let mut cases = Vec::new();
    for (case_id, claims) in [
        ("SIG-issue", Vec::new()),
        (
            "SIG-advisory",
            vec![Claim {
                id: "RUSTSEC-0003".into(),
                source: "osv".into(),
                aliases: Vec::new(),
                instance_id: instance.id.clone(),
                summary: "SYNTHETIC RUSTSEC-0003".into(),
                applicability: Applicability::Affected,
                evidence: advisory.clone(),
                known_exploited: false,
            }],
        ),
    ] {
        let case = Case {
            schema_version: 1,
            case_id: case_id.into(),
            project_id: project.clone(),
            snapshot_id: "snapshot".into(),
            instances: vec![instance.clone()],
            claims,
            upstream_events: Vec::new(),
            evidence: vec![context.clone()],
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
        store.save_case(&case).unwrap();
        let answer = |question, value: &str| vulnbell::impact::ImpactAnswer {
            instance_id: instance.id.clone(),
            question,
            answer: serde_json::from_value(json!(value)).unwrap(),
            rationale: "Deployment edge is not documented.".into(),
            evidence: vec![EvidenceReference {
                id: context.id.clone(),
                sha256: context.sha256.clone(),
            }],
        };
        use vulnbell::impact::ImpactQuestionId::*;
        let result = vulnbell::impact::assess(
            &mut store,
            case_id,
            vulnbell::impact::ImpactSubmission {
                schema_version: 1,
                case_id: case_id.into(),
                facts_sha256: "facts".into(),
                answers: vec![
                    answer(ArtifactDeployed, "unknown"),
                    answer(AffectedFeatureUsed, "yes"),
                    answer(UntrustedInputReachesFeature, "unknown"),
                    answer(RequiredConditionsPresent, "unknown"),
                    answer(FixOrMitigationApplied, "no"),
                ],
            },
        )
        .unwrap();
        assert_eq!(
            result.verdict,
            vulnbell::impact::ImpactVerdict::NeedsEvidence
        );
        cases.push(store.case(case_id).unwrap());
    }
    let mut snapshot = Snapshot {
        schema_version: 1,
        id: "snapshot".into(),
        project_id: project.clone(),
        profile_sha256: "profile".into(),
        started_at: vulnbell::now(),
        finished_at: vulnbell::now(),
        instances: vec![instance.clone()],
        cases,
        coverage: Vec::new(),
        partial: false,
        alert_status: "local".into(),
    };
    let pending = |snapshot: &Snapshot, store: &Store| {
        let report = vulnbell::output::morning_report(snapshot, store, "cyber").unwrap();
        let needed: Vec<(String, bool)> = report
            .finding_checks
            .iter()
            .map(|check| {
                assert!(!check.local_checks[0].sandbox_needed);
                (
                    check.case_id.clone(),
                    check.local_checks[0].sandbox_candidate,
                )
            })
            .collect();
        let pending: Vec<String> = report
            .verification_pending
            .iter()
            .map(|item| {
                assert_eq!(
                    item.reason,
                    vulnbell::output::PendingReason::ReviewDispositionMissing
                );
                item.case_id.clone()
            })
            .collect();
        (needed, pending)
    };
    let (needed, open) = pending(&snapshot, &store);
    assert!(needed.contains(&("SIG-issue".into(), true)));
    assert!(needed.contains(&("SIG-advisory".into(), false)));
    assert_eq!(open, ["SIG-issue"]);

    let legacy = store
        .record_evidence(
            &serde_json::to_vec(&json!({
                "schema_version": 1,
                "case_id": "SIG-issue",
                "facts_sha256": "facts",
                "instance_id": instance.id,
                "reason": "Deployment configuration is unavailable.",
            }))
            .unwrap(),
            "local_validation_blocker",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut issue = store.case("SIG-issue").unwrap();
    issue.evidence.push(legacy);
    store.save_case(&issue).unwrap();
    snapshot.cases[0] = issue;
    let (_, open) = pending(&snapshot, &store);
    assert_eq!(open, ["SIG-issue"]);

    snapshot.cases[0] = vulnbell::sandbox::record_blocker(
        &mut store,
        "SIG-issue",
        None,
        vulnbell::sandbox::BlockerKind::DetailsUndisclosed,
        "The report withholds the trigger until a fix ships.",
    )
    .unwrap();
    let (_, open) = pending(&snapshot, &store);
    assert!(open.is_empty());
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    let check = &report
        .finding_checks
        .iter()
        .find(|check| check.case_id == "SIG-issue")
        .unwrap()
        .local_checks[0];
    assert_eq!(
        check.blocker,
        Some(vulnbell::sandbox::BlockerKind::DetailsUndisclosed)
    );
    assert!(check.detail.starts_with("details not disclosed: "));
    let old_evidence_count = snapshot.cases[0].evidence.len();
    snapshot.cases[0] = vulnbell::sandbox::clear_blocker(
        &mut store,
        "SIG-issue",
        None,
        "The previous blocker was misclassified; verification is still required.",
    )
    .unwrap();
    assert!(snapshot.cases[0].evidence.len() > old_evidence_count);
    let (_, open) = pending(&snapshot, &store);
    assert_eq!(open, ["SIG-issue"]);
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    let check = &report
        .finding_checks
        .iter()
        .find(|check| check.case_id == "SIG-issue")
        .unwrap()
        .local_checks[0];
    assert_eq!(check.result, vulnbell::output::LocalResult::NotRun);
    assert!(check.detail.contains("misclassified"));
    let invalid = store
        .record_evidence(
            b"not a valid blocker",
            "local_validation_blocker",
            None,
            EvidenceKind::Context,
        )
        .unwrap();
    let mut issue = store.case("SIG-issue").unwrap();
    issue.evidence.push(invalid);
    store.save_case(&issue).unwrap();
    snapshot.cases[0] = issue;
    let report = vulnbell::output::morning_report(&snapshot, &store, "cyber").unwrap();
    assert_eq!(
        report.verification_pending[0].reason,
        vulnbell::output::PendingReason::InvalidVerificationEvidence
    );
    drop(store);
    std::fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
