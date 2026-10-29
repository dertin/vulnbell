use serde_json::json;
use std::{fs, path::Path};
use vulnbell::{
    model::{Applicability, Decision, EvidenceReference, Verdict, Verification},
    profile::{self, Profile},
    store::Store,
};
/// The parallel `status` test opens every project read-only, and SQLite can recreate WAL side
/// files while another test deletes its project directory.
fn remove_project(project_id: &str) {
    let directory = vulnbell::store::data_root().join(project_id);
    for _ in 0..20 {
        if fs::remove_dir_all(&directory).is_ok() || !directory.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    fs::remove_dir_all(&directory).unwrap();
}
fn cache(
    store: &Store,
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
    response: serde_json::Value,
) {
    let key = vulnbell::digest(
        format!(
            "{method}:{url}:{}",
            body.map(|value| value.to_string()).unwrap_or_default()
        )
        .as_bytes(),
    );
    store
        .connection
        .execute(
            "INSERT OR REPLACE INTO cache VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                key,
                serde_json::to_vec(&response).unwrap(),
                chrono::Utc::now().timestamp()
            ],
        )
        .unwrap();
}
#[test]
fn manual_then_mixed_monitor_is_auditable_and_preserves_history() {
    let directory = tempfile::tempdir().unwrap();
    // Unique project UUID isolates state without mutating process environment in parallel tests.
    let project = uuid::Uuid::new_v4();
    let path = directory.path().join("vulnbell.yaml");
    let yaml = format!(
        "schema: 1\nproject_id: {project}\nname: contract-fixture\ncomponents:\n  - ref: pkg:npm/lodash\n    version: '4.17.20'\nresearch:\n  web: agent\n"
    );
    fs::write(&path, &yaml).unwrap();
    let profile = profile::load(&path).unwrap();
    let mut store = Store::open(&project.to_string()).unwrap();
    cache(
        &store,
        "GET",
        "https://registry.npmjs.org/lodash/4.17.20",
        None,
        json!({"name":"lodash","version":"4.17.20"}),
    );
    let query = json!({"queries":[{"package":{"purl":"pkg:npm/lodash"},"version":"4.17.20"}]});
    cache(
        &store,
        "POST",
        "https://api.osv.dev/v1/querybatch",
        Some(query),
        json!({"results":[{"vulns":[{"id":"GHSA-synthetic-test"}]}]}),
    );
    cache(
        &store,
        "GET",
        "https://api.osv.dev/v1/vulns/GHSA-synthetic-test",
        None,
        json!({"id":"GHSA-synthetic-test","aliases":["CVE-2099-0001"],"summary":"SYNTHETIC fixture; not a real finding","affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}),
    );
    cache(
        &store,
        "GET",
        "https://api.github.com/advisories?ecosystem=npm&affects=lodash%404.17.20&per_page=100&page=1",
        None,
        json!([{"ghsa_id":"GHSA-synthetic-test","cve_id":"CVE-2099-0001","summary":"SYNTHETIC fixture","withdrawn_at":null}]),
    );
    cache(
        &store,
        "GET",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        None,
        json!({"vulnerabilities":[]}),
    );
    cache(
        &store,
        "GET",
        "https://cveawg.mitre.org/api/cve/CVE-2099-0001",
        None,
        json!({"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED"}}),
    );
    let first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(first.instances.len(), 1);
    assert_eq!(first.cases.len(), 1);
    assert_eq!(first.cases[0].claims.len(), 2);
    assert_eq!(first.cases[0].decision, Decision::Actionable);
    assert!(first.partial);
    let case = &first.cases[0];
    let forged = Verdict {
        workspace_revisions: Vec::new(),
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        applicability: Applicability::Affected,
        verification: Verification::LabReproduced,
        decision: Decision::Actionable,
        rationale: "forged".into(),
        evidence: vec![EvidenceReference {
            id: case.evidence[0].id.clone(),
            sha256: case.evidence[0].sha256.clone(),
        }],
    };
    assert!(vulnbell::engine::triage(&mut store, &case.case_id, forged).is_err());
    let second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(second.cases[0].facts_sha256, case.facts_sha256);
    cache(
        &store,
        "GET",
        "https://api.osv.dev/v1/vulns/GHSA-synthetic-test",
        None,
        json!({"id":"GHSA-synthetic-test","aliases":["CVE-2099-0000","CVE-2099-0001"],"summary":"SYNTHETIC alias assignment update","affected":[{"package":{"purl":"pkg:npm/lodash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}),
    );
    let aliased = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(aliased.cases.len(), 1);
    assert_eq!(aliased.cases[0].case_id, case.case_id);
    fs::create_dir(directory.path().join("workspace")).unwrap();
    let mut workspace_lock: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/workspace/js/package-lock.json")).unwrap();
    workspace_lock["packages"][""]["dependencies"] = json!({"lodash":"4.17.20"});
    fs::write(
        directory.path().join("workspace/package-lock.json"),
        serde_json::to_vec(&workspace_lock).unwrap(),
    )
    .unwrap();
    let before = fs::read(directory.path().join("workspace/package-lock.json")).unwrap();
    fs::write(&path, format!("{yaml}workspaces: [workspace]\n")).unwrap();
    let mixed: Profile = profile::load(&path).unwrap();
    let snapshot = vulnbell::engine::scan(&mixed, &path, true).unwrap();
    assert_eq!(snapshot.instances.len(), 4);
    assert_eq!(snapshot.project_id, first.project_id);
    assert_eq!(
        fs::read(directory.path().join("workspace/package-lock.json")).unwrap(),
        before
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        format!("{yaml}workspaces: [workspace]\n")
    );
    let count: u32 = store
        .connection
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 4);
    let locked_case = snapshot
        .cases
        .iter()
        .find(|case| case.instances[0].origin == vulnbell::model::Origin::Locked)
        .unwrap();
    let mut research_case = locked_case.clone();
    research_case.case_id = "SIG-synthetic-research-context".into();
    research_case.claims.clear();
    research_case.evidence.clear();
    research_case.decision = Decision::Informational;
    store.save_case(&research_case).unwrap();
    let lock_path = directory.path().join("workspace/package-lock.json");
    let mut lock: serde_json::Value = serde_json::from_slice(&before).unwrap();
    lock["packages"]["node_modules/aaa-unrelated"] = json!({"version":"1.0.0"});
    fs::write(&lock_path, serde_json::to_vec_pretty(&lock).unwrap()).unwrap();
    let expanded = vulnbell::engine::scan(&mixed, &path, true).unwrap();
    let unchanged = expanded
        .cases
        .iter()
        .find(|case| case.case_id == locked_case.case_id)
        .unwrap();
    assert_eq!(unchanged.facts_sha256, locked_case.facts_sha256);
    assert_eq!(
        store.case(&research_case.case_id).unwrap().decision,
        Decision::Informational
    );
    assert_ne!(
        unchanged.instances[0].provenance.sha256,
        locked_case.instances[0].provenance.sha256
    );
    lock["packages"]["node_modules/lodash"]["integrity"] = json!("sha512-changed-artifact");
    fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
    let changed = vulnbell::engine::scan(&mixed, &path, true).unwrap();
    let reopened = changed
        .cases
        .iter()
        .find(|case| case.case_id == locked_case.case_id)
        .unwrap();
    assert_ne!(reopened.facts_sha256, locked_case.facts_sha256);
    let research_reopened = store.case(&research_case.case_id).unwrap();
    assert_eq!(research_reopened.decision, Decision::Review);
    assert_ne!(research_reopened.facts_sha256, research_case.facts_sha256);
    drop(store);
    remove_project(&project.to_string());
}
#[test]
fn cli_scaffold_is_valid_and_scan_rejects_empty_scope() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vulnbell.yaml");
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["init", "--output"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let initialized: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["validate"])
        .arg(&path)
        .arg("--json")
        .assert()
        .success();
    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["scan", "--project"])
        .arg(&path)
        .arg("--offline")
        .assert()
        .failure();
    assert!(profile::load(Path::new(&path)).is_ok());
    remove_project(initialized["project_id"].as_str().unwrap());
}

#[test]
fn status_lists_registered_projects_and_persisted_schedule_outcomes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vulnbell.yaml");
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["init", "--output"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let initialized: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let project_id = initialized["project_id"].as_str().unwrap();
    let mut profile = profile::load(&path).unwrap();
    profile.schedule = Some(vulnbell::profile::Schedule::Daily);
    fs::write(&path, serde_saphyr::to_string(&profile).unwrap()).unwrap();

    let store = Store::open(project_id).unwrap();
    let runner_id = format!("status-{project_id}");
    let runner = vulnbell::runners::RunnerConfig {
        schema_version: 1,
        id: runner_id.clone(),
        adapter: vulnbell::runners::AdapterConfig::Codex {
            executable: std::env::current_exe().unwrap(),
            model: None,
        },
    };
    vulnbell::runners::save(&runner).unwrap();
    let config = vulnbell::scheduler::ScheduleConfig {
        schema_version: 2,
        project_id: project_id.into(),
        runner: runner_id.clone(),
        timezone: "America/Montevideo".into(),
        at: "08:00".into(),
        window_minutes: 180,
        frequency: vulnbell::scheduler::Frequency::Daily,
        report_dir: directory.path().join("reports"),
    };
    vulnbell::scheduler::save_config(&profile, &store, &config).unwrap();
    store
        .set_meta(
            "last_skipped_job",
            r#"{"schema_version":1,"state":"skipped_expired","slot":"2026-10-24-0800","expires_at":"2026-10-24T14:00:00Z","next_iteration":"timer schedule; no late catch-up"}"#,
        )
        .unwrap();
    store
        .set_meta("last_job_outcome", "partial_fallback_report")
        .unwrap();
    store
        .set_meta(
            "last_report",
            &directory.path().join("reports/latest.md").to_string_lossy(),
        )
        .unwrap();
    drop(store);

    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let project = status["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|project| project["project_id"] == project_id)
        .unwrap();
    assert_eq!(project["profile_available"], true);
    assert_eq!(project["schedule"]["requested"], "daily");
    assert_eq!(project["schedule"]["configured"], true);
    assert_eq!(project["schedule"]["configuration_valid"], true);
    assert_eq!(project["schedule"]["runner"], runner_id);
    assert_eq!(project["schedule"]["runner_configured"], true);
    assert_eq!(project["schedule"]["installed"], false);
    assert_eq!(project["schedule"]["healthy"], false);
    assert_eq!(
        project["schedule"]["last_skipped_job"]["state"],
        "skipped_expired"
    );
    assert_eq!(
        project["schedule"]["last_job_outcome"],
        "partial_fallback_report"
    );

    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .arg("status")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("requested but not ready"));
    assert!(text.contains("2026-10-24-0800"));

    fs::remove_file(&path).unwrap();
    let output = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let project = status["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|project| project["project_id"] == project_id)
        .unwrap();
    assert_eq!(project["profile_available"], false);
    assert!(
        project["errors"][0]
            .as_str()
            .unwrap()
            .contains("profile unavailable or invalid")
    );

    remove_project(project_id);
    fs::remove_file(vulnbell::runners::config_path(&runner_id).unwrap()).unwrap();
}

#[test]
fn offline_scan_skips_a_configured_notification_without_resolving_its_secret() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: offline-notifications\ncomponents:\n  - ref: unknown-product\n")).unwrap();
    let mut profile = profile::load(&path).unwrap();
    profile.alerts.webhook_env = Some("VULNBELL_TEST_ABSENT_WEBHOOK".into());
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(
        snapshot.alert_status,
        "offline: notification delivery skipped"
    );
    remove_project(&project);
}

#[test]
fn a_repository_advisory_confirms_the_version_and_absorbs_the_research_case() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(
        &path,
        format!(
            "schema: 1\nproject_id: {project}\nname: repository-advisories\ncomponents:\n  - ref: pkg:cargo/synthetic-crate\n    version: '1.2.0'\n    upstream: https://github.com/synthetic-org/synthetic-crate\nresearch:\n  web: agent\n"
        ),
    )
    .unwrap();
    let profile = profile::load(&path).unwrap();
    let mut store = Store::open(&project.to_string()).unwrap();
    let advisories_url = "https://api.github.com/repos/synthetic-org/synthetic-crate/security-advisories?state=published&per_page=100&page=1";
    cache(&store, "GET", advisories_url, None, json!([]));
    let first = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert!(first.cases.is_empty());
    let instance = first.instances[0].clone();
    let research = vulnbell::model::Case {
            workspace_revisions: Vec::new(),
        schema_version: 1,
        case_id: "SIG-synthetic-research-advisory".into(),
        project_id: project.to_string(),
        snapshot_id: first.id.clone(),
        instances: vec![instance.clone()],
        claims: Vec::new(),
        upstream_events: vec![vulnbell::model::UpstreamEvent {
            provider: "github".into(),
            kind: "advisory".into(),
            id: "synthetic-org/synthetic-crate/GHSA-synt-hetc-0001".into(),
            url: "https://github.com/synthetic-org/synthetic-crate/security/advisories/GHSA-synt-hetc-0001".into(),
            title: "SYNTHETIC fixture".into(),
            updated_at: None,
            sha256: "0".repeat(64),
            source_facts: Default::default(),
        }],
        evidence: Vec::new(),
        coverage: Vec::new(),
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "synthetic".into(),
        open_questions: Vec::new(),
        suggested_search_queries: Vec::new(),
        sandbox: vulnbell::sandbox::availability(),
        updated_at: vulnbell::now(),
    };
    store.save_case(&research).unwrap();
    cache(
        &store,
        "GET",
        advisories_url,
        None,
        json!([
            {"ghsa_id":"GHSA-synt-hetc-0001","cve_id":null,"summary":"SYNTHETIC affected","withdrawn_at":null,
             "vulnerabilities":[{"package":{"ecosystem":"rust","name":"synthetic-crate"},"vulnerable_version_range":">= 1.0.0, < 1.3.0","patched_versions":">= 1.3.0"}]},
            {"ghsa_id":"GHSA-synt-hetc-0002","cve_id":null,"summary":"SYNTHETIC older line","withdrawn_at":null,
             "html_url":"https://github.com/synthetic-org/synthetic-crate/security/advisories/GHSA-synt-hetc-0002",
             "references":["https://github.com/synthetic-org/synthetic-crate/pull/2"],
             "vulnerabilities":[{"package":{"ecosystem":"rust","name":"synthetic-crate"},"vulnerable_version_range":"< 1.0.0"}]},
            {"ghsa_id":"GHSA-synt-hetc-0003","cve_id":null,"summary":"SYNTHETIC ambiguous","withdrawn_at":null,
             "vulnerabilities":[{"package":{"ecosystem":"rust","name":"synthetic-crate"},"vulnerable_version_range":"< 0.5.16, >= 0.6.0 < 0.6.3"}]},
            {"ghsa_id":"GHSA-synt-hetc-0004","cve_id":null,"summary":"SYNTHETIC fixed on the line","withdrawn_at":null,
             "vulnerabilities":[{"package":{"ecosystem":"rust","name":"synthetic-crate"},"vulnerable_version_range":">= 0.9.0","patched_versions":"1.2.0"}]}
        ]),
    );
    let second = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let affected = |snapshot: &vulnbell::model::Snapshot| {
        snapshot
            .cases
            .iter()
            .filter(|case| case.decision == Decision::Actionable)
            .cloned()
            .collect::<Vec<_>>()
    };
    let cases = affected(&second);
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].case_id, research.case_id);
    assert_eq!(cases[0].claims[0].source, "github_repository");
    assert_eq!(cases[0].upstream_events.len(), 1);
    let fixed: Vec<_> = second
        .cases
        .iter()
        .filter(|case| {
            case.claims
                .iter()
                .any(|claim| claim.id == "GHSA-synt-hetc-0004")
        })
        .collect();
    assert_eq!(fixed.len(), 1);
    assert_eq!(fixed[0].decision, Decision::Informational);
    assert_eq!(second.cases.len(), 3);
    assert!(second.cases.iter().any(|case| {
        case.decision == Decision::Review
            && case.claims.iter().any(|claim| {
                claim.id == "GHSA-synt-hetc-0003" && claim.applicability == Applicability::Unknown
            })
    }));
    let coverage = second
        .coverage
        .iter()
        .find(|item| item.source == "repository_advisories" && item.scope == instance.id)
        .unwrap();
    assert!(coverage.detail.contains("GHSA-synt-hetc-0003"));
    let report = vulnbell::output::morning_report(&second, &store, "cyber").unwrap();
    assert_eq!(report.actionable.len(), 1);
    assert_eq!(
        report.actionable[0].advisory_details[0].fixed_versions,
        ["1.3.0"]
    );
    let check = report
        .finding_checks
        .iter()
        .find(|check| check.case_id == research.case_id)
        .unwrap();
    assert!(
        check
            .references
            .iter()
            .all(|reference| !reference.url.contains("GHSA-synt-hetc-0002")
                && !reference.url.ends_with("/pull/2"))
    );

    let late_research = vulnbell::model::Case {
        workspace_revisions: Vec::new(),
        case_id: "SIG-0-late-research".into(),
        snapshot_id: second.id.clone(),
        ..research.clone()
    };
    store.save_case(&late_research).unwrap();
    let third = vulnbell::engine::scan(&profile, &path, true).unwrap();
    let cases = affected(&third);
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].case_id, research.case_id);
    assert_eq!(cases[0].upstream_events.len(), 1);
    assert!(
        third
            .cases
            .iter()
            .all(|case| case.case_id != late_research.case_id)
    );
    drop(store);
    remove_project(&project.to_string());
}

#[test]
fn reimported_research_keeps_promoted_advisory_and_evidence() {
    use vulnbell::research::{
        self, Assessment, EventKind, ResearchBatch, ResearchEvent, ReviewCoverage, SourceReview,
    };
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: research-promotion\ncomponents:\n  - ref: pkg:cargo/synthetic-crate\n    version: '1.2.0'\n    upstream: https://github.com/synthetic-org/synthetic-crate\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let mut store = Store::open(&project).unwrap();
    let advisory_url = "https://api.github.com/repos/synthetic-org/synthetic-crate/security-advisories?state=published&per_page=100&page=1";
    cache(&store, "GET", advisory_url, None, json!([]));
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let plan = research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let event = ResearchEvent {
        workspace_revisions: Vec::new(),
        upstream: target.upstream.clone(), instance_ids: target.instance_ids.clone(),
        reviewed_instance_ids: target.instance_ids.clone(), provider: "github".into(),
        external_id: "synthetic-org/synthetic-crate/GHSA-synt-hetc-0001".into(),
        kind: EventKind::Advisory,
        url: "https://github.com/synthetic-org/synthetic-crate/security/advisories/GHSA-synt-hetc-0001".into(),
        title: "synthetic advisory".into(), excerpt: "synthetic".into(), updated_at: target.until.clone(),
        assessment: Assessment::Review, not_applicable_reason: None,
        rationale: "Review the reported issue.".into(), source_facts: Default::default(),
    };
    let source = |target: &research::ResearchTarget| SourceReview {
        upstream: target.upstream.clone(),
        from: target.from.clone(),
        until: target.until.clone(),
        coverage: ReviewCoverage::Partial,
        detail: "synthetic".into(),
        continuation: None,
    };
    research::import(
        &mut store,
        ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id,
            sources: vec![source(target)],
            events: vec![event.clone()],
        },
    )
    .unwrap();
    let case_id = store.cases().unwrap()[0].case_id.clone();
    cache(
        &store,
        "GET",
        advisory_url,
        None,
        json!([{
            "ghsa_id":"GHSA-synt-hetc-0001","cve_id":null,"summary":"synthetic","withdrawn_at":null,
            "vulnerabilities":[{"package":{"ecosystem":"rust","name":"synthetic-crate"},"vulnerable_version_range":">= 1.0.0, < 1.3.0","patched_versions":">= 1.3.0"}]
        }]),
    );
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let promoted = store.case(&case_id).unwrap();
    assert_eq!(promoted.decision, Decision::Actionable);
    assert!(!promoted.claims.is_empty());
    let plan = research::plan_page(&store, "", 20).unwrap();
    let target = &plan.targets[0];
    let mut updated = event;
    updated.rationale = "The upstream report has additional context.".into();
    research::import(
        &mut store,
        ResearchBatch {
            schema_version: 1,
            project_id: project.clone(),
            snapshot_id: plan.snapshot_id,
            sources: vec![source(target)],
            events: vec![updated],
        },
    )
    .unwrap();
    let current = store.case(&case_id).unwrap();
    assert_eq!(current.decision, Decision::Actionable);
    assert_eq!(current.claims.len(), promoted.claims.len());
    assert!(
        promoted
            .evidence
            .iter()
            .all(|old| current.evidence.iter().any(|new| old.sha256 == new.sha256))
    );
    assert_ne!(current.facts_sha256, promoted.facts_sha256);
    assert!(
        current
            .open_questions
            .iter()
            .any(|question| question.contains("advisory evidence"))
    );
    drop(store);
    remove_project(&project);
}

#[test]
fn contradictory_osv_detail_remains_in_review() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\ncomponents:\n  - ref: pkg:npm/lodash\n    version: '4.17.20'\n")).unwrap();
    let profile = profile::load(&path).unwrap();
    let store = Store::open(&project.to_string()).unwrap();
    cache(
        &store,
        "GET",
        "https://registry.npmjs.org/lodash/4.17.20",
        None,
        json!({"name":"lodash","version":"4.17.20"}),
    );
    cache(
        &store,
        "POST",
        "https://api.osv.dev/v1/querybatch",
        Some(json!({"queries":[{"package":{"purl":"pkg:npm/lodash"},"version":"4.17.20"}]})),
        json!({"results":[{"vulns":[{"id":"GHSA-synthetic-test"}]}]}),
    );
    cache(
        &store,
        "GET",
        "https://api.osv.dev/v1/vulns/GHSA-synthetic-test",
        None,
        json!({"id":"GHSA-synthetic-test","summary":"synthetic conflict","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"versions":["4.17.20"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"database_specific":{"last_known_affected_version_range":"< 1.0.0"}}]}),
    );
    cache(
        &store,
        "GET",
        "https://api.github.com/advisories?ecosystem=npm&affects=lodash%404.17.20&per_page=100&page=1",
        None,
        json!([]),
    );
    cache(
        &store,
        "GET",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        None,
        json!({"vulnerabilities":[]}),
    );
    let snapshot = vulnbell::engine::scan(&profile, &path, true).unwrap();
    assert_eq!(snapshot.cases.len(), 1);
    let case = &snapshot.cases[0];
    assert_eq!(case.claims[0].applicability, Applicability::Unknown);
    assert_eq!(case.decision, Decision::Review);
    assert_eq!(case.verification, Verification::Inconclusive);
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|coverage| coverage.source == "osv"
                && coverage.state == vulnbell::model::CoverageState::Partial)
    );
    drop(store);
    remove_project(&project.to_string());
}

#[test]
fn refreshing_an_affected_repository_advisory_with_ambiguous_details_keeps_it_open() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!(
        "schema: 1\nproject_id: {project}\nname: refresh-advisory\ncomponents:\n  - ref: pkg:cargo/synthetic-crate\n    version: '1.2.0'\n    upstream: https://github.com/synthetic-org/synthetic-crate\n"
    )).unwrap();
    let profile = profile::load(&path).unwrap();
    let mut store = Store::open(&project.to_string()).unwrap();
    let mut instance = vulnbell::model::Instance::declared(&profile.components[0]);
    instance.purl = Some("pkg:cargo/synthetic-crate".into());
    let id = "GHSA-synt-hetc-0001";
    let url = format!(
        "https://api.github.com/repos/synthetic-org/synthetic-crate/security-advisories/{id}"
    );
    let case = vulnbell::model::Case {
        workspace_revisions: Vec::new(),
        schema_version: 1,
        case_id: "SIG-refresh-advisory".into(),
        project_id: project.to_string(),
        snapshot_id: "synthetic".into(),
        instances: vec![instance],
        claims: vec![],
        upstream_events: vec![vulnbell::model::UpstreamEvent {
            provider: "github".into(),
            kind: "advisory".into(),
            id: id.into(),
            url: format!(
                "https://github.com/synthetic-org/synthetic-crate/security/advisories/{id}"
            ),
            title: "fixture".into(),
            updated_at: None,
            sha256: "fixture".into(),
            source_facts: Default::default(),
        }],
        evidence: vec![],
        coverage: vec![],
        applicability: Applicability::Unknown,
        verification: Verification::Inconclusive,
        decision: Decision::Review,
        facts_sha256: "fixture".into(),
        open_questions: vec![],
        suggested_search_queries: vec![],
        sandbox: vulnbell::sandbox::availability(),
        updated_at: vulnbell::now(),
    };
    store.save_case(&case).unwrap();
    let mut document = json!({
        "state":"published", "ghsa_id":id, "cve_id":null, "summary":"fixture", "withdrawn_at":null,
        "vulnerabilities":[{"package":{"ecosystem":"rust","name":"synthetic-crate"},"vulnerable_version_range":">= 1.0.0, < 2.0.0"}]
    });
    cache(&store, "GET", &url, None, document.clone());
    let refresh = || {
        assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("vulnbell"))
            .args(["case", "SIG-refresh-advisory", "--project"])
            .arg(&path)
            .arg("--evidence-url")
            .arg(&url)
            .assert()
            .success();
    };
    refresh();
    let affected = store.case("SIG-refresh-advisory").unwrap();
    assert_eq!(affected.claims.len(), 1);
    assert_eq!(affected.claims[0].applicability, Applicability::Affected);
    let mut changed_version = affected.clone();
    changed_version.instances[0].resolved_version = Some("1.2.0-rc1".into());
    store.save_case(&changed_version).unwrap();
    refresh();
    let changed_version = store.case("SIG-refresh-advisory").unwrap();
    assert_eq!(
        changed_version.claims[0].applicability,
        Applicability::Unknown
    );
    assert_eq!(
        affected.claims[0].evidence.sha256,
        changed_version.claims[0].evidence.sha256
    );
    let mut changed_version = changed_version;
    changed_version.instances[0].resolved_version = Some("1.2.0".into());
    store.save_case(&changed_version).unwrap();
    document["vulnerabilities"][0]["vulnerable_version_range"] = json!(">= 1.0.0, < 1.0.0");
    cache(&store, "GET", &url, None, document);
    refresh();
    let uncertain = store.case("SIG-refresh-advisory").unwrap();
    assert_eq!(uncertain.claims.len(), 1);
    assert_eq!(uncertain.claims[0].applicability, Applicability::Unknown);
    assert_eq!(uncertain.decision, Decision::Review);
    assert_eq!(uncertain.verification, Verification::Inconclusive);
    assert_ne!(
        affected.claims[0].evidence.sha256,
        uncertain.claims[0].evidence.sha256
    );
    drop(store);
    remove_project(&project.to_string());
}
