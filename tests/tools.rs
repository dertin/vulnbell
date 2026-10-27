use chrono::{DateTime, Duration};
use std::{fs, path::Path};
use vulnbell::{
    model::Decision,
    research::Assessment,
    store::Store,
    tools::{cases, draft, hits},
};

fn write(directory: &Path, relative: &str, contents: &str) {
    let path = directory.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

#[test]
fn hits_draft_and_case_batches_cover_one_daily_review() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: tools-fixture\ncomponents:\n  - ref: example\n    version: '1.0.0'\n    upstream: https://github.com/example/project\n")).unwrap();
    let profile = vulnbell::profile::load(&path).unwrap();
    vulnbell::engine::scan(&profile, &path, true).unwrap();
    let mut store = Store::open(&project).unwrap();
    let plan = vulnbell::research::plan_page(&store, "", 20).unwrap();
    let until = DateTime::parse_from_rfc3339(&plan.targets[0].until).unwrap();
    let updated = (until - Duration::minutes(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let raw = directory.path().join("raw");
    let repository = "github/example/project";
    write(
        &raw,
        &format!("{repository}/issues.json"),
        &format!(
            r#"[[
      {{"number": 1, "title": "SYNTHETIC token reuse", "html_url": "https://github.com/example/project/issues/1",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "An attacker can reuse a token. Synthetic fixture."}},
      {{"number": 2, "title": "Check the token audience", "html_url": "https://github.com/example/project/pull/2",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "Fixes #1", "pull_request": {{}}}},
      {{"number": 3, "title": "build(deps): bump example-lib", "html_url": "https://github.com/example/project/pull/3",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "Upstream notes mention a security fix.", "pull_request": {{}}}},
      {{"number": 4, "title": "Docs typo", "html_url": "https://github.com/example/project/issues/4",
        "state": "open", "updated_at": "{updated}", "labels": [], "body": "Wording."}}
    ]]"#
        ),
    );
    write(&raw, &format!("{repository}/releases.json"), "[[]]");
    write(
        &raw,
        &format!("{repository}/security-advisories.json"),
        "[[]]",
    );

    let prepared = hits::prepare(&store, &raw, true).unwrap();
    let packet = hits::packet(&prepared, None);
    assert_eq!(packet.missing.len(), 1);
    assert_eq!(
        packet.missing[0].path,
        format!("{repository}/discussions.json")
    );
    assert_eq!(packet.summary.listed, 4);
    assert_eq!(packet.summary.selected, 3);
    assert_eq!(packet.summary.rule_resolved, 2);
    let keys: Vec<&str> = packet.review.iter().map(|item| item.key.as_str()).collect();
    assert_eq!(keys, vec!["example/project#1"]);

    let decisions_path = directory.path().join("research.json");
    fs::write(&decisions_path, r#"{"schema_version": 1, "decisions": []}"#).unwrap();
    let empty = draft::ResearchDecisions::load(&decisions_path).unwrap();
    assert!(draft::draft(hits::prepare(&store, &raw, true).unwrap(), &empty, false).is_err());

    write(
        &raw,
        &format!("{repository}/discussions.json"),
        r#"[{"data": {"search": {"nodes": []}}}]"#,
    );
    let decisions = serde_json::json!({
        "schema_version": 1,
        "decisions": [{
            "key": "example/project#1",
            "updated_at": updated,
            "assessment": "review",
            "rationale": "Synthetic report of token reuse; check the audience validation in the monitored version."
        }]
    });
    fs::write(&decisions_path, serde_json::to_vec(&decisions).unwrap()).unwrap();
    let decisions = draft::ResearchDecisions::load(&decisions_path).unwrap();
    let (batch, summary) = draft::draft(
        hits::prepare(&store, &raw, true).unwrap(),
        &decisions,
        false,
    )
    .unwrap();
    assert_eq!(summary.complete_sources, 1);
    assert_eq!(summary.events, 3);
    assert_eq!(summary.assessments["ignore"], 2);
    let reviewed = batch
        .events
        .iter()
        .find(|event| event.external_id == "example/project#1")
        .unwrap();
    assert_eq!(reviewed.assessment, Assessment::Review);
    assert_eq!(reviewed.provider, "github");
    let imported = vulnbell::research::import(&mut store, batch).unwrap();
    assert_eq!(imported["changed_cases"], 1);

    let again = hits::packet(&hits::prepare(&store, &raw, true).unwrap(), None);
    assert_eq!(again.summary.unchanged, 3);
    assert!(again.review.is_empty());

    let pending = cases::pending(&store).unwrap();
    assert!(pending.research_open.is_empty());
    assert_eq!(pending.verdict_missing.len(), 1);
    let case_id = pending.verdict_missing[0].clone();

    let batches = directory.path().join("run");
    write(
        &batches,
        "notes/token.md",
        "Synthetic note: audience is validated in src/token.rs:42.",
    );
    write(
        &batches,
        "impact.json",
        &serde_json::json!({
            "schema_version": 1,
            "cases": [{
                "case_id": case_id,
                "notes": ["notes/token.md"],
                "answers": [{
                    "question": "artifact_deployed",
                    "answer": "unknown",
                    "rationale": "Synthetic fixture without deployment records."
                }]
            }]
        })
        .to_string(),
    );
    let impact = cases::load_impact(&batches.join("impact.json")).unwrap();
    let outcomes = cases::apply_impact(&mut store, &impact, &batches);
    assert!(outcomes[0].applied, "{:?}", outcomes[0].error);

    write(
        &batches,
        "verdicts.json",
        &serde_json::json!({
            "schema_version": 1,
            "verdicts": [{
                "case_id": case_id,
                "decision": "review",
                "applicability": "possible",
                "verification": "inconclusive",
                "rationale": "Synthetic fixture; the claim needs a source reading.",
                "notes": ["notes/token.md"]
            }]
        })
        .to_string(),
    );
    let verdicts = cases::load_verdicts(&batches.join("verdicts.json")).unwrap();
    let outcomes = cases::apply_verdicts(&mut store, &verdicts, &batches);
    assert!(outcomes[0].applied, "{:?}", outcomes[0].error);
    let case = store.case(&case_id).unwrap();
    assert_eq!(case.decision, Decision::Review);
    assert_eq!(
        case.evidence
            .iter()
            .filter(|evidence| evidence.source == "local_impact_evidence")
            .count(),
        1
    );
    assert!(cases::pending(&store).unwrap().verdict_missing.is_empty());
    drop(store);
    fs::remove_dir_all(vulnbell::store::data_root().join(project)).unwrap();
}
