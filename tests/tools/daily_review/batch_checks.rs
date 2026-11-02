use super::super::write;
use std::path::Path;
use vulnbell::{store::Store, tools::cases};

pub(super) fn prepared_report(
    snapshot: &vulnbell::model::Snapshot,
    store: &Store,
    audience: &str,
) -> anyhow::Result<vulnbell::output::MorningReport> {
    let mut report = vulnbell::output::morning_report(snapshot, store, audience)?;
    vulnbell::output::prepare_report_paths(&mut report, store)?;
    Ok(report)
}

pub(super) fn reused_evidence(store: &mut Store, batches: &Path, case_id: &str, facts: &str) {
    let evidence = store
        .case(case_id)
        .unwrap()
        .evidence
        .into_iter()
        .find(|item| item.source == "local_impact_evidence")
        .unwrap();
    let reference = serde_json::json!({"id": evidence.id, "sha256": evidence.sha256});
    let mut reused: cases::ImpactBatch = serde_json::from_value(serde_json::json!({
        "schema_version": 1, "cases": [{"case_id": case_id, "facts_sha256": facts, "question_set_sha256": vulnbell::impact::question_set_sha256(), "answers": [{
            "question": "affected_feature_used", "answer": "unknown",
            "rationale": "The registered note covers this fixture.", "evidence": [reference]
        }]}]
    }))
    .unwrap();
    assert!(cases::apply_impact(store, &reused, batches)[0].applied);
    reused.cases[0].answers[0].evidence[0].sha256 = "forged".into();
    assert!(!cases::apply_impact(store, &reused, batches)[0].applied);
}

pub(super) fn stale_facts(
    store: &mut Store,
    batches: &Path,
    case_id: &str,
    impact: &cases::ImpactBatch,
    verdicts: &cases::VerdictBatch,
) {
    write(
        batches,
        "notes/stale.md",
        "This note belongs only to the earlier case facts.",
    );
    let original_case = store.case(case_id).unwrap();
    let mut updated_case = original_case.clone();
    updated_case.facts_sha256 = "new-facts-after-scan".into();
    store.save_case(&updated_case).unwrap();
    let before = serde_json::to_vec(&store.case(case_id).unwrap()).unwrap();
    let mut old_impact: cases::ImpactBatch =
        serde_json::from_value(serde_json::to_value(impact).unwrap()).unwrap();
    old_impact.cases[0].notes = vec!["notes/stale.md".into()];
    let mut old_verdict: cases::VerdictBatch =
        serde_json::from_value(serde_json::to_value(verdicts).unwrap()).unwrap();
    old_verdict.verdicts[0].notes = vec!["notes/stale.md".into()];
    assert!(!cases::apply_impact(store, &old_impact, batches)[0].applied);
    assert!(!cases::apply_verdicts(store, &old_verdict, batches)[0].applied);
    assert_eq!(
        serde_json::to_vec(&store.case(case_id).unwrap()).unwrap(),
        before
    );
    assert!(
        !store
            .directory
            .join("evidence")
            .join(vulnbell::digest(
                b"This note belongs only to the earlier case facts."
            ))
            .exists()
    );
    store.save_case(&original_case).unwrap();
}
