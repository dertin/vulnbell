use super::markdown as markdown_helpers;
use super::{
    ClosedMode, CoverageState, Decision, Language, Snapshot, Store, branding, ensure_report_store,
    report_codebase_paths, report_codebase_roots, report_codebase_roots_with_history, text,
};
use anyhow::Result;

pub fn markdown(snapshot: &Snapshot) -> String {
    report_codebase_paths(
        &snapshot_markdown(snapshot, Language::En),
        &report_codebase_roots(snapshot),
    )
}

pub fn audit_markdown(snapshot: &Snapshot, store: &Store) -> Result<String> {
    audit_markdown_with_closed(snapshot, store, ClosedMode::Full)
}

pub fn audit_markdown_with_closed(
    snapshot: &Snapshot,
    store: &Store,
    closed: ClosedMode,
) -> Result<String> {
    ensure_report_store(&snapshot.project_id, store)?;
    let roots = report_codebase_roots_with_history(
        &report_codebase_roots(snapshot),
        &snapshot.project_id,
        store,
    )?;
    let mut selected = snapshot.clone();
    let language = text::report_language(store);
    selected
        .cases
        .retain(|case| case.decision != Decision::Retracted);
    if closed == ClosedMode::Full {
        return Ok(report_codebase_paths(
            &snapshot_markdown(&selected, language),
            &roots,
        ));
    }
    selected.cases.retain(|case| {
        matches!(case.decision, Decision::Actionable | Decision::Review)
            || crate::tools::cases::verdict_missing(case, store)
    });
    let base = snapshot_markdown(&selected, language);
    let mut rendered = branding::without_footer(&base).to_owned();
    if closed == ClosedMode::Summary {
        let words = text::text(language);
        rendered.push_str(words.informational_heading);
        rendered.push_str(words.informational_table);
        for case in snapshot.cases.iter().filter(|case| {
            case.decision == Decision::Informational
                && !crate::tools::cases::verdict_missing(case, store)
        }) {
            let components = case
                .instances
                .iter()
                .map(|instance| instance.reference.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            rendered.push_str(&format!(
                "| `{}` | {} | {} |\n",
                markdown_helpers::inline(&case.case_id),
                markdown_helpers::inline(&components),
                markdown_helpers::inline(
                    case.open_questions
                        .first()
                        .map(String::as_str)
                        .unwrap_or(words.informational_context)
                )
            ));
        }
    }
    Ok(report_codebase_paths(
        &branding::finish(&rendered, language),
        &roots,
    ))
}

fn snapshot_markdown(snapshot: &Snapshot, language: Language) -> String {
    let words = text::text(language);
    let status = if snapshot.partial {
        CoverageState::Partial
    } else {
        CoverageState::Checked
    };
    let mut report = text::fill(
        words.audit_header,
        &[
            &branding::LINK,
            &snapshot.project_id,
            &snapshot.finished_at,
            &text::coverage_state(language, status),
            &text::notification_status(language, &snapshot.alert_status),
            &snapshot.instances.len(),
            &snapshot.cases.len(),
        ],
    );
    report.push_str(&markdown_helpers::codebase_revisions_markdown(
        &crate::codebase_revision::compare(&snapshot.codebase_revisions),
        false,
        language,
    ));
    for case in &snapshot.cases {
        report.push_str(&format!(
            "- `{}`: {}; {}; {}\n",
            case.case_id,
            text::decision(language, case.decision),
            text::applicability(language, case.applicability),
            text::verification(language, case.verification)
        ));
    }
    report.push_str(words.audit_coverage_heading);
    for coverage in &snapshot.coverage {
        report.push_str(&format!(
            "- {} / `{}`: {} - {}\n",
            coverage.source,
            coverage.scope,
            text::coverage_state(language, coverage.state),
            text::coverage_detail(language, &coverage.detail).replace(['\n', '\r'], " ")
        ));
    }
    branding::finish(&report, language)
}
