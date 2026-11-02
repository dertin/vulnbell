use super::{
    Checks, HandoffItem, MorningReport, case_impact, case_labels, components_label,
    containment_reason, fill, fixed_versions, inline, text,
};

/// Advisories that match the version but whose recorded impact rules out project exposure, one
/// row per component and recorded reason; per-case detail stays in the JSON report.
pub(super) fn contained_markdown(
    report: &MorningReport,
    checks: &Checks<'_>,
    items: &[&HandoffItem],
    heading: &str,
) -> String {
    if items.is_empty() {
        return String::new();
    }
    let words = text::text(report.language);
    let mut groups: std::collections::BTreeMap<(String, String), Vec<&HandoffItem>> =
        std::collections::BTreeMap::new();
    for item in items {
        let reason = case_impact(checks, &item.case_id)
            .map(containment_reason)
            .unwrap_or_default()
            .to_owned();
        groups
            .entry((components_label(&item.provenance, report.language), reason))
            .or_default()
            .push(item);
    }
    let mut text = fill(words.contained_table, &[&heading, &items.len()]);
    for ((component, reason), group) in groups {
        let mut labels: Vec<String> = group.iter().flat_map(|item| case_labels(item)).collect();
        labels.sort();
        labels.dedup();
        let shown = if labels.len() > CONTAINED_LABELS {
            fill(
                words.and_more,
                &[
                    &labels[..CONTAINED_LABELS].join(", "),
                    &(labels.len() - CONTAINED_LABELS),
                ],
            )
        } else {
            labels.join(", ")
        };
        let mut fixes: Vec<String> = group.iter().map(|item| fixed_versions(item)).collect();
        fixes.retain(|fix| !fix.is_empty());
        fixes.sort();
        fixes.dedup();
        text.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            inline(&component),
            inline(&shown),
            inline(&reason),
            inline(&fixes.join("; "))
        ));
    }
    text.push('\n');
    text
}

const CONTAINED_LABELS: usize = 6;
