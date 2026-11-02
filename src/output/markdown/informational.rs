use super::{Language, MorningReport, inline};

pub(super) fn render(report: &MorningReport, language: Language) -> String {
    let words = super::text::text(language);
    let mut text = String::new();
    if report.closed != crate::output::ClosedMode::None && !report.informational.is_empty() {
        text.push_str(words.informational_heading);
        text.push_str(words.informational_table);
        for item in &report.informational {
            let reason: String = item.reason.chars().take(300).collect();
            let context = if item.impact_assessed {
                ""
            } else {
                words.informational_context
            };
            text.push_str(&format!(
                "| `{}` | {} | {} {} |\n",
                inline(&item.case_id),
                inline(&item.components.join(", ")),
                inline(&reason),
                context
            ));
        }
        text.push('\n');
    }
    text
}
