use super::text::{self, fill};
use super::{
    FindingCheck, HandoffItem, LocalResult, MonitoredComponent, MorningReport, PendingReason,
    verification,
};
use crate::{
    impact::{ImpactAnswerValue, ImpactQuestionId, ImpactResult, ImpactVerdict},
    model::{Decision, SourceFacts},
    profile::Language,
};
use std::collections::HashMap;

type Checks<'a> = HashMap<&'a str, &'a FindingCheck>;

fn case_impact<'a>(checks: &Checks<'a>, case_id: &str) -> Option<&'a ImpactResult> {
    checks.get(case_id)?.impact.as_ref()
}

/// Cases without an assessment rank with those that need evidence.
fn impact_rank(checks: &Checks<'_>, case_id: &str) -> u8 {
    crate::impact::verdict_priority(
        case_impact(checks, case_id).map_or(ImpactVerdict::NeedsEvidence, |impact| impact.verdict),
    )
}

/// An affected library version whose recorded project impact rules out exposure.
fn contained(impact: &ImpactResult) -> bool {
    matches!(
        impact.verdict,
        ImpactVerdict::NotAffected | ImpactVerdict::Mitigated
    )
}

/// The rationale of the answer that closed the project impact.
fn containment_reason(impact: &ImpactResult) -> &str {
    impact
        .answers
        .iter()
        .find(|answer| {
            answer.answer == ImpactAnswerValue::No
                && answer.question != ImpactQuestionId::FixOrMitigationApplied
        })
        .or_else(|| {
            impact.answers.iter().find(|answer| {
                answer.answer == ImpactAnswerValue::Yes
                    && answer.question == ImpactQuestionId::FixOrMitigationApplied
            })
        })
        .map_or("", |answer| answer.rationale.as_str())
}

fn impact_action(language: Language, verdict: ImpactVerdict, fixes: &str) -> Option<String> {
    let words = text::text(language);
    let target = if fixes.is_empty() {
        words.fix_target_default
    } else {
        fixes
    };
    let template = match verdict {
        ImpactVerdict::UrgentUpdate => words.action_urgent,
        ImpactVerdict::PriorityUpdate => words.action_priority,
        ImpactVerdict::RoutineUpdate => words.action_routine,
        ImpactVerdict::NeedsEvidence | ImpactVerdict::NotAffected | ImpactVerdict::Mitigated => {
            return None;
        }
    };
    Some(fill(template, &[&target]))
}

fn fixed_versions(item: &HandoffItem) -> String {
    let mut fixes: Vec<&str> = item
        .advisory_details
        .iter()
        .flat_map(|detail| detail.fixed_versions.iter().map(String::as_str))
        .collect();
    fixes.sort_unstable();
    fixes.dedup();
    fixes.join(", ")
}

fn impact_summary(checks: &Checks<'_>, language: Language, case_id: &str) -> Option<String> {
    let impact = case_impact(checks, case_id)?;
    Some(fill(
        text::text(language).impact_summary,
        &[
            &text::impact_verdict(language, impact.verdict),
            &text::confidence(language, impact.confidence),
        ],
    ))
}

pub(super) const LISTED_COMPONENTS: usize = 3;

/// Component labels of one case; more than a few that share version and location, such as every
/// artifact of one release in an SBOM, become one count with examples. JSON keeps the full list.
fn components_label(provenance: &[String], language: Language) -> String {
    if provenance.len() <= LISTED_COMPONENTS {
        return provenance.join("; ");
    }
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
    for label in provenance {
        let (component, origin) = label
            .split_once(' ')
            .map_or((label.as_str(), ""), |(reference, rest)| (reference, rest));
        match groups.iter_mut().find(|(known, _)| *known == origin) {
            Some((_, components)) => components.push(component),
            None => groups.push((origin, vec![component])),
        }
    }
    groups
        .into_iter()
        .map(|(origin, components)| {
            if components.len() <= LISTED_COMPONENTS {
                return components
                    .iter()
                    .map(|component| format!("{component} {origin}"))
                    .collect::<Vec<_>>()
                    .join("; ");
            }
            let examples = components
                .iter()
                .take(2)
                .map(|component| component.rsplit('/').next().unwrap_or(component))
                .collect::<Vec<_>>()
                .join(", ");
            fill(
                text::text(language).components_group,
                &[&components.len(), &origin, &examples],
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn morning_markdown(report: &MorningReport) -> String {
    let language = report.language;
    let words = text::text(language);
    let mut checks: Checks<'_> = HashMap::with_capacity(report.finding_checks.len());
    for check in &report.finding_checks {
        checks.entry(check.case_id.as_str()).or_insert(check);
    }
    let assessed = |item: &&HandoffItem| case_impact(&checks, &item.case_id).is_some();
    let actionable: Vec<&HandoffItem> = report.actionable.iter().filter(assessed).collect();
    let needs_review: Vec<&HandoffItem> = report.needs_review.iter().filter(assessed).collect();
    let mut unassessed: Vec<&HandoffItem> = report
        .actionable
        .iter()
        .chain(&report.needs_review)
        .filter(|item| !assessed(item))
        .collect();
    unassessed.sort_by_key(|item| !item.known_exploited);
    let mut text = fill(
        words.header,
        &[
            &inline(&report.project_name),
            &report.last_scan,
            &report.last_agent_review.as_deref().unwrap_or(words.pending),
            &actionable.len(),
            &needs_review.len(),
            &unassessed.len(),
            &report.informational_count,
            &report.dismissed_count,
            &report.not_applicable_count,
            &coverage_groups(&report.coverage_gaps).len(),
            &report.coverage_gaps.len(),
        ],
    );
    for (items, label) in [
        (&actionable, words.contained_actionable_prefix),
        (&needs_review, words.contained_review_prefix),
    ] {
        let contained_count = items
            .iter()
            .filter(|item| case_impact(&checks, &item.case_id).is_some_and(contained))
            .count();
        if contained_count > 0 {
            text.push_str(&fill(
                words.contained_split,
                &[&label, &(items.len() - contained_count), &contained_count],
            ));
        }
    }
    if !report.verification_pending.is_empty() {
        let count = |reason| {
            report
                .verification_pending
                .iter()
                .filter(|pending| pending.reason == reason)
                .count()
        };
        text.insert_str(
            text.find("\n\n").map_or(0, |index| index + 2),
            &fill(
                words.incomplete_banner,
                &[
                    &count(PendingReason::ImpactNotAssessed),
                    &count(PendingReason::ReviewDispositionMissing),
                    &count(PendingReason::SandboxCheckMissing),
                    &count(PendingReason::InvalidVerificationEvidence),
                ],
            ),
        );
    }
    let missing_verdict = actionable
        .iter()
        .chain(&needs_review)
        .filter(|item| item.recorded_verdict.is_none())
        .count();
    if missing_verdict > 0 {
        let message = if language == Language::Es {
            "Con impacto evaluado, pero sin veredicto vigente"
        } else {
            "Impact assessed, but no current verdict"
        };
        text.push_str(&format!("{message}: **{missing_verdict}**.\n\n"));
    }
    if report.workspace_scope_changed {
        text.push_str(if language == Language::Es {
            "> **Workspaces modificados:** ejecute un nuevo scan antes de continuar.\n\n"
        } else {
            "> **Workspace configuration changed:** run a new scan before continuing.\n\n"
        });
    }
    text.push_str(&workspace_revisions_markdown(
        &report.workspace_revisions,
        report.workspace_context_unrecorded,
        language,
    ));
    text.push_str(&inventory_markdown(&report.inventory, language));
    text.push_str(&super::discovery::discovery_summary_markdown(report));
    for (decision, items) in [
        (Decision::Actionable, &actionable),
        (Decision::Review, &needs_review),
    ] {
        let label = if decision == Decision::Actionable {
            words.heading_actionable
        } else {
            words.heading_review
        };
        text.push_str(&format!("## {label}\n\n"));
        if items.is_empty() {
            text.push_str(words.no_findings);
            continue;
        }
        if decision == Decision::Review {
            let (contained_items, mut rows): (Vec<&HandoffItem>, Vec<&HandoffItem>) = items
                .iter()
                .copied()
                .partition(|item| case_impact(&checks, &item.case_id).is_some_and(contained));
            rows.sort_by_key(|item| std::cmp::Reverse(impact_rank(&checks, &item.case_id)));
            if rows.is_empty() {
                text.push_str(words.no_exposed_hypotheses);
            } else {
                text.push_str(words.review_table_header);
            }
            for item in rows {
                let check = checks.get(item.case_id.as_str()).copied();
                let handoff = check.and_then(|check| check.review_handoff.as_ref());
                let mut review_context = fill(
                    words.review_context,
                    &[
                        &text::applicability(language, item.applicability),
                        &text::verification(language, item.verification),
                    ],
                );
                for facts in &item.source_facts {
                    review_context.push_str(words.per_source);
                    review_context.push_str(&source_facts_text(facts, language));
                    review_context.push('.');
                }
                if handoff.is_none() {
                    for question in &item.open_questions {
                        review_context.push(' ');
                        review_context.push_str(question);
                    }
                }
                if let Some(verdict) = &item.recorded_verdict {
                    review_context.push_str(words.recorded_verdict_inline);
                    review_context.push_str(verdict);
                }
                if let Some(impact) = impact_summary(&checks, language, &item.case_id) {
                    review_context.push_str(words.impact_inline);
                    review_context.push_str(&impact);
                }
                if let Some(handoff) = handoff {
                    review_context.push(' ');
                    review_context.push_str(&handoff.rationale);
                    review_context.push(' ');
                    review_context.push_str(&handoff.uncertainty);
                }
                let link = item
                    .evidence_links
                    .first()
                    .map(|link| {
                        format!(
                            "<{}>",
                            link.replace(['<', '>', '\n', '\r'], "").replace('|', "%7C")
                        )
                    })
                    .unwrap_or_else(|| words.no_link.into());
                let blocked = check.is_some_and(|check| {
                    !check.local_checks.is_empty()
                        && check
                            .local_checks
                            .iter()
                            .all(|local| local.result == LocalResult::Blocked)
                });
                let next_step = if let Some(handoff) = handoff {
                    inline(&handoff.next_step)
                } else if blocked {
                    words.resolve_blocker.to_owned()
                } else {
                    inline(&item.recommended_action)
                };
                text.push_str(&format!(
                    "| {} / {} | {} | {} | {} | {} |\n",
                    inline(&item.case_id),
                    inline(&components_label(&item.provenance, language)),
                    inline(&item.summary),
                    inline(&review_context),
                    next_step,
                    link
                ));
            }
            text.push('\n');
            text.push_str(&contained_markdown(
                report,
                &checks,
                &contained_items,
                words.contained_review_heading,
            ));
            continue;
        }
        let (contained_items, mut cards): (Vec<&HandoffItem>, Vec<&HandoffItem>) = items
            .iter()
            .copied()
            .partition(|item| case_impact(&checks, &item.case_id).is_some_and(contained));
        cards.sort_by_key(|item| std::cmp::Reverse(impact_rank(&checks, &item.case_id)));
        if cards.is_empty() {
            text.push_str(words.no_exposed_findings);
        }
        for item in cards {
            let impact = case_impact(&checks, &item.case_id);
            let fixes = fixed_versions(item);
            text.push_str(&format!(
                "### {} — {}\n\n",
                item.case_id,
                inline(&item.summary)
            ));
            if item.provenance.len() > LISTED_COMPONENTS {
                text.push_str(&fill(
                    words.card_components,
                    &[
                        &item.provenance.len(),
                        &inline(&components_label(&item.provenance, language)),
                    ],
                ));
            } else {
                for provenance in &item.provenance {
                    text.push_str(&fill(words.card_component, &[&inline(provenance)]));
                }
            }
            if let Some(verdict) = &item.recorded_verdict {
                text.push_str(&fill(words.card_verdict, &[&inline(verdict)]));
            }
            text.push_str(&fill(
                words.card_impact,
                &[&impact_summary(&checks, language, &item.case_id)
                    .unwrap_or_else(|| words.impact_not_assessed.to_owned())],
            ));
            text.push_str(&fill(
                words.card_state,
                &[
                    &text::applicability(language, item.applicability),
                    &text::verification(language, item.verification),
                    &if item.known_exploited {
                        words.kev_yes
                    } else {
                        words.kev_none
                    },
                ],
            ));
            for facts in &item.source_facts {
                text.push_str(&fill(
                    words.card_source_facts,
                    &[&inline(&source_facts_text(facts, language))],
                ));
            }
            let mut severities = item
                .advisory_details
                .iter()
                .filter_map(|detail| {
                    detail.severity.as_ref().map(|severity| {
                        format!(
                            "{}: {} ({})",
                            text::source_label(language, &detail.source),
                            severity,
                            detail.advisory_id
                        )
                    })
                })
                .collect::<Vec<_>>();
            severities.sort();
            severities.dedup();
            if !severities.is_empty() {
                text.push_str(&fill(
                    words.card_severity,
                    &[&inline(&severities.join("; "))],
                ));
            }
            let mut descriptions = Vec::new();
            for detail in &item.advisory_details {
                let normalized = advisory_excerpt(&detail.description);
                if !normalized.is_empty() && !descriptions.contains(&normalized) {
                    descriptions.push(normalized);
                }
            }
            for description in descriptions.iter().take(2) {
                let excerpt = description.chars().take(300).collect::<String>();
                text.push_str(&fill(
                    words.card_problem,
                    &[
                        &inline(&excerpt),
                        &if description.chars().count() > 300 {
                            words.excerpt_more
                        } else {
                            ""
                        },
                    ],
                ));
            }
            text.push_str(&fill(
                words.card_fixes,
                &[&if fixes.is_empty() {
                    words.no_fix.to_owned()
                } else {
                    fill(words.fix_check, &[&inline(&fixes)])
                }],
            ));
            match impact {
                Some(impact) => {
                    let mut seen = std::collections::BTreeSet::new();
                    for answer in &impact.answers {
                        let assessed = !matches!(
                            answer.question,
                            ImpactQuestionId::ArtifactDeployed
                                | ImpactQuestionId::FixOrMitigationApplied
                        );
                        if assessed && seen.insert((answer.question, answer.rationale.as_str())) {
                            let label = text::impact_question(language, answer.question);
                            let mut label_chars = label.chars();
                            let label = label_chars.next().map_or(String::new(), |first| {
                                first.to_uppercase().chain(label_chars).collect()
                            });
                            text.push_str(&format!(
                                "- **{}:** {} — {}\n",
                                label,
                                text::impact_answer(language, answer.answer),
                                inline(&answer.rationale)
                            ));
                        }
                    }
                    let mut open: Vec<&str> = impact
                        .instances
                        .iter()
                        .flat_map(|instance| instance.open_questions.iter())
                        .map(|question| text::impact_question(language, *question))
                        .collect();
                    open.sort_unstable();
                    open.dedup();
                    if !open.is_empty() {
                        text.push_str(&format!(
                            "- **{}:** {}.\n",
                            words.to_check,
                            inline(&open.join(", "))
                        ));
                    }
                }
                None => {
                    for question in &item.open_questions {
                        text.push_str(&format!("- **{}:** {}\n", words.to_check, inline(question)));
                    }
                }
            }
            let action = impact
                .and_then(|impact| impact_action(language, impact.verdict, &fixes))
                .unwrap_or_else(|| item.recommended_action.clone());
            text.push_str(&format!("- **{}:** {}\n", words.action, inline(&action)));
            for link in &item.evidence_links {
                text.push_str(&format!(
                    "- **{}:** <{}>\n",
                    words.evidence,
                    link.replace(['<', '>', '\n', '\r'], "")
                ));
            }
            for gap in &item.detail_gaps {
                text.push_str(&format!(
                    "- **{}:** {}\n",
                    words.detail_pending,
                    inline(gap)
                ));
            }
            text.push('\n');
        }
        text.push_str(&contained_markdown(
            report,
            &checks,
            &contained_items,
            words.contained_actionable_heading,
        ));
    }
    if !unassessed.is_empty() {
        text.push_str(if language == Language::Es {
            "## Señales sin evaluación vigente\n\nLa evidencia anterior puede servir, pero debe contrastarse con los datos actuales. La lista completa está en el reporte JSON y la cola.\n\n"
        } else {
            "## Signals without a current assessment\n\nEarlier evidence may help but must be checked against current facts. The JSON report and queue contain the complete list.\n\n"
        });
        for item in unassessed.iter().take(8) {
            text.push_str(&format!(
                "- `{}` — {}: {}",
                inline(&item.case_id),
                inline(&components_label(&item.provenance, language)),
                inline(&item.summary)
            ));
            if let Some(link) = item.evidence_links.first() {
                text.push_str(&format!(" <{}>", link.replace(['<', '>', '\n', '\r'], "")));
            }
            text.push('\n');
        }
        text.push('\n');
    }
    text.push_str(&coverage_markdown(report));
    text.push_str(&fill(
        words.delivery,
        &[&inline(&text::notification_status(
            language,
            &report.notification_status,
        ))],
    ));
    text.push_str(&verification_section(report, false));
    text
}
/// Advisories that match the version but whose recorded impact rules out project exposure, one
/// row per component and recorded reason; per-case detail stays in the JSON report.
fn contained_markdown(
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

/// Advisory IDs, or `owner/repo#number` for upstream research events, so a reader can find the
/// source without the internal case ID.
fn case_labels(item: &HandoffItem) -> Vec<String> {
    if !item.advisory_details.is_empty() {
        return item
            .advisory_details
            .iter()
            .map(|detail| detail.advisory_id.clone())
            .collect();
    }
    let forge = item.evidence_links.iter().find_map(|link| {
        let url = url::Url::parse(link).ok()?;
        let segments: Vec<&str> = url.path_segments()?.collect();
        match segments.as_slice() {
            [owner, repo, "issues" | "pull", number, ..] => {
                Some(format!("{owner}/{repo}#{number}"))
            }
            _ => None,
        }
    });
    vec![forge.unwrap_or_else(|| item.case_id.clone())]
}

/// Locked packages are summarized per lockfile; declared, deployed and observed components are
/// listed with their source location. The full inventory stays in the JSON report.
fn inventory_markdown(inventory: &[MonitoredComponent], language: Language) -> String {
    let words = text::text(language);
    let mut text = words.inventory_heading.to_owned();
    let mut lockfiles: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut listed = Vec::new();
    for component in inventory {
        let location = match (&component.workspace, &component.path) {
            (Some(workspace), Some(path)) => format!("{}/{path}", workspace.trim_end_matches('/')),
            (None, Some(path)) => path.clone(),
            (_, None) => words.profile_location.to_owned(),
        };
        if component.origin == crate::model::Origin::Locked {
            *lockfiles.entry(location).or_default() += 1;
        } else {
            let location = match component.line {
                Some(line) => format!("{location}:{line}"),
                None => location,
            };
            listed.push((component, location));
        }
    }
    if !lockfiles.is_empty() {
        text.push_str(words.lockfile_table);
        for (location, count) in &lockfiles {
            text.push_str(&format!("| {} | {count} |\n", inline(location)));
        }
        text.push('\n');
    }
    if !listed.is_empty() {
        text.push_str(words.inventory_table);
        for (component, location) in listed {
            text.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                inline(&component.reference),
                inline(
                    component
                        .resolved_version
                        .as_deref()
                        .unwrap_or(words.unresolved)
                ),
                inline(&location),
                text::origin(language, component.origin)
            ));
        }
        text.push('\n');
    }
    text.push_str(&fill(words.inventory_total, &[&inventory.len()]));
    text
}

/// Gaps sharing source, state and detail are one row with a count and example scopes.
fn coverage_groups(gaps: &[crate::model::Coverage]) -> Vec<(&crate::model::Coverage, Vec<&str>)> {
    let mut groups: Vec<(&crate::model::Coverage, Vec<&str>)> = Vec::new();
    let mut positions: HashMap<
        (
            &str,
            std::mem::Discriminant<crate::model::CoverageState>,
            &str,
        ),
        usize,
    > = HashMap::new();
    for gap in gaps {
        let key = (
            gap.source.as_str(),
            std::mem::discriminant(&gap.state),
            gap.detail.as_str(),
        );
        if let Some(&position) = positions.get(&key) {
            groups[position].1.push(&gap.scope);
        } else {
            positions.insert(key, groups.len());
            groups.push((gap, vec![&gap.scope]));
        }
    }
    groups
}

/// Scopes are instance IDs; readers need the component they stand for.
fn coverage_markdown(report: &MorningReport) -> String {
    let language = report.language;
    let words = text::text(language);
    let mut inventory = HashMap::with_capacity(report.inventory.len());
    for component in &report.inventory {
        inventory
            .entry(component.instance_id.as_str())
            .or_insert(component);
    }
    let scope_label = |scope: &str| {
        inventory.get(scope).map_or_else(
            || inline(scope),
            |component| {
                let version = component
                    .resolved_version
                    .as_deref()
                    .or(component.requested_version.as_deref())
                    .unwrap_or(words.no_version);
                inline(&format!("{} {version}", component.reference))
            },
        )
    };
    let mut text = words.coverage_table.to_owned();
    for (gap, scopes) in coverage_groups(&report.coverage_gaps) {
        let examples = scopes
            .iter()
            .take(3)
            .map(|scope| scope_label(scope))
            .collect::<Vec<_>>();
        let scope = if scopes.len() > 3 {
            fill(words.scope_examples, &[&scopes.len(), &examples.join(", ")])
        } else {
            examples.join(", ")
        };
        text.push_str(&format!(
            "| {} | {} | {}: {} |\n",
            inline(&text::source_label(language, &gap.source)),
            scope,
            text::coverage_state(language, gap.state),
            inline(&gap.detail)
        ));
    }
    text
}

/// Standalone section for outputs that do not render the case cards.
pub fn verification_markdown(report: &MorningReport) -> String {
    verification_section(report, true)
}

/// Only open cases with possible project exposure get references and local checks; the rest are
/// counted and keep their detail in the JSON report.
fn verification_section(report: &MorningReport, impact_answers: bool) -> String {
    let open: Vec<&FindingCheck> = report
        .finding_checks
        .iter()
        .filter(|check| matches!(check.decision, Decision::Actionable | Decision::Review))
        .collect();
    let (contained_checks, exposed): (Vec<&FindingCheck>, Vec<&FindingCheck>) = open
        .iter()
        .partition(|check| check.impact.as_ref().is_some_and(contained));
    let exposed: Vec<&FindingCheck> = exposed
        .into_iter()
        .filter(|check| {
            impact_answers
                || (check.impact.is_some()
                    && check
                        .local_checks
                        .iter()
                        .any(|local| local.sandbox_needed || local.result != LocalResult::NotRun))
        })
        .collect();
    let words = text::text(report.language);
    let mut text = if !impact_answers && exposed.is_empty() {
        String::new()
    } else {
        verification::markdown(&exposed, impact_answers, report.language)
    };
    if !contained_checks.is_empty() {
        text.push_str(&fill(words.open_contained_note, &[&contained_checks.len()]));
    }
    let closed = report.finding_checks.len() - open.len();
    if closed > 0 {
        text.push_str(&fill(words.closed_note, &[&closed]));
    }
    text
}
fn advisory_excerpt(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !(line.starts_with('_') && line.ends_with('_'))
        })
        .collect::<Vec<_>>()
        .join(" ")
}
pub(super) fn inline(value: &str) -> String {
    let escaped = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('|', "\\|");
    escape_underscores(&escaped)
}

/// An underscore between two alphanumerics never opens or closes emphasis (`KC_DB_URL`).
fn escape_underscores(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut escaped = String::with_capacity(value.len());
    for (index, character) in characters.iter().enumerate() {
        let intraword = index > 0
            && characters[index - 1].is_alphanumeric()
            && characters
                .get(index + 1)
                .is_some_and(|next| next.is_alphanumeric());
        if *character == '_' && !intraword {
            escaped.push('\\');
        }
        escaped.push(*character);
    }
    escaped
}

fn source_facts_text(facts: &SourceFacts, language: Language) -> String {
    let words = text::text(language);
    let mut parts = Vec::new();
    if !facts.identifiers.is_empty() {
        parts.push(fill(words.cites, &[&facts.identifiers.join(", ")]));
    }
    for (label, value) in [
        (words.affects, &facts.affected_versions),
        (words.fixed_in, &facts.fixed_in),
        (words.fix, &facts.fix_reference),
        (words.requires, &facts.required_feature),
    ] {
        if !value.trim().is_empty() {
            parts.push(format!("{label}: {}", value.trim()));
        }
    }
    parts.join("; ")
}

pub(super) fn workspace_revisions_markdown(
    revisions: &[crate::workspace_revision::WorkspaceComparison],
    unrecorded: bool,
    language: Language,
) -> String {
    let es = language == Language::Es;
    if unrecorded {
        return if es {
            "> **Contexto Git no registrado:** ejecute un nuevo scan antes de continuar la revisión.\n\n".into()
        } else {
            "> **Git context not recorded:** run a new scan before continuing the review.\n\n"
                .into()
        };
    }
    if revisions.is_empty() {
        return String::new();
    }
    let mut out = if es {
        "## Workspaces revisados\n\n| Workspace | Rama | Commit | Estado |\n|---|---|---|---|\n"
            .to_owned()
    } else {
        "## Reviewed workspaces\n\n| Workspace | Branch | Commit | State |\n|---|---|---|---|\n"
            .to_owned()
    };
    for item in revisions {
        let reviewed = &item.reviewed;
        let state = if !item.matches {
            if es {
                "Cambió o no está disponible; ejecutar un nuevo scan"
            } else {
                "Changed or unavailable; run a new scan"
            }
        } else if reviewed.state == crate::workspace_revision::RepositoryState::NotGit {
            if es {
                "Sin repositorio Git"
            } else {
                "Not a Git repository"
            }
        } else if reviewed.dirty == Some(true) {
            if es {
                "Cambios locales; el commit no identifica todo el contenido"
            } else {
                "Local changes; the commit does not identify all content"
            }
        } else if es {
            "Sin cambios locales detectados"
        } else {
            "No local changes detected"
        };
        let missing = if es { "no disponible" } else { "unavailable" };
        let branch = reviewed
            .branch
            .as_deref()
            .unwrap_or(if reviewed.commit.is_some() {
                "detached HEAD"
            } else {
                missing
            });
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} |\n",
            inline(&reviewed.workspace),
            inline(branch),
            inline(reviewed.commit.as_deref().unwrap_or(missing)),
            state
        ));
        if !item.matches {
            out.push_str(&format!(
                "| ↳ {} | `{}` | `{}` | {} |\n",
                if es { "actual" } else { "current" },
                inline(item.current.branch.as_deref().unwrap_or(missing)),
                inline(item.current.commit.as_deref().unwrap_or(missing)),
                if es {
                    "requiere revisión"
                } else {
                    "requires review"
                }
            ));
        }
    }
    out.push_str(if es { "\nEl estado local excluye archivos privados, archivos ignorados y contenido de submódulos.\n\n" } else { "\nLocal state excludes private paths, ignored files and submodule contents.\n\n" });
    out
}
