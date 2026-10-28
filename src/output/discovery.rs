use super::MorningReport;
use super::markdown::{LISTED_COMPONENTS, inline};
use super::text::{self, fill};
use crate::{
    discovery::{MappingState, SourceKind},
    model::Decision,
};
use std::collections::{BTreeSet, HashMap};

const SUMMARY_LIST: usize = 30;

pub fn discovery_markdown(report: &MorningReport) -> String {
    let language = report.language;
    let words = text::text(language);
    let mut text = String::new();
    if let Some(discovery) = &report.discovery {
        let state = if !discovery.enabled {
            words.discovery_disabled
        } else if discovery.complete {
            words.discovery_complete
        } else {
            words.discovery_partial
        };
        text.push_str(&fill(
            words.discovery,
            &[
                &state,
                &discovery.directories_pending,
                &discovery.files_pending,
                &discovery.files_reviewed,
                &discovery.files_excluded,
                &discovery.files_unavailable,
                &discovery.components_unmapped,
                &discovery.sources_unavailable,
                &discovery.deferred_transitive,
                &discovery.deferred_unknown_depth,
            ],
        ));
    }
    if !report.source_map.is_empty() {
        let mut references: HashMap<&str, &str> = HashMap::with_capacity(report.inventory.len());
        for item in &report.inventory {
            references
                .entry(&item.instance_id)
                .or_insert(&item.reference);
        }
        let open_instances: std::collections::HashSet<&str> = report
            .finding_checks
            .iter()
            .filter(|check| matches!(check.decision, Decision::Actionable | Decision::Review))
            .flat_map(|check| {
                check
                    .local_checks
                    .iter()
                    .map(|local| local.instance_id.as_str())
            })
            .collect();
        let without_repository: Vec<&str> = report
            .source_map
            .iter()
            .filter(|mapping| {
                !mapping.sources.iter().any(|source| {
                    source.kind == SourceKind::Repository && source.state == MappingState::Mapped
                })
            })
            .map(|mapping| {
                references
                    .get(mapping.instance_id.as_str())
                    .copied()
                    .unwrap_or(&mapping.instance_id)
            })
            .collect();
        text.push_str(&fill(
            words.source_map,
            &[
                &report.source_map.len(),
                &(report.source_map.len() - without_repository.len()),
                &without_repository.len(),
            ],
        ));
        if !without_repository.is_empty() {
            let mut names: Vec<&str> = without_repository.clone();
            names.sort_unstable();
            names.dedup();
            let shown = names
                .iter()
                .take(SUMMARY_LIST)
                .map(|name| inline(name))
                .collect::<Vec<_>>();
            let more = if names.len() > SUMMARY_LIST {
                fill(words.and_more_json, &[&(names.len() - SUMMARY_LIST)])
            } else {
                String::new()
            };
            text.push_str(&fill(words.without_repository, &[&shown.join(", "), &more]));
        }
        let detailed: Vec<_> = report
            .source_map
            .iter()
            .filter(|mapping| open_instances.contains(mapping.instance_id.as_str()))
            .collect();
        if detailed.is_empty() {
            return text;
        }
        text.push_str(words.source_map_table);
        let mut shown = BTreeSet::new();
        let mut rows: Vec<SourceMapRow> = Vec::new();
        let mut positions: HashMap<(String, String, String), usize> = HashMap::new();
        for mapping in detailed {
            let reference = references
                .get(mapping.instance_id.as_str())
                .copied()
                .unwrap_or(&mapping.instance_id);
            if !shown.insert(reference) {
                continue;
            }
            let repository = mapping
                .sources
                .iter()
                .find(|source| source.kind == SourceKind::Repository);
            let repository_url = repository.and_then(|source| source.url.as_deref());
            let repository_cell = match repository {
                Some(source) if source.state == MappingState::Mapped => {
                    inline(repository_url.unwrap_or("—"))
                }
                Some(source) => fill(words.repository_unavailable, &[&inline(&source.detail)]),
                None => "—".to_owned(),
            };
            let mut others = Vec::new();
            let mut releases = None;
            let mut unmapped = Vec::new();
            // The scan reads the advisories of a mapped GitHub repository and reports their
            // coverage separately, so they are not an unmapped source.
            let repository_advisories_read = repository.is_some_and(|source| {
                source.state == MappingState::Mapped
                    && repository_url.is_some_and(|url| url.starts_with("https://github.com/"))
            });
            for source in &mapping.sources {
                if source.kind == SourceKind::Repository
                    || source.kind == SourceKind::Advisories && repository_advisories_read
                {
                    continue;
                }
                match (source.state, source.url.as_deref()) {
                    (MappingState::Mapped, Some(url)) if Some(url) != repository_url => {
                        let label = format!(
                            "{}: {}",
                            text::source_kind(language, source.kind),
                            inline(url)
                        );
                        if source.kind == SourceKind::Releases {
                            releases = Some(label);
                        } else {
                            others.push(label);
                        }
                    }
                    (MappingState::Mapped, _) => {}
                    (MappingState::Unavailable, _) => {
                        unmapped.push(text::source_kind(language, source.kind));
                    }
                    (MappingState::NotApplicable, _) => {}
                }
            }
            let row = SourceMapRow {
                repository: repository_cell,
                others: others.join("; "),
                unmapped: unmapped.join(", "),
                members: vec![(reference.to_owned(), releases)],
            };
            let key = (
                row.repository.clone(),
                row.others.clone(),
                row.unmapped.clone(),
            );
            if let Some(&position) = positions.get(&key) {
                rows[position].members.extend(row.members);
            } else {
                positions.insert(key, rows.len());
                rows.push(row);
            }
        }
        for row in rows {
            let unmapped = if row.unmapped.is_empty() {
                "—".to_owned()
            } else {
                row.unmapped.clone()
            };
            if row.members.len() <= LISTED_COMPONENTS {
                for (reference, releases) in &row.members {
                    let others: Vec<&str> = [row.others.as_str()]
                        .into_iter()
                        .chain(releases.as_deref())
                        .filter(|value| !value.is_empty())
                        .collect();
                    text.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        inline(reference),
                        row.repository,
                        if others.is_empty() {
                            "—".to_owned()
                        } else {
                            others.join("; ")
                        },
                        unmapped
                    ));
                }
                continue;
            }
            let examples = row
                .members
                .iter()
                .take(2)
                .map(|(reference, _)| inline(reference))
                .collect::<Vec<_>>()
                .join(", ");
            let releases = row
                .members
                .iter()
                .filter(|(_, releases)| releases.is_some())
                .count();
            let others: Vec<String> = [row.others.clone()]
                .into_iter()
                .chain((releases > 0).then(|| fill(words.releases_per_component, &[&releases])))
                .filter(|value| !value.is_empty())
                .collect();
            text.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                fill(words.components_examples, &[&row.members.len(), &examples]),
                row.repository,
                if others.is_empty() {
                    "—".to_owned()
                } else {
                    others.join("; ")
                },
                unmapped
            ));
        }
        text.push('\n');
    }
    text
}

/// Components with the same repository, other sources and unmapped categories share one row;
/// their per-component release pages stay in JSON.
struct SourceMapRow {
    repository: String,
    others: String,
    unmapped: String,
    members: Vec<(String, Option<String>)>,
}
