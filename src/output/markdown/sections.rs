use super::{fill, inline, text};
use crate::{
    output::{MonitoredComponent, MorningReport},
    profile::Language,
};
use std::collections::HashMap;

/// Locked packages are summarized per lockfile; declared, deployed and observed components are
/// listed with their source location. The full inventory stays in the JSON report.
pub(super) fn inventory_markdown(inventory: &[MonitoredComponent], language: Language) -> String {
    let words = text::text(language);
    let mut text = words.inventory_heading.to_owned();
    let mut lockfiles: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut listed = Vec::new();
    for component in inventory {
        let location = match (&component.codebase, &component.path) {
            (Some(codebase), Some(path)) => format!("{}/{path}", codebase.trim_end_matches('/')),
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
pub(super) fn coverage_groups(
    gaps: &[crate::model::Coverage],
) -> Vec<(&crate::model::Coverage, Vec<&str>)> {
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
pub(super) fn coverage_markdown(report: &MorningReport) -> String {
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
            inline(&text::coverage_detail(language, &gap.detail))
        ));
    }
    text
}

pub(in crate::output) fn codebase_revisions_markdown(
    revisions: &[crate::codebase_revision::CodebaseComparison],
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
        "## Codebases revisadas\n\n| Codebase | Rama | Commit | Estado |\n|---|---|---|---|\n"
            .to_owned()
    } else {
        "## Reviewed codebases\n\n| Codebase | Branch | Commit | State |\n|---|---|---|---|\n"
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
        } else if reviewed.state == crate::codebase_revision::RepositoryState::NotGit {
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
            inline(&reviewed.codebase),
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
