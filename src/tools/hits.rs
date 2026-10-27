//! Preparation shared by `tools hits` and `tools draft`: read the fetched responses of every
//! research target, screen them, skip items already imported with the same update time, resolve
//! the advisories they cite, and settle the items that deterministic rules decide.
use super::{
    Item, ItemKind,
    advisories::{self, BuildMatch, BuildStatus, Resolution},
    draft::{DecisionLookup, ResearchDecisions},
    raw::{self, MissingFetch, TargetItems},
    screen::{self, Screen, SignalPlace},
};
use crate::{
    model::{Instance, SourceFacts},
    network::Http,
    output::text::{self, fill},
    profile::Language,
    research::{Assessment, NotApplicableReason, ResearchTarget},
    sources::{RangeMatch, github_range_match, repository_package_is},
    store::Store,
};
use anyhow::Result;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::Path,
};

const FACT_LIMIT: usize = 500;
const HTTP_BUDGET: usize = 3000;

pub struct Prepared {
    pub project_id: String,
    pub snapshot_id: String,
    pub targets: Vec<PreparedTarget>,
    pub resolutions: BTreeMap<String, Resolution>,
}

pub struct PreparedTarget {
    pub target: ResearchTarget,
    pub collected: TargetItems,
    /// Items without a security signal; counted in the source review, never recorded.
    pub not_selected: usize,
    pub entries: Vec<Entry>,
}

pub struct Entry {
    pub item: Item,
    pub screen: Screen,
    pub disposition: Disposition,
}

pub enum Disposition {
    /// Imported earlier with the same update time; it keeps its recorded reading.
    Unchanged,
    Rule(RuleOutcome),
    /// Needs an agent decision. `unpublished` lists cited IDs that neither the repository nor a
    /// public database publishes yet.
    Review {
        unpublished: Vec<String>,
    },
}

pub struct RuleOutcome {
    pub assessment: Assessment,
    pub reason: Option<NotApplicableReason>,
    pub rationale: String,
    pub facts: SourceFacts,
    /// Empty means every instance of the target.
    pub instance_ids: Vec<String>,
}

/// Screened items of one target before advisory resolution.
struct Screened {
    target: ResearchTarget,
    collected: TargetItems,
    not_selected: usize,
    selected_keys: HashSet<String>,
    items: Vec<(Item, Screen, bool)>,
}

pub fn prepare(store: &Store, raw: &Path, offline: bool) -> Result<Prepared> {
    let plan = crate::research::full_plan(store)?;
    let snapshot = store.latest()?;
    let mut screened_targets: Vec<Screened> = Vec::new();
    let mut cited: BTreeSet<String> = BTreeSet::new();
    for target in plan.targets {
        let mut collected = raw::read_target(raw, &target);
        let issue_bodies: HashMap<String, String> = collected
            .items
            .iter()
            .filter(|item| item.kind == ItemKind::Issue)
            .map(|item| (item.key.clone(), screen::clean(&item.body)))
            .collect();
        let mut not_selected = 0;
        let mut selected_keys = HashSet::new();
        let mut items = Vec::new();
        for item in std::mem::take(&mut collected.items) {
            let linked: String = item
                .closes
                .iter()
                .filter_map(|key| issue_bodies.get(key))
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            let Some(screen) = screen::screen(&item, &linked) else {
                not_selected += 1;
                collected.items.push(item);
                continue;
            };
            let unchanged = target.seen.iter().any(|seen| {
                seen.context_current
                    && seen.url == item.url
                    && super::same_instant(&seen.updated_at, &item.updated_at)
            });
            if !unchanged {
                cited.extend(screen.identifiers.iter().cloned());
            }
            selected_keys.insert(item.key.clone());
            collected.items.push(item.clone());
            items.push((item, screen, unchanged));
        }
        screened_targets.push(Screened {
            target,
            collected,
            not_selected,
            selected_keys,
            items,
        });
    }
    let mut http = Http::new(store, offline);
    http.budget = HTTP_BUDGET;
    let resolutions = advisories::resolve(&cited, &snapshot.instances, &mut http);
    let language = crate::output::report_language(store);
    let mut targets = Vec::new();
    for screened in screened_targets {
        let target_instances: Vec<&Instance> = snapshot
            .instances
            .iter()
            .filter(|instance| screened.target.instance_ids.contains(&instance.id))
            .collect();
        let context = RuleContext {
            collected: &screened.collected,
            selected_keys: &screened.selected_keys,
            resolutions: &resolutions,
            target_instances: &target_instances,
            language,
        };
        let entries = screened
            .items
            .into_iter()
            .map(|(item, screen, unchanged)| {
                let disposition = if unchanged {
                    Disposition::Unchanged
                } else {
                    disposition(&item, &screen, &context)
                };
                Entry {
                    item,
                    screen,
                    disposition,
                }
            })
            .collect();
        targets.push(PreparedTarget {
            target: screened.target,
            collected: screened.collected,
            not_selected: screened.not_selected,
            entries,
        });
    }
    Ok(Prepared {
        project_id: plan.project_id,
        snapshot_id: plan.snapshot_id,
        targets,
        resolutions,
    })
}

pub(super) struct RuleContext<'a> {
    pub(super) collected: &'a TargetItems,
    pub(super) selected_keys: &'a HashSet<String>,
    pub(super) resolutions: &'a BTreeMap<String, Resolution>,
    pub(super) target_instances: &'a [&'a Instance],
    /// Language of the rationales the rules record.
    pub(super) language: Language,
}

pub(super) fn disposition(item: &Item, screen: &Screen, context: &RuleContext<'_>) -> Disposition {
    let words = text::text(context.language);
    let unpublished: Vec<String> = screen
        .identifiers
        .iter()
        .filter(|id| {
            !context.collected.published_identifiers.contains(*id)
                && !context
                    .resolutions
                    .get(*id)
                    .is_some_and(|resolution| resolution.published)
        })
        .cloned()
        .collect();
    if item.kind == ItemKind::Advisory {
        return advisory_rule(item, context);
    }
    if item.kind == ItemKind::Release {
        if unpublished.is_empty() {
            return Disposition::Rule(RuleOutcome {
                assessment: Assessment::Informational,
                reason: None,
                rationale: words.rule_release_published.into(),
                facts: SourceFacts::default(),
                instance_ids: Vec::new(),
            });
        }
        return Disposition::Review { unpublished };
    }
    let closes_selected_issues = !item.closes.is_empty()
        && item
            .closes
            .iter()
            .all(|key| context.selected_keys.contains(key));
    if item.kind.is_proposed_change() && !screen.own_signal() && closes_selected_issues {
        return Disposition::Rule(RuleOutcome {
            assessment: Assessment::Ignore,
            reason: None,
            rationale: fill(words.rule_fix_pr, &[&item.closes.join(", ")]),
            facts: SourceFacts::default(),
            instance_ids: Vec::new(),
        });
    }
    if screen.dependency_update
        && let Some(outcome) = dependency_relay(screen, context)
    {
        return Disposition::Rule(outcome);
    }
    Disposition::Review { unpublished }
}

/// A dependency update relays its dependency's advisories. It needs no review when it names no
/// advisory, or when every advisory it names is published and no monitored instance is, or may
/// be, inside an affected range.
fn dependency_relay(screen: &Screen, context: &RuleContext<'_>) -> Option<RuleOutcome> {
    let words = text::text(context.language);
    if screen.identifiers.is_empty() {
        return Some(RuleOutcome {
            assessment: Assessment::Ignore,
            reason: None,
            rationale: words.rule_relay_without_ids.into(),
            facts: SourceFacts::default(),
            instance_ids: Vec::new(),
        });
    }
    let mut packages: BTreeSet<&str> = BTreeSet::new();
    for id in &screen.identifiers {
        let resolution = context.resolutions.get(id)?;
        if !resolution.published || resolution.may_affect_build() {
            return None;
        }
        packages.extend(resolution.packages.iter().map(String::as_str));
    }
    let named: Vec<&str> = packages.into_iter().take(6).collect();
    let identifiers: Vec<&str> = screen
        .identifiers
        .iter()
        .take(6)
        .map(String::as_str)
        .collect();
    let more = if screen.identifiers.len() > 6 {
        words.and_others
    } else {
        ""
    };
    Some(RuleOutcome {
        assessment: Assessment::Ignore,
        reason: None,
        rationale: fill(
            words.rule_relay_with_ids,
            &[&identifiers.join(", "), &more, &named.join(", ")],
        ),
        facts: SourceFacts::default(),
        instance_ids: Vec::new(),
    })
}

/// A repository advisory's ranges, evaluated for the target's instances.
fn advisory_rule(item: &Item, context: &RuleContext<'_>) -> Disposition {
    let words = text::text(context.language);
    let review = Disposition::Review {
        unpublished: Vec::new(),
    };
    let Some(advisory) = &item.advisory else {
        return review;
    };
    let mut identifiers = vec![advisory.ghsa_id.clone()];
    identifiers.extend(advisory.cve_id.iter().cloned());
    let join = |parts: Vec<String>| super::truncate_bytes(&parts.join("; "), FACT_LIMIT);
    let facts = SourceFacts {
        identifiers,
        affected_versions: join(
            advisory
                .packages
                .iter()
                .filter(|package| !package.vulnerable_range.is_empty())
                .map(|package| format!("{} {}", package.name, package.vulnerable_range))
                .collect(),
        ),
        fixed_in: join(
            advisory
                .packages
                .iter()
                .filter(|package| !package.patched.is_empty())
                .map(|package| format!("{} {}", package.name, package.patched))
                .collect(),
        ),
        ..SourceFacts::default()
    };
    let mut matches: Vec<(&Instance, BuildStatus)> = Vec::new();
    for package in &advisory.packages {
        for instance in context.target_instances {
            if !repository_package_is(instance, &package.ecosystem, &package.name) {
                continue;
            }
            let patched = Some(package.patched.as_str()).filter(|patched| !patched.is_empty());
            let status = instance
                .resolved_version
                .as_deref()
                .and_then(|version| crate::identity::normalized_version(version).ok())
                .and_then(|version| {
                    github_range_match(&package.vulnerable_range, patched, &version)
                })
                .map(|found| match found {
                    RangeMatch::Outside => BuildStatus::Outside,
                    RangeMatch::FixedOnLine => BuildStatus::FixedOnLine,
                    RangeMatch::Affected => BuildStatus::Affected,
                })
                .unwrap_or(BuildStatus::Unknown);
            matches.push((instance, status));
        }
    }
    let packages: Vec<&str> = advisory
        .packages
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    if matches.is_empty() {
        return Disposition::Rule(RuleOutcome {
            assessment: Assessment::NotApplicable,
            reason: Some(NotApplicableReason::ComponentNotInBuild),
            rationale: fill(
                words.rule_advisory_other_package,
                &[&if packages.is_empty() {
                    words.no_package.to_owned()
                } else {
                    packages.join(", ")
                }],
            ),
            facts,
            instance_ids: Vec::new(),
        });
    }
    if matches
        .iter()
        .any(|(_, status)| matches!(status, BuildStatus::Affected | BuildStatus::Unknown))
    {
        return review;
    }
    let versions: Vec<String> = matches
        .iter()
        .map(|(instance, _)| {
            format!(
                "{}@{}",
                instance.reference,
                instance.resolved_version.as_deref().unwrap_or("?")
            )
        })
        .collect();
    let fixed = matches
        .iter()
        .any(|(_, status)| *status == BuildStatus::FixedOnLine);
    let (reason, rationale) = if fixed && !facts.fixed_in.is_empty() {
        (
            NotApplicableReason::FixedInMonitoredVersion,
            fill(words.rule_advisory_fixed, &[&versions.join(", ")]),
        )
    } else if !facts.affected_versions.is_empty() {
        (
            NotApplicableReason::AffectsOtherVersion,
            fill(words.rule_advisory_outside, &[&versions.join(", ")]),
        )
    } else {
        return review;
    };
    Disposition::Rule(RuleOutcome {
        assessment: Assessment::NotApplicable,
        reason: Some(reason),
        rationale,
        facts,
        instance_ids: Vec::new(),
    })
}

#[derive(Serialize)]
pub struct ReviewPacket {
    pub schema_version: u32,
    pub project_id: String,
    pub snapshot_id: String,
    pub summary: PacketSummary,
    /// Responses still to fetch; rerun `tools hits` after writing them.
    pub missing: Vec<MissingFetch>,
    pub errors: Vec<TargetError>,
    pub review: Vec<ReviewItem>,
}

#[derive(Serialize, Default)]
pub struct PacketSummary {
    pub targets: usize,
    pub complete_targets: usize,
    pub listed: usize,
    pub selected: usize,
    pub unchanged: usize,
    pub rule_resolved: usize,
    pub decided: usize,
    pub to_review: usize,
}

#[derive(Serialize)]
pub struct TargetError {
    pub upstream: String,
    pub error: String,
}

#[derive(Serialize)]
pub struct ReviewItem {
    pub key: String,
    pub upstream: String,
    pub kind: ItemKind,
    pub url: String,
    pub title: String,
    pub state: String,
    pub labels: Vec<String>,
    pub updated_at: String,
    pub signals: Vec<SignalPlace>,
    pub identifiers: Vec<String>,
    pub dependency_update: bool,
    pub snippets: Vec<String>,
    pub closes: Vec<String>,
    pub unpublished: Vec<String>,
    pub advisories: Vec<CitedAdvisory>,
    pub instance_ids: Vec<String>,
    /// Decision recorded for an earlier update of this item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_decision: Option<PreviousDecision>,
}

#[derive(Serialize)]
pub struct CitedAdvisory {
    pub id: String,
    pub published: bool,
    pub title: String,
    pub in_build: Vec<BuildMatch>,
}

#[derive(Serialize)]
pub struct PreviousDecision {
    pub updated_at: String,
    pub assessment: Assessment,
    pub rationale: String,
}

pub fn packet(prepared: &Prepared, decisions: Option<&ResearchDecisions>) -> ReviewPacket {
    let resolutions = &prepared.resolutions;
    let mut summary = PacketSummary {
        targets: prepared.targets.len(),
        ..PacketSummary::default()
    };
    let mut missing = Vec::new();
    let mut errors = Vec::new();
    let mut review = Vec::new();
    for prepared_target in &prepared.targets {
        let collected = &prepared_target.collected;
        if collected.complete() {
            summary.complete_targets += 1;
        }
        missing.extend(collected.missing.iter().cloned());
        errors.extend(collected.errors.iter().map(|error| TargetError {
            upstream: prepared_target.target.upstream.clone(),
            error: error.clone(),
        }));
        summary.listed += collected.items.len();
        summary.selected += prepared_target.entries.len();
        for entry in &prepared_target.entries {
            let lookup = decisions.map(|decisions| decisions.lookup(&entry.item));
            let unpublished = match &entry.disposition {
                Disposition::Unchanged => {
                    summary.unchanged += 1;
                    continue;
                }
                Disposition::Rule(_) => {
                    summary.rule_resolved += 1;
                    continue;
                }
                Disposition::Review { unpublished } => unpublished,
            };
            let previous_decision = match lookup {
                Some(DecisionLookup::Current(_)) => {
                    summary.decided += 1;
                    continue;
                }
                Some(DecisionLookup::Stale(decision)) => Some(PreviousDecision {
                    updated_at: decision.updated_at.clone(),
                    assessment: decision.assessment,
                    rationale: decision.rationale.clone(),
                }),
                Some(DecisionLookup::Missing) | None => None,
            };
            summary.to_review += 1;
            review.push(ReviewItem {
                key: entry.item.key.clone(),
                upstream: prepared_target.target.upstream.clone(),
                kind: entry.item.kind,
                url: entry.item.url.clone(),
                title: entry.item.title.clone(),
                state: entry.item.state.clone(),
                labels: entry.item.labels.clone(),
                updated_at: entry.item.updated_at.clone(),
                signals: entry.screen.places.clone(),
                identifiers: entry.screen.identifiers.clone(),
                dependency_update: entry.screen.dependency_update,
                snippets: entry.screen.snippets.clone(),
                closes: entry.item.closes.clone(),
                unpublished: unpublished.clone(),
                advisories: entry
                    .screen
                    .identifiers
                    .iter()
                    .filter_map(|id| resolutions.get(id))
                    .map(|resolution| CitedAdvisory {
                        id: resolution.id.clone(),
                        published: resolution.published,
                        title: resolution.title.clone(),
                        in_build: resolution.in_build.clone(),
                    })
                    .collect(),
                instance_ids: prepared_target.target.instance_ids.clone(),
                previous_decision,
            });
        }
    }
    ReviewPacket {
        schema_version: 1,
        project_id: prepared.project_id.clone(),
        snapshot_id: prepared.snapshot_id.clone(),
        summary,
        missing,
        errors,
        review,
    }
}
