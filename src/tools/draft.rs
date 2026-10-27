//! `tools draft`: the research batch built from the screened items, the deterministic rules and
//! the agent's decisions.
use super::{
    Item,
    hits::{Disposition, Prepared, PreparedTarget},
    screen::Screen,
    truncate_bytes, truncate_chars,
};
use crate::{
    model::SourceFacts,
    research::{
        Assessment, NotApplicableReason, ResearchBatch, ResearchEvent, ResearchTarget,
        ReviewCoverage, SourceReview, validate_source_facts,
    },
};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

const EXCERPT_CHARS: usize = 1500;
const TITLE_BYTES: usize = 2000;
const DETAIL_BYTES: usize = 2000;
const FACT_BYTES: usize = 500;

/// The agent's reviewed readings of screened items, kept across runs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchDecisions {
    pub schema_version: u32,
    pub decisions: Vec<ItemDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemDecision {
    /// Item key reported by `tools hits`.
    pub key: String,
    /// The item's `updated_at` when it was reviewed; a later update lists the item again.
    pub updated_at: String,
    pub assessment: Assessment,
    /// Required with `not_applicable`; forbidden otherwise.
    #[serde(default)]
    pub not_applicable_reason: Option<NotApplicableReason>,
    pub rationale: String,
    #[serde(default)]
    pub source_facts: SourceFacts,
    /// Instances of the item's upstream the reading applies to; empty means all of them.
    #[serde(default)]
    pub instance_ids: Vec<String>,
}

pub enum DecisionLookup<'a> {
    Current(&'a ItemDecision),
    /// Recorded for an earlier update of the item.
    Stale(&'a ItemDecision),
    Missing,
}

impl ResearchDecisions {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = crate::read_limited(path, 32 * 1024 * 1024)
            .with_context(|| format!("cannot read decisions {}", path.display()))?;
        let decisions: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid decisions {}", path.display()))?;
        decisions.validate()?;
        Ok(decisions)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("decisions schema_version must be 1");
        }
        let mut keys = HashMap::new();
        for decision in &self.decisions {
            let key = decision.key.as_str();
            if key.trim().is_empty() || key.len() > 300 {
                bail!("decision key must be 1..300 bytes");
            }
            if keys.insert(key, ()).is_some() {
                bail!("duplicate decision for {key}");
            }
            if super::normalize_time(&decision.updated_at).is_none() {
                bail!("decision {key}: updated_at must be the item's RFC3339 time");
            }
            if decision.rationale.trim().is_empty() || decision.rationale.len() > 4000 {
                bail!("decision {key}: rationale must be 1..4000 bytes");
            }
            if (decision.assessment == Assessment::NotApplicable)
                != decision.not_applicable_reason.is_some()
            {
                bail!(
                    "decision {key}: not_applicable requires not_applicable_reason, and only it accepts one"
                );
            }
            validate_source_facts(&decision.source_facts, decision.not_applicable_reason)
                .with_context(|| format!("decision {key}"))?;
        }
        Ok(())
    }

    pub fn lookup(&self, item: &Item) -> DecisionLookup<'_> {
        match self
            .decisions
            .iter()
            .find(|decision| decision.key == item.key)
        {
            Some(decision) if super::same_instant(&decision.updated_at, &item.updated_at) => {
                DecisionLookup::Current(decision)
            }
            Some(decision) => DecisionLookup::Stale(decision),
            None => DecisionLookup::Missing,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DraftSummary {
    pub sources: usize,
    pub complete_sources: usize,
    pub events: usize,
    pub assessments: BTreeMap<String, usize>,
    /// Items still without a current decision; only `--partial` accepts them.
    pub undecided: Vec<String>,
    /// Upstreams with missing or unreadable responses; only `--partial` accepts them.
    pub incomplete: Vec<String>,
}

pub fn draft(
    prepared: Prepared,
    decisions: &ResearchDecisions,
    partial: bool,
) -> Result<(ResearchBatch, DraftSummary)> {
    let mut sources = Vec::new();
    let mut events = Vec::new();
    let mut undecided = Vec::new();
    let mut incomplete = Vec::new();
    for prepared_target in &prepared.targets {
        let complete = prepared_target.collected.complete();
        if !complete {
            incomplete.push(prepared_target.target.upstream.clone());
        }
        let review = target_events(prepared_target, decisions, &mut events, &mut undecided)?;
        let coverage = if complete && review.undecided == 0 {
            ReviewCoverage::Complete
        } else {
            ReviewCoverage::Partial
        };
        sources.push(SourceReview {
            upstream: prepared_target.target.upstream.clone(),
            from: prepared_target.target.from.clone(),
            until: prepared_target.target.until.clone(),
            coverage,
            detail: truncate_bytes(&detail(prepared_target, &review), DETAIL_BYTES),
            continuation: None,
        });
    }
    if !partial && !incomplete.is_empty() {
        bail!(
            "{} upstreams have missing or unreadable responses ({}); fetch what `tools hits` lists, or pass --partial",
            incomplete.len(),
            preview(&incomplete)
        );
    }
    if !partial && !undecided.is_empty() {
        bail!(
            "{} screened items have no current decision ({}); add them to the decisions file, or pass --partial",
            undecided.len(),
            preview(&undecided)
        );
    }
    let mut assessments: BTreeMap<String, usize> = BTreeMap::new();
    for event in &events {
        let name = serde_json::to_value(event.assessment)?
            .as_str()
            .unwrap_or_default()
            .to_owned();
        *assessments.entry(name).or_default() += 1;
    }
    let summary = DraftSummary {
        sources: sources.len(),
        complete_sources: sources
            .iter()
            .filter(|source| source.coverage == ReviewCoverage::Complete)
            .count(),
        events: events.len(),
        assessments,
        undecided,
        incomplete,
    };
    let batch = ResearchBatch {
        schema_version: 1,
        project_id: prepared.project_id,
        snapshot_id: prepared.snapshot_id,
        sources,
        events,
    };
    Ok((batch, summary))
}

#[derive(Default)]
struct TargetReview {
    unchanged: usize,
    by_rule: usize,
    decided: usize,
    undecided: usize,
}

fn target_events(
    prepared_target: &PreparedTarget,
    decisions: &ResearchDecisions,
    events: &mut Vec<ResearchEvent>,
    undecided: &mut Vec<String>,
) -> Result<TargetReview> {
    let target = &prepared_target.target;
    let provider = prepared_target.collected.provider.event_provider();
    let mut review = TargetReview::default();
    for entry in &prepared_target.entries {
        if matches!(entry.disposition, Disposition::Unchanged) {
            review.unchanged += 1;
            continue;
        }
        let reading = match (decisions.lookup(&entry.item), &entry.disposition) {
            (DecisionLookup::Current(decision), _) => {
                review.decided += 1;
                Reading {
                    assessment: decision.assessment,
                    reason: decision.not_applicable_reason,
                    rationale: &decision.rationale,
                    facts: &decision.source_facts,
                    instance_ids: &decision.instance_ids,
                }
            }
            (_, Disposition::Rule(outcome)) => {
                review.by_rule += 1;
                Reading {
                    assessment: outcome.assessment,
                    reason: outcome.reason,
                    rationale: &outcome.rationale,
                    facts: &outcome.facts,
                    instance_ids: &outcome.instance_ids,
                }
            }
            _ => {
                review.undecided += 1;
                undecided.push(entry.item.key.clone());
                continue;
            }
        };
        events.push(event(
            target,
            provider,
            &entry.item,
            &entry.screen,
            reading,
        )?);
    }
    Ok(review)
}

struct Reading<'a> {
    assessment: Assessment,
    reason: Option<NotApplicableReason>,
    rationale: &'a str,
    facts: &'a SourceFacts,
    instance_ids: &'a [String],
}

fn event(
    target: &ResearchTarget,
    provider: &str,
    item: &Item,
    screen: &Screen,
    reading: Reading<'_>,
) -> Result<ResearchEvent> {
    if let Some(outside) = reading
        .instance_ids
        .iter()
        .find(|id| !target.instance_ids.contains(id))
    {
        bail!(
            "decision {}: instance {outside} is not an instance of {}",
            item.key,
            target.upstream
        );
    }
    let mut facts = reading.facts.clone();
    if facts.identifiers.is_empty() {
        facts.identifiers = screen.identifiers.iter().take(32).cloned().collect();
    }
    for text in [
        &mut facts.affected_versions,
        &mut facts.fixed_in,
        &mut facts.fix_reference,
        &mut facts.required_feature,
    ] {
        *text = truncate_bytes(text, FACT_BYTES);
    }
    let body = item.body.trim();
    let excerpt = truncate_chars(
        if body.is_empty() { &item.title } else { body },
        EXCERPT_CHARS,
    );
    Ok(ResearchEvent {
        upstream: target.upstream.clone(),
        instance_ids: if reading.instance_ids.is_empty() {
            target.instance_ids.clone()
        } else {
            reading.instance_ids.to_vec()
        },
        provider: provider.to_owned(),
        external_id: item.key.clone(),
        kind: item.kind.event_kind(),
        url: item.url.clone(),
        title: truncate_bytes(&item.title, TITLE_BYTES),
        excerpt,
        updated_at: item.updated_at.clone(),
        assessment: reading.assessment,
        not_applicable_reason: reading.reason,
        rationale: reading.rationale.to_owned(),
        source_facts: facts,
    })
}

fn detail(prepared_target: &PreparedTarget, review: &TargetReview) -> String {
    let collected = &prepared_target.collected;
    let listed = collected.items.len();
    let selected = prepared_target.entries.len();
    let mut text = format!(
        "{} Listed {listed} items updated in the window; {selected} matched the security screen (strong terms in title, labels, body or closed issue; bug-class terms in title or labels): {} unchanged since their last review, {} settled by deterministic rules, {} by agent decisions.",
        collected.method, review.unchanged, review.by_rule, review.decided
    );
    if review.undecided > 0 {
        text.push_str(&format!(" {} still undecided.", review.undecided));
    }
    if !collected.missing.is_empty() {
        let paths: Vec<&str> = collected
            .missing
            .iter()
            .map(|missing| missing.path.as_str())
            .collect();
        text.push_str(&format!(" Missing responses: {}.", preview(&paths)));
    }
    if !collected.errors.is_empty() {
        text.push_str(&format!(
            " Unreadable responses: {}.",
            preview(&collected.errors)
        ));
    }
    text.push_str(&format!(
        " {} items without a security signal are not recorded.",
        prepared_target.not_selected
    ));
    text
}

fn preview<T: AsRef<str>>(values: &[T]) -> String {
    let shown: Vec<&str> = values.iter().take(10).map(AsRef::as_ref).collect();
    let more = values.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}
