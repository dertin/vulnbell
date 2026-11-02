//! Offline evaluation of independently labelled source-review cases.
use anyhow::{Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Labels {
    pub schema_version: u32,
    pub cases: Vec<Label>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub id: String,
    pub language: String,
    pub vulnerable: bool,
    pub high_priority: bool,
    pub rationale: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observations {
    pub schema_version: u32,
    pub cases: Vec<Observation>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub id: String,
    pub result: ObservationResult,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationResult {
    Found,
    NotFound,
    Unreviewed,
}

#[derive(Default, Serialize)]
pub struct Counts {
    pub true_positive: usize,
    pub false_positive: usize,
    pub true_negative: usize,
    pub false_negative: usize,
    pub unreviewed: usize,
    pub positive_unreviewed: usize,
    pub negative_unreviewed: usize,
    pub coverage: f64,
    pub high_priority_missed: Vec<String>,
    pub high_priority_unreviewed: Vec<String>,
    pub unreviewed_ids: Vec<String>,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
}

#[derive(Serialize)]
pub struct Evaluation {
    pub schema_version: u32,
    pub total: usize,
    pub counts: Counts,
    pub languages: BTreeMap<String, Counts>,
    pub limitations: &'static str,
}

fn add(counts: &mut Counts, label: &Label, result: ObservationResult) {
    match (label.vulnerable, result) {
        (_, ObservationResult::Unreviewed) => {
            counts.unreviewed += 1;
            if label.vulnerable {
                counts.positive_unreviewed += 1;
            } else {
                counts.negative_unreviewed += 1;
            }
            counts.unreviewed_ids.push(label.id.clone());
            if label.high_priority {
                counts.high_priority_unreviewed.push(label.id.clone());
            }
        }
        (true, ObservationResult::Found) => counts.true_positive += 1,
        (true, ObservationResult::NotFound) => {
            counts.false_negative += 1;
            if label.high_priority {
                counts.high_priority_missed.push(label.id.clone());
            }
        }
        (false, ObservationResult::Found) => counts.false_positive += 1,
        (false, ObservationResult::NotFound) => counts.true_negative += 1,
    }
}

fn ratios(counts: &mut Counts) {
    let selected = counts.true_positive + counts.false_positive;
    let relevant = counts.true_positive + counts.false_negative;
    let reviewed =
        counts.true_positive + counts.false_positive + counts.true_negative + counts.false_negative;
    let total = reviewed + counts.unreviewed;
    counts.coverage = if total == 0 {
        0.0
    } else {
        reviewed as f64 / total as f64
    };
    counts.precision = (selected > 0).then(|| counts.true_positive as f64 / selected as f64);
    counts.recall = (relevant > 0).then(|| counts.true_positive as f64 / relevant as f64);
}

pub fn evaluate(labels: Labels, observations: Observations) -> Result<Evaluation> {
    if labels.schema_version != 1
        || observations.schema_version != 1
        || labels.cases.is_empty()
        || labels.cases.len() > 10_000
        || observations.cases.len() > 10_000
    {
        bail!("use schema version 1 and 1..=10000 labelled cases");
    }
    let mut seen = HashSet::new();
    for label in &labels.cases {
        if !seen.insert(label.id.clone())
            || !super::code_findings::text_valid(&label.id, 120)
            || !super::code_findings::text_valid(&label.language, 60)
            || !super::code_findings::text_valid(&label.rationale, 1000)
            || (label.high_priority && !label.vulnerable)
        {
            bail!(
                "each case requires a unique ID, language and rationale; high priority requires a positive label"
            );
        }
    }
    let mut results = HashMap::new();
    for observation in observations.cases {
        if !seen.contains(&observation.id)
            || results.insert(observation.id, observation.result).is_some()
        {
            bail!("observations must have unique labelled IDs");
        }
    }
    let mut counts = Counts::default();
    let mut languages = BTreeMap::new();
    for label in &labels.cases {
        let result = results
            .get(&label.id)
            .copied()
            .unwrap_or(ObservationResult::Unreviewed);
        add(&mut counts, label, result);
        add(
            languages
                .entry(label.language.clone())
                .or_insert_with(Counts::default),
            label,
            result,
        );
    }
    ratios(&mut counts);
    for counts in languages.values_mut() {
        ratios(counts);
    }
    Ok(Evaluation {
        schema_version: 1,
        total: labels.cases.len(),
        counts,
        languages,
        limitations: "Measures independently labelled reviewed cases only; unreviewed cases are excluded from precision and recall. Labels and observation matching require independent validation.",
    })
}
