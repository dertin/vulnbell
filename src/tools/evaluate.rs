//! Offline evaluation against independently labelled items. This never changes review decisions.
use super::{
    Item,
    hits::{self, Disposition, Entry},
    screen,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub schema_version: u32,
    pub items: Vec<LabelledItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelledItem {
    pub item: Item,
    /// Independent human label: relevant to review, not necessarily confirmed affected.
    pub relevant: bool,
    /// A human rationale and source reference support auditing labels.
    pub rationale: String,
    #[serde(default)]
    pub linked_body: String,
}

#[derive(Serialize)]
pub struct Evaluation {
    pub schema_version: u32,
    pub model: &'static str,
    pub total: usize,
    pub relevant: usize,
    pub selected: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub false_negative_keys: Vec<String>,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub top: usize,
    pub precision_at_top: Option<f64>,
    pub recall_at_top: Option<f64>,
    pub baseline_select_all_precision: Option<f64>,
    pub limitations: &'static str,
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 / denominator as f64)
}

pub fn evaluate(corpus: Corpus, top: usize) -> Result<Evaluation> {
    if corpus.schema_version != 1 || corpus.items.len() > 10_000 || top == 0 || top > 10_000 {
        bail!("use schema_version 1, at most 10000 items and top in 1..=10000");
    }
    let mut seen = HashSet::new();
    let total = corpus.items.len();
    let mut relevant = 0;
    let mut selected: Vec<(hits::ReviewPriority, String, bool)> = Vec::new();
    let mut false_negative_keys = Vec::new();
    for labelled in corpus.items {
        if labelled.item.key.is_empty()
            || !seen.insert(labelled.item.key.clone())
            || labelled.rationale.trim().is_empty()
            || labelled.rationale.len() > 4000
        {
            bail!("each item needs a unique key and a bounded, nonempty rationale");
        }
        relevant += usize::from(labelled.relevant);
        let item = labelled.item;
        let linked = labelled.linked_body.clone();
        match screen::screen(&item, &linked) {
            Some(screen) => {
                let entry = Entry {
                    item,
                    screen,
                    disposition: Disposition::Review {
                        unpublished: Vec::new(),
                    },
                };
                let priority = hits::review_priority(&entry, &BTreeMap::new(), &[]);
                selected.push((priority, entry.item.key, labelled.relevant));
            }
            None if labelled.relevant => false_negative_keys.push(item.key),
            None => {}
        }
    }
    selected.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let true_positive = selected.iter().filter(|item| item.2).count();
    let selected_count = selected.len();
    let top_count = top.min(selected_count);
    let top_relevant = selected
        .iter()
        .take(top_count)
        .filter(|item| item.2)
        .count();
    Ok(Evaluation {
        schema_version: 1,
        model: "deterministic-v1",
        total,
        relevant,
        selected: selected_count,
        true_positive,
        false_positive: selected_count - true_positive,
        false_negative_keys,
        precision: ratio(true_positive, selected_count),
        recall: ratio(true_positive, relevant),
        top: top_count,
        precision_at_top: ratio(top_relevant, top_count),
        recall_at_top: ratio(top_relevant, relevant),
        baseline_select_all_precision: ratio(relevant, total),
        limitations: "Measures this labelled corpus only; advisory resolution and exact affected matches are not simulated. Labels require independent review; screen exclusions can miss relevant issues.",
    })
}
