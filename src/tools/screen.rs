//! Two-level security screen. Strong signals select an item wherever they appear: title, labels,
//! body, or the body of the issue a proposed change closes. Weak bug-class terms select a body
//! only when it also names a security-relevant technical context.
use super::{Item, ItemKind};
use regex::Regex;
use serde::Serialize;
use std::{collections::BTreeSet, sync::LazyLock};

#[cfg(test)]
mod tests;

static STRONG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(CVE-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3}|RUSTSEC-\d{4}-\d+|vulnerab\w*|security (?:issue|fix|flaw|bug|vulnerabilit\w*|advisory|report|impact|implications?|concern|risk)|attacker\w*|exploit\w*|bypass\w*|privilege escalation|unauthori[sz]ed access|denial[- ]of[- ]service|remote code execution|account takeover|session fixation|open redirect)",
    )
    .expect("static strong-signal pattern")
});
static TITLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(CVE-\d{4}-\d+|GHSA-|RUSTSEC-|security|vulnerab|XSS|CSRF|SSRF|injection|bypass|privilege escalation|deserializ|denial of service|DoS\b|leak|disclos|takeover|open redirect|traversal|smuggl|RCE\b|remote code|out-of-bounds|overflow|unbounded|exhaust|unsound|undefined behavio|use[- ]after[- ]free|double[- ]free|uninitiali[sz]ed|data race|panic|crash|infinite loop|timing (?:attack|leak|side)|side[- ]channel|spoof|forger(?:y|ies)|forged|impersonat|escalat|unauthori[sz]ed)",
    )
    .expect("static title pattern")
});
static LABEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)secur|cve|vulnerab|weakness|unsound").expect("static label pattern")
});
static BODY_BUG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:crash\w*|panic\w*|overflow\w*|out.of.bounds|use.after.free|unbounded|exhaust\w*|data race|deadlock\w*|hang\w*)\b").expect("static body bug pattern")
});
static BODY_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:pars\w*|decod\w*|deserializ\w*|authenticat\w*|authoriz\w*|request\w*|network|protocol|packet\w*|untrusted|remote|input\w*)\b").expect("static body context pattern")
});
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|RUSTSEC-\d{4}-\d{4})\b")
        .expect("static identifier pattern")
});
static DEPENDENCY_UPDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:\[[^\]]+\]\s*)?(?:build\(deps[^)]*\)|chore\(deps[^)]*\)|fix\(deps[^)]*\)|deps?:|bump\b|update (?:dependency|module|plugin|rust crate)|update \S+ to v?\d)",
    )
    .expect("static dependency-update pattern")
});
/// Issue templates live in HTML comments, and URL paths such as Dependabot's
/// `.../managing-security-vulnerabilities/...` make no claim about the item. A URL naming an
/// advisory ID is a citation and stays.
static TEMPLATE_NOISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<!--.*?(?:-->|$)|https?://\S+").expect("static template-noise pattern")
});

const SNIPPET_RADIUS: usize = 160;
const MAX_SNIPPETS: usize = 4;
const MAX_IDENTIFIERS: usize = 32;

#[derive(Default)]
struct Identifiers {
    values: BTreeSet<String>,
    truncated: bool,
}

impl Identifiers {
    fn insert(&mut self, value: String) {
        if self.values.contains(&value) {
            return;
        }
        if self.values.len() < MAX_IDENTIFIERS {
            self.values.insert(value);
        } else {
            self.truncated = true;
            if self.values.last().is_some_and(|last| &value < last) {
                self.values.pop_last();
                self.values.insert(value);
            }
        }
    }

    fn scan(&mut self, text: &str) {
        for matched in IDENTIFIER.find_iter(text) {
            let raw = matched.as_str();
            let normalized = if raw.to_ascii_uppercase().starts_with("GHSA") {
                format!("GHSA{}", raw[4..].to_ascii_lowercase())
            } else {
                raw.to_ascii_uppercase()
            };
            self.insert(normalized);
        }
    }

    fn merge(&mut self, other: &Self) {
        self.truncated |= other.truncated;
        for value in &other.values {
            self.insert(value.clone());
        }
    }
}

/// Bounded signals extracted from linked tracker items.
#[derive(Default)]
pub(super) struct LinkedSignals {
    identifiers: Identifiers,
    selected: bool,
    strong: bool,
    bug: bool,
    context: bool,
    snippets: Vec<String>,
    excerpt: String,
}

impl LinkedSignals {
    fn add_text(&mut self, text: &str) {
        self.strong |= STRONG.is_match(text);
        self.bug |= BODY_BUG.is_match(text);
        self.context |= BODY_CONTEXT.is_match(text);
        self.identifiers.scan(text);
        if self.snippets.len() < MAX_SNIPPETS {
            self.snippets.extend(
                snippets(text)
                    .into_iter()
                    .take(MAX_SNIPPETS - self.snippets.len()),
            );
        }
        if !text.is_empty() && self.excerpt.chars().count() < SNIPPET_RADIUS * 2 {
            if !self.excerpt.is_empty() {
                self.excerpt.push('\n');
            }
            let room = SNIPPET_RADIUS * 2 - self.excerpt.chars().count();
            self.excerpt.push_str(&super::truncate_chars(text, room));
        }
    }

    pub(super) fn from_item(item: &Item) -> Self {
        let mut signals = Self::default();
        let body = clean(&item.body);
        signals.selected = item.kind == ItemKind::Advisory
            || item.labels.iter().any(|label| LABEL.is_match(label))
            || TITLE.is_match(&item.title)
            || STRONG.is_match(&body)
            || (BODY_BUG.is_match(&body) && BODY_CONTEXT.is_match(&body));
        signals.add_text(&item.title);
        for label in &item.labels {
            signals.add_text(label);
        }
        signals.add_text(&body);
        signals
    }

    pub(super) fn merge(&mut self, other: &Self) {
        self.identifiers.merge(&other.identifiers);
        self.selected |= other.selected;
        self.strong |= other.strong;
        self.bug |= other.bug;
        self.context |= other.context;
        if self.snippets.len() < MAX_SNIPPETS {
            self.snippets.extend(
                other
                    .snippets
                    .iter()
                    .take(MAX_SNIPPETS - self.snippets.len())
                    .cloned(),
            );
        }
        if self.excerpt.is_empty() {
            self.excerpt = other.excerpt.clone();
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignalPlace {
    Label,
    Title,
    Body,
    LinkedIssue,
    Advisory,
    ContextualBug,
    LinkedContextualBug,
}

#[derive(Debug, Clone, Serialize)]
pub struct Screen {
    pub places: Vec<SignalPlace>,
    /// Advisory IDs cited in the title, body or linked issue.
    pub identifiers: Vec<String>,
    /// Additional distinct identifiers were present but not included.
    pub identifiers_truncated: bool,
    /// The item contains only advisory identifiers and neutral separators.
    pub sole_advisory_identifiers: bool,
    pub dependency_update: bool,
    /// Text around strong signals, so the reviewer reads the claim without the full body.
    pub snippets: Vec<String>,
}

impl Screen {
    /// The item itself carries a signal, not only the issue it closes.
    pub fn own_signal(&self) -> bool {
        self.places.iter().any(|place| {
            !matches!(
                place,
                SignalPlace::LinkedIssue | SignalPlace::LinkedContextualBug
            )
        })
    }
}

/// `None` when the item has no security signal. `linked` holds the screened bodies of the issues a
/// proposed change closes.
pub fn screen(item: &Item, linked: &str) -> Option<Screen> {
    screen_with_linked(item, linked, false)
}

/// Include the independently screened title, labels and body of a linked issue.
pub fn screen_with_linked(item: &Item, linked: &str, linked_selected: bool) -> Option<Screen> {
    let mut signals = LinkedSignals {
        selected: linked_selected,
        ..Default::default()
    };
    signals.add_text(linked);
    screen_with_signals(item, &signals)
}

pub(super) fn screen_with_signals(item: &Item, linked: &LinkedSignals) -> Option<Screen> {
    let body = clean(&item.body);
    let mut places = Vec::new();
    if item.kind == ItemKind::Advisory {
        places.push(SignalPlace::Advisory);
    }
    if item.labels.iter().any(|label| LABEL.is_match(label)) {
        places.push(SignalPlace::Label);
    }
    if TITLE.is_match(&item.title) {
        places.push(SignalPlace::Title);
    }
    if STRONG.is_match(&body) {
        places.push(SignalPlace::Body);
    }
    if linked.selected || linked.strong {
        places.push(SignalPlace::LinkedIssue);
    }
    if BODY_BUG.is_match(&body) && BODY_CONTEXT.is_match(&body) {
        places.push(SignalPlace::ContextualBug);
    }
    if linked.bug && linked.context {
        places.push(SignalPlace::LinkedContextualBug);
    }
    if places.is_empty() {
        return None;
    }
    let own_text = format!("{}\n{body}", item.title);
    let mut snippets = snippets(&own_text);
    if snippets.is_empty() {
        snippets = linked.snippets.clone();
    }
    if snippets.is_empty() && linked.selected {
        snippets.push(linked.excerpt.clone());
    }
    if snippets.is_empty()
        && (places.contains(&SignalPlace::ContextualBug)
            || places.contains(&SignalPlace::LinkedContextualBug))
    {
        let source = if BODY_BUG.is_match(&body) && BODY_CONTEXT.is_match(&body) {
            &body
        } else {
            &linked.excerpt
        };
        snippets.push(super::truncate_chars(source, SNIPPET_RADIUS * 2));
    }
    let mut ids = Identifiers::default();
    ids.scan(&item.title);
    ids.scan(&item.body);
    ids.merge(&linked.identifiers);
    let sole_advisory_identifiers = !TITLE.is_match(&item.title)
        && !item.labels.iter().any(|label| LABEL.is_match(label))
        && item.closes.is_empty()
        && !linked.selected
        && !linked.strong
        && !linked.bug
        && !linked.context
        && linked.identifiers.values.is_empty()
        && identifiers_only(&item.body);
    Some(Screen {
        places,
        identifiers: ids.values.into_iter().collect(),
        identifiers_truncated: ids.truncated,
        sole_advisory_identifiers,
        dependency_update: DEPENDENCY_UPDATE.is_match(&item.title),
        snippets,
    })
}

fn identifiers_only(text: &str) -> bool {
    let separator =
        |character: char| character.is_whitespace() || ",;:.()[]*#-".contains(character);
    let mut end = 0;
    let mut found = false;
    for matched in IDENTIFIER.find_iter(text) {
        if !text[end..matched.start()].chars().all(separator) {
            return false;
        }
        found = true;
        end = matched.end();
    }
    found && text[end..].chars().all(separator)
}

/// Text whose strong terms are claims by the item rather than template or link text.
pub fn clean(text: &str) -> String {
    TEMPLATE_NOISE
        .replace_all(text, |captures: &regex::Captures<'_>| {
            let matched = &captures[0];
            if IDENTIFIER.is_match(matched) {
                matched.to_owned()
            } else {
                " ".to_owned()
            }
        })
        .into_owned()
}

/// Returns sorted advisory IDs and whether the result omitted any distinct IDs.
pub fn identifiers(texts: &[&str]) -> (Vec<String>, bool) {
    let mut ids = Identifiers::default();
    for text in texts {
        ids.scan(text);
    }
    (ids.values.into_iter().collect(), ids.truncated)
}

fn snippets(text: &str) -> Vec<String> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for matched in STRONG.find_iter(text) {
        let start = char_floor(text, matched.start().saturating_sub(SNIPPET_RADIUS));
        let end = char_ceil(
            text,
            matched
                .end()
                .min(matched.start().saturating_add(SNIPPET_RADIUS))
                .saturating_add(SNIPPET_RADIUS),
        );
        match ranges.last_mut() {
            Some(last) if start <= last.1 => last.1 = end,
            _ => ranges.push((start, end)),
        }
        if ranges.len() > MAX_SNIPPETS {
            break;
        }
    }
    ranges
        .into_iter()
        .take(MAX_SNIPPETS)
        .map(|(start, end)| {
            text[start..end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

fn char_floor(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn char_ceil(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index += 1;
    }
    index
}
