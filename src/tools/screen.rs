//! Two-level security screen. Strong signals select an item wherever they appear: title, labels,
//! body, or the body of the issue a proposed change closes. Weak bug-class terms select a body
//! only when it also names a security-relevant technical context.
use super::{Item, ItemKind};
use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

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
    if linked_selected || STRONG.is_match(linked) {
        places.push(SignalPlace::LinkedIssue);
    }
    if BODY_BUG.is_match(&body) && BODY_CONTEXT.is_match(&body) {
        places.push(SignalPlace::ContextualBug);
    }
    if BODY_BUG.is_match(linked) && BODY_CONTEXT.is_match(linked) {
        places.push(SignalPlace::LinkedContextualBug);
    }
    if places.is_empty() {
        return None;
    }
    let own_text = format!("{}\n{body}", item.title);
    let mut snippets = snippets(&own_text);
    if snippets.is_empty() {
        snippets = self::snippets(linked);
    }
    if snippets.is_empty() && linked_selected {
        snippets.push(super::truncate_chars(linked, SNIPPET_RADIUS * 2));
    }
    if snippets.is_empty()
        && (places.contains(&SignalPlace::ContextualBug)
            || places.contains(&SignalPlace::LinkedContextualBug))
    {
        let source = if BODY_BUG.is_match(&body) && BODY_CONTEXT.is_match(&body) {
            &body
        } else {
            linked
        };
        snippets.push(super::truncate_chars(source, SNIPPET_RADIUS * 2));
    }
    Some(Screen {
        places,
        identifiers: identifiers(&[&item.title, &item.body, linked]),
        dependency_update: DEPENDENCY_UPDATE.is_match(&item.title),
        snippets,
    })
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

/// Sorted, deduplicated advisory IDs: `GHSA-` keeps its lowercase body, other IDs are uppercase.
pub fn identifiers(texts: &[&str]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for text in texts {
        for matched in IDENTIFIER.find_iter(text) {
            let raw = matched.as_str();
            let normalized = if raw.to_ascii_uppercase().starts_with("GHSA") {
                format!("GHSA{}", raw[4..].to_ascii_lowercase())
            } else {
                raw.to_ascii_uppercase()
            };
            found.push(normalized);
        }
    }
    found.sort_unstable();
    found.dedup();
    found.truncate(MAX_IDENTIFIERS);
    found
}

fn snippets(text: &str) -> Vec<String> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for matched in STRONG.find_iter(text) {
        let start = char_floor(text, matched.start().saturating_sub(SNIPPET_RADIUS));
        let end = char_ceil(text, matched.end().saturating_add(SNIPPET_RADIUS));
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
