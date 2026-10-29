use super::{LinkedSignals, screen, screen_with_linked, screen_with_signals};
use crate::tools::{Item, ItemKind};

fn issue(title: &str, body: &str) -> Item {
    Item {
        key: "owner/project#1".into(),
        kind: ItemKind::Issue,
        url: "https://github.com/owner/project/issues/1".into(),
        title: title.into(),
        state: "open".into(),
        labels: vec![],
        updated_at: "2026-10-20T00:00:00Z".into(),
        body: body.into(),
        closes: vec![],
        advisory: None,
    }
}

#[test]
fn linked_summaries_preserve_selection_and_identifiers() {
    let first = issue("Parser issue", "A parser crashes on input; CVE-2026-1234.");
    let second = issue("SSRF", "A security issue concerns CVE-2026-1235.");
    let mut pull = issue("Fix processing", "Fixes #1");
    pull.kind = ItemKind::PullRequest;
    let linked_text = format!(
        "{}\n\n{}\n{}\n\n{}",
        first.title, first.body, second.title, second.body
    );
    let previous = screen_with_linked(
        &pull,
        &linked_text,
        screen(&first, "").is_some() || screen(&second, "").is_some(),
    )
    .unwrap();
    let mut linked = LinkedSignals::default();
    linked.merge(&LinkedSignals::from_item(&first));
    linked.merge(&LinkedSignals::from_item(&second));
    let current = screen_with_signals(&pull, &linked).unwrap();
    assert_eq!(current.places, previous.places);
    assert_eq!(current.identifiers, previous.identifiers);
    assert_eq!(
        current.identifiers_truncated,
        previous.identifiers_truncated
    );
}

#[test]
fn combined_linked_identifiers_retain_truncation_and_bound_excerpts() {
    let mut linked = LinkedSignals::default();
    for number in 0..33 {
        let report = issue(
            "Security issue",
            &format!("CVE-2026-{:04} {}", number + 1000, "a".repeat(10000)),
        );
        linked.merge(&LinkedSignals::from_item(&report));
    }
    let mut pull = issue("Fix processing", "Fixes #1");
    pull.kind = ItemKind::PullRequest;
    let selected = screen_with_signals(&pull, &linked).unwrap();
    assert_eq!(selected.identifiers.len(), 32);
    assert!(selected.identifiers_truncated);
    assert!(selected.snippets.iter().all(|snippet| snippet.len() <= 640));
    assert!(linked.excerpt.len() <= 320);
}

#[test]
fn linked_summaries_bound_long_matching_tokens() {
    let report = issue("Report", &format!("vulnerab{}", "a".repeat(100_000)));
    let summary = LinkedSignals::from_item(&report);
    assert!(summary.selected);
    assert!(summary.snippets.iter().all(|snippet| snippet.len() <= 640));
    let mut linked = LinkedSignals::default();
    for _ in 0..1000 {
        linked.merge(&summary);
    }
    assert_eq!(linked.snippets.len(), 4);
    assert!(linked.snippets.iter().all(|snippet| snippet.len() <= 640));
}

#[test]
fn identifier_only_requires_no_other_claims_or_linked_context() {
    let plain = issue("v1.0.0", "CVE-2026-12345, GHSA-abcd-1234-efgh");
    assert!(screen(&plain, "").unwrap().sole_advisory_identifiers);

    let mut titled = plain.clone();
    titled.title = "Authentication bypass".into();
    assert!(!screen(&titled, "").unwrap().sole_advisory_identifiers);

    let mut labelled = plain.clone();
    labelled.labels.push("security".into());
    assert!(!screen(&labelled, "").unwrap().sole_advisory_identifiers);

    let mut text = plain.clone();
    text.body.push_str(" and an unrelated security issue");
    assert!(!screen(&text, "").unwrap().sole_advisory_identifiers);

    assert!(
        !screen_with_linked(&plain, "SSRF", true)
            .unwrap()
            .sole_advisory_identifiers
    );
}
