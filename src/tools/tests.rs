use super::{
    AdvisoryPackage, Item, ItemKind, RepositoryAdvisory,
    draft::{DecisionLookup, ItemDecision, ResearchDecisions},
    hits::{Disposition, Entry, ReviewPriority, RuleContext, disposition, review_priority},
    normalize_time,
    raw::{self, TargetItems},
    screen::{self, SignalPlace},
    workspace,
};
use crate::{
    model::{Instance, SourceFacts},
    profile::Language,
    research::{Assessment, NotApplicableReason, ResearchTarget},
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

fn item(kind: ItemKind, title: &str, body: &str) -> Item {
    Item {
        key: "example/project#1".into(),
        kind,
        url: "https://github.com/example/project/issues/1".into(),
        title: title.into(),
        state: "open".into(),
        labels: Vec::new(),
        updated_at: "2026-10-20T10:00:00+00:00".into(),
        body: body.into(),
        closes: Vec::new(),
        closure: None,
        advisory: None,
    }
}

fn target(upstream: &str) -> ResearchTarget {
    ResearchTarget {
        upstream: upstream.into(),
        context_sha256: "a".repeat(64),
        instance_ids: vec!["instance-1".into()],
        components: Vec::new(),
        from: "2026-10-19T00:00:00+00:00".into(),
        until: "2026-10-21T00:00:00+00:00".into(),
        last_complete_review: None,
        seen: Vec::new(),
        seen_truncated: false,
        continuation: None,
        progress: None,
        stale_progress: None,
        context_reopened: false,
    }
}

fn instance(purl: &str, version: &str) -> Instance {
    let profile: crate::profile::Profile = serde_saphyr::from_str(&format!(
        "schema: 1\nproject_id: 0de0a8e7-f1a4-4bdc-a198-422b90bbbd84\nname: tools\ncomponents:\n  - ref: example\n    version: '{version}'\n"
    ))
    .unwrap();
    let mut instance = Instance::declared(&profile.components[0]);
    instance.purl = Some(purl.into());
    instance
}

fn empty_collected(upstream: &str) -> TargetItems {
    TargetItems {
        provider: raw::provider_for(upstream),
        method: String::new(),
        missing: Vec::new(),
        errors: Vec::new(),
        items: Vec::new(),
        linked_issues: Vec::new(),
        published_identifiers: BTreeSet::new(),
    }
}

#[test]
fn multi_component_review_requires_an_explicit_scope() {
    let upstream = "https://github.com/example/project";
    let make_prepared = || {
        let mut target = target(upstream);
        target.instance_ids.push("instance-2".into());
        let issue = item(
            ItemKind::Issue,
            "Security issue in parser",
            "A parser fails.",
        );
        let screen = screen::screen(&issue, "").unwrap();
        super::hits::Prepared {
            project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
            recheck: false,
            snapshot_id: "snapshot".into(),
            codebase_revisions: Vec::new(),
            targets: vec![super::hits::PreparedTarget {
                target,
                collected: empty_collected(upstream),
                not_selected: 0,
                entries: vec![Entry {
                    item: issue,
                    screen,
                    disposition: Disposition::Review {
                        unpublished: vec![],
                    },
                }],
            }],
            resolutions: BTreeMap::new(),
        }
    };
    let mut decisions = ResearchDecisions {
        schema_version: 1,
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        recheck: false,
        decisions: vec![ItemDecision {
            reviewed_instance_ids: vec!["instance-1".into()],
            codebase_revisions: Vec::new(),
            upstream: upstream.into(),
            key: "example/project#1".into(),
            updated_at: "2026-10-20T10:00:00+00:00".into(),
            context_sha256: "a".repeat(64),
            assessment: Assessment::Review,
            not_applicable_reason: None,
            artifact_evidence: None,
            rationale: "Review the parser used by the selected component.".into(),
            source_facts: SourceFacts::default(),
            instance_ids: vec![],
            all_instances: false,
        }],
    };
    let packet = super::hits::packet(&make_prepared(), Some(&decisions));
    assert_eq!(packet.review.len(), 1);
    assert!(packet.review[0].scope_required);
    assert_eq!(
        packet.review[0]
            .previous_decision
            .as_ref()
            .unwrap()
            .reviewed_instance_ids,
        vec!["instance-1"]
    );
    assert!(super::draft::draft(make_prepared(), &decisions, false).is_err());

    let mut ruled = make_prepared();
    ruled.targets[0].entries[0].disposition = Disposition::Rule(super::hits::RuleOutcome {
        assessment: Assessment::Ignore,
        reason: None,
        rationale: "Deterministic rule".into(),
        facts: SourceFacts::default(),
        instance_ids: Vec::new(),
    });
    let packet = super::hits::packet(&ruled, Some(&decisions));
    assert_eq!(packet.review.len(), 1);
    assert!(packet.review[0].scope_required);
    assert!(super::draft::draft(ruled, &decisions, false).is_err());

    decisions.decisions[0].instance_ids = vec!["instance-2".into()];
    assert!(super::draft::draft(make_prepared(), &decisions, false).is_err());
    decisions.decisions[0]
        .reviewed_instance_ids
        .push("instance-2".into());
    let (batch, _) = super::draft::draft(make_prepared(), &decisions, false).unwrap();
    assert_eq!(batch.events[0].instance_ids, vec!["instance-2"]);
    assert_eq!(
        batch.events[0].reviewed_instance_ids,
        vec!["instance-1", "instance-2"]
    );

    decisions.decisions[0].instance_ids.clear();
    decisions.decisions[0].all_instances = true;
    let (batch, _) = super::draft::draft(make_prepared(), &decisions, false).unwrap();
    assert_eq!(
        batch.events[0].instance_ids,
        vec!["instance-1", "instance-2"]
    );

    decisions.decisions[0].instance_ids = vec!["outside".into()];
    decisions.decisions[0].all_instances = false;
    assert!(super::draft::draft(make_prepared(), &decisions, false).is_err());
}

#[test]
fn recheck_skips_decisions_from_the_current_pass() {
    let upstream = "https://github.com/example/project";
    let target = target(upstream);
    let entries = (0..12)
        .map(|index| {
            let mut item = item(ItemKind::Issue, "Security issue", "A synthetic claim.");
            item.key = format!("example/project#{index:02}");
            let screen = screen::screen(&item, "").unwrap();
            Entry {
                item,
                screen,
                disposition: Disposition::Review {
                    unpublished: vec![],
                },
            }
        })
        .collect();
    let prepared = super::hits::Prepared {
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        snapshot_id: "snapshot".into(),
        recheck: true,
        codebase_revisions: vec![],
        targets: vec![super::hits::PreparedTarget {
            target,
            collected: empty_collected(upstream),
            not_selected: 0,
            entries,
        }],
        resolutions: BTreeMap::new(),
    };
    let mut decisions = ResearchDecisions {
        schema_version: 1,
        project_id: prepared.project_id.clone(),
        recheck: true,
        decisions: vec![],
    };
    let first = super::hits::packet_with_recheck(&prepared, Some(&decisions), true);
    assert_eq!(first.review.len(), 12);
    for item in first.review.iter().take(10) {
        decisions.decisions.push(ItemDecision {
            reviewed_instance_ids: vec!["instance-1".into()],
            upstream: item.upstream.clone(),
            key: item.key.clone(),
            updated_at: item.updated_at.clone(),
            context_sha256: item.context_sha256.clone(),
            codebase_revisions: vec![],
            assessment: Assessment::Review,
            not_applicable_reason: None,
            artifact_evidence: None,
            rationale: "Review the synthetic claim.".into(),
            source_facts: SourceFacts::default(),
            instance_ids: vec![],
            all_instances: false,
        });
    }
    let second = super::hits::packet_with_recheck(&prepared, Some(&decisions), true);
    assert_eq!(second.review.len(), 2);
    assert_eq!(second.summary.decided, 10);
    decisions.recheck = false;
    assert_eq!(
        super::hits::packet_with_recheck(&prepared, Some(&decisions), true)
            .review
            .len(),
        12
    );
}

#[test]
fn priority_uses_exact_target_instance_without_suppressing_unknowns() {
    use super::advisories::{BuildMatch, BuildStatus, Resolution};
    let issue = item(
        ItemKind::Issue,
        "CVE-2026-12345 in parser",
        "Security issue.",
    );
    let entry = Entry {
        screen: screen::screen(&issue, "").unwrap(),
        item: issue,
        disposition: Disposition::Review {
            unpublished: vec![],
        },
    };
    let resolutions = BTreeMap::from([(
        "CVE-2026-12345".into(),
        Resolution {
            in_build: vec![BuildMatch {
                instance_id: "one".into(),
                reference: "example".into(),
                version: "1.0.0".into(),
                status: BuildStatus::Affected,
                range: "< 2.0.0".into(),
            }],
            ..Resolution::default()
        },
    )]);
    assert_eq!(
        review_priority(&entry, &resolutions, &["one".into()]),
        ReviewPriority::ExactAffected
    );
    assert_eq!(
        review_priority(&entry, &resolutions, &["other".into()]),
        ReviewPriority::NamedAdvisory
    );
}

#[test]
fn evaluation_exposes_false_negatives_and_top_k_without_changing_decisions() {
    let entry = |key: &str, title: &str, body: &str, relevant: bool| {
        let mut value = item(ItemKind::Issue, title, body);
        value.key = key.into();
        super::evaluate::LabelledItem {
            item: value,
            relevant,
            high_priority: key == "a" || key == "c",
            rationale: "independent synthetic label".into(),
            linked_body: String::new(),
            linked_items: Vec::new(),
        }
    };
    let corpus = super::evaluate::Corpus {
        schema_version: 1,
        items: vec![
            entry("a", "CVE-2026-12345", "A reported issue", true),
            entry("b", "Parser crash", "A non-security bug", false),
            entry("c", "Handle malformed input", "A crash occurs", true),
            entry("d", "Fix wording", "Documentation only", false),
        ],
    };
    let result = serde_json::to_value(super::evaluate::evaluate(corpus, 1).unwrap()).unwrap();
    assert_eq!(result["selected"], 2);
    assert_eq!(result["precision"], 0.5);
    assert_eq!(result["false_positive_keys"][0], "b");
    assert_eq!(result["recall"], 0.5);
    assert_eq!(result["precision_at_top"], 1.0);
    assert_eq!(result["false_negative_keys"][0], "c");
    assert_eq!(result["high_priority"], 2);
    assert_eq!(result["high_priority_recall"], 0.5);
    assert_eq!(result["high_priority_missed_keys"][0], "c");
    assert_eq!(result["high_priority_recall_at_top"], 0.5);
}

#[test]
fn evaluation_rejects_high_priority_items_labelled_irrelevant() {
    let corpus = super::evaluate::Corpus {
        schema_version: 1,
        items: vec![super::evaluate::LabelledItem {
            item: item(ItemKind::Issue, "Example", ""),
            relevant: false,
            high_priority: true,
            rationale: "Contradictory synthetic label".into(),
            linked_body: String::new(),
            linked_items: Vec::new(),
        }],
    };
    assert!(super::evaluate::evaluate(corpus, 1).is_err());
}

#[test]
fn evaluation_screens_linked_item_metadata_like_research() {
    let mut linked = item(ItemKind::Issue, "Response handling", "No details provided.");
    linked.key = "example/project#2".into();
    linked.labels = vec!["security".into()];
    let mut change = item(ItemKind::PullRequest, "Adjust response handling", "");
    change.closes = vec![linked.key.clone()];
    let entry = super::evaluate::LabelledItem {
        item: change,
        relevant: true,
        high_priority: false,
        rationale: "A linked tracker item has a security label.".into(),
        linked_body: String::new(),
        linked_items: vec![linked],
    };
    let result = super::evaluate::evaluate(
        super::evaluate::Corpus {
            schema_version: 1,
            items: vec![entry],
        },
        1,
    )
    .unwrap();
    assert_eq!(result.selected, 1);
    assert!(result.false_negative_keys.is_empty());
}

#[test]
fn evaluation_rejects_unrelated_linked_items() {
    let entry = super::evaluate::LabelledItem {
        item: item(ItemKind::PullRequest, "Adjust response handling", ""),
        relevant: true,
        high_priority: false,
        rationale: "Only referenced items are valid context.".into(),
        linked_body: String::new(),
        linked_items: vec![item(ItemKind::Issue, "Security issue", "")],
    };
    assert!(
        super::evaluate::evaluate(
            super::evaluate::Corpus {
                schema_version: 1,
                items: vec![entry]
            },
            1
        )
        .is_err()
    );
}

#[test]
fn screen_selects_claimed_phishing() {
    for body in [
        "An email verification flow may enable phishing.",
        "The login page can be used for a phishing attack.",
    ] {
        assert!(screen::screen(&item(ItemKind::Issue, "Request handling", body), "").is_some());
    }
    assert!(
        screen::screen(
            &item(
                ItemKind::Issue,
                "Request handling",
                "A hard-coded timeout is too short."
            ),
            ""
        )
        .is_none()
    );
}

#[test]
fn times_keep_second_precision_and_accept_jira_and_naive_formats() {
    assert_eq!(
        normalize_time("2026-10-16T12:00:00Z").as_deref(),
        Some("2026-10-16T12:00:00+00:00")
    );
    assert_eq!(
        normalize_time("2026-10-16T12:00:00.123+0000").as_deref(),
        Some("2026-10-16T12:00:00+00:00")
    );
    assert_eq!(
        normalize_time("2026-10-16T09:00:00-03:00").as_deref(),
        Some("2026-10-16T09:00:00-03:00")
    );
    assert_eq!(
        normalize_time("2026-10-16 12:00:00").as_deref(),
        Some("2026-10-16T12:00:00+00:00")
    );
    assert!(normalize_time("yesterday").is_none());
}

#[test]
fn weak_terms_select_only_in_title_and_template_text_is_not_a_claim() {
    assert!(screen::screen(&item(ItemKind::Issue, "Crash on startup", ""), "").is_some());
    assert!(
        screen::screen(
            &item(
                ItemKind::Issue,
                "Startup is slow",
                "It may crash or leak memory."
            ),
            ""
        )
        .is_none()
    );
    let template = "<!-- Report security vulnerabilities privately -->\nSee https://docs.github.com/managing-security-vulnerabilities/about";
    assert!(screen::screen(&item(ItemKind::Issue, "Docs typo", template), "").is_none());
    let contextual = item(
        ItemKind::Issue,
        "Handle malformed input",
        "The parser crashes on a packet.",
    );
    assert!(
        screen::screen(&contextual, "")
            .unwrap()
            .places
            .contains(&SignalPlace::ContextualBug)
    );
    let cited = item(
        ItemKind::Issue,
        "Docs typo",
        "Tracked in https://osv.dev/vulnerability/ghsa-ABCD-1234-wxyz and CVE-2026-12345",
    );
    let found = screen::screen(&cited, "").unwrap();
    assert_eq!(found.places, vec![SignalPlace::Body]);
    assert_eq!(
        found.identifiers,
        vec!["CVE-2026-12345", "GHSA-abcd-1234-wxyz"]
    );
}

#[test]
fn a_fix_pr_without_its_own_signal_is_settled_through_the_issue_it_closes() {
    let mut pull = item(
        ItemKind::PullRequest,
        "Check the token audience",
        "Fixes #7",
    );
    pull.closes = vec!["example/project#7".into()];
    let found = screen::screen(&pull, "An attacker can reuse a token").unwrap();
    assert_eq!(found.places, vec![SignalPlace::LinkedIssue]);
    assert!(!found.own_signal());
    let collected = empty_collected("https://github.com/example/project");
    let selected: HashSet<String> = HashSet::from(["example/project#7".to_owned()]);
    let resolutions = BTreeMap::new();
    let context = RuleContext {
        collected: &collected,
        selected_keys: &selected,
        resolutions: &resolutions,
        target_instances: &[],
        language: Language::En,
    };
    let Disposition::Rule(outcome) = disposition(&pull, &found, &context) else {
        panic!("fix PR should be settled by rule");
    };
    assert_eq!(outcome.assessment, Assessment::Ignore);
    assert!(
        outcome
            .rationale
            .starts_with("Proposed change for example/project#7")
    );

    let spanish = RuleContext {
        language: Language::Es,
        ..context
    };
    let Disposition::Rule(outcome) = disposition(&pull, &found, &spanish) else {
        panic!("fix PR should be settled by rule");
    };
    assert!(
        outcome
            .rationale
            .starts_with("Cambio propuesto para example/project#7")
    );

    let unselected = HashSet::new();
    let context = RuleContext {
        selected_keys: &unselected,
        ..context
    };
    assert!(matches!(
        disposition(&pull, &found, &context),
        Disposition::Review { .. }
    ));
}

#[test]
fn unlinked_security_updates_and_releases_need_review() {
    let bump = item(
        ItemKind::PullRequest,
        "build(deps): bump example-lib from 1.2.0 to 1.2.1",
        "Release notes: security fix for header parsing.",
    );
    let found = screen::screen(&bump, "").unwrap();
    assert!(found.dependency_update);
    let collected = empty_collected("https://github.com/example/project");
    let selected = HashSet::new();
    let resolutions = BTreeMap::new();
    let context = RuleContext {
        collected: &collected,
        selected_keys: &selected,
        resolutions: &resolutions,
        target_instances: &[],
        language: Language::En,
    };
    assert!(matches!(
        disposition(&bump, &found, &context),
        Disposition::Review { .. }
    ));

    let unlinked_release = item(ItemKind::Release, "v2.0.1", "Security fix in parser.");
    let unlinked_screen = screen::screen(&unlinked_release, "").unwrap();
    assert!(matches!(
        disposition(&unlinked_release, &unlinked_screen, &context),
        Disposition::Review { .. }
    ));

    let release = item(
        ItemKind::Release,
        "v2.0.1",
        "Security fix for CVE-2026-11111.",
    );
    let found = screen::screen(&release, "").unwrap();
    let Disposition::Review { unpublished } = disposition(&release, &found, &context) else {
        panic!("release citing an unpublished advisory needs review");
    };
    assert_eq!(unpublished, vec!["CVE-2026-11111"]);
    let mut published = empty_collected("https://github.com/example/project");
    published
        .published_identifiers
        .insert("CVE-2026-11111".into());
    let context = RuleContext {
        collected: &published,
        ..context
    };
    assert!(matches!(
        disposition(&release, &found, &context),
        Disposition::Review { .. }
    ));
}

#[test]
fn published_advisory_does_not_hide_independent_security_claims() {
    use super::advisories::Resolution;
    let mut collected = empty_collected("https://github.com/example/project");
    collected
        .published_identifiers
        .insert("CVE-2026-12345".into());
    let resolutions = BTreeMap::from([(
        "CVE-2026-12345".into(),
        Resolution {
            published: true,
            ..Default::default()
        },
    )]);
    let selected = HashSet::new();
    let context = RuleContext {
        collected: &collected,
        selected_keys: &selected,
        resolutions: &resolutions,
        target_instances: &[],
        language: Language::En,
    };
    for (kind, title) in [
        (ItemKind::Release, "v2.0.1"),
        (ItemKind::PullRequest, "build(deps): bump example"),
    ] {
        let report = item(
            kind,
            title,
            "CVE-2026-12345. An attacker can bypass authentication.",
        );
        let found = screen::screen(&report, "").unwrap();
        assert!(matches!(
            disposition(&report, &found, &context),
            Disposition::Review { .. }
        ));

        let relay = item(kind, title, "CVE-2026-12345");
        let found = screen::screen(&relay, "").unwrap();
        assert!(matches!(
            disposition(&relay, &found, &context),
            Disposition::Rule(_)
        ));
    }
}

#[test]
fn truncated_identifiers_require_review_for_releases_and_dependency_updates() {
    use super::advisories::Resolution;

    let ids: Vec<String> = (1..=33)
        .map(|number| format!("CVE-2026-{number:04}"))
        .collect();
    let mut collected = empty_collected("https://github.com/example/project");
    collected
        .published_identifiers
        .extend(ids[..32].iter().cloned());
    let resolutions: BTreeMap<String, Resolution> = ids[..32]
        .iter()
        .map(|id| {
            (
                id.clone(),
                Resolution {
                    published: true,
                    ..Resolution::default()
                },
            )
        })
        .collect();
    let selected = HashSet::new();
    let context = RuleContext {
        collected: &collected,
        selected_keys: &selected,
        resolutions: &resolutions,
        target_instances: &[],
        language: Language::En,
    };
    let duplicates = format!("{} {}", ids[..32].join(" "), ids[0]);
    assert!(
        !screen::screen(&item(ItemKind::Release, "v2.0.1", &duplicates), "")
            .unwrap()
            .identifiers_truncated
    );
    for (kind, title) in [
        (ItemKind::Release, "v2.0.1"),
        (ItemKind::PullRequest, "build(deps): bump example"),
    ] {
        let complete = item(kind, title, &ids[..32].join(" "));
        let complete_screen = screen::screen(&complete, "").unwrap();
        assert!(!complete_screen.identifiers_truncated);
        assert!(matches!(
            disposition(&complete, &complete_screen, &context),
            Disposition::Rule(_)
        ));

        let incomplete = item(kind, title, &ids.join(" "));
        let incomplete_screen = screen::screen(&incomplete, "").unwrap();
        assert_eq!(incomplete_screen.identifiers.len(), 32);
        assert!(incomplete_screen.identifiers_truncated);
        assert!(matches!(
            disposition(&incomplete, &incomplete_screen, &context),
            Disposition::Review { .. }
        ));
    }
    let release = item(ItemKind::Release, "v2.0.1", &ids.join(" "));
    let screen = screen::screen(&release, "").unwrap();
    let disposition = disposition(&release, &screen, &context);
    let mut prepared = super::hits::Prepared {
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        recheck: false,
        snapshot_id: "snapshot".into(),
        codebase_revisions: Vec::new(),
        targets: vec![super::hits::PreparedTarget {
            target: target("https://github.com/example/project"),
            collected,
            not_selected: 0,
            entries: vec![Entry {
                disposition,
                item: release,
                screen,
            }],
        }],
        resolutions,
    };
    let packet = serde_json::to_value(super::hits::packet(&prepared, None)).unwrap();
    assert_eq!(packet["review"][0]["identifiers_truncated"], true);
    prepared.targets[0].entries[0].item.kind = ItemKind::PullRequest;
    prepared.targets[0].entries[0].item.closure = Some(super::PullRequestClosure::ClosedUnmerged);
    let packet = serde_json::to_value(super::hits::packet(&prepared, None)).unwrap();
    assert_eq!(packet["review"][0]["closure"], "closed_unmerged");
}

#[test]
fn repository_advisories_are_evaluated_against_the_target_instances() {
    let mut advisory = item(
        ItemKind::Advisory,
        "GHSA-abcd-1234-wxyz: header smuggling",
        "",
    );
    advisory.advisory = Some(RepositoryAdvisory {
        ghsa_id: "GHSA-abcd-1234-wxyz".into(),
        cve_id: Some("CVE-2026-22222".into()),
        packages: vec![AdvisoryPackage {
            ecosystem: "rust".into(),
            name: "example-http".into(),
            vulnerable_range: "< 1.4.0".into(),
            patched: "1.4.0".into(),
        }],
    });
    let found = screen::screen(&advisory, "").unwrap();
    let collected = empty_collected("https://github.com/example/project");
    let selected = HashSet::new();
    let resolutions = BTreeMap::new();
    let outcome = |instances: &[&Instance]| {
        let context = RuleContext {
            collected: &collected,
            selected_keys: &selected,
            resolutions: &resolutions,
            target_instances: instances,
            language: Language::En,
        };
        disposition(&advisory, &found, &context)
    };

    let other = instance("pkg:cargo/other-crate@1.0.0", "1.0.0");
    let Disposition::Rule(missing) = outcome(&[&other]) else {
        panic!("advisory for another package is settled by rule");
    };
    assert_eq!(
        missing.reason,
        Some(NotApplicableReason::ComponentNotInBuild)
    );

    let fixed = instance("pkg:cargo/example-http@1.5.0", "1.5.0");
    let Disposition::Rule(outside) = outcome(&[&fixed]) else {
        panic!("version outside the range is settled by rule");
    };
    assert_eq!(
        outside.reason,
        Some(NotApplicableReason::AffectsOtherVersion)
    );
    assert_eq!(outside.facts.affected_versions, "example-http < 1.4.0");
    assert_eq!(
        outside.facts.identifiers,
        vec!["GHSA-abcd-1234-wxyz", "CVE-2026-22222"]
    );

    let affected = instance("pkg:cargo/example-http@1.3.0", "1.3.0");
    assert!(matches!(outcome(&[&affected]), Disposition::Review { .. }));
    let mut unknown = other.clone();
    unknown.purl = None;
    assert!(matches!(
        outcome(&[&other, &unknown]),
        Disposition::Review { .. }
    ));
    assert!(matches!(outcome(&[]), Disposition::Review { .. }));
    let mut no_packages = advisory.clone();
    no_packages.advisory.as_mut().unwrap().packages.clear();
    let context = RuleContext {
        collected: &collected,
        selected_keys: &selected,
        resolutions: &resolutions,
        target_instances: &[&other],
        language: Language::En,
    };
    assert!(matches!(
        disposition(&no_packages, &found, &context),
        Disposition::Review { .. }
    ));
}

#[test]
fn decisions_are_validated_and_stale_ones_are_reported() {
    let decision = ItemDecision {
        reviewed_instance_ids: vec!["instance-1".into()],
        codebase_revisions: Vec::new(),
        upstream: "https://github.com/example/project".into(),
        key: "example/project#7".into(),
        updated_at: "2026-10-20T10:00:00Z".into(),
        context_sha256: "a".repeat(64),
        assessment: Assessment::NotApplicable,
        not_applicable_reason: Some(NotApplicableReason::AffectsOtherVersion),
        artifact_evidence: None,
        rationale: "Only the 1.x line is affected.".into(),
        source_facts: SourceFacts {
            affected_versions: "1.x".into(),
            ..SourceFacts::default()
        },
        instance_ids: Vec::new(),
        all_instances: false,
    };
    let decisions = ResearchDecisions {
        schema_version: 1,
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        recheck: false,
        decisions: vec![decision.clone()],
    };
    decisions.validate().unwrap();
    let mut reviewed = item(ItemKind::Issue, "Token reuse", "");
    reviewed.key = "example/project#7".into();
    reviewed.updated_at = "2026-10-20T10:00:00+00:00".into();
    assert!(matches!(
        decisions.lookup(
            &reviewed,
            &target("https://github.com/example/project"),
            &[]
        ),
        DecisionLookup::Current(_)
    ));
    reviewed.updated_at = "2026-10-20T12:00:00+00:00".into();
    assert!(matches!(
        decisions.lookup(
            &reviewed,
            &target("https://github.com/example/project"),
            &[]
        ),
        DecisionLookup::Stale(_)
    ));

    let mut duplicated = decisions.clone();
    duplicated.decisions.push(decision.clone());
    assert!(duplicated.validate().is_err());
    let mut without_fact = decision;
    without_fact.source_facts = SourceFacts::default();
    let invalid = ResearchDecisions {
        schema_version: 1,
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        recheck: false,
        decisions: vec![without_fact],
    };
    assert!(invalid.validate().is_err());
}

#[path = "tests/decisions.rs"]
mod decisions;
