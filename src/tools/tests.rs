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
            project_id: "project".into(),
            snapshot_id: "snapshot".into(),
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
        decisions: vec![ItemDecision {
            upstream: upstream.into(),
            key: "example/project#1".into(),
            updated_at: "2026-10-20T10:00:00+00:00".into(),
            context_sha256: "a".repeat(64),
            assessment: Assessment::Review,
            not_applicable_reason: None,
            rationale: "Review the parser used by the selected component.".into(),
            source_facts: SourceFacts::default(),
            instance_ids: vec![],
            all_instances: false,
        }],
    };
    let packet = super::hits::packet(&make_prepared(), Some(&decisions));
    assert_eq!(packet.review.len(), 1);
    assert!(packet.review[0].scope_required);
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
    let (batch, _) = super::draft::draft(make_prepared(), &decisions, false).unwrap();
    assert_eq!(batch.events[0].instance_ids, vec!["instance-2"]);

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
            rationale: "independent synthetic label".into(),
            linked_body: String::new(),
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
    assert_eq!(result["recall"], 0.5);
    assert_eq!(result["precision_at_top"], 1.0);
    assert_eq!(result["false_negative_keys"][0], "c");
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
    assert!(outcome.rationale.starts_with("Fix for example/project#7"));

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
            .starts_with("Corrección de example/project#7")
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
    let prepared = super::hits::Prepared {
        project_id: "project".into(),
        snapshot_id: "snapshot".into(),
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
        upstream: "https://github.com/example/project".into(),
        key: "example/project#7".into(),
        updated_at: "2026-10-20T10:00:00Z".into(),
        context_sha256: "a".repeat(64),
        assessment: Assessment::NotApplicable,
        not_applicable_reason: Some(NotApplicableReason::AffectsOtherVersion),
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
        decisions: vec![decision.clone()],
    };
    decisions.validate().unwrap();
    let mut reviewed = item(ItemKind::Issue, "Token reuse", "");
    reviewed.key = "example/project#7".into();
    reviewed.updated_at = "2026-10-20T10:00:00+00:00".into();
    assert!(matches!(
        decisions.lookup(&reviewed, &target("https://github.com/example/project")),
        DecisionLookup::Current(_)
    ));
    reviewed.updated_at = "2026-10-20T12:00:00+00:00".into();
    assert!(matches!(
        decisions.lookup(&reviewed, &target("https://github.com/example/project")),
        DecisionLookup::Stale(_)
    ));

    let mut duplicated = decisions.clone();
    duplicated.decisions.push(decision.clone());
    assert!(duplicated.validate().is_err());
    let mut without_fact = decision;
    without_fact.source_facts = SourceFacts::default();
    let invalid = ResearchDecisions {
        schema_version: 1,
        decisions: vec![without_fact],
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn decisions_with_the_same_key_are_scoped_to_the_upstream() {
    let github = "https://github.com/example/project";
    let gitlab = "https://gitlab.com/example/project";
    let make_prepared = || super::hits::Prepared {
        project_id: "project".into(),
        snapshot_id: "snapshot".into(),
        targets: [github, gitlab]
            .into_iter()
            .map(|upstream| {
                let mut issue = item(
                    ItemKind::Issue,
                    "Security issue",
                    "Security issue in parser.",
                );
                issue.url = format!("{upstream}/issues/1");
                super::hits::PreparedTarget {
                    target: target(upstream),
                    collected: empty_collected(upstream),
                    not_selected: 0,
                    entries: vec![Entry {
                        screen: screen::screen(&issue, "").unwrap(),
                        item: issue,
                        disposition: Disposition::Review {
                            unpublished: vec![],
                        },
                    }],
                }
            })
            .collect(),
        resolutions: BTreeMap::new(),
    };
    let mut decisions = ResearchDecisions {
        schema_version: 1,
        decisions: vec![ItemDecision {
            upstream: github.into(),
            key: "example/project#1".into(),
            updated_at: "2026-10-20T10:00:00+00:00".into(),
            context_sha256: "a".repeat(64),
            assessment: Assessment::Ignore,
            not_applicable_reason: None,
            rationale: "GitHub item is unrelated.".into(),
            source_facts: SourceFacts::default(),
            instance_ids: vec![],
            all_instances: false,
        }],
    };
    decisions.validate().unwrap();
    let packet = super::hits::packet(&make_prepared(), Some(&decisions));
    assert_eq!(packet.review.len(), 1);
    assert_eq!(packet.review[0].upstream, gitlab);
    assert!(super::draft::draft(make_prepared(), &decisions, false).is_err());

    let mut gitlab_decision = decisions.decisions[0].clone();
    gitlab_decision.upstream = gitlab.into();
    gitlab_decision.assessment = Assessment::Review;
    gitlab_decision.rationale = "GitLab item needs review.".into();
    decisions.decisions.push(gitlab_decision);
    decisions.validate().unwrap();
    let (batch, _) = super::draft::draft(make_prepared(), &decisions, false).unwrap();
    assert_eq!(batch.events.len(), 2);
    assert_eq!(batch.events[0].upstream, github);
    assert_eq!(batch.events[0].assessment, Assessment::Ignore);
    assert_eq!(batch.events[1].upstream, gitlab);
    assert_eq!(batch.events[1].assessment, Assessment::Review);

    decisions.decisions.push(decisions.decisions[0].clone());
    assert!(decisions.validate().is_err());
    decisions.decisions.pop();
    decisions.decisions[0].upstream = "http://example.org/project".into();
    assert!(decisions.validate().is_err());
    let mut missing_upstream = serde_json::to_value(&decisions.decisions[0]).unwrap();
    missing_upstream.as_object_mut().unwrap().remove("upstream");
    assert!(serde_json::from_value::<ItemDecision>(missing_upstream).is_err());
}

#[test]
fn workspace_init_creates_the_monitor_layout_and_rejects_bad_names() {
    let directory = tempfile::tempdir().unwrap();
    let layout = workspace::init(directory.path(), "keycloak", "2026-10-27").unwrap();
    assert!(!layout.profile_exists);
    assert!(directory.path().join("notes").is_dir());
    assert!(
        directory
            .path()
            .join("monitors/keycloak/runs/2026-10-27/raw")
            .is_dir()
    );
    assert_eq!(
        layout.decisions,
        directory
            .path()
            .join("monitors/keycloak/decisions/research.json")
    );
    assert!(workspace::init(directory.path(), "Keycloak", "2026-10-27").is_err());
    assert!(workspace::init(directory.path(), "../x", "2026-10-27").is_err());
    assert!(workspace::init(directory.path(), "keycloak", "27/10/2026").is_err());
}

#[test]
fn truncated_seen_item_requires_a_review_decision() {
    let report = item(
        ItemKind::Issue,
        "Security report",
        &(0..33)
            .map(|n| format!("CVE-2026-{:04}", n + 1000))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let screen = screen::screen(&report, "").unwrap();
    assert!(screen.identifiers_truncated);
    let mut research_target = target("https://github.com/example/project");
    research_target.seen.push(crate::research::SeenEvent {
        external_id: report.key.clone(),
        url: report.url.clone(),
        content_sha256: "a".repeat(64),
        updated_at: report.updated_at.clone(),
        context_current: true,
        assessment: Some(Assessment::Ignore),
        not_applicable_reason: None,
        rationale: String::new(),
    });
    assert!(!super::hits::already_reviewed(
        &research_target,
        &report,
        &screen
    ));
    research_target.seen[0].assessment = Some(Assessment::Review);
    assert!(super::hits::already_reviewed(
        &research_target,
        &report,
        &screen
    ));
}
