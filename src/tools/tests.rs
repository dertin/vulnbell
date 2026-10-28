use super::{
    AdvisoryPackage, Item, ItemKind, RepositoryAdvisory,
    draft::{DecisionLookup, ItemDecision, ResearchDecisions},
    hits::{Disposition, Entry, ReviewPriority, RuleContext, disposition, review_priority},
    normalize_time,
    raw::{self, FetchTool, JiraApi, Provider, TargetItems},
    screen::{self, SignalPlace},
    workspace,
};
use crate::{
    model::{Instance, SourceFacts},
    profile::Language,
    research::{Assessment, NotApplicableReason, ResearchTarget},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::Path,
};

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
fn github_requires_terminal_page_and_fetches_old_linked_issues() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let repo = "github/example/project";
    let issue = serde_json::json!({"number": 1, "title": "Routine cleanup", "html_url": "https://github.com/example/project/pull/1", "state": "open", "updated_at": "2026-10-20T10:00:00Z", "labels": [], "body": "Fixes #42", "pull_request": {}});
    let page: Vec<_> = (0..100).map(|_| issue.clone()).collect();
    write(
        raw,
        &format!("{repo}/issues.page-1.json"),
        &serde_json::to_string(&page).unwrap(),
    );
    write(raw, &format!("{repo}/releases.page-1.json"), "[]");
    write(
        raw,
        &format!("{repo}/security-advisories.page-1.json"),
        "[]",
    );
    write(
        raw,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let target = target("https://github.com/example/project");
    let incomplete = raw::read_target(raw, &target);
    assert!(
        incomplete
            .missing
            .iter()
            .any(|fetch| fetch.path.ends_with("issues.page-2.json"))
    );
    assert!(!incomplete.complete());
    write(raw, &format!("{repo}/issues.page-2.json"), "[]");
    let linked_missing = raw::read_target(raw, &target);
    assert!(
        linked_missing
            .missing
            .iter()
            .any(|fetch| fetch.path.ends_with("linked-issues/42.json")
                && fetch.tool == FetchTool::GhRestSingle)
    );
    assert!(!linked_missing.complete());
    write(
        raw,
        &format!("{repo}/linked-issues/42.json"),
        r#"{"number":42,"title":"Old report","html_url":"https://github.com/example/project/issues/42","state":"open","updated_at":"2025-01-01T00:00:00Z","labels":[],"body":"An attacker can bypass authentication."}"#,
    );
    let collected = raw::read_target(raw, &target);
    assert!(collected.complete());
    assert_eq!(collected.linked_issues.len(), 1);
    assert!(!collected.items.iter().any(|item| item.key.ends_with("#42")));
    assert!(screen::screen(&collected.items[0], &collected.linked_issues[0].body).is_some());
    let mut title_only = collected.linked_issues[0].clone();
    title_only.title = "SSRF in request handling".into();
    title_only.body = "Details pending".into();
    assert!(screen::screen(&title_only, "").is_some());
    assert!(screen::screen_with_linked(&collected.items[0], &title_only.title, true).is_some());
}

#[test]
fn github_screens_security_signals_after_the_old_body_limit() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let repo = "github/example/project";
    let issue = serde_json::json!({"number": 1, "title": "Parser update", "html_url": "https://github.com/example/project/issues/1", "state": "open", "updated_at": "2026-10-20T10:00:00Z", "labels": [], "body": format!("{} attacker can bypass checks", "x".repeat(9000))});
    write(
        raw,
        &format!("{repo}/issues.page-1.json"),
        &serde_json::json!([issue]).to_string(),
    );
    write(raw, &format!("{repo}/releases.page-1.json"), "[]");
    write(
        raw,
        &format!("{repo}/security-advisories.page-1.json"),
        "[]",
    );
    write(
        raw,
        &format!("{repo}/discussions.json"),
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let collected = raw::read_target(raw, &target("https://github.com/example/project"));
    assert!(collected.complete());
    assert!(screen::screen(&collected.items[0], "").is_some());
}

#[test]
fn gitlab_and_forgejo_fetch_linked_issues_outside_the_window() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path();
    let gitlab = "gitlab/gitlab.com/example/project";
    write(raw, &format!("{gitlab}/issues.page-1.json"), "[]");
    write(raw, &format!("{gitlab}/releases.page-1.json"), "[]");
    write(
        raw,
        &format!("{gitlab}/merge_requests.page-1.json"),
        r#"[{"iid":1,"title":"Maintenance","web_url":"https://gitlab.com/example/project/-/merge_requests/1","state":"opened","updated_at":"2026-10-20T10:00:00Z","labels":[],"description":"Fixes #42"}]"#,
    );
    let gitlab_target = target("https://gitlab.com/example/project");
    let missing = raw::read_target(raw, &gitlab_target);
    assert!(missing.missing.iter().any(
        |fetch| fetch.path.ends_with("linked-issues/42.json") && fetch.tool == FetchTool::Curl
    ));
    write(
        raw,
        &format!("{gitlab}/linked-issues/42.json"),
        r#"{"iid":42,"title":"Old issue","web_url":"https://gitlab.com/example/project/-/issues/42","state":"opened","updated_at":"2025-01-01T00:00:00Z","labels":[],"description":"Security issue"}"#,
    );
    let linked = raw::read_target(raw, &gitlab_target);
    assert!(linked.complete(), "{:?}", linked.errors);
    assert_eq!(linked.linked_issues[0].key, "example/project#42");

    let forgejo = "forgejo/codeberg.org/example/project";
    write(
        raw,
        &format!("{forgejo}/issues.page-1.json"),
        r#"[{"number":1,"title":"Maintenance","html_url":"https://codeberg.org/example/project/pulls/1","state":"open","updated_at":"2026-10-20T10:00:00Z","labels":[],"body":"Fixes #42","pull_request":{}}]"#,
    );
    write(raw, &format!("{forgejo}/releases.page-1.json"), "[]");
    let forgejo_target = target("https://codeberg.org/example/project");
    let missing = raw::read_target(raw, &forgejo_target);
    assert!(
        missing
            .missing
            .iter()
            .any(|fetch| fetch.path.ends_with("linked-issues/42.json"))
    );
    write(
        raw,
        &format!("{forgejo}/linked-issues/42.json"),
        r#"{"number":42,"title":"Old issue","html_url":"https://codeberg.org/example/project/issues/42","state":"open","updated_at":"2025-01-01T00:00:00Z","labels":[],"body":"Security issue"}"#,
    );
    let linked = raw::read_target(raw, &forgejo_target);
    assert!(linked.complete(), "{:?}", linked.errors);
    assert_eq!(linked.linked_issues[0].key, "example/project#42");
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

fn write(directory: &Path, relative: &str, contents: &str) {
    let path = directory.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
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
        Disposition::Rule(ref outcome) if outcome.assessment == Assessment::Informational
    ));
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
fn providers_map_to_their_raw_directories() {
    assert_eq!(
        raw::provider_for("https://github.com/example/project.git"),
        Provider::GitHub {
            owner: "example".into(),
            repository: "project".into(),
            mirror: false
        }
    );
    assert_eq!(
        raw::provider_for("https://gitbox.apache.org/repos/asf?p=commons-io.git"),
        Provider::GitHub {
            owner: "apache".into(),
            repository: "commons-io".into(),
            mirror: true
        }
    );
    assert!(matches!(
        raw::provider_for("https://issues.jboss.org/browse/WFLY"),
        Provider::Jira { api: JiraApi::SearchJqlV3, ref host, ref project, .. }
            if host == "redhat.atlassian.net" && project == "WFLY"
    ));
    assert!(matches!(
        raw::provider_for("https://gitlab.com/group/sub/project/-/issues"),
        Provider::GitLab { ref project, .. } if project == "group/sub/project"
    ));
    let Provider::Manual { directory, .. } =
        raw::provider_for("https://sourceforge.net/projects/../../etc")
    else {
        panic!("unsupported host is manual");
    };
    assert!(!directory.contains(".."));
}

#[test]
fn github_responses_are_parsed_and_missing_files_name_their_request() {
    let directory = tempfile::tempdir().unwrap();
    let raw_dir = directory.path();
    let target = target("https://github.com/example/project");
    let partial = raw::read_target(raw_dir, &target);
    assert_eq!(partial.missing.len(), 4);
    assert!(
        partial
            .missing
            .iter()
            .any(|missing| missing.tool == FetchTool::GhGraphqlDiscussions
                && missing.request == "repo:example/project updated:>=2026-10-19T00:00:00Z")
    );

    write(
        raw_dir,
        "github/example/project/issues.page-1.json",
        r#"[[
          {"number": 7, "title": "Token reuse", "html_url": "https://github.com/example/project/issues/7",
           "state": "open", "updated_at": "2026-10-20T10:00:00Z", "labels": [{"name": "security"}], "body": "An attacker can reuse a token"},
          {"number": 8, "title": "Check audience", "html_url": "https://github.com/example/project/pull/8",
           "state": "closed", "updated_at": "2026-10-20T11:00:00Z", "labels": [], "body": "Closes #7",
           "pull_request": {"url": "x"}},
          {"number": 9, "title": "Old", "html_url": "https://github.com/example/project/issues/9",
           "state": "open", "updated_at": "2026-10-01T11:00:00Z", "labels": [], "body": null}
        ]]"#,
    );
    write(
        raw_dir,
        "github/example/project/releases.page-1.json",
        "[[]]",
    );
    write(
        raw_dir,
        "github/example/project/security-advisories.page-1.json",
        r#"[[{"ghsa_id": "GHSA-abcd-1234-wxyz", "cve_id": "CVE-2026-22222", "html_url": "https://github.com/example/project/security/advisories/GHSA-abcd-1234-wxyz",
              "summary": "Old advisory", "description": null, "updated_at": "2025-01-01T00:00:00Z", "withdrawn_at": null, "vulnerabilities": []}]]"#,
    );
    write(
        raw_dir,
        "github/example/project/discussions.json",
        r#"[{"data": {"search": {"discussionCount": 0, "nodes": [{}], "pageInfo": {"hasNextPage": false, "endCursor": null}}}}]"#,
    );
    let complete = raw::read_target(raw_dir, &target);
    assert!(complete.complete(), "{:?}", complete.errors);
    let keys: Vec<&str> = complete
        .items
        .iter()
        .map(|item| item.key.as_str())
        .collect();
    assert_eq!(keys, vec!["example/project#7", "example/project#8"]);
    assert_eq!(complete.items[1].kind, ItemKind::PullRequest);
    assert_eq!(complete.items[1].closes, vec!["example/project#7"]);
    assert!(complete.published_identifiers.contains("CVE-2026-22222"));

    write(
        raw_dir,
        "github/example/project/discussions.json",
        r#"[{"data":{"search":{"discussionCount":1,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    let incomplete_count = raw::read_target(raw_dir, &target);
    assert!(
        incomplete_count
            .errors
            .iter()
            .any(|error| error.contains("discussion results are incomplete"))
    );

    write(
        raw_dir,
        "github/example/project/discussions.json",
        r#"[{"data":{"search":{"discussionCount":1,"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"next"}}}}]"#,
    );
    assert!(!raw::read_target(raw_dir, &target).complete());

    write(
        raw_dir,
        "github/example/project/releases.page-1.json",
        r#"{"message": "Not Found", "status": "404"}"#,
    );
    assert!(!raw::read_target(raw_dir, &target).errors.is_empty());

    write(
        raw_dir,
        "github/example/project/releases.page-1.json",
        " \n",
    );
    let truncated = raw::read_target(raw_dir, &target);
    assert!(truncated.errors.iter().any(|error| {
        error.contains("github/example/project/releases.page-1.json")
            && error.contains("empty response file")
    }));
    write(
        raw_dir,
        "github/example/project/releases.page-1.json",
        "[[]]",
    );
    write(
        raw_dir,
        "github/example/project/discussions.json",
        r#"[{"data":{"search":{"discussionCount":0,"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}]"#,
    );
    write(
        raw_dir,
        "github/example/project/issues.page-1.json",
        r#"[[{"number":7,"title":"Issue","html_url":"https://github.com/example/project/issues/7","state":"open","updated_at":"invalid","labels":[],"body":"A security issue"}]]"#,
    );
    let bad_date = raw::read_target(raw_dir, &target);
    assert!(!bad_date.complete());
    assert!(
        bad_date
            .errors
            .iter()
            .any(|error| error.contains("invalid update timestamp"))
    );
}

#[test]
fn jira_v3_pages_follow_the_next_page_token() {
    let directory = tempfile::tempdir().unwrap();
    let raw_dir = directory.path();
    let target = target("https://hibernate.atlassian.net/browse/HHH");
    write(
        raw_dir,
        "jira/hibernate.atlassian.net/HHH.page-1.json",
        r#"{"issues": [{"key": "HHH-1", "fields": {"summary": "SQL injection in order by", "updated": "2026-10-20T10:00:00.000+0000",
            "status": {"name": "Open"}, "issuetype": {"name": "Bug"}, "labels": [],
            "description": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Crafted input"}]}]}}}],
            "isLast": false, "nextPageToken": "abc=="}"#,
    );
    let first = raw::read_target(raw_dir, &target);
    assert_eq!(first.items.len(), 1);
    assert_eq!(
        first.items[0].url,
        "https://hibernate.atlassian.net/browse/HHH-1"
    );
    assert!(first.items[0].body.contains("Crafted input"));
    assert_eq!(first.missing.len(), 1);
    assert!(
        first.missing[0]
            .request
            .ends_with("&nextPageToken=abc%3D%3D")
    );
    assert!(
        first.missing[0]
            .request
            .contains("/rest/api/3/search/jql?jql=")
    );
}

#[test]
fn decisions_are_validated_and_stale_ones_are_reported() {
    let decision = ItemDecision {
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
