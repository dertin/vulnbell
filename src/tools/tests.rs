use super::{
    AdvisoryPackage, Item, ItemKind, RepositoryAdvisory,
    draft::{DecisionLookup, ItemDecision, ResearchDecisions},
    hits::{Disposition, RuleContext, disposition},
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
        instance_ids: vec!["instance-1".into()],
        components: Vec::new(),
        from: "2026-10-19T00:00:00+00:00".into(),
        until: "2026-10-21T00:00:00+00:00".into(),
        last_complete_review: None,
        seen: Vec::new(),
        seen_truncated: false,
        continuation: None,
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
        published_identifiers: BTreeSet::new(),
    }
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
fn dependency_updates_without_identifiers_are_relays_and_releases_need_published_ids() {
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
        Disposition::Rule(ref outcome) if outcome.assessment == Assessment::Ignore
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
            if host == "issues.redhat.com" && project == "WFLY"
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
        "github/example/project/issues.json",
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
    write(raw_dir, "github/example/project/releases.json", "[[]]");
    write(
        raw_dir,
        "github/example/project/security-advisories.json",
        r#"[[{"ghsa_id": "GHSA-abcd-1234-wxyz", "cve_id": "CVE-2026-22222", "html_url": "https://github.com/example/project/security/advisories/GHSA-abcd-1234-wxyz",
              "summary": "Old advisory", "description": null, "updated_at": "2025-01-01T00:00:00Z", "withdrawn_at": null, "vulnerabilities": []}]]"#,
    );
    write(
        raw_dir,
        "github/example/project/discussions.json",
        r#"[{"data": {"search": {"nodes": [{}]}}}]"#,
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
        "github/example/project/releases.json",
        r#"{"message": "Not Found", "status": "404"}"#,
    );
    assert!(!raw::read_target(raw_dir, &target).errors.is_empty());
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
        assessment: Assessment::NotApplicable,
        not_applicable_reason: Some(NotApplicableReason::AffectsOtherVersion),
        rationale: "Only the 1.x line is affected.".into(),
        source_facts: SourceFacts {
            affected_versions: "1.x".into(),
            ..SourceFacts::default()
        },
        instance_ids: Vec::new(),
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
        decisions.lookup(&reviewed),
        DecisionLookup::Current(_)
    ));
    reviewed.updated_at = "2026-10-20T12:00:00+00:00".into();
    assert!(matches!(
        decisions.lookup(&reviewed),
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
