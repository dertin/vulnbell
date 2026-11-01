use super::*;

#[test]
fn decisions_with_the_same_key_are_scoped_to_the_upstream() {
    let github = "https://github.com/example/project";
    let gitlab = "https://gitlab.com/example/project";
    let make_prepared = || super::super::hits::Prepared {
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        recheck: false,
        snapshot_id: "snapshot".into(),
        codebase_revisions: Vec::new(),
        targets: [github, gitlab]
            .into_iter()
            .map(|upstream| {
                let mut issue = item(
                    ItemKind::Issue,
                    "Security issue",
                    "Security issue in parser.",
                );
                issue.url = format!("{upstream}/issues/1");
                super::super::hits::PreparedTarget {
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
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        recheck: false,
        decisions: vec![ItemDecision {
            reviewed_instance_ids: vec!["instance-1".into()],
            codebase_revisions: Vec::new(),
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
    let packet = super::super::hits::packet(&make_prepared(), Some(&decisions));
    assert_eq!(packet.review.len(), 1);
    assert_eq!(packet.review[0].upstream, gitlab);
    assert!(super::super::draft::draft(make_prepared(), &decisions, false).is_err());

    let mut gitlab_decision = decisions.decisions[0].clone();
    gitlab_decision.upstream = gitlab.into();
    gitlab_decision.assessment = Assessment::Review;
    gitlab_decision.rationale = "GitLab item needs review.".into();
    decisions.decisions.push(gitlab_decision);
    decisions.validate().unwrap();
    let (batch, _) = super::super::draft::draft(make_prepared(), &decisions, false).unwrap();
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
    assert!(!super::super::hits::already_reviewed(
        &research_target,
        &report,
        &screen
    ));
    research_target.seen[0].assessment = Some(Assessment::Review);
    assert!(super::super::hits::already_reviewed(
        &research_target,
        &report,
        &screen
    ));
}

#[test]
fn decision_codebase_metadata_must_match_the_review_packet() {
    use crate::codebase_revision::{CodebaseRevision, RepositoryState};
    let revision = CodebaseRevision {
        codebase: "/example/project".into(),
        state: RepositoryState::Git,
        repository: Some("/example/project".into()),
        branch: Some("main".into()),
        commit: Some("a".repeat(40)),
        dirty: Some(false),
        worktree_status_sha256: Some("b".repeat(64)),
        observed_at: "2026-10-20T10:00:00Z".into(),
    };
    let mut reviewed = item(ItemKind::Issue, "Security issue", "");
    reviewed.key = "example/project#7".into();
    let decision = ItemDecision {
        reviewed_instance_ids: vec!["instance-1".into()],
        upstream: "https://github.com/example/project".into(),
        key: reviewed.key.clone(),
        updated_at: reviewed.updated_at.clone(),
        context_sha256: "a".repeat(64),
        codebase_revisions: vec![revision.clone()],
        assessment: Assessment::Review,
        not_applicable_reason: None,
        rationale: "Review the issue.".into(),
        source_facts: SourceFacts::default(),
        instance_ids: vec![],
        all_instances: false,
    };
    let decisions = ResearchDecisions {
        schema_version: 1,
        project_id: "0de0a8e7-f1a4-4bdc-a198-422b90bbbd84".into(),
        recheck: false,
        decisions: vec![decision],
    };
    let mut next_observation = revision.clone();
    next_observation.observed_at = "2026-10-20T12:00:00Z".into();
    let source = target("https://github.com/example/project");
    assert!(matches!(
        decisions.lookup(&reviewed, &source, &[next_observation]),
        DecisionLookup::Current(_)
    ));
    let mut changed = revision;
    changed.branch = Some("other".into());
    assert!(matches!(
        decisions.lookup(&reviewed, &source, &[changed]),
        DecisionLookup::Stale(_)
    ));
    assert!(matches!(
        decisions.lookup(&reviewed, &source, &[]),
        DecisionLookup::Stale(_)
    ));
    let mut not_git = decisions.decisions[0].codebase_revisions[0].clone();
    not_git.state = RepositoryState::NotGit;
    not_git.repository = None;
    not_git.branch = None;
    not_git.commit = None;
    not_git.dirty = None;
    not_git.worktree_status_sha256 = None;
    let mut without_revision = decisions.clone();
    without_revision.decisions[0].codebase_revisions.clear();
    assert!(matches!(
        without_revision.lookup(&reviewed, &source, &[not_git]),
        DecisionLookup::Stale(_)
    ));
    let mut serialized = serde_json::to_value(&decisions.decisions[0]).unwrap();
    serialized
        .as_object_mut()
        .unwrap()
        .remove("codebase_revisions");
    assert!(serde_json::from_value::<ItemDecision>(serialized).is_err());
}
